#include "llvm/Transforms/Obfuscator/NativeConnected.h"
#include "llvm/Transforms/Obfuscator/NativePlan.h"
#include "llvm/Transforms/Obfuscator/NativeInvariant.h"
#include "llvm/Transforms/Obfuscator/NativeCall.h"
#include "llvm/Transforms/Obfuscator/FunctionSnapshot.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Support/CommandLine.h"
#include <memory>
#include <numeric>
#include <vector>

using namespace llvm;
namespace llvm::obf {
namespace {
cl::opt<unsigned> NativeLaneTransitionsOpt("native-lane-transitions",
    cl::desc("P6 experiment: key flattening dispatcher transitions on the live encoded-data "
             "word (0 off, 1 on, 2 stale-relation ablation for the canonical-repair arm)"),
    cl::init(0));
}
unsigned nativeLaneTransitions() { return NativeLaneTransitionsOpt; }
namespace {
bool width(Type *T, bool Boolean = false) {
  return (T->isIntegerTy() && llvm::is_contained(ArrayRef<unsigned>{8, 16, 32, 64}, T->getIntegerBitWidth())) ||
         (Boolean && T->isIntegerTy(1));
}
bool safe(const Function &F) {
  if (F.isDeclaration() || F.isVarArg() || F.hasPersonalityFn() ||
      F.hasFnAttribute(Attribute::Naked) || F.getInstructionCount() > 12000) return false;
  for (const Instruction &I : instructions(F)) {
    if (I.isEHPad() || isa<InvokeInst, CallBrInst, IndirectBrInst>(I)) return false;
    if (const auto *C = dyn_cast<CallBase>(&I))
      if (C->isInlineAsm() || C->hasFnAttr(Attribute::ReturnsTwice) ||
          (isa<CallInst>(C) && cast<CallInst>(C)->isMustTailCall())) return false;
  }
  return true;
}
struct Pair { Value *E = nullptr, *R = nullptr; };
struct Object {
  AllocaInst *A;
  Type *Element;
  uint64_t Elements;
  SmallVector<GetElementPtrInst *, 16> GEPs;
  SmallVector<LoadInst *, 16> Loads;
  SmallVector<StoreInst *, 16> Stores;
  SmallVector<Instruction *, 8> Lifetimes;
  DenseMap<Value *, Value *> EP, RP;
  std::string ID;
  // Set when the object was admitted by the constant-offset leaf walk rather
  // than by the narrow scalar/flat-array rule. Element is then null, because
  // the leaves do not share one width.
  bool Aggregate = false;
  uint64_t Leaves = 0;
  Object(AllocaInst *A, Type *Element, uint64_t Elements, std::string ID)
      : A(A), Element(Element), Elements(Elements), ID(std::move(ID)) {}
};
// One supported integer field at a constant byte offset in an object.
struct Leaf { uint64_t Offset = 0; Type *Ty = nullptr; };
// The same 64-slot ceiling the narrow flat-array rule already used. Neither
// this nor the eight-object budget is raised by the aggregate experiment.
constexpr unsigned MaxLeaves = 64, MaxLeafDepth = 8;
// Enumerate an object type as nothing but supported integer leaves. Any
// float, pointer, vector, i1, odd-width integer, opaque or scalable part
// fails the whole object: a leaf set that does not describe every byte we
// might touch is not a proof of anything.
bool enumerateLeaves(Type *T, uint64_t Base, const DataLayout &DL,
                     SmallVectorImpl<Leaf> &Out, unsigned Depth) {
  if (Depth > MaxLeafDepth || Out.size() >= MaxLeaves) return false;
  if (T->isIntegerTy()) {
    if (!width(T)) return false;
    Out.push_back(Leaf{Base, T});
    return true;
  }
  if (auto *AT = dyn_cast<ArrayType>(T)) {
    if (AT->getNumElements() > MaxLeaves) return false;
    TypeSize Stride = DL.getTypeAllocSize(AT->getElementType());
    if (Stride.isScalable()) return false;
    for (uint64_t N = 0; N < AT->getNumElements(); ++N)
      if (!enumerateLeaves(AT->getElementType(), Base + N * Stride.getFixedValue(), DL, Out, Depth + 1))
        return false;
    return true;
  }
  auto *ST = dyn_cast<StructType>(T);
  if (!ST || ST->isOpaque() || ST->isScalableTy() || ST->getNumElements() > MaxLeaves) return false;
  const StructLayout *SL = DL.getStructLayout(ST);
  for (unsigned N = 0; N < ST->getNumElements(); ++N)
    if (!enumerateLeaves(ST->getElementType(N), Base + SL->getElementOffset(N), DL, Out, Depth + 1))
      return false;
  return true;
}
struct Region {
  SmallVector<Instruction *, 32> Nodes;
  unsigned ID = 0, Component = 0, Shard = 0, Cost = 0, Score = 0;
  bool Affine = false, Sharded = false;
};
// One bounded joint-output group: two selected nodes whose encoded lanes are
// replaced by the lanes of U = First + Second and V = First + 2*Second.
struct JointGroup { Instruction *First = nullptr, *Second = nullptr; };
// Fixed skip vocabularies. Node reasons count each examined node once; pair
// reasons count each examined ordered pair once. Unknown is never success.
enum JointNodeSkip { JN_Phi, JN_Unused, JN_WalkBound, JN_NoRoots, JN_Budget,
                     JN_TestBudget, JN_NoPartner, JN_Count };
enum JointPairSkip { JP_Width, JP_Family, JP_Dominance, JP_Shared, JP_Identical,
                     JP_NoUse, JP_Paired, JP_Count };
const char *const JointNodeSkipName[JN_Count] = {
    "phi-representation", "unused-value", "dependency-walk-bound", "no-live-dependency",
    "group-budget", "pair-test-budget", "no-compatible-partner"};
const char *const JointPairSkipName[JP_Count] = {
    "width-mismatch", "family-mismatch", "no-dominance", "shared-dependency",
    "identical-dependencies", "no-dominated-use", "already-grouped"};
// The object walk's precise rejection reasons, classified into the fixed M0
// vocabulary. The verbatim walk reason is kept beside this classification in
// the plan: the vocabulary is what the inventory counts, the walk reason is
// what a person diagnoses from, and neither one replaces the other.
plan::Boundary objectBoundary(StringRef Reason) {
  if (Reason.starts_with("address-escape") || Reason == "pointer-compare") return plan::Boundary::ObjectEscape;
  if (Reason == "object-budget" || Reason == "component-budget") return plan::Boundary::ComponentLimit;
  return plan::Boundary::UnsupportedOperation;
}
// Normalize a dependency root so that two reloads of one object, or a cast of
// one value, are not mistaken for two distinct live dependencies.
Value *rootKey(Value *V) {
  for (unsigned Steps = 0; Steps < 8; ++Steps) {
    if (auto *L = dyn_cast<LoadInst>(V)) { V = getUnderlyingObject(L->getPointerOperand()); continue; }
    if (auto *C = dyn_cast<CastInst>(V)) { V = C->getOperand(0); continue; }
    break;
  }
  return V;
}
// Shared node estimates so component, shard and region accounting cannot
// drift apart. They include pin/context/boundary work; the exact
// transactional ceiling catches underestimates. These are not hardness scores.
unsigned nodeCost(const Instruction *I) {
  return (I->getOpcode() == Instruction::Add || I->getOpcode() == Instruction::Sub ||
          isa<ICmpInst>(I)) ? 320 : 96;
}
unsigned nodeScore(const Instruction *I) {
  unsigned Score = isa<ICmpInst>(I) ? 8 : isa<LoadInst>(I) ? 4 : 1;
  for (const User *U : I->users()) if (isa<ReturnInst, StoreInst, BranchInst>(U)) Score += 4;
  return Score;
}

class Encoder {
  Function &F;
  NativeConnectedOptions O;
  Rng RNG;
  SmallVector<Object, 8> Objects;
  SmallVector<Region, 8> Regions;
  SmallVector<Instruction *, 64> Nodes;
  DenseMap<Instruction *, unsigned> RegionOf;
  DenseMap<Instruction *, Pair> Encoded;
  DenseMap<LoadInst *, unsigned> MemoryLoads;
  SmallPtrSet<StoreInst *, 32> MemoryStores;
  AllocaInst *Context = nullptr, *Witness = nullptr;
  // Encoded-call pairs this function consumed without a scalar decode, keyed
  // by the interface that owns them. Published only if the function survives.
  StringMap<NativeCallAbsorption> Absorbed;
  SmallPtrSet<Instruction *, 8> AbsorbedParameters;
  unsigned Inputs = 0, Outputs = 0, Predicates = 0, MultiplyBridges = 0;
  unsigned MemoryEdges = 0, PersistentEdges = 0, SkippedComponents = 0, Site = 0, Copies = 0, EligibleNodes = 0;
  unsigned EligibleMemoryEdges = 0, PhiPairs = 0;
  unsigned EligibleAggregateObjects = 0, EligibleMemoryLeaves = 0;
  unsigned AggregateObjects = 0, AggregateMemoryEdges = 0;
  unsigned FamilyConversions = 0, MixedComponents = 0;
  unsigned OversizedComponents = 0, ShardedComponents = 0, SelectedShards = 0, ShardLostNodes = 0;
  unsigned EligibleCost = 0, SelectedCost = 0, SkippedCost = 0, ShardLostCost = 0;
  unsigned ReserveDenied = 0, ReserveDeniedCost = 0;
  unsigned CostLimit = 0, ShardCostLimit = 0;
  DominatorTree DT;
  // The private typed plan. It records the decisions this planner already
  // makes; it never makes one of its own and never emits an instruction, so
  // the protected IR does not depend on whether it is being built.
  plan::Plan ThePlan;
  DenseMap<const Instruction *, unsigned> OpIndex;
  SmallVector<Instruction *, 64> OpNodeInst;
  SmallVector<unsigned, 8> ObjectPlan;
  DenseMap<const AllocaInst *, unsigned> AllocaPlan;
  // Useful work per planned operation, computed once when the plan is sealed.
  SmallVector<unsigned, 64> UsefulWorkOf;
  // Distinct (value, reason) pairs already counted as a boundary origin. Used
  // only to decide whether a count is new; never iterated, so no hash order
  // reaches the output.
  DenseSet<std::pair<const Value *, unsigned>> BoundaryOrigins;
  unsigned StructuralReserve = 0;
  SmallVector<JointGroup, 8> JointGroups;
  unsigned JointCandidates = 0, JointCoupled = 0, JointRewrittenUses = 0, JointPairTests = 0;
  unsigned JointNodeSkips[JN_Count] = {}, JointPairSkips[JP_Count] = {};
  json::Array ObjectReport;

  std::string seedNamespace() const {
    return ("native-connected-v1/" + F.getName()).str();
  }
  static plan::NodeKind kindOf(const Instruction *I) {
    if (isa<LoadInst>(I)) return plan::NodeKind::Load;
    if (isa<ICmpInst>(I)) return plan::NodeKind::Compare;
    if (isa<PHINode>(I)) return plan::NodeKind::Phi;
    if (isa<SelectInst>(I)) return plan::NodeKind::Select;
    if (isa<CastInst>(I)) return plan::NodeKind::Cast;
    return plan::NodeKind::Pure;
  }
  // The single place a representation family is described. A verified offline
  // family is added by declaring its lanes, carrier width, valid-state
  // invariant, seed namespace and how its laws were established, not by
  // threading another boolean through the emitter.
  unsigned representation(bool Affine) {
    plan::Representation R;
    R.Fam = Affine ? plan::Family::AdditivePair : plan::Family::XorPrefixPair;
    R.Rev = 1;
    R.Lanes = 2;
    // A region carries several widths at once, so the width fields belong to
    // the individual values and live on the operation nodes. 0 here means
    // mixed, and is published as unknown rather than as a zero width.
    R.LogicalWidth = 0;
    R.LaneWidth = 0;
    R.Invariant = Affine ? "difference-of-lanes" : "xor-of-lanes";
    R.SeedNamespace = seedNamespace();
    // Derived algebraically and cross-checked against the independent
    // conformance model. Not SMT-proved in tree, which is what this says.
    R.Verified = plan::Verification::Algebraic;
    return ThePlan.intern(R);
  }
  unsigned recordObject(AllocaInst *A, StringRef ID, StringRef Layout, uint64_t Elements,
                        uint64_t Leaves, unsigned Width, StringRef SkipReason) {
    if (!O.Plan) return plan::Invalid;
    plan::ObjectNode N;
    N.Origin = ID.str();
    N.Name = A->getName().str();
    N.Layout = Layout.str();
    N.Elements = Elements;
    N.Leaves = Leaves;
    N.ElementWidth = Width;
    N.Owned = SkipReason.empty();
    N.SkipReason = SkipReason.str();
    if (!SkipReason.empty()) N.Reason = objectBoundary(SkipReason);
    ThePlan.Objects.push_back(std::move(N));
    AllocaPlan[A] = ThePlan.Objects.size() - 1;
    return ThePlan.Objects.size() - 1;
  }
  void recordBoundary(plan::Boundary B, const Value *Origin, unsigned Edges = 1) {
    if (!O.Plan) return;
    ThePlan.Inventory.record(B, Edges, BoundaryOrigins.insert({Origin, unsigned(B)}).second);
  }
  // Which storage a load or store this pass does not own belongs to. The
  // object walk already decided why it was not owned; reuse that answer rather
  // than inventing a second one.
  plan::Boundary storageBoundary(Value *Pointer) {
    if (auto *A = dyn_cast<AllocaInst>(getUnderlyingObject(Pointer)))
      if (auto It = AllocaPlan.find(A); It != AllocaPlan.end() &&
          ThePlan.Objects[It->second].Reason != plan::Boundary::Count)
        return ThePlan.Objects[It->second].Reason;
    return plan::Boundary::ObjectEscape;
  }
  // Where one scalar entering a region came from, in the fixed vocabulary.
  plan::Boundary entryBoundary(Value *V) {
    if (isa<Argument>(V)) return plan::Boundary::ExternalABI;
    auto *I = dyn_cast<Instruction>(V);
    if (!I) return plan::Boundary::UnsupportedOperation;
    for (StringRef Tag : {"sre.native.call.arg", "sre.native.call.split", "sre.native.call.result"})
      if (I->getMetadata(Tag)) return plan::Boundary::InterfaceMismatch;
    // An eligible operation the planner dropped is a selection loss, not an
    // unsupported one: say which loss it was.
    if (auto It = OpIndex.find(I); It != OpIndex.end() && ThePlan.Ops[It->second].Reason != plan::Boundary::Count)
      return ThePlan.Ops[It->second].Reason;
    if (auto *L = dyn_cast<LoadInst>(I)) return storageBoundary(L->getPointerOperand());
    if (auto *C = dyn_cast<CallBase>(I)) {
      Function *G = C->getCalledFunction();
      return G && !G->isDeclaration() && G->hasLocalLinkage() ? plan::Boundary::InterfaceMismatch
                                                              : plan::Boundary::ExternalABI;
    }
    return plan::Boundary::UnsupportedOperation;
  }
  // Which kind of crossing one scalar consumer is. Order matters: a consumer
  // that is itself an eligible operation the planner dropped is a selection
  // loss, and must not be reported as an unsupported operation.
  plan::Boundary exitBoundary(Instruction *User) {
    if (auto It = OpIndex.find(User); It != OpIndex.end() && ThePlan.Ops[It->second].Reason != plan::Boundary::Count)
      return ThePlan.Ops[It->second].Reason;
    if (isa<GetElementPtrInst>(User)) return plan::Boundary::AddressExposure;
    if (isa<ReturnInst>(User))
      return F.hasLocalLinkage() ? plan::Boundary::InterfaceMismatch : plan::Boundary::ExternalABI;
    if (auto *C = dyn_cast<CallBase>(User)) {
      Function *G = C->getCalledFunction();
      return G && !G->isDeclaration() && G->hasLocalLinkage() ? plan::Boundary::InterfaceMismatch
                                                              : plan::Boundary::ExternalABI;
    }
    if (auto *S = dyn_cast<StoreInst>(User)) return storageBoundary(S->getPointerOperand());
    return plan::Boundary::UnsupportedOperation;
  }
  unsigned contractFor(StringRef Interface) {
    for (unsigned K = 0; K < ThePlan.Calls.size(); ++K)
      if (ThePlan.Calls[K].Interface == Interface) return K;
    plan::CallContract C;
    C.Origin = plan::originId(F.getName(), "call", ThePlan.Calls.size());
    C.Interface = Interface.str();
    // Encoded pairs cross a private interface in the XOR family; a contract
    // that carried another family would have to say so here.
    C.Rep = representation(false);
    C.Status = "boundary";
    ThePlan.Calls.push_back(std::move(C));
    return ThePlan.Calls.size() - 1;
  }
  void recordEntry(Value *V, unsigned RegionID) {
    if (!O.Plan) return;
    ThePlan.transfer(ThePlan.Regions[RegionID].Origin, plan::TransferKind::Entry, plan::Invalid,
                     ThePlan.Regions[RegionID].Rep, plan::Verification::Algebraic);
    // A build constant exposes no program data, so it is counted apart from
    // the reason table rather than padding it.
    if (isa<Constant>(V)) { ++ThePlan.Inventory.ConstantEntries; return; }
    recordBoundary(entryBoundary(V), V);
  }
  void markSkipped(ArrayRef<Instruction *> Dropped, plan::Boundary B) {
    if (!O.Plan) return;
    for (Instruction *I : Dropped)
      if (auto It = OpIndex.find(I); It != OpIndex.end() && !ThePlan.Ops[It->second].Selected)
        ThePlan.Ops[It->second].Reason = B;
  }
  ConstantInt *constant(Type *T, uint64_t X) {
    return ConstantInt::get(F.getContext(), APInt(T->getIntegerBitWidth(), X, false, true));
  }
  Value *rotate(IRBuilder<> &B, Value *V, unsigned N) {
    unsigned W = V->getType()->getIntegerBitWidth();
    if (W == 1) return V;
    N = 1 + N % (W - 1);
    return B.CreateOr(B.CreateShl(V, N), B.CreateLShr(V, W - N));
  }
  Pair bxor(IRBuilder<> &B, Pair X, Pair Y) {
    return {B.CreateXor(X.E, Y.E), B.CreateXor(X.R, Y.R)};
  }
  Pair band(IRBuilder<> &B, Pair X, Pair Y) {
    // Keep one product in the second coordinate: no temporary combines all
    // four terms into plaintext. Site-level pinning refreshes the pair later.
    Value *E = B.CreateXor(B.CreateXor(B.CreateAnd(X.E, Y.E), B.CreateAnd(X.E, Y.R)),
                          B.CreateAnd(X.R, Y.E));
    return {E, B.CreateAnd(X.R, Y.R)};
  }
  Pair bor(IRBuilder<> &B, Pair X, Pair Y) { return bxor(B, bxor(B, X, Y), band(B, X, Y)); }
  Pair bnot(IRBuilder<> &B, Pair X) { return {B.CreateNot(X.E), X.R}; }
  Pair shl(IRBuilder<> &B, Pair X, unsigned D) { return {B.CreateShl(X.E, D), B.CreateShl(X.R, D)}; }
  Pair lshr(IRBuilder<> &B, Pair X, unsigned D) { return {B.CreateLShr(X.E, D), B.CreateLShr(X.R, D)}; }
  Pair convert(IRBuilder<> &B, Pair X, Type *T, bool Sign = false) {
    return {B.CreateIntCast(X.E, T, Sign), B.CreateIntCast(X.R, T, Sign)};
  }
  Pair badd(IRBuilder<> &B, Pair X, Pair Y, bool CarryIn = false) {
    Pair P = bxor(B, X, Y), Original = P;
    unsigned W = X.E->getType()->getIntegerBitWidth();
    if (CarryIn) Original.E = B.CreateXor(Original.E, constant(X.E->getType(), 1));
    if (W == 1) return Original;
    Pair G = band(B, X, Y);
    if (CarryIn) G = bor(B, G, band(B, P, {constant(X.E->getType(), 1), constant(X.E->getType(), 0)}));
    for (unsigned D = 1; D < W; D *= 2) {
      G = bor(B, G, band(B, P, shl(B, G, D)));
      if (D * 2 < W) P = band(B, P, shl(B, P, D));
    }
    return bxor(B, Original, shl(B, G, 1));
  }
  Pair convertFamily(IRBuilder<> &B, Pair X, bool FromAffine, bool ToAffine) {
    if (FromAffine == ToAffine) return X;
    ++FamilyConversions;
    if (O.Plan)
      ThePlan.transfer(plan::originId(F.getName(), "conversion", 0), plan::TransferKind::Family,
                       representation(FromAffine), representation(ToAffine),
                       plan::Verification::Algebraic);
    Type *T = X.E->getType();
    if (ToAffine) {
      // e xor r = e + r - 2*(e & r), with the fresh coordinate added to the
      // FIRST partial sum. Adding it last, as v03 did, leaves e + r - 2*(e & r)
      // in a register, and that subexpression is exactly the decoded value.
      // Same function of the same operands; no intermediate is the plaintext.
      Value *R = constant(T, RNG.fork("conversion").fork(Site++).u64());
      Value *TwiceBoth = B.CreateMul(B.CreateAnd(X.E, X.R), constant(T, 2));
      Value *E = B.CreateSub(B.CreateAdd(B.CreateAdd(X.E, R), X.R), TwiceBoth);
      return {E, R};
    }
    // Treat each additive coordinate as a separately shared XOR value, then
    // subtract them with the verified carry network. Neither input share is
    // the decoded value e-r.
    Value *A = constant(T, RNG.fork("conversion-a").fork(Site++).u64());
    Value *R = constant(T, RNG.fork("conversion-r").fork(Site++).u64());
    Pair EShare{B.CreateXor(X.E, A), A};
    Pair RShare{B.CreateXor(X.R, R), R};
    return badd(B, EShare, bnot(B, RShare), true);
  }
  Pair less(IRBuilder<> &B, Pair X, Pair Y, bool Signed) {
    Pair P = bnot(B, bxor(B, X, Y)), G = band(B, bnot(B, X), Y);
    unsigned W = X.E->getType()->getIntegerBitWidth();
    for (unsigned D = 1; D < W; D *= 2) {
      G = bor(B, G, band(B, P, shl(B, G, D)));
      if (D * 2 < W) P = band(B, P, shl(B, P, D));
    }
    Pair L = convert(B, W == 1 ? G : lshr(B, G, W - 1), B.getInt1Ty());
    if (!Signed) return L;
    Pair SX = convert(B, W == 1 ? X : lshr(B, X, W - 1), B.getInt1Ty());
    Pair SY = convert(B, W == 1 ? Y : lshr(B, Y, W - 1), B.getInt1Ty());
    Pair D = bxor(B, SX, SY);
    return bor(B, band(B, D, SX), band(B, bnot(B, D), L));
  }
  Pair equality(IRBuilder<> &B, Pair X, Pair Y) {
    Pair Z = bxor(B, X, Y);
    for (unsigned D = 1; D < X.E->getType()->getIntegerBitWidth(); D *= 2)
      Z = bor(B, Z, lshr(B, Z, D));
    return bnot(B, convert(B, Z, B.getInt1Ty()));
  }
  // Pair-level linear combination on encoded lanes. The additive family is
  // linear coordinate-wise; the XOR family reuses the verified carry network.
  // Neither path ever forms the decoded scalar.
  Pair padd(IRBuilder<> &B, Pair X, Pair Y, bool Affine) {
    if (Affine) return {B.CreateAdd(X.E, Y.E), B.CreateAdd(X.R, Y.R)};
    return badd(B, X, Y);
  }
  Pair psub(IRBuilder<> &B, Pair X, Pair Y, bool Affine) {
    if (Affine) return {B.CreateSub(X.E, Y.E), B.CreateSub(X.R, Y.R)};
    return badd(B, X, bnot(B, Y), true);
  }
  // Doubling is a pair addition, never `shl 1`: a one-bit shift by one is
  // poison at width 1, and the carry network already covers that width.
  Pair pdouble(IRBuilder<> &B, Pair X, bool Affine) { return padd(B, X, X, Affine); }
  Pair pin(IRBuilder<> &B, Pair X, bool Affine, bool Joint = false) {
    Type *T = X.E->getType();
    Value *Refresh = B.CreateXor(rotate(B, X.E, 7), constant(T, RNG.fork(Site++).u64()));
    X = Affine ? Pair{B.CreateAdd(X.E, Refresh), B.CreateAdd(X.R, Refresh)}
               : Pair{B.CreateXor(X.E, Refresh), B.CreateXor(X.R, Refresh)};
    if (Witness) {
      Value *Residual = B.CreateZExtOrTrunc(nativeResidual(B, Context, Witness), T);
      X.E = Affine ? B.CreateAdd(X.E, Residual) : B.CreateXor(X.E, Residual);
    }
    IRBuilder<> Entry(getAllocaIP(F));
    auto *AT = ArrayType::get(T, 2);
    auto *Slot = Entry.CreateAlloca(AT, nullptr, Joint ? "sre.connected.joint" : "sre.connected.pair");
    Slot->setMetadata("sre.native.value", MDNode::get(F.getContext(), {}));
    if (Joint) Slot->setMetadata("sre.native.joint", MDNode::get(F.getContext(), {}));
    Value *EP = B.CreateInBoundsGEP(AT, Slot, {B.getInt32(0), B.getInt32(0)});
    Value *RP = B.CreateInBoundsGEP(AT, Slot, {B.getInt32(0), B.getInt32(1)});
    B.CreateStore(X.E, EP)->setVolatile(true); B.CreateStore(X.R, RP)->setVolatile(true);
    auto *E = B.CreateLoad(T, EP), *R = B.CreateLoad(T, RP);
    E->setVolatile(true); R->setVolatile(true);
    if (Context) {
      auto *H = B.CreateLoad(B.getInt32Ty(), Context); H->setVolatile(true);
      // Unlike v01's XOR-wide update, do not write E xor R (the plaintext)
      // into the activation context. This is still recoverable software state.
      Value *Next = B.CreateAdd(rotate(B, H, 5), B.CreateXor(B.CreateZExtOrTrunc(E, B.getInt32Ty()),
          rotate(B, B.CreateZExtOrTrunc(R, B.getInt32Ty()), 11)));
      auto *S = B.CreateStore(Next, Context); S->setVolatile(true);
      S->setMetadata("sre.native.context.update", MDNode::get(F.getContext(), MDString::get(F.getContext(), "data")));
      storeNativeWitness(B, Witness, Next);
    }
    return {E, R};
  }
  Pair input(IRBuilder<> &B, Value *V, unsigned RegionID) {
    if (auto *I = dyn_cast<Instruction>(V); I && RegionOf.count(I)) {
      unsigned Source = RegionOf.lookup(I);
      return convertFamily(B, emit(I), Regions[Source].Affine,
                           Regions[RegionID].Affine);
    }
    // A rebuilt encoded-call parameter is already a pair: consume its two
    // operands directly instead of freezing the plaintext into a fresh
    // boundary pair. The reconstruction itself is erased once nothing else
    // needs the plaintext.
    if (auto *I = dyn_cast<Instruction>(V); I && I->getMetadata("sre.native.call.arg")) {
      AbsorbedParameters.insert(I);
      return convertFamily(B, Pair{I->getOperand(0), I->getOperand(1)}, false,
                           Regions[RegionID].Affine);
    }
    ++Inputs;
    recordEntry(V, RegionID);
    Value *X = B.CreateFreeze(V);
    Value *R = B.CreateXor(rotate(B, X, 3), constant(V->getType(), RNG.fork(Site++).u64()));
    return {Regions[RegionID].Affine ? B.CreateAdd(X, R) : B.CreateXor(X, R), R};
  }
  bool candidate(const Instruction &I) {
    // Encoded-call plumbing already holds a pair, or hides one coordinate of
    // it. Encoding it would encode an encoding and would put the pair out of
    // reach of direct absorption. The join xor is deliberately not listed: its
    // result is the plaintext value the application itself consumes.
    for (StringRef Tag : {"sre.native.call.arg", "sre.native.call.split",
                          "sre.native.call.result", "sre.native.call.state"})
      if (I.getMetadata(Tag)) return false;
    if (auto *L = dyn_cast<LoadInst>(&I)) return MemoryLoads.count(const_cast<LoadInst *>(L));
    if (auto *C = dyn_cast<ICmpInst>(&I))
      return O.Predicates && width(C->getOperand(0)->getType(), true);
    if (!width(I.getType(), O.Predicates)) return false;
    if (isa<PHINode, SelectInst>(I)) return true;
    if (isa<TruncInst, ZExtInst, SExtInst>(I)) return width(I.getOperand(0)->getType(), O.Predicates);
    if (I.isShift()) {
      auto *C = dyn_cast<ConstantInt>(I.getOperand(1));
      return C && C->getValue().ult(I.getType()->getIntegerBitWidth());
    }
    return I.getOpcode() == Instruction::Add || I.getOpcode() == Instruction::Sub ||
      I.getOpcode() == Instruction::Mul || I.getOpcode() == Instruction::And ||
      I.getOpcode() == Instruction::Or || I.getOpcode() == Instruction::Xor;
  }
  void findObjects() {
    if (!O.Memory) return;
    // The bounded byte-copy normalization below is deliberately NOT extended
    // to aggregate layouts: LocalBytes() still matches only an i8 alloca or a
    // flat i8 array, so a memcpy that touches a struct or nested array is
    // rejected as "memory-intrinsic" rather than rewritten. A copy that one
    // of its i8 ends does get normalized may land on an aggregate; the leaf
    // walk then admits it only if every resulting byte access covers an i8
    // leaf exactly, and rejects it as a partial access otherwise.
    SmallVector<MemCpyInst *, 8> CopiesToNormalize;
    for (Instruction &I : instructions(F)) if (auto *C = dyn_cast<MemCpyInst>(&I)) {
      auto *Length = dyn_cast<ConstantInt>(C->getLength());
      auto LocalBytes = [](Value *P) {
        auto *A = dyn_cast<AllocaInst>(getUnderlyingObject(P));
        if (!A) return false;
        Type *T = A->getAllocatedType();
        if (auto *AT = dyn_cast<ArrayType>(T)) T = AT->getElementType();
        return T->isIntegerTy(8);
      };
      if (!C->isVolatile() && Length && Length->getValue().ule(64) &&
          (LocalBytes(C->getSource()) || LocalBytes(C->getDest())) && CopiesToNormalize.size() < 8)
        CopiesToNormalize.push_back(C);
    }
    for (auto *C : CopiesToNormalize) {
      IRBuilder<> B(C); SmallVector<Value *, 64> Bytes;
      unsigned N = cast<ConstantInt>(C->getLength())->getZExtValue();
      for (unsigned J = 0; J < N; ++J) {
        auto *L = B.CreateLoad(B.getInt8Ty(), B.CreateInBoundsGEP(B.getInt8Ty(), C->getSource(), B.getInt64(J)));
        L->setAlignment(Align(1)); Bytes.push_back(L);
      }
      for (unsigned J = 0; J < N; ++J)
        B.CreateStore(Bytes[J], B.CreateInBoundsGEP(B.getInt8Ty(), C->getDest(), B.getInt64(J)))->setAlignment(Align(1));
      C->eraseFromParent(); ++Copies;
    }
    unsigned ObjectID = 0;
    for (Instruction &I : F.getEntryBlock()) {
      auto *A = dyn_cast<AllocaInst>(&I);
      if (!A || A->getAddressSpace() != 0 || !isa<ConstantInt>(A->getArraySize()) ||
          !cast<ConstantInt>(A->getArraySize())->isOne()) continue;
      std::string ID = (F.getName() + "/alloca/" + Twine(ObjectID++)).str();
      Type *T = A->getAllocatedType(), *E = T;
      uint64_t N = 1;
      if (auto *AT = dyn_cast<ArrayType>(T)) { E = AT->getElementType(); N = AT->getNumElements(); }
      auto Skip = [&](StringRef Reason) {
        ObjectReport.push_back(json::Object{{"object", A->getName().str()}, {"origin", ID}, {"status", "skipped"}, {"reason", Reason.str()}});
        recordObject(A, ID, "", N, 0, width(E) ? E->getIntegerBitWidth() : 0, Reason);
      };
      bool Narrow = width(E) && N && N <= 64;
      if (!Narrow && !O.Aggregates) { Skip("unsupported-layout"); continue; }
      if (Objects.size() >= 8) { Skip("object-budget"); continue; }
      if (Narrow) {
        Object Obj{A, E, N, ID};
        Obj.Leaves = N;
        SmallVector<Value *, 16> Work{A}; SmallPtrSet<Value *, 32> Seen;
        bool Safe = true;
        for (unsigned J = 0; J < Work.size() && Safe; ++J) {
          Value *P = Work[J];
          if (!Seen.insert(P).second) continue;
          for (User *U : P->users()) {
            if (auto *G = dyn_cast<GetElementPtrInst>(U)) {
              if (!G->isInBounds() || (G->getSourceElementType() != T && G->getSourceElementType() != E) ||
                  (G->getResultElementType() != T && G->getResultElementType() != E)) { Safe = false; break; }
              Obj.GEPs.push_back(G); Work.push_back(G);
            } else if (auto *L = dyn_cast<LoadInst>(U); L && L->isSimple() && L->getType() == E) Obj.Loads.push_back(L);
            else if (auto *S = dyn_cast<StoreInst>(U); S && S->isSimple() && S->getPointerOperand() == P && S->getValueOperand()->getType() == E) Obj.Stores.push_back(S);
            else if (auto *II = dyn_cast<IntrinsicInst>(U); II && II->isLifetimeStartOrEnd()) Obj.Lifetimes.push_back(II);
            else { Safe = false; break; }
          }
        }
        if (Safe && !Obj.Loads.empty() && !Obj.Stores.empty()) {
          EligibleMemoryLeaves += Obj.Leaves;
          unsigned Slot = recordObject(A, ID, N > 1 ? "flat-array" : "scalar", N, Obj.Leaves,
                                       E->getIntegerBitWidth(), "");
          if (Slot != plan::Invalid) {
            ThePlan.Objects[Slot].Loads = Obj.Loads.size();
            ThePlan.Objects[Slot].Stores = Obj.Stores.size();
          }
          ObjectPlan.push_back(Slot);
          for (LoadInst *L : Obj.Loads) MemoryLoads[L] = Objects.size();
          Objects.push_back(std::move(Obj));
          continue;
        }
        // The narrow rule's uniform element type also permits a runtime
        // index. The leaf walk below does not, so it is a retry, not a
        // replacement: with the experiment off, this is the only answer.
        if (!O.Aggregates) { Skip("escape-or-unsupported-access"); continue; }
      }
      if (StringRef Reason = admitLeafObject(A, T, ID); !Reason.empty()) Skip(Reason);
    }
  }
  // Admit one object whose accesses are all constant-offset leaves. Returns an
  // empty reason on success, else exactly why the object was rejected.
  //
  // Precision comes first here. Every pointer derived from the alloca is
  // resolved to a constant byte offset; every load and store must cover one
  // enumerated leaf exactly, at that leaf's own type. Nothing else is
  // tolerated: a use this walk does not understand rejects the object rather
  // than being assumed harmless, because a wrong answer silently miscompiles.
  // Proving that no derived pointer escapes is also what proves nothing else
  // in the function can alias the object.
  StringRef admitLeafObject(AllocaInst *A, Type *T, const std::string &ID) {
    const DataLayout &DL = F.getParent()->getDataLayout();
    SmallVector<Leaf, 32> Leaves;
    if (!enumerateLeaves(T, 0, DL, Leaves, 0) || Leaves.empty()) return "leaf-layout-unsupported";
    // Disjointness is checked against the layout, not assumed from the type.
    DenseMap<uint64_t, unsigned> LeafAt;
    uint64_t End = 0;
    for (unsigned J = 0; J < Leaves.size(); ++J) {
      if (Leaves[J].Offset < End) return "overlapping-leaf";
      End = Leaves[J].Offset + DL.getTypeStoreSize(Leaves[J].Ty).getFixedValue();
      LeafAt[Leaves[J].Offset] = J;
    }
    uint64_t Size = DL.getTypeAllocSize(T).getFixedValue();
    auto leafAt = [&](uint64_t Offset, Type *Ty) -> int {
      auto It = LeafAt.find(Offset);
      return It == LeafAt.end() || Leaves[It->second].Ty != Ty ? -1 : int(It->second);
    };
    Object Obj{A, nullptr, Leaves.size(), ID};
    Obj.Aggregate = true; Obj.Leaves = Leaves.size();
    SmallVector<std::pair<Value *, uint64_t>, 16> Work{{A, 0}};
    SmallPtrSet<Value *, 32> Seen;
    SmallVector<bool, 64> Loaded(Leaves.size(), false), Stored(Leaves.size(), false);
    StringRef Reason;
    for (unsigned J = 0; J < Work.size() && Reason.empty(); ++J) {
      Value *P = Work[J].first;
      uint64_t Offset = Work[J].second;
      if (!Seen.insert(P).second) continue;
      for (User *U : P->users()) {
        if (auto *G = dyn_cast<GetElementPtrInst>(U)) {
          // Derive only ordinary scalar pointers from the base pointer, and
          // only as the base: anything else is not an offset we can mirror.
          if (G->getPointerOperand() != P || !G->getType()->isPointerTy()) {
            Reason = "address-escape-other"; break;
          }
          APInt Delta(DL.getIndexTypeSizeInBits(G->getType()), 0);
          if (!G->accumulateConstantOffset(DL, Delta)) { Reason = "dynamic-index"; break; }
          int64_t Next = int64_t(Offset) + Delta.getSExtValue();
          // A one-past-the-end pointer may be formed but never accessed.
          if (Next < 0 || uint64_t(Next) > Size) { Reason = "offset-out-of-range"; break; }
          Obj.GEPs.push_back(G); Work.push_back({G, uint64_t(Next)});
        } else if (auto *L = dyn_cast<LoadInst>(U)) {
          if (!L->isSimple()) { Reason = "unsupported-access"; break; }
          int K = leafAt(Offset, L->getType());
          if (K < 0) { Reason = "partial-leaf-access"; break; }
          Loaded[K] = true; Obj.Loads.push_back(L);
        } else if (auto *S = dyn_cast<StoreInst>(U)) {
          if (S->getPointerOperand() != P) { Reason = "address-escape-store"; break; }
          if (!S->isSimple()) { Reason = "unsupported-access"; break; }
          int K = leafAt(Offset, S->getValueOperand()->getType());
          if (K < 0) { Reason = "partial-leaf-access"; break; }
          Stored[K] = true; Obj.Stores.push_back(S);
        } else if (auto *II = dyn_cast<IntrinsicInst>(U); II && II->isLifetimeStartOrEnd()) {
          // A lifetime marker on a derived pointer would scope part of the
          // object independently; only a marker on the object is understood.
          if (P != A) { Reason = "unsupported-access"; break; }
          Obj.Lifetimes.push_back(II);
        } else if (isa<MemIntrinsic>(U)) { Reason = "memory-intrinsic"; break; }
        else if (isa<ICmpInst>(U)) { Reason = "pointer-compare"; break; }
        else if (isa<CallBase>(U)) { Reason = "address-escape-call"; break; }
        else { Reason = "address-escape-other"; break; }
      }
    }
    if (Reason.empty() && (Obj.Loads.empty() || Obj.Stores.empty())) Reason = "no-load-or-store";
    // Full coverage: a leaf that is read but never written through a tracked
    // store would read a share pair this pass never established.
    for (unsigned K = 0; Reason.empty() && K < Leaves.size(); ++K)
      if (Loaded[K] && !Stored[K]) Reason = "uncovered-leaf";
    if (!Reason.empty()) return Reason;
    EligibleMemoryLeaves += Obj.Leaves;
    ++EligibleAggregateObjects;
    unsigned Slot = recordObject(A, ID, "aggregate-leaves", Leaves.size(), Obj.Leaves, 0, "");
    if (Slot != plan::Invalid) {
      ThePlan.Objects[Slot].Loads = Obj.Loads.size();
      ThePlan.Objects[Slot].Stores = Obj.Stores.size();
    }
    ObjectPlan.push_back(Slot);
    for (LoadInst *L : Obj.Loads) MemoryLoads[L] = Objects.size();
    Objects.push_back(std::move(Obj));
    return "";
  }
  // The original operation and effect graph, recorded before any expansion.
  // Only original instructions are walked and only original operand edges are
  // added, so a generated instruction can neither enter a denominator nor
  // present itself as a new independent dependency.
  void recordOriginGraph(ArrayRef<Instruction *> Candidates) {
    ThePlan.Function = F.getName().str();
    ThePlan.Seed = RNG.baseSeed();
    ThePlan.SeedNamespace = seedNamespace();
    ThePlan.EligibleNodes = Candidates.size();
    for (unsigned K = 0; K < Candidates.size(); ++K) {
      Instruction *I = Candidates[K];
      OpIndex[I] = K;
      OpNodeInst.push_back(I);
      plan::OpNode N;
      N.Origin = plan::originId(F.getName(), "op", K);
      N.Kind = kindOf(I);
      N.LogicalWidth = I->getType()->isIntegerTy() ? I->getType()->getIntegerBitWidth() : 0;
      N.EstimatedCost = nodeCost(I);
      N.Score = nodeScore(I);
      if (auto *L = dyn_cast<LoadInst>(I); L && MemoryLoads.count(L)) {
        N.Effects |= plan::EffectReadsObject;
        N.Object = ObjectPlan[MemoryLoads.lookup(L)];
      }
      ThePlan.Ops.push_back(std::move(N));
    }
    for (unsigned K = 0; K < Candidates.size(); ++K)
      for (Value *V : Candidates[K]->operands())
        if (auto *Q = dyn_cast<Instruction>(V))
          if (auto It = OpIndex.find(Q); It != OpIndex.end()) ThePlan.Ops[K].Operands.push_back(It->second);
    // Effects visible only from the use side: a value stored into an object
    // this pass owns, and a value crossing a private call interface.
    for (unsigned J = 0; J < Objects.size(); ++J)
      for (StoreInst *S : Objects[J].Stores)
        if (auto *V = dyn_cast<Instruction>(S->getValueOperand()))
          if (auto It = OpIndex.find(V); It != OpIndex.end()) {
            ThePlan.Ops[It->second].Effects |= plan::EffectWritesObject;
            if (ThePlan.Ops[It->second].Object == plan::Invalid) ThePlan.Ops[It->second].Object = ObjectPlan[J];
          }
    for (unsigned K = 0; K < Candidates.size(); ++K) {
      for (Value *V : Candidates[K]->operands())
        if (auto *Q = dyn_cast<Instruction>(V); Q && Q->getMetadata("sre.native.call.arg"))
          ThePlan.Ops[K].Effects |= plan::EffectCallArgument;
      for (User *U : Candidates[K]->users())
        if (auto *X = dyn_cast<Instruction>(U);
            X && (X->getMetadata("sre.native.call.split") || X->getMetadata("sre.native.call.result")))
          ThePlan.Ops[K].Effects |= plan::EffectCallResult;
    }
  }
  // Close the original-graph half of the plan: control joins, the scalar-use
  // edges each selected operation still has, and the planner's own cost model.
  // Nothing structural is added after this point.
  void recordJoinsAndSeal() {
    DominatorTree Local;
    Local.recalculate(F);
    for (Instruction *I : Nodes) if (auto *Phi = dyn_cast<PHINode>(I)) {
      plan::LoopJoin J;
      J.Origin = plan::originId(F.getName(), "join", ThePlan.Joins.size());
      J.Node = OpIndex.lookup(Phi);
      J.Rep = ThePlan.Regions[RegionOf.lookup(Phi)].Rep;
      J.Incoming = Phi->getNumIncomingValues();
      for (BasicBlock *B : Phi->blocks())
        if (Local.dominates(Phi->getParent(), B)) J.Backedge = true;
      ThePlan.Joins.push_back(std::move(J));
    }
    // A store into an object this pass encodes is not a scalar use: the value
    // stays in its representation across it.
    SmallPtrSet<const Instruction *, 32> EncodedStores;
    for (const Object &Obj : Objects)
      if (RegionOf.count(Obj.Loads.front()))
        for (StoreInst *S : Obj.Stores) EncodedStores.insert(S);
    for (unsigned K = 0; K < ThePlan.Ops.size(); ++K) {
      if (!ThePlan.Ops[K].Selected) continue;
      unsigned Crossings = 0;
      for (const User *U : OpNodeInst[K]->users()) {
        if (const auto *X = dyn_cast<Instruction>(U)) {
          if (auto It = OpIndex.find(X); It != OpIndex.end() && ThePlan.Ops[It->second].Selected) continue;
          if (EncodedStores.contains(X)) continue;
        }
        ++Crossings;
      }
      ThePlan.Ops[K].ScalarUses = Crossings;
    }
    ThePlan.EligibleMemoryEdges = EligibleMemoryEdges;
    ThePlan.EligibleObjects = Objects.size();
    ThePlan.Cost.EligibleEstimated = EligibleCost;
    ThePlan.Cost.SelectedEstimated = SelectedCost;
    ThePlan.Cost.SkippedEstimated = SkippedCost;
    ThePlan.Cost.LostEstimated = ShardLostCost;
    ThePlan.Cost.ComponentLimit = CostLimit;
    ThePlan.Cost.ShardLimit = O.Shards ? ShardCostLimit : 0;
    ThePlan.Cost.ReservedStructural = StructuralReserve;
    ThePlan.Cost.ReserveDenied = ReserveDenied;
    ThePlan.Cost.ReserveDeniedCost = ReserveDeniedCost;
    ThePlan.Sealed = true;
    // One pass for the whole function, so a function with many exposures does
    // not pay a dependency walk per exposure.
    ThePlan.usefulWorkAll(UsefulWorkOf);
  }
  void plan() {
    findObjects();
    for (const Object &Obj : Objects) EligibleMemoryEdges += Obj.Loads.size() + Obj.Stores.size();
    SmallVector<Instruction *, 128> Candidates;
    DenseMap<Instruction *, unsigned> Index;
    for (Instruction &I : instructions(F)) if (candidate(I)) {
      Index[&I] = Candidates.size(); Candidates.push_back(&I);
    }
    EligibleNodes = Candidates.size();
    if (O.Plan) recordOriginGraph(Candidates);
    std::vector<unsigned> Parent(Candidates.size()); std::iota(Parent.begin(), Parent.end(), 0);
    auto Root = [&](unsigned I) { while (Parent[I] != I) { Parent[I] = Parent[Parent[I]]; I = Parent[I]; } return I; };
    auto Unite = [&](unsigned A, unsigned B) { A = Root(A); B = Root(B); if (A != B) Parent[B] = A; };
    for (Instruction *I : Candidates)
      for (Value *V : I->operands()) if (auto *P = dyn_cast<Instruction>(V); P && Index.count(P)) Unite(Index[I], Index[P]);
    for (const Object &Obj : Objects) {
      unsigned Anchor = Index[Obj.Loads.front()];
      for (LoadInst *L : Obj.Loads) Unite(Anchor, Index[L]);
      for (StoreInst *S : Obj.Stores)
        if (auto *V = dyn_cast<Instruction>(S->getValueOperand()); V && Index.count(V)) Unite(Anchor, Index[V]);
    }
    DenseMap<unsigned, unsigned> Groups;
    SmallVector<Region, 16> Planned;
    for (Instruction *I : Candidates) {
      unsigned Key = Root(Index[I]);
      if (!Groups.count(Key)) { Groups[Key] = Planned.size(); Planned.push_back(Region{}); }
      Region &R = Planned[Groups[Key]];
      R.Nodes.push_back(I);
      R.Cost += nodeCost(I);
      R.Score += nodeScore(I);
    }
    // Stable input order breaks equal scores; unrelated function order does
    // not change this function's stream. Whole-component selection avoids
    // cutting a memory object in half to meet the node cap; shards keep every
    // load of one encoded object inside a single shard for the same reason.
    llvm::stable_sort(Planned, [](const Region &A, const Region &B) {
      return uint64_t(A.Score) * B.Cost > uint64_t(B.Score) * A.Cost;
    });
    for (const Region &R : Planned) EligibleCost += R.Cost;
    unsigned Cost = 0;
    unsigned Component = 0;
    bool SawAffine = false, SawXor = false;
    // One selection step: split a node set into its representation families
    // and register the resulting regions. Selection order fixes Component, so
    // a build without shards keeps its exact previous family stream.
    auto select = [&](ArrayRef<Instruction *> Selected, unsigned Origin, unsigned Shard,
                      bool Sharded, unsigned PartCost, unsigned PartScore) {
      auto SupportsAffine = [](Instruction *I) {
        return llvm::is_contained(ArrayRef<unsigned>{Instruction::Add, Instruction::Sub,
            Instruction::Mul, Instruction::Shl, Instruction::PHI, Instruction::Load},
            I->getOpcode());
      };
      bool HasMul = llvm::any_of(Selected, [](Instruction *I) {
        return I->getOpcode() == Instruction::Mul;
      });
      bool HasRequiredXor = llvm::any_of(Selected, [&](Instruction *I) {
        return !SupportsAffine(I);
      });
      bool HasAffine = llvm::any_of(Selected, SupportsAffine);
      bool UseAffine = O.Families && HasAffine && (HasMul || HasRequiredXor ||
          ((Sharded ? RNG.fork("family-shard").fork(Component).fork(Shard)
                    : RNG.fork("family-partition").fork(Component)).u32() & 1));
      Region Affine, Xor;
      Affine.Affine = true; Xor.Affine = false;
      for (Instruction *I : Selected)
        (UseAffine && SupportsAffine(I) ? Affine : Xor).Nodes.push_back(I);
      for (Region *Part : {&Affine, &Xor}) {
        if (Part->Nodes.empty()) continue;
        if (Part->Affine) SawAffine = true; else SawXor = true;
        Part->ID = Regions.size(); Part->Component = Origin;
        Part->Shard = Shard; Part->Sharded = Sharded;
        for (Instruction *I : Part->Nodes) {
          Part->Cost += nodeCost(I); Part->Score += nodeScore(I);
          RegionOf[I] = Part->ID; Nodes.push_back(I);
        }
        if (O.Plan) {
          plan::RegionDescriptor D;
          D.Origin = plan::originId(F.getName(), "region", Part->ID);
          D.Component = Origin; D.Shard = Shard; D.Sharded = Sharded;
          D.Rep = representation(Part->Affine);
          D.Nodes = Part->Nodes.size();
          D.EstimatedCost = Part->Cost; D.Score = Part->Score;
          for (Instruction *I : Part->Nodes)
            if (auto It = OpIndex.find(I); It != OpIndex.end()) {
              ThePlan.Ops[It->second].Selected = true;
              ThePlan.Ops[It->second].Region = Part->ID;
            }
          ThePlan.Regions.push_back(std::move(D));
        }
        Regions.push_back(std::move(*Part));
      }
      SelectedCost += PartCost;
    };
    CostLimit = O.BoundedGrowth ? std::min(20000u, O.GrowthBudget) : 20000;
    // Shards divide the same component limit; they never raise it.
    ShardCostLimit = std::min(CostLimit, std::max(2048u, CostLimit / 4));
    // Hold back part of the component limit from components that own no
    // encoded storage, so a coherent structural unit is still affordable after
    // a cheap expression component. A zero reserve leaves Limit equal to
    // CostLimit for every component, which is exactly the previous selection.
    StructuralReserve = unsigned(uint64_t(CostLimit) * std::min(O.StructuralReserve, 50u) / 100);
    for (unsigned N = 0; N < Planned.size(); ++N) {
      Region &R = Planned[N];
      if (R.Nodes.size() < 2) {
        ++SkippedComponents; SkippedCost += R.Cost;
        markSkipped(R.Nodes, plan::Boundary::ComponentLimit);
        continue;
      }
      bool Owns = llvm::any_of(R.Nodes, [&](Instruction *I) {
        auto *L = dyn_cast<LoadInst>(I);
        return L && MemoryLoads.count(L);
      });
      unsigned Limit = Owns || StructuralReserve >= CostLimit ? CostLimit : CostLimit - StructuralReserve;
      SawAffine = SawXor = false;
      if (Nodes.size() + R.Nodes.size() <= O.Nodes && Cost + R.Cost > Limit && Cost + R.Cost <= CostLimit) {
        // Denied only by the structural reserve: it would have fit the
        // component limit. That is a selection loss with its own term, not an
        // oversized component, and it is never silently folded into one.
        ++SkippedComponents; SkippedCost += R.Cost;
        ++ReserveDenied; ReserveDeniedCost += R.Cost;
        markSkipped(R.Nodes, plan::Boundary::BudgetLoss);
        continue;
      }
      if (Nodes.size() + R.Nodes.size() <= O.Nodes && Cost + R.Cost <= Limit) {
        select(R.Nodes, N, 0, false, R.Cost, R.Score);
        Cost += R.Cost; ++Component;
        if (SawAffine && SawXor) ++MixedComponents;
        continue;
      }
      ++OversizedComponents;
      if (!O.Shards) {
        ++SkippedComponents; SkippedCost += R.Cost;
        markSkipped(R.Nodes, plan::Boundary::ComponentLimit);
        continue;
      }
      // Bounded shards in stable instruction order. A unit is one node, except
      // that all loads of one encoded object form a single atomic unit:
      // prepareMemory() redirects every store of an encoded object, so a load
      // left unselected would read an abandoned allocation. An aggregate
      // object is one object, so its leaf loads enlarge that atomic unit
      // rather than splitting it; a unit that cannot fit the remaining budget
      // is dropped whole and its object stays unencoded.
      struct Unit { SmallVector<Instruction *, 8> Nodes; unsigned Cost = 0, Score = 0; };
      SmallVector<Unit, 32> Units;
      DenseMap<unsigned, unsigned> ObjectUnit;
      for (Instruction *I : R.Nodes) {
        unsigned Slot = Units.size();
        if (auto *L = dyn_cast<LoadInst>(I); L && MemoryLoads.count(L))
          Slot = ObjectUnit.try_emplace(MemoryLoads.lookup(L), Slot).first->second;
        if (Slot == Units.size()) Units.push_back(Unit{});
        Units[Slot].Nodes.push_back(I);
        Units[Slot].Cost += nodeCost(I);
        Units[Slot].Score += nodeScore(I);
      }
      unsigned Shard = 0, ShardCost = 0, ShardScore = 0;
      SmallVector<Instruction *, 32> Current;
      // Seeded extent inside the fixed bound, so two seeded builds of one
      // program cut the same component at different points. The stream depends
      // on the component's planning index, never on pointer order.
      auto extent = [&](unsigned Index) {
        unsigned Half = ShardCostLimit / 2;
        return ShardCostLimit - Half + RNG.fork("shard-extent").fork(N).fork(Index).range(Half + 1);
      };
      unsigned Target = extent(0);
      auto flush = [&]() {
        // A single-node shard would encode a value and immediately decode it.
        if (Current.size() >= 2) {
          select(Current, N, Shard++, true, ShardCost, ShardScore);
          Cost += ShardCost; ++SelectedShards;
        } else {
          ShardLostNodes += Current.size(); ShardLostCost += ShardCost;
          markSkipped(Current, plan::Boundary::BudgetLoss);
        }
        Current.clear(); ShardCost = ShardScore = 0;
        Target = extent(Shard);
      };
      for (const Unit &U : Units) {
        if (U.Cost > ShardCostLimit) {
          // A memory unit is indivisible. It must not silently exceed the
          // reported shard ceiling after flushing a smaller prefix.
          ShardLostNodes += U.Nodes.size(); ShardLostCost += U.Cost;
          markSkipped(U.Nodes, plan::Boundary::BudgetLoss);
          continue;
        }
        if (Nodes.size() + Current.size() + U.Nodes.size() > O.Nodes ||
            Cost + ShardCost + U.Cost > Limit || ShardCost + U.Cost > Target) {
          flush();
          if (Nodes.size() + U.Nodes.size() > O.Nodes || Cost + U.Cost > Limit) {
            ShardLostNodes += U.Nodes.size(); ShardLostCost += U.Cost;
            markSkipped(U.Nodes, plan::Boundary::BudgetLoss);
            continue;
          }
        }
        Current.append(U.Nodes.begin(), U.Nodes.end());
        ShardCost += U.Cost; ShardScore += U.Score;
      }
      flush();
      if (Shard) {
        ++ShardedComponents; ++Component;
        if (SawAffine && SawXor) ++MixedComponents;
      } else ++SkippedComponents;
    }
    planJointOutputs();
    if (O.Plan) recordJoinsAndSeal();
  }
  // Bounded pairing of selected nodes into joint-output groups, decided on the
  // pre-emission IR in stable instruction order. Nothing here depends on
  // pointer or hash iteration order, and nothing runs when the flag is off.
  static constexpr unsigned JointLimit = 4, JointTestLimit = 4096;
  void planJointOutputs() {
    if (!O.JointOutputs || Nodes.empty()) return;
    DT.recalculate(F);
    SmallVector<Instruction *, 64> Members;
    for (Instruction &I : instructions(F)) if (RegionOf.count(&I)) Members.push_back(&I);
    struct Facts {
      SmallPtrSet<Instruction *, 32> Reach;
      SmallPtrSet<Value *, 16> Roots;
      bool Bounded = true, Eligible = false;
    };
    std::vector<Facts> Live(Members.size());
    for (unsigned K = 0; K < Members.size(); ++K) {
      Instruction *N = Members[K];
      // A PHI's lane pair is pre-created and filled after emission; rewriting
      // it would break that fill, so PHIs are never group members.
      if (isa<PHINode>(N)) { ++JointNodeSkips[JN_Phi]; continue; }
      if (N->use_empty()) { ++JointNodeSkips[JN_Unused]; continue; }
      Facts &A = Live[K];
      SmallVector<Instruction *, 32> Work{N};
      while (!Work.empty()) {
        Instruction *P = Work.pop_back_val();
        if (!A.Reach.insert(P).second) continue;
        if (A.Reach.size() + A.Roots.size() > 256) { A.Bounded = false; break; }
        for (Value *V : P->operands()) {
          if (isa<Constant>(V)) continue;
          if (auto *Q = dyn_cast<Instruction>(V); Q && RegionOf.count(Q)) { Work.push_back(Q); continue; }
          A.Roots.insert(rootKey(V));
        }
      }
      if (!A.Bounded) { ++JointNodeSkips[JN_WalkBound]; continue; }
      if (A.Roots.empty()) { ++JointNodeSkips[JN_NoRoots]; continue; }
      A.Eligible = true; ++JointCandidates;
    }
    auto has_private = [](const SmallPtrSetImpl<Value *> &A, const SmallPtrSetImpl<Value *> &B) {
      return llvm::any_of(A, [&](Value *V) { return !B.count(V); });
    };
    SmallVector<bool, 64> Paired(Members.size(), false);
    for (unsigned I = 0; I < Members.size(); ++I) {
      if (!Live[I].Eligible || Paired[I]) continue;
      if (JointGroups.size() >= JointLimit) { ++JointNodeSkips[JN_Budget]; continue; }
      bool Found = false, Budget = false;
      for (unsigned J = I + 1; J < Members.size() && !Found; ++J) {
        if (!Live[J].Eligible) continue;
        if (JointPairTests >= JointTestLimit) { Budget = true; break; }
        ++JointPairTests;
        if (Paired[J]) { ++JointPairSkips[JP_Paired]; continue; }
        Instruction *X = Members[I], *Y = Members[J];
        if (X->getType() != Y->getType()) { ++JointPairSkips[JP_Width]; continue; }
        if (Regions[RegionOf.lookup(X)].Affine != Regions[RegionOf.lookup(Y)].Affine) {
          ++JointPairSkips[JP_Family]; continue;
        }
        if (!DT.dominates(X, Y)) { ++JointPairSkips[JP_Dominance]; continue; }
        // Dataflow dependence in either direction disqualifies the pair: a
        // value coupled with something it already feeds, or that feeds it, is
        // not two distinct live dependencies.
        if (Live[J].Reach.count(X) || Live[I].Reach.count(Y)) { ++JointPairSkips[JP_Shared]; continue; }
        // Each member must depend on a normalized root the other does not.
        // Reloads of one object and casts of one value share a root, so a
        // copy can never present itself as a distinct dependency.
        if (!has_private(Live[I].Roots, Live[J].Roots) || !has_private(Live[J].Roots, Live[I].Roots)) {
          ++JointPairSkips[JP_Identical]; continue;
        }
        // The coupling governs only lane uses the unmix dominates. Require at
        // least one for the first member; every use of the second qualifies.
        if (llvm::none_of(X->uses(), [&](const Use &U) { return DT.dominates(Y, U); })) {
          ++JointPairSkips[JP_NoUse]; continue;
        }
        JointGroups.push_back({X, Y});
        Paired[I] = Paired[J] = true; Found = true;
      }
      if (!Found) ++JointNodeSkips[Budget ? JN_TestBudget : JN_NoPartner];
    }
    if (!O.Plan) return;
    for (unsigned K = 0; K < JointGroups.size(); ++K) {
      plan::Bundle B;
      B.Origin = plan::originId(F.getName(), "bundle", K);
      for (Instruction *M : {JointGroups[K].First, JointGroups[K].Second})
        if (auto It = OpIndex.find(M); It != OpIndex.end()) B.Members.push_back(It->second);
      B.Rep = ThePlan.Regions[RegionOf.lookup(JointGroups[K].First)].Rep;
      B.Status = "planned";
      ThePlan.Bundles.push_back(std::move(B));
    }
  }
  unsigned redirect(Value *Old, Value *New, Instruction *Anchor) {
    SmallVector<Use *, 16> Uses;
    for (Use &U : Old->uses()) Uses.push_back(&U);
    unsigned Count = 0;
    for (Use *U : Uses) if (DT.dominates(Anchor, *U)) { U->set(New); ++Count; }
    return Count;
  }
  // Replace both members' lanes with lanes recovered from the pinned joint
  // pairs. This runs after every other lane use exists, so each use is either
  // dominated by the unmix and redirected, or left on the original lanes and
  // counted as ungoverned.
  void coupleJointOutputs() {
    for (unsigned K = 0; K < JointGroups.size(); ++K) {
      const JointGroup &G = JointGroups[K];
      Pair X = Encoded.lookup(G.First), Y = Encoded.lookup(G.Second);
      if (!X.E || !Y.E) {
        if (O.Plan) ThePlan.Bundles[K].RejectReason = "no-encoded-pair";
        continue;
      }
      bool Affine = Regions[RegionOf.lookup(G.First)].Affine;
      IRBuilder<> B(G.Second);
      // U = X + Y and V = X + 2Y are the only quantities that cross the pinned
      // per-activation slots. The inverse X = 2U - V, Y = V - U is exact at
      // every width because the coupling matrix has determinant one; doubling
      // is a pair addition, so width 1 never sees a one-bit shift by one.
      Pair U = pin(B, padd(B, X, Y, Affine), Affine, true);
      Pair V = pin(B, padd(B, X, pdouble(B, Y, Affine), Affine), Affine, true);
      Pair RX = psub(B, pdouble(B, U, Affine), V, Affine);
      Pair RY = psub(B, V, U, Affine);
      // G.Second still sits after everything emitted above, so it is an exact
      // anchor for "the unmix dominates this use". Encoded is deliberately not
      // updated: its pairs are valid everywhere, these are not.
      unsigned Governed = redirect(X.E, RX.E, G.Second);
      Governed += redirect(X.R, RX.R, G.Second);
      Governed += redirect(Y.E, RY.E, G.Second);
      Governed += redirect(Y.R, RY.R, G.Second);
      JointRewrittenUses += Governed;
      if (O.Plan) {
        ThePlan.Bundles[K].Status = "coupled";
        ThePlan.Bundles[K].GovernedUses = Governed;
      }
      ++JointCoupled;
    }
  }
  void prepareMemory() {
    for (unsigned N = 0; N < Objects.size(); ++N) {
      Object &Obj = Objects[N];
      if (!RegionOf.count(Obj.Loads.front())) {
        ObjectReport.push_back(json::Object{{"object", Obj.A->getName().str()}, {"origin", Obj.ID}, {"status", "skipped"}, {"reason", "component-budget"}});
        // Proved closed but not encoded: ownership and the reason it went
        // unused are separate facts and both stay in the plan.
        if (O.Plan && ObjectPlan[N] != plan::Invalid) {
          ThePlan.Objects[ObjectPlan[N]].SkipReason = "component-budget";
          ThePlan.Objects[ObjectPlan[N]].Reason = plan::Boundary::ComponentLimit;
        }
        continue;
      }
      IRBuilder<> B(Obj.A);
      auto *E = B.CreateAlloca(Obj.A->getAllocatedType(), nullptr, "sre.connected.memory.e");
      auto *R = B.CreateAlloca(Obj.A->getAllocatedType(), nullptr, "sre.connected.memory.r");
      E->setAlignment(Obj.A->getAlign()); R->setAlignment(Obj.A->getAlign());
      E->setMetadata("sre.native.memory", MDNode::get(F.getContext(), {}));
      R->setMetadata("sre.native.memory", MDNode::get(F.getContext(), {}));
      Obj.EP[Obj.A] = E; Obj.RP[Obj.A] = R;
      for (auto *G : Obj.GEPs) {
        IRBuilder<> At(G); SmallVector<Value *, 4> Indices(G->indices());
        Obj.EP[G] = At.CreateGEP(G->getSourceElementType(), Obj.EP.lookup(G->getPointerOperand()), Indices);
        Obj.RP[G] = At.CreateGEP(G->getSourceElementType(), Obj.RP.lookup(G->getPointerOperand()), Indices);
      }
      for (auto *S : Obj.Stores) MemoryStores.insert(S);
      MemoryEdges += Obj.Loads.size() + Obj.Stores.size();
      if (O.Plan && ObjectPlan[N] != plan::Invalid) {
        plan::StorageMap Map;
        Map.Origin = Obj.ID;
        Map.Mapping = "parallel-lane-allocas";
        Map.Object = ObjectPlan[N];
        Map.Rep = ThePlan.Regions[RegionOf.lookup(Obj.Loads.front())].Rep;
        Map.LoadEdges = Obj.Loads.size();
        Map.StoreEdges = Obj.Stores.size();
        // Accesses whose address is computed at run time. A CPU eventually
        // requires an address; this says how often one is built here.
        for (auto *G : Obj.GEPs) if (!G->hasAllConstantIndices()) ++Map.AddressExposures;
        ThePlan.Objects[ObjectPlan[N]].Storage = ThePlan.Storage.size();
        ThePlan.Objects[ObjectPlan[N]].Region = RegionOf.lookup(Obj.Loads.front());
        ThePlan.Storage.push_back(std::move(Map));
      }
      if (Obj.Aggregate) {
        ++AggregateObjects;
        AggregateMemoryEdges += Obj.Loads.size() + Obj.Stores.size();
      }
      // An aggregate's leaves do not share one width, so the single-width
      // field is unknown for it, never zero.
      ObjectReport.push_back(json::Object{{"object", Obj.A->getName().str()}, {"status", "encoded"},
          {"origin", Obj.ID},
          {"layout", Obj.Aggregate ? "aggregate-leaves" : Obj.Elements > 1 ? "flat-array" : "scalar"},
          {"elements", Obj.Elements}, {"leaves", Obj.Leaves},
          {"width", Obj.Element ? json::Value(Obj.Element->getIntegerBitWidth()) : json::Value(nullptr)},
          {"loads", Obj.Loads.size()}, {"stores", Obj.Stores.size()}, {"implicit_load_decodes", 0}});
    }
  }
  Pair emit(Instruction *I) {
    if (auto It = Encoded.find(I); It != Encoded.end()) return It->second;
    unsigned ID = RegionOf.lookup(I); bool Affine = Regions[ID].Affine;
    if (O.Plan)
      ThePlan.transfer(ThePlan.Regions[ID].Origin,
                       isa<LoadInst>(I) ? plan::TransferKind::Storage : plan::TransferKind::Operation,
                       ThePlan.Regions[ID].Rep, ThePlan.Regions[ID].Rep, plan::Verification::Algebraic);
    IRBuilder<> B(I); Pair Out;
    if (auto *L = dyn_cast<LoadInst>(I)) {
      Object &Obj = Objects[MemoryLoads.lookup(L)];
      auto *E = B.CreateLoad(L->getType(), Obj.EP.lookup(L->getPointerOperand()));
      auto *R = B.CreateLoad(L->getType(), Obj.RP.lookup(L->getPointerOperand()));
      E->setAlignment(L->getAlign()); R->setAlignment(L->getAlign());
      E->setVolatile(true); R->setVolatile(true); Out = {E, R};
    } else if (auto *S = dyn_cast<SelectInst>(I)) {
      Pair C = input(B, S->getCondition(), ID), T = input(B, S->getTrueValue(), ID), N = input(B, S->getFalseValue(), ID);
      Out = bxor(B, N, band(B, convert(B, C, I->getType(), true), bxor(B, T, N)));
    } else if (auto *C = dyn_cast<ICmpInst>(I)) {
      ++Predicates;
      Pair X = input(B, I->getOperand(0), ID), Y = input(B, I->getOperand(1), ID);
      auto P = C->getPredicate();
      if (P == CmpInst::ICMP_EQ || P == CmpInst::ICMP_NE) {
        Out = equality(B, X, Y); if (P == CmpInst::ICMP_NE) Out = bnot(B, Out);
      } else {
        bool Swap = P == CmpInst::ICMP_UGT || P == CmpInst::ICMP_SGT || P == CmpInst::ICMP_ULE || P == CmpInst::ICMP_SLE;
        bool Invert = P == CmpInst::ICMP_UGE || P == CmpInst::ICMP_SGE || P == CmpInst::ICMP_ULE || P == CmpInst::ICMP_SLE;
        Out = less(B, Swap ? Y : X, Swap ? X : Y, C->isSigned());
        if (Invert) Out = bnot(B, Out);
      }
    } else {
      Pair X = input(B, I->getOperand(0), ID);
      if (isa<CastInst>(I)) Out = convert(B, X, I->getType(), isa<SExtInst>(I));
      else if (I->isShift()) {
        auto Op = static_cast<Instruction::BinaryOps>(I->getOpcode());
        Out = {B.CreateBinOp(Op, X.E, I->getOperand(1)), B.CreateBinOp(Op, X.R, I->getOperand(1))};
      } else {
        Pair Y = input(B, I->getOperand(1), ID);
        if (Affine) {
          if (I->getOpcode() == Instruction::Mul) {
            // The output mask joins the FIRST partial product. Adding it last
            // leaves ex*ey - cross + r*s in a register, which is exactly x*y.
            Value *Mask = B.CreateXor(X.R, Y.R);
            Value *Cross = B.CreateAdd(B.CreateMul(X.E, Y.R), B.CreateMul(Y.E, X.R));
            Out = {B.CreateAdd(B.CreateSub(B.CreateAdd(B.CreateMul(X.E, Y.E), Mask), Cross),
                               B.CreateMul(X.R, Y.R)), Mask};
          } else {
            auto Op = static_cast<Instruction::BinaryOps>(I->getOpcode());
            Out = {B.CreateBinOp(Op, X.E, Y.E), B.CreateBinOp(Op, X.R, Y.R)};
          }
        } else switch (I->getOpcode()) {
          case Instruction::Xor: Out = bxor(B, X, Y); break;
          case Instruction::And: Out = band(B, X, Y); break;
          case Instruction::Or: Out = bor(B, X, Y); break;
          case Instruction::Add: Out = badd(B, X, Y); break;
          case Instruction::Sub: Out = badd(B, X, bnot(B, Y), true); break;
          case Instruction::Mul: {
            ++MultiplyBridges;
            Value *V = B.CreateMul(B.CreateXor(X.E, X.R), B.CreateXor(Y.E, Y.R));
            Value *R = B.CreateAdd(X.R, Y.R); Out = {B.CreateXor(V, R), R}; break;
          }
          default: llvm_unreachable("unsupported connected node");
        }
      }
    }
    return Encoded[I] = pin(B, Out, Affine);
  }

public:
  // Absorption is published only once the caller keeps the transformed body:
  // a rolled-back function absorbed nothing.
  void publish(StringMap<NativeCallAbsorption> &Out) const {
    for (const auto &Entry : Absorbed) {
      auto &Total = Out[Entry.first()];
      Total.Arguments += Entry.second.Arguments;
      Total.PartialArguments += Entry.second.PartialArguments;
      Total.Results += Entry.second.Results;
    }
  }
  Encoder(Function &F, uint64_t Seed, NativeConnectedOptions O)
      : F(F), O(O), RNG(Rng(Seed).fork("native-connected-v1").fork(F.getName())) { plan(); }
  // Exact planning accounting: eligible = selected + skipped + shard loss.
  // Estimates are the planner's own cost model, not measured instructions.
  void accounting(json::Object &Item) {
    Item["eligible_nodes"] = EligibleNodes;
    Item["eligible_memory_edges"] = EligibleMemoryEdges;
    Item["eligible_memory_objects"] = Objects.size();
    // The aggregate experiment only ever adds objects to this denominator.
    Item["eligible_aggregate_memory_objects"] = EligibleAggregateObjects;
    Item["eligible_memory_leaves"] = EligibleMemoryLeaves;
    Item["memory_layout_policy"] = O.Aggregates ? "constant-index-aggregate-leaves"
                                                : "scalar-and-flat-array-only";
    Item["skipped_components"] = SkippedComponents;
    Item["oversized_components"] = OversizedComponents;
    Item["sharded_components"] = ShardedComponents;
    Item["shards"] = SelectedShards;
    Item["shard_lost_nodes"] = ShardLostNodes;
    Item["eligible_estimated_cost"] = EligibleCost;
    Item["selected_estimated_cost"] = SelectedCost;
    Item["skipped_estimated_cost"] = SkippedCost;
    Item["shard_lost_estimated_cost"] = ShardLostCost;
    Item["component_estimated_cost_limit"] = CostLimit;
    // The object walk's own ceilings, so a per-object cap is a number in the
    // report rather than an unknown a consumer has to guess.
    Item["object_leaf_limit"] = MaxLeaves;
    Item["object_leaf_depth_limit"] = MaxLeafDepth;
    Item["shard_estimated_cost_limit"] = O.Shards ? ShardCostLimit : 0;
    Item["shard_policy"] = O.Shards ? "instruction-order-units-with-atomic-memory-objects"
                                    : "whole-component-only";
    Item["normalized_copies"] = Copies;
    Item["reserved_structural_cost"] = StructuralReserve;
    Item["reserve_denied_components"] = ReserveDenied;
    Item["reserve_denied_estimated_cost"] = ReserveDeniedCost;
    // Joint-output accounting. Candidates are the selected nodes that could be
    // a group member at all; every rejection carries a fixed reason, and the
    // rewritten-use count is measured, not estimated.
    Item["joint_output_groups"] = JointCoupled;
    Item["joint_output_candidates"] = JointCandidates;
    Item["joint_lane_uses_rewritten"] = JointRewrittenUses;
    Item["joint_policy"] = O.JointOutputs ? "pairwise-unimodular-u-v-v1" : "disabled";
    Item["joint_dependency_test"] = O.JointOutputs
        ? "distinct-normalized-root-dependencies-both-ways-plus-no-dataflow-dependence" : "none";
    json::Object NodeSkips, PairSkips;
    for (unsigned K = 0; K < JN_Count; ++K) NodeSkips[JointNodeSkipName[K]] = JointNodeSkips[K];
    for (unsigned K = 0; K < JP_Count; ++K) PairSkips[JointPairSkipName[K]] = JointPairSkips[K];
    Item["joint_node_skips"] = std::move(NodeSkips);
    Item["joint_pair_skips"] = std::move(PairSkips);
  }
  // Measured totals, filled once emission is complete. The inventory is only
  // marked measured here, so a consumer never reads a partial count as a zero.
  void finalizePlan() {
    if (!O.Plan) return;
    ThePlan.Inventory.ProtectedOps = Nodes.size();
    ThePlan.Inventory.Exposures = ThePlan.Decodes.size();
    for (const plan::DecodeSite &D : ThePlan.Decodes) {
      ThePlan.Inventory.UsefulWorkTotal += D.UsefulWork;
      ThePlan.Inventory.UsefulWorkMax = std::max(ThePlan.Inventory.UsefulWorkMax, D.UsefulWork);
    }
    ThePlan.Inventory.Measured = true;
  }
  // Published by the caller, which alone knows the actual instruction counts
  // and whether the body it produced was kept.
  json::Value planJSON(unsigned Before, unsigned After, bool RolledBack) {
    ThePlan.Cost.InstructionsBefore = Before;
    ThePlan.Cost.InstructionsAfter = After;
    ThePlan.Cost.RolledBack = RolledBack;
    return ThePlan.toJSON();
  }
  json::Object run() {
    if (Nodes.empty()) {
      json::Object Item{{"function", F.getName().str()}, {"status", "skipped"},
          {"origin", plan::originId(F.getName(), "function", 0)},
          {"reason", O.Shards && OversizedComponents ? "no-shard-within-budget"
                                                     : "no-whole-component-within-budget"}};
      finalizePlan();
      accounting(Item);
      Item["objects"] = std::move(ObjectReport);
      return Item;
    }
    if (O.CoupleState) {
      IRBuilder<> B(getAllocaIP(F));
      Context = B.CreateAlloca(B.getInt32Ty(), nullptr, "sre.value.context");
      Context->setMetadata("sre.native.context", MDNode::get(F.getContext(), {}));
      Value *H = B.getInt32(RNG.fork("context").u32());
      if (O.LaneTransitions) {
        // Every later value of this word already comes from pinned lane
        // coordinates. Seed it from a live argument too, so the first
        // transition of an activation is not keyed on a build constant.
        // Freeze first: an undef argument must not make this poison.
        for (Argument &A : F.args())
          if (A.getType()->isIntegerTy()) {
            H = B.CreateXor(H, B.CreateZExtOrTrunc(B.CreateFreeze(&A), B.getInt32Ty()), "sre.lane.seed");
            break;
          }
      }
      B.CreateStore(H, Context)->setVolatile(true);
      if (O.Invariant) {
        Witness = B.CreateAlloca(B.getInt32Ty(), nullptr, "sre.value.witness");
        Witness->setMetadata("sre.native.witness", MDNode::get(F.getContext(), {}));
        storeNativeWitness(B, Witness, H);
      }
    }
    prepareMemory();
    for (Instruction *I : Nodes) {
      for (Value *V : I->operands()) if (auto *P = dyn_cast<Instruction>(V); P && RegionOf.count(P)) ++PersistentEdges;
      if (auto *P = dyn_cast<PHINode>(I)) {
        ++PhiPairs;
        Encoded[I] = {PHINode::Create(I->getType(), P->getNumIncomingValues(), "sre.connected.phi.e", I->getIterator()),
                      PHINode::Create(I->getType(), P->getNumIncomingValues(), "sre.connected.phi.r", I->getIterator())};
      }
    }
    for (Instruction *I : Nodes) emit(I);
    for (Instruction *I : Nodes) if (auto *P = dyn_cast<PHINode>(I)) {
      DenseMap<BasicBlock *, Pair> Incoming;
      for (unsigned N = 0; N < P->getNumIncomingValues(); ++N) {
        auto *Pred = P->getIncomingBlock(N); IRBuilder<> B(Pred->getTerminator());
        if (!Incoming.count(Pred)) Incoming[Pred] = input(B, P->getIncomingValue(N), RegionOf.lookup(I));
        if (O.Plan)
          ThePlan.transfer(ThePlan.Regions[RegionOf.lookup(I)].Origin, plan::TransferKind::Join,
                           ThePlan.Regions[RegionOf.lookup(I)].Rep,
                           ThePlan.Regions[RegionOf.lookup(I)].Rep, plan::Verification::Algebraic);
        cast<PHINode>(Encoded[I].E)->addIncoming(Incoming[Pred].E, Pred);
        cast<PHINode>(Encoded[I].R)->addIncoming(Incoming[Pred].R, Pred);
      }
    }
    for (Object &Obj : Objects) if (!Obj.EP.empty()) {
      unsigned ID = RegionOf.lookup(Obj.Loads.front());
      for (StoreInst *S : Obj.Stores) {
        IRBuilder<> B(S); Pair P = input(B, S->getValueOperand(), ID);
        auto *E = B.CreateStore(P.E, Obj.EP.lookup(S->getPointerOperand()));
        auto *R = B.CreateStore(P.R, Obj.RP.lookup(S->getPointerOperand()));
        E->setAlignment(S->getAlign()); R->setAlignment(S->getAlign()); E->setVolatile(true); R->setVolatile(true);
      }
    }
    // Supply an encoded pair straight to an encoded-call interface instead of
    // decoding it at the boundary. The split/result xor and the activation
    // mask it hides behind are used only by each other and by the call or the
    // returned struct, so replacing both coordinates leaves the interface
    // reading this region's own pair. Collect first: this erases users.
    SmallVector<Instruction *, 8> Supplied;
    SmallPtrSet<Instruction *, 8> Listed;
    for (Instruction *I : Nodes)
      for (User *U : I->users())
        if (auto *X = dyn_cast<Instruction>(U);
            X && X->getOpcode() == Instruction::Xor && X->getOperand(0) == I &&
            (X->getMetadata("sre.native.call.split") || X->getMetadata("sre.native.call.result")))
          if (Listed.insert(X).second) Supplied.push_back(X);
    for (Instruction *X : Supplied) {
      auto *I = cast<Instruction>(X->getOperand(0));
      auto *Mask = dyn_cast<Instruction>(X->getOperand(1));
      // The interface this pair belongs to: a result stays in its own callee,
      // a split names the callee of the site it feeds. Anything else is not
      // the structure NativeCall builds, and is left to decode.
      StringRef Owner = F.getName();
      if (X->getMetadata("sre.native.call.split")) {
        Owner = StringRef();
        for (User *Consumer : X->users())
          if (auto *C = dyn_cast<CallInst>(Consumer))
            if (Function *G = C->getCalledFunction()) Owner = G->getName();
      }
      // Both coordinates have to move together, so the mask must be the
      // private activation read this pair hides behind and nothing else: one
      // use here and one in the call or the returned struct.
      if (!Mask || Owner.empty() || RegionOf.count(Mask) || !Mask->hasNUses(2)) {
        // The pair could not be supplied to the interface, so the plaintext
        // reconstruction stays. That is a boundary, whatever the metadata says.
        recordBoundary(plan::Boundary::InterfaceMismatch, X);
        continue;
      }
      IRBuilder<> B(X);
      Pair P = convertFamily(B, Encoded.lookup(I), Regions[RegionOf.lookup(I)].Affine, false);
      X->replaceAllUsesWith(P.E);
      X->eraseFromParent();
      Mask->replaceAllUsesWith(P.R);
      // The activation read existed only to hide the coordinate this region
      // just supplied; a reconstruction with no users must not survive.
      SmallVector<Instruction *, 4> Dead{Mask};
      SmallPtrSet<Instruction *, 4> Gone;
      while (!Dead.empty()) {
        Instruction *D = Dead.pop_back_val();
        if (Gone.count(D) || !D->use_empty() || D->isTerminator() || RegionOf.count(D)) continue;
        for (Value *Op : D->operands())
          if (auto *Prior = dyn_cast<Instruction>(Op)) Dead.push_back(Prior);
        Gone.insert(D);
        D->eraseFromParent();
      }
      ++Absorbed[Owner].Results;
      if (O.Plan) {
        plan::CallContract &C = ThePlan.Calls[contractFor(Owner)];
        C.CarriesResult = true;
        ++C.SuppliedPairs;
        C.Status = "absorbed";
        ++ThePlan.Inventory.AbsorbedEdges;
        ThePlan.transfer(C.Origin, plan::TransferKind::Interface,
                         ThePlan.Regions[RegionOf.lookup(I)].Rep, C.Rep, plan::Verification::Algebraic);
      }
    }
    // Capture AFTER emitting memory GEPs: their new scalar index uses must
    // also receive an explicit address boundary before originals are erased.
    SmallVector<Use *, 64> Exits;
    for (Instruction *I : Nodes) for (Use &U : I->uses()) {
      auto *User = dyn_cast<Instruction>(U.getUser());
      if (User && !RegionOf.count(User) && !(isa<StoreInst>(User) && MemoryStores.contains(cast<StoreInst>(User)))) Exits.push_back(&U);
    }
    DenseMap<std::pair<Instruction *, Instruction *>, Value *> DecodedAt;
    DenseMap<std::pair<Instruction *, Instruction *>, unsigned> DecodeIndex;
    for (Use *U : Exits) {
      auto *I = cast<Instruction>(U->get()), *User = cast<Instruction>(U->getUser());
      Instruction *IP = User;
      if (auto *P = dyn_cast<PHINode>(User)) IP = P->getIncomingBlock(U->getOperandNo())->getTerminator();
      auto Key = std::make_pair(I, IP);
      // Every use edge is counted, whether or not it reuses a decode that
      // already exists: the scalar this consumer reads is a real crossing.
      plan::Boundary Crossing = O.Plan ? exitBoundary(User) : plan::Boundary::Count;
      if (O.Plan) recordBoundary(Crossing, I);
      if (auto Found = DecodedAt.find(Key); Found != DecodedAt.end()) {
        if (O.Plan) ++ThePlan.Decodes[DecodeIndex.lookup(Key)].Uses;
        U->set(Found->second); ++Outputs; continue;
      }
      if (O.Plan) {
        plan::DecodeSite D;
        D.Origin = ThePlan.Ops[OpIndex.lookup(I)].Origin;
        D.Consumer = isa<BranchInst>(User) ? "branch-choice"
            : isa<GetElementPtrInst>(User) ? "address"
            : isa<ReturnInst>(User) ? "return"
            : isa<CallBase>(User) ? "call"
            : isa<StoreInst>(User) ? "store"
            : isa<PHINode>(User) ? "phi" : "unsupported-consumer";
        D.Reason = Crossing;
        D.Uses = 1;
        D.UsefulWork = UsefulWorkOf[OpIndex.lookup(I)];
        DecodeIndex[Key] = ThePlan.Decodes.size();
        ThePlan.Decodes.push_back(std::move(D));
        ThePlan.transfer(ThePlan.Regions[RegionOf.lookup(I)].Origin, plan::TransferKind::Exit,
                         ThePlan.Regions[RegionOf.lookup(I)].Rep, plan::Invalid,
                         plan::Verification::Algebraic);
      }
      IRBuilder<> B(IP); Pair X = Encoded.lookup(I);
      Value *Plain = Regions[RegionOf.lookup(I)].Affine ? B.CreateSub(X.E, X.R, "sre.connected.output")
                                                      : B.CreateXor(X.E, X.R, "sre.connected.output");
      if (auto *Boundary = dyn_cast<Instruction>(Plain)) {
        Boundary->setMetadata("sre.native.boundary", MDNode::get(F.getContext(), MDString::get(F.getContext(),
            isa<BranchInst>(User) ? "branch-choice" : isa<GetElementPtrInst>(User) ? "address" : "unsupported-consumer")));
        if (isa<BranchInst>(User) && I->getType()->isIntegerTy(1) && !Regions[RegionOf.lookup(I)].Affine)
          Boundary->setMetadata("sre.native.predicate", MDNode::get(F.getContext(), {}));
      }
      U->set(Plain); ++Outputs;
      DecodedAt[Key] = Plain;
    }
    coupleJointOutputs();
    finalizePlan();
    json::Array RegionReport;
    // component is the original connected component's stable planning index;
    // shard identifies the bounded part of it that this region belongs to.
    for (const Region &R : Regions) RegionReport.push_back(json::Object{{"id", R.ID}, {"component", R.Component},
        {"origin", plan::originId(F.getName(), "region", R.ID)},
        {"shard", R.Shard}, {"sharded", R.Sharded}, {"nodes", R.Nodes.size()},
        {"estimated_cost", R.Cost}, {"representation", R.Affine ? "additive-pair-v1" : "xor-prefix-pair-v1"}});
    // Distinct integer widths this function actually encoded, ascending, read
    // before the node instructions are erased. Connected regions also encode
    // i1 branch predicates, so this set is not confined to the four scalar
    // widths the legacy planner supports.
    SmallVector<unsigned, 5> Widths;
    for (Instruction *I : Nodes) {
      unsigned W = I->getType()->getIntegerBitWidth();
      if (!llvm::is_contained(Widths, W)) Widths.push_back(W);
    }
    llvm::sort(Widths);
    json::Array WidthReport;
    for (unsigned W : Widths) WidthReport.push_back(W);
    for (StoreInst *S : MemoryStores) S->eraseFromParent();
    for (Instruction *I : Nodes) I->dropAllReferences();
    for (Instruction *I : Nodes) I->eraseFromParent();
    // Absorbed parameters are never region nodes, so they outlive the erase
    // above. One whose every consumer was absorbed is a plaintext parameter
    // kept alive for nothing.
    for (Instruction *I : AbsorbedParameters) {
      if (I->use_empty()) {
        ++Absorbed[F.getName()].Arguments;
        if (O.Plan) {
          plan::CallContract &C = ThePlan.Calls[contractFor(F.getName())];
          C.CarriesArguments = true;
          ++C.AbsorbedArguments;
          if (C.Status != "partial") C.Status = "absorbed";
          ++ThePlan.Inventory.AbsorbedEdges;
        }
        I->eraseFromParent();
      } else {
        // At least one encoded consumer used the pair, but an unsupported
        // consumer still needs the scalar reconstruction. Report it separately,
        // and count the surviving reconstruction as the boundary it is.
        ++Absorbed[F.getName()].PartialArguments;
        if (O.Plan) {
          plan::CallContract &C = ThePlan.Calls[contractFor(F.getName())];
          C.CarriesArguments = true;
          ++C.PartialArguments;
          C.Status = "partial";
        }
        recordBoundary(plan::Boundary::InterfaceMismatch, I);
      }
    }
    for (Object &Obj : Objects) if (!Obj.EP.empty()) {
      for (Instruction *I : Obj.Lifetimes) I->eraseFromParent();
      for (auto *G : llvm::reverse(Obj.GEPs)) if (G->use_empty()) G->eraseFromParent();
      if (Obj.A->use_empty()) Obj.A->eraseFromParent();
    }
    F.setMemoryEffects(MemoryEffects::unknown()); F.removeFnAttr(Attribute::Speculatable);
    json::Object Item{{"function", F.getName().str()}, {"status", "encoded"}, {"nodes", Nodes.size()},
        {"origin", plan::originId(F.getName(), "function", 0)},
        {"regions", std::move(RegionReport)}, {"widths", std::move(WidthReport)},
        {"phi_pairs", PhiPairs},
        {"persistent_edges", PersistentEdges}, {"memory_edges", MemoryEdges}, {"predicates", Predicates},
        {"aggregate_memory_objects", AggregateObjects}, {"aggregate_memory_edges", AggregateMemoryEdges},
        {"family_conversions", FamilyConversions}, {"mixed_family_components", MixedComponents},
        {"boundary_inputs", Inputs}, {"boundary_outputs", Outputs}, {"multiply_decode_bridges", MultiplyBridges},
        {"reachable_invariant", Witness != nullptr},
        {"lane_transitions", O.LaneTransitions},
        {"lane_word", Context != nullptr && O.LaneTransitions ? "sre.value.context" : ""}};
    accounting(Item);
    Item["objects"] = std::move(ObjectReport);
    return Item;
  }
};
}

json::Array encodeNativeConnected(Module &M, uint64_t Seed, const NativeConnectedOptions &O,
                                  StringMap<NativeCallAbsorption> *Absorbed) {
  json::Array Report;
  SmallVector<Function *, 64> Work;
  uint64_t Weight = 0;
  auto weight = [](const Function &F) { return std::clamp(F.getInstructionCount(), 32u, 4096u); };
  for (Function &F : M) {
    if (!F.hasFnAttribute("sre.native.original")) continue;
    if (!safe(F)) { Report.push_back(json::Object{{"function", F.getName().str()}, {"status", "skipped"}, {"reason", "structure-or-size"}}); continue; }
    Work.push_back(&F); Weight += weight(F);
  }
  // Allocate once, not first-come-first-served. Unused shares stay unused;
  // adding/reordering functions cannot change an existing site's RNG stream.
  for (Function *F : Work) {
    auto Local = O;
    if (O.BoundedGrowth) Local.GrowthBudget = uint64_t(O.GrowthBudget) * weight(*F) / Weight;
    unsigned Before = F->getInstructionCount();
    std::unique_ptr<FunctionSnapshot> Snapshot;
    if (O.BoundedGrowth) Snapshot = std::make_unique<FunctionSnapshot>(*F);
    Encoder Encode(*F, Seed, Local);
    auto Item = Encode.run();
    unsigned After = F->getInstructionCount();
    bool RolledBack = Snapshot && After > uint64_t(Before) + Local.GrowthBudget;
    if (RolledBack) {
      // Connected encoding creates only local instructions/allocas, no module
      // globals or callees. This body-only rollback is therefore complete.
      Snapshot->restore();
      json::Object Rolled{{"function", F->getName().str()}, {"status", "skipped"},
          {"reason", "connected-growth-rollback"}, {"attempted_instructions", After}};
      // Planning denominators describe eligibility, so they survive a rollback.
      for (StringRef Key : {"eligible_nodes", "eligible_memory_edges", "eligible_memory_objects",
                            "eligible_aggregate_memory_objects", "eligible_memory_leaves",
                            "memory_layout_policy", "origin",
                            "eligible_estimated_cost", "oversized_components",
                            "component_estimated_cost_limit", "shard_estimated_cost_limit",
                            "object_leaf_limit", "object_leaf_depth_limit",
                            "reserved_structural_cost", "reserve_denied_components",
                            "reserve_denied_estimated_cost",
                            "shard_policy", "joint_output_candidates", "joint_policy",
                            "joint_dependency_test", "joint_node_skips", "joint_pair_skips"})
        if (auto *Value = Item.get(Key)) Rolled[Key] = std::move(*Value);
      // Selection loss inside a rolled-back function is not rollback loss.
      // Keeping only the eligible total and the attempted selection would
      // charge this function's genuine skips and shard losses to the rollback.
      if (auto *Value = Item.get("skipped_estimated_cost"))
        Rolled["attempted_skipped_estimated_cost"] = std::move(*Value);
      if (auto *Value = Item.get("shard_lost_estimated_cost"))
        Rolled["attempted_shard_lost_estimated_cost"] = std::move(*Value);
      if (auto *Value = Item.get("joint_output_groups")) Rolled["attempted_joint_output_groups"] = std::move(*Value);
      if (auto *Value = Item.get("joint_lane_uses_rewritten"))
        Rolled["attempted_joint_lane_uses_rewritten"] = std::move(*Value);
      // Everything the encoder actually selected was undone: record it as
      // attempted, never as coverage.
      if (auto *Value = Item.get("nodes")) Rolled["attempted_nodes"] = std::move(*Value);
      if (auto *Value = Item.get("shards")) Rolled["attempted_shards"] = std::move(*Value);
      if (auto *Value = Item.get("selected_estimated_cost"))
        Rolled["attempted_estimated_cost"] = std::move(*Value);
      Item = std::move(Rolled);
    } else if (Absorbed)
      Encode.publish(*Absorbed);
    Snapshot.reset();
    Item["instructions_before"] = Before;
    Item["instructions_after"] = F->getInstructionCount();
    // The plan is published after the rollback decision, so its actual costs
    // describe the body that was kept, not the one that was undone.
    if (Local.Plan) Item["plan"] = Encode.planJSON(Before, F->getInstructionCount(), RolledBack);
    Item["bounded_growth"] = O.BoundedGrowth;
    if (O.BoundedGrowth) Item["growth_allocation"] = Local.GrowthBudget;
    Report.push_back(std::move(Item));
  }
  return Report;
}
}
