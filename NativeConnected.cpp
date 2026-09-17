#include "llvm/Transforms/Obfuscator/NativeConnected.h"
#include "llvm/Transforms/Obfuscator/NativeInvariant.h"
#include "llvm/Transforms/Obfuscator/NativeCall.h"
#include "llvm/Transforms/Obfuscator/FunctionSnapshot.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include <memory>
#include <numeric>

using namespace llvm;
namespace llvm::obf {
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
  Object(AllocaInst *A, Type *Element, uint64_t Elements, std::string ID)
      : A(A), Element(Element), Elements(Elements), ID(std::move(ID)) {}
};
struct Region {
  SmallVector<Instruction *, 32> Nodes;
  unsigned ID = 0, Component = 0, Shard = 0, Cost = 0, Score = 0;
  bool Affine = false, Sharded = false;
};
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
  unsigned EligibleMemoryEdges = 0;
  unsigned FamilyConversions = 0, MixedComponents = 0;
  unsigned OversizedComponents = 0, ShardedComponents = 0, SelectedShards = 0, ShardLostNodes = 0;
  unsigned EligibleCost = 0, SelectedCost = 0, SkippedCost = 0, ShardLostCost = 0;
  unsigned CostLimit = 0, ShardCostLimit = 0;
  json::Array ObjectReport;

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
    Type *T = X.E->getType();
    if (ToAffine) {
      // e xor r = e + r - 2*(e & r). Add a fresh second coordinate
      // without ever creating the decoded scalar as an SSA value.
      Value *R = constant(T, RNG.fork("conversion").fork(Site++).u64());
      Value *TwiceBoth = B.CreateMul(B.CreateAnd(X.E, X.R), constant(T, 2));
      Value *E = B.CreateAdd(B.CreateSub(B.CreateAdd(X.E, X.R), TwiceBoth), R);
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
  Pair pin(IRBuilder<> &B, Pair X, bool Affine) {
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
    auto *Slot = Entry.CreateAlloca(AT, nullptr, "sre.connected.pair");
    Slot->setMetadata("sre.native.value", MDNode::get(F.getContext(), {}));
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
      if (AbsorbedParameters.insert(I).second)
        ++Absorbed[F.getName()].Arguments;
      return convertFamily(B, Pair{I->getOperand(0), I->getOperand(1)}, false,
                           Regions[RegionID].Affine);
    }
    ++Inputs;
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
      };
      if (!width(E) || !N || N > 64) { Skip("unsupported-layout"); continue; }
      if (Objects.size() >= 8) { Skip("object-budget"); continue; }
      Object Obj{A, E, N, ID};
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
      if (!Safe || Obj.Loads.empty() || Obj.Stores.empty()) { Skip("escape-or-unsupported-access"); continue; }
      for (LoadInst *L : Obj.Loads) MemoryLoads[L] = Objects.size();
      Objects.push_back(std::move(Obj));
    }
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
        Part->Cost = PartCost * Part->Nodes.size() / Selected.size();
        Part->Score = PartScore * Part->Nodes.size() / Selected.size();
        for (Instruction *I : Part->Nodes) {
          RegionOf[I] = Part->ID; Nodes.push_back(I);
        }
        Regions.push_back(std::move(*Part));
      }
      SelectedCost += PartCost;
    };
    CostLimit = O.BoundedGrowth ? std::min(20000u, O.GrowthBudget) : 20000;
    // Shards divide the same component limit; they never raise it.
    ShardCostLimit = std::min(CostLimit, std::max(2048u, CostLimit / 4));
    for (unsigned N = 0; N < Planned.size(); ++N) {
      Region &R = Planned[N];
      if (R.Nodes.size() < 2) { ++SkippedComponents; SkippedCost += R.Cost; continue; }
      SawAffine = SawXor = false;
      if (Nodes.size() + R.Nodes.size() <= O.Nodes && Cost + R.Cost <= CostLimit) {
        select(R.Nodes, N, 0, false, R.Cost, R.Score);
        Cost += R.Cost; ++Component;
        if (SawAffine && SawXor) ++MixedComponents;
        continue;
      }
      ++OversizedComponents;
      if (!O.Shards) { ++SkippedComponents; SkippedCost += R.Cost; continue; }
      // Bounded shards in stable instruction order. A unit is one node, except
      // that all loads of one encoded object form a single atomic unit:
      // prepareMemory() redirects every store of an encoded object, so a load
      // left unselected would read an abandoned allocation.
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
        }
        Current.clear(); ShardCost = ShardScore = 0;
        Target = extent(Shard);
      };
      for (const Unit &U : Units) {
        if (Nodes.size() + Current.size() + U.Nodes.size() > O.Nodes ||
            Cost + ShardCost + U.Cost > CostLimit || ShardCost + U.Cost > Target) {
          flush();
          if (Nodes.size() + U.Nodes.size() > O.Nodes || Cost + U.Cost > CostLimit) {
            ShardLostNodes += U.Nodes.size(); ShardLostCost += U.Cost; continue;
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
  }
  void prepareMemory() {
    for (unsigned N = 0; N < Objects.size(); ++N) {
      Object &Obj = Objects[N];
      if (!RegionOf.count(Obj.Loads.front())) {
        ObjectReport.push_back(json::Object{{"object", Obj.A->getName().str()}, {"origin", Obj.ID}, {"status", "skipped"}, {"reason", "component-budget"}});
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
      ObjectReport.push_back(json::Object{{"object", Obj.A->getName().str()}, {"status", "encoded"},
          {"origin", Obj.ID},
          {"elements", Obj.Elements}, {"width", Obj.Element->getIntegerBitWidth()},
          {"loads", Obj.Loads.size()}, {"stores", Obj.Stores.size()}, {"implicit_load_decodes", 0}});
    }
  }
  Pair emit(Instruction *I) {
    if (auto It = Encoded.find(I); It != Encoded.end()) return It->second;
    unsigned ID = RegionOf.lookup(I); bool Affine = Regions[ID].Affine;
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
            Value *Mask = B.CreateXor(X.R, Y.R);
            Value *Cross = B.CreateAdd(B.CreateMul(X.E, Y.R), B.CreateMul(Y.E, X.R));
            Out = {B.CreateAdd(B.CreateAdd(B.CreateSub(B.CreateMul(X.E, Y.E), Cross), B.CreateMul(X.R, Y.R)), Mask), Mask};
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
    Item["shard_estimated_cost_limit"] = O.Shards ? ShardCostLimit : 0;
    Item["shard_policy"] = O.Shards ? "instruction-order-units-with-atomic-memory-objects"
                                    : "whole-component-only";
    Item["normalized_copies"] = Copies;
  }
  json::Object run() {
    if (Nodes.empty()) {
      json::Object Item{{"function", F.getName().str()}, {"status", "skipped"},
          {"reason", O.Shards && OversizedComponents ? "no-shard-within-budget"
                                                     : "no-whole-component-within-budget"}};
      accounting(Item);
      Item["objects"] = std::move(ObjectReport);
      return Item;
    }
    if (O.CoupleState) {
      IRBuilder<> B(getAllocaIP(F));
      Context = B.CreateAlloca(B.getInt32Ty(), nullptr, "sre.value.context");
      Context->setMetadata("sre.native.context", MDNode::get(F.getContext(), {}));
      Value *H = B.getInt32(RNG.fork("context").u32()); B.CreateStore(H, Context)->setVolatile(true);
      if (O.Invariant) {
        Witness = B.CreateAlloca(B.getInt32Ty(), nullptr, "sre.value.witness");
        Witness->setMetadata("sre.native.witness", MDNode::get(F.getContext(), {}));
        storeNativeWitness(B, Witness, H);
      }
    }
    prepareMemory();
    for (Instruction *I : Nodes) {
      for (Value *V : I->operands()) if (auto *P = dyn_cast<Instruction>(V); P && RegionOf.count(P)) ++PersistentEdges;
      if (auto *P = dyn_cast<PHINode>(I))
        Encoded[I] = {PHINode::Create(I->getType(), P->getNumIncomingValues(), "sre.connected.phi.e", I->getIterator()),
                      PHINode::Create(I->getType(), P->getNumIncomingValues(), "sre.connected.phi.r", I->getIterator())};
    }
    for (Instruction *I : Nodes) emit(I);
    for (Instruction *I : Nodes) if (auto *P = dyn_cast<PHINode>(I)) {
      DenseMap<BasicBlock *, Pair> Incoming;
      for (unsigned N = 0; N < P->getNumIncomingValues(); ++N) {
        auto *Pred = P->getIncomingBlock(N); IRBuilder<> B(Pred->getTerminator());
        if (!Incoming.count(Pred)) Incoming[Pred] = input(B, P->getIncomingValue(N), RegionOf.lookup(I));
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
      if (!Mask || Owner.empty() || RegionOf.count(Mask) || !Mask->hasNUses(2)) continue;
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
    }
    // Capture AFTER emitting memory GEPs: their new scalar index uses must
    // also receive an explicit address boundary before originals are erased.
    SmallVector<Use *, 64> Exits;
    for (Instruction *I : Nodes) for (Use &U : I->uses()) {
      auto *User = dyn_cast<Instruction>(U.getUser());
      if (User && !RegionOf.count(User) && !(isa<StoreInst>(User) && MemoryStores.contains(cast<StoreInst>(User)))) Exits.push_back(&U);
    }
    DenseMap<std::pair<Instruction *, Instruction *>, Value *> DecodedAt;
    for (Use *U : Exits) {
      auto *I = cast<Instruction>(U->get()), *User = cast<Instruction>(U->getUser());
      Instruction *IP = User;
      if (auto *P = dyn_cast<PHINode>(User)) IP = P->getIncomingBlock(U->getOperandNo())->getTerminator();
      auto Key = std::make_pair(I, IP);
      if (auto Found = DecodedAt.find(Key); Found != DecodedAt.end()) {
        U->set(Found->second); ++Outputs; continue;
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
    json::Array RegionReport;
    // component is the original connected component's stable planning index;
    // shard identifies the bounded part of it that this region belongs to.
    for (const Region &R : Regions) RegionReport.push_back(json::Object{{"id", R.ID}, {"component", R.Component},
        {"shard", R.Shard}, {"sharded", R.Sharded}, {"nodes", R.Nodes.size()},
        {"estimated_cost", R.Cost}, {"representation", R.Affine ? "additive-pair-v1" : "xor-prefix-pair-v1"}});
    for (StoreInst *S : MemoryStores) S->eraseFromParent();
    for (Instruction *I : Nodes) I->dropAllReferences();
    for (Instruction *I : Nodes) I->eraseFromParent();
    // Absorbed parameters are never region nodes, so they outlive the erase
    // above. One whose every consumer was absorbed is a plaintext parameter
    // kept alive for nothing.
    for (Instruction *I : AbsorbedParameters) if (I->use_empty()) I->eraseFromParent();
    for (Object &Obj : Objects) if (!Obj.EP.empty()) {
      for (Instruction *I : Obj.Lifetimes) I->eraseFromParent();
      for (auto *G : llvm::reverse(Obj.GEPs)) if (G->use_empty()) G->eraseFromParent();
      if (Obj.A->use_empty()) Obj.A->eraseFromParent();
    }
    F.setMemoryEffects(MemoryEffects::unknown()); F.removeFnAttr(Attribute::Speculatable);
    json::Object Item{{"function", F.getName().str()}, {"status", "encoded"}, {"nodes", Nodes.size()},
        {"regions", std::move(RegionReport)},
        {"persistent_edges", PersistentEdges}, {"memory_edges", MemoryEdges}, {"predicates", Predicates},
        {"family_conversions", FamilyConversions}, {"mixed_family_components", MixedComponents},
        {"boundary_inputs", Inputs}, {"boundary_outputs", Outputs}, {"multiply_decode_bridges", MultiplyBridges},
        {"reachable_invariant", Witness != nullptr}};
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
    if (Snapshot && After > uint64_t(Before) + Local.GrowthBudget) {
      // Connected encoding creates only local instructions/allocas, no module
      // globals or callees. This body-only rollback is therefore complete.
      Snapshot->restore();
      json::Object Rolled{{"function", F->getName().str()}, {"status", "skipped"},
          {"reason", "connected-growth-rollback"}, {"attempted_instructions", After}};
      // Planning denominators describe eligibility, so they survive a rollback.
      for (StringRef Key : {"eligible_nodes", "eligible_memory_edges", "eligible_memory_objects",
                            "eligible_estimated_cost", "oversized_components",
                            "component_estimated_cost_limit", "shard_estimated_cost_limit",
                            "shard_policy"})
        if (auto *Value = Item.get(Key)) Rolled[Key] = std::move(*Value);
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
    Item["bounded_growth"] = O.BoundedGrowth;
    if (O.BoundedGrowth) Item["growth_allocation"] = Local.GrowthBudget;
    Report.push_back(std::move(Item));
  }
  return Report;
}
}
