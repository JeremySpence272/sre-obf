#include "llvm/Transforms/Obfuscator/NativeBundle.h"
#include "llvm/Transforms/Obfuscator/NativeBundleMath.h"
#include "llvm/Transforms/Obfuscator/NativeCall.h"
#include "llvm/Transforms/Obfuscator/FunctionSnapshot.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/ValueHandle.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/KnownBits.h"
#include <algorithm>
#include <optional>

using namespace llvm;
namespace llvm::obf {
namespace {
using transfer::Family;
using transfer::Pair;
constexpr StringLiteral TagName = "sre.native.bundle";

bool owned(const Instruction &I) {
  for (StringRef Tag : {"sre.native.bundle", "sre.native.value", "sre.native.context", "sre.native.witness",
                        "sre.native.call.arg", "sre.native.call.split",
                        "sre.native.call.result", "sre.native.call.state"})
    if (I.getMetadata(Tag)) return true;
  return false;
}
std::string origin(const Instruction &I) {
  if (auto *MD = I.getMetadata("sre.native.input-origin"))
    if (MD->getNumOperands() == 1)
      if (auto *S = dyn_cast<MDString>(MD->getOperand(0))) return S->getString().str();
  return {};
}
bool safe(const Function &F) {
  if (F.isDeclaration() || F.isVarArg() || F.hasPersonalityFn() ||
      F.hasFnAttribute(Attribute::Naked) || F.getInstructionCount() > 12000) return false;
  for (const Instruction &I : instructions(F)) {
    if (I.isEHPad() || isa<InvokeInst, CallBrInst, IndirectBrInst>(I)) return false;
    if (auto *C = dyn_cast<CallBase>(&I)) {
      if (C->isInlineAsm() || C->hasFnAttr(Attribute::ReturnsTwice) || C->isMustTailCall()) return false;
      if (auto *II = dyn_cast<IntrinsicInst>(C))
        if (II->getIntrinsicID() == Intrinsic::stacksave ||
            II->getIntrinsicID() == Intrinsic::stackrestore) return false;
    }
  }
  return true;
}

// Pointer-free storage descriptor and access/operation inventory. Bindings
// retain the original CFG and operand edges; this is not a whole-CFG replay
// schedule. No byte reads, pointer escape or implicit zero initialization.
struct Access {
  std::optional<unsigned> Constant;
  bool Store = false, Initializer = false;
  unsigned Elements = 1;
  std::string Origin;
};
struct Step { unsigned Opcode; std::string Origin; };
struct Plan {
  unsigned ID = 0, Width = 0, Cells = 0, Cost = 0;
  Family Coordinates = Family::Xor;
  bool Phases = false;
  unsigned CallSupplies = 0;
  SmallVector<uint64_t, 4> Salts;
  SmallVector<unsigned, 4> Rotations, Physical;
  SmallVector<Access, 16> Accesses;
  SmallVector<Step, 32> Steps;
};
struct Binding {
  Function *F = nullptr;
  AllocaInst *Object = nullptr;
  Plan P;
  SmallVector<GetElementPtrInst *, 16> Pointers;
  SmallVector<Instruction *, 16> Memory;
  SmallVector<LifetimeIntrinsic *, 8> Lifetimes;
  LifetimeIntrinsic *LifetimeStart = nullptr;
  SmallVector<WeakTrackingVH, 16> Indices;
  SmallVector<StoreInst *, 4> Initializers;
  StoreInst *LastInitializer = nullptr;
  SmallVector<Instruction *, 32> Nodes;
  unsigned BoundaryValues = 0, BoundaryUses = 0, AddressUses = 0;
  unsigned ScalarInputs = 0;
  unsigned VectorOutputs = 0, VectorUses = 0, VectorLanes = 0;
  std::string Reason;
};

bool planLifetime(Binding &B, const DominatorTree &DT) {
  auto fail = [&](StringRef Reason) { B.Reason = Reason.str(); return false; };
  if (B.Lifetimes.empty()) return true;
  unsigned Starts = 0, Ends = 0;
  for (LifetimeIntrinsic *I : B.Lifetimes) {
    if (!DT.isReachableFromEntry(I->getParent())) return fail("unreachable-lifetime-marker");
    if (I->getIntrinsicID() == Intrinsic::lifetime_start) { ++Starts; B.LifetimeStart = I; }
    else ++Ends;
  }
  if (Starts != 1 || B.LifetimeStart->getParent() != &B.F->getEntryBlock())
    return fail("requires-single-entry-lifetime");
  if (Ends > 8) return fail("lifetime-end-limit");
  for (Instruction *I : B.Memory)
    if (!DT.dominates(B.LifetimeStart, I)) return fail("lifetime-start-does-not-dominate");
  SmallPtrSet<Instruction *, 32> Accesses(B.Memory.begin(), B.Memory.end());
  SmallPtrSet<Instruction *, 16> Markers(B.Lifetimes.begin(), B.Lifetimes.end());
  for (LifetimeIntrinsic *End : B.Lifetimes) {
    if (End == B.LifetimeStart) continue;
    if (!DT.dominates(B.LifetimeStart, End)) return fail("lifetime-start-does-not-dominate");
    // Check the suffix, then reachable successors (including a possible return
    // to this block). No memory access or second marker may follow an end on
    // ANY path. Mutually exclusive ends need not postdominate one another.
    auto check = [&](Instruction *First) {
      for (Instruction *I = First; I; I = I->getNextNode()) {
        if (Accesses.contains(I)) return fail("access-after-lifetime-end");
        if (Markers.contains(I)) return fail("repeated-lifetime-end");
      }
      return true;
    };
    if (!check(End->getNextNode())) return false;
    SmallVector<BasicBlock *, 16> Queue(successors(End->getParent()));
    SmallPtrSet<BasicBlock *, 32> Seen;
    for (unsigned K = 0; K < Queue.size(); ++K) {
      BasicBlock *BB = Queue[K];
      if (!Seen.insert(BB).second) continue;
      if (!check(&BB->front())) return false;
      llvm::append_range(Queue, successors(BB));
    }
  }
  return true;
}

bool planObject(Binding &B, const NativeBundleOptions &O, const DominatorTree &DT) {
  AllocaInst *A = B.Object;
  auto fail = [&](StringRef Reason) { B.Reason = Reason.str(); return false; };
  if (owned(*A)) return fail("existing-owner");
  auto *T = dyn_cast<ArrayType>(A->getAllocatedType());
  auto *Count = dyn_cast<ConstantInt>(A->getArraySize());
  if (A->getAddressSpace() || !Count || !Count->isOne() || !T ||
      T->getNumElements() < 2 || T->getNumElements() > O.ObjectMaxCells ||
      !T->getElementType()->isIntegerTy()) return fail("requires-small-flat-integer-array");
  B.P.Width = T->getElementType()->getIntegerBitWidth();
  B.P.Cells = T->getNumElements();
  if (!llvm::is_contained(ArrayRef<unsigned>{8, 16, 32, 64}, B.P.Width))
    return fail("unsupported-width");
  Type *E = T->getElementType();
  DenseMap<Value *, Value *> Index;
  Index[A] = ConstantInt::get(Type::getInt32Ty(A->getContext()), 0);
  // Root-relative GEPs only, including constant byte offsets emitted by O2.
  // A byte-addressed pointer is not permission for bytewise observation.
  for (User *U : A->users()) if (auto *G = dyn_cast<GetElementPtrInst>(U)) {
    if (!G->isInBounds() || G->getPointerOperand() != A)
      return fail("unsupported-pointer-layout");
    Value *V = nullptr;
    if (G->getSourceElementType() == T && G->getNumIndices() == 2) {
      auto *Zero = dyn_cast<ConstantInt>(G->getOperand(1));
      if (!Zero || !Zero->isZero()) return fail("unsupported-pointer-layout");
      V = G->getOperand(2);
    } else if (G->getSourceElementType() == E && G->getNumIndices() == 1) {
      V = G->getOperand(1);
    } else if (G->getSourceElementType()->isIntegerTy(8) && G->getNumIndices() == 1) {
      auto *Offset = dyn_cast<ConstantInt>(G->getOperand(1));
      unsigned Bytes = B.P.Width / 8;
      if (!Offset || Offset->isNegative() || Offset->getValue().uge(uint64_t(Bytes) * B.P.Cells) ||
          Offset->getZExtValue() % Bytes) return fail("unaligned-or-unbounded-byte-offset");
      V = ConstantInt::get(Type::getInt64Ty(A->getContext()), Offset->getZExtValue() / Bytes);
    } else return fail("unsupported-pointer-layout");
    if (!V->getType()->isIntegerTy()) return fail("unproved-index");
    KnownBits K = computeKnownBits(V, A->getModule()->getDataLayout(), nullptr, G, &DT);
    if (!K.isNonNegative() || !K.getMaxValue().ult(B.P.Cells)) return fail("unproved-index");
    Index[G] = V;
  }
  SmallVector<Value *, 16> PointerOrder{A};
  for (Instruction &I : instructions(*B.F))
    if (auto *G = dyn_cast<GetElementPtrInst>(&I); G && Index.contains(G)) {
      PointerOrder.push_back(G); B.Pointers.push_back(G);
    }
  for (Value *Pointer : PointerOrder) for (User *U : Pointer->users()) {
    if (auto *G = dyn_cast<GetElementPtrInst>(U)) {
      if (Pointer == A && Index.contains(G)) continue;
      return fail("derived-pointer");
    }
    if (auto *L = dyn_cast<LoadInst>(U)) {
      bool Exact = L->getType() == E;
      if (auto *V = dyn_cast<FixedVectorType>(L->getType())) {
        auto *Start = dyn_cast<ConstantInt>(Index.lookup(Pointer));
        Exact = V->getElementType() == E && Start &&
                V->getNumElements() >= 2 && V->getNumElements() <= B.P.Cells &&
                Start->getZExtValue() + V->getNumElements() <= B.P.Cells;
      }
      if (L->getPointerOperand() != Pointer || !Exact || !L->isSimple())
        return fail("partial-volatile-or-atomic-access");
    } else if (auto *S = dyn_cast<StoreInst>(U)) {
      if (S->getPointerOperand() != Pointer || S->getValueOperand()->getType() != E || !S->isSimple())
        return fail("partial-volatile-or-atomic-access");
    } else if (auto *I = dyn_cast<LifetimeIntrinsic>(U)) {
      if (Pointer != A || I->arg_size() != 1 || I->getArgOperand(0) != A || I->hasOperandBundles())
        return fail("requires-root-lifetime-marker");
    } else return fail("pointer-escape-or-observation");
  }
  // Deterministic order independent of pointer use lists / hash iteration.
  for (Instruction &I : instructions(*B.F)) {
    if (auto *L = dyn_cast<LifetimeIntrinsic>(&I); L && L->getArgOperand(0) == A)
      B.Lifetimes.push_back(L);
    Value *Ptr = nullptr;
    if (auto *L = dyn_cast<LoadInst>(&I)) Ptr = L->getPointerOperand();
    if (auto *S = dyn_cast<StoreInst>(&I)) Ptr = S->getPointerOperand();
    if (!Ptr || !Index.contains(Ptr)) continue;
    if (!DT.isReachableFromEntry(I.getParent())) return fail("unreachable-access");
    Access M;
    M.Store = isa<StoreInst>(I); M.Origin = origin(I);
    if (auto *V = dyn_cast<FixedVectorType>(I.getType())) {
      M.Elements = V->getNumElements();
      ++B.VectorOutputs; B.VectorUses += I.getNumUses(); B.VectorLanes += M.Elements;
    }
    Value *V = Index.lookup(Ptr);
    if (auto *C = dyn_cast<ConstantInt>(V)) M.Constant = C->getZExtValue();
    B.Indices.push_back(V); B.Memory.push_back(&I); B.P.Accesses.push_back(M);
    if (B.Memory.size() > 64) return fail("memory-access-limit");
  }
  if (!planLifetime(B, DT)) return false;
  B.Initializers.resize(B.P.Cells, nullptr);
  unsigned Initialized = 0;
  for (unsigned K = 0; K < B.Memory.size(); ++K) {
    auto &M = B.P.Accesses[K];
    auto *S = dyn_cast<StoreInst>(B.Memory[K]);
    if (Initialized < B.P.Cells) {
      if (!S || !M.Constant || S->getParent() != &B.F->getEntryBlock() || B.Initializers[*M.Constant])
        return fail("requires-complete-entry-initialization");
      B.Initializers[*M.Constant] = S; B.LastInitializer = S;
      M.Initializer = true; ++Initialized;
    } else if (!DT.dominates(B.LastInitializer, B.Memory[K])) {
      return fail("initialization-does-not-dominate");
    }
  }
  if (Initialized != B.P.Cells) return fail("requires-complete-entry-initialization");

  SmallPtrSet<Instruction *, 32> Forward, Useful;
  SmallVector<Instruction *, 32> Queue;
  for (Instruction *I : B.Memory) if (isa<LoadInst>(I) && I->getType() == E) {
    Forward.insert(I); Queue.push_back(I);
  }
  if (Queue.empty()) return fail("no-loads");
  for (unsigned K = 0; K < Queue.size(); ++K) for (User *U : Queue[K]->users()) {
    auto *I = dyn_cast<Instruction>(U);
    if (!I || owned(*I) || I->getType() != E || !bundle::operationSupported(*I)) continue;
    if (Forward.insert(I).second) Queue.push_back(I);
    if (Queue.size() > B.Memory.size() + O.Nodes) return fail("operation-limit");
  }
  Queue.clear();
  for (Instruction *I : B.Memory) if (auto *S = dyn_cast<StoreInst>(I)) {
    auto *V = dyn_cast<Instruction>(S->getValueOperand());
    if (V && Forward.contains(V) && Useful.insert(V).second) Queue.push_back(V);
  }
  for (unsigned K = 0; K < Queue.size(); ++K) for (Value *V : Queue[K]->operands()) {
    auto *I = dyn_cast<Instruction>(V);
    if (I && Forward.contains(I) && Useful.insert(I).second) Queue.push_back(I);
  }
  SmallPtrSet<Instruction *, 32> Members;
  for (Instruction &I : instructions(*B.F)) {
    if (isa<LoadInst>(I) && Forward.contains(&I)) Members.insert(&I);
    else if (Useful.contains(&I)) {
      Members.insert(&I); B.Nodes.push_back(&I);
      B.P.Steps.push_back({I.getOpcode(), origin(I)});
    }
  }
  if (B.Nodes.size() < 4) return fail("no-useful-encoded-update");
  SmallPtrSet<Value *, 32> Inputs;
  auto input = [&](Value *V) {
    if (!isa<Constant>(V) && !Members.contains(dyn_cast<Instruction>(V))) Inputs.insert(V);
  };
  for (Instruction *I : B.Nodes) for (Value *V : I->operands()) input(V);
  for (Instruction *I : B.Memory) if (auto *S = dyn_cast<StoreInst>(I)) input(S->getValueOperand());
  B.ScalarInputs = Inputs.size();
  for (Instruction *I : Members) {
    unsigned Uses = 0;
    for (Use &U : I->uses()) {
      auto *User = dyn_cast<Instruction>(U.getUser());
      if (Members.contains(User)) continue;
      if (auto *S = dyn_cast_or_null<StoreInst>(User);
          S && llvm::is_contained(B.Memory, S) && U.getOperandNo() == 0) continue;
      ++Uses;
      if (O.CallOutputs && User && isNativeBundleCallSupply(*User, I)) ++B.P.CallSupplies;
      if (isa_and_nonnull<GetElementPtrInst>(User)) ++B.AddressUses;
    }
    B.BoundaryValues += Uses != 0; B.BoundaryUses += Uses;
  }
  B.P.Phases = O.ObjectPhases;
  B.P.Cost = 512 + B.Nodes.size() * 1200 + B.Memory.size() * B.P.Cells * 192;
  B.P.Cost += B.P.CallSupplies * 384;
  if (B.P.Phases) B.P.Cost += 64 * B.Memory.size() * (B.P.Cells + 2);
  if (B.P.Cost > 65536) return fail("function-cost-limit");
  return true;
}

class Lowering {
  Binding &Bound;
  const Plan &P;
  IRBuilder<> B;
  AllocaInst *Storage;
  ArrayType *StorageType;
  bool Pin, CallInputs, CallOutputs;
  DenseMap<Value *, Pair> Pairs;
  SmallPtrSet<Instruction *, 32> Members;
  ConstantInt *c(uint64_t X) { return ConstantInt::get(B.getIntNTy(P.Width), X); }
  Value *pointer(Value *K) {
    return B.CreateInBoundsGEP(StorageType, Storage, {B.getInt32(0), K});
  }
  Value *pointer(unsigned K) {
    return pointer(B.getInt32(K));
  }
  Value *slot(unsigned K, Value *Phase) {
    if (!P.Phases) return pointer(P.Physical[K]);
    // Phase one rotates the seeded physical permutation by one. Each phase
    // is a bijection over exactly N slots, even when N is not a power of two.
    Value *Index = B.CreateSelect(B.CreateICmpNE(Phase, c(0)),
        B.getInt32(P.Physical[(K + 1) % P.Cells]), B.getInt32(P.Physical[K]));
    return pointer(Index);
  }
  Value *mask(ArrayRef<Value *> Z, Value *M, unsigned K) {
    return bundle::mask(B, Z, M, K, P.Salts[K], P.Rotations[K]);
  }
  SmallVector<Value *, 4> load(Value *&M, Value *&Phase) {
    SmallVector<Value *, 4> Z;
    Phase = c(0);
    if (P.Phases) {
      auto *L = B.CreateLoad(B.getIntNTy(P.Width), pointer(P.Cells + 1));
      L->setVolatile(Pin); Phase = L;
    }
    for (unsigned K = 0; K < P.Cells; ++K) {
      auto *L = B.CreateLoad(B.getIntNTy(P.Width), slot(K, Phase)); L->setVolatile(Pin); Z.push_back(L);
    }
    auto *L = B.CreateLoad(B.getIntNTy(P.Width), pointer(P.Cells)); L->setVolatile(Pin); M = L;
    return Z;
  }
  void store(ArrayRef<Value *> Z, Value *M, Value *Phase) {
    for (unsigned K = 0; K < P.Cells; ++K) B.CreateStore(Z[K], slot(K, Phase))->setVolatile(Pin);
    B.CreateStore(M, pointer(P.Cells))->setVolatile(Pin);
    if (P.Phases) B.CreateStore(Phase, pointer(P.Cells + 1))->setVolatile(Pin);
  }
  Value *matches(unsigned Access, unsigned K) {
    if (P.Accesses[Access].Constant) return B.getInt1(*P.Accesses[Access].Constant == K);
    Value *V = Bound.Indices[Access];
    // LLVM permits i1/i2 GEP indices. Do not truncate K into that type: e.g.
    // constant 2 would become i1 zero and alias logical slots zero and two.
    unsigned Width = V->getType()->getIntegerBitWidth();
    if (Width < 64 && K >= (uint64_t(1) << Width)) return B.getFalse();
    return B.CreateICmpEQ(V, ConstantInt::get(V->getType(), K));
  }
  Pair read(Value *V) {
    if (auto It = Pairs.find(V); It != Pairs.end()) return It->second;
    auto *I = dyn_cast<Instruction>(V);
    if (!I || !Members.contains(I)) return bundle::importPair(B, V, P.Coordinates, CallInputs);
    IRBuilderBase::InsertPointGuard Guard(B);
    B.SetInsertPoint(I);
    Pair X = read(I->getOperand(0)), Y = read(I->getOperand(1));
    auto Out = bundle::operation(B, I->getOpcode(), X, Y, P.Coordinates, B.CreateXor(X.E, Y.R));
    Pairs[I] = Out;
    return Out;
  }
public:
  Lowering(Binding &Bound, bool Pin, bool CallInputs, bool CallOutputs) : Bound(Bound), P(Bound.P),
      B(Bound.LastInitializer), Pin(Pin), CallInputs(CallInputs), CallOutputs(CallOutputs) {}
  void run() {
    Function &F = *Bound.F;
    SmallPtrSet<Instruction *, 32> Original;
    for (Instruction &I : instructions(F)) Original.insert(&I);
    MDNode *Tag = MDNode::get(F.getContext(), MDString::get(F.getContext(), "native-object-bundle-v1"));
    IRBuilder<> Entry(getAllocaIP(F));
    StorageType = ArrayType::get(B.getIntNTy(P.Width), P.Cells + 1 + unsigned(P.Phases));
    Storage = Entry.CreateAlloca(StorageType, nullptr, "sre.tile.tuple");
    // Retargeted lifetime argument attributes may promise the original
    // alignment. Preserve that promise on the larger private allocation.
    Storage->setAlignment(std::max(Storage->getAlign(), Bound.Object->getAlign()));
    Storage->setMetadata("sre.native.value", MDNode::get(F.getContext(), {}));
    // LLVM 22 lifetimes name the whole alloca, not a byte-size argument.
    // Retarget in place: no marker motion, deletion, or new intrinsic callee.
    for (LifetimeIntrinsic *I : Bound.Lifetimes) { I->setArgOperand(0, Storage); I->setMetadata(TagName, Tag); }
    SmallVector<Value *, 4> Initial, Z;
    for (StoreInst *S : Bound.Initializers) Initial.push_back(B.CreateFreeze(S->getValueOperand()));
    Value *M = B.CreateAdd(bundle::rotate(B, Initial[0], P.Rotations[0]), B.CreateXor(Initial[1], c(P.Salts[0])));
    for (unsigned K = 0; K < P.Cells; ++K)
      Z.push_back(transfer::remask(B, {Initial[K], c(0)}, P.Coordinates, mask(Z, M, K)));
    Value *Phase = c(0);
    store(Z, M, Phase);
    for (Instruction *I : Bound.Nodes) Members.insert(I);
    for (unsigned K = 0; K < Bound.Memory.size(); ++K) {
      auto *L = dyn_cast<LoadInst>(Bound.Memory[K]);
      if (!L) continue;
      B.SetInsertPoint(L);
      Z = load(M, Phase);
      if (auto *V = dyn_cast<FixedVectorType>(L->getType())) {
        Value *Out = PoisonValue::get(V);
        unsigned First = *P.Accesses[K].Constant;
        for (unsigned J = 0; J < V->getNumElements(); ++J) {
          Value *R = mask(Z, M, First + J);
          Value *X = P.Coordinates == Family::Xor ? B.CreateXor(Z[First + J], R)
                                                 : B.CreateSub(Z[First + J], R);
          if (auto *I = dyn_cast<Instruction>(X))
            I->setMetadata("sre.native.boundary", MDNode::get(F.getContext(), MDString::get(F.getContext(), "tile-vector-exit")));
          Out = B.CreateInsertElement(Out, X, J);
        }
        L->replaceAllUsesWith(Out);
        continue;
      }
      Members.insert(L);
      Pair Out{Z[0], mask(Z, M, 0)};
      for (unsigned J = 1; J < P.Cells; ++J) {
        Value *C = matches(K, J);
        Out = {B.CreateSelect(C, Z[J], Out.E), B.CreateSelect(C, mask(Z, M, J), Out.R)};
      }
      Pairs[L] = Out;
    }
    // SmallPtrSet iteration becomes address-dependent beyond its inline size.
    // Preserve function order for named boundary emission and destruction even
    // for objects with many loads and a small useful arithmetic region.
    SmallVector<Instruction *, 64> OrderedMembers;
    for (Instruction &I : instructions(F)) if (Members.contains(&I)) OrderedMembers.push_back(&I);
    for (Instruction *I : Bound.Nodes) { B.SetInsertPoint(I); read(I); }
    for (unsigned K = 0; K < Bound.Memory.size(); ++K) {
      auto *S = dyn_cast<StoreInst>(Bound.Memory[K]);
      if (!S || P.Accesses[K].Initializer) continue;
      B.SetInsertPoint(S);
      Pair V = read(S->getValueOperand());
      Z = load(M, Phase);
      Value *NextM = M, *NextPhase = Phase;
      if (P.Phases) {
        NextPhase = B.CreateXor(Phase, c(1));
        // The carrier depends on prior stored coordinates and the actual
        // encoded update. All old masks use the OLD tuple/carrier; every new
        // mask uses the completed prefix and NEW carrier. No scalar decode
        // or phase-reset mirror is emitted, including for untouched cells.
        Value *History = bundle::rotate(B, B.CreateXor(M, Z.back()), P.Rotations.back());
        Value *Update = B.CreateAdd(B.CreateXor(V.E, Z.front()), V.R);
        NextM = B.CreateXor(B.CreateAdd(History, Update),
            B.CreateMul(NextPhase, c(P.Salts[0] | 1)));
      }
      SmallVector<Value *, 4> Next;
      for (unsigned J = 0; J < P.Cells; ++J) {
        Value *C = matches(K, J);
        Pair Selected{B.CreateSelect(C, V.E, Z[J]), B.CreateSelect(C, V.R, mask(Z, M, J))};
        Next.push_back(transfer::remask(B, Selected, P.Coordinates, mask(Next, NextM, J)));
      }
      store(Next, NextM, NextPhase);
    }
    // Indices are also scalar boundaries: generated comparisons still refer
    // to their original SSA value and are rewritten here before it is erased.
    for (Instruction *I : OrderedMembers) {
      if (CallOutputs) supplyNativeBundleCalls(F, I, Pairs.lookup(I), P.Coordinates);
      auto external = [&](Use &U) {
        auto *User = dyn_cast<Instruction>(U.getUser());
        return !Members.contains(User) && !llvm::is_contained(Bound.Memory, User);
      };
      if (llvm::none_of(I->uses(), external)) continue;
      B.SetInsertPoint(I);
      Pair V = Pairs.lookup(I);
      Value *Scalar = P.Coordinates == Family::Xor ? B.CreateXor(V.E, V.R, "sre.tile.boundary")
                                                  : B.CreateSub(V.E, V.R, "sre.tile.boundary");
      if (auto *Boundary = dyn_cast<Instruction>(Scalar))
        Boundary->setMetadata("sre.native.boundary", MDNode::get(F.getContext(), MDString::get(F.getContext(), "tile-exit")));
      I->replaceUsesWithIf(Scalar, external);
    }
    for (Instruction *I : Bound.Memory)
      if (isa<StoreInst>(I) || I->getType()->isVectorTy()) I->eraseFromParent();
    for (Instruction *I : OrderedMembers) I->dropAllReferences();
    for (Instruction *I : OrderedMembers) I->eraseFromParent();
    for (GetElementPtrInst *G : Bound.Pointers) G->eraseFromParent();
    Bound.Object->eraseFromParent();
    for (Instruction &I : instructions(F)) if (!Original.contains(&I)) I.setMetadata(TagName, Tag);
  }
};

json::Object describe(const Binding &B) {
  const Plan &P = B.P;
  json::Array Physical, Salts, Rotations, Accesses, Steps;
  for (unsigned K : P.Physical) Physical.push_back(K);
  for (uint64_t K : P.Salts) Salts.push_back(utohexstr(K));
  for (unsigned K : P.Rotations) Rotations.push_back(K);
  unsigned Loads = 0, Stores = 0, Dynamic = 0;
  for (const Access &A : P.Accesses) {
    Loads += !A.Store; Stores += A.Store; Dynamic += !A.Constant;
    Accesses.push_back(json::Object{{"kind", A.Store ? "store" : "load"}, {"initializer", A.Initializer},
        {"index", A.Constant ? json::Value(*A.Constant) : json::Value(nullptr)},
        {"bounds", A.Constant ? "constant" : "known-bits-nonnegative-in-range"},
        {"elements", A.Elements}, {"input_origin", A.Origin}});
  }
  for (const Step &S : P.Steps) Steps.push_back(json::Object{
      {"opcode", Instruction::getOpcodeName(S.Opcode)}, {"input_origin", S.Origin}});
  return json::Object{{"width", P.Width}, {"cells", P.Cells},
      {"family", P.Coordinates == Family::Xor ? "triangular-xor-v1" : "triangular-additive-v1"},
      {"law", "closed-initialized-tile-v1"}, {"phase_mode", P.Phases ? "store-toggle-v1" : "static"},
      {"phase_contract", json::Object{{"states", P.Phases ? 2 : 1}, {"entry", 0},
          {"transition", P.Phases ? "toggle-after-update" : "identity"},
          {"carrier", P.Phases ? "history-and-encoded-update-v1" : "entry-only"},
          {"layout", P.Phases ? "rotate-logical-slots-by-phase" : "seeded-permutation"},
          {"static_update_sites", P.Phases ? Stores - P.Cells : 0},
          {"bytes_reencoded_per_update", P.Phases ? (P.Cells + 2) * P.Width / 8 : 0}}},
      {"ownership", "closed-entry-alloca"}, {"initialization", "complete-entry-stores-dominate-accesses"},
      {"physical_slots", std::move(Physical)}, {"salts_hex", std::move(Salts)}, {"rotations", std::move(Rotations)},
      {"source_loads", Loads}, {"source_stores", Stores}, {"dynamic_accesses", Dynamic},
      {"physical_loads", (Loads + Stores - P.Cells) * (P.Cells + 1 + unsigned(P.Phases))},
      {"physical_stores", (1 + Stores - P.Cells) * (P.Cells + 1 + unsigned(P.Phases))},
      {"scalar_input_values", B.ScalarInputs}, {"scalar_output_values", B.BoundaryValues},
      {"scalar_output_uses", B.BoundaryUses}, {"scalar_address_uses", B.AddressUses},
      {"call_supply_uses", P.CallSupplies}, {"call_supply_reservation", P.CallSupplies * 384},
      {"vector_output_values", B.VectorOutputs}, {"vector_output_uses", B.VectorUses},
      {"decoded_vector_lanes", B.VectorLanes},
      {"lifetime", json::Object{{"contract", "sre-tile-lifetime-v1"},
          {"mode", B.LifetimeStart ? "single-entry" : "whole-function"},
          {"source_starts", B.LifetimeStart ? 1 : 0},
          {"source_ends", B.Lifetimes.size() - (B.LifetimeStart ? 1 : 0)},
          {"translated_markers", B.Lifetimes.size()},
          {"proof", "start-dominates-accesses-no-access-or-marker-reachable-after-end"}}},
      {"accesses", std::move(Accesses)}, {"steps", std::move(Steps)}};
}
}

json::Array encodeNativeObjectBundles(Module &M, uint64_t Seed, const NativeBundleOptions &O) {
  SmallVector<Binding, 16> Work;
  for (Function &F : M) {
    if (!F.hasFnAttribute("sre.native.original") || F.isDeclaration()) continue;
    DominatorTree DT(F);
    bool Safe = safe(F);
    unsigned ID = 0;
    for (Instruction &I : F.getEntryBlock()) if (auto *A = dyn_cast<AllocaInst>(&I)) {
      Binding B; B.F = &F; B.Object = A; B.P.ID = ID++;
      if (!Safe) B.Reason = "function-structure-or-size";
      else planObject(B, O, DT);
      Work.push_back(std::move(B));
    }
  }
  // Coherent objects, not partial element rewrites. Select one per owner by
  // useful operation density; deterministic lexical ties, fixed module cap.
  SmallVector<unsigned, 16> Order;
  for (unsigned K = 0; K < Work.size(); ++K) if (Work[K].Reason.empty()) Order.push_back(K);
  llvm::stable_sort(Order, [&](unsigned A, unsigned B) {
    const Binding &X = Work[A], &Y = Work[B];
    uint64_t Left = X.Nodes.size() * uint64_t(Y.P.Cost), Right = Y.Nodes.size() * uint64_t(X.P.Cost);
    if (Left != Right) return Left > Right;
    if (X.F->getName() != Y.F->getName()) return X.F->getName() < Y.F->getName();
    return X.P.ID < Y.P.ID;
  });
  SmallPtrSet<Function *, 16> Owners;
  unsigned Remaining = O.GrowthBudget;
  for (unsigned K : Order) {
    Binding &B = Work[K];
    if (Owners.contains(B.F)) B.Reason = "one-object-per-function";
    else if (B.P.Cost > Remaining) B.Reason = "module-unit-budget";
    else { Owners.insert(B.F); Remaining -= B.P.Cost; }
  }
  json::Array Report;
  // Describe all rejected objects BEFORE mutation; later bindings may contain
  // values that an earlier selected object replaces or a rollback invalidates.
  for (Binding &B : Work) {
    json::Object Row{{"function", B.F->getName().str()}, {"object", B.P.ID},
        {"schema", "sre-object-bundle-v1"}, {"status", "skipped"}, {"reason", B.Reason},
        {"growth_allocation", B.Reason.empty() ? B.P.Cost : 0}, {"module_growth_limit", O.GrowthBudget},
        {"attempted_operations", 0}, {"retained_operations", 0}, {"rolled_back_operations", 0},
        {"pins", O.Pin}, {"max_cells", O.ObjectMaxCells}, {"hardness_evaluated", false}};
    if (B.Reason.empty()) {
      Rng R = Rng(Seed).fork("native-object-bundles-v1").fork(B.F->getName()).fork(B.P.ID);
      B.P.Coordinates = O.Family == "additive" || (O.Family == "seeded" && (R.u64() & 1))
                          ? Family::Additive : Family::Xor;
      for (unsigned K = 0; K < B.P.Cells; ++K) {
        B.P.Salts.push_back(R.u64()); B.P.Rotations.push_back(1 + R.range(B.P.Width - 1));
        B.P.Physical.push_back(K);
      }
      R.shuffle<unsigned>(B.P.Physical);
      Row["plan"] = describe(B);
    }
    Report.push_back(std::move(Row));
  }
  for (unsigned K = 0; K < Work.size(); ++K) {
    Binding &B = Work[K];
    if (!B.Reason.empty()) continue;
    auto &Row = *Report[K].getAsObject();
    unsigned Before = B.F->getInstructionCount();
    FunctionSnapshot Snapshot(*B.F);
    Lowering(B, O.Pin, O.CallInputs, O.CallOutputs).run();
    unsigned Attempted = B.F->getInstructionCount();
    if (verifyFunction(*B.F, &errs())) report_fatal_error("native object bundle produced invalid IR");
    bool Rollback = Attempted > uint64_t(Before) + B.P.Cost;
    if (Rollback) Snapshot.restore();
    Row["status"] = Rollback ? "rolled-back" : "encoded";
    Row["reason"] = Rollback ? "growth-budget" : "";
    Row["attempted_operations"] = B.P.Steps.size();
    Row["retained_operations"] = Rollback ? 0 : B.P.Steps.size();
    Row["rolled_back_operations"] = Rollback ? B.P.Steps.size() : 0;
    Row["instructions_before"] = Before; Row["attempted_instructions"] = Attempted;
    Row["instructions_after"] = B.F->getInstructionCount();
  }
  return Report;
}
}
