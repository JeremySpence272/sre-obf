#include "llvm/Transforms/Obfuscator/NativeBundle.h"
#include "llvm/Transforms/Obfuscator/NativeBundleMath.h"
#include "llvm/Transforms/Obfuscator/NativeBundleControl.h"
#include "llvm/Transforms/Obfuscator/NativeCall.h"
#include "llvm/Transforms/Obfuscator/NativeTransfer.h"
#include "llvm/Transforms/Obfuscator/FunctionSnapshot.h"
#include "llvm/Transforms/Obfuscator/NativePlan.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/ValueHandle.h"
#include "llvm/IR/Verifier.h"
#include <algorithm>

using namespace llvm;
namespace llvm::obf {
namespace {
constexpr StringLiteral OriginTag = "sre.native.input-origin";
constexpr StringLiteral BundleTag = "sre.native.bundle";
constexpr unsigned MinNodes = 8, MaxRegions = 8;
using transfer::Family;
using transfer::Pair;

std::string origin(const Instruction &I) {
  if (auto *MD = I.getMetadata(OriginTag))
    if (MD->getNumOperands() == 1)
      if (auto *S = dyn_cast<MDString>(MD->getOperand(0))) return S->getString().str();
  return {}; // Never silently relabel generated code as a frontend operation.
}
bool supported(const Instruction &I) {
  if (!bundle::operationSupported(I) || I.getMetadata(BundleTag)) return false;
  // Do not steal encoded-call coordinates from their current owner.
  for (StringRef Tag : {"sre.native.call.arg", "sre.native.call.split",
                        "sre.native.call.result", "sre.native.call.state"})
    if (I.getMetadata(Tag)) return false;
  return true;
}

// The executable plan is a bounded register schedule, not an observation of an
// already-expanded graph. Operands and slots are decided and validated before
// any instruction is inserted. LLVM pointers live only in the separate binding.
struct Operand {
  bool Constant = false;
  uint64_t Bits = 0;
  unsigned Slot = 0;
};
struct Step {
  unsigned Opcode = 0, Destination = 0;
  Operand X, Y;
  std::string Origin;
};
struct Backedge {
  unsigned Block = 0;
  SmallVector<unsigned, 4> Slots;
};
struct PredicateTarget {
  unsigned Output = 0;
  uint64_t Bits = 0;
  std::string Origin;
};
struct PredicatePlan {
  bool AnyDifferent = false;
  std::string Origin;
  SmallVector<PredicateTarget, 4> Targets;
};
struct Program {
  unsigned ID = 0, Width = 0, Lanes = 0, EstimatedCost = 0;
  plan::Representation Rep;
  SmallVector<Step, 32> Steps;
  SmallVector<unsigned, 4> OutputSlots;
  SmallVector<uint64_t, 4> Salts;
  SmallVector<unsigned, 4> Rotations;
  // Each edge maps completed output slots to canonical header input slots.
  SmallVector<Backedge, 4> Backedges;
  SmallVector<unsigned, 4> ScalarInputs;
  bool Phases = false;
  unsigned CallSupplies = 0;
  SmallVector<PredicatePlan, 4> Predicates;
  std::optional<json::Object> Selection;
  Family coordinates() const {
    switch (Rep.Fam) {
    case plan::Family::TriangularXor: return Family::Xor;
    case plan::Family::TriangularAdditive: return Family::Additive;
    default: llvm_unreachable("unverified bundle representation");
    }
  }
};
struct Binding {
  Program P;
  SmallVector<Instruction *, 32> Nodes, Outputs;
  // Header scalar projections may replace a PHI before another region lowers.
  // Follow RAUW even when block order differs from dominance order.
  SmallVector<WeakTrackingVH, 4> Inputs;
  unsigned BoundaryUses = 0, InputBoundaryUses = 0;
  BasicBlock *Preheader = nullptr;
  SmallVector<BasicBlock *, 4> Latches;
  SmallVector<PHINode *, 4> Recurrences;
  std::string LoopReason = "disabled";
  // Preorder, root first. The pure plan above contains no LLVM identities.
  SmallVector<SmallVector<Instruction *, 8>, 4> PredicateTrees;
};

unsigned predicateReservation(unsigned Lanes) { return 512 + 256 * Lanes; }

void planPredicates(Binding &B) {
  BasicBlock *BB = B.Nodes.front()->getParent();
  SmallPtrSet<Instruction *, 32> Claimed;
  // Prefer complete outer reductions over their smaller nested subexpressions.
  for (Instruction &Root : llvm::reverse(*BB)) {
    if (B.P.Predicates.size() == 4) break;
    if (Root.use_empty() || !Root.getType()->isIntegerTy(1) || Claimed.contains(&Root) ||
        (Root.getOpcode() != Instruction::And && Root.getOpcode() != Instruction::Or)) continue;
    PredicatePlan P;
    P.AnyDifferent = Root.getOpcode() == Instruction::Or;
    P.Origin = origin(Root);
    SmallVector<Instruction *, 8> Tree, Work{&Root};
    SmallPtrSet<Instruction *, 8> Seen;
    bool Valid = true;
    while (!Work.empty() && Valid) {
      Instruction *I = Work.pop_back_val();
      if (!I || I->getParent() != BB || !B.Nodes.back()->comesBefore(I) ||
          Claimed.contains(I) || !Seen.insert(I).second || Tree.size() == 7 ||
          (I != &Root && !I->hasOneUse())) { Valid = false; break; }
      Tree.push_back(I);
      if (auto *Cmp = dyn_cast<ICmpInst>(I)) {
        if (Cmp->getPredicate() != (P.AnyDifferent ? ICmpInst::ICMP_NE : ICmpInst::ICMP_EQ)) { Valid = false; break; }
        Value *V = Cmp->getOperand(0), *C = Cmp->getOperand(1);
        if (isa<ConstantInt>(V)) std::swap(V, C);
        auto *Constant = dyn_cast<ConstantInt>(C);
        auto It = llvm::find(B.Outputs, V);
        if (!Constant || It == B.Outputs.end() || Constant->getBitWidth() != B.P.Width) { Valid = false; break; }
        unsigned Output = It - B.Outputs.begin();
        if (llvm::any_of(P.Targets, [&](const PredicateTarget &T) { return T.Output == Output; })) { Valid = false; break; }
        P.Targets.push_back({Output, Constant->getZExtValue(), origin(*Cmp)});
      } else if (I->getOpcode() == Root.getOpcode() && I->getType()->isIntegerTy(1)) {
        Work.push_back(dyn_cast<Instruction>(I->getOperand(1)));
        Work.push_back(dyn_cast<Instruction>(I->getOperand(0)));
      } else Valid = false;
    }
    if (!Valid || P.Targets.size() < 2 || P.Targets.size() > 4) continue;
    for (Instruction *I : Tree) Claimed.insert(I);
    B.P.EstimatedCost += predicateReservation(B.P.Lanes);
    B.P.Predicates.push_back(std::move(P));
    B.PredicateTrees.push_back(std::move(Tree));
  }
}

void planLoop(Binding &B, const NativeBundleOptions &O, const DominatorTree &DT) {
  if (!O.Loops) return;
  B.LoopReason = "not-natural-loop-header";
  BasicBlock *Header = B.Nodes.front()->getParent();
  if (!DT.isReachableFromEntry(Header)) return;
  SmallVector<BasicBlock *, 4> Preds(predecessors(Header));
  SmallPtrSet<BasicBlock *, 8> Unique(Preds.begin(), Preds.end());
  B.LoopReason = "duplicate-header-edges";
  if (Unique.size() != Preds.size()) return;
  B.LoopReason = "unreachable-header-predecessor";
  if (llvm::any_of(Preds, [&](BasicBlock *BB) { return !DT.isReachableFromEntry(BB); })) return;
  BasicBlock *Pre = nullptr;
  SmallVector<BasicBlock *, 4> Latches;
  SmallVector<Backedge, 4> Edges;
  // Function order, not use-list order, gives the edge IDs a stable meaning.
  unsigned Block = 0;
  for (BasicBlock &BB : *Header->getParent()) {
    unsigned ID = Block++;
    if (!Unique.contains(&BB)) continue;
    if (DT.dominates(Header, &BB)) {
      B.LoopReason = "unsupported-backedge-terminator";
      if (!isa<BranchInst>(BB.getTerminator())) return;
      Latches.push_back(&BB); Edges.push_back({ID, {}});
    } else {
      B.LoopReason = "requires-unconditional-preheader";
      if (Pre) return;
      Pre = &BB;
    }
  }
  B.LoopReason = "not-natural-loop-header";
  if (Latches.empty()) return;
  B.LoopReason = "backedge-count-limit";
  if (Latches.size() > 4) return;
  B.LoopReason = "requires-unconditional-preheader";
  if (!Pre) return;
  auto *Entry = dyn_cast<BranchInst>(Pre->getTerminator());
  if (!Entry || !Entry->isUnconditional() || Entry->getSuccessor(0) != Header) return;
  SmallPtrSet<Instruction *, 32> Members(B.Nodes.begin(), B.Nodes.end());
  SmallVector<PHINode *, 4> Phis;
  SmallVector<unsigned, 4> ScalarInputs;
  unsigned ScalarUses = 0;
  for (Value *V : B.Inputs) {
    B.LoopReason = "input-is-not-header-recurrence";
    auto *Phi = dyn_cast<PHINode>(V);
    if (!Phi || Phi->getParent() != Header || Phi->getNumIncomingValues() != Preds.size()) return;
    B.LoopReason = "recurrence-has-external-users";
    unsigned Uses = 0;
    for (User *U : Phi->users())
      Uses += !Members.contains(dyn_cast<Instruction>(U));
    if (Uses && !O.LoopBoundaries) return;
    if (Uses) ScalarInputs.push_back(Phis.size());
    ScalarUses += Uses;
    B.LoopReason = "backedge-is-not-region-output";
    for (unsigned E = 0; E < Latches.size(); ++E) {
      auto It = llvm::find(B.Outputs, Phi->getIncomingValueForBlock(Latches[E]));
      if (It == B.Outputs.end()) return;
      Edges[E].Slots.push_back(B.P.OutputSlots[It - B.Outputs.begin()]);
    }
    Phis.push_back(Phi);
  }
  B.Preheader = Pre;
  B.Recurrences = std::move(Phis);
  B.Latches = std::move(Latches);
  B.P.Backedges = std::move(Edges);
  B.P.ScalarInputs = std::move(ScalarInputs);
  B.InputBoundaryUses = ScalarUses;
  B.P.Phases = O.Phases;
  B.BoundaryUses -= B.Recurrences.size() * B.Latches.size();
  B.P.EstimatedCost += 2048 * B.Latches.size() + 64 * B.P.ScalarInputs.size();
  B.LoopReason.clear();
}

bool schedule(ArrayRef<Instruction *> Nodes, unsigned Lanes, Binding &Out) {
  if (Nodes.size() < MinNodes) return false;
  SmallPtrSet<Instruction *, 32> Members(Nodes.begin(), Nodes.end());
  DenseMap<Value *, unsigned> Last;
  for (unsigned N = 0; N < Nodes.size(); ++N) {
    for (Value *V : Nodes[N]->operands()) {
      if (isa<ConstantInt>(V)) continue;
      auto *I = dyn_cast<Instruction>(V);
      if ((!I || !Members.contains(I)) && !llvm::is_contained(Out.Inputs, V))
        Out.Inputs.push_back(V);
      Last[V] = N;
    }
    bool Escapes = false;
    for (User *U : Nodes[N]->users()) {
      auto *I = dyn_cast<Instruction>(U);
      if (!I || !Members.contains(I)) { ++Out.BoundaryUses; Escapes = true; }
    }
    if (Escapes) Out.Outputs.push_back(Nodes[N]);
  }
  // Multiple actual input values AND multiple consumed output values. These
  // are syntactic dependencies, not a proof of independent input entropy.
  if (Out.Inputs.size() < 2 || Out.Inputs.size() > Lanes || Out.Outputs.size() < 2 ||
      Out.Outputs.size() > Lanes) return false;
  SmallPtrSet<Instruction *, 32> Useful;
  SmallVector<Instruction *, 32> Work(Out.Outputs.begin(), Out.Outputs.end());
  while (!Work.empty()) {
    Instruction *I = Work.pop_back_val();
    if (!Useful.insert(I).second) continue;
    for (Value *V : I->operands())
      if (auto *Def = dyn_cast<Instruction>(V); Def && Members.contains(Def)) Work.push_back(Def);
  }
  if (Useful.size() != Nodes.size()) return false;
  for (Instruction *I : Out.Outputs) Last[I] = Nodes.size();
  SmallVector<Value *, 4> Slots(Lanes, nullptr);
  for (unsigned N = 0; N < Out.Inputs.size(); ++N) Slots[N] = Out.Inputs[N];
  auto slot = [&](Value *V) {
    auto It = llvm::find(Slots, V);
    return It == Slots.end() ? plan::Invalid : unsigned(It - Slots.begin());
  };
  auto operand = [&](Value *V) {
    if (auto *C = dyn_cast<ConstantInt>(V)) return Operand{true, C->getZExtValue(), 0};
    return Operand{false, 0, slot(V)};
  };
  for (unsigned N = 0; N < Nodes.size(); ++N) {
    Instruction *I = Nodes[N];
    Step S;
    S.Opcode = I->getOpcode(); S.Origin = origin(*I);
    S.X = operand(I->getOperand(0)); S.Y = operand(I->getOperand(1));
    if ((!S.X.Constant && S.X.Slot == plan::Invalid) ||
        (!S.Y.Constant && S.Y.Slot == plan::Invalid)) return false;
    // Read both old operands before reusing their last-use slot.
    for (Value *&V : Slots) if (V && Last.lookup(V) <= N) V = nullptr;
    unsigned Dest = slot(nullptr);
    if (Dest == plan::Invalid) return false;
    S.Destination = Dest; Slots[Dest] = I;
    Out.P.Steps.push_back(std::move(S));
  }
  for (Instruction *I : Out.Outputs) {
    unsigned K = slot(I);
    if (K == plan::Invalid) return false;
    Out.P.OutputSlots.push_back(K);
  }
  Out.Nodes.append(Nodes.begin(), Nodes.end());
  Out.P.Width = Nodes.front()->getType()->getIntegerBitWidth();
  Out.P.Lanes = Lanes;
  // Conservative primitive expansion plus tuple repair. Exact function growth
  // is checked transactionally; estimates are never counted as emitted work.
  Out.P.EstimatedCost = 256 + unsigned(Nodes.size()) * 1200;
  return true;
}

bool valid(const Binding &B) {
  const Program &P = B.P;
  if (P.Steps.size() != B.Nodes.size() || P.Steps.size() < MinNodes ||
      P.OutputSlots.size() != B.Outputs.size() || P.Salts.size() != P.Lanes ||
      P.Rotations.size() != P.Lanes || P.Predicates.size() != B.PredicateTrees.size()) return false;
  for (unsigned N = 0; N < P.Predicates.size(); ++N) {
    const auto &Predicate = P.Predicates[N];
    if (Predicate.Targets.size() < 2 || Predicate.Targets.size() > 4 ||
        B.PredicateTrees[N].size() != 2 * Predicate.Targets.size() - 1) return false;
    for (const auto &T : Predicate.Targets) if (T.Output >= P.OutputSlots.size()) return false;
  }
  if ((P.Rep.Fam != plan::Family::TriangularXor && P.Rep.Fam != plan::Family::TriangularAdditive) ||
      P.Rep.Rev != 1 || P.Rep.LogicalWidth != P.Width || P.Rep.LaneWidth != P.Width ||
      P.Rep.Lanes != P.Lanes + 1 || P.Rep.Verified != plan::Verification::Algebraic) return false;
  for (unsigned N = 0; N < P.Steps.size(); ++N) {
    const Step &S = P.Steps[N];
    if (!supported(*B.Nodes[N]) || S.Opcode != B.Nodes[N]->getOpcode() ||
        B.Nodes[N]->getType()->getIntegerBitWidth() != P.Width || S.Destination >= P.Lanes ||
        (!S.X.Constant && S.X.Slot >= P.Lanes) || (!S.Y.Constant && S.Y.Slot >= P.Lanes)) return false;
  }
  for (unsigned K : P.OutputSlots) if (K >= P.Lanes) return false;
  for (unsigned R : P.Rotations) if (!R || R >= P.Width) return false;
  if (!P.Backedges.empty()) {
    if (!B.Preheader || B.Recurrences.size() != B.Inputs.size() ||
        P.Backedges.size() != B.Latches.size() || P.Backedges.size() > 4) return false;
    for (const Backedge &E : P.Backedges) {
      if (E.Slots.size() != B.Inputs.size()) return false;
      for (unsigned K : E.Slots) if (!llvm::is_contained(P.OutputSlots, K)) return false;
    }
    for (unsigned K : P.ScalarInputs) if (K >= B.Inputs.size()) return false;
  }
  return true;
}

// Encoded coordinates are chained, not the plaintext values:
//   Z[0] = X[0] (+ or xor) H(M)
//   Z[k] = X[k] (+ or xor) H(Z[k-1], M, k).
// Replacing one slot repairs every affected downstream coordinate with the
// old/new masks, without reconstructing the other logical values. The complete
// tuple persists across all the program's operations and has multiple outputs.
class Lowering {
  Function &F;
  const Program &P;
  IRBuilder<> B;
  SmallVector<Value *, 4> Z;
  Value *M = nullptr;
  PHINode *CarrierPhi = nullptr, *PhasePhi = nullptr;
  SmallVector<PHINode *, 4> StatePhis;
  MDNode *Tag;
  bool Pin, CallInputs, CallOutputs;
  ConstantInt *c(uint64_t X) { return ConstantInt::get(B.getIntNTy(P.Width), X); }
  Value *rotate(Value *X, unsigned R) {
    return B.CreateOr(B.CreateShl(X, R), B.CreateLShr(X, P.Width - R));
  }
  Value *mask(ArrayRef<Value *> State, unsigned K) {
    return bundle::mask(B, State, M, K, P.Salts[K], P.Rotations[K]);
  }
  Pair read(const Operand &O) {
    if (O.Constant) return {c(O.Bits), c(0)};
    return {Z[O.Slot], mask(Z, O.Slot)};
  }
  void pin() {
    if (!Pin) return;
    IRBuilder<> Entry(getAllocaIP(F));
    auto *T = ArrayType::get(B.getIntNTy(P.Width), P.Lanes + 1);
    auto *A = Entry.CreateAlloca(T, nullptr, "sre.bundle.tuple");
    A->setMetadata(BundleTag, Tag);
    A->setMetadata("sre.native.value", MDNode::get(F.getContext(), {}));
    SmallVector<Value *, 5> All(Z.begin(), Z.end()); All.push_back(M);
    for (unsigned K = 0; K < All.size(); ++K) {
      Value *Ptr = B.CreateInBoundsGEP(T, A, {B.getInt32(0), B.getInt32(K)});
      B.CreateStore(All[K], Ptr)->setVolatile(true);
      auto *L = B.CreateLoad(B.getIntNTy(P.Width), Ptr);
      L->setVolatile(true);
      if (K < P.Lanes) Z[K] = L; else M = L;
    }
  }
  void markRange(Instruction *Prev, Instruction *End) {
    for (Instruction *I = Prev ? Prev->getNextNode() : &End->getParent()->front();
         I != End; I = I->getNextNode()) I->setMetadata(BundleTag, Tag);
  }
  void predicates(const Binding &Bound) {
    for (unsigned N = 0; N < P.Predicates.size(); ++N) {
      const PredicatePlan &Predicate = P.Predicates[N];
      SmallVector<Value *, 4> Expected, Residuals;
      for (unsigned K = 0; K < P.Lanes; ++K) {
        auto It = llvm::find_if(Predicate.Targets, [&](const PredicateTarget &T) { return P.OutputSlots[T.Output] == K; });
        Value *NextMask = mask(Expected, K), *Next;
        if (It != Predicate.Targets.end())
          Next = P.coordinates() == Family::Xor ? B.CreateXor(c(It->Bits), NextMask)
                                                 : B.CreateAdd(c(It->Bits), NextMask);
        else
          Next = transfer::remask(B, {Z[K], mask(Z, K)}, P.coordinates(), NextMask);
        Expected.push_back(Next);
        Residuals.push_back(B.CreateXor(Z[K], Next));
      }
      // Invertible triangular residual map, followed by exact full-width OR.
      // Zero iff every coordinate agrees. No hash collision or scalar decode.
      Value *Combined = c(0);
      for (unsigned K = 0; K < P.Lanes; ++K) {
        if (K) Residuals[K] = B.CreateXor(Residuals[K], rotate(Residuals[K - 1], P.Rotations[K]));
        Combined = B.CreateOr(Combined, Residuals[K]);
      }
      Value *Test = Predicate.AnyDifferent ? B.CreateICmpNE(Combined, c(0)) : B.CreateICmpEQ(Combined, c(0));
      auto *Root = new FreezeInst(Test, "sre.bundle.predicate", B.GetInsertPoint());
      Root->setMetadata("sre.native.bundle.predicate", MDNode::get(F.getContext(), {
          Tag->getOperand(0).get(), ConstantAsMetadata::get(B.getInt32(N)),
          ConstantAsMetadata::get(B.getInt32(Predicate.Targets.size()))}));
      Bound.PredicateTrees[N].front()->replaceAllUsesWith(Root);
      // Preorder removal drops each parent use before deleting its children.
      for (Instruction *I : Bound.PredicateTrees[N]) {
        assert(I->use_empty() && "predicate tree has an unowned user");
        I->eraseFromParent();
      }
    }
  }
  void enter(ArrayRef<Value *> Values) {
    if (llvm::any_of(Values, [&](Value *V) { return bundle::inputPair(V, CallInputs) != nullptr; })) {
      SmallVector<Pair, 4> Inputs;
      for (Value *V : Values) Inputs.push_back(bundle::importPair(B, V, P.coordinates(), CallInputs));
      M = B.CreateAdd(rotate(Inputs[0].E, P.Rotations[0]),
          B.CreateXor(B.CreateAdd(Inputs[1].E, Inputs[1].R), c(P.Salts[0])));
      for (unsigned K = 0; K < P.Lanes; ++K) {
        Pair X = K < Inputs.size() ? Inputs[K] : Pair{c(0), c(0)};
        Z.push_back(transfer::remask(B, X, P.coordinates(), mask(Z, K)));
      }
      pin();
      return;
    }
    SmallVector<Value *, 4> Inputs;
    for (Value *V : Values) Inputs.push_back(B.CreateFreeze(V));
    M = B.CreateAdd(rotate(Inputs[0], P.Rotations[0]),
                    B.CreateXor(Inputs[1], c(P.Salts[0])));
    for (unsigned K = 0; K < P.Lanes; ++K) {
      Value *X = K < Inputs.size() ? Inputs[K] : c(0);
      Value *R = mask(Z, K);
      Z.push_back(P.coordinates() == Family::Xor ? B.CreateXor(X, R) : B.CreateAdd(X, R));
    }
    pin(); // Compiler pinning is a removable control, not hardness evidence.
  }
  void enterLoop(const Binding &Bound) {
    Instruction *Term = Bound.Preheader->getTerminator(), *Prev = Term->getPrevNode();
    B.SetInsertPoint(Term);
    SmallVector<Value *, 4> Inputs;
    for (PHINode *Phi : Bound.Recurrences)
      Inputs.push_back(Phi->getIncomingValueForBlock(Bound.Preheader));
    enter(Inputs);
    markRange(Prev, Term);
    BasicBlock *Header = Bound.Nodes.front()->getParent();
    auto phi = [&](Value *Initial, StringRef Name) {
      auto *Phi = PHINode::Create(B.getIntNTy(P.Width), Bound.Latches.size() + 1, Name, Header->begin());
      Phi->addIncoming(Initial, Bound.Preheader);
      Phi->setMetadata(BundleTag, Tag);
      return Phi;
    };
    for (Value *&V : Z) {
      PHINode *Phi = phi(V, "sre.bundle.loop.state");
      StatePhis.push_back(Phi); V = Phi;
    }
    CarrierPhi = phi(M, "sre.bundle.loop.carrier"); M = CarrierPhi;
    if (P.Phases) PhasePhi = phi(c(0), "sre.bundle.loop.phase");
    if (nativeBundleControl()) {
      auto mark = [&](PHINode *Phi, StringRef Role) {
        Phi->setMetadata(NativeBundleControlState, MDNode::get(F.getContext(), {
            Tag->getOperand(0).get(), MDString::get(F.getContext(), Role),
            ConstantAsMetadata::get(ConstantInt::get(B.getInt1Ty(), P.Phases))}));
      };
      mark(StatePhis[0], "state0"); mark(StatePhis[1], "state1");
      mark(CarrierPhi, "carrier");
      if (PhasePhi) mark(PhasePhi, "phase");
    }
    if (!P.ScalarInputs.empty()) {
      // Header placement dominates ordinary users and the incoming edge of
      // outside PHI users. These plaintext projections are deliberately exposed
      // in the plan, not counted as entirely encoded input lifetimes.
      Instruction *End = &*Header->getFirstInsertionPt(), *Before = End->getPrevNode();
      B.SetInsertPoint(End);
      for (unsigned K : P.ScalarInputs) {
        Value *R = mask(Z, K);
        Value *X = P.coordinates() == Family::Xor ? B.CreateXor(Z[K], R, "sre.bundle.loop.input")
                                                 : B.CreateSub(Z[K], R, "sre.bundle.loop.input");
        cast<Instruction>(X)->setMetadata("sre.native.boundary", MDNode::get(F.getContext(),
            MDString::get(F.getContext(), "bundle-loop-input")));
        Bound.Recurrences[K]->replaceAllUsesWith(X);
      }
      markRange(Before, End);
    }
    B.SetInsertPoint(Bound.Nodes.front());
  }
  void backedge(const Binding &Bound, unsigned Edge) {
    // Capture source pairs BEFORE replacing the carrier or predecessor slots.
    SmallVector<Pair, 4> Old;
    for (unsigned K : P.Backedges[Edge].Slots) Old.push_back({Z[K], mask(Z, K)});
    if (P.Phases) {
      Value *NextPhase = B.CreateXor(PhasePhi, c(1));
      Value *History = B.CreateAdd(rotate(B.CreateXor(M, Z.back()), P.Rotations.back()),
                                  B.CreateXor(Z.front(), c(P.Salts.back())));
      M = B.CreateXor(History, B.CreateMul(NextPhase, c(P.Salts[0] | 1)));
      PhasePhi->addIncoming(NextPhase, Bound.Latches[Edge]);
    }
    // Reorder/rekey directly in encoded coordinates, with no reconstructed
    // recurrence scalar. Unused logical slots reset to zero, not fake entropy.
    Z.clear();
    for (unsigned K = 0; K < P.Lanes; ++K) {
      Pair V = K < Old.size() ? Old[K] : Pair{c(0), c(0)};
      Z.push_back(transfer::remask(B, V, P.coordinates(), mask(Z, K)));
    }
    pin();
    for (unsigned K = 0; K < P.Lanes; ++K) StatePhis[K]->addIncoming(Z[K], Bound.Latches[Edge]);
    CarrierPhi->addIncoming(M, Bound.Latches[Edge]);
  }
public:
  Lowering(Function &F, const Binding &Bound, bool Pin, bool CallInputs, bool CallOutputs)
      : F(F), P(Bound.P), B(Bound.Nodes.front()),
        Tag(MDNode::get(F.getContext(), MDString::get(F.getContext(),
            plan::originId(F.getName(), "native-bundle", P.ID)))), Pin(Pin), CallInputs(CallInputs), CallOutputs(CallOutputs) {}
  void run(const Binding &Bound) {
    Instruction *First = Bound.Nodes.front(), *Prev = First->getPrevNode();
    if (Bound.Preheader) enterLoop(Bound);
    else {
      SmallVector<Value *, 4> Inputs(Bound.Inputs.begin(), Bound.Inputs.end());
      enter(Inputs);
    }
    for (const Step &S : P.Steps) {
      Pair X = read(S.X), Y = read(S.Y), Out = X;
      Value *Fresh = B.CreateXor(M, Z.back());
      Out = bundle::operation(B, S.Opcode, X, Y, P.coordinates(), Fresh);
      SmallVector<Value *, 4> Old = Z;
      for (unsigned K = S.Destination; K < P.Lanes; ++K) {
        Pair V = K == S.Destination ? Out : Pair{Old[K], mask(Old, K)};
        Z[K] = transfer::remask(B, V, P.coordinates(), mask(Z, K));
      }
    }
    if (!Bound.Preheader) pin();
    predicates(Bound);
    SmallPtrSet<Instruction *, 32> Members(Bound.Nodes.begin(), Bound.Nodes.end());
    for (PHINode *Phi : Bound.Recurrences) Members.insert(Phi);
    SmallVector<Value *, 4> Outputs;
    for (unsigned N = 0; N < P.OutputSlots.size(); ++N) {
      unsigned K = P.OutputSlots[N];
      if (CallOutputs && llvm::any_of(Bound.Outputs[N]->users(), [&](User *U) {
            auto *I = dyn_cast<Instruction>(U);
            return I && isNativeBundleCallSupply(*I, Bound.Outputs[N]);
          })) supplyNativeBundleCalls(F, Bound.Outputs[N], {Z[K], mask(Z, K)}, P.coordinates());
      bool Needed = llvm::any_of(Bound.Outputs[N]->users(), [&](User *U) {
        return !Members.contains(dyn_cast<Instruction>(U));
      });
      if (!Needed) { Outputs.push_back(nullptr); continue; }
      Value *R = mask(Z, K);
      Value *X = P.coordinates() == Family::Xor ? B.CreateXor(Z[K], R, "sre.bundle.boundary")
                                    : B.CreateSub(Z[K], R, "sre.bundle.boundary");
      if (auto *I = dyn_cast<Instruction>(X))
        I->setMetadata("sre.native.boundary", MDNode::get(F.getContext(), MDString::get(F.getContext(), "bundle-exit")));
      Outputs.push_back(X);
    }
    if (Bound.Preheader) {
      SmallVector<Value *, 4> Completed = Z;
      Value *Carrier = M;
      for (unsigned E = 0; E < Bound.Latches.size(); ++E) {
        // Every edge starts from the SAME completed region, never from the
        // tuple just emitted for another mutually exclusive predecessor.
        Z = Completed; M = Carrier;
        Instruction *End = Bound.Latches[E] == First->getParent() ? First
                                                                 : Bound.Latches[E]->getTerminator();
        Instruction *Before = End->getPrevNode();
        B.SetInsertPoint(End);
        backedge(Bound, E);
        markRange(Before, End);
      }
    }
    markRange(Prev, First);
    for (unsigned K = 0; K < Bound.Outputs.size(); ++K)
      if (Outputs[K]) Bound.Outputs[K]->replaceUsesWithIf(Outputs[K], [&](Use &U) {
        auto *I = dyn_cast<Instruction>(U.getUser());
        return !I || !Members.contains(I);
      });
    for (PHINode *Phi : Bound.Recurrences) Phi->dropAllReferences();
    for (Instruction *I : llvm::reverse(Bound.Nodes)) I->eraseFromParent();
    for (PHINode *Phi : Bound.Recurrences) Phi->eraseFromParent();
  }
};

json::Object report(const Binding &B) {
  const Program &P = B.P;
  json::Array Steps, Outputs, Salts, Rotations, NextSlots, Edges, ScalarInputs, Predicates;
  unsigned PredicateUses = 0;
  for (unsigned N = 0; N < P.Predicates.size(); ++N) {
    const auto &Predicate = P.Predicates[N];
    json::Array Targets;
    for (const auto &T : Predicate.Targets) Targets.push_back(json::Object{
        {"output", T.Output}, {"slot", P.OutputSlots[T.Output]}, {"constant_hex", utohexstr(T.Bits)},
        {"input_origin", T.Origin.empty() ? json::Value(nullptr) : json::Value(T.Origin)}});
    PredicateUses += Predicate.Targets.size();
    Predicates.push_back(json::Object{{"id", N}, {"mode", Predicate.AnyDifferent ? "any-different" : "all-equal"},
        {"input_origin", Predicate.Origin.empty() ? json::Value(nullptr) : json::Value(Predicate.Origin)},
        {"targets", std::move(Targets)}, {"source_operand_uses", Predicate.Targets.size()},
        {"tree_instructions", B.PredicateTrees[N].size()}, {"law", "exact-tuple-replacement-v1"}});
  }
  auto operand = [](const Operand &O) {
    return O.Constant ? json::Object{{"constant_hex", utohexstr(O.Bits)}}
                      : json::Object{{"slot", O.Slot}};
  };
  for (const Step &S : P.Steps)
    Steps.push_back(json::Object{{"opcode", Instruction::getOpcodeName(S.Opcode)},
        {"destination", S.Destination}, {"x", operand(S.X)}, {"y", operand(S.Y)},
        {"input_origin", S.Origin.empty() ? json::Value(nullptr) : json::Value(S.Origin)}});
  for (unsigned K : P.OutputSlots) Outputs.push_back(K);
  for (uint64_t S : P.Salts) Salts.push_back(utohexstr(S));
  for (unsigned R : P.Rotations) Rotations.push_back(R);
  for (unsigned E = 0; E < P.Backedges.size(); ++E) {
    json::Array Slots;
    for (unsigned K : P.Backedges[E].Slots) Slots.push_back(K);
    Edges.push_back(json::Object{{"id", E}, {"predecessor_block", P.Backedges[E].Block},
                                {"next_input_slots", std::move(Slots)}});
  }
  if (P.Backedges.size() == 1)
    for (unsigned K : P.Backedges.front().Slots) NextSlots.push_back(K);
  for (unsigned K : P.ScalarInputs) ScalarInputs.push_back(K);
  json::Object Result{{"id", P.ID}, {"width", P.Width}, {"lanes", P.Lanes},
      {"family", plan::familyVersion(P.Rep.Fam, P.Rep.Rev)},
      {"representation", json::Object{{"family", plan::name(P.Rep.Fam)}, {"revision", P.Rep.Rev},
          {"physical_lanes", P.Rep.Lanes}, {"logical_width", P.Rep.LogicalWidth},
          {"lane_width", P.Rep.LaneWidth}, {"invariant", P.Rep.Invariant},
          {"seed_namespace", P.Rep.SeedNamespace}, {"verification", plan::name(P.Rep.Verified)}}},
      {"law", "triangular-slot-update-v1"}, {"verification", "algebraic"},
      {"useful_operations", P.Steps.size()}, {"inputs", B.Inputs.size()},
      {"outputs", B.Outputs.size()}, {"scalar_output_uses", B.BoundaryUses},
      {"call_supply_uses", P.CallSupplies}, {"call_supply_reservation", P.CallSupplies * 384},
      {"predicates", std::move(Predicates)}, {"predicate_operand_uses", PredicateUses},
      {"predicate_reservation", P.Predicates.size() * predicateReservation(P.Lanes)},
      {"loop", json::Object{{"status", B.Preheader ? "encoded" : "straight-line"},
          {"contract", "sre-bundle-loop-v2"}, {"graph_scope", "dominated-header-recurrence"},
          {"reason", B.LoopReason}, {"law", "triangular-recurrence-rebase-v1"},
          {"phase_mode", P.Phases ? "two-phase" : "static"},
          {"phase_count", P.Phases ? 2 : 1}, {"initial_phase", 0},
          {"backedge_uses", B.Recurrences.size() * B.Latches.size()},
          {"scalar_input_uses", B.InputBoundaryUses}, {"scalar_input_slots", std::move(ScalarInputs)},
          {"backedges", std::move(Edges)},
          {"next_input_slots", std::move(NextSlots)}}},
      {"estimated_cost", P.EstimatedCost}, {"steps", std::move(Steps)},
      {"output_slots", std::move(Outputs)}, {"salts_hex", std::move(Salts)},
      {"rotations", std::move(Rotations)}};
  if (P.Selection) Result["selection"] = json::Object(*P.Selection);
  return Result;
}
}

json::Array stampNativeBundleOrigins(Module &M) {
  json::Array Report;
  for (Function &F : M) {
    if (F.isDeclaration()) continue;
    unsigned N = 0, Pure = 0;
    for (Instruction &I : instructions(F)) {
      // Replace untrusted/stale metadata on entry to this compilation.
      I.setMetadata(OriginTag, MDNode::get(M.getContext(), MDString::get(M.getContext(),
          plan::originId(F.getName(), "input-op", N++))));
      Pure += supported(I);
    }
    Report.push_back(json::Object{{"function", F.getName().str()},
        {"instructions", N}, {"eligible_pure_operations", Pure}});
  }
  return Report;
}

namespace {
constexpr unsigned FunctionCostLimit = 65536;
struct FunctionPlan {
  Function *F;
  unsigned Before = 0, Eligible = 0, Weight = 0, Reserved = 0, Selected = 0;
  bool Blocked = false;
  SmallVector<Binding, 8> Candidates;
};
// Selection sees actual whole-region candidates, not just a function-size
// proxy. Small unusable nominal shares are pooled instead of starving every
// region in a large module. The total cap never changes.
FunctionPlan planFunction(Function &F, uint64_t Seed, const NativeBundleOptions &O) {
  FunctionPlan Result;
  Result.F = &F;
  Result.Before = F.getInstructionCount();
  Result.Weight = std::clamp(Result.Before, 32u, 4096u);
  for (Instruction &I : instructions(F)) Result.Eligible += supported(I);
  Result.Blocked = F.isVarArg() || F.hasPersonalityFn() || Result.Before > 12000 ||
                   F.hasFnAttribute(Attribute::Naked);
  if (Result.Blocked) return Result;
  DominatorTree DT;
  if (O.Loops) DT.recalculate(F);
  auto &Plans = Result.Candidates;
  unsigned Estimated = 0;
  // Stable block/instruction order, bounded windows. Effects, width changes,
  // unknown shifts and control boundaries stop a window; nothing is hoisted
  // out of a guard or speculated across a call or load.
  for (BasicBlock &BB : F) {
    SmallVector<Instruction *, 32> Run;
    auto flush = [&]() {
      unsigned Start = 0;
      while (Start + MinNodes <= Run.size() && Plans.size() < MaxRegions) {
        bool Found = false;
        for (unsigned N = std::min<unsigned>(O.Nodes, Run.size() - Start); N >= MinNodes; --N) {
          Binding B;
          if (256 + N * 1200 > FunctionCostLimit - Estimated ||
              !schedule(ArrayRef<Instruction *>(Run).slice(Start, N), O.Values, B)) continue;
          planLoop(B, O, DT);
          if (O.Predicates) planPredicates(B);
          if (O.CallOutputs) {
            for (Instruction *Output : B.Outputs) for (User *U : Output->users())
              if (auto *I = dyn_cast<Instruction>(U); I && isNativeBundleCallSupply(*I, Output)) ++B.P.CallSupplies;
            B.P.EstimatedCost += B.P.CallSupplies * 384;
          }
          if (B.P.EstimatedCost > FunctionCostLimit - Estimated) continue;
          B.P.ID = Plans.size();
          Rng R = Rng(Seed).fork("native-bundles-v1").fork(F.getName()).fork(B.P.ID);
          B.P.Rep.Fam = O.Family == "additive" || (O.Family == "seeded" && (R.u64() & 1))
                          ? plan::Family::TriangularAdditive : plan::Family::TriangularXor;
          if (O.Policy) {
            // Never transfer measurements across a different phase/call/predicate contract.
            bool InScope = B.P.Backedges.empty() && B.P.Predicates.empty() &&
                           !B.P.CallSupplies && !O.CallInputs;
            const auto *Rule = InScope ? O.Policy->match(B.P.Width, B.P.Lanes, N, O.Pin) : nullptr;
            json::Array Candidates;
            if (Rule) {
              for (const std::string &C : Rule->Candidates) Candidates.push_back(C);
              const auto &Chosen = Rule->Candidates[R.fork("cached-policy-v1").u64() % Rule->Candidates.size()];
              B.P.Rep.Fam = Chosen == "additive" ? plan::Family::TriangularAdditive : plan::Family::TriangularXor;
            }
            B.P.Selection = O.Policy->identity();
            (*B.P.Selection)["status"] = Rule ? "matched" : "seeded-fallback";
            (*B.P.Selection)["reason"] = Rule ? "" : InScope ? "unmeasured-shape" : "unsupported-context";
            (*B.P.Selection)["candidates"] = std::move(Candidates);
          }
          B.P.Rep.Rev = 1;
          B.P.Rep.LogicalWidth = B.P.Rep.LaneWidth = B.P.Width;
          B.P.Rep.Lanes = B.P.Lanes + 1;
          B.P.Rep.Invariant = B.P.coordinates() == Family::Xor ? "triangular-xor-carrier" : "triangular-additive-carrier";
          B.P.Rep.Verified = plan::Verification::Algebraic;
          B.P.Rep.SeedNamespace = ("native-bundles-v1/" + F.getName() + "/" + Twine(B.P.ID)).str();
          for (unsigned K = 0; K < O.Values; ++K) {
            B.P.Salts.push_back(R.fork(K).u64());
            B.P.Rotations.push_back(1 + R.fork(K).fork("rotate").u64() % (B.P.Width - 1));
          }
          if (!valid(B)) report_fatal_error("invalid native bundle schedule");
          Estimated += B.P.EstimatedCost; Plans.push_back(std::move(B));
          Start += N; Found = true; break;
        }
        if (!Found) ++Start;
      }
      Run.clear();
    };
    for (Instruction &I : BB) {
      if (!supported(I) || (!Run.empty() && Run.front()->getType() != I.getType())) flush();
      if (supported(I)) Run.push_back(&I);
    }
    flush();
  }
  return Result;
}

void allocate(SmallVectorImpl<FunctionPlan> &Plans, unsigned Budget) {
  uint64_t Weight = 0;
  for (const FunctionPlan &P : Plans) if (!P.Candidates.empty()) Weight += P.Weight;
  unsigned Remaining = Budget;
  for (FunctionPlan &P : Plans) {
    unsigned Share = Weight ? uint64_t(Budget) * P.Weight / Weight : 0;
    for (const Binding &B : P.Candidates) {
      if (B.P.EstimatedCost > Share - P.Reserved) break;
      P.Reserved += B.P.EstimatedCost; ++P.Selected;
      Remaining -= B.P.EstimatedCost;
    }
  }
  while (true) {
    FunctionPlan *Best = nullptr;
    for (FunctionPlan &P : Plans) {
      if (P.Selected == P.Candidates.size()) continue;
      unsigned Cost = P.Candidates[P.Selected].P.EstimatedCost;
      if (Cost > Remaining) continue;
      if (!Best) { Best = &P; continue; }
      unsigned Other = Best->Candidates[Best->Selected].P.EstimatedCost;
      uint64_t Left = uint64_t(P.Weight) * (Best->Reserved + Other);
      uint64_t Right = uint64_t(Best->Weight) * (P.Reserved + Cost);
      if (Left > Right || (Left == Right && P.F->getName() < Best->F->getName())) Best = &P;
    }
    if (!Best) break;
    unsigned Cost = Best->Candidates[Best->Selected++].P.EstimatedCost;
    Best->Reserved += Cost; Remaining -= Cost;
  }
}

} // namespace

json::Array nativeBundlePredicateInventory(Module &M) {
  json::Array Rows;
  for (Function &F : M) if (!F.isDeclaration())
    for (Instruction &I : instructions(F)) if (auto *MD = I.getMetadata("sre.native.bundle.predicate"))
      Rows.push_back(json::Object{{"function", F.getName().str()},
          {"origin", cast<MDString>(MD->getOperand(0))->getString().str()},
          {"id", mdconst::extract<ConstantInt>(MD->getOperand(1))->getZExtValue()},
          {"source_operand_uses", mdconst::extract<ConstantInt>(MD->getOperand(2))->getZExtValue()},
          {"live_consumers", I.getNumUses()}, {"contract", "joint-predicate-v1"},
          {"stage", "after-bundles-before-regions"}, {"hardness_evaluated", false}});
  return Rows;
}

json::Array encodeNativeBundles(Module &M, uint64_t Seed, const NativeBundleOptions &O) {
  json::Array Report;
  SmallVector<FunctionPlan, 16> Work;
  for (Function &F : M) if (F.hasFnAttribute("sre.native.original"))
    Work.push_back(planFunction(F, Seed, O));
  allocate(Work, O.GrowthBudget);
  for (FunctionPlan &W : Work) {
    Function *F = W.F;
    unsigned Before = W.Before, Eligible = W.Eligible, Budget = W.Reserved;
    json::Object Row{{"function", F->getName().str()}, {"schema", "sre-bundle-plan-v1"},
        {"eligible_operations", Eligible}, {"growth_allocation", Budget},
        {"module_growth_limit", O.GrowthBudget}, {"allocation_policy", "coherent-weighted-v1"},
        {"candidate_regions", W.Candidates.size()},
        {"graph_scope", "pre-bundle-lowering"}, {"source_lineage", "input-ir-metadata"},
        {"pins", O.Pin}, {"loops", O.Loops}, {"phases", O.Phases},
        {"loop_boundaries", O.LoopBoundaries},
        {"instructions_before", Before}};
    if (W.Blocked) {
      Row["status"] = "skipped"; Row["reason"] = "structure-or-size";
      Row["retained_operations"] = 0; Row["instructions_after"] = Before;
      Report.push_back(std::move(Row)); continue;
    }
    ArrayRef<Binding> Plans(W.Candidates.data(), W.Selected);
    unsigned Estimated = W.Reserved;
    unsigned Selected = 0;
    json::Array Regions;
    for (const Binding &B : Plans) { Selected += B.Nodes.size(); Regions.push_back(report(B)); }
    bool Rollback = false;
    unsigned After = Before;
    if (!Plans.empty()) {
      FunctionSnapshot Snapshot(*F);
      // Backwards emission keeps later bindings alive when an earlier output
      // feeds a later region's entry. RAUW updates the already-emitted use.
      for (const Binding &B : llvm::reverse(Plans)) Lowering(*F, B, O.Pin, O.CallInputs, O.CallOutputs).run(B);
      After = F->getInstructionCount();
      Rollback = After > uint64_t(Before) + Budget;
      if (verifyFunction(*F, &errs())) report_fatal_error("native bundle lowering produced invalid IR");
      if (Rollback) Snapshot.restore();
    }
    Row["status"] = Rollback ? "rolled-back" : Selected ? "encoded" : "skipped";
    Row["reason"] = Rollback ? "growth-budget" : Selected ? "" :
                    W.Candidates.empty() ? "no-fitting-multi-output-region" : "module-unit-budget";
    Row["attempted_operations"] = Selected;
    Row["retained_operations"] = Rollback ? 0 : Selected;
    Row["unselected_operations"] = Eligible - Selected;
    Row["rolled_back_operations"] = Rollback ? Selected : 0;
    Row["estimated_cost"] = Estimated;
    Row["instructions_after"] = F->getInstructionCount();
    Row["attempted_instructions"] = After;
    Row["regions_scope"] = Rollback ? "attempted" : "retained";
    Row["regions"] = std::move(Regions);
    Row["hardness_evaluated"] = false;
    Report.push_back(std::move(Row));
  }
  return Report;
}
}
