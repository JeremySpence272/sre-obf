#include "llvm/Transforms/Obfuscator/NativeConsumer.h"
#include "llvm/Transforms/Obfuscator/FunctionSnapshot.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/ValueHandle.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <memory>

using namespace llvm;
namespace llvm::obf {
namespace {
AllocaInst *root(Value *V) {
  while (auto *G = dyn_cast<GEPOperator>(V)) {
    if (!G->hasAllZeroIndices()) return nullptr;
    V = G->getPointerOperand();
  }
  return dyn_cast<AllocaInst>(V);
}
bool byteArray(AllocaInst *A, uint64_t N) {
  if (!A || A->getAddressSpace()) return false;
  auto *Count = dyn_cast<ConstantInt>(A->getArraySize());
  auto *T = dyn_cast<ArrayType>(A->getAllocatedType());
  return Count && Count->isOne() && T && T->getElementType()->isIntegerTy(8) &&
         T->getNumElements() == N && A->getParent() == &A->getFunction()->getEntryBlock();
}
bool equalityCall(CallInst &Call) {
  auto *F = Call.getCalledFunction();
  if (!F || !F->isDeclaration() || Call.hasFnAttr(Attribute::NoBuiltin) ||
      (F->getName() != "memcmp" && F->getName() != "bcmp") ||
      Call.arg_size() != 3 || !Call.getType()->isIntegerTy(32) ||
      !Call.getArgOperand(0)->getType()->isPointerTy() ||
      !Call.getArgOperand(1)->getType()->isPointerTy() ||
      !Call.getArgOperand(2)->getType()->isIntegerTy(64) ||
      Call.isMustTailCall() || Call.hasOperandBundles() || Call.use_empty()) return false;
  for (User *U : Call.users()) {
    auto *Cmp = dyn_cast<ICmpInst>(U);
    if (!Cmp || !Cmp->isEquality()) return false;
    Value *Other = Cmp->getOperand(0) == &Call ? Cmp->getOperand(1) : Cmp->getOperand(0);
    auto *Zero = dyn_cast<ConstantInt>(Other);
    if (!Zero || !Zero->isZero()) return false;
  }
  return true;
}
unsigned arrays(const Function &F) {
  unsigned N = 0;
  for (const Instruction &I : instructions(F))
    if (auto *A = dyn_cast<AllocaInst>(&I))
      if (auto *T = dyn_cast<ArrayType>(A->getAllocatedType());
          T && T->getElementType()->isIntegerTy(8)) ++N;
  return N;
}
bool escaped(AllocaInst *A, CallInst *Compare) {
  SmallVector<Value *, 32> Queue{A};
  SmallPtrSet<Value *, 32> Seen;
  for (unsigned K = 0; K < Queue.size(); ++K) {
    if (!Seen.insert(Queue[K]).second) continue;
    for (User *U : Queue[K]->users()) {
      if (auto *G = dyn_cast<GetElementPtrInst>(U)) { Queue.push_back(G); continue; }
      if (auto *S = dyn_cast<StoreInst>(U)) {
        if (S->getPointerOperand() == Queue[K] && S->isSimple() &&
            S->getValueOperand()->getType()->isIntegerTy(8)) continue;
      }
      if (auto *L = dyn_cast<LoadInst>(U)) {
        if (L->getPointerOperand() == Queue[K] && L->isSimple() &&
            L->getType()->isIntegerTy(8)) continue;
      }
      if (U == Compare || isa<LifetimeIntrinsic>(U)) continue;
      return true;
    }
  }
  return false;
}
}

json::Array integrateNativeExactConsumers(Module &M, ModuleAnalysisManager &AM, unsigned Budget) {
  json::Array Rows;
  auto &FAM = AM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  PassBuilder PB;
  FunctionPassManager Normalize, Unroll, Scalarize;
  if (auto E = PB.parsePassPipeline(Normalize,
      "sroa,instcombine,simplifycfg,loop-simplify,lcssa"))
    report_fatal_error(Twine("exact consumer normalization: ") + toString(std::move(E)));
  if (auto E = PB.parsePassPipeline(Unroll, "loop(loop-unroll-full),instcombine,simplifycfg"))
    report_fatal_error(Twine("exact consumer unrolling: ") + toString(std::move(E)));
  if (auto E = PB.parsePassPipeline(Scalarize, "sroa"))
    report_fatal_error(Twine("exact consumer scalarization: ") + toString(std::move(E)));
  SmallVector<Function *, 32> Functions;
  for (Function &F : M) if (!F.isDeclaration()) Functions.push_back(&F);
  unsigned Spent = 0;
  for (Function *F : Functions) {
    if (F->hasPersonalityFn() || F->isVarArg() || F->hasFnAttribute(Attribute::Naked) ||
        F->getInstructionCount() > 2000 || F->hasFnAttribute("sre.runtime.support")) continue;
    SmallVector<WeakTrackingVH, 8> Candidates;
    for (Instruction &I : instructions(F))
      if (auto *Call = dyn_cast<CallInst>(&I); Call && equalityCall(*Call)) {
        auto *Len = dyn_cast<ConstantInt>(Call->getArgOperand(2));
        if (!Len || Len->getZExtValue() == 0 || Len->getZExtValue() > 64) continue;
        uint64_t N = Len->getZExtValue();
        auto *A = root(Call->getArgOperand(0)), *B = root(Call->getArgOperand(1));
        if (A != B && byteArray(A, N) && byteArray(B, N)) Candidates.push_back(Call);
      }
    if (Candidates.empty()) continue;
    unsigned Before = F->getInstructionCount(), ArraysBefore = arrays(*F);
    if (Spent + 4096 > Budget) {
      Rows.push_back(json::Object{{"function", F->getName().str()}, {"status", "excluded"},
                                 {"reason", "growth-reservation"}});
      continue;
    }
    FunctionSnapshot Snapshot(*F);
    SmallPtrSet<GlobalValue *, 32> Existing;
    for (GlobalValue &G : M.global_values()) Existing.insert(&G);
    unsigned Inlined = 0;
    // Only private calls actually borrowing a candidate's exact stack root are
    // considered. Inlining preserves their effects; it is not a purity guess.
    SmallPtrSet<AllocaInst *, 8> Roots;
    for (auto &Handle : Candidates) {
      auto *Call = cast<CallInst>(Handle);
      Roots.insert(root(Call->getArgOperand(0)));
      Roots.insert(root(Call->getArgOperand(1)));
    }
    SmallVector<CallInst *, 16> Borrowers;
    for (Instruction &I : instructions(F)) {
      auto *Call = dyn_cast<CallInst>(&I);
      if (!Call || equalityCall(*Call) || isa<IntrinsicInst>(Call)) continue;
      Function *G = Call->getCalledFunction();
      if (!G || G == F || !G->hasLocalLinkage() || G->hasAddressTaken() ||
          G->hasPersonalityFn() || G->getInstructionCount() > 256 ||
          Call->isMustTailCall() || Call->hasOperandBundles()) continue;
      for (Value *V : Call->args())
        if (V->getType()->isPointerTy() && Roots.contains(root(V))) {
          Borrowers.push_back(Call);
          break;
        }
    }
    for (CallInst *Call : Borrowers) {
      if (Inlined == 4) break;
      InlineFunctionInfo Info;
      if (InlineFunction(*Call, Info).isSuccess()) ++Inlined;
    }
    // Keep the equality boundary recognizable during producer normalization.
    // The original calls were checked not to carry this attribute.
    for (auto &Handle : Candidates)
      if (auto *Call = dyn_cast_or_null<CallInst>(static_cast<Value *>(Handle)))
        Call->addFnAttr(Attribute::NoBuiltin);
    FAM.invalidate(*F, PreservedAnalyses::none());
    Normalize.run(*F, FAM);
    // Only statically counted innermost loops with a bounded expansion may ask
    // for full unrolling. Re-evaluate outer loops after each round; never guess
    // a runtime trip count or unroll an arbitrarily deep nest in one step.
    for (unsigned Round = 0; Round < 3 && F->getInstructionCount() <= 4096; ++Round) {
      auto &Loops = FAM.getResult<LoopAnalysis>(*F);
      auto &Evolution = FAM.getResult<ScalarEvolutionAnalysis>(*F);
      bool Tagged = false;
      for (Loop *L : Loops.getLoopsInPreorder()) {
        if (!L->getSubLoops().empty()) continue;
        unsigned Trip = Evolution.getSmallConstantTripCount(L), Size = 0;
        for (BasicBlock *BB : L->blocks()) Size += BB->size();
        if (!Trip || Trip > 64 || uint64_t(Trip) * Size > 4096) continue;
        SmallVector<Metadata *, 8> Operands{nullptr};
        bool Disabled = false;
        if (auto *ID = L->getLoopID())
          for (unsigned K = 1; K < ID->getNumOperands(); ++K) {
            auto *Node = dyn_cast<MDNode>(ID->getOperand(K));
            auto *Name = Node && Node->getNumOperands() ? dyn_cast<MDString>(Node->getOperand(0)) : nullptr;
            if (Name && Name->getString() == "llvm.loop.unroll.disable") Disabled = true;
            if (!Name || !Name->getString().starts_with("llvm.loop.unroll."))
              Operands.push_back(ID->getOperand(K));
          }
        if (Disabled) continue;
        Operands.push_back(MDNode::get(M.getContext(), MDString::get(M.getContext(), "llvm.loop.unroll.full")));
        auto *ID = MDNode::getDistinct(M.getContext(), Operands);
        ID->replaceOperandWith(0, ID);
        L->setLoopID(ID);
        Tagged = true;
      }
      if (!Tagged) break;
      FAM.invalidate(*F, PreservedAnalyses::none());
      Unroll.run(*F, FAM);
    }
    for (auto &Handle : Candidates)
      if (auto *Call = dyn_cast_or_null<CallInst>(static_cast<Value *>(Handle)))
        Call->removeFnAttr(Attribute::NoBuiltin);
    unsigned Expanded = 0, Bytes = 0;
    SmallVector<CallInst *, 8> Comparisons;
    for (Instruction &I : instructions(F))
      if (auto *Call = dyn_cast<CallInst>(&I); Call && equalityCall(*Call))
        Comparisons.push_back(Call);
    for (CallInst *Call : Comparisons) {
      auto *Len = dyn_cast<ConstantInt>(Call->getArgOperand(2));
      if (!Len || Len->getZExtValue() == 0 || Len->getZExtValue() > 64) continue;
      unsigned N = Len->getZExtValue();
      auto *A = root(Call->getArgOperand(0)), *B = root(Call->getArgOperand(1));
      if (A == B || !byteArray(A, N) || !byteArray(B, N) ||
          escaped(A, Call) || escaped(B, Call)) continue;
      IRBuilder<> At(Call);
      Value *Equal = At.getTrue();
      for (unsigned K = 0; K < N; ++K) {
        auto *X = At.CreateLoad(At.getInt8Ty(), At.CreateGEP(At.getInt8Ty(), A, At.getInt64(K)));
        auto *Y = At.CreateLoad(At.getInt8Ty(), At.CreateGEP(At.getInt8Ty(), B, At.getInt64(K)));
        X->setAlignment(Align(1)); Y->setAlignment(Align(1));
        Equal = At.CreateAnd(Equal, At.CreateICmpEQ(X, Y));
      }
      Call->replaceAllUsesWith(At.CreateSelect(Equal, At.getInt32(0), At.getInt32(1)));
      Call->eraseFromParent();
      ++Expanded; Bytes += N;
    }
    FAM.invalidate(*F, PreservedAnalyses::none());
    if (Expanded) Scalarize.run(*F, FAM);
    unsigned After = F->getInstructionCount(), ArraysAfter = arrays(*F);
    bool Invalid = verifyFunction(*F, &errs());
    unsigned Growth = After > Before ? After - Before : 0;
    bool Rollback = !Expanded || Invalid || Growth > 4096 || Spent + Growth > Budget;
    if (Rollback) {
      Snapshot.restore();
      SmallVector<GlobalValue *, 16> Added;
      for (GlobalValue &G : M.global_values()) if (!Existing.contains(&G)) Added.push_back(&G);
      for (GlobalValue *G : Added) G->dropAllReferences();
      for (GlobalValue *G : Added) G->eraseFromParent();
      FAM.invalidate(*F, PreservedAnalyses::none());
    } else Spent += Growth;
    Rows.push_back(json::Object{{"function", F->getName().str()},
        {"status", Rollback ? "rolled-back" : "integrated"},
        {"reason", Rollback ? (!Expanded ? "ownership-or-normalization-boundary" :
                               Invalid ? "invalid-ir" : "growth-budget") : ""},
        {"instructions_before", Before}, {"instructions_after", F->getInstructionCount()},
        {"private_producers_inlined", Rollback ? 0 : Inlined},
        {"exact_consumers", Rollback ? 0 : Expanded}, {"compared_bytes", Rollback ? 0 : Bytes},
        {"byte_arrays_before", ArraysBefore}, {"byte_arrays_after", Rollback ? ArraysBefore : ArraysAfter},
        {"complete_chain_claim", false}, {"hardness_evaluated", false}});
  }
  return Rows;
}
}
