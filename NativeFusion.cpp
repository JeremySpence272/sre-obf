#include "llvm/Transforms/Obfuscator/NativeRegions.h"
#include "llvm/Transforms/Obfuscator/NativeConnected.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"

using namespace llvm;
namespace llvm::obf {
namespace {
bool unsafe(const Function &F) {
  if (F.isDeclaration() || F.isVarArg() || F.hasPersonalityFn() ||
      F.hasFnAttribute(Attribute::Naked) || F.hasFnAttribute(Attribute::ReturnsTwice)) return true;
  for (const Instruction &I : instructions(F)) {
    if (I.isEHPad() || isa<InvokeInst, CallBrInst, IndirectBrInst>(&I)) return true;
    if (const auto *C = dyn_cast<CallBase>(&I)) {
      if (C->isInlineAsm() || C->hasFnAttr(Attribute::ReturnsTwice) || !C->getCalledFunction()) return true;
      if (const auto *CI = dyn_cast<CallInst>(C); CI && CI->isMustTailCall()) return true;
    }
  }
  return false;
}
bool reaches(Function *Start, Function *Target) {
  SmallVector<Function *, 16> Work{Start};
  SmallPtrSet<Function *, 32> Seen;
  while (!Work.empty()) {
    Function *F = Work.pop_back_val();
    if (F == Target) return true;
    if (!Seen.insert(F).second || F->isDeclaration()) continue;
    for (Instruction &I : instructions(F))
      if (auto *C = dyn_cast<CallBase>(&I))
        if (Function *Next = C->getCalledFunction()) Work.push_back(Next);
  }
  return false;
}
}
json::Array fuseNativeFunctions(Module &M, uint64_t Seed, ArrayRef<std::string> Selected) {
  json::Array Report;
  unsigned Total = 0;
  for (Function &F : M) {
    if (unsafe(F) || (!Selected.empty() && !llvm::is_contained(Selected, F.getName().str()))) continue;
    unsigned Count = 0;
    // Rescan after each inline so a producer->consumer chain can become a
    // single protection region. No ABI rewriting of exported/address-taken code.
    for (unsigned Round = 0; Round < 8 && Total < 32; ++Round) {
      SmallVector<CallInst *, 16> Calls;
      for (Instruction &I : instructions(F))
        if (auto *C = dyn_cast<CallInst>(&I); C && !isa<IntrinsicInst>(C)) Calls.push_back(C);
      Rng R = Rng(Seed).fork("native-fusion-v1").fork(F.getName()).fork(Round);
      R.shuffle(MutableArrayRef(Calls));
      bool Changed = false;
      for (CallInst *C : Calls) {
        Function *G = C->getCalledFunction();
        std::string Reason;
        if (!G || G->isDeclaration()) Reason = "external-or-indirect";
        else if (!G->hasLocalLinkage() || G->hasAddressTaken()) Reason = "exported-or-address-taken";
        else if (unsafe(*G) || C->isMustTailCall() || C->hasOperandBundles()) Reason = "unsafe-call-structure";
        else if (reaches(G, &F)) Reason = "recursive-component";
        else if (G->getInstructionCount() > 500 || F.getInstructionCount() + G->getInstructionCount() > 2000)
          Reason = "instruction-budget";
        if (!Reason.empty()) {
          if (Round == 0) Report.push_back(json::Object{{"caller", F.getName().str()},
              {"callee", G ? G->getName().str() : ""}, {"status", "skipped"}, {"reason", Reason}});
          continue;
        }
        std::string Name = G->getName().str();
        InlineFunctionInfo IFI;
        InlineResult Result = InlineFunction(*C, IFI);
        if (!Result.isSuccess()) {
          Report.push_back(json::Object{{"caller", F.getName().str()}, {"callee", Name},
              {"status", "skipped"}, {"reason", Result.getFailureReason()}});
          continue;
        }
        Report.push_back(json::Object{{"caller", F.getName().str()}, {"callee", Name}, {"status", "fused"}});
        ++Count; ++Total; Changed = true; break;
      }
      if (!Changed) break;
    }
    if (Count) {
      // Explicit SSA preparation, not default<O2>. Escaping/aggregate storage
      // stays in memory for the separate closed-object representation pass.
      SmallVector<AllocaInst *, 16> Promotable;
      for (Instruction &I : F.getEntryBlock())
        if (auto *A = dyn_cast<AllocaInst>(&I); A && isAllocaPromotable(A)) Promotable.push_back(A);
      DominatorTree DT(F);
      PromoteMemToReg(Promotable, DT);
    }
  }
  bool Removed;
  do {
    Removed = false;
    for (Function &F : make_early_inc_range(M))
      if (F.hasLocalLinkage() && F.use_empty()) { F.eraseFromParent(); Removed = true; }
  } while (Removed);
  return Report;
}

json::Array absorbNativeSupport(Module &M) {
  json::Array Report;
  unsigned Total = 0;
  SmallVector<Function *, 16> Helpers;
  for (Function &F : M)
    if (F.getFnAttribute("sre.native.helper").getValueAsString() == "data-decoder") Helpers.push_back(&F);
  for (Function &F : M) {
    if (!F.hasFnAttribute("sre.native.original")) continue;
    SmallVector<CallInst *, 16> Calls;
    for (Instruction &I : instructions(F)) if (auto *C = dyn_cast<CallInst>(&I))
      if (llvm::is_contained(Helpers, C->getCalledFunction())) Calls.push_back(C);
    unsigned Count = 0;
    for (CallInst *C : Calls) {
      Function *H = C->getCalledFunction();
      std::string Reason;
      if (!H->hasLocalLinkage() || H->hasAddressTaken() || unsafe(*H) || C->isMustTailCall() || C->hasOperandBundles())
        Reason = "unsupported-helper-interface";
      else if (Count >= 16 || Total >= 128 || H->getInstructionCount() > 80 || F.getInstructionCount() + H->getInstructionCount() > 4000)
        Reason = "support-region-budget";
      std::string Name = H->getName().str();
      if (Reason.empty()) {
        InlineFunctionInfo IFI; auto Result = InlineFunction(*C, IFI);
        if (!Result.isSuccess()) Reason = Result.getFailureReason();
        else { ++Count; ++Total; }
      }
      Report.push_back(json::Object{{"caller", F.getName().str()}, {"helper", Name},
          {"status", Reason.empty() ? "absorbed" : "skipped"}, {"reason", Reason}});
    }
  }
  for (Function *H : Helpers) if (H->use_empty()) H->eraseFromParent();
  return Report;
}
}
