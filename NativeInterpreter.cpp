#include "llvm/Transforms/Obfuscator/NativeInterpreter.h"
#include "llvm/Transforms/Obfuscator/FunctionSnapshot.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/VMPass.h"
#include "llvm/Transforms/Obfuscator/VMPass_Impl.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Verifier.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <memory>
using namespace llvm;
namespace llvm::obf {
namespace {
unsigned count(const Module &M) {
  unsigned N = 0;
  for (const Function &F : M) N += F.getInstructionCount();
  return N;
}
bool word(Type *T) { return T->isIntegerTy(32) || T->isIntegerTy(64); }
bool eligible(Function &F) {
  if (!F.hasLocalLinkage() || F.hasAddressTaken() || F.isVarArg() ||
      F.size() != 1 || F.arg_size() > 4 || !word(F.getReturnType()) ||
      F.getInstructionCount() < 5 || F.getInstructionCount() > 64 ||
      F.hasPersonalityFn() || F.hasFnAttribute(Attribute::Naked) ||
      F.hasFnAttribute("sre.runtime.support")) return false;
  for (Argument &A : F.args()) if (!word(A.getType())) return false;
  for (Instruction &I : instructions(F)) {
    if (isa<ReturnInst>(I)) continue;
    if (!isa<BinaryOperator, ICmpInst, SelectInst, TruncInst, ZExtInst, SExtInst>(I)) return false;
    if (!word(I.getType()) && !I.getType()->isIntegerTy(1)) return false;
    for (Value *V : I.operands())
      if (!isa<Instruction, Argument, ConstantInt>(V) ||
          (!word(V->getType()) && !V->getType()->isIntegerTy(1))) return false;
  }
  return true;
}
}
json::Object interpretNativeRegions(Module &M, ModuleAnalysisManager &AM,
                                    unsigned Budget, bool ForceRollback) {
  json::Object Report{{"schema", "sre-selective-interpreter-v1"},
    {"status", "no-eligible-region"}, {"hardness_evaluated", false},
    {"complete_chain_claim", false}, {"anti_debug", false},
    {"contract", "private-single-block-i32-i64-pure-functions-max64-instructions-max4-arguments"},
    {"growth_budget", Budget}, {"bytecode_verifier", true},
    {"bytecode_encryption", false}, {"register_representation", "per-slot-xor-rolling"}};
  SmallVector<Function *, 4> Selected;
  json::Array Rows;
  for (Function &F : M) {
    if (!eligible(F)) continue;
    if (Selected.size() < 4 && Budget >= 8192) Selected.push_back(&F);
    else Rows.push_back(json::Object{{"function", F.getName().str()},
      {"status", "excluded"}, {"reason", "bounded-region-budget"}});
  }
  if (Selected.empty()) { Report["regions"] = std::move(Rows); return Report; }
  // All selected regions and their shared engine form one transaction. Never
  // leave an engine or dispatch table behind after restoring application bodies.
  unsigned Before = count(M), OriginalOps = 0;
  std::vector<std::unique_ptr<FunctionSnapshot>> Snapshots;
  for (Function *F : Selected) {
    OriginalOps += F->getInstructionCount();
    Snapshots.push_back(std::make_unique<FunctionSnapshot>(*F));
  }
  SmallPtrSet<GlobalValue *, 32> Existing;
  for (GlobalValue &G : M.global_values()) Existing.insert(&G);
  auto &Cache = AM.getResult<ObfuscationAnnotationAnalysis>(M);
  auto &FAM = AM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  // Explicit low-cost contract. No broad presets, timing reads, anti-debug,
  // opaque corruption, nested VM, mutable code, or entropy/global constructors.
  const char *Spec = "obf:vm(minBlocks=1,maxBlocks=1,encBytecode=0,encDispatch=1,"
    "regEncrypt=1,rollingRegKey=1,antiDebug=0,bindAntiDebug=0,hardened=0,"
    "nestedVM=0,nestedVMHardened=0,handlerVariants=1,handlerDecoys=0,"
    "randISA=1,enginePoolSize=1,perFnEngine=0,metamorphicEngines=0)";
  bool Failed = false;
  for (Function *F : Selected) {
    Cache.PerFunction[F] = AnnotationParser::parseAnnotationString(Spec);
    F->addFnAttr("sre.native.interpreter");
    FAM.invalidate(*F, PreservedAnalyses::none());
    auto PA = VMPass().run(*F, FAM);
    if (PA.areAllPreserved()) Failed = true;
    FAM.invalidate(*F, PreservedAnalyses::none());
    Cache.PerFunction.erase(F);
  }
  unsigned After = count(M);
  // Snapshot bodies are excluded from the retained growth accounting.
  int64_t Growth = int64_t(After) - Before - OriginalOps;
  bool Rollback = Failed || ForceRollback || Growth > Budget || verifyModule(M, &errs());
  VMEngine::releaseSharedState(M);
  SmallVector<GlobalValue *, 32> Created;
  for (GlobalValue &G : M.global_values()) if (!Existing.contains(&G)) Created.push_back(&G);
  if (Rollback) {
    for (auto &S : Snapshots) S->restore();
    for (GlobalValue *G : Created) {
      if (auto *F = dyn_cast<Function>(G)) FAM.clear(*F, F->getName());
      G->dropAllReferences();
    }
    for (GlobalValue *G : Created) G->eraseFromParent();
  } else {
    for (GlobalValue *G : Created) if (auto *F = dyn_cast<Function>(G)) {
      F->addFnAttr("sre.runtime.support");
      F->addFnAttr("sre.native.interpreter.support");
    }
    for (Function *F : Selected) F->addFnAttr("sre.runtime.support");
  }
  for (Function *F : Selected)
    Rows.push_back(json::Object{{"function", F->getName().str()},
      {"status", Rollback ? "rolled-back" : "interpreted"},
      {"reason", Rollback ? (ForceRollback ? "forced-test-rollback" : "growth-or-verifier-or-emitter") : ""}});
  Snapshots.clear();
  Report["status"] = Rollback ? "rolled-back" : "interpreted";
  Report["instructions_before"] = Before;
  Report["instructions_after"] = count(M);
  Report["original_instructions"] = Rollback ? 0 : OriginalOps;
  Report["regions"] = std::move(Rows);
  return Report;
}
}
