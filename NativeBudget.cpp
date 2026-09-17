#include "llvm/Transforms/Obfuscator/NativeBudget.h"
#include "llvm/Transforms/Obfuscator.h"
#include "llvm/IR/InstIterator.h"

using namespace llvm;
namespace llvm::obf {
json::Array budgetNativeStructure(Module &M, ModuleAnalysisManager &AM,
                                 uint64_t Pool,
                                 ArrayRef<std::pair<Function *, unsigned>> Weights) {
  auto &Cache = AM.getResult<ObfuscationAnnotationAnalysis>(M);
  auto &FAM = AM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  SmallVector<std::pair<Function *, unsigned>, 64> Work;
  for (auto Item : Weights)
    if (Cache.getConfig(*Item.first).isPassEnabled("flattening")) Work.push_back(Item);
  // Favor source work per control block; a tie uses symbol order, never pointer
  // order. This has no program-specific names or knowledge of acceptance paths.
  llvm::sort(Work, [](const auto &A, const auto &B) {
    uint64_t Left = uint64_t(A.second) * (B.first->size() + 1);
    uint64_t Right = uint64_t(B.second) * (A.first->size() + 1);
    return Left != Right ? Left > Right : A.first->getName() < B.first->getName();
  });
  const uint64_t PerFunction = std::max<uint64_t>(2048, Pool / 8);
  json::Array Report;
  for (const auto &[F, Weight] : Work) {
    auto Saved = Cache.getConfig(*F);
    auto Only = Saved;
    llvm::erase_if(Only.passes, [](const PassConfig &P) { return P.passName != "flattening"; });
    llvm::erase_if(Saved.passes, [](const PassConfig &P) { return P.passName == "flattening"; });
    unsigned Before = F->getInstructionCount();
    uint64_t Grant = std::min(Pool, PerFunction);
    std::string Status = "structural-pool-exhausted";
    if (Grant >= 512 && F->size() >= 2) {
      Only.budgetMultiplier = 1000000;
      Only.budgetHardCap = Before + Grant;
      Cache.PerFunction[F] = std::move(Only);
      F->addFnAttr("sre.native.stage", "structural");
      FAM.invalidate(*F, PreservedAnalyses::none());
      auto PA = ObfuscationFunctionDriverPass().run(*F, FAM);
      FAM.invalidate(*F, PA);
      Status = "not-applied-or-rolled-back";
      for (Instruction &I : instructions(*F))
        if (isa<AllocaInst>(I) && I.getName() == "fla.state") Status = "applied";
    } else if (F->size() < 2) Status = "too-few-blocks";
    // No second attempt in the application stage. Unspent structural headroom
    // returns to the ordinary fair allocator; exact body caps remain enforced.
    Cache.PerFunction[F] = std::move(Saved);
    F->addFnAttr("sre.native.stage", "application");
    unsigned After = F->getInstructionCount();
    uint64_t Charge = After > Before ? After - Before : 0;
    if (Charge > Grant) report_fatal_error("native structural allocation exceeded its transaction");
    Pool -= Charge;
    Report.push_back(json::Object{{"function", F->getName().str()}, {"status", Status},
        {"source_weight", Weight}, {"instructions_before", Before}, {"instructions_after", After},
        {"growth_grant", Grant}, {"growth_charge", Charge}, {"remaining_pool", Pool}});
  }
  return Report;
}
}
