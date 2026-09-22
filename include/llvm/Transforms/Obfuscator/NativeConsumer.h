#pragma once
#include "llvm/IR/PassManager.h"
#include "llvm/Support/JSON.h"

namespace llvm::obf {
// Bounded exact equality preparation for two distinct closed stack byte arrays.
// This eliminates eligible scratch materialization, not public Boolean outputs.
json::Array integrateNativeExactConsumers(Module &, ModuleAnalysisManager &, unsigned GrowthBudget);
}
