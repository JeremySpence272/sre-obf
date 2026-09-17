#pragma once

#include "llvm/ADT/ArrayRef.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/JSON.h"
#include <utility>

namespace llvm::obf {
// Reserve usable, transactional CFF shares before distributing expression
// headroom. The result records allocation, not inferred resistance.
json::Array budgetNativeStructure(Module &, ModuleAnalysisManager &, uint64_t,
                                 ArrayRef<std::pair<Function *, unsigned>>);
}
