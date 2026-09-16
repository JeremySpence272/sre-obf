#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {
// Explicit optimized-IR entry point. Does not alter the legacy auto-Clang hook.
class NativeObfuscationPass : public PassInfoMixin<NativeObfuscationPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
  static bool isRequired() { return true; }
};
} // namespace llvm
