#pragma once
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/JSON.h"
namespace llvm::obf {
json::Object interpretNativeRegions(Module &, ModuleAnalysisManager &, unsigned, bool);
}
