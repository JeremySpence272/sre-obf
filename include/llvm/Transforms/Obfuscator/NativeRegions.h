#pragma once
#include "llvm/IR/Module.h"
#include "llvm/Support/JSON.h"

namespace llvm::obf {
json::Array outlineNativeRegions(Module &M, uint64_t Seed);
json::Array encodeNativeValues(Module &M, uint64_t Seed, unsigned MaxNodes, bool CoupleState,
                               bool Wide = false, bool Invariant = false);
json::Array fuseNativeFunctions(Module &M, uint64_t Seed, ArrayRef<std::string> Selected);
json::Array encodeNativeMemory(Module &M, uint64_t Seed);
}
