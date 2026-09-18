#pragma once

#include "llvm/IR/Module.h"
#include "llvm/Support/JSON.h"
#include <cstdint>
#include <string>

namespace llvm::obf {
struct NativeBundleOptions {
  // Two descriptor-driven triangular families, or a seeded per-region choice.
  std::string Family = "seeded";
  unsigned Values = 4, Nodes = 16, GrowthBudget = 0;
  bool Pin = true;
  bool Loops = false, Phases = false;
};
// Stamp once, before fusion/merging; clones retain lineage, generated operations
// without lineage remain explicitly unknown. This does not count clones as new
// source operations or claim to recover source eliminated by frontend O2.
json::Array stampNativeBundleOrigins(Module &);
json::Array encodeNativeBundles(Module &, uint64_t, const NativeBundleOptions &);
}
