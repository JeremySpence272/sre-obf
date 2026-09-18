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
  unsigned ObjectMaxCells = 4;
  unsigned ObjectRetainedGrowth = 65536;
  bool ObjectCalls = false;
  bool Pin = true;
  bool Loops = false, Phases = false;
  bool LoopBoundaries = false;
  bool ObjectPhases = false;
  bool CallInputs = false;
  bool CallOutputs = false;
  bool Predicates = false;
};
// Stamp once, before fusion/merging; clones retain lineage, generated operations
// without lineage remain explicitly unknown. This does not count clones as new
// source operations or claim to recover source eliminated by frontend O2.
json::Array stampNativeBundleOrigins(Module &);
json::Array encodeNativeBundles(Module &, uint64_t, const NativeBundleOptions &);
json::Array nativeBundlePredicateInventory(Module &);
// One closed, fully initialized local integer tile per function; four-cell
// default, explicit eight-cell shape experiment with the same growth caps.
// Shares the caller's bundle growth allowance; disabled by default in driver.
json::Array encodeNativeObjectBundles(Module &, uint64_t, const NativeBundleOptions &);
}
