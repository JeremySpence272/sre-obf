#pragma once
#include "llvm/IR/Module.h"
#include "llvm/Support/JSON.h"

namespace llvm::obf {
struct NativeConnectedOptions {
  unsigned Nodes = 128;
  bool Memory = false;
  bool Predicates = false;
  bool Families = false;
  bool CoupleState = false;
  bool Invariant = false;
  bool BoundedGrowth = false;
  // Partition an oversized component into bounded shards under the same cost
  // limit instead of skipping it whole. The limit itself is never raised.
  bool Shards = false;
  // Admit bounded constant-index integer leaves of structs and nested arrays
  // as closed objects, after a precise use walk. Off, only the narrow scalar
  // and flat-array rule applies, exactly as before.
  bool Aggregates = false;
  // Couple two genuinely used encoded lanes into joint outputs U = X + Y and
  // V = X + 2Y, pinned, and recover X = 2U - V, Y = V - U. Lane arithmetic
  // only: no decoded scalar is ever created.
  bool JointOutputs = false;
  // P6: seed the per-activation encoded-data word from a live argument instead
  // of a constant when dispatcher transitions are keyed on it. 0 off, 1 on,
  // 2 stale-relation ablation.
  unsigned LaneTransitions = 0;
  unsigned GrowthBudget = 0;
};
json::Array encodeNativeConnected(Module &, uint64_t, const NativeConnectedOptions &);
json::Array absorbNativeSupport(Module &);
}
