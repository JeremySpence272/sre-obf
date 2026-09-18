#pragma once
#include "llvm/IR/Module.h"
#include "llvm/Support/JSON.h"
#include "llvm/Transforms/Obfuscator/NativeCall.h"

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
  // Prioritize already-encoded input/owned-memory consumers. Bounded atomic
  // producer/consumer units use the same function, shard and module caps.
  bool ContinuityPriority = false;
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
  // M1: build the private typed plan and publish it, with the M0 boundary
  // inventory, in each connected region row. Recording only: the plan observes
  // the decisions the planner already makes and emits no instruction, so the
  // protected IR is identical whether this is on or off.
  bool Plan = false;
  // M1: percent of the component cost limit held back from components that own
  // no encoded storage, so a coherent structural unit can still be afforded
  // after a cheap expression component. 0 reserves nothing and is exactly the
  // previous selection.
  unsigned StructuralReserve = 0;
};
// Absorbed, when given, receives the encoded-call pairs these regions
// consumed without a scalar decode, keyed by the interface that owns them.
json::Array encodeNativeConnected(Module &, uint64_t, const NativeConnectedOptions &,
                                  StringMap<NativeCallAbsorption> *Absorbed = nullptr);
json::Array absorbNativeSupport(Module &);
}
