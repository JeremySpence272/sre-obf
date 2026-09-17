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
  unsigned GrowthBudget = 0;
};
// Absorbed, when given, receives the encoded-call pairs these regions
// consumed without a scalar decode, keyed by the interface that owns them.
json::Array encodeNativeConnected(Module &, uint64_t, const NativeConnectedOptions &,
                                  StringMap<NativeCallAbsorption> *Absorbed = nullptr);
json::Array absorbNativeSupport(Module &);
}
