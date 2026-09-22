#pragma once
#include "llvm/IR/Module.h"
#include "llvm/Support/JSON.h"
#include <cstdint>
#include <optional>

namespace llvm::obf {
// The caller explicitly supplies the single-thread/non-signal-reentry contract.
// No application RNG, debugger detection or environment seed override is used.
struct NativeRuntimeOptions {
  bool Phases = false;
  bool Buffers = false;
  unsigned GrowthBudget = 20000;
  std::optional<uint64_t> TestSeed;
  bool TestRollback = false;
};
json::Object encodeNativeRuntimeState(Module &, uint64_t, const NativeRuntimeOptions &);
// Separate, bounded semantics-preserving preparation; not retained-state coverage.
json::Array importNativeRuntimeGetters(Module &, unsigned MaxCalls);
}
