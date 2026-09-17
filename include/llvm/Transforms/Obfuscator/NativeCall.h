#pragma once
#include "llvm/ADT/StringMap.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/JSON.h"

namespace llvm::obf {
// P5 private encoded-call interfaces. A private callee stops taking plaintext
// scalars: each integer argument arrives as a pair (E, R) with x = E xor R,
// and an integer result leaves the same way. This moves the decode off the
// call boundary only when a later pass consumes the pair directly; on its own
// it MOVES the decode across the boundary rather than removing it.
struct NativeCallOptions { unsigned Functions = 32; };

// Pairs a later pass consumed without materializing a scalar, keyed by the
// encoded callee's symbol name. Zero everywhere until absorption runs.
struct NativeCallAbsorption { unsigned Arguments = 0, Results = 0; };

// The encoded twin of F is always named F + this suffix, so a report row and
// the function it describes can be matched without a side table.
constexpr StringLiteral NativeEncodedCallSuffix = ".sre.encoded";

json::Array encodeNativeCalls(Module &, uint64_t Seed, const NativeCallOptions &);
// Fold absorption measured by a later pass into this pass's own rows. Rows
// keep their zeros when nothing was absorbed.
void recordNativeCallAbsorption(json::Array &Rows,
                                const StringMap<NativeCallAbsorption> &Absorbed);
} // namespace llvm::obf
