#pragma once
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/JSON.h"
#include <string>
#include <vector>

namespace llvm::obf {
// P5 private encoded-call interfaces. A private callee stops taking plaintext
// scalars: each integer argument arrives as a pair (E, R) with x = E xor R,
// and an integer result leaves the same way. This moves the decode off the
// call boundary only when a later pass consumes the pair directly; on its own
// it MOVES the decode across the boundary rather than removing it.
struct NativeCallOptions { unsigned Functions = 32; bool SelfRecursion = false; };

// Pairs a later pass consumed without materializing a scalar, keyed by the
// encoded callee's symbol name. Zero everywhere until absorption runs.
struct NativeCallAbsorption {
  unsigned Arguments = 0, PartialArguments = 0, Results = 0;
};

// Preferred suffix; the report records the actual LLVM-uniquified symbol.
constexpr StringLiteral NativeEncodedCallSuffix = ".sre.encoded";

// W5 arbitration. Bounded merging, region fusion and encoded private calls all
// compete for the same internal functions, and merging runs first: it folds a
// helper into an i64-argument super-function, which erases the per-width
// interface and is routinely mutually recursive, so the call pass then refuses
// the same helper as `recursive`. This decides once, before either pass runs,
// which one owns each source-owned function, and records the decision instead
// of letting pass order settle it silently.
struct NativeCallPolicyOptions { unsigned Interfaces = 32; bool SelfRecursion = false; };

// The decision travels on the function, so each later pass reads one recorded
// fact instead of deriving a competing answer. Its value is the policy.
constexpr StringLiteral NativeCallPolicyAttr = "sre.native.policy";
// Policy vocabulary. Exactly one applies to each source-owned function.
constexpr StringLiteral NativeCallPolicyInterface = "encoded-interface";
constexpr StringLiteral NativeCallPolicyFused = "fused";
constexpr StringLiteral NativeCallPolicyScalar = "scalar-boundary";

// Runs before module preparation, while every function is still its source
// self. One row per source-owned function: a function neither pass takes is
// visible rather than absent.
json::Array planNativeCallPolicy(Module &, const NativeCallPolicyOptions &);
// Runs after merging and the call pass. Fills each row's observed outcome, so
// a policy that did not get what it chose is readable as such.
void reconcileNativeCallPolicy(Module &, json::Array &Policy, const json::Array &Calls);

// Region fusion settles a group's policy before merging or the call pass is
// consulted, by inlining a private function into its caller and erasing it. It
// records the inlined calls but not the disappearance, so a consumed function
// could previously only be found by differencing a whole-module inventory,
// which mis-attributes as soon as any other stage removes a function. These
// two attribute it to fusion alone: the names are captured immediately before
// fusion runs, and each absorption is credited from fusion's own per-call row.
std::vector<std::string> nativeFusionCandidates(const Module &);
json::Array nativeFusionAbsorption(ArrayRef<std::string> Before, const Module &After,
                                   const json::Array &Fused);

json::Array encodeNativeCalls(Module &, uint64_t Seed, const NativeCallOptions &);
// Fold absorption measured by a later pass into this pass's own rows. Rows
// keep their zeros when nothing was absorbed.
void recordNativeCallAbsorption(json::Array &Rows,
                                const StringMap<NativeCallAbsorption> &Absorbed);
// Inventory after bundle lowering, before the legacy consumer. The finalizer
// credits markers not already reconciled by a retained connected transaction.
json::Array nativeBundleCallInputs(const Module &);
void finishNativeBundleCallInputs(Module &, StringMap<NativeCallAbsorption> &);
} // namespace llvm::obf
