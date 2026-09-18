#pragma once
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/JSON.h"
#include "llvm/Transforms/Obfuscator/Rng.h"

namespace llvm::obf {
// Registry v1: exact modular bit-vector encodings, with no overflow flags.
// The same families serve scalar materialization and indexed array decoders.
enum class NativeFamily : unsigned { Xor, Add, RotateXor, MultiplyAdd };
NativeFamily nativeFamily(Rng &R);
const char *nativeFamilyName(NativeFamily F);
APInt encodeNative(const APInt &Plain, const APInt &Key, NativeFamily Family,
                   const APInt &Odd, unsigned Rotation);
Value *decodeNative(IRBuilder<> &B, Value *Encoded, Value *Key,
                    NativeFamily Family, const APInt &Odd, unsigned Rotation);
// nullptr means the explicit module/site budget was reached; callers retain
// their legacy representation and the native report records that fallback.
Value *materializeNative(IRBuilder<> &B, const APInt &Bits, Rng &Root,
                         StringRef Role, unsigned Site);
json::Array encodeNativeData(Module &M, uint64_t Seed, bool Joint = false,
                             bool Pin = true, unsigned GrowthBudget = 0);
// Capture stage-local scalar-use edges after bundle consumers have imported
// coordinates, before later scalar lowering can obscure that boundary count.
json::Array nativeImmutableContinuity(Module &M, StringRef Stage, bool EraseDead);
json::Object nativeEncodingInventory(Module &M);
} // namespace llvm::obf
