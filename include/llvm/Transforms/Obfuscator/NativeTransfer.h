#pragma once

#include "llvm/IR/IRBuilder.h"

namespace llvm::obf::transfer {
// Coordinates, not a decoded value. XOR: X = E xor R; additive: X = E - R.
struct Pair { Value *E = nullptr, *R = nullptr; };
enum class Family { Xor, Additive };

Pair bxor(IRBuilder<> &, Pair, Pair);
Pair band(IRBuilder<> &, Pair, Pair);
Pair bor(IRBuilder<> &, Pair, Pair);
Pair bnot(IRBuilder<> &, Pair);
Pair shl(IRBuilder<> &, Pair, unsigned);
Pair lshr(IRBuilder<> &, Pair, unsigned);
Pair cast(IRBuilder<> &, Pair, Type *, bool Sign = false);
Pair add(IRBuilder<> &, Pair, Pair, bool CarryIn = false);
// Mask must have the coordinate width. Neither conversion creates a decoded
// intermediate; an optimizer can still recover one by algebraic reasoning.
Pair toAdditive(IRBuilder<> &, Pair, Value *Mask);
Pair toXor(IRBuilder<> &, Pair, Value *Mask);
Pair multiply(IRBuilder<> &, Pair, Pair, Value *Mask);
Pair operation(IRBuilder<> &, unsigned Opcode, Pair, Pair, Family, Value *Mask);
Value *remask(IRBuilder<> &, Pair, Family, Value *Mask);
}
