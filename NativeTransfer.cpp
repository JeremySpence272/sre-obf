#include "llvm/Transforms/Obfuscator/NativeTransfer.h"

using namespace llvm;
namespace llvm::obf::transfer {
Pair bxor(IRBuilder<> &B, Pair X, Pair Y) {
  return {B.CreateXor(X.E, Y.E), B.CreateXor(X.R, Y.R)};
}
Pair band(IRBuilder<> &B, Pair X, Pair Y) {
  return {B.CreateXor(B.CreateXor(B.CreateAnd(X.E, Y.E), B.CreateAnd(X.E, Y.R)),
                       B.CreateAnd(X.R, Y.E)), B.CreateAnd(X.R, Y.R)};
}
Pair bor(IRBuilder<> &B, Pair X, Pair Y) { return bxor(B, bxor(B, X, Y), band(B, X, Y)); }
Pair bnot(IRBuilder<> &B, Pair X) { return {B.CreateNot(X.E), X.R}; }
Pair shl(IRBuilder<> &B, Pair X, unsigned D) { return {B.CreateShl(X.E, D), B.CreateShl(X.R, D)}; }
Pair lshr(IRBuilder<> &B, Pair X, unsigned D) { return {B.CreateLShr(X.E, D), B.CreateLShr(X.R, D)}; }
Pair cast(IRBuilder<> &B, Pair X, Type *T, bool Sign) {
  return {B.CreateIntCast(X.E, T, Sign), B.CreateIntCast(X.R, T, Sign)};
}
Pair add(IRBuilder<> &B, Pair X, Pair Y, bool CarryIn) {
  Pair P = bxor(B, X, Y), Original = P;
  unsigned W = X.E->getType()->getIntegerBitWidth();
  if (CarryIn) Original.E = B.CreateXor(Original.E, ConstantInt::get(X.E->getType(), 1));
  if (W == 1) return Original;
  Pair G = band(B, X, Y);
  if (CarryIn)
    G = bor(B, G, band(B, P, {ConstantInt::get(X.E->getType(), 1),
                              ConstantInt::get(X.E->getType(), 0)}));
  for (unsigned D = 1; D < W; D *= 2) {
    G = bor(B, G, band(B, P, shl(B, G, D)));
    if (D * 2 < W) P = band(B, P, shl(B, P, D));
  }
  return bxor(B, Original, shl(B, G, 1));
}
Pair toAdditive(IRBuilder<> &B, Pair X, Value *Mask) {
  Value *Both = B.CreateMul(B.CreateAnd(X.E, X.R), ConstantInt::get(Mask->getType(), 2));
  return {B.CreateSub(B.CreateAdd(B.CreateAdd(X.E, Mask), X.R), Both), Mask};
}
Pair toXor(IRBuilder<> &B, Pair X, Value *Mask) {
  // Each additive coordinate is independently shared before subtraction.
  Pair E{B.CreateXor(X.E, Mask), Mask};
  Pair R{B.CreateXor(X.R, B.CreateNot(Mask)), B.CreateNot(Mask)};
  return add(B, E, bnot(B, R), true);
}
Pair multiply(IRBuilder<> &B, Pair X, Pair Y, Value *Mask) {
  Value *Cross = B.CreateAdd(B.CreateMul(X.E, Y.R), B.CreateMul(Y.E, X.R));
  return {B.CreateAdd(B.CreateSub(B.CreateAdd(B.CreateMul(X.E, Y.E), Mask), Cross),
                      B.CreateMul(X.R, Y.R)), Mask};
}
Value *remask(IRBuilder<> &B, Pair X, Family F, Value *Mask) {
  return F == Family::Xor ? B.CreateXor(X.E, B.CreateXor(X.R, Mask))
                         : B.CreateSub(B.CreateAdd(X.E, Mask), X.R);
}
Pair operation(IRBuilder<> &B, unsigned Opcode, Pair X, Pair Y, Family F, Value *Mask) {
  if (F == Family::Additive) {
    if (Opcode == Instruction::Mul) return multiply(B, X, Y, Mask);
    if (Opcode == Instruction::Add || Opcode == Instruction::Sub) {
      auto Op = static_cast<Instruction::BinaryOps>(Opcode);
      return {B.CreateBinOp(Op, X.E, Y.E), B.CreateBinOp(Op, X.R, Y.R)};
    }
    Pair Z = operation(B, Opcode, toXor(B, X, Mask), toXor(B, Y, B.CreateNot(Mask)),
                       Family::Xor, Mask);
    return toAdditive(B, Z, Mask);
  }
  switch (Opcode) {
  case Instruction::Xor: return bxor(B, X, Y);
  case Instruction::And: return band(B, X, Y);
  case Instruction::Or: return bor(B, X, Y);
  case Instruction::Add: return add(B, X, Y);
  case Instruction::Sub: return add(B, X, bnot(B, Y), true);
  case Instruction::Mul:
    return toXor(B, multiply(B, toAdditive(B, X, Mask),
                            toAdditive(B, Y, B.CreateNot(Mask)), Mask), Mask);
  default: llvm_unreachable("unsupported native transfer");
  }
}
}
