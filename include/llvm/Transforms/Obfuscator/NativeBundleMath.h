#pragma once

#include "llvm/Transforms/Obfuscator/NativeTransfer.h"

namespace llvm::obf::bundle {
inline bool operationSupported(const Instruction &I) {
  if (!I.getType()->isIntegerTy()) return false;
  unsigned W = I.getType()->getIntegerBitWidth();
  if (W != 8 && W != 16 && W != 32 && W != 64) return false;
  switch (I.getOpcode()) {
  case Instruction::Add: case Instruction::Sub: case Instruction::Mul:
  case Instruction::And: case Instruction::Or: case Instruction::Xor: return true;
  case Instruction::Shl: case Instruction::LShr: case Instruction::AShr: {
    auto *C = dyn_cast<ConstantInt>(I.getOperand(1));
    return C && C->getValue().ult(W);
  }
  default: return false;
  }
}
inline Value *rotate(IRBuilder<> &B, Value *X, unsigned R) {
  unsigned W = X->getType()->getIntegerBitWidth();
  return B.CreateOr(B.CreateShl(X, R), B.CreateLShr(X, W - R));
}
inline Value *mask(IRBuilder<> &B, ArrayRef<Value *> Z, Value *M,
                   unsigned K, uint64_t Salt, unsigned Rotation) {
  auto C = [&](uint64_t X) { return ConstantInt::get(M->getType(), X); };
  Value *A = K ? Z[K - 1] : M;
  Value *T = B.CreateAdd(B.CreateXor(A, C(Salt)), M);
  return B.CreateXor(rotate(B, T, Rotation), B.CreateMul(A, C(Salt | 1)));
}
inline transfer::Pair operation(IRBuilder<> &B, unsigned Opcode,
                                transfer::Pair X, transfer::Pair Y,
                                transfer::Family Family, Value *Fresh) {
  if (Opcode != Instruction::Shl && Opcode != Instruction::LShr && Opcode != Instruction::AShr)
    return transfer::operation(B, Opcode, X, Y, Family, Fresh);
  if (Family == transfer::Family::Additive) X = transfer::toXor(B, X, Fresh);
  auto Op = static_cast<Instruction::BinaryOps>(Opcode);
  transfer::Pair Out{B.CreateBinOp(Op, X.E, Y.E), B.CreateBinOp(Op, X.R, Y.E)};
  if (Family == transfer::Family::Additive) Out = transfer::toAdditive(B, Out, Fresh);
  return Out;
}
}
