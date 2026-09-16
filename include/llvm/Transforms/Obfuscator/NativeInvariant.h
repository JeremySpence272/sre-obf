#pragma once
#include "llvm/IR/IRBuilder.h"

namespace llvm::obf {
// Reachable relation W = rol(H,7)*(H|1)+C. This is software redundancy,
// not authentication or a secret key. Recovery by invariant inference is allowed.
inline Value *nativeWitness(IRBuilder<> &B, Value *H) {
  Value *Rotate = B.CreateOr(B.CreateShl(H, 7), B.CreateLShr(H, 25));
  return B.CreateAdd(B.CreateMul(Rotate, B.CreateOr(H, B.getInt32(1))), B.getInt32(0x9e3779b9));
}
inline Value *nativeResidual(IRBuilder<> &B, AllocaInst *H, AllocaInst *W) {
  auto *HL = B.CreateLoad(B.getInt32Ty(), H);
  auto *WL = B.CreateLoad(B.getInt32Ty(), W);
  HL->setVolatile(true); WL->setVolatile(true);
  Value *Residual = B.CreateSub(WL, nativeWitness(B, HL), "sre.invariant.residual");
  if (auto *I = dyn_cast<Instruction>(Residual))
    I->setMetadata("sre.native.invariant.use", MDNode::get(B.getContext(), {}));
  return Residual;
}
inline void storeNativeWitness(IRBuilder<> &B, AllocaInst *W, Value *H) {
  if (!W) return;
  auto *S = B.CreateStore(nativeWitness(B, H), W);
  S->setVolatile(true);
  S->setMetadata("sre.native.invariant.update", MDNode::get(B.getContext(), {}));
}
}
