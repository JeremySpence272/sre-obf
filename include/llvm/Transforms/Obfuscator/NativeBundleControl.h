#pragma once

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/JSON.h"

namespace llvm::obf {
constexpr StringLiteral NativeBundleControlState = "sre.native.bundle.control-state";
bool nativeBundleControl();
// A complete, closed, initialized recurrence group, not a copy of its values.
SmallVector<AllocaInst *, 4> bindNativeBundleControl(Function &);
json::Array nativeBundleControlInventory(Module &, const json::Array &);

inline void nativeBundleControlKeys(IRBuilder<> &B, Value *&Key, Value *&Salt,
                                    ArrayRef<AllocaInst *> Words, bool Dispatcher) {
  auto rotate = [&](Value *V, unsigned N) {
    return B.CreateOr(B.CreateShl(V, N), B.CreateLShr(V, 32 - N));
  };
  for (unsigned K = 0; K < Words.size(); ++K) {
    Type *T = Words[K]->getAllocatedType();
    auto *Load = B.CreateLoad(T, Words[K], Dispatcher ? "fla.bundle.dispatch.load" : "fla.bundle.edge.load");
    Load->setVolatile(true);
    Load->setMetadata("sre.native.bundle.control-read", MDNode::get(B.getContext(),
        MDString::get(B.getContext(), Dispatcher ? "dispatcher" : "transition")));
    Value *W = B.CreateZExtOrTrunc(Load, B.getInt32Ty());
    if (T->isIntegerTy(64))
      W = B.CreateXor(W, B.CreateTrunc(B.CreateLShr(Load, 32), B.getInt32Ty()));
    // One shared relation at both ends. No useful storage word is written by
    // control flow. These are recoverable encoded data, not secret entropy.
    Value *A = rotate(W, 5 + 7 * K);
    Key = B.CreateAdd(Key, B.CreateXor(A, B.getInt32(0x9e3779b9u * (K + 1))), "sre.bundle.control.key");
    Salt = B.CreateXor(Salt, B.CreateAdd(rotate(W, 3 + 5 * K),
        B.CreateMul(W, B.getInt32(0x85ebca6bu + 2 * K))), "sre.bundle.control.salt");
  }
}
}
