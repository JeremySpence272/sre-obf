#pragma once

#include "llvm/IR/Constants.h"
#include "llvm/Transforms/Utils/Cloning.h"

namespace llvm::obf {

// Body-only transaction. A pass's newly created module objects need separate
// ownership; references to existing address-taken blocks must survive rollback.
class FunctionSnapshot {
  Function &Original;
  Function *Body;
  GlobalValue::LinkageTypes Linkage;
  bool DSOLocal;
  ValueToValueMapTy Forward;

public:
  explicit FunctionSnapshot(Function &F)
      : Original(F), Linkage(F.getLinkage()), DSOLocal(F.isDSOLocal()) {
    Body = CloneFunction(&F, Forward);
    Body->setLinkage(GlobalValue::InternalLinkage);
  }
  FunctionSnapshot(const FunctionSnapshot &) = delete;
  FunctionSnapshot &operator=(const FunctionSnapshot &) = delete;
  ~FunctionSnapshot() { Body->eraseFromParent(); }

  void restore() {
    // deleteBody replaces surviving blockaddress constants with inttoptr(1).
    // Move their uses (including global jump tables) onto the snapshot first.
    // Iterate live blocks: keys for instructions deleted by a pass can be
    // stale, and must not be dereferenced while consulting the clone map.
    for (BasicBlock &BB : Original) {
      if (!BB.hasAddressTaken()) continue;
      auto *Saved = dyn_cast_or_null<BasicBlock>(Forward.lookup(&BB));
      if (!Saved) continue;
      BlockAddress::get(&Original, &BB)->replaceAllUsesWith(
          BlockAddress::get(Body, Saved));
    }
    Original.deleteBody();
    Original.setLinkage(Linkage);
    ValueToValueMapTy Back;
    Back[Body] = &Original;
    for (unsigned I = 0; I < Original.arg_size(); ++I)
      Back[Body->getArg(I)] = Original.getArg(I);
    SmallVector<ReturnInst *, 8> Returns;
    CloneFunctionInto(&Original, Body, Back,
                      CloneFunctionChangeType::LocalChangesOnly, Returns);
    // Making the saved body internal also makes it dso_local. Cloning that
    // body back must not change preemption of the original exported symbol.
    Original.setDSOLocal(DSOLocal);
    Original.setAttributes(Body->getAttributes());
    for (BasicBlock &BB : *Body)
      if (BB.hasAddressTaken())
        BlockAddress::get(Body, &BB)->replaceAllUsesWith(
            BlockAddress::get(&Original, cast<BasicBlock>(Back.lookup(&BB))));
  }
};

} // namespace llvm::obf
