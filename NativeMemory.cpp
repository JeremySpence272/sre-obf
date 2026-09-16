#include "llvm/Transforms/Obfuscator/NativeRegions.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/Analysis/ValueTracking.h"

using namespace llvm;
namespace llvm::obf {
json::Array encodeNativeMemory(Module &M, uint64_t Seed) {
  json::Array Report;
  unsigned Total = 0;
  for (Function &F : M) {
    if (!F.hasFnAttribute("sre.native.original") || F.hasPersonalityFn() || F.isVarArg() ||
        F.getInstructionCount() > 12000) continue;
    // Normalize only small nonvolatile byte copies involving a local byte
    // object, before changing any object's representation. Read the complete
    // source first (also valid for overlap), then store: no raw memcpy remains
    // that would accidentally copy encoded bytes as if they were plaintext.
    SmallVector<MemCpyInst *, 8> Copies;
    for (Instruction &I : instructions(F))
      if (auto *C = dyn_cast<MemCpyInst>(&I)) {
        auto *Length = dyn_cast<ConstantInt>(C->getLength());
        auto LocalBytes = [](Value *P) {
          auto *A = dyn_cast<AllocaInst>(getUnderlyingObject(P));
          if (!A) return false;
          Type *T = A->getAllocatedType();
          if (auto *AT = dyn_cast<ArrayType>(T)) T = AT->getElementType();
          return T->isIntegerTy(8);
        };
        if (!C->isVolatile() && Length && Length->getValue().ule(64) &&
            (LocalBytes(C->getDest()) || LocalBytes(C->getSource())) && Copies.size() < 8) Copies.push_back(C);
      }
    for (auto *C : Copies) {
      IRBuilder<> B(C);
      unsigned Length = cast<ConstantInt>(C->getLength())->getZExtValue();
      SmallVector<Value *, 64> Bytes;
      for (unsigned I = 0; I < Length; ++I) {
        auto *L = B.CreateLoad(B.getInt8Ty(), B.CreateInBoundsGEP(B.getInt8Ty(), C->getSource(), B.getInt64(I)));
        L->setAlignment(Align(1)); Bytes.push_back(L);
      }
      for (unsigned I = 0; I < Length; ++I)
        B.CreateStore(Bytes[I], B.CreateInBoundsGEP(B.getInt8Ty(), C->getDest(), B.getInt64(I)))->setAlignment(Align(1));
      Report.push_back(json::Object{{"function", F.getName().str()}, {"status", "normalized-copy"}, {"bytes", Length}});
      C->eraseFromParent();
    }
    SmallVector<AllocaInst *, 16> Objects;
    for (Instruction &I : F.getEntryBlock())
      if (auto *A = dyn_cast<AllocaInst>(&I); A && !A->getMetadata("sre.native.value") &&
          !A->getMetadata("sre.native.context") && !A->getMetadata("sre.native.witness")) Objects.push_back(A);
    unsigned Count = 0;
    for (AllocaInst *A : Objects) {
      auto Skip = [&](StringRef Why) {
        Report.push_back(json::Object{{"function", F.getName().str()}, {"object", A->getName().str()},
                                      {"status", "skipped"}, {"reason", Why.str()}});
      };
      Type *T = A->getAllocatedType(), *Element = T;
      uint64_t N = 1;
      if (auto *AT = dyn_cast<ArrayType>(T)) { Element = AT->getElementType(); N = AT->getNumElements(); }
      if (!Element->isIntegerTy() || !llvm::is_contained(ArrayRef<unsigned>{8,16,32,64}, Element->getIntegerBitWidth()) ||
          !isa<ConstantInt>(A->getArraySize()) || !cast<ConstantInt>(A->getArraySize())->isOne() ||
          A->getAddressSpace() != 0 || N == 0 || N > 64) { Skip("unsupported-object-layout"); continue; }
      if (Count == 8 || Total == 64) { Skip("object-budget"); continue; }
      SmallVector<Value *, 16> Pointers{A};
      SmallVector<GetElementPtrInst *, 16> GEPs;
      SmallVector<LoadInst *, 16> Loads;
      SmallVector<StoreInst *, 16> Stores;
      SmallVector<Instruction *, 8> Lifetimes;
      bool Safe = true;
      for (unsigned J = 0; J < Pointers.size() && Safe; ++J)
        for (User *U : Pointers[J]->users()) {
          if (auto *G = dyn_cast<GetElementPtrInst>(U)) {
            // Preserve a closed graph of same-element offsets, including the
            // common array decay followed by scalar GEPs after inlining. On
            // defined executions inbounds keeps accesses within this object.
            if (!G->isInBounds() || (G->getSourceElementType() != T && G->getSourceElementType() != Element) ||
                (G->getResultElementType() != T && G->getResultElementType() != Element)) { Safe = false; break; }
            Pointers.push_back(G); GEPs.push_back(G);
          } else if (auto *L = dyn_cast<LoadInst>(U)) {
            if (L->getType() != Element || !L->isSimple()) { Safe = false; break; }
            Loads.push_back(L);
          } else if (auto *S = dyn_cast<StoreInst>(U)) {
            if (S->getPointerOperand() != Pointers[J] || S->getValueOperand()->getType() != Element || !S->isSimple()) {
              Safe = false; break;
            }
            Stores.push_back(S);
          } else if (auto *I = dyn_cast<IntrinsicInst>(U); I && I->isLifetimeStartOrEnd()) Lifetimes.push_back(I);
          else { Safe = false; break; }
        }
      if (!Safe || Loads.empty() || Stores.empty()) { Skip("escape-alias-or-unsupported-access"); continue; }
      Rng R = Rng(Seed).fork("native-memory-v1").fork(F.getName()).fork(Count);
      unsigned W = Element->getIntegerBitWidth();
      IRBuilder<> Entry(A);
      auto *E = Entry.CreateAlloca(T, nullptr, "sre.memory.encoded");
      auto *K = Entry.CreateAlloca(T, nullptr, "sre.memory.mask");
      E->setAlignment(A->getAlign()); K->setAlignment(A->getAlign());
      E->setMetadata("sre.native.memory", MDNode::get(M.getContext(), {}));
      K->setMetadata("sre.native.memory", MDNode::get(M.getContext(), {}));
      DenseMap<Value *, Value *> EP, KP;
      EP[A] = E; KP[A] = K;
      for (auto *G : GEPs) {
        IRBuilder<> B(G);
        SmallVector<Value *, 2> Indices(G->indices());
        EP[G] = B.CreateGEP(G->getSourceElementType(), EP.lookup(G->getPointerOperand()), Indices);
        KP[G] = B.CreateGEP(G->getSourceElementType(), KP.lookup(G->getPointerOperand()), Indices);
      }
      for (auto *S : Stores) {
        IRBuilder<> B(S);
        Value *X = B.CreateFreeze(S->getValueOperand());
        unsigned Shift = 1 + R.range(W - 1);
        Value *Mask = B.CreateXor(B.CreateOr(B.CreateShl(X, Shift), B.CreateLShr(X, W - Shift)),
            ConstantInt::get(M.getContext(), APInt(W, R.u64(), false, true)));
        auto *SE = B.CreateStore(B.CreateXor(X, Mask), EP[S->getPointerOperand()]);
        auto *SK = B.CreateStore(Mask, KP[S->getPointerOperand()]);
        SE->setAlignment(S->getAlign()); SK->setAlignment(S->getAlign());
        SE->setVolatile(true); SK->setVolatile(true);
        S->eraseFromParent();
      }
      for (auto *L : Loads) {
        IRBuilder<> B(L);
        auto *LE = B.CreateLoad(Element, EP[L->getPointerOperand()]);
        auto *LK = B.CreateLoad(Element, KP[L->getPointerOperand()]);
        LE->setAlignment(L->getAlign()); LK->setAlignment(L->getAlign());
        LE->setVolatile(true); LK->setVolatile(true);
        L->replaceAllUsesWith(B.CreateXor(LE, LK, "sre.memory.output"));
        L->eraseFromParent();
      }
      Report.push_back(json::Object{{"function", F.getName().str()}, {"object", A->getName().str()},
          {"status", "encoded"}, {"elements", N}, {"width", W}, {"loads", Loads.size()},
          {"stores", Stores.size()}, {"representation", "xor-two-lane-memory-v1"},
          {"load_decode_boundaries", Loads.size()}});
      for (Instruction *I : Lifetimes) I->eraseFromParent();
      for (auto *G : llvm::reverse(GEPs)) G->eraseFromParent();
      A->eraseFromParent();
      F.setMemoryEffects(MemoryEffects::unknown()); F.removeFnAttr(Attribute::Speculatable);
      ++Count; ++Total;
    }
  }
  return Report;
}
}
