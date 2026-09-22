#include "llvm/Transforms/Obfuscator/NativeRuntime.h"
#include "llvm/Transforms/Obfuscator/NativeBundleMath.h"
#include "llvm/Transforms/Obfuscator/FunctionSnapshot.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Operator.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <memory>
#include <functional>
#include <algorithm>

using namespace llvm;
namespace llvm::obf {
namespace {
using transfer::Pair;
constexpr StringLiteral Tag = "sre.native.bundle";
unsigned count(const Module &M) {
  unsigned N = 0;
  for (const Function &F : M) if (!F.isDeclaration()) N += F.getInstructionCount();
  return N;
}
bool width(Type *T) {
  return T->isIntegerTy(8) || T->isIntegerTy(16) ||
         T->isIntegerTy(32) || T->isIntegerTy(64);
}
bool supported(const Instruction &I) {
  if (bundle::operationSupported(I)) return true;
  if (isa<TruncInst, ZExtInst, SExtInst>(I))
    return width(I.getType()) && width(I.getOperand(0)->getType());
  if (auto *C = dyn_cast<ICmpInst>(&I))
    return C->isEquality() && width(C->getOperand(0)->getType());
  return isa<SelectInst>(I) && width(I.getType());
}
unsigned cost(const Instruction &I) {
  switch (I.getOpcode()) {
  case Instruction::Mul: return 400;
  case Instruction::Add: case Instruction::Sub: return 300;
  default: return 16;
  }
}
struct Object {
  GlobalVariable *Data = nullptr, *Mask = nullptr;
  Constant *Initial = nullptr;
  uint64_t Salt = 0;
  Type *Element = nullptr;
  unsigned Cells = 1;
  SmallVector<MemSetInst *, 4> Resets;
  SmallVector<LoadInst *, 16> Loads;
  SmallVector<StoreInst *, 16> Stores;
  std::string Reason;
};

bool inspect(Object &O) {
  GlobalVariable &G = *O.Data;
  auto fail = [&](StringRef Why) { O.Reason = Why.str(); return false; };
  if (!G.hasLocalLinkage()) return fail("external-storage");
  if (G.isThreadLocal() || G.getAddressSpace() || G.isExternallyInitialized())
    return fail("unsupported-storage-lifetime");
  O.Element = G.getValueType();
  if (auto *A = dyn_cast<ArrayType>(O.Element)) {
    O.Cells = A->getNumElements();
    O.Element = A->getElementType();
    for (unsigned I = 0; I < O.Cells; ++I)
      if (!isa_and_nonnull<ConstantInt>(G.getInitializer()->getAggregateElement(I)))
        return fail("unsupported-initializer");
  } else if (!isa<ConstantInt>(G.getInitializer())) return fail("unsupported-initializer");
  SmallVector<Value *, 16> Pointers{&G};
  for (unsigned PI = 0; PI < Pointers.size(); ++PI) {
   Value *P = Pointers[PI];
   for (User *U : P->users()) {
    if (auto *GEP = dyn_cast<GEPOperator>(U)) {
      // A single inbounds [0,index] step preserves allocation provenance. A
      // defined original element access proves index in [0,Cells), including
      // dynamic indices; no unchecked index is used to access another object.
      bool ArrayStep = GEP->getSourceElementType() == G.getValueType() &&
          GEP->getNumIndices() == 2 && isa<ConstantInt>(GEP->getOperand(1)) &&
          cast<ConstantInt>(GEP->getOperand(1))->isZero();
      bool ElementStep = GEP->getSourceElementType() == O.Element && GEP->getNumIndices() == 1;
      if (P != &G || O.Cells == 1 || !GEP->isInBounds() || (!ArrayStep && !ElementStep))
        return fail("unsupported-buffer-index");
      Pointers.push_back(cast<Value>(U));
      continue;
    }
    auto *UseInstruction = dyn_cast<Instruction>(U);
    if (!UseInstruction) return fail("unmodeled-pointer-use");
    Function &F = *UseInstruction->getFunction();
    if (F.hasPersonalityFn() || F.hasFnAttribute(Attribute::Naked) ||
        F.hasFnAttribute(Attribute::ReturnsTwice))
      return fail("unsupported-owner");
    for (const Instruction &I : instructions(F))
      if (auto *Call = dyn_cast<CallBase>(&I);
          Call && (Call->isInlineAsm() || Call->hasFnAttr(Attribute::ReturnsTwice)))
        return fail("unsupported-owner");
    if (auto *Reset = dyn_cast<MemSetInst>(U)) {
      auto *Length = dyn_cast<ConstantInt>(Reset->getLength());
      if (P != &G || !O.Element->isIntegerTy(8) || Reset->isVolatile() ||
          Reset->getRawDest() != P || !Length || Length->getZExtValue() != O.Cells)
        return fail("unsupported-buffer-reset");
      O.Resets.push_back(Reset);
    } else if (auto *L = dyn_cast<LoadInst>(U)) {
      if (L->getPointerOperand() != P || L->isAtomic() || L->isVolatile() || L->getType() != O.Element)
        return fail("unsupported-load");
      O.Loads.push_back(L);
    } else if (auto *S = dyn_cast<StoreInst>(U)) {
      if (S->getPointerOperand() != P || S->isAtomic() || S->isVolatile() ||
          S->getValueOperand()->getType() != O.Element)
        return fail("unsupported-store");
      O.Stores.push_back(S);
    } else return fail("unmodeled-pointer-use");
  }
  }
  if (O.Loads.empty() || (O.Stores.empty() && O.Resets.empty())) return fail("not-recurrent-storage");
  return true;
}

Value *project(IRBuilder<> &B, Pair P) {
  if (auto *C = dyn_cast<ConstantInt>(P.R); C && C->isZero()) return P.E;
  return B.CreateXor(P.E, P.R, "runtime.public");
}
std::string origin(const Instruction &I) {
  if (auto *MD = I.getMetadata("sre.native.input-origin"))
    if (MD->getNumOperands() == 1)
      if (auto *S = dyn_cast<MDString>(MD->getOperand(0))) return S->getString().str();
  return "";
}
StringRef boundary(const Instruction *I) {
  if (!I) return "unknown-use";
  if (isa<ReturnInst>(I)) return "return";
  if (isa<PHINode>(I)) return "unrepresented-phi";
  if (isa<StoreInst>(I)) return "unrepresented-store";
  if (auto *Call = dyn_cast<CallBase>(I)) {
    auto *F = Call->getCalledFunction();
    return F && F->hasLocalLinkage() ? "private-call" : "external-or-indirect-call";
  }
  return "unsupported-operation";
}
Value *cellPointer(IRBuilder<> &B, Object &O, GlobalVariable *G, unsigned I) {
  return O.Cells == 1 ? static_cast<Value *>(G) :
      B.CreateInBoundsGEP(G->getValueType(), G, {B.getInt64(0), B.getInt64(I)});
}
Value *maskPointer(IRBuilder<> &B, Object &O, Value *P) {
  if (P == O.Data) return O.Mask;
  auto *GEP = cast<GEPOperator>(P);
  SmallVector<Value *, 2> Indices(GEP->indices());
  return B.CreateInBoundsGEP(GEP->getSourceElementType(), O.Mask, Indices);
}
LoadInst *load(IRBuilder<> &B, Type *T, Value *P) {
  auto *L = B.CreateLoad(T, P);
  L->setVolatile(true);
  L->setAlignment(Align(1));
  return L;
}
void store(IRBuilder<> &B, Value *V, Value *P) {
  auto *S = B.CreateStore(V, P);
  S->setVolatile(true);
  S->setAlignment(Align(1));
}

}

json::Array importNativeRuntimeGetters(Module &M, unsigned MaxCalls) {
  json::Array Rows;
  SmallVector<Function *, 32> Getters;
  for (Function &F : M) {
    if (!F.hasLocalLinkage() || F.hasAddressTaken() || F.size() != 1 ||
        !F.arg_empty() || F.getInstructionCount() != 2 ||
        F.hasPersonalityFn() || F.hasFnAttribute(Attribute::Convergent) ||
        F.hasFnAttribute(Attribute::NoDuplicate) || F.hasFnAttribute(Attribute::Naked) ||
        F.hasFnAttribute("sre.runtime.support")) continue;
    auto *L = dyn_cast<LoadInst>(&F.front().front());
    auto *Ret = dyn_cast<ReturnInst>(F.front().getTerminator());
    auto *G = L ? dyn_cast<GlobalVariable>(L->getPointerOperand()) : nullptr;
    if (L && Ret && Ret->getReturnValue() == L && !L->isVolatile() && !L->isAtomic() &&
        width(L->getType()) && G && G->hasLocalLinkage() && !G->isThreadLocal())
      Getters.push_back(&F);
  }
  unsigned Used = 0;
  for (Function *F : Getters) {
    SmallVector<CallInst *, 16> Calls;
    for (User *U : F->users())
      if (auto *Call = dyn_cast<CallInst>(U); Call && Call->getCalledFunction() == F)
        Calls.push_back(Call);
    std::string Name = F->getName().str();
    for (CallInst *Call : Calls) {
      json::Object Row{{"callee", Name}, {"caller", Call->getFunction()->getName().str()}};
      if (Used >= MaxCalls || Call->isMustTailCall() || Call->hasOperandBundles()) {
        Row["status"] = "excluded";
        Row["reason"] = Used >= MaxCalls ? "preparation-call-budget" : "unsupported-call-contract";
      } else {
        InlineFunctionInfo Info;
        auto Result = InlineFunction(*Call, Info);
        Row["status"] = Result.isSuccess() ? "imported" : "excluded";
        Row["reason"] = Result.isSuccess() ? "" : Result.getFailureReason();
        if (Result.isSuccess()) ++Used;
      }
      Rows.push_back(std::move(Row));
    }
    if (F->use_empty()) F->eraseFromParent();
  }
  return Rows;
}

json::Object encodeNativeRuntimeState(Module &M, uint64_t Seed, const NativeRuntimeOptions &Opts) {
  json::Object Report{{"schema", "sre-runtime-state-v1"}, {"status", "no-eligible-storage"},
    {"contract", "private-integer-globals-single-thread-no-signal-reentry"},
    {"phases", Opts.Phases}, {"test_context", bool(Opts.TestSeed)},
    {"test_rollback", Opts.TestRollback},
    {"hardness_evaluated", false}, {"complete_chain_claim", false}};
  json::Array Rows;
  std::vector<Object> Objects;
  for (GlobalVariable &G : M.globals()) {
    if (G.isDeclaration() || G.isConstant() || G.getName().starts_with("llvm.")) continue;
    Object O;
    O.Data = &G;
    auto *Array = dyn_cast<ArrayType>(G.getValueType());
    bool Buffer = Opts.Buffers && Array && Array->getNumElements() >= 2 &&
                  Array->getNumElements() <= 64 && width(Array->getElementType());
    if (!width(G.getValueType()) && !Buffer) {
      Rows.push_back(json::Object{{"object", G.getName().str()}, {"status", "excluded"},
                                 {"reason", "unsupported-aggregate-or-width"}});
      continue;
    }
    if (!inspect(O)) {
      Rows.push_back(json::Object{{"object", G.getName().str()}, {"status", "excluded"},
                                 {"reason", O.Reason}});
      continue;
    }
    O.Initial = G.getInitializer();
    O.Salt = mix64(Seed ^ fnv1a64(G.getName()) ^ 0x72756e74696d6531ULL);
    Objects.push_back(std::move(O));
  }
  // Constructor ordering and runtime symbol ownership are part of the contract,
  // not guessed. In particular a user's definition cannot supply our entropy.
  std::string Blocker;
  if (M.getNamedGlobal("llvm.global_ctors")) Blocker = "existing-constructor-order";
  if (!M.getModuleInlineAsm().empty()) Blocker = "module-inline-assembly";
  for (StringRef Name : {"getentropy", "_exit"})
    if (auto *G = M.getNamedValue(Name)) {
      auto *F = dyn_cast<Function>(G);
      auto &C = M.getContext();
      auto *Expected = Name == "_exit"
          ? FunctionType::get(Type::getVoidTy(C), {Type::getInt32Ty(C)}, false)
          : FunctionType::get(Type::getInt32Ty(C),
              {PointerType::getUnqual(C), Type::getInt64Ty(C)}, false);
      if (!F || !F->isDeclaration() || F->getFunctionType() != Expected ||
          F->getCallingConv() != CallingConv::C)
        Blocker = "runtime-symbol-collision";
    }
  if (Objects.empty() || !Blocker.empty()) {
    for (Object &O : Objects)
      Rows.push_back(json::Object{{"object", O.Data->getName().str()}, {"status", "excluded"},
                                 {"reason", Blocker}});
    Report["objects"] = std::move(Rows);
    return Report;
  }

  SmallPtrSet<Instruction *, 32> Nodes, Stores;
  SmallPtrSet<Function *, 32> Owners;
  SmallVector<Instruction *, 128> Work;
  // Forward closure is explicitly bounded. PHIs, variable shifts, unknown calls
  // and non-equality predicates are public scalar exits in this first contract.
  // Whole buffers need a complete reservation before small scalar objects can
  // consume the allowance. Stable ordering keeps ties deterministic.
  std::stable_sort(Objects.begin(), Objects.end(), [](const Object &A, const Object &B) {
    return A.Cells > B.Cells;
  });
  unsigned Reserved = 32;
  std::vector<Object> Selected;
  for (Object &O : Objects) {
    SmallVector<Instruction *, 64> Candidate;
    SmallPtrSet<Instruction *, 32> Seen;
    for (LoadInst *L : O.Loads)
      if (Seen.insert(L).second) Candidate.push_back(L);
    for (unsigned Index = 0; Index < Candidate.size() && Candidate.size() <= 1024; ++Index)
      for (User *U : Candidate[Index]->users()) {
        auto *I = dyn_cast<Instruction>(U);
        if (I && supported(*I) && Seen.insert(I).second) Candidate.push_back(I);
      }
    uint64_t Additional = O.Stores.size() * 16 + O.Cells * (16 + 16 * O.Resets.size());
    for (Instruction *I : Candidate) if (!Nodes.contains(I)) Additional += cost(*I);
    if (Candidate.size() > 1024 || Additional + Reserved > Opts.GrowthBudget) {
      Rows.push_back(json::Object{{"object", O.Data->getName().str()}, {"status", "excluded"},
                                 {"reason", "growth-reservation"}});
      continue;
    }
    Reserved += Additional;
    for (Instruction *I : Candidate) if (Nodes.insert(I).second) Work.push_back(I);
    for (LoadInst *L : O.Loads) Owners.insert(L->getFunction());
    for (StoreInst *S : O.Stores) { Stores.insert(S); Owners.insert(S->getFunction()); }
    for (MemSetInst *R : O.Resets) Owners.insert(R->getFunction());
    Selected.push_back(std::move(O));
  }
  Objects = std::move(Selected);
  unsigned Before = count(M);
  if (Objects.empty()) {
    Report["objects"] = std::move(Rows);
    Report["instructions_before"] = Before;
    return Report;
  }
  Report["reserved_growth"] = Reserved;
  // Snapshot every participating body before creating support objects. The
  // precomputed bindings never accidentally include the snapshots' own uses.
  std::vector<std::unique_ptr<FunctionSnapshot>> Snapshots;
  unsigned BodyBefore = 0;
  for (Function *F : Owners) BodyBefore += F->getInstructionCount();
  for (Function *F : Owners) Snapshots.push_back(std::make_unique<FunctionSnapshot>(*F));
  SmallPtrSet<Instruction *, 32> Original;
  for (Function *F : Owners) for (Instruction &I : instructions(F)) Original.insert(&I);
  LLVMContext &C = M.getContext();
  auto *I64 = Type::getInt64Ty(C);
  auto *I32 = Type::getInt32Ty(C);
  auto *Ptr = PointerType::getUnqual(C);
  bool NewEntropy = !M.getNamedValue("getentropy"), NewExit = !M.getNamedValue("_exit");
  FunctionCallee Entropy = M.getOrInsertFunction("getentropy", I32, Ptr, I64);
  FunctionCallee Exit = M.getOrInsertFunction("_exit", Type::getVoidTy(C), I32);
  auto *Init = Function::Create(FunctionType::get(Type::getVoidTy(C), false),
                                GlobalValue::InternalLinkage, "__sre_runtime_init", M);
  Init->addFnAttr("sre.runtime.support");
  Init->addFnAttr(Attribute::NoInline);
  auto *Entry = BasicBlock::Create(C, "entry", Init);
  auto *Good = BasicBlock::Create(C, "ready", Init);
  auto *Bad = BasicBlock::Create(C, "entropy_failure", Init);
  IRBuilder<> B(Entry);
  Value *Nonce;
  if (Opts.TestSeed) {
    Nonce = B.getInt64(*Opts.TestSeed);
    B.CreateBr(Good);
  } else {
    auto *Slot = B.CreateAlloca(I64);
    Value *Code = B.CreateCall(Entropy, {Slot, B.getInt64(8)});
    B.CreateCondBr(B.CreateICmpEQ(Code, B.getInt32(0)), Good, Bad);
    B.SetInsertPoint(Good);
    Nonce = B.CreateLoad(I64, Slot);
  }
  B.SetInsertPoint(Bad);
  // A documented nonzero process exit works even in hosts that restrict signal
  // delivery. No fallback to a predictable context or silently altered output.
  B.CreateCall(Exit, {B.getInt32(78)});
  B.CreateUnreachable();
  B.SetInsertPoint(Good);
  for (Object &O : Objects) {
    auto *T = O.Data->getValueType();
    O.Mask = new GlobalVariable(M, T, false, GlobalValue::InternalLinkage,
                                Constant::getNullValue(T), O.Data->getName() + ".runtime.mask");
    for (unsigned I = 0; I < O.Cells; ++I) {
      Value *K = B.CreateTruncOrBitCast(B.CreateXor(Nonce, B.getInt64(mix64(O.Salt + I))), O.Element);
      Constant *Initial = O.Cells == 1 ? O.Initial : O.Initial->getAggregateElement(I);
      store(B, K, cellPointer(B, O, O.Mask, I));
      store(B, B.CreateXor(Initial, K), cellPointer(B, O, O.Data, I));
    }
  }
  B.CreateRetVoid();
  appendToGlobalCtors(M, Init, 0);

  DenseMap<Value *, Pair> Pairs;
  for (Object &O : Objects)
    for (LoadInst *L : O.Loads) {
      IRBuilder<> At(L);
      Pairs[L] = {load(At, O.Element, L->getPointerOperand()),
                  load(At, O.Element, maskPointer(At, O, L->getPointerOperand()))};
    }
  std::function<Pair(Value *)> lower = [&](Value *V) -> Pair {
    if (auto It = Pairs.find(V); It != Pairs.end()) return It->second;
    auto *I = dyn_cast<Instruction>(V);
    if (!I || !Nodes.contains(I)) return {V, ConstantInt::get(V->getType(), 0)};
    IRBuilder<> At(I);
    Pair Out;
    if (auto *Cmp = dyn_cast<ICmpInst>(I)) {
      Pair X = lower(I->getOperand(0)), Y = lower(I->getOperand(1));
      Out = {At.CreateICmp(Cmp->getPredicate(), At.CreateXor(X.E, Y.E), At.CreateXor(X.R, Y.R)),
             At.getInt1(false)};
    } else if (auto *Select = dyn_cast<SelectInst>(I)) {
      Pair X = lower(Select->getTrueValue()), Y = lower(Select->getFalseValue());
      Out = {At.CreateSelect(Select->getCondition(), X.E, Y.E),
             At.CreateSelect(Select->getCondition(), X.R, Y.R)};
    } else if (isa<CastInst>(I)) {
      Out = transfer::cast(At, lower(I->getOperand(0)), I->getType(), isa<SExtInst>(I));
    } else {
      Pair X = lower(I->getOperand(0)), Y = lower(I->getOperand(1));
      Out = bundle::operation(At, I->getOpcode(), X, Y, transfer::Family::Xor, X.R);
    }
    Pairs[V] = Out;
    return Out;
  };
  for (Instruction *I : Work) lower(I);
  for (Object &O : Objects)
    for (StoreInst *S : O.Stores) {
      IRBuilder<> At(S);
      Value *MP = maskPointer(At, O, S->getPointerOperand());
      Value *K = load(At, O.Element, MP);
      if (Opts.Phases)
        K = At.CreateAdd(At.CreateMul(K, ConstantInt::get(K->getType(), O.Salt | 1)),
                          ConstantInt::get(K->getType(), (O.Salt >> 32) | 1));
      Pair V = lower(S->getValueOperand());
      store(At, transfer::remask(At, V, transfer::Family::Xor, K), S->getPointerOperand());
      if (Opts.Phases) store(At, K, MP);
    }
  for (Object &O : Objects) for (MemSetInst *R : O.Resets) {
    IRBuilder<> At(R);
    for (unsigned I = 0; I < O.Cells; ++I) {
      Value *MP = cellPointer(At, O, O.Mask, I);
      Value *K = load(At, O.Element, MP);
      if (Opts.Phases) {
        K = At.CreateAdd(At.CreateMul(K, ConstantInt::get(O.Element, O.Salt | 1)),
                         ConstantInt::get(O.Element, (O.Salt >> 32) | 1));
        store(At, K, MP);
      }
      store(At, At.CreateXor(R->getValue(), K), cellPointer(At, O, O.Data, I));
    }
    R->eraseFromParent();
  }
  unsigned Exits = 0, Predicates = 0, SourceOperations = Work.size();
  json::Array Boundaries, Operations;
  for (Instruction *I : Work) {
    Operations.push_back(json::Object{{"function", I->getFunction()->getName().str()},
        {"origin", origin(*I)}, {"opcode", I->getOpcodeName()}});
    Value *Public = nullptr;
    for (Use &U : make_early_inc_range(I->uses())) {
      auto *Consumer = dyn_cast<Instruction>(U.getUser());
      if (Consumer && (Nodes.contains(Consumer) || Stores.contains(Consumer))) continue;
      if (!Public) {
        IRBuilder<> At(I);
        Public = project(At, Pairs.lookup(I));
      }
      U.set(Public);
      if (!isa<ICmpInst>(I)) {
        ++Exits;
        Boundaries.push_back(json::Object{{"function", I->getFunction()->getName().str()},
            {"origin", origin(*I)}, {"reason", boundary(Consumer).str()},
            {"consumer", Consumer ? Consumer->getOpcodeName() : "unknown"}});
      }
    }
    if (isa<ICmpInst>(I)) ++Predicates;
  }
  for (Object &O : Objects) for (StoreInst *S : O.Stores) S->eraseFromParent();
  for (Instruction *I : Work) I->dropAllReferences();
  for (Instruction *I : Work) I->eraseFromParent();
  for (Function *F : Owners) {
    F->setMemoryEffects(MemoryEffects::unknown());
    F->removeFnAttr(Attribute::Speculatable);
    for (Instruction &I : instructions(F))
      if (!Original.contains(&I)) {
        I.setMetadata(Tag, MDNode::get(C, {}));
        I.setMetadata("sre.runtime.state", MDNode::get(C, {}));
      }
  }
  // Destroying snapshots first would prevent rollback. Calculate retained growth
  // from the actual participating bodies and support rather than module totals.
  unsigned RetainedGrowth = Init->getInstructionCount();
  int64_t BodyDelta = -int64_t(BodyBefore);
  for (Function *F : Owners) BodyDelta += F->getInstructionCount();
  RetainedGrowth += BodyDelta > 0 ? unsigned(BodyDelta) : 0;
  bool Invalid = verifyModule(M, &errs());
  bool Rollback = RetainedGrowth > Opts.GrowthBudget || Invalid || Opts.TestRollback;
  if (Rollback) {
    for (auto &Snapshot : Snapshots) Snapshot->restore();
    M.getNamedGlobal("llvm.global_ctors")->eraseFromParent();
    Init->eraseFromParent();
    for (Object &O : Objects) { O.Data->setInitializer(O.Initial); O.Mask->eraseFromParent(); }
    if (NewEntropy) cast<Function>(Entropy.getCallee())->eraseFromParent();
    if (NewExit) cast<Function>(Exit.getCallee())->eraseFromParent();
  }
  for (Object &O : Objects)
    Rows.push_back(json::Object{{"object", O.Data->getName().str()},
      {"status", Rollback ? "rolled-back" : "encoded"},
      {"reason", Rollback ? (Opts.TestRollback ? "forced-test-rollback" : "growth-or-verifier") : ""},
      {"width", O.Element->getIntegerBitWidth()}, {"cells", O.Cells},
      {"bounds_contract", O.Cells == 1 ? "scalar" : "defined-inbounds-element-access"},
      {"source_loads", O.Loads.size()}, {"source_resets", O.Resets.size()},
      {"source_stores", O.Stores.size() + O.Resets.size()}, {"phase", Opts.Phases ? "per-store" : "startup-only"}});
  Snapshots.clear();
  Report["status"] = Rollback ? "rolled-back" : "encoded";
  Report["objects"] = std::move(Rows);
  Report["instructions_before"] = Before;
  Report["instructions_after"] = count(M);
  Report["growth_budget"] = Opts.GrowthBudget;
  Report["retained_operations"] = Rollback ? 0 : SourceOperations;
  Report["scalar_exit_uses"] = Rollback ? 0 : Exits;
  Report["attempted_operations"] = std::move(Operations);
  Report["attempted_boundaries"] = std::move(Boundaries);
  Report["exact_predicates"] = Rollback ? 0 : Predicates;
  Report["closed_scalar_exits"] = !Rollback && Exits == 0;
  return Report;
}
}
