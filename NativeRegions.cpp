#include "llvm/Transforms/Obfuscator/NativeRegions.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Transforms/Utils/ValueMapper.h"

using namespace llvm;
namespace llvm::obf {
namespace {
bool supportedWidth(Type *T) {
  if (!T->isIntegerTy()) return false;
  unsigned W = T->getIntegerBitWidth();
  return W == 8 || W == 16 || W == 32 || W == 64;
}

bool safeFunction(const Function &F) {
  if (F.isDeclaration() || F.hasPersonalityFn() || F.isVarArg() ||
      F.hasFnAttribute(Attribute::Naked)) return false;
  for (const Instruction &I : instructions(F)) {
    if (I.isEHPad() || isa<InvokeInst>(I) || isa<CallBrInst>(I) || isa<IndirectBrInst>(I))
      return false;
    if (const auto *C = dyn_cast<CallBase>(&I)) {
      if (C->isInlineAsm()) return false;
      if (const auto *CI = dyn_cast<CallInst>(C); CI && CI->isMustTailCall()) return false;
    }
  }
  return true;
}

bool outlineable(const Instruction &I) {
  if (!supportedWidth(I.getType())) return false;
  // No loads, calls, divisions, variable shifts, casts or vector operations.
  // Pure modular integer operations may be moved only within their block.
  switch (I.getOpcode()) {
  case Instruction::Add: case Instruction::Sub: case Instruction::Mul:
  case Instruction::And: case Instruction::Or: case Instruction::Xor:
    return true;
  case Instruction::Shl: case Instruction::LShr: case Instruction::AShr:
    if (auto *C = dyn_cast<ConstantInt>(I.getOperand(1)))
      return C->getValue().ult(I.getType()->getIntegerBitWidth());
    return false;
  default: return false;
  }
}

bool valueCandidate(const Instruction &I) {
  if (!supportedWidth(I.getType())) return false;
  if (isa<PHINode>(I) || isa<SelectInst>(I)) return true;
  switch (I.getOpcode()) {
  case Instruction::Add: case Instruction::Sub: case Instruction::Mul: return true;
  case Instruction::Shl:
    if (auto *C = dyn_cast<ConstantInt>(I.getOperand(1)))
      return C->getValue().ult(I.getType()->getIntegerBitWidth());
    return false;
  default: return false;
  }
}

APInt oddInverse(const APInt &A) {
  APInt R(A.getBitWidth(), 1);
  for (unsigned I = 1; I < A.getBitWidth(); I *= 2)
    R *= APInt(A.getBitWidth(), 2) - A * R;
  return R;
}

struct Pair { Value *E = nullptr, *R = nullptr; };
struct Coefficients {
  APInt A, B, Inverse;
  Coefficients(unsigned W, Rng R)
      : A(W, R.u64() | 1, false, true), B(W, R.u64() | 1, false, true),
        Inverse(oddInverse(A)) {}
};

// E = A*x + B*r (mod 2^W). Carry BOTH lanes through arithmetic and PHI/select
// joins. Unsupported consumers explicitly decode at the representation boundary.
class ValueEncoder {
  Function &F;
  Rng R;
  SmallVector<Instruction *, 32> Nodes;
  SmallPtrSet<Instruction *, 32> Selected;
  DenseMap<Instruction *, Pair> Encoded;
  unsigned BoundaryInputs = 0, BoundaryOutputs = 0, PersistentEdges = 0, Phis = 0;
  unsigned Site = 0;
  bool CoupleState;
  AllocaInst *Context = nullptr;

  Coefficients coeff(Type *T) { return Coefficients(T->getIntegerBitWidth(), R.fork(T->getIntegerBitWidth())); }
  Constant *constant(const APInt &V) { return ConstantInt::get(F.getContext(), V); }
  Value *rotate(IRBuilder<> &B, Value *V, unsigned N) {
    unsigned W = V->getType()->getIntegerBitWidth();
    return B.CreateOr(B.CreateShl(V, N), B.CreateLShr(V, W - N));
  }
  Pair pin(IRBuilder<> &B, Pair P, unsigned ID) {
    IRBuilder<> Entry(getAllocaIP(F));
    auto *Slot = Entry.CreateAlloca(ArrayType::get(P.E->getType(), 2), nullptr, "sre.value.pair");
    Slot->setMetadata("sre.native.value", MDNode::get(F.getContext(), MDString::get(F.getContext(), Twine(ID).str())));
    auto *AT = cast<ArrayType>(Slot->getAllocatedType());
    Value *EP = B.CreateInBoundsGEP(AT, Slot, {B.getInt32(0), B.getInt32(0)});
    Value *RP = B.CreateInBoundsGEP(AT, Slot, {B.getInt32(0), B.getInt32(1)});
    B.CreateStore(P.E, EP)->setVolatile(true);
    B.CreateStore(P.R, RP)->setVolatile(true);
    auto *E = B.CreateLoad(P.E->getType(), EP, "sre.value.encoded");
    auto *Mask = B.CreateLoad(P.R->getType(), RP, "sre.value.mask");
    E->setVolatile(true); Mask->setVolatile(true);
    if (Context) {
      Value *Next = B.CreateXor(B.CreateZExtOrTrunc(E, B.getInt32Ty()),
                                B.CreateZExtOrTrunc(Mask, B.getInt32Ty()));
      auto *S = B.CreateStore(Next, Context);
      S->setVolatile(true);
      S->setMetadata("sre.native.context.update", MDNode::get(F.getContext(),
          MDString::get(F.getContext(), "data")));
    }
    return {E, Mask};
  }
  Pair input(Value *V, IRBuilder<> &At) {
    if (auto *I = dyn_cast<Instruction>(V); I && Selected.contains(I)) return emit(I);
    ++BoundaryInputs;
    Coefficients C = coeff(V->getType());
    Value *X = At.CreateFreeze(V, "sre.value.input");
    unsigned W = V->getType()->getIntegerBitWidth();
    APInt Salt(W, R.fork(Site++).u64(), false, true);
    Value *Mask = At.CreateXor(rotate(At, X, 1 + R.range(W - 1)), constant(Salt));
    return {At.CreateAdd(At.CreateMul(X, constant(C.A)),
                         At.CreateMul(Mask, constant(C.B))), Mask};
  }
  Pair emit(Instruction *I) {
    if (auto Found = Encoded.find(I); Found != Encoded.end()) return Found->second;
    IRBuilder<> At(I);
    Pair Out;
    if (auto *S = dyn_cast<SelectInst>(I)) {
      Pair T = input(S->getTrueValue(), At), N = input(S->getFalseValue(), At);
      Value *Cond = At.CreateFreeze(S->getCondition());
      Out = {At.CreateSelect(Cond, T.E, N.E), At.CreateSelect(Cond, T.R, N.R)};
    } else {
      Coefficients C = coeff(I->getType());
      Pair X = input(I->getOperand(0), At);
      Pair Y = I->getOpcode() == Instruction::Shl
          ? Pair{ConstantInt::get(I->getType(), 0), ConstantInt::get(I->getType(), 0)}
          : input(I->getOperand(1), At);
      unsigned W = I->getType()->getIntegerBitWidth();
      APInt Salt(W, R.fork(Site++).u64(), false, true);
      Value *Mask = At.CreateAdd(rotate(At, At.CreateXor(X.R, Y.R), 1 + R.range(W - 1)),
                                 At.CreateXor(At.CreateAdd(X.E, Y.E), constant(Salt)), "sre.value.next.mask");
      if (Context) {
        auto *State = At.CreateLoad(At.getInt32Ty(), Context, "sre.value.context.load");
        State->setVolatile(true);
        Mask = At.CreateXor(Mask, At.CreateZExtOrTrunc(State, I->getType()));
      }
      Value *E = nullptr;
      switch (I->getOpcode()) {
      case Instruction::Add:
        E = At.CreateAdd(At.CreateAdd(X.E, Y.E), At.CreateMul(constant(C.B),
            At.CreateSub(At.CreateSub(Mask, X.R), Y.R))); break;
      case Instruction::Sub:
        E = At.CreateAdd(At.CreateSub(X.E, Y.E), At.CreateMul(constant(C.B),
            At.CreateAdd(At.CreateSub(Mask, X.R), Y.R))); break;
      case Instruction::Shl:
        E = At.CreateAdd(At.CreateShl(X.E, I->getOperand(1)), At.CreateMul(constant(C.B),
            At.CreateSub(Mask, At.CreateShl(X.R, I->getOperand(1))))); break;
      case Instruction::Mul: {
        // Joint transfer: expand in encoded coordinates; never individually
        // reconstruct x or y before their multiplication.
        Value *Cross = At.CreateAdd(At.CreateMul(X.E, Y.R), At.CreateMul(Y.E, X.R));
        Value *Product = At.CreateAdd(At.CreateSub(At.CreateMul(X.E, Y.E),
            At.CreateMul(constant(C.B), Cross)),
            At.CreateMul(constant(C.B * C.B), At.CreateMul(X.R, Y.R)));
        E = At.CreateAdd(At.CreateMul(constant(C.Inverse), Product), At.CreateMul(constant(C.B), Mask));
        break;
      }
      default: llvm_unreachable("unsupported persistent-value operation");
      }
      Out = {E, Mask};
    }
    // Local, nonescaping, per-activation storage pins the representation through
    // codegen. Memory-aware deobfuscation is explicitly an allowed recovery attack.
    Out = pin(At, Out, Site++);
    Encoded[I] = Out;
    return Out;
  }

public:
  ValueEncoder(Function &F, uint64_t Seed, unsigned MaxNodes, bool CoupleState)
      : F(F), R(Rng(Seed).fork("native-values-v1").fork(F.getName())), CoupleState(CoupleState) {
    for (Instruction &I : instructions(F))
      if (Nodes.size() < MaxNodes && valueCandidate(I)) {
        Nodes.push_back(&I); Selected.insert(&I);
      }
  }
  json::Object run() {
    for (Instruction *I : Nodes)
      for (Value *V : I->operands())
        if (auto *P = dyn_cast<Instruction>(V); P && Selected.contains(P)) ++PersistentEdges;
    if (PersistentEdges == 0)
      return json::Object{{"function", F.getName().str()}, {"status", "skipped"},
                          {"reason", "no-connected-supported-values"}};
    if (CoupleState && F.getFnAttribute("sre.native.spec").getValueAsString().contains("flattening(")) {
      IRBuilder<> Entry(getAllocaIP(F));
      Context = Entry.CreateAlloca(Entry.getInt32Ty(), nullptr, "sre.value.context");
      Context->setMetadata("sre.native.context", MDNode::get(F.getContext(), {}));
      Entry.CreateStore(Entry.getInt32(R.fork("context").u32()), Context)->setVolatile(true);
    }
    SmallVector<Use *, 32> Exits;
    for (Instruction *I : Nodes) {
      for (Use &U : I->uses())
        if (auto *User = dyn_cast<Instruction>(U.getUser()); User && !Selected.contains(User))
          Exits.push_back(&U);
      if (auto *Phi = dyn_cast<PHINode>(I)) {
        ++Phis;
        auto *E = PHINode::Create(I->getType(), Phi->getNumIncomingValues(), "sre.value.phi.e", I->getIterator());
        auto *Mask = PHINode::Create(I->getType(), Phi->getNumIncomingValues(), "sre.value.phi.r", I->getIterator());
        Encoded[I] = {E, Mask};
      }
    }
    for (Instruction *I : Nodes) emit(I);
    for (Instruction *I : Nodes)
      if (auto *Phi = dyn_cast<PHINode>(I)) {
        Pair P = Encoded.lookup(I);
        DenseMap<BasicBlock *, Pair> IncomingByBlock;
        for (unsigned N = 0; N < Phi->getNumIncomingValues(); ++N) {
          BasicBlock *Pred = Phi->getIncomingBlock(N);
          IRBuilder<> At(Pred->getTerminator());
          // Switches may have multiple edges from one predecessor. LLVM
          // requires identical incoming SSA values for those duplicate edges.
          auto Found = IncomingByBlock.find(Pred);
          Pair Incoming = Found == IncomingByBlock.end()
              ? input(Phi->getIncomingValue(N), At) : Found->second;
          IncomingByBlock[Pred] = Incoming;
          cast<PHINode>(P.E)->addIncoming(Incoming.E, Pred);
          cast<PHINode>(P.R)->addIncoming(Incoming.R, Pred);
        }
      }
    DenseMap<std::pair<Instruction *, Instruction *>, Value *> DecodedAt;
    for (Use *U : Exits) {
      auto *Original = cast<Instruction>(U->get());
      auto *User = cast<Instruction>(U->getUser());
      Instruction *IP = User;
      if (auto *Phi = dyn_cast<PHINode>(User)) IP = Phi->getIncomingBlock(U->getOperandNo())->getTerminator();
      auto Key = std::make_pair(Original, IP);
      if (auto Found = DecodedAt.find(Key); Found != DecodedAt.end()) {
        U->set(Found->second); ++BoundaryOutputs; continue;
      }
      IRBuilder<> At(IP);
      Pair P = Encoded.lookup(Original);
      Coefficients C = coeff(Original->getType());
      Value *Plain = At.CreateMul(At.CreateSub(P.E, At.CreateMul(constant(C.B), P.R)),
                                  constant(C.Inverse), "sre.value.output");
      U->set(Plain); ++BoundaryOutputs;
      DecodedAt[Key] = Plain;
    }
    unsigned Count = Nodes.size();
    SmallVector<unsigned, 4> Widths;
    for (Instruction *I : Nodes) {
      unsigned W = I->getType()->getIntegerBitWidth();
      if (!llvm::is_contained(Widths, W)) Widths.push_back(W);
    }
    llvm::sort(Widths);
    json::Array WidthReport;
    for (unsigned W : Widths) WidthReport.push_back(W);
    for (Instruction *I : Nodes) I->dropAllReferences();
    for (Instruction *I : Nodes) I->eraseFromParent();
    F.setMemoryEffects(MemoryEffects::unknown());
    F.removeFnAttr(Attribute::Speculatable);
    return json::Object{{"function", F.getName().str()}, {"status", "encoded"},
        {"nodes", Count}, {"persistent_edges", PersistentEdges}, {"phi_pairs", Phis},
        {"widths", std::move(WidthReport)},
        {"coupled_context_created", Context != nullptr},
        {"boundary_inputs", BoundaryInputs}, {"boundary_outputs", BoundaryOutputs},
        {"representation", "affine-two-lane-v1"}};
  }
};
} // namespace

json::Array encodeNativeValues(Module &M, uint64_t Seed, unsigned MaxNodes, bool CoupleState) {
  json::Array Report;
  for (Function &F : M) {
    if (!F.hasFnAttribute("sre.native.original") &&
        F.getFnAttribute("sre.native.helper").getValueAsString() != "outlined-region") continue;
    if (!safeFunction(F) || F.getInstructionCount() > 4000) {
      Report.push_back(json::Object{{"function", F.getName().str()}, {"status", "skipped"},
                                   {"reason", "structure-or-size"}});
      continue;
    }
    Report.push_back(ValueEncoder(F, Seed, MaxNodes, CoupleState).run());
  }
  return Report;
}

json::Array outlineNativeRegions(Module &M, uint64_t Seed) {
  json::Array Report;
  SmallVector<Function *, 16> Originals;
  for (Function &F : M)
    if (F.hasFnAttribute("sre.native.original")) Originals.push_back(&F);
  unsigned Total = 0;
  for (Function *F : Originals) {
    if (!safeFunction(*F) || F->getInstructionCount() > 4000) {
      Report.push_back(json::Object{{"function", F->getName().str()}, {"status", "skipped"},
                                   {"reason", "structure-or-size"}});
      continue;
    }
    unsigned Regions = 0;
    Rng R = Rng(Seed).fork("native-outlining-v1").fork(F->getName());
    SmallVector<SmallVector<Instruction *, 8>, 8> Candidates;
    for (BasicBlock &BB : *F) {
      SmallVector<Instruction *, 8> Run;
      auto Flush = [&]() { if (Run.size() >= 3) Candidates.push_back(Run); Run.clear(); };
      for (Instruction &I : BB) {
        if (outlineable(I)) { Run.push_back(&I); if (Run.size() == 8) Flush(); }
        else Flush();
      }
      Flush();
    }
    R.shuffle(MutableArrayRef(Candidates));
    for (auto &Region : Candidates) {
      if (Regions == 2 || Total == 16) break;
      SmallPtrSet<Instruction *, 16> Members(Region.begin(), Region.end());
      SmallVector<Value *, 8> Inputs;
      SmallVector<Instruction *, 4> Outputs;
      bool UnsafeInput = false;
      for (Instruction *I : Region) {
        for (Value *V : I->operands()) {
          if (isa<Constant>(V) || (isa<Instruction>(V) && Members.contains(cast<Instruction>(V)))) continue;
          if (!supportedWidth(V->getType())) { UnsafeInput = true; break; }
          if (!llvm::is_contained(Inputs, V)) Inputs.push_back(V);
        }
        if (llvm::any_of(I->users(), [&](User *U) {
              auto *UI = dyn_cast<Instruction>(U); return !UI || !Members.contains(UI);
            })) Outputs.push_back(I);
      }
      if (UnsafeInput || Inputs.size() > 6 || Outputs.empty() || Outputs.size() > 4) continue;
      SmallVector<Type *, 8> InTypes, OutTypes;
      for (Value *V : Inputs) InTypes.push_back(V->getType());
      for (Instruction *I : Outputs) OutTypes.push_back(I->getType());
      auto *ResultTy = StructType::get(M.getContext(), OutTypes);
      auto *H = Function::Create(FunctionType::get(ResultTy, InTypes, false),
          GlobalValue::InternalLinkage, "sre.region", M);
      markObfGenerated(*H);
      H->addFnAttr("sre.native.helper", "outlined-region");
      H->addFnAttr("sre.native.origin", F->getName());
      H->addFnAttr(Attribute::NoInline);
      H->addFnAttr(Attribute::NoUnwind);
      ValueToValueMapTy Map;
      IRBuilder<> Body(BasicBlock::Create(M.getContext(), "entry", H));
      for (unsigned I = 0; I < Inputs.size(); ++I) Map[Inputs[I]] = H->getArg(I);
      for (Instruction *I : Region) {
        Instruction *Copy = I->clone();
        RemapInstruction(Copy, Map, RF_NoModuleLevelChanges | RF_IgnoreMissingLocals);
        // Refinement on defined source executions; do not leak poison from a
        // dead tuple field to a live field through upstream overflow flags.
        Copy->dropPoisonGeneratingFlags();
        Copy->setDebugLoc(DebugLoc());
        Body.Insert(Copy);
        Map[I] = Copy;
      }
      Value *Result = PoisonValue::get(ResultTy);
      for (unsigned I = 0; I < Outputs.size(); ++I)
        Result = Body.CreateInsertValue(Result, Map[Outputs[I]], I);
      Body.CreateRet(Result);
      IRBuilder<> At(Region.back()->getNextNode());
      SmallVector<Value *, 8> FrozenInputs;
      for (Value *V : Inputs) FrozenInputs.push_back(At.CreateFreeze(V));
      Value *Call = At.CreateCall(H, FrozenInputs);
      for (unsigned I = 0; I < Outputs.size(); ++I) {
        Value *Out = At.CreateExtractValue(Call, I);
        SmallVector<Use *, 8> Uses;
        for (Use &U : Outputs[I]->uses())
          if (!Members.contains(dyn_cast<Instruction>(U.getUser()))) Uses.push_back(&U);
        for (Use *U : Uses) U->set(Out);
      }
      unsigned Count = Region.size();
      for (Instruction *I : llvm::reverse(Region)) I->eraseFromParent();
      Report.push_back(json::Object{{"function", F->getName().str()}, {"helper", H->getName().str()},
          {"status", "outlined"}, {"nodes", Count}, {"inputs", Inputs.size()}, {"outputs", Outputs.size()}});
      ++Regions; ++Total;
    }
    if (!Regions) Report.push_back(json::Object{{"function", F->getName().str()},
        {"status", "skipped"}, {"reason", Total == 16 ? "module-region-cap" : "no-bounded-pure-region"}});
  }
  return Report;
}
} // namespace llvm::obf
