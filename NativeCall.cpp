#include "llvm/Transforms/Obfuscator/NativeCall.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"

using namespace llvm;
namespace llvm::obf {
namespace {
bool supported(Type *T) {
  return T->isIntegerTy() &&
      llvm::is_contained(ArrayRef<unsigned>{8, 16, 32, 64}, T->getIntegerBitWidth());
}
// The native data passes exclude any function with a personality function or
// an EH pad; an encoded interface keeps that exclusion exactly.
bool unwinds(const Function &F) {
  if (F.hasPersonalityFn()) return true;
  for (const Instruction &I : instructions(F))
    if (I.isEHPad() || isa<InvokeInst, CallBrInst>(&I)) return true;
  return false;
}
// Every direct-call cycle in the module, in one pass. NativeFusion answers the
// same question with a per-candidate reachability walk; that is O(module) per
// query, and this pass asks it for every definition. Tarjan over the direct
// call edges is seeded from every function in module order, so a recursive
// function that is unreachable from any exported root is still detected.
// Indirect edges are not modeled: a candidate is never address-taken, so no
// indirect call can name it.
void findCycles(Module &M, SmallPtrSetImpl<const Function *> &Cyclic) {
  DenseMap<const Function *, SmallVector<const Function *, 8>> Edges;
  for (Function &F : M) {
    auto &Callees = Edges[&F];
    SmallPtrSet<const Function *, 8> Seen;
    for (Instruction &I : instructions(F))
      if (auto *C = dyn_cast<CallBase>(&I))
        if (Function *G = C->getCalledFunction())
          if (Seen.insert(G).second) Callees.push_back(G);
  }
  DenseMap<const Function *, unsigned> Index, Low;
  SmallVector<const Function *, 32> Component;
  DenseSet<const Function *> Open;
  struct Frame { const Function *F; unsigned Child; };
  unsigned Next = 0;
  for (Function &Root : M) {
    if (Index.count(&Root)) continue;
    Index[&Root] = Low[&Root] = Next++;
    Component.push_back(&Root); Open.insert(&Root);
    SmallVector<Frame, 32> Work{{&Root, 0}};
    while (!Work.empty()) {
      const Function *Cur = Work.back().F;
      ArrayRef<const Function *> Callees = Edges.find(Cur)->second;
      if (Work.back().Child < Callees.size()) {
        const Function *V = Callees[Work.back().Child++];
        if (!Index.count(V)) {
          Index[V] = Low[V] = Next++;
          Component.push_back(V); Open.insert(V);
          Work.push_back({V, 0});
        } else if (Open.count(V))
          Low[Cur] = std::min(Low[Cur], Index[V]);
        continue;
      }
      Work.pop_back();
      if (!Work.empty()) Low[Work.back().F] = std::min(Low[Work.back().F], Low[Cur]);
      if (Low[Cur] != Index[Cur]) continue;
      SmallVector<const Function *, 8> Members;
      const Function *Member = nullptr;
      do {
        Member = Component.pop_back_val(); Open.erase(Member); Members.push_back(Member);
      } while (Member != Cur);
      if (Members.size() > 1 || llvm::is_contained(Callees, Cur))
        for (const Function *X : Members) Cyclic.insert(X);
    }
  }
}

class Interfaces {
  Module &M;
  Rng RNG;
  NativeCallOptions O;
  SmallPtrSet<const Function *, 16> Cyclic;
  // One activation slot per function body. Identity keyed, never iterated, so
  // no pointer order can reach the output. When a host is itself encoded the
  // entry is re-keyed onto the twin its body moved into.
  DenseMap<Function *, AllocaInst *> Slots;
  unsigned Allocas = 0, Encoded = 0;

  // Per-activation mask material. It is an entry alloca, never a module
  // global, so concurrent activations of one interface never share it. The
  // slot seeds itself from its own address and every read is volatile: a pair
  // whose second coordinate is a plain constant folds straight back into the
  // plaintext it is supposed to hide.
  AllocaInst *slot(Function &F) {
    if (auto It = Slots.find(&F); It != Slots.end()) return It->second;
    BasicBlock &Entry = F.getEntryBlock();
    IRBuilder<> B(&Entry, Entry.begin());
    auto *Slot = B.CreateAlloca(B.getInt64Ty(), nullptr, "sre.call.activation");
    Slot->setMetadata("sre.native.call.state", MDNode::get(F.getContext(), {}));
    Value *Init = B.CreateXor(B.CreatePtrToInt(Slot, B.getInt64Ty()),
        B.getInt64(RNG.fork("activation").fork(F.getName()).u64()));
    B.CreateStore(Init, Slot)->setVolatile(true);
    ++Allocas;
    return Slots[&F] = Slot;
  }
  Value *mask(IRBuilder<> &B, Function &Host, Type *T, StringRef Owner,
              StringRef Role, unsigned Site, unsigned Index) {
    auto *Read = B.CreateLoad(B.getInt64Ty(), slot(Host), "sre.call.activation.read");
    Read->setVolatile(true);
    Value *Mask = B.CreateXor(Read, B.getInt64(RNG.fork(Owner).fork(Role)
        .fork(Host.getName()).fork(Site).fork(Index).u64()));
    return B.CreateIntCast(Mask, T, false, "sre.call.mask");
  }
  // Symbol order, then instruction order inside each caller. Use-list order
  // never reaches a seeded stream.
  SmallVector<CallInst *, 16> sites(Function &F) {
    SmallVector<Function *, 8> Hosts;
    SmallPtrSet<Function *, 8> Seen;
    for (User *U : F.users())
      if (auto *C = dyn_cast<CallInst>(U))
        if (Seen.insert(C->getFunction()).second) Hosts.push_back(C->getFunction());
    llvm::sort(Hosts, [](const Function *A, const Function *B) {
      return A->getName() < B->getName();
    });
    SmallVector<CallInst *, 16> Sites;
    for (Function *Host : Hosts)
      for (Instruction &I : instructions(*Host))
        if (auto *C = dyn_cast<CallInst>(&I); C && C->getCalledFunction() == &F)
          Sites.push_back(C);
    return Sites;
  }

  // Move F's body into a twin whose interface carries (E, R) pairs, rebuild
  // every parameter and result inside the twin, and rewrite every call site.
  // The original is erased: a wrapper here would be a duplicate plaintext body
  // with the same summary the encoded interface is meant to cost an attacker.
  void encode(Function &F, json::Object &Row) {
    LLVMContext &Ctx = F.getContext();
    std::string Owner = F.getName().str();
    Type *Ret = F.getReturnType();
    SmallVector<Type *, 16> Params;
    for (Argument &A : F.args()) { Params.push_back(A.getType()); Params.push_back(A.getType()); }
    Type *Out = Ret->isVoidTy() ? Ret : cast<Type>(StructType::get(Ctx, {Ret, Ret}));
    auto *NF = Function::Create(FunctionType::get(Out, Params, false),
        GlobalValue::InternalLinkage, F.getName() + NativeEncodedCallSuffix, &M);
    NF->setCallingConv(F.getCallingConv());
    // Function attributes carry the sre.native.* stage, spec and family
    // markers, so the twin stays application code for every later stage.
    // Parameter and return attributes describe the old signature and are not
    // copied; both sides of this private ABI are rewritten together.
    for (Attribute A : F.getAttributes().getFnAttrs()) NF->addFnAttr(A);
    NF->setMemoryEffects(MemoryEffects::unknown());
    NF->removeFnAttr(Attribute::Speculatable);
    if (DISubprogram *SP = F.getSubprogram()) { F.setSubprogram(nullptr); NF->setSubprogram(SP); }
    NF->splice(NF->begin(), &F);
    if (auto It = Slots.find(&F); It != Slots.end()) { Slots[NF] = It->second; Slots.erase(&F); }

    BasicBlock &Entry = NF->getEntryBlock();
    IRBuilder<> B(&Entry, Entry.begin());
    for (unsigned N = 0; N < F.arg_size(); ++N) {
      Argument *E = NF->getArg(2 * N), *R = NF->getArg(2 * N + 1);
      E->setName("sre.call.e"); R->setName("sre.call.r");
      auto *Plain = cast<Instruction>(B.CreateXor(E, R, "sre.call.arg"));
      Plain->setMetadata("sre.native.call.arg", MDNode::get(Ctx, {}));
      F.getArg(N)->replaceAllUsesWith(Plain);
    }
    unsigned Returns = 0;
    if (!Ret->isVoidTy())
      for (BasicBlock &BB : *NF) {
        auto *RI = dyn_cast<ReturnInst>(BB.getTerminator());
        if (!RI) continue;
        IRBuilder<> RB(RI);
        Value *R = mask(RB, *NF, Ret, Owner, "result", Returns++, 0);
        auto *E = cast<Instruction>(RB.CreateXor(RI->getReturnValue(), R, "sre.call.result"));
        E->setMetadata("sre.native.call.result", MDNode::get(Ctx, {}));
        E->setDebugLoc(RI->getDebugLoc());
        Value *Pair = RB.CreateInsertValue(PoisonValue::get(Out), E, 0);
        RB.CreateRet(RB.CreateInsertValue(Pair, R, 1))->setDebugLoc(RI->getDebugLoc());
        RI->eraseFromParent();
      }

    unsigned Site = 0;
    for (CallInst *C : sites(F)) {
      Function &Host = *C->getFunction();
      IRBuilder<> CB(C);
      SmallVector<Value *, 16> Args;
      for (unsigned N = 0; N < C->arg_size(); ++N) {
        Value *X = C->getArgOperand(N);
        Value *R = mask(CB, Host, X->getType(), Owner, "split", Site, N);
        auto *E = cast<Instruction>(CB.CreateXor(X, R, "sre.call.split"));
        E->setMetadata("sre.native.call.split", MDNode::get(Ctx, {}));
        E->setDebugLoc(C->getDebugLoc());
        Args.push_back(E); Args.push_back(R);
      }
      auto *NC = CB.CreateCall(NF, Args);
      NC->setCallingConv(NF->getCallingConv());
      NC->setDebugLoc(C->getDebugLoc());
      if (!Ret->isVoidTy()) {
        Value *E = CB.CreateExtractValue(NC, 0, "sre.call.pair.e");
        Value *R = CB.CreateExtractValue(NC, 1, "sre.call.pair.r");
        auto *Plain = cast<Instruction>(CB.CreateXor(E, R, "sre.call.join"));
        Plain->setMetadata("sre.native.call.join", MDNode::get(Ctx, {}));
        Plain->setDebugLoc(C->getDebugLoc());
        C->replaceAllUsesWith(Plain);
      }
      C->eraseFromParent();
      ++Site;
    }
    Row["encoded_parameters"] = F.arg_size();
    Row["returns_pair"] = !Ret->isVoidTy();
    Row["call_sites_rewritten"] = Site;
    Row["activation_allocas"] = Allocas;
    if (!F.use_empty()) report_fatal_error("native encoded call left a plaintext use");
    F.eraseFromParent();
    ++Encoded;
  }

public:
  Interfaces(Module &M, uint64_t Seed, const NativeCallOptions &O)
      : M(M), RNG(Rng(Seed).fork("native-encoded-calls-v1")), O(O) {
    findCycles(M, Cyclic);
  }

  json::Array run() {
    json::Array Report;
    // Module order, so adding or reordering functions cannot move an existing
    // interface's stream. Twins are appended and never reconsidered.
    SmallVector<Function *, 64> Candidates;
    for (Function &F : M) if (!F.isDeclaration()) Candidates.push_back(&F);
    for (Function *F : Candidates) {
      Type *Ret = F->getReturnType();
      json::Array Widths;
      SmallVector<unsigned, 8> Seen;
      auto note = [&](Type *T) {
        if (!supported(T)) return;
        unsigned Bits = T->getIntegerBitWidth();
        if (!llvm::is_contained(Seen, Bits)) Seen.push_back(Bits);
      };
      for (Argument &A : F->args()) note(A.getType());
      note(Ret);
      llvm::sort(Seen);
      for (unsigned Bits : Seen) Widths.push_back(int64_t(Bits));

      // An interface with no pair to carry is not encoded coverage: a void
      // function of no arguments is reported as an unsupported signature.
      bool Signature = (Ret->isVoidTy() || supported(Ret)) &&
          (F->arg_size() || !Ret->isVoidTy()) &&
          llvm::all_of(F->args(), [](const Argument &A) { return supported(A.getType()); });
      SmallPtrSet<const Function *, 8> Callers;
      bool Direct = true;
      for (const Use &U : F->uses()) {
        const auto *C = dyn_cast<CallInst>(U.getUser());
        if (!C || !C->isCallee(&U) || C->hasOperandBundles() || C->isMustTailCall() ||
            C->getFunctionType() != F->getFunctionType()) { Direct = false; break; }
        Callers.insert(C->getFunction());
      }
      std::string Reason;
      if (!F->hasFnAttribute("sre.native.original")) Reason = "not-original";
      else if (!F->hasLocalLinkage() || F->hasAddressTaken()) Reason = "exported-or-address-taken";
      else if (F->isVarArg()) Reason = "varargs";
      else if (unwinds(*F)) Reason = "eh-or-personality";
      else if (Cyclic.count(F)) Reason = "recursive";
      else if (!Signature) Reason = "unsupported-signature";
      else if (!Direct) Reason = "unsupported-call-site";
      else if (Callers.empty()) Reason = "no-callers";
      else if (Encoded >= O.Functions) Reason = "function-budget";

      // absorbed_* count pairs a later pass consumed without a scalar decode.
      // They stay zero here: on its own this interface only moves the decode
      // across the call boundary.
      json::Object Row{{"function", F->getName().str()},
          {"status", Reason.empty() ? "encoded" : "skipped"}, {"reason", Reason},
          {"parameters", F->arg_size()}, {"encoded_parameters", 0},
          {"returns_pair", false}, {"widths", std::move(Widths)},
          {"callers", Callers.size()}, {"call_sites_rewritten", 0},
          {"wrapper_retained", false}, {"representation", "xor-pair-v1"},
          {"activation_allocas", 0}, {"absorbed_arguments", 0}, {"absorbed_results", 0}};
      if (Reason.empty()) { Allocas = 0; encode(*F, Row); }
      Report.push_back(std::move(Row));
    }
    return Report;
  }
};
} // namespace

json::Array encodeNativeCalls(Module &M, uint64_t Seed, const NativeCallOptions &O) {
  return Interfaces(M, Seed, O).run();
}

void recordNativeCallAbsorption(json::Array &Rows,
                                const StringMap<NativeCallAbsorption> &Absorbed) {
  for (json::Value &Value : Rows) {
    json::Object *Row = Value.getAsObject();
    if (!Row) continue;
    auto Name = Row->getString("function"), Status = Row->getString("status");
    if (!Name || !Status || *Status != "encoded") continue;
    auto Found = Absorbed.find((*Name + NativeEncodedCallSuffix).str());
    if (Found == Absorbed.end()) continue;
    (*Row)["absorbed_arguments"] = Found->second.Arguments;
    (*Row)["absorbed_results"] = Found->second.Results;
  }
}
} // namespace llvm::obf
