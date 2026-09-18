#include "llvm/Transforms/Obfuscator/NativeCall.h"
#include "llvm/Transforms/Obfuscator/NativeBundleMath.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"

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
StringRef bodyBlocker(const Function &F) {
  if (F.hasFnAttribute(Attribute::ReturnsTwice)) return "returns-twice";
  bool Returns = false;
  for (const Instruction &I : instructions(F)) {
    Returns |= isa<ReturnInst>(I);
    if (const auto *C = dyn_cast<CallBase>(&I)) {
      if (const auto *CI = dyn_cast<CallInst>(C); CI && CI->isMustTailCall())
        return "musttail-body";
      if (C->hasFnAttr(Attribute::ReturnsTwice)) return "returns-twice";
    }
  }
  // There is no result pair to measure in a non-returning integer function.
  if (!F.getReturnType()->isVoidTy() && !Returns) return "no-return";
  return "";
}
// Every direct-call cycle in the module, in one pass. NativeFusion answers the
// same question with a per-candidate reachability walk; that is O(module) per
// query, and this pass asks it for every definition. Tarjan over the direct
// call edges is seeded from every function in module order, so a recursive
// function that is unreachable from any exported root is still detected.
// Indirect edges are not modeled: a candidate is never address-taken, so no
// indirect call can name it.
void findCycles(Module &M, SmallPtrSetImpl<const Function *> &Cyclic,
                SmallPtrSetImpl<const Function *> *Self = nullptr) {
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
      if (Self && Members.size() == 1 && llvm::is_contained(Callees, Cur)) Self->insert(Cur);
    }
  }
}

// Every reason encodeNativeCalls refuses an interface for, in the order that
// pass checks them, over a function that has not been merged yet. Shared with
// the arbitration so a policy can never promise an interface the pass would
// then refuse. function-budget is the pass's own running state and stays there.
std::string interfaceBlocker(const Function &F,
                             const SmallPtrSetImpl<const Function *> &Cyclic,
                             SmallPtrSetImpl<const Function *> &Callers, bool AllowSelf = false) {
  bool Direct = true;
  for (const Use &U : F.uses()) {
    const auto *C = dyn_cast<CallInst>(U.getUser());
    if (!C || !C->isCallee(&U) || C->hasOperandBundles() || C->isMustTailCall() ||
        C->getFunctionType() != F.getFunctionType()) { Direct = false; break; }
    Callers.insert(C->getFunction());
  }
  Type *Ret = F.getReturnType();
  // An interface with no pair to carry is not encoded coverage: a void
  // function of no arguments is reported as an unsupported signature.
  bool Signature = (Ret->isVoidTy() || supported(Ret)) &&
      (F.arg_size() || !Ret->isVoidTy()) &&
      llvm::all_of(F.args(), [](const Argument &A) { return supported(A.getType()); });
  if (!F.hasFnAttribute("sre.native.original")) return "not-original";
  if (!F.hasLocalLinkage() || F.hasAddressTaken()) return "exported-or-address-taken";
  if (F.isVarArg()) return "varargs";
  if (unwinds(F)) return "eh-or-personality";
  if (StringRef Blocker = bodyBlocker(F); !Blocker.empty()) return Blocker.str();
  if (Cyclic.count(&F)) {
    if (!AllowSelf) return "recursive";
    // Initial recursive contract: only direct self calls and non-observing
    // lifetime/debug markers. Unknown callbacks, other callees, inline asm,
    // stack/frame observation and exception edges are not silently admitted.
    if (F.hasFnAttribute(Attribute::Naked)) return "recursive-unsupported-effect";
    for (const Instruction &I : instructions(F)) if (const auto *C = dyn_cast<CallBase>(&I)) {
      if (C->getCalledFunction() == &F) continue;
      if (isa<LifetimeIntrinsic, DbgInfoIntrinsic>(I) && !C->hasOperandBundles()) continue;
      return "recursive-unsupported-effect";
    }
  }
  if (!Signature) return "unsupported-signature";
  if (!Direct) return "unsupported-call-site";
  if (Callers.empty()) return "no-callers";
  return "";
}

class Interfaces {
  Module &M;
  Rng RNG;
  NativeCallOptions O;
  SmallPtrSet<const Function *, 16> Cyclic, SelfRecursive;
  // One activation slot per function body. Identity keyed, never iterated, so
  // no pointer order can reach the output. When a host is itself encoded the
  // entry is re-keyed onto the twin its body moved into.
  DenseMap<Function *, AllocaInst *> Slots;
  unsigned Allocas = 0, Encoded = 0;

  // A bounded, homogeneous private argument tuple. Return values retain the
  // existing pair ABI. Descriptor values are build constants, not secrets.
  struct JointPlan {
    SmallVector<uint64_t, 4> Salts;
    SmallVector<unsigned, 4> Rotations;
    unsigned MaskInstructions = 0;
    bool enabled() const { return !Salts.empty(); }
  };

  JointPlan jointPlan(Function &F, json::Object &Row) {
    JointPlan P;
    if (!O.JointArguments) return P;
    StringRef Reason;
    unsigned N = F.arg_size(), Sites = sites(F).size();
    if (N < 2 || N > 4) Reason = "argument-count";
    else if (llvm::any_of(F.args(), [&](const Argument &A) {
               return A.getType() != F.getArg(0)->getType(); })) Reason = "mixed-argument-widths";
    else if (Sites > 8) Reason = "call-site-limit";
    json::Object Contract{{"contract", "triangular-call-arguments-v1"},
        {"status", Reason.empty() ? "joint" : "paired-fallback"}, {"reason", Reason.str()},
        {"abi_words", 2 * N}, {"mask_reservation", 0}, {"mask_instructions", 0}};
    if (Reason.empty()) {
      unsigned W = F.getArg(0)->getType()->getIntegerBitWidth();
      Rng R = RNG.fork("joint-arguments").fork(F.getName());
      json::Array Salts, Rotations;
      for (unsigned K = 0; K < N; ++K) {
        APInt Salt(W, R.u64());
        SmallString<16> Hex;
        Salt.toStringUnsigned(Hex, 16);
        P.Salts.push_back(Salt.getZExtValue()); Salts.push_back(Hex.str().str());
        P.Rotations.push_back(1 + R.u64() % (W - 1)); Rotations.push_back(P.Rotations.back());
      }
      Contract["descriptor"] = json::Object{{"width", W}, {"family", "triangular-xor-v1"},
          {"salts_hex", std::move(Salts)}, {"rotations", std::move(Rotations)}};
      Contract["abi_words"] = N + 1;
      // At most seven mask instructions per argument at each rewritten site
      // and at entry. The reserve allows one extra per lane; no growth caps
      // are raised. The bounded eight-site contract limits the reserve to 288.
      Contract["mask_reservation"] = 8 * N * (Sites + 1);
      Row["representation"] = "triangular-xor-arguments-v1";
    }
    Row["joint_arguments"] = std::move(Contract);
    return P;
  }

  Value *jointMask(IRBuilder<> &B, ArrayRef<Value *> Z, Value *Carrier,
                   unsigned K, JointPlan &P) {
    auto End = B.GetInsertPoint();
    auto *BB = B.GetInsertBlock();
    Instruction *Prev = End == BB->begin() ? nullptr : &*std::prev(End);
    Value *R = bundle::mask(B, Z, Carrier, K, P.Salts[K], P.Rotations[K]);
    auto Begin = Prev ? std::next(Prev->getIterator()) : BB->begin();
    for (auto I = Begin; I != End; ++I) { state(&*I); ++P.MaskInstructions; }
    return R;
  }

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
    state(Slot);
    Value *Address = B.CreatePtrToInt(Slot, B.getInt64Ty());
    state(Address);
    Value *Init = B.CreateXor(Address, B.getInt64(RNG.fork("activation").fork(F.getName()).u64()));
    state(Init);
    auto *Store = B.CreateStore(Init, Slot);
    Store->setVolatile(true);
    state(Store);
    ++Allocas;
    return Slots[&F] = Slot;
  }
  // Interface plumbing, not application arithmetic: a later representation
  // pass must leave it alone, or it would encode the very coordinate that
  // hides a pair and could no longer hand the pair on unchanged.
  void state(Value *V) {
    if (auto *I = dyn_cast<Instruction>(V))
      I->setMetadata("sre.native.call.state", MDNode::get(I->getContext(), {}));
  }
  Value *mask(IRBuilder<> &B, Function &Host, Type *T, StringRef Owner,
              StringRef Role, unsigned Site, unsigned Index) {
    auto *Read = B.CreateLoad(B.getInt64Ty(), slot(Host), "sre.call.activation.read");
    Read->setVolatile(true);
    state(Read);
    Value *Mask = B.CreateXor(Read, B.getInt64(RNG.fork(Owner).fork(Role)
        .fork(Host.getName()).fork(Site).fork(Index).u64()));
    state(Mask);
    Value *Out = B.CreateIntCast(Mask, T, false, "sre.call.mask");
    state(Out);
    return Out;
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

  // Move F's body into a pair/tuple-interface twin, rebuild
  // every parameter and result inside the twin, and rewrite every call site.
  // The original is erased: a wrapper here would be a duplicate plaintext body
  // with the same summary the encoded interface is meant to cost an attacker.
  void encode(Function &F, json::Object &Row) {
    LLVMContext &Ctx = F.getContext();
    std::string Owner = F.getName().str();
    Type *Ret = F.getReturnType();
    JointPlan Joint = jointPlan(F, Row);
    SmallVector<Type *, 16> Params;
    for (Argument &A : F.args()) {
      Params.push_back(A.getType());
      if (!Joint.enabled()) Params.push_back(A.getType());
    }
    if (Joint.enabled()) Params.push_back(F.getArg(0)->getType());
    Type *Out = Ret->isVoidTy() ? Ret : cast<Type>(StructType::get(Ctx, {Ret, Ret}));
    auto *NF = Function::Create(FunctionType::get(Out, Params, false),
        GlobalValue::InternalLinkage, F.getName() + NativeEncodedCallSuffix, &M);
    // LLVM can uniquify this name when an input symbol already uses the
    // suffix. Keep the actual name for downstream absorption accounting.
    Row["encoded_function"] = NF->getName().str();
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
    SmallVector<Value *, 4> InputState;
    for (unsigned N = 0; N < F.arg_size(); ++N) {
      Argument *E = NF->getArg(Joint.enabled() ? N : 2 * N);
      Value *R = Joint.enabled() ? jointMask(B, InputState, NF->getArg(F.arg_size()), N, Joint) :
                                  NF->getArg(2 * N + 1);
      E->setName("sre.call.e");
      if (!Joint.enabled()) R->setName("sre.call.r");
      auto *Plain = cast<Instruction>(B.CreateXor(E, R, "sre.call.arg"));
      Plain->setMetadata("sre.native.call.arg", MDNode::get(Ctx, {}));
      F.getArg(N)->replaceAllUsesWith(Plain);
      InputState.push_back(E);
    }
    if (Joint.enabled()) NF->getArg(F.arg_size())->setName("sre.call.carrier");
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
    unsigned SelfSites = 0;
    for (CallInst *C : sites(F)) {
      Function &Host = *C->getFunction();
      SelfSites += &Host == NF;
      IRBuilder<> CB(C);
      SmallVector<Value *, 16> Args;
      SmallVector<Value *, 4> State;
      Value *Carrier = Joint.enabled() ? mask(CB, Host, C->getArgOperand(0)->getType(),
                                              Owner, "joint-carrier", Site, 0) : nullptr;
      for (unsigned N = 0; N < C->arg_size(); ++N) {
        Value *X = C->getArgOperand(N);
        Value *R = Joint.enabled() ? jointMask(CB, State, Carrier, N, Joint) :
                                    mask(CB, Host, X->getType(), Owner, "split", Site, N);
        auto *E = cast<Instruction>(CB.CreateXor(X, R, "sre.call.split"));
        E->setMetadata("sre.native.call.split", MDNode::get(Ctx, {}));
        if (Joint.enabled()) E->setMetadata("sre.native.call.joint-split", MDNode::get(Ctx, {}));
        E->setDebugLoc(C->getDebugLoc());
        Args.push_back(E);
        if (!Joint.enabled()) Args.push_back(R);
        State.push_back(E);
      }
      if (Joint.enabled()) Args.push_back(Carrier);
      auto *NC = CB.CreateCall(NF, Args);
      NC->setCallingConv(NF->getCallingConv());
      if (C->isNoTailCall()) NC->setTailCallKind(CallInst::TCK_NoTail);
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
    // The denominator absorbed_results is measured against, together with the
    // argument pairs: one rebuild per return site, plus one split per argument
    // per call site.
    Row["result_rebuilds"] = Returns;
    Row["call_sites_rewritten"] = Site;
    if (O.SelfRecursion) Row["recursive_calls_rewritten"] = SelfSites;
    Row["activation_allocas"] = Allocas;
    if (Joint.enabled()) (*Row.getObject("joint_arguments"))["mask_instructions"] = Joint.MaskInstructions;
    if (!F.use_empty()) report_fatal_error("native encoded call left a plaintext use");
    F.eraseFromParent();
    ++Encoded;
  }

public:
  Interfaces(Module &M, uint64_t Seed, const NativeCallOptions &O)
      : M(M), RNG(Rng(Seed).fork("native-encoded-calls-v1")), O(O) {
    findCycles(M, Cyclic, &SelfRecursive);
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

      SmallPtrSet<const Function *, 8> Callers;
      std::string Reason = interfaceBlocker(*F, Cyclic, Callers, O.SelfRecursion && SelfRecursive.contains(F));
      if (Reason.empty() && F->hasFnAttribute(NativeCallPolicyAttr) &&
          F->getFnAttribute(NativeCallPolicyAttr).getValueAsString() != NativeCallPolicyInterface)
        Reason = "call-policy-owner";
      if (Reason.empty() && Encoded >= O.Functions) Reason = "function-budget";

      // absorbed_* count pairs a later pass consumed without a scalar decode.
      // They stay zero here: on its own this interface only moves the decode
      // across the call boundary.
      json::Object Row{{"function", F->getName().str()},
          {"status", Reason.empty() ? "encoded" : "skipped"}, {"reason", Reason},
          {"parameters", F->arg_size()}, {"encoded_parameters", 0},
          {"returns_pair", false}, {"result_rebuilds", 0}, {"widths", std::move(Widths)},
          {"callers", Callers.size()}, {"call_sites_rewritten", 0},
          {"wrapper_retained", false}, {"representation", "xor-pair-v1"},
          {"encoded_function", ""}, {"activation_allocas", 0},
          {"absorbed_arguments", 0}, {"partially_absorbed_arguments", 0}, {"absorbed_results", 0}};
      if (O.JointArguments) {
        json::Array ArgumentWidths;
        for (Argument &A : F->args()) ArgumentWidths.push_back(supported(A.getType()) ? A.getType()->getIntegerBitWidth() : 0);
        Row["argument_widths"] = std::move(ArgumentWidths);
      }
      if (O.SelfRecursion) {
        Row["recursion_contract"] = "direct-self-activation-v1";
        Row["self_recursive"] = SelfRecursive.contains(F);
        Row["recursive_calls_rewritten"] = 0;
      }
      if (Reason.empty()) { Allocas = 0; encode(*F, Row); }
      Report.push_back(std::move(Row));
    }
    return Report;
  }
};
// Which source-owned functions bounded merging may still fold. FunctionMerging
// only considers a function the driver gave an `fmerge` clause, so reading the
// driver's own recorded spec avoids re-deriving that pass's eligibility. It
// over-approximates on purpose: a function merging would reject anyway is only
// ever contracted too eagerly, which can cost an interface but can never
// promise one that merging then destroys.
bool mergeCandidate(const Function &F) {
  return F.hasFnAttribute("sre.native.original") &&
      F.getFnAttribute("sre.native.spec").getValueAsString().contains("fmerge(");
}
// The label FunctionMerging would bucket this candidate under. The native
// profile emits no explicit group, and that pass calls an unlabelled bucket
// `_auto`; an explicit `group=` in the spec is read back here.
std::string mergeGroupLabel(const Function &F) {
  if (!mergeCandidate(F)) return "";
  StringRef Spec = F.getFnAttribute("sre.native.spec").getValueAsString();
  StringRef Clause = Spec.substr(Spec.find("fmerge("));
  Clause = Clause.substr(0, Clause.find(')'));
  size_t At = Clause.find("group=");
  if (At == StringRef::npos) return "_auto";
  StringRef Label = Clause.substr(At + 6);
  return Label.substr(0, Label.find(',')).str();
}

// The call graph as it will look once merging has run: every candidate this
// arbitration did not reserve is contracted into one node per merge group, so
// a call into a group and a call back out of it close exactly the cycle the
// call pass would later refuse as `recursive`. Contracting whole groups rather
// than merging's actual chunks can only add edges, so a function this reports
// as acyclic stays acyclic whatever chunking merging picks.
void buildMergeView(Module &M, const SmallPtrSetImpl<Function *> &Reserved,
                    DenseMap<const Function *, unsigned> &Node,
                    SmallVectorImpl<SmallVector<unsigned, 4>> &Edges,
                    const SmallPtrSetImpl<const Function *> *AllowedSelf = nullptr) {
  // Module order throughout: no pointer or use-list order reaches a node id.
  StringMap<unsigned> Groups;
  for (Function &F : M) {
    if (F.isDeclaration()) continue;
    if (mergeCandidate(F) && !Reserved.count(&F)) {
      std::string Label = mergeGroupLabel(F);
      auto It = Groups.find(Label);
      if (It == Groups.end()) {
        It = Groups.insert({Label, unsigned(Edges.size())}).first;
        Edges.emplace_back();
      }
      Node[&F] = It->second;
      continue;
    }
    Node[&F] = Edges.size();
    Edges.emplace_back();
  }
  for (Function &F : M) {
    if (F.isDeclaration()) continue;
    unsigned From = Node.find(&F)->second;
    for (Instruction &I : instructions(F))
      if (auto *C = dyn_cast<CallBase>(&I))
        if (Function *G = C->getCalledFunction()) {
          // Ignore only an already-proved self edge on a reserved standalone
          // interface. A merge-induced multi-node cycle must still lose.
          if (G == &F && Reserved.contains(&F) && AllowedSelf && AllowedSelf->contains(&F)) continue;
          if (auto It = Node.find(G);
              It != Node.end() && !llvm::is_contained(Edges[From], It->second))
            Edges[From].push_back(It->second);
        }
  }
}

// Nodes on a cycle: an SCC with more than one member, or a self edge. Same
// iterative Tarjan as findCycles, over the contracted node ids.
void cyclicNodes(ArrayRef<SmallVector<unsigned, 4>> Edges, SmallVectorImpl<bool> &OnCycle) {
  unsigned N = Edges.size();
  OnCycle.assign(N, false);
  SmallVector<unsigned, 64> Index(N, 0), Low(N, 0), Component;
  SmallVector<bool, 64> Open(N, false);
  struct Frame { unsigned V, Child; };
  unsigned Next = 1;                       // index 0 means unvisited
  for (unsigned Root = 0; Root < N; ++Root) {
    if (Index[Root]) continue;
    Index[Root] = Low[Root] = Next++;
    Component.push_back(Root); Open[Root] = true;
    SmallVector<Frame, 32> Work{{Root, 0}};
    while (!Work.empty()) {
      unsigned V = Work.back().V;
      if (Work.back().Child < Edges[V].size()) {
        unsigned W = Edges[V][Work.back().Child++];
        if (!Index[W]) {
          Index[W] = Low[W] = Next++;
          Component.push_back(W); Open[W] = true;
          Work.push_back({W, 0});
        } else if (Open[W])
          Low[V] = std::min(Low[V], Index[W]);
        continue;
      }
      Work.pop_back();
      if (!Work.empty()) Low[Work.back().V] = std::min(Low[Work.back().V], Low[V]);
      if (Low[V] != Index[V]) continue;
      SmallVector<unsigned, 8> Members;
      unsigned Member = 0;
      do {
        Member = Component.pop_back_val(); Open[Member] = false; Members.push_back(Member);
      } while (Member != V);
      if (Members.size() > 1 || llvm::is_contained(Edges[V], V))
        for (unsigned X : Members) OnCycle[X] = true;
    }
  }
}
} // namespace

std::vector<std::string> nativeFusionCandidates(const Module &M) {
  // Module order. Declarations cannot be absorbed and are not tracked.
  std::vector<std::string> Names;
  for (const Function &F : M)
    if (!F.isDeclaration()) Names.push_back(F.getName().str());
  return Names;
}

json::Array nativeFusionAbsorption(ArrayRef<std::string> Before, const Module &After,
                                   const json::Array &Fused) {
  // Which callers fusion inlined each callee into, from its own rows. A callee
  // inlined at one site but still called from another has not been absorbed,
  // so presence in the module, not this map, decides.
  StringMap<SmallVector<std::string, 2>> Inlined;
  for (const json::Value &Value : Fused) {
    const json::Object *Row = Value.getAsObject();
    if (!Row) continue;
    auto Status = Row->getString("status"), Callee = Row->getString("callee"),
         Caller = Row->getString("caller");
    if (!Status || *Status != "fused" || !Callee || !Caller || Callee->empty()) continue;
    auto &Callers = Inlined[*Callee];
    if (!llvm::is_contained(Callers, Caller->str())) Callers.push_back(Caller->str());
  }
  json::Array Rows;
  for (StringRef Name : Before) {
    const Function *F = After.getFunction(Name);
    if (F && !F->isDeclaration()) continue;
    auto Found = Inlined.find(Name);
    // The caller named here is where fusion put the body. Fusion can afterwards
    // erase that caller too, so a name recorded here is the origin of the
    // absorption, not a promise that the absorbing function still exists.
    std::string By;
    if (Found != Inlined.end())
      for (const std::string &Caller : Found->second) {
        if (!By.empty()) By += ",";
        By += Caller;
      }
    // Absent from fusion's own record, the function was erased as an unused
    // local definition. That is reported as such and credited to no caller,
    // never guessed at.
    Rows.push_back(json::Object{{"function", Name.str()}, {"absorbed_by", By},
        {"reason", By.empty() ? "dead-after-fusion" : "fusion-inlined"},
        {"absorbing_callers",
         Found == Inlined.end() ? 0 : int64_t(Found->second.size())}});
  }
  return Rows;
}

json::Array planNativeCallPolicy(Module &M, const NativeCallPolicyOptions &O) {
  SmallPtrSet<const Function *, 16> Cyclic, SelfRecursive;
  findCycles(M, Cyclic, &SelfRecursive);
  // Module order. Source-owned is the denominator the driver stamped before
  // any obfuscation pass ran, so a function neither pass takes still gets a row.
  SmallVector<Function *, 64> Source;
  for (Function &F : M)
    if (!F.isDeclaration() && F.hasFnAttribute("sre.native.source")) Source.push_back(&F);

  // The contest is decided in favour of the encoded interface, because merging
  // can still take everything the interface does not win, while the reverse is
  // false: a merged super-function has no per-width interface left to encode.
  DenseMap<const Function *, std::string> Blocker;
  SmallPtrSet<Function *, 16> Reserved;
  unsigned Budget = 0;
  for (Function *F : Source) {
    SmallPtrSet<const Function *, 8> Callers;
    Blocker[F] = interfaceBlocker(*F, Cyclic, Callers, O.SelfRecursion && SelfRecursive.contains(F));
    if (!Blocker[F].empty() || Budget >= O.Interfaces) continue;
    Reserved.insert(F);
    ++Budget;
  }

  // Reserving a function pulls it out of its merge group, which can close a
  // cycle for another reservation, so repeat until the reserved set stops
  // shrinking. It only ever shrinks, so this terminates.
  SmallPtrSet<const Function *, 16> Induced;
  for (bool Changed = true; Changed;) {
    Changed = false;
    DenseMap<const Function *, unsigned> Node;
    SmallVector<SmallVector<unsigned, 4>, 64> Edges;
    buildMergeView(M, Reserved, Node, Edges, O.SelfRecursion ? &SelfRecursive : nullptr);
    SmallVector<bool, 64> OnCycle;
    cyclicNodes(Edges, OnCycle);
    for (Function *F : Source)
      if (Reserved.count(F) && OnCycle[Node.find(F)->second]) {
        Reserved.erase(F);
        Induced.insert(F);
        Changed = true;
      }
  }

  json::Array Rows;
  for (Function *F : Source) {
    const bool Merge = mergeCandidate(*F);
    // Exactly one owner. The interface wins what it can take; merging keeps
    // what the driver gave it an fmerge clause for; anything neither pass can
    // take stays a recorded plaintext boundary. `fused` and `scalar-boundary`
    // are decisions about who may act, never claims that either one did: the
    // reconciled outcome below is the measurement.
    StringRef Policy = Reserved.count(F) ? NativeCallPolicyInterface
        : Merge ? NativeCallPolicyFused : NativeCallPolicyScalar;
    // Why the encoded interface did or did not win this function.
    StringRef Why = "interface-preferred";
    if (!Reserved.count(F)) {
      if (Induced.count(F))
        // Eligible on its own, but merging would close a cycle through it and
        // the call pass refuses a cyclic callee.
        Why = "merge-induced-recursion";
      else if (Blocker[F].empty()) Why = "interface-budget";
      else if (!F->hasFnAttribute("sre.native.original")) Why = "not-selected";
      // interface_blocker names which of the call pass's own refusals applied.
      else Why = "interface-ineligible";
    }
    // The decision goes on the function so merging reads one recorded fact.
    F->addFnAttr(NativeCallPolicyAttr, Policy);
    Rows.push_back(json::Object{{"function", F->getName().str()},
        {"policy", Policy.str()}, {"reason", Why.str()},
        {"merge_group", mergeGroupLabel(*F)}, {"merge_candidate", Merge},
        {"selected", F->hasFnAttribute("sre.native.original")},
        {"interface_blocker", Blocker[F]}, {"outcome", "unknown"}});
  }
  return Rows;
}

void reconcileNativeCallPolicy(Module &M, json::Array &Policy, const json::Array &Calls) {
  StringSet<> Encoded;
  for (const json::Value &V : Calls) {
    const json::Object *Row = V.getAsObject();
    if (!Row) continue;
    auto Name = Row->getString("function"), Status = Row->getString("status");
    if (Name && Status && *Status == "encoded") Encoded.insert(*Name);
  }
  // Every origin a super-function absorbed, named by the merge pass itself
  // rather than guessed from what went missing.
  StringSet<> Folded;
  for (Function &F : M) {
    if (!F.hasFnAttribute("sre.native.merged")) continue;
    StringRef Origins = F.getFnAttribute("sre.native.merged").getValueAsString();
    while (!Origins.empty()) {
      auto [Head, Tail] = Origins.split(',');
      if (!Head.empty()) Folded.insert(Head);
      Origins = Tail;
    }
  }
  for (json::Value &V : Policy) {
    json::Object *Row = V.getAsObject();
    if (!Row) continue;
    auto Name = Row->getString("function");
    if (!Name) continue;
    const Function *F = M.getFunction(*Name);
    const bool Live = F && !F->isDeclaration();
    // unclaimed is the load-bearing one: the function is still its source self,
    // so neither pass took it and no protection may be credited for it.
    StringRef Outcome = "absent";
    if (Encoded.count(*Name)) Outcome = "encoded";
    else if (Folded.count(*Name)) Outcome = Live ? "thunked" : "merged";
    else if (Live) Outcome = "unclaimed";
    (*Row)["outcome"] = Outcome.str();
  }
}

json::Array encodeNativeCalls(Module &M, uint64_t Seed, const NativeCallOptions &O) {
  return Interfaces(M, Seed, O).run();
}

namespace {
const Function *bundleSupplyOwner(const Instruction &I, const Value *V) {
  if (I.getOpcode() != Instruction::Xor || I.getOperand(0) != V) return nullptr;
  if (I.getMetadata("sre.native.call.joint-split")) {
    // A coordinate also feeds the next argument's mask. Supplying it must
    // remask under the existing destination relation, never replace that
    // relation independently as the older two-word interface allowed.
    const Function *Owner = nullptr;
    unsigned Sites = 0;
    for (const Use &U : I.uses()) {
      if (const auto *C = dyn_cast<CallInst>(U.getUser()); C && C->isArgOperand(&U) && C->getCalledFunction()) {
        Owner = C->getCalledFunction(); ++Sites;
      } else {
        const auto *User = dyn_cast<Instruction>(U.getUser());
        if (!User || !User->getMetadata("sre.native.call.state")) return nullptr;
      }
    }
    return Sites == 1 ? Owner : nullptr;
  }
  if (!I.hasOneUse()) return nullptr;
  if (I.getMetadata("sre.native.call.split")) {
    const auto *C = dyn_cast<CallInst>(*I.user_begin());
    return C && C->isArgOperand(&*I.use_begin()) ? C->getCalledFunction() : nullptr;
  }
  if (I.getMetadata("sre.native.call.result")) {
    const auto *Insert = dyn_cast<InsertValueInst>(*I.user_begin());
    if (Insert && Insert->getInsertedValueOperand() == &I && Insert->getIndices().size() == 1 &&
        Insert->getIndices().front() == 0) return I.getFunction();
  }
  return nullptr;
}
}

bool isNativeBundleCallSupply(const Instruction &I, const Value *V) {
  return bundleSupplyOwner(I, V) != nullptr;
}

void supplyNativeBundleCalls(Function &F, Value *V, transfer::Pair P, transfer::Family Family) {
  // Stable function order, not the address/use-list order of a multi-user exit.
  SmallVector<Instruction *, 8> Sites;
  for (Instruction &I : instructions(F)) if (isNativeBundleCallSupply(I, V)) Sites.push_back(&I);
  for (Instruction *I : Sites) {
    const Function *Owner = bundleSupplyOwner(*I, V);
    Instruction *Prev = I->getPrevNode();
    IRBuilder<> B(I);
    Value *Mask = I->getOperand(1);
    transfer::Pair X = Family == transfer::Family::Additive ? transfer::toXor(B, P, Mask) : P;
    Value *E = transfer::remask(B, X, transfer::Family::Xor, Mask);
    // One explicit identity per site gives the retained transaction a unique
    // accounting owner even if constant folding reuses an existing coordinate.
    auto *Supply = new FreezeInst(E, "sre.bundle.call.supply", I->getIterator());
    Supply->setMetadata("sre.native.bundle.call-supply", MDNode::get(F.getContext(), {
        MDString::get(F.getContext(), Owner->getName()),
        MDString::get(F.getContext(), I->getMetadata("sre.native.call.split") ? "argument" : "result")}));
    MDNode *Owned = MDNode::get(F.getContext(), {});
    for (Instruction *N = Prev ? Prev->getNextNode() : &I->getParent()->front(); N != I; N = N->getNextNode())
      N->setMetadata("sre.native.bundle", Owned);
    I->replaceAllUsesWith(Supply);
    I->eraseFromParent();
  }
}

json::Array finishNativeBundleCallOutputs(Module &M, StringMap<NativeCallAbsorption> &Absorbed) {
  json::Array Rows;
  for (Function &F : M) {
    // First-seen owner order is determined by the IR, never by a hash table.
    SmallVector<std::string, 8> Owners;
    StringMap<std::pair<unsigned, unsigned>> Counts;
    for (Instruction &I : instructions(F))
      if (MDNode *MD = I.getMetadata("sre.native.bundle.call-supply")) {
        StringRef Owner = cast<MDString>(MD->getOperand(0))->getString();
        bool Argument = cast<MDString>(MD->getOperand(1))->getString() == "argument";
        if (!Counts.count(Owner)) Owners.push_back(Owner.str());
        auto &Count = Counts[Owner];
        if (Argument) ++Count.first; else ++Count.second;
        ++Absorbed[Owner].Results;
        I.setMetadata("sre.native.bundle.call-supply", nullptr);
      }
    for (const std::string &Owner : Owners) {
      auto Count = Counts.lookup(Owner);
      Rows.push_back(json::Object{{"function", F.getName().str()}, {"interface", Owner},
          {"contract", "bundle-call-supply-v1"}, {"stage", "after-bundles-before-regions"},
          {"argument_pairs", Count.first}, {"result_pairs", Count.second}});
    }
  }
  return Rows;
}

json::Array nativeBundleCallInputs(const Module &M) {
  json::Array Rows;
  for (const Function &F : M) {
    unsigned Full = 0, Partial = 0, Uses = 0;
    for (const Instruction &I : instructions(F))
      if (I.getMetadata("sre.native.call.bundle-input")) {
        if (I.use_empty()) ++Full; else ++Partial;
        Uses += I.getNumUses();
      }
    if (Full + Partial) Rows.push_back(json::Object{{"function", F.getName().str()},
        {"contract", "bundle-call-input-v1"}, {"stage", "after-bundles-before-regions"},
        {"imported_arguments", Full + Partial}, {"fully_absorbed_arguments", Full},
        {"partially_absorbed_arguments", Partial}, {"remaining_scalar_uses", Uses}});
  }
  return Rows;
}

void finishNativeBundleCallInputs(Module &M, StringMap<NativeCallAbsorption> &Absorbed) {
  for (Function &F : M) {
    SmallVector<Instruction *, 8> Dead;
    for (Instruction &I : instructions(F))
      if (I.getMetadata("sre.native.call.bundle-input")) {
        // Connected lowering clears the marker only when its own accounting
        // owns it. Its rollback restores both the marker and the old users.
        I.setMetadata("sre.native.call.bundle-input", nullptr);
        auto &Count = Absorbed[F.getName()];
        if (I.use_empty()) { ++Count.Arguments; Dead.push_back(&I); }
        else ++Count.PartialArguments;
      }
    for (Instruction *I : Dead) I->eraseFromParent();
  }
}

void recordNativeCallAbsorption(json::Array &Rows,
                                const StringMap<NativeCallAbsorption> &Absorbed) {
  for (json::Value &Value : Rows) {
    json::Object *Row = Value.getAsObject();
    if (!Row) continue;
    auto Name = Row->getString("function"), Status = Row->getString("status");
    if (!Name || !Status || *Status != "encoded") continue;
    auto EncodedName = Row->getString("encoded_function");
    if (!EncodedName) continue;
    auto Found = Absorbed.find(*EncodedName);
    if (Found == Absorbed.end()) continue;
    (*Row)["absorbed_arguments"] = Found->second.Arguments;
    (*Row)["partially_absorbed_arguments"] = Found->second.PartialArguments;
    (*Row)["absorbed_results"] = Found->second.Results;
  }
}
} // namespace llvm::obf
