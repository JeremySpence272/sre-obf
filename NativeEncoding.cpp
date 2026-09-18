#include "llvm/Transforms/Obfuscator/NativeEncoding.h"
#include "llvm/Transforms/Obfuscator/NativeBundleMath.h"
#include "llvm/Transforms/Obfuscator/FunctionSnapshot.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;
namespace llvm::obf {
namespace {
cl::opt<int> ForcedFamily("native-family",
    cl::desc("Diagnostic family ablation: -1 seeded, 0 xor, 1 add, 2 rotate, 3 multiply"),
    cl::init(-1));
constexpr unsigned MaxScalarSites = 4096;
constexpr uint64_t MaxDataBytes = 65536;

APInt inverseOdd(const APInt &Odd) {
  // Newton iteration doubles the correct low bits each time, modulo 2^W.
  APInt X(Odd.getBitWidth(), 1);
  for (unsigned Bits = 1; Bits < Odd.getBitWidth(); Bits *= 2)
    X *= APInt(Odd.getBitWidth(), 2) - Odd * X;
  return X;
}

MDNode *tag(LLVMContext &C, StringRef ID, StringRef Family) {
  return MDNode::get(C, {MDString::get(C, ID), MDString::get(C, Family)});
}

// Closed use graph: no address escape, comparisons, stores, aliases, atomics,
// partial/overlapping accesses, bulk copies, or unsupported constant expressions.
bool findLoads(Value *V, ArrayType *AT, SmallPtrSetImpl<Value *> &Seen,
               SmallVectorImpl<LoadInst *> &Loads, std::string &Reason) {
  if (!Seen.insert(V).second) return true;
  for (User *U : V->users()) {
    if (auto *L = dyn_cast<LoadInst>(U)) {
      if (L->getPointerOperand() != V || L->getType() != AT->getElementType() ||
          L->isVolatile() || L->isAtomic()) {
        Reason = "non-scalar-or-volatile-access"; return false;
      }
      if (!L->getFunction()->hasFnAttribute("sre.native.original") &&
          !L->getFunction()->hasFnAttribute("sre.native.helper")) {
        Reason = "unselected-reader"; return false;
      }
      Loads.push_back(L);
    } else if (auto *G = dyn_cast<GEPOperator>(U)) {
      if (G->getPointerOperand() != V ||
          (G->getSourceElementType() != AT &&
           G->getSourceElementType() != AT->getElementType())) {
        Reason = "unsupported-gep"; return false;
      }
      if (G->getSourceElementType() == AT &&
          (G->getNumIndices() != 2 ||
           !isa<ConstantInt>(G->getOperand(1)) ||
           !cast<ConstantInt>(G->getOperand(1))->isZero())) {
        Reason = "unsupported-array-gep"; return false;
      }
      if (!findLoads(U, AT, Seen, Loads, Reason)) return false;
    } else {
      Reason = "address-escape-or-unsupported-use"; return false;
    }
  }
  return true;
}
} // namespace

NativeFamily nativeFamily(Rng &R) {
  if (ForcedFamily < -1 || ForcedFamily > 3)
    report_fatal_error("native-family must be -1 or 0..3");
  return static_cast<NativeFamily>(ForcedFamily >= 0 ? ForcedFamily.getValue() : R.range(4));
}

const char *nativeFamilyName(NativeFamily F) {
  static const char *Names[] = {"xor-shares-v1", "add-shares-v1",
                                "rotate-xor-v1", "odd-multiply-add-v1"};
  return Names[static_cast<unsigned>(F)];
}

APInt encodeNative(const APInt &Plain, const APInt &Key, NativeFamily Family,
                   const APInt &Odd, unsigned Rotation) {
  switch (Family) {
  case NativeFamily::Xor: return Plain ^ Key;
  case NativeFamily::Add: return Plain + Key;
  case NativeFamily::RotateXor: return (Plain ^ Key).rotl(Rotation);
  case NativeFamily::MultiplyAdd: return Plain * Odd + Key;
  }
  llvm_unreachable("family");
}

Value *decodeNative(IRBuilder<> &B, Value *E, Value *K, NativeFamily Family,
                    const APInt &Odd, unsigned Rotation) {
  switch (Family) {
  case NativeFamily::Xor: return B.CreateXor(E, K);
  case NativeFamily::Add: return B.CreateSub(E, K);
  case NativeFamily::RotateXor: {
    unsigned W = E->getType()->getIntegerBitWidth();
    // Rotation is always in [1,W-1]: neither shift can introduce poison.
    Value *R = B.CreateOr(B.CreateLShr(E, Rotation),
                          B.CreateShl(E, W - Rotation));
    return B.CreateXor(R, K);
  }
  case NativeFamily::MultiplyAdd:
    return B.CreateMul(B.CreateSub(E, K), ConstantInt::get(B.getContext(), inverseOdd(Odd)));
  }
  llvm_unreachable("family");
}

Value *materializeNative(IRBuilder<> &B, const APInt &Bits, Rng &Root,
                         StringRef Role, unsigned Site) {
  Module &M = *B.GetInsertBlock()->getModule();
  auto *Sites = M.getOrInsertNamedMetadata("sre.native.sites");
  if (Site >= 64 || Sites->getNumOperands() >= MaxScalarSites) {
    auto *Limits = M.getOrInsertNamedMetadata("sre.native.family_limits");
    // One record per invocation would itself be an unbounded report.
    if (Limits->getNumOperands() == 0)
      Limits->addOperand(tag(M.getContext(), "scalar-site-cap", "legacy-fallback"));
    return nullptr;
  }
  Function &F = *B.GetInsertBlock()->getParent();
  StringRef Stage = F.getFnAttribute("sre.native.stage").getValueAsString();
  Rng SiteR = Root.fork("native-families-v1").fork(Stage).fork(Site);
  Rng Choice = SiteR.fork("family"), Coeff = SiteR.fork("coefficients");
  NativeFamily Family = nativeFamily(Choice);
  unsigned W = Bits.getBitWidth();
  // LLVM 22 requires explicit truncation: in release builds, the default
  // constructor can otherwise retain invalid high bits in narrow APInts.
  APInt K(W, Coeff.u64(), false, true), Odd(W, Coeff.u64() | 1, false, true);
  unsigned Rotation = 1 + Coeff.range(W - 1);
  APInt E = encodeNative(Bits, K, Family, Odd, Rotation);
  std::string ID = (F.getName() + "/" + Stage + "/" + Role +
                    "/" + Twine(Site)).str();
  auto *MD = tag(M.getContext(), ID, nativeFamilyName(Family));
  auto *AT = ArrayType::get(B.getIntNTy(W), 2);
  Constant *Values[] = {ConstantInt::get(M.getContext(), E),
                        ConstantInt::get(M.getContext(), K)};
  // Physically writable shares are never modified. No constructor/lazy init,
  // no races, no reliance on entropy/environment. Volatile accesses preserve
  // the intended storage boundary through ordinary backend lowering.
  auto *GV = new GlobalVariable(M, AT, false, GlobalValue::PrivateLinkage,
      ConstantArray::get(AT, Values), "sre.share");
  GV->setMetadata("sre.native.encoding", MD);
  auto Load = [&](unsigned Index) {
    Value *P = B.CreateInBoundsGEP(AT, GV, {B.getInt32(0), B.getInt32(Index)});
    LoadInst *L = B.CreateLoad(AT->getElementType(), P);
    L->setVolatile(true);
    return L;
  };
  Value *Encoded = Load(0), *Key = Load(1);
  Value *Decoded = decodeNative(B, Encoded, Key, Family, Odd, Rotation);
  if (auto *I = dyn_cast<Instruction>(Decoded)) I->setMetadata("sre.native.encoding", MD);
  Sites->addOperand(MD);
  return Decoded;
}

namespace {
json::Object encodeJointData(GlobalVariable &G, ArrayRef<APInt> Plain,
                              ArrayRef<LoadInst *> UnorderedLoads, uint64_t Seed,
                              bool Pin, unsigned &Remaining) {
  Module &M = *G.getParent();
  auto *AT = cast<ArrayType>(G.getValueType());
  unsigned W = AT->getElementType()->getIntegerBitWidth();
  // Keep all pointer and load bindings in stable module/instruction order.
  SmallPtrSet<LoadInst *, 32> Set(UnorderedLoads.begin(), UnorderedLoads.end());
  SmallVector<LoadInst *, 16> Loads;
  SmallVector<Function *, 8> Owners;
  for (Function &F : M) {
    bool Owns = false;
    for (Instruction &I : instructions(F))
      if (auto *L = dyn_cast<LoadInst>(&I); L && Set.contains(L)) { Loads.push_back(L); Owns = true; }
    if (Owns) Owners.push_back(&F);
  }
  uint64_t Cost = 192 * uint64_t(Loads.size());
  json::Object Row{{"object", G.getName().str()}, {"status", "skipped"},
      {"contract", "sre-immutable-tile-v1"}, {"read_sites", Loads.size()},
      {"growth_estimate", Cost}, {"growth_available", Remaining}, {"growth_retained", 0}, {"pins", Pin}};
  if (Cost > Remaining) { Row["reason"] = "immutable-growth-budget"; return Row; }
  Rng R = Rng(Seed).fork("native-immutable-tiles-v1").fork(G.getName());
  bool Additive = R.u64() & 1;
  APInt K0(W, R.u64(), false, true), K1(W, R.u64() | 1, false, true);
  SmallVector<APInt, 4> Salts;
  SmallVector<unsigned, 4> Rotations;
  for (unsigned K = 0; K < 4; ++K) {
    Salts.emplace_back(W, R.u64(), false, true); Rotations.push_back(1 + R.range(W - 1));
  }
  SmallVector<Constant *, 32> Encoded;
  APInt Carrier(W, 0), Previous(W, 0);
  for (unsigned I = 0; I < Plain.size(); ++I) {
    unsigned K = I % 4;
    if (!K) { Carrier = K0 + APInt(W, I, false, true) * K1; Previous = Carrier; }
    APInt Mask = ((Previous ^ Salts[K]) + Carrier).rotl(Rotations[K]);
    Mask ^= Previous * (Salts[K] | APInt(W, 1));
    Previous = Additive ? Plain[I] + Mask : Plain[I] ^ Mask;
    Encoded.push_back(ConstantInt::get(M.getContext(), Previous));
  }
  Constant *OldInitializer = G.getInitializer();
  bool OldConstant = G.isConstant();
  SmallVector<std::unique_ptr<FunctionSnapshot>, 8> Snapshots;
  unsigned Before = 0;
  for (Function *F : Owners) {
    Before += F->getInstructionCount();
    Snapshots.push_back(std::make_unique<FunctionSnapshot>(*F));
  }
  G.setInitializer(ConstantArray::get(AT, Encoded));
  G.setConstant(false); // No runtime writes; pinning is a separate ablation.
  unsigned Site = 0;
  for (LoadInst *L : Loads) {
    Function &F = *L->getFunction();
    F.setMemoryEffects(MemoryEffects::unknown());
    F.removeFnAttr(Attribute::Speculatable);
    IRBuilder<> B(L);
    Instruction *Prev = L->getPrevNode();
    Value *Index = B.CreatePtrDiff(AT->getElementType(), L->getPointerOperand(), &G);
    auto *IT = cast<IntegerType>(Index->getType());
    Value *Base = B.CreateAnd(Index, ConstantInt::get(IT, ~uint64_t(3)));
    Value *Slot = B.CreateAnd(Index, ConstantInt::get(IT, 3));
    Value *C = B.CreateAdd(ConstantInt::get(M.getContext(), K0),
        B.CreateMul(B.CreateZExtOrTrunc(Base, AT->getElementType()), ConstantInt::get(M.getContext(), K1)));
    SmallVector<Value *, 4> Z, Masks;
    for (unsigned K = 0; K < 4; ++K) {
      Value *Offset = B.CreateAdd(Base, ConstantInt::get(IT, K));
      Value *Last = ConstantInt::get(IT, Plain.size() - 1);
      // A tail's nonexistent cells are NOT read. Duplicate the last legal
      // coordinate for unused candidate slots; a defined source index can
      // never select them. This adds no access outside the original object.
      Offset = B.CreateSelect(B.CreateICmpULT(Offset, Last), Offset, Last);
      auto *E = B.CreateLoad(AT->getElementType(),
          B.CreateInBoundsGEP(AT, &G, {B.getInt32(0), Offset}));
      // The original selected load can promise stronger alignment than its
      // neighbours. Conversely, a deliberately under-aligned global need not
      // satisfy the element ABI alignment. Prove the new full-tile reads from
      // the base and element stride, not from the selected source load.
      E->setAlignment(commonAlignment(G.getAlign().value_or(M.getDataLayout().getABITypeAlign(AT)), W / 8));
      E->setVolatile(Pin);
      Masks.push_back(bundle::mask(B, Z, C, K, Salts[K].getZExtValue(), Rotations[K]));
      Z.push_back(E);
    }
    Value *E = Z[0], *Key = Masks[0];
    for (unsigned K = 1; K < 4; ++K) {
      Value *Selected = B.CreateICmpEQ(Slot, ConstantInt::get(IT, K));
      E = B.CreateSelect(Selected, Z[K], E); Key = B.CreateSelect(Selected, Masks[K], Key);
    }
    Value *Decoded = Additive ? B.CreateSub(E, Key, "sre.immutable.boundary")
                              : B.CreateXor(E, Key, "sre.immutable.boundary");
    auto *I = cast<Instruction>(Decoded);
    I->setMetadata("sre.native.immutable.pair", MDNode::get(M.getContext(), {
        MDString::get(M.getContext(), G.getName()), MDString::get(M.getContext(), F.getName()),
        ConstantAsMetadata::get(B.getInt32(Site++)), ConstantAsMetadata::get(B.getInt32(L->getNumUses()))}));
    auto *Tag = MDNode::get(M.getContext(), MDString::get(M.getContext(), "native-immutable-tile-v1"));
    for (Instruction *New = Prev ? Prev->getNextNode() : &L->getParent()->front(); New != L; New = New->getNextNode())
      New->setMetadata("sre.native.bundle", Tag);
    L->replaceAllUsesWith(Decoded);
    L->eraseFromParent();
  }
  unsigned After = 0;
  for (Function *F : Owners) {
    if (verifyFunction(*F, &errs())) report_fatal_error("immutable bundle emitted invalid IR");
    After += F->getInstructionCount();
  }
  Row["growth_attempted"] = After > Before ? After - Before : 0;
  if (After > uint64_t(Before) + Cost) {
    G.setInitializer(OldInitializer); G.setConstant(OldConstant);
    for (auto &Snapshot : Snapshots) Snapshot->restore();
    Row["status"] = "rolled-back"; Row["reason"] = "immutable-growth-budget";
    return Row;
  }
  unsigned Growth = After > Before ? After - Before : 0;
  Remaining -= Growth;
  G.setMetadata("sre.native.encoding", tag(M.getContext(), G.getName(), "immutable-triangular-v1"));
  Row["status"] = "encoded"; Row["reason"] = "";
  Row["family"] = Additive ? "triangular-additive-v1" : "triangular-xor-v1";
  Row["width"] = W; Row["cells"] = Plain.size(); Row["tile_cells"] = 4;
  Row["bytes"] = Plain.size() * (W / 8); Row["physical_reads_per_site"] = 4;
  Row["storage"] = "immutable-closed-initialized-array";
  Row["tail"] = "duplicate-last-valid-coordinate";
  json::Array SaltValues, RotationValues;
  for (unsigned K = 0; K < 4; ++K) {
    SaltValues.push_back(utohexstr(Salts[K].getZExtValue())); RotationValues.push_back(Rotations[K]);
  }
  Row["salts_hex"] = std::move(SaltValues); Row["rotations"] = std::move(RotationValues);
  Row["carrier_base_hex"] = utohexstr(K0.getZExtValue());
  Row["carrier_step_hex"] = utohexstr(K1.getZExtValue());
  Row["growth_retained"] = Growth;
  return Row;
}
} // namespace

json::Array nativeImmutableContinuity(Module &M, StringRef Stage, bool EraseDead) {
  json::Array Rows;
  SmallVector<Instruction *, 32> Dead;
  for (Function &F : M) for (Instruction &I : instructions(F)) {
    auto *MD = I.getMetadata("sre.native.immutable.pair");
    if (!MD || MD->getNumOperands() != 4 || !isa<MDString>(MD->getOperand(0)) ||
        !isa<MDString>(MD->getOperand(1)) || !mdconst::dyn_extract<ConstantInt>(MD->getOperand(2)) ||
        !mdconst::dyn_extract<ConstantInt>(MD->getOperand(3))) continue;
    unsigned Original = mdconst::extract<ConstantInt>(MD->getOperand(3))->getZExtValue();
    unsigned Remaining = I.getNumUses();
    Rows.push_back(json::Object{{"schema", "sre-immutable-continuity-v1"},
        {"object", cast<MDString>(MD->getOperand(0))->getString().str()},
        {"reader_at_encoding", cast<MDString>(MD->getOperand(1))->getString().str()},
        {"current_reader", F.getName().str()},
        {"site", mdconst::extract<ConstantInt>(MD->getOperand(2))->getZExtValue()},
        {"original_scalar_uses", Original}, {"remaining_scalar_uses", Remaining},
        {"eliminated_scalar_uses", Original > Remaining ? Original - Remaining : 0},
        {"added_scalar_uses", Remaining > Original ? Remaining - Original : 0},
        {"scope", Stage.str()}, {"hardness_evaluated", false}});
    if (EraseDead && I.use_empty()) Dead.push_back(&I);
  }
  for (Instruction *I : Dead) I->eraseFromParent();
  return Rows;
}

json::Array encodeNativeData(Module &M, uint64_t Seed, bool Joint, bool Pin, unsigned GrowthBudget) {
  json::Array Records;
  SmallVector<GlobalVariable *, 32> Originals;
  for (GlobalVariable &G : M.globals())
    if (!G.getName().starts_with("llvm.") && !G.getMetadata("sre.native.encoding"))
      Originals.push_back(&G);
  uint64_t Bytes = 0;
  for (GlobalVariable *G : Originals) {
    auto *AT = dyn_cast<ArrayType>(G->getValueType());
    if (!AT || !AT->getElementType()->isIntegerTy()) continue;
    unsigned W = AT->getElementType()->getIntegerBitWidth();
    std::string Reason;
    SmallPtrSet<Value *, 32> Seen;
    SmallVector<LoadInst *, 16> Loads;
    uint64_t Size = M.getDataLayout().getTypeAllocSize(AT).getFixedValue();
    if (!G->hasLocalLinkage() || !G->isConstant() || !G->hasInitializer() ||
        G->isThreadLocal() || G->getAddressSpace() != 0 || G->hasSection() || G->isExternallyInitialized())
      Reason = "linkage-mutability-or-storage";
    else if (W != 8 && W != 16 && W != 32 && W != 64)
      Reason = "unsupported-width";
    else if (Joint && AT->getNumElements() == 0)
      Reason = "no-initialized-cells";
    else if (Size > MaxDataBytes || Bytes > MaxDataBytes - Size)
      Reason = "module-data-byte-cap";
    else if (!findLoads(G, AT, Seen, Loads, Reason)) {}
    else if (Loads.empty()) Reason = "no-scalar-readers";

    SmallVector<APInt, 32> Plain;
    if (Reason.empty())
      for (unsigned I = 0; I < AT->getNumElements(); ++I) {
        auto *V = dyn_cast_or_null<ConstantInt>(G->getInitializer()->getAggregateElement(I));
        if (!V) { Reason = "non-integer-initializer"; break; }
        Plain.push_back(V->getValue());
      }
    if (!Reason.empty()) {
      Records.push_back(json::Object{{"object", G->getName().str()},
          {"status", "skipped"}, {"reason", Reason}});
      continue;
    }
    if (Joint) {
      auto Row = encodeJointData(*G, Plain, Loads, Seed, Pin, GrowthBudget);
      if (Row.getString("status") == "encoded") Bytes += Size;
      Records.push_back(std::move(Row));
      continue;
    }
    Rng ObjectR = Rng(Seed).fork("native-data-v1").fork(G->getName());
    Rng Choice = ObjectR.fork("family"), Coeff = ObjectR.fork("coefficients");
    NativeFamily Family = nativeFamily(Choice);
    APInt K0(W, Coeff.u64(), false, true), K1(W, Coeff.u64() | 1, false, true);
    APInt K2(W, Coeff.u64(), false, true), K3(W, Coeff.u64() | 1, false, true);
    APInt Odd(W, Coeff.u64() | 1, false, true);
    unsigned Rotation = 1 + Coeff.range(W - 1);
    SmallVector<Constant *, 32> Encoded;
    for (unsigned I = 0; I < Plain.size(); ++I) {
      APInt Key = (I & 1 ? K2 : K0) + APInt(W, I, false, true) * (I & 1 ? K3 : K1);
      Encoded.push_back(ConstantInt::get(M.getContext(),
          encodeNative(Plain[I], Key, Family, Odd, Rotation)));
    }
    G->setInitializer(ConstantArray::get(AT, Encoded));
    G->setMetadata("sre.native.encoding",
                   tag(M.getContext(), G->getName(), nativeFamilyName(Family)));
    Type *T = AT->getElementType();
    auto *H = Function::Create(FunctionType::get(T, {T, T}, false),
        GlobalValue::InternalLinkage, "sre.decode", M);
    markObfGenerated(*H);
    H->addFnAttr("sre.native.helper", "data-decoder");
    H->addFnAttr("sre.native.origin", G->getName());
    H->addFnAttr(Attribute::NoInline);
    auto *Entry = BasicBlock::Create(M.getContext(), "entry", H);
    auto *Even = BasicBlock::Create(M.getContext(), "even", H);
    auto *OddBB = BasicBlock::Create(M.getContext(), "odd", H);
    auto *Join = BasicBlock::Create(M.getContext(), "join", H);
    IRBuilder<> B(Entry);
    Value *Index = H->getArg(1);
    B.CreateCondBr(B.CreateICmpEQ(B.CreateAnd(Index, ConstantInt::get(T, 1)),
                                ConstantInt::get(T, 0)), Even, OddBB);
    auto MakeKey = [&](BasicBlock *BB, APInt A, APInt S) {
      B.SetInsertPoint(BB);
      Value *K = B.CreateAdd(ConstantInt::get(M.getContext(), A),
          B.CreateMul(Index, ConstantInt::get(M.getContext(), S)));
      B.CreateBr(Join);
      return K;
    };
    Value *KE = MakeKey(Even, K0, K1), *KO = MakeKey(OddBB, K2, K3);
    B.SetInsertPoint(Join);
    auto *Key = B.CreatePHI(T, 2);
    Key->addIncoming(KE, Even); Key->addIncoming(KO, OddBB);
    B.CreateRet(decodeNative(B, H->getArg(0), Key, Family, Odd, Rotation));

    for (LoadInst *L : Loads) {
      // A generated reader can be exempt from the later helper profile. Its
      // decoder may still acquire volatile reads, so invalidate the reader's
      // original memory promises at the rewrite boundary itself.
      L->getFunction()->setMemoryEffects(MemoryEffects::unknown());
      L->getFunction()->removeFnAttr(Attribute::Speculatable);
      IRBuilder<> At(L->getNextNode());
      // Both pointers refer into the same proven, non-escaping array.
      Value *IndexV = At.CreatePtrDiff(T, L->getPointerOperand(), G);
      IndexV = At.CreateZExtOrTrunc(IndexV, T);
      // Capture users before adding the decoding call (which itself uses L).
      SmallVector<Use *, 8> Uses;
      for (Use &U : L->uses()) Uses.push_back(&U);
      Value *Decoded = At.CreateCall(H, {L, IndexV});
      for (Use *U : Uses) U->set(Decoded);
      // Optimized-source range facts describe plaintext, not encoded bytes.
      L->setMetadata(LLVMContext::MD_range, nullptr);
      L->setMetadata(LLVMContext::MD_invariant_load, nullptr);
    }
    Bytes += Size;
    Records.push_back(json::Object{{"object", G->getName().str()},
        {"status", "encoded"}, {"width", W}, {"bytes", static_cast<int64_t>(Size)},
        {"read_sites", static_cast<int64_t>(Loads.size())},
        {"family", nativeFamilyName(Family)}, {"helper", H->getName().str()}});
  }
  return Records;
}

json::Object nativeEncodingInventory(Module &M) {
  json::Array Families;
  unsigned Counts[4] = {};
  if (auto *Sites = M.getNamedMetadata("sre.native.sites"))
    for (MDNode *N : Sites->operands())
      for (unsigned I = 0; I < 4; ++I)
        if (cast<MDString>(N->getOperand(1))->getString() ==
            nativeFamilyName(static_cast<NativeFamily>(I))) ++Counts[I];
  for (unsigned I = 0; I < 4; ++I)
    Families.push_back(json::Object{
        {"family", nativeFamilyName(static_cast<NativeFamily>(I))}, {"sites", Counts[I]}});
  return json::Object{{"registry", "native-families-v1"},
      {"emitted_sites_including_rolled_back", std::move(Families)},
      {"site_cap_reached", M.getNamedMetadata("sre.native.family_limits") != nullptr},
      {"effective_decompiler_diversity", "unmeasured"}};
}
} // namespace llvm::obf
