#include "llvm/Transforms/Obfuscator/NativeBundle.h"
#include "llvm/Transforms/Obfuscator/NativeTransfer.h"
#include "llvm/Transforms/Obfuscator/FunctionSnapshot.h"
#include "llvm/Transforms/Obfuscator/NativePlan.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Verifier.h"
#include <algorithm>

using namespace llvm;
namespace llvm::obf {
namespace {
constexpr StringLiteral OriginTag = "sre.native.input-origin";
constexpr StringLiteral BundleTag = "sre.native.bundle";
constexpr unsigned MinNodes = 8, MaxRegions = 8;
using transfer::Family;
using transfer::Pair;

std::string origin(const Instruction &I) {
  if (auto *MD = I.getMetadata(OriginTag))
    if (MD->getNumOperands() == 1)
      if (auto *S = dyn_cast<MDString>(MD->getOperand(0))) return S->getString().str();
  return {}; // Never silently relabel generated code as a frontend operation.
}
bool supported(const Instruction &I) {
  if (!I.getType()->isIntegerTy() || I.getMetadata(BundleTag)) return false;
  unsigned W = I.getType()->getIntegerBitWidth();
  if (!llvm::is_contained(ArrayRef<unsigned>{8, 16, 32, 64}, W)) return false;
  // Do not steal encoded-call coordinates from their current owner.
  for (StringRef Tag : {"sre.native.call.arg", "sre.native.call.split",
                        "sre.native.call.result", "sre.native.call.state"})
    if (I.getMetadata(Tag)) return false;
  switch (I.getOpcode()) {
  case Instruction::Add: case Instruction::Sub: case Instruction::Mul:
  case Instruction::And: case Instruction::Or: case Instruction::Xor: return true;
  case Instruction::Shl: case Instruction::LShr: case Instruction::AShr: {
    const auto *C = dyn_cast<ConstantInt>(I.getOperand(1));
    return C && C->getValue().ult(W);
  }
  default: return false;
  }
}

// The executable plan is a bounded register schedule, not an observation of an
// already-expanded graph. Operands and slots are decided and validated before
// any instruction is inserted. LLVM pointers live only in the separate binding.
struct Operand {
  bool Constant = false;
  uint64_t Bits = 0;
  unsigned Slot = 0;
};
struct Step {
  unsigned Opcode = 0, Destination = 0;
  Operand X, Y;
  std::string Origin;
};
struct Program {
  unsigned ID = 0, Width = 0, Lanes = 0, EstimatedCost = 0;
  plan::Representation Rep;
  SmallVector<Step, 32> Steps;
  SmallVector<unsigned, 4> OutputSlots;
  SmallVector<uint64_t, 4> Salts;
  SmallVector<unsigned, 4> Rotations;
  Family coordinates() const {
    switch (Rep.Fam) {
    case plan::Family::TriangularXor: return Family::Xor;
    case plan::Family::TriangularAdditive: return Family::Additive;
    default: llvm_unreachable("unverified bundle representation");
    }
  }
};
struct Binding {
  Program P;
  SmallVector<Instruction *, 32> Nodes, Outputs;
  SmallVector<Value *, 4> Inputs;
  unsigned BoundaryUses = 0;
};

bool schedule(ArrayRef<Instruction *> Nodes, unsigned Lanes, Binding &Out) {
  if (Nodes.size() < MinNodes) return false;
  SmallPtrSet<Instruction *, 32> Members(Nodes.begin(), Nodes.end());
  DenseMap<Value *, unsigned> Last;
  for (unsigned N = 0; N < Nodes.size(); ++N) {
    for (Value *V : Nodes[N]->operands()) {
      if (isa<ConstantInt>(V)) continue;
      auto *I = dyn_cast<Instruction>(V);
      if ((!I || !Members.contains(I)) && !llvm::is_contained(Out.Inputs, V))
        Out.Inputs.push_back(V);
      Last[V] = N;
    }
    bool Escapes = false;
    for (User *U : Nodes[N]->users()) {
      auto *I = dyn_cast<Instruction>(U);
      if (!I || !Members.contains(I)) { ++Out.BoundaryUses; Escapes = true; }
    }
    if (Escapes) Out.Outputs.push_back(Nodes[N]);
  }
  // Multiple actual input values AND multiple consumed output values. These
  // are syntactic dependencies, not a proof of independent input entropy.
  if (Out.Inputs.size() < 2 || Out.Inputs.size() > Lanes || Out.Outputs.size() < 2 ||
      Out.Outputs.size() > Lanes) return false;
  SmallPtrSet<Instruction *, 32> Useful;
  SmallVector<Instruction *, 32> Work(Out.Outputs.begin(), Out.Outputs.end());
  while (!Work.empty()) {
    Instruction *I = Work.pop_back_val();
    if (!Useful.insert(I).second) continue;
    for (Value *V : I->operands())
      if (auto *Def = dyn_cast<Instruction>(V); Def && Members.contains(Def)) Work.push_back(Def);
  }
  if (Useful.size() != Nodes.size()) return false;
  for (Instruction *I : Out.Outputs) Last[I] = Nodes.size();
  SmallVector<Value *, 4> Slots(Lanes, nullptr);
  for (unsigned N = 0; N < Out.Inputs.size(); ++N) Slots[N] = Out.Inputs[N];
  auto slot = [&](Value *V) {
    auto It = llvm::find(Slots, V);
    return It == Slots.end() ? plan::Invalid : unsigned(It - Slots.begin());
  };
  auto operand = [&](Value *V) {
    if (auto *C = dyn_cast<ConstantInt>(V)) return Operand{true, C->getZExtValue(), 0};
    return Operand{false, 0, slot(V)};
  };
  for (unsigned N = 0; N < Nodes.size(); ++N) {
    Instruction *I = Nodes[N];
    Step S;
    S.Opcode = I->getOpcode(); S.Origin = origin(*I);
    S.X = operand(I->getOperand(0)); S.Y = operand(I->getOperand(1));
    if ((!S.X.Constant && S.X.Slot == plan::Invalid) ||
        (!S.Y.Constant && S.Y.Slot == plan::Invalid)) return false;
    // Read both old operands before reusing their last-use slot.
    for (Value *&V : Slots) if (V && Last.lookup(V) <= N) V = nullptr;
    unsigned Dest = slot(nullptr);
    if (Dest == plan::Invalid) return false;
    S.Destination = Dest; Slots[Dest] = I;
    Out.P.Steps.push_back(std::move(S));
  }
  for (Instruction *I : Out.Outputs) {
    unsigned K = slot(I);
    if (K == plan::Invalid) return false;
    Out.P.OutputSlots.push_back(K);
  }
  Out.Nodes.append(Nodes.begin(), Nodes.end());
  Out.P.Width = Nodes.front()->getType()->getIntegerBitWidth();
  Out.P.Lanes = Lanes;
  // Conservative primitive expansion plus tuple repair. Exact function growth
  // is checked transactionally; estimates are never counted as emitted work.
  Out.P.EstimatedCost = 256 + unsigned(Nodes.size()) * 1200;
  return true;
}

bool valid(const Binding &B) {
  const Program &P = B.P;
  if (P.Steps.size() != B.Nodes.size() || P.Steps.size() < MinNodes ||
      P.OutputSlots.size() != B.Outputs.size() || P.Salts.size() != P.Lanes ||
      P.Rotations.size() != P.Lanes) return false;
  if ((P.Rep.Fam != plan::Family::TriangularXor && P.Rep.Fam != plan::Family::TriangularAdditive) ||
      P.Rep.Rev != 1 || P.Rep.LogicalWidth != P.Width || P.Rep.LaneWidth != P.Width ||
      P.Rep.Lanes != P.Lanes + 1 || P.Rep.Verified != plan::Verification::Algebraic) return false;
  for (unsigned N = 0; N < P.Steps.size(); ++N) {
    const Step &S = P.Steps[N];
    if (!supported(*B.Nodes[N]) || S.Opcode != B.Nodes[N]->getOpcode() ||
        B.Nodes[N]->getType()->getIntegerBitWidth() != P.Width || S.Destination >= P.Lanes ||
        (!S.X.Constant && S.X.Slot >= P.Lanes) || (!S.Y.Constant && S.Y.Slot >= P.Lanes)) return false;
  }
  for (unsigned K : P.OutputSlots) if (K >= P.Lanes) return false;
  for (unsigned R : P.Rotations) if (!R || R >= P.Width) return false;
  return true;
}

// Encoded coordinates are chained, not the plaintext values:
//   Z[0] = X[0] (+ or xor) H(M)
//   Z[k] = X[k] (+ or xor) H(Z[k-1], M, k).
// Replacing one slot repairs every affected downstream coordinate with the
// old/new masks, without reconstructing the other logical values. The complete
// tuple persists across all the program's operations and has multiple outputs.
class Lowering {
  Function &F;
  const Program &P;
  IRBuilder<> B;
  SmallVector<Value *, 4> Z;
  Value *M = nullptr;
  MDNode *Tag;
  bool Pin;
  ConstantInt *c(uint64_t X) { return ConstantInt::get(B.getIntNTy(P.Width), X); }
  Value *rotate(Value *X, unsigned R) {
    return B.CreateOr(B.CreateShl(X, R), B.CreateLShr(X, P.Width - R));
  }
  Value *mask(ArrayRef<Value *> State, unsigned K) {
    Value *A = K ? State[K - 1] : M;
    // Seeded reversible ARX kernel is a mask function, not a secret key and
    // not itself a claim of inversion resistance.
    Value *T = B.CreateAdd(B.CreateXor(A, c(P.Salts[K])), M);
    return B.CreateXor(rotate(T, P.Rotations[K]), B.CreateMul(A, c(P.Salts[K] | 1)));
  }
  Pair read(const Operand &O) {
    if (O.Constant) return {c(O.Bits), c(0)};
    return {Z[O.Slot], mask(Z, O.Slot)};
  }
  void pin() {
    if (!Pin) return;
    IRBuilder<> Entry(getAllocaIP(F));
    auto *T = ArrayType::get(B.getIntNTy(P.Width), P.Lanes + 1);
    auto *A = Entry.CreateAlloca(T, nullptr, "sre.bundle.tuple");
    A->setMetadata(BundleTag, Tag);
    A->setMetadata("sre.native.value", MDNode::get(F.getContext(), {}));
    SmallVector<Value *, 5> All(Z.begin(), Z.end()); All.push_back(M);
    for (unsigned K = 0; K < All.size(); ++K) {
      Value *Ptr = B.CreateInBoundsGEP(T, A, {B.getInt32(0), B.getInt32(K)});
      B.CreateStore(All[K], Ptr)->setVolatile(true);
      auto *L = B.CreateLoad(B.getIntNTy(P.Width), Ptr);
      L->setVolatile(true);
      if (K < P.Lanes) Z[K] = L; else M = L;
    }
  }
public:
  Lowering(Function &F, const Binding &Bound, bool Pin)
      : F(F), P(Bound.P), B(Bound.Nodes.front()),
        Tag(MDNode::get(F.getContext(), MDString::get(F.getContext(),
            plan::originId(F.getName(), "native-bundle", P.ID)))), Pin(Pin) {}
  void run(const Binding &Bound) {
    Instruction *First = Bound.Nodes.front(), *Prev = First->getPrevNode();
    SmallVector<Value *, 4> Inputs;
    for (Value *V : Bound.Inputs) Inputs.push_back(B.CreateFreeze(V));
    M = B.CreateAdd(rotate(Inputs[0], P.Rotations[0]),
                    B.CreateXor(Inputs[1], c(P.Salts[0])));
    for (unsigned K = 0; K < P.Lanes; ++K) {
      Value *X = K < Inputs.size() ? Inputs[K] : c(0);
      Value *R = mask(Z, K);
      Z.push_back(P.coordinates() == Family::Xor ? B.CreateXor(X, R) : B.CreateAdd(X, R));
    }
    pin(); // Compiler pinning is an independently removable control, not hardness.
    for (const Step &S : P.Steps) {
      Pair X = read(S.X), Y = read(S.Y), Out = X;
      Value *Fresh = B.CreateXor(M, Z.back());
      if (S.Opcode == Instruction::Shl || S.Opcode == Instruction::LShr || S.Opcode == Instruction::AShr) {
        if (P.coordinates() == Family::Additive) X = transfer::toXor(B, X, Fresh);
        auto Op = static_cast<Instruction::BinaryOps>(S.Opcode);
        Out = {B.CreateBinOp(Op, X.E, c(S.Y.Bits)), B.CreateBinOp(Op, X.R, c(S.Y.Bits))};
        if (P.coordinates() == Family::Additive) Out = transfer::toAdditive(B, Out, Fresh);
      } else Out = transfer::operation(B, S.Opcode, X, Y, P.coordinates(), Fresh);
      SmallVector<Value *, 4> Old = Z;
      for (unsigned K = S.Destination; K < P.Lanes; ++K) {
        Pair V = K == S.Destination ? Out : Pair{Old[K], mask(Old, K)};
        Z[K] = transfer::remask(B, V, P.coordinates(), mask(Z, K));
      }
    }
    pin();
    SmallVector<Value *, 4> Outputs;
    for (unsigned K : P.OutputSlots) {
      Value *R = mask(Z, K);
      Value *X = P.coordinates() == Family::Xor ? B.CreateXor(Z[K], R, "sre.bundle.boundary")
                                    : B.CreateSub(Z[K], R, "sre.bundle.boundary");
      if (auto *I = dyn_cast<Instruction>(X))
        I->setMetadata("sre.native.boundary", MDNode::get(F.getContext(), MDString::get(F.getContext(), "bundle-exit")));
      Outputs.push_back(X);
    }
    for (Instruction *I = Prev ? Prev->getNextNode() : &First->getParent()->front(); I != First; I = I->getNextNode())
      I->setMetadata(BundleTag, Tag);
    SmallPtrSet<Instruction *, 32> Members(Bound.Nodes.begin(), Bound.Nodes.end());
    for (unsigned K = 0; K < Bound.Outputs.size(); ++K)
      Bound.Outputs[K]->replaceUsesWithIf(Outputs[K], [&](Use &U) {
        auto *I = dyn_cast<Instruction>(U.getUser());
        return !I || !Members.contains(I);
      });
    for (Instruction *I : llvm::reverse(Bound.Nodes)) I->eraseFromParent();
  }
};

json::Object report(const Binding &B) {
  const Program &P = B.P;
  json::Array Steps, Outputs, Salts, Rotations;
  auto operand = [](const Operand &O) {
    return O.Constant ? json::Object{{"constant_hex", utohexstr(O.Bits)}}
                      : json::Object{{"slot", O.Slot}};
  };
  for (const Step &S : P.Steps)
    Steps.push_back(json::Object{{"opcode", Instruction::getOpcodeName(S.Opcode)},
        {"destination", S.Destination}, {"x", operand(S.X)}, {"y", operand(S.Y)},
        {"input_origin", S.Origin.empty() ? json::Value(nullptr) : json::Value(S.Origin)}});
  for (unsigned K : P.OutputSlots) Outputs.push_back(K);
  for (uint64_t S : P.Salts) Salts.push_back(utohexstr(S));
  for (unsigned R : P.Rotations) Rotations.push_back(R);
  return json::Object{{"id", P.ID}, {"width", P.Width}, {"lanes", P.Lanes},
      {"family", plan::familyVersion(P.Rep.Fam, P.Rep.Rev)},
      {"representation", json::Object{{"family", plan::name(P.Rep.Fam)}, {"revision", P.Rep.Rev},
          {"physical_lanes", P.Rep.Lanes}, {"logical_width", P.Rep.LogicalWidth},
          {"lane_width", P.Rep.LaneWidth}, {"invariant", P.Rep.Invariant},
          {"seed_namespace", P.Rep.SeedNamespace}, {"verification", plan::name(P.Rep.Verified)}}},
      {"law", "triangular-slot-update-v1"}, {"verification", "algebraic"},
      {"useful_operations", P.Steps.size()}, {"inputs", B.Inputs.size()},
      {"outputs", B.Outputs.size()}, {"scalar_output_uses", B.BoundaryUses},
      {"estimated_cost", P.EstimatedCost}, {"steps", std::move(Steps)},
      {"output_slots", std::move(Outputs)}, {"salts_hex", std::move(Salts)},
      {"rotations", std::move(Rotations)}};
}
}

json::Array stampNativeBundleOrigins(Module &M) {
  json::Array Report;
  for (Function &F : M) {
    if (F.isDeclaration()) continue;
    unsigned N = 0, Pure = 0;
    for (Instruction &I : instructions(F)) {
      // Replace untrusted/stale metadata on entry to this compilation.
      I.setMetadata(OriginTag, MDNode::get(M.getContext(), MDString::get(M.getContext(),
          plan::originId(F.getName(), "input-op", N++))));
      Pure += supported(I);
    }
    Report.push_back(json::Object{{"function", F.getName().str()},
        {"instructions", N}, {"eligible_pure_operations", Pure}});
  }
  return Report;
}

namespace {
constexpr unsigned FunctionCostLimit = 65536;
struct FunctionPlan {
  Function *F;
  unsigned Before = 0, Eligible = 0, Weight = 0, Reserved = 0, Selected = 0;
  bool Blocked = false;
  SmallVector<Binding, 8> Candidates;
};
// Selection sees actual whole-region candidates, not just a function-size
// proxy. Small unusable nominal shares are pooled instead of starving every
// region in a large module. The total cap never changes.
FunctionPlan planFunction(Function &F, uint64_t Seed, const NativeBundleOptions &O) {
  FunctionPlan Result;
  Result.F = &F;
  Result.Before = F.getInstructionCount();
  Result.Weight = std::clamp(Result.Before, 32u, 4096u);
  for (Instruction &I : instructions(F)) Result.Eligible += supported(I);
  Result.Blocked = F.isVarArg() || F.hasPersonalityFn() || Result.Before > 12000 ||
                   F.hasFnAttribute(Attribute::Naked);
  if (Result.Blocked) return Result;
  auto &Plans = Result.Candidates;
  unsigned Estimated = 0;
  // Stable block/instruction order, bounded windows. Effects, width changes,
  // unknown shifts and control boundaries stop a window; nothing is hoisted
  // out of a guard or speculated across a call or load.
  for (BasicBlock &BB : F) {
    SmallVector<Instruction *, 32> Run;
    auto flush = [&]() {
      unsigned Start = 0;
      while (Start + MinNodes <= Run.size() && Plans.size() < MaxRegions) {
        bool Found = false;
        for (unsigned N = std::min<unsigned>(O.Nodes, Run.size() - Start); N >= MinNodes; --N) {
          Binding B;
          if (256 + N * 1200 > FunctionCostLimit - Estimated ||
              !schedule(ArrayRef<Instruction *>(Run).slice(Start, N), O.Values, B)) continue;
          B.P.ID = Plans.size();
          Rng R = Rng(Seed).fork("native-bundles-v1").fork(F.getName()).fork(B.P.ID);
          B.P.Rep.Fam = O.Family == "additive" || (O.Family == "seeded" && (R.u64() & 1))
                          ? plan::Family::TriangularAdditive : plan::Family::TriangularXor;
          B.P.Rep.Rev = 1;
          B.P.Rep.LogicalWidth = B.P.Rep.LaneWidth = B.P.Width;
          B.P.Rep.Lanes = B.P.Lanes + 1;
          B.P.Rep.Invariant = B.P.coordinates() == Family::Xor ? "triangular-xor-carrier" : "triangular-additive-carrier";
          B.P.Rep.Verified = plan::Verification::Algebraic;
          B.P.Rep.SeedNamespace = ("native-bundles-v1/" + F.getName() + "/" + Twine(B.P.ID)).str();
          for (unsigned K = 0; K < O.Values; ++K) {
            B.P.Salts.push_back(R.fork(K).u64());
            B.P.Rotations.push_back(1 + R.fork(K).fork("rotate").u64() % (B.P.Width - 1));
          }
          if (!valid(B)) report_fatal_error("invalid native bundle schedule");
          Estimated += B.P.EstimatedCost; Plans.push_back(std::move(B));
          Start += N; Found = true; break;
        }
        if (!Found) ++Start;
      }
      Run.clear();
    };
    for (Instruction &I : BB) {
      if (!supported(I) || (!Run.empty() && Run.front()->getType() != I.getType())) flush();
      if (supported(I)) Run.push_back(&I);
    }
    flush();
  }
  return Result;
}

void allocate(SmallVectorImpl<FunctionPlan> &Plans, unsigned Budget) {
  uint64_t Weight = 0;
  for (const FunctionPlan &P : Plans) if (!P.Candidates.empty()) Weight += P.Weight;
  unsigned Remaining = Budget;
  for (FunctionPlan &P : Plans) {
    unsigned Share = Weight ? uint64_t(Budget) * P.Weight / Weight : 0;
    for (const Binding &B : P.Candidates) {
      if (B.P.EstimatedCost > Share - P.Reserved) break;
      P.Reserved += B.P.EstimatedCost; ++P.Selected;
      Remaining -= B.P.EstimatedCost;
    }
  }
  while (true) {
    FunctionPlan *Best = nullptr;
    for (FunctionPlan &P : Plans) {
      if (P.Selected == P.Candidates.size()) continue;
      unsigned Cost = P.Candidates[P.Selected].P.EstimatedCost;
      if (Cost > Remaining) continue;
      if (!Best) { Best = &P; continue; }
      unsigned Other = Best->Candidates[Best->Selected].P.EstimatedCost;
      uint64_t Left = uint64_t(P.Weight) * (Best->Reserved + Other);
      uint64_t Right = uint64_t(Best->Weight) * (P.Reserved + Cost);
      if (Left > Right || (Left == Right && P.F->getName() < Best->F->getName())) Best = &P;
    }
    if (!Best) break;
    unsigned Cost = Best->Candidates[Best->Selected++].P.EstimatedCost;
    Best->Reserved += Cost; Remaining -= Cost;
  }
}
}

json::Array encodeNativeBundles(Module &M, uint64_t Seed, const NativeBundleOptions &O) {
  json::Array Report;
  SmallVector<FunctionPlan, 16> Work;
  for (Function &F : M) if (F.hasFnAttribute("sre.native.original"))
    Work.push_back(planFunction(F, Seed, O));
  allocate(Work, O.GrowthBudget);
  for (FunctionPlan &W : Work) {
    Function *F = W.F;
    unsigned Before = W.Before, Eligible = W.Eligible, Budget = W.Reserved;
    json::Object Row{{"function", F->getName().str()}, {"schema", "sre-bundle-plan-v1"},
        {"eligible_operations", Eligible}, {"growth_allocation", Budget},
        {"module_growth_limit", O.GrowthBudget}, {"allocation_policy", "coherent-weighted-v1"},
        {"candidate_regions", W.Candidates.size()},
        {"graph_scope", "pre-bundle-lowering"}, {"source_lineage", "input-ir-metadata"},
        {"pins", O.Pin}, {"instructions_before", Before}};
    if (W.Blocked) {
      Row["status"] = "skipped"; Row["reason"] = "structure-or-size";
      Row["retained_operations"] = 0; Row["instructions_after"] = Before;
      Report.push_back(std::move(Row)); continue;
    }
    ArrayRef<Binding> Plans(W.Candidates.data(), W.Selected);
    unsigned Estimated = W.Reserved;
    unsigned Selected = 0;
    json::Array Regions;
    for (const Binding &B : Plans) { Selected += B.Nodes.size(); Regions.push_back(report(B)); }
    bool Rollback = false;
    unsigned After = Before;
    if (!Plans.empty()) {
      FunctionSnapshot Snapshot(*F);
      // Backwards emission keeps later bindings alive when an earlier output
      // feeds a later region's entry. RAUW updates the already-emitted use.
      for (const Binding &B : llvm::reverse(Plans)) Lowering(*F, B, O.Pin).run(B);
      After = F->getInstructionCount();
      Rollback = After > uint64_t(Before) + Budget;
      if (verifyFunction(*F, &errs())) report_fatal_error("native bundle lowering produced invalid IR");
      if (Rollback) Snapshot.restore();
    }
    Row["status"] = Rollback ? "rolled-back" : Selected ? "encoded" : "skipped";
    Row["reason"] = Rollback ? "growth-budget" : Selected ? "" :
                    W.Candidates.empty() ? "no-fitting-multi-output-region" : "module-unit-budget";
    Row["attempted_operations"] = Selected;
    Row["retained_operations"] = Rollback ? 0 : Selected;
    Row["unselected_operations"] = Eligible - Selected;
    Row["rolled_back_operations"] = Rollback ? Selected : 0;
    Row["estimated_cost"] = Estimated;
    Row["instructions_after"] = F->getInstructionCount();
    Row["attempted_instructions"] = After;
    Row["regions_scope"] = Rollback ? "attempted" : "retained";
    Row["regions"] = std::move(Regions);
    Row["hardness_evaluated"] = false;
    Report.push_back(std::move(Row));
  }
  return Report;
}
}
