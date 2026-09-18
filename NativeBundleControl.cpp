#include "llvm/Transforms/Obfuscator/NativeBundleControl.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;
namespace llvm::obf {
namespace {
cl::opt<bool> NativeBundleControlOpt("native-bundle-control",
    cl::desc("Key native dispatch on actual persistent bundle recurrence storage"), cl::init(false));
constexpr StringLiteral Roles[] = {"state0", "state1", "carrier", "phase"};
unsigned roleNumber(StringRef Role) {
  for (unsigned K = 0; K < 4; ++K) if (Role == Roles[K]) return K;
  return 4;
}
struct Group { std::string Origin; AllocaInst *Words[4] = {}; bool Phase = false, Valid = true; };
SmallVector<Group, 8> groups(Function &F, StringRef Tag) {
  SmallVector<Group, 8> Groups;
  for (Instruction &I : F.getEntryBlock()) {
    auto *A = dyn_cast<AllocaInst>(&I);
    MDNode *MD = A ? A->getMetadata(Tag) : nullptr;
    if (!MD || MD->getNumOperands() != 3 || !A->isStaticAlloca() || A->isArrayAllocation()) continue;
    auto *Origin = dyn_cast<MDString>(MD->getOperand(0));
    auto *Role = dyn_cast<MDString>(MD->getOperand(1));
    auto *Phase = mdconst::dyn_extract<ConstantInt>(MD->getOperand(2));
    if (!Origin || !Role || !Phase || !A->getAllocatedType()->isIntegerTy()) continue;
    unsigned W = A->getAllocatedType()->getIntegerBitWidth(), K = roleNumber(Role->getString());
    if ((W != 8 && W != 16 && W != 32 && W != 64) || K == 4) continue;
    auto It = llvm::find_if(Groups, [&](const Group &G) { return G.Origin == Origin->getString(); });
    if (It == Groups.end()) {
      Groups.push_back({Origin->getString().str(), {}, !Phase->isZero(), true});
      It = std::prev(Groups.end());
    }
    if (It->Words[K] || It->Phase != !Phase->isZero()) It->Valid = false;
    It->Words[K] = A;
  }
  return Groups;
}
bool initialized(AllocaInst &A, const DominatorTree &DT) {
  for (User *U : A.users())
    if (auto *S = dyn_cast<StoreInst>(U); S && S->getPointerOperand() == &A &&
        S->getParent() == &A.getFunction()->getEntryBlock())
      if (auto *C = dyn_cast<Constant>(S->getValueOperand()); C && C->isNullValue()) {
        bool Dominates = true;
        for (User *User : A.users()) if (auto *L = dyn_cast<LoadInst>(User)) Dominates &= DT.dominates(S, L);
        if (Dominates) return true;
      }
  return false;
}
}
bool nativeBundleControl() { return NativeBundleControlOpt; }

SmallVector<AllocaInst *, 4> bindNativeBundleControl(Function &F) {
  DominatorTree DT(F);
  for (const Group &G : groups(F, NativeBundleControlState)) {
    unsigned N = G.Phase ? 4 : 3;
    if (!G.Valid || llvm::any_of(ArrayRef(G.Words, N), [](AllocaInst *A) { return !A; })) continue;
    bool Closed = true;
    SmallVector<LoadInst *, 16> Useful;
    SmallVector<StoreInst *, 16> Stores;
    for (unsigned K = 0; K < N; ++K) {
      AllocaInst *A = G.Words[K];
      bool Read = false;
      if (A->getAllocatedType() != G.Words[0]->getAllocatedType() || !initialized(*A, DT)) { Closed = false; break; }
      for (User *U : A->users()) {
        if (auto *L = dyn_cast<LoadInst>(U); L && L->getPointerOperand() == A && L->isSimple() && !L->use_empty()) {
          Read = true; Useful.push_back(L);
        } else if (auto *S = dyn_cast<StoreInst>(U); S && S->getPointerOperand() == A && S->isSimple()) {
          Stores.push_back(S);
        } else { Closed = false; break; }
      }
      Closed &= Read;
    }
    if (!Closed) continue;
    auto *Origin = MDNode::get(F.getContext(), MDString::get(F.getContext(), G.Origin));
    for (LoadInst *L : Useful) L->setMetadata("sre.native.bundle.control-useful", Origin);
    for (StoreInst *S : Stores) S->setMetadata("sre.native.bundle.control-data-store", Origin);
    SmallVector<AllocaInst *, 4> Out;
    for (unsigned K = 0; K < N; ++K) {
      G.Words[K]->setMetadata("sre.native.bundle.control-bound", G.Words[K]->getMetadata(NativeBundleControlState));
      Out.push_back(G.Words[K]);
    }
    return Out;
  }
  return {};
}

json::Array nativeBundleControlInventory(Module &M, const json::Array &Bundles) {
  json::Array Rows;
  for (const json::Value &Value : Bundles) {
    const auto &Bundle = *Value.getAsObject();
    StringRef Name = *Bundle.getString("function");
    unsigned Requested = 0;
    if (Bundle.getString("status") == "encoded")
      if (const auto *Regions = Bundle.getArray("regions")) for (const json::Value &V : *Regions)
        if (const auto *Loop = V.getAsObject()->getObject("loop")) Requested += Loop->getString("status") == "encoded";
    json::Array WordRows;
    unsigned Dispatcher = 0, Transition = 0, Useful = 0;
    std::string Origin;
    bool Valid = true;
    if (Function *F = M.getFunction(Name); F && !F->isDeclaration()) {
      DominatorTree DT(*F);
      auto Groups = groups(*F, "sre.native.bundle.control-bound");
      Valid = Groups.size() <= 1;
      for (const Group &G : Groups) {
        Origin = G.Origin;
        Valid &= G.Valid;
        for (unsigned K = 0, N = G.Phase ? 4 : 3; K < N; ++K) {
          AllocaInst *A = G.Words[K];
          if (!A) { Valid = false; continue; }
          unsigned D = 0, T = 0, U = 0, Stores = 0, Unknown = 0;
          for (User *User : A->users()) {
            if (auto *L = dyn_cast<LoadInst>(User); L && L->getPointerOperand() == A) {
              if (MDNode *Role = L->getMetadata("sre.native.bundle.control-read")) {
                StringRef Kind = cast<MDString>(Role->getOperand(0))->getString();
                D += Kind == "dispatcher"; T += Kind == "transition";
                Unknown += !L->isVolatile() || (Kind != "dispatcher" && Kind != "transition");
              } else if (L->getMetadata("sre.native.bundle.control-useful") && !L->use_empty()) ++U;
              else ++Unknown;
            } else if (auto *S = dyn_cast<StoreInst>(User); S && S->getPointerOperand() == A &&
                       S->getMetadata("sre.native.bundle.control-data-store")) ++Stores;
            else ++Unknown;
          }
          bool Init = initialized(*A, DT);
          Valid &= Init && D && T && U && Stores && !Unknown;
          Dispatcher += D; Transition += T; Useful += U;
          WordRows.push_back(json::Object{{"role", Roles[K]}, {"width", A->getAllocatedType()->getIntegerBitWidth()},
              {"initialized_before_all_reads", Init}, {"dispatcher_reads", D}, {"transition_reads", T},
              {"useful_reads", U}, {"data_store_sites", Stores}, {"unclassified_accesses", Unknown}});
        }
      }
    }
    bool Coupled = Valid && Dispatcher && Transition && Useful;
    Rows.push_back(json::Object{{"function", Name.str()}, {"contract", "persistent-bundle-control-v1"},
        {"stage", "final-ir"}, {"requested_regions", Requested}, {"bound_origin", Origin},
        {"status", Coupled ? "coupled" : WordRows.empty() ? "unavailable" : "invalid"},
        {"reason", Coupled ? "" : Requested ? "no-retained-complete-control-contract" : "no-selected-persistent-loop"},
        {"words", std::move(WordRows)}, {"dispatcher_reads", Dispatcher}, {"transition_reads", Transition},
        {"useful_reads", Useful}, {"hardness_evaluated", false}});
  }
  return Rows;
}
}
