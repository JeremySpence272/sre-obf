#include "llvm/Transforms/Obfuscator/NativeRegions.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;
namespace llvm::obf {
namespace {
StringRef linkageName(GlobalValue::LinkageTypes L) {
  switch (L) {
  case GlobalValue::ExternalLinkage: return "external";
  case GlobalValue::AvailableExternallyLinkage: return "available-externally";
  case GlobalValue::LinkOnceAnyLinkage: return "linkonce-any";
  case GlobalValue::LinkOnceODRLinkage: return "linkonce-odr";
  case GlobalValue::WeakAnyLinkage: return "weak-any";
  case GlobalValue::WeakODRLinkage: return "weak-odr";
  case GlobalValue::AppendingLinkage: return "appending";
  case GlobalValue::InternalLinkage: return "internal";
  case GlobalValue::PrivateLinkage: return "private";
  case GlobalValue::ExternalWeakLinkage: return "external-weak";
  case GlobalValue::CommonLinkage: return "common";
  }
  return "unknown";
}
}  // namespace
json::Object nativeBoundaryInventory(const Module &M, StringRef Stage) {
  json::Array Functions;
  uint64_t Definitions = 0, Instructions = 0, Selected = 0, SelectedInstructions = 0;
  uint64_t Helpers = 0, HelperInstructions = 0;
  for (const Function &F : M) {
    if (F.isDeclaration()) continue;
    ++Definitions;
    const bool Helper = F.hasFnAttribute("sre.native.helper");
    const bool Protect = F.hasFnAttribute("sre.native.original");
    uint64_t Loads = 0, Stores = 0, Comparisons = 0, Selects = 0, Indirect = 0;
    uint64_t NamedBoundaries = 0, TaggedBoundaries = 0, Objects = 0, Handoffs = 0;
    json::Array Calls;
    for (const Instruction &I : instructions(F)) {
      Loads += isa<LoadInst>(I); Stores += isa<StoreInst>(I);
      Comparisons += isa<ICmpInst>(I); Selects += isa<SelectInst>(I);
      Objects += isa<AllocaInst>(I);
      // Legacy names are a diagnostic only: later passes can replace them.
      NamedBoundaries += I.getName().starts_with("sre.value.output") ||
                         I.getName().starts_with("sre.memory.output");
      TaggedBoundaries += I.getMetadata("sre.native.boundary") != nullptr;
      Handoffs += I.getMetadata("sre.native.predicate.handoff") != nullptr;
      if (const auto *C = dyn_cast<CallBase>(&I)) {
        const Function *Target = C->getCalledFunction();
        if (!Target) ++Indirect;
        else if (Target->hasFnAttribute("sre.native.helper"))
          Calls.push_back(Target->getName().str());
      }
    }
    uint64_t Count = F.getInstructionCount();
    Instructions += Count;
    if (Helper) { ++Helpers; HelperInstructions += Count; }
    if (Protect) { ++Selected; SelectedInstructions += Count; }
    Functions.push_back(json::Object{
        {"function", F.getName().str()}, {"instructions", Count},
        {"selected_attribute", Protect}, {"generated_helper", Helper},
        {"external_linkage", !F.hasLocalLinkage()}, {"blocks", F.size()},
        {"loads", Loads}, {"stores", Stores}, {"local_objects", Objects},
        {"integer_comparisons", Comparisons}, {"selects", Selects},
        {"indirect_calls", Indirect}, {"direct_helper_calls", std::move(Calls)},
        {"legacy_named_decode_boundaries", NamedBoundaries},
        {"surviving_tagged_boundaries", TaggedBoundaries}});
    Functions.back().getAsObject()->insert({"surviving_predicate_handoffs", Handoffs});
  }
  // Module globals, so the object denominator is a count rather than a null.
  // A global with observable linkage, a taken address or unknown accesses is
  // not a closed object; these fields say which, they do not claim coverage.
  json::Array Globals;
  uint64_t GlobalDefinitions = 0, GlobalBytes = 0, UnknownGlobalSizes = 0;
  const DataLayout &DL = M.getDataLayout();
  for (const GlobalVariable &G : M.globals()) {
    if (G.isDeclaration()) continue;
    ++GlobalDefinitions;
    // An unsized or scalable type has an unknown size, which is null, not zero.
    json::Value Bytes(nullptr);
    if (G.getValueType()->isSized()) {
      TypeSize Size = DL.getTypeAllocSize(G.getValueType());
      if (!Size.isScalable()) {
        Bytes = json::Value(Size.getFixedValue());
        GlobalBytes += Size.getFixedValue();
      }
    }
    if (!Bytes.getAsInteger()) ++UnknownGlobalSizes;
    // Conservative: any use that is not a plain load or store of the global
    // itself is treated as taking its address, a GEP included.
    bool AddressTaken = false;
    for (const User *U : G.users()) {
      if (const auto *L = dyn_cast<LoadInst>(U); L && L->getPointerOperand() == &G) continue;
      if (const auto *S = dyn_cast<StoreInst>(U); S && S->getPointerOperand() == &G) continue;
      AddressTaken = true;
      break;
    }
    Globals.push_back(json::Object{{"global", G.getName().str()},
        {"linkage", linkageName(G.getLinkage())}, {"bytes", std::move(Bytes)},
        {"constant", G.isConstant()}, {"external_linkage", !G.hasLocalLinkage()},
        {"has_initializer", G.hasInitializer()},
        {"unnamed_address", G.hasGlobalUnnamedAddr()},
        {"address_taken", AddressTaken}});
  }
  return json::Object{{"schema", "sre-boundary-inventory-v1"}, {"stage", Stage.str()},
      {"definitions", Definitions}, {"instructions", Instructions},
      {"global_definitions", GlobalDefinitions},
      {"global_bytes", UnknownGlobalSizes ? json::Value(nullptr) : json::Value(GlobalBytes)},
      {"known_global_bytes", GlobalBytes}, {"globals_unknown_size", UnknownGlobalSizes},
      {"globals", std::move(Globals)},
      {"selected_definitions", Selected}, {"selected_instructions", SelectedInstructions},
      {"helper_definitions", Helpers}, {"helper_instructions", HelperInstructions},
      {"selection_is_not_protection_proof", true},
      {"missing_boundary_tags_do_not_prove_absence", true},
      {"functions", std::move(Functions)}};
}
}
