#include "llvm/Transforms/Obfuscator/NativeRegions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;
namespace llvm::obf {
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
    uint64_t NamedBoundaries = 0, TaggedBoundaries = 0, Objects = 0;
    json::Array Calls;
    for (const Instruction &I : instructions(F)) {
      Loads += isa<LoadInst>(I); Stores += isa<StoreInst>(I);
      Comparisons += isa<ICmpInst>(I); Selects += isa<SelectInst>(I);
      Objects += isa<AllocaInst>(I);
      // Legacy names are a diagnostic only: later passes can replace them.
      NamedBoundaries += I.getName().starts_with("sre.value.output") ||
                         I.getName().starts_with("sre.memory.output");
      TaggedBoundaries += I.getMetadata("sre.native.boundary") != nullptr;
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
  }
  return json::Object{{"schema", "sre-boundary-inventory-v1"}, {"stage", Stage.str()},
      {"definitions", Definitions}, {"instructions", Instructions},
      {"selected_definitions", Selected}, {"selected_instructions", SelectedInstructions},
      {"helper_definitions", Helpers}, {"helper_instructions", HelperInstructions},
      {"selection_is_not_protection_proof", true},
      {"missing_boundary_tags_do_not_prove_absence", true},
      {"functions", std::move(Functions)}};
}
}
