#include "llvm/Transforms/Obfuscator/NativeObfuscation.h"
#include "llvm/Transforms/Obfuscator.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/Path.h"

using namespace llvm;

namespace {
cl::opt<std::string> NativeLevel(
    "native-level", cl::desc("Native profile: max or smoke (explicit test profile)"),
    cl::init("max"));
cl::list<std::string> NativeFunctions(
    "native-functions", cl::CommaSeparated,
    cl::desc("Exact function names to protect; empty selects all definitions"));
cl::list<std::string> NativePasses(
    "native-passes", cl::CommaSeparated,
    cl::desc("Explicit native pass ablation; empty retains the complete profile"));
cl::opt<std::string> NativeReport(
    "native-report-json", cl::desc("Private native-profile provenance/coverage JSON"),
    cl::init(""));

std::string profile(bool Structural) {
  const bool Max = NativeLevel == "max";
  std::string Spec = Max
      ? "obf: constenc(prob=100,maxSites=1000,encFP=0,wrapMBA=1),"
        "mba(preset=max,prob=100,maxDepth=3,maxSites=300),"
        "substitution(loop=2,maxSites=300),split(num=6),"
        "sdiff(prob=100,slots=4,maxSites=200),"
        "bcf(prob=40,loop=1,maxBlocks=1000),"
      : "obf: constenc(prob=100,maxSites=24,encFP=0),"
        "mba(preset=high,prob=25,maxSites=8),"
        "substitution(loop=1,maxSites=8),split(num=2),"
        "sdiff(prob=50,slots=2,maxSites=8),"
        "bcf(prob=15,loop=1,maxBlocks=200),";
  if (Structural)
    Spec += Max
        ? "flattening(minBlocks=2,maxBlocks=1500,allowIndirect=0,hybrid=1,"
          "opaqueState=1,fakeTransitions=1,fakeCases=4,perDispatcherDomain=1,"
          "obfuscateStatePtr=1,opaqueAliasStatePtr=1),"
        : "flattening(minBlocks=2,maxBlocks=500,opaqueState=1,"
          "fakeTransitions=1,fakeCases=2),";
  Spec += Max
      ? "vcall(prob=100,maxSites=128,indexStrength=3,encryptTable=1,mergeVTables=0),"
        "shield(maxSites=400),adec(prob=100,strength=3,maxSites=100,asm=0,rdtsc=0,"
        "fakeLoop=0,constLaunder=1)"
      : "vcall(prob=50,maxSites=8,indexStrength=2,encryptTable=1,mergeVTables=0),"
        "shield(maxSites=12),adec(prob=25,strength=1,maxSites=8,asm=0,rdtsc=0)";
  if (NativePasses.empty()) return Spec;
  ObfuscationConfig Parsed = AnnotationParser::parseAnnotationString(Spec);
  std::string Filtered = "obf: ";
  for (const PassConfig &P : Parsed.passes) {
    if (!llvm::is_contained(NativePasses, P.passName)) continue;
    if (Filtered != "obf: ") Filtered += ",";
    Filtered += P.passName + "(" + P.rawInner + ")";
  }
  return Filtered;
}

std::string structuralBlocker(const Function &F) {
  if (F.hasPersonalityFn()) return "exception-personality";
  if (F.isVarArg()) return "varargs";
  if (F.hasFnAttribute(Attribute::Naked)) return "naked";
  for (const Instruction &I : instructions(F)) {
    if (I.isEHPad() || isa<InvokeInst>(I) || isa<ResumeInst>(I))
      return "exception-handling";
    if (isa<IndirectBrInst>(I) || isa<CallBrInst>(I)) return "indirect-control";
    if (const auto *CB = dyn_cast<CallBase>(&I)) {
      if (CB->isInlineAsm()) return "source-inline-asm";
      if (!CB->getCalledFunction()) return "indirect-call";
      if (const auto *CI = dyn_cast<CallInst>(CB))
        if (CI->isMustTailCall()) return "musttail";
    }
  }
  if (F.size() < 2) return "single-basic-block";
  return "";
}

bool selected(const Function &F) {
  return NativeFunctions.empty() ||
      llvm::is_contained(NativeFunctions, F.getName().str());
}
} // namespace

PreservedAnalyses NativeObfuscationPass::run(Module &M, ModuleAnalysisManager &AM) {
  if (NativeLevel != "max" && NativeLevel != "smoke")
    report_fatal_error("native-level must be max or smoke");
  if (ObfSeed.getNumOccurrences() == 0)
    report_fatal_error("native-obfuscation requires an explicit -obf-seed");
  for (const std::string &Name : NativePasses)
    if (!llvm::is_contained(
            ArrayRef<StringRef>{"constenc", "mba", "substitution", "split", "sdiff",
                                "bcf", "flattening", "vcall", "shield", "adec"}, Name))
      report_fatal_error(Twine("unsupported native pass ablation: ") + Name);
  if (!Triple(M.getTargetTriple()).isX86() ||
      !Triple(M.getTargetTriple()).isArch64Bit())
    report_fatal_error("native-obfuscation currently supports x86-64 only");
  for (const std::string &Name : NativeFunctions)
    if (!M.getFunction(Name) || M.getFunction(Name)->isDeclaration())
      report_fatal_error(Twine("native-functions: no definition for ") + Name);

  // Output-directory names must not change RNG streams or encoded data.
  M.setModuleIdentifier(sys::path::filename(M.getSourceFileName()));
  json::Array Coverage;
  auto &Cache = AM.getResult<ObfuscationAnnotationAnalysis>(M);
  Cache.PerFunction.clear();
  for (Function &F : M) {
    if (F.isDeclaration()) continue;
    std::string Blocker = structuralBlocker(F);
    bool Protect = selected(F);
    // Do not transform naked/asm bodies at all. Other blockers get a reported
    // expression-only fallback, never an unreported claim of flattening.
    if (Blocker == "naked" || Blocker == "source-inline-asm") Protect = false;
    std::string Spec = Protect ? profile(Blocker.empty()) : "";
    F.addFnAttr("sre.native.spec", Spec);
    if (Protect) {
      F.addFnAttr("sre.native.original");
      // Added volatile storage invalidates optimized input's memory claims.
      F.setMemoryEffects(MemoryEffects::unknown());
      F.removeFnAttr(Attribute::Speculatable);
      Cache.PerFunction[&F] = AnnotationParser::parseAnnotationString(Spec);
    }
    Coverage.push_back(json::Object{
        {"function", F.getName().str()}, {"selected", Protect},
        {"structural_eligible", Protect && Blocker.empty()},
        {"reason", Blocker}, {"spec", Spec},
        {"instructions_before", static_cast<int64_t>(F.getInstructionCount())}});
  }

  ObfuscationModulePass().run(M, AM);
  // This entry point only supplies known IR-only configurations. Check actual
  // generated code as well: do not allow source annotations to enable a VM or
  // an assembly/timing technique behind the profile's back.
  for (const Function &F : M) {
    if (F.isDeclaration() || !F.hasFnAttribute("sre.native.original")) continue;
    for (const Instruction &I : instructions(F)) {
      if (const auto *CB = dyn_cast<CallBase>(&I)) {
        if (CB->isInlineAsm())
          report_fatal_error("native profile unexpectedly emitted inline assembly");
        if (const Function *Callee = CB->getCalledFunction())
          if (Callee->getName().contains("readcyclecounter") ||
              Callee->getName().contains("rdtsc"))
            report_fatal_error("native profile unexpectedly emitted timing reads");
      }
    }
  }
  if (verifyModule(M, &errs()))
    report_fatal_error("native-obfuscation produced invalid IR");

  if (!NativeReport.empty()) {
    std::error_code EC;
    raw_fd_ostream OS(NativeReport, EC, sys::fs::OF_Text);
    if (EC) report_fatal_error(Twine("native report: ") + EC.message());
    json::Object Result{{"schema", "sre-native-v1"},
                        {"profile", "native-" + NativeLevel.getValue() + "-ir"},
                        {"seed", std::to_string(static_cast<uint64_t>(ObfSeed))},
                        {"vm", false}, {"injected_assembly", false},
                        {"functions", std::move(Coverage)}};
    OS << formatv("{0:2}\n", json::Value(std::move(Result)));
  }
  return PreservedAnalyses::none();
}
