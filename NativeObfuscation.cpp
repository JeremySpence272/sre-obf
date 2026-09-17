#include "llvm/Transforms/Obfuscator/NativeObfuscation.h"
#include "llvm/Transforms/Obfuscator/NativeEncoding.h"
#include "llvm/Transforms/Obfuscator/NativeRegions.h"
#include "llvm/Transforms/Obfuscator/NativeConnected.h"
#include "llvm/Transforms/Obfuscator/NativeBudget.h"
#include "llvm/Transforms/Obfuscator/ConstantEncryption.h"
#include "llvm/Transforms/Obfuscator.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Analysis/ValueTracking.h"
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
cl::opt<bool> NativeDiversity("native-diversity",
    cl::desc("F1: shared seeded representation families"), cl::init(true));
cl::opt<bool> NativeData("native-data",
    cl::desc("F2: encode non-escaping immutable integer arrays"), cl::init(true));
cl::opt<bool> NativeHelpers("native-helper-hardening",
    cl::desc("F3: process registered generated helpers once"), cl::init(true));
cl::opt<bool> NativeLate("native-late-constants",
    cl::desc("F2: one bounded late constant sweep"), cl::init(true));
cl::opt<bool> NativeStrings("native-strings",
    cl::desc("Module-local AES string encoding with bounded helper hardening"), cl::init(true));
cl::opt<bool> NativeMerge("native-merge",
    cl::desc("Bounded internal application-function merging"), cl::init(true));
cl::opt<bool> NativeMultiState("native-multistate",
    cl::desc("Three-word per-activation relational flattening state"), cl::init(true));
cl::opt<unsigned> NativeStateFamily("native-state-family",
    cl::desc("Multi-state encoding family: 0..2 forced, 3 seeded"), cl::init(3));
cl::opt<bool> NativeValues("native-values",
    cl::desc("Experimental persistent two-lane integer SSA representations"), cl::init(false));
cl::opt<unsigned> NativeValueNodes("native-value-nodes",
    cl::desc("Maximum persistent-value nodes per eligible function (2..64)"), cl::init(24));
cl::opt<bool> NativeOutline("native-outline",
    cl::desc("Experimental bounded pure-integer region outlining"), cl::init(false));
cl::opt<bool> NativeCoupledState("native-coupled-state",
    cl::desc("Experimental per-activation coupling of encoded data and flattening"), cl::init(false));
cl::opt<bool> NativeFusion("native-fusion", cl::desc("Bounded private cross-function fusion and SSA preparation"), cl::init(false));
cl::opt<bool> NativeMemory("native-memory", cl::desc("Encode closed local integer objects across stores and loads"), cl::init(false));
cl::opt<bool> NativeWide("native-values-wide", cl::desc("XOR-share regions including bitwise, shifts and casts"), cl::init(false));
cl::opt<bool> NativeInvariant("native-invariant", cl::desc("Reachable witness invariant shared by data and control"), cl::init(false));
cl::opt<std::string> NativeRegionPlan("native-region-plan", cl::desc("Value planner: legacy or connected"), cl::init("legacy"));
cl::opt<unsigned> NativeConnectedNodes("native-connected-nodes", cl::desc("Connected node cap per function (2..512)"), cl::init(128));
cl::opt<bool> NativeConnectedShards("native-connected-shards",
    cl::desc("Partition an oversized connected component into bounded shards under the same cost limit"), cl::init(false));
cl::opt<bool> NativeConnectedAggregates("native-connected-aggregates",
    cl::desc("Admit bounded constant-index integer leaves of structs and nested arrays as closed connected memory"), cl::init(false));
cl::opt<bool> NativeJointOutputs("native-joint-outputs",
    cl::desc("Couple two genuinely used encoded lanes into pinned joint outputs U=X+Y and V=X+2Y"), cl::init(false));
cl::opt<bool> NativeMemorySSA("native-memory-ssa", cl::desc("Connected memory and SSA lanes without per-load decoding"), cl::init(false));
cl::opt<bool> NativePredicateRegions("native-predicate-regions", cl::desc("Connected bit-vector comparisons and Boolean uses"), cl::init(false));
cl::opt<bool> NativeRegionalFamilies("native-regional-families", cl::desc("Seeded XOR/additive families for whole supported components"), cl::init(false));
cl::opt<bool> NativeSupportRegions("native-support-regions", cl::desc("Absorb bounded generated data decoders before region planning"), cl::init(false));
cl::opt<std::string> NativeStageDir("native-stage-dir", cl::desc("Private directory for pre-driver and post-driver IR snapshots"), cl::init(""));
cl::opt<unsigned> NativeModuleInsts("native-module-insts", cl::desc("Explicit module IR instruction cap (10000..5000000)"), cl::init(250000));
cl::opt<bool> NativeScaleBudget("native-scale-budget", cl::desc("Opt-in fair connected/application/helper growth allocations; reports all coverage losses"), cl::init(false));
cl::opt<bool> NativeScaleStructure("native-scale-structure", cl::desc("Reserve usable CFF transactions before fair expression allocation"), cl::init(false));

void saveNativeStage(const Module &M, StringRef Stage) {
  if (NativeStageDir.empty()) return;
  if (std::error_code EC = sys::fs::create_directories(NativeStageDir)) report_fatal_error(Twine("native stage directory: ") + EC.message());
  SmallString<256> Path(NativeStageDir.getValue()); sys::path::append(Path, Stage);
  std::error_code EC; raw_fd_ostream OS(Path, EC, sys::fs::OF_Text);
  if (EC) report_fatal_error(Twine("native stage snapshot: ") + EC.message());
  M.print(OS, nullptr);
}

void enableFamilies(Function &F) {
  if (NativeDiversity) F.addFnAttr("sre.native.families");
}

uint64_t moduleInstructions(const Module &M) {
  uint64_t Total = 0;
  for (const Function &F : M) Total += F.getInstructionCount();
  return Total;
}

void checkInstructionBudget(const Module &M, StringRef Stage, uint64_t Total) {
  if (Total > NativeModuleInsts) {
    if (!NativeReport.empty()) {
      std::error_code EC;
      raw_fd_ostream OS(NativeReport.getValue() + ".budget.json", EC, sys::fs::OF_Text);
      if (!EC) OS << formatv("{0:2}\n", json::Value(json::Object{
          {"status", "module-budget-failure"}, {"stage", Stage.str()}, {"instructions", Total}, {"limit", NativeModuleInsts.getValue()},
          {"inventory", obf::nativeBoundaryInventory(M, Stage)}}));
    }
    report_fatal_error(Twine("native module instruction cap exceeded: ") + Twine(Total) + " > " + Twine(NativeModuleInsts.getValue()));
  }
}

void checkModuleBudget(const Module &M, StringRef Stage) {
  checkInstructionBudget(M, Stage, moduleInstructions(M));
}

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
  if (Structural) {
    Spec += "flattening(multiState=" + std::to_string(NativeMultiState.getValue()) +
        ",stateFamily=" + std::to_string(NativeStateFamily.getValue()) + ",";
    Spec += Max
        ? "minBlocks=2,maxBlocks=1500,allowIndirect=0,hybrid=1,"
          "opaqueState=1,fakeTransitions=1,fakeCases=4,perDispatcherDomain=1,"
          "obfuscateStatePtr=1,opaqueAliasStatePtr=1),"
        : "minBlocks=2,maxBlocks=500,opaqueState=1,"
          "fakeTransitions=1,fakeCases=2),";
  }
  Spec += Max
      ? "vcall(prob=100,maxSites=128,indexStrength=3,encryptTable=1,mergeVTables=0),"
        "shield(maxSites=400),adec(prob=100,strength=3,maxSites=100,asm=0,rdtsc=0,"
        "fakeLoop=0,constLaunder=1)"
      : "vcall(prob=50,maxSites=8,indexStrength=2,encryptTable=1,mergeVTables=0),"
        "shield(maxSites=12),adec(prob=25,strength=1,maxSites=8,asm=0,rdtsc=0)";
  if (NativeStrings) Spec += ",strenc(cipher=aes,keysplit=1,minlen=1)";
  if (NativeMerge)
    Spec += ",fmerge(chunk=4,opaqueSel=1,launderSel=1,dispatch=switch,thunkAddrTaken=0)";
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
  if (NativeStateFamily > 3)
    report_fatal_error("native-state-family must be 0..3");
  if (NativeValueNodes < 2 || NativeValueNodes > 64)
    report_fatal_error("native-value-nodes must be 2..64");
  if (NativeRegionPlan != "legacy" && NativeRegionPlan != "connected")
    report_fatal_error("native-region-plan must be legacy or connected");
  if (NativeConnectedNodes < 2 || NativeConnectedNodes > 512)
    report_fatal_error("native-connected-nodes must be 2..512");
  if (NativeModuleInsts < 10000 || NativeModuleInsts > 5000000)
    report_fatal_error("native-module-insts must be 10000..5000000");
  if (NativeScaleBudget && NativeRegionPlan != "connected")
    report_fatal_error("native-scale-budget requires connected regions");
  if (NativeScaleStructure && !NativeScaleBudget)
    report_fatal_error("native-scale-structure requires native-scale-budget");
  if (NativeRegionPlan == "connected" && (!NativeValues || !NativeWide))
    report_fatal_error("connected regions require native-values and native-values-wide");
  if ((NativeMemorySSA || NativePredicateRegions || NativeRegionalFamilies || NativeSupportRegions ||
       NativeConnectedShards || NativeConnectedAggregates || NativeJointOutputs) &&
      NativeRegionPlan != "connected")
    report_fatal_error("connected subfeatures require native-region-plan=connected");
  if (NativeMemorySSA && !NativeMemory) report_fatal_error("native-memory-ssa requires native-memory");
  if (NativeConnectedAggregates && !NativeMemorySSA)
    report_fatal_error("native-connected-aggregates requires native-memory-ssa");
  if (NativeWide && !NativeValues) report_fatal_error("native-values-wide requires native-values");
  if (NativeInvariant && !NativeCoupledState) report_fatal_error("native-invariant requires native-coupled-state");
  if (NativeCoupledState && (!NativeValues || !NativeMultiState))
    report_fatal_error("native-coupled-state requires native-values and native-multistate");
  if (NativeCoupledState && !NativePasses.empty() &&
      !llvm::is_contained(NativePasses, "flattening"))
    report_fatal_error("native-coupled-state requires flattening in the pass ablation");
  if (ObfSeed.getNumOccurrences() == 0)
    report_fatal_error("native-obfuscation requires an explicit -obf-seed");
  for (const std::string &Name : NativePasses)
    if (!llvm::is_contained(
            ArrayRef<StringRef>{"constenc", "mba", "substitution", "split", "sdiff",
                                "bcf", "flattening", "vcall", "shield", "adec",
                                "strenc", "fmerge"}, Name))
      report_fatal_error(Twine("unsupported native pass ablation: ") + Name);
  if (!Triple(M.getTargetTriple()).isX86() ||
      !Triple(M.getTargetTriple()).isArch64Bit())
    report_fatal_error("native-obfuscation currently supports x86-64 only");
  for (const std::string &Name : NativeFunctions)
    if (!M.getFunction(Name) || M.getFunction(Name)->isDeclaration())
      report_fatal_error(Twine("native-functions: no definition for ") + Name);

  // Output-directory names must not change RNG streams or encoded data.
  M.setModuleIdentifier(sys::path::filename(M.getSourceFileName()));
  auto InputInventory = obf::nativeBoundaryInventory(M, "input-before-fusion");
  json::Array FusionCoverage;
  if (NativeFusion) {
    FusionCoverage = obf::fuseNativeFunctions(M, static_cast<uint64_t>(ObfSeed), NativeFunctions);
    AM.invalidate(M, PreservedAnalyses::none());
    if (verifyModule(M, &errs())) report_fatal_error("native fusion produced invalid IR");
    checkModuleBudget(M, "after-fusion");
  }
  json::Array Coverage;
  auto &Cache = AM.getResult<ObfuscationAnnotationAnalysis>(M);
  Cache.PerFunction.clear();
  for (Function &F : M) {
    if (F.isDeclaration()) continue;
    F.addFnAttr("sre.native.source");
    std::string Blocker = structuralBlocker(F);
    bool Protect = selected(F);
    // Do not transform naked/asm bodies at all. Other blockers get a reported
    // no-flattening fallback, never an unreported claim of flattening.
    if (Blocker == "naked" || Blocker == "source-inline-asm") Protect = false;
    std::string Spec = Protect ? profile(Blocker.empty()) : "";
    F.addFnAttr("sre.native.spec", Spec);
    if (Protect) {
      F.addFnAttr("sre.native.original");
      F.addFnAttr("sre.native.stage", "application");
      enableFamilies(F);
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

  // Run module preparation exactly once, before data inventory and application
  // transforms. Rebuild native cache entries after merging removes originals.
  ModulePassManager Preparation;
  Preparation.addPass(FunctionMergingPass());
  Preparation.addPass(StringEncryptionPass());
  Preparation.run(M, AM);
  auto &PreparedCache = AM.getResult<ObfuscationAnnotationAnalysis>(M);
  PreparedCache.PerFunction.clear();
  json::Array MergedCoverage;
  for (Function &F : M) {
    if (F.isDeclaration()) continue;
    if (F.hasFnAttribute("sre.native.merged")) {
      std::string Spec = profile(structuralBlocker(F).empty());
      F.addFnAttr("sre.native.spec", Spec);
      MergedCoverage.push_back(json::Object{{"function", F.getName().str()},
          {"members", F.getFnAttribute("sre.native.merged").getValueAsString().str()}});
    }
    if (!F.hasFnAttribute("sre.native.source") &&
        !F.hasFnAttribute("sre.native.original")) {
      F.addFnAttr("sre.native.helper", "module-runtime");
      F.addFnAttr("sre.native.origin", "native-module-preparation");
      F.addFnAttr("sre.native.spec", "");
    }
    if (F.hasFnAttribute("sre.native.original"))
      PreparedCache.PerFunction[&F] = AnnotationParser::parseAnnotationString(
          F.getFnAttribute("sre.native.spec").getValueAsString().str());
  }
  json::Array DataCoverage;
  if (NativeData)
    DataCoverage = obf::encodeNativeData(M, PreparedCache.ModuleSeed);
  json::Array OutlineCoverage, ValueCoverage, MemoryCoverage, ConnectedCoverage, SupportCoverage;
  if (NativeSupportRegions) SupportCoverage = obf::absorbNativeSupport(M);
  if (NativeOutline)
    OutlineCoverage = obf::outlineNativeRegions(M, PreparedCache.ModuleSeed);
  SmallVector<std::pair<Function *, unsigned>, 64> SourceWeights;
  for (Function &F : M)
    if (F.hasFnAttribute("sre.native.original"))
      SourceWeights.emplace_back(&F, std::clamp(F.getInstructionCount(), 32u, 4096u));
  json::Array GrowthCoverage;
  if (NativeRegionPlan == "connected") {
    obf::NativeConnectedOptions Options;
    Options.Nodes = NativeConnectedNodes;
    Options.Memory = NativeMemorySSA;
    Options.Predicates = NativePredicateRegions;
    Options.Families = NativeRegionalFamilies;
    Options.Shards = NativeConnectedShards;
    Options.Aggregates = NativeConnectedAggregates;
    Options.JointOutputs = NativeJointOutputs;
    Options.CoupleState = NativeCoupledState;
    Options.Invariant = NativeInvariant;
    if (NativeScaleBudget) {
      checkModuleBudget(M, "before-connected-allocation");
      Options.BoundedGrowth = true;
      Options.GrowthBudget = (NativeModuleInsts - moduleInstructions(M)) / 3;
    }
    ConnectedCoverage = obf::encodeNativeConnected(M, PreparedCache.ModuleSeed, Options);
  } else if (NativeValues)
    ValueCoverage = obf::encodeNativeValues(M, PreparedCache.ModuleSeed, NativeValueNodes, NativeCoupledState, NativeWide, NativeInvariant);
  if (NativeMemory && !NativeMemorySSA) MemoryCoverage = obf::encodeNativeMemory(M, PreparedCache.ModuleSeed);
  saveNativeStage(M, "regions.ll");
  auto RegionInventory = obf::nativeBoundaryInventory(M, "after-regions-before-function-driver");
  if (NativeOutline || NativeValues || NativeMemory) {
    auto &ChangedFAM = AM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
    for (Function &F : M)
      if (!F.isDeclaration()) ChangedFAM.invalidate(F, PreservedAnalyses::none());
    if (verifyModule(M, &errs()))
      report_fatal_error("native value/region preparation produced invalid IR");
    checkModuleBudget(M, "after-regions");
  }
  // O2 may put call-site memory(none)/readonly promises on calls. Updating only
  // the callee's attributes is insufficient when protection adds volatile reads.
  for (Function &F : M)
    for (Instruction &I : instructions(F))
      if (auto *CB = dyn_cast<CallBase>(&I))
        if (!isa<IntrinsicInst>(CB) && !CB->isInlineAsm()) {
          CB->setMemoryEffects(MemoryEffects::unknown());
          CB->removeFnAttr(Attribute::Speculatable);
        }
  if (obf::isReportEnabled()) (void)AM.getResult<ObfReportAnalysis>(M);
  json::Array StructuralCoverage;
  if (NativeScaleStructure) {
    uint64_t Pool = (NativeModuleInsts - moduleInstructions(M)) * 3 / 5;
    StructuralCoverage = obf::budgetNativeStructure(M, AM, Pool, SourceWeights);
    checkModuleBudget(M, "after-structural-allocation");
    saveNativeStage(M, "structural.ll");
  }
  if (NativeScaleBudget) {
    uint64_t Weight = 0;
    for (const auto &Item : SourceWeights) Weight += Item.second;
    // Reserve one fifth of remaining headroom for generated support and late
    // constants. Fixed shares avoid order-dependent module-budget starvation.
    uint64_t Available = (NativeModuleInsts - moduleInstructions(M)) * 4 / 5;
    auto &AC = AM.getResult<ObfuscationAnnotationAnalysis>(M);
    for (auto &Item : SourceWeights) {
      Function &F = *Item.first;
      unsigned Limit = F.getInstructionCount() + (Weight ? Available * Item.second / Weight : 0);
      auto &Config = AC.PerFunction[&F];
      Config.budgetMultiplier = 1000000; Config.budgetHardCap = Limit;
      GrowthCoverage.push_back(json::Object{{"function", F.getName().str()}, {"stage", "application"},
          {"source_weight", Item.second}, {"instructions_before", F.getInstructionCount()}, {"instruction_ceiling", Limit}});
    }
  }
  ModulePassManager Applications;
  Applications.addPass(createModuleToFunctionPassAdaptor(ObfuscationFunctionDriverPass()));
  Applications.run(M, AM);
  saveNativeStage(M, "applications.ll");
  checkModuleBudget(M, "after-applications");

  // Closed, generation-one worklist. New helpers are captured by identity,
  // never inferred solely from prefixes. The helper profile cannot create
  // further call-table/VM/string helpers.
  SmallVector<Function *, 32> Helpers;
  for (Function &F : M) {
    if (F.isDeclaration() || F.hasFnAttribute("sre.native.source") ||
        F.hasFnAttribute("sre.native.original")) continue;
    if (!F.hasFnAttribute("sre.native.helper"))
      F.addFnAttr("sre.native.helper", F.hasFnAttribute("obf.helper.role")
          ? F.getFnAttribute("obf.helper.role").getValueAsString() : "upstream-generated");
    if (!F.hasFnAttribute("sre.native.origin"))
      F.addFnAttr("sre.native.origin", F.hasFnAttribute("obf.helper.origin")
          ? F.getFnAttribute("obf.helper.origin").getValueAsString() : "native-application-pipeline");
    Helpers.push_back(&F);
  }
  unsigned HelperLimit = NativeScaleBudget ? 4096 : 256;
  if (Helpers.size() > HelperLimit)
    report_fatal_error(Twine("native generated-helper cap exceeded: ") + Twine(HelperLimit));
  auto &FAM = AM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  unsigned HelperAllocation = NativeScaleBudget && !Helpers.empty()
      ? (NativeModuleInsts - moduleInstructions(M)) / (2 * Helpers.size()) : 0;
  json::Array HelperCoverage;
  // This closed profile changes the current helper and adds globals, never
  // other function bodies. Charge its delta rather than scan a million-IR
  // module for each of thousands of helpers. Recount at the stage boundary.
  uint64_t HelperTotal = moduleInstructions(M);
  for (Function *H : Helpers) {
    std::string Reason = structuralBlocker(*H);
    const bool Safe = Reason != "naked" && Reason != "source-inline-asm" &&
                      !H->hasPersonalityFn() && H->getInstructionCount() < 3000;
    std::string Status = !NativeHelpers ? "disabled" : !Safe ? "exempt" : "processed";
    unsigned Before = H->getInstructionCount();
    if (Before >= 3000) Reason = "helper-size-cap";
    if (NativeHelpers && Safe) {
      H->addFnAttr("sre.native.stage", "helper");
      enableFamilies(*H);
      H->setMemoryEffects(MemoryEffects::unknown());
      H->removeFnAttr(Attribute::Speculatable);
      std::string Spec = "obf: constenc(prob=100,maxSites=24,encFP=0),"
                         "sdiff(prob=50,slots=2,maxSites=8),shield(maxSites=12)";
      if (Reason.empty())
        Spec += ",flattening(minBlocks=2,maxBlocks=500,opaqueState=1,fakeCases=2,multiState=" +
            std::to_string(NativeMultiState.getValue()) + ",stateFamily=" +
            std::to_string(NativeStateFamily.getValue()) + ")";
      H->addFnAttr("sre.native.spec", Spec);
      H->addFnAttr("sre.native.helper.run");
      auto &HC = AM.getResult<ObfuscationAnnotationAnalysis>(M);
      HC.PerFunction[H] = AnnotationParser::parseAnnotationString(Spec);
      if (NativeScaleBudget) {
        HC.PerFunction[H].budgetMultiplier = 1000000;
        HC.PerFunction[H].budgetHardCap = H->getInstructionCount() + HelperAllocation;
      }
      FAM.invalidate(*H, PreservedAnalyses::none());
      auto PA = ObfuscationFunctionDriverPass().run(*H, FAM);
      FAM.invalidate(*H, PA);
      H->removeFnAttr("sre.native.helper.run");
      H->addFnAttr("sre.native.helper.processed");
      HelperTotal = HelperTotal - Before + H->getInstructionCount();
      checkInstructionBudget(M, "after-helper", HelperTotal);
    }
    json::Array Calls, Globals;
    SmallPtrSet<GlobalValue *, 16> Dependencies;
    for (Instruction &I : instructions(*H)) {
      if (auto *CB = dyn_cast<CallBase>(&I))
        if (Function *C = CB->getCalledFunction())
          if (!C->isIntrinsic() && Dependencies.insert(C).second)
            Calls.push_back(C->getName().str());
      for (Value *V : I.operands())
        if (V->getType()->isPointerTy())
          if (auto *G = dyn_cast<GlobalVariable>(getUnderlyingObject(V)))
            if (Dependencies.insert(G).second) Globals.push_back(G->getName().str());
    }
    HelperCoverage.push_back(json::Object{{"function", H->getName().str()},
        {"role", H->getFnAttribute("sre.native.helper").getValueAsString().str()},
        {"origin", H->getFnAttribute("sre.native.origin").getValueAsString().str()},
        {"generation", 1}, {"status", Status}, {"structural_reason", Reason},
        {"direct_calls", std::move(Calls)}, {"referenced_globals", std::move(Globals)},
        {"instructions_before", Before},
        {"instructions_after", H->getInstructionCount()}});
  }
  checkModuleBudget(M, "after-helpers");
  saveNativeStage(M, "helpers.ll");
  json::Array LateCoverage;
  if (NativeLate) {
    unsigned LateCount = 0;
    for (Function &F : M)
      LateCount += F.hasFnAttribute("sre.native.original") || F.hasFnAttribute("sre.native.helper.processed");
    unsigned LateAllocation = NativeScaleBudget && LateCount ? (NativeModuleInsts - moduleInstructions(M)) / LateCount : 0;
    for (Function &F : M) {
      if (!F.hasFnAttribute("sre.native.original") &&
          !F.hasFnAttribute("sre.native.helper.processed")) continue;
      if (F.getInstructionCount() > 29000) {
        LateCoverage.push_back(json::Object{{"function", F.getName().str()},
            {"status", "skipped"}, {"reason", "late-function-budget"}});
        continue;
      }
      auto &LC = AM.getResult<ObfuscationAnnotationAnalysis>(M);
      F.addFnAttr("sre.native.stage", "late");
      auto Saved = LC.PerFunction[&F];
      LC.PerFunction[&F] = AnnotationParser::parseAnnotationString(
          "obf: constenc(prob=100,maxSites=16,encFP=0)");
      if (NativeScaleBudget) {
        LC.PerFunction[&F].budgetMultiplier = 1000000;
        LC.PerFunction[&F].budgetHardCap = F.getInstructionCount() + LateAllocation;
      }
      FAM.invalidate(F, PreservedAnalyses::none());
      // The ordinary driver supplies transactional hard-cap enforcement in
      // scale mode; legacy late-pass behavior stays unchanged when disabled.
      bool HelperRun = F.hasFnAttribute("sre.native.helper");
      if (NativeScaleBudget && HelperRun) F.addFnAttr("sre.native.helper.run");
      auto PA = NativeScaleBudget ? ObfuscationFunctionDriverPass().run(F, FAM) : ConstEncPass().run(F, FAM);
      if (NativeScaleBudget && HelperRun) F.removeFnAttr("sre.native.helper.run");
      FAM.invalidate(F, PA);
      LC.PerFunction[&F] = std::move(Saved);
      LateCoverage.push_back(json::Object{{"function", F.getName().str()},
          {"status", PA.areAllPreserved() ? "no-change" : "processed"}});
    }
    checkModuleBudget(M, "after-late-constants");
  }
  // Rewrite after helper passes so they cannot disappear from the legacy sink.
  if (obf::isReportEnabled())
    if (Error E = obf::maybeWriteObfReportJson(M, AM))
      report_fatal_error(Twine("native pass report: ") + toString(std::move(E)));
  // This entry point only supplies known IR-only configurations. Check actual
  // generated code as well: do not allow source annotations to enable a VM or
  // an assembly/timing technique behind the profile's back.
  for (const Function &F : M) {
    if (F.isDeclaration() || (!F.hasFnAttribute("sre.native.original") &&
                             !F.hasFnAttribute("sre.native.helper"))) continue;
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
    // Inventory final IR, not emission counters or attributes that can survive
    // a budget rollback. Later passes may rewrite individual comparisons.
    json::Array StateCoverage;
    for (const Function &F : M) {
      unsigned Words = 0, Comparisons = 0, DataUpdates = 0, ControlUpdates = 0;
      for (const Instruction &I : instructions(F)) {
        if (isa<AllocaInst>(I) &&
            (I.getName() == "fla.state" || I.getName() == "fla.multi.key" ||
             I.getName() == "fla.multi.salt")) ++Words;
        if (isa<ICmpInst>(I) && I.getName().starts_with("fla.multi.match"))
          ++Comparisons;
        if (auto *Tag = I.getMetadata("sre.native.context.update")) {
          StringRef Role = cast<MDString>(Tag->getOperand(0))->getString();
          if (Role == "data") ++DataUpdates;
          if (Role == "control") ++ControlUpdates;
        }
      }
      if (Words) StateCoverage.push_back(json::Object{
          {"function", F.getName().str()}, {"words", Words},
          {"coupled_data_updates", DataUpdates}, {"coupled_control_updates", ControlUpdates},
          {"remaining_named_comparisons", Comparisons}});
    }
    std::error_code EC;
    raw_fd_ostream OS(NativeReport, EC, sys::fs::OF_Text);
    if (EC) report_fatal_error(Twine("native report: ") + EC.message());
    json::Object Result{{"schema", "sre-native-v3"},
                        {"profile", "native-" + NativeLevel.getValue() + "-ir"},
                        {"seed", std::to_string(static_cast<uint64_t>(ObfSeed))},
                        {"vm", false}, {"injected_assembly", false},
                        {"features", json::Object{{"diversity", NativeDiversity.getValue()},
                            {"data", NativeData.getValue()}, {"helpers", NativeHelpers.getValue()},
                            {"strings", NativeStrings.getValue()}, {"merge", NativeMerge.getValue()},
                            {"multistate", NativeMultiState.getValue()},
                            {"state_family", NativeStateFamily.getValue()},
                            {"values", NativeValues.getValue()}, {"outline", NativeOutline.getValue()},
                            {"coupled_state", NativeCoupledState.getValue()},
                            {"fusion", NativeFusion.getValue()}, {"memory", NativeMemory.getValue()},
                            {"values_wide", NativeWide.getValue()}, {"invariant", NativeInvariant.getValue()},
                            {"value_nodes", NativeValueNodes.getValue()},
                            {"region_plan", NativeRegionPlan.getValue()}, {"connected_nodes", NativeConnectedNodes.getValue()},
                            {"module_instruction_limit", NativeModuleInsts.getValue()},
                            {"scale_budget", NativeScaleBudget.getValue()}, {"helper_limit", HelperLimit},
                            {"scale_structure", NativeScaleStructure.getValue()},
                            {"memory_ssa", NativeMemorySSA.getValue()}, {"predicate_regions", NativePredicateRegions.getValue()},
                            {"regional_families", NativeRegionalFamilies.getValue()}, {"support_regions", NativeSupportRegions.getValue()},
                            {"connected_shards", NativeConnectedShards.getValue()},
                            {"connected_aggregates", NativeConnectedAggregates.getValue()},
                            {"joint_outputs", NativeJointOutputs.getValue()},
                            {"late_constants", NativeLate.getValue()}}},
                        {"merged_groups", std::move(MergedCoverage)},
                        {"fused_calls", std::move(FusionCoverage)}, {"memory", std::move(MemoryCoverage)},
                        {"flattening_state", std::move(StateCoverage)},
                        {"values", std::move(ValueCoverage)}, {"outlined_regions", std::move(OutlineCoverage)},
                        {"connected_regions", std::move(ConnectedCoverage)}, {"support_regions", std::move(SupportCoverage)},
                        {"encodings", obf::nativeEncodingInventory(M)},
                        {"data", std::move(DataCoverage)},
                        {"helpers", std::move(HelperCoverage)},
                        {"late_constants", std::move(LateCoverage)},
                        {"functions", std::move(Coverage)}};
    Result["input_inventory"] = std::move(InputInventory);
    Result["growth_allocations"] = std::move(GrowthCoverage);
    Result["structural_allocations"] = std::move(StructuralCoverage);
    Result["region_inventory"] = std::move(RegionInventory);
    Result["final_inventory"] = obf::nativeBoundaryInventory(M, "final-ir");
    OS << formatv("{0:2}\n", json::Value(std::move(Result)));
  }
  return PreservedAnalyses::none();
}
