#include "llvm/Transforms/Obfuscator/NativePlan.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>

using namespace llvm;
namespace llvm::obf::plan {
namespace {
const char *const BoundaryNames[unsigned(Boundary::Count)] = {
    "external-abi", "address-exposure", "unsupported-operation", "object-escape",
    "component-limit", "interface-mismatch", "budget-loss"};
const char *const FamilyNames[unsigned(Family::Count)] = {
    "none", "xor-prefix-pair", "additive-pair", "triangular-xor", "triangular-additive"};
const char *const NodeKindNames[unsigned(NodeKind::Count)] = {
    "pure", "load", "store", "compare", "phi", "select", "cast"};
const char *const TransferNames[unsigned(TransferKind::Count)] = {
    "entry", "operation", "family", "join", "backedge", "storage", "interface", "exit"};
const char *const VerificationNames[unsigned(Verification::Count)] = {
    "unverified", "algebraic", "enumerated", "smt"};
// A count whose denominator was never measured is unknown, never zero.
json::Value known(bool Measured, unsigned V) {
  return Measured ? json::Value(V) : json::Value(nullptr);
}
json::Value index(unsigned V) { return V == Invalid ? json::Value(nullptr) : json::Value(V); }
json::Array indices(ArrayRef<unsigned> Values) {
  json::Array Result;
  for (unsigned V : Values) Result.push_back(V);
  return Result;
}
}  // namespace

StringRef name(Boundary B) { return BoundaryNames[unsigned(B)]; }
StringRef name(Family F) { return FamilyNames[unsigned(F)]; }
StringRef name(NodeKind K) { return NodeKindNames[unsigned(K)]; }
StringRef name(TransferKind K) { return TransferNames[unsigned(K)]; }
StringRef name(Verification V) { return VerificationNames[unsigned(V)]; }

std::string familyVersion(Family F, uint16_t Rev) {
  return (Twine(name(F)) + "-v" + Twine(Rev)).str();
}

std::string originId(StringRef Function, StringRef Kind, unsigned Index) {
  return (Twine(Function) + "/" + Kind + "/" + Twine(Index)).str();
}

void BoundaryInventory::record(Boundary B, unsigned E, bool NewOrigin) {
  Edges[unsigned(B)] += E;
  if (NewOrigin) ++Origins[unsigned(B)];
}

unsigned BoundaryInventory::totalEdges() const {
  unsigned Total = 0;
  for (unsigned K = 0; K < unsigned(Boundary::Count); ++K) Total += Edges[K];
  return Total;
}

unsigned Plan::intern(const Representation &R) {
  for (unsigned K = 0; K < Representations.size(); ++K) {
    const Representation &E = Representations[K];
    if (E.Fam == R.Fam && E.Rev == R.Rev && E.Lanes == R.Lanes &&
        E.LogicalWidth == R.LogicalWidth && E.LaneWidth == R.LaneWidth &&
        E.Invariant == R.Invariant && E.SeedNamespace == R.SeedNamespace &&
        E.Verified == R.Verified)
      return K;
  }
  Representations.push_back(R);
  return Representations.size() - 1;
}

void Plan::transfer(StringRef Origin, TransferKind Kind, unsigned From, unsigned To,
                    Verification V, unsigned Count) {
  // One row per (origin, kind, endpoints): instances accumulate instead of
  // filling the plan with a row per emitted instruction.
  for (Transfer &T : Transfers)
    if (T.Kind == Kind && T.From == From && T.To == To && T.Origin == Origin) {
      T.Count += Count;
      if (T.Verified != V) T.Verified = std::min(T.Verified, V);
      return;
    }
  Transfer T;
  T.Origin = Origin.str(); T.Kind = Kind; T.From = From; T.To = To;
  T.Verified = V; T.Count = Count;
  Transfers.push_back(std::move(T));
}

void Plan::usefulWorkAll(SmallVectorImpl<unsigned> &Out) const {
  // DFS acyclic depth of pre-connected-lowering SELECTED operations at each node,
  // inclusive: the source work that stayed in a representation up to that
  // point. Only selected nodes are walked, so an eligible-but-skipped
  // operation cannot lengthen a chain, and only original operand edges exist
  // here, so lowering cannot inflate one. A PHI operand can close a cycle, so
  // a node already on the walk contributes nothing rather than looping
  // forever. Memoizing a cycle-cut walk is deterministic but not an exact
  // longest simple path in a cyclic graph; report the metric accordingly.
  //
  // Iterative, memoized and computed for every node in one pass: a function
  // with many exposures must not pay a walk per exposure.
  Out.assign(Ops.size(), 0);
  SmallVector<uint8_t, 64> State(Ops.size(), 0);  // 0 unseen, 1 on walk, 2 done
  SmallVector<std::pair<unsigned, unsigned>, 64> Work;
  for (unsigned Root = 0; Root < Ops.size(); ++Root) {
    if (State[Root] || !Ops[Root].Selected) continue;
    Work.push_back({Root, 0});
    State[Root] = 1;
    while (!Work.empty()) {
      auto &[N, Next] = Work.back();
      if (Next < Ops[N].Operands.size()) {
        unsigned P = Ops[N].Operands[Next++];
        if (P >= Ops.size() || State[P] == 1 || !Ops[P].Selected) continue;
        if (State[P] == 2) { Out[N] = std::max(Out[N], Out[P]); continue; }
        State[P] = 1;
        Work.push_back({P, 0});
        continue;
      }
      Out[N] += 1;
      State[N] = 2;
      unsigned Done = N;
      Work.pop_back();
      if (!Work.empty()) Out[Work.back().first] = std::max(Out[Work.back().first], Out[Done]);
    }
  }
}

unsigned Plan::usefulWork(unsigned Op) const {
  if (Op >= Ops.size() || !Ops[Op].Selected) return 0;
  SmallVector<unsigned, 64> All;
  usefulWorkAll(All);
  return All[Op];
}

json::Object Plan::toJSON() const {
  json::Array Reps;
  for (const Representation &R : Representations)
    Reps.push_back(json::Object{{"family", name(R.Fam)}, {"revision", R.Rev},
        {"name", familyVersion(R.Fam, R.Rev)}, {"lanes", R.Lanes},
        {"logical_width", R.LogicalWidth ? json::Value(R.LogicalWidth) : json::Value(nullptr)},
        {"lane_width", R.LaneWidth ? json::Value(R.LaneWidth) : json::Value(nullptr)},
        {"invariant", R.Invariant},
        {"seed_namespace", R.SeedNamespace}, {"verification", name(R.Verified)}});
  json::Array Nodes;
  for (const OpNode &N : Ops)
    Nodes.push_back(json::Object{{"origin", N.Origin}, {"kind", name(N.Kind)},
        {"logical_width", N.LogicalWidth}, {"effects", N.Effects},
        {"region", index(N.Region)}, {"object", index(N.Object)},
        {"estimated_cost", N.EstimatedCost}, {"operands", indices(N.Operands)},
        {"operand_count", N.Operands.size()},
        {"scalar_uses", N.ScalarUses}, {"selected", N.Selected},
        {"reason", N.Reason == Boundary::Count ? json::Value(nullptr) : json::Value(name(N.Reason))}});
  json::Array Objs;
  for (const ObjectNode &O : Objects)
    Objs.push_back(json::Object{{"origin", O.Origin}, {"object", O.Name}, {"layout", O.Layout},
        {"elements", O.Elements}, {"leaves", O.Leaves},
        {"element_width", O.ElementWidth ? json::Value(O.ElementWidth) : json::Value(nullptr)},
        {"loads", O.Loads}, {"stores", O.Stores}, {"owned", O.Owned},
        {"region", index(O.Region)}, {"storage", index(O.Storage)},
        {"skip_reason", O.SkipReason.empty() ? json::Value(nullptr) : json::Value(O.SkipReason)},
        {"reason", O.Reason == Boundary::Count ? json::Value(nullptr) : json::Value(name(O.Reason))}});
  json::Array Maps;
  for (const StorageMap &S : Storage)
    Maps.push_back(json::Object{{"origin", S.Origin}, {"mapping", S.Mapping},
        {"object", index(S.Object)}, {"representation", index(S.Rep)},
        {"load_edges", S.LoadEdges}, {"store_edges", S.StoreEdges},
        {"address_exposures", S.AddressExposures}});
  json::Array Contracts;
  for (const CallContract &C : Calls)
    Contracts.push_back(json::Object{{"origin", C.Origin}, {"interface", C.Interface},
        {"carries_arguments", C.CarriesArguments}, {"carries_result", C.CarriesResult},
        {"supplied_pairs", C.SuppliedPairs}, {"absorbed_arguments", C.AbsorbedArguments},
        {"partial_arguments", C.PartialArguments}, {"representation", index(C.Rep)},
        {"status", C.Status},
        {"reason", C.Reason == Boundary::Count ? json::Value(nullptr) : json::Value(name(C.Reason))}});
  json::Array Regs;
  for (const RegionDescriptor &R : Regions)
    Regs.push_back(json::Object{{"origin", R.Origin}, {"component", R.Component},
        {"shard", R.Shard}, {"sharded", R.Sharded}, {"representation", index(R.Rep)},
        {"nodes", R.Nodes}, {"estimated_cost", R.EstimatedCost}, {"score", R.Score}});
  json::Array Groups;
  for (const Bundle &B : Bundles)
    Groups.push_back(json::Object{{"origin", B.Origin}, {"members", indices(B.Members)},
        {"member_count", B.Members.size()},
        {"representation", index(B.Rep)}, {"phase", B.Phase},
        {"governed_uses", B.GovernedUses}, {"status", B.Status},
        {"reject_reason", B.RejectReason.empty() ? json::Value(nullptr) : json::Value(B.RejectReason)}});
  json::Array Moves;
  for (const Transfer &T : Transfers)
    Moves.push_back(json::Object{{"origin", T.Origin}, {"kind", name(T.Kind)},
        {"from", index(T.From)}, {"to", index(T.To)}, {"from_phase", T.FromPhase},
        {"to_phase", T.ToPhase}, {"verification", name(T.Verified)}, {"instances", T.Count}});
  json::Array PhaseRows;
  for (const PhaseTransition &P : Phases)
    PhaseRows.push_back(json::Object{{"origin", P.Origin}, {"law", P.Law}, {"from", P.From},
        {"to", P.To}, {"kind", name(P.Kind)}, {"instances", P.Count}});
  json::Array JoinRows;
  for (const LoopJoin &J : Joins)
    JoinRows.push_back(json::Object{{"origin", J.Origin}, {"node", index(J.Node)},
        {"representation", index(J.Rep)}, {"incoming", J.Incoming}, {"backedge", J.Backedge}});
  json::Array Sites;
  for (const DecodeSite &D : Decodes)
    Sites.push_back(json::Object{{"origin", D.Origin}, {"consumer", D.Consumer},
        {"reason", name(D.Reason)}, {"uses", D.Uses}, {"useful_work", D.UsefulWork}});
  json::Object Reasons, ReasonOrigins;
  for (unsigned K = 0; K < unsigned(Boundary::Count); ++K) {
    Reasons[BoundaryNames[K]] = known(Inventory.Measured, Inventory.Edges[K]);
    ReasonOrigins[BoundaryNames[K]] = known(Inventory.Measured, Inventory.Origins[K]);
  }
  json::Object Inv{{"measured", Inventory.Measured},
      {"scalar_use_edges", std::move(Reasons)},
      {"origins", std::move(ReasonOrigins)},
      {"total_scalar_use_edges", known(Inventory.Measured, Inventory.totalEdges())},
      {"absorbed_edges", known(Inventory.Measured, Inventory.AbsorbedEdges)},
      {"constant_entries", known(Inventory.Measured, Inventory.ConstantEntries)},
      {"protected_operations", known(Inventory.Measured, Inventory.ProtectedOps)},
      {"exposures", known(Inventory.Measured, Inventory.Exposures)},
      {"useful_work_total", known(Inventory.Measured, Inventory.UsefulWorkTotal)},
      {"useful_work_max", known(Inventory.Measured, Inventory.UsefulWorkMax)},
      {"useful_work_metric", "dfs-acyclic-depth"},
      {"vocabulary", "origin-and-reason-v1"}};
  json::Object Costs{{"eligible_estimated", Cost.EligibleEstimated},
      {"selected_estimated", Cost.SelectedEstimated},
      {"skipped_estimated", Cost.SkippedEstimated},
      {"lost_estimated", Cost.LostEstimated},
      {"component_limit", Cost.ComponentLimit}, {"shard_limit", Cost.ShardLimit},
      {"reserved_structural", Cost.ReservedStructural},
      {"reserve_denied_components", Cost.ReserveDenied},
      {"reserve_denied_estimated", Cost.ReserveDeniedCost},
      {"instructions_before", Cost.InstructionsBefore},
      {"instructions_after", Cost.InstructionsAfter},
      {"rolled_back", Cost.RolledBack}, {"rollback_scope", Cost.RollbackScope}};
  SmallVector<std::string, 8> Violations;
  validate(Violations);
  json::Array Bad;
  for (const std::string &V : Violations) Bad.push_back(V);
  return json::Object{{"plan_version", FormatVersion}, {"function", Function},
      {"emission_status", Cost.RolledBack ? "rolled-back" : "retained"},
      {"inventory_scope", Cost.RolledBack ? "attempted-emission" : "retained-emission"},
      {"graph_scope", "pre-connected-lowering"},
      {"source_lineage", "function-level-only"},
      {"seed_namespace", SeedNamespace}, {"sealed", Sealed},
      {"eligible_nodes", EligibleNodes}, {"eligible_objects", EligibleObjects},
      {"eligible_memory_edges", EligibleMemoryEdges},
      {"representations", std::move(Reps)}, {"operations", std::move(Nodes)},
      {"objects", std::move(Objs)}, {"storage", std::move(Maps)},
      {"calls", std::move(Contracts)}, {"regions", std::move(Regs)},
      {"bundles", std::move(Groups)}, {"transfers", std::move(Moves)},
      {"phases", std::move(PhaseRows)}, {"joins", std::move(JoinRows)},
      {"decodes", std::move(Sites)}, {"boundary_inventory", std::move(Inv)},
      {"costs", std::move(Costs)}, {"violations", std::move(Bad)}};
}

void Plan::validate(SmallVectorImpl<std::string> &V) const {
  auto fail = [&](const Twine &T) { V.push_back(T.str()); };
  if (FormatVersion != Version) fail("plan version " + Twine(FormatVersion) + " is not " + Twine(Version));
  if (!Sealed) fail("plan was never sealed: original graph analysis did not complete");
  // This denominator is fixed before this pass expands the graph; it is not
  // a claim that instructions inserted by earlier passes have source origins.
  if (Ops.size() > EligibleNodes)
    fail("planned " + Twine(Ops.size()) + " operations from " + Twine(EligibleNodes) + " eligible");
  unsigned Selected = 0;
  for (unsigned K = 0; K < Ops.size(); ++K) {
    const OpNode &N = Ops[K];
    if (N.Origin.empty()) fail("operation " + Twine(K) + " has no origin");
    for (unsigned P : N.Operands)
      if (P >= Ops.size()) fail(N.Origin + ": operand index out of range");
    if (N.Selected) {
      ++Selected;
      if (N.Region >= Regions.size()) fail(N.Origin + ": selected without a region");
      if (N.Reason != Boundary::Count) fail(N.Origin + ": selected and carries a skip reason");
    } else if (N.Reason == Boundary::Count)
      fail(N.Origin + ": unselected without a reason");
    if (N.Object != Invalid && N.Object >= Objects.size()) fail(N.Origin + ": object index out of range");
  }
  unsigned RegionNodes = 0, RegionCost = 0;
  SmallVector<unsigned, 16> ActualNodes(Regions.size(), 0), ActualCosts(Regions.size(), 0);
  for (const OpNode &N : Ops)
    if (N.Selected && N.Region < Regions.size()) {
      ++ActualNodes[N.Region];
      ActualCosts[N.Region] += N.EstimatedCost;
    }
  for (unsigned K = 0; K < Regions.size(); ++K) {
    const RegionDescriptor &R = Regions[K];
    if (R.Rep >= Representations.size()) fail(R.Origin + ": region without a representation");
    if (R.Nodes != ActualNodes[K] || R.EstimatedCost != ActualCosts[K])
      fail(R.Origin + ": region membership or cost disagrees with its operations");
    RegionNodes += R.Nodes;
    RegionCost += R.EstimatedCost;
  }
  if (RegionNodes != Selected)
    fail("regions hold " + Twine(RegionNodes) + " nodes, " + Twine(Selected) + " operations are selected");
  if (RegionCost != Cost.SelectedEstimated)
    fail("region costs " + Twine(RegionCost) + " != selected " + Twine(Cost.SelectedEstimated));
  // Eligible = selected + skipped + lost, exactly, as the shipped accounting
  // identity already requires.
  if (Cost.EligibleEstimated != Cost.SelectedEstimated + Cost.SkippedEstimated + Cost.LostEstimated)
    fail("eligible cost does not equal selected + skipped + lost");
  if (Cost.SelectedEstimated > Cost.ComponentLimit && Cost.ComponentLimit)
    fail("selected cost exceeds the component limit");
  for (const ObjectNode &O : Objects) {
    // Ownership and use are separate facts: an object can be proved closed and
    // still go unencoded for cost. What must agree is the skip reason and the
    // fixed classification put beside it.
    if (O.SkipReason.empty() != (O.Reason == Boundary::Count))
      fail(O.Origin + ": skip reason and its classification disagree");
    if (O.Region != Invalid && O.Region >= Regions.size()) fail(O.Origin + ": region index out of range");
    if (O.Storage != Invalid && O.Storage >= Storage.size()) fail(O.Origin + ": storage index out of range");
  }
  for (const StorageMap &S : Storage)
    if (S.Object >= Objects.size() || S.Rep >= Representations.size())
      fail(S.Origin + ": storage map references an unknown object or representation");
  for (const Bundle &B : Bundles) {
    if (B.Rep != Invalid && B.Rep >= Representations.size()) fail(B.Origin + ": bundle representation out of range");
    for (unsigned M : B.Members)
      if (M >= Ops.size()) fail(B.Origin + ": bundle member out of range");
    if (B.Status != "coupled" && B.GovernedUses) fail(B.Origin + ": ungoverned bundle reports governed uses");
  }
  for (const Transfer &T : Transfers)
    if ((T.From != Invalid && T.From >= Representations.size()) ||
        (T.To != Invalid && T.To >= Representations.size()))
      fail(T.Origin + ": transfer references an unknown representation");
  for (const DecodeSite &D : Decodes)
    if (D.Consumer.empty()) fail(D.Origin + ": decode site without a consumer");
  if (Inventory.Measured) {
    if (Inventory.Exposures != Decodes.size())
      fail("inventory reports " + Twine(Inventory.Exposures) + " exposures against " +
           Twine(Decodes.size()) + " decode sites");
    for (unsigned K = 0; K < unsigned(Boundary::Count); ++K)
      if (Inventory.Origins[K] > Inventory.Edges[K])
        fail(Twine(BoundaryNames[K]) + ": more origins than scalar-use edges");
    if (Inventory.ProtectedOps > Selected)
      fail("inventory protects more operations than were selected");
    if (Inventory.UsefulWorkMax > Inventory.ProtectedOps)
      fail("useful work exceeds the protected operation count");
  }
}

}  // namespace llvm::obf::plan
