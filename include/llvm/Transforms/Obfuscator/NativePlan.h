#pragma once
// The private, typed plan the connected encoder decides before it expands
// anything. It is a record of decisions, not a second compiler IR: it holds no
// LLVM pointers, no expressions and no instruction list, so it can be printed,
// serialized, diffed between seeds and validated independently of the module
// it describes. Execution remains ordinary LLVM IR; nothing here is
// interpreted at runtime.
//
// Two rules give the structure its meaning:
//
//   1. Op nodes describe the graph at entry to connected lowering. They are
//      sealed before this encoder expands them. Earlier passes may already
//      have inserted or cloned instructions; instruction-level frontend source
//      lineage is not implemented. "Original" below means pre-lowering, not
//      an original C/C++ operation. The input inventory is a separate scope.
//   2. Every reference is a stable index or an origin string. Nothing is keyed
//      by a pointer or a hash bucket, so the plan is identical across runs of
//      one seed and comparable across seeds.
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/JSON.h"
#include <cstdint>
#include <string>

namespace llvm::obf::plan {

// Version of this plan format. Independent of the report `schema` string: a
// consumer reads the plan version to know which fields exist.
constexpr unsigned Version = 2;
constexpr unsigned Invalid = ~0u;

// ---------------------------------------------------------------------------
// Fixed vocabularies. Every enumerator has exactly one name, and `Count` is
// never a value: an unclassifiable item is a bug, not a new category.
// ---------------------------------------------------------------------------

// Why a logical value exists as an ordinary scalar at some point in the
// program. This is the M0 inventory vocabulary and it is closed. These are
// diagnostics about where a representation ends; they are not a percentage of
// unprotected source instructions, and removing the metadata that marks a
// boundary does not remove the boundary.
enum class Boundary : uint8_t {
  ExternalABI,           // a supported caller, callee or return must see a scalar
  AddressExposure,       // a machine address had to be materialized
  UnsupportedOperation,  // no supported transfer exists for this consumer
  ObjectEscape,          // storage could not be proved closed to this function
  ComponentLimit,        // the owning component was not selected at all
  InterfaceMismatch,     // an internal edge that no encoded contract covers
  BudgetLoss,            // eligible and selected against, for cost
  Count
};
StringRef name(Boundary);

// Representation families. `Version` on Representation distinguishes revisions
// of one family; the pair (Family, Version) is what a transfer law is proved
// against. A verified offline family is added here and nowhere else.
enum class Family : uint8_t {
  None,
  XorPrefixPair,   // e ^ r, carry network for arithmetic          (v03 baseline)
  AdditivePair,    // e - r, coordinate-wise for linear operations (v03 baseline)
  TriangularXor,  // jointly chained XOR coordinates plus a carrier
  TriangularAdditive, // jointly chained additive coordinates plus a carrier
  Count
};
StringRef name(Family);
// The report string for one family revision, e.g. "xor-prefix-pair-v1".
std::string familyVersion(Family, uint16_t Version);

// What an op node is, taken from the original instruction.
enum class NodeKind : uint8_t { Pure, Load, Store, Compare, Phi, Select, Cast, Count };
StringRef name(NodeKind);

// The kinds of transfer the plan can require. A lowering that cannot name its
// transfer kind does not have one.
enum class TransferKind : uint8_t {
  Entry,      // scalar -> representation
  Operation,  // representation -> representation across one source operation
  Family,     // conversion between families at one phase
  Join,       // control join between representations
  Backedge,   // loop-carried join, which must converge
  Storage,    // object load or store
  Interface,  // private-call argument or result
  Exit,       // representation -> scalar; this is a decode site
  Count
};
StringRef name(TransferKind);

// How a law was established. `Unverified` is the honest default and is never
// silently upgraded; SMT `unknown` stays `Unverified`, it does not become
// `Smt`. Offline enumeration of a complete small domain is `Enumerated`.
enum class Verification : uint8_t { Unverified, Algebraic, Enumerated, Smt, Count };
StringRef name(Verification);

// Effects an op node has on planned storage and interfaces. Recorded from the
// original graph, so an effect cannot appear because lowering created one.
enum Effect : uint8_t {
  EffectNone = 0,
  EffectReadsObject = 1,
  EffectWritesObject = 2,
  EffectCallArgument = 4,
  EffectCallResult = 8
};

// Stable identity for a planned item: "<function>/<kind>/<index>". Index is
// the item's position in the function's own stable IR walk, never a pointer
// and never a counter shared across functions.
std::string originId(StringRef Function, StringRef Kind, unsigned Index);

// ---------------------------------------------------------------------------
// Descriptors
// ---------------------------------------------------------------------------

// One representation instance, and the seam an offline-verified family plugs
// into. A family is declared in exactly one place (the encoder's
// representation() helper): its lane count, carrier width, valid-state
// invariant, seed namespace, and how its laws were established. Every region,
// bundle, storage map and call contract then names a representation by index,
// and every transfer names the representation on each side, so a reference
// model can be checked against the plan without reading the emitter.
//
// The v03 connected path still branches on its per-region `Affine` boolean.
// NativeBundle's new lowering instead dispatches from this descriptor and a
// sealed slot schedule; declaring a family here alone never supplies a lowering.
struct Representation {
  Family Fam = Family::None;
  uint16_t Rev = 0;          // revision of that family
  uint8_t Lanes = 0;         // physical coordinates, including shared carriers
  uint16_t LogicalWidth = 0; // source value width in bits; 0 = mixed
  uint16_t LaneWidth = 0;    // physical carrier width per lane, in bits
  // The invariant a valid lane tuple satisfies, as a checkable name, e.g.
  // "xor-of-lanes" or "difference-of-lanes". An emitter that cannot name its
  // invariant does not get to claim one.
  std::string Invariant;
  // Hierarchical RNG namespace this representation draws from. Fork labels are
  // derived from the seed and this string only, never from iteration order.
  std::string SeedNamespace;
  Verification Verified = Verification::Unverified;
};

// One original operation, recorded before expansion.
struct OpNode {
  std::string Origin;
  NodeKind Kind = NodeKind::Pure;
  uint16_t LogicalWidth = 0;
  uint8_t Effects = EffectNone;
  unsigned Region = Invalid;   // owning region, or Invalid when not selected
  unsigned Object = Invalid;   // storage this node reads or writes
  unsigned EstimatedCost = 0, Score = 0;
  // Indices into Plan::Ops of this node's ORIGINAL operands that are
  // themselves planned operations. Source edges only. Nothing generated is
  // ever added here, so this graph cannot inflate.
  SmallVector<unsigned, 4> Operands;
  // Original uses of this node that leave the plan. Measured, not estimated.
  unsigned ScalarUses = 0;
  // Selected, or the reason it was not. Empty reason means selected.
  Boundary Reason = Boundary::Count;
  bool Selected = false;
};

// One storage object and the ownership claimed over it.
struct ObjectNode {
  std::string Origin, Name, Layout;
  uint64_t Elements = 0, Leaves = 0;
  // 0 means "mixed or not a single width" and is reported as unknown, never
  // as a zero-width field.
  uint16_t ElementWidth = 0;
  unsigned Loads = 0, Stores = 0;
  unsigned Region = Invalid, Storage = Invalid;
  // Proved closed to this function: no escape, no unknown alias, every access
  // understood. False means the object is described but not owned.
  bool Owned = false;
  // The precise walk reason, kept verbatim for diagnosis, plus its fixed
  // boundary classification. Empty reason means admitted.
  std::string SkipReason;
  Boundary Reason = Boundary::Count;
};

// How an owned object's state is physically mapped.
struct StorageMap {
  std::string Origin, Mapping;  // e.g. "parallel-lane-allocas"
  unsigned Object = Invalid, Rep = Invalid;
  unsigned LoadEdges = 0, StoreEdges = 0;
  // Addresses that had to be materialized for this object. A CPU eventually
  // requires an address; this counts how often.
  unsigned AddressExposures = 0;
};

// What one call edge is permitted to exchange without a scalar decode.
struct CallContract {
  std::string Origin, Interface;
  bool CarriesArguments = false, CarriesResult = false;
  unsigned SuppliedPairs = 0, AbsorbedArguments = 0, PartialArguments = 0;
  unsigned Rep = Invalid;
  // "absorbed", "partial" or "boundary".
  std::string Status;
  Boundary Reason = Boundary::Count;
};

// One selected region: the unit that currently carries one representation.
struct RegionDescriptor {
  std::string Origin;
  unsigned Component = 0, Shard = 0;
  bool Sharded = false;
  unsigned Rep = Invalid;
  unsigned Nodes = 0, EstimatedCost = 0, Score = 0;
};

// A bundle of logical values intended to share one joint representation. v03
// couples exactly two; the descriptor does not assume that number.
struct Bundle {
  std::string Origin;
  SmallVector<unsigned, 4> Members;  // indices into Plan::Ops
  unsigned Rep = Invalid, Phase = 0;
  // Uses actually governed by the joint representation, counted after
  // emission. An ungoverned use is not coverage.
  unsigned GovernedUses = 0;
  std::string Status;  // "planned", "coupled" or "rejected"
  std::string RejectReason;
};

// A transfer the plan requires, with the representations on each side.
struct Transfer {
  std::string Origin;
  TransferKind Kind = TransferKind::Entry;
  unsigned From = Invalid, To = Invalid;  // indices into Plan::Representations
  unsigned FromPhase = 0, ToPhase = 0;
  Verification Verified = Verification::Unverified;
  unsigned Count = 0;  // instances emitted; measured
};

// A representation change at a program point. v04 milestone M3 fills these in;
// M1 records the descriptor and an empty finite phase set.
struct PhaseTransition {
  std::string Origin, Law;
  unsigned From = 0, To = 0;
  TransferKind Kind = TransferKind::Join;
  unsigned Count = 0;
};

// A control join between representations, including loop backedges, which must
// converge over the finite phase set.
struct LoopJoin {
  std::string Origin;
  unsigned Node = Invalid, Rep = Invalid;
  unsigned Incoming = 0;
  bool Backedge = false;
};

// One place a representation ends and an ordinary scalar exists.
struct DecodeSite {
  std::string Origin;
  // Fixed consumer vocabulary: "branch-choice", "address", "return", "call",
  // "store", "phi" or "unsupported-consumer".
  std::string Consumer;
  Boundary Reason = Boundary::UnsupportedOperation;
  unsigned Uses = 0;
  // Original operations carried in a representation upstream of this exposure,
  // counted over the ORIGINAL operand graph only. This is the "useful work
  // between exposures" measure; it is a count of source operations, never of
  // generated instructions, and it is a diagnostic, not a hardness claim.
  unsigned UsefulWork = 0;
};

// Costs. Estimates are the planner's own model; actuals are instruction
// counts. They are reported side by side so a model drift is visible.
struct CostRecord {
  unsigned EligibleEstimated = 0, SelectedEstimated = 0;
  unsigned SkippedEstimated = 0, LostEstimated = 0;
  unsigned ComponentLimit = 0, ShardLimit = 0;
  // Structural budget held back from components that own no storage or bundle,
  // so a coherent unit can still be afforded later. Zero when the reservation
  // is off, which is the default and is exactly the previous behaviour.
  unsigned ReservedStructural = 0, ReserveDenied = 0, ReserveDeniedCost = 0;
  unsigned InstructionsBefore = 0, InstructionsAfter = 0;
  bool RolledBack = false;
  // What a rollback undoes. The connected encoder creates only function-local
  // instructions and allocas, so its scope is the function body; a lowering
  // that creates globals or callees must widen this and say so.
  std::string RollbackScope = "function-body";
};

// The M0 boundary inventory, keyed by origin and reason.
struct BoundaryInventory {
  // Scalar-use edges crossing each reason, and distinct origins producing
  // them. Edges are counted at the point a scalar is actually materialized,
  // not from the presence of any metadata.
  unsigned Edges[unsigned(Boundary::Count)] = {};
  unsigned Origins[unsigned(Boundary::Count)] = {};
  // Edges that were eligible to be a boundary and were carried encoded across
  // an interface instead. Kept visible so absorbing a crossing cannot make the
  // denominator shrink.
  unsigned AbsorbedEdges = 0;
  // Build constants entering a representation. Not a boundary: no program data
  // is exposed. Counted separately so it cannot pad the reason table.
  unsigned ConstantEntries = 0;
  // Useful work between exposures, over original operations only.
  unsigned ProtectedOps = 0, Exposures = 0;
  unsigned UsefulWorkTotal = 0, UsefulWorkMax = 0;
  // False means every field above is unknown for this function, and the
  // consumer must read null rather than zero.
  bool Measured = false;

  void record(Boundary, unsigned Edges = 1, bool NewOrigin = false);
  unsigned totalEdges() const;
};

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

struct Plan {
  unsigned FormatVersion = Version;
  std::string Function, SeedNamespace;
  uint64_t Seed = 0;
  // Denominators from the pre-connected-lowering graph. Earlier passes may
  // already have inserted support, call interfaces or normalized memory ops.
  unsigned EligibleNodes = 0, EligibleObjects = 0, EligibleMemoryEdges = 0;

  SmallVector<Representation, 4> Representations;
  SmallVector<OpNode, 64> Ops;
  SmallVector<ObjectNode, 8> Objects;
  SmallVector<StorageMap, 8> Storage;
  SmallVector<CallContract, 8> Calls;
  SmallVector<RegionDescriptor, 8> Regions;
  SmallVector<Bundle, 8> Bundles;
  SmallVector<Transfer, 16> Transfers;
  SmallVector<PhaseTransition, 4> Phases;
  SmallVector<LoopJoin, 8> Joins;
  SmallVector<DecodeSite, 32> Decodes;
  BoundaryInventory Inventory;
  CostRecord Cost;

  // Set once the original graph has been analysed, before the encoder emits
  // anything. What actually enforces "analysis before expansion" is that op
  // nodes are built in one place, from the unexpanded function; this flag is
  // how a consumer can tell, and validate() rejects an unsealed plan. It is a
  // published fact, not a lock: a future lowering that added nodes after
  // sealing would have to be caught here.
  bool Sealed = false;

  // Intern a representation, returning its index. Identical descriptors share
  // one entry, so the table stays inspectably small.
  unsigned intern(const Representation &);
  // Add one instance of a transfer between two interned representations.
  void transfer(StringRef Origin, TransferKind, unsigned From, unsigned To,
                Verification, unsigned Count = 1);
  // DFS acyclic depth of pre-lowering SELECTED operations ending at each op,
  // inclusive: the source work carried in a representation up to that point.
  // One O(nodes + edges) pass for the whole function; a caller that needs many
  // of these computes the vector once rather than asking per site.
  void usefulWorkAll(SmallVectorImpl<unsigned> &Out) const;
  unsigned usefulWork(unsigned Op) const;

  json::Object toJSON() const;
  // Internal consistency only. A violation is a planner bug, never a program
  // property: indices in range, no generated node, denominators that add up,
  // every unselected node carrying a reason, every decode carrying one.
  void validate(SmallVectorImpl<std::string> &Violations) const;
};

}  // namespace llvm::obf::plan
