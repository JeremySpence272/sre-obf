"""Unit tests for the W0 supplied-region control and its shared phases.

Hermetic: no Docker, no angr, no private artifact. The symbolic lifter is
exercised only through the pure-Python oracle, so what is tested here is the
part that decides whether a recovery may be *claimed*.
"""
from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from conformance import extract_phases as ph
from conformance import extract_supplied as es

W = 32
M = ph.mask_of(W)


def oracle(fn, width=W, arity=1, domain=None):
  return ph.CallableOracle(fn, width, arity, domain=domain)


def fitted(fn, width=W, arity=1, domain=None):
  models = ph.fit_models(oracle(fn, width, arity, domain), width, domain)
  return models[0] if models else None


class PhaseRecordTest(unittest.TestCase):
  def test_reason_must_come_from_the_fixed_vocabulary(self):
    with self.assertRaises(ValueError):
      ph.phase("lift", "inconclusive", "because-i-said-so")

  def test_ok_phase_carries_no_reason(self):
    with self.assertRaises(ValueError):
      ph.phase("lift", "ok", "budget-exhausted")

  def test_unknown_status_is_rejected(self):
    with self.assertRaises(ValueError):
      ph.phase("lift", "great")

  def test_every_reason_is_usable(self):
    for reason in ph.REASONS:
      self.assertEqual(ph.phase("lift", "inconclusive", reason)["reason"], reason)


class GrammarTest(unittest.TestCase):
  def test_identity(self):
    self.assertEqual(fitted(lambda x: x).kind, "identity-index")

  def test_xor_constant(self):
    model = fitted(lambda x: x ^ 0xDEADBEEF)
    self.assertEqual(model.kind, "xor-constant")
    self.assertEqual(model.params["k"], 0xDEADBEEF)

  def test_mask(self):
    model = fitted(lambda x: x & 0xFF)
    self.assertEqual(model.kind, "mask")
    self.assertEqual(model.params["m"], 0xFF)

  def test_affine(self):
    model = fitted(lambda x: (0x9E3779B1 * x + 0x1234) & M)
    self.assertEqual(model.kind, "affine")
    self.assertEqual((model.params["a"], model.params["b"]), (0x9E3779B1, 0x1234))

  def test_rotation(self):
    model = fitted(lambda x: ((x << 7) | (x >> 25)) & M)
    self.assertEqual(model.kind, "rotate-left")
    self.assertEqual(model.params["r"], 7)

  def test_bit_permutation(self):
    model = fitted(lambda x: int.from_bytes(x.to_bytes(4, "little"), "big"))
    self.assertEqual(model.kind, "bit-permutation")

  def test_bound_predicate(self):
    model = fitted(lambda x: 1 if x < 1000 else 0)
    self.assertEqual(model.kind, "bound")
    self.assertEqual(model.params["n"], 1000)

  def test_lookup_table_over_a_declared_domain(self):
    model = fitted(lambda x: (x * x + 3) % 7, domain=16)
    self.assertEqual(model.kind, "lookup-table")
    self.assertEqual(model.params["table"], [(i * i + 3) % 7 for i in range(16)])

  def test_pair_relations(self):
    self.assertEqual(fitted(lambda a, b: (a - b) & M, arity=2).kind, "difference")
    self.assertEqual(fitted(lambda a, b: (a + b) & M, arity=2).kind, "sum")
    self.assertEqual(fitted(lambda a, b: (a ^ b) & M, arity=2).kind, "xor-pair")

  def test_an_operation_outside_the_grammar_fits_nothing(self):
    self.assertIsNone(fitted(lambda x: (x * x) & M))

  def test_a_closed_form_relation_outranks_a_table(self):
    # A table always fits its own domain, so it must never displace a relation.
    models = ph.fit_models(oracle(lambda x: x ^ 0xAB, 8, domain=256), 8, 256)
    self.assertEqual(models[0].kind, "xor-constant")
    self.assertIn("lookup-table", [m.kind for m in models])

  def test_recurrences(self):
    states = [5]
    for _ in range(6):
      states.append(states[-1] ^ 0x9)
    model = ph.fit_recurrence(states, W)
    self.assertEqual(model.step.kind, "xor-constant")

    states = [1]
    for _ in range(6):
      states.append((states[-1] * 1103515245 + 12345) & M)
    model = ph.fit_recurrence(states, W)
    self.assertEqual(model.step.kind, "affine")
    self.assertEqual(model.step.params["a"], 1103515245)
    self.assertEqual(model.step.params["b"], 12345)
    self.assertEqual(model.iterate(1, 2), states[1:3])

  def test_models_round_trip_through_both_backends(self):
    model = ph.Rotate(W, r=5)
    backend = ph.IntBackend(W)
    self.assertEqual(model.build(backend, [0x12345678]), model.apply([0x12345678]))


class AntiOverclaimTest(unittest.TestCase):
  """The two rules plan section 2 and W0 make load-bearing."""

  def test_constructed_points_alone_do_not_accept_a_model(self):
    # No finite domain and no solver: the model fits every constructed point
    # and is still not accepted, because nothing ruled out the rest of 2**32.
    fn = lambda x: x ^ 0xDEADBEEF
    result = ph.test_model(fitted(fn), oracle(fn), W)
    self.assertEqual(result["constructed_positives"]["agreeing"],
                     result["constructed_positives"]["points"])
    self.assertFalse(result["accepted"])
    self.assertEqual(result["status"], "inconclusive")
    self.assertEqual(result["counterexample_check"]["status"], "inconclusive")

  def test_an_exhaustive_domain_can_accept_a_model(self):
    fn = lambda x: 1 if x < 10 else 0
    result = ph.test_model(fitted(fn, domain=64), oracle(fn, domain=64), W, domain=64)
    self.assertTrue(result["accepted"])
    self.assertEqual(result["counterexample_check"]["method"], "exhaustive")

  def test_a_wrong_model_is_refuted_not_merely_unproven(self):
    result = ph.test_model(ph.XorConst(W, k=1), oracle(lambda x: x ^ 2), W, domain=256)
    self.assertFalse(result["accepted"])
    self.assertEqual(result["status"], "failed")
    self.assertEqual(result["reason"], "counterexample-found")

  def test_a_probe_set_that_cannot_separate_neighbours_is_vacuous(self):
    # Pin the probe set to points that every neighbouring bound agrees on, so
    # the negatives cannot discriminate. The verdict must say so rather than
    # accept the model on its positives.
    original = ph.constructed_points
    try:
      ph.constructed_points = lambda width, arity=1: [(0,), (1,)]
      model = ph.Bound(W, n=1000)
      model.witnesses = lambda: []
      result = ph.test_model(model, oracle(lambda x: 1 if x < 1000 else 0), W)
      self.assertFalse(result["accepted"])
      self.assertEqual(result["reason"], "discriminator-vacuous")
      self.assertTrue(result["constructed_negatives"]["undiscriminated"])
    finally:
      ph.constructed_points = original

  def test_random_agreement_never_promotes_a_model(self):
    fn = lambda x: x ^ 0xDEADBEEF
    result = ph.test_model(fitted(fn), oracle(fn), W, random_samples=256)
    self.assertEqual(result["random_diagnostic"]["agreeing"], 256)
    self.assertFalse(result["accepted"])
    self.assertIn("diagnostic only", result["random_diagnostic"]["note"])

  def test_a_model_predicting_one_site_is_not_a_summary(self):
    model = ph.XorConst(W, k=7)
    sites = {"a": oracle(lambda x: x ^ 7, domain=256),
             "b": oracle(lambda x: x ^ 9, domain=256)}
    result = ph.probe_sites(model, sites, W, domain=256)
    self.assertEqual(result["status"], "inconclusive")
    self.assertEqual(result["reason"], "single-site")
    self.assertEqual(result["sites_predicted"], 1)

  def test_a_model_predicting_two_sites_is_a_summary(self):
    model = ph.XorConst(W, k=7)
    sites = {"a": oracle(lambda x: x ^ 7, domain=256),
             "b": oracle(lambda x: x ^ 7, domain=256)}
    result = ph.probe_sites(model, sites, W, domain=256)
    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["sites_predicted"], 2)

  def test_per_site_models_that_never_transfer_are_reported_single_site(self):
    sites = {f"lane_{i}": oracle(lambda x, i=i: x ^ (i + 1), domain=256)
             for i in range(4)}
    fits = {name: ph.fit_models(o, W, 256)[0] for name, o in sites.items()}
    result = ph.probe_model_reuse(fits, sites, W, domain=256)
    self.assertEqual(result["reason"], "single-site")
    self.assertEqual(result["reusable_models"] if "reusable_models" in result else 0, 0)

  def test_a_model_shared_by_two_lanes_is_reusable(self):
    sites = {"lane_0": oracle(lambda x: x ^ 5, domain=256),
             "lane_1": oracle(lambda x: x ^ 9, domain=256),
             "lane_2": oracle(lambda x: x ^ 5, domain=256),
             "lane_3": oracle(lambda x: x ^ 9, domain=256)}
    fits = {name: ph.fit_models(o, W, 256)[0] for name, o in sites.items()}
    result = ph.probe_model_reuse(fits, sites, W, domain=256)
    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["distinct_models"], 2)
    self.assertEqual(result["reusable_models"], 2)

  def test_a_slice_family_needs_more_than_one_explained_slice(self):
    table = [(i * 37 + 11) & 0xFF for i in range(256)]
    site = {"result": oracle(lambda a, b: a ^ table[b], 8, 2, domain=256)}
    result = ph.slice_family(site, 8, 256)
    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["kinds"], ["xor-constant"])
    self.assertGreaterEqual(result["slices_accepted"], 2)
    self.assertFalse(result["budget_exhausted"])

  def test_a_slice_sweep_that_runs_out_of_budget_says_so(self):
    # Zero budget stops before the first slice. The verdict must be
    # budget-exhausted, never "nothing fitted".
    site = {"result": oracle(lambda a, b: (a ^ b) & 0xFF, 8, 2, domain=256)}
    result = ph.slice_family(site, 8, 256, seconds=-1)
    self.assertEqual(result["status"], "inconclusive")
    self.assertEqual(result["reason"], "budget-exhausted")
    self.assertEqual(result["slices_probed"], 0)


class RecoveryBridgeTest(unittest.TestCase):
  """The discovery adapter's models, made provable instead of only enumerable."""

  def model(self, family, params, width=W, arity=1):
    return ph.RecoveryModel({"family": family, "params": params,
                             "width": width, "arity": arity})

  def test_each_family_evaluates(self):
    cases = [
        ("identity", {}, [5], 5),
        ("xor_const", {"k": 0xF0}, [0x0F], 0xFF),
        ("add_const", {"k": 3}, [M], 2),
        ("sub_const", {"k": 10}, [4], 6),
        ("mask_const", {"k": 0xFF}, [0x1234], 0x34),
        ("rotl", {"r": 4}, [0x0000000F], 0x000000F0),
        ("rotl", {"r": 0}, [0x1234], 0x1234),
        ("affine", {"a": 3, "b": 1}, [5], 16),
        ("bounds", {"low": 10, "high": 20}, [15], 1),
        ("bounds", {"low": 10, "high": 20}, [21], 0),
        ("bounds", {"low": 10, "high": 20}, [9], 0),
        ("table", {"domain": [0, 2, 7], "values": [11, 22, 33]}, [2], 22),
    ]
    for family, params, args, want in cases:
      with self.subTest(family=family, args=args):
        self.assertEqual(self.model(family, params).apply(args), want)

  def test_pair_families(self):
    self.assertEqual(self.model("xor_join", {"k": 1}, arity=2).apply([6, 3]), 4)
    self.assertEqual(self.model("sum_join", {"k": 1}, arity=2).apply([6, 3]), 10)
    self.assertEqual(self.model("difference", {"k": 1}, arity=2).apply([6, 3]), 4)
    self.assertEqual(self.model("affine_join", {"a": 2, "b": 3, "k": 1},
                                arity=2).apply([5, 7]), 32)

  def test_gf2_linear_is_a_xor_of_selected_columns(self):
    columns = [1 << i for i in range(W)]
    self.assertEqual(self.model("gf2_linear", {"columns": columns}).apply([0xABCD]), 0xABCD)

  def test_a_recurrence_has_no_fixed_size_term(self):
    # Its trip count is an input, so there is no term to prove. Refusing is the
    # honest answer; inventing one would manufacture a proof.
    with self.assertRaises(ValueError):
      self.model("recurrence", {"a": 5, "b": 3, "seed": 1}).apply([4])

  def test_an_unknown_family_is_rejected(self):
    with self.assertRaises(ValueError):
      self.model("telekinesis", {})

  def test_bridged_models_carry_perturbations_and_witnesses(self):
    bounded = self.model("bounds", {"low": 10, "high": 20})
    self.assertTrue(bounded.perturbations())
    self.assertIn((10,), bounded.witnesses())
    self.assertIn((21,), bounded.witnesses())
    table = self.model("table", {"domain": [0, 2, 7], "values": [1, 2, 3]})
    self.assertEqual(table.witnesses(), [(0,), (2,), (7,)])
    self.assertTrue(any(m.params["values"] != [1, 2, 3] for m in table.perturbations()))

  def test_a_bridged_model_is_accepted_only_on_the_usual_evidence(self):
    model = self.model("xor_const", {"k": 0xAB}, width=8)
    result = ph.test_model(model, oracle(lambda x: x ^ 0xAB, 8, domain=256), 8, domain=256)
    self.assertTrue(result["accepted"])
    wrong = self.model("xor_const", {"k": 0xAC}, width=8)
    self.assertFalse(ph.test_model(wrong, oracle(lambda x: x ^ 0xAB, 8, domain=256),
                                   8, domain=256)["accepted"])

  def test_models_round_trip_into_the_discovery_dict_form(self):
    self.assertEqual(ph.as_recovery_model(ph.XorConst(W, k=9)),
                     {"family": "xor_const", "params": {"k": 9}, "width": W, "arity": 1})
    self.assertEqual(ph.as_recovery_model(ph.Mask(W, m=0xFF))["family"], "mask_const")
    self.assertEqual(ph.as_recovery_model(ph.Identity(W))["family"], "identity")
    self.assertEqual(ph.as_recovery_model(ph.Difference(W))["arity"], 2)
    bridged = self.model("rotl", {"r": 3})
    self.assertEqual(ph.as_recovery_model(bridged)["family"], "rotl")

  def test_a_family_the_other_grammar_lacks_reports_the_gap(self):
    # Better a null than a dict that means something else on the other side.
    self.assertIsNone(ph.as_recovery_model(ph.BitPermutation(W, perm=list(range(W)))))
    self.assertIsNone(ph.as_recovery_model(ph.Bound(W, n=5)))

  def test_agreement_with_the_discovery_adapter_when_it_is_present(self):
    # Live cross-check once both branches are integrated; skipped before that.
    try:
      from conformance import recovery
    except ImportError:  # pragma: no cover
      self.skipTest("conformance.recovery is unavailable")
    if not hasattr(recovery, "predict"):
      self.skipTest("conformance.recovery predates the shared grammar")
    cases = [("identity", {}, 1), ("xor_const", {"k": 0xDEAD}, 1),
             ("add_const", {"k": 7}, 1), ("sub_const", {"k": 7}, 1),
             ("mask_const", {"k": 0xFF00}, 1), ("rotl", {"r": 11}, 1),
             ("affine", {"a": 1103515245, "b": 12345}, 1),
             ("bounds", {"low": 3, "high": 9}, 1),
             ("table", {"domain": [0, 4, 8], "values": [1, 2, 3]}, 1),
             ("xor_join", {"k": 5}, 2), ("sum_join", {"k": 5}, 2),
             ("difference", {"k": 5}, 2), ("affine_join", {"a": 3, "b": 5, "k": 7}, 2)]
    points = [0, 1, 2, 3, 4, 8, 9, 10, M, M - 1, 1 << 31, 0x55555555]
    for family, params, arity in cases:
      spec = {"family": family, "params": params, "width": W, "arity": arity}
      bridged = ph.RecoveryModel(spec)
      for x in points:
        for y in (0, 1, M):
          args = [x, y][:arity]
          want = recovery.predict(spec, args)
          if want is None:
            continue
          with self.subTest(family=family, args=args):
            self.assertEqual(bridged.apply(args), want)


class IndexMapTest(unittest.TestCase):
  def test_identity_rotation_and_permutation(self):
    self.assertEqual(ph.fit_source_map([0, 1, 2, 3], 4)["kind"], "identity-index")
    rotated = ph.fit_source_map([4, 5, 6, 7, 0, 1, 2, 3], 8)
    self.assertEqual(rotated["kind"], "byte-rotation")
    self.assertEqual(rotated["rotation"], 4)
    self.assertEqual(ph.fit_source_map([1, 0, 3, 2], 4)["kind"], "byte-permutation")

  def test_an_unresolved_lane_is_not_a_map(self):
    result = ph.fit_source_map([0, None, 2, 3], 4)
    self.assertEqual(result["status"], "inconclusive")
    self.assertEqual(result["reason"], "unresolved-memory")

  def test_a_lane_map_that_is_not_a_bijection_fits_nothing(self):
    self.assertEqual(ph.fit_source_map([0, 0, 2, 3], 4)["reason"], "no-candidate-model")


class SliceAndMemoryTest(unittest.TestCase):
  INTERFACE = {"abi": "int-words", "params": [{"name": "x"}, {"name": "y"}]}

  def test_declared_inputs_per_abi(self):
    self.assertEqual(ph.declared_inputs(self.INTERFACE), ["x", "y"])
    self.assertEqual(ph.declared_inputs({"abi": "buffer-in-out", "input_bytes": 3}),
                     ["in_0", "in_1", "in_2"])
    with self.assertRaises(ValueError):
      ph.declared_inputs({"abi": "telepathy"})

  def test_a_closed_slice_validates(self):
    lift = {"variables": ["x", "y"], "domain_complete": True, "steps": 12}
    self.assertEqual(ph.validate_slice(lift, self.INTERFACE)["status"], "ok")

  def test_an_undeclared_read_is_an_unresolved_boundary(self):
    lift = {"variables": ["x", "mem_401000"], "domain_complete": True}
    result = ph.validate_slice(lift, self.INTERFACE)
    self.assertEqual(result["reason"], "unresolved-memory")
    self.assertEqual(result["undeclared_reads"], ["mem_401000"])

  def test_incomplete_domain_coverage_is_not_a_validated_slice(self):
    lift = {"variables": ["x"], "domain_complete": False}
    self.assertEqual(ph.validate_slice(lift, self.INTERFACE)["reason"], "budget-exhausted")

  def test_memory_forwarding_is_claimed_only_when_nothing_is_left(self):
    lift = {"variables": ["x"], "domain_complete": True, "unresolved_reads": []}
    good = ph.validate_slice(lift, self.INTERFACE)
    self.assertTrue(ph.forward_local_memory(lift, good)["forwarded"])

    lift["unresolved_reads"] = ["stack_8"]
    result = ph.forward_local_memory(lift, good)
    self.assertFalse(result["forwarded"])
    self.assertEqual(result["reason"], "unresolved-memory")

  def test_forwarding_is_skipped_when_the_slice_did_not_validate(self):
    lift = {"variables": ["q"], "domain_complete": True}
    bad = ph.validate_slice(lift, self.INTERFACE)
    result = ph.forward_local_memory(lift, bad)
    self.assertEqual(result["status"], "skipped")
    self.assertIsNone(result["forwarded"])


class NormalizeTest(unittest.TestCase):
  def test_simplification_is_measured(self):
    result = ph.normalize_result(120, 93, "opt", ["-O2"], True)
    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["reduction"], 0.225)

  def test_an_empty_output_is_an_invalid_test_not_a_perfect_reduction(self):
    # A v03 -fwhole-program attempt discarded the unreferenced recovered
    # function. That must never score as a 100% simplification.
    result = ph.normalize_result(120, 0, "gcc", ["-O3", "-fwhole-program"], False)
    self.assertEqual(result["status"], "failed")
    self.assertEqual(result["reason"], "empty-normalizer-output")
    self.assertIsNone(result["instructions_after"])

  def test_a_missing_denominator_is_null_not_zero(self):
    result = ph.normalize_result(0, 40, "opt", ["-O2"], True)
    self.assertIsNone(result["instructions_before"])

  def test_instruction_counting_over_a_textual_module(self):
    module = ("define internal i32 @f(i32 %0) {\n"
              "entry:\n"
              "  %1 = add i32 %0, 1\n"
              "  ; a comment\n"
              "  ret i32 %1\n"
              "}\n")
    self.assertEqual(es.count_instructions(module, "f"), (2, True))
    self.assertEqual(es.count_instructions(module, "g"), (0, False))


class ImmutableDataTest(unittest.TestCase):
  """A tiny synthetic ELF64, so immutability is read, never assumed."""

  def _elf(self, path):
    names = b"\x00.shstrtab\x00.rodata\x00.data\x00"
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2
    payload_offset = 64
    rodata = bytes(range(8))
    data = b"\xaa\xbb\xcc\xdd"
    body = rodata + data + names
    strtab_offset = payload_offset + len(rodata) + len(data)
    sections = [
        # Section 0 doubles as this fixture's section-name string table.
        (1, 3, 0, 0, strtab_offset, len(names)),
        (11, 1, 0x2, 0x400000, payload_offset, len(rodata)),          # .rodata, read-only
        (19, 1, 0x3, 0x500000, payload_offset + len(rodata), len(data)),  # .data, writable
    ]
    struct.pack_into("<Q", header, 0x28, payload_offset + len(body))
    struct.pack_into("<HHH", header, 0x3A, 64, 3, 0)
    # An ELF64 section header is 64 bytes; the parser reads the leading 40.
    table = b"".join(struct.pack("<IIQQQQ", *s) + bytes(24) for s in sections)
    path.write_bytes(bytes(header) + body + table)

  def test_read_only_backing_is_immutable_and_writable_backing_is_not(self):
    with tempfile.TemporaryDirectory() as tmp:
      target = Path(tmp) / "fixture.elf"
      self._elf(target)
      result = ph.recover_immutable_data(target, [
          {"name": "table", "address": 0x400000, "bytes": 8},
          {"name": "seed", "address": 0x500000, "bytes": 4}])
      self.assertEqual(result["status"], "ok")
      by_name = {item["name"]: item for item in result["items"]}
      self.assertTrue(by_name["table"]["immutable"])
      self.assertEqual(by_name["table"]["values"], list(range(8)))
      self.assertFalse(by_name["seed"]["immutable"])

  def test_an_address_outside_every_section_is_a_boundary(self):
    with tempfile.TemporaryDirectory() as tmp:
      target = Path(tmp) / "fixture.elf"
      self._elf(target)
      result = ph.recover_immutable_data(target, [
          {"name": "nowhere", "address": 0x900000, "bytes": 4}])
      self.assertEqual(result["reason"], "address-exposure")
      self.assertEqual(result["unresolved"], 1)

  def test_a_non_elf_input_is_inconclusive_not_a_crash(self):
    with tempfile.TemporaryDirectory() as tmp:
      target = Path(tmp) / "not.elf"
      target.write_bytes(b"not an elf at all")
      result = ph.recover_immutable_data(target, [{"name": "x", "address": 0, "bytes": 1}])
      self.assertEqual(result["status"], "inconclusive")
      self.assertEqual(result["reason"], "tool-error")


class ReportTest(unittest.TestCase):
  def test_region_status_follows_the_worst_phase(self):
    ok = [ph.phase("lift", "ok"), ph.phase("fit", "ok")]
    self.assertEqual(ph.region_report("r", "supplied-region", ok)["status"], "recovered")

    weak = ok + [ph.phase("test", "inconclusive", "solver-unknown")]
    self.assertEqual(ph.region_report("r", "supplied-region", weak)["status"], "inconclusive")

    broken = weak + [ph.phase("normalize", "failed", "empty-normalizer-output")]
    self.assertEqual(ph.region_report("r", "supplied-region", broken)["status"], "failed")

  def test_a_skipped_phase_does_not_demote_a_region(self):
    rows = [ph.phase("lift", "ok"), ph.phase("normalize", "skipped", "not-attempted")]
    self.assertEqual(ph.region_report("r", "supplied-region", rows)["status"], "recovered")

  def test_adapter_report_counts_and_disclaims(self):
    regions = [ph.region_report("a", "supplied-region", [ph.phase("lift", "ok")]),
               ph.region_report("b", "supplied-region",
                                [ph.phase("lift", "inconclusive", "budget-exhausted")])]
    report = ph.adapter_report("supplied-region", regions)
    self.assertEqual(report["schema"], "sre-extract-v1")
    self.assertEqual((report["regions_total"], report["regions_recovered"]), (2, 1))
    self.assertIn("not a hardness claim", report["interpretation"])


class SuppliedSpecTest(unittest.TestCase):
  def _spec(self, **region):
    base = {"region": "r", "entry": "0x1000", "interface": {"abi": "int-words",
                                                            "params": [{"name": "x"}]}}
    base.update(region)
    return {"schema": es.SPEC_SCHEMA,
            "targets": [{"name": "t", "binary": "/dev/null", "regions": [base]}]}

  def test_a_valid_spec_passes(self):
    self.assertTrue(es.validate(self._spec()))

  def test_the_control_refuses_to_locate_a_region_itself(self):
    spec = self._spec()
    del spec["targets"][0]["regions"][0]["entry"]
    with self.assertRaises(ValueError):
      es.validate(spec)

  def test_a_missing_interface_is_rejected(self):
    spec = self._spec()
    del spec["targets"][0]["regions"][0]["interface"]
    with self.assertRaises(ValueError):
      es.validate(spec)

  def test_an_absent_interface_must_say_why(self):
    with self.assertRaises(ValueError):
      es.validate(self._spec(entry=None))
    self.assertTrue(es.validate(self._spec(entry=None, absent_reason="interface-mismatch")))

  def test_a_foreign_schema_is_rejected(self):
    spec = self._spec()
    spec["schema"] = "something-else"
    with self.assertRaises(ValueError):
      es.validate(spec)


if __name__ == "__main__":
  unittest.main()
