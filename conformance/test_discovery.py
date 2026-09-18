"""Tests for the binary discovery adapter and the validated-outcome selection metric.

The ELF fixtures are synthesized here rather than compiled, so these run without
a toolchain and cannot drift with a compiler version. The adapter was separately
exercised against real statically linked, stripped binaries; that evidence is in
the agent report, not in this suite.
"""
import contextlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from conformance import recovery
from conformance.extract_discovery import (Boundary, Image, discover, protocol_spec,
                                           startup_main, unwind_functions)

@contextlib.contextmanager
def _temporary(data: bytes):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "binary"
        path.write_bytes(data)
        yield path


@contextlib.contextmanager
def _temporary_json(value):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "protocol.json"
        path.write_text(json.dumps(value))
        yield path


CODE_VA, CODE_OFF = 0x401000, 0x1000
RO_VA, RO_OFF = 0x500000, 0x3000
START, MAIN, TARGET, SHARED, LIBC = 0x401000, 0x401100, 0x401200, 0x401300, 0x401400
NOISE = 0x401500
TEXT = b"%u %u\x00result: %u\n\x00"
SPEC = {"schema": "sre-discovery-protocol-v1", "tokens": ["%u %u"], "arity": 2, "width": 32}


def call(site, target):
    return b"\xe8" + struct.pack("<i", target - (site + 5))


def code(startup=True):
    """A miniature program: a startup stub, main, a target and a shared helper."""
    blob = bytearray(b"\x90" * 0x600)

    def put(addr, payload):
        blob[addr - CODE_VA:addr - CODE_VA + len(payload)] = payload

    stub = b"\x31\xed" + (b"\x48\xc7\xc7" + struct.pack("<I", MAIN) if startup else b"")
    put(START, stub + call(START + len(stub), LIBC))
    body = b"\x48\x8d\x3d" + struct.pack("<i", RO_VA - (MAIN + 7))
    body += call(MAIN + len(body), TARGET)
    body += call(MAIN + len(body), SHARED)
    put(MAIN, body)
    put(TARGET, call(TARGET, SHARED))
    put(SHARED, b"\xc3")
    for i in range(6):
        put(NOISE + i * 0x10, call(NOISE + i * 0x10, SHARED))
    return bytes(blob)


def cie():
    body = b"\x01zR\x00\x01\x78\x10\x01\x1b"
    body += b"\x00" * (-(len(body) + 8) % 4)
    return struct.pack("<II", len(body) + 4, 0) + body


def fde(cie_at, at, function, size):
    body = struct.pack("<ii", function - (at + 8), size) + b"\x00"
    body += b"\x00" * (-(len(body) + 8) % 4)
    return struct.pack("<II", len(body) + 4, at + 4 - cie_at) + body


def frames(at):
    blob, cursor = bytearray(cie()), at + len(cie())
    for function, size in ((START, 0x40), (MAIN, 0x60), (TARGET, 0x40),
                           (SHARED, 0x10), (LIBC, 0x10),
                           *[(NOISE + i * 0x10, 0x10) for i in range(6)]):
        entry = fde(at, cursor, function, size)
        blob += entry
        cursor += len(entry)
    return bytes(blob + b"\x00\x00\x00\x00")


def elf(*, startup=True, unwind=True, eh_frame_hdr=False):
    segments = [(1, 5, CODE_OFF, CODE_VA), (1, 4, RO_OFF, RO_VA)]
    rodata = bytearray(TEXT)
    frame_at = RO_VA + 0x100
    if unwind:
        rodata += b"\x00" * (0x100 - len(rodata)) + frames(frame_at)
    header = struct.pack("<4sBBBBB7xHHIQQQIHHHHHH", b"\x7fELF", 2, 1, 1, 0, 0,
                         2, 0x3E, 1, START, 64, 0, 0, 64, 56, len(segments) + eh_frame_hdr,
                         64, 0, 0)
    hdr_va, hdr_off = RO_VA + 0x80, RO_OFF + 0x80
    if eh_frame_hdr:
        segments.append((0x6474E550, 4, hdr_off, hdr_va))
        table = b"\x01\x1b\x03\x3b" + struct.pack("<i", frame_at - (hdr_va + 4))
        rodata[0x80:0x80 + len(table)] = table
    phdrs = b"".join(struct.pack("<IIQQQQQQ", kind, flags, off, va, va, 0x800, 0x800, 0x1000)
                     for kind, flags, off, va in segments)
    data = bytearray(header + phdrs)
    data += b"\x00" * (CODE_OFF - len(data))
    data += code(startup)
    data += b"\x00" * (RO_OFF - len(data))
    data += rodata
    return bytes(data)


class ImageTests(unittest.TestCase):
    def test_a_non_elf_input_is_a_reported_boundary(self):
        with self.assertRaises(Boundary) as caught:
            Image(b"MZ" + b"\x00" * 200)
        self.assertEqual(caught.exception.reason, "not-elf64-little-endian")

    def test_unwind_functions_are_recovered_from_both_frame_sources(self):
        for hdr, source in ((False, "scanned-cie"), (True, "pt-gnu-eh-frame")):
            functions, used = unwind_functions(Image(elf(eh_frame_hdr=hdr)))
            self.assertEqual(used, source)
            self.assertEqual([f["start"] for f in functions][:5],
                             [START, MAIN, TARGET, SHARED, LIBC])

    def test_missing_unwind_information_is_a_boundary_not_an_empty_answer(self):
        with self.assertRaises(Boundary) as caught:
            unwind_functions(Image(elf(unwind=False)))
        self.assertEqual(caught.exception.reason, "no-unwind-information")

    def test_startup_decode_finds_main_and_is_confirmed_by_the_frame_table(self):
        image = Image(elf())
        functions, _ = unwind_functions(image)
        found = startup_main(image, functions)
        self.assertEqual(found["address"], MAIN)
        self.assertTrue(found["confirmed_by_unwind"])

    def test_startup_pattern_absent_is_a_boundary(self):
        image = Image(elf(startup=False))
        with self.assertRaises(Boundary) as caught:
            startup_main(image, unwind_functions(image)[0])
        self.assertEqual(caught.exception.reason, "startup-pattern-not-matched")


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.binary = self.enterContext(_temporary(elf()))

    def test_the_called_application_region_is_ranked_first(self):
        ranked, phases, anchor = discover(self.binary, SPEC)
        self.assertEqual(anchor, MAIN)
        self.assertEqual([p["status"] for p in phases], ["ok"] * 6)
        self.assertEqual(ranked[0]["address"], TARGET)
        self.assertEqual(ranked[0]["callers"], 1)
        # The helper every other function calls is ranked below it.
        shared = next(r for r in ranked if r["address"] == SHARED)
        self.assertGreater(shared["callers"], ranked[0]["callers"])

    def test_protocol_cross_reference_confirms_the_startup_anchor(self):
        _, phases, _ = discover(self.binary, SPEC)
        xrefs = next(p for p in phases if p["phase"] == "xrefs")
        self.assertTrue(xrefs["anchor_agrees"])
        self.assertGreaterEqual(xrefs["references"], 1)

    def test_a_protocol_reference_anchors_discovery_when_the_stub_does_not_decode(self):
        with _temporary(elf(startup=False)) as binary:
            ranked, phases, anchor = discover(binary, SPEC)
        self.assertEqual(anchor, MAIN)
        self.assertEqual(next(p for p in phases if p["phase"] == "startup")["reason"],
                         "startup-pattern-not-matched")
        self.assertEqual(next(p for p in phases if p["phase"] == "xrefs")["anchor"],
                         "protocol-reference-fallback")
        self.assertEqual(ranked[0]["address"], TARGET)

    def test_discovery_without_unwind_information_reports_a_reason_and_no_candidates(self):
        with _temporary(elf(unwind=False)) as binary:
            ranked, phases, anchor = discover(binary, SPEC)
        self.assertEqual((ranked, anchor), ([], None))
        self.assertIn("unwind:no-unwind-information", recovery.costs(phases)["boundaries"])

    def test_discovery_cost_is_accounted_separately_from_mechanism_cost(self):
        _, phases, _ = discover(self.binary, SPEC)
        cost = recovery.costs(phases)
        self.assertEqual(cost["discovery_phases"], 6)
        self.assertEqual(cost["mechanism_phases"], 0)
        self.assertEqual(cost["repair_phases"], 0)
        self.assertGreaterEqual(cost["discovery_seconds"], 0)
        # A class nothing ran is null, never a zero that reads as "nothing to do".
        self.assertIsNone(cost["mechanism_seconds"])
        self.assertIsNone(cost["repair_steps"])


class ProtocolTests(unittest.TestCase):
    def test_a_protocol_carrying_private_provenance_is_refused(self):
        for spec in ({"schema": "sre-discovery-protocol-v1", "entry": 4198400},
                     {"schema": "sre-discovery-protocol-v1", "tokens": ["0x401970"]},
                     {"schema": "sre-discovery-protocol-v1", "tokens": ["4200816"]}):
            with _temporary_json(spec) as path, self.assertRaises(Boundary) as caught:
                protocol_spec(path)
            self.assertEqual(caught.exception.reason, "protocol-contains-private-provenance")

    def test_a_public_protocol_is_accepted(self):
        with _temporary_json(SPEC) as path:
            self.assertEqual(protocol_spec(path)["tokens"], ["%u %u"])


class ModelTests(unittest.TestCase):
    WIDTH = 32
    XS = (0, 1, 2, 7, 31, 32, 255, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x55555555, 12345)

    def sites(self, function, ys):
        return [{"name": f"y={y}", "observations": [[[x, y], function(x, y)] for x in self.XS]}
                for y in ys]

    def constructed(self, function, y):
        return [((x, y), function(x, y)) for x in (3, 4, 5, 6, 9, 11)]

    def test_a_relation_that_holds_at_every_site_is_accepted(self):
        f = lambda x, y: (x ^ y ^ 0x9E3779B9) & 0xFFFFFFFF
        positives = self.constructed(f, 0x0BADC0DE)
        result = recovery.summarize(self.sites(f, (0, 1, 0xDEADBEEF)), self.WIDTH,
                                    positives=positives,
                                    negatives=recovery.constructed_negatives(positives))
        self.assertEqual(result["status"], "summarized")
        self.assertEqual(result["best"]["model"]["family"], "xor_join")
        self.assertEqual(result["best"]["verification"], "constructed")
        self.assertEqual(result["best"]["sites_predicted"], 3)

    def test_a_model_that_predicts_only_its_own_site_is_not_a_summary(self):
        f = lambda x, y: (x ^ y ^ 0x9E3779B9) & 0xFFFFFFFF
        other = {"name": "unrelated", "observations": [[[x, 1], (x * 7) & 0xFFFFFFFF] for x in self.XS]}
        positives = [((x, 0), f(x, 0)) for x in (3, 4, 5)]
        result = recovery.summarize([self.sites(f, (0,))[0], other], self.WIDTH,
                                    positives=positives,
                                    negatives=recovery.constructed_negatives(positives))
        self.assertFalse(result["validated"])
        self.assertEqual(result["reason"], "predicts-fewer-than-two-sites")

    def test_a_table_memorized_at_one_site_is_rejected_but_a_shared_one_is_not(self):
        table = {3: 0x11, 4: 0x99, 5: 0x07, 6: 0x08, 9: 0x21, 11: 0x42}
        alone = [{"name": "a", "observations": [[[k], v] for k, v in table.items()]}]
        positives = [((3,), 0x11)]
        lonely = recovery.summarize(alone * 1 + [{"name": "b", "observations":
                                    [[[k], v + 1] for k, v in table.items()]}], self.WIDTH,
                                    positives=positives, negatives=[((3,), 0x12)])
        self.assertFalse(lonely["validated"])
        shared = recovery.summarize([{"name": n, "observations": [[[k], v] for k, v in table.items()]}
                                     for n in ("a", "b", "c")], self.WIDTH,
                                    positives=positives, negatives=[((3,), 0x12)])
        self.assertTrue(shared["validated"])
        self.assertTrue(shared["best"]["falsifiable"])

    def test_sampled_agreement_alone_never_validates(self):
        f = lambda x, y: (x ^ y ^ 5) & 0xFFFFFFFF
        result = recovery.summarize(self.sites(f, (0, 1)), self.WIDTH, sampled=True)
        self.assertFalse(result["validated"])
        self.assertEqual(result["reason"], "sampled-equality-only")

    def test_an_exhaustive_check_rejects_a_model_that_is_right_on_every_sample(self):
        truth = lambda x: (3 * x + 1) & 0xFF if x < 128 else (3 * x + 2) & 0xFF
        sites = [{"name": "low", "observations": [[[x], truth(x)] for x in range(0, 60)]},
                 {"name": "mid", "observations": [[[x], truth(x)] for x in range(60, 120)]}]
        positives = [((x,), truth(x)) for x in (121, 122, 123)]
        negatives = recovery.constructed_negatives(positives)
        without = recovery.summarize(sites, 8, positives=positives, negatives=negatives)
        self.assertTrue(without["validated"])
        with_oracle = recovery.summarize(sites, 8, positives=positives, negatives=negatives,
                                         oracle=lambda i: truth(i[0]),
                                         domain=[(i,) for i in range(256)])
        self.assertFalse(with_oracle["validated"])
        self.assertEqual(with_oracle["reason"], "counterexample-found")

    def test_a_negative_the_model_accepts_is_a_failed_validation(self):
        f = lambda x, y: (x + y + 9) & 0xFFFFFFFF
        positives = self.constructed(f, 4)
        outcome = recovery.summarize(self.sites(f, (0, 1)), self.WIDTH, positives=positives,
                                     negatives=[((3, 4), f(3, 4))])
        self.assertFalse(outcome["validated"])
        self.assertEqual(outcome["reason"], "negative-case-accepted")

    def test_families_round_trip_at_every_supported_width(self):
        for width in (8, 16, 32, 64):
            mask = (1 << width) - 1
            for family, params in (("xor_const", {"k": 0x5A & mask}),
                                   ("add_const", {"k": 7}), ("sub_const", {"k": 3}),
                                   ("rotl", {"r": width // 4}),
                                   ("affine", {"a": 0x9E3779B1 & mask | 1, "b": 11}),
                                   ("xor_join", {"k": 0x1F}), ("sum_join", {"k": 2}),
                                   ("difference", {"k": 5}),
                                   ("affine_join", {"a": 3, "b": 5, "k": 7})):
                model = {"family": family, "params": params, "width": width,
                         "arity": 2 if "join" in family or family == "difference" else 1}
                # A two-dimensional grid: y must not be an affine image of x, or
                # the two-input coefficients are genuinely unidentifiable.
                points = [(a & mask, b & mask) for a in (0, 1, 2, 3, 5, 8, 13, mask)
                          for b in (0, 1, 7, mask >> 1)]
                site = {"name": "s", "observations": [[[a, b], recovery.predict(model, (a, b))]
                                                      for a, b in points]}
                self.assertIn(family, [m["family"] for m in recovery.fit(site, width)])


class NormalizationTests(unittest.TestCase):
    BEFORE = "unsigned f(unsigned x){ return x ^ 3; }\n"

    def test_an_optimizer_that_discarded_the_function_is_an_invalid_test(self):
        result = recovery.normalization(self.BEFORE, "/* nothing survived */\n", "f")
        self.assertEqual(result["status"], "invalid_test")
        self.assertEqual(result["reason"], "optimizer-discarded-function")
        self.assertFalse(result["kept_function"])

    def test_empty_optimizer_output_is_never_evidence_of_simplification(self):
        for text in ("", "   \n"):
            result = recovery.normalization(self.BEFORE, text, "f")
            self.assertEqual(result["status"], "invalid_test")
            self.assertEqual(result["reason"], "empty-optimizer-output")

    def test_a_smaller_surviving_function_is_recorded_as_simplified(self):
        result = recovery.normalization(self.BEFORE, "unsigned f(unsigned x){return x^3;}\n", "f")
        self.assertEqual(result["status"], "simplified")
        self.assertLess(result["ratio"], 1)

    def test_decompiled_pseudocode_is_never_assumed_equivalent(self):
        record = recovery.pseudocode(["ghidra-type-repair", "upper-bit-reconstruction"])
        self.assertIsNone(record["equivalent"])
        self.assertEqual(record["repair_count"], 2)
        self.assertEqual(recovery.pseudocode([], "differential")["equivalent"], True)
        with self.assertRaises(ValueError):
            recovery.pseudocode([], "assumed")


def _row(candidate="a", *, status="recovered", control="recovered", growth=2, runtime=1,
         summarized=False, mechanism=10, repair=0, discovery=0, ast=12, steps=7):
    native = {"status": status, "ast_nodes": ast, "steps": steps,
              "cost": {"mechanism_steps": mechanism, "repair_steps": repair,
                       "discovery_steps": discovery}}
    if status in ("recovered", "lifted_large"):
        native["summary"] = {"validated": summarized,
                             "reason": None if summarized else "no-family-fits"}
    return {"candidate": candidate, "native": native, "control": {"status": control},
            "growth": growth, "runtime_ratio": runtime}


class SelectionTests(unittest.TestCase):
    def test_blocked_attacks_are_reported_and_never_ranked(self):
        for row, reason in ((_row(status="budget"), "attack-blocked:time-step-or-path-cap"),
                            (_row(status="inconclusive"), "attack-blocked:inconclusive"),
                            (_row(control="budget"), "clean-control-not-recovered"),
                            (_row(growth=9), "growth-budget-exceeded"),
                            (_row(runtime=17), "runtime-budget-exceeded")):
            if row["native"]["status"] == "budget":
                row["native"]["reason"] = "time-step-or-path-cap"
            ranked, blocked = recovery.choose([row], 8)
            self.assertEqual(ranked, [])
            self.assertEqual(blocked[0]["reasons"], [reason])

    def test_a_missing_runtime_ratio_is_never_read_as_a_pass(self):
        ranked, blocked = recovery.choose([{**_row(), "runtime_ratio": None}], 8)
        self.assertEqual(ranked, [])
        self.assertEqual(blocked[0]["reasons"], ["runtime-ratio-unavailable"])

    def test_a_lifted_candidate_outranks_a_fully_summarized_one(self):
        rows = [_row("lifted-only", mechanism=5), _row("summarized", summarized=True, mechanism=500)]
        ranked, blocked = recovery.choose(rows, 8)
        self.assertEqual(blocked, [])
        self.assertEqual([r["candidate"] for r in ranked], ["lifted-only", "summarized"])
        self.assertEqual(ranked[0]["attack_level"], "lifted")

    def test_measured_cost_orders_candidates_at_the_same_level(self):
        rows = [_row("cheap", mechanism=10), _row("dear", mechanism=40, repair=5)]
        ranked, _ = recovery.choose(rows, 8)
        self.assertEqual([r["candidate"] for r in ranked], ["dear", "cheap"])
        self.assertEqual(ranked[0]["cost"], 45)

    def test_discovery_cost_is_reported_but_cannot_buy_a_better_rank(self):
        rows = [_row("hidden", mechanism=10, discovery=10_000), _row("plain", mechanism=10)]
        ranked, _ = recovery.choose(rows, 8)
        self.assertEqual([r["cost"] for r in ranked], [10, 10])
        self.assertEqual({r["candidate"]: r["discovery_cost"] for r in ranked},
                         {"hidden": 10_000, "plain": 0})
        self.assertEqual([r["candidate"] for r in ranked], ["hidden", "plain"])

    def test_the_historical_ablation_is_retained_and_can_disagree(self):
        rows = [_row("big-ast", ast=900, steps=100, mechanism=10, summarized=True),
                _row("costly", ast=10, steps=5, mechanism=400)]
        ranked, _ = recovery.choose(rows, 8)
        ablation = recovery.choose_ast_ablation(rows, 8)
        self.assertEqual(ranked[0]["candidate"], "costly")
        self.assertEqual(ablation[0]["candidate"], "big-ast")
        self.assertEqual(ablation[0]["score"], 1000)
        self.assertIn("historical ablation", ablation[0]["metric"])

    def test_the_ablation_still_refuses_broken_controls(self):
        self.assertEqual(recovery.choose_ast_ablation([_row(control="budget")], 8), [])
        self.assertEqual(recovery.choose_ast_ablation([_row(status="budget")], 8), [])

    def test_a_probe_result_without_sites_is_not_summarized(self):
        self.assertEqual(recovery.probe_summary({"status": "recovered"})["reason"],
                         "probe-emitted-fewer-than-two-sites")


class PhaseTests(unittest.TestCase):
    def test_phase_names_and_cost_classes_are_closed_vocabularies(self):
        with self.assertRaises(ValueError):
            recovery.phase("guess", "discovery", 1, "ok")
        with self.assertRaises(ValueError):
            recovery.phase("lift", "wallclock", 1, "ok")
        with self.assertRaises(ValueError):
            recovery.phase("lift", "discovery", 1, "boundary")

    def test_costs_keep_the_three_classes_apart(self):
        phases = [recovery.phase("lift", "discovery", 1.5, "ok", steps=3),
                  recovery.phase("normalize", "repair", 2.0, "ok", steps=4),
                  recovery.phase("probe", "mechanism", 4.0, "boundary", "budget", steps=9)]
        cost = recovery.costs(phases)
        self.assertEqual(cost["discovery_steps"], 3)
        self.assertEqual(cost["repair_seconds"], 2.0)
        self.assertEqual(cost["mechanism_steps"], 9)
        self.assertEqual(cost["boundaries"], ["probe:budget"])


if __name__ == "__main__":
    unittest.main()
