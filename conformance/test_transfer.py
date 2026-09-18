"""Unit gate for the v04 W1 candidate transfer families.

Everything here runs without a solver. Complete small domains are enumerated
where they are affordable, which is the strongest statement available offline;
`conformance/connected_proof.py` states the same laws as bounded QF_BV queries
at 8/16/32/64 and records an unknown as unknown.

Negative results are asserted, not described. If a fitting attack recovers a
family, the test says so, so that the attack failing later is a regression and
the family cannot quietly be promoted.
"""
import unittest

from conformance import transfer_model as tm
from conformance.connected_model import (xor_to_additive, xor_to_additive_grouped,
                                         affine_mul_grouped)

SMALL = 2      # complete domains are enumerated at this width
IR = 8         # the smallest homogeneous vector width W1 starts from


def nlcarry(width=IR, seed=11, lanes=3, kernel="arx"):
  return tm.NlCarry(width, seed, lanes=lanes, kernel=kernel)


class PrimitiveTests(unittest.TestCase):
  """Explicit bit-vector semantics, including what must be refused."""

  def test_rotation_matches_the_bit_index_definition(self):
    for width in (1, 2, 4, 8, 16):
      for amount in range(width):
        program = tm.Program("rot", width, ("x",))
        tm.rotl(program.input("x"), amount, width)
        backend = tm.Concrete(width)
        last = program.steps[-1][0] if program.steps else "x"
        for value in range(1 << width):
          got = tm.evaluate(program, {"x": value}, backend)[last]
          self.assertEqual(got, tm.ref_rotl(value, amount, width),
                           f"width {width} amount {amount} value {value}")

  def test_zero_rotation_emits_nothing(self):
    program = tm.Program("rot", 8, ("x",))
    self.assertIs(tm.rotl(program.input("x"), 0, 8), program.input("x"))
    self.assertEqual(program.size, 0)

  def test_out_of_range_shift_is_refused_not_modelled(self):
    program = tm.Program("shift", 8, ("x",))
    with self.assertRaises(ValueError): program.input("x") << 8
    with self.assertRaises(ValueError): program.input("x").lshr(8)
    with self.assertRaises(ValueError): program.input("x") << -1
    for backend in (tm.Concrete(8),):
      with self.assertRaises(ValueError): backend.shl(1, 8)
      with self.assertRaises(ValueError): backend.lshr(1, 8)

  def test_width_one_has_no_legal_shift_so_doubling_is_an_addition(self):
    program = tm.Program("double", 1, ("x",))
    with self.assertRaises(ValueError): program.input("x") << 1
    doubled = tm.double(program.input("x"))
    self.assertEqual(program.steps[-1][1], "add")
    backend = tm.Concrete(1)
    for value in (0, 1):
      self.assertEqual(tm.evaluate(program, {"x": value}, backend)[doubled.name],
                       tm.ref_double(value, 1))

  def test_doubling_is_an_addition_at_every_width(self):
    for width in tm.WIDTHS:
      program = tm.Program("double", width, ("x",))
      doubled = tm.double(program.input("x"))
      self.assertNotIn("shl", [op for _, op, _ in program.steps])
      backend = tm.Concrete(width)
      for value in (0, 1, (1 << width) - 1, 1 << (width - 1)):
        self.assertEqual(tm.evaluate(program, {"x": value}, backend)[doubled.name],
                         tm.ref_double(value, width))

  def test_evaluate_rejects_unbound_inputs_and_width_mismatch(self):
    program = tm.Program("p", 8, ("x", "y"))
    program.input("x") ^ program.input("y")
    with self.assertRaises(KeyError): tm.evaluate(program, {"x": 1}, tm.Concrete(8))
    with self.assertRaises(ValueError):
      tm.evaluate(program, {"x": 1, "y": 2}, tm.Concrete(16))

  def test_unsupported_width_is_refused(self):
    with self.assertRaises(ValueError): tm.Program("p", 7, ())
    with self.assertRaises(ValueError): tm.XorPair(7, 1)


class NetworkTests(unittest.TestCase):
  """The seeded reversible network: a bijection with an exact inverse."""

  def test_inverse_is_exact_on_a_complete_domain(self):
    for width in (2, 4):
      for pattern in ("random", "mixer"):
        net = tm.ArxNetwork(width, 5, words=2, rounds=3, pattern=pattern)
        span = range(1 << width)
        seen = set()
        for a in span:
          for b in span:
            mixed = net.ref_apply([a, b])
            seen.add(tuple(mixed))
            self.assertEqual(net.ref_invert(mixed), [a, b])
        self.assertEqual(len(seen), (1 << width) ** 2, "not a bijection")

  def test_traced_program_agrees_with_the_independent_reference(self):
    width = 4
    net = tm.ArxNetwork(width, 5, words=2, rounds=3, pattern="mixer")
    program = tm.Program("net", width, ("a", "b"))
    out = net.apply([program.input("a"), program.input("b")])
    backend = tm.Concrete(width)
    for a in range(1 << width):
      for b in range(1 << width):
        values = tm.evaluate(program, {"a": a, "b": b}, backend)
        got = [values[node.name] if isinstance(node, tm.Node) else node for node in out]
        self.assertEqual(got, net.ref_apply([a, b]))

  def test_preconditions_are_enforced(self):
    with self.assertRaises(ValueError):
      tm.ArxNetwork(8, 1, words=3, pattern="mixer")
    with self.assertRaises(ValueError): tm.inverse_odd(4, 8)
    self.assertEqual(tm.inverse_odd(3, 8) * 3 % 256, 1)


class EncodingLawTests(unittest.TestCase):
  """Every family: exact inverse, and a state space that is entirely reachable."""

  def families(self, width):
    out = [tm.XorPair(width, 5, lanes=2), tm.AdditivePair(width, 5, lanes=2),
           tm.UnimodularPair(width, 5), tm.BitslicePermutation(width, 5, lanes=2),
           tm.ArxValue(width, 3, lanes=2), tm.TriCouple(width, 7)]
    out += [tm.NlCarry(width, 11, lanes=2, kernel=k) for k in tm.NlCarry.KERNELS]
    return out

  def test_inverse_is_exact_on_a_complete_domain(self):
    for site in self.families(SMALL):
      with self.subTest(site.identifier):
        self.assertTrue(tm.check_inverse(site, complete=True)["passed"])

  def test_encoding_is_a_bijection_so_every_state_is_reachable(self):
    for site in self.families(SMALL):
      with self.subTest(site.identifier):
        self.assertTrue(site.encode_is_bijective())

  def test_inverse_holds_at_the_ir_widths(self):
    for width in (8, 16, 32, 64):
      for site in self.families(width):
        with self.subTest(f"{site.identifier}-{width}"):
          self.assertTrue(tm.check_inverse(site, trials=150)["passed"])


class TransferLawTests(unittest.TestCase):
  """decode(transfer(Z)) == F(decode(Z)), against an independent reference."""

  def test_every_transfer_holds_on_a_complete_domain(self):
    for site in (tm.NlCarry(SMALL, 11, lanes=2, kernel="and"), tm.TriCouple(SMALL, 7)):
      for name in site.transfer_names():
        try:
          transfer = site.build(name)
        except ValueError:
          continue
        with self.subTest(transfer.identifier):
          report = tm.check_laws(transfer, complete=True)
          self.assertTrue(report["passed"], report)
          self.assertEqual(report["points"], site.domain_size())

  def test_every_transfer_holds_at_the_ir_widths(self):
    for width in (8, 32):
      for site in (nlcarry(width), tm.TriCouple(width, 7),
                   tm.ArxValue(width, 3, lanes=2)):
        for name in site.transfer_names():
          transfer = site.build(name)
          with self.subTest(f"{transfer.identifier}-{width}"):
            self.assertTrue(tm.check_laws(transfer, trials=120)["passed"])

  def test_shifts_at_zero_and_at_width_minus_one(self):
    """Gate 7A asks for both ends explicitly; both are in range, and a shift by
    the width itself is not and must be refused."""
    for width in (8, 32, 64):
      site = nlcarry(width)
      for amount in (0, 1, width - 1):
        transfer = site.build("shl", amount=amount)
        with self.subTest(f"shl-{width}-{amount}"):
          self.assertTrue(tm.check_laws(transfer, trials=120)["passed"])
        transfer = site.build("lshr", amount=amount)
        with self.subTest(f"lshr-{width}-{amount}"):
          self.assertTrue(tm.check_laws(transfer, trials=120)["passed"])
      with self.assertRaises(ValueError): site.build("shl", amount=width)

  def test_a_zero_shift_emits_no_instruction(self):
    site = nlcarry()
    self.assertLess(len(tm.live_steps(site.build("shl", amount=0))),
                    len(tm.live_steps(site.build("shl", amount=1))))

  def test_constructed_boundary_cases_are_included(self):
    site = nlcarry()
    points = tm.constructed_points(site)
    values = {v for lanes, _ in points for v in lanes}
    for edge in (0, 1, site.mask, 1 << (site.width - 1)):
      self.assertIn(edge, values)
    self.assertTrue(any(len(set(lanes)) == 1 for lanes, _ in points), "no all-equal case")
    self.assertTrue(any(len(set(lanes)) > 1 for lanes, _ in points), "no all-different case")

  def test_a_corrupted_constant_is_caught_so_the_law_test_has_teeth(self):
    for name in ("add", "combined", "mul", "cmp_ult"):
      transfer = nlcarry().build(name)
      with self.subTest(name):
        report = tm.mutate_counterexample(transfer)
        self.assertGreater(report["effective"], 0, "no mutant changed the output")
        self.assertEqual(report["escaped"], [], report)
        self.assertTrue(report["caught"])

  def test_an_equivalent_mutant_is_excluded_rather_than_counted_as_an_escape(self):
    """Writing a result back onto one of its own operands cancels that carrier,
    so corrupting it really does leave the transfer unchanged."""
    report = tm.mutate_counterexample(nlcarry().build("xor"), attempts=8)
    self.assertGreater(report["equivalent"], 0)
    self.assertEqual(report["escaped"], [])

  def test_predicates_stay_in_their_own_representation(self):
    site = nlcarry(lanes=2)
    for name in ("cmp_ult", "cmp_eq", "cmp_slt"):
      transfer = site.build(name)
      with self.subTest(name):
        self.assertEqual(transfer.kind, "predicate")
        self.assertEqual(transfer.outputs, {})
        report = tm.check_laws(transfer, trials=200)
        self.assertTrue(report["passed"], report)
        backend = tm.Concrete(site.width)
        for lanes in ([0, 0], [0, site.mask], [site.mask, 0],
                      [1 << (site.width - 1), (1 << (site.width - 1)) - 1]):
          state = site.reference_encode(lanes, [3, 5])
          _, value = transfer.run(state, backend)
          self.assertIn(value, (0, 1))


class AbstractCarrierTests(unittest.TestCase):
  """Uninterpreted carriers: one proof that covers every kernel."""

  def test_laws_hold_with_free_carriers_at_every_ir_width(self):
    for width in (8, 16, 32, 64):
      site = tm.NlCarryAbstract(width, 11, lanes=3, kernel="and")
      for name in site.transfer_names():
        transfer = site.build(name)
        with self.subTest(f"{name}-{width}"):
          self.assertTrue(tm.check_laws(transfer, trials=120)["passed"])

  def test_free_carriers_agree_with_every_concrete_kernel(self):
    """The abstract law is the concrete one with the kernel substituted in."""
    for kernel in tm.NlCarry.KERNELS:
      concrete = tm.NlCarry(IR, 11, lanes=3, kernel=kernel)
      abstract = tm.NlCarryAbstract(IR, 11, lanes=3, kernel=kernel)
      backend = tm.Concrete(IR)
      for name in ("xor", "add", "combined"):
        with self.subTest(f"{kernel}-{name}"):
          left, right = concrete.build(name), abstract.build(name)
          for lanes, masks in ([[1, 2, 3], [7, 9]], [[0, 255, 128], [255, 1]]):
            carriers = [concrete.carrier(masks[0], masks[1], i, reference=True)
                        for i in range(concrete.carriers)]
            a = left.run(concrete.reference_encode(lanes, masks), backend)[1]
            b = right.run(abstract.reference_encode(lanes, carriers), backend)[1]
            self.assertEqual([a[f"e{i}"] for i in range(3)],
                             [b[f"e{i}"] for i in range(3)])

  def test_the_abstract_variant_states_what_it_does_not_cover(self):
    site = tm.NlCarryAbstract(IR, 11, lanes=2)
    self.assertIn("excludes", site.preconditions())
    self.assertIn("not_applicable", site.distinct_carriers())


class RejectionTests(unittest.TestCase):
  """The plan forbids hiding one instruction between two recognizable inverses."""

  def review(self, transfer):
    return tm.review(transfer, repeats=4, extra=6, mask_points=12)

  def test_every_candidate_transfer_matches_its_declared_expectation(self):
    for site in (nlcarry(), tm.TriCouple(IR, 7), tm.ArxValue(IR, 3, lanes=2)):
      for name in site.transfer_names():
        transfer = site.build(name)
        with self.subTest(transfer.identifier):
          verdict = self.review(transfer)
          self.assertEqual(verdict["outcome"], transfer.expect, verdict["exposes"])

  def test_an_adjacent_decode_add_encode_wrapper_is_rejected(self):
    verdict = self.review(nlcarry().build("add_sandwich"))
    self.assertFalse(verdict["accepted"])
    self.assertTrue(set(verdict["exposes"]) & {"in0", "in1", "out0"}, verdict["exposes"])

  def test_the_same_function_is_accepted_when_it_is_grouped_correctly(self):
    site = nlcarry()
    good, bad = site.build("xor"), site.build("xor_sandwich")
    self.assertTrue(tm.check_laws(good, trials=120)["passed"])
    self.assertTrue(tm.check_laws(bad, trials=120)["passed"], "both compute the same value")
    self.assertTrue(self.review(good)["accepted"])
    self.assertFalse(self.review(bad)["accepted"])

  def test_the_v03_conversions_expose_the_plain_value_and_the_grouped_ones_do_not(self):
    """Recorded as a test because it is a defect in code that ships today."""
    site = nlcarry()
    self.assertFalse(self.review(site.build("mul_v03_refresh"))["accepted"])
    self.assertTrue(self.review(site.build("mul"))["accepted"])
    for width in (8, 16, 32):
      mask = (1 << width) - 1
      for x0, x1, refresh in ((3, 5, 9), (mask, 1, 7), (0, mask, mask)):
        with self.subTest(f"conversion-{width}"):
          self.assertEqual(xor_to_additive((x0, x1), refresh, width),
                           xor_to_additive_grouped((x0, x1), refresh, width))
      for a, r, b, s in ((7, 3, 11, 5), (mask, 1, 2, mask)):
        with self.subTest(f"product-{width}"):
          reference = ((a * b - (a * s + b * r) + r * s + (r ^ s)) & mask, r ^ s)
          self.assertEqual(affine_mul_grouped((a, r), (b, s), width), reference)

  def test_the_ablation_kernel_cannot_even_be_emitted_safely(self):
    """A GF(2)-affine carrier cancels inside the signed compare network, so the
    ablation is not merely attackable, it exposes a logical value."""
    site = tm.NlCarry(IR, 11, lanes=3, kernel="linear")
    self.assertFalse(self.review(site.build("cmp_slt"))["accepted"])

  def test_the_rejection_criterion_uses_the_live_slice(self):
    transfer = nlcarry().build("xor")
    live = tm.live_steps(transfer)
    self.assertLess(len(live), transfer.program.size, "carriers are traced eagerly")
    names = {step[0] for step in live}
    self.assertTrue(names.issuperset(set(transfer.outputs.values())))


class PreconditionTests(unittest.TestCase):
  """Boundaries are reported with a reason, never silently worked around."""

  def test_carriers_must_be_distinct_functions(self):
    for kernel in tm.NlCarry.KERNELS:
      for width, lanes in ((4, 2), (IR, 3), (16, 4), (32, 4), (64, 4)):
        site = tm.NlCarry(width, 11, lanes=lanes, kernel=kernel)
        with self.subTest(f"w{width}-{kernel}"):
          complete = width <= 4
          report = site.distinct_carriers(trials=256, complete=complete)
          self.assertTrue(report["passed"], report["clashes"])

  def test_tricouple_carriers_must_also_be_three_distinct_functions(self):
    for width in (4, IR, 32, 64):
      report = tm.TriCouple(width, 7).distinct_carriers(trials=128)
      with self.subTest(width):
        self.assertTrue(report["passed"], report["clashes"])

  def test_width_one_cannot_carry_a_data_bundle(self):
    """At width 1 every rotation is zero and every odd multiplier is one, so the
    carriers collapse. The family is simply unavailable there; i1 values belong
    to the separately typed predicate representation."""
    site = tm.NlCarry(1, 11, lanes=2, kernel="arx")
    report = site.distinct_carriers(complete=True)
    self.assertFalse(report["passed"])
    self.assertTrue(report["clashes"])

  def test_shift_transfers_are_unavailable_at_width_one_with_a_reason(self):
    site = tm.NlCarry(1, 11, lanes=2, kernel="and")
    for name in ("shl", "lshr"):
      with self.assertRaises(ValueError) as caught: site.build(name)
      self.assertIn("addition", str(caught.exception))
    record = tm.describe(site)
    self.assertIn("unavailable", record["transfers"]["shl"])

  def test_unimodular_control_mixes_exactly_two_lanes(self):
    with self.assertRaises(ValueError): tm.UnimodularPair(IR, 1, lanes=3)

  def test_the_combined_transfer_needs_three_lanes(self):
    with self.assertRaises(ValueError): tm.NlCarry(IR, 1, lanes=2).build("combined")


class CombinedTransferTests(unittest.TestCase):
  """A bounded transfer over a short sequence with several real outputs."""

  def test_the_combined_transfer_has_several_real_outputs(self):
    for site, count in ((nlcarry(lanes=3), 2), (tm.TriCouple(IR, 7), 2)):
      transfer = site.build("combined")
      with self.subTest(site.identifier):
        self.assertEqual(len(transfer.outputs), count)
        lanes = [1, 2, 3][:site.n]
        results = transfer.spec(lanes)
        self.assertEqual(len(results), count)
        self.assertTrue(tm.check_laws(transfer, trials=150)["passed"])
        self.assertTrue(tm.review(transfer, repeats=4, extra=6,
                                  mask_points=12)["accepted"])

  def test_the_combined_transfer_stays_bounded(self):
    transfer = nlcarry(lanes=3).build("combined")
    self.assertLess(len(tm.live_steps(transfer)), 600)

  def test_bundling_amortizes_the_carrier_cost(self):
    """The quantitative case for a combined transfer: the carriers are
    recomputed once for four source operations instead of once each."""
    for width in (8, 32):
      record = tm.describe(nlcarry(width, lanes=3))
      combined = record["transfers"]["combined"]
      single = record["transfers"]["add"]
      with self.subTest(width):
        self.assertEqual(combined["source_operations"], 4)
        self.assertEqual(single["source_operations"], 1)
        self.assertLess(combined["instructions_per_source_operation"],
                        single["instructions_per_source_operation"])

  def test_a_transfer_standing_for_one_operation_says_so(self):
    """The plan warns about a candidate that hides a single instruction, so the
    count is recorded rather than left for a reader to infer."""
    site = nlcarry(lanes=3)
    self.assertEqual(site.build("xor").source_ops, 1)
    self.assertEqual(site.build("combined").source_ops, 4)
    self.assertEqual(tm.TriCouple(IR, 7).build("combined").source_ops, 2)

  def test_tricouple_couples_the_lanes_with_a_genuinely_nonlinear_term(self):
    """W1 item 3 asks for cross-value nonlinear terms. In `tricouple` lane one
    decodes through a kernel of lane zero's state word, so with the mask held
    fixed X1 is a nonlinear function of lane zero. A GF(2)-affine fit of that
    kernel in the bits of z0 must fail; the same fit on a linear carrier must
    succeed, so the test cannot pass vacuously."""
    site = tm.TriCouple(IR, 7)
    mask_value = 0xA5
    system = tm.Gf2System()
    monos = tm.monomials(IR, 1)
    for z0 in range(1 << IR):
      system.add(tm.features(z0, monos),
                 site.link_carrier(z0, mask_value, reference=True))
    wrong = sum(1 for z0 in range(1 << IR)
                if system.predict(tm.features(z0, monos)) !=
                site.link_carrier(z0, mask_value, reference=True))
    self.assertGreater(wrong, 0, "the coupling kernel is affine in lane zero")
    linear = tm.Gf2System()
    for z0 in range(1 << IR):
      linear.add(tm.features(z0, monos), tm.ref_rotl(z0, 3, IR) ^ mask_value)
    self.assertTrue(all(linear.predict(tm.features(z0, monos)) ==
                        tm.ref_rotl(z0, 3, IR) ^ mask_value
                        for z0 in range(1 << IR)), "the control must be fitted")

  def test_a_consumer_of_lane_one_must_read_lane_zero(self):
    site = tm.TriCouple(IR, 7)
    base = site.reference_encode([1, 2], [7])
    moved = dict(base, z0=base["z0"] ^ 1)
    self.assertNotEqual(site.reference_decode(base)[1],
                        site.reference_decode(moved)[1])

  def test_tricouple_joins_two_state_words_for_one_logical_update(self):
    """One logical value changes; two state words must be rewritten."""
    transfer = tm.TriCouple(IR, 7).build("addc0")
    self.assertEqual(set(transfer.outputs), {"z0", "z1"})
    self.assertEqual(len(transfer.spec([1, 2])), 1)


class AttackTests(unittest.TestCase):
  """What our own fitting attacks already break, asserted rather than described."""

  def test_the_baselines_and_ablations_fall_immediately(self):
    for site in (tm.XorPair(IR, 5, lanes=2), tm.BitslicePermutation(IR, 5, lanes=2),
                 tm.NlCarry(IR, 5, lanes=2, kernel="linear")):
      with self.subTest(site.identifier):
        report = tm.gf2_attack(site, degree=1)
        self.assertTrue(report["broken"], report)
        self.assertEqual(report["bits_recovered"], IR)

  def test_the_ring_affine_baselines_fall_to_a_modular_fit(self):
    for site in (tm.AdditivePair(IR, 5, lanes=2), tm.UnimodularPair(IR, 5)):
      with self.subTest(site.identifier):
        self.assertTrue(tm.modular_affine_attack(site)["broken"])

  def test_the_and_kernel_survives_a_linear_fit_and_falls_to_a_quadratic_one(self):
    site = tm.NlCarry(IR, 5, lanes=2, kernel="and")
    self.assertEqual(tm.gf2_attack(site, degree=1)["bits_recovered"], 0)
    self.assertTrue(tm.gf2_attack(site, degree=2)["broken"], "negative result")

  def test_the_candidate_kernels_survive_the_low_degree_fits(self):
    for kernel in ("mul", "arx"):
      site = tm.NlCarry(IR, 5, lanes=2, kernel=kernel)
      with self.subTest(kernel):
        self.assertFalse(tm.gf2_attack(site, degree=1)["broken"])
        self.assertFalse(tm.gf2_attack(site, degree=2)["broken"])

  def test_guessing_the_kernel_shape_recovers_the_closed_form_kernels(self):
    """The seeds are a search space, not a secret. Reported as a trial count."""
    for kernel in ("linear", "and", "mul"):
      site = tm.NlCarry(IR, 5, lanes=2, kernel=kernel)
      with self.subTest(kernel):
        report = tm.kernel_shape_attack(site)
        self.assertTrue(report["recovered"], report)
        self.assertLessEqual(report["trials"], IR * IR)

  def test_the_network_kernel_search_space_is_recorded_as_not_attempted(self):
    report = tm.kernel_shape_attack(tm.NlCarry(IR, 5, lanes=2, kernel="arx"))
    self.assertFalse(report["attempted"])
    self.assertIn("reason", report)
    self.assertNotIn("recovered", report)

  def test_a_carrier_fit_peels_low_bits_of_the_modular_kernel(self):
    site = tm.NlCarry(IR, 5, lanes=2, kernel="mul")
    report = tm.carrier_fit_attack(site, degree=2)
    self.assertGreater(report["bits_recovered"], 0, report)
    self.assertFalse(report["broken"], "a degree two fit should not take every bit")
    self.assertTrue(tm.carrier_fit_attack(site, degree=1)["bits_recovered"] <
                    report["bits_recovered"], "more degree must buy more bits")

  def test_a_projection_does_not_transfer_to_another_lane_of_the_same_site(self):
    site = tm.NlCarry(IR, 11, lanes=3, kernel="and")
    other = tm.NlCarry(IR, 99, lanes=3, kernel="and")
    report = tm.projection_transfer_attack(site, other, degree=2)
    self.assertTrue(report["results"]["same-site"]["transfers"])
    self.assertFalse(report["results"]["other-lane"]["transfers"])

  def test_closed_form_kernels_collide_across_independently_seeded_sites(self):
    """Recorded because it is a hazard for the planner, not a property to keep.
    Seeding a carrier only through its rotation amounts gives a space of
    (w-1)^2, so at eight-bit lanes many sites share a carrier and one recovered
    projection decodes all of them."""
    for kernel in ("linear", "and", "mul"):
      report = tm.seed_collision_probe(IR, kernel, sites=64)
      with self.subTest(kernel):
        self.assertEqual(report["parameter_space"], (IR - 1) ** 2)
        self.assertGreater(report["collisions"], 0)
    network = tm.seed_collision_probe(IR, "arx", sites=64)
    self.assertEqual(network["collisions"], 0)
    self.assertIsNone(network["parameter_space"])

  def test_a_fitted_projection_does_not_transfer_to_another_seed(self):
    for kernel in ("linear", "and"):
      a = tm.NlCarry(IR, 11, lanes=2, kernel=kernel)
      b = tm.NlCarry(IR, 99, lanes=2, kernel=kernel)
      with self.subTest(kernel):
        report = tm.projection_transfer_attack(a, b, degree=2)
        self.assertTrue(report["results"]["same-site"]["transfers"],
                        "one fit should decode every use of the same site")
        self.assertFalse(report["results"]["other-seed"]["transfers"])

  def test_reading_the_emitted_constants_decodes_every_family(self):
    """The threat model, as an executable statement. No family here is hard:
    the constants are instruction operands. A fit failing means the fit was the
    wrong tool, never that the family was not recovered."""
    for site in (tm.NlCarry(IR, 5, lanes=2, kernel="arx"), tm.TriCouple(IR, 7),
                 tm.ArxValue(IR, 3, lanes=2), tm.XorPair(IR, 5)):
      with self.subTest(site.identifier):
        report = tm.constant_readback_attack(site)
        self.assertTrue(report["recovered"])
        self.assertEqual(report["exact"], report["trials"])

  def test_a_fit_too_large_to_run_is_recorded_as_not_attempted(self):
    """Not attempted is not evidence of resistance, so it is labelled as such
    with the monomial count rather than reported as a zero."""
    report = tm.gf2_attack(tm.NlCarry(32, 5, lanes=3, kernel="and"), degree=2)
    self.assertFalse(report["attempted"])
    self.assertIsNone(report["bits_recovered"])
    self.assertFalse(report["broken"])
    self.assertGreater(report["monomials"], report["budget"])

  def test_the_and_kernel_falls_to_a_quadratic_fit_at_sixteen_bits_too(self):
    report = tm.gf2_attack(tm.NlCarry(16, 5, lanes=2, kernel="and"), degree=2)
    self.assertTrue(report["broken"], report)

  def test_an_unfittable_model_is_never_reported_as_recovered(self):
    site = tm.NlCarry(IR, 5, lanes=2, kernel="arx")
    report = tm.modular_affine_attack(site)
    self.assertFalse(report["broken"])
    self.assertIn("fitted", report)


class DescriptionTests(unittest.TestCase):
  """The record a planner would read before lowering anything."""

  def test_each_family_states_its_law_preconditions_and_inverse(self):
    for site in (nlcarry(), tm.TriCouple(IR, 7), tm.ArxValue(IR, 3, lanes=2)):
      record = tm.describe(site)
      with self.subTest(site.identifier):
        self.assertIn("decode", record["preconditions"])
        self.assertTrue(record["mask_words"])
        self.assertTrue(record["transfers"])
        for name, entry in record["transfers"].items():
          if "unavailable" in entry: continue
          self.assertIn(entry["expect"], ("accept", "reject"))
          self.assertGreater(entry["instructions"], 0)

  def test_ablations_are_labelled_as_ablations(self):
    self.assertTrue(tm.describe(tm.BitslicePermutation(IR, 5))["ablation"])
    self.assertTrue(tm.describe(tm.NlCarry(IR, 5, kernel="linear"))["ablation"])
    self.assertFalse(tm.describe(tm.NlCarry(IR, 5, kernel="arx"))["ablation"])


if __name__ == "__main__":
  unittest.main()
