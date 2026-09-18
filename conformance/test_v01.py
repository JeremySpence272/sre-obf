import random
import unittest
from conformance.recovery import choose, choose_ast_ablation
from conformance.whole import parser


def shared_add(x, y, rx, ry, width):
    mask = (1 << width) - 1
    def xor(a, b): return (a[0] ^ b[0], a[1] ^ b[1])
    def land(a, b):
        r = a[1] ^ (((b[1] << 1) | (b[1] >> (width - 1))) & mask)
        e = (a[0] & b[0]) ^ (a[0] & b[1]) ^ (a[1] & b[0]) ^ (a[1] & b[1])
        return (e ^ r, r)
    def lor(a, b): return xor(xor(a, b), land(a, b))
    def shl(a, n): return ((a[0] << n) & mask, (a[1] << n) & mask)
    a, b = (x ^ rx, rx), (y ^ ry, ry)
    p, g = xor(a, b), land(a, b)
    original = p
    distance = 1
    while distance < width:
        g = lor(g, land(p, shl(g, distance)))
        p = land(p, shl(p, distance))
        distance *= 2
    e, r = xor(original, shl(g, 1))
    return e ^ r


class V01Tests(unittest.TestCase):
    def test_prefix_shares_at_all_widths(self):
        rng = random.Random(81992)
        for width in (8, 16, 32, 64):
            mask = (1 << width) - 1
            edge = (0, 1, mask, mask >> 1, 1 << (width - 1))
            pairs = [(x, y) for x in edge for y in edge]
            pairs += [(rng.getrandbits(width), rng.getrandbits(width)) for _ in range(2000)]
            for x, y in pairs:
                self.assertEqual(shared_add(x, y, rng.getrandbits(width), rng.getrandbits(width), width), (x + y) & mask)

    def test_reachable_witness_is_not_an_arbitrary_mask_identity(self):
        def witness(h):
            return ((((h << 7) | (h >> 25)) & 0xffffffff) * (h | 1) + 0x9e3779b9) & 0xffffffff
        rng = random.Random(518)
        for _ in range(2000):
            h, x = rng.getrandbits(32), rng.getrandbits(32)
            w = witness(h)
            self.assertEqual(x ^ ((w - witness(h)) & 0xffffffff), x)
            self.assertNotEqual(x ^ (((w ^ 1) - witness(h)) & 0xffffffff), x)

    def test_new_features_are_opt_in(self):
        args = parser().parse_args(["source.c", "--out", "/tmp/not-created"])
        self.assertFalse(any((args.fusion, args.memory, args.values, args.values_wide, args.invariant, args.closed_world)))

    def test_timeouts_errors_and_failed_controls_are_never_selected(self):
        # Both the live metric and the retained ablation must refuse these rows.
        def row(native, control="recovered", growth=2):
            return {"candidate": "a", "native": {"status": native, "ast_nodes": 12, "steps": 7,
                    "summary": {"validated": False, "reason": "no-family-fits"}},
                    "control": {"status": control, "summary": {"validated": True,
                                "best": {"verification": "proved"}}},
                    "growth": growth, "runtime_ratio": 1}
        for case in ([row(s) for s in ("budget", "inconclusive", "tool_error")] +
                     [row("recovered", control="budget"), row("recovered", growth=9),
                      {**row("recovered"), "runtime_ratio": None},
                      {**row("recovered"), "runtime_ratio": 17}]):
            self.assertEqual(choose_ast_ablation([case], 8), [])
            self.assertEqual(choose([case], 8)[0], [])
        self.assertEqual(choose_ast_ablation([row("recovered")], 8)[0]["score"], 19)
        # The ablation scores AST size; the live metric wants a validated outcome.
        ranked, blocked = choose([row("recovered")], 8)
        self.assertEqual(ranked[0]["attack_level"], "lifted")
        self.assertEqual(blocked, [])


if __name__ == "__main__":
    unittest.main()
