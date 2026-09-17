"""Measure what an analyst must read to canonicalize a flattening dispatcher.

Three arms over one protected module, all bounded and deterministic:

  supplied-relation  the encoding family and the participating per-activation
                     words are handed to the analyst; the residual cost is the
                     closed-form inversion in conformance/state_model.py.
  inferred-relation  nothing is handed over; the word set is recovered by a
                     backward slice from each dispatcher comparison.
  canonical-repair   the frozen previous relation (state/key/salt only) is
                     replayed unchanged and either still describes the emitted
                     dispatcher or does not.

Every word counted here is ordinary software state that is present in the
binary. A larger word set raises the joint cost of following control and
recovering data together; it is not secrecy and it is not a hardness claim.
This reads value names, which a stripped binary does not carry, so it is
deliberately generous to the analyst.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import re
import sys
import time

from conformance import state_model
from conformance.process import digest, dump

# The relation the previous recovery script assumed: the token is a function of
# the three flattening words alone, all of which are free of encoded data.
FROZEN_V02_WORDS = ("fla.state", "fla.multi.key", "fla.multi.salt")

DEFINE = re.compile(r"^define\b.*?@([\w.$]+)\(")
ASSIGN = re.compile(r"^\s*%([\w.]+)\s*=\s*(.*)$")
ALLOCA = re.compile(r"^alloca\b")
LOAD = re.compile(r"^load\s+(?:volatile\s+)?[^,]+,\s*ptr\s+(%[\w.]+|@[\w.]+)")
OPERAND = re.compile(r"%([\w.]+)")
MATCH = re.compile(r"^\s*%(fla\.multi\.match[\w.]*)\s*=\s*icmp\s+eq\s+i32\s+([^,]+),\s*(.+?)\s*$")
METADATA = re.compile(r"^!(\d+)\s*=\s*!\{(.*)\}\s*$")


def functions(text):
    """Split a textual module into (name, body lines). Bodies are not nested."""
    out, name, body = [], None, []
    for line in text.splitlines():
        if name is None:
            found = DEFINE.match(line)
            if found:
                name, body = found.group(1), []
            continue
        if line.startswith("}"):
            out.append((name, body))
            name = None
            continue
        body.append(line)
    return out


def data_context_words(text):
    """Allocas that the encoded-data pass updates, from its own metadata tags.

    A store tagged "data" is written by a pinned lane, so the word it writes is
    only produced by actually evaluating the encoded region.
    """
    roles = {}
    for line in text.splitlines():
        found = METADATA.match(line)
        if found and '"' in found.group(2):
            roles[found.group(1)] = found.group(2).split('"')[1]
    words = set()
    for line in text.splitlines():
        if "sre.native.context.update" not in line or "store" not in line:
            continue
        tag = re.search(r"sre\.native\.context\.update !(\d+)", line)
        pointer = re.search(r"store\s+volatile\s+i32\s+[^,]+,\s*ptr\s+%([\w.]+)", line)
        if tag and pointer and roles.get(tag.group(1)) == "data":
            words.add(re.sub(r"\d+$", "", pointer.group(1)))
    return words


class Body:
    """Definitions of one function body, with pointer roots resolved."""

    def __init__(self, lines):
        self.defs, self.allocas = {}, set()
        for line in lines:
            found = ASSIGN.match(line)
            if not found:
                continue
            name, rest = found.group(1), found.group(2)
            self.defs[name] = rest
            if ALLOCA.match(rest):
                self.allocas.add(name)

    def root(self, pointer, depth=0):
        """Resolve a pointer operand to the alloca or global it addresses."""
        if depth > 16 or not pointer:
            return pointer
        if pointer.startswith("@"):
            return pointer
        name = pointer.lstrip("%")
        if name in self.allocas:
            return name
        rest = self.defs.get(name)
        if not rest:
            return name
        if rest.split()[0] in ("getelementptr", "bitcast", "addrspacecast", "select", "phi"):
            for operand in OPERAND.findall(rest):
                resolved = self.root("%" + operand, depth + 1)
                if resolved in self.allocas or str(resolved).startswith("@"):
                    return resolved
        return name

    def slice(self, seeds, limit=20000):
        """Backward slice: visited instruction count and the words it reads."""
        seen, work, words = set(), list(seeds), set()
        while work and len(seen) <= limit:
            name = work.pop()
            if name in seen:
                continue
            seen.add(name)
            rest = self.defs.get(name)
            if rest is None:
                continue
            found = LOAD.match(rest)
            if found:
                words.add(str(self.root(found.group(1))))
                # A load ends the value slice; its pointer is resolved above.
                continue
            work.extend(OPERAND.findall(rest))
        return {"visited": len(seen), "words": words, "truncated": len(seen) > limit}


def supplied_arm(words, trials, seed):
    """Residual cost once the relation is known: closed-form inversion only."""
    rng = random.Random(seed)
    start = time.monotonic()
    checked = 0
    for family in (0, 1, 2):
        for _ in range(trials):
            label, key, salt = (rng.getrandbits(32) for _ in range(3))
            token = state_model.encode(label, key, salt, family)
            if state_model.recover(token, key, salt, family) != label:
                raise ValueError("reference relation is not invertible")
            checked += 1
    return {"arm": "supplied-relation", "words_required": sorted(words),
            "word_count": len(words), "inversion": "closed-form-modular-inverse",
            "search_required": False, "round_trips_checked": checked,
            "seconds": round(time.monotonic() - start, 4),
            "note": "cost after the relation is known; the words themselves must still be read at runtime"}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("module", type=Path, help="protected .ll emitted by the harness")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--trials", type=int, default=2000)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--require-lane-coupling", action="store_true",
                   help="fail unless at least one dispatcher reads an encoded-data word")
    args = p.parse_args(argv)
    if args.trials <= 0 or args.out.exists():
        p.error("positive trials and a fresh output path are required")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    text = args.module.read_text()
    data_words = data_context_words(text)
    rows, every_word, coupled = [], set(), 0
    start = time.monotonic()
    for name, lines in functions(text):
        body = Body(lines)
        dispatchers = []
        for line in lines:
            found = MATCH.match(line)
            if not found:
                continue
            seeds = OPERAND.findall(found.group(2)) + OPERAND.findall(found.group(3))
            result = body.slice(seeds)
            dispatchers.append(result)
        if not dispatchers:
            continue
        words = sorted(set().union(*(d["words"] for d in dispatchers)))
        control = [w for w in words if w in FROZEN_V02_WORDS or w in data_words]
        reads_data = sorted(w for w in words if w in data_words)
        coupled += bool(reads_data)
        every_word.update(control)
        rows.append({"function": name, "comparisons": len(dispatchers),
                     "inferred_words": words, "control_words": sorted(control),
                     "encoded_data_words": reads_data,
                     "slice_instructions_max": max(d["visited"] for d in dispatchers),
                     "slice_instructions_total": sum(d["visited"] for d in dispatchers),
                     "slice_truncated": any(d["truncated"] for d in dispatchers),
                     # The frozen script assumed the token is a function of the
                     # three flattening words alone. It transfers only if that
                     # is still true of every comparison in this function.
                     "frozen_v02_relation_transfers": not reads_data})
    inferred_seconds = round(time.monotonic() - start, 4)
    result = {
        "schema": "sre-relation-recovery-v1",
        "module": str(args.module), "module_sha256": digest(args.module),
        "adapter_sha256": digest(Path(__file__)),
        "functions_with_dispatchers": len(rows),
        "functions_reading_encoded_data": coupled,
        "arms": {
            "supplied_relation": supplied_arm(every_word, args.trials, args.seed),
            "inferred_relation": {
                "arm": "inferred-relation", "method": "backward slice from each dispatcher comparison",
                "seconds": inferred_seconds,
                "words_recovered": sorted(every_word),
                "assumption": "value names are readable; a stripped binary is strictly harder",
            },
            "canonical_repair": {
                "arm": "canonical-repair",
                "frozen_words": list(FROZEN_V02_WORDS),
                "functions_where_frozen_relation_transfers":
                    sum(1 for r in rows if r["frozen_v02_relation_transfers"]),
                "functions_where_frozen_relation_fails":
                    sum(1 for r in rows if not r["frozen_v02_relation_transfers"]),
                "repairable": True,
                "repair_cost": "read one further per-activation word; all words are software state in the binary",
            },
        },
        "functions": rows,
        "interpretation": "relative joint recovery cost, not secrecy and not a hardness claim",
    }
    dump(args.out, result)
    if args.require_lane_coupling and not coupled:
        print("sre-relation-recovery: no dispatcher reads an encoded-data word", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
