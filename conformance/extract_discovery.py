"""Binary discovery adapter: find the regions the supplied-region control is given.

The control in `conformance/extract_supplied.py` receives a region interface from
private provenance and measures only the cost of recovering its semantics. This
adapter receives the binary and the public protocol and nothing else. It models
the path the v03 solve actually used -- startup code, read-only strings, code
cross-references and unwind information -- and then hands the region it found to
the *same* recovery machinery (`conformance/recovery.py`), so that discovery cost
and repair cost are accounted separately from mechanism cost.

Discovery cost is a diagnostic, never a protection claim. An entry point that is
expensive to find is not a semantic property of the program: the plan is explicit
that discovery hygiene alone cannot close the semantic weakness. Accordingly a
region this adapter fails to find is reported `inconclusive` with a reason, and
`conformance.recovery.choose` refuses to rank such a row above a measured one.

Everything here reads the binary as bytes. Nothing is executed, no symbol table
is consulted, and the protocol file is rejected if it carries addresses or
symbol names, which would make this the supplied control wearing a disguise.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import struct
import sys
import time

from conformance import recovery
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, image_identity

PT_LOAD, PT_GNU_EH_FRAME = 1, 0x6474E550
PF_X, PF_W = 1, 2
# DW_EH_PE pointer encodings we decode. 0x80 (indirect) is deliberately absent:
# it needs a relocated load we cannot perform statically, and guessing is worse
# than reporting the boundary.
PE_OMIT = 0xFF
STRING = re.compile(rb"[ -~]{4,}")


class Boundary(Exception):
    """A discovery step that cannot proceed. Carries a fixed-vocabulary reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class Image:
    """Read-only ELF64 little-endian view built from program headers alone.

    Section headers are ignored on purpose. The evaluation targets are stripped
    and a discovery adapter that needed `.symtab` would not be measuring
    discovery. Segments are the only mapping a loader itself needs.
    """

    def __init__(self, data: bytes):
        if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise Boundary("not-elf64-little-endian")
        if struct.unpack_from("<H", data, 18)[0] != 0x3E:
            raise Boundary("unsupported-machine")
        self.data = data
        self.type, self.entry = struct.unpack_from("<H", data, 16)[0], struct.unpack_from("<Q", data, 24)[0]
        offset, size, count = (struct.unpack_from("<Q", data, 32)[0],
                               struct.unpack_from("<H", data, 54)[0],
                               struct.unpack_from("<H", data, 56)[0])
        if size < 56 or offset + size * count > len(data):
            raise Boundary("invalid-program-header-table")
        self.segments = []
        for i in range(count):
            base = offset + i * size
            if base + 56 > len(data):
                raise Boundary("truncated-program-headers")
            kind, flags = struct.unpack_from("<II", data, base)
            file_offset, vaddr = struct.unpack_from("<QQ", data, base + 8)
            file_size, mem_size = struct.unpack_from("<QQ", data, base + 32)
            if file_offset + file_size > len(data) or (kind == PT_LOAD and file_size > mem_size):
                raise Boundary("invalid-file-backed-segment")
            self.segments.append({"type": kind, "flags": flags, "offset": file_offset,
                                  "vaddr": vaddr, "file_size": file_size, "mem_size": mem_size})
        self.load = [s for s in self.segments if s["type"] == PT_LOAD and s["file_size"]]
        if not self.load:
            raise Boundary("no-loadable-segments")

    def owner(self, addr: int, length: int = 1):
        if addr < 0 or length < 0:
            return None
        for s in self.load:
            if s["vaddr"] <= addr and addr + length <= s["vaddr"] + s["file_size"]:
                return s
        return None

    def executable(self, addr: int) -> bool:
        s = self.owner(addr)
        return bool(s and s["flags"] & PF_X)

    def read(self, addr: int, length: int) -> bytes:
        s = self.owner(addr, length)
        if s is None:
            raise Boundary("address-outside-file-backed-segments")
        start = s["offset"] + (addr - s["vaddr"])
        return self.data[start:start + length]

    def code(self):
        return [s for s in self.load if s["flags"] & PF_X]


def uleb(data: bytes, i: int):
    value = shift = 0
    while True:
        if i >= len(data):
            raise Boundary("truncated-uleb128")
        byte = data[i]
        i += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, i


def sleb(data: bytes, i: int):
    value, start = uleb(data, i)
    width = (start - i) * 7
    if value >> (width - 1) & 1:
        value -= 1 << width
    return value, start


def pointer(data: bytes, i: int, encoding: int, base: int):
    """Decode one DW_EH_PE pointer. `base` is the virtual address of data[i]."""
    if encoding == PE_OMIT:
        raise Boundary("omitted-pointer")
    if encoding & 0x80:
        raise Boundary("indirect-pointer-encoding")
    fmt = {0x00: "<Q", 0x02: "<H", 0x03: "<I", 0x04: "<Q",
           0x0A: "<h", 0x0B: "<i", 0x0C: "<q"}.get(encoding & 0x0F)
    if fmt is not None:
        size = struct.calcsize(fmt)
        if i + size > len(data):
            raise Boundary("truncated-pointer")
        value, i = struct.unpack_from(fmt, data, i)[0], i + size
    elif encoding & 0x0F == 0x01:
        value, i = uleb(data, i)
    elif encoding & 0x0F == 0x09:
        value, i = sleb(data, i)
    else:
        raise Boundary("unsupported-pointer-encoding")
    application = encoding & 0x70
    if application == 0x10:
        value += base
    elif application not in (0x00,):
        raise Boundary("unsupported-pointer-application")
    return value & 0xFFFFFFFFFFFFFFFF, i


def eh_frame_span(image: Image):
    """Locate `.eh_frame` without section headers.

    Preferred source is the PT_GNU_EH_FRAME header, whose `eh_frame_ptr` field
    points at the frame table. Static glibc links frequently omit that segment,
    so the fallback scans read-only, non-executable segments for a well-formed
    CIE and keeps the candidate whose entry chain parses furthest.
    """
    for s in image.segments:
        if s["type"] != PT_GNU_EH_FRAME or s["file_size"] < 8:
            continue
        head = image.data[s["offset"]:s["offset"] + s["file_size"]]
        if head[0] != 1:
            continue
        try:
            addr, _ = pointer(head, 4, head[1], s["vaddr"] + 4)
        except Boundary:
            continue
        if image.owner(addr) is not None:
            return addr, "pt-gnu-eh-frame", s["vaddr"]
    best = None
    for s in image.load:
        if s["flags"] & (PF_X | PF_W):
            continue
        blob = image.data[s["offset"]:s["offset"] + s["file_size"]]
        for match in re.finditer(rb"[\x08-\xff]\x00\x00\x00\x00\x00\x00\x00\x01", blob):
            start = match.start()
            if start % 4:
                continue
            addr = s["vaddr"] + start
            reach = _chain_length(image, addr)
            if reach and (best is None or reach > best[0]):
                best = (reach, addr, s["vaddr"])
    if best is None:
        raise Boundary("no-unwind-information")
    return best[1], "scanned-cie", best[2]


def _chain_length(image: Image, addr: int) -> int:
    count, cursor = 0, addr
    while count < 1 << 16:
        try:
            length = struct.unpack("<I", image.read(cursor, 4))[0]
        except Boundary:
            return count
        if length < 4 or length == 0xFFFFFFFF:
            return count
        cursor += 4 + length
        count += 1
    return count


def unwind_functions(image: Image):
    """Function start/size pairs recovered from the frame description entries."""
    addr, source, hdr_base = eh_frame_span(image)
    cies, functions, cursor, guard = {}, [], addr, 0
    while guard < 1 << 17:
        guard += 1
        try:
            length = struct.unpack("<I", image.read(cursor, 4))[0]
        except Boundary:
            break
        if length < 4 or length == 0xFFFFFFFF:
            break
        body_at, body = cursor + 8, None
        try:
            body = image.read(cursor + 8, length - 4)
            identifier = struct.unpack("<I", image.read(cursor + 4, 4))[0]
        except Boundary:
            break
        if identifier == 0:
            try:
                cies[cursor] = _cie(body, body_at, hdr_base)
            except (IndexError, ValueError, Boundary):
                raise Boundary("malformed-cie") from None
        else:
            cie = cies.get(cursor + 4 - identifier)
            if cie and cie.get("encoding") is not None:
                try:
                    start, i = pointer(body, 0, cie["encoding"], body_at)
                    size, _ = pointer(body, i, cie["encoding"] & 0x0F, body_at + i)
                except Boundary:
                    size = None
                    start = None
                if start is not None and size and image.executable(start):
                    functions.append({"start": start, "size": size})
        cursor += 4 + length
    functions.sort(key=lambda f: (f["start"], f["size"]))
    deduped = []
    for f in functions:
        if not deduped or deduped[-1]["start"] != f["start"]:
            deduped.append(f)
    if not deduped:
        raise Boundary("no-frame-description-entries")
    return deduped, source


def _cie(body: bytes, body_at: int, hdr_base: int):
    version = body[0]
    end = body.index(b"\x00", 1)
    augmentation = body[1:end].decode("ascii", "replace")
    i = end + 1
    if version >= 4:
        i += 2
    _, i = uleb(body, i)
    _, i = sleb(body, i)
    if version == 1:
        i += 1
    else:
        _, i = uleb(body, i)
    cie = {"augmentation": augmentation, "encoding": None}
    if not augmentation.startswith("z"):
        return cie
    _, i = uleb(body, i)
    for letter in augmentation[1:]:
        if letter == "R":
            cie["encoding"] = body[i]
            i += 1
        elif letter == "L":
            i += 1
        elif letter == "P":
            encoding = body[i]
            i += 1
            try:
                _, i = pointer(body, i, encoding, body_at + i)
            except Boundary:
                return cie
        elif letter == "S":
            continue
        else:
            return cie
    return cie


# _start writes main's address into RDI before calling __libc_start_main. These
# are the encodings GCC and Clang emit for that write on x86-64. A match is a
# candidate, never an answer: it is confirmed against the unwind table below.
RDI_LOADS = ((b"\x48\x8d\x3d", 3, 4, True), (b"\x48\xc7\xc7", 3, 4, False),
             (b"\x48\xbf", 2, 8, False), (b"\xbf", 1, 4, False))
CALL = b"\xe8"


def startup_main(image: Image, functions):
    """Recover `main` by decoding the startup stub, as the v03 solve did."""
    starts = {f["start"] for f in functions} if functions else set()
    try:
        window = image.read(image.entry, 96)
    except Boundary:
        raise Boundary("entry-outside-file-backed-segments")
    candidate, i = None, 0
    while i < len(window):
        if window[i:i + 1] == CALL and i + 5 <= len(window):
            break
        for prefix, skip, width, relative in RDI_LOADS:
            if not window.startswith(prefix, i):
                continue
            if i + skip + width > len(window):
                break
            raw = struct.unpack_from("<i" if width == 4 else "<q", window, i + skip)[0]
            target = (image.entry + i + skip + width + raw) if relative else raw
            target &= 0xFFFFFFFFFFFFFFFF
            if image.executable(target) and target != image.entry:
                candidate = {"address": target, "form": prefix.hex(), "offset": i}
            i += skip + width - 1
            break
        i += 1
    if candidate is None:
        raise Boundary("startup-pattern-not-matched")
    candidate["confirmed_by_unwind"] = candidate["address"] in starts
    return candidate


def strings(image: Image, limit: int = 4096):
    found = []
    for s in image.load:
        if s["flags"] & (PF_X | PF_W):
            continue
        blob = image.data[s["offset"]:s["offset"] + s["file_size"]]
        for match in STRING.finditer(blob):
            found.append({"address": s["vaddr"] + match.start(), "text": match.group().decode("ascii")})
            if len(found) >= limit:
                return found
    return found


def references(image: Image, targets):
    """RIP-relative references from code to a set of data addresses.

    Linear byte scanning over a code segment necessarily decodes some non-
    instruction bytes. A hit is kept only when the computed target is one of the
    addresses we are looking for, which makes a false positive a coincidence of
    four specific bytes rather than a routine event; the remaining rate is
    reported, not assumed to be zero.
    """
    wanted, hits = set(targets), []
    for s in image.code():
        blob = image.data[s["offset"]:s["offset"] + s["file_size"]]
        for i in range(len(blob) - 6):
            if blob[i] & 0xF8 != 0x48:
                continue
            for skip in (3, 4):
                if i + skip + 4 > len(blob):
                    continue
                displacement = struct.unpack_from("<i", blob, i + skip)[0]
                target = s["vaddr"] + i + skip + 4 + displacement
                if target in wanted:
                    hits.append({"site": s["vaddr"] + i, "target": target})
    return hits


def call_graph(image: Image, functions):
    """Direct `call rel32` edges, attributed to the unwind-derived function set."""
    bounds = [(f["start"], f["start"] + f["size"]) for f in functions]
    starts = [b[0] for b in bounds]
    import bisect

    def containing(addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i >= 0 and bounds[i][0] <= addr < bounds[i][1]:
            return bounds[i][0]
        return None

    edges = {}
    for s in image.code():
        blob = image.data[s["offset"]:s["offset"] + s["file_size"]]
        for i in range(len(blob) - 4):
            if blob[i] != 0xE8:
                continue
            displacement = struct.unpack_from("<i", blob, i + 1)[0]
            site, target = s["vaddr"] + i, s["vaddr"] + i + 5 + displacement
            caller, callee = containing(site), containing(target)
            if caller is None or callee is None or caller == callee:
                continue
            edges.setdefault(caller, set()).add(callee)
    return edges


def protocol_spec(path: Path):
    """The *public* protocol. Private provenance is rejected, not merely ignored.

    Without this check the adapter could be handed `{"entry": 0x401830}` and
    would silently become the supplied-region control, which would make the two
    adapters' costs incomparable -- the one thing they exist to separate.
    """
    spec = json.loads(path.read_text())
    if spec.get("schema") != "sre-discovery-protocol-v1":
        raise Boundary("unsupported-protocol-schema")
    allowed = {"schema", "stdin_format", "tokens", "arity", "width"}
    extra = set(spec) - allowed
    if extra:
        raise Boundary("protocol-contains-private-provenance")
    tokens = spec.get("tokens", [])
    if not isinstance(tokens, list) or any(not isinstance(t, str) for t in tokens):
        raise Boundary("invalid-protocol-tokens")
    for token in tokens:
        if re.fullmatch(r"0[xX][0-9a-fA-F]+|\d{4,}", token.strip()):
            raise Boundary("protocol-contains-private-provenance")
    return spec


def discover(binary: Path, spec: dict, depth: int = 3):
    """Run the discovery phases and rank candidate application regions.

    Returns (ranked regions, phase records, anchor). Every phase is timed into
    the `discovery` cost class so the caller can subtract it from mechanism cost.
    """
    phases = []
    started = time.monotonic()
    data = binary.read_bytes()

    def finish(name, status, reason=None, **detail):
        nonlocal started
        now = time.monotonic()
        phases.append(recovery.phase(name, "discovery", now - started, status, reason, **detail))
        started = now

    try:
        image = Image(data)
        finish("lift", "ok", segments=len(image.segments), pic=image.type == 3)
    except Boundary as exc:
        finish("lift", "boundary", exc.reason)
        return [], phases, None
    try:
        functions, unwind_source = unwind_functions(image)
        finish("unwind", "ok", functions=len(functions), source=unwind_source)
    except Boundary as exc:
        functions, unwind_source = [], None
        finish("unwind", "boundary", exc.reason)
    try:
        start = startup_main(image, functions)
        finish("startup", "ok", **start)
    except Boundary as exc:
        start = None
        finish("startup", "boundary", exc.reason)
    literals = strings(image)
    wanted = [s["address"] for s in literals
              if any(token in s["text"] for token in spec.get("tokens", []))]
    finish("strings", "ok" if wanted else "boundary",
           None if wanted else "no-protocol-strings",
           strings=len(literals), protocol_strings=len(wanted))
    hits = references(image, wanted) if wanted else []
    if not functions:
        finish("xrefs", "boundary", "no-unwind-information", references=len(hits))
        finish("select", "boundary", "no-startup-or-unwind-anchor")
        return [], phases, None
    holders = _holders(functions, [hit["site"] for hit in hits])
    # The startup decode and the protocol references are independent evidence for
    # the same anchor. Agreement is a confirmation; disagreement is reported, and
    # a protocol reference is the fallback anchor when the stub does not decode.
    if start is None and holders:
        start = {"address": sorted(holders)[0], "form": "protocol-reference",
                 "confirmed_by_unwind": True, "offset": None}
        finish("xrefs", "ok", None, references=len(hits), anchor="protocol-reference-fallback")
    else:
        finish("xrefs", "ok" if hits else "boundary", None if hits else "no-protocol-references",
               references=len(hits),
               anchor_agrees=None if start is None else start["address"] in holders)
    if start is None:
        finish("select", "boundary", "no-startup-or-unwind-anchor")
        return [], phases, None
    edges = call_graph(image, functions)
    indegree = {}
    for caller, callees in edges.items():
        for callee in callees:
            indegree[callee] = indegree.get(callee, 0) + 1
    by_start = {f["start"]: f for f in functions}
    reached, frontier = {}, [(start["address"], 0)]
    while frontier:
        addr, level = frontier.pop(0)
        if addr in reached or level > depth or addr not in by_start:
            continue
        reached[addr] = level
        frontier.extend((callee, level + 1) for callee in sorted(edges.get(addr, ())))
    anchor = start["address"]
    ranked = []
    for addr, level in reached.items():
        if addr == anchor:
            continue
        # Library code is reached from many call sites; application code from few.
        # Objects named on the link line are laid out next to each other and
        # before archive members, so distance from the anchor separates the
        # application's own functions from libc without naming either. These are
        # generic layout heuristics: the measured rank is reported, not assumed.
        ranked.append({"address": addr, "size": by_start[addr]["size"], "depth": level,
                       "callers": indegree.get(addr, 0), "distance": abs(addr - anchor),
                       "near_protocol_data": addr in holders,
                       "callees": len(edges.get(addr, ()))})
    ranked.sort(key=lambda r: (r["depth"], r["callers"], r["distance"], -r["size"], r["address"]))
    finish("select", "ok" if ranked else "boundary", None if ranked else "no-candidate-regions",
           reached=len(reached), ranked=len(ranked), anchor=anchor)
    return ranked, phases, anchor


def _holders(functions, sites):
    """Which unwind-derived functions contain the given code addresses."""
    holders = set()
    for site in sites:
        for f in functions:
            if f["start"] <= site < f["start"] + f["size"]:
                holders.add(f["start"])
                break
    return holders


def run(args):
    spec = protocol_spec(args.protocol)
    ranked, phases, anchor = discover(args.binary, spec, args.depth)
    result = {"schema": "sre-discovery-adapter-v1", "adapter": "binary-discovery",
              "binary_sha256": digest(args.binary), "protocol_sha256": digest(args.protocol),
              "candidates": ranked[:args.candidates], "phases": phases, "anchor": anchor,
              "costs": recovery.costs(phases),
              # No decompiler runs here, so there is no repair cost to report.
              # That is null, not zero: nothing repaired anything, which is not
              # the same as pseudocode that needed no repair.
              "repair": {"status": "not_run", "reason": "no-decompiler-configured",
                         "repairs": None, "equivalence": "unchecked"},
              "interpretation": "discovery cost is a diagnostic; an unfound region is "
                                "inconclusive and never counts as protection"}
    if not ranked:
        result.update(status="inconclusive",
                      reason=next((p["reason"] for p in reversed(phases) if p["reason"]), "no-candidate-regions"))
        return result
    # A region the compiler inlined into the entry is not a callee of it, so the
    # ranked list cannot contain it. Reporting the anchor as an explicit fallback
    # keeps that case visible instead of silently ranking the wrong functions.
    result["status"] = "discovered"
    result["fallback_region"] = {"address": anchor,
                                 "reason": "target-may-be-inlined-into-the-entry"}
    if args.expect_entry is not None:
        # Evaluation-only accuracy diagnostic. It is computed after ranking and is
        # never an input to it; the adapter cannot see it while choosing.
        order = [c["address"] for c in ranked]
        rank = order.index(args.expect_entry) + 1 if args.expect_entry in order else None
        result["accuracy"] = {"expected": args.expect_entry, "rank": rank,
                              "ranked_regions": len(ranked),
                              "probes_to_reach_expected": rank,
                              "note": "private provenance, scores discovery only"}
    if args.analysis_image:
        result["probe_interface"] = {"arity": 2, "width": 32,
            "abi": "sysv-amd64-int-words", "basis": "public-protocol-assumption",
            "callee_signature_inferred": False}
        if spec.get("arity", 2) != 2 or spec.get("width", 32) != 32:
            result["mechanism_status"] = "inconclusive"
            result["mechanism_reason"] = "unsupported-probe-interface"
            return result
        result["probes"] = [_probe(args, region["address"], index)
                            for index, region in enumerate(ranked[:args.probe_candidates])]
        for record in result["probes"]:
            result["phases"].append(record.pop("phase"))
        result["costs"] = recovery.costs(result["phases"])
        result["analysis_image"] = image_identity(args.analysis_image)
        result["model_transfer"] = _transfer(result["probes"])
    return result


def _probe(args, entry, index):
    """Run the shared recovery probe at one discovered region."""
    dest = args.out / f"probe-{index}"
    dest.mkdir(parents=True)
    runner = Runner(ROOT, dest / "logs", args.analysis_image,
                    timeout=args.seconds + 15, mounts=(args.out, args.binary.parent))
    started = time.monotonic()
    try:
        runner.run(["python3", str(ROOT / "conformance/recovery_probe.py"),
                    "--binary", str(args.binary), "--entry", hex(entry),
                    "--out", str(dest), "--seconds", str(args.seconds)])
        probe = json.loads((dest / "result.json").read_text())
    except (ToolFailure, OSError) as exc:
        probe = {"status": "inconclusive", "reason": type(exc).__name__}
    if probe.get("status") in ("recovered", "lifted_large"):
        probe["summary"] = recovery.probe_summary(probe)
    return {"entry": entry, "result": probe,
            "phase": recovery.phase("probe", "mechanism", time.monotonic() - started,
                                    "ok" if probe.get("status") == "recovered" else "boundary",
                                    probe.get("reason") or (None if probe.get("status") == "recovered"
                                                            else "not-recovered"),
                                    steps=int(probe.get("steps", 0)), entry=entry)}


def _transfer(probes):
    """Does one inferred model describe more than one discovered region?

    A summary that holds at exactly one site is not a summary; it is that site
    written down again. This records whether the model fitted at the first probed
    region also predicts the others, and says `null` when there was nothing to
    transfer it to rather than reporting a zero.
    """
    fitted = next((p for p in probes if (p["result"].get("summary") or {}).get("validated")), None)
    others = [p for p in probes if p is not fitted and p["result"].get("sites")]
    if fitted is None:
        return {"status": "no_model", "reason": "no-validated-model-at-any-region",
                "regions_predicted": None}
    if not others:
        return {"status": "not_transferred", "reason": "no-second-region-probed",
                "regions_predicted": None}
    model = fitted["result"]["summary"]["best"]["model"]
    predicted = [p["entry"] for p in others
                 if all(recovery.predict(model, tuple(inputs)) == out
                        for site in p["result"]["sites"] for inputs, out in site["observations"])]
    return {"status": "sampled_agreement" if predicted else "not_transferred",
            "validated": False, "reason": "cross-region-equivalence-not-checked",
            "model": model["family"], "fitted_at": fitted["entry"],
            "regions_predicted": len(predicted), "regions_tested": len(others),
            "predicted": predicted}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--protocol", type=Path, required=True, help="public protocol JSON")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--analysis-image", help="run the shared recovery probe on the discovered region")
    p.add_argument("--seconds", type=float, default=20)
    p.add_argument("--depth", type=int, default=3)
    p.add_argument("--candidates", type=int, default=16)
    p.add_argument("--probe-candidates", type=int, default=1,
                   help="probe this many ranked regions; >1 tests model transfer across regions")
    p.add_argument("--expect-entry", type=lambda s: int(s, 0),
                   help="private provenance; scores discovery accuracy only")
    args = p.parse_args(argv)
    try:
        if min(args.seconds, args.depth, args.candidates, args.probe_candidates) <= 0:
            raise ValueError("budgets must be positive")
        args.out = args.out.resolve()
        args.binary = args.binary.resolve()
        args.out.mkdir(parents=True, exist_ok=False)
        result = run(args)
        dump(args.out / "discovery.json", result)
        print(json.dumps({k: result[k] for k in ("status", "costs") if k in result}))
        return 0 if result["status"] == "discovered" else 1
    except (Boundary, OSError, ValueError, ToolFailure) as exc:
        print(f"sre-discovery: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
