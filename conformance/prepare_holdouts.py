"""Freeze clean holdout IO contracts from pinned archives, without obfuscation.

No fetching, protected compilation, candidate measurement or tuning is done.
The output proposes manifest hashes for an explicit corpus-lock revision.
"""
import argparse
import base64
import bz2
import hashlib
import json
from pathlib import Path
import shutil

from conformance import corpora
from conformance.fetch_scale import extract, workload
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES


def contracts(project):
    if project == "bzip2":
        payloads = (b"", bytes(range(256)) * 32,
                    b"bounded block-sorting conformance\n" * 512 + bytes(range(255, -1, -1)))
        result = []
        for number, payload in enumerate(payloads):
            compressed = bz2.compress(payload, compresslevel=9)
            result.append(workload(f"compress-{number}", payload, compressed, ("-9", "-c")))
            result.append(workload(f"decompress-{number}", compressed, payload, ("-d", "-c")))
        return result
    if project != "cjson": raise ValueError("unknown holdout")
    values = [None, True, False, [], {}, 0, -1, 2147483647, -2147483648,
              {"text": "quotes: \" and slash: \\ and tab:\t", "unicode": "λ🙂"},
              {"items": [{"id": i, "enabled": bool(i % 2), "children": [i, None, "x"]}
                         for i in range(64)]}]
    nested = {"leaf": [1, 2, 3]}
    for _ in range(32): nested = [nested]
    values.append(nested)
    expected = "".join(json.dumps(v, ensure_ascii=False, separators=(",", ":")) + "\n" for v in values)
    incoming = "".join(json.dumps(v, ensure_ascii=True) + "\n" for v in values)
    return [workload("parse-serialize-scalars-objects-recursion", incoming.encode(), expected.encode()),
            workload("invalid-documents", b"{{\nnot-json\n\"unterminated\n", b"invalid\n" * 3)]


def prepare(args):
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    lock = corpora.load(args.corpora_lock)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, mounts=(out,), timeout=180)
    result = {"schema": "sre-holdout-preparation-v1", "passed": False, "projects": {},
              "protected_builds": 0, "candidate_measurements": 0, "parent_lock": corpora.summary(lock)}
    try:
        for name, archive in (("bzip2", args.bzip2_archive), ("cjson", args.cjson_archive)):
            record = lock["corpora"][name]
            identity = record["acquisition"]
            if record["split"] != "holdout" or digest(archive) != identity["archive_sha256"]:
                raise ValueError(f"{name}: archive does not match held-out identity")
            project = out / name
            project.mkdir()
            retained = project / "source.tar.gz"
            shutil.copy2(archive, retained)
            extract(retained.read_bytes(), project / "source", False)
            root = project / "source" / ("bzip2-1.0.8" if name == "bzip2" else "cJSON-1.7.18")
            if name == "bzip2":
                source_names = [s + ".c" for s in ("blocksort", "huffman", "crctable", "randtable",
                                                   "compress", "decompress", "bzlib", "bzip2")]
                cflags, links = ["-D_FILE_OFFSET_BITS=64"], []
            else:
                # Only a new driver is added; upstream files are never edited.
                shutil.copy2(FIXTURES / "cjson_workload.c", root / "sre_workload.c")
                source_names = ["cJSON.c", "sre_workload.c"]
                cflags, links = [], ["-lm"]
            source_paths = [root / name for name in source_names]
            inputs = [{"path": str(p.relative_to(root)), "sha256": digest(p)}
                      for p in sorted(root.rglob("*")) if p.is_file() and p.suffix in (".c", ".h")]
            spec = {"schema": "sre-scale-v1", "project": name, "revision": identity["revision"],
                    "archive_sha256": digest(retained), "url": identity["url"], "root": str(root),
                    "sources": [{"path": p.name, "sha256": digest(p)} for p in source_paths],
                    "inputs": inputs, "cflags": cflags + ["-g0", "-fno-pie"],
                    "link_flags": links + ["-static", "-no-pie", "-s"], "workloads": contracts(name),
                    "contract_scope": "clean reference only; no obfuscator or protected holdout measurement"}
            binary = project / "reference"
            runner.run(["clang", "-O2", *spec["cflags"], *map(str, source_paths),
                        *spec["link_flags"], "-o", str(binary)])
            for case in spec["workloads"]:
                actual = runner.run([str(binary), *case["argv"]], stdin=base64.b64decode(case["stdin_base64"]))
                if hashlib.sha256(actual).hexdigest() != case["stdout_sha256"]:
                    raise ToolFailure(f"{name}/{case['name']}: independent clean IO contract mismatch")
            if any(digest(root / i["path"]) != i["sha256"] for i in inputs):
                raise ToolFailure("clean reference build changed its sources")
            manifest = out / (name + ".json")
            dump(manifest, spec)
            result["projects"][name] = {"manifest": str(manifest), "manifest_sha256": digest(manifest),
                "archive_sha256": digest(retained), "reference_sha256": digest(binary),
                "workloads": len(spec["workloads"]), "sources_unchanged": True}
            dump(out / "summary.json", result)
        result["passed"] = True
    except (OSError, ValueError, ToolFailure) as exc:
        result["error"] = str(exc)
    finally:
        result["commands"] = runner.records
        dump(out / "summary.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--bzip2-archive", type=Path, required=True)
    parser.add_argument("--cjson-archive", type=Path, required=True)
    parser.add_argument("--toolchain-image", required=True)
    parser.add_argument("--corpora-lock", type=Path, default=Path(__file__).with_name("corpora.lock.json"))
    result = prepare(parser.parse_args())
    print(json.dumps({k: result.get(k) for k in ("passed", "projects", "error")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
