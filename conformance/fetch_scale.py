"""Fetch pinned official source releases and prepare private scale manifests.

No downloaded code is executed. Archive paths, types and expanded sizes are
checked before extraction. A lock records the exact acquired archive hashes;
pass --lock on subsequent acquisition to reject upstream replacement.
"""
from __future__ import annotations
import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request
import zipfile

RELEASES = {
    "sqlite": ("3.49.2", "https://www.sqlite.org/2025/sqlite-amalgamation-3490200.zip", "sqlite-amalgamation-3490200"),
    "lua": ("5.4.8", "https://www.lua.org/ftp/lua-5.4.8.tar.gz", "lua-5.4.8"),
    "zlib": ("1.3.1", "https://zlib.net/fossils/zlib-1.3.1.tar.gz", "zlib-1.3.1"),
}


def sha(data): return hashlib.sha256(data).hexdigest()


def extract(data, destination, zipped):
    destination.mkdir()
    archive = zipfile.ZipFile(io.BytesIO(data)) if zipped else tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    members = archive.infolist() if zipped else archive.getmembers()
    total = 0
    for item in members:
        name = item.filename if zipped else item.name
        path = (destination / name).resolve()
        if not path.is_relative_to(destination.resolve()):
            raise ValueError("unsafe archive path")
        if not zipped and not (item.isdir() or item.isfile()):
            raise ValueError("unsupported archive link/device")
        if zipped and ((item.external_attr >> 16) & 0o170000) == 0o120000:
            raise ValueError("archive symlink")
        total += item.file_size if zipped else item.size
        if total > 128 * 1024 * 1024:
            raise ValueError("expanded archive cap")
    if zipped:
        archive.extractall(destination)
    else:
        archive.extractall(destination, filter="data")
    archive.close()


def workload(name, stdin, stdout, argv=()):
    return {"name": name, "stdin_base64": base64.b64encode(stdin).decode(),
            "stdout_sha256": sha(stdout), "argv": list(argv)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--lock", type=Path, default=Path(__file__).with_name("scale_sources.lock.json"))
    args = p.parse_args()
    out = args.out.resolve()
    if out.exists(): p.error("fresh source/output directory required")
    previous = json.loads(args.lock.read_text())
    out.mkdir(parents=True)
    lock = {"schema": "sre-scale-source-lock-v1", "projects": {}}
    for project, (revision, url, directory) in RELEASES.items():
        request = urllib.request.Request(url, headers={"User-Agent": "sre-obf-conformance/1"})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(16 * 1024 * 1024 + 1)
        if len(data) > 16 * 1024 * 1024: raise ValueError("download cap")
        checksum = sha(data)
        pinned = previous["projects"][project]
        if (pinned["archive_sha256"] != checksum or pinned["revision"] != revision or pinned["url"] != url):
            raise ValueError("archive hash differs from lock")
        archive = out / (project + (".zip" if url.endswith(".zip") else ".tar.gz"))
        archive.write_bytes(data)
        extract(data, out / project, url.endswith(".zip"))
        root = out / project / directory
        if project == "sqlite":
            sources = ["sqlite3.c", "shell.c"]
            cflags, links = ["-D_GNU_SOURCE"], ["-lm", "-ldl", "-pthread"]
            sql = ("create table t(a integer,b text);\n"
                   "with recursive n(x) as (select 1 union all select x+1 from n where x<1000) "
                   "insert into t select x,printf('%04d',x) from n;\n"
                   "select count(*),sum(a),max(b) from t;\n"
                   "select sum(a) from t where a%7=0;\n"
                   "select json_extract('{\"x\":[4,9]}','$.x[1]');\n")
            workloads = [workload("query-parser-state-json", sql.encode(), b"1000|500500|1000\n71071\n9\n", [":memory:"])]
        elif project == "lua":
            sources = [str(s.relative_to(root)) for s in sorted((root / "src").glob("*.c")) if s.name != "luac.c"]
            cflags, links = ["-D_GNU_SOURCE", "-DLUA_USE_LINUX"], ["-lm", "-ldl"]
            script = ("local t={} for i=1,2000 do t[i]=i end local s=0 "
                      "for _,v in ipairs(t) do s=s+v end print(s)\n"
                      "local function fib(n) if n<2 then return n end return fib(n-1)+fib(n-2) end print(fib(20))\n"
                      "local a={'pear','apple','plum'} table.sort(a) print(table.concat(a,','))\n")
            workloads = [workload("tables-recursion-parser", script.encode(), b"2001000\n6765\napple,pear,plum\n", ["-"])]
        else:
            sources = [name + ".c" for name in ("adler32", "compress", "crc32", "deflate", "gzclose", "gzlib", "gzread", "gzwrite", "infback", "inffast", "inflate", "inftrees", "trees", "uncompr", "zutil")]
            sources.append("test/minigzip.c")
            cflags, links = ["-D_GNU_SOURCE", "-DHAVE_UNISTD_H", "-I" + str(root)], []
            payload = bytes(range(256)) * 32 + b"whole-program static conformance\n" * 256
            workloads = [workload("gzip-full-byte-domain", gzip.compress(payload, mtime=0), payload, ["-d"])]
        source_records = [{"path": name, "sha256": sha((root / name).read_bytes())} for name in sources]
        inputs = [{"path": str(path.relative_to(root)), "sha256": sha(path.read_bytes())}
                  for path in sorted(root.rglob("*")) if path.is_file() and path.suffix in (".c", ".h")]
        spec = {"schema": "sre-scale-v1", "project": project, "revision": revision,
                "archive_sha256": checksum, "url": url, "root": str(root), "sources": source_records, "inputs": inputs,
                "cflags": cflags + ["-g0", "-fno-pie"], "link_flags": links + ["-static", "-no-pie", "-s"],
                "workloads": workloads}
        (out / (project + ".json")).write_text(json.dumps(spec, indent=2) + "\n")
        lock["projects"][project] = {"revision": revision, "url": url, "archive_sha256": checksum}
        (out / "source-lock.json").write_text(json.dumps(lock, indent=2) + "\n")
        print(project, revision, checksum, flush=True)


if __name__ == "__main__":
    main()
