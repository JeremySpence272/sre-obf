"""String lifetime/identity boundaries, with and without merged pointer returns."""
import argparse
from pathlib import Path

from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--toolchain-image", default="sre-obf-dev:llvm22")
    p.add_argument("--plugin", type=Path, default=ROOT / "build/Obfuscator.so")
    args = p.parse_args(argv)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plugin = args.plugin.resolve(strict=True)
    plugin_hash = digest(plugin)
    runner = Runner(ROOT, out / "logs", args.toolchain_image, timeout=300,
                    mounts=(out, plugin.parent))
    driver = out / "driver.o"
    runner.run(["clang", "-O0", "-fPIE", "-c",
                str(FIXTURES / "string_lifetime_driver.c"), "-o", str(driver)])
    rows = []
    summary = {"status": "running", "plugin_sha256": plugin_hash, "cases": rows}
    try:
        for optimization in ("O0", "O2"):
            clean = out / (optimization + "-clean")
            runner.run(["clang", "-" + optimization, "-fPIE", "-static-pie",
                        str(FIXTURES / "string_lifetime.c"), str(driver), "-o", str(clean)])
            expected = runner.run([str(clean)])
            for cipher in ("aes", "chacha", "xor"):
                for merge in (False, True):
                    spec = ("obf: strenc(minlen=1,aes=0)" if cipher == "xor" else
                            "obf: strenc(minlen=1,cipher=" + cipher + ",keysplit=1)")
                    if merge:
                        spec += ",fmerge(chunk=4,opaqueSel=1,launderSel=1,dispatch=switch)"
                    stem = optimization + "-" + cipher + "-merge" + str(int(merge))
                    source = out / (stem + ".input.ll")
                    runner.run(["clang", "-" + optimization, "-fPIE", "-S", "-emit-llvm",
                                "-Xclang", "-disable-O0-optnone", '-DOBF_SPEC="' + spec + '"',
                                str(FIXTURES / "string_lifetime.c"), "-o", str(source)])
                    for seed in (1, 17):
                        name = stem + "-seed" + str(seed)
                        ir, binary = out / (name + ".ll"), out / name
                        runner.run(opt_command(plugin) + ["-passes=obfuscation",
                                   "-obf-deterministic", "-obf-verify", "-obf-verbose",
                                   "-obf-seed=" + str(seed), "-S", str(source), "-o", str(ir)])
                        text = ir.read_text()
                        if "local-consumer-secret" in text:
                            raise ToolFailure("noncapturing consumer lost string encryption")
                        for literal in ("south-return-literal", "output-slot-literal",
                                        "retained-call-literal", "global-table-literal"):
                            if literal not in text:
                                raise ToolFailure("escaping literal was rewritten: " + literal)
                        if merge and "define internal i64 @__obf_merged" not in text:
                            raise ToolFailure("merged-return regression did not exercise fmerge")
                        runner.run(["clang", "-" + optimization, "-fPIE", "-static-pie", "-s",
                                    str(ir), str(driver), "-o", str(binary)])
                        if runner.run([str(binary)]) != expected:
                            raise ToolFailure("string lifetime output mismatch: " + name)
                        rows.append({"case": name, "passed": True})
                        print(name + ": pass", flush=True)
        for cipher in ("aes", "chacha", "xor"):
            name = "edges-" + cipher
            source, ir = out / (name + ".input.ll"), out / (name + ".ll")
            spec = "aes=0" if cipher == "xor" else "cipher=" + cipher
            source.write_text((FIXTURES / "string_lifetime_edges.ll").read_text().replace(
                "cipher=aes", spec))
            runner.run(opt_command(plugin) + ["-passes=obfuscation", "-obf-seed=1",
                       "-obf-deterministic", "-obf-verify", "-S", str(source), "-o", str(ir)])
            text = ir.read_text()
            if "cycle-local" in text:
                raise ToolFailure("safe cyclic pointer was not encrypted")
            for literal in ("musttail", "derived-address", "select-escape"):
                if 'c"' + literal + '\\00"' not in text:
                    raise ToolFailure("identity/tail boundary was rewritten: " + literal)
            if "musttail call" not in text:
                raise ToolFailure("mandatory tail-call semantics were removed")
            rows.append({"case": name, "passed": True})
            print(name + ": pass", flush=True)
        if digest(plugin) != plugin_hash:
            raise ToolFailure("plugin changed during regression")
        summary["status"] = "pass"
    except Exception as exc:
        summary.update(status="failed", error=str(exc))
        raise
    finally:
        dump(out / "summary.json", summary)


if __name__ == "__main__":
    main()
