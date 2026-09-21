"""Count AES decoder executions on cold, merged, looping and PHI-edge paths."""
import argparse
from pathlib import Path
import re

from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command


def counted_ir(text):
    text, count = re.subn(r"(call void )@__aes_decrypt\(",
                          r"\1@strenc_test_decrypt(", text)
    if not count:
        raise ToolFailure("AES decoder calls missing from fixture")
    return text + '''
@strenc_test_calls = external global i32
define internal void @strenc_test_decrypt(ptr %buf, i32 %len, ptr %nonce) {
  call void @__aes_decrypt(ptr %buf, i32 %len, ptr %nonce)
  %old = load volatile i32, ptr @strenc_test_calls
  %next = add i32 %old, 1
  store volatile i32 %next, ptr @strenc_test_calls
  ret void
}
'''


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
                str(FIXTURES / "string_lazy_driver.c"), "-o", str(driver)])
    rows = []
    summary = {"status": "running", "plugin_sha256": plugin_hash, "cases": rows}
    try:
        for optimization in ("O0", "O2"):
            clean = out / (optimization + "-clean")
            runner.run(["clang", "-" + optimization, "-fPIE", "-static-pie",
                        "-DEXPECT_DECRYPTS=0", str(FIXTURES / "string_lazy.c"),
                        str(FIXTURES / "string_lazy_edges.ll"),
                        str(FIXTURES / "string_lazy_driver.c"), "-o", str(clean)])
            expected = runner.run([str(clean)])
            for merge in (False, True):
                spec = "obf: strenc(minlen=1,cipher=aes,keysplit=1)"
                if merge:
                    spec += ",fmerge(chunk=4,opaqueSel=1,launderSel=1,dispatch=switch)"
                stem = optimization + "-merge" + str(int(merge))
                source, linked = out / (stem + ".input.ll"), out / (stem + ".linked.ll")
                runner.run(["clang", "-" + optimization, "-fPIE", "-S", "-emit-llvm",
                            "-Xclang", "-disable-O0-optnone", '-DOBF_SPEC="' + spec + '"',
                            str(FIXTURES / "string_lazy.c"), "-o", str(source)])
                runner.run(["llvm-link", "-S", str(source),
                            str(FIXTURES / "string_lazy_edges.ll"), "-o", str(linked)])
                for seed in (1, 17):
                    name = stem + "-seed" + str(seed)
                    ir, binary = out / (name + ".ll"), out / name
                    runner.run(opt_command(plugin) + ["-passes=obfuscation",
                               "-obf-deterministic", "-obf-verify", "-obf-verbose",
                               "-obf-seed=" + str(seed), "-S", str(linked), "-o", str(ir)])
                    text = ir.read_text()
                    for literal in ("cold-only-secret", "loop-only-secret",
                                    "shared-branch-secret", "recursive-only-secret",
                                    "nested-only-secret", "phi-left", "phi-right", "cycle-use"):
                        if literal in text:
                            raise ToolFailure("string lost encryption: " + literal)
                    if merge and "define internal i64 @__obf_merged" not in text:
                        raise ToolFailure("lazy fixture did not exercise function merging")
                    counted = out / (name + ".counted.ll")
                    counted.write_text(counted_ir(text))
                    runner.run(["clang", "-" + optimization, "-fPIE", "-static-pie", "-s",
                                str(counted), str(driver), "-o", str(binary)])
                    if runner.run([str(binary)]) != expected:
                        raise ToolFailure("lazy string output mismatch: " + name)
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
