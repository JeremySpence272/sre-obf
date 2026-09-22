"""Bounded interpreter differential/composition tests and transaction controls."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
from conformance.process import Runner, digest, dump
from conformance.run import ROOT, opt_command


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--toolchain-image', default='sre-obf-dev:llvm22')
    p.add_argument('--plugin', type=Path, default=ROOT / 'build/Obfuscator.so')
    args = p.parse_args(argv)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plugin = out / 'Obfuscator.so'
    before = digest(args.plugin)
    shutil.copyfile(args.plugin, plugin)
    if digest(plugin) != before:
        raise AssertionError('plugin changed during snapshot')
    run = Runner(ROOT, out / 'logs', args.toolchain_image, timeout=180, mounts=(out,))
    source = ROOT / 'conformance/fixtures/selective_interpreter.c'
    ir, clean = out / 'input.ll', out / 'clean'
    run.run(['clang', '-O0', '-Xclang', '-disable-O0-optnone', '-emit-llvm', '-S', str(source), '-o', str(ir)])
    run.run(['clang', str(ir), '-o', str(clean)])
    expected = run.run([str(clean)])
    cases = []
    for seed in (1, 2, 3):
        for mode in ('interpreter', 'composition', 'rollback'):
            label = f's{seed}-{mode}'
            protected, report, binary = (out / (label + suffix) for suffix in ('.ll', '.json', ''))
            flags = ['-native-interpreter=1', '-native-level=smoke', '-native-passes=constenc',
                     '-native-data=0', '-native-strings=0', '-native-merge=0',
                     '-native-helper-hardening=0', '-native-late-constants=0',
                     f'-obf-seed={seed}', f'-native-report-json={report}']
            if mode == 'composition':
                flags += ['-native-runtime-state=1', '-native-runtime-single-thread=1', '-native-runtime-phases=1']
            if mode == 'rollback':
                flags += ['-native-interpreter-test-rollback=1']
            run.run(opt_command(plugin) + ['-passes=native-obfuscation', *flags, '-S', str(ir), '-o', str(protected)])
            data = json.loads(report.read_text())['selective_interpreter']
            wanted = 'rolled-back' if mode == 'rollback' else 'interpreted'
            if data['status'] != wanted:
                raise AssertionError(f'{label}: {data}')
            owned = {r['function'] for r in data['regions'] if r['status'] == 'interpreted'}
            if mode != 'rollback' and owned != {'mix32', 'mix64', 'signed_transfer'}:
                raise AssertionError(f'incorrect interpreter coverage: {owned}')
            if mode == 'rollback' and '.vm.' in protected.read_text():
                raise AssertionError('rollback left VM artifacts')
            run.run(['clang', str(protected), '-lm', '-o', str(binary)])
            for _ in range(3 if mode == 'composition' else 1):
                if run.run([str(binary)]) != expected:
                    raise AssertionError(f'{label}: differential mismatch')
            cases.append({'case': label, 'status': 'pass', 'selective_interpreter': data})
            dump(out / 'summary.json', {'status': 'running', 'cases': cases})
    dump(out / 'summary.json', {'status': 'pass', 'cases': cases, 'plugin_sha256': before,
                               'source_sha256': digest(source),
                               'expected_output_sha256': hashlib.sha256(expected).hexdigest()})
    print('9 interpreter, composition, and rollback cases passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
