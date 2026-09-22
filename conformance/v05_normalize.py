"""Trusted optimizer-parity controls for the v05 conformance artifacts.

This checks defined behavior after ordinary LLVM optimization. It is not an
analyst evaluation and makes no claim about surviving semantic recovery.
"""
import argparse
import hashlib
from pathlib import Path
from conformance.process import Runner, digest, dump
from conformance.run import ROOT


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--consumer', type=Path, required=True)
    p.add_argument('--interpreter', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--toolchain-image', default='sre-obf-dev:llvm22')
    args = p.parse_args(argv)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    run = Runner(ROOT, out / 'logs', args.toolchain_image, timeout=180, mounts=(out,))
    jobs = [('runtime', args.runtime.resolve(), 's1-p1-cNone.ll'),
            ('consumer', args.consumer.resolve(), 'seed-1.ll'),
            ('interpreter', args.interpreter.resolve(), 's1-composition.ll')]
    cases = []
    for name, folder, filename in jobs:
        source = folder / filename
        before = digest(source)
        expected = run.run([str(folder / 'clean')])
        normalized, binary = out / (name + '.ll'), out / name
        run.run(['opt', '-verify-each', '-passes=default<O2>', '-S', str(source), '-o', str(normalized)])
        run.run(['clang', str(normalized), '-lm', '-o', str(binary)])
        for _ in range(3):
            if run.run([str(binary)]) != expected:
                raise AssertionError(name + ': optimizer changed defined behavior')
        if digest(source) != before:
            raise AssertionError(name + ': original artifact changed')
        cases.append({'case': name, 'status': 'pass', 'input_sha256': before,
                      'normalized_sha256': digest(normalized), 'binary_sha256': digest(binary),
                      'output_sha256': hashlib.sha256(expected).hexdigest()})
        dump(out / 'summary.json', {'status': 'running', 'cases': cases})
    dump(out / 'summary.json', {'status': 'pass', 'cases': cases, 'hardness_evaluated': False})
    print('All three O2 normalization parity controls passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
