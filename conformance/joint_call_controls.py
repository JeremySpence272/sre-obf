"""Bounded argument-count/site-limit controls, not protection measurements."""
import argparse
import json
from pathlib import Path
import shutil

from conformance.bundle_run import inputs
from conformance.connected_check import report_violations
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command


def fixture(width, count, sites):
    ty = f'i{width}'
    args = ', '.join(f'{ty} %x{k}' for k in range(count))
    lines = ['target triple = "x86_64-unknown-linux-gnu"',
             f'define internal {ty} @subject({args}) noinline {{', 'entry:']
    value = '%x0' if count else '7'
    for k in range(1, count):
        lines.append(f'  %sum{k} = add {ty} {value}, %x{k}')
        value = f'%sum{k}'
    lines += [f'  ret {ty} {value}', '}', 'define i64 @invoke(i64 %a, i64 %b) {', 'entry:']
    a, b = '%a', '%b'
    if width != 64:
        lines += [f'  %a0 = trunc i64 %a to {ty}', f'  %b0 = trunc i64 %b to {ty}']
        a, b = '%a0', '%b0'
    previous = '0'
    for site in range(sites):
        for k in range(count): lines.append(f'  %arg{site}_{k} = add {ty} {b if k % 2 else a}, {site + k}')
        args = ', '.join(f'{ty} %arg{site}_{k}' for k in range(count))
        lines.append(f'  %call{site} = call {ty} @subject({args})')
        value = f'%call{site}'
        if width != 64:
            lines.append(f'  %wide{site} = zext {ty} {value} to i64')
            value = f'%wide{site}'
        lines.append(f'  %acc{site} = add i64 {previous}, {value}')
        previous = f'%acc{site}'
    return '\n'.join(lines + [f'  ret i64 {previous}', '}']) + '\n'


def oracle(a, b, width, count, sites):
    mask = (1 << width) - 1
    return sum((sum((b if k % 2 else a) + site + k for k in range(count)) if count else 7) & mask
               for site in range(sites)) & ((1 << 64) - 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--toolchain-image', required=True)
    args = parser.parse_args()
    out = args.out.resolve(); out.mkdir(parents=True, exist_ok=False)
    plugin = out / 'Obfuscator.so'; shutil.copy2(ROOT / 'build/Obfuscator.so', plugin)
    runner = Runner(ROOT, out / 'logs', args.toolchain_image, mounts=(out,))
    result = {'passed': False, 'cases': [], 'plugin_sha256': digest(plugin), 'hardness_evaluated': False}
    flags = ['-passes=native-obfuscation', '-native-level=smoke', '-native-passes=constenc',
             '-native-strings=0', '-native-data=0', '-native-helper-hardening=0', '-native-late-constants=0',
             '-native-merge=0', '-native-values=1', '-native-values-wide=1', '-native-region-plan=connected',
             '-native-connected-nodes=2', '-native-bundles=1', '-native-encoded-calls=1',
             '-native-joint-call-arguments=1', '-obf-seed=4', '-obf-deterministic', '-obf-verify']
    try:
        driver = out / 'driver.o'
        runner.run(['clang', '-O2', '-c', str(FIXTURES / 'bundle_driver.c'), '-o', str(driver)])
        cases = [(32, n, 2) for n in range(6)] + [(32, 4, 8), (32, 4, 9), (8, 2, 2), (64, 4, 2)]
        for width, count, sites in cases:
            name = f'i{width}-args{count}-sites{sites}'
            case = out / name; case.mkdir()
            source = case / 'clean.ll'; source.write_text(fixture(width, count, sites))
            vectors = inputs(width, 128)
            expected = ''.join(f'{oracle(a, b, width, count, sites):016x}\n' for a, b in
                               (map(int, line.split()) for line in vectors.splitlines())).encode()
            report, native = case / 'native.json', case / 'native.ll'
            command = opt_command(plugin) + flags + [f'-native-report-json={report}',
                f'-native-stage-dir={case / "stages"}', '-S', str(source), '-o', str(native)]
            runner.run(command)
            data = json.loads(report.read_text())
            errors = report_violations(data)
            if errors: raise ToolFailure('; '.join(errors))
            row = next(r for r in data['encoded_calls'] if r['function'] == 'subject')
            reason = 'argument-count' if not 2 <= count <= 4 else 'call-site-limit' if sites > 8 else ''
            if row['status'] != 'encoded' or row['joint_arguments']['reason'] != reason:
                raise ToolFailure('unexpected argument-interface disposition')
            before = digest(native), digest(report); runner.run(command)
            if before != (digest(native), digest(report)): raise ToolFailure('nondeterministic argument interface')
            normalized = case / 'post-o2.ll'
            runner.run(['opt', '-passes=default<O2>,verify', '-S', str(native), '-o', str(normalized)])
            for ir in (source, native, normalized):
                binary = ir.with_suffix('.bin')
                runner.run(['clang', str(ir), str(driver), '-o', str(binary)])
                if runner.run([str(binary)], stdin=vectors) != expected: raise ToolFailure('argument control mismatch')
            result['cases'].append({'name': name, 'reason': reason, 'passed': True})
            print(f'{name}: passed', flush=True)
        result['passed'] = True
    except (ToolFailure, ValueError, KeyError) as error:
        result['error'] = str(error)
    dump(out / 'summary.json', result)
    print(json.dumps({'passed': result['passed'], 'error': result.get('error')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
