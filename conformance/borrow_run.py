"""Closed caller/callee object transactions and strict negative controls."""
import argparse
import json
from pathlib import Path
import shutil

from conformance.bundle_run import inputs
from conformance.connected_check import report_violations
from conformance.process import Runner, ToolFailure, digest, dump
from conformance.run import ROOT, FIXTURES, opt_command
from conformance.tile_run import fixture as local_fixture, oracle as local_oracle, index_mask

FALLBACKS = {'escape': 'pointer-escape-or-observation', 'external': 'unproved-private-borrow',
             'shared-callee': 'unproved-private-borrow', 'callback': 'unsupported-borrow-effect',
             'byval': 'unsupported-borrow-signature', 'early-call': 'initialization-does-not-dominate',
             'lifetime-ended-call': 'access-after-lifetime-end', 'unbounded': 'unproved-index'}


def fixture(width, cells, shape='supported'):
    ty, array = f'i{width}', f'[{cells} x i{width}]'
    source = local_fixture(width, cells, 'lifetime' if shape.startswith('lifetime') else 'supported')
    start, end = source.index('  %idx ='), source.index('  %next =')
    body = source[start:end].replace('ptr %tile', 'ptr %borrow').replace(f'ptr %p{cells - 1}', 'ptr %last')
    ret = ty if shape == 'return-value' else 'void'
    call = f'  {"%call.result = " if ret != "void" else ""}call {ret} @tile_step(ptr %tile, {ty} %a, {ty} %b)\n'
    source = source[:start] + call + source[end:]
    helper = (f'define internal {ret} @tile_step(ptr %borrow, {ty} %a, {ty} %b) noinline {{\nentry:\n'
              f'  %last = getelementptr inbounds {array}, ptr %borrow, i32 0, i32 {cells - 1}\n' + body +
              f'  ret {ret}{" %v5" if ret != "void" else ""}\n}}\n')
    if shape == 'return-value':
        source = source.replace(f'  %r0 = load {ty}, ptr %p0\n', f'  %raw0 = load {ty}, ptr %p0\n  %r0 = xor {ty} %raw0, %call.result\n')
    elif shape == 'aligned':
        source = source.replace(f'%tile = alloca {array}', f'%tile = alloca {array}, align 64')
        source = source.replace('@tile_step(ptr %tile,', '@tile_step(ptr align 64 %tile,')
        helper = helper.replace('@tile_step(ptr %borrow,', '@tile_step(ptr align 64 %borrow,')
    elif shape == 'escape': helper = helper.replace('entry:\n', 'entry:\n  %identity = ptrtoint ptr %borrow to i64\n', 1)
    elif shape == 'external': helper = helper.replace('define internal ', 'define ', 1)
    elif shape == 'shared-callee': source = source.replace(call, call + call, 1)
    elif shape == 'callback':
        helper = helper.replace('entry:\n', 'entry:\n  call void @observer()\n', 1) + 'declare void @observer()\n'
    elif shape == 'byval':
        helper = helper.replace('ptr %borrow,', f'ptr byval({array}) %borrow,', 1)
        source = source.replace('@tile_step(ptr %tile,', f'@tile_step(ptr byval({array}) %tile,')
    elif shape == 'early-call':
        source = source.replace(call, '', 1).replace('  %p0 =', call + '  %p0 =', 1)
    elif shape == 'lifetime-ended-call':
        end = '  call void @llvm.lifetime.end.p0(ptr %tile)\n'
        source = source.replace(end, '', 1).replace(call, end + call, 1)
        # Only the remote access follows the end: this catches a lifetime walk
        # that checks local loads but forgets to project the call into its CFG.
        for k in range(cells):
            source = source.replace(f'%r{k} = load {ty}, ptr %p{k}', f'%r{k} = add {ty} 0, 0')
    elif shape == 'unbounded': helper = helper.replace(f'%idx = and {ty} %b, {index_mask(cells)}', f'%idx = add {ty} %b, 0')
    return source + helper


def oracle(a, b, width, cells, shape='supported'):
    out = local_oracle(a, b, width, cells)
    if shape == 'return-value': out[0] ^= out[b & index_mask(cells)]
    return out


def c_oracle(a, b):
    mask = (1 << 64) - 1
    a, b = a & mask, b & mask
    tile, index = [a, b], b & 1
    value = ((((tile[index] + b) & mask) ^ tile[1]) * 3) & mask
    tile[index] = (((value >> 1) - a) & mask) | 1
    return [*tile, a ^ b, (a + b) & mask]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--toolchain-image', required=True)
    parser.add_argument('--widths', type=int, nargs='+', choices=(8, 16, 32, 64), default=[32])
    parser.add_argument('--cells', type=int, choices=(2, 4), default=2)
    parser.add_argument('--shapes', nargs='+', choices=('supported', 'return-value', 'aligned', 'lifetime', *FALLBACKS), default=['supported'])
    parser.add_argument('--family', choices=('xor', 'additive', 'seeded'), default='xor')
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--phases', action='store_true')
    parser.add_argument('--pins', type=int, nargs='+', choices=(0, 1), default=[0, 1])
    parser.add_argument('--profile', choices=('smoke', 'max'), default='smoke')
    parser.add_argument('--all-passes', action='store_true')
    parser.add_argument('--c-o2', action='store_true', help='ordinary optimized C: widths64/cells2/supported only')
    args = parser.parse_args()
    if args.c_o2 and (args.widths != [64] or args.cells != 2 or args.shapes != ['supported']):
        parser.error('--c-o2 requires --widths 64 --cells 2 --shapes supported')
    out = args.out.resolve(); out.mkdir(parents=True, exist_ok=False)
    plugin = out / 'Obfuscator.so'; shutil.copy2(ROOT / 'build/Obfuscator.so', plugin)
    runner = Runner(ROOT, out / 'logs', args.toolchain_image, mounts=(out,), timeout=240)
    result = {'passed': False, 'cases': [], 'plugin_sha256': digest(plugin), 'hardness_evaluated': False,
              'frontend': 'clang-O2' if args.c_o2 else 'IR-fixture'}
    c_source = out / 'source.c'
    if args.c_o2:
        shutil.copy2(FIXTURES / 'borrow_c_kernel.c', c_source)
        result['source_c_sha256'] = digest(c_source)
    flags = ['-passes=native-obfuscation', f'-native-level={args.profile}',
             *([] if args.all_passes else ['-native-passes=constenc']),
             '-native-strings=0', '-native-data=0', '-native-helper-hardening=0', '-native-late-constants=0',
             '-native-merge=0', '-native-values=1', '-native-values-wide=1', '-native-region-plan=connected',
             '-native-connected-nodes=2', '-native-functions=kernel,tile_step', '-native-plan=1', '-native-scale-budget=1',
             '-native-bundles=1', '-native-object-bundles=1', '-native-object-calls=1',
             f'-native-object-phases={int(args.phases)}', f'-native-transfer-family={args.family}',
             f'-obf-seed={args.seed}', '-obf-deterministic', '-obf-verify']
    try:
        driver = out / 'driver.o'
        runner.run(['clang', '-O2', '-pthread', '-c', str(FIXTURES / 'tile_driver.c'), '-o', str(driver)])
        for width in args.widths:
            vectors = inputs(width, 256)
            pairs = [tuple(map(int, line.split())) for line in vectors.splitlines()]
            for shape in args.shapes:
                for pin in args.pins:
                    name = f'i{width}-{shape}-pins{pin}'
                    case = out / name; case.mkdir()
                    source = case / 'clean.ll'
                    if args.c_o2:
                        runner.run(['clang', '-O2', '-S', '-emit-llvm', str(c_source), '-o', str(source)])
                    else: source.write_text(fixture(width, args.cells, shape))
                    expected = ''.join(' '.join(f'{x:016x}' for x in (c_oracle(a, b) if args.c_o2 else oracle(a, b, width, args.cells, shape))) + '\n'
                                       for a, b in pairs).encode() if shape not in FALLBACKS else None
                    native, report = case / 'native.ll', case / 'native.json'
                    command = opt_command(plugin) + flags + [f'-native-bundle-pins={pin}',
                        f'-native-report-json={report}', f'-native-stage-dir={case / "stages"}', '-S', str(source), '-o', str(native)]
                    runner.run(command)
                    data = json.loads(report.read_text()); errors = report_violations(data)
                    if errors: raise ToolFailure('; '.join(errors))
                    row = next(r for r in data['object_bundles'] if r['function'] == 'kernel')
                    if shape in FALLBACKS:
                        if row['status'] != 'skipped' or row['reason'] != FALLBACKS[shape]:
                            raise ToolFailure(f'unexpected borrower rejection: {row}')
                    else:
                        if row['status'] != 'encoded' or row['plan'].get('closed_call', {}).get('callee') != 'tile_step':
                            raise ToolFailure(f'no actual encoded borrow: {row}')
                        if args.c_o2 and (row['plan']['lifetime']['mode'] != 'single-entry' or row['plan']['decoded_vector_lanes'] != 2):
                            raise ToolFailure('optimized C did not exercise lifetimes and packed output reads')
                        prior = digest(native), digest(report); runner.run(command)
                        if prior != (digest(native), digest(report)): raise ToolFailure('nondeterministic borrow')
                        stage = case / 'stages/object-bundles.ll'
                        stage_text = stage.read_text()
                        if '!sre.native.object.borrow ' not in stage_text: raise ToolFailure('no retained pointer edge')
                        if shape == 'aligned' and not any('sre.tile.tuple = alloca' in line and 'align 64' in line for line in stage_text.splitlines()):
                            raise ToolFailure('borrow alignment contract lost')
                        normalized = case / 'post-o2.ll'
                        runner.run(['opt', '-passes=default<O2>,verify', '-S', str(native), '-o', str(normalized)])
                        arms = [source, stage, native, normalized]
                        unencoded_stage = None
                        for label, extra in (('off', ['-native-object-calls=0']), ('rollback', ['-native-object-retained-growth=1'])):
                            ir, rp = case / f'{label}.ll', case / f'{label}.json'
                            filtered = [f for f in flags if f != '-native-object-calls=1'] if label == 'off' else flags
                            runner.run(opt_command(plugin) + filtered + extra + [f'-native-bundle-pins={pin}',
                                f'-native-report-json={rp}', f'-native-stage-dir={case / (label + "-stages")}', '-S', str(source), '-o', str(ir)])
                            control = json.loads(rp.read_text())
                            if report_violations(control): raise ToolFailure(f'invalid {label} report')
                            r = next(r for r in control['object_bundles'] if r['function'] == 'kernel')
                            status, reason = ('skipped', 'pointer-escape-or-observation') if label == 'off' else ('rolled-back', 'growth-budget')
                            if r['status'] != status or r['reason'] != reason: raise ToolFailure(f'{label} did not exercise its contract')
                            restored = (case / (label + '-stages') / 'object-bundles.ll').read_text()
                            if 'sre.tile.tuple' in restored or '!sre.native.object.borrow ' in restored:
                                raise ToolFailure(f'{label} left encoded object state behind')
                            if label == 'off': unencoded_stage = restored
                            elif restored != unencoded_stage:
                                raise ToolFailure('rollback did not exactly restore both bodies and symbol/parameter attributes')
                            o2 = case / f'{label}-post-o2.ll'
                            runner.run(['opt', '-passes=default<O2>,verify', '-S', str(ir), '-o', str(o2)])
                            arms += [ir, o2]
                        for number, ir in enumerate(arms):
                            binary = case / f'arm-{number}'
                            runner.run(['clang', str(ir), str(driver), '-pthread', '-o', str(binary)])
                            if runner.run([str(binary)], stdin=vectors) != expected: raise ToolFailure(f'borrow mismatch in {ir.name}')
                            runner.run([str(binary), '--threads'])
                    result['cases'].append({'name': name, 'passed': True, 'status': row['status']})
                    print(f'{name}: passed', flush=True)
        result['passed'] = True
    except (ToolFailure, ValueError, KeyError) as error:
        result['error'] = str(error)
    dump(out / 'summary.json', result)
    print(json.dumps({'passed': result['passed'], 'error': result.get('error')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
