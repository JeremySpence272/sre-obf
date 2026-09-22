"""Freeze and run the RevGame v05 performance matrix, retaining every block.

One second is a reported target. Only the registered strict 20x and resource
ceilings gate performance; this command does not certify analysis resistance.
"""
from __future__ import annotations
import argparse
from collections import Counter
import contextlib
import json
from pathlib import Path
import shutil
import re
import subprocess

from conformance.process import digest, dump
from conformance.runtime_check import runtime_violations, v05_violations
from integrations.revgame import benchmark, performance
from integrations.revgame.performance import evaluate_matrix

SCHEMA = 'sre-revgame-matrix-v1'
WORKLOAD_IDS = ('reference-all-eggs', 'reference-deathless', 'short-mixed',
                'alternate-movement', 'long-movement')


def validate_registration(reg):
    if reg.get('schema') != SCHEMA:
        raise ValueError('unsupported matrix registration')
    builds, workloads = reg.get('builds', []), reg.get('workloads', [])
    seeds = [b['seed'] for b in builds]
    if any(not isinstance(s, str) or not s.isdecimal() or not 0 <= int(s) < 2**64 for s in seeds):
        raise ValueError('invalid compiler seed')
    if len(seeds) < 3 or len(seeds) != len(set(seeds)):
        raise ValueError('at least three distinct compiler seeds required')
    if {w['id'] for w in workloads} != set(WORKLOAD_IDS) or len(workloads) != len(WORKLOAD_IDS):
        raise ValueError('missing or duplicate frozen workload class')
    if (type(reg.get('confirmations')) is not int or type(reg.get('samples')) is not int
            or reg['confirmations'] < 2 or reg['samples'] < 31):
        raise ValueError('requires two confirmation blocks and 31 measured pairs')
    if reg.get('slowdown_ceiling') != 20 or reg.get('absolute_target_gates') is not False:
        raise ValueError('invalid runtime policy: one second is not a gate')
    if len({b.get('plugin_sha256') for b in builds}) != 1:
        raise ValueError('mixed compiler plugins')
    if len({b['clean_sha256'] for b in builds}) != 1:
        raise ValueError('unmatched clean baselines')
    for key in ('binary_limit_bytes', 'rss_limit_kib', 'minimum_clean_seconds'):
        value = reg.get(key)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 < value < float('inf'):
            raise ValueError('invalid registered limit: ' + key)
    for w in workloads:
        if w.get('turns', 0) < 128 or w.get('actions', 0) < 128:
            raise ValueError('non-substantive workload: ' + w['id'])


def verify_files(reg):
    for b in reg['builds']:
        root = Path(b['path'])
        for name, relative in [('manifest', 'build/manifest.json'), ('clean', 'build/clean'),
                               ('native', 'build/native'), ('report', 'build/native.json')]:
            if digest(root / relative) != b[name + '_sha256']:
                raise ValueError('registered build changed: ' + str(root / relative))
    for w in reg['workloads']:
        if digest(Path(w['path'])) != w['sha256']:
            raise ValueError('registered workload changed: ' + w['id'])
    previous = reg['previous']
    for arm in ('clean', 'native'):
        if digest(Path(previous['path']) / 'build' / arm) != previous[arm + '_sha256']:
            raise ValueError('frozen v04 arm changed')


def register(builds, previous, out):
    out.mkdir(parents=True, exist_ok=False)
    rows = []
    for root in builds:
        root = root.resolve()
        manifest = json.loads((root / 'build/manifest.json').read_text())
        report = json.loads((root / 'build/native.json').read_text())
        failures = runtime_violations(report) + v05_violations(report)
        if failures:
            raise ValueError('invalid retained feature accounting: ' + '; '.join(failures))
        if report.get('features', {}).get('runtime_test_context'):
            raise ValueError('fixed diagnostic runtime context cannot enter release timings')
        for arm in ('clean', 'native'):
            if digest(root / 'build' / arm) != manifest['artifacts'][arm]['binary_sha256']:
                raise ValueError('build does not match manifest')
        if manifest['budgets']['module_instruction_limit'] > 250000 or manifest['budgets']['compile_timeout_seconds'] > 600:
            raise ValueError('build exceeds registered compile resource limits')
        text_sizes = {}
        for arm in ('clean', 'native'):
            sections = subprocess.check_output(['readelf', '-SW', str(root / 'build' / arm)], text=True)
            match = re.search(r'\]\s+\.text\s+\S+\s+\S+\s+\S+\s+([0-9a-fA-F]+)', sections)
            if not match:
                raise ValueError('missing executable text section')
            text_sizes[arm] = int(match[1], 16)
        rows.append({'path': str(root), 'seed': str(manifest['seed']),
                     'text_bytes': text_sizes,
                     'compile_seconds': sum(c['seconds'] for c in manifest['commands']),
                     'max_compile_command_seconds': max(c['seconds'] for c in manifest['commands']),
                     'budgets': manifest['budgets'], 'plugin_sha256': manifest['plugin_sha256'],
                     'toolchain_image': manifest['toolchain_image'],
                     **{name + '_sha256': digest(root / 'build' / relative) for name, relative in
                        [('manifest', 'manifest.json'), ('clean', 'clean'), ('native', 'native'), ('report', 'native.json')]}})
    source = builds[0].resolve() / 'source'
    previous = previous.resolve()
    if digest(previous / 'build/clean') != rows[0]['clean_sha256']:
        raise ValueError('v04 clean baseline mismatch')
    frozen = out / 'workloads'
    frozen.mkdir()
    reference = source / 'docs/reference/submission-all-eggs.json'
    data = json.loads(reference.read_text())['runs'][0]
    recipes = [
        ('reference-all-eggs', reference, None, 'mixed long reference'),
        ('reference-deathless', source / 'docs/reference/submission-egg-f-deathless.json', None, 'alternate long reference'),
        ('short-mixed', reference, {'runs': [{**data, 'actions': data['actions'][:1024]}]}, 'short prefix; startup included'),
        ('alternate-movement', None, {'runs': [{'seed': [17, 2, 3, 4], 'actions': [
            {'type': 'move', 'dir': direction} for _ in range(512)
            for direction in ('north', 'east', 'south', 'west')]}]}, 'alternate seed; recurrent movement updates'),
        ('long-movement', None, {'runs': [{'seed': [31, 2, 3, 4], 'actions': [
            {'type': 'move', 'dir': direction} for _ in range(4096)
            for direction in ('north', 'east', 'south', 'west')]}]}, 'long alternate seed; concentrated movement updates'),
    ]
    workloads = []
    for name, origin, contents, purpose in recipes:
        path = frozen / (name + '.json')
        if contents is None:
            shutil.copyfile(origin, path)
        else:
            dump(path, contents)
        actions = json.loads(path.read_text())['runs'][0]['actions']
        # Preflight is clean-only correctness evidence, never a candidate timing
        # used to choose or discard a workload. Recipes are fixed above.
        control = benchmark.replay(builds[0].resolve() / 'build/clean', path,
                                   frozen / (name + '-preflight.log'), 120)
        workloads.append({'id': name, 'path': str(path), 'sha256': digest(path),
                          'source_sha256': digest(origin) if origin else None,
                          'purpose': purpose, 'actions': len(actions),
                          'action_types': dict(Counter(a['type'] for a in actions)),
                          'turns': control['turns'], 'output_sha256': control['output_sha256'],
                          'holdout': False})
    reg = {'schema': SCHEMA, 'builds': rows, 'workloads': workloads,
           'previous': {'path': str(previous), **{a + '_sha256': digest(previous / 'build' / a)
                                                for a in ('clean', 'native')}},
           'confirmations': 2, 'samples': 31, 'slowdown_ceiling': 20,
           'absolute_target_seconds': 1.0, 'absolute_target_gates': False,
           'binary_limit_bytes': 16 * 1024 * 1024, 'rss_limit_kib': 512 * 1024,
           'minimum_clean_seconds': 0.001,
           'noise_policy': 'retain every block; no sample deletion or automatic slow-block replacement',
           'candidate_ready': False, 'hardness_evaluated': False}
    validate_registration(reg)
    verify_files(reg)
    dump(out / 'registration.json', reg)
    return out / 'registration.json'


def resources(block, reg, workload):
    errors = []
    for arm, b in block.get('binaries', {}).items():
        if type(b.get('bytes')) is not int or b['bytes'] > reg['binary_limit_bytes']:
            errors.append(arm + ': binary size limit')
    for row in block.get('samples', []):
        rss = row.get('peak_rss_kib')
        if type(rss) is not int or not 0 < rss <= reg['rss_limit_kib']:
            errors.append('invalid or excessive peak RSS')
        if row.get('turns') != workload['turns'] or row.get('output_sha256') != workload['output_sha256']:
            errors.append('timed output differs from frozen clean preflight')
    return sorted(set(errors))


def run(registration, out):
    reg = json.loads(registration.read_text())
    validate_registration(reg)
    verify_files(reg)
    registration_hash = digest(registration)
    protocol_files = [Path(__file__).resolve(), Path(benchmark.__file__).resolve(), Path(performance.__file__).resolve()]
    protocol_hashes = {str(p): digest(p) for p in protocol_files}
    out.mkdir(parents=True, exist_ok=False)
    blocks, evidence, errors = [], [], []
    cells = [(b['seed'], w['id'], w['sha256']) for b in reg['builds'] for w in reg['workloads']]
    summary = {'schema': SCHEMA, 'status': 'running', 'registration_sha256': registration_hash,
               'blocks': evidence, 'errors': errors, 'candidate_ready': False, 'hardness_evaluated': False,
               'protocol_sha256': protocol_hashes}
    dump(out / 'summary.json', summary)
    # Separate confirmations in time; rotate the cell order as well as arms.
    jobs = [(b, w) for b in reg['builds'] for w in reg['workloads']]
    for confirmation in range(reg['confirmations']):
        ordered = jobs[confirmation:] + jobs[:confirmation]
        for build, workload in ordered:
            name = f"c{confirmation + 1}-s{build['seed']}-{workload['id']}"
            destination = out / name
            dump(out / 'active.json', {'block': name})
            try:
                verify_files(reg)
                with (out / (name + '.log')).open('w') as log, contextlib.redirect_stdout(log):
                    benchmark.main(['--build', build['path'], '--previous', reg['previous']['path'],
                                    '--out', str(destination), '--reference', workload['path'],
                                    '--workload-id', workload['id'], '--runs', str(reg['samples']),
                                    '--minimum-clean-seconds', str(reg['minimum_clean_seconds'])])
            except Exception as exc:
                errors.append(name + ': ' + str(exc))
            report_path = destination / 'summary.json'
            if report_path.exists():
                block = json.loads(report_path.read_text())
                blocks.append(block)
                violations = resources(block, reg, workload)
                errors.extend(name + ': ' + e for e in violations)
                evidence.append({'id': name, 'summary': str(report_path), 'sha256': digest(report_path),
                                 'status': block.get('status'), 'metrics': block.get('acceptance', {}).get('metrics'),
                                 'resource_errors': violations})
            else:
                errors.append(name + ': missing block evidence')
            summary['performance'] = evaluate_matrix(blocks, cells, reg['confirmations'])
            dump(out / 'summary.json', summary)
            print(name, evidence[-1]['status'] if evidence and evidence[-1]['id'] == name else 'failed', flush=True)
    try:
        verify_files(reg)
        if any(digest(Path(p)) != h for p, h in protocol_hashes.items()):
            raise ValueError('measurement protocol code changed during matrix')
        if digest(registration) != registration_hash:
            raise ValueError('registration changed during matrix')
    except Exception as exc:
        errors.append(str(exc))
    summary['performance'] = evaluate_matrix(blocks, cells, reg['confirmations'])
    summary['status'] = 'pass' if not errors and summary['performance']['status'] == 'pass' else 'failed'
    dump(out / 'summary.json', summary)
    return 0 if summary['status'] == 'pass' else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('register')
    p.add_argument('--build', type=Path, action='append', required=True)
    p.add_argument('--previous', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p = sub.add_parser('run')
    p.add_argument('--registration', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == 'register':
        print(register(args.build, args.previous, args.out.resolve()))
        return 0
    return run(args.registration.resolve(), args.out.resolve())


if __name__ == '__main__':
    raise SystemExit(main())
