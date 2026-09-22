import copy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from conformance.process import dump
from conformance.test_v05_performance import block
from integrations.revgame import matrix
from integrations.revgame.performance import evaluate


def registration():
    return {'schema': matrix.SCHEMA, 'builds': [
        {'seed': str(s), 'path': '/build/' + str(s), 'clean_sha256': 'a' * 64, 'plugin_sha256': 'e' * 64}
        for s in (1, 2, 3)],
        'workloads': [{'id': name, 'path': '/' + name, 'sha256': 'c' * 64, 'turns': 128,
                       'actions': 128, 'output_sha256': 'd' * 64} for name in matrix.WORKLOAD_IDS],
        'previous': {'path': '/v04'}, 'confirmations': 2, 'samples': 31, 'slowdown_ceiling': 20,
        'absolute_target_gates': False, 'binary_limit_bytes': 16000000, 'rss_limit_kib': 524288,
        'minimum_clean_seconds': 0.001}


class MatrixTests(unittest.TestCase):
    def test_registration_rejects_missing_cells_and_policy_changes(self):
        matrix.validate_registration(registration())
        mutations = [lambda r: r['builds'].pop(), lambda r: r['workloads'].pop(),
                     lambda r: r.update(absolute_target_gates=True),
                     lambda r: r.update(confirmations=1), lambda r: r.update(samples=30),
                     lambda r: r['builds'][1].update(seed='1'),
                     lambda r: r['builds'][1].update(clean_sha256='f' * 64),
                     lambda r: r['builds'][1].update(plugin_sha256='f' * 64),
                     lambda r: r['workloads'][0].update(turns=1),
                     lambda r: r.update(rss_limit_kib=float('nan'))]
        for mutate in mutations:
            r = registration()
            mutate(r)
            with self.assertRaises(ValueError):
                matrix.validate_registration(r)

    def test_all_blocks_run_and_one_failure_prevents_acceptance(self):
        for failure in (None, 'slow', 'output', 'rss', 'exception'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                reg = root / 'registration.json'
                dump(reg, registration())
                calls = []
                def fake(argv):
                    args = dict(zip(argv[::2], argv[1::2]))
                    destination = Path(args['--out'])
                    calls.append(destination.name)
                    if failure == 'exception' and len(calls) == 1:
                        raise RuntimeError('injected process failure')
                    destination.mkdir()
                    # Above one second deliberately passes when below 20x.
                    r = block(clean=0.2, native=1.5)
                    r.update(block_id=destination.name, compiler_seed=Path(args['--build']).name,
                             workload_id=args['--workload-id'])
                    for binary in r['binaries'].values():
                        binary['bytes'] = 1024
                    for row in r['samples']:
                        row.update(turns=128, peak_rss_kib=1024)
                        if len(calls) == 1:
                            if failure == 'slow' and row['arm'] == 'native':
                                row.update(replay_seconds=4, full_process_seconds=4.1)
                            if failure == 'output': row['output_sha256'] = 'f' * 64
                            if failure == 'rss': row['peak_rss_kib'] = 1000000
                    r['acceptance'] = evaluate(r)
                    r['status'] = r['acceptance']['status']
                    dump(destination / 'summary.json', r)
                    return int(r['status'] != 'pass')
                with patch.object(matrix, 'verify_files'), patch.object(matrix.benchmark, 'main', side_effect=fake), contextlib.redirect_stdout(io.StringIO()):
                    code = matrix.run(reg, root / 'matrix')
                self.assertEqual(len(calls), 30)
                result = json.loads((root / 'matrix/summary.json').read_text())
                self.assertEqual(code, int(failure is not None))
                self.assertEqual(result['status'], 'pass' if failure is None else 'failed')
                self.assertFalse(result['candidate_ready'])
                self.assertEqual(len(result['blocks']), 29 if failure == 'exception' else 30)

    def test_workload_file_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'workload.json'
            path.write_text('changed')
            r = {'builds': [], 'workloads': [{'path': str(path), 'id': 'x', 'sha256': 'c' * 64}]}
            with self.assertRaisesRegex(ValueError, 'workload changed'):
                matrix.verify_files(r)


if __name__ == '__main__':
    unittest.main()
