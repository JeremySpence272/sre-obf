import argparse
import copy
from types import SimpleNamespace
import unittest

from conformance import bundle_options
from conformance.borrow_run import fixture, oracle, c_oracle
from conformance.test_tile import lifetime_report
from conformance.tile_check import tile_summary, tile_violations


def report():
    data = lifetime_report()
    data['features'].update(object_bundle_contract=5, object_calls=True, object_max_cells=4, object_retained_growth=65536)
    row = data['object_bundles'][0]
    row.update(max_cells=4, retained_growth_limit=row['growth_allocation'])
    plan = row['plan']
    plan.update(ownership='closed-private-borrow', initialization='complete-entry-stores-dominate-accesses-and-call',
        phase_contract={'states': 1, 'entry': 0, 'transition': 'identity', 'carrier': 'entry-only',
                        'layout': 'seeded-permutation', 'static_update_sites': 0, 'bytes_reencoded_per_update': 0},
        closed_call={'contract': 'sole-private-leaf-borrow-v1', 'caller': 'f', 'callee': 'g',
                     'pointer_argument': 0, 'direct_sites': 1, 'layout_words': 3, 'callee_operations': 6,
                     'proof': 'sole-use-leaf-single-pointer-closed-accesses-initialization-dominates-call'})
    plan['lifetime'].update(mode='whole-function', source_starts=0, source_ends=0, translated_markers=0)
    for k, access in enumerate(plan['accesses']): access['function'] = 'g' if 2 <= k <= 4 else 'f'
    return data


class PrivateBorrows(unittest.TestCase):
    def test_valid_and_summary(self):
        self.assertEqual(tile_violations(report()), [])
        self.assertEqual(tile_summary(report())['retained_private_borrows'], 1)
        data = report()
        data['object_bundles'][0]['plan']['lifetime'].update(mode='single-entry', source_starts=1,
                                                           source_ends=1, translated_markers=2)
        self.assertEqual(tile_violations(data), [])
        from conformance.scale import source_ledger
        data['input_inventory'] = {'functions': [{'function': 'f', 'instructions': 40}, {'function': 'g', 'instructions': 20}]}
        data['functions'] = [{'function': f, 'selected': True} for f in ('f', 'g')]
        ledger = source_ledger(data)
        self.assertEqual(ledger['object_storage_owners'], 1)
        self.assertEqual(ledger['object_borrowers'], 1)
        self.assertEqual(ledger['object_bundle_owners'], 2)
        self.assertEqual(ledger['functions']['encoded'], 2)

    def test_contract_owner_and_shape_mutations(self):
        for key, value in (('contract', 'guess'), ('caller', 'g'), ('callee', 'f'),
                           ('direct_sites', 2), ('pointer_argument', -1), ('layout_words', 2),
                           ('callee_operations', 3), ('callee_operations', 7), ('proof', 'assumed')):
            data = report(); data['object_bundles'][0]['plan']['closed_call'][key] = value
            self.assertTrue(tile_violations(data), key)
        data = report(); data['features']['object_calls'] = False
        self.assertTrue(tile_violations(data))
        data = report(); data['object_bundles'][0]['plan']['accesses'][0]['function'] = 'g'
        self.assertTrue(tile_violations(data))
        data = report(); data['object_bundles'][0]['plan']['accesses'][3]['function'] = 'other'
        self.assertTrue(tile_violations(data))

    def test_reserved_callee_cannot_be_owned_again(self):
        data = report()
        row = copy.deepcopy(data['object_bundles'][0]); row['function'] = 'g'
        data['object_bundles'].append(row)
        self.assertTrue(tile_violations(data))

    def test_downward_cap_forces_real_restored_transaction(self):
        data = report(); data['features']['object_retained_growth'] = 1
        row = data['object_bundles'][0]
        row.update(retained_growth_limit=1, status='rolled-back', reason='growth-budget', retained_operations=0,
                   rolled_back_operations=6, instructions_after=row['instructions_before'])
        self.assertEqual(tile_violations(data), [])
        self.assertEqual(tile_summary(data)['retained_private_borrows'], 0)
        row['instructions_after'] += 1
        self.assertTrue(tile_violations(data))
        for ceiling in (0, 65537, True):
            data = report(); data['features']['object_retained_growth'] = ceiling
            self.assertTrue(tile_violations(data))

    def test_source_fixture_passes_pointer_not_plaintext_copy(self):
        text = fixture(32, 4)
        self.assertEqual(text.count('call void @tile_step('), 1)
        self.assertIn('@tile_step(ptr %borrow, i32 %a, i32 %b)', text)
        self.assertIn('getelementptr inbounds [4 x i32], ptr %borrow', text)
        self.assertEqual(fixture(32, 4, 'shared-callee').count('call void @tile_step('), 2)
        self.assertIn('ptr byval([4 x i32])', fixture(32, 4, 'byval'))
        plain = oracle(19, 37, 32, 4)
        returned = oracle(19, 37, 32, 4, 'return-value')
        self.assertEqual(returned, [plain[0] ^ plain[1], *plain[1:]])
        self.assertEqual(c_oracle(2, 4), [1, 4, 6, 6])
        self.assertEqual(c_oracle(2, 3), [2, 5, 1, 5])

    def test_shared_options_and_legacy_namespace(self):
        parser = argparse.ArgumentParser(); bundle_options.add_options(parser)
        for flags in (['--object-calls'], ['--bundles', '--object-calls'],
                      ['--bundles', '--object-bundles', '--object-retained-growth', '0']):
            with self.assertRaises(ValueError): bundle_options.validate(parser.parse_args(flags), True)
        args = parser.parse_args(['--bundles', '--object-bundles', '--object-calls', '--object-retained-growth', '1'])
        bundle_options.validate(args, True)
        self.assertEqual(bundle_options.flags(args), bundle_options.flags(parser.parse_args(bundle_options.argv(args))))
        self.assertIn('-native-object-retained-growth=1', bundle_options.flags(args))
        self.assertIn('-native-bundles=1', bundle_options.flags(SimpleNamespace(bundles=True)))
