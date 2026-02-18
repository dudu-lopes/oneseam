import unittest

import oneseam as oe


class TestCliTraderFlowActions(unittest.TestCase):
    def test_compute_next_actions_wait_lock_a(self):
        swap = {
            'swap_id': 'swap_1',
            'state': oe.SWAP_STATE_WAIT_LOCK_A,
            'metadata': {'peer_a': 'ALICE', 'peer_b': 'BOB'}
        }
        actions = oe.compute_next_actions(swap=swap, client_id='ALICE')
        codes = [a['code'] for a in actions]
        self.assertIn('SEND_LOCK_A', codes)
        self.assertEqual(actions[0]['code'], 'SEND_LOCK_A')

    def test_compute_next_actions_ready_claim_for_peer_b(self):
        swap = {
            'swap_id': 'swap_2',
            'state': oe.SWAP_STATE_READY_CLAIM,
            'metadata': {'peer_a': 'ALICE', 'peer_b': 'BOB'}
        }
        actions = oe.compute_next_actions(swap=swap, client_id='BOB')
        codes = [a['code'] for a in actions]
        self.assertIn('SEND_CLAIM_B', codes)
        self.assertNotIn('SEND_CLAIM_A', codes)

    def test_compute_next_actions_completed_fee_pending(self):
        swap = {
            'swap_id': 'swap_3',
            'state': oe.SWAP_STATE_COMPLETED,
            'metadata': {'peer_a': 'ALICE', 'peer_b': 'BOB'}
        }
        invoice = {'payment_status': 'pending'}
        actions = oe.compute_next_actions(swap=swap, fee_invoice=invoice, client_id='ALICE')
        codes = [a['code'] for a in actions]
        self.assertIn('CONFIRM_FEE', codes)
        self.assertNotIn('ISSUE_FEE', codes)

    def test_compute_next_actions_completed_without_invoice(self):
        swap = {
            'swap_id': 'swap_4',
            'state': oe.SWAP_STATE_COMPLETED,
            'metadata': {'peer_a': 'ALICE', 'peer_b': 'BOB'}
        }
        actions = oe.compute_next_actions(swap=swap, fee_invoice=None, client_id='ALICE')
        codes = [a['code'] for a in actions]
        self.assertIn('ISSUE_FEE', codes)


if __name__ == '__main__':
    unittest.main()
