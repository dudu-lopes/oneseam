import unittest
from unittest.mock import patch

import oneseam_simple_cli as simple_cli


class DummyAdapter:
    def __init__(self):
        self.status_calls = 0

    def node_status(self):
        self.status_calls += 1

    def post_order(self, payload, actor_ctx):
        return {'intent_id': 'intent_1', 'matches_detected': []}

    def list_matches(self, actor_ctx):
        return []

    def accept_match_and_start(self, match_id, actor_ctx):
        return {'match_id': match_id, 'session': {}, 'swap': {}}

    def list_orders(self, actor_ctx):
        return {'intents': [], 'matches': [], 'swaps': [], 'fee_invoices': {}}

    def compute_next_actions(self, **kwargs):
        return []

    def execute_next_action(self, action, actor_ctx, source='simple_cli'):
        return True


class TestSimpleCliModule(unittest.TestCase):
    def test_quick_access_zero_triggers_node_status(self):
        adapter = DummyAdapter()
        with patch('builtins.input', side_effect=['0', '6']):
            with self.assertRaises(SystemExit):
                simple_cli.run_simple_cli(adapter)
        self.assertEqual(adapter.status_calls, 1)


if __name__ == '__main__':
    unittest.main()
