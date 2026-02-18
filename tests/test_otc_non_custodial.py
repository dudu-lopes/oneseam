import os
import tempfile
import unittest

import oneseam_enterprise as oe


class FakeEscrow:
    def prepare_action_payload(self, trade, action, timeout_seconds=None):
        ttl = int(timeout_seconds) if timeout_seconds else 600
        return {
            'to': '0x00000000000000000000000000000000000000aa',
            'data': '0xdeadbeef',
            'value': '0',
            'chain_id': oe.EVM_CHAIN_ID,
            'gas_hint': {'limit': 210000},
            'action': action,
            'trade_id': trade['trade_id'],
            'contract_name': 'OTCEscrow',
            'contract_version': '1.0.0',
            'contract_address': '0x00000000000000000000000000000000000000aa',
            'expires_at': int(oe.time.time() * 1000) + (ttl * 1000)
        }

    def verify_submitted_action(self, tx_hash, trade, action, escrow_trade_ref=None):
        tx = tx_hash.strip().lower()
        payload = {
            'tx_hash': tx,
            'verified': True,
            'block_number': 123,
            'confirmations': 3,
            'chain_id': oe.EVM_CHAIN_ID,
            'contract_address': '0x00000000000000000000000000000000000000aa',
            'event_name': oe.OTC_ACTION_EVENT_MAP[action],
            'event_args': {'tradeId': trade['trade_id']},
            'escrow_trade_ref': ''
        }
        if action == oe.OTC_ACTION_ESCROW_CREATE:
            payload['event_args']['escrowTradeRef'] = '0x' + ('ab' * 32)
            payload['escrow_trade_ref'] = payload['event_args']['escrowTradeRef']
        return payload


class TestOTCNonCustodialFlow(unittest.TestCase):
    def setUp(self):
        tmp_root = os.path.join(os.getcwd(), '.tmp_tests')
        os.makedirs(tmp_root, exist_ok=True)
        self.tmpdir = tempfile.TemporaryDirectory(dir=tmp_root)
        self.addCleanup(self.tmpdir.cleanup)

        self.prev_storage = oe.STORAGE_DB
        self.prev_key_provider = oe.KEY_PROVIDER
        self.prev_escrow = oe.OTC_ESCROW
        self.prev_node_id = oe.node_id

        oe.KEY_PROVIDER = oe.LocalKeyProvider(os.path.join(self.tmpdir.name, 'keys.json'))
        oe.STORAGE_DB = oe.StorageDB('sqlite', os.path.join(self.tmpdir.name, 'oneseam.db'), '')
        oe.STORAGE_DB.connect()
        oe.STORAGE_DB.init_schema()
        oe.OTC_ESCROW = FakeEscrow()
        oe.node_id = 'TEST_NODE'

        self.client = {'client_id': 'BANK_ALPHA', 'roles': ['admin'], 'claims': {}}
        self.trade_id = 'trade_test_001'
        oe.STORAGE_DB.create_trade({
            'trade_id': self.trade_id,
            'rfq_id': '',
            'buyer_client_id': 'BANK_ALPHA',
            'seller_client_id': 'BANK_BETA',
            'buyer_wallet': '0x0000000000000000000000000000000000000001',
            'seller_wallet': '0x0000000000000000000000000000000000000002',
            'base_asset': 'BTC',
            'quote_asset': 'USDT',
            'base_amount': 1.0,
            'quote_amount': 1000.0,
            'status': oe.TRADE_STATUS_CREATED,
            'fee_bps': 20,
            'fee_amount': 2.0,
            'fee_asset': 'USDT',
            'escrow_chain_id': oe.EVM_CHAIN_ID,
            'escrow_factory': '0x00000000000000000000000000000000000000aa',
            'escrow_trade_ref': '',
            'escrow_tx_hashes': [],
            'private_instruction_id': '',
            'metadata': {}
        })

    def tearDown(self):
        try:
            oe.STORAGE_DB.close()
        except Exception:
            pass
        oe.STORAGE_DB = self.prev_storage
        oe.KEY_PROVIDER = self.prev_key_provider
        oe.OTC_ESCROW = self.prev_escrow
        oe.node_id = self.prev_node_id

    def test_prepare_creates_intent(self):
        prepared = oe.otc_prepare_escrow(self.client, self.trade_id, timeout_seconds=120, request_id='req_prepare')
        self.assertTrue(prepared.get('intent_id', '').startswith('intent_'))
        self.assertEqual(prepared.get('action'), oe.OTC_ACTION_ESCROW_CREATE)
        intent = oe.STORAGE_DB.get_onchain_intent(prepared['intent_id'])
        self.assertIsNotNone(intent)
        self.assertEqual(intent.get('status'), 'prepared')

    def test_submit_escrow_confirms_intent_and_updates_trade(self):
        prepared = oe.otc_prepare_escrow(self.client, self.trade_id, timeout_seconds=120, request_id='req_prepare')
        tx_hash = '0x' + ('1' * 64)
        trade = oe.otc_create_escrow(
            self.client,
            self.trade_id,
            tx_hash=tx_hash,
            intent_id=prepared['intent_id'],
            request_id='req_submit'
        )
        self.assertEqual(trade.get('status'), oe.TRADE_STATUS_ESCROW_CREATED)
        intent = oe.STORAGE_DB.get_onchain_intent(prepared['intent_id'])
        self.assertEqual(intent.get('status'), 'confirmed')

    def test_replay_tx_hash_is_blocked(self):
        prepared = oe.otc_prepare_escrow(self.client, self.trade_id, request_id='req_prepare')
        tx_hash = '0x' + ('2' * 64)
        oe.otc_create_escrow(self.client, self.trade_id, tx_hash=tx_hash, intent_id=prepared['intent_id'], request_id='req_submit')
        with self.assertRaises(ValueError) as exc:
            oe.otc_create_escrow(self.client, self.trade_id, tx_hash=tx_hash, request_id='req_replay')
        self.assertEqual(str(exc.exception), 'tx_hash_reused')

    def test_settle_requires_escrow_state(self):
        tx_hash = '0x' + ('3' * 64)
        with self.assertRaises(ValueError) as exc:
            oe.otc_settle_trade(self.client, self.trade_id, tx_hash=tx_hash, request_id='req_settle')
        self.assertEqual(str(exc.exception), 'trade_not_settle_ready')


if __name__ == '__main__':
    unittest.main()
