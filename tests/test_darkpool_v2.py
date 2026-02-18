import os
import tempfile
import unittest

import oneseam as oe


class TestDarkPoolV2Flow(unittest.TestCase):
    def setUp(self):
        if not oe.EVM_SIGNATURE_AVAILABLE:
            self.skipTest('EVM signature support not available')

        tmp_root = os.path.join(os.getcwd(), '.tmp_tests')
        os.makedirs(tmp_root, exist_ok=True)
        self.tmpdir = tempfile.TemporaryDirectory(dir=tmp_root)
        self.addCleanup(self.tmpdir.cleanup)

        self.prev_storage = oe.STORAGE_DB
        self.prev_key_provider = oe.KEY_PROVIDER
        self.prev_node_id = oe.node_id
        self.prev_intent_max_notional = oe.INTENT_MAX_NOTIONAL
        self.prev_wallet_attestation_required = oe.WALLET_ATTESTATION_REQUIRED
        self.prev_proof_wallet_attestation_required = oe.PROOF_WALLET_ATTESTATION_REQUIRED
        self.prev_proof_server_side_verification_required = oe.PROOF_SERVER_SIDE_VERIFICATION_REQUIRED
        self.prev_proof_verifier_url = oe.PROOF_VERIFIER_URL

        oe.KEY_PROVIDER = oe.LocalKeyProvider(os.path.join(self.tmpdir.name, 'keys.json'))
        oe.STORAGE_DB = oe.StorageDB('sqlite', os.path.join(self.tmpdir.name, 'oneseam.db'), '')
        oe.STORAGE_DB.connect()
        oe.STORAGE_DB.init_schema()
        oe.node_id = 'TEST_NODE'

        oe.WALLET_ATTESTATION_REQUIRED = True
        oe.PROOF_WALLET_ATTESTATION_REQUIRED = True

        self.alice = {'client_id': 'ALICE', 'roles': ['issuer'], 'claims': {}}
        self.bob = {'client_id': 'BOB', 'roles': ['issuer'], 'claims': {}}

        self.alice_account = oe.Account.create()
        self.bob_account = oe.Account.create()
        self.alice_wallet = self.alice_account.address.lower()
        self.bob_wallet = self.bob_account.address.lower()

        oe.STORAGE_DB.bind_wallet('ALICE', self.alice_wallet, oe.EVM_CHAIN_ID)
        oe.STORAGE_DB.bind_wallet('BOB', self.bob_wallet, oe.EVM_CHAIN_ID)

    def tearDown(self):
        try:
            oe.STORAGE_DB.close()
        except Exception:
            pass
        oe.STORAGE_DB = self.prev_storage
        oe.KEY_PROVIDER = self.prev_key_provider
        oe.node_id = self.prev_node_id
        oe.INTENT_MAX_NOTIONAL = self.prev_intent_max_notional
        oe.WALLET_ATTESTATION_REQUIRED = self.prev_wallet_attestation_required
        oe.PROOF_WALLET_ATTESTATION_REQUIRED = self.prev_proof_wallet_attestation_required
        oe.PROOF_SERVER_SIDE_VERIFICATION_REQUIRED = self.prev_proof_server_side_verification_required
        oe.PROOF_VERIFIER_URL = self.prev_proof_verifier_url

    def _mk_exp(self, seconds=600):
        return int(oe.time.time() * 1000) + (seconds * 1000)

    def _sign_message(self, private_key, message_text):
        signed = oe.Account.sign_message(oe.encode_defunct(text=message_text), private_key=private_key)
        return signed.signature.hex()

    def _signed_intent_payload(self, client, account, sell_asset, buy_asset, amount, price_min, price_max):
        payload = {
            'maker_wallet': account.address.lower(),
            'sell_asset': sell_asset,
            'buy_asset': buy_asset,
            'amount': amount,
            'price_min': price_min,
            'price_max': price_max,
            'expiration': self._mk_exp(),
            'wallet_nonce': f"nonce_{client['client_id']}_{int(oe.time.time())}",
        }
        prepared = oe.prepare_trade_intent_signature(client, payload)
        payload['wallet_signature'] = self._sign_message(account.key, prepared['message'])
        return payload

    def _create_swap(self):
        oe.create_trade_intent(self.alice, self._signed_intent_payload(
            self.alice, self.alice_account, 'BTC', 'USDT', 1.0, 49000.0, 51000.0
        ))
        b = oe.create_trade_intent(self.bob, self._signed_intent_payload(
            self.bob, self.bob_account, 'USDT', 'BTC', 50000.0, 1 / 51000.0, 1 / 49000.0
        ))
        match_id = b['matches_detected'][0]
        return oe.open_secure_session(self.alice, match_id)['swap']['swap_id']

    def _signed_proof_payload(self, client, account, swap_id, proof_type, tx_hash, confirmations, secret=None):
        swap_obj = oe.get_swap_status(client, swap_id)
        payload = {
            'proof_type': proof_type,
            'tx_hash': tx_hash,
            'confirmations': confirmations,
            'secret': secret,
            'signer_wallet': account.address.lower(),
            'wallet_nonce': f"proof_{proof_type}_{int(oe.time.time())}",
            'metadata': {}
        }
        prepared = oe.prepare_htlc_proof_signature(client, swap_obj, payload, account.address.lower())
        payload['wallet_signature'] = self._sign_message(account.key, prepared['message'])
        return payload

    def test_intent_match_session_swap_completion_and_fee(self):
        a = oe.create_trade_intent(self.alice, self._signed_intent_payload(
            self.alice, self.alice_account, 'BTC', 'USDT', 1.0, 49000.0, 51000.0
        ), request_id='req_a')
        self.assertEqual(a['status'], oe.INTENT_STATUS_OPEN)

        b = oe.create_trade_intent(self.bob, self._signed_intent_payload(
            self.bob, self.bob_account, 'USDT', 'BTC', 50000.0, 1 / 51000.0, 1 / 49000.0
        ), request_id='req_b')

        self.assertTrue(b.get('matches_detected'))
        match_id = b['matches_detected'][0]
        opened = oe.open_secure_session(self.alice, match_id, request_id='req_sess')
        swap_id = opened['swap']['swap_id']

        oe.submit_htlc_proof(self.alice, swap_id, self._signed_proof_payload(
            self.alice, self.alice_account, swap_id, 'lock_a', '0x' + ('1' * 64), max(1, oe.HTLC_MIN_CONFIRMATIONS)
        ), request_id='req_lock_a')

        oe.submit_htlc_proof(self.bob, swap_id, self._signed_proof_payload(
            self.bob, self.bob_account, swap_id, 'lock_b', '0x' + ('2' * 64), max(1, oe.HTLC_MIN_CONFIRMATIONS)
        ), request_id='req_lock_b')

        oe.submit_htlc_proof(self.alice, swap_id, self._signed_proof_payload(
            self.alice, self.alice_account, swap_id, 'claim_a', '0x' + ('3' * 64), max(1, oe.HTLC_MIN_CONFIRMATIONS)
        ), request_id='req_claim_a')

        finished = oe.submit_htlc_proof(self.bob, swap_id, self._signed_proof_payload(
            self.bob, self.bob_account, swap_id, 'claim_b', '0x' + ('4' * 64), max(1, oe.HTLC_MIN_CONFIRMATIONS)
        ), request_id='req_claim_b')

        self.assertEqual(finished['swap']['state'], oe.SWAP_STATE_COMPLETED)
        self.assertIsNotNone(finished.get('fee_invoice'))

    def test_trade_intent_requires_wallet_signature(self):
        payload = {
            'maker_wallet': self.alice_wallet,
            'sell_asset': 'BTC',
            'buy_asset': 'USDT',
            'amount': 1.0,
            'price_min': 49000.0,
            'price_max': 51000.0,
            'expiration': self._mk_exp(),
            'wallet_nonce': 'missing_sig'
        }
        with self.assertRaises(ValueError) as exc:
            oe.create_trade_intent(self.alice, payload)
        self.assertEqual(str(exc.exception), 'wallet_signature_required')

    def test_trade_intent_notional_limit_rejected(self):
        oe.INTENT_MAX_NOTIONAL = 1000.0
        with self.assertRaises(ValueError) as exc:
            oe.create_trade_intent(self.alice, self._signed_intent_payload(
                self.alice, self.alice_account, 'BTC', 'USDT', 1.0, 49000.0, 51000.0
            ))
        self.assertEqual(str(exc.exception), 'notional_limit_exceeded')

    def test_proof_replay_rejected(self):
        swap_id = self._create_swap()
        tx_hash = '0x' + ('6' * 64)
        oe.submit_htlc_proof(self.alice, swap_id, self._signed_proof_payload(
            self.alice, self.alice_account, swap_id, 'lock_a', tx_hash, max(1, oe.HTLC_MIN_CONFIRMATIONS)
        ))
        with self.assertRaises(ValueError) as exc:
            oe.submit_htlc_proof(self.bob, swap_id, self._signed_proof_payload(
                self.bob, self.bob_account, swap_id, 'lock_b', tx_hash, max(1, oe.HTLC_MIN_CONFIRMATIONS)
            ))
        self.assertEqual(str(exc.exception), 'proof_replay_detected')

    def test_proof_side_enforcement(self):
        swap_id = self._create_swap()
        with self.assertRaises(PermissionError) as exc:
            oe.submit_htlc_proof(self.bob, swap_id, self._signed_proof_payload(
                self.bob, self.bob_account, swap_id, 'lock_a', '0x' + ('7' * 64), max(1, oe.HTLC_MIN_CONFIRMATIONS)
            ))
        self.assertEqual(str(exc.exception), 'actor_not_allowed_for_proof')

    def test_server_side_proof_verification_required(self):
        swap_id = self._create_swap()
        oe.PROOF_SERVER_SIDE_VERIFICATION_REQUIRED = True
        oe.PROOF_VERIFIER_URL = ''
        with self.assertRaises(RuntimeError) as exc:
            oe.submit_htlc_proof(self.alice, swap_id, self._signed_proof_payload(
                self.alice, self.alice_account, swap_id, 'lock_a', '0x' + ('8' * 64), max(1, oe.HTLC_MIN_CONFIRMATIONS)
            ))
        self.assertEqual(str(exc.exception), 'proof_verifier_missing')


if __name__ == '__main__':
    unittest.main()
