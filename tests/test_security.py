import os
import json
import time
import tempfile
import unittest

import oneseam as oe

try:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except Exception:
    jwt = None

class TestJWT(unittest.TestCase):
    def setUp(self):
        if jwt is None:
            self.skipTest('PyJWT not available')
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.private_pem = private_pem
        oe.JWT_PUBLIC_KEY_CACHE = [public_pem]
        oe.JWT_ISSUER = 'oneseam'
        oe.JWT_AUDIENCE = 'oneseam-api'

    def test_auth_jwt_valid(self):
        token = jwt.encode(
            {'sub':'BANK_ALPHA','roles':['issuer'],'scopes':['instruction:write'],
             'iss':'oneseam','aud':'oneseam-api','exp':int(time.time())+60},
            self.private_pem, algorithm='RS256')
        claims = oe._verify_jwt(token)
        self.assertEqual(claims['sub'], 'BANK_ALPHA')

    def test_auth_jwt_invalid_signature(self):
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = jwt.encode(
            {'sub':'BANK_ALPHA','roles':['issuer'],'scopes':['instruction:write'],
             'iss':'oneseam','aud':'oneseam-api','exp':int(time.time())+60},
            other_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8'),
            algorithm='RS256')
        with self.assertRaises(Exception):
            oe._verify_jwt(token)

    def test_auth_jwt_expired(self):
        token = jwt.encode(
            {'sub':'BANK_ALPHA','roles':['issuer'],'scopes':['instruction:write'],
             'iss':'oneseam','aud':'oneseam-api','exp':int(time.time())-1},
            self.private_pem, algorithm='RS256')
        with self.assertRaises(Exception):
            oe._verify_jwt(token)

class TestAuditLog(unittest.TestCase):
    def test_audit_log_hash_chain(self):
        tmp_root = os.path.join(os.getcwd(), '.tmp_tests')
        os.makedirs(tmp_root, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=tmp_root) as d:
            oe.KEY_PROVIDER = oe.LocalKeyProvider(os.path.join(d, 'keys.json'))
            oe.STORAGE_DB = oe.StorageDB('sqlite', os.path.join(d, 'oneseam.db'), '')
            oe.STORAGE_DB.connect()
            oe.STORAGE_DB.init_schema()
            oe.node_id = 'TEST_NODE'
            oe.append_audit_event('test_event', 'tester', 'instr_1', {'x':1}, 'req1')
            oe.append_audit_event('test_event', 'tester', 'instr_1', {'x':2}, 'req2')
            events = oe.STORAGE_DB.list_audit_events()
            self.assertEqual(len(events), 2)
            self.assertEqual(events[1].get('prev_hash'), events[0].get('hash'))
            oe.STORAGE_DB.close()

if __name__ == '__main__':
    unittest.main()
