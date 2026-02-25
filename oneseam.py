# Copyright (c) 2026 Eduardo de Figueiredo.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
ONESEAM - DarkPool P2P Non-Custodial Trading Coordination
Version: 3.2.0

Enterprise-grade decentralized coordination with privacy-preserving transport.
- Byzantine fault-tolerant (configurable k-of-n quorum)
- Shamir Secret Sharing (zero-knowledge sharding)
- Trade Intent/Match/Session lifecycle with HTLC coordination
- Blind Relay (Repasse Cego) - nodes accept and relay shards toward destination
- AES-256-GCM encryption
- On-grid / off-grid mesh network capable
- REST API for enterprise integration

Non-custodial by design: the node never signs, executes, or custody-holds client funds.
"""

import os
import sys
import threading
import asyncio
import sqlite3
import socket
import json
import time
import uuid
import base64
import signal
import secrets
import ssl
import hmac
import hashlib
import math
import urllib.request
import urllib.error
import uuid as uuid_lib
from hashlib import sha256
from typing import List, Optional, Dict, Tuple, Any, Literal
from itertools import combinations

# Shamir Secret Sharing (PyCryptodome)
try:
    from Crypto.Random import get_random_bytes
    from Crypto.Cipher import AES
    try:
        from Crypto.Protocol.SecretSharing import Shamir
        SSS_AVAILABLE = True
    except (ImportError, AttributeError):
        SSS_AVAILABLE = False
except ImportError:
    SSS_AVAILABLE = False
    get_random_bytes = None

# ===== ENTERPRISE ENCRYPTION (AES-256-GCM) =====
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[WARNING] cryptography library not found. Install: pip install cryptography")
    print("[WARNING] Encryption disabled until cryptography is installed.")

# JWT
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

# Async HTTP
try:
    import aiohttp
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

# Web3 (EVM escrow integration)
try:
    from web3 import Web3
    from eth_account import Account
    from eth_account.messages import encode_defunct
    WEB3_AVAILABLE = True
    EVM_SIGNATURE_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False
    EVM_SIGNATURE_AVAILABLE = False
    Account = None
    encode_defunct = None

# Pydantic validation
try:
    from pydantic import BaseModel, ValidationError, Field
    from pydantic import ConfigDict
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False

# Blind matching primitives (optional local module)
try:
    from oneseam_blind_matching import (
        DEFAULT_GLOBAL_SALT as BLIND_DEFAULT_GLOBAL_SALT,
        build_blind_commitment_meta,
        blind_overlap_tokens,
        build_public_blind_commitment
    )
    BLIND_MATCHING_AVAILABLE = True
except ImportError:
    BLIND_MATCHING_AVAILABLE = False
    BLIND_DEFAULT_GLOBAL_SALT = "ONESEAM_BLIND_MATCHING_V1_PRICE_SLOTS"

    def build_blind_commitment_meta(*args, **kwargs):
        raise RuntimeError("blind_matching_module_unavailable")

    def blind_overlap_tokens(meta_a, meta_b):
        return None

    def build_public_blind_commitment(intent, commitment_meta):
        return {}

if PYDANTIC_AVAILABLE:
    class P2PStoreShard(BaseModel):
        model_config = ConfigDict(extra='forbid')
        cmd: Literal['STORE_SHARD']
        shard_name: str
        shard_data: str
        shard_dict: Optional[Dict[str, Any]] = None
        instruction_id: Optional[str] = None
        destination: Optional[str] = ''
        data_region: Optional[str] = ''
        relay_hops: int = 0
        signature: Optional[str] = ''
        sender_id: Optional[str] = ''
    
    class P2PStoreManifest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        cmd: Literal['STORE_MANIFEST']
        instruction_id: str
        manifest: Dict[str, Any]
    
    class P2PFetchShard(BaseModel):
        model_config = ConfigDict(extra='forbid')
        cmd: Literal['FETCH_SHARD']
        shard_name: str
    
    class P2PFetchManifest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        cmd: Literal['FETCH_MANIFEST']
        instruction_id: str
    
    class P2PHealth(BaseModel):
        model_config = ConfigDict(extra='forbid')
        cmd: Literal['HEALTH_CHECK']
    
    class P2PHandshake(BaseModel):
        model_config = ConfigDict(extra='forbid')
        cmd: Literal['HANDSHAKE']
        node_id: str
        node_port: int
        capabilities: List[str]
        version: str
        transport_mode: str
        region: Optional[str] = ''
        country_code: Optional[str] = ''
        served_destinations: List[str] = Field(default_factory=list)
        node_signing_pub: Optional[str] = ''

    class WalletBindRequest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        wallet_address: str
        chain_id: Optional[int] = None

    class OTCRFQCreateRequest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        maker_wallet: str
        base_asset: str
        quote_asset: str
        base_amount: float
        quote_amount: float
        maker_side: Literal['buy', 'sell'] = 'sell'
        taker_client_id: Optional[str] = None
        expires_in_seconds: int = 900
        metadata: Optional[Dict[str, Any]] = None
        private_terms: Optional[Dict[str, Any]] = None

    class OTCRFQAcceptRequest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        taker_wallet: str

    class OTCTradeCreateRequest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        buyer_client_id: str
        buyer_wallet: str
        seller_client_id: str
        seller_wallet: str
        base_asset: str
        quote_asset: str
        base_amount: float
        quote_amount: float
        metadata: Optional[Dict[str, Any]] = None
        private_terms: Optional[Dict[str, Any]] = None

    class OTCTradeActionRequest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        tx_hash: str
        escrow_trade_ref: Optional[str] = None
        intent_id: Optional[str] = None

    class OTCPrepareRequest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        timeout_seconds: Optional[int] = None

    class TradeIntentCreateRequest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        maker_wallet: str
        sell_asset: str
        buy_asset: str
        amount: float
        price_min: float
        price_max: float
        expiration: int
        wallet_signature: Optional[str] = None
        wallet_nonce: Optional[str] = None
        metadata: Optional[Dict[str, Any]] = None
        private_terms: Optional[Dict[str, Any]] = None

    class HTLCProofRequest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        proof_type: Literal['lock_a', 'lock_b', 'claim_a', 'claim_b', 'refund_a', 'refund_b']
        tx_hash: str
        confirmations: int = 0
        secret: Optional[str] = None
        signer_wallet: Optional[str] = None
        wallet_signature: Optional[str] = None
        wallet_nonce: Optional[str] = None
        metadata: Optional[Dict[str, Any]] = None

    class FeeConfirmRequest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        payment_ref: str

def derive_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """Derive AES-256 key from password using PBKDF2HMAC"""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography is required for AES-256-GCM")
    
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_payload_aes256(data: str, password: str) -> str:
    """Encrypt with AES-256-GCM"""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography is required for AES-256-GCM")
    
    key, salt = derive_key_from_password(password)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    
    # Return: salt + nonce + ciphertext (need salt+nonce for decryption)
    return base64.b64encode(salt + nonce + ciphertext).decode()

def decrypt_payload_aes256(data: str, password: str) -> str:
    """Decrypt AES-256-GCM"""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography is required for AES-256-GCM")
    
    decoded = base64.b64decode(data.encode())
    if len(decoded) < 16 + 12:
        raise ValueError("Invalid encrypted payload")
    salt = decoded[:16]
    nonce = decoded[16:28]
    encrypted = decoded[28:]
    
    key, _ = derive_key_from_password(password, salt)
    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(nonce, encrypted, None)
    return decrypted.decode()

def generate_dna_hash(data: str) -> str:
    """Generate SHA-256 hash for integrity verification"""
    return sha256(data.encode()).hexdigest()

# ===== CONFIGURATIONS =====
# Load config file if exists
CONFIG = {}
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'oneseam_config.yaml')
if os.path.exists(CONFIG_PATH):
    try:
        import yaml
        with open(CONFIG_PATH) as f:
            CONFIG = yaml.safe_load(f) or {}
    except (ImportError, OSError, AttributeError, ValueError):
        pass

def _config(key: str, default: Any) -> Any:
    return CONFIG.get(key, default)

def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ('1', 'true', 'yes', 'on')
    return bool(value)

NODE_PORT = _config('node_port', 5001)
BROADCAST_PORT = _config('broadcast_port', 5002)
API_PORT = _config('api_port', 8000)
API_BIND = _config('api_bind', '127.0.0.1')
DB_BACKEND = _config('db_backend', 'sqlite')
DB_PATH = _config('db_path', 'oneseam.db')
DB_DSN = _config('db_dsn', '')
TLS_ENABLED = _as_bool(_config('tls_enabled', False))
TLS_CERT_PATH = _config('tls_cert_path', '')
TLS_KEY_PATH = _config('tls_key_path', '')
MTLS_CA_PATH = _config('mtls_ca_path', '')
MTLS_ALLOWED_CNS = _config('mtls_allowed_cns', []) or []
JWT_ISSUER = _config('jwt_issuer', '')
JWT_AUDIENCE = _config('jwt_audience', '')
JWT_PUBLIC_KEYS = _config('jwt_public_keys', []) or []
JWT_ALGORITHMS = _config('jwt_algorithms', ['RS256', 'ES256']) or ['RS256', 'ES256']
ALLOW_LEGACY_API_KEYS = _as_bool(_config('allow_legacy_api_keys', True))
API_MAX_PAYLOAD_BYTES = _config('api_max_payload_bytes', 1024 * 1024)
RATE_LIMIT_RPS = _config('rate_limit_rps', 5)
RATE_LIMIT_BURST = _config('rate_limit_burst', 10)
IDEMPOTENCY_TTL_SECONDS = _config('idempotency_ttl_seconds', 300)
IDEMPOTENCY_MAX_ENTRIES = _config('idempotency_max_entries', 10000)
P2P_TLS_ENABLED = _as_bool(_config('p2p_tls_enabled', False))
P2P_TLS_CERT_PATH = _config('p2p_tls_cert_path', '')
P2P_TLS_KEY_PATH = _config('p2p_tls_key_path', '')
P2P_MTLS_CA_PATH = _config('p2p_mtls_ca_path', '')
P2P_MTLS_ALLOWED_CNS = _config('p2p_mtls_allowed_cns', []) or []
P2P_MTLS_REQUIRED = _as_bool(_config('p2p_mtls_required', True))
P2P_RETRIES = _config('p2p_retries', 3)
P2P_BACKOFF_BASE = _config('p2p_backoff_base', 0.2)
SEED_NODES = _config('seed_nodes', []) or []
UPNP_ENABLED = _as_bool(_config('upnp_enabled', False))
SHARD_SIGNATURE_REQUIRED = _as_bool(_config('shard_signature_required', True))
SHARD_SIGNING_PRIVATE_KEY = _config('shard_signing_private_key', 'shard_signing_priv.pem')
SHARD_SIGNING_PUBLIC_KEY = _config('shard_signing_public_key', 'shard_signing_pub.pem')
TRUSTED_NODE_PUBKEYS = _config('trusted_node_pubkeys', {}) or {}
BROADCAST_ADDR = _config('broadcast_addr', '<broadcast>')
BUFFER_SIZE = 1024 * 1024  # 1MB
NODE_ID_FILE = 'node_id.txt'
LOCAL_TEST_MODE = ('--local-test' in sys.argv) or (os.environ.get('ONESEAM_LOCAL_TEST', '').strip().lower() in ('1', 'true', 'yes'))
CLI_ADMIN_UI_MODE = ('--admin-ui' in sys.argv) or (os.environ.get('ONESEAM_ADMIN_UI', '').strip().lower() in ('1', 'true', 'yes'))
CLI_ADVANCED_MODE = ('--advanced' in sys.argv) or (os.environ.get('ONESEAM_CLI_ADVANCED', '').strip().lower() in ('1', 'true', 'yes'))
CLI_MODE_OVERRIDE = (os.environ.get('ONESEAM_CLI_MODE', '').strip().lower() or '')
if '--mode' in sys.argv:
    try:
        mode_index = sys.argv.index('--mode')
        if mode_index + 1 < len(sys.argv):
            CLI_MODE_OVERRIDE = str(sys.argv[mode_index + 1]).strip().lower()
    except ValueError:
        pass
LOCAL_TEST_PORT_SCAN_SIZE = int(_config('local_test_port_scan_size', 20))
LOCAL_TEST_DISCOVERY_INTERVAL = float(_config('local_test_discovery_interval', 2.0))
LOCAL_TEST_REGISTRY_DIR = _config('local_test_registry_dir', '.oneseam_local')
LOCAL_TEST_REGISTRY_TTL_SECONDS = int(_config('local_test_registry_ttl_seconds', 90))
LOG_FILE = _config('log_file', '')
LOG_JSON = _as_bool(_config('log_json', True))
LOG_LEVEL = _config('log_level', 'INFO')
NEIGHBOR_TTL_SECONDS = _config('neighbor_ttl_seconds', 60)
METRICS_ENABLED = _as_bool(_config('metrics_enabled', True))
DEFAULT_QUORUM_K = _config('quorum_k', 2)
DEFAULT_QUORUM_N = _config('quorum_n', 3)
TRANSPORT_MODE = _config('transport_mode', 'HYBRID')  # ON_GRID, OFF_GRID, HYBRID
BLIND_RELAY_ENABLED = _as_bool(_config('blind_relay_enabled', True))
MAX_RELAY_HOPS = _config('max_relay_hops', 10)
SERVED_DESTINATIONS = _config('served_destinations', []) or []
BLIND_RELAY_FLOOD = _as_bool(_config('blind_relay_flood', False))
OTC_ENABLED = _as_bool(_config('otc_enabled', True))
EVM_RPC_URL = _config('evm_rpc_url', '')
EVM_CHAIN_ID = int(_config('evm_chain_id', 11155111))
ESCROW_CONTRACT_ADDRESS = _config('escrow_contract_address', _config('escrow_factory_address', ''))
ESCROW_CONTRACT_ABI_PATH = _config('escrow_contract_abi_path', 'contracts/abi/OTCEscrow.json')
ESCROW_CONTRACT_NAME = _config('escrow_contract_name', 'OTCEscrow')
ESCROW_CONTRACT_VERSION = _config('escrow_contract_version', '1.0.0')
ESCROW_CONFIRMATIONS_REQUIRED = int(_config('escrow_confirmations_required', 1))
ESCROW_VERIFY_ON_SUBMIT = _as_bool(_config('escrow_verify_on_submit', True))
ESCROW_PREPARE_TTL_SECONDS = int(_config('escrow_prepare_ttl_seconds', 600))
ESCROW_EVENT_STRICT_VALIDATION = _as_bool(_config('escrow_event_strict_validation', True))
ESCROW_RECONCILE_INTERVAL_SECONDS = int(_config('escrow_reconcile_interval_seconds', 20))
OTC_ASSETS = _config('otc_assets', {}) or {}
OTC_DEFAULT_FEE_BPS = int(_config('otc_default_fee_bps', 20))
OTC_MAX_TRADE_NOTIONAL = float(_config('otc_max_trade_notional', 10_000_000))
WALLET_BINDING_REQUIRED = _as_bool(_config('wallet_binding_required', True))
ALLOWED_BASE_ASSETS = set((_config('allowed_base_assets', ['BTC', 'ETH', 'USDT']) or []))
ALLOWED_QUOTE_ASSETS = set((_config('allowed_quote_assets', ['USDT', 'USDC', 'USD']) or []))
# Backward compatibility for legacy variable name used across older code paths.
ESCROW_FACTORY_ADDRESS = ESCROW_CONTRACT_ADDRESS

# Dark-pool v2 (trade intents + private matching + HTLC coordination)
DARKPOOL_ENABLED = _as_bool(_config('darkpool_enabled', True))
LEGACY_OTC_API_ENABLED = _as_bool(_config('legacy_otc_api_enabled', True))
INTENT_BUCKET_SIZE_PRICE = float(_config('intent_bucket_size_price', 100.0))
INTENT_BUCKET_SIZE_AMOUNT = float(_config('intent_bucket_size_amount', 0.1))
BLIND_MATCHING_ENABLED = _as_bool(_config('blind_matching_enabled', True))
BLIND_PRICE_SLOT_SIZE = float(_config('blind_price_slot_size', _config('price_slot_size', INTENT_BUCKET_SIZE_PRICE)))
BLIND_MAX_PRICE_SLOTS = int(_config('blind_max_price_slots', 2048))
BLIND_GLOBAL_SALT = str(_config('blind_global_salt', BLIND_DEFAULT_GLOBAL_SALT))
BLIND_COMMITMENT_DESTINATION = str(_config('blind_commitment_destination', 'blind_orderbook') or 'blind_orderbook').strip()
SESSION_HANDSHAKE_TTL_SECONDS = int(_config('session_handshake_ttl_seconds', 600))
HTLC_CHAIN_A = _config('htlc_chain_a', 'BTC')
HTLC_CHAIN_B = _config('htlc_chain_b', 'LIGHTNING')
HTLC_MIN_CONFIRMATIONS = int(_config('htlc_min_confirmations', 1))
HTLC_TIMEOUT_LOCK_A_SECONDS = int(_config('htlc_timeout_lock_a_seconds', 7200))
HTLC_TIMEOUT_LOCK_B_SECONDS = int(_config('htlc_timeout_lock_b_seconds', 3600))
FEE_BPS = int(_config('fee_bps', 1))  # 0.01%
FEE_LIGHTNING_ENDPOINT = _config('fee_lightning_endpoint', '')
INTENT_MIN_EXPIRATION_SECONDS = int(_config('intent_min_expiration_seconds', 30))
INTENT_MAX_EXPIRATION_SECONDS = int(_config('intent_max_expiration_seconds', 86400))
INTENT_MAX_NOTIONAL = float(_config('intent_max_notional', OTC_MAX_TRADE_NOTIONAL))
COUNTERPARTY_ALLOWLIST = _config('counterparty_allowlist', {}) or {}
SWAP_ENFORCE_SIDE_PROOFS = _as_bool(_config('swap_enforce_side_proofs', True))
SWAP_TIMEOUT_SWEEP_INTERVAL_SECONDS = int(_config('swap_timeout_sweep_interval_seconds', 5))
WALLET_ATTESTATION_REQUIRED = _as_bool(_config('wallet_attestation_required', True))
PROOF_WALLET_ATTESTATION_REQUIRED = _as_bool(_config('proof_wallet_attestation_required', True))
PRODUCTION_MODE = _as_bool(_config('production_mode', False))
PROOF_SERVER_SIDE_VERIFICATION_REQUIRED = _as_bool(_config('proof_server_side_verification_required', False))
PROOF_VERIFIER_URL = (_config('proof_verifier_url', '') or '').strip()
PROOF_VERIFIER_AUTH_TOKEN = (_config('proof_verifier_auth_token', '') or '').strip()
PROOF_VERIFIER_TIMEOUT_SECONDS = int(_config('proof_verifier_timeout_seconds', 8))
BTC_RPC_URL = (_config('btc_rpc_url', '') or '').strip()
BTC_RPC_USER = (_config('btc_rpc_user', '') or '').strip()
BTC_RPC_PASSWORD = (_config('btc_rpc_password', '') or '').strip()
BTC_RPC_TIMEOUT_SECONDS = int(_config('btc_rpc_timeout_seconds', 8))

# Protocol commands
CMD_HANDSHAKE = 'HANDSHAKE'
CMD_STORE_SHARD = 'STORE_SHARD'
CMD_STORE_MANIFEST = 'STORE_MANIFEST'
CMD_FETCH_SHARD = 'FETCH_SHARD'
CMD_FETCH_MANIFEST = 'FETCH_MANIFEST'
CMD_HEALTH_CHECK = 'HEALTH_CHECK'
APP_VERSION = '3.2.0'

# OTC states
RFQ_STATUS_OPEN = 'RFQ_OPEN'
RFQ_STATUS_ACCEPTED = 'RFQ_ACCEPTED'
RFQ_STATUS_CANCELLED = 'CANCELLED'
RFQ_STATUS_EXPIRED = 'EXPIRED'
TRADE_STATUS_CREATED = 'CREATED'
TRADE_STATUS_ESCROW_CREATED = 'ESCROW_CREATED'
TRADE_STATUS_FUNDED = 'FUNDED'
TRADE_STATUS_SETTLED = 'SETTLED'
TRADE_STATUS_REFUNDED = 'REFUNDED'
TRADE_STATUS_CANCELLED = 'CANCELLED'
TRADE_STATUS_EXPIRED = 'EXPIRED'
OTC_ACTION_ESCROW_CREATE = 'escrow_create'
OTC_ACTION_SETTLE = 'settle'
OTC_ACTION_REFUND = 'refund'
OTC_ACTION_EVENT_MAP = {
    OTC_ACTION_ESCROW_CREATE: 'TradeCreated',
    OTC_ACTION_SETTLE: 'TradeSettled',
    OTC_ACTION_REFUND: 'TradeRefunded'
}
OTC_ACTION_EVENT_TYPE_MAP = {
    OTC_ACTION_ESCROW_CREATE: 'escrow_created',
    OTC_ACTION_SETTLE: 'trade_settled',
    OTC_ACTION_REFUND: 'trade_refunded'
}
OTC_ACTION_NEXT_STATE = {
    OTC_ACTION_ESCROW_CREATE: TRADE_STATUS_ESCROW_CREATED,
    OTC_ACTION_SETTLE: TRADE_STATUS_SETTLED,
    OTC_ACTION_REFUND: TRADE_STATUS_REFUNDED
}
OTC_ALLOWED_STATE_TRANSITIONS = {
    OTC_ACTION_ESCROW_CREATE: {TRADE_STATUS_CREATED},
    OTC_ACTION_SETTLE: {TRADE_STATUS_ESCROW_CREATED, TRADE_STATUS_FUNDED},
    OTC_ACTION_REFUND: {TRADE_STATUS_ESCROW_CREATED, TRADE_STATUS_FUNDED}
}
OTC_ACTION_INVALID_STATE_ERROR = {
    OTC_ACTION_ESCROW_CREATE: 'trade_not_in_escrow_creatable_state',
    OTC_ACTION_SETTLE: 'trade_not_settle_ready',
    OTC_ACTION_REFUND: 'trade_not_refundable'
}

# Dark-pool statuses
INTENT_STATUS_OPEN = 'OPEN'
INTENT_STATUS_MATCHED = 'MATCHED'
INTENT_STATUS_CANCELLED = 'CANCELLED'
INTENT_STATUS_EXPIRED = 'EXPIRED'
MATCH_STATUS_FOUND = 'FOUND'
MATCH_STATUS_SESSION_OPEN = 'SESSION_OPEN'
MATCH_STATUS_SETTLED = 'SETTLED'
MATCH_STATUS_CANCELLED = 'CANCELLED'
SESSION_STATUS_OPEN = 'OPEN'
SESSION_STATUS_CLOSED = 'CLOSED'
SWAP_STATE_INIT = 'SWAP_INIT'
SWAP_STATE_WAIT_LOCK_A = 'WAIT_LOCK_A'
SWAP_STATE_WAIT_LOCK_B = 'WAIT_LOCK_B'
SWAP_STATE_READY_CLAIM = 'READY_CLAIM'
SWAP_STATE_CLAIMED_A = 'CLAIMED_A'
SWAP_STATE_CLAIMED_B = 'CLAIMED_B'
SWAP_STATE_COMPLETED = 'COMPLETED'
SWAP_STATE_REFUNDED = 'REFUNDED'
SWAP_STATE_FAILED = 'FAILED'

# Node state
node_id = None
neighbors = {}
neighbors_lock = threading.Lock()
QUIET_MODE = True  # Set to True to suppress RELAY logs
ASYNC_LOOP = None
RELAY_QUEUE = asyncio.Queue()

if BLIND_MATCHING_ENABLED and not BLIND_MATCHING_AVAILABLE:
    print("[WARNING] blind matching enabled but oneseam_blind_matching.py is not available.")

def run_async(coro):
    global ASYNC_LOOP
    try:
        loop = ASYNC_LOOP
        if loop and loop.is_running():
            fut = asyncio.run_coroutine_threadsafe(coro, loop)
            return fut.result()
    except RuntimeError:
        pass
    return asyncio.run(coro)

# Enterprise API keys (in production: secure storage)
def _load_api_keys() -> Dict[str, Dict[str, str]]:
    config_keys = _config('api_keys', None)
    if isinstance(config_keys, dict):
        return config_keys
    
    env_raw = os.environ.get('ONESEAM_API_KEYS_JSON', '').strip()
    if not env_raw:
        return {}
    try:
        env_keys = json.loads(env_raw)
        if isinstance(env_keys, dict):
            return env_keys
    except json.JSONDecodeError:
        print("[API] Invalid ONESEAM_API_KEYS_JSON; expected JSON object.")
    return {}

API_KEYS = _load_api_keys()

# ===== STORAGE (DATABASE) =====
class StorageDB:
    def __init__(self, backend: str, path: str, dsn: str):
        self.backend = backend
        self.path = path
        self.dsn = dsn
        self.lock = threading.Lock()
        self.conn = None
    
    def connect(self):
        if self.conn:
            return
        if self.backend == 'sqlite':
            self.conn = sqlite3.connect(self.path, check_same_thread=False)
            self.conn.execute('PRAGMA journal_mode=WAL;')
            self.conn.execute('PRAGMA synchronous=FULL;')
            self.conn.execute('PRAGMA foreign_keys=ON;')
        elif self.backend == 'postgres':
            try:
                import psycopg2
            except ImportError:
                raise RuntimeError('psycopg2 required for postgres backend')
            self.conn = psycopg2.connect(self.dsn)
            self.conn.autocommit = True
        else:
            raise RuntimeError(f'Unsupported db_backend: {self.backend}')
    
    def init_schema(self):
        with self.lock:
            cur = self.conn.cursor()
            if self.backend == 'sqlite':
                cur.execute("""
                CREATE TABLE IF NOT EXISTS shards (
                    shard_name TEXT PRIMARY KEY,
                    instruction_id TEXT,
                    shard_index INTEGER,
                    replica INTEGER,
                    data TEXT,
                    share TEXT,
                    signature TEXT,
                    sender_id TEXT,
                    destination TEXT,
                    data_region TEXT,
                    relay_hops INTEGER,
                    received_at INTEGER,
                    created_at INTEGER
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_shards_instruction ON shards(instruction_id)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS manifests (
                    instruction_id TEXT PRIMARY KEY,
                    manifest_json TEXT NOT NULL,
                    created_at INTEGER
                )
                """)
                cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    event_id TEXT PRIMARY KEY,
                    timestamp INTEGER,
                    actor TEXT,
                    node_id TEXT,
                    instruction_id TEXT,
                    event_type TEXT,
                    details_json TEXT,
                    request_id TEXT,
                    prev_hash TEXT,
                    hash TEXT,
                    signature TEXT,
                    key_id TEXT,
                    key_version INTEGER
                )
                """)
                cur.execute("""
                CREATE TABLE IF NOT EXISTS wallet_bindings (
                    client_id TEXT,
                    wallet_address TEXT,
                    chain_id INTEGER,
                    status TEXT,
                    created_at INTEGER,
                    PRIMARY KEY (client_id, wallet_address, chain_id)
                )
                """)
                cur.execute("""
                CREATE TABLE IF NOT EXISTS rfqs (
                    rfq_id TEXT PRIMARY KEY,
                    maker_client_id TEXT,
                    maker_wallet TEXT,
                    taker_client_id TEXT,
                    maker_side TEXT,
                    base_asset TEXT,
                    quote_asset TEXT,
                    base_amount REAL,
                    quote_amount REAL,
                    price REAL,
                    expires_at INTEGER,
                    status TEXT,
                    metadata_json TEXT,
                    private_instruction_id TEXT,
                    created_at INTEGER,
                    updated_at INTEGER
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_rfqs_status ON rfqs(status)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS trades (
                    trade_id TEXT PRIMARY KEY,
                    rfq_id TEXT,
                    buyer_client_id TEXT,
                    seller_client_id TEXT,
                    buyer_wallet TEXT,
                    seller_wallet TEXT,
                    base_asset TEXT,
                    quote_asset TEXT,
                    base_amount REAL,
                    quote_amount REAL,
                    status TEXT,
                    fee_bps INTEGER,
                    fee_amount REAL,
                    fee_asset TEXT,
                    escrow_chain_id INTEGER,
                    escrow_factory TEXT,
                    escrow_trade_ref TEXT,
                    escrow_tx_hashes_json TEXT,
                    private_instruction_id TEXT,
                    metadata_json TEXT,
                    created_at INTEGER,
                    updated_at INTEGER
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_trades_status ON trades(status)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS escrow_events (
                    event_id TEXT PRIMARY KEY,
                    trade_id TEXT,
                    event_type TEXT,
                    intent_id TEXT,
                    contract_address TEXT,
                    event_name TEXT,
                    tx_hash TEXT,
                    block_number INTEGER,
                    confirmations INTEGER DEFAULT 0,
                    chain_id INTEGER,
                    verified INTEGER DEFAULT 0,
                    payload_json TEXT,
                    created_at INTEGER
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_escrow_events_trade ON escrow_events(trade_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_escrow_events_tx ON escrow_events(tx_hash)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS onchain_intents (
                    intent_id TEXT PRIMARY KEY,
                    trade_id TEXT,
                    action TEXT,
                    expected_event TEXT,
                    prepared_payload_json TEXT,
                    tx_hash TEXT,
                    status TEXT,
                    expires_at INTEGER,
                    created_at INTEGER,
                    updated_at INTEGER
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_onchain_intents_trade_action ON onchain_intents(trade_id, action)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_onchain_intents_status ON onchain_intents(status)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS trade_fee_events (
                    event_id TEXT PRIMARY KEY,
                    trade_id TEXT,
                    client_id TEXT,
                    fee_bps INTEGER,
                    notional_amount REAL,
                    fee_amount REAL,
                    asset TEXT,
                    status TEXT,
                    created_at INTEGER
                )
                """)
                cur.execute("""
                CREATE TABLE IF NOT EXISTS trade_intents (
                    intent_id TEXT PRIMARY KEY,
                    maker_client_id TEXT,
                    maker_wallet TEXT,
                    sell_asset TEXT,
                    buy_asset TEXT,
                    amount REAL,
                    price_min REAL,
                    price_max REAL,
                    expiration INTEGER,
                    commitment_meta_json TEXT,
                    private_instruction_id TEXT,
                    status TEXT,
                    metadata_json TEXT,
                    created_at INTEGER,
                    updated_at INTEGER
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_trade_intents_status ON trade_intents(status)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_trade_intents_pair ON trade_intents(sell_asset, buy_asset)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS intent_shards_index (
                    intent_id TEXT,
                    instruction_id TEXT,
                    manifest_id TEXT,
                    created_at INTEGER,
                    PRIMARY KEY (intent_id, instruction_id)
                )
                """)
                cur.execute("""
                CREATE TABLE IF NOT EXISTS matches (
                    match_id TEXT PRIMARY KEY,
                    intent_sell_id TEXT,
                    intent_buy_id TEXT,
                    overlap_min REAL,
                    overlap_max REAL,
                    amount REAL,
                    confidence REAL,
                    status TEXT,
                    metadata_json TEXT,
                    created_at INTEGER,
                    updated_at INTEGER
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_matches_status ON matches(status)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS secure_sessions (
                    session_id TEXT PRIMARY KEY,
                    match_id TEXT,
                    peer_a TEXT,
                    peer_b TEXT,
                    noise_handshake_state_json TEXT,
                    expires_at INTEGER,
                    status TEXT,
                    created_at INTEGER,
                    updated_at INTEGER
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_secure_sessions_match ON secure_sessions(match_id)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS swap_coordination (
                    swap_id TEXT PRIMARY KEY,
                    match_id TEXT,
                    secret_hash TEXT,
                    htlc_a_json TEXT,
                    htlc_b_json TEXT,
                    state TEXT,
                    timeouts_json TEXT,
                    proofs_json TEXT,
                    completed_at INTEGER,
                    metadata_json TEXT,
                    created_at INTEGER,
                    updated_at INTEGER
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_swap_coordination_match ON swap_coordination(match_id)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS htlc_proofs (
                    proof_id TEXT PRIMARY KEY,
                    swap_id TEXT,
                    proof_type TEXT,
                    tx_hash TEXT,
                    confirmations INTEGER,
                    secret TEXT,
                    metadata_json TEXT,
                    created_at INTEGER
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_htlc_proofs_swap ON htlc_proofs(swap_id)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS fee_invoices (
                    invoice_id TEXT PRIMARY KEY,
                    swap_id TEXT,
                    fee_bps INTEGER,
                    fee_amount REAL,
                    fee_asset TEXT,
                    invoice_ref TEXT,
                    payment_status TEXT,
                    payment_ref TEXT,
                    created_at INTEGER,
                    updated_at INTEGER
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_fee_invoices_swap ON fee_invoices(swap_id)")
                self.conn.commit()
            else:
                cur.execute("""
                CREATE TABLE IF NOT EXISTS shards (
                    shard_name TEXT PRIMARY KEY,
                    instruction_id TEXT,
                    shard_index INTEGER,
                    replica INTEGER,
                    data TEXT,
                    share TEXT,
                    signature TEXT,
                    sender_id TEXT,
                    destination TEXT,
                    data_region TEXT,
                    relay_hops INTEGER,
                    received_at INTEGER,
                    created_at INTEGER
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_shards_instruction ON shards(instruction_id)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS manifests (
                    instruction_id TEXT PRIMARY KEY,
                    manifest_json TEXT NOT NULL,
                    created_at INTEGER
                )
                """)
                cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    event_id TEXT PRIMARY KEY,
                    timestamp INTEGER,
                    actor TEXT,
                    node_id TEXT,
                    instruction_id TEXT,
                    event_type TEXT,
                    details_json TEXT,
                    request_id TEXT,
                    prev_hash TEXT,
                    hash TEXT,
                    signature TEXT,
                    key_id TEXT,
                    key_version INTEGER
                )
                """)
                cur.execute("""
                CREATE TABLE IF NOT EXISTS wallet_bindings (
                    client_id TEXT,
                    wallet_address TEXT,
                    chain_id INTEGER,
                    status TEXT,
                    created_at INTEGER,
                    PRIMARY KEY (client_id, wallet_address, chain_id)
                )
                """)
                cur.execute("""
                CREATE TABLE IF NOT EXISTS rfqs (
                    rfq_id TEXT PRIMARY KEY,
                    maker_client_id TEXT,
                    maker_wallet TEXT,
                    taker_client_id TEXT,
                    maker_side TEXT,
                    base_asset TEXT,
                    quote_asset TEXT,
                    base_amount DOUBLE PRECISION,
                    quote_amount DOUBLE PRECISION,
                    price DOUBLE PRECISION,
                    expires_at BIGINT,
                    status TEXT,
                    metadata_json TEXT,
                    private_instruction_id TEXT,
                    created_at BIGINT,
                    updated_at BIGINT
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_rfqs_status ON rfqs(status)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS trades (
                    trade_id TEXT PRIMARY KEY,
                    rfq_id TEXT,
                    buyer_client_id TEXT,
                    seller_client_id TEXT,
                    buyer_wallet TEXT,
                    seller_wallet TEXT,
                    base_asset TEXT,
                    quote_asset TEXT,
                    base_amount DOUBLE PRECISION,
                    quote_amount DOUBLE PRECISION,
                    status TEXT,
                    fee_bps INTEGER,
                    fee_amount DOUBLE PRECISION,
                    fee_asset TEXT,
                    escrow_chain_id INTEGER,
                    escrow_factory TEXT,
                    escrow_trade_ref TEXT,
                    escrow_tx_hashes_json TEXT,
                    private_instruction_id TEXT,
                    metadata_json TEXT,
                    created_at BIGINT,
                    updated_at BIGINT
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_trades_status ON trades(status)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS escrow_events (
                    event_id TEXT PRIMARY KEY,
                    trade_id TEXT,
                    event_type TEXT,
                    intent_id TEXT,
                    contract_address TEXT,
                    event_name TEXT,
                    tx_hash TEXT,
                    block_number BIGINT,
                    confirmations BIGINT DEFAULT 0,
                    chain_id INTEGER,
                    verified BOOLEAN DEFAULT FALSE,
                    payload_json TEXT,
                    created_at BIGINT
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_escrow_events_trade ON escrow_events(trade_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_escrow_events_tx ON escrow_events(tx_hash)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS onchain_intents (
                    intent_id TEXT PRIMARY KEY,
                    trade_id TEXT,
                    action TEXT,
                    expected_event TEXT,
                    prepared_payload_json TEXT,
                    tx_hash TEXT,
                    status TEXT,
                    expires_at BIGINT,
                    created_at BIGINT,
                    updated_at BIGINT
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_onchain_intents_trade_action ON onchain_intents(trade_id, action)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_onchain_intents_status ON onchain_intents(status)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS trade_fee_events (
                    event_id TEXT PRIMARY KEY,
                    trade_id TEXT,
                    client_id TEXT,
                    fee_bps INTEGER,
                    notional_amount DOUBLE PRECISION,
                    fee_amount DOUBLE PRECISION,
                    asset TEXT,
                    status TEXT,
                    created_at BIGINT
                )
                """)
                cur.execute("""
                CREATE TABLE IF NOT EXISTS trade_intents (
                    intent_id TEXT PRIMARY KEY,
                    maker_client_id TEXT,
                    maker_wallet TEXT,
                    sell_asset TEXT,
                    buy_asset TEXT,
                    amount DOUBLE PRECISION,
                    price_min DOUBLE PRECISION,
                    price_max DOUBLE PRECISION,
                    expiration BIGINT,
                    commitment_meta_json TEXT,
                    private_instruction_id TEXT,
                    status TEXT,
                    metadata_json TEXT,
                    created_at BIGINT,
                    updated_at BIGINT
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_trade_intents_status ON trade_intents(status)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_trade_intents_pair ON trade_intents(sell_asset, buy_asset)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS intent_shards_index (
                    intent_id TEXT,
                    instruction_id TEXT,
                    manifest_id TEXT,
                    created_at BIGINT,
                    PRIMARY KEY (intent_id, instruction_id)
                )
                """)
                cur.execute("""
                CREATE TABLE IF NOT EXISTS matches (
                    match_id TEXT PRIMARY KEY,
                    intent_sell_id TEXT,
                    intent_buy_id TEXT,
                    overlap_min DOUBLE PRECISION,
                    overlap_max DOUBLE PRECISION,
                    amount DOUBLE PRECISION,
                    confidence DOUBLE PRECISION,
                    status TEXT,
                    metadata_json TEXT,
                    created_at BIGINT,
                    updated_at BIGINT
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_matches_status ON matches(status)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS secure_sessions (
                    session_id TEXT PRIMARY KEY,
                    match_id TEXT,
                    peer_a TEXT,
                    peer_b TEXT,
                    noise_handshake_state_json TEXT,
                    expires_at BIGINT,
                    status TEXT,
                    created_at BIGINT,
                    updated_at BIGINT
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_secure_sessions_match ON secure_sessions(match_id)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS swap_coordination (
                    swap_id TEXT PRIMARY KEY,
                    match_id TEXT,
                    secret_hash TEXT,
                    htlc_a_json TEXT,
                    htlc_b_json TEXT,
                    state TEXT,
                    timeouts_json TEXT,
                    proofs_json TEXT,
                    completed_at BIGINT,
                    metadata_json TEXT,
                    created_at BIGINT,
                    updated_at BIGINT
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_swap_coordination_match ON swap_coordination(match_id)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS htlc_proofs (
                    proof_id TEXT PRIMARY KEY,
                    swap_id TEXT,
                    proof_type TEXT,
                    tx_hash TEXT,
                    confirmations BIGINT,
                    secret TEXT,
                    metadata_json TEXT,
                    created_at BIGINT
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_htlc_proofs_swap ON htlc_proofs(swap_id)")
                cur.execute("""
                CREATE TABLE IF NOT EXISTS fee_invoices (
                    invoice_id TEXT PRIMARY KEY,
                    swap_id TEXT,
                    fee_bps INTEGER,
                    fee_amount DOUBLE PRECISION,
                    fee_asset TEXT,
                    invoice_ref TEXT,
                    payment_status TEXT,
                    payment_ref TEXT,
                    created_at BIGINT,
                    updated_at BIGINT
                )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_fee_invoices_swap ON fee_invoices(swap_id)")
            if self.backend == 'sqlite':
                self._migrate_sqlite_schema(cur)
            else:
                self._migrate_postgres_schema(cur)

    def _column_exists_sqlite(self, cur, table: str, column: str) -> bool:
        cur.execute(f"PRAGMA table_info({table})")
        return any((row[1] == column) for row in cur.fetchall())

    def _migrate_sqlite_schema(self, cur):
        cols = [
            ('intent_id', 'TEXT'),
            ('contract_address', 'TEXT'),
            ('event_name', 'TEXT'),
            ('confirmations', 'INTEGER DEFAULT 0'),
            ('verified', 'INTEGER DEFAULT 0')
        ]
        for col, typ in cols:
            if not self._column_exists_sqlite(cur, 'escrow_events', col):
                cur.execute(f"ALTER TABLE escrow_events ADD COLUMN {col} {typ}")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_escrow_events_trade ON escrow_events(trade_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_escrow_events_tx ON escrow_events(tx_hash)")

    def _migrate_postgres_schema(self, cur):
        cur.execute("ALTER TABLE escrow_events ADD COLUMN IF NOT EXISTS intent_id TEXT")
        cur.execute("ALTER TABLE escrow_events ADD COLUMN IF NOT EXISTS contract_address TEXT")
        cur.execute("ALTER TABLE escrow_events ADD COLUMN IF NOT EXISTS event_name TEXT")
        cur.execute("ALTER TABLE escrow_events ADD COLUMN IF NOT EXISTS confirmations BIGINT DEFAULT 0")
        cur.execute("ALTER TABLE escrow_events ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT FALSE")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_escrow_events_trade ON escrow_events(trade_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_escrow_events_tx ON escrow_events(tx_hash)")

    def _execute(self, query: str, params: Tuple = ()):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(query, params)
            if self.backend == 'sqlite':
                self.conn.commit()
            return cur
    
    def store_shard(self, shard_name: str, instruction_id: str, shard_index: int, replica: int,
                    data: str, share: Optional[str], signature: Optional[str], sender_id: str,
                    destination: str, data_region: str, relay_hops: int, received_at: int):
        created_at = int(time.time())
        if self.backend == 'sqlite':
            self._execute("""
                INSERT OR REPLACE INTO shards
                (shard_name, instruction_id, shard_index, replica, data, share, signature, sender_id,
                 destination, data_region, relay_hops, received_at, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (shard_name, instruction_id, shard_index, replica, data, share, signature, sender_id,
                  destination, data_region, relay_hops, received_at, created_at))
        else:
            self._execute("""
                INSERT INTO shards
                (shard_name, instruction_id, shard_index, replica, data, share, signature, sender_id,
                 destination, data_region, relay_hops, received_at, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (shard_name) DO UPDATE SET
                  instruction_id=EXCLUDED.instruction_id,
                  shard_index=EXCLUDED.shard_index,
                  replica=EXCLUDED.replica,
                  data=EXCLUDED.data,
                  share=EXCLUDED.share,
                  signature=EXCLUDED.signature,
                  sender_id=EXCLUDED.sender_id,
                  destination=EXCLUDED.destination,
                  data_region=EXCLUDED.data_region,
                  relay_hops=EXCLUDED.relay_hops,
                  received_at=EXCLUDED.received_at,
                  created_at=EXCLUDED.created_at
            """, (shard_name, instruction_id, shard_index, replica, data, share, signature, sender_id,
                  destination, data_region, relay_hops, received_at, created_at))
    
    def get_shard(self, shard_name: str) -> Optional[Dict[str, Any]]:
        cur = self._execute("SELECT shard_name, instruction_id, shard_index, replica, data, share, signature, sender_id, destination, data_region, relay_hops, received_at FROM shards WHERE shard_name=?"
                            if self.backend == 'sqlite'
                            else "SELECT shard_name, instruction_id, shard_index, replica, data, share, signature, sender_id, destination, data_region, relay_hops, received_at FROM shards WHERE shard_name=%s",
                            (shard_name,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            'shard_name': row[0],
            'instruction_id': row[1],
            'index': row[2],
            'replica': row[3],
            'data': row[4],
            'share': row[5],
            'signature': row[6],
            'sender_id': row[7],
            'destination': row[8],
            'data_region': row[9],
            'relay_hops': row[10],
            'received_at': row[11]
        }
    
    def list_shards(self) -> List[str]:
        cur = self._execute("SELECT shard_name FROM shards")
        return [r[0] for r in cur.fetchall()]
    
    def list_shards_by_instruction(self, instruction_id: str) -> List[Dict[str, Any]]:
        cur = self._execute("SELECT shard_name, shard_index, replica FROM shards WHERE instruction_id=?"
                            if self.backend == 'sqlite'
                            else "SELECT shard_name, shard_index, replica FROM shards WHERE instruction_id=%s",
                            (instruction_id,))
        return [{'shard_name': r[0], 'index': r[1], 'replica': r[2]} for r in cur.fetchall()]
    
    def store_manifest(self, instruction_id: str, manifest: Dict[str, Any]):
        manifest_json = json.dumps(manifest)
        created_at = int(time.time())
        if self.backend == 'sqlite':
            self._execute("INSERT OR REPLACE INTO manifests (instruction_id, manifest_json, created_at) VALUES (?,?,?)",
                          (instruction_id, manifest_json, created_at))
        else:
            self._execute("""INSERT INTO manifests (instruction_id, manifest_json, created_at)
                             VALUES (%s,%s,%s)
                             ON CONFLICT (instruction_id) DO UPDATE SET manifest_json=EXCLUDED.manifest_json, created_at=EXCLUDED.created_at""",
                          (instruction_id, manifest_json, created_at))
    
    def get_manifest(self, instruction_id: str) -> Optional[Dict[str, Any]]:
        cur = self._execute("SELECT manifest_json FROM manifests WHERE instruction_id=?"
                            if self.backend == 'sqlite'
                            else "SELECT manifest_json FROM manifests WHERE instruction_id=%s",
                            (instruction_id,))
        row = cur.fetchone()
        if not row:
            return None
        return json.loads(row[0])
    
    def list_manifests(self) -> List[Dict[str, Any]]:
        cur = self._execute("SELECT manifest_json FROM manifests")
        return [json.loads(r[0]) for r in cur.fetchall()]
    
    def record_audit(self, event: Dict[str, Any]):
        self._execute("""INSERT OR REPLACE INTO audit_log
            (event_id, timestamp, actor, node_id, instruction_id, event_type, details_json, request_id,
             prev_hash, hash, signature, key_id, key_version)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"""
            if self.backend == 'sqlite' else
            """INSERT INTO audit_log
            (event_id, timestamp, actor, node_id, instruction_id, event_type, details_json, request_id,
             prev_hash, hash, signature, key_id, key_version)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (event_id) DO NOTHING""",
            (event['event_id'], event['timestamp'], event['actor'], event['node_id'],
             event['instruction_id'], event['event_type'], json.dumps(event.get('details', {})),
             event.get('request_id', ''), event.get('prev_hash', ''), event.get('hash', ''),
             event.get('signature', ''), event.get('key_id', ''), event.get('key_version', 0)))
    
    def list_audit_events(self) -> List[Dict[str, Any]]:
        cur = self._execute("SELECT event_id, timestamp, actor, node_id, instruction_id, event_type, details_json, request_id, prev_hash, hash, signature, key_id, key_version FROM audit_log ORDER BY timestamp ASC, event_id ASC")
        out = []
        for r in cur.fetchall():
            out.append({
                'event_id': r[0],
                'timestamp': r[1],
                'actor': r[2],
                'node_id': r[3],
                'instruction_id': r[4],
                'event_type': r[5],
                'details': json.loads(r[6]) if r[6] else {},
                'request_id': r[7],
                'prev_hash': r[8],
                'hash': r[9],
                'signature': r[10],
                'key_id': r[11],
                'key_version': r[12]
            })
        return out
    
    def bind_wallet(self, client_id: str, wallet_address: str, chain_id: int, status: str = 'active'):
        created_at = int(time.time() * 1000)
        if self.backend == 'sqlite':
            self._execute("""INSERT OR REPLACE INTO wallet_bindings (client_id, wallet_address, chain_id, status, created_at)
                             VALUES (?,?,?,?,?)""", (client_id, wallet_address.lower(), chain_id, status, created_at))
        else:
            self._execute("""INSERT INTO wallet_bindings (client_id, wallet_address, chain_id, status, created_at)
                             VALUES (%s,%s,%s,%s,%s)
                             ON CONFLICT (client_id, wallet_address, chain_id)
                             DO UPDATE SET status=EXCLUDED.status, created_at=EXCLUDED.created_at""",
                          (client_id, wallet_address.lower(), chain_id, status, created_at))

    def wallet_bound(self, client_id: str, wallet_address: str, chain_id: int) -> bool:
        cur = self._execute("SELECT 1 FROM wallet_bindings WHERE client_id=? AND wallet_address=? AND chain_id=? AND status='active'"
                            if self.backend == 'sqlite'
                            else "SELECT 1 FROM wallet_bindings WHERE client_id=%s AND wallet_address=%s AND chain_id=%s AND status='active'",
                            (client_id, wallet_address.lower(), chain_id))
        return cur.fetchone() is not None

    def create_rfq(self, rfq: Dict[str, Any]):
        now_ms = int(time.time() * 1000)
        data = (
            rfq['rfq_id'], rfq['maker_client_id'], rfq['maker_wallet'].lower(), rfq.get('taker_client_id', ''),
            rfq.get('maker_side', 'sell'), rfq['base_asset'], rfq['quote_asset'], rfq['base_amount'],
            rfq['quote_amount'], rfq['price'], rfq['expires_at'], rfq['status'],
            json.dumps(rfq.get('metadata', {})), rfq.get('private_instruction_id', ''), now_ms, now_ms
        )
        if self.backend == 'sqlite':
            self._execute("""INSERT INTO rfqs
                (rfq_id, maker_client_id, maker_wallet, taker_client_id, maker_side, base_asset, quote_asset,
                 base_amount, quote_amount, price, expires_at, status, metadata_json, private_instruction_id, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", data)
        else:
            self._execute("""INSERT INTO rfqs
                (rfq_id, maker_client_id, maker_wallet, taker_client_id, maker_side, base_asset, quote_asset,
                 base_amount, quote_amount, price, expires_at, status, metadata_json, private_instruction_id, created_at, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", data)

    def get_rfq(self, rfq_id: str) -> Optional[Dict[str, Any]]:
        cur = self._execute("""SELECT rfq_id, maker_client_id, maker_wallet, taker_client_id, maker_side, base_asset,
                               quote_asset, base_amount, quote_amount, price, expires_at, status, metadata_json,
                               private_instruction_id, created_at, updated_at FROM rfqs WHERE rfq_id=?"""
                            if self.backend == 'sqlite'
                            else """SELECT rfq_id, maker_client_id, maker_wallet, taker_client_id, maker_side, base_asset,
                               quote_asset, base_amount, quote_amount, price, expires_at, status, metadata_json,
                               private_instruction_id, created_at, updated_at FROM rfqs WHERE rfq_id=%s""",
                            (rfq_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            'rfq_id': row[0], 'maker_client_id': row[1], 'maker_wallet': row[2], 'taker_client_id': row[3],
            'maker_side': row[4], 'base_asset': row[5], 'quote_asset': row[6], 'base_amount': row[7],
            'quote_amount': row[8], 'price': row[9], 'expires_at': row[10], 'status': row[11],
            'metadata': json.loads(row[12]) if row[12] else {}, 'private_instruction_id': row[13],
            'created_at': row[14], 'updated_at': row[15]
        }

    def update_rfq_status(self, rfq_id: str, status: str):
        now_ms = int(time.time() * 1000)
        self._execute("UPDATE rfqs SET status=?, updated_at=? WHERE rfq_id=?"
                      if self.backend == 'sqlite'
                      else "UPDATE rfqs SET status=%s, updated_at=%s WHERE rfq_id=%s",
                      (status, now_ms, rfq_id))

    def list_rfqs(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        if status:
            cur = self._execute("""SELECT rfq_id, maker_client_id, maker_wallet, taker_client_id, maker_side, base_asset,
                                   quote_asset, base_amount, quote_amount, price, expires_at, status, metadata_json,
                                   private_instruction_id, created_at, updated_at FROM rfqs WHERE status=? ORDER BY created_at DESC"""
                                if self.backend == 'sqlite'
                                else """SELECT rfq_id, maker_client_id, maker_wallet, taker_client_id, maker_side, base_asset,
                                   quote_asset, base_amount, quote_amount, price, expires_at, status, metadata_json,
                                   private_instruction_id, created_at, updated_at FROM rfqs WHERE status=%s ORDER BY created_at DESC""",
                                (status,))
        else:
            cur = self._execute("""SELECT rfq_id, maker_client_id, maker_wallet, taker_client_id, maker_side, base_asset,
                                   quote_asset, base_amount, quote_amount, price, expires_at, status, metadata_json,
                                   private_instruction_id, created_at, updated_at FROM rfqs ORDER BY created_at DESC""")
        out = []
        for row in cur.fetchall():
            out.append({
                'rfq_id': row[0], 'maker_client_id': row[1], 'maker_wallet': row[2], 'taker_client_id': row[3],
                'maker_side': row[4], 'base_asset': row[5], 'quote_asset': row[6], 'base_amount': row[7],
                'quote_amount': row[8], 'price': row[9], 'expires_at': row[10], 'status': row[11],
                'metadata': json.loads(row[12]) if row[12] else {}, 'private_instruction_id': row[13],
                'created_at': row[14], 'updated_at': row[15]
            })
        return out

    def create_trade(self, trade: Dict[str, Any]):
        now_ms = int(time.time() * 1000)
        data = (
            trade['trade_id'], trade.get('rfq_id', ''), trade['buyer_client_id'], trade['seller_client_id'],
            trade['buyer_wallet'].lower(), trade['seller_wallet'].lower(), trade['base_asset'], trade['quote_asset'],
            trade['base_amount'], trade['quote_amount'], trade['status'], trade['fee_bps'], trade['fee_amount'],
            trade['fee_asset'], trade.get('escrow_chain_id', EVM_CHAIN_ID), trade.get('escrow_factory', ESCROW_FACTORY_ADDRESS),
            trade.get('escrow_trade_ref', ''), json.dumps(trade.get('escrow_tx_hashes', [])),
            trade.get('private_instruction_id', ''), json.dumps(trade.get('metadata', {})), now_ms, now_ms
        )
        if self.backend == 'sqlite':
            self._execute("""INSERT INTO trades
                (trade_id, rfq_id, buyer_client_id, seller_client_id, buyer_wallet, seller_wallet, base_asset, quote_asset,
                 base_amount, quote_amount, status, fee_bps, fee_amount, fee_asset, escrow_chain_id, escrow_factory,
                 escrow_trade_ref, escrow_tx_hashes_json, private_instruction_id, metadata_json, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", data)
        else:
            self._execute("""INSERT INTO trades
                (trade_id, rfq_id, buyer_client_id, seller_client_id, buyer_wallet, seller_wallet, base_asset, quote_asset,
                 base_amount, quote_amount, status, fee_bps, fee_amount, fee_asset, escrow_chain_id, escrow_factory,
                 escrow_trade_ref, escrow_tx_hashes_json, private_instruction_id, metadata_json, created_at, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", data)

    def get_trade(self, trade_id: str) -> Optional[Dict[str, Any]]:
        cur = self._execute("""SELECT trade_id, rfq_id, buyer_client_id, seller_client_id, buyer_wallet, seller_wallet,
                               base_asset, quote_asset, base_amount, quote_amount, status, fee_bps, fee_amount, fee_asset,
                               escrow_chain_id, escrow_factory, escrow_trade_ref, escrow_tx_hashes_json,
                               private_instruction_id, metadata_json, created_at, updated_at
                               FROM trades WHERE trade_id=?"""
                            if self.backend == 'sqlite'
                            else """SELECT trade_id, rfq_id, buyer_client_id, seller_client_id, buyer_wallet, seller_wallet,
                               base_asset, quote_asset, base_amount, quote_amount, status, fee_bps, fee_amount, fee_asset,
                               escrow_chain_id, escrow_factory, escrow_trade_ref, escrow_tx_hashes_json,
                               private_instruction_id, metadata_json, created_at, updated_at
                               FROM trades WHERE trade_id=%s""",
                            (trade_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            'trade_id': row[0], 'rfq_id': row[1], 'buyer_client_id': row[2], 'seller_client_id': row[3],
            'buyer_wallet': row[4], 'seller_wallet': row[5], 'base_asset': row[6], 'quote_asset': row[7],
            'base_amount': row[8], 'quote_amount': row[9], 'status': row[10], 'fee_bps': row[11],
            'fee_amount': row[12], 'fee_asset': row[13], 'escrow_chain_id': row[14], 'escrow_factory': row[15],
            'escrow_trade_ref': row[16], 'escrow_tx_hashes': json.loads(row[17]) if row[17] else [],
            'private_instruction_id': row[18], 'metadata': json.loads(row[19]) if row[19] else {},
            'created_at': row[20], 'updated_at': row[21]
        }

    def update_trade_state(self, trade_id: str, status: str, escrow_trade_ref: Optional[str] = None,
                           add_tx_hash: Optional[str] = None):
        trade = self.get_trade(trade_id)
        if not trade:
            return
        txs = trade.get('escrow_tx_hashes', [])
        if add_tx_hash and add_tx_hash not in txs:
            txs.append(add_tx_hash)
        now_ms = int(time.time() * 1000)
        self._execute("""UPDATE trades SET status=?, escrow_trade_ref=?, escrow_tx_hashes_json=?, updated_at=?
                         WHERE trade_id=?"""
                      if self.backend == 'sqlite'
                      else """UPDATE trades SET status=%s, escrow_trade_ref=%s, escrow_tx_hashes_json=%s, updated_at=%s
                         WHERE trade_id=%s""",
                      (status, escrow_trade_ref or trade.get('escrow_trade_ref', ''), json.dumps(txs), now_ms, trade_id))

    def list_trades(self, client_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if client_id:
            cur = self._execute("""SELECT trade_id, rfq_id, buyer_client_id, seller_client_id, buyer_wallet, seller_wallet,
                                   base_asset, quote_asset, base_amount, quote_amount, status, fee_bps, fee_amount, fee_asset,
                                   escrow_chain_id, escrow_factory, escrow_trade_ref, escrow_tx_hashes_json,
                                   private_instruction_id, metadata_json, created_at, updated_at
                                   FROM trades WHERE buyer_client_id=? OR seller_client_id=? ORDER BY created_at DESC"""
                                if self.backend == 'sqlite'
                                else """SELECT trade_id, rfq_id, buyer_client_id, seller_client_id, buyer_wallet, seller_wallet,
                                   base_asset, quote_asset, base_amount, quote_amount, status, fee_bps, fee_amount, fee_asset,
                                   escrow_chain_id, escrow_factory, escrow_trade_ref, escrow_tx_hashes_json,
                                   private_instruction_id, metadata_json, created_at, updated_at
                                   FROM trades WHERE buyer_client_id=%s OR seller_client_id=%s ORDER BY created_at DESC""",
                                (client_id, client_id))
        else:
            cur = self._execute("""SELECT trade_id, rfq_id, buyer_client_id, seller_client_id, buyer_wallet, seller_wallet,
                                   base_asset, quote_asset, base_amount, quote_amount, status, fee_bps, fee_amount, fee_asset,
                                   escrow_chain_id, escrow_factory, escrow_trade_ref, escrow_tx_hashes_json,
                                   private_instruction_id, metadata_json, created_at, updated_at
                                   FROM trades ORDER BY created_at DESC""")
        out = []
        for row in cur.fetchall():
            out.append({
                'trade_id': row[0], 'rfq_id': row[1], 'buyer_client_id': row[2], 'seller_client_id': row[3],
                'buyer_wallet': row[4], 'seller_wallet': row[5], 'base_asset': row[6], 'quote_asset': row[7],
                'base_amount': row[8], 'quote_amount': row[9], 'status': row[10], 'fee_bps': row[11],
                'fee_amount': row[12], 'fee_asset': row[13], 'escrow_chain_id': row[14], 'escrow_factory': row[15],
                'escrow_trade_ref': row[16], 'escrow_tx_hashes': json.loads(row[17]) if row[17] else [],
                'private_instruction_id': row[18], 'metadata': json.loads(row[19]) if row[19] else {},
                'created_at': row[20], 'updated_at': row[21]
            })
        return out

    def record_escrow_event(self, event: Dict[str, Any]):
        data = (
            event.get('event_id', str(uuid_lib.uuid4())), event['trade_id'], event['event_type'],
            event.get('intent_id', ''), event.get('contract_address', ''), event.get('event_name', ''),
            event.get('tx_hash', ''), event.get('block_number', 0), event.get('confirmations', 0),
            event.get('chain_id', EVM_CHAIN_ID), 1 if event.get('verified', False) else 0,
            json.dumps(event.get('payload', {})), int(time.time() * 1000)
        )
        self._execute("""INSERT INTO escrow_events
                         (event_id, trade_id, event_type, intent_id, contract_address, event_name,
                          tx_hash, block_number, confirmations, chain_id, verified, payload_json, created_at)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"""
                      if self.backend == 'sqlite'
                      else """INSERT INTO escrow_events
                         (event_id, trade_id, event_type, intent_id, contract_address, event_name,
                          tx_hash, block_number, confirmations, chain_id, verified, payload_json, created_at)
                         VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                      data)

    def get_escrow_event_by_tx_hash(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        cur = self._execute("""SELECT event_id, trade_id, event_type, intent_id, contract_address, event_name,
                               tx_hash, block_number, confirmations, chain_id, verified, payload_json, created_at
                               FROM escrow_events WHERE tx_hash=? ORDER BY created_at DESC LIMIT 1"""
                            if self.backend == 'sqlite'
                            else """SELECT event_id, trade_id, event_type, intent_id, contract_address, event_name,
                               tx_hash, block_number, confirmations, chain_id, verified, payload_json, created_at
                               FROM escrow_events WHERE tx_hash=%s ORDER BY created_at DESC LIMIT 1""",
                            (tx_hash,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            'event_id': row[0],
            'trade_id': row[1],
            'event_type': row[2],
            'intent_id': row[3],
            'contract_address': row[4],
            'event_name': row[5],
            'tx_hash': row[6],
            'block_number': row[7],
            'confirmations': row[8],
            'chain_id': row[9],
            'verified': bool(row[10]),
            'payload': json.loads(row[11]) if row[11] else {},
            'created_at': row[12]
        }

    def create_onchain_intent(self, intent: Dict[str, Any]):
        now_ms = int(time.time() * 1000)
        expires_at = int(intent.get('expires_at', now_ms + ESCROW_PREPARE_TTL_SECONDS * 1000))
        data = (
            intent['intent_id'],
            intent['trade_id'],
            intent['action'],
            intent.get('expected_event', ''),
            json.dumps(intent.get('prepared_payload', {})),
            intent.get('tx_hash', ''),
            intent.get('status', 'prepared'),
            expires_at,
            now_ms,
            now_ms
        )
        self._execute("""INSERT INTO onchain_intents
                         (intent_id, trade_id, action, expected_event, prepared_payload_json, tx_hash, status, expires_at, created_at, updated_at)
                         VALUES (?,?,?,?,?,?,?,?,?,?)"""
                      if self.backend == 'sqlite'
                      else """INSERT INTO onchain_intents
                         (intent_id, trade_id, action, expected_event, prepared_payload_json, tx_hash, status, expires_at, created_at, updated_at)
                         VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                      data)

    def get_onchain_intent(self, intent_id: str) -> Optional[Dict[str, Any]]:
        cur = self._execute("""SELECT intent_id, trade_id, action, expected_event, prepared_payload_json, tx_hash, status, expires_at, created_at, updated_at
                               FROM onchain_intents WHERE intent_id=?"""
                            if self.backend == 'sqlite'
                            else """SELECT intent_id, trade_id, action, expected_event, prepared_payload_json, tx_hash, status, expires_at, created_at, updated_at
                               FROM onchain_intents WHERE intent_id=%s""",
                            (intent_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            'intent_id': row[0],
            'trade_id': row[1],
            'action': row[2],
            'expected_event': row[3],
            'prepared_payload': json.loads(row[4]) if row[4] else {},
            'tx_hash': row[5] or '',
            'status': row[6],
            'expires_at': row[7],
            'created_at': row[8],
            'updated_at': row[9]
        }

    def get_latest_onchain_intent(self, trade_id: str, action: str) -> Optional[Dict[str, Any]]:
        cur = self._execute("""SELECT intent_id, trade_id, action, expected_event, prepared_payload_json, tx_hash, status, expires_at, created_at, updated_at
                               FROM onchain_intents WHERE trade_id=? AND action=? ORDER BY created_at DESC LIMIT 1"""
                            if self.backend == 'sqlite'
                            else """SELECT intent_id, trade_id, action, expected_event, prepared_payload_json, tx_hash, status, expires_at, created_at, updated_at
                               FROM onchain_intents WHERE trade_id=%s AND action=%s ORDER BY created_at DESC LIMIT 1""",
                            (trade_id, action))
        row = cur.fetchone()
        if not row:
            return None
        return {
            'intent_id': row[0],
            'trade_id': row[1],
            'action': row[2],
            'expected_event': row[3],
            'prepared_payload': json.loads(row[4]) if row[4] else {},
            'tx_hash': row[5] or '',
            'status': row[6],
            'expires_at': row[7],
            'created_at': row[8],
            'updated_at': row[9]
        }

    def list_onchain_intents(self, statuses: Optional[List[str]] = None, limit: int = 100) -> List[Dict[str, Any]]:
        if statuses:
            placeholders = ','.join(['?'] * len(statuses)) if self.backend == 'sqlite' else ','.join(['%s'] * len(statuses))
            query = f"""SELECT intent_id, trade_id, action, expected_event, prepared_payload_json, tx_hash, status, expires_at, created_at, updated_at
                        FROM onchain_intents WHERE status IN ({placeholders}) ORDER BY created_at DESC LIMIT {'?' if self.backend == 'sqlite' else '%s'}"""
            params = tuple(statuses) + (limit,)
            cur = self._execute(query, params)
        else:
            cur = self._execute("""SELECT intent_id, trade_id, action, expected_event, prepared_payload_json, tx_hash, status, expires_at, created_at, updated_at
                                   FROM onchain_intents ORDER BY created_at DESC LIMIT ?"""
                                if self.backend == 'sqlite'
                                else """SELECT intent_id, trade_id, action, expected_event, prepared_payload_json, tx_hash, status, expires_at, created_at, updated_at
                                   FROM onchain_intents ORDER BY created_at DESC LIMIT %s""",
                                (limit,))
        out = []
        for row in cur.fetchall():
            out.append({
                'intent_id': row[0],
                'trade_id': row[1],
                'action': row[2],
                'expected_event': row[3],
                'prepared_payload': json.loads(row[4]) if row[4] else {},
                'tx_hash': row[5] or '',
                'status': row[6],
                'expires_at': row[7],
                'created_at': row[8],
                'updated_at': row[9]
            })
        return out

    def update_onchain_intent_status(self, intent_id: str, status: str, tx_hash: Optional[str] = None):
        now_ms = int(time.time() * 1000)
        current = self.get_onchain_intent(intent_id)
        if not current:
            return
        new_tx_hash = tx_hash or current.get('tx_hash', '')
        self._execute("""UPDATE onchain_intents SET status=?, tx_hash=?, updated_at=? WHERE intent_id=?"""
                      if self.backend == 'sqlite'
                      else """UPDATE onchain_intents SET status=%s, tx_hash=%s, updated_at=%s WHERE intent_id=%s""",
                      (status, new_tx_hash, now_ms, intent_id))

    def record_trade_fee_event(self, event: Dict[str, Any]):
        data = (
            event.get('event_id', str(uuid_lib.uuid4())), event['trade_id'], event['client_id'],
            event['fee_bps'], event['notional_amount'], event['fee_amount'], event['asset'],
            event.get('status', 'pending'), int(time.time() * 1000)
        )
        self._execute("""INSERT INTO trade_fee_events
                         (event_id, trade_id, client_id, fee_bps, notional_amount, fee_amount, asset, status, created_at)
                         VALUES (?,?,?,?,?,?,?,?,?)"""
                      if self.backend == 'sqlite'
                      else """INSERT INTO trade_fee_events
                         (event_id, trade_id, client_id, fee_bps, notional_amount, fee_amount, asset, status, created_at)
                         VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                      data)

    def list_trade_fee_events(self, client_id: str, start_ms: int, end_ms: int) -> List[Dict[str, Any]]:
        cur = self._execute("""SELECT trade_id, client_id, fee_bps, notional_amount, fee_amount, asset, status, created_at
                               FROM trade_fee_events WHERE client_id=? AND created_at BETWEEN ? AND ? ORDER BY created_at DESC"""
                            if self.backend == 'sqlite'
                            else """SELECT trade_id, client_id, fee_bps, notional_amount, fee_amount, asset, status, created_at
                               FROM trade_fee_events WHERE client_id=%s AND created_at BETWEEN %s AND %s ORDER BY created_at DESC""",
                            (client_id, start_ms, end_ms))
        out = []
        for row in cur.fetchall():
            out.append({
                'trade_id': row[0], 'client_id': row[1], 'fee_bps': row[2], 'notional_amount': row[3],
                'fee_amount': row[4], 'asset': row[5], 'status': row[6], 'created_at': row[7]
            })
        return out

    # ----- Dark pool v2 storage -----
    def create_trade_intent(self, intent: Dict[str, Any]):
        now_ms = int(time.time() * 1000)
        data = (
            intent['intent_id'], intent['maker_client_id'], intent['maker_wallet'].lower(),
            intent['sell_asset'], intent['buy_asset'], float(intent['amount']),
            float(intent['price_min']), float(intent['price_max']), int(intent['expiration']),
            json.dumps(intent.get('commitment_meta', {})), intent.get('private_instruction_id', ''),
            intent.get('status', INTENT_STATUS_OPEN), json.dumps(intent.get('metadata', {})),
            now_ms, now_ms
        )
        self._execute("""INSERT INTO trade_intents
                         (intent_id, maker_client_id, maker_wallet, sell_asset, buy_asset, amount, price_min, price_max,
                          expiration, commitment_meta_json, private_instruction_id, status, metadata_json, created_at, updated_at)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
                      if self.backend == 'sqlite'
                      else """INSERT INTO trade_intents
                         (intent_id, maker_client_id, maker_wallet, sell_asset, buy_asset, amount, price_min, price_max,
                          expiration, commitment_meta_json, private_instruction_id, status, metadata_json, created_at, updated_at)
                         VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                      data)

    def get_trade_intent(self, intent_id: str) -> Optional[Dict[str, Any]]:
        cur = self._execute("""SELECT intent_id, maker_client_id, maker_wallet, sell_asset, buy_asset, amount, price_min, price_max,
                               expiration, commitment_meta_json, private_instruction_id, status, metadata_json, created_at, updated_at
                               FROM trade_intents WHERE intent_id=?"""
                            if self.backend == 'sqlite'
                            else """SELECT intent_id, maker_client_id, maker_wallet, sell_asset, buy_asset, amount, price_min, price_max,
                               expiration, commitment_meta_json, private_instruction_id, status, metadata_json, created_at, updated_at
                               FROM trade_intents WHERE intent_id=%s""",
                            (intent_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            'intent_id': row[0], 'maker_client_id': row[1], 'maker_wallet': row[2], 'sell_asset': row[3], 'buy_asset': row[4],
            'amount': float(row[5]), 'price_min': float(row[6]), 'price_max': float(row[7]), 'expiration': int(row[8]),
            'commitment_meta': json.loads(row[9]) if row[9] else {}, 'private_instruction_id': row[10], 'status': row[11],
            'metadata': json.loads(row[12]) if row[12] else {}, 'created_at': row[13], 'updated_at': row[14]
        }

    def update_trade_intent_status(self, intent_id: str, status: str):
        now_ms = int(time.time() * 1000)
        self._execute("""UPDATE trade_intents SET status=?, updated_at=? WHERE intent_id=?"""
                      if self.backend == 'sqlite'
                      else """UPDATE trade_intents SET status=%s, updated_at=%s WHERE intent_id=%s""",
                      (status, now_ms, intent_id))

    def list_open_trade_intents(self) -> List[Dict[str, Any]]:
        now_ms = int(time.time() * 1000)
        cur = self._execute("""SELECT intent_id FROM trade_intents
                               WHERE status=? AND expiration>=? ORDER BY created_at DESC"""
                            if self.backend == 'sqlite'
                            else """SELECT intent_id FROM trade_intents
                               WHERE status=%s AND expiration>=%s ORDER BY created_at DESC""",
                            (INTENT_STATUS_OPEN, now_ms))
        out = []
        for r in cur.fetchall():
            item = self.get_trade_intent(r[0])
            if item:
                out.append(item)
        return out

    def list_trade_intents_for_client(self, client_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        cur = self._execute("""SELECT intent_id FROM trade_intents WHERE maker_client_id=? ORDER BY created_at DESC LIMIT ?"""
                            if self.backend == 'sqlite'
                            else """SELECT intent_id FROM trade_intents WHERE maker_client_id=%s ORDER BY created_at DESC LIMIT %s""",
                            (client_id, limit))
        out = []
        for r in cur.fetchall():
            item = self.get_trade_intent(r[0])
            if item:
                out.append(item)
        return out

    def link_intent_shard(self, intent_id: str, instruction_id: str, manifest_id: str):
        created_at = int(time.time() * 1000)
        self._execute("""INSERT OR REPLACE INTO intent_shards_index (intent_id, instruction_id, manifest_id, created_at)
                         VALUES (?,?,?,?)"""
                      if self.backend == 'sqlite'
                      else """INSERT INTO intent_shards_index (intent_id, instruction_id, manifest_id, created_at)
                         VALUES (%s,%s,%s,%s)
                         ON CONFLICT (intent_id, instruction_id)
                         DO UPDATE SET manifest_id=EXCLUDED.manifest_id, created_at=EXCLUDED.created_at""",
                      (intent_id, instruction_id, manifest_id, created_at))

    def create_match(self, match: Dict[str, Any]):
        now_ms = int(time.time() * 1000)
        data = (
            match['match_id'], match['intent_sell_id'], match['intent_buy_id'],
            float(match['overlap_min']), float(match['overlap_max']), float(match['amount']),
            float(match.get('confidence', 1.0)), match.get('status', MATCH_STATUS_FOUND),
            json.dumps(match.get('metadata', {})), now_ms, now_ms
        )
        self._execute("""INSERT INTO matches
                         (match_id, intent_sell_id, intent_buy_id, overlap_min, overlap_max, amount, confidence, status, metadata_json, created_at, updated_at)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?)"""
                      if self.backend == 'sqlite'
                      else """INSERT INTO matches
                         (match_id, intent_sell_id, intent_buy_id, overlap_min, overlap_max, amount, confidence, status, metadata_json, created_at, updated_at)
                         VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                      data)

    def find_match_by_intents(self, intent_a: str, intent_b: str) -> Optional[Dict[str, Any]]:
        cur = self._execute("""SELECT match_id FROM matches
                               WHERE (intent_sell_id=? AND intent_buy_id=?) OR (intent_sell_id=? AND intent_buy_id=?)
                               ORDER BY created_at DESC LIMIT 1"""
                            if self.backend == 'sqlite'
                            else """SELECT match_id FROM matches
                               WHERE (intent_sell_id=%s AND intent_buy_id=%s) OR (intent_sell_id=%s AND intent_buy_id=%s)
                               ORDER BY created_at DESC LIMIT 1""",
                            (intent_a, intent_b, intent_b, intent_a))
        row = cur.fetchone()
        return self.get_match(row[0]) if row else None

    def get_match(self, match_id: str) -> Optional[Dict[str, Any]]:
        cur = self._execute("""SELECT match_id, intent_sell_id, intent_buy_id, overlap_min, overlap_max, amount, confidence, status, metadata_json, created_at, updated_at
                               FROM matches WHERE match_id=?"""
                            if self.backend == 'sqlite'
                            else """SELECT match_id, intent_sell_id, intent_buy_id, overlap_min, overlap_max, amount, confidence, status, metadata_json, created_at, updated_at
                               FROM matches WHERE match_id=%s""",
                            (match_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            'match_id': row[0], 'intent_sell_id': row[1], 'intent_buy_id': row[2], 'overlap_min': float(row[3]),
            'overlap_max': float(row[4]), 'amount': float(row[5]), 'confidence': float(row[6]), 'status': row[7],
            'metadata': json.loads(row[8]) if row[8] else {}, 'created_at': row[9], 'updated_at': row[10]
        }

    def update_match_status(self, match_id: str, status: str):
        now_ms = int(time.time() * 1000)
        self._execute("""UPDATE matches SET status=?, updated_at=? WHERE match_id=?"""
                      if self.backend == 'sqlite'
                      else """UPDATE matches SET status=%s, updated_at=%s WHERE match_id=%s""",
                      (status, now_ms, match_id))

    def list_matches_for_client(self, client_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        cur = self._execute("""SELECT m.match_id
                               FROM matches m
                               JOIN trade_intents a ON a.intent_id = m.intent_sell_id
                               JOIN trade_intents b ON b.intent_id = m.intent_buy_id
                               WHERE a.maker_client_id=? OR b.maker_client_id=?
                               ORDER BY m.created_at DESC LIMIT ?"""
                            if self.backend == 'sqlite'
                            else """SELECT m.match_id
                               FROM matches m
                               JOIN trade_intents a ON a.intent_id = m.intent_sell_id
                               JOIN trade_intents b ON b.intent_id = m.intent_buy_id
                               WHERE a.maker_client_id=%s OR b.maker_client_id=%s
                               ORDER BY m.created_at DESC LIMIT %s""",
                            (client_id, client_id, limit))
        out = []
        for r in cur.fetchall():
            item = self.get_match(r[0])
            if item:
                out.append(item)
        return out

    def create_secure_session(self, session: Dict[str, Any]):
        now_ms = int(time.time() * 1000)
        data = (
            session['session_id'], session['match_id'], session['peer_a'], session['peer_b'],
            json.dumps(session.get('noise_handshake_state', {})), int(session['expires_at']),
            session.get('status', SESSION_STATUS_OPEN), now_ms, now_ms
        )
        self._execute("""INSERT INTO secure_sessions
                         (session_id, match_id, peer_a, peer_b, noise_handshake_state_json, expires_at, status, created_at, updated_at)
                         VALUES (?,?,?,?,?,?,?,?,?)"""
                      if self.backend == 'sqlite'
                      else """INSERT INTO secure_sessions
                         (session_id, match_id, peer_a, peer_b, noise_handshake_state_json, expires_at, status, created_at, updated_at)
                         VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                      data)

    def get_secure_session_by_match(self, match_id: str) -> Optional[Dict[str, Any]]:
        cur = self._execute("""SELECT session_id, match_id, peer_a, peer_b, noise_handshake_state_json, expires_at, status, created_at, updated_at
                               FROM secure_sessions WHERE match_id=? ORDER BY created_at DESC LIMIT 1"""
                            if self.backend == 'sqlite'
                            else """SELECT session_id, match_id, peer_a, peer_b, noise_handshake_state_json, expires_at, status, created_at, updated_at
                               FROM secure_sessions WHERE match_id=%s ORDER BY created_at DESC LIMIT 1""",
                            (match_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            'session_id': row[0], 'match_id': row[1], 'peer_a': row[2], 'peer_b': row[3],
            'noise_handshake_state': json.loads(row[4]) if row[4] else {}, 'expires_at': int(row[5]),
            'status': row[6], 'created_at': row[7], 'updated_at': row[8]
        }

    def create_swap(self, swap: Dict[str, Any]):
        now_ms = int(time.time() * 1000)
        data = (
            swap['swap_id'], swap['match_id'], swap.get('secret_hash', ''),
            json.dumps(swap.get('htlc_a', {})), json.dumps(swap.get('htlc_b', {})),
            swap.get('state', SWAP_STATE_INIT), json.dumps(swap.get('timeouts', {})),
            json.dumps(swap.get('proofs', [])), swap.get('completed_at'),
            json.dumps(swap.get('metadata', {})), now_ms, now_ms
        )
        self._execute("""INSERT INTO swap_coordination
                         (swap_id, match_id, secret_hash, htlc_a_json, htlc_b_json, state, timeouts_json, proofs_json, completed_at, metadata_json, created_at, updated_at)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"""
                      if self.backend == 'sqlite'
                      else """INSERT INTO swap_coordination
                         (swap_id, match_id, secret_hash, htlc_a_json, htlc_b_json, state, timeouts_json, proofs_json, completed_at, metadata_json, created_at, updated_at)
                         VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                      data)

    def get_swap(self, swap_id: str) -> Optional[Dict[str, Any]]:
        cur = self._execute("""SELECT swap_id, match_id, secret_hash, htlc_a_json, htlc_b_json, state, timeouts_json, proofs_json, completed_at, metadata_json, created_at, updated_at
                               FROM swap_coordination WHERE swap_id=?"""
                            if self.backend == 'sqlite'
                            else """SELECT swap_id, match_id, secret_hash, htlc_a_json, htlc_b_json, state, timeouts_json, proofs_json, completed_at, metadata_json, created_at, updated_at
                               FROM swap_coordination WHERE swap_id=%s""",
                            (swap_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            'swap_id': row[0], 'match_id': row[1], 'secret_hash': row[2],
            'htlc_a': json.loads(row[3]) if row[3] else {}, 'htlc_b': json.loads(row[4]) if row[4] else {},
            'state': row[5], 'timeouts': json.loads(row[6]) if row[6] else {}, 'proofs': json.loads(row[7]) if row[7] else [],
            'completed_at': row[8], 'metadata': json.loads(row[9]) if row[9] else {}, 'created_at': row[10], 'updated_at': row[11]
        }

    def update_swap(self, swap_id: str, state: Optional[str] = None, completed_at: Optional[int] = None,
                    secret_hash: Optional[str] = None, proofs: Optional[List[Dict[str, Any]]] = None):
        swap = self.get_swap(swap_id)
        if not swap:
            return
        now_ms = int(time.time() * 1000)
        new_state = state or swap.get('state', SWAP_STATE_INIT)
        new_completed = completed_at if completed_at is not None else swap.get('completed_at')
        new_secret_hash = secret_hash if secret_hash is not None else swap.get('secret_hash', '')
        new_proofs = proofs if proofs is not None else swap.get('proofs', [])
        self._execute("""UPDATE swap_coordination
                         SET state=?, completed_at=?, secret_hash=?, proofs_json=?, updated_at=?
                         WHERE swap_id=?"""
                      if self.backend == 'sqlite'
                      else """UPDATE swap_coordination
                         SET state=%s, completed_at=%s, secret_hash=%s, proofs_json=%s, updated_at=%s
                         WHERE swap_id=%s""",
                      (new_state, new_completed, new_secret_hash, json.dumps(new_proofs), now_ms, swap_id))

    def add_htlc_proof(self, swap_id: str, proof: Dict[str, Any]):
        data = (
            proof.get('proof_id', str(uuid_lib.uuid4())), swap_id, proof['proof_type'], proof.get('tx_hash', ''),
            int(proof.get('confirmations', 0)), proof.get('secret', ''), json.dumps(proof.get('metadata', {})),
            int(time.time() * 1000)
        )
        self._execute("""INSERT INTO htlc_proofs
                         (proof_id, swap_id, proof_type, tx_hash, confirmations, secret, metadata_json, created_at)
                         VALUES (?,?,?,?,?,?,?,?)"""
                      if self.backend == 'sqlite'
                      else """INSERT INTO htlc_proofs
                         (proof_id, swap_id, proof_type, tx_hash, confirmations, secret, metadata_json, created_at)
                         VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                      data)

    def list_htlc_proofs(self, swap_id: str) -> List[Dict[str, Any]]:
        cur = self._execute("""SELECT proof_id, proof_type, tx_hash, confirmations, secret, metadata_json, created_at
                               FROM htlc_proofs WHERE swap_id=? ORDER BY created_at ASC"""
                            if self.backend == 'sqlite'
                            else """SELECT proof_id, proof_type, tx_hash, confirmations, secret, metadata_json, created_at
                               FROM htlc_proofs WHERE swap_id=%s ORDER BY created_at ASC""",
                            (swap_id,))
        out = []
        for row in cur.fetchall():
            out.append({
                'proof_id': row[0], 'proof_type': row[1], 'tx_hash': row[2], 'confirmations': int(row[3]),
                'secret': row[4], 'metadata': json.loads(row[5]) if row[5] else {}, 'created_at': row[6]
            })
        return out

    def htlc_tx_hash_exists(self, tx_hash: str) -> bool:
        tx_hash = (tx_hash or '').strip().lower()
        if not tx_hash:
            return False
        cur = self._execute("""SELECT 1 FROM htlc_proofs WHERE lower(tx_hash)=? LIMIT 1"""
                            if self.backend == 'sqlite'
                            else """SELECT 1 FROM htlc_proofs WHERE lower(tx_hash)=%s LIMIT 1""",
                            (tx_hash,))
        return cur.fetchone() is not None

    def list_active_swaps(self, limit: int = 200) -> List[Dict[str, Any]]:
        terminal = (SWAP_STATE_COMPLETED, SWAP_STATE_REFUNDED, SWAP_STATE_FAILED)
        cur = self._execute("""SELECT swap_id FROM swap_coordination
                               WHERE state NOT IN (?,?,?) ORDER BY updated_at ASC LIMIT ?"""
                            if self.backend == 'sqlite'
                            else """SELECT swap_id FROM swap_coordination
                               WHERE state NOT IN (%s,%s,%s) ORDER BY updated_at ASC LIMIT %s""",
                            (*terminal, limit))
        out = []
        for row in cur.fetchall():
            item = self.get_swap(row[0])
            if item:
                out.append(item)
        return out

    def create_fee_invoice(self, invoice: Dict[str, Any]):
        now_ms = int(time.time() * 1000)
        data = (
            invoice.get('invoice_id', str(uuid_lib.uuid4())), invoice['swap_id'], int(invoice['fee_bps']),
            float(invoice['fee_amount']), invoice.get('fee_asset', ''), invoice.get('invoice_ref', ''),
            invoice.get('payment_status', 'pending'), invoice.get('payment_ref', ''), now_ms, now_ms
        )
        self._execute("""INSERT INTO fee_invoices
                         (invoice_id, swap_id, fee_bps, fee_amount, fee_asset, invoice_ref, payment_status, payment_ref, created_at, updated_at)
                         VALUES (?,?,?,?,?,?,?,?,?,?)"""
                      if self.backend == 'sqlite'
                      else """INSERT INTO fee_invoices
                         (invoice_id, swap_id, fee_bps, fee_amount, fee_asset, invoice_ref, payment_status, payment_ref, created_at, updated_at)
                         VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                      data)

    def get_latest_fee_invoice(self, swap_id: str) -> Optional[Dict[str, Any]]:
        cur = self._execute("""SELECT invoice_id, swap_id, fee_bps, fee_amount, fee_asset, invoice_ref, payment_status, payment_ref, created_at, updated_at
                               FROM fee_invoices WHERE swap_id=? ORDER BY created_at DESC LIMIT 1"""
                            if self.backend == 'sqlite'
                            else """SELECT invoice_id, swap_id, fee_bps, fee_amount, fee_asset, invoice_ref, payment_status, payment_ref, created_at, updated_at
                               FROM fee_invoices WHERE swap_id=%s ORDER BY created_at DESC LIMIT 1""",
                            (swap_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            'invoice_id': row[0], 'swap_id': row[1], 'fee_bps': int(row[2]), 'fee_amount': float(row[3]),
            'fee_asset': row[4], 'invoice_ref': row[5], 'payment_status': row[6], 'payment_ref': row[7],
            'created_at': row[8], 'updated_at': row[9]
        }

    def update_fee_invoice(self, invoice_id: str, payment_status: str, payment_ref: Optional[str] = None):
        now_ms = int(time.time() * 1000)
        current_ref = ''
        cur = self._execute("SELECT payment_ref FROM fee_invoices WHERE invoice_id=?"
                            if self.backend == 'sqlite'
                            else "SELECT payment_ref FROM fee_invoices WHERE invoice_id=%s",
                            (invoice_id,))
        row = cur.fetchone()
        if row:
            current_ref = row[0] or ''
        self._execute("""UPDATE fee_invoices SET payment_status=?, payment_ref=?, updated_at=? WHERE invoice_id=?"""
                      if self.backend == 'sqlite'
                      else """UPDATE fee_invoices SET payment_status=%s, payment_ref=%s, updated_at=%s WHERE invoice_id=%s""",
                      (payment_status, payment_ref or current_ref, now_ms, invoice_id))

    def close(self):
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass

STORAGE_DB = StorageDB(DB_BACKEND, DB_PATH, DB_DSN)

def store_shard_record(shard_name: str, shard_data: str, shard_dict: Optional[Dict[str, Any]],
                       relay_meta: Dict[str, Any], signature: Optional[str], sender_id: str):
    instruction_id = shard_name.split('_shard', 1)[0] if '_shard' in shard_name else ''
    shard_index = shard_dict.get('index') if shard_dict else None
    replica = None
    if '_v' in shard_name:
        try:
            replica = int(shard_name.rsplit('_v', 1)[1].split('.')[0])
        except Exception:
            replica = None
    STORAGE_DB.store_shard(
        shard_name=shard_name,
        instruction_id=instruction_id,
        shard_index=int(shard_index) if shard_index is not None else None,
        replica=replica or 1,
        data=shard_data,
        share=shard_dict.get('share') if shard_dict else None,
        signature=signature,
        sender_id=sender_id,
        destination=relay_meta.get('destination', ''),
        data_region=relay_meta.get('data_region', ''),
        relay_hops=int(relay_meta.get('relay_hops', 0)),
        received_at=int(relay_meta.get('received_at', int(time.time())))
    )

def get_shard_record(shard_name: str) -> Optional[Dict[str, Any]]:
    return STORAGE_DB.get_shard(shard_name)

def shard_exists(shard_name: str) -> bool:
    return get_shard_record(shard_name) is not None

def store_manifest_record(instruction_id: str, manifest: Dict[str, Any]):
    STORAGE_DB.store_manifest(instruction_id, manifest)

def get_manifest_record(instruction_id: str) -> Optional[Dict[str, Any]]:
    return STORAGE_DB.get_manifest(instruction_id)

def list_manifest_records() -> List[Dict[str, Any]]:
    return STORAGE_DB.list_manifests()
# ===== KEY MANAGEMENT (KMS/HSM-READY) =====
KEY_STORE_PATH = _config('key_store_path', 'oneseam_keys.json')
DEFAULT_SIGNING_KEY_ID = _config('signing_key_id', 'node_signing')

class KeyProvider:
    """Abstract key provider interface."""
    def get_key(self, key_id: str) -> Tuple[bytes, int]:
        raise NotImplementedError
    def rotate_key(self, key_id: str) -> Tuple[bytes, int]:
        raise NotImplementedError

class LocalKeyProvider(KeyProvider):
    """Local file-based key provider (on-prem)."""
    def __init__(self, path: str):
        self.path = path
        self._cache = None
    
    def _load(self) -> Dict[str, Dict[str, Any]]:
        if self._cache is not None:
            return self._cache
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    self._cache = json.load(f)
                    return self._cache
            except (OSError, json.JSONDecodeError, TypeError):
                pass
        self._cache = {}
        return self._cache
    
    def _save(self, data: Dict[str, Dict[str, Any]]):
        with open(self.path, 'w') as f:
            json.dump(data, f, indent=2)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
    
    def get_key(self, key_id: str) -> Tuple[bytes, int]:
        data = self._load()
        entry = data.get(key_id)
        if entry:
            return base64.b64decode(entry['material']), int(entry.get('version', 1))
        key = os.urandom(32)
        entry = {
            'version': 1,
            'material': base64.b64encode(key).decode('ascii')
        }
        data[key_id] = entry
        self._save(data)
        return key, 1
    
    def rotate_key(self, key_id: str) -> Tuple[bytes, int]:
        data = self._load()
        entry = data.get(key_id, {'version': 0})
        version = int(entry.get('version', 0)) + 1
        key = os.urandom(32)
        data[key_id] = {
            'version': version,
            'material': base64.b64encode(key).decode('ascii')
        }
        self._save(data)
        return key, version

class EnvKeyProvider(KeyProvider):
    """Environment-based key provider (dev only)."""
    def get_key(self, key_id: str) -> Tuple[bytes, int]:
        env = os.environ.get('ONESEAM_KEYS_JSON', '').strip()
        if not env:
            raise RuntimeError("ONESEAM_KEYS_JSON not set")
        data = json.loads(env)
        entry = data.get(key_id)
        if not entry:
            raise RuntimeError(f"Key not found: {key_id}")
        return base64.b64decode(entry['material']), int(entry.get('version', 1))
    def rotate_key(self, key_id: str) -> Tuple[bytes, int]:
        raise RuntimeError("EnvKeyProvider does not support rotation")

KEY_PROVIDER = LocalKeyProvider(KEY_STORE_PATH)

def get_signing_key() -> Tuple[bytes, int, str]:
    key, version = KEY_PROVIDER.get_key(DEFAULT_SIGNING_KEY_ID)
    return key, version, DEFAULT_SIGNING_KEY_ID

def _load_or_create_shard_signing_keys() -> Tuple[ed25519.Ed25519PrivateKey, bytes]:
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography required for shard signing")
    priv = None
    pub_bytes = None
    if SHARD_SIGNING_PRIVATE_KEY and os.path.exists(SHARD_SIGNING_PRIVATE_KEY):
        with open(SHARD_SIGNING_PRIVATE_KEY, 'rb') as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
    if priv is None:
        priv = ed25519.Ed25519PrivateKey.generate()
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(SHARD_SIGNING_PRIVATE_KEY, 'wb') as f:
            f.write(pem)
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if SHARD_SIGNING_PUBLIC_KEY and not os.path.exists(SHARD_SIGNING_PUBLIC_KEY):
        with open(SHARD_SIGNING_PUBLIC_KEY, 'wb') as f:
            f.write(pub_bytes)
    return priv, pub_bytes

def get_node_signing_public() -> str:
    _, pub_bytes = _load_or_create_shard_signing_keys()
    return pub_bytes.decode('utf-8')

def sign_shard_payload(shard_name: str, shard_data: str, instruction_id: str) -> str:
    priv, _ = _load_or_create_shard_signing_keys()
    msg = f"{shard_name}|{instruction_id}|{shard_data}".encode()
    sig = priv.sign(msg)
    return base64.b64encode(sig).decode('ascii')

def verify_shard_signature(sender_id: str, shard_name: str, shard_data: str, instruction_id: str, signature: str) -> bool:
    if not signature:
        return False
    pub_pem = TRUSTED_NODE_PUBKEYS.get(sender_id) or neighbors.get(sender_id, {}).get('signing_pub')
    if not pub_pem:
        return False
    try:
        pub = serialization.load_pem_public_key(pub_pem.encode('utf-8'))
        msg = f"{shard_name}|{instruction_id}|{shard_data}".encode()
        pub.verify(base64.b64decode(signature), msg)
        return True
    except Exception:
        return False

# ===== JWT AUTH =====
def _load_jwt_public_keys() -> List[str]:
    keys = []
    for item in JWT_PUBLIC_KEYS:
        if not item:
            continue
        if isinstance(item, str) and 'BEGIN PUBLIC KEY' in item:
            keys.append(item)
            continue
        if isinstance(item, str) and os.path.exists(item):
            try:
                with open(item) as f:
                    keys.append(f.read())
            except OSError:
                continue
    return keys

JWT_PUBLIC_KEY_CACHE = _load_jwt_public_keys()

def _verify_jwt(token: str) -> Optional[Dict[str, Any]]:
    if not JWT_AVAILABLE:
        raise RuntimeError("PyJWT not installed")
    if not JWT_PUBLIC_KEY_CACHE:
        raise RuntimeError("No JWT public keys configured")
    last_error = None
    for key in JWT_PUBLIC_KEY_CACHE:
        try:
            return jwt.decode(
                token,
                key=key,
                algorithms=JWT_ALGORITHMS,
                issuer=JWT_ISSUER if JWT_ISSUER else None,
                audience=JWT_AUDIENCE if JWT_AUDIENCE else None,
                options={"require": ["exp", "sub"]}
            )
        except Exception as e:
            last_error = e
            continue
    raise last_error or RuntimeError("JWT verification failed")

# ===== RATE LIMITING =====
_rate_state = {}
_idempotency_cache = {}

def _rate_limit_ok(client_id: str, endpoint: str) -> bool:
    now = time.time()
    key = (client_id, endpoint)
    state = _rate_state.get(key)
    if state is None:
        _rate_state[key] = {'tokens': RATE_LIMIT_BURST - 1, 'last': now}
        return True
    elapsed = now - state['last']
    refill = elapsed * RATE_LIMIT_RPS
    state['tokens'] = min(RATE_LIMIT_BURST, state['tokens'] + refill)
    state['last'] = now
    if state['tokens'] >= 1:
        state['tokens'] -= 1
        return True
    return False

def _idempotency_cleanup(now: float):
    if len(_idempotency_cache) <= IDEMPOTENCY_MAX_ENTRIES:
        return
    expired = [k for k, v in _idempotency_cache.items()
               if now - v.get('ts', 0) > IDEMPOTENCY_TTL_SECONDS]
    for k in expired:
        _idempotency_cache.pop(k, None)
    if len(_idempotency_cache) > IDEMPOTENCY_MAX_ENTRIES:
        for k in list(_idempotency_cache.keys())[:len(_idempotency_cache) - IDEMPOTENCY_MAX_ENTRIES]:
            _idempotency_cache.pop(k, None)

def idempotency_get(client_id: str, key: str):
    now = time.time()
    entry = _idempotency_cache.get((client_id, key))
    if not entry:
        return None
    if now - entry.get('ts', 0) > IDEMPOTENCY_TTL_SECONDS:
        _idempotency_cache.pop((client_id, key), None)
        return None
    return entry

def idempotency_put(client_id: str, key: str, payload: Dict[str, Any], status: int):
    now = time.time()
    _idempotency_cache[(client_id, key)] = {'ts': now, 'payload': payload, 'status': status}
    _idempotency_cleanup(now)

# ===== OTC DOMAIN (RFQ/TRADES/ESCROW) =====
def generate_rfq_id() -> str:
    return f"rfq_{int(time.time())}_{secrets.token_hex(4)}"

def generate_trade_id() -> str:
    return f"trade_{int(time.time())}_{secrets.token_hex(4)}"

def _normalize_wallet(wallet_address: str) -> str:
    return (wallet_address or '').strip().lower()

def _normalize_asset(asset: str) -> str:
    return (asset or '').strip().upper()

def _ensure_allowed_assets(base_asset: str, quote_asset: str):
    base = _normalize_asset(base_asset)
    quote = _normalize_asset(quote_asset)
    if ALLOWED_BASE_ASSETS and base not in ALLOWED_BASE_ASSETS:
        raise ValueError(f"Unsupported base asset: {base}")
    if ALLOWED_QUOTE_ASSETS and quote not in ALLOWED_QUOTE_ASSETS:
        raise ValueError(f"Unsupported quote asset: {quote}")
    if base == quote:
        raise ValueError("base_asset and quote_asset must be different")

def _ensure_allowed_intent_assets(sell_asset: str, buy_asset: str):
    sell = _normalize_asset(sell_asset)
    buy = _normalize_asset(buy_asset)
    allowed = set(ALLOWED_BASE_ASSETS) | set(ALLOWED_QUOTE_ASSETS)
    if allowed and sell not in allowed:
        raise ValueError(f"Unsupported sell asset: {sell}")
    if allowed and buy not in allowed:
        raise ValueError(f"Unsupported buy asset: {buy}")
    if sell == buy:
        raise ValueError("sell_asset and buy_asset must be different")

def _calculate_trade_fee(notional_amount: float, fee_bps: int) -> float:
    return round((float(notional_amount) * float(fee_bps)) / 10000.0, 8)

def _ensure_wallet_authorized(client: Dict[str, Any], wallet_address: str, chain_id: int):
    wallet = _normalize_wallet(wallet_address)
    if not wallet:
        raise ValueError("wallet_address is required")
    client_id = client.get('client_id', '')
    if WALLET_BINDING_REQUIRED and not STORAGE_DB.wallet_bound(client_id, wallet, chain_id):
        raise PermissionError("wallet not bound to authenticated client")
    claims = client.get('claims') or {}
    if isinstance(claims, dict):
        claim_wallets = claims.get('wallets') or claims.get('wallet_addresses') or []
        if isinstance(claim_wallets, str):
            claim_wallets = [claim_wallets]
        normalized = {_normalize_wallet(w) for w in claim_wallets if w}
        if normalized and wallet not in normalized:
            raise PermissionError("wallet not permitted by JWT claims")

def _canonical_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, separators=(',', ':'), sort_keys=True)

def _normalize_signature(signature: str) -> str:
    sig = (signature or '').strip()
    if not sig:
        return ''
    return sig if sig.startswith('0x') else f'0x{sig}'

def _normalize_tx_hash(tx_hash: str) -> str:
    raw = (tx_hash or '').strip().lower()
    if raw.startswith('0x'):
        raw = raw[2:]
    if len(raw) != 64 or any(c not in '0123456789abcdef' for c in raw):
        raise ValueError('invalid_tx_hash')
    return f'0x{raw}'

def _recover_wallet_from_signature(message_text: str, signature: str) -> str:
    if not EVM_SIGNATURE_AVAILABLE:
        raise RuntimeError("wallet_attestation_unavailable")
    sig = _normalize_signature(signature)
    if not sig:
        raise ValueError("wallet_signature_required")
    try:
        recovered = Account.recover_message(encode_defunct(text=message_text), signature=sig)
    except Exception:
        raise ValueError("wallet_signature_invalid")
    return _normalize_wallet(recovered)

def _sign_message_with_env_wallet(message_text: str, wallet_hint: str = '') -> str:
    if not EVM_SIGNATURE_AVAILABLE:
        return ''
    raw_key = (os.environ.get('ONESEAM_WALLET_PRIVATE_KEY', '') or '').strip()
    if not raw_key:
        return ''
    key = raw_key if raw_key.startswith('0x') else f'0x{raw_key}'
    try:
        account = Account.from_key(key)
    except Exception:
        raise ValueError('invalid_env_wallet_private_key')
    normalized_hint = _normalize_wallet(wallet_hint)
    if normalized_hint and _normalize_wallet(account.address) != normalized_hint:
        raise PermissionError('env_wallet_key_mismatch')
    signed = Account.sign_message(encode_defunct(text=message_text), private_key=key)
    return '0x' + signed.signature.hex()

def _build_trade_intent_attestation_payload(client: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    metadata_hash = sha256(_canonical_json(data.get('metadata') or {}).encode('utf-8')).hexdigest()
    private_terms_hash = sha256(_canonical_json(data.get('private_terms') or {}).encode('utf-8')).hexdigest()
    return {
        'kind': 'oneseam.trade_intent.v1',
        'maker_client_id': client.get('client_id', ''),
        'maker_wallet': _normalize_wallet(data.get('maker_wallet', '')),
        'sell_asset': _normalize_asset(data.get('sell_asset', '')),
        'buy_asset': _normalize_asset(data.get('buy_asset', '')),
        'amount': float(data.get('amount', 0)),
        'price_min': float(data.get('price_min', 0)),
        'price_max': float(data.get('price_max', 0)),
        'expiration': int(data.get('expiration', 0)),
        'wallet_nonce': (data.get('wallet_nonce') or '').strip(),
        'metadata_hash': metadata_hash,
        'private_terms_hash': private_terms_hash
    }

def prepare_trade_intent_signature(client: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    payload = _build_trade_intent_attestation_payload(client, data)
    message_text = _canonical_json(payload)
    return {
        'wallet': payload['maker_wallet'],
        'payload': payload,
        'message': message_text,
        'message_hash': sha256(message_text.encode('utf-8')).hexdigest(),
    }

def _verify_trade_intent_wallet_signature(client: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    if WALLET_ATTESTATION_REQUIRED and not EVM_SIGNATURE_AVAILABLE:
        raise RuntimeError("wallet_attestation_unavailable")
    prepared = prepare_trade_intent_signature(client, data)
    signature = (data.get('wallet_signature') or '').strip()
    if not signature:
        if WALLET_ATTESTATION_REQUIRED:
            raise ValueError("wallet_signature_required")
        return {'verified': False, 'wallet': prepared['wallet'], 'message_hash': prepared['message_hash'], 'signature_hash': ''}
    recovered = _recover_wallet_from_signature(prepared['message'], signature)
    if recovered != prepared['wallet']:
        raise PermissionError("wallet_signature_wallet_mismatch")
    return {
        'verified': True,
        'wallet': recovered,
        'message_hash': prepared['message_hash'],
        'signature_hash': sha256(_normalize_signature(signature).encode('utf-8')).hexdigest(),
    }

def _build_htlc_proof_attestation_payload(client: Dict[str, Any], swap: Dict[str, Any], proof: Dict[str, Any], signer_wallet: str) -> Dict[str, Any]:
    secret_hash = ''
    if proof.get('secret'):
        secret_hash = sha256(str(proof.get('secret')).encode('utf-8')).hexdigest()
    return {
        'kind': 'oneseam.htlc_proof.v1',
        'swap_id': swap.get('swap_id', ''),
        'actor_client_id': client.get('client_id', ''),
        'proof_type': str(proof.get('proof_type', '')).strip(),
        'tx_hash': _normalize_tx_hash(str(proof.get('tx_hash', '')).strip()),
        'confirmations': int(proof.get('confirmations', 0)),
        'secret_hash': secret_hash,
        'signer_wallet': _normalize_wallet(signer_wallet),
        'wallet_nonce': str(proof.get('wallet_nonce', '') or '').strip(),
    }

def prepare_htlc_proof_signature(client: Dict[str, Any], swap: Dict[str, Any], proof: Dict[str, Any], signer_wallet: str) -> Dict[str, Any]:
    payload = _build_htlc_proof_attestation_payload(client, swap, proof, signer_wallet)
    message_text = _canonical_json(payload)
    return {
        'wallet': payload['signer_wallet'],
        'payload': payload,
        'message': message_text,
        'message_hash': sha256(message_text.encode('utf-8')).hexdigest(),
    }

def _verify_htlc_proof_wallet_signature(client: Dict[str, Any], swap: Dict[str, Any], proof: Dict[str, Any], signer_wallet: str) -> Dict[str, Any]:
    if PROOF_WALLET_ATTESTATION_REQUIRED and not EVM_SIGNATURE_AVAILABLE:
        raise RuntimeError("wallet_attestation_unavailable")
    prepared = prepare_htlc_proof_signature(client, swap, proof, signer_wallet)
    signature = (proof.get('wallet_signature') or '').strip()
    if not signature:
        if PROOF_WALLET_ATTESTATION_REQUIRED:
            raise ValueError("wallet_signature_required")
        return {'verified': False, 'wallet': prepared['wallet'], 'message_hash': prepared['message_hash'], 'signature_hash': ''}
    recovered = _recover_wallet_from_signature(prepared['message'], signature)
    if recovered != prepared['wallet']:
        raise PermissionError("wallet_signature_wallet_mismatch")
    return {
        'verified': True,
        'wallet': recovered,
        'message_hash': prepared['message_hash'],
        'signature_hash': sha256(_normalize_signature(signature).encode('utf-8')).hexdigest(),
    }

def _production_readiness_issues() -> List[str]:
    issues: List[str] = []
    if not PRODUCTION_MODE:
        return issues
    if not DARKPOOL_ENABLED:
        issues.append('darkpool_disabled')
    if BLIND_MATCHING_ENABLED and not BLIND_MATCHING_AVAILABLE:
        issues.append('blind_matching_module_missing')
    if LEGACY_OTC_API_ENABLED:
        issues.append('legacy_otc_api_enabled')
    if not TLS_ENABLED:
        issues.append('tls_required')
    if ALLOW_LEGACY_API_KEYS:
        issues.append('legacy_api_keys_enabled')
    if not JWT_PUBLIC_KEY_CACHE:
        issues.append('jwt_public_keys_missing')
    if not P2P_TLS_ENABLED:
        issues.append('p2p_tls_required')
    if not P2P_MTLS_REQUIRED:
        issues.append('p2p_mtls_required')
    if P2P_MTLS_REQUIRED and not P2P_MTLS_CA_PATH:
        issues.append('p2p_mtls_ca_missing')
    if not SHARD_SIGNATURE_REQUIRED:
        issues.append('shard_signature_required')
    if not WALLET_ATTESTATION_REQUIRED:
        issues.append('wallet_attestation_required')
    if not PROOF_WALLET_ATTESTATION_REQUIRED:
        issues.append('proof_wallet_attestation_required')
    if (WALLET_ATTESTATION_REQUIRED or PROOF_WALLET_ATTESTATION_REQUIRED) and not EVM_SIGNATURE_AVAILABLE:
        issues.append('wallet_attestation_unavailable')
    if PROOF_SERVER_SIDE_VERIFICATION_REQUIRED:
        if not PROOF_VERIFIER_URL and not BTC_RPC_URL:
            issues.append('proof_verifier_or_btc_rpc_missing')
        if not _is_btc_chain_name(HTLC_CHAIN_B) and not PROOF_VERIFIER_URL:
            issues.append('proof_verifier_url_missing_for_chain_b')
    return issues

def _assert_production_ready_or_raise():
    issues = _production_readiness_issues()
    if issues:
        raise RuntimeError('production_not_ready:' + ','.join(issues))

def _post_json(url: str, payload: Dict[str, Any], timeout_seconds: int = 8, auth_token: str = '') -> Dict[str, Any]:
    body = json.dumps(payload).encode('utf-8')
    headers = {'Content-Type': 'application/json'}
    if auth_token:
        headers['Authorization'] = f'Bearer {auth_token}'
    req = urllib.request.Request(url=url, data=body, headers=headers, method='POST')
    with urllib.request.urlopen(req, timeout=max(1, int(timeout_seconds))) as resp:
        content = resp.read().decode('utf-8')
    try:
        data = json.loads(content) if content else {}
    except Exception:
        data = {}
    if not isinstance(data, dict):
        raise ValueError('proof_verifier_invalid_response')
    return data

def _is_btc_chain_name(chain: str) -> bool:
    return str(chain or '').strip().upper() in ('BTC', 'BITCOIN')

def _btc_rpc_call(method: str, params: Optional[List[Any]] = None) -> Any:
    if not BTC_RPC_URL:
        raise RuntimeError('btc_rpc_unavailable')
    payload = {
        'jsonrpc': '2.0',
        'id': 'oneseam',
        'method': method,
        'params': params or [],
    }
    body = json.dumps(payload).encode('utf-8')
    headers = {'Content-Type': 'application/json'}
    if BTC_RPC_USER or BTC_RPC_PASSWORD:
        token = base64.b64encode(f"{BTC_RPC_USER}:{BTC_RPC_PASSWORD}".encode('utf-8')).decode('ascii')
        headers['Authorization'] = f'Basic {token}'
    req = urllib.request.Request(url=BTC_RPC_URL, data=body, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=max(1, BTC_RPC_TIMEOUT_SECONDS)) as resp:
            content = resp.read().decode('utf-8')
    except urllib.error.URLError:
        raise RuntimeError('btc_rpc_unreachable')
    except Exception:
        raise RuntimeError('btc_rpc_error')
    try:
        data = json.loads(content) if content else {}
    except Exception:
        raise RuntimeError('btc_rpc_invalid_response')
    if not isinstance(data, dict):
        raise RuntimeError('btc_rpc_invalid_response')
    if data.get('error'):
        raise RuntimeError('btc_rpc_error')
    return data.get('result')

def _verify_htlc_proof_via_btc_rpc(tx_hash: str) -> Dict[str, Any]:
    txid = tx_hash[2:] if tx_hash.startswith('0x') else tx_hash
    tx = _btc_rpc_call('getrawtransaction', [txid, True])
    if not isinstance(tx, dict):
        raise RuntimeError('btc_rpc_invalid_response')
    confirmations = int(tx.get('confirmations', 0) or 0)
    observed_txid = str(tx.get('txid', txid)).strip().lower()
    normalized = observed_txid if observed_txid.startswith('0x') else f'0x{observed_txid}'
    return {
        'verifier': 'btc_rpc',
        'tx_hash': normalized,
        'confirmations': confirmations,
    }

def _verify_htlc_proof_server_side(swap: Dict[str, Any], proof: Dict[str, Any]) -> Dict[str, Any]:
    tx_hash = _normalize_tx_hash(str(proof.get('tx_hash', '')).strip())
    chain = HTLC_CHAIN_A if str(proof.get('proof_type', '')).strip().endswith('_a') else HTLC_CHAIN_B
    if _is_btc_chain_name(chain) and BTC_RPC_URL:
        return _verify_htlc_proof_via_btc_rpc(tx_hash)
    if not PROOF_VERIFIER_URL:
        if PROOF_SERVER_SIDE_VERIFICATION_REQUIRED:
            raise RuntimeError('proof_verifier_missing')
        return {
            'verifier': 'client_declared',
            'tx_hash': tx_hash,
            'confirmations': int(proof.get('confirmations', 0))
        }
    payload = {
        'swap_id': swap.get('swap_id', ''),
        'match_id': swap.get('match_id', ''),
        'chain': chain,
        'proof': {
            'proof_type': str(proof.get('proof_type', '')).strip(),
            'tx_hash': tx_hash,
            'confirmations': int(proof.get('confirmations', 0)),
            'secret_hash': sha256(str(proof.get('secret', '')).encode('utf-8')).hexdigest() if proof.get('secret') else '',
            'metadata': proof.get('metadata') or {}
        }
    }
    try:
        result = _post_json(PROOF_VERIFIER_URL, payload, timeout_seconds=PROOF_VERIFIER_TIMEOUT_SECONDS, auth_token=PROOF_VERIFIER_AUTH_TOKEN)
    except urllib.error.URLError:
        raise RuntimeError('proof_verifier_unreachable')
    except Exception:
        raise RuntimeError('proof_verifier_error')
    ok = bool(result.get('ok', False))
    if not ok:
        reason = str(result.get('error', '') or 'proof_verification_failed')
        raise ValueError(reason)
    observed_tx = str(result.get('tx_hash', tx_hash)).strip().lower()
    if observed_tx and observed_tx != tx_hash:
        raise ValueError('proof_tx_hash_mismatch')
    return {
        'verifier': str(result.get('verifier', 'external')),
        'tx_hash': tx_hash,
        'confirmations': int(result.get('confirmations', 0))
    }

def _trade_actor_allowed(client: Dict[str, Any], trade: Dict[str, Any]) -> bool:
    roles = client.get('roles') or []
    if 'admin' in roles:
        return True
    actor = client.get('client_id', '')
    return actor in (trade.get('buyer_client_id'), trade.get('seller_client_id'))

def _persist_private_otc_payload(origin_client_id: str, destination_client_id: str,
                                 payload_obj: Dict[str, Any]) -> str:
    payload_text = json.dumps(payload_obj, separators=(',', ':'))
    instr = create_financial_instruction(
        payload=payload_text,
        origin=origin_client_id,
        destination=destination_client_id or origin_client_id
    )
    k, n = DEFAULT_QUORUM_K, DEFAULT_QUORUM_N
    if not SSS_AVAILABLE:
        k = n
    instr_json = json.dumps(instr)
    if SSS_AVAILABLE:
        encrypted_b64, shard_dicts = shard_instruction(instr_json, k, n)
        manifest = create_instruction_manifest(
            instr,
            [],
            encrypted_payload_b64=encrypted_b64,
            shard_dicts=shard_dicts,
            quorum_k=k,
            quorum_n=n
        )
        manifest['shards'] = [
            f"{instr['instruction_id']}_shard{s['index']}_v{r+1}.json"
            for s in shard_dicts for r in range(3)
        ]
        distribute_shards_smart(shard_dicts, instr['instruction_id'], destination_client_id, manifest, k, n, use_sss=True)
    else:
        shards = split_text(instr_json, n)
        manifest = create_instruction_manifest(instr, shards, quorum_k=k, quorum_n=n)
        manifest['shards'] = [f"{instr['instruction_id']}_shard{i+1}_v{r+1}.json" for i in range(n) for r in range(3)]
        distribute_shards_smart(shards, instr['instruction_id'], destination_client_id, manifest, k, n, use_sss=False)
    return instr['instruction_id']

def otc_bind_wallet(client: Dict[str, Any], wallet_address: str, chain_id: int) -> Dict[str, Any]:
    wallet = _normalize_wallet(wallet_address)
    if not wallet:
        raise ValueError("wallet_address is required")
    STORAGE_DB.bind_wallet(client['client_id'], wallet, chain_id, status='active')
    append_audit_event(
        'wallet_bound',
        client['client_id'],
        details={'wallet': wallet, 'chain_id': chain_id}
    )
    return {'client_id': client['client_id'], 'wallet_address': wallet, 'chain_id': chain_id, 'status': 'active'}

def otc_create_rfq(client: Dict[str, Any], data: Dict[str, Any], request_id: str = '') -> Dict[str, Any]:
    if not OTC_ENABLED:
        raise RuntimeError("otc_disabled")
    maker_wallet = _normalize_wallet(data.get('maker_wallet', ''))
    _ensure_wallet_authorized(client, maker_wallet, EVM_CHAIN_ID)
    base_asset = _normalize_asset(data.get('base_asset', ''))
    quote_asset = _normalize_asset(data.get('quote_asset', ''))
    _ensure_allowed_assets(base_asset, quote_asset)
    base_amount = float(data.get('base_amount', 0))
    quote_amount = float(data.get('quote_amount', 0))
    if base_amount <= 0 or quote_amount <= 0:
        raise ValueError("base_amount and quote_amount must be positive")
    if quote_amount > OTC_MAX_TRADE_NOTIONAL:
        raise ValueError("trade exceeds otc_max_trade_notional")
    expires_in = int(data.get('expires_in_seconds', 900))
    if expires_in < 30 or expires_in > 7 * 24 * 3600:
        raise ValueError("expires_in_seconds out of bounds")
    rfq_id = generate_rfq_id()
    now_ms = int(time.time() * 1000)
    private_instruction_id = ''
    if data.get('private_terms'):
        private_instruction_id = _persist_private_otc_payload(
            client['client_id'],
            data.get('taker_client_id') or client['client_id'],
            {'kind': 'otc_rfq_private_terms', 'rfq_id': rfq_id, 'private_terms': data.get('private_terms')}
        )
    rfq = {
        'rfq_id': rfq_id,
        'maker_client_id': client['client_id'],
        'maker_wallet': maker_wallet,
        'taker_client_id': (data.get('taker_client_id') or '').strip(),
        'maker_side': (data.get('maker_side') or 'sell').strip().lower(),
        'base_asset': base_asset,
        'quote_asset': quote_asset,
        'base_amount': base_amount,
        'quote_amount': quote_amount,
        'price': round(quote_amount / base_amount, 12),
        'expires_at': now_ms + (expires_in * 1000),
        'status': RFQ_STATUS_OPEN,
        'metadata': data.get('metadata') or {},
        'private_instruction_id': private_instruction_id
    }
    if rfq['maker_side'] not in ('buy', 'sell'):
        raise ValueError("maker_side must be 'buy' or 'sell'")
    STORAGE_DB.create_rfq(rfq)
    append_audit_event(
        'rfq_created',
        client['client_id'],
        rfq_id,
        details={
            'base_asset': base_asset,
            'quote_asset': quote_asset,
            'base_amount': base_amount,
            'quote_amount': quote_amount
        },
        request_id=request_id
    )
    return rfq

def otc_accept_rfq(client: Dict[str, Any], rfq_id: str, taker_wallet: str, request_id: str = '') -> Dict[str, Any]:
    rfq = STORAGE_DB.get_rfq(rfq_id)
    if not rfq:
        raise ValueError("rfq_not_found")
    if rfq.get('status') != RFQ_STATUS_OPEN:
        raise ValueError("rfq_not_open")
    if int(rfq.get('expires_at', 0)) < int(time.time() * 1000):
        STORAGE_DB.update_rfq_status(rfq_id, RFQ_STATUS_EXPIRED)
        raise ValueError("rfq_expired")
    taker_client_id = client['client_id']
    rfq_taker = (rfq.get('taker_client_id') or '').strip()
    if rfq_taker and rfq_taker != taker_client_id:
        raise PermissionError("rfq_restricted_to_other_taker")
    taker_wallet_normalized = _normalize_wallet(taker_wallet)
    _ensure_wallet_authorized(client, taker_wallet_normalized, EVM_CHAIN_ID)

    if rfq.get('maker_side') == 'sell':
        buyer_client_id = taker_client_id
        buyer_wallet = taker_wallet_normalized
        seller_client_id = rfq['maker_client_id']
        seller_wallet = rfq['maker_wallet']
    else:
        buyer_client_id = rfq['maker_client_id']
        buyer_wallet = rfq['maker_wallet']
        seller_client_id = taker_client_id
        seller_wallet = taker_wallet_normalized

    fee_bps = OTC_DEFAULT_FEE_BPS
    fee_amount = _calculate_trade_fee(rfq['quote_amount'], fee_bps)
    trade = {
        'trade_id': generate_trade_id(),
        'rfq_id': rfq_id,
        'buyer_client_id': buyer_client_id,
        'seller_client_id': seller_client_id,
        'buyer_wallet': buyer_wallet,
        'seller_wallet': seller_wallet,
        'base_asset': rfq['base_asset'],
        'quote_asset': rfq['quote_asset'],
        'base_amount': float(rfq['base_amount']),
        'quote_amount': float(rfq['quote_amount']),
        'status': TRADE_STATUS_CREATED,
        'fee_bps': fee_bps,
        'fee_amount': fee_amount,
        'fee_asset': rfq['quote_asset'],
        'escrow_chain_id': EVM_CHAIN_ID,
        'escrow_factory': ESCROW_FACTORY_ADDRESS,
        'private_instruction_id': rfq.get('private_instruction_id', ''),
        'metadata': {'source': 'rfq_accept'}
    }
    STORAGE_DB.create_trade(trade)
    STORAGE_DB.update_rfq_status(rfq_id, RFQ_STATUS_ACCEPTED)
    half_fee = round(fee_amount / 2.0, 8)
    STORAGE_DB.record_trade_fee_event({
        'trade_id': trade['trade_id'],
        'client_id': trade['buyer_client_id'],
        'fee_bps': fee_bps,
        'notional_amount': trade['quote_amount'],
        'fee_amount': half_fee,
        'asset': trade['fee_asset'],
        'status': 'pending'
    })
    STORAGE_DB.record_trade_fee_event({
        'trade_id': trade['trade_id'],
        'client_id': trade['seller_client_id'],
        'fee_bps': fee_bps,
        'notional_amount': trade['quote_amount'],
        'fee_amount': half_fee,
        'asset': trade['fee_asset'],
        'status': 'pending'
    })
    append_audit_event('rfq_accepted', client['client_id'], rfq_id, request_id=request_id)
    append_audit_event('trade_created', client['client_id'], trade['trade_id'], request_id=request_id)
    return trade

def otc_create_trade_direct(client: Dict[str, Any], data: Dict[str, Any], request_id: str = '') -> Dict[str, Any]:
    buyer_client_id = (data.get('buyer_client_id') or '').strip()
    seller_client_id = (data.get('seller_client_id') or '').strip()
    if not buyer_client_id or not seller_client_id:
        raise ValueError("buyer_client_id and seller_client_id are required")
    if buyer_client_id == seller_client_id:
        raise ValueError("buyer and seller must be different")
    roles = client.get('roles') or []
    actor = client.get('client_id', '')
    if actor not in (buyer_client_id, seller_client_id) and 'admin' not in roles:
        raise PermissionError("actor must be one side of trade or admin")
    base_asset = _normalize_asset(data.get('base_asset', ''))
    quote_asset = _normalize_asset(data.get('quote_asset', ''))
    _ensure_allowed_assets(base_asset, quote_asset)
    base_amount = float(data.get('base_amount', 0))
    quote_amount = float(data.get('quote_amount', 0))
    if base_amount <= 0 or quote_amount <= 0:
        raise ValueError("base_amount and quote_amount must be positive")
    if quote_amount > OTC_MAX_TRADE_NOTIONAL:
        raise ValueError("trade exceeds otc_max_trade_notional")

    buyer_wallet = _normalize_wallet(data.get('buyer_wallet', ''))
    seller_wallet = _normalize_wallet(data.get('seller_wallet', ''))
    if actor == buyer_client_id:
        _ensure_wallet_authorized(
            {'client_id': buyer_client_id, 'claims': client.get('claims'), 'roles': roles},
            buyer_wallet,
            EVM_CHAIN_ID
        )
    elif 'admin' in roles:
        _ensure_wallet_authorized(
            {'client_id': buyer_client_id, 'claims': {}, 'roles': roles},
            buyer_wallet,
            EVM_CHAIN_ID
        )
    if actor == seller_client_id:
        _ensure_wallet_authorized(
            {'client_id': seller_client_id, 'claims': client.get('claims'), 'roles': roles},
            seller_wallet,
            EVM_CHAIN_ID
        )
    elif 'admin' in roles:
        _ensure_wallet_authorized(
            {'client_id': seller_client_id, 'claims': {}, 'roles': roles},
            seller_wallet,
            EVM_CHAIN_ID
        )

    fee_bps = OTC_DEFAULT_FEE_BPS
    fee_amount = _calculate_trade_fee(quote_amount, fee_bps)
    trade_id = generate_trade_id()
    private_instruction_id = ''
    if data.get('private_terms'):
        private_instruction_id = _persist_private_otc_payload(
            buyer_client_id,
            seller_client_id,
            {'kind': 'otc_trade_private_terms', 'trade_id': trade_id, 'private_terms': data.get('private_terms')}
        )
    trade = {
        'trade_id': trade_id,
        'rfq_id': '',
        'buyer_client_id': buyer_client_id,
        'seller_client_id': seller_client_id,
        'buyer_wallet': buyer_wallet,
        'seller_wallet': seller_wallet,
        'base_asset': base_asset,
        'quote_asset': quote_asset,
        'base_amount': base_amount,
        'quote_amount': quote_amount,
        'status': TRADE_STATUS_CREATED,
        'fee_bps': fee_bps,
        'fee_amount': fee_amount,
        'fee_asset': quote_asset,
        'escrow_chain_id': EVM_CHAIN_ID,
        'escrow_factory': ESCROW_FACTORY_ADDRESS,
        'private_instruction_id': private_instruction_id,
        'metadata': data.get('metadata') or {}
    }
    STORAGE_DB.create_trade(trade)
    half_fee = round(fee_amount / 2.0, 8)
    for cid in (buyer_client_id, seller_client_id):
        STORAGE_DB.record_trade_fee_event({
            'trade_id': trade_id,
            'client_id': cid,
            'fee_bps': fee_bps,
            'notional_amount': quote_amount,
            'fee_amount': half_fee,
            'asset': quote_asset,
            'status': 'pending'
        })
    append_audit_event('trade_created', client['client_id'], trade_id, request_id=request_id)
    return trade

class OTCEscrow:
    def __init__(self):
        self.w3 = None
        self.contract = None
        self.contract_abi = None
        self.contract_address = ''

    def _ensure_ready(self):
        if not WEB3_AVAILABLE:
            raise RuntimeError("web3_not_installed")
        if not EVM_RPC_URL:
            raise RuntimeError("evm_rpc_url_not_configured")
        if self.w3:
            return
        self.w3 = Web3(Web3.HTTPProvider(EVM_RPC_URL, request_kwargs={'timeout': 20}))
        if not self.w3.is_connected():
            raise RuntimeError("evm_rpc_unreachable")

    def _ensure_contract(self, require_abi: bool = True):
        self._ensure_ready()
        if not ESCROW_CONTRACT_ADDRESS:
            raise RuntimeError("escrow_contract_not_configured")
        if not Web3.is_address(ESCROW_CONTRACT_ADDRESS):
            raise RuntimeError("escrow_contract_invalid_address")
        if not self.contract_address:
            self.contract_address = Web3.to_checksum_address(ESCROW_CONTRACT_ADDRESS)

        if not require_abi and self.contract is not None:
            return
        if self.contract_abi is None:
            if not ESCROW_CONTRACT_ABI_PATH:
                raise RuntimeError("escrow_abi_not_configured")
            if not os.path.exists(ESCROW_CONTRACT_ABI_PATH):
                raise RuntimeError("escrow_abi_not_found")
            with open(ESCROW_CONTRACT_ABI_PATH, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            abi = raw.get('abi') if isinstance(raw, dict) else raw
            if not isinstance(abi, list):
                raise RuntimeError("escrow_abi_invalid")
            self.contract_abi = abi
        if self.contract is None:
            self.contract = self.w3.eth.contract(address=self.contract_address, abi=self.contract_abi)

    @staticmethod
    def _normalize_tx_hash(tx_hash: str) -> str:
        value = (tx_hash or '').strip().lower()
        if not value.startswith('0x') or len(value) != 66:
            raise ValueError("invalid_tx_hash")
        return value

    @staticmethod
    def _normalize_ref(value: Any) -> str:
        if value is None:
            return ''
        if isinstance(value, (bytes, bytearray)):
            return '0x' + bytes(value).hex()
        return str(value).strip().lower()

    @staticmethod
    def _json_safe(value: Any) -> Any:
        if isinstance(value, (bytes, bytearray)):
            return '0x' + bytes(value).hex()
        if isinstance(value, list):
            return [OTCEscrow._json_safe(v) for v in value]
        if isinstance(value, tuple):
            return [OTCEscrow._json_safe(v) for v in value]
        if isinstance(value, dict):
            return {str(k): OTCEscrow._json_safe(v) for k, v in value.items()}
        try:
            json.dumps(value)
            return value
        except Exception:
            return str(value)

    def _to_checksum_wallet(self, wallet_address: str, field: str) -> str:
        wallet = (wallet_address or '').strip()
        if not wallet:
            raise ValueError(f"{field}_required")
        if not Web3.is_address(wallet):
            raise ValueError(f"{field}_invalid")
        return Web3.to_checksum_address(wallet)

    def _asset_decimals(self, asset_symbol: str) -> int:
        symbol = _normalize_asset(asset_symbol)
        cfg = OTC_ASSETS.get(symbol) or OTC_ASSETS.get(symbol.lower()) or {}
        if isinstance(cfg, dict):
            try:
                return max(0, min(30, int(cfg.get('decimals', 8))))
            except Exception:
                return 8
        return 8

    def _encode_amount(self, amount: float, asset_symbol: str) -> int:
        decimals = self._asset_decimals(asset_symbol)
        scaled = int(round(float(amount) * (10 ** decimals)))
        if scaled <= 0:
            raise ValueError("invalid_amount")
        return scaled

    def _build_action_call(self, trade: Dict[str, Any], action: str, timeout_seconds: Optional[int] = None):
        if action == OTC_ACTION_ESCROW_CREATE:
            timeout = int(timeout_seconds) if timeout_seconds is not None else ESCROW_PREPARE_TTL_SECONDS
            timeout = max(60, min(timeout, 7 * 24 * 3600))
            timeout_at = int(time.time()) + timeout
            args = [
                trade['trade_id'],
                self._to_checksum_wallet(trade.get('buyer_wallet', ''), 'buyer_wallet'),
                self._to_checksum_wallet(trade.get('seller_wallet', ''), 'seller_wallet'),
                trade.get('base_asset', ''),
                trade.get('quote_asset', ''),
                self._encode_amount(float(trade.get('base_amount', 0)), trade.get('base_asset', '')),
                self._encode_amount(float(trade.get('quote_amount', 0)), trade.get('quote_asset', '')),
                timeout_at
            ]
            return 'createTrade', args, {'limit': 350000}
        if action == OTC_ACTION_SETTLE:
            return 'settleTrade', [trade['trade_id']], {'limit': 220000}
        if action == OTC_ACTION_REFUND:
            return 'refundTrade', [trade['trade_id']], {'limit': 220000}
        raise ValueError("invalid_trade_action")

    def prepare_action_payload(self, trade: Dict[str, Any], action: str, timeout_seconds: Optional[int] = None) -> Dict[str, Any]:
        self._ensure_contract(require_abi=True)
        fn_name, args, gas_hint = self._build_action_call(trade, action, timeout_seconds)
        try:
            data = self.contract.encodeABI(fn_name=fn_name, args=args)
        except Exception:
            fn = getattr(self.contract.functions, fn_name)(*args)
            data = fn._encode_transaction_data()
        now_ms = int(time.time() * 1000)
        ttl = int(timeout_seconds) if timeout_seconds is not None else ESCROW_PREPARE_TTL_SECONDS
        ttl = max(60, min(ttl, 7 * 24 * 3600))
        return {
            'to': self.contract_address,
            'data': data,
            'value': '0',
            'chain_id': EVM_CHAIN_ID,
            'gas_hint': gas_hint,
            'action': action,
            'trade_id': trade['trade_id'],
            'contract_name': ESCROW_CONTRACT_NAME,
            'contract_version': ESCROW_CONTRACT_VERSION,
            'contract_address': self.contract_address,
            'expires_at': now_ms + (ttl * 1000)
        }

    def _extract_expected_event(self, receipt: Any, expected_event: str) -> Dict[str, Any]:
        self._ensure_contract(require_abi=True)
        event_cls = getattr(self.contract.events, expected_event, None)
        if event_cls is None:
            raise ValueError("wrong_event")
        events = event_cls().process_receipt(receipt)
        if not events:
            raise ValueError("wrong_event")
        event = events[0]
        raw_args = dict(event.get('args', {}) or {})
        args = {k: self._json_safe(v) for k, v in raw_args.items()}
        return {'event_name': event.get('event', expected_event), 'args': args}

    def verify_submitted_action(self, tx_hash: str, trade: Dict[str, Any], action: str,
                                escrow_trade_ref: Optional[str] = None) -> Dict[str, Any]:
        expected_event = OTC_ACTION_EVENT_MAP.get(action)
        if not expected_event:
            raise ValueError("invalid_trade_action")

        normalized = self._normalize_tx_hash(tx_hash)
        result = {
            'tx_hash': normalized,
            'verified': False,
            'block_number': 0,
            'confirmations': 0,
            'chain_id': EVM_CHAIN_ID,
            'contract_address': ESCROW_CONTRACT_ADDRESS,
            'event_name': '',
            'event_args': {}
        }
        if not ESCROW_VERIFY_ON_SUBMIT:
            return result

        self._ensure_contract(require_abi=ESCROW_EVENT_STRICT_VALIDATION)
        try:
            receipt = self.w3.eth.get_transaction_receipt(normalized)
        except Exception:
            raise ValueError("tx_not_found")
        if not receipt:
            raise ValueError("tx_not_found")
        if int(receipt.status) != 1:
            raise ValueError("tx_reverted")
        block_number = int(receipt.blockNumber or 0)
        latest = int(self.w3.eth.block_number)
        confirmations = max(0, latest - block_number + 1) if block_number else 0
        if confirmations < max(1, ESCROW_CONFIRMATIONS_REQUIRED):
            raise ValueError("tx_not_confirmed")

        tx = self.w3.eth.get_transaction(normalized)
        tx_to = tx.get('to') if isinstance(tx, dict) else getattr(tx, 'to', None)
        if not tx_to:
            raise ValueError("wrong_contract")
        if Web3.to_checksum_address(tx_to) != self.contract_address:
            raise ValueError("wrong_contract")

        event_name = expected_event
        event_args = {}
        resolved_trade_ref = ''
        if ESCROW_EVENT_STRICT_VALIDATION:
            event_data = self._extract_expected_event(receipt, expected_event)
            event_name = event_data.get('event_name', expected_event)
            event_args = event_data.get('args', {})
            event_trade_id = str(event_args.get('tradeId') or event_args.get('trade_id') or '').strip()
            if not event_trade_id or event_trade_id != trade.get('trade_id'):
                raise ValueError("trade_mismatch")
            observed_ref = self._normalize_ref(
                event_args.get('escrowTradeRef') or event_args.get('escrow_trade_ref') or event_args.get('tradeRef') or ''
            )
            expected_ref = self._normalize_ref(escrow_trade_ref or '')
            if expected_ref and observed_ref and expected_ref != observed_ref:
                raise ValueError("trade_mismatch")
            if expected_ref and not observed_ref:
                raise ValueError("trade_mismatch")
            resolved_trade_ref = observed_ref

        result.update({
            'verified': True,
            'block_number': block_number,
            'confirmations': confirmations,
            'contract_address': self.contract_address,
            'event_name': event_name,
            'event_args': event_args,
            'escrow_trade_ref': resolved_trade_ref
        })
        return result

OTC_ESCROW = OTCEscrow()
def _new_intent_id() -> str:
    return f"intent_{int(time.time())}_{secrets.token_hex(4)}"

def _validate_trade_action(trade: Dict[str, Any], action: str):
    allowed = OTC_ALLOWED_STATE_TRANSITIONS.get(action)
    if not allowed:
        raise ValueError("invalid_trade_action")
    if trade.get('status') not in allowed:
        raise ValueError(OTC_ACTION_INVALID_STATE_ERROR.get(action, 'invalid_trade_state'))

def _resolve_onchain_intent(trade_id: str, action: str, intent_id: Optional[str]) -> Optional[Dict[str, Any]]:
    if intent_id:
        intent = STORAGE_DB.get_onchain_intent(intent_id)
        if not intent:
            raise ValueError("intent_not_found")
        if intent.get('trade_id') != trade_id:
            raise ValueError("intent_trade_mismatch")
        if intent.get('action') != action:
            raise ValueError("intent_action_mismatch")
        return intent
    latest = STORAGE_DB.get_latest_onchain_intent(trade_id, action)
    if latest and latest.get('status') == 'prepared':
        return latest
    return None

def _ensure_intent_not_expired(intent: Optional[Dict[str, Any]]):
    if not intent:
        return
    now_ms = int(time.time() * 1000)
    if int(intent.get('expires_at', 0) or 0) and now_ms > int(intent.get('expires_at', 0)):
        STORAGE_DB.update_onchain_intent_status(intent['intent_id'], 'expired', tx_hash=intent.get('tx_hash'))
        raise ValueError("intent_expired")

def _ensure_tx_not_replayed(trade_id: str, action: str, tx_hash: str):
    existing = STORAGE_DB.get_escrow_event_by_tx_hash(tx_hash)
    if not existing:
        return
    expected_type = OTC_ACTION_EVENT_TYPE_MAP.get(action, '')
    if existing.get('trade_id') != trade_id or existing.get('event_type') != expected_type:
        raise ValueError("tx_hash_reused")
    raise ValueError("tx_hash_reused")

def otc_prepare_trade_action(client: Dict[str, Any], trade_id: str, action: str,
                             timeout_seconds: Optional[int] = None, request_id: str = '') -> Dict[str, Any]:
    trade = STORAGE_DB.get_trade(trade_id)
    if not trade:
        raise ValueError("trade_not_found")
    if not _trade_actor_allowed(client, trade):
        raise PermissionError("actor_not_allowed_for_trade")
    _validate_trade_action(trade, action)
    prepared = OTC_ESCROW.prepare_action_payload(trade, action, timeout_seconds=timeout_seconds)
    intent_id = _new_intent_id()
    prepared['intent_id'] = intent_id
    STORAGE_DB.create_onchain_intent({
        'intent_id': intent_id,
        'trade_id': trade_id,
        'action': action,
        'expected_event': OTC_ACTION_EVENT_MAP[action],
        'prepared_payload': prepared,
        'status': 'prepared',
        'expires_at': int(prepared.get('expires_at', int(time.time() * 1000)))
    })
    append_audit_event(
        f"{action}_prepared",
        client['client_id'],
        trade_id,
        details={'intent_id': intent_id, 'action': action},
        request_id=request_id
    )
    return prepared

def otc_submit_trade_action(client: Dict[str, Any], trade_id: str, action: str, tx_hash: str,
                            escrow_trade_ref: Optional[str] = None, intent_id: Optional[str] = None,
                            request_id: str = '') -> Dict[str, Any]:
    trade = STORAGE_DB.get_trade(trade_id)
    if not trade:
        raise ValueError("trade_not_found")
    if not _trade_actor_allowed(client, trade):
        raise PermissionError("actor_not_allowed_for_trade")

    normalized_hash = OTCEscrow._normalize_tx_hash(tx_hash)
    _ensure_tx_not_replayed(trade_id, action, normalized_hash)
    _validate_trade_action(trade, action)

    intent = _resolve_onchain_intent(trade_id, action, intent_id)
    _ensure_intent_not_expired(intent)
    if intent:
        STORAGE_DB.update_onchain_intent_status(intent['intent_id'], 'submitted', tx_hash=normalized_hash)

    onchain = OTC_ESCROW.verify_submitted_action(normalized_hash, trade, action, escrow_trade_ref=escrow_trade_ref)
    next_state = OTC_ACTION_NEXT_STATE[action]
    event_type = OTC_ACTION_EVENT_TYPE_MAP[action]
    resolved_trade_ref = trade.get('escrow_trade_ref', '')
    if action == OTC_ACTION_ESCROW_CREATE:
        resolved_trade_ref = onchain.get('escrow_trade_ref') or escrow_trade_ref or resolved_trade_ref or normalized_hash

    STORAGE_DB.update_trade_state(
        trade_id,
        next_state,
        escrow_trade_ref=resolved_trade_ref if action == OTC_ACTION_ESCROW_CREATE else None,
        add_tx_hash=onchain.get('tx_hash', normalized_hash)
    )
    STORAGE_DB.record_escrow_event({
        'trade_id': trade_id,
        'event_type': event_type,
        'intent_id': intent['intent_id'] if intent else '',
        'contract_address': onchain.get('contract_address', ESCROW_CONTRACT_ADDRESS),
        'event_name': onchain.get('event_name', OTC_ACTION_EVENT_MAP[action]),
        'tx_hash': onchain.get('tx_hash', normalized_hash),
        'block_number': onchain.get('block_number', 0),
        'confirmations': onchain.get('confirmations', 0),
        'chain_id': EVM_CHAIN_ID,
        'verified': bool(onchain.get('verified', False)),
        'payload': {
            'request_id': request_id,
            'external_submission': True,
            'verified': onchain.get('verified', False),
            'action': action,
            'event_args': onchain.get('event_args', {})
        }
    })
    if intent:
        STORAGE_DB.update_onchain_intent_status(intent['intent_id'], 'confirmed', tx_hash=onchain.get('tx_hash', normalized_hash))
    append_audit_event(
        event_type,
        client['client_id'],
        trade_id,
        details={
            'intent_id': intent['intent_id'] if intent else '',
            'tx_hash': onchain.get('tx_hash', normalized_hash),
            'event_name': onchain.get('event_name', '')
        },
        request_id=request_id
    )
    trade = STORAGE_DB.get_trade(trade_id) or trade
    trade[f'{action}_tx'] = onchain
    return trade

def otc_prepare_escrow(client: Dict[str, Any], trade_id: str, timeout_seconds: Optional[int] = None,
                       request_id: str = '') -> Dict[str, Any]:
    return otc_prepare_trade_action(client, trade_id, OTC_ACTION_ESCROW_CREATE, timeout_seconds=timeout_seconds, request_id=request_id)

def otc_prepare_settle(client: Dict[str, Any], trade_id: str, timeout_seconds: Optional[int] = None,
                       request_id: str = '') -> Dict[str, Any]:
    return otc_prepare_trade_action(client, trade_id, OTC_ACTION_SETTLE, timeout_seconds=timeout_seconds, request_id=request_id)

def otc_prepare_refund(client: Dict[str, Any], trade_id: str, timeout_seconds: Optional[int] = None,
                       request_id: str = '') -> Dict[str, Any]:
    return otc_prepare_trade_action(client, trade_id, OTC_ACTION_REFUND, timeout_seconds=timeout_seconds, request_id=request_id)

def otc_create_escrow(client: Dict[str, Any], trade_id: str, tx_hash: str,
                      escrow_trade_ref: Optional[str] = None, intent_id: Optional[str] = None,
                      request_id: str = '') -> Dict[str, Any]:
    return otc_submit_trade_action(
        client, trade_id, OTC_ACTION_ESCROW_CREATE, tx_hash=tx_hash,
        escrow_trade_ref=escrow_trade_ref, intent_id=intent_id, request_id=request_id
    )

def otc_settle_trade(client: Dict[str, Any], trade_id: str, tx_hash: str,
                     intent_id: Optional[str] = None, request_id: str = '') -> Dict[str, Any]:
    return otc_submit_trade_action(
        client, trade_id, OTC_ACTION_SETTLE, tx_hash=tx_hash,
        intent_id=intent_id, request_id=request_id
    )

def otc_refund_trade(client: Dict[str, Any], trade_id: str, tx_hash: str,
                     intent_id: Optional[str] = None, request_id: str = '') -> Dict[str, Any]:
    return otc_submit_trade_action(
        client, trade_id, OTC_ACTION_REFUND, tx_hash=tx_hash,
        intent_id=intent_id, request_id=request_id
    )

# ===== DARK POOL DOMAIN (TRADE INTENTS / MATCH / HTLC) =====
def generate_trade_intent_id() -> str:
    return f"intent_{int(time.time())}_{secrets.token_hex(4)}"

def generate_match_id() -> str:
    return f"match_{int(time.time())}_{secrets.token_hex(4)}"

def generate_session_id() -> str:
    return f"sess_{int(time.time())}_{secrets.token_hex(4)}"

def generate_swap_id() -> str:
    return f"swap_{int(time.time())}_{secrets.token_hex(4)}"

def _bucket_range(min_value: float, max_value: float, step: float) -> Tuple[int, int]:
    step = max(0.00000001, float(step))
    a = int(math.floor(float(min_value) / step))
    b = int(math.floor(float(max_value) / step))
    return (min(a, b), max(a, b))

def _bucket_amount(amount: float, step: float) -> int:
    step = max(0.00000001, float(step))
    return int(math.floor(float(amount) / step))

def _build_commitment_meta(intent: Dict[str, Any]) -> Dict[str, Any]:
    pb_min, pb_max = _bucket_range(intent['price_min'], intent['price_max'], INTENT_BUCKET_SIZE_PRICE)
    ab = _bucket_amount(intent['amount'], INTENT_BUCKET_SIZE_AMOUNT)
    seed = f"{intent['sell_asset']}:{intent['buy_asset']}:{pb_min}:{pb_max}:{ab}"
    meta = {
        'price_bucket_min': pb_min,
        'price_bucket_max': pb_max,
        'amount_bucket': ab,
        'pair_commitment': generate_dna_hash(f"pair:{intent['sell_asset']}:{intent['buy_asset']}"),
        'price_commitment': generate_dna_hash(f"price:{pb_min}:{pb_max}"),
        'amount_commitment': generate_dna_hash(f"amount:{ab}"),
        'composite_commitment': generate_dna_hash(seed)
    }
    if BLIND_MATCHING_ENABLED and BLIND_MATCHING_AVAILABLE:
        try:
            blind_meta = build_blind_commitment_meta(
                intent,
                slot_size=BLIND_PRICE_SLOT_SIZE,
                amount_bucket_size=INTENT_BUCKET_SIZE_AMOUNT,
                global_salt=BLIND_GLOBAL_SALT,
                max_slots=BLIND_MAX_PRICE_SLOTS
            )
            meta.update(blind_meta)
        except Exception as exc:
            meta['blind_matching_error'] = str(exc)
    return meta

def _normalize_counterparty_allowlist(raw: Any) -> Dict[str, set]:
    parsed: Dict[str, set] = {}
    if not isinstance(raw, dict):
        return parsed
    for key, value in raw.items():
        client_id = str(key or '').strip()
        if not client_id:
            continue
        if isinstance(value, str):
            entries = [x.strip() for x in value.split(',') if x.strip()]
        elif isinstance(value, list):
            entries = [str(x).strip() for x in value if str(x).strip()]
        else:
            entries = []
        if entries:
            parsed[client_id] = set(entries)
    return parsed

_COUNTERPARTY_ALLOWLIST_CACHE = _normalize_counterparty_allowlist(COUNTERPARTY_ALLOWLIST)

def _is_counterparty_allowed(client_a: str, client_b: str) -> bool:
    if not _COUNTERPARTY_ALLOWLIST_CACHE:
        return True
    allowed_a = _COUNTERPARTY_ALLOWLIST_CACHE.get(client_a)
    if allowed_a is not None and client_b not in allowed_a:
        return False
    allowed_b = _COUNTERPARTY_ALLOWLIST_CACHE.get(client_b)
    if allowed_b is not None and client_a not in allowed_b:
        return False
    return True

def _is_intent_expired(intent: Dict[str, Any]) -> bool:
    return int(intent.get('expiration', 0)) < int(time.time() * 1000)

def _intent_to_common_quote(intent: Dict[str, Any]) -> Tuple[str, str, float, float]:
    # Returns (base_asset, quote_asset, quote_per_base_min, quote_per_base_max)
    sell_asset = intent['sell_asset']
    buy_asset = intent['buy_asset']
    pmin = float(intent['price_min'])
    pmax = float(intent['price_max'])
    if pmin <= 0 or pmax <= 0:
        raise ValueError("invalid_price_range")
    return sell_asset, buy_asset, min(pmin, pmax), max(pmin, pmax)

def _compute_overlap(a: Dict[str, Any], b: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # Match requires opposite pair
    if a['sell_asset'] != b['buy_asset'] or a['buy_asset'] != b['sell_asset']:
        return None
    if _is_intent_expired(a) or _is_intent_expired(b):
        return None

    a_base, a_quote, a_min, a_max = _intent_to_common_quote(a)
    b_base, b_quote, b_min_raw, b_max_raw = _intent_to_common_quote(b)
    # b is opposite direction, invert range to compare in a quote/base unit
    b_min = min(1.0 / b_max_raw, 1.0 / b_min_raw)
    b_max = max(1.0 / b_max_raw, 1.0 / b_min_raw)

    overlap_min = max(a_min, b_min)
    overlap_max = min(a_max, b_max)
    if overlap_min > overlap_max:
        return None

    # a.amount is in a.sell_asset units.
    # b.amount is in b.sell_asset units (which equals a.buy_asset due to opposite pair).
    # Convert b capacity into a.sell_asset units conservatively using overlap_max (quote/base).
    amount = min(float(a['amount']), float(b['amount']) / max(overlap_max, 1e-12))
    amount = max(0.0, amount)
    if amount <= 0:
        return None

    confidence = 1.0 if overlap_max > overlap_min else 0.5
    return {
        'overlap_min': overlap_min,
        'overlap_max': overlap_max,
        'amount': amount,
        'confidence': confidence,
        'base_asset': a_base,
        'quote_asset': a_quote
    }

def _blind_overlap_tokens_for_intents(a: Dict[str, Any], b: Dict[str, Any]) -> Optional[List[str]]:
    if not BLIND_MATCHING_ENABLED or not BLIND_MATCHING_AVAILABLE:
        return None
    a_meta = a.get('commitment_meta') if isinstance(a.get('commitment_meta'), dict) else {}
    b_meta = b.get('commitment_meta') if isinstance(b.get('commitment_meta'), dict) else {}
    return blind_overlap_tokens(a_meta, b_meta)

def _bucketed_candidate(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """Phase-A matching filter. Uses blind token overlap when available."""
    if a.get('sell_asset') != b.get('buy_asset') or a.get('buy_asset') != b.get('sell_asset'):
        return False
    overlap_tokens = _blind_overlap_tokens_for_intents(a, b)
    if overlap_tokens is None:
        return True
    return len(overlap_tokens) > 0

def _persist_private_trade_intent(intent: Dict[str, Any], private_terms: Optional[Dict[str, Any]]) -> str:
    payload_obj = {
        'kind': 'trade_intent_private',
        'intent_id': intent['intent_id'],
        'sell_asset': intent['sell_asset'],
        'buy_asset': intent['buy_asset'],
        'amount': intent['amount'],
        'price_min': intent['price_min'],
        'price_max': intent['price_max'],
        'expiration': intent['expiration'],
        'private_terms': private_terms or {}
    }
    return _persist_private_otc_payload(intent['maker_client_id'], intent['maker_client_id'], payload_obj)

def _broadcast_blind_commitment(intent: Dict[str, Any], request_id: str = '') -> str:
    if not BLIND_MATCHING_ENABLED or not BLIND_MATCHING_AVAILABLE:
        return ''
    commitment_meta = intent.get('commitment_meta') if isinstance(intent.get('commitment_meta'), dict) else {}
    if not commitment_meta:
        return ''
    payload_obj = build_public_blind_commitment(intent, commitment_meta)
    if not payload_obj or not payload_obj.get('blind_slot_tokens'):
        return ''
    destination = BLIND_COMMITMENT_DESTINATION or 'blind_orderbook'
    instruction_id = _persist_private_otc_payload(intent['maker_client_id'], destination, payload_obj)
    append_audit_event(
        'blind_commitment_broadcast',
        intent['maker_client_id'],
        intent['intent_id'],
        details={
            'instruction_id': instruction_id,
            'destination': destination,
            'token_count': int(payload_obj.get('blind_slot_token_count', 0))
        },
        request_id=request_id
    )
    return instruction_id

def _refresh_intent_expiry_state(intent: Dict[str, Any]):
    if intent.get('status') == INTENT_STATUS_OPEN and _is_intent_expired(intent):
        STORAGE_DB.update_trade_intent_status(intent['intent_id'], INTENT_STATUS_EXPIRED)

def _run_private_matching(new_intent: Dict[str, Any], request_id: str = '') -> List[Dict[str, Any]]:
    candidates = STORAGE_DB.list_open_trade_intents()
    matches = []
    for other in candidates:
        if not other:
            continue
        if other['intent_id'] == new_intent['intent_id']:
            continue
        if other['maker_client_id'] == new_intent['maker_client_id']:
            continue
        if not _is_counterparty_allowed(new_intent['maker_client_id'], other['maker_client_id']):
            continue
        _refresh_intent_expiry_state(other)
        if other.get('status') != INTENT_STATUS_OPEN:
            continue
        if not _bucketed_candidate(new_intent, other):
            continue
        if STORAGE_DB.find_match_by_intents(new_intent['intent_id'], other['intent_id']):
            continue
        blind_overlap = _blind_overlap_tokens_for_intents(new_intent, other)
        overlap = _compute_overlap(new_intent, other)
        if not overlap:
            continue
        matched_by_blind_tokens = bool(blind_overlap)
        match_method = 'blind_token_overlap' if matched_by_blind_tokens else 'pair_filter'
        match_id = generate_match_id()
        match = {
            'match_id': match_id,
            'intent_sell_id': new_intent['intent_id'],
            'intent_buy_id': other['intent_id'],
            'overlap_min': overlap['overlap_min'],
            'overlap_max': overlap['overlap_max'],
            'amount': overlap['amount'],
            'confidence': overlap['confidence'],
            'status': MATCH_STATUS_FOUND,
            'metadata': {
                'base_asset': overlap['base_asset'],
                'quote_asset': overlap['quote_asset'],
                'participants': [new_intent['maker_client_id'], other['maker_client_id']],
                'darkpool': True,
                'blind_matching_enabled': bool(BLIND_MATCHING_ENABLED and BLIND_MATCHING_AVAILABLE),
                'blind_matched': matched_by_blind_tokens,
                'matching_method': match_method,
                'blind_overlap_tokens': len(blind_overlap or [])
            }
        }
        STORAGE_DB.create_match(match)
        STORAGE_DB.update_trade_intent_status(new_intent['intent_id'], INTENT_STATUS_MATCHED)
        STORAGE_DB.update_trade_intent_status(other['intent_id'], INTENT_STATUS_MATCHED)
        append_audit_event(
            'blind_match_detected' if matched_by_blind_tokens else 'match_detected',
            new_intent['maker_client_id'],
            match_id,
            details={
                'intent_a': new_intent['intent_id'],
                'intent_b': other['intent_id'],
                'overlap_min': overlap['overlap_min'],
                'overlap_max': overlap['overlap_max'],
                'matching_method': match_method,
                'blind_overlap_tokens': len(blind_overlap or [])
            },
            request_id=request_id
        )
        matches.append(match)
    return matches

def _ensure_match_participant(client: Dict[str, Any], match_obj: Dict[str, Any]):
    roles = client.get('roles') or []
    if 'admin' in roles:
        return
    intent_sell = STORAGE_DB.get_trade_intent(match_obj['intent_sell_id'])
    intent_buy = STORAGE_DB.get_trade_intent(match_obj['intent_buy_id'])
    actor = client.get('client_id', '')
    allowed = {intent_sell.get('maker_client_id', ''), intent_buy.get('maker_client_id', '')}
    if actor not in allowed:
        raise PermissionError("actor_not_allowed_for_match")

def create_trade_intent(client: Dict[str, Any], data: Dict[str, Any], request_id: str = '') -> Dict[str, Any]:
    if not DARKPOOL_ENABLED:
        raise RuntimeError("darkpool_disabled")

    maker_wallet = _normalize_wallet(data.get('maker_wallet', ''))
    _ensure_wallet_authorized(client, maker_wallet, EVM_CHAIN_ID)
    sell_asset = _normalize_asset(data.get('sell_asset', ''))
    buy_asset = _normalize_asset(data.get('buy_asset', ''))
    _ensure_allowed_intent_assets(sell_asset, buy_asset)

    amount = float(data.get('amount', 0))
    price_min = float(data.get('price_min', 0))
    price_max = float(data.get('price_max', 0))
    expiration = int(data.get('expiration', 0))
    now_ms = int(time.time() * 1000)
    if amount <= 0:
        raise ValueError("amount_must_be_positive")
    if price_min <= 0 or price_max <= 0 or price_min > price_max:
        raise ValueError("invalid_price_range")
    min_exp_ms = now_ms + (max(1, INTENT_MIN_EXPIRATION_SECONDS) * 1000)
    max_exp_ms = now_ms + (max(INTENT_MIN_EXPIRATION_SECONDS, INTENT_MAX_EXPIRATION_SECONDS) * 1000)
    if expiration < min_exp_ms:
        raise ValueError("expiration_too_soon")
    if expiration > max_exp_ms:
        raise ValueError("expiration_too_far")
    notional_mid = ((price_min + price_max) / 2.0) * amount
    if INTENT_MAX_NOTIONAL > 0 and notional_mid > INTENT_MAX_NOTIONAL:
        raise ValueError("notional_limit_exceeded")
    intent_attestation = _verify_trade_intent_wallet_signature(client, data)

    intent_id = generate_trade_intent_id()
    metadata = dict(data.get('metadata') or {})
    metadata['wallet_attestation'] = {
        'verified': bool(intent_attestation.get('verified', False)),
        'wallet': intent_attestation.get('wallet', maker_wallet),
        'message_hash': intent_attestation.get('message_hash', ''),
        'signature_hash': intent_attestation.get('signature_hash', ''),
    }
    intent = {
        'intent_id': intent_id,
        'maker_client_id': client['client_id'],
        'maker_wallet': maker_wallet,
        'sell_asset': sell_asset,
        'buy_asset': buy_asset,
        'amount': amount,
        'price_min': price_min,
        'price_max': price_max,
        'expiration': expiration,
        'status': INTENT_STATUS_OPEN,
        'metadata': metadata
    }
    intent['commitment_meta'] = _build_commitment_meta(intent)
    private_instruction_id = _persist_private_trade_intent(intent, data.get('private_terms'))
    intent['private_instruction_id'] = private_instruction_id
    STORAGE_DB.create_trade_intent(intent)
    STORAGE_DB.link_intent_shard(intent_id, private_instruction_id, private_instruction_id)
    blind_commitment_instruction_id = ''
    try:
        blind_commitment_instruction_id = _broadcast_blind_commitment(intent, request_id=request_id)
        if blind_commitment_instruction_id:
            STORAGE_DB.link_intent_shard(intent_id, blind_commitment_instruction_id, blind_commitment_instruction_id)
            intent['blind_commitment_instruction_id'] = blind_commitment_instruction_id
    except Exception as exc:
        append_audit_event(
            'blind_commitment_broadcast_failed',
            client['client_id'],
            intent_id,
            details={'error': str(exc)},
            request_id=request_id
        )
    append_audit_event(
        'intent_created',
        client['client_id'],
        intent_id,
        details={
            'sell_asset': sell_asset,
            'buy_asset': buy_asset,
            'amount': amount,
            'price_min': price_min,
            'price_max': price_max,
            'wallet_attested': bool(intent_attestation.get('verified', False)),
        },
        request_id=request_id
    )
    append_audit_event(
        'intent_sharded',
        client['client_id'],
        intent_id,
        details={'instruction_id': private_instruction_id},
        request_id=request_id
    )
    matched = _run_private_matching(intent, request_id=request_id)
    intent['matches_detected'] = [m['match_id'] for m in matched]
    return intent

def get_trade_intent(client: Dict[str, Any], intent_id: str) -> Dict[str, Any]:
    intent = STORAGE_DB.get_trade_intent(intent_id)
    if not intent:
        raise ValueError("intent_not_found")
    roles = client.get('roles') or []
    if 'admin' not in roles and intent.get('maker_client_id') != client.get('client_id'):
        raise PermissionError("actor_not_allowed_for_intent")
    _refresh_intent_expiry_state(intent)
    return STORAGE_DB.get_trade_intent(intent_id) or intent

def cancel_trade_intent(client: Dict[str, Any], intent_id: str, request_id: str = '') -> Dict[str, Any]:
    intent = get_trade_intent(client, intent_id)
    if intent.get('status') not in (INTENT_STATUS_OPEN, INTENT_STATUS_MATCHED):
        raise ValueError("intent_not_cancellable")
    STORAGE_DB.update_trade_intent_status(intent_id, INTENT_STATUS_CANCELLED)
    append_audit_event('intent_cancelled', client['client_id'], intent_id, request_id=request_id)
    return STORAGE_DB.get_trade_intent(intent_id) or intent

def get_match(client: Dict[str, Any], match_id: str) -> Dict[str, Any]:
    match_obj = STORAGE_DB.get_match(match_id)
    if not match_obj:
        raise ValueError("match_not_found")
    _ensure_match_participant(client, match_obj)
    return match_obj

def _generate_noise_handshake() -> Dict[str, Any]:
    return {
        'protocol': 'Noise_NN_25519_ChaChaPoly_BLAKE2s',
        'initiator_ephemeral_pub': base64.b64encode(os.urandom(32)).decode('ascii'),
        'responder_ephemeral_pub': base64.b64encode(os.urandom(32)).decode('ascii'),
        'handshake_hash': base64.b64encode(os.urandom(32)).decode('ascii')
    }

def _ensure_swap_for_match(match_obj: Dict[str, Any], session: Dict[str, Any], actor: str) -> Dict[str, Any]:
    metadata = match_obj.get('metadata', {})
    existing_swap_id = metadata.get('swap_id', '')
    if existing_swap_id:
        swap = STORAGE_DB.get_swap(existing_swap_id)
        if swap:
            return swap
    secret = secrets.token_hex(32)
    secret_hash = hashlib.sha256(secret.encode('utf-8')).hexdigest()
    now_ms = int(time.time() * 1000)
    peer_session_a = session.get('peer_a', '')
    peer_session_b = session.get('peer_b', '')
    sell_intent = STORAGE_DB.get_trade_intent(match_obj.get('intent_sell_id', '')) or {}
    buy_intent = STORAGE_DB.get_trade_intent(match_obj.get('intent_buy_id', '')) or {}
    wallet_map = {
        sell_intent.get('maker_client_id', ''): _normalize_wallet(sell_intent.get('maker_wallet', '')),
        buy_intent.get('maker_client_id', ''): _normalize_wallet(buy_intent.get('maker_wallet', '')),
    }
    peer_a = actor
    peer_b = peer_session_b if actor == peer_session_a else peer_session_a
    if not peer_b or peer_b == peer_a:
        peer_b = peer_session_a if peer_session_a and peer_session_a != peer_a else peer_session_b

    swap = {
        'swap_id': generate_swap_id(),
        'match_id': match_obj['match_id'],
        'secret_hash': secret_hash,
        'htlc_a': {'chain': HTLC_CHAIN_A, 'status': 'pending'},
        'htlc_b': {'chain': HTLC_CHAIN_B, 'status': 'pending'},
        'state': SWAP_STATE_INIT,
        'timeouts': {
            'lock_a_timeout': now_ms + HTLC_TIMEOUT_LOCK_A_SECONDS * 1000,
            'lock_b_timeout': now_ms + HTLC_TIMEOUT_LOCK_B_SECONDS * 1000
        },
        'proofs': [],
        'metadata': {
            'session_id': session['session_id'],
            'initiator': actor,
            'peer_a': peer_a,
            'peer_b': peer_b,
            'peer_a_wallet': wallet_map.get(peer_a, ''),
            'peer_b_wallet': wallet_map.get(peer_b, ''),
            'secret_hint': secret[:8] + '...'
        }
    }
    STORAGE_DB.create_swap(swap)
    match_obj['metadata']['swap_id'] = swap['swap_id']
    STORAGE_DB.update_match_status(match_obj['match_id'], MATCH_STATUS_SESSION_OPEN)
    STORAGE_DB._execute("""UPDATE matches SET metadata_json=?, updated_at=? WHERE match_id=?"""
                        if STORAGE_DB.backend == 'sqlite'
                        else """UPDATE matches SET metadata_json=%s, updated_at=%s WHERE match_id=%s""",
                        (json.dumps(match_obj.get('metadata', {})), int(time.time() * 1000), match_obj['match_id']))
    return swap

def open_secure_session(client: Dict[str, Any], match_id: str, request_id: str = '') -> Dict[str, Any]:
    match_obj = get_match(client, match_id)
    existing = STORAGE_DB.get_secure_session_by_match(match_id)
    now_ms = int(time.time() * 1000)
    if existing and existing.get('status') == SESSION_STATUS_OPEN and int(existing.get('expires_at', 0)) > now_ms:
        swap = _ensure_swap_for_match(match_obj, existing, client['client_id'])
        return {'session': existing, 'swap': swap}

    sell_intent = STORAGE_DB.get_trade_intent(match_obj['intent_sell_id']) or {}
    buy_intent = STORAGE_DB.get_trade_intent(match_obj['intent_buy_id']) or {}
    session = {
        'session_id': generate_session_id(),
        'match_id': match_id,
        'peer_a': sell_intent.get('maker_client_id', ''),
        'peer_b': buy_intent.get('maker_client_id', ''),
        'noise_handshake_state': _generate_noise_handshake(),
        'expires_at': now_ms + (SESSION_HANDSHAKE_TTL_SECONDS * 1000),
        'status': SESSION_STATUS_OPEN
    }
    STORAGE_DB.create_secure_session(session)
    append_audit_event('session_opened', client['client_id'], match_id, details={'session_id': session['session_id']}, request_id=request_id)
    swap = _ensure_swap_for_match(match_obj, session, client['client_id'])
    return {'session': session, 'swap': swap}

def start_htlc_coordination(client: Dict[str, Any], match_id: str, request_id: str = '') -> Dict[str, Any]:
    opened = open_secure_session(client, match_id, request_id=request_id)
    swap = opened.get('swap') or {}
    if swap.get('state') == SWAP_STATE_INIT:
        STORAGE_DB.update_swap(swap.get('swap_id', ''), state=SWAP_STATE_WAIT_LOCK_A)
        swap = STORAGE_DB.get_swap(swap.get('swap_id', '')) or swap
    append_audit_event(
        'swap_init',
        client['client_id'],
        swap.get('swap_id', ''),
        details={'match_id': match_id, 'session_id': opened.get('session', {}).get('session_id', '')},
        request_id=request_id
    )
    return swap

def _swap_transition(state: str, proof_type: str) -> str:
    if state == SWAP_STATE_INIT and proof_type == 'lock_a':
        return SWAP_STATE_WAIT_LOCK_B
    if state == SWAP_STATE_WAIT_LOCK_A and proof_type == 'lock_a':
        return SWAP_STATE_WAIT_LOCK_B
    if state == SWAP_STATE_WAIT_LOCK_B and proof_type == 'lock_b':
        return SWAP_STATE_READY_CLAIM
    if state == SWAP_STATE_READY_CLAIM and proof_type == 'claim_a':
        return SWAP_STATE_CLAIMED_A
    if state == SWAP_STATE_READY_CLAIM and proof_type == 'claim_b':
        return SWAP_STATE_CLAIMED_B
    if state == SWAP_STATE_CLAIMED_A and proof_type == 'claim_b':
        return SWAP_STATE_COMPLETED
    if state == SWAP_STATE_CLAIMED_B and proof_type == 'claim_a':
        return SWAP_STATE_COMPLETED
    if state in (SWAP_STATE_WAIT_LOCK_B, SWAP_STATE_READY_CLAIM) and proof_type in ('refund_a', 'refund_b'):
        return SWAP_STATE_REFUNDED
    raise ValueError("invalid_swap_transition")

def _swap_timeout_expired(swap: Dict[str, Any]) -> Optional[str]:
    now_ms = int(time.time() * 1000)
    timeouts = swap.get('timeouts', {}) or {}
    lock_a_timeout = int(timeouts.get('lock_a_timeout', 0) or 0)
    lock_b_timeout = int(timeouts.get('lock_b_timeout', 0) or 0)
    state = swap.get('state')
    if state in (SWAP_STATE_INIT, SWAP_STATE_WAIT_LOCK_A) and lock_a_timeout and now_ms > lock_a_timeout:
        return SWAP_STATE_FAILED
    if state in (SWAP_STATE_WAIT_LOCK_B, SWAP_STATE_READY_CLAIM, SWAP_STATE_CLAIMED_A, SWAP_STATE_CLAIMED_B) and lock_b_timeout and now_ms > lock_b_timeout:
        return SWAP_STATE_REFUNDED
    return None

def _refresh_swap_timeout_state(swap_id: str) -> Dict[str, Any]:
    swap = STORAGE_DB.get_swap(swap_id) or {}
    if not swap:
        return {}
    timed_out_state = _swap_timeout_expired(swap)
    if timed_out_state and swap.get('state') not in (SWAP_STATE_COMPLETED, SWAP_STATE_REFUNDED, SWAP_STATE_FAILED):
        STORAGE_DB.update_swap(swap_id, state=timed_out_state, completed_at=int(time.time() * 1000))
        append_audit_event('swap_timeout', 'system', swap_id, details={'to_state': timed_out_state})
        swap = STORAGE_DB.get_swap(swap_id) or swap
    return swap

def _is_proof_actor_allowed(client: Dict[str, Any], swap: Dict[str, Any], proof_type: str) -> bool:
    roles = client.get('roles') or []
    if 'admin' in roles:
        return True
    actor = client.get('client_id', '')
    metadata = swap.get('metadata', {}) or {}
    peer_a = metadata.get('peer_a', '')
    peer_b = metadata.get('peer_b', '')
    if not peer_a or not peer_b:
        return _swap_actor_allowed(client, swap)
    if not SWAP_ENFORCE_SIDE_PROOFS:
        return actor in (peer_a, peer_b)
    if proof_type.endswith('_a'):
        return actor == peer_a
    if proof_type.endswith('_b'):
        return actor == peer_b
    return False

def _expected_wallet_for_proof(swap: Dict[str, Any], proof_type: str) -> str:
    metadata = swap.get('metadata', {}) or {}
    if proof_type.endswith('_a'):
        return _normalize_wallet(metadata.get('peer_a_wallet', ''))
    if proof_type.endswith('_b'):
        return _normalize_wallet(metadata.get('peer_b_wallet', ''))
    return ''

def _swap_actor_allowed(client: Dict[str, Any], swap: Dict[str, Any]) -> bool:
    roles = client.get('roles') or []
    if 'admin' in roles:
        return True
    match_obj = STORAGE_DB.get_match(swap['match_id'])
    if not match_obj:
        return False
    sell_intent = STORAGE_DB.get_trade_intent(match_obj['intent_sell_id']) or {}
    buy_intent = STORAGE_DB.get_trade_intent(match_obj['intent_buy_id']) or {}
    return client.get('client_id') in (sell_intent.get('maker_client_id'), buy_intent.get('maker_client_id'))

def _estimate_notional_for_swap(swap: Dict[str, Any]) -> Tuple[float, str]:
    match_obj = STORAGE_DB.get_match(swap['match_id']) or {}
    metadata = match_obj.get('metadata', {})
    overlap_mid = (float(match_obj.get('overlap_min', 0)) + float(match_obj.get('overlap_max', 0))) / 2.0
    amount = float(match_obj.get('amount', 0))
    notional = max(0.0, overlap_mid * amount)
    fee_asset = metadata.get('quote_asset', '')
    return notional, fee_asset

def _ensure_fee_invoice_for_swap(swap: Dict[str, Any], request_id: str = '') -> Dict[str, Any]:
    existing = STORAGE_DB.get_latest_fee_invoice(swap['swap_id'])
    if existing:
        return existing
    notional, fee_asset = _estimate_notional_for_swap(swap)
    fee_amount = round((notional * FEE_BPS) / 10000.0, 8)
    invoice = {
        'swap_id': swap['swap_id'],
        'fee_bps': FEE_BPS,
        'fee_amount': fee_amount,
        'fee_asset': fee_asset,
        'invoice_ref': f"lninv_{secrets.token_hex(8)}",
        'payment_status': 'pending'
    }
    STORAGE_DB.create_fee_invoice(invoice)
    append_audit_event('fee_invoiced', 'system', swap['swap_id'], details={'invoice_ref': invoice['invoice_ref'], 'fee_amount': fee_amount}, request_id=request_id)
    return STORAGE_DB.get_latest_fee_invoice(swap['swap_id']) or invoice

def submit_htlc_proof(client: Dict[str, Any], swap_id: str, proof: Dict[str, Any], request_id: str = '') -> Dict[str, Any]:
    swap = _refresh_swap_timeout_state(swap_id) or STORAGE_DB.get_swap(swap_id)
    if not swap:
        raise ValueError("swap_not_found")
    if not _swap_actor_allowed(client, swap):
        raise PermissionError("actor_not_allowed_for_swap")
    proof_type = str(proof.get('proof_type', '')).strip()
    tx_hash = _normalize_tx_hash(str(proof.get('tx_hash', '')).strip())
    if not proof_type:
        raise ValueError("invalid_proof_type")
    if not _is_proof_actor_allowed(client, swap, proof_type):
        raise PermissionError("actor_not_allowed_for_proof")
    expected_wallet = _expected_wallet_for_proof(swap, proof_type)
    signer_wallet = _normalize_wallet(proof.get('signer_wallet') or expected_wallet)
    if expected_wallet and signer_wallet and expected_wallet != signer_wallet:
        raise PermissionError("proof_signer_wallet_mismatch")
    if signer_wallet:
        _ensure_wallet_authorized(client, signer_wallet, EVM_CHAIN_ID)
    if swap.get('state') in (SWAP_STATE_COMPLETED, SWAP_STATE_REFUNDED, SWAP_STATE_FAILED):
        raise ValueError("swap_terminal_state")
    if STORAGE_DB.htlc_tx_hash_exists(tx_hash):
        raise ValueError("proof_replay_detected")
    verification = _verify_htlc_proof_server_side(swap, proof)
    observed_confirmations = int(verification.get('confirmations', 0))
    if observed_confirmations < HTLC_MIN_CONFIRMATIONS:
        raise ValueError("insufficient_confirmations")
    proof_attestation = _verify_htlc_proof_wallet_signature(client, swap, proof, signer_wallet)

    next_state = _swap_transition(swap.get('state', SWAP_STATE_INIT), proof_type)
    proof['proof_type'] = proof_type
    proof['tx_hash'] = str(verification.get('tx_hash', tx_hash)).strip().lower()
    proof['confirmations'] = observed_confirmations
    proof['signer_wallet'] = signer_wallet
    proof_metadata = dict(proof.get('metadata') or {})
    proof_metadata['wallet_attestation'] = {
        'verified': bool(proof_attestation.get('verified', False)),
        'wallet': proof_attestation.get('wallet', signer_wallet),
        'message_hash': proof_attestation.get('message_hash', ''),
        'signature_hash': proof_attestation.get('signature_hash', ''),
    }
    proof['metadata'] = proof_metadata
    STORAGE_DB.add_htlc_proof(swap_id, proof)
    proofs = STORAGE_DB.list_htlc_proofs(swap_id)

    secret_hash = swap.get('secret_hash', '')
    if proof.get('secret'):
        observed_hash = hashlib.sha256(proof['secret'].encode('utf-8')).hexdigest()
        if secret_hash and observed_hash != secret_hash:
            raise ValueError("secret_hash_mismatch")
        secret_hash = observed_hash

    completed_at = int(time.time() * 1000) if next_state == SWAP_STATE_COMPLETED else None
    STORAGE_DB.update_swap(swap_id, state=next_state, completed_at=completed_at, secret_hash=secret_hash, proofs=proofs)
    append_audit_event(
        'htlc_lock_verified' if proof_type.startswith('lock') else 'secret_revealed' if proof_type.startswith('claim') else 'swap_refunded',
        client['client_id'],
        swap_id,
        details={
            'proof_type': proof_type,
            'tx_hash': proof.get('tx_hash', tx_hash),
            'confirmations': observed_confirmations,
            'proof_verifier': verification.get('verifier', 'client_declared'),
            'wallet_attested': bool(proof_attestation.get('verified', False))
        },
        request_id=request_id
    )

    swap = STORAGE_DB.get_swap(swap_id) or swap
    invoice = None
    if swap.get('state') == SWAP_STATE_COMPLETED:
        append_audit_event('swap_completed', client['client_id'], swap_id, request_id=request_id)
        invoice = _ensure_fee_invoice_for_swap(swap, request_id=request_id)
    return {'swap': swap, 'fee_invoice': invoice}

def get_swap_status(client: Dict[str, Any], swap_id: str) -> Dict[str, Any]:
    swap = _refresh_swap_timeout_state(swap_id) or STORAGE_DB.get_swap(swap_id)
    if not swap:
        raise ValueError("swap_not_found")
    if not _swap_actor_allowed(client, swap):
        raise PermissionError("actor_not_allowed_for_swap")
    swap['proofs'] = STORAGE_DB.list_htlc_proofs(swap_id)
    swap['fee_invoice'] = STORAGE_DB.get_latest_fee_invoice(swap_id)
    return swap

def issue_fee_invoice(client: Dict[str, Any], swap_id: str, request_id: str = '') -> Dict[str, Any]:
    swap = STORAGE_DB.get_swap(swap_id)
    if not swap:
        raise ValueError("swap_not_found")
    if not _swap_actor_allowed(client, swap) and 'admin' not in (client.get('roles') or []):
        raise PermissionError("actor_not_allowed_for_swap")
    if swap.get('state') != SWAP_STATE_COMPLETED:
        raise ValueError("swap_not_completed")
    return _ensure_fee_invoice_for_swap(swap, request_id=request_id)

def confirm_fee_payment(client: Dict[str, Any], swap_id: str, payment_ref: str, request_id: str = '') -> Dict[str, Any]:
    invoice = STORAGE_DB.get_latest_fee_invoice(swap_id)
    if not invoice:
        raise ValueError("fee_invoice_not_found")
    STORAGE_DB.update_fee_invoice(invoice['invoice_id'], 'paid', payment_ref=payment_ref)
    append_audit_event('fee_paid', client['client_id'], swap_id, details={'payment_ref': payment_ref}, request_id=request_id)
    return STORAGE_DB.get_latest_fee_invoice(swap_id) or invoice

# ===== LOGGING =====
_LEVELS = {'DEBUG': 10, 'INFO': 20, 'WARN': 30, 'ERROR': 40}
_metrics = {
    'requests_total': 0,
    'auth_failed_total': 0,
    'rate_limited_total': 0,
    'instructions_created_total': 0,
    'instructions_reconstructed_total': 0,
    'p2p_messages_total': 0,
    'p2p_errors_total': 0
}

def _log_allowed(level: str) -> bool:
    return _LEVELS.get(level, 20) >= _LEVELS.get(LOG_LEVEL, 20)

def log_event(level: str, message: str, **fields):
    if not _log_allowed(level):
        return
    payload = {
        'ts': int(time.time()),
        'level': level,
        'message': message,
        'node_id': node_id or '',
        **fields
    }
    if LOG_JSON:
        line = json.dumps(payload)
    else:
        line = f"[{level}] {message} {fields}".strip()
    if LOG_FILE:
        try:
            with open(LOG_FILE, 'a') as f:
                f.write(line + '\n')
        except Exception:
            print(line)
    else:
        print(line)

def metric_inc(name: str, value: int = 1):
    if not METRICS_ENABLED:
        return
    _metrics[name] = _metrics.get(name, 0) + value

def metrics_snapshot() -> Dict[str, Any]:
    return dict(_metrics)

# ===== AUDIT LOG (IMMUTABLE CHAIN) =====
def _audit_last_hash() -> str:
    try:
        events = STORAGE_DB.list_audit_events()
        if not events:
            return ''
        return events[-1].get('hash', '')
    except Exception:
        return ''

def append_audit_event(event_type: str, actor: str, instruction_id: Optional[str] = None,
                       details: Optional[Dict[str, Any]] = None, request_id: Optional[str] = None):
    if not node_id:
        get_node_id()
    key, version, key_id = get_signing_key()
    prev_hash = _audit_last_hash()
    event = {
        'event_id': str(uuid_lib.uuid4()),
        'timestamp': int(time.time() * 1000),
        'actor': actor,
        'node_id': node_id,
        'instruction_id': instruction_id or '',
        'event_type': event_type,
        'details': details or {},
        'request_id': request_id or '',
        'prev_hash': prev_hash
    }
    event_str = json.dumps(event, sort_keys=True)
    event_hash = sha256((prev_hash + event_str).encode()).hexdigest()
    signature = hmac.new(key, event_hash.encode(), hashlib.sha256).hexdigest()
    event['hash'] = event_hash
    event['signature'] = signature
    event['key_id'] = key_id
    event['key_version'] = version
    try:
        STORAGE_DB.record_audit(event)
    except Exception:
        pass
    log_event('INFO', 'audit_event', event_type=event_type, actor=actor,
              instruction_id=instruction_id or '', request_id=request_id or '')

def verify_audit_log() -> Tuple[bool, int]:
    """Verify audit log hash chain integrity. Returns (ok, count)."""
    prev_hash = ''
    count = 0
    try:
        events = STORAGE_DB.list_audit_events()
        for event in events:
            event_hash = event.get('hash', '')
            prev = event.get('prev_hash', '')
            if prev != prev_hash:
                return False, count
            core = dict(event)
            core.pop('hash', None)
            core.pop('signature', None)
            core.pop('key_id', None)
            core.pop('key_version', None)
            event_str = json.dumps(core, sort_keys=True)
            expected = sha256((prev_hash + event_str).encode()).hexdigest()
            if expected != event_hash:
                return False, count
            prev_hash = event_hash
            count += 1
    except Exception:
        return False, count
    return True, count

# ===== UTILITY FUNCTIONS =====
def get_node_id() -> str:
    """Get or create unique node ID"""
    global node_id
    if LOCAL_TEST_MODE:
        # Local test mode uses ephemeral node IDs to allow multiple terminals on one host.
        node_id = str(uuid.uuid4())
        return node_id
    if os.path.exists(NODE_ID_FILE):
        with open(NODE_ID_FILE, 'r') as f:
            node_id = f.read().strip()
    else:
        node_id = str(uuid.uuid4())
        with open(NODE_ID_FILE, 'w') as f:
            f.write(node_id)
    return node_id

def ensure_storage():
    """Initialize storage backend"""
    try:
        STORAGE_DB.connect()
        STORAGE_DB.init_schema()
    except Exception as e:
        raise RuntimeError(f'Failed to initialize storage: {e}')

def list_shards() -> List[str]:
    """List all shard names in storage"""
    return STORAGE_DB.list_shards()


def split_text(text: str, n: int) -> List[str]:
    """Legacy: Split text into n equal parts (NOT zero-knowledge)"""
    k, m = divmod(len(text), n)
    return [text[i*k+min(i, m):(i+1)*k+min(i+1, m)] for i in range(n)]

# ===== SHAMIR SECRET SHARING (Zero-Knowledge Sharding) =====
def shard_with_sss(payload_bytes: bytes, k: int, n: int) -> Tuple[bytes, List[Tuple[int, bytes]]]:
    """
    Encrypt payload with random AES key, then SSS-split the key.
    Each shard is a key share - no shard reveals any payload content.
    Returns: (encrypted_payload_with_nonce_tag, [(index, share), ...])
    """
    if not SSS_AVAILABLE:
        raise RuntimeError("pycryptodome required for Shamir Secret Sharing")
    # pycryptodome Shamir expects a 16-byte secret. We derive AES-256 key material
    # from that secret to keep 256-bit encryption while preserving SSS compatibility.
    sss_secret = get_random_bytes(16)
    aes_key = sha256(sss_secret).digest()
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(payload_bytes)
    encrypted_blob = cipher.nonce + tag + ciphertext
    shares = Shamir.split(k, n, sss_secret)
    return encrypted_blob, shares

def reconstruct_from_sss(encrypted_blob: bytes, shares: List[Tuple[int, bytes]]) -> bytes:
    """Reconstruct payload from encrypted blob and k SSS shares."""
    if not SSS_AVAILABLE:
        raise RuntimeError("pycryptodome required for Shamir Secret Sharing")
    sss_secret = Shamir.combine(shares)
    key = sha256(sss_secret).digest()
    nonce = encrypted_blob[:16]
    tag = encrypted_blob[16:32]
    ciphertext = encrypted_blob[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def shard_instruction(instr_json: str, k: int, n: int) -> Tuple[str, List[Dict]]:
    """
    Shard instruction using SSS. Returns (encrypted_blob_b64, list of shard dicts).
    Each shard: {"index": i, "share": base64(share_bytes)} - zero-knowledge.
    """
    payload_bytes = instr_json.encode('utf-8')
    encrypted_blob, shares = shard_with_sss(payload_bytes, k, n)
    encrypted_b64 = base64.b64encode(encrypted_blob).decode('ascii')
    shard_dicts = [
        {"index": idx, "share": base64.b64encode(share).decode('ascii')}
        for idx, share in shares
    ]
    return encrypted_b64, shard_dicts

def reconstruct_instruction_from_shards(encrypted_b64: str, shard_dicts: List[Dict]) -> str:
    """Reconstruct instruction from encrypted blob and SSS shards."""
    encrypted_blob = base64.b64decode(encrypted_b64)
    shares = [(s["index"], base64.b64decode(s["share"])) for s in shard_dicts]
    payload_bytes = reconstruct_from_sss(encrypted_blob, shares)
    return payload_bytes.decode('utf-8')

def parse_reconstructed_instruction(instr_json: str) -> Dict[str, Any]:
    """
    Parse reconstructed instruction payload with strict validation.
    Supports normal JSON object and double-encoded JSON string payloads.
    """
    payload = (instr_json or '').strip()
    if not payload:
        raise ValueError('empty reconstructed payload')
    obj = json.loads(payload)
    if isinstance(obj, str):
        obj = json.loads(obj)
    if not isinstance(obj, dict):
        raise ValueError('reconstructed payload is not a JSON object')
    return obj

def print_status():
    """Display node status"""
    print('\n' + '='*47)
    print('  ONESEAM DARKPOOL NODE STATUS')
    print('='*47)
    print(f'Node ID: {node_id[:16]}...')
    print(f'Node address (P2P): 0.0.0.0:{NODE_PORT}')
    print(f'API address: {API_BIND}:{API_PORT}')
    print(f'Transport: {TRANSPORT_MODE} | Quorum: {DEFAULT_QUORUM_K}-of-{DEFAULT_QUORUM_N}')
    intent_count = len(STORAGE_DB.list_open_trade_intents())
    cur = STORAGE_DB._execute("SELECT COUNT(*) FROM matches")
    match_count = int(cur.fetchone()[0]) if cur else 0
    cur = STORAGE_DB._execute("SELECT COUNT(*) FROM swap_coordination")
    swap_count = int(cur.fetchone()[0]) if cur else 0
    print(f'Orders open: {intent_count} | Matches: {match_count} | Swaps: {swap_count}')
    
    with neighbors_lock:
        peer_items = list(neighbors.items())
        count = len(peer_items)
        print(f'Network: {count} peers online')
        if count == 0:
            print('  (no peers discovered yet)')
        else:
            print('  Address = IP:Port of each peer node.')
            for nid, info in peer_items[:8]:
                ip = info.get('ip', '-')
                port = info.get('node_port', NODE_PORT)
                print(f'  - {nid[:8]}... | address: {ip}:{port}')

# ===== PRIVATE OTC PAYLOAD =====
def generate_instruction_id() -> str:
    """Generate unique instruction ID"""
    timestamp = int(time.time())
    random_part = secrets.token_hex(4)
    return f'instr_{timestamp}_{random_part}'

def create_financial_instruction(
    payload: str,
    origin: str,
    destination: str,
    encryption_key: Optional[str] = None,
    quorum_k: Optional[int] = None,
    quorum_n: Optional[int] = None,
    jurisdiction: Optional[str] = None,
    data_region: Optional[str] = None,
    compliance_frameworks: Optional[List[str]] = None
) -> Dict:
    """Create private OTC payload envelope for sharded P2P distribution."""
    instruction_id = generate_instruction_id()
    timestamp = int(time.time())
    
    # Encrypt payload if key provided
    if encryption_key:
        payload_final = encrypt_payload_aes256(payload, encryption_key)
        encrypted = True
    else:
        payload_final = payload
        encrypted = False
    
    # Generate integrity hash
    integrity_hash = generate_dna_hash(payload)
    
    return {
        'instruction_id': instruction_id,
        'payload': payload_final,
        'timestamp': timestamp,
        'origin': origin,
        'destination': destination,
        'encrypted': encrypted,
        'integrity_hash': integrity_hash,
        'version': '2.0',
        'quorum_k': quorum_k if quorum_k is not None else DEFAULT_QUORUM_K,
        'quorum_n': quorum_n if quorum_n is not None else DEFAULT_QUORUM_N,
        'jurisdiction': jurisdiction or '',
        'data_region': data_region or '',
        'compliance_frameworks': compliance_frameworks or []
    }

# ===== MANIFEST & AUDIT LOGS =====
def sign_log_entry(entry: Dict, signing_key: str) -> str:
    """Cryptographically sign audit log entry"""
    if not signing_key:
        signing_key = get_node_id()
    entry_str = json.dumps(entry, sort_keys=True)
    signature = sha256((entry_str + signing_key).encode()).hexdigest()
    return signature

def create_instruction_manifest(instr: Dict, shards: List, encrypted_payload_b64: Optional[str] = None,
                                shard_dicts: Optional[List[Dict]] = None, quorum_k: Optional[int] = None,
                                quorum_n: Optional[int] = None) -> Dict:
    """
    Create manifest for instruction distribution.
    Includes audit trail, shard mapping, and encrypted payload (for SSS mode).
    """
    k = quorum_k or instr.get('quorum_k', DEFAULT_QUORUM_K)
    n = quorum_n or instr.get('quorum_n', DEFAULT_QUORUM_N)
    
    manifest = {
        'instruction_id': instr['instruction_id'],
        'timestamp': instr['timestamp'],
        'origin': instr['origin'],
        'destination': instr['destination'],
        'encrypted': instr.get('encrypted', False),
        'integrity_hash': instr.get('integrity_hash'),
        'total_shards': n,
        'quorum_threshold': k,
        'quorum_k': k,
        'quorum_n': n,
        'shards': [],
        'log': [],
        'jurisdiction': instr.get('jurisdiction', ''),
        'data_region': instr.get('data_region', ''),
        'compliance_frameworks': instr.get('compliance_frameworks', []),
        'sharding_mode': 'sss' if (encrypted_payload_b64 and shard_dicts) else 'legacy',
        'encrypted_payload_b64': encrypted_payload_b64,
        'shard_indices': [s['index'] for s in (shard_dicts or [])]
    }
    
    # Log creation event
    log_entry = {
        'event': 'instruction_created',
        'instruction_id': instr['instruction_id'],
        'timestamp': instr['timestamp'],
        'node_id': node_id
    }
    log_entry['signature'] = sign_log_entry(log_entry, node_id)
    manifest['log'].append(log_entry)
    try:
        append_audit_event('instruction_created', instr.get('origin', ''), instr['instruction_id'])
    except Exception:
        pass
    
    return manifest

def append_log_to_manifest(instruction_id: str, event: str, node_id_override: str = None):
    """Append audit event to manifest"""
    try:
        manifest = get_manifest_record(instruction_id)
        if not manifest:
            return
        
        log_entry = {
            'event': event,
            'instruction_id': instruction_id,
            'timestamp': int(time.time() * 1000),
            'node_id': node_id_override or node_id
        }
        log_entry['signature'] = sign_log_entry(log_entry, node_id_override or node_id)
        manifest.setdefault('log', []).append(log_entry)
        
        store_manifest_record(instruction_id, manifest)
        try:
            append_audit_event(event, node_id_override or node_id, instruction_id)
        except Exception:
            pass
    except Exception as e:
        print(f'[AUDIT] Failed to log event: {e}')

# ===== QUORUM RECONSTRUCTION (k-of-n) =====
def reconstruct_with_quorum(instruction_id: str, threshold: Optional[int] = None) -> Optional[Dict]:
    """
    Byzantine fault-tolerant reconstruction (k-of-n).
    Supports both SSS (zero-knowledge) and legacy sharding.
    
    Args:
        instruction_id: Instruction to reconstruct
        threshold: Minimum shards needed (default: from manifest)
    
    Returns:
        Reconstructed instruction or None if quorum not met
    """
    manifest = get_manifest_record(instruction_id)
    if not manifest:
        print(f'[QUORUM] Manifest not found: {instruction_id}')
        return None
    
    k = threshold or manifest.get('quorum_threshold', manifest.get('quorum_k', 2))
    n = manifest.get('quorum_n', manifest.get('total_shards', 3))
    sharding_mode = manifest.get('sharding_mode', 'legacy')
    
    if sharding_mode == 'sss' and not SSS_AVAILABLE:
        print('[QUORUM] SSS shards present but pycryptodome not available')
        return None
    
    if sharding_mode == 'sss' and SSS_AVAILABLE:
        # SSS mode: collect key share shards
        encrypted_b64 = manifest.get('encrypted_payload_b64')
        if not encrypted_b64:
            print(f'[QUORUM] SSS manifest missing encrypted_payload_b64')
            return None
        
        shard_indices = manifest.get('shard_indices', list(range(1, n + 1)))
        available_shards = []
        seen_indices = set()
        
        for shard_idx in shard_indices:
            for replica in range(1, 4):  # Up to 3 replicas
                shard_name = f'{instruction_id}_shard{shard_idx}_v{replica}.json'
                data = get_shard_record(shard_name)
                if data:
                    idx = data.get('index')
                    share = data.get('share')
                    if idx is not None and share and idx not in seen_indices:
                        available_shards.append({'index': idx, 'share': share})
                        seen_indices.add(idx)
                        break
        
        if len(available_shards) < k:
            print(f'[QUORUM] [X] Only {len(available_shards)}/{k} SSS shards available')
            return None
        
        print(f'[QUORUM] [OK] Achieved ({len(available_shards)}/{k} SSS shards)')
        
        instruction = None
        last_error = None
        # Try every k-of-n combination to tolerate one bad or stale shard.
        for combo in combinations(available_shards, int(k)):
            try:
                instr_json = reconstruct_instruction_from_shards(encrypted_b64, list(combo))
                instruction = parse_reconstructed_instruction(instr_json)
                break
            except Exception as e:
                last_error = e
                continue
        if instruction is None:
            print(f'[QUORUM] [X] SSS reconstruction failed: {last_error}')
            return None
    else:
        # Legacy mode
        available_shards = []
        for shard_idx in range(1, n + 1):
            shard_found = False
            for replica in range(1, 4):
                shard_name = f'{instruction_id}_shard{shard_idx}_v{replica}.json'
                data = get_shard_record(shard_name)
                if data:
                    payload = data.get('data')
                    available_shards.append((shard_idx, payload))
                    shard_found = True
                    break
            if not shard_found:
                print(f'[QUORUM] Shard {shard_idx} completely missing')
        
        unique_shards = {idx for idx, _ in available_shards}
        if len(unique_shards) < n:
            print(f'[QUORUM] [X] Only {len(unique_shards)}/{n} shards available')
            return None
        
        print(f'[QUORUM] [OK] Achieved ({len(unique_shards)}/{n} shards)')
        shard_map = {}
        for idx, data in available_shards:
            if idx not in shard_map:
                shard_map[idx] = data
        if len(shard_map) < n:
            print(f'[QUORUM] [X] Missing legacy shards for full reconstruction')
            return None
        reconstruction_data = [shard_map[i] for i in range(1, n + 1)]
        
        try:
            instr_json = ''.join(reconstruction_data)
            instruction = parse_reconstructed_instruction(instr_json)
        except Exception as e:
            print(f'[QUORUM] [X] Reconstruction failed: {e}')
            return None
    
    # Verify integrity
    if manifest.get('integrity_hash'):
        expected = manifest.get('integrity_hash')
        if instruction.get('encrypted'):
            print('[QUORUM] Integrity verification skipped (payload encrypted)')
        elif 'payload' in instruction:
            actual = generate_dna_hash(str(instruction['payload']))
            if actual == expected:
                print(f'[QUORUM] Integrity check: OK ({expected[:16]}...)')
            else:
                print(f'[QUORUM] Integrity check: FAIL (expected {expected[:16]}..., got {actual[:16]}...)')
        else:
            print('[QUORUM] Integrity verification skipped (no payload)')
    
    # Legacy billing hooks are intentionally disabled in OTC mode.
    append_log_to_manifest(instruction_id, 'instruction_reconstructed')
    metric_inc('instructions_reconstructed_total')
    print(f'[QUORUM] [OK] Instruction reconstructed successfully')
    return instruction

# ===== BLIND RELAY (Repasse Cego) =====
def is_destination_node(destination_bank_id: str) -> bool:
    """
    Returns True if this node serves the destination institution.
    """
    if not destination_bank_id:
        return False
    return destination_bank_id in SERVED_DESTINATIONS

def find_relay_targets(instruction_id: str, destination: str, data_region: str,
                       exclude_ips: Optional[List[str]] = None) -> List[Dict]:
    """
    Find neighbors "closer" to the destination for Blind Relay.
    Priority: (a) neighbors that serve destination, (b) same region, (c) others.
    Excludes IPs in exclude_ips to avoid relaying back to sender.
    """
    exclude_ips = exclude_ips or []
    with neighbors_lock:
        all_neighbors = [n for n in neighbors.values() if n.get('ip') not in exclude_ips and n.get('ip') != '127.0.0.1']
    
    def score(n: Dict) -> Tuple[int, str]:
        served = n.get('served_destinations') or []
        if destination in served:
            return (2, n.get('ip', ''))
        if data_region and (n.get('region') or '').upper() == data_region.upper():
            return (1, n.get('ip', ''))
        return (0, n.get('ip', ''))
    
    sorted_neighbors = sorted(all_neighbors, key=score, reverse=True)
    return [n for n in sorted_neighbors if score(n)[0] >= 0]

async def relay_worker():
    """
    Relay worker: repass shards immediately from an in-memory queue.
    """
    while True:
        shard_payload = await RELAY_QUEUE.get()
        try:
            if not BLIND_RELAY_ENABLED:
                continue
            shard_name = shard_payload['shard_name']
            destination = shard_payload.get('destination', '')
            data_region = shard_payload.get('data_region', '')
            relay_hops = int(shard_payload.get('relay_hops', 0))
            shard_data = shard_payload.get('shard_data', '')
            shard_dict = shard_payload.get('shard_dict')
            signature = shard_payload.get('signature', '')
            sender_id = shard_payload.get('sender_id', '')
            
            if is_destination_node(destination):
                continue
            if relay_hops >= MAX_RELAY_HOPS:
                continue
            
            instruction_id = shard_name.rsplit('_shard', 1)[0] if '_shard' in shard_name else ''
            if not instruction_id:
                continue
            
            targets = find_relay_targets(instruction_id, destination, data_region)
            if not targets:
                continue
            
            relay_meta = {
                'destination': destination,
                'data_region': data_region,
                'relay_hops': relay_hops + 1
            }
            msg = {
                'cmd': CMD_STORE_SHARD,
                'shard_name': shard_name,
                'shard_data': shard_data,
                'instruction_id': instruction_id,
                'signature': signature,
                'sender_id': sender_id,
                **relay_meta
            }
            if shard_dict:
                msg['shard_dict'] = shard_dict
            
            for target in targets[:2]:
                ip = target.get('ip')
                if not ip or ip == '127.0.0.1':
                    continue
                resp = await send_to_node_async(ip, msg, port=target.get('node_port', NODE_PORT))
                if resp and resp == b'OK':
                    if not QUIET_MODE:
                        print(f'[RELAY] [OK] Relayed {shard_name} -> {ip} (hops={relay_hops + 1})')
                    break
        except Exception as e:
            if not QUIET_MODE:
                print(f'[RELAY] Error: {e}')
        finally:
            RELAY_QUEUE.task_done()

# ===== SMART ROUTING (Data Sovereignty) =====
def find_nodes_near_bank(bank_id: str, region_hint: Optional[str] = None,
                         data_region: Optional[str] = None) -> List[Dict]:
    """
    Find nodes geographically close to destination bank.
    Filters by region for data sovereignty (GDPR, LGPD).
    """
    with neighbors_lock:
        all_neighbors = list(neighbors.values())
    
    region = region_hint or data_region
    if not region:
        return all_neighbors
    
    # Filter by region for compliance
    filtered = [n for n in all_neighbors if n.get('region', '').upper() == region.upper()]
    return filtered if filtered else all_neighbors

def distribute_shards_smart(shards_data, instruction_id: str, destination_bank_id: str,
                           manifest: Dict, k: int, n: int, use_sss: bool = True):
    """
    Distribute shards with intelligent routing.
    SSS mode: shards_data = list of shard dicts (index, share).
    Legacy mode: shards_data = list of string fragments.
    Hybrid Strategy: (1) Prioritize nodes serving destination, (2) Filter by region, (3) Fallback to all neighbors
    """
    ensure_storage()
    
    # Hybrid routing: prioritize nodes that serve the destination bank
    with neighbors_lock:
        all_neighbors = [n for n in neighbors.values() if n.get('ip') != '127.0.0.1']
    
    # Priority 1: Nodes that explicitly serve the destination bank
    serving_nodes = [n for n in all_neighbors 
                     if destination_bank_id in (n.get('served_destinations') or [])]
    
    # Priority 2: Nodes in same region for data sovereignty
    if not serving_nodes:
        region = manifest.get('data_region', '')
        if region:
            serving_nodes = [n for n in all_neighbors 
                           if n.get('region', '').upper() == region.upper()]
    
    # Priority 3: All neighbors (fallback to blind relay)
    if not serving_nodes:
        serving_nodes = all_neighbors
    
    destination_nodes = serving_nodes + [{'ip': '127.0.0.1'}] if serving_nodes else [{'ip': '127.0.0.1'}]
    
    total_distributed = 0
    
    if use_sss and isinstance(shards_data, list) and shards_data and isinstance(shards_data[0], dict):
        # SSS mode: distribute key share shards
        for idx, shard_dict in enumerate(shards_data):
            for replica in range(3):
                shard_idx = shard_dict.get('index', idx + 1)
                shard_name = f'{instruction_id}_shard{shard_idx}_v{replica+1}.json'
                shard_payload = json.dumps({'index': shard_dict['index'], 'share': shard_dict['share']})
                signature = sign_shard_payload(shard_name, shard_payload, instruction_id) if SHARD_SIGNATURE_REQUIRED else ''
                target = destination_nodes[(idx * 3 + replica) % len(destination_nodes)]
                ip = target['ip']
                relay_meta = {
                    'destination': destination_bank_id,
                    'data_region': manifest.get('data_region', ''),
                    'relay_hops': 0
                }
                if ip == '127.0.0.1':
                    store_shard_record(
                        shard_name,
                        shard_payload,
                        shard_dict,
                        {**relay_meta, 'received_at': int(time.time())},
                        signature,
                        node_id or ''
                    )
                    print(f'[DISTRIBUTE] [OK] Local: {shard_name}')
                    total_distributed += 1
                else:
                    msg = {
                        'cmd': CMD_STORE_SHARD,
                        'shard_name': shard_name,
                        'shard_data': shard_payload,
                        'shard_dict': shard_dict,
                        'instruction_id': instruction_id,
                        'signature': signature,
                        'sender_id': node_id or '',
                        **relay_meta
                    }
                    resp = send_to_node(ip, msg, port=target.get('node_port', NODE_PORT))
                    if resp and resp == b'OK':
                        print(f'[DISTRIBUTE] [OK] Remote: {shard_name} -> {ip}')
                        total_distributed += 1
                    else:
                        print(f'[DISTRIBUTE] [X] Failed: {shard_name} -> {ip}')
    else:
        # Legacy mode
        relay_meta = {
            'destination': destination_bank_id,
            'data_region': manifest.get('data_region', ''),
            'relay_hops': 0
        }
        for idx, shard in enumerate(shards_data):
            for replica in range(3):
                shard_name = f'{instruction_id}_shard{idx+1}_v{replica+1}.json'
                signature = sign_shard_payload(shard_name, shard, instruction_id) if SHARD_SIGNATURE_REQUIRED else ''
                target = destination_nodes[(idx * 3 + replica) % len(destination_nodes)]
                ip = target['ip']
                if ip == '127.0.0.1':
                    store_shard_record(
                        shard_name,
                        shard,
                        None,
                        {**relay_meta, 'received_at': int(time.time())},
                        signature,
                        node_id or ''
                    )
                    print(f'[DISTRIBUTE] [OK] Local: {shard_name}')
                    total_distributed += 1
                else:
                    msg = {'cmd': CMD_STORE_SHARD, 'shard_name': shard_name, 'shard_data': shard,
                           'instruction_id': instruction_id, 'signature': signature,
                           'sender_id': node_id or '', **relay_meta}
                    resp = send_to_node(ip, msg, port=target.get('node_port', NODE_PORT))
                    if resp and resp == b'OK':
                        print(f'[DISTRIBUTE] [OK] Remote: {shard_name} -> {ip}')
                        total_distributed += 1
                    else:
                        print(f'[DISTRIBUTE] [X] Failed: {shard_name} -> {ip}')
    
    expected = n * 3
    print(f'[DISTRIBUTE] Total: {total_distributed}/{expected} shards distributed')
    
    store_manifest_record(instruction_id, manifest)
    print(f'[DISTRIBUTE] Manifest saved: {instruction_id}')
    
    # Distribute manifest to neighbors (destination can fetch)
    for target in destination_nodes[:5]:
        if target['ip'] != '127.0.0.1':
            msg = {'cmd': CMD_STORE_MANIFEST, 'instruction_id': instruction_id, 'manifest': manifest}
            resp = send_to_node(target['ip'], msg, port=target.get('node_port', NODE_PORT))
            if resp and b'OK' in resp:
                print(f'[DISTRIBUTE] [OK] Manifest sent to {target["ip"]}')

async def collect_shards_dynamically_async(instruction_id: str, max_attempts: int = 10,
                                           poll_interval: float = 2.0) -> bool:
    """
    Destination node: dynamically collect shards from neighbors until quorum.
    Returns True if quorum achieved and shards collected locally.
    """
    manifest = get_manifest_record(instruction_id)
    if not manifest:
        print(f'[COLLECT] Manifest not found: {instruction_id}')
        return False
    
    k = manifest.get('quorum_k', manifest.get('quorum_threshold', 2))
    n = manifest.get('quorum_n', manifest.get('total_shards', 3))
    sharding_mode = manifest.get('sharding_mode', 'legacy')
    required = k if sharding_mode == 'sss' else n
    
    for attempt in range(max_attempts):
        collected_indices = set()
        for shard_idx in range(1, n + 1):
            if sharding_mode == 'sss':
                for replica in range(1, 4):
                    shard_name = f'{instruction_id}_shard{shard_idx}_v{replica}.json'
                    data = get_shard_record(shard_name)
                    if data:
                        idx = data.get('index')
                        if idx is not None:
                            collected_indices.add(idx)
                        break
            else:
                for replica in range(1, 4):
                    shard_name = f'{instruction_id}_shard{shard_idx}_v{replica}.json'
                    if shard_exists(shard_name):
                        collected_indices.add(shard_idx)
                        break
        
        if len(collected_indices) >= required:
            print(f'[COLLECT] [OK] Quorum achieved locally ({len(collected_indices)}/{required})')
            return True
        
        with neighbors_lock:
            neighbor_list = list(neighbors.values())
        
        for neighbor in neighbor_list:
            if neighbor['ip'] == '127.0.0.1':
                continue
            for shard_idx in manifest.get('shard_indices', list(range(1, n + 1))):
                for replica in range(1, 4):
                    shard_name = f'{instruction_id}_shard{shard_idx}_v{replica}.json'
                    if shard_exists(shard_name):
                        continue
                    msg = {'cmd': CMD_FETCH_SHARD, 'shard_name': shard_name}
                    resp = await send_to_node_async(neighbor['ip'], msg)
                    if resp:
                        try:
                            r = json.loads(resp.decode())
                            if r.get('status') == 'OK':
                                if r.get('index') is not None and r.get('share'):
                                    if SHARD_SIGNATURE_REQUIRED and not verify_shard_signature(r.get('sender_id', ''), shard_name, r.get('shard_data'), instruction_id, r.get('signature', '')):
                                        continue
                                    store_shard_record(
                                        shard_name,
                                        r.get('shard_data'),
                                        {'index': r['index'], 'share': r['share']},
                                        {'received_at': int(time.time()), 'destination': manifest.get('destination', ''),
                                         'data_region': manifest.get('data_region', ''), 'relay_hops': 0},
                                        r.get('signature'),
                                        r.get('sender_id', '')
                                    )
                                else:
                                    data = r.get('shard_data', r)
                                    if SHARD_SIGNATURE_REQUIRED and not verify_shard_signature(r.get('sender_id', ''), shard_name, data, instruction_id, r.get('signature', '')):
                                        continue
                                    store_shard_record(
                                        shard_name,
                                        data,
                                        None,
                                        {'received_at': int(time.time()), 'destination': manifest.get('destination', ''),
                                         'data_region': manifest.get('data_region', ''), 'relay_hops': 0},
                                        r.get('signature'),
                                        r.get('sender_id', '')
                                    )
                                print(f'[COLLECT] [OK] Fetched {shard_name} from {neighbor["ip"]}')
                                break
                        except Exception:
                            pass
        
        await asyncio.sleep(poll_interval)
    
    print(f'[COLLECT] [X] Quorum not achieved after {max_attempts} attempts')
    return False

def collect_shards_dynamically(instruction_id: str, max_attempts: int = 10,
                               poll_interval: float = 2.0) -> bool:
    return run_async(collect_shards_dynamically_async(instruction_id, max_attempts, poll_interval))

# ===== NETWORKING: DISCOVERY (On-Grid / Off-Grid) =====
async def broadcast_presence_async():
    """Broadcast node presence via UDP (on-grid) or mesh (off-grid)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setblocking(False)
    
    capabilities = ['storage', 'reconstruction', 'routing', 'otc_v1']
    if TRANSPORT_MODE in ('OFF_GRID', 'HYBRID'):
        capabilities.append('mesh')
    
    loop = asyncio.get_running_loop()
    while True:
        try:
            msg = json.dumps({
                'cmd': CMD_HANDSHAKE,
                'node_id': node_id,
                'node_port': NODE_PORT,
                'capabilities': capabilities,
                'version': '2.0',
                'transport_mode': TRANSPORT_MODE,
                'region': CONFIG.get('region', ''),
                'country_code': CONFIG.get('country_code', ''),
                'served_destinations': SERVED_DESTINATIONS,
                'node_signing_pub': get_node_signing_public()
            }).encode()
            await loop.sock_sendto(s, msg, (BROADCAST_ADDR, BROADCAST_PORT))
        except Exception:
            pass
        await asyncio.sleep(5)

async def listen_broadcast_async():
    """Listen for UDP broadcasts from other nodes"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', BROADCAST_PORT))
    s.setblocking(False)
    loop = asyncio.get_running_loop()
    
    while True:
        try:
            data, addr = await loop.sock_recvfrom(s, BUFFER_SIZE)
            msg = json.loads(data.decode())
            
            if msg.get('cmd') == CMD_HANDSHAKE and msg.get('node_id') != node_id:
                with neighbors_lock:
                    neighbors[msg['node_id']] = {
                        'ip': addr[0],
                        'node_port': msg.get('node_port', NODE_PORT),
                        'capabilities': msg.get('capabilities', []),
                        'version': msg.get('version', '0.0'),
                        'transport_mode': msg.get('transport_mode', 'ON_GRID'),
                        'region': msg.get('region', ''),
                        'country_code': msg.get('country_code', ''),
                        'served_destinations': msg.get('served_destinations', []),
                        'last_seen': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'last_seen_ts': time.time(),
                        'signing_pub': msg.get('node_signing_pub', '')
                    }
        except Exception:
            await asyncio.sleep(0.1)

def _parse_seed_nodes() -> List[Dict[str, Any]]:
    seeds = []
    for item in SEED_NODES:
        if isinstance(item, str):
            if ':' in item:
                host, port = item.split(':', 1)
                try:
                    port = int(port)
                except Exception:
                    port = NODE_PORT
                seeds.append({'ip': host, 'port': port})
            else:
                seeds.append({'ip': item, 'port': NODE_PORT})
        elif isinstance(item, dict):
            seeds.append({'ip': item.get('ip'), 'port': item.get('port', NODE_PORT)})
    return [s for s in seeds if s.get('ip')]

def _local_test_registry_path() -> str:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.isabs(LOCAL_TEST_REGISTRY_DIR):
        return LOCAL_TEST_REGISTRY_DIR
    return os.path.join(base_dir, LOCAL_TEST_REGISTRY_DIR)

def _local_test_registry_file() -> str:
    safe_node = (node_id or 'unknown').replace(':', '_').replace('/', '_').replace('\\', '_')
    return os.path.join(_local_test_registry_path(), f'{safe_node}.json')

def local_test_registry_touch():
    if not LOCAL_TEST_MODE or not node_id:
        return
    try:
        reg_dir = _local_test_registry_path()
        os.makedirs(reg_dir, exist_ok=True)
        record = {
            'node_id': node_id,
            'node_port': NODE_PORT,
            'updated_at': int(time.time()),
            'pid': os.getpid()
        }
        target = _local_test_registry_file()
        tmp = f'{target}.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(record, f)
        os.replace(tmp, target)
    except Exception:
        pass

def local_test_registry_peers() -> List[Dict[str, Any]]:
    peers: List[Dict[str, Any]] = []
    if not LOCAL_TEST_MODE:
        return peers
    now_ts = int(time.time())
    reg_dir = _local_test_registry_path()
    if not os.path.isdir(reg_dir):
        return peers
    try:
        for name in os.listdir(reg_dir):
            if not name.endswith('.json'):
                continue
            full_path = os.path.join(reg_dir, name)
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    rec = json.load(f)
            except Exception:
                continue
            remote_id = rec.get('node_id', '')
            try:
                remote_port = int(rec.get('node_port', 0))
                updated_at = int(rec.get('updated_at', 0))
            except Exception:
                continue
            if not remote_id or remote_id == node_id or remote_port <= 0:
                continue
            if now_ts - updated_at > LOCAL_TEST_REGISTRY_TTL_SECONDS:
                try:
                    os.remove(full_path)
                except Exception:
                    pass
                continue
            peers.append({'node_id': remote_id, 'ip': '127.0.0.1', 'port': remote_port})
    except Exception:
        return peers
    return peers

def local_test_registry_cleanup():
    if not LOCAL_TEST_MODE or not node_id:
        return
    try:
        os.remove(_local_test_registry_file())
    except Exception:
        pass

async def bootstrap_seeds():
    while True:
        seeds = _parse_seed_nodes()
        if not seeds:
            await asyncio.sleep(30)
            continue
        msg = {
            'cmd': CMD_HANDSHAKE,
            'node_id': node_id,
            'node_port': NODE_PORT,
            'capabilities': ['storage', 'reconstruction', 'routing', 'otc_v1'],
            'version': '2.0',
            'transport_mode': TRANSPORT_MODE,
            'region': CONFIG.get('region', ''),
            'country_code': CONFIG.get('country_code', ''),
            'served_destinations': SERVED_DESTINATIONS,
            'node_signing_pub': get_node_signing_public()
        }
        for seed in seeds:
            try:
                await send_to_node_async(seed['ip'], msg, port=seed['port'])
            except Exception:
                continue
        await asyncio.sleep(30)

async def local_test_discovery_async():
    """
    Local discovery helper for same-host testing.
    Uses a local node registry directory and exchanges handshakes.
    """
    if not LOCAL_TEST_MODE:
        return
    while True:
        try:
            local_test_registry_touch()
            msg = {
                'cmd': CMD_HANDSHAKE,
                'node_id': node_id,
                'node_port': NODE_PORT,
                'capabilities': ['storage', 'reconstruction', 'routing', 'otc_v1'],
                'version': '2.0',
                'transport_mode': TRANSPORT_MODE,
                'region': CONFIG.get('region', ''),
                'country_code': CONFIG.get('country_code', ''),
                'served_destinations': SERVED_DESTINATIONS,
                'node_signing_pub': get_node_signing_public()
            }
            for peer in local_test_registry_peers():
                try:
                    await send_to_node_async(peer['ip'], msg, port=peer['port'])
                except Exception:
                    pass
        except Exception:
            pass
        await asyncio.sleep(max(0.5, LOCAL_TEST_DISCOVERY_INTERVAL))

def try_upnp():
    if not UPNP_ENABLED:
        return
    try:
        import miniupnpc
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 200
        upnp.discover()
        upnp.selectigd()
        external_ip = upnp.externalipaddress()
        upnp.addportmapping(NODE_PORT, 'TCP', upnp.lanaddr, NODE_PORT, 'Oneseam P2P', '')
        print(f'[UPNP] Mapped TCP {NODE_PORT} on {external_ip}')
    except Exception as e:
        print(f'[UPNP] Failed: {e}')

async def prune_neighbors_async():
    """Remove stale neighbors."""
    while True:
        try:
            now = time.time()
            with neighbors_lock:
                stale = []
                for nid, info in neighbors.items():
                    last = info.get('last_seen_ts', None)
                    if last and now - last > NEIGHBOR_TTL_SECONDS:
                        stale.append(nid)
                for nid in stale:
                    neighbors.pop(nid, None)
            await asyncio.sleep(NEIGHBOR_TTL_SECONDS)
        except Exception:
            await asyncio.sleep(NEIGHBOR_TTL_SECONDS)

def _apply_verified_action_from_intent(intent: Dict[str, Any], trade: Dict[str, Any], onchain: Dict[str, Any]):
    action = intent.get('action', '')
    next_state = OTC_ACTION_NEXT_STATE.get(action)
    event_type = OTC_ACTION_EVENT_TYPE_MAP.get(action, '')
    if not next_state or not event_type:
        raise ValueError("invalid_trade_action")
    trade_id = intent.get('trade_id', '')
    tx_hash = onchain.get('tx_hash', '')
    if not tx_hash:
        raise ValueError("tx_not_found")

    existing = STORAGE_DB.get_escrow_event_by_tx_hash(tx_hash)
    if existing and existing.get('trade_id') != trade_id:
        raise ValueError("tx_hash_reused")
    if existing and existing.get('trade_id') == trade_id:
        STORAGE_DB.update_onchain_intent_status(intent['intent_id'], 'confirmed', tx_hash=tx_hash)
        return

    escrow_ref = trade.get('escrow_trade_ref', '')
    if action == OTC_ACTION_ESCROW_CREATE:
        escrow_ref = onchain.get('escrow_trade_ref') or escrow_ref or tx_hash

    STORAGE_DB.update_trade_state(
        trade_id,
        next_state,
        escrow_trade_ref=escrow_ref if action == OTC_ACTION_ESCROW_CREATE else None,
        add_tx_hash=tx_hash
    )
    STORAGE_DB.record_escrow_event({
        'trade_id': trade_id,
        'event_type': event_type,
        'intent_id': intent.get('intent_id', ''),
        'contract_address': onchain.get('contract_address', ESCROW_CONTRACT_ADDRESS),
        'event_name': onchain.get('event_name', OTC_ACTION_EVENT_MAP.get(action, '')),
        'tx_hash': tx_hash,
        'block_number': onchain.get('block_number', 0),
        'confirmations': onchain.get('confirmations', 0),
        'chain_id': EVM_CHAIN_ID,
        'verified': bool(onchain.get('verified', False)),
        'payload': {
            'reconciled': True,
            'action': action,
            'event_args': onchain.get('event_args', {})
        }
    })
    STORAGE_DB.update_onchain_intent_status(intent['intent_id'], 'confirmed', tx_hash=tx_hash)
    append_audit_event(
        'onchain_reconciled',
        'system',
        trade_id,
        details={'intent_id': intent.get('intent_id', ''), 'tx_hash': tx_hash, 'action': action}
    )

async def onchain_reconciler_async():
    while True:
        try:
            intents = STORAGE_DB.list_onchain_intents(statuses=['prepared', 'submitted'], limit=200)
            now_ms = int(time.time() * 1000)
            for intent in intents:
                intent_id = intent.get('intent_id', '')
                status = intent.get('status', '')
                expires_at = int(intent.get('expires_at', 0) or 0)
                if expires_at and now_ms > expires_at and status == 'prepared':
                    STORAGE_DB.update_onchain_intent_status(intent_id, 'expired', tx_hash=intent.get('tx_hash'))
                    continue
                if status != 'submitted':
                    continue
                tx_hash = (intent.get('tx_hash') or '').strip().lower()
                if not tx_hash:
                    continue
                trade = STORAGE_DB.get_trade(intent.get('trade_id', ''))
                if not trade:
                    STORAGE_DB.update_onchain_intent_status(intent_id, 'failed', tx_hash=tx_hash)
                    continue
                try:
                    onchain = OTC_ESCROW.verify_submitted_action(
                        tx_hash=tx_hash,
                        trade=trade,
                        action=intent.get('action', ''),
                        escrow_trade_ref=trade.get('escrow_trade_ref')
                    )
                    _apply_verified_action_from_intent(intent, trade, onchain)
                except Exception as e:
                    code = str(e)
                    if code in ('tx_not_found', 'tx_not_confirmed'):
                        continue
                    STORAGE_DB.update_onchain_intent_status(intent_id, 'failed', tx_hash=tx_hash)
                    append_audit_event(
                        'onchain_reconcile_failed',
                        'system',
                        trade.get('trade_id', ''),
                        details={'intent_id': intent_id, 'error': code, 'tx_hash': tx_hash}
                    )
        except Exception as e:
            log_event('WARN', 'onchain_reconcile_error', error=str(e))
        await asyncio.sleep(max(5, ESCROW_RECONCILE_INTERVAL_SECONDS))

async def swap_timeout_sweeper_async():
    while True:
        try:
            active = STORAGE_DB.list_active_swaps(limit=200)
            for swap in active:
                swap_id = swap.get('swap_id', '')
                if not swap_id:
                    continue
                _refresh_swap_timeout_state(swap_id)
        except Exception as e:
            log_event('WARN', 'swap_timeout_sweep_error', error=str(e))
        await asyncio.sleep(max(1, SWAP_TIMEOUT_SWEEP_INTERVAL_SECONDS))

# ===== NETWORKING: TCP SERVER =====
async def start_p2p_server():
    """Async TCP server to receive requests from other nodes"""
    global NODE_PORT
    ensure_storage()
    ssl_ctx = None
    if P2P_TLS_ENABLED:
        if not P2P_TLS_CERT_PATH or not P2P_TLS_KEY_PATH:
            raise RuntimeError('[P2P] TLS enabled but cert/key not configured.')
        if P2P_MTLS_REQUIRED and not P2P_MTLS_CA_PATH:
            raise RuntimeError('[P2P] mTLS required but CA not configured.')
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(P2P_TLS_CERT_PATH, P2P_TLS_KEY_PATH)
        if P2P_MTLS_CA_PATH:
            ssl_ctx.load_verify_locations(P2P_MTLS_CA_PATH)
            ssl_ctx.verify_mode = ssl.CERT_REQUIRED

    server = None
    if LOCAL_TEST_MODE:
        # In local tests, auto-pick a free port if default is already in use.
        scan = max(1, LOCAL_TEST_PORT_SCAN_SIZE)
        for candidate_port in range(NODE_PORT, NODE_PORT + scan + 1):
            try:
                server = await asyncio.start_server(handle_client_async, host='', port=candidate_port, ssl=ssl_ctx)
                if candidate_port != NODE_PORT:
                    print(f'[LOCAL-TEST] P2P port {NODE_PORT} in use, switched to {candidate_port}')
                    NODE_PORT = candidate_port
                break
            except OSError:
                continue
        if server is None:
            raise RuntimeError('[P2P] Failed to bind any local-test port')
    else:
        server = await asyncio.start_server(handle_client_async, host='', port=NODE_PORT, ssl=ssl_ctx)

    log_event('INFO', 'p2p_listen', port=NODE_PORT, tls=P2P_TLS_ENABLED)
    if LOCAL_TEST_MODE:
        local_test_registry_touch()
    async with server:
        await server.serve_forever()

async def handle_client_async(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handle incoming P2P request (async)"""
    try:
        metric_inc('p2p_messages_total')
        if P2P_TLS_ENABLED and P2P_MTLS_CA_PATH and P2P_MTLS_ALLOWED_CNS:
            try:
                ssl_obj = writer.get_extra_info('ssl_object')
                cert = ssl_obj.getpeercert() if ssl_obj else None
                subject = cert.get('subject', []) if cert else []
                cn = ''
                for attrs in subject:
                    for k, v in attrs:
                        if k == 'commonName':
                            cn = v
                            break
                if not cn or cn not in P2P_MTLS_ALLOWED_CNS:
                    writer.write(json.dumps({'status': 'FORBIDDEN'}).encode())
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return
            except Exception:
                writer.write(json.dumps({'status': 'FORBIDDEN'}).encode())
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return
        data = await reader.read(BUFFER_SIZE)
        msg = json.loads(data.decode())
        if PYDANTIC_AVAILABLE:
            try:
                if msg.get('cmd') == CMD_STORE_SHARD:
                    msg = P2PStoreShard.model_validate(msg).model_dump()
                elif msg.get('cmd') == CMD_STORE_MANIFEST:
                    msg = P2PStoreManifest.model_validate(msg).model_dump()
                elif msg.get('cmd') == CMD_FETCH_SHARD:
                    msg = P2PFetchShard.model_validate(msg).model_dump()
                elif msg.get('cmd') == CMD_FETCH_MANIFEST:
                    msg = P2PFetchManifest.model_validate(msg).model_dump()
                elif msg.get('cmd') == CMD_HEALTH_CHECK:
                    msg = P2PHealth.model_validate(msg).model_dump()
                elif msg.get('cmd') == CMD_HANDSHAKE:
                    msg = P2PHandshake.model_validate(msg).model_dump()
            except ValidationError:
                writer.write(json.dumps({'status': 'BAD_REQUEST'}).encode())
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return
        cmd = msg.get('cmd')
        
        if cmd == CMD_STORE_SHARD:
            shard_name = msg['shard_name']
            shard_data = msg['shard_data']
            shard_dict = msg.get('shard_dict')
            signature = msg.get('signature', '')
            sender_id = msg.get('sender_id', '')
            relay_meta = {
                'destination': msg.get('destination', ''),
                'data_region': msg.get('data_region', ''),
                'relay_hops': msg.get('relay_hops', 0),
                'received_at': int(time.time())
            }
            instruction_id = msg.get('instruction_id', shard_name.split('_shard', 1)[0] if '_shard' in shard_name else '')
            if SHARD_SIGNATURE_REQUIRED:
                if not verify_shard_signature(sender_id, shard_name, shard_data, instruction_id, signature):
                    writer.write(json.dumps({'status': 'FORBIDDEN'}).encode())
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return
            
            store_shard_record(shard_name, shard_data, shard_dict, relay_meta, signature, sender_id)
            if BLIND_RELAY_ENABLED and not is_destination_node(relay_meta.get('destination', '')) and relay_meta.get('relay_hops', 0) < MAX_RELAY_HOPS:
                await RELAY_QUEUE.put({
                    'shard_name': shard_name,
                    'shard_data': shard_data,
                    'shard_dict': shard_dict,
                    'destination': relay_meta.get('destination', ''),
                    'data_region': relay_meta.get('data_region', ''),
                    'relay_hops': relay_meta.get('relay_hops', 0),
                    'signature': signature,
                    'sender_id': sender_id
                })
            writer.write(b'OK')
            await writer.drain()
        
        elif cmd == CMD_STORE_MANIFEST:
            instruction_id = msg.get('instruction_id')
            manifest = msg.get('manifest')
            if instruction_id and manifest:
                store_manifest_record(instruction_id, manifest)
                writer.write(b'OK')
                await writer.drain()
                try:
                    dest = manifest.get('destination', '')
                    if dest and is_destination_node(dest):
                        asyncio.create_task(collect_shards_dynamically_async(instruction_id, 10, 2.0))
                except Exception:
                    pass
            else:
                writer.write(json.dumps({'status': 'BAD_REQUEST'}).encode())
                await writer.drain()
            
        elif cmd == CMD_FETCH_SHARD:
            shard_name = msg['shard_name']
            stored = get_shard_record(shard_name)
            if stored:
                shard_data = stored.get('data')
                if stored.get('index') is not None and stored.get('share'):
                    response = json.dumps({'status': 'OK', 'shard_data': shard_data,
                                          'index': stored['index'], 'share': stored['share'],
                                          'signature': stored.get('signature', ''), 'sender_id': stored.get('sender_id', '')})
                else:
                    response = json.dumps({'status': 'OK', 'shard_data': shard_data,
                                           'signature': stored.get('signature', ''), 'sender_id': stored.get('sender_id', '')})
                writer.write(response.encode())
                await writer.drain()
            else:
                writer.write(json.dumps({'status': 'NOT_FOUND'}).encode())
                await writer.drain()
        
        elif cmd == CMD_FETCH_MANIFEST:
            instruction_id = msg.get('instruction_id')
            if instruction_id:
                manifest = get_manifest_record(instruction_id)
                if manifest:
                    response = json.dumps({'status': 'OK', 'manifest': manifest})
                    writer.write(response.encode())
                    await writer.drain()
                else:
                    writer.write(json.dumps({'status': 'NOT_FOUND'}).encode())
                    await writer.drain()
            else:
                writer.write(json.dumps({'status': 'NOT_FOUND'}).encode())
                await writer.drain()
        
        elif cmd == CMD_HANDSHAKE:
            try:
                remote_node_id = msg.get('node_id', '')
                if remote_node_id and remote_node_id != node_id:
                    with neighbors_lock:
                        neighbors[remote_node_id] = {
                            'ip': writer.get_extra_info('peername')[0] if writer.get_extra_info('peername') else '',
                            'node_port': msg.get('node_port', NODE_PORT),
                            'capabilities': msg.get('capabilities', []),
                            'version': msg.get('version', '0.0'),
                            'transport_mode': msg.get('transport_mode', 'ON_GRID'),
                            'region': msg.get('region', ''),
                            'country_code': msg.get('country_code', ''),
                            'served_destinations': msg.get('served_destinations', []),
                            'last_seen': time.strftime('%Y-%m-%d %H:%M:%S'),
                            'last_seen_ts': time.time(),
                            'signing_pub': msg.get('node_signing_pub', '')
                        }
                writer.write(b'OK')
                await writer.drain()
            except Exception:
                writer.write(json.dumps({'status': 'BAD_REQUEST'}).encode())
                await writer.drain()
                
        elif cmd == CMD_HEALTH_CHECK:
            response = json.dumps({
                'status': 'OK',
                'node_id': node_id,
                'version': APP_VERSION,
                'domain': 'darkpool_p2p_otc',
                'uptime': int(time.time())
            })
            writer.write(response.encode())
            await writer.drain()
            
        else:
            writer.write(json.dumps({'status': 'UNKNOWN_CMD'}).encode())
            await writer.drain()
            
    except Exception as e:
        metric_inc('p2p_errors_total')
        print(f'[P2P] Error handling client: {e}')
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def send_to_node_async(ip: str, msg: Dict, port: int = None) -> Optional[bytes]:
    """Send request to another node (async)"""
    if port is None:
        port = NODE_PORT
    ssl_ctx = None
    if P2P_TLS_ENABLED:
        if P2P_MTLS_REQUIRED and (not P2P_TLS_CERT_PATH or not P2P_TLS_KEY_PATH):
            raise RuntimeError('[P2P] mTLS required but client cert/key not configured.')
        ssl_ctx = ssl.create_default_context(cafile=P2P_MTLS_CA_PATH) if P2P_MTLS_CA_PATH else ssl.create_default_context()
        ssl_ctx.check_hostname = False
        if P2P_TLS_CERT_PATH and P2P_TLS_KEY_PATH:
            ssl_ctx.load_cert_chain(P2P_TLS_CERT_PATH, P2P_TLS_KEY_PATH)
        if not P2P_MTLS_CA_PATH:
            ssl_ctx.verify_mode = ssl.CERT_NONE
    for attempt in range(1, P2P_RETRIES + 1):
        try:
            reader, writer = await asyncio.open_connection(ip, port, ssl=ssl_ctx)
            writer.write(json.dumps(msg).encode())
            await writer.drain()
            data = await reader.read(BUFFER_SIZE)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return data
        except Exception as e:
            metric_inc('p2p_errors_total')
            if attempt >= P2P_RETRIES:
                print(f'[P2P] Error sending to {ip}:{port}: {e}')
                return None
            await asyncio.sleep(P2P_BACKOFF_BASE * (2 ** (attempt - 1)))

def send_to_node(ip: str, msg: Dict, port: int = None) -> Optional[bytes]:
    return run_async(send_to_node_async(ip, msg, port))

# ===== SHUTDOWN & MIGRATION =====
def migrate_shards_on_shutdown():
    """Transfer local shards to other nodes before shutdown"""
    print("[SHUTDOWN] Migrating local shards...")
    ensure_storage()
    
    local_shards = [
        f for f in list_shards() 
        if '_shard' in f
    ]
    
    neighbor_list = [n for n in neighbors.values() if n['ip'] != '127.0.0.1']
    
    if not neighbor_list:
        print("[SHUTDOWN] No neighbors available. Data at risk!")
        return
    
    for shard_file in local_shards:
        try:
            stored = get_shard_record(shard_file)
            if not stored:
                continue
            shard_data = stored.get('data', '')
            shard_dict = {'index': stored['index'], 'share': stored['share']} if stored.get('index') is not None and stored.get('share') else None
            
            relay_meta = {
                'destination': stored.get('destination', ''),
                'data_region': stored.get('data_region', ''),
                'relay_hops': stored.get('relay_hops', 0)
            }
            success = 0
            for n in neighbor_list[:3]:  # Try top 3 neighbors
                msg = {'cmd': CMD_STORE_SHARD, 'shard_name': shard_file, 'shard_data': shard_data, **relay_meta}
                if shard_dict:
                    msg['shard_dict'] = shard_dict
                if stored.get('signature'):
                    msg['signature'] = stored.get('signature')
                if stored.get('sender_id'):
                    msg['sender_id'] = stored.get('sender_id')
                resp = send_to_node(n['ip'], msg, port=n.get('node_port', NODE_PORT))
                if resp and resp == b'OK':
                    success += 1
            
            if success:
                print(f'[SHUTDOWN] [OK] Migrated: {shard_file} -> {success} nodes')
        except Exception as e:
            print(f'[SHUTDOWN] [X] Migration failed for {shard_file}: {e}')

def handle_shutdown(signum, frame):
    """Graceful shutdown handler"""
    migrate_shards_on_shutdown()
    local_test_registry_cleanup()
    try:
        STORAGE_DB.close()
    except Exception:
        pass
    print('[SHUTDOWN] Node stopped.')
    raise SystemExit(0)

# ===== OTC CLI OPERATIONS =====
def _cli_otc_client(client_id: str) -> Dict[str, Any]:
    return {'client_id': client_id, 'roles': ['admin'], 'scopes': ['*'], 'claims': {}}

def _cli_auto_bind_wallet(client_id: str, wallet: str):
    wallet_norm = _normalize_wallet(wallet)
    if not wallet_norm:
        return
    if WALLET_BINDING_REQUIRED and not STORAGE_DB.wallet_bound(client_id, wallet_norm, EVM_CHAIN_ID):
        STORAGE_DB.bind_wallet(client_id, wallet_norm, EVM_CHAIN_ID, status='active')
        print(f'[OTC] Wallet bound: {client_id} -> {wallet_norm}')

def _simple_cli_actor(actor_ctx: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    client_id = str((actor_ctx or {}).get('client_id', '')).strip()
    if not client_id:
        raise ValueError('client_id_required')
    return client_id, _cli_otc_client(client_id)

def _summarize_match_for_client(client_id: str, match_obj: Dict[str, Any]) -> Dict[str, Any]:
    sell_intent = STORAGE_DB.get_trade_intent(match_obj.get('intent_sell_id', '')) or {}
    buy_intent = STORAGE_DB.get_trade_intent(match_obj.get('intent_buy_id', '')) or {}
    seller_id = sell_intent.get('maker_client_id', '')
    buyer_id = buy_intent.get('maker_client_id', '')
    actor_side = 'seller' if client_id == seller_id else 'buyer' if client_id == buyer_id else 'observer'
    actor_intent = sell_intent if actor_side == 'seller' else buy_intent if actor_side == 'buyer' else {}
    counterparty_id = buyer_id if actor_side == 'seller' else seller_id if actor_side == 'buyer' else ''
    suggested_price = round((float(match_obj.get('overlap_min', 0)) + float(match_obj.get('overlap_max', 0))) / 2.0, 8)
    return {
        'match_id': match_obj.get('match_id', ''),
        'status': match_obj.get('status', ''),
        'you_side': actor_side.upper(),
        'counterparty_client_id': counterparty_id,
        'you_sell_asset': actor_intent.get('sell_asset', ''),
        'you_buy_asset': actor_intent.get('buy_asset', ''),
        'you_amount': actor_intent.get('amount', 0),
        'overlap_min': match_obj.get('overlap_min', 0),
        'overlap_max': match_obj.get('overlap_max', 0),
        'suggested_price': suggested_price,
    }

class SimpleCLIAdapter:
    """
    Adapter used by oneseam_simple_cli.py.
    Keeps simplified UX decoupled from core engine internals.
    """
    def post_order(self, payload: Dict[str, Any], actor_ctx: Dict[str, Any]) -> Dict[str, Any]:
        client_id, client_obj = _simple_cli_actor(actor_ctx)
        maker_wallet = _normalize_wallet(payload.get('maker_wallet', ''))
        _cli_auto_bind_wallet(client_id, maker_wallet)
        request_payload = {
            'maker_wallet': maker_wallet,
            'sell_asset': _normalize_asset(payload.get('sell_asset', '')),
            'buy_asset': _normalize_asset(payload.get('buy_asset', '')),
            'amount': float(payload.get('amount', 0)),
            'price_min': float(payload.get('price_min', 0)),
            'price_max': float(payload.get('price_max', 0)),
            'expiration': int(payload.get('expiration', int(time.time() * 1000) + 900000)),
            'wallet_nonce': str(payload.get('wallet_nonce', '')).strip(),
            'metadata': {'cli_source': 'simple_cli', 'operation': 'post_order'}
        }
        if WALLET_ATTESTATION_REQUIRED:
            prepared = prepare_trade_intent_signature(client_obj, request_payload)
            auto_signature = ''
            try:
                auto_signature = _sign_message_with_env_wallet(prepared['message'], maker_wallet)
            except Exception:
                auto_signature = ''
            if auto_signature:
                request_payload['wallet_signature'] = auto_signature
                print('[SIGN] wallet_signature applied from ONESEAM_WALLET_PRIVATE_KEY')
            else:
                print('[SIGN] Sign this message with your wallet:')
                print(prepared['message'])
                request_payload['wallet_signature'] = input('wallet_signature (0x...): ').strip()
        intent = create_trade_intent(client_obj, request_payload)
        append_audit_event(
            'cli_action',
            client_id,
            intent.get('intent_id', ''),
            details={'source': 'simple_cli', 'operation': 'post_order'}
        )
        return intent

    def list_matches(self, actor_ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        client_id, _ = _simple_cli_actor(actor_ctx)
        out: List[Dict[str, Any]] = []
        for match_obj in STORAGE_DB.list_matches_for_client(client_id, limit=100):
            item = _summarize_match_for_client(client_id, match_obj)
            swap = None
            for s in _list_swaps_for_client(client_id, limit=200):
                if s.get('match_id') == match_obj.get('match_id'):
                    swap = s
                    break
            if swap and swap.get('state') in (SWAP_STATE_COMPLETED, SWAP_STATE_REFUNDED, SWAP_STATE_FAILED):
                item['readiness'] = 'DONE'
            elif swap:
                item['readiness'] = 'IN_PROGRESS'
            else:
                item['readiness'] = 'READY'
            out.append(item)
        return out

    def accept_match_and_start(self, match_id: str, actor_ctx: Dict[str, Any]) -> Dict[str, Any]:
        client_id, client_obj = _simple_cli_actor(actor_ctx)
        opened = open_secure_session(client_obj, match_id)
        swap = start_htlc_coordination(client_obj, match_id)
        append_audit_event(
            'cli_action',
            client_id,
            match_id,
            details={'source': 'simple_cli', 'operation': 'accept_match_and_swap'}
        )
        return {'match_id': match_id, 'session': opened.get('session', {}), 'swap': swap}

    def list_orders(self, actor_ctx: Dict[str, Any]) -> Dict[str, Any]:
        client_id, _ = _simple_cli_actor(actor_ctx)
        intents = STORAGE_DB.list_trade_intents_for_client(client_id, limit=100)
        matches = STORAGE_DB.list_matches_for_client(client_id, limit=100)
        swaps = _list_swaps_for_client(client_id, limit=200)
        invoices = {}
        for swap in swaps:
            sid = swap.get('swap_id', '')
            if sid:
                invoices[sid] = STORAGE_DB.get_latest_fee_invoice(sid)
        return {'intents': intents, 'matches': matches, 'swaps': swaps, 'fee_invoices': invoices}

    def compute_next_actions(self, intent: Optional[Dict[str, Any]] = None,
                             match: Optional[Dict[str, Any]] = None,
                             session: Optional[Dict[str, Any]] = None,
                             swap: Optional[Dict[str, Any]] = None,
                             fee_invoice: Optional[Dict[str, Any]] = None,
                             actor_ctx: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        client_id = str((actor_ctx or {}).get('client_id', '')).strip()
        return compute_next_actions(intent=intent, match=match, session=session, swap=swap, fee_invoice=fee_invoice, client_id=client_id)

    def execute_next_action(self, action: Dict[str, Any], actor_ctx: Dict[str, Any], source: str = 'simple_cli') -> bool:
        client_id, _ = _simple_cli_actor(actor_ctx)
        return _execute_next_action(client_id, action, source=source)

    def node_status(self):
        print_status()

def run_simple_cli_menu():
    try:
        from oneseam_simple_cli import run_simple_cli
    except Exception as e:
        print(f'[CLI] Failed to load simple CLI module, falling back to advanced mode: {e}')
        cli_menu_advanced()
        return
    adapter = SimpleCLIAdapter()
    run_simple_cli(adapter)

def cli_create_rfq():
    print('\n' + '='*47)
    print('  CREATE RFQ')
    print('='*47)
    maker_client_id = input('Maker client ID: ').strip()
    maker_wallet = input('Maker wallet (0x...): ').strip()
    maker_side = (input('Maker side (buy/sell) [sell]: ').strip().lower() or 'sell')
    base_asset = input('Base asset (e.g. BTC): ').strip().upper()
    quote_asset = input('Quote asset (e.g. USDT): ').strip().upper()
    base_amount = float(input('Base amount: ').strip())
    quote_amount = float(input('Quote amount: ').strip())
    taker_client_id = input('Taker client ID (optional): ').strip()
    expires_in_seconds = int(input('Expires in seconds [900]: ').strip() or '900')
    _cli_auto_bind_wallet(maker_client_id, maker_wallet)
    rfq = otc_create_rfq(_cli_otc_client(maker_client_id), {
        'maker_wallet': maker_wallet,
        'base_asset': base_asset,
        'quote_asset': quote_asset,
        'base_amount': base_amount,
        'quote_amount': quote_amount,
        'maker_side': maker_side,
        'taker_client_id': taker_client_id,
        'expires_in_seconds': expires_in_seconds
    })
    print(f'[OK] RFQ created: {rfq["rfq_id"]}')

def cli_accept_rfq():
    print('\n' + '='*47)
    print('  ACCEPT RFQ')
    print('='*47)
    rfq_id = input('RFQ ID: ').strip()
    taker_client_id = input('Taker client ID: ').strip()
    taker_wallet = input('Taker wallet (0x...): ').strip()
    _cli_auto_bind_wallet(taker_client_id, taker_wallet)
    trade = otc_accept_rfq(_cli_otc_client(taker_client_id), rfq_id, taker_wallet)
    print(f'[OK] Trade created from RFQ: {trade["trade_id"]}')

def cli_create_trade():
    print('\n' + '='*47)
    print('  CREATE DIRECT TRADE')
    print('='*47)
    actor = input('Actor client ID (buyer/seller/admin): ').strip()
    buyer_client_id = input('Buyer client ID: ').strip()
    buyer_wallet = input('Buyer wallet (0x...): ').strip()
    seller_client_id = input('Seller client ID: ').strip()
    seller_wallet = input('Seller wallet (0x...): ').strip()
    base_asset = input('Base asset: ').strip().upper()
    quote_asset = input('Quote asset: ').strip().upper()
    base_amount = float(input('Base amount: ').strip())
    quote_amount = float(input('Quote amount: ').strip())
    _cli_auto_bind_wallet(buyer_client_id, buyer_wallet)
    _cli_auto_bind_wallet(seller_client_id, seller_wallet)
    trade = otc_create_trade_direct(_cli_otc_client(actor), {
        'buyer_client_id': buyer_client_id,
        'buyer_wallet': buyer_wallet,
        'seller_client_id': seller_client_id,
        'seller_wallet': seller_wallet,
        'base_asset': base_asset,
        'quote_asset': quote_asset,
        'base_amount': base_amount,
        'quote_amount': quote_amount
    })
    print(f'[OK] Direct trade created: {trade["trade_id"]}')

def cli_create_escrow():
    print('\n' + '='*47)
    print('  CREATE ESCROW')
    print('='*47)
    trade_id = input('Trade ID: ').strip()
    actor = input('Actor client ID: ').strip()
    tx_hash = input('Escrow tx_hash (0x...): ').strip()
    escrow_trade_ref = input('Escrow trade ref (optional): ').strip() or None
    trade = otc_create_escrow(_cli_otc_client(actor), trade_id, tx_hash=tx_hash, escrow_trade_ref=escrow_trade_ref)
    print(f'[OK] Escrow created: trade={trade_id}')

def cli_settle_trade():
    print('\n' + '='*47)
    print('  SETTLE TRADE')
    print('='*47)
    trade_id = input('Trade ID: ').strip()
    actor = input('Actor client ID: ').strip()
    tx_hash = input('Settlement tx_hash (0x...): ').strip()
    trade = otc_settle_trade(_cli_otc_client(actor), trade_id, tx_hash=tx_hash)
    print(f'[OK] Trade settled: trade={trade_id}')

def cli_refund_trade():
    print('\n' + '='*47)
    print('  REFUND TRADE')
    print('='*47)
    trade_id = input('Trade ID: ').strip()
    actor = input('Actor client ID: ').strip()
    tx_hash = input('Refund tx_hash (0x...): ').strip()
    trade = otc_refund_trade(_cli_otc_client(actor), trade_id, tx_hash=tx_hash)
    print(f'[OK] Trade refunded: trade={trade_id}')

def monitor_otc_trades():
    print('\n' + '='*47)
    print('  OTC TRADES')
    print('='*47)
    client_filter = input('Client ID filter (optional): ').strip() or None
    trades = STORAGE_DB.list_trades(client_filter)
    if not trades:
        print('No OTC trades found.')
        return
    for trade in trades[:50]:
        print(f"- {trade['trade_id']} | {trade['base_asset']}/{trade['quote_asset']} | {trade['status']} | "
              f"{trade['buyer_client_id']} <-> {trade['seller_client_id']} | fee={trade['fee_amount']} {trade['fee_asset']}")

def audit_otc():
    print('\n' + '='*47)
    print('  OTC AUDIT')
    print('='*47)
    events = STORAGE_DB.list_audit_events()
    if not events:
        print('No audit events.')
        return
    interesting = {'rfq_created', 'rfq_accepted', 'trade_created', 'escrow_created', 'trade_settled', 'trade_refunded', 'wallet_bound'}
    count = 0
    for event in reversed(events):
        if event.get('event_type') not in interesting:
            continue
        count += 1
        print(f"- {event.get('event_type')} | actor={event.get('actor')} | instruction_id={event.get('instruction_id')} | ts={event.get('timestamp')}")
        if count >= 100:
            break
    if count == 0:
        print('No OTC-specific audit events.')

def cli_create_trade_intent():
    print('\n' + '=' * 47)
    print('  CREATE TRADE INTENT')
    print('=' * 47)
    maker_client_id = input('Maker client ID: ').strip()
    maker_wallet = input('Maker wallet (0x...): ').strip()
    sell_asset = input('Sell asset (e.g. BTC): ').strip().upper()
    buy_asset = input('Buy asset (e.g. USDT): ').strip().upper()
    amount = float(input('Amount: ').strip())
    price_min = float(input('Price min: ').strip())
    price_max = float(input('Price max: ').strip())
    expires_sec = int(input('Expiration seconds from now [900]: ').strip() or '900')
    wallet_nonce = input('Wallet nonce (optional): ').strip()
    _cli_auto_bind_wallet(maker_client_id, maker_wallet)
    client_obj = _cli_otc_client(maker_client_id)
    payload = {
        'maker_wallet': maker_wallet,
        'sell_asset': sell_asset,
        'buy_asset': buy_asset,
        'amount': amount,
        'price_min': price_min,
        'price_max': price_max,
        'expiration': int(time.time() * 1000) + expires_sec * 1000,
        'wallet_nonce': wallet_nonce
    }
    if WALLET_ATTESTATION_REQUIRED:
        prepared = prepare_trade_intent_signature(client_obj, payload)
        auto_signature = ''
        try:
            auto_signature = _sign_message_with_env_wallet(prepared['message'], maker_wallet)
        except Exception as e:
            print(f"[WARN] Auto-sign unavailable: {e}")
        if auto_signature:
            payload['wallet_signature'] = auto_signature
            print('[SIGN] wallet_signature applied from ONESEAM_WALLET_PRIVATE_KEY')
        else:
            print('[SIGN] Sign this message with your wallet:')
            print(prepared['message'])
            payload['wallet_signature'] = input('wallet_signature (0x...): ').strip()
    intent = create_trade_intent(client_obj, payload)
    print(f"[OK] Intent created: {intent['intent_id']}")
    if intent.get('matches_detected'):
        print(f"[MATCH] Candidates: {', '.join(intent.get('matches_detected', []))}")

def cli_monitor_intents():
    print('\n' + '=' * 47)
    print('  MONITOR INTENTS')
    print('=' * 47)
    client_id = input('Client ID: ').strip()
    intents = STORAGE_DB.list_trade_intents_for_client(client_id, limit=100)
    if not intents:
        print('No intents found.')
        return
    for item in intents:
        print(f"- {item['intent_id']} | {item['sell_asset']}->{item['buy_asset']} | {item['amount']} | "
              f"{item['price_min']}-{item['price_max']} | {item['status']}")

def cli_view_matches():
    print('\n' + '=' * 47)
    print('  VIEW MATCHES')
    print('=' * 47)
    client_id = input('Client ID: ').strip()
    matches = STORAGE_DB.list_matches_for_client(client_id, limit=100)
    if not matches:
        print('No matches found.')
        return
    for m in matches:
        print(f"- {m['match_id']} | intents={m['intent_sell_id']} x {m['intent_buy_id']} | "
              f"overlap={m['overlap_min']}-{m['overlap_max']} | status={m['status']}")

def cli_open_session():
    print('\n' + '=' * 47)
    print('  OPEN SECURE SESSION')
    print('=' * 47)
    client_id = input('Actor client ID: ').strip()
    match_id = input('Match ID: ').strip()
    result = open_secure_session(_cli_otc_client(client_id), match_id)
    print(f"[OK] Session: {result['session']['session_id']} | expires={result['session']['expires_at']}")
    print(f"[OK] Swap initialized: {result['swap']['swap_id']} | state={result['swap']['state']}")

def cli_start_htlc_coordination():
    print('\n' + '=' * 47)
    print('  START HTLC COORDINATION')
    print('=' * 47)
    client_id = input('Actor client ID: ').strip()
    match_id = input('Match ID: ').strip()
    swap = start_htlc_coordination(_cli_otc_client(client_id), match_id)
    print(f"[OK] Swap: {swap['swap_id']} | state={swap['state']}")
    print(f"Secret hash: {swap.get('secret_hash', '')}")
    timeouts = swap.get('timeouts', {})
    print(f"lock_a_timeout={timeouts.get('lock_a_timeout')} | lock_b_timeout={timeouts.get('lock_b_timeout')}")

def cli_submit_htlc_proof():
    print('\n' + '=' * 47)
    print('  SUBMIT HTLC PROOF')
    print('=' * 47)
    client_id = input('Actor client ID: ').strip()
    swap_id = input('Swap ID: ').strip()
    proof_type = input('Proof type (lock_a/lock_b/claim_a/claim_b/refund_a/refund_b): ').strip()
    tx_hash = input('Tx hash: ').strip()
    confirmations = int(input('Confirmations: ').strip() or '0')
    secret = input('Secret (optional): ').strip() or None
    signer_wallet = input('Signer wallet (optional): ').strip()
    wallet_nonce = input('Wallet nonce (optional): ').strip()
    client_obj = _cli_otc_client(client_id)
    payload = {
        'proof_type': proof_type,
        'tx_hash': tx_hash,
        'confirmations': confirmations,
        'secret': secret,
        'signer_wallet': signer_wallet or None,
        'wallet_nonce': wallet_nonce,
        'metadata': {}
    }
    if PROOF_WALLET_ATTESTATION_REQUIRED:
        swap_obj = get_swap_status(client_obj, swap_id)
        prepared = prepare_htlc_proof_signature(client_obj, swap_obj, payload, _normalize_wallet(signer_wallet or _expected_wallet_for_proof(swap_obj, proof_type)))
        auto_signature = ''
        try:
            auto_signature = _sign_message_with_env_wallet(prepared['message'], prepared.get('wallet', ''))
        except Exception as e:
            print(f"[WARN] Auto-sign unavailable: {e}")
        if auto_signature:
            payload['wallet_signature'] = auto_signature
            print('[SIGN] wallet_signature applied from ONESEAM_WALLET_PRIVATE_KEY')
        else:
            print('[SIGN] Sign this HTLC proof message with your wallet:')
            print(prepared['message'])
            payload['wallet_signature'] = input('wallet_signature (0x...): ').strip()
    result = submit_htlc_proof(client_obj, swap_id, payload)
    print(f"[OK] Swap state: {result['swap']['state']}")
    if result.get('fee_invoice'):
        print(f"[FEE] Invoice: {result['fee_invoice'].get('invoice_ref')} amount={result['fee_invoice'].get('fee_amount')}")

def cli_monitor_swap():
    print('\n' + '=' * 47)
    print('  MONITOR SWAP')
    print('=' * 47)
    client_id = input('Actor client ID: ').strip()
    swap_id = input('Swap ID: ').strip()
    swap = get_swap_status(_cli_otc_client(client_id), swap_id)
    print(f"Swap: {swap['swap_id']} | state={swap['state']} | secret_hash={swap.get('secret_hash', '')}")
    print(f"HTLC A: {swap.get('htlc_a', {})}")
    print(f"HTLC B: {swap.get('htlc_b', {})}")
    print(f"Proofs: {len(swap.get('proofs', []))}")
    if swap.get('fee_invoice'):
        invoice = swap['fee_invoice']
        print(f"Fee invoice: {invoice.get('invoice_ref')} | status={invoice.get('payment_status')} | amount={invoice.get('fee_amount')}")

def cli_fee_invoice_status():
    print('\n' + '=' * 47)
    print('  FEE INVOICE STATUS')
    print('=' * 47)
    client_id = input('Actor client ID: ').strip()
    swap_id = input('Swap ID: ').strip()
    invoice = issue_fee_invoice(_cli_otc_client(client_id), swap_id)
    print(f"Invoice: {invoice.get('invoice_ref')} | status={invoice.get('payment_status')} | amount={invoice.get('fee_amount')}")
    mark_paid = input('Mark as paid now? (y/n): ').strip().lower() == 'y'
    if mark_paid:
        payment_ref = input('Payment reference: ').strip()
        updated = confirm_fee_payment(_cli_otc_client(client_id), swap_id, payment_ref)
        print(f"[OK] Updated status: {updated.get('payment_status')}")

def audit_darkpool():
    print('\n' + '=' * 47)
    print('  DARKPOOL AUDIT')
    print('=' * 47)
    events = STORAGE_DB.list_audit_events()
    interesting = {
        'intent_created', 'intent_sharded', 'match_detected',
        'session_opened', 'swap_init', 'htlc_lock_verified', 'secret_revealed',
        'swap_completed', 'fee_invoiced', 'fee_paid'
    }
    count = 0
    for event in reversed(events):
        if event.get('event_type') not in interesting:
            continue
        count += 1
        print(f"- {event.get('event_type')} | actor={event.get('actor')} | id={event.get('instruction_id')} | ts={event.get('timestamp')}")
        if count >= 100:
            break
    if count == 0:
        print('No darkpool events found.')

def _action_def(code: str, label: str, priority: int, context: Optional[Dict[str, Any]] = None,
                risky: bool = False, auto: bool = True) -> Dict[str, Any]:
    return {
        'code': code,
        'label': label,
        'priority': int(priority),
        'context': context or {},
        'risky': bool(risky),
        'auto': bool(auto),
    }

def compute_next_actions(intent: Optional[Dict[str, Any]] = None,
                         match: Optional[Dict[str, Any]] = None,
                         session: Optional[Dict[str, Any]] = None,
                         swap: Optional[Dict[str, Any]] = None,
                         fee_invoice: Optional[Dict[str, Any]] = None,
                         client_id: str = '') -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    actor = (client_id or '').strip()

    if intent:
        status = str(intent.get('status', ''))
        if status == INTENT_STATUS_OPEN:
            actions.append(_action_def(
                'VIEW_INTENT_STATUS',
                'Monitor open intent',
                90,
                {'intent_id': intent.get('intent_id', '')},
                risky=False,
                auto=False
            ))
        wallet_att = (intent.get('metadata') or {}).get('wallet_attestation', {})
        if wallet_att and not wallet_att.get('verified'):
            actions.append(_action_def(
                'SIGN_INTENT',
                'Sign pending intent',
                1,
                {'intent_id': intent.get('intent_id', '')},
                risky=False,
                auto=False
            ))

    if match and not session:
        actions.append(_action_def(
            'OPEN_SESSION',
            'Open secure session',
            20,
            {'match_id': match.get('match_id', '')},
            risky=False,
            auto=True
        ))

    if session and not swap:
        actions.append(_action_def(
            'START_SWAP',
            'Start HTLC coordination',
            25,
            {'match_id': session.get('match_id', '')},
            risky=False,
            auto=True
        ))

    if swap:
        swap_id = swap.get('swap_id', '')
        state = str(swap.get('state', ''))
        metadata = swap.get('metadata') or {}
        peer_a = str(metadata.get('peer_a', '')).strip()
        peer_b = str(metadata.get('peer_b', '')).strip()

        def allowed(target_peer: str) -> bool:
            return not actor or not target_peer or actor == target_peer

        if state in (SWAP_STATE_INIT, SWAP_STATE_WAIT_LOCK_A):
            if allowed(peer_a):
                actions.append(_action_def('SEND_LOCK_A', 'Submit lock_a proof', 10, {'swap_id': swap_id, 'proof_type': 'lock_a'}))
        if state == SWAP_STATE_WAIT_LOCK_B:
            if allowed(peer_b):
                actions.append(_action_def('SEND_LOCK_B', 'Submit lock_b proof', 11, {'swap_id': swap_id, 'proof_type': 'lock_b'}))
            if allowed(peer_a):
                actions.append(_action_def('REFUND_A', 'Execute refund_a', 80, {'swap_id': swap_id, 'proof_type': 'refund_a'}, risky=True, auto=False))
            if allowed(peer_b):
                actions.append(_action_def('REFUND_B', 'Execute refund_b', 81, {'swap_id': swap_id, 'proof_type': 'refund_b'}, risky=True, auto=False))
        if state == SWAP_STATE_READY_CLAIM:
            if allowed(peer_a):
                actions.append(_action_def('SEND_CLAIM_A', 'Submit claim_a proof', 12, {'swap_id': swap_id, 'proof_type': 'claim_a'}, risky=True, auto=False))
            if allowed(peer_b):
                actions.append(_action_def('SEND_CLAIM_B', 'Submit claim_b proof', 13, {'swap_id': swap_id, 'proof_type': 'claim_b'}, risky=True, auto=False))
            if allowed(peer_a):
                actions.append(_action_def('REFUND_A', 'Execute refund_a', 82, {'swap_id': swap_id, 'proof_type': 'refund_a'}, risky=True, auto=False))
            if allowed(peer_b):
                actions.append(_action_def('REFUND_B', 'Execute refund_b', 83, {'swap_id': swap_id, 'proof_type': 'refund_b'}, risky=True, auto=False))
        if state == SWAP_STATE_CLAIMED_A and allowed(peer_b):
            actions.append(_action_def('SEND_CLAIM_B', 'Submit claim_b proof', 14, {'swap_id': swap_id, 'proof_type': 'claim_b'}, risky=True, auto=False))
        if state == SWAP_STATE_CLAIMED_B and allowed(peer_a):
            actions.append(_action_def('SEND_CLAIM_A', 'Submit claim_a proof', 14, {'swap_id': swap_id, 'proof_type': 'claim_a'}, risky=True, auto=False))
        if state == SWAP_STATE_COMPLETED:
            if not fee_invoice:
                actions.append(_action_def('ISSUE_FEE', 'Issue fee invoice', 30, {'swap_id': swap_id}, risky=False, auto=True))
            elif str(fee_invoice.get('payment_status', 'pending')).lower() != 'paid':
                actions.append(_action_def('CONFIRM_FEE', 'Confirm fee payment', 40, {'swap_id': swap_id}, risky=True, auto=False))

    actions.sort(key=lambda x: x['priority'])
    return actions

def render_trade_summary(intent: Optional[Dict[str, Any]] = None,
                         match: Optional[Dict[str, Any]] = None,
                         swap: Optional[Dict[str, Any]] = None,
                         fee_invoice: Optional[Dict[str, Any]] = None) -> str:
    parts: List[str] = []
    if intent:
        parts.append(
            f"intent={intent.get('intent_id','')} {intent.get('sell_asset','')}->{intent.get('buy_asset','')} "
            f"amount={intent.get('amount','')} status={intent.get('status','')}"
        )
    if match:
        parts.append(
            f"match={match.get('match_id','')} overlap={match.get('overlap_min','')}-{match.get('overlap_max','')} "
            f"status={match.get('status','')}"
        )
    if swap:
        parts.append(f"swap={swap.get('swap_id','')} state={swap.get('state','')}")
    if fee_invoice:
        parts.append(
            f"fee={fee_invoice.get('fee_amount','')} {fee_invoice.get('fee_asset','')} "
            f"status={fee_invoice.get('payment_status','pending')}"
        )
    return " | ".join(parts) if parts else "no trade context"

def _list_swaps_for_client(client_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    if not client_id:
        return []
    if STORAGE_DB.backend == 'sqlite':
        query = """
            SELECT s.swap_id
            FROM swap_coordination s
            JOIN matches m ON m.match_id = s.match_id
            JOIN trade_intents a ON a.intent_id = m.intent_sell_id
            JOIN trade_intents b ON b.intent_id = m.intent_buy_id
            WHERE a.maker_client_id=? OR b.maker_client_id=?
            ORDER BY s.updated_at DESC
            LIMIT ?
        """
    else:
        query = """
            SELECT s.swap_id
            FROM swap_coordination s
            JOIN matches m ON m.match_id = s.match_id
            JOIN trade_intents a ON a.intent_id = m.intent_sell_id
            JOIN trade_intents b ON b.intent_id = m.intent_buy_id
            WHERE a.maker_client_id=%s OR b.maker_client_id=%s
            ORDER BY s.updated_at DESC
            LIMIT %s
        """
    cur = STORAGE_DB._execute(query, (client_id, client_id, limit))
    rows = cur.fetchall() if cur else []
    out: List[Dict[str, Any]] = []
    for row in rows:
        swap = _refresh_swap_timeout_state(row[0]) or STORAGE_DB.get_swap(row[0])
        if swap:
            out.append(swap)
    return out

def _submit_htlc_proof_interactive(client_id: str, swap_id: str, proof_type: str, source: str) -> Optional[Dict[str, Any]]:
    print(f"\n[ACTION] {proof_type} | swap={swap_id}")
    tx_hash = input('Tx hash: ').strip()
    confirmations = int(input(f'Confirmations [{HTLC_MIN_CONFIRMATIONS}]: ').strip() or str(HTLC_MIN_CONFIRMATIONS))
    secret = None
    if proof_type.startswith('claim') or proof_type.startswith('refund'):
        secret = input('Secret (optional): ').strip() or None
    signer_wallet = input('Signer wallet (optional): ').strip()
    wallet_nonce = input('Wallet nonce (optional): ').strip()
    client_obj = _cli_otc_client(client_id)
    payload = {
        'proof_type': proof_type,
        'tx_hash': tx_hash,
        'confirmations': confirmations,
        'secret': secret,
        'signer_wallet': signer_wallet or None,
        'wallet_nonce': wallet_nonce,
        'metadata': {'cli_source': source, 'operation': proof_type}
    }
    if PROOF_WALLET_ATTESTATION_REQUIRED:
        swap_obj = get_swap_status(client_obj, swap_id)
        expected_wallet = _normalize_wallet(signer_wallet or _expected_wallet_for_proof(swap_obj, proof_type))
        prepared = prepare_htlc_proof_signature(client_obj, swap_obj, payload, expected_wallet)
        auto_signature = ''
        try:
            auto_signature = _sign_message_with_env_wallet(prepared['message'], prepared.get('wallet', ''))
        except Exception as e:
            print(f"[WARN] Auto-sign unavailable: {e}")
        if auto_signature:
            payload['wallet_signature'] = auto_signature
            print('[SIGN] wallet_signature applied from ONESEAM_WALLET_PRIVATE_KEY')
        else:
            print('[SIGN] Sign this HTLC proof message with your wallet:')
            print(prepared['message'])
            payload['wallet_signature'] = input('wallet_signature (0x...): ').strip()
    append_audit_event('cli_action', client_id, swap_id, details={'cli_source': source, 'operation': proof_type})
    return submit_htlc_proof(client_obj, swap_id, payload)

def _execute_next_action(client_id: str, action: Dict[str, Any], source: str) -> bool:
    code = str(action.get('code', '')).strip()
    ctx = action.get('context') or {}
    client_obj = _cli_otc_client(client_id)
    try:
        if code == 'OPEN_SESSION':
            match_id = ctx.get('match_id', '')
            append_audit_event('cli_action', client_id, match_id, details={'cli_source': source, 'operation': code})
            open_secure_session(client_obj, match_id)
            print(f"[OK] Session opened for match {match_id}")
            return True
        if code == 'START_SWAP':
            match_id = ctx.get('match_id', '')
            append_audit_event('cli_action', client_id, match_id, details={'cli_source': source, 'operation': code})
            swap = start_htlc_coordination(client_obj, match_id)
            print(f"[OK] Swap started: {swap.get('swap_id','')} state={swap.get('state','')}")
            return True
        if code.startswith('SEND_') or code.startswith('REFUND_'):
            swap_id = ctx.get('swap_id', '')
            proof_type = ctx.get('proof_type', '')
            if action.get('risky') and input(f"Confirm risky action {proof_type} on swap {swap_id}? (y/n): ").strip().lower() != 'y':
                return False
            result = _submit_htlc_proof_interactive(client_id, swap_id, proof_type, source=source)
            if result:
                print(f"[OK] Swap state: {result.get('swap', {}).get('state', '')}")
            return True
        if code == 'ISSUE_FEE':
            swap_id = ctx.get('swap_id', '')
            append_audit_event('cli_action', client_id, swap_id, details={'cli_source': source, 'operation': code})
            invoice = issue_fee_invoice(client_obj, swap_id)
            print(f"[FEE] Invoice: {invoice.get('invoice_ref','')} status={invoice.get('payment_status','')}")
            return True
        if code == 'CONFIRM_FEE':
            swap_id = ctx.get('swap_id', '')
            if input(f"Confirm fee payment for swap {swap_id}? (y/n): ").strip().lower() != 'y':
                return False
            payment_ref = input('Payment reference: ').strip()
            append_audit_event('cli_action', client_id, swap_id, details={'cli_source': source, 'operation': code})
            invoice = confirm_fee_payment(client_obj, swap_id, payment_ref)
            print(f"[FEE] Status: {invoice.get('payment_status','')}")
            return True
    except Exception as e:
        print(f"[X] Action failed ({code}): {e}")
    return False

def cli_trade_wizard():
    print('\n' + '=' * 47)
    print('  NEW TRADE (WIZARD)')
    print('=' * 47)
    maker_client_id = input('Maker client ID: ').strip()
    maker_wallet = input('Maker wallet (0x...): ').strip()
    sell_asset = input('Sell asset (e.g. BTC): ').strip().upper()
    buy_asset = input('Buy asset (e.g. USDT): ').strip().upper()
    amount = float(input('Amount: ').strip())
    price_min = float(input('Price min: ').strip())
    price_max = float(input('Price max: ').strip())
    expires_sec = int(input('Expiration seconds from now [900]: ').strip() or '900')
    wallet_nonce = input('Wallet nonce (optional): ').strip()
    _cli_auto_bind_wallet(maker_client_id, maker_wallet)
    client_obj = _cli_otc_client(maker_client_id)
    payload = {
        'maker_wallet': maker_wallet,
        'sell_asset': sell_asset,
        'buy_asset': buy_asset,
        'amount': amount,
        'price_min': price_min,
        'price_max': price_max,
        'expiration': int(time.time() * 1000) + expires_sec * 1000,
        'wallet_nonce': wallet_nonce
    }
    if WALLET_ATTESTATION_REQUIRED:
        prepared = prepare_trade_intent_signature(client_obj, payload)
        auto_signature = ''
        try:
            auto_signature = _sign_message_with_env_wallet(prepared['message'], maker_wallet)
        except Exception as e:
            print(f"[WARN] Auto-sign unavailable: {e}")
        if auto_signature:
            payload['wallet_signature'] = auto_signature
            print('[SIGN] wallet_signature applied from ONESEAM_WALLET_PRIVATE_KEY')
        else:
            print('[SIGN] Sign this message with your wallet:')
            print(prepared['message'])
            payload['wallet_signature'] = input('wallet_signature (0x...): ').strip()
    intent = create_trade_intent(client_obj, payload)
    append_audit_event('cli_action', maker_client_id, intent.get('intent_id', ''), details={'source': 'wizard', 'action': 'CREATE_INTENT'})
    print(f"[OK] Intent created: {intent['intent_id']}")
    if not intent.get('matches_detected'):
        print('[INFO] No immediate match. Use "Pending Actions" or "My Trades".')
        return
    print(f"[MATCH] Candidates: {', '.join(intent.get('matches_detected', []))}")
    selected_match = intent.get('matches_detected', [])[0]
    if len(intent.get('matches_detected', [])) > 1:
        chosen = input(f"Select match ID [{selected_match}]: ").strip()
        if chosen:
            selected_match = chosen
    if input(f"Open session for match {selected_match}? (y/n): ").strip().lower() != 'y':
        return
    opened = open_secure_session(client_obj, selected_match)
    swap = opened.get('swap') or {}
    print(f"[OK] Session opened, swap={swap.get('swap_id','')} state={swap.get('state','')}")
    if input('Start HTLC coordination now? (y/n): ').strip().lower() == 'y':
        swap = start_htlc_coordination(client_obj, selected_match)
    while True:
        swap = get_swap_status(client_obj, swap.get('swap_id', ''))
        invoice = STORAGE_DB.get_latest_fee_invoice(swap.get('swap_id', '')) if swap else None
        print('[SUMMARY]', render_trade_summary(intent=intent, match=STORAGE_DB.get_match(selected_match), swap=swap, fee_invoice=invoice))
        next_actions = compute_next_actions(intent=intent, match=STORAGE_DB.get_match(selected_match), session=opened.get('session'), swap=swap, fee_invoice=invoice, client_id=maker_client_id)
        if not next_actions:
            print('[INFO] No next actions.')
            return
        recommended = next_actions[0]
        print(f"[NEXT] Recommended: {recommended.get('label')} ({recommended.get('code')})")
        if recommended.get('auto') and not recommended.get('risky'):
            proceed = input('Execute recommended action now? (y/n): ').strip().lower() == 'y'
            if proceed:
                _execute_next_action(maker_client_id, recommended, source='wizard')
                continue
        print('Available actions:')
        for idx, act in enumerate(next_actions, start=1):
            mark = 'RISK' if act.get('risky') else 'SAFE'
            print(f"  {idx}. {act.get('label')} [{mark}]")
        print(f"  {len(next_actions)+1}. Finish")
        choice = input('Select option: ').strip()
        if choice == str(len(next_actions)+1):
            return
        try:
            selected = next_actions[int(choice)-1]
        except Exception:
            print('[!] Invalid option.')
            continue
        _execute_next_action(maker_client_id, selected, source='wizard')

def cli_commit_trade_intent():
    """
    Commit an intent into the network.
    This is the explicit 'commit' step: intent publication for matching.
    """
    print('\n' + '=' * 47)
    print('  COMMIT TRADE INTENT')
    print('=' * 47)
    maker_client_id = input('Maker client ID: ').strip()
    maker_wallet = input('Maker wallet (0x...): ').strip()
    sell_asset = input('Sell asset (e.g. BTC): ').strip().upper()
    buy_asset = input('Buy asset (e.g. USDT): ').strip().upper()
    amount = float(input('Amount: ').strip())
    price_min = float(input('Price min: ').strip())
    price_max = float(input('Price max: ').strip())
    expires_sec = int(input('Expiration seconds from now [900]: ').strip() or '900')
    wallet_nonce = input('Wallet nonce (optional): ').strip()
    _cli_auto_bind_wallet(maker_client_id, maker_wallet)
    client_obj = _cli_otc_client(maker_client_id)
    payload = {
        'maker_wallet': maker_wallet,
        'sell_asset': sell_asset,
        'buy_asset': buy_asset,
        'amount': amount,
        'price_min': price_min,
        'price_max': price_max,
        'expiration': int(time.time() * 1000) + expires_sec * 1000,
        'wallet_nonce': wallet_nonce
    }
    if WALLET_ATTESTATION_REQUIRED:
        prepared = prepare_trade_intent_signature(client_obj, payload)
        auto_signature = ''
        try:
            auto_signature = _sign_message_with_env_wallet(prepared['message'], maker_wallet)
        except Exception as e:
            print(f"[WARN] Auto-sign unavailable: {e}")
        if auto_signature:
            payload['wallet_signature'] = auto_signature
            print('[SIGN] wallet_signature applied from ONESEAM_WALLET_PRIVATE_KEY')
        else:
            print('[SIGN] Sign this message with your wallet:')
            print(prepared['message'])
            payload['wallet_signature'] = input('wallet_signature (0x...): ').strip()
    intent = create_trade_intent(client_obj, payload)
    append_audit_event('cli_action', maker_client_id, intent.get('intent_id', ''), details={'source': 'manual', 'action': 'COMMIT_INTENT'})
    print(f"[OK] Intent committed: {intent['intent_id']}")
    if intent.get('matches_detected'):
        print(f"[MATCH] Found: {', '.join(intent.get('matches_detected', []))}")
        print('[NEXT] Use option "Accept Trade (from Match)".')

def cli_accept_trade_from_match():
    """
    Accept a matched trade and move it to session/swap coordination.
    """
    print('\n' + '=' * 47)
    print('  ACCEPT TRADE (FROM MATCH)')
    print('=' * 47)
    client_id = input('Actor client ID: ').strip()
    matches = STORAGE_DB.list_matches_for_client(client_id, limit=100)
    if not matches:
        print('[INFO] No matches available for this client.')
        return
    for idx, match in enumerate(matches[:20], start=1):
        print(f"  {idx}. {match.get('match_id','')} | status={match.get('status','')} | "
              f"overlap={match.get('overlap_min','')}-{match.get('overlap_max','')}")
    raw = input('Select match number or enter match_id: ').strip()
    match_id = ''
    if raw.isdigit():
        pick = int(raw)
        if pick < 1 or pick > min(20, len(matches)):
            print('[!] Invalid option.')
            return
        match_id = matches[pick - 1].get('match_id', '')
    else:
        match_id = raw
    if not match_id:
        print('[!] Match ID required.')
        return
    confirm = input(f'Accept trade for match {match_id}? (y/n): ').strip().lower()
    if confirm != 'y':
        return
    client_obj = _cli_otc_client(client_id)
    opened = open_secure_session(client_obj, match_id)
    swap = start_htlc_coordination(client_obj, match_id)
    append_audit_event('cli_action', client_id, match_id, details={'source': 'manual', 'action': 'ACCEPT_TRADE'})
    print(f"[OK] Trade accepted: match={match_id}")
    print(f"[OK] Session: {opened.get('session', {}).get('session_id', '')}")
    print(f"[OK] Swap: {swap.get('swap_id', '')} | state={swap.get('state', '')}")
    print('[NEXT] Continue in Pending Actions/My Trades for lock/claim proofs.')

def cli_pending_actions():
    print('\n' + '=' * 47)
    print('  PENDING ACTIONS')
    print('=' * 47)
    client_id = input('Client ID: ').strip()
    pending: List[Dict[str, Any]] = []
    intents = STORAGE_DB.list_trade_intents_for_client(client_id, limit=100)
    matches_map = {m.get('match_id', ''): m for m in STORAGE_DB.list_matches_for_client(client_id, limit=200)}
    for intent in intents:
        related_match = None
        for m in matches_map.values():
            if intent.get('intent_id') in (m.get('intent_sell_id'), m.get('intent_buy_id')):
                related_match = m
                break
        session = STORAGE_DB.get_secure_session_by_match(related_match.get('match_id', '')) if related_match else None
        swap = None
        if related_match:
            for s in _list_swaps_for_client(client_id, limit=200):
                if s.get('match_id') == related_match.get('match_id'):
                    swap = s
                    break
        fee_invoice = STORAGE_DB.get_latest_fee_invoice(swap.get('swap_id', '')) if swap else None
        for act in compute_next_actions(intent=intent, match=related_match, session=session, swap=swap, fee_invoice=fee_invoice, client_id=client_id):
            item = dict(act)
            item['intent_id'] = intent.get('intent_id', '')
            item['match_id'] = related_match.get('match_id', '') if related_match else ''
            item['swap_id'] = swap.get('swap_id', '') if swap else ''
            pending.append(item)
    pending.sort(key=lambda x: int(x.get('priority', 999)))
    if not pending:
        print('[INFO] No pending actions.')
        return
    for idx, act in enumerate(pending, start=1):
        ref = act.get('swap_id') or act.get('match_id') or act.get('intent_id')
        mark = 'RISK' if act.get('risky') else 'SAFE'
        print(f"  {idx}. {act.get('label')} | ref={ref} | {mark}")
    print(f"  {len(pending)+1}. Back")
    choice = input('Select action: ').strip()
    if choice == str(len(pending)+1):
        return
    try:
        action = pending[int(choice)-1]
    except Exception:
        print('[!] Invalid option.')
        return
    _execute_next_action(client_id, action, source='pending_inbox')

def cli_my_trades():
    print('\n' + '=' * 47)
    print('  MY TRADES')
    print('=' * 47)
    client_id = input('Client ID: ').strip()
    status_filter = input('Status filter (optional, e.g. OPEN/MATCHED/SWAP_INIT/COMPLETED): ').strip().upper()
    intents = STORAGE_DB.list_trade_intents_for_client(client_id, limit=100)
    matches = STORAGE_DB.list_matches_for_client(client_id, limit=100)
    swaps = _list_swaps_for_client(client_id, limit=100)
    if status_filter:
        intents = [x for x in intents if str(x.get('status', '')).upper() == status_filter]
        matches = [x for x in matches if str(x.get('status', '')).upper() == status_filter]
        swaps = [x for x in swaps if str(x.get('state', '')).upper() == status_filter]
    print(f'Intents: {len(intents)} | Matches: {len(matches)} | Swaps: {len(swaps)}')
    for item in intents[:20]:
        print(f"- intent {item.get('intent_id','')} | {item.get('sell_asset','')}->{item.get('buy_asset','')} | {item.get('status','')}")
    for item in matches[:20]:
        print(f"- match {item.get('match_id','')} | status={item.get('status','')}")
    for item in swaps[:20]:
        fee = STORAGE_DB.get_latest_fee_invoice(item.get('swap_id', ''))
        print(f"- {render_trade_summary(swap=item, fee_invoice=fee)}")
    swap_id = input('Open swap details (swap_id, optional): ').strip()
    if not swap_id:
        return
    swap = get_swap_status(_cli_otc_client(client_id), swap_id)
    fee = STORAGE_DB.get_latest_fee_invoice(swap_id)
    print(render_trade_summary(swap=swap, fee_invoice=fee))
    actions = compute_next_actions(swap=swap, fee_invoice=fee, client_id=client_id)
    if not actions:
        print('[INFO] No actions available for this swap.')
        return
    for idx, act in enumerate(actions, start=1):
        print(f"  {idx}. {act.get('label')}")
    print(f"  {len(actions)+1}. Back")
    choice = input('Select action: ').strip()
    if choice == str(len(actions)+1):
        return
    try:
        _execute_next_action(client_id, actions[int(choice)-1], source='my_trades')
    except Exception:
        print('[!] Invalid option.')

def cli_admin_menu():
    while True:
        print('\n' + '='*47)
        print('  ONESEAM ADMIN/TECHNICAL')
        print('='*47)
        print('  1. Node Status')
        print('  2. Audit DarkPool')
        print('  3. Monitor Intent Status')
        print('  4. View Matches')
        print('  5. Monitor Swap')
        print('  6. Legacy OTC Menu (Deprecated)')
        print('  7. Back')
        choice = input('\nSelect option: ').strip()
        try:
            if choice == '1':
                print_status()
            elif choice == '2':
                audit_darkpool()
            elif choice == '3':
                cli_monitor_intents()
            elif choice == '4':
                cli_view_matches()
            elif choice == '5':
                cli_monitor_swap()
            elif choice == '6':
                cli_menu_legacy_otc()
            elif choice == '7':
                return
            else:
                print('[!] Invalid option.')
        except Exception as e:
            print(f'[X] Operation failed: {e}')

# ===== CLI MENU =====
def cli_menu_legacy_otc():
    """Legacy OTC CLI menu (deprecated)."""
    while True:
        print('\n' + '='*47)
        print('  ONESEAM OTC LEGACY (DEPRECATED)')
        print('='*47)
        print('  1. Node Status')
        print('  2. Create RFQ')
        print('  3. Accept RFQ')
        print('  4. Create Trade')
        print('  5. Create Escrow')
        print('  6. Settle Trade')
        print('  7. Refund Trade')
        print('  8. Monitor OTC Trades')
        print('  9. Audit OTC')
        print('  10. Back')

        choice = input('\nSelect option: ').strip()
        try:
            if choice == '1':
                print_status()
            elif choice == '2':
                cli_create_rfq()
            elif choice == '3':
                cli_accept_rfq()
            elif choice == '4':
                cli_create_trade()
            elif choice == '5':
                cli_create_escrow()
            elif choice == '6':
                cli_settle_trade()
            elif choice == '7':
                cli_refund_trade()
            elif choice == '8':
                monitor_otc_trades()
            elif choice == '9':
                audit_otc()
            elif choice == '10':
                return
            else:
                print('[!] Invalid option.')
        except Exception as e:
            print(f'[X] Operation failed: {e}')

def cli_menu_advanced():
    """Advanced/manual CLI menu (technical operators and debugging)."""
    if not DARKPOOL_ENABLED:
        print('[INFO] darkpool_enabled=false, switching to legacy OTC menu.')
        cli_menu_legacy_otc()
        return
    show_admin = CLI_ADMIN_UI_MODE or (CLI_MODE_OVERRIDE == 'admin')
    while True:
        print('\n' + '=' * 47)
        print('  ONESEAM ADVANCED CLI')
        print('=' * 47)
        print('  1. Node Status')
        print('  2. Commit Trade Intent (for matching)')
        print('  3. Accept Trade (from match)')
        print('  4. Pending Actions')
        print('  5. My Trades')
        print('  6. Guided Wizard')
        print('  7. Exit')
        if show_admin:
            print('  9. Admin/Technical')
        choice = input('\nSelect option: ').strip()
        try:
            if choice == '1':
                print_status()
            elif choice == '2':
                cli_commit_trade_intent()
            elif choice == '3':
                cli_accept_trade_from_match()
            elif choice == '4':
                cli_pending_actions()
            elif choice == '5':
                cli_my_trades()
            elif choice == '6':
                cli_trade_wizard()
            elif choice == '7':
                print('\n[SHUTDOWN] Stopping node...')
                local_test_registry_cleanup()
                raise SystemExit(0)
            elif choice == '9' and show_admin:
                cli_admin_menu()
            elif choice in ('99', ':admin'):
                admin_client_id = input('Admin client ID: ').strip()
                admin_client = _cli_otc_client(admin_client_id)
                if 'admin' not in (admin_client.get('roles') or []):
                    print('[X] Admin role required.')
                else:
                    cli_admin_menu()
            else:
                print('[!] Invalid option.')
        except Exception as e:
            print(f'[X] Operation failed: {e}')

def _cli_use_advanced_mode() -> bool:
    if CLI_ADVANCED_MODE:
        return True
    if CLI_MODE_OVERRIDE in ('advanced', 'admin'):
        return True
    if CLI_MODE_OVERRIDE in ('simple', 'trader'):
        return False
    return False

def cli_menu():
    """Default CLI entrypoint: simplified CLI unless advanced mode is requested."""
    if _cli_use_advanced_mode():
        cli_menu_advanced()
        return
    run_simple_cli_menu()

# ===== ENTERPRISE REST API =====
async def start_rest_api():
    """Start enterprise REST API server (aiohttp)"""
    _assert_production_ready_or_raise()
    if not AIOHTTP_AVAILABLE:
        print('[API] aiohttp not installed. API disabled.')
        return
    if not JWT_AVAILABLE and not ALLOW_LEGACY_API_KEYS:
        print('[API] PyJWT not installed and legacy API keys disabled.')
        return
    if API_BIND not in ('127.0.0.1', 'localhost') and not TLS_ENABLED:
        print('[API] TLS is required for non-local bind.')
        return
    if TLS_ENABLED and (not TLS_CERT_PATH or not TLS_KEY_PATH):
        print('[API] TLS enabled but cert/key not configured.')
        return
    if not JWT_PUBLIC_KEY_CACHE and not ALLOW_LEGACY_API_KEYS:
        print('[API] No JWT public keys configured and legacy API keys disabled.')
        return

    @web.middleware
    async def request_id_middleware(request, handler):
        request['request_id'] = str(uuid_lib.uuid4())
        metric_inc('requests_total')
        try:
            response = await handler(request)
        except web.HTTPException as ex:
            response = ex
        response.headers['X-Request-Id'] = request['request_id']
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Pragma'] = 'no-cache'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        if str(request.path).startswith('/v1/otc/'):
            response.headers['Deprecation'] = 'true'
            response.headers['Warning'] = '299 - "v1 OTC API is legacy and will be removed in a future release"'
        if TLS_ENABLED:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    app = web.Application(middlewares=[request_id_middleware], client_max_size=API_MAX_PAYLOAD_BYTES)

    def json_error(request, status: int, code: str, message: str):
        return web.json_response({'error': message, 'error_code': code, 'request_id': request['request_id']}, status=status)

    async def ensure_auth(request, required_scopes=None, required_roles=None):
        if MTLS_CA_PATH and MTLS_ALLOWED_CNS:
            ssl_obj = request.transport.get_extra_info('ssl_object')
            cert = ssl_obj.getpeercert() if ssl_obj else None
            subject = cert.get('subject', []) if cert else []
            cn = ''
            for attrs in subject:
                for k, v in attrs:
                    if k == 'commonName':
                        cn = v
                        break
            if not cn or (cn not in MTLS_ALLOWED_CNS and not any(x in cn for x in MTLS_ALLOWED_CNS)):
                raise web.HTTPForbidden()
        client = None
        auth = request.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            token = auth.split(' ', 1)[1].strip()
            try:
                claims = _verify_jwt(token)
            except Exception:
                raise web.HTTPUnauthorized()
            client = {
                'client_id': claims.get('sub'),
                'roles': claims.get('roles', []),
                'scopes': claims.get('scopes', []),
                'claims': claims
            }
        elif ALLOW_LEGACY_API_KEYS:
            api_key = request.headers.get('X-API-Key')
            if api_key and api_key in API_KEYS:
                legacy = API_KEYS[api_key]
                client = {
                    'client_id': legacy.get('client_id'),
                    'roles': legacy.get('roles', ['issuer']),
                    'scopes': legacy.get('scopes', [
                        'otc:rfq:write', 'otc:rfq:read', 'otc:trade:write', 'otc:trade:read', 'otc:settle',
                        'intent:write', 'intent:read', 'match:read', 'session:write', 'swap:write', 'swap:read', 'fee:write', 'fee:read'
                    ])
                }
        if not client or not client.get('client_id'):
            metric_inc('auth_failed_total')
            raise web.HTTPUnauthorized()
        scopes = client.get('scopes', [])
        if isinstance(scopes, str):
            scopes = scopes.split()
        roles = client.get('roles', [])
        if required_scopes:
            for s in required_scopes:
                if s not in scopes:
                    metric_inc('auth_failed_total')
                    raise web.HTTPForbidden()
        if required_roles:
            ok = any(r in roles for r in required_roles)
            if not ok:
                metric_inc('auth_failed_total')
                raise web.HTTPForbidden()
        if not _rate_limit_ok(client['client_id'], request.path):
            metric_inc('rate_limited_total')
            raise web.HTTPTooManyRequests()
        request['client'] = client
        return client

    async def health(request):
        return web.json_response({
            'status': 'healthy',
            'service': 'ONESEAM DarkPool Infrastructure',
            'version': APP_VERSION,
            'domain': 'darkpool_p2p_otc',
            'non_custodial': True,
            'production_mode': PRODUCTION_MODE,
            'node_id': node_id,
            'request_id': request['request_id']
        })

    async def ready(request):
        ok = True
        reasons = []
        if TLS_ENABLED and (not TLS_CERT_PATH or not TLS_KEY_PATH):
            ok = False
            reasons.append('tls_not_configured')
        if not JWT_PUBLIC_KEY_CACHE and not ALLOW_LEGACY_API_KEYS:
            ok = False
            reasons.append('jwt_keys_missing')
        if LEGACY_OTC_API_ENABLED and OTC_ENABLED and ESCROW_VERIFY_ON_SUBMIT:
            if not EVM_RPC_URL:
                ok = False
                reasons.append('evm_rpc_url_missing')
            if not ESCROW_CONTRACT_ADDRESS:
                ok = False
                reasons.append('escrow_contract_address_missing')
            if ESCROW_EVENT_STRICT_VALIDATION and not os.path.exists(ESCROW_CONTRACT_ABI_PATH):
                ok = False
                reasons.append('escrow_contract_abi_missing')
        if PROOF_SERVER_SIDE_VERIFICATION_REQUIRED:
            if not PROOF_VERIFIER_URL and not BTC_RPC_URL:
                ok = False
                reasons.append('proof_verifier_or_btc_rpc_missing')
            if not _is_btc_chain_name(HTLC_CHAIN_B) and not PROOF_VERIFIER_URL:
                ok = False
                reasons.append('proof_verifier_url_missing_for_chain_b')
        if (WALLET_ATTESTATION_REQUIRED or PROOF_WALLET_ATTESTATION_REQUIRED) and not EVM_SIGNATURE_AVAILABLE:
            ok = False
            reasons.append('wallet_attestation_unavailable')
        prod_issues = _production_readiness_issues()
        if prod_issues:
            ok = False
            reasons.extend(prod_issues)
        reasons = list(dict.fromkeys(reasons))
        status = 'ready' if ok else 'not_ready'
        return web.json_response({'status': status, 'reasons': reasons, 'request_id': request['request_id']}, status=200 if ok else 503)

    async def metrics(request):
        if not METRICS_ENABLED:
            return json_error(request, 404, 'metrics_disabled', 'Metrics disabled')
        return web.json_response({'request_id': request['request_id'], 'metrics': metrics_snapshot()})

    def _map_otc_error(request, err: Exception):
        msg = str(err)
        if isinstance(err, PermissionError):
            return json_error(request, 403, 'forbidden', msg or 'Forbidden')
        error_status_map = {
            'rfq_not_found': 404,
            'trade_not_found': 404,
            'intent_not_found': 404,
            'match_not_found': 404,
            'swap_not_found': 404,
            'fee_invoice_not_found': 404,
            'intent_trade_mismatch': 409,
            'intent_action_mismatch': 409,
            'intent_expired': 409,
            'intent_not_cancellable': 409,
            'amount_must_be_positive': 400,
            'invalid_price_range': 400,
            'expiration_too_soon': 400,
            'expiration_too_far': 400,
            'notional_limit_exceeded': 409,
            'wallet_signature_required': 401,
            'wallet_signature_invalid': 401,
            'wallet_signature_wallet_mismatch': 403,
            'invalid_env_wallet_private_key': 400,
            'env_wallet_key_mismatch': 403,
            'wallet_attestation_unavailable': 503,
            'proof_verifier_missing': 503,
            'proof_verifier_unreachable': 503,
            'proof_verifier_error': 503,
            'proof_verifier_invalid_response': 503,
            'proof_verifier_or_btc_rpc_missing': 503,
            'proof_verifier_url_missing_for_chain_b': 503,
            'proof_verification_failed': 422,
            'proof_tx_hash_mismatch': 409,
            'btc_rpc_unavailable': 503,
            'btc_rpc_unreachable': 503,
            'btc_rpc_error': 503,
            'btc_rpc_invalid_response': 503,
            'production_not_ready': 503,
            'actor_not_allowed_for_intent': 403,
            'actor_not_allowed_for_match': 403,
            'actor_not_allowed_for_swap': 403,
            'actor_not_allowed_for_proof': 403,
            'proof_signer_wallet_mismatch': 403,
            'darkpool_disabled': 503,
            'invalid_swap_transition': 409,
            'swap_terminal_state': 409,
            'swap_not_completed': 409,
            'insufficient_confirmations': 409,
            'secret_hash_mismatch': 409,
            'invalid_proof_type': 400,
            'invalid_tx_hash': 400,
            'proof_replay_detected': 409,
            'tx_not_found': 404,
            'tx_not_confirmed': 409,
            'tx_reverted': 422,
            'wrong_contract': 409,
            'wrong_event': 409,
            'trade_mismatch': 409,
            'tx_hash_reused': 409,
            'trade_not_in_escrow_creatable_state': 409,
            'trade_not_settle_ready': 409,
            'trade_not_refundable': 409
        }
        if isinstance(err, RuntimeError):
            code = (msg.split(':', 1)[0] if msg else 'service_unavailable').strip() or 'service_unavailable'
            return json_error(request, error_status_map.get(code, 503), code, msg or code)
        if isinstance(err, ValueError):
            code = msg if msg else 'invalid_request'
            return json_error(request, error_status_map.get(code, 400), code, code)
        return json_error(request, 503, 'service_unavailable', msg or 'Service unavailable')

    async def wallet_bind_api(request):
        await ensure_auth(request, required_scopes=['otc:trade:write'], required_roles=['issuer', 'receiver', 'admin'])
        try:
            data = await request.json()
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = WalletBindRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        chain_id = int(data.get('chain_id') or EVM_CHAIN_ID)
        try:
            result = otc_bind_wallet(request['client'], data.get('wallet_address', ''), chain_id)
        except Exception as e:
            return _map_otc_error(request, e)
        result['request_id'] = request['request_id']
        return web.json_response(result, status=201)

    async def otc_create_rfq_api(request):
        await ensure_auth(request, required_scopes=['otc:rfq:write'], required_roles=['issuer', 'admin'])
        try:
            data = await request.json()
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = OTCRFQCreateRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            rfq = otc_create_rfq(request['client'], data, request_id=request['request_id'])
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'rfq': rfq, 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 201)
        return web.json_response(payload, status=201)

    async def otc_get_rfq_api(request):
        await ensure_auth(request, required_scopes=['otc:rfq:read'], required_roles=['issuer', 'receiver', 'auditor', 'admin'])
        rfq_id = request.match_info.get('rfq_id')
        rfq = STORAGE_DB.get_rfq(rfq_id)
        if not rfq:
            return json_error(request, 404, 'rfq_not_found', 'rfq_not_found')
        return web.json_response({'rfq': rfq, 'request_id': request['request_id']})

    async def otc_accept_rfq_api(request):
        await ensure_auth(request, required_scopes=['otc:trade:write'], required_roles=['issuer', 'receiver', 'admin'])
        rfq_id = request.match_info.get('rfq_id')
        try:
            data = await request.json()
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = OTCRFQAcceptRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            trade = otc_accept_rfq(request['client'], rfq_id, data.get('taker_wallet', ''), request_id=request['request_id'])
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'trade': trade, 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 201)
        return web.json_response(payload, status=201)

    async def otc_create_trade_api(request):
        await ensure_auth(request, required_scopes=['otc:trade:write'], required_roles=['issuer', 'admin'])
        try:
            data = await request.json()
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = OTCTradeCreateRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            trade = otc_create_trade_direct(request['client'], data, request_id=request['request_id'])
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'trade': trade, 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 201)
        return web.json_response(payload, status=201)

    async def otc_get_trade_api(request):
        await ensure_auth(request, required_scopes=['otc:trade:read'], required_roles=['issuer', 'receiver', 'auditor', 'admin'])
        trade_id = request.match_info.get('trade_id')
        trade = STORAGE_DB.get_trade(trade_id)
        if not trade:
            return json_error(request, 404, 'trade_not_found', 'trade_not_found')
        return web.json_response({'trade': trade, 'request_id': request['request_id']})

    async def otc_prepare_escrow_api(request):
        await ensure_auth(request, required_scopes=['otc:trade:write'], required_roles=['issuer', 'receiver', 'admin'])
        trade_id = request.match_info.get('trade_id')
        try:
            data = await request.json() if (request.content_length or 0) > 0 else {}
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = OTCPrepareRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            prepared = otc_prepare_escrow(
                request['client'],
                trade_id,
                timeout_seconds=data.get('timeout_seconds'),
                request_id=request['request_id']
            )
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'prepared_transaction': prepared, 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 200)
        return web.json_response(payload)

    async def otc_prepare_settle_api(request):
        await ensure_auth(request, required_scopes=['otc:settle'], required_roles=['issuer', 'receiver', 'admin'])
        trade_id = request.match_info.get('trade_id')
        try:
            data = await request.json() if (request.content_length or 0) > 0 else {}
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = OTCPrepareRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            prepared = otc_prepare_settle(
                request['client'],
                trade_id,
                timeout_seconds=data.get('timeout_seconds'),
                request_id=request['request_id']
            )
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'prepared_transaction': prepared, 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 200)
        return web.json_response(payload)

    async def otc_prepare_refund_api(request):
        await ensure_auth(request, required_scopes=['otc:settle'], required_roles=['issuer', 'receiver', 'admin'])
        trade_id = request.match_info.get('trade_id')
        try:
            data = await request.json() if (request.content_length or 0) > 0 else {}
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = OTCPrepareRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            prepared = otc_prepare_refund(
                request['client'],
                trade_id,
                timeout_seconds=data.get('timeout_seconds'),
                request_id=request['request_id']
            )
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'prepared_transaction': prepared, 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 200)
        return web.json_response(payload)

    async def otc_create_escrow_api(request):
        await ensure_auth(request, required_scopes=['otc:trade:write'], required_roles=['issuer', 'receiver', 'admin'])
        trade_id = request.match_info.get('trade_id')
        try:
            data = await request.json()
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = OTCTradeActionRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        elif not data.get('tx_hash'):
            return json_error(request, 400, 'invalid_payload', 'tx_hash is required')
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            trade = otc_create_escrow(
                request['client'],
                trade_id,
                data.get('tx_hash', ''),
                escrow_trade_ref=data.get('escrow_trade_ref'),
                intent_id=data.get('intent_id'),
                request_id=request['request_id']
            )
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'trade': trade, 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 200)
        return web.json_response(payload)

    async def otc_settle_trade_api(request):
        await ensure_auth(request, required_scopes=['otc:settle'], required_roles=['issuer', 'receiver', 'admin'])
        trade_id = request.match_info.get('trade_id')
        try:
            data = await request.json()
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = OTCTradeActionRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        elif not data.get('tx_hash'):
            return json_error(request, 400, 'invalid_payload', 'tx_hash is required')
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            trade = otc_settle_trade(
                request['client'],
                trade_id,
                data.get('tx_hash', ''),
                intent_id=data.get('intent_id'),
                request_id=request['request_id']
            )
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'trade': trade, 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 200)
        return web.json_response(payload)

    async def otc_refund_trade_api(request):
        await ensure_auth(request, required_scopes=['otc:settle'], required_roles=['issuer', 'receiver', 'admin'])
        trade_id = request.match_info.get('trade_id')
        try:
            data = await request.json()
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = OTCTradeActionRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        elif not data.get('tx_hash'):
            return json_error(request, 400, 'invalid_payload', 'tx_hash is required')
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            trade = otc_refund_trade(
                request['client'],
                trade_id,
                data.get('tx_hash', ''),
                intent_id=data.get('intent_id'),
                request_id=request['request_id']
            )
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'trade': trade, 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 200)
        return web.json_response(payload)

    async def otc_fees_api(request):
        await ensure_auth(request, required_scopes=['otc:trade:read'], required_roles=['issuer', 'receiver', 'auditor', 'admin'])
        start = int(request.query.get('start', 0))
        end = int(request.query.get('end', int(time.time() * 1000)))
        fees = STORAGE_DB.list_trade_fee_events(request['client']['client_id'], start, end)
        return web.json_response({
            'client_id': request['client']['client_id'],
            'fee_bps_default': OTC_DEFAULT_FEE_BPS,
            'fees': fees,
            'request_id': request['request_id']
        })

    async def create_trade_intent_api(request):
        await ensure_auth(request, required_scopes=['intent:write'], required_roles=['issuer', 'receiver', 'admin'])
        if not DARKPOOL_ENABLED:
            return json_error(request, 503, 'darkpool_disabled', 'darkpool_disabled')
        try:
            data = await request.json()
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = TradeIntentCreateRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            intent = create_trade_intent(request['client'], data, request_id=request['request_id'])
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'trade_intent': intent, 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 201)
        return web.json_response(payload, status=201)

    async def prepare_trade_intent_signature_api(request):
        await ensure_auth(request, required_scopes=['intent:write'], required_roles=['issuer', 'receiver', 'admin'])
        if not DARKPOOL_ENABLED:
            return json_error(request, 503, 'darkpool_disabled', 'darkpool_disabled')
        try:
            data = await request.json()
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = TradeIntentCreateRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        try:
            prepared = prepare_trade_intent_signature(request['client'], data)
        except Exception as e:
            return _map_otc_error(request, e)
        return web.json_response({'attestation': prepared, 'request_id': request['request_id']})

    async def get_trade_intent_api(request):
        await ensure_auth(request, required_scopes=['intent:read'], required_roles=['issuer', 'receiver', 'auditor', 'admin'])
        if not DARKPOOL_ENABLED:
            return json_error(request, 503, 'darkpool_disabled', 'darkpool_disabled')
        intent_id = request.match_info.get('intent_id')
        try:
            intent = get_trade_intent(request['client'], intent_id)
        except Exception as e:
            return _map_otc_error(request, e)
        return web.json_response({'trade_intent': intent, 'request_id': request['request_id']})

    async def cancel_trade_intent_api(request):
        await ensure_auth(request, required_scopes=['intent:write'], required_roles=['issuer', 'receiver', 'admin'])
        if not DARKPOOL_ENABLED:
            return json_error(request, 503, 'darkpool_disabled', 'darkpool_disabled')
        intent_id = request.match_info.get('intent_id')
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            intent = cancel_trade_intent(request['client'], intent_id, request_id=request['request_id'])
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'trade_intent': intent, 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 200)
        return web.json_response(payload)

    async def get_match_api(request):
        await ensure_auth(request, required_scopes=['match:read'], required_roles=['issuer', 'receiver', 'auditor', 'admin'])
        if not DARKPOOL_ENABLED:
            return json_error(request, 503, 'darkpool_disabled', 'darkpool_disabled')
        match_id = request.match_info.get('match_id')
        try:
            match_obj = get_match(request['client'], match_id)
        except Exception as e:
            return _map_otc_error(request, e)
        return web.json_response({'match': match_obj, 'request_id': request['request_id']})

    async def open_session_api(request):
        await ensure_auth(request, required_scopes=['session:write'], required_roles=['issuer', 'receiver', 'admin'])
        if not DARKPOOL_ENABLED:
            return json_error(request, 503, 'darkpool_disabled', 'darkpool_disabled')
        match_id = request.match_info.get('match_id')
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            payload_obj = open_secure_session(request['client'], match_id, request_id=request['request_id'])
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'session': payload_obj.get('session'), 'swap': payload_obj.get('swap'), 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 200)
        return web.json_response(payload)

    async def start_swap_api(request):
        await ensure_auth(request, required_scopes=['swap:write'], required_roles=['issuer', 'receiver', 'admin'])
        if not DARKPOOL_ENABLED:
            return json_error(request, 503, 'darkpool_disabled', 'darkpool_disabled')
        match_id = request.match_info.get('match_id')
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            swap = start_htlc_coordination(request['client'], match_id, request_id=request['request_id'])
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'swap': swap, 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 200)
        return web.json_response(payload)

    async def submit_htlc_proof_api(request):
        await ensure_auth(request, required_scopes=['swap:write'], required_roles=['issuer', 'receiver', 'admin'])
        if not DARKPOOL_ENABLED:
            return json_error(request, 503, 'darkpool_disabled', 'darkpool_disabled')
        swap_id = request.match_info.get('swap_id')
        try:
            data = await request.json()
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = HTLCProofRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            result = submit_htlc_proof(request['client'], swap_id, data, request_id=request['request_id'])
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'swap': result.get('swap'), 'fee_invoice': result.get('fee_invoice'), 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 200)
        return web.json_response(payload)

    async def prepare_htlc_proof_signature_api(request):
        await ensure_auth(request, required_scopes=['swap:write'], required_roles=['issuer', 'receiver', 'admin'])
        if not DARKPOOL_ENABLED:
            return json_error(request, 503, 'darkpool_disabled', 'darkpool_disabled')
        swap_id = request.match_info.get('swap_id')
        try:
            data = await request.json()
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = HTLCProofRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        swap = _refresh_swap_timeout_state(swap_id) or STORAGE_DB.get_swap(swap_id)
        if not swap:
            return json_error(request, 404, 'swap_not_found', 'swap_not_found')
        if not _swap_actor_allowed(request['client'], swap):
            return json_error(request, 403, 'actor_not_allowed_for_swap', 'actor_not_allowed_for_swap')
        proof_type = str(data.get('proof_type', '')).strip()
        if proof_type and not _is_proof_actor_allowed(request['client'], swap, proof_type):
            return json_error(request, 403, 'actor_not_allowed_for_proof', 'actor_not_allowed_for_proof')
        signer_wallet = _normalize_wallet(data.get('signer_wallet') or _expected_wallet_for_proof(swap, proof_type))
        if signer_wallet:
            try:
                _ensure_wallet_authorized(request['client'], signer_wallet, EVM_CHAIN_ID)
            except Exception as e:
                return _map_otc_error(request, e)
        try:
            prepared = prepare_htlc_proof_signature(request['client'], swap, data, signer_wallet)
        except Exception as e:
            return _map_otc_error(request, e)
        return web.json_response({'attestation': prepared, 'request_id': request['request_id']})

    async def get_swap_api(request):
        await ensure_auth(request, required_scopes=['swap:read'], required_roles=['issuer', 'receiver', 'auditor', 'admin'])
        if not DARKPOOL_ENABLED:
            return json_error(request, 503, 'darkpool_disabled', 'darkpool_disabled')
        swap_id = request.match_info.get('swap_id')
        try:
            swap = get_swap_status(request['client'], swap_id)
        except Exception as e:
            return _map_otc_error(request, e)
        return web.json_response({'swap': swap, 'request_id': request['request_id']})

    async def issue_fee_invoice_api(request):
        await ensure_auth(request, required_scopes=['fee:write'], required_roles=['issuer', 'receiver', 'admin'])
        if not DARKPOOL_ENABLED:
            return json_error(request, 503, 'darkpool_disabled', 'darkpool_disabled')
        swap_id = request.match_info.get('swap_id')
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            invoice = issue_fee_invoice(request['client'], swap_id, request_id=request['request_id'])
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'fee_invoice': invoice, 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 200)
        return web.json_response(payload)

    async def confirm_fee_invoice_api(request):
        await ensure_auth(request, required_scopes=['fee:write'], required_roles=['issuer', 'receiver', 'admin'])
        if not DARKPOOL_ENABLED:
            return json_error(request, 503, 'darkpool_disabled', 'darkpool_disabled')
        swap_id = request.match_info.get('swap_id')
        try:
            data = await request.json()
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = FeeConfirmRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        try:
            invoice = confirm_fee_payment(request['client'], swap_id, data.get('payment_ref', ''), request_id=request['request_id'])
        except Exception as e:
            return _map_otc_error(request, e)
        payload = {'fee_invoice': invoice, 'request_id': request['request_id']}
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 200)
        return web.json_response(payload)

    routes = [
        web.get('/health', health),
        web.get('/ready', ready),
        web.get('/metrics', metrics),
    ]
    if LEGACY_OTC_API_ENABLED:
        routes.extend([
            web.post('/v1/otc/wallet/bind', wallet_bind_api),
            web.post('/v1/otc/rfqs', otc_create_rfq_api),
            web.get('/v1/otc/rfqs/{rfq_id}', otc_get_rfq_api),
            web.post('/v1/otc/rfqs/{rfq_id}/accept', otc_accept_rfq_api),
            web.post('/v1/otc/trades', otc_create_trade_api),
            web.get('/v1/otc/trades/{trade_id}', otc_get_trade_api),
            web.post('/v1/otc/trades/{trade_id}/escrow/prepare', otc_prepare_escrow_api),
            web.post('/v1/otc/trades/{trade_id}/settle/prepare', otc_prepare_settle_api),
            web.post('/v1/otc/trades/{trade_id}/refund/prepare', otc_prepare_refund_api),
            web.post('/v1/otc/trades/{trade_id}/escrow/create', otc_create_escrow_api),
            web.post('/v1/otc/trades/{trade_id}/settle', otc_settle_trade_api),
            web.post('/v1/otc/trades/{trade_id}/refund', otc_refund_trade_api),
            web.get('/v1/otc/fees', otc_fees_api),
        ])
    if DARKPOOL_ENABLED:
        routes.extend([
            web.post('/v2/intents/prepare-signature', prepare_trade_intent_signature_api),
            web.post('/v2/intents', create_trade_intent_api),
            web.get('/v2/intents/{intent_id}', get_trade_intent_api),
            web.post('/v2/intents/{intent_id}/cancel', cancel_trade_intent_api),
            web.get('/v2/matches/{match_id}', get_match_api),
            web.post('/v2/matches/{match_id}/session/open', open_session_api),
            web.post('/v2/matches/{match_id}/swap/start', start_swap_api),
            web.post('/v2/swaps/{swap_id}/htlc/proof/prepare-signature', prepare_htlc_proof_signature_api),
            web.post('/v2/swaps/{swap_id}/htlc/proof', submit_htlc_proof_api),
            web.get('/v2/swaps/{swap_id}', get_swap_api),
            web.post('/v2/swaps/{swap_id}/fee/invoice', issue_fee_invoice_api),
            web.post('/v2/swaps/{swap_id}/fee/confirm', confirm_fee_invoice_api),
        ])
    app.add_routes(routes)

    ssl_context = None
    if TLS_ENABLED:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(TLS_CERT_PATH, TLS_KEY_PATH)
        if MTLS_CA_PATH:
            ssl_context.load_verify_locations(MTLS_CA_PATH)
            ssl_context.verify_mode = ssl.CERT_REQUIRED

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, API_BIND, API_PORT, ssl_context=ssl_context)
    await site.start()
    log_event('INFO', 'api_start', bind=API_BIND, port=API_PORT, tls=bool(ssl_context))
# ===== MAIN ENTRY =====
if __name__ == '__main__':
    print("""
===============================================
  ONESEAM DARKPOOL v3.2
  P2P Non-Custodial Trade Coordination
  Private Intents + Matching + HTLC (BTC/LN)
===============================================
    """)

    # Register shutdown handlers
    signal.signal(signal.SIGINT, handle_shutdown)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, handle_shutdown)

    async def main_async():
        global ASYNC_LOOP
        ASYNC_LOOP = asyncio.get_running_loop()
        get_node_id()
        ensure_storage()
        _assert_production_ready_or_raise()
        try_upnp()

        print(f'[INIT] Node ID: {node_id[:16]}...')
        if LOCAL_TEST_MODE:
            print('[INIT] Local test mode: ephemeral node ID enabled')
        print(f'[INIT] Storage: db_backend={DB_BACKEND}')
        print(f'[INIT] Production mode: {PRODUCTION_MODE}')
        print(f'[INIT] DarkPool mode: enabled={DARKPOOL_ENABLED}')
        print(f'[INIT] Legacy OTC API: enabled={LEGACY_OTC_API_ENABLED}')
        print(f'[INIT] Supported flow: intent -> match -> session -> HTLC coordination -> fee invoice')

        tasks = [
            asyncio.create_task(broadcast_presence_async()),
            asyncio.create_task(listen_broadcast_async()),
            asyncio.create_task(start_p2p_server()),
            asyncio.create_task(prune_neighbors_async()),
            asyncio.create_task(bootstrap_seeds()),
            asyncio.create_task(onchain_reconciler_async()),
            asyncio.create_task(swap_timeout_sweeper_async())
        ]
        if LOCAL_TEST_MODE:
            tasks.append(asyncio.create_task(local_test_discovery_async()))
            print('[INIT] Local test discovery: localhost probing enabled')
        if BLIND_RELAY_ENABLED:
            tasks.append(asyncio.create_task(relay_worker()))
            print('[INIT] Blind Relay (Repasse Cego) enabled')

        if 'api' in sys.argv:
            print('[MODE] Starting in API mode (REST server)')
            await start_rest_api()
            await asyncio.Event().wait()
        else:
            print('[MODE] Starting in CLI mode')
            print('[INFO] For API mode, run: python oneseam.py api')
            print('[INFO] For advanced CLI, run: python oneseam.py --advanced')
            print('[INFO] For advanced admin UI, run: python oneseam.py --advanced --admin-ui')
            await asyncio.to_thread(cli_menu)

    try:
        asyncio.run(main_async())
    except RuntimeError as e:
        print(f'[FATAL] {e}')
        raise SystemExit(1)

