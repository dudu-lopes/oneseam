"""
Oneseam Enterprise - Resilient Cryptographic Messaging Infrastructure
Version: 2.0.0

Enterprise-grade P2P messaging system for financial settlement instructions.
- Byzantine fault-tolerant (configurable k-of-n quorum)
- Shamir Secret Sharing (zero-knowledge sharding)
- SEAM Protocol (Settlement Evidence & Agreement Message)
- Blind Relay (Repasse Cego) - nodes accept and relay shards toward destination
- AES-256-GCM encryption
- Cryptographic metering with Access Release Token (ART)
- On-grid / off-grid mesh network capable
- Data sovereignty and compliance metadata
- REST API for enterprise integration

No custody of funds. Messages only. Compliance-native.
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
import uuid as uuid_lib
from hashlib import sha256
from getpass import getpass
from typing import List, Optional, Dict, Tuple, Any, Literal
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum

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

# Pydantic validation
try:
    from pydantic import BaseModel, ValidationError, Field
    from pydantic import ConfigDict
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False

if PYDANTIC_AVAILABLE:
    class PaymentObligationRequest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        amount: float
        currency: str = 'USD'
        creditor: str
        debtor: str
        due_date: Optional[int] = None
        terms: Optional[str] = None
        reference: Optional[str] = None
        interest_rate: Optional[float] = None
        jurisdiction: Optional[str] = None
    
    class InstructionRequest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        payload: str
        destination: str
        encryption_key: Optional[str] = None
        jurisdiction: Optional[str] = None
        data_region: Optional[str] = None
        compliance_frameworks: Optional[List[str]] = None
    
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
    combined = base64.b64encode(salt + nonce + ciphertext).decode()
    return combined

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

# ===== SEAM PROTOCOL (Settlement Evidence & Agreement Message) =====

class SEAMType(Enum):
    """Standard SEAM message types"""
    PAYMENT_OBLIGATION = "PAYMENT_OBLIGATION"
    INVOICE = "INVOICE"
    LETTER_OF_CREDIT = "LETTER_OF_CREDIT"
    PURCHASE_ORDER = "PURCHASE_ORDER"
    DELIVERY_CONFIRMATION = "DELIVERY_CONFIRMATION"
    CUSTOM = "CUSTOM"

class SEAMValidator:
    """
    SEAM Protocol Validator
    
    Ensures messages follow Settlement Evidence & Agreement Message standard.
    SEAM transforms encrypted messages into economically interpretable obligations.
    """
    
    # ISO 4217 currency codes (subset - expand as needed)
    VALID_CURRENCIES = {
        'USD', 'EUR', 'BRL', 'GBP', 'JPY', 'CHF', 'CAD', 'AUD', 
        'CNY', 'INR', 'MXN', 'ZAR', 'KRW', 'SGD', 'HKD'
    }
    
    # Required fields for SEAM-compliant messages
    REQUIRED_FIELDS = {
        'instruction_id',
        'seam_type',
        'amount',
        'currency',
        'creditor',
        'debtor',
        'timestamp',
        'integrity_hash'
    }
    
    # Optional but recommended fields
    OPTIONAL_FIELDS = {
        'due_date',
        'terms',
        'reference',
        'jurisdiction',
        'dispute_resolution',
        'collateral',
        'interest_rate',
        'penalties'
    }
    
    @classmethod
    def validate(cls, instruction: Dict) -> Tuple[bool, Optional[str]]:
        """
        Validate if instruction is SEAM-compliant
        
        Returns:
            (is_valid, error_message)
        """
        # Check required fields
        missing = cls.REQUIRED_FIELDS - set(instruction.keys())
        if missing:
            return False, f"Missing required SEAM fields: {missing}"
        
        # Validate SEAM type
        seam_type = instruction.get('seam_type')
        try:
            SEAMType(seam_type)
        except ValueError:
            return False, f"Invalid SEAM type: {seam_type}"
        
        # Validate amount
        try:
            amount = Decimal(str(instruction['amount']))
            if amount <= 0:
                return False, "Amount must be positive"
        except:
            return False, "Invalid amount format"
        
        # Validate currency
        currency = instruction.get('currency', '').upper()
        if currency not in cls.VALID_CURRENCIES:
            return False, f"Invalid currency: {currency} (not in ISO 4217)"
        
        # Validate due_date if present
        if 'due_date' in instruction:
            try:
                due_date = int(instruction['due_date'])
                timestamp = int(instruction['timestamp'])
            except Exception:
                return False, "Invalid due_date or timestamp format"
            if due_date <= timestamp:
                return False, "due_date must be after timestamp"
        
        # Validate integrity hash
        if not instruction.get('integrity_hash'):
            return False, "Missing integrity_hash"
        
        # Validate parties
        if not instruction.get('creditor') or not instruction.get('debtor'):
            return False, "Both creditor and debtor must be specified"
        
        return True, None
    
    @classmethod
    def is_seam_compliant(cls, instruction: Dict) -> bool:
        """Quick check if instruction is SEAM-compliant"""
        is_valid, _ = cls.validate(instruction)
        return is_valid
    
    @classmethod
    def get_validation_report(cls, instruction: Dict) -> Dict:
        """Get detailed validation report"""
        is_valid, error = cls.validate(instruction)
        
        return {
            'is_valid': is_valid,
            'error': error,
            'seam_version': '1.0',
            'validated_at': int(time.time()),
            'fields_present': list(instruction.keys()),
            'missing_optional': list(cls.OPTIONAL_FIELDS - set(instruction.keys()))
        }

def create_seam_payment_obligation(
    amount: float,
    currency: str,
    creditor: str,
    debtor: str,
    due_date: Optional[int] = None,
    terms: str = None,
    reference: str = None,
    interest_rate: float = None,
    jurisdiction: str = None
) -> Dict:
    """
    Create SEAM-compliant Payment Obligation
    
    A payment obligation represents an unconditional promise to pay.
    Can be used as:
    - Collateral for loans
    - Tradeable instrument (factoring)
    - Supply chain financing
    
    Args:
        amount: Payment amount (must be positive)
        currency: ISO 4217 currency code (USD, EUR, BRL, etc)
        creditor: Entity receiving payment
        debtor: Entity making payment
        due_date: Unix timestamp for payment deadline (optional)
        terms: Payment terms/conditions
        reference: External reference (PO number, invoice, etc)
        interest_rate: Annual interest rate if late (optional)
        jurisdiction: Legal jurisdiction for enforcement
    
    Returns:
        SEAM-compliant instruction dict
    """
    instruction_id = generate_instruction_id()
    timestamp = int(time.time())
    
    # Default due date: 90 days from now
    if due_date is None:
        due_date = timestamp + (90 * 24 * 3600)
    
    # Build SEAM payload
    seam_data = {
        'seam_type': SEAMType.PAYMENT_OBLIGATION.value,
        'amount': float(amount),
        'currency': currency.upper(),
        'creditor': creditor,
        'debtor': debtor,
        'due_date': due_date,
        'terms': terms or 'Unconditional payment obligation',
        'reference': reference or instruction_id,
        'timestamp': timestamp
    }
    
    if interest_rate:
        seam_data['interest_rate'] = float(interest_rate)
    if jurisdiction:
        seam_data['jurisdiction'] = jurisdiction
    
    # Generate integrity hash
    payload_str = json.dumps(seam_data, sort_keys=True)
    integrity_hash = generate_dna_hash(payload_str)
    
    instruction = {
        'instruction_id': instruction_id,
        'seam_type': SEAMType.PAYMENT_OBLIGATION.value,
        'seam_version': '1.0',
        'amount': float(amount),
        'currency': currency.upper(),
        'creditor': creditor,
        'debtor': debtor,
        'due_date': due_date,
        'terms': terms or 'Unconditional payment obligation',
        'reference': reference or instruction_id,
        'timestamp': timestamp,
        'integrity_hash': integrity_hash,
        'payload': payload_str,
        'encrypted': False
    }
    
    if interest_rate:
        instruction['interest_rate'] = float(interest_rate)
    if jurisdiction:
        instruction['jurisdiction'] = jurisdiction
    
    # Validate
    is_valid, error = SEAMValidator.validate(instruction)
    if not is_valid:
        raise ValueError(f"SEAM validation failed: {error}")
    
    return instruction

def create_seam_invoice(
    amount: float,
    currency: str,
    creditor: str,
    debtor: str,
    invoice_number: str,
    due_date: int,
    line_items: List[Dict] = None,
    tax_amount: float = None,
    discount_amount: float = None
) -> Dict:
    """
    Create SEAM-compliant Invoice
    
    Represents goods/services delivered, payment due.
    
    Args:
        amount: Total invoice amount
        currency: ISO 4217 currency code
        creditor: Seller/service provider
        debtor: Buyer/customer
        invoice_number: Unique invoice identifier
        due_date: Payment deadline (unix timestamp)
        line_items: List of items (optional)
        tax_amount: Total tax (optional)
        discount_amount: Total discount (optional)
    """
    instruction_id = generate_instruction_id()
    timestamp = int(time.time())
    
    seam_data = {
        'seam_type': SEAMType.INVOICE.value,
        'amount': float(amount),
        'currency': currency.upper(),
        'creditor': creditor,
        'debtor': debtor,
        'due_date': due_date,
        'invoice_number': invoice_number,
        'terms': 'Payment due upon receipt of valid invoice',
        'reference': invoice_number,
        'timestamp': timestamp
    }
    
    if line_items:
        seam_data['line_items'] = line_items
    if tax_amount:
        seam_data['tax_amount'] = float(tax_amount)
    if discount_amount:
        seam_data['discount_amount'] = float(discount_amount)
    
    payload_str = json.dumps(seam_data, sort_keys=True)
    integrity_hash = generate_dna_hash(payload_str)
    
    instruction = {
        'instruction_id': instruction_id,
        'seam_type': SEAMType.INVOICE.value,
        'seam_version': '1.0',
        'amount': float(amount),
        'currency': currency.upper(),
        'creditor': creditor,
        'debtor': debtor,
        'due_date': due_date,
        'invoice_number': invoice_number,
        'terms': 'Payment due upon receipt of valid invoice',
        'reference': invoice_number,
        'timestamp': timestamp,
        'integrity_hash': integrity_hash,
        'payload': payload_str,
        'encrypted': False
    }
    
    if line_items:
        instruction['line_items'] = line_items
    if tax_amount:
        instruction['tax_amount'] = float(tax_amount)
    if discount_amount:
        instruction['discount_amount'] = float(discount_amount)
    
    # Validate
    is_valid, error = SEAMValidator.validate(instruction)
    if not is_valid:
        raise ValueError(f"SEAM validation failed: {error}")
    
    return instruction

def create_seam_letter_of_credit(
    amount: float,
    currency: str,
    creditor: str,
    debtor: str,
    issuing_bank: str,
    beneficiary_bank: str,
    expiry_date: int,
    terms: str,
    documents_required: List[str] = None
) -> Dict:
    """
    Create SEAM-compliant Letter of Credit
    
    Bank guarantee that buyer's payment to seller will be received on time.
    
    Args:
        amount: Credit amount
        currency: ISO 4217 currency code
        creditor: Beneficiary (seller)
        debtor: Applicant (buyer)
        issuing_bank: Bank issuing the LC
        beneficiary_bank: Seller's bank
        expiry_date: LC expiration (unix timestamp)
        terms: Conditions for payment
        documents_required: List of required documents
    """
    instruction_id = generate_instruction_id()
    timestamp = int(time.time())
    
    seam_data = {
        'seam_type': SEAMType.LETTER_OF_CREDIT.value,
        'amount': float(amount),
        'currency': currency.upper(),
        'creditor': creditor,
        'debtor': debtor,
        'issuing_bank': issuing_bank,
        'beneficiary_bank': beneficiary_bank,
        'due_date': expiry_date,
        'terms': terms,
        'reference': f'LC-{instruction_id[:8]}',
        'timestamp': timestamp
    }
    
    if documents_required:
        seam_data['documents_required'] = documents_required
    
    payload_str = json.dumps(seam_data, sort_keys=True)
    integrity_hash = generate_dna_hash(payload_str)
    
    instruction = {
        'instruction_id': instruction_id,
        'seam_type': SEAMType.LETTER_OF_CREDIT.value,
        'seam_version': '1.0',
        'amount': float(amount),
        'currency': currency.upper(),
        'creditor': creditor,
        'debtor': debtor,
        'issuing_bank': issuing_bank,
        'beneficiary_bank': beneficiary_bank,
        'due_date': expiry_date,
        'terms': terms,
        'reference': f'LC-{instruction_id[:8]}',
        'timestamp': timestamp,
        'integrity_hash': integrity_hash,
        'payload': payload_str,
        'encrypted': False
    }
    
    if documents_required:
        instruction['documents_required'] = documents_required
    
    # Validate
    is_valid, error = SEAMValidator.validate(instruction)
    if not is_valid:
        raise ValueError(f"SEAM validation failed: {error}")
    
    return instruction

def create_seam_purchase_order(
    amount: float,
    currency: str,
    creditor: str,
    debtor: str,
    po_number: str,
    delivery_date: int,
    items: List[Dict],
    shipping_address: str = None
) -> Dict:
    """
    Create SEAM-compliant Purchase Order
    
    Commercial document issued by buyer to seller.
    
    Args:
        amount: Total PO amount
        currency: ISO 4217 currency code
        creditor: Seller
        debtor: Buyer
        po_number: Purchase order number
        delivery_date: Expected delivery (unix timestamp)
        items: List of items to purchase
        shipping_address: Delivery address
    """
    instruction_id = generate_instruction_id()
    timestamp = int(time.time())
    
    seam_data = {
        'seam_type': SEAMType.PURCHASE_ORDER.value,
        'amount': float(amount),
        'currency': currency.upper(),
        'creditor': creditor,
        'debtor': debtor,
        'due_date': delivery_date,
        'po_number': po_number,
        'items': items,
        'terms': 'Payment upon delivery',
        'reference': po_number,
        'timestamp': timestamp
    }
    
    if shipping_address:
        seam_data['shipping_address'] = shipping_address
    
    payload_str = json.dumps(seam_data, sort_keys=True)
    integrity_hash = generate_dna_hash(payload_str)
    
    instruction = {
        'instruction_id': instruction_id,
        'seam_type': SEAMType.PURCHASE_ORDER.value,
        'seam_version': '1.0',
        'amount': float(amount),
        'currency': currency.upper(),
        'creditor': creditor,
        'debtor': debtor,
        'due_date': delivery_date,
        'po_number': po_number,
        'items': items,
        'terms': 'Payment upon delivery',
        'reference': po_number,
        'timestamp': timestamp,
        'integrity_hash': integrity_hash,
        'payload': payload_str,
        'encrypted': False
    }
    
    if shipping_address:
        instruction['shipping_address'] = shipping_address
    
    # Validate
    is_valid, error = SEAMValidator.validate(instruction)
    if not is_valid:
        raise ValueError(f"SEAM validation failed: {error}")
    
    return instruction

# ===== CONFIGURATIONS =====
# Load config file if exists
CONFIG = {}
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'oneseam_config.yaml')
if os.path.exists(CONFIG_PATH):
    try:
        import yaml
        with open(CONFIG_PATH, 'r') as f:
            CONFIG = yaml.safe_load(f) or {}
    except Exception:
        pass

def _config(key: str, default: Any) -> Any:
    return CONFIG.get(key, default)

NODE_PORT = _config('node_port', 5001)
BROADCAST_PORT = _config('broadcast_port', 5002)
API_PORT = _config('api_port', 8000)
API_BIND = _config('api_bind', '127.0.0.1')
DB_BACKEND = _config('db_backend', 'sqlite')
DB_PATH = _config('db_path', 'oneseam.db')
DB_DSN = _config('db_dsn', '')
TLS_ENABLED = _config('tls_enabled', False)
TLS_CERT_PATH = _config('tls_cert_path', '')
TLS_KEY_PATH = _config('tls_key_path', '')
MTLS_CA_PATH = _config('mtls_ca_path', '')
MTLS_ALLOWED_CNS = _config('mtls_allowed_cns', []) or []
JWT_ISSUER = _config('jwt_issuer', '')
JWT_AUDIENCE = _config('jwt_audience', '')
JWT_PUBLIC_KEYS = _config('jwt_public_keys', []) or []
JWT_ALGORITHMS = _config('jwt_algorithms', ['RS256', 'ES256']) or ['RS256', 'ES256']
ALLOW_LEGACY_API_KEYS = _config('allow_legacy_api_keys', True)
API_MAX_PAYLOAD_BYTES = _config('api_max_payload_bytes', 1024 * 1024)
RATE_LIMIT_RPS = _config('rate_limit_rps', 5)
RATE_LIMIT_BURST = _config('rate_limit_burst', 10)
IDEMPOTENCY_TTL_SECONDS = _config('idempotency_ttl_seconds', 300)
IDEMPOTENCY_MAX_ENTRIES = _config('idempotency_max_entries', 10000)
P2P_TLS_ENABLED = _config('p2p_tls_enabled', False)
P2P_TLS_CERT_PATH = _config('p2p_tls_cert_path', '')
P2P_TLS_KEY_PATH = _config('p2p_tls_key_path', '')
P2P_MTLS_CA_PATH = _config('p2p_mtls_ca_path', '')
P2P_MTLS_ALLOWED_CNS = _config('p2p_mtls_allowed_cns', []) or []
P2P_MTLS_REQUIRED = _config('p2p_mtls_required', True)
P2P_RETRIES = _config('p2p_retries', 3)
P2P_BACKOFF_BASE = _config('p2p_backoff_base', 0.2)
SEED_NODES = _config('seed_nodes', []) or []
UPNP_ENABLED = _config('upnp_enabled', False)
SHARD_SIGNATURE_REQUIRED = _config('shard_signature_required', True)
SHARD_SIGNING_PRIVATE_KEY = _config('shard_signing_private_key', 'shard_signing_priv.pem')
SHARD_SIGNING_PUBLIC_KEY = _config('shard_signing_public_key', 'shard_signing_pub.pem')
TRUSTED_NODE_PUBKEYS = _config('trusted_node_pubkeys', {}) or {}
BROADCAST_ADDR = _config('broadcast_addr', '<broadcast>')
BUFFER_SIZE = 1024 * 1024  # 1MB
NODE_ID_FILE = 'node_id.txt'
LOG_FILE = _config('log_file', '')
LOG_JSON = _config('log_json', True)
LOG_LEVEL = _config('log_level', 'INFO')
NEIGHBOR_TTL_SECONDS = _config('neighbor_ttl_seconds', 60)
METRICS_ENABLED = _config('metrics_enabled', True)
DEFAULT_QUORUM_K = _config('quorum_k', 2)
DEFAULT_QUORUM_N = _config('quorum_n', 3)
TRANSPORT_MODE = _config('transport_mode', 'HYBRID')  # ON_GRID, OFF_GRID, HYBRID
BLIND_RELAY_ENABLED = _config('blind_relay_enabled', True)
MAX_RELAY_HOPS = _config('max_relay_hops', 10)
SERVED_DESTINATIONS = _config('served_destinations', []) or []
BLIND_RELAY_FLOOD = _config('blind_relay_flood', False)

# Protocol commands
CMD_HANDSHAKE = 'HANDSHAKE'
CMD_STORE_SHARD = 'STORE_SHARD'
CMD_STORE_MANIFEST = 'STORE_MANIFEST'
CMD_FETCH_SHARD = 'FETCH_SHARD'
CMD_FETCH_MANIFEST = 'FETCH_MANIFEST'
CMD_HEALTH_CHECK = 'HEALTH_CHECK'

# Node state
node_id = None
neighbors = {}
neighbors_lock = threading.Lock()
QUIET_MODE = True  # Set to True to suppress RELAY logs
ASYNC_LOOP = None
RELAY_QUEUE = asyncio.Queue()

def run_async(coro):
    global ASYNC_LOOP
    try:
        loop = ASYNC_LOOP
        if loop and loop.is_running():
            fut = asyncio.run_coroutine_threadsafe(coro, loop)
            return fut.result()
    except Exception:
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
    except Exception:
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
                CREATE TABLE IF NOT EXISTS metering_events (
                    instruction_id TEXT,
                    client_id TEXT,
                    timestamp INTEGER,
                    node_id TEXT,
                    event_type TEXT,
                    billable INTEGER,
                    price_usd REAL,
                    access_release_token TEXT,
                    signature TEXT
                )
                """)
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
                CREATE TABLE IF NOT EXISTS metering_events (
                    instruction_id TEXT,
                    client_id TEXT,
                    timestamp INTEGER,
                    node_id TEXT,
                    event_type TEXT,
                    billable INTEGER,
                    price_usd REAL,
                    access_release_token TEXT,
                    signature TEXT
                )
                """)
    
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
    
    def record_metering(self, event: Dict[str, Any]):
        self._execute("""INSERT INTO metering_events
            (instruction_id, client_id, timestamp, node_id, event_type, billable, price_usd,
             access_release_token, signature)
            VALUES (?,?,?,?,?,?,?,?,?)"""
            if self.backend == 'sqlite' else
            """INSERT INTO metering_events
            (instruction_id, client_id, timestamp, node_id, event_type, billable, price_usd,
             access_release_token, signature)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (event['instruction_id'], event['client_id'], event['timestamp'], event['node_id'],
             event['event_type'], 1 if event.get('billable') else 0,
             event['price_usd'], event.get('access_release_token', ''), event.get('signature', '')))
    
    def list_metering_events(self, client_id: str, start: int, end: int) -> List[Dict[str, Any]]:
        cur = self._execute("SELECT instruction_id, client_id, timestamp, node_id, event_type, billable, price_usd, access_release_token, signature FROM metering_events WHERE client_id=? AND timestamp BETWEEN ? AND ?"
                            if self.backend == 'sqlite'
                            else "SELECT instruction_id, client_id, timestamp, node_id, event_type, billable, price_usd, access_release_token, signature FROM metering_events WHERE client_id=%s AND timestamp BETWEEN %s AND %s",
                            (client_id, start, end))
        out = []
        for r in cur.fetchall():
            out.append({
                'instruction_id': r[0],
                'client_id': r[1],
                'timestamp': r[2],
                'node_id': r[3],
                'event_type': r[4],
                'billable': bool(r[5]),
                'price_usd': r[6],
                'access_release_token': r[7],
                'signature': r[8]
            })
        return out

    def list_metering_clients(self) -> List[str]:
        cur = self._execute("SELECT DISTINCT client_id FROM metering_events")
        return [r[0] for r in cur.fetchall() if r and r[0]]

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
                with open(self.path, 'r') as f:
                    self._cache = json.load(f)
                    return self._cache
            except Exception:
                pass
        self._cache = {}
        return self._cache
    
    def _save(self, data: Dict[str, Dict[str, Any]]):
        with open(self.path, 'w') as f:
            json.dump(data, f, indent=2)
        try:
            os.chmod(self.path, 0o600)
        except Exception:
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
    if SHARD_SIGNING_PUBLIC_KEY:
        if not os.path.exists(SHARD_SIGNING_PUBLIC_KEY):
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
                with open(item, 'r') as f:
                    keys.append(f.read())
            except Exception:
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

# ===== METERING & BILLING (with Access Release Token) =====
def generate_access_release_token(instruction_id: str, origin: str, destination: str) -> str:
    """
    Generate cryptographic Access Release Token (ART).
    Proves that reconstruction is cryptographically authorized.
    """
    if not node_id:
        get_node_id()
    timestamp = int(time.time())
    payload = f"{instruction_id}|{origin}|{destination}|{timestamp}|{node_id}"
    return sha256(payload.encode()).hexdigest()

def record_metering_event(instruction_id: str, client_id: str, access_release_token: Optional[str] = None):
    """
    Record billable event with cryptographic signature and Access Release Token.
    Immutable proof for billing disputes.
    Price: $0.02 per instruction reconstructed.
    """
    if not node_id:
        get_node_id()
    if access_release_token is None:
        access_release_token = generate_access_release_token(instruction_id, client_id, 'destination')
    event = {
        'instruction_id': instruction_id,
        'client_id': client_id,
        'timestamp': int(time.time() * 1000),
        'node_id': node_id,
        'event_type': 'instruction_reconstructed',
        'billable': True,
        'price_usd': 0.02,
        'access_release_token': access_release_token
    }
    
    # Cryptographic signature (proof of billing)
    event_str = json.dumps(event, sort_keys=True)
    event['signature'] = sha256(
        (event_str + node_id + str(event['timestamp'])).encode()
    ).hexdigest()
    
    # Persist metering event
    try:
        STORAGE_DB.record_metering(event)
        print(f'[METERING] [OK] Billable event: {instruction_id} (${event["price_usd"]}) [ART: {access_release_token[:16]}...]')
    except Exception as e:
        print(f'[METERING] [X] Failed to record: {e}')

def get_billing_report(client_id: str, start_time: int, end_time: int) -> Dict:
    """
    Generate billing report for client
    Returns: instruction count x $0.02
    """
    count = 0
    events = []
    try:
        events = STORAGE_DB.list_metering_events(client_id, start_time, end_time)
        for event in events:
            if event.get('billable', False):
                count += 1
    except Exception as e:
        print(f'[BILLING] Error reading metering: {e}')
    
    return {
        'client_id': client_id,
        'period_start': start_time,
        'period_end': end_time,
        'total_instructions': count,
        'price_per_instruction': 0.02,
        'amount_due_usd': round(count * 0.02, 2),
        'events': events[:10]  # Sample (first 10)
    }

# ===== UTILITY FUNCTIONS =====
def get_node_id() -> str:
    """Get or create unique node ID"""
    global node_id
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
    key = get_random_bytes(32)  # AES-256 key
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(payload_bytes)
    encrypted_blob = cipher.nonce + tag + ciphertext
    shares = Shamir.split(k, n, key)
    return encrypted_blob, shares

def reconstruct_from_sss(encrypted_blob: bytes, shares: List[Tuple[int, bytes]]) -> bytes:
    """Reconstruct payload from encrypted blob and k SSS shares."""
    if not SSS_AVAILABLE:
        raise RuntimeError("pycryptodome required for Shamir Secret Sharing")
    key = Shamir.combine(shares)
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

def print_status():
    """Display node status"""
    print('\n' + '='*47)
    print('  ONESEAM ENTERPRISE NODE STATUS')
    print('='*47)
    print(f'Node ID: {node_id[:16]}...')
    relay_status = 'Blind Relay ON' if BLIND_RELAY_ENABLED else 'Blind Relay OFF'
    print(f'Transport: {TRANSPORT_MODE} | Quorum: {DEFAULT_QUORUM_K}-of-{DEFAULT_QUORUM_N} | {relay_status}')
    print(f'SEAM Protocol: v1.0 (enabled)')
    shard_count = len(list_shards())
    manifest_count = len(list_manifest_records())
    print(f'Storage: db_backend={DB_BACKEND}')
    print(f'Shards: {shard_count}')
    print(f'Instructions: {manifest_count}')
    
    with neighbors_lock:
        count = len(neighbors)
        print(f'Network: {count} neighbors')
        if count == 0:
            print('  (no peers discovered yet)')
        else:
            for nid, info in list(neighbors.items())[:20]:
                ip = info.get('ip', '-')
                port = info.get('node_port', NODE_PORT)
                served = info.get('served_destinations') or []
                served_str = ','.join(served) if served else '-'
                region = info.get('region', '-')
                last = info.get('last_seen', '-')
                print(f'  - {nid[:8]}... @ {ip}:{port} | serves: {served_str} | region: {region} | seen {last}')

# ===== FINANCIAL INSTRUCTION =====
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
    """
    Create financial settlement instruction (legacy format)
    
    For SEAM-compliant instructions, use:
    - create_seam_payment_obligation()
    - create_seam_invoice()
    - create_seam_letter_of_credit()
    - create_seam_purchase_order()
    
    Args:
        payload: Settlement message (e.g., "SETTLE ORDER #12345")
        origin: Source institution ID
        destination: Target institution ID
        encryption_key: Optional AES-256 key
        quorum_k: Minimum shards for reconstruction (default: config or 2)
        quorum_n: Total shards (default: config or 3)
        jurisdiction: Legal jurisdiction (e.g., "EU", "BR")
        data_region: Data sovereignty region (e.g., "EU", "BR")
        compliance_frameworks: List of frameworks (e.g., ["GDPR", "LGPD"])
    
    Returns:
        Instruction dict with metadata
    """
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
    
    # Check if SEAM-compliant
    is_seam = SEAMValidator.is_seam_compliant(instr)
    
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
        'shard_indices': [s['index'] for s in (shard_dicts or [])],
        'seam_compliant': is_seam,
        'seam_type': instr.get('seam_type'),
        'seam_version': instr.get('seam_version')
    }
    
    # Log creation event
    log_entry = {
        'event': 'instruction_created',
        'instruction_id': instr['instruction_id'],
        'timestamp': instr['timestamp'],
        'node_id': node_id,
        'seam_compliant': is_seam
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
def reconstruct_with_quorum(instruction_id: str, threshold: Optional[int] = None,
                           access_release_token: Optional[str] = None) -> Optional[Dict]:
    """
    Byzantine fault-tolerant reconstruction (k-of-n).
    Supports both SSS (zero-knowledge) and legacy sharding.
    
    Args:
        instruction_id: Instruction to reconstruct
        threshold: Minimum shards needed (default: from manifest)
        access_release_token: Cryptographic ART for billing proof
    
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
        
        try:
            instr_json = reconstruct_instruction_from_shards(encrypted_b64, available_shards[:k])
            instruction = json.loads(instr_json)
        except Exception as e:
            print(f'[QUORUM] [X] SSS reconstruction failed: {e}')
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
            instruction = json.loads(instr_json)
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
    
    # Validate SEAM compliance if applicable
    if manifest.get('seam_compliant'):
        is_valid, error = SEAMValidator.validate(instruction)
        if is_valid:
            print(f'[QUORUM] [OK] SEAM validation passed (type: {instruction.get("seam_type")})')
        else:
            print(f'[QUORUM] [WARN] SEAM validation warning: {error}')
    
    # Generate ART if not provided
    if access_release_token is None:
        access_release_token = generate_access_release_token(
            instruction_id, instruction.get('origin', 'unknown'), manifest.get('destination', ''))
    
    # Record metering event with ART
    record_metering_event(instruction_id, instruction.get('origin', 'unknown'), access_release_token)
    
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
    
    capabilities = ['storage', 'reconstruction', 'routing', 'seam_v1']
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
            'capabilities': ['storage', 'reconstruction', 'routing', 'seam_v1'],
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

# ===== NETWORKING: TCP SERVER =====
async def start_p2p_server():
    """Async TCP server to receive requests from other nodes"""
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
    server = await asyncio.start_server(handle_client_async, host='', port=NODE_PORT, ssl=ssl_ctx)
    log_event('INFO', 'p2p_listen', port=NODE_PORT, tls=P2P_TLS_ENABLED)
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
                with neighbors_lock:
                    neighbors[msg['node_id']] = {
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
                'version': '2.0',
                'seam_version': '1.0',
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
    try:
        STORAGE_DB.close()
    except Exception:
        pass
    print('[SHUTDOWN] Node stopped.')
    raise SystemExit(0)

# ===== CLI OPERATIONS =====
def send_instruction():
    """CLI: Send new financial instruction"""
    print('\n' + '='*47)
    print('  NEW FINANCIAL INSTRUCTION')
    print('='*47)
    
    print('\nSelect instruction type:')
    print('  1. SEAM Payment Obligation')
    print('  2. SEAM Invoice')
    print('  3. SEAM Letter of Credit')
    print('  4. SEAM Purchase Order')
    print('  5. Legacy (free-form message)')
    
    choice = input('\nSelect (1-5): ').strip()
    
    origin = input('Origin institution ID: ').strip() or 'BANK_DEMO'
    destination = input('Destination institution ID: ').strip() or 'BANK_TARGET'
    
    # Optional encryption for all SEAM types (1-4) and Legacy (5)
    use_crypto = input('Encrypt? (y/n): ').strip().lower() == 'y'
    encryption_key = None
    if use_crypto:
        encryption_key = getpass('Encryption password: ')
    
    if choice == '1':
        # SEAM Payment Obligation
        amount = float(input('Amount: ').strip() or '0')
        currency = input('Currency (USD/EUR/BRL): ').strip().upper() or 'USD'
        due_days = int(input('Due in days (default 90): ').strip() or '90')
        due_date = int(time.time()) + (due_days * 24 * 3600)
        terms = input('Terms (optional): ').strip() or None
        
        instr = create_seam_payment_obligation(
            amount=amount,
            currency=currency,
            creditor=destination,
            debtor=origin,
            due_date=due_date,
            terms=terms
        )
        instr['origin'] = origin
        instr['destination'] = destination
        
    elif choice == '2':
        # SEAM Invoice
        amount = float(input('Amount: ').strip() or '0')
        currency = input('Currency (USD/EUR/BRL): ').strip().upper() or 'USD'
        invoice_number = input('Invoice number: ').strip() or f'INV-{int(time.time())}'
        due_days = int(input('Due in days (default 30): ').strip() or '30')
        due_date = int(time.time()) + (due_days * 24 * 3600)
        
        instr = create_seam_invoice(
            amount=amount,
            currency=currency,
            creditor=destination,
            debtor=origin,
            invoice_number=invoice_number,
            due_date=due_date
        )
        instr['origin'] = origin
        instr['destination'] = destination
        
    elif choice == '3':
        # SEAM Letter of Credit
        amount = float(input('Amount: ').strip() or '0')
        currency = input('Currency (USD/EUR/BRL): ').strip().upper() or 'USD'
        issuing_bank = input('Issuing bank: ').strip() or origin
        beneficiary_bank = input('Beneficiary bank: ').strip() or destination
        expiry_days = int(input('Expiry in days (default 180): ').strip() or '180')
        expiry_date = int(time.time()) + (expiry_days * 24 * 3600)
        terms = input('Terms: ').strip() or 'Payment upon presentation of documents'
        
        instr = create_seam_letter_of_credit(
            amount=amount,
            currency=currency,
            creditor=destination,
            debtor=origin,
            issuing_bank=issuing_bank,
            beneficiary_bank=beneficiary_bank,
            expiry_date=expiry_date,
            terms=terms
        )
        instr['origin'] = origin
        instr['destination'] = destination
        
    elif choice == '4':
        # SEAM Purchase Order
        amount = float(input('Amount: ').strip() or '0')
        currency = input('Currency (USD/EUR/BRL): ').strip().upper() or 'USD'
        po_number = input('PO number: ').strip() or f'PO-{int(time.time())}'
        delivery_days = int(input('Delivery in days (default 60): ').strip() or '60')
        delivery_date = int(time.time()) + (delivery_days * 24 * 3600)
        
        instr = create_seam_purchase_order(
            amount=amount,
            currency=currency,
            creditor=destination,
            debtor=origin,
            po_number=po_number,
            delivery_date=delivery_date,
            items=[{'description': 'As specified', 'quantity': 1}]
        )
        instr['origin'] = origin
        instr['destination'] = destination
        
    else:
        # Legacy
        payload = input('Settlement message: ').strip()
        if not payload:
            print('[!] Empty message. Cancelled.')
            return
        
        instr = create_financial_instruction(payload, origin, destination, encryption_key)
    
    print(f'\n[[OK]] Instruction created: {instr["instruction_id"]}')
    
    # Encrypt payload if requested (do not encrypt the entire instruction)
    if use_crypto and encryption_key and 'payload' in instr:
        if not instr.get('encrypted', False):
            instr['payload'] = encrypt_payload_aes256(instr['payload'], encryption_key)
            instr['encrypted'] = True
    
    # Display SEAM validation if applicable
    if SEAMValidator.is_seam_compliant(instr):
        print(f'[[OK]] SEAM-compliant: {instr.get("seam_type")}')
        print(f'    Amount: {instr.get("currency")} {instr.get("amount"):,.2f}')
        print(f'    Creditor: {instr.get("creditor")}')
        print(f'    Debtor: {instr.get("debtor")}')
    
    k, n = instr.get('quorum_k', 2), instr.get('quorum_n', 3)
    if not SSS_AVAILABLE:
        k = n
    instr_json = json.dumps(instr, ensure_ascii=False)
    
    if SSS_AVAILABLE:
        encrypted_b64, shard_dicts = shard_instruction(instr_json, k, n)
        manifest = create_instruction_manifest(instr, [], encrypted_payload_b64=encrypted_b64,
                                              shard_dicts=shard_dicts, quorum_k=k, quorum_n=n)
        manifest['shards'] = [f'{instr["instruction_id"]}_shard{s["index"]}_v{r+1}.json'
                             for s in shard_dicts for r in range(3)]
        distribute_shards_smart(shard_dicts, instr['instruction_id'], destination, manifest, k, n, use_sss=True)
    else:
        shards = split_text(instr_json, n)
        manifest = create_instruction_manifest(instr, shards, quorum_k=k, quorum_n=n)
        manifest['shards'] = [f'{instr["instruction_id"]}_shard{i+1}_v{r+1}.json'
                             for i in range(n) for r in range(3)]
        distribute_shards_smart(shards, instr['instruction_id'], destination, manifest, k, n, use_sss=False)
    
    print(f'\n[[OK]] Instruction dispatched to network')
    print(f'[i] Destination: {destination}')
    print(f'[i] Quorum: {k}-of-{n} shards required for reconstruction')

def monitor_instructions():
    """CLI: Monitor received instructions"""
    print('\n' + '='*47)
    print('  RECEIVED INSTRUCTIONS')
    print('='*47)
    
    manifests = list_manifest_records()
    
    if not manifests:
        print('[i] No instructions received yet.')
        return
    
    for m in manifests:
        instr_id = m['instruction_id']
        k = m.get('quorum_k', m.get('quorum_threshold', 2))
        n = m.get('quorum_n', m.get('total_shards', 3))
        shard_indices = m.get('shard_indices', list(range(1, n + 1)))
        
        # Count available shards (unique indices for SSS)
        seen = set()
        for shard_idx in shard_indices:
            for replica in range(1, 4):
                shard_name = f'{instr_id}_shard{shard_idx}_v{replica}.json'
                d = get_shard_record(shard_name)
                if d:
                    idx = d.get('index', shard_idx)
                    seen.add(idx)
                    break
        available = len(seen)
        
        status = '[OK] Ready' if available >= k else f'[PENDING] ({available}/{k})'
        seam_badge = f' [SEAM: {m.get("seam_type")}]' if m.get('seam_compliant') else ''
        
        print(f'{instr_id}: {status}{seam_badge}')
        print(f'  Origin: {m.get("origin")} -> Destination: {m.get("destination")}')
        print(f'  Encrypted: {m.get("encrypted", False)}')
        print()

def rebuild_instruction():
    """CLI: Reconstruct instruction with quorum"""
    print('\n' + '='*47)
    print('  RECONSTRUCT INSTRUCTION')
    print('='*47)
    
    manifests = list_manifest_records()
    
    if not manifests:
        print('[!] No instructions available.')
        return
    
    print('Available instructions:')
    for i, m in enumerate(sorted(manifests, key=lambda x: x['timestamp']), 1):
        seam_badge = f' [SEAM: {m.get("seam_type")}]' if m.get('seam_compliant') else ''
        print(f'  {i}. {m["instruction_id"]}{seam_badge}')
        print(f'     {m.get("origin")} -> {m.get("destination")}')
    
    try:
        choice = int(input('\nSelect instruction number: ').strip())
        manifest = sorted(manifests, key=lambda x: x['timestamp'])[choice - 1]
    except:
        print('[!] Invalid selection.')
        return
    
    instruction_id = manifest['instruction_id']
    k = manifest.get('quorum_k', manifest.get('quorum_threshold', 2))
    
    # Try dynamic collection if quorum not met locally
    collect_shards_dynamically(instruction_id, max_attempts=3)
    
    # Attempt reconstruction with quorum
    instr = reconstruct_with_quorum(instruction_id, threshold=k)
    
    if not instr:
        print('\n[[X]] Reconstruction failed. Waiting for more shards...')
        return
    
    # Decrypt if needed
    if instr.get('encrypted'):
        decrypt = input('\nDecrypt payload<- (y/n): ').strip().lower() == 'y'
        if decrypt:
            key = getpass('Decryption key: ')
            try:
                instr['payload'] = decrypt_payload_aes256(instr['payload'], key)
                print('[[OK]] Payload decrypted')
            except Exception as e:
                print(f'[[X]] Decryption failed: {e}')
    
    # Display
    print('\n' + '='*47)
    print('  RECONSTRUCTED INSTRUCTION')
    print('='*47)
    
    # Pretty print SEAM fields if applicable
    if SEAMValidator.is_seam_compliant(instr):
        print(f'\n[SEAM] Type: {instr.get("seam_type")}')
        print(f'[SEAM] Amount: {instr.get("currency")} {instr.get("amount"):,.2f}')
        print(f'[SEAM] Creditor: {instr.get("creditor")}')
        print(f'[SEAM] Debtor: {instr.get("debtor")}')
        if instr.get('due_date'):
            due_str = datetime.fromtimestamp(instr['due_date']).strftime('%Y-%m-%d')
            print(f'[SEAM] Due Date: {due_str}')
        if instr.get('terms'):
            print(f'[SEAM] Terms: {instr["terms"]}')
        print()
    
    print(json.dumps(instr, indent=2, ensure_ascii=False))

def audit_logs():
    """CLI: View audit trail"""
    print('\n' + '='*47)
    print('  AUDIT TRAIL')
    print('='*47)
    
    for manifest in list_manifest_records():
        try:
            seam_badge = f' [SEAM: {manifest.get("seam_type")}]' if manifest.get('seam_compliant') else ''
            print(f"\nInstruction: {manifest['instruction_id']}{seam_badge}")
            print(f"Origin: {manifest.get('origin')} -> Destination: {manifest.get('destination')}")
            
            for entry in manifest.get('log', []):
                print(f"  - {entry['event']}")
                print(f"    Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry['timestamp']))}")
                print(f"    Node: {entry.get('node_id', 'unknown')[:16]}...")
                print(f"    Signature: {entry.get('signature', '')[:24]}...")
                
        except Exception as e:
            print(f'[!] Error reading manifest: {e}')

def view_billing():
    """CLI: View billing report"""
    print('\n' + '='*47)
    print('  BILLING REPORT')
    print('='*47)
    
    client_id = input('Client ID (or press Enter for all): ').strip()
    
    # Last 30 days
    end_time = int(time.time())
    start_time = end_time - (30 * 24 * 3600)
    
    if client_id:
        report = get_billing_report(client_id, start_time, end_time)
        print(f"\nClient: {report['client_id']}")
        print(f"Instructions: {report['total_instructions']}")
        print(f"Amount Due: ${report['amount_due_usd']:.2f} USD")
    else:
        # All clients
        all_clients = set(STORAGE_DB.list_metering_clients())
        
        total_revenue = 0
        for cid in all_clients:
            report = get_billing_report(cid, start_time, end_time)
            print(f"\n{cid}:")
            print(f"  Instructions: {report['total_instructions']}")
            print(f"  Amount: ${report['amount_due_usd']:.2f}")
            total_revenue += report['amount_due_usd']
        
        print(f"\n{'='*40}")
        print(f"TOTAL REVENUE: ${total_revenue:.2f} USD")

# ===== CLI MENU =====
def cli_menu():
    """Interactive CLI menu"""
    while True:
        print('\n' + '='*47)
        print('  ONESEAM ENTERPRISE NODE')
        print('='*47)
        print('  1. Node Status')
        print('  2. Send Financial Instruction')
        print('  3. Monitor Received Instructions')
        print('  4. Collect Shards Dynamically')
        print('  5. Reconstruct Instruction')
        print('  6. Audit Logs')
        print('  7. Billing Report')
        print('  8. Exit')
        
        choice = input('\nSelect option: ').strip()
        
        if choice == '1':
            print_status()
        elif choice == '2':
            send_instruction()
        elif choice == '3':
            monitor_instructions()
        elif choice == '4':
            instruction_id = input('Instruction ID: ').strip()
            if instruction_id:
                collect_shards_dynamically(instruction_id)
        elif choice == '5':
            rebuild_instruction()
        elif choice == '6':
            audit_logs()
        elif choice == '7':
            view_billing()
        elif choice == '8':
            print('\n[SHUTDOWN] Stopping node...')
            raise SystemExit(0)
        else:
            print('[!] Invalid option.')

# ===== ENTERPRISE REST API =====
async def start_rest_api():
    """Start enterprise REST API server (aiohttp)"""
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
                    'scopes': legacy.get('scopes', ['instruction:write', 'instruction:read'])
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
            'service': 'Oneseam Enterprise Infrastructure',
            'version': '2.0.0',
            'seam_version': '1.0',
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
        status = 'ready' if ok else 'not_ready'
        return web.json_response({'status': status, 'reasons': reasons, 'request_id': request['request_id']}, status=200 if ok else 503)

    async def metrics(request):
        if not METRICS_ENABLED:
            return json_error(request, 404, 'metrics_disabled', 'Metrics disabled')
        return web.json_response({'request_id': request['request_id'], 'metrics': metrics_snapshot()})

    async def create_payment_obligation_api(request):
        await ensure_auth(request, required_scopes=['seam:write'], required_roles=['issuer', 'admin'])
        try:
            data = await request.json()
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = PaymentObligationRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        if Decimal(str(data['amount'])) <= 0:
            return json_error(request, 400, 'invalid_amount', 'Amount must be positive')
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        instr = create_seam_payment_obligation(
            amount=data['amount'],
            currency=data.get('currency', 'USD'),
            creditor=data['creditor'],
            debtor=data['debtor'],
            due_date=data.get('due_date'),
            terms=data.get('terms'),
            reference=data.get('reference'),
            interest_rate=data.get('interest_rate'),
            jurisdiction=data.get('jurisdiction')
        )
        instr['origin'] = request['client']['client_id']
        instr['destination'] = data['creditor']
        append_audit_event('api_seam_payment_obligation', request['client']['client_id'], instr['instruction_id'], request_id=request['request_id'])
        metric_inc('instructions_created_total')
        k, n = DEFAULT_QUORUM_K, DEFAULT_QUORUM_N
        if not SSS_AVAILABLE:
            k = n
        instr_json = json.dumps(instr)
        if SSS_AVAILABLE:
            encrypted_b64, shard_dicts = shard_instruction(instr_json, k, n)
            manifest = create_instruction_manifest(instr, [], encrypted_payload_b64=encrypted_b64,
                                                  shard_dicts=shard_dicts, quorum_k=k, quorum_n=n)
            manifest['shards'] = [f"{instr['instruction_id']}_shard{s['index']}_v{r+1}.json" for s in shard_dicts for r in range(3)]
            distribute_shards_smart(shard_dicts, instr['instruction_id'], data['creditor'], manifest, k, n, use_sss=True)
        else:
            shards = split_text(instr_json, n)
            manifest = create_instruction_manifest(instr, shards, quorum_k=k, quorum_n=n)
            manifest['shards'] = [f"{instr['instruction_id']}_shard{i+1}_v{r+1}.json" for i in range(n) for r in range(3)]
            distribute_shards_smart(shards, instr['instruction_id'], data['creditor'], manifest, k, n, use_sss=False)
        payload = {
            'instruction_id': instr['instruction_id'],
            'seam_type': instr['seam_type'],
            'status': 'dispatched',
            'amount': instr['amount'],
            'currency': instr['currency'],
            'quorum': f'{k}-of-{n}',
            'request_id': request['request_id']
        }
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 201)
        return web.json_response(payload, status=201)

    async def submit_instruction(request):
        await ensure_auth(request, required_scopes=['instruction:write'], required_roles=['issuer', 'admin'])
        try:
            data = await request.json()
        except Exception:
            return json_error(request, 400, 'invalid_payload', 'Invalid payload')
        if PYDANTIC_AVAILABLE:
            try:
                data = InstructionRequest.model_validate(data).model_dump()
            except ValidationError as e:
                return json_error(request, 400, 'invalid_payload', str(e))
        if not data.get('payload') or not data.get('destination'):
            return json_error(request, 400, 'missing_fields', 'Missing payload or destination')
        if len(data['payload']) > API_MAX_PAYLOAD_BYTES:
            return json_error(request, 413, 'payload_too_large', 'Payload too large')
        cached = idempotency_get(request['client']['client_id'], request.headers.get('Idempotency-Key', ''))
        if cached:
            return web.json_response(cached['payload'], status=cached['status'])
        instr = create_financial_instruction(
            payload=data['payload'],
            origin=request['client']['client_id'],
            destination=data['destination'],
            encryption_key=data.get('encryption_key'),
            jurisdiction=data.get('jurisdiction'),
            data_region=data.get('data_region'),
            compliance_frameworks=data.get('compliance_frameworks')
        )
        k, n = DEFAULT_QUORUM_K, DEFAULT_QUORUM_N
        if not SSS_AVAILABLE:
            k = n
        instr_json = json.dumps(instr)
        if SSS_AVAILABLE:
            encrypted_b64, shard_dicts = shard_instruction(instr_json, k, n)
            manifest = create_instruction_manifest(instr, [], encrypted_payload_b64=encrypted_b64,
                                                  shard_dicts=shard_dicts, quorum_k=k, quorum_n=n)
            manifest['shards'] = [f"{instr['instruction_id']}_shard{s['index']}_v{r+1}.json" for s in shard_dicts for r in range(3)]
            distribute_shards_smart(shard_dicts, instr['instruction_id'], data['destination'], manifest, k, n, use_sss=True)
        else:
            shards = split_text(instr_json, n)
            manifest = create_instruction_manifest(instr, shards, quorum_k=k, quorum_n=n)
            manifest['shards'] = [f"{instr['instruction_id']}_shard{i+1}_v{r+1}.json" for i in range(n) for r in range(3)]
            distribute_shards_smart(shards, instr['instruction_id'], data['destination'], manifest, k, n, use_sss=False)
        append_audit_event('api_instruction_submit', request['client']['client_id'], instr['instruction_id'], request_id=request['request_id'])
        metric_inc('instructions_created_total')
        payload = {
            'instruction_id': instr['instruction_id'],
            'status': 'dispatched',
            'shards': n * 3,
            'quorum': f'{k}-of-{n}',
            'request_id': request['request_id']
        }
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if idem_key:
            idempotency_put(request['client']['client_id'], idem_key, payload, 201)
        return web.json_response(payload, status=201)

    async def get_instruction(request):
        await ensure_auth(request, required_scopes=['instruction:read'], required_roles=['receiver', 'auditor', 'admin'])
        instruction_id = request.match_info.get('instruction_id')
        await collect_shards_dynamically_async(instruction_id, max_attempts=2)
        result = reconstruct_with_quorum(instruction_id)
        if result:
            response = {
                'instruction_id': instruction_id,
                'status': 'reconstructed',
                'quorum': 'achieved',
                'request_id': request['request_id']
            }
            if SEAMValidator.is_seam_compliant(result):
                response['seam_compliant'] = True
                response['seam_type'] = result.get('seam_type')
                response['amount'] = result.get('amount')
                response['currency'] = result.get('currency')
                response['creditor'] = result.get('creditor')
                response['debtor'] = result.get('debtor')
            else:
                response['payload'] = result.get('payload') if not result.get('encrypted') else '[encrypted]'
            return web.json_response(response)
        return web.json_response({
            'instruction_id': instruction_id,
            'status': 'pending',
            'quorum': 'not_achieved',
            'request_id': request['request_id']
        }, status=202)

    async def billing(request):
        await ensure_auth(request, required_scopes=['billing:read'], required_roles=['auditor', 'admin'])
        start = int(request.query.get('start', 0))
        end = int(request.query.get('end', time.time()))
        report = get_billing_report(request['client']['client_id'], start, end)
        report['request_id'] = request['request_id']
        return web.json_response(report)

    app.add_routes([
        web.get('/health', health),
        web.get('/ready', ready),
        web.get('/metrics', metrics),
        web.post('/v1/seam/payment_obligation', create_payment_obligation_api),
        web.post('/v1/instructions', submit_instruction),
        web.get('/v1/instructions/{instruction_id}', get_instruction),
        web.get('/v1/billing', billing),
    ])

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
  ONESEAM ENTERPRISE v2.0
  Resilient Financial Settlement Messaging
  SEAM Protocol v1.0 (enabled)
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
        try_upnp()

        print(f'[INIT] Node ID: {node_id[:16]}...')
        print(f'[INIT] Storage: db_backend={DB_BACKEND}')
        print(f'[INIT] SEAM Protocol: v1.0')
        print(f'[INIT] Supported types: PAYMENT_OBLIGATION, INVOICE, LETTER_OF_CREDIT, PURCHASE_ORDER')

        tasks = [
            asyncio.create_task(broadcast_presence_async()),
            asyncio.create_task(listen_broadcast_async()),
            asyncio.create_task(start_p2p_server()),
            asyncio.create_task(prune_neighbors_async()),
            asyncio.create_task(bootstrap_seeds())
        ]
        if BLIND_RELAY_ENABLED:
            tasks.append(asyncio.create_task(relay_worker()))
            print('[INIT] Blind Relay (Repasse Cego) enabled')

        if len(sys.argv) > 1 and sys.argv[1] == 'api':
            print('[MODE] Starting in API mode (REST server)')
            await start_rest_api()
            await asyncio.Event().wait()
        else:
            print('[MODE] Starting in CLI mode')
            print('[INFO] For API mode, run: python oneseam_enterprise.py api')
            await asyncio.to_thread(cli_menu)

    asyncio.run(main_async())
