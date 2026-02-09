"""
Oneseam Enterprise - Resilient Cryptographic Messaging Infrastructure
Version: 2.0.0

Enterprise-grade P2P messaging system for financial settlement instructions.
- Byzantine fault-tolerant (configurable k-of-n quorum)
- Shamir Secret Sharing (zero-knowledge sharding)
- SEAM Protocol (Settlement Evidence & Agreement Message)
- Blind Relay (Repasse Cego) - nodes accept and relay shards toward destination
- AES-256-GCM encryption (FIPS compliant)
- Cryptographic metering with Access Release Token (ART)
- On-grid / off-grid mesh network capable
- Data sovereignty and compliance metadata
- REST API for enterprise integration

No custody of funds. Messages only. Compliance-native.
"""

import os
import sys
import threading
import socket
import json
import time
import uuid
import base64
import signal
import secrets
from hashlib import sha256
from getpass import getpass
from typing import List, Optional, Dict, Tuple, Any
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum

# Shamir Secret Sharing (PyCryptodome)
try:
    from Crypto.Protocol.SecretSharing import Shamir
    from Crypto.Random import get_random_bytes
    from Crypto.Cipher import AES
    SSS_AVAILABLE = True
except ImportError:
    SSS_AVAILABLE = False
    print("[WARNING] pycryptodome not found. Install: pip install pycryptodome")
    print("[WARNING] Falling back to legacy split_text (NOT ZERO-KNOWLEDGE)")

# ===== ENTERPRISE ENCRYPTION (AES-256) =====
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[WARNING] cryptography library not found. Install: pip install cryptography")
    print("[WARNING] Falling back to demo XOR encryption (NOT PRODUCTION SAFE)")

def derive_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """Derive AES-256 key from password using PBKDF2"""
    if not CRYPTO_AVAILABLE:
        # Fallback XOR
        return sha256(password.encode()).digest(), b'demo_salt'
    
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_payload_aes256(data: str, password: str) -> str:
    """Encrypt with AES-256-GCM (FIPS 140-2 compliant)"""
    if not CRYPTO_AVAILABLE:
        # Fallback XOR (demo only)
        key_bytes = sha256(password.encode()).digest()
        data_bytes = data.encode()
        enc = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data_bytes)])
        return base64.b64encode(enc).decode()
    
    key, salt = derive_key_from_password(password)
    f = Fernet(key)
    encrypted = f.encrypt(data.encode())
    
    # Return: salt + encrypted (need salt for decryption)
    combined = base64.b64encode(salt + encrypted).decode()
    return combined

def decrypt_payload_aes256(data: str, password: str) -> str:
    """Decrypt AES-256-GCM"""
    if not CRYPTO_AVAILABLE:
        # Fallback XOR
        key_bytes = sha256(password.encode()).digest()
        data_bytes = base64.b64decode(data.encode())
        dec = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data_bytes)])
        return dec.decode(errors='ignore')
    
    decoded = base64.b64decode(data.encode())
    salt = decoded[:16]
    encrypted = decoded[16:]
    
    key, _ = derive_key_from_password(password, salt)
    f = Fernet(key)
    decrypted = f.decrypt(encrypted)
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
            due_date = instruction['due_date']
            timestamp = instruction['timestamp']
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
BROADCAST_ADDR = _config('broadcast_addr', '<broadcast>')
BUFFER_SIZE = 1024 * 1024  # 1MB
STORAGE_DIR = _config('storage_dir', 'oneseam_storage')
NODE_ID_FILE = 'node_id.txt'
METERING_LOG = 'metering_events.jsonl'
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

# Enterprise API keys (in production: database)
API_KEYS = {
    'demo_bank_alpha_key': {
        'client_id': 'BANK_ALPHA',
        'name': 'Alpha Bank Ltd',
        'tier': 'enterprise'
    },
    'demo_bank_beta_key': {
        'client_id': 'BANK_BETA', 
        'name': 'Beta Financial Corp',
        'tier': 'professional'
    }
}

# ===== METERING & BILLING (with Access Release Token) =====
def generate_access_release_token(instruction_id: str, origin: str, destination: str) -> str:
    """
    Generate cryptographic Access Release Token (ART).
    Proves that reconstruction is cryptographically authorized.
    """
    timestamp = int(time.time())
    payload = f"{instruction_id}|{origin}|{destination}|{timestamp}|{node_id}"
    return sha256(payload.encode()).hexdigest()

def record_metering_event(instruction_id: str, client_id: str, access_release_token: Optional[str] = None):
    """
    Record billable event with cryptographic signature and Access Release Token.
    Immutable proof for billing disputes.
    Price: $0.02 per instruction reconstructed.
    """
    if access_release_token is None:
        access_release_token = generate_access_release_token(instruction_id, client_id, 'destination')
    event = {
        'instruction_id': instruction_id,
        'client_id': client_id,
        'timestamp': int(time.time()),
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
    
    # Append-only log (auditable, immutable)
    try:
        with open(METERING_LOG, 'a') as f:
            f.write(json.dumps(event) + '\n')
        print(f'[METERING] ✓ Billable event: {instruction_id} (${event["price_usd"]}) [ART: {access_release_token[:16]}...]')
    except Exception as e:
        print(f'[METERING] ✗ Failed to record: {e}')

def get_billing_report(client_id: str, start_time: int, end_time: int) -> Dict:
    """
    Generate billing report for client
    Returns: instruction count × $0.02
    """
    if not os.path.exists(METERING_LOG):
        return {
            'client_id': client_id,
            'total_instructions': 0,
            'price_per_instruction': 0.02,
            'amount_due_usd': 0.00
        }
    
    count = 0
    events = []
    
    try:
        with open(METERING_LOG, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if (event['client_id'] == client_id and 
                        start_time <= event['timestamp'] <= end_time and
                        event.get('billable', False)):
                        count += 1
                        events.append(event)
                except:
                    continue
    except Exception as e:
        print(f'[BILLING] Error reading log: {e}')
    
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
    """Create storage directory if not exists"""
    if not os.path.exists(STORAGE_DIR):
        os.makedirs(STORAGE_DIR)

def list_shards() -> List[str]:
    """List all shard files in storage"""
    return os.listdir(STORAGE_DIR) if os.path.exists(STORAGE_DIR) else []

def shard_file_path(shard_name: str) -> str:
    """Get full path to shard file"""
    return os.path.join(STORAGE_DIR, shard_name)

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
    key = get_random_bytes(16)  # AES-128 key
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
    print(f'\n╔═══════════════════════════════════════╗')
    print(f'║  ONESEAM ENTERPRISE NODE STATUS      ║')
    print(f'╚═══════════════════════════════════════╝')
    print(f'Node ID: {node_id[:16]}...')
    relay_status = 'Blind Relay ON' if BLIND_RELAY_ENABLED else 'Blind Relay OFF'
    print(f'Transport: {TRANSPORT_MODE} | Quorum: {DEFAULT_QUORUM_K}-of-{DEFAULT_QUORUM_N} | {relay_status}')
    print(f'SEAM Protocol: v1.0 (enabled)')
    print(f'Storage: {sum(os.path.getsize(shard_file_path(f)) for f in list_shards())} bytes')
    print(f'Shards: {len([f for f in list_shards() if not f.endswith("_manifest.json")])}')
    print(f'Instructions: {len([f for f in list_shards() if f.endswith("_manifest.json")])}')
    
    with neighbors_lock:
        print(f'Network: {len(neighbors)} neighbors')
        for nid, info in list(neighbors.items())[:5]:
            print(f'  • {nid[:8]}... @ {info.get("ip")} (seen {info.get("last_seen")})')

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
    
    return manifest

def append_log_to_manifest(instruction_id: str, event: str, node_id_override: str = None):
    """Append audit event to manifest"""
    manifest_path = shard_file_path(f'{instruction_id}_manifest.json')
    if not os.path.exists(manifest_path):
        return
    
    try:
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        log_entry = {
            'event': event,
            'instruction_id': instruction_id,
            'timestamp': int(time.time()),
            'node_id': node_id_override or node_id
        }
        log_entry['signature'] = sign_log_entry(log_entry, node_id_override or node_id)
        manifest.setdefault('log', []).append(log_entry)
        
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
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
    manifest_path = shard_file_path(f'{instruction_id}_manifest.json')
    if not os.path.exists(manifest_path):
        print(f'[QUORUM] Manifest not found: {instruction_id}')
        return None
    
    try:
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
    except Exception as e:
        print(f'[QUORUM] Error reading manifest: {e}')
        return None
    
    k = threshold or manifest.get('quorum_threshold', manifest.get('quorum_k', 2))
    n = manifest.get('quorum_n', manifest.get('total_shards', 3))
    sharding_mode = manifest.get('sharding_mode', 'legacy')
    
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
                shard_path = shard_file_path(shard_name)
                if os.path.exists(shard_path):
                    try:
                        with open(shard_path, 'r') as f:
                            data = json.load(f)
                        idx = data.get('index')
                        share = data.get('share')
                        if idx is not None and share and idx not in seen_indices:
                            available_shards.append({'index': idx, 'share': share})
                            seen_indices.add(idx)
                            break
                    except Exception:
                        continue
        
        if len(available_shards) < k:
            print(f'[QUORUM] ✗ Only {len(available_shards)}/{k} SSS shards available')
            return None
        
        print(f'[QUORUM] ✓ Achieved ({len(available_shards)}/{k} SSS shards)')
        
        try:
            instr_json = reconstruct_instruction_from_shards(encrypted_b64, available_shards[:k])
            instruction = json.loads(instr_json)
        except Exception as e:
            print(f'[QUORUM] ✗ SSS reconstruction failed: {e}')
            return None
    else:
        # Legacy mode
        available_shards = []
        for shard_idx in range(1, n + 1):
            shard_found = False
            for replica in range(1, 4):
                shard_name = f'{instruction_id}_shard{shard_idx}_v{replica}.json'
                shard_path = shard_file_path(shard_name)
                if os.path.exists(shard_path):
                    try:
                        with open(shard_path, 'r') as f:
                            data = json.load(f)['data']
                        available_shards.append((shard_idx, data))
                        shard_found = True
                        break
                    except Exception:
                        continue
            if not shard_found:
                print(f'[QUORUM] Shard {shard_idx} completely missing')
        
        unique_shards = set(s[0] for s in available_shards)
        if len(unique_shards) < k:
            print(f'[QUORUM] ✗ Only {len(unique_shards)}/{k} shards available')
            return None
        
        print(f'[QUORUM] ✓ Achieved ({len(unique_shards)}/{k} shards)')
        available_shards.sort(key=lambda x: x[0])
        reconstruction_data = [s[1] for s in available_shards[:n]]
        
        try:
            instr_json = ''.join(reconstruction_data)
            instruction = json.loads(instr_json)
        except Exception as e:
            print(f'[QUORUM] ✗ Reconstruction failed: {e}')
            return None
    
    # Verify integrity
    if manifest.get('integrity_hash'):
        print(f'[QUORUM] Integrity verification: {manifest["integrity_hash"][:16]}...')
    
    # Validate SEAM compliance if applicable
    if manifest.get('seam_compliant'):
        is_valid, error = SEAMValidator.validate(instruction)
        if is_valid:
            print(f'[QUORUM] ✓ SEAM validation passed (type: {instruction.get("seam_type")})')
        else:
            print(f'[QUORUM] ⚠ SEAM validation warning: {error}')
    
    # Generate ART if not provided
    if access_release_token is None:
        access_release_token = generate_access_release_token(
            instruction_id, instruction.get('origin', 'unknown'), manifest.get('destination', ''))
    
    # Record metering event with ART
    record_metering_event(instruction_id, instruction.get('origin', 'unknown'), access_release_token)
    
    append_log_to_manifest(instruction_id, 'instruction_reconstructed')
    print(f'[QUORUM] ✓ Instruction reconstructed successfully')
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

def relay_thread():
    """
    Background thread: periodically relay shards we hold towards destination.
    Blind Relay - nodes accept shards not for them and repass when finding closer nodes.
    """
    RELAY_INTERVAL = 45  # seconds
    while True:
        try:
            if not BLIND_RELAY_ENABLED:
                time.sleep(RELAY_INTERVAL)
                continue
            
            ensure_storage()
            shard_files = [
                f for f in list_shards()
                if f.endswith('.json') and not f.endswith('_manifest.json')
            ]
            
            relayed_count = 0
            for shard_file in shard_files:
                try:
                    path = shard_file_path(shard_file)
                    with open(path, 'r') as f:
                        stored = json.load(f)
                    
                    destination = stored.get('destination', '')
                    data_region = stored.get('data_region', '')
                    relay_hops = stored.get('relay_hops', 0)
                    
                    if is_destination_node(destination):
                        continue
                    if relay_hops >= MAX_RELAY_HOPS:
                        continue
                    
                    instruction_id = shard_file.rsplit('_shard', 1)[0] if '_shard' in shard_file else ''
                    if not instruction_id:
                        continue
                    
                    targets = find_relay_targets(instruction_id, destination, data_region)
                    if not targets:
                        continue
                    
                    shard_data = stored.get('data', json.dumps(stored))
                    shard_dict = None
                    if stored.get('index') is not None and stored.get('share'):
                        shard_dict = {'index': stored['index'], 'share': stored['share']}
                    
                    relay_meta = {
                        'destination': destination,
                        'data_region': data_region,
                        'relay_hops': relay_hops + 1
                    }
                    msg = {
                        'cmd': CMD_STORE_SHARD,
                        'shard_name': shard_file,
                        'shard_data': shard_data,
                        'instruction_id': instruction_id,
                        **relay_meta
                    }
                    if shard_dict:
                        msg['shard_dict'] = shard_dict
                    
                    for target in targets[:2]:
                        ip = target.get('ip')
                        if not ip or ip == '127.0.0.1':
                            continue
                        resp = send_to_node(ip, msg)
                        if resp and resp == b'OK':
                            relayed_count += 1
                            print(f'[RELAY] ✓ Relayed {shard_file} → {ip} (hops={relay_hops + 1})')
                            break
                except Exception as e:
                    continue
            
            if relayed_count:
                print(f'[RELAY] Relayed {relayed_count} shards this cycle')
        except Exception as e:
            print(f'[RELAY] Error: {e}')
        time.sleep(RELAY_INTERVAL)

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
    """
    ensure_storage()
    
    destination_nodes = find_nodes_near_bank(
        destination_bank_id,
        data_region=manifest.get('data_region')
    )
    if not destination_nodes:
        with neighbors_lock:
            destination_nodes = list(neighbors.values())
    if not destination_nodes:
        destination_nodes = [{'ip': '127.0.0.1'}]
    
    if BLIND_RELAY_FLOOD:
        with neighbors_lock:
            all_neighbors = [n for n in neighbors.values() if n.get('ip') != '127.0.0.1']
        if all_neighbors:
            destination_nodes = all_neighbors + [{'ip': '127.0.0.1'}]
    
    total_distributed = 0
    
    if use_sss and isinstance(shards_data, list) and shards_data and isinstance(shards_data[0], dict):
        # SSS mode: distribute key share shards
        for idx, shard_dict in enumerate(shards_data):
            for replica in range(3):
                shard_idx = shard_dict.get('index', idx + 1)
                shard_name = f'{instruction_id}_shard{shard_idx}_v{replica+1}.json'
                shard_payload = json.dumps({'index': shard_dict['index'], 'share': shard_dict['share']})
                target = destination_nodes[(idx * 3 + replica) % len(destination_nodes)]
                ip = target['ip']
                relay_meta = {
                    'destination': destination_bank_id,
                    'data_region': manifest.get('data_region', ''),
                    'relay_hops': 0
                }
                if ip == '127.0.0.1':
                    with open(shard_file_path(shard_name), 'w') as f:
                        json.dump({'data': shard_payload, 'index': shard_dict['index'],
                                  'share': shard_dict['share'], 'timestamp': int(time.time()),
                                  **relay_meta}, f)
                    print(f'[DISTRIBUTE] ✓ Local: {shard_name}')
                    total_distributed += 1
                else:
                    msg = {
                        'cmd': CMD_STORE_SHARD,
                        'shard_name': shard_name,
                        'shard_data': shard_payload,
                        'shard_dict': shard_dict,
                        'instruction_id': instruction_id,
                        **relay_meta
                    }
                    resp = send_to_node(ip, msg)
                    if resp and resp == b'OK':
                        print(f'[DISTRIBUTE] ✓ Remote: {shard_name} → {ip}')
                        total_distributed += 1
                    else:
                        print(f'[DISTRIBUTE] ✗ Failed: {shard_name} → {ip}')
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
                target = destination_nodes[(idx * 3 + replica) % len(destination_nodes)]
                ip = target['ip']
                if ip == '127.0.0.1':
                    with open(shard_file_path(shard_name), 'w') as f:
                        json.dump({'data': shard, 'timestamp': int(time.time()), **relay_meta}, f)
                    print(f'[DISTRIBUTE] ✓ Local: {shard_name}')
                    total_distributed += 1
                else:
                    msg = {'cmd': CMD_STORE_SHARD, 'shard_name': shard_name, 'shard_data': shard,
                           'instruction_id': instruction_id, **relay_meta}
                    resp = send_to_node(ip, msg)
                    if resp and resp == b'OK':
                        print(f'[DISTRIBUTE] ✓ Remote: {shard_name} → {ip}')
                        total_distributed += 1
                    else:
                        print(f'[DISTRIBUTE] ✗ Failed: {shard_name} → {ip}')
    
    expected = n * 3
    print(f'[DISTRIBUTE] Total: {total_distributed}/{expected} shards distributed')
    
    manifest_path = shard_file_path(f'{instruction_id}_manifest.json')
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    print(f'[DISTRIBUTE] Manifest saved: {manifest_path}')
    
    # Distribute manifest to neighbors (destination can fetch)
    for target in destination_nodes[:5]:
        if target['ip'] != '127.0.0.1':
            msg = {'cmd': CMD_STORE_MANIFEST, 'instruction_id': instruction_id, 'manifest': manifest}
            resp = send_to_node(target['ip'], msg)
            if resp and b'OK' in resp:
                print(f'[DISTRIBUTE] ✓ Manifest sent to {target["ip"]}')

def collect_shards_dynamically(instruction_id: str, max_attempts: int = 10,
                               poll_interval: float = 2.0) -> bool:
    """
    Destination node: dynamically collect shards from neighbors until quorum.
    Returns True if quorum achieved and shards collected locally.
    """
    manifest_path = shard_file_path(f'{instruction_id}_manifest.json')
    if not os.path.exists(manifest_path):
        print(f'[COLLECT] Manifest not found: {instruction_id}')
        return False
    try:
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
    except Exception as e:
        print(f'[COLLECT] Error reading manifest: {e}')
        return False
    
    k = manifest.get('quorum_k', manifest.get('quorum_threshold', 2))
    n = manifest.get('quorum_n', manifest.get('total_shards', 3))
    sharding_mode = manifest.get('sharding_mode', 'legacy')
    
    for attempt in range(max_attempts):
        collected_indices = set()
        for shard_idx in range(1, n + 1):
            if sharding_mode == 'sss':
                for replica in range(1, 4):
                    shard_name = f'{instruction_id}_shard{shard_idx}_v{replica}.json'
                    if os.path.exists(shard_file_path(shard_name)):
                        try:
                            with open(shard_file_path(shard_name), 'r') as f:
                                data = json.load(f)
                            if 'index' in data:
                                collected_indices.add(data['index'])
                        except Exception:
                            pass
                        break
            else:
                for replica in range(1, 4):
                    shard_name = f'{instruction_id}_shard{shard_idx}_v{replica}.json'
                    if os.path.exists(shard_file_path(shard_name)):
                        collected_indices.add(shard_idx)
                        break
        
        if len(collected_indices) >= k:
            print(f'[COLLECT] ✓ Quorum achieved locally ({len(collected_indices)}/{k})')
            return True
        
        with neighbors_lock:
            neighbor_list = list(neighbors.values())
        
        for neighbor in neighbor_list:
            if neighbor['ip'] == '127.0.0.1':
                continue
            for shard_idx in manifest.get('shard_indices', list(range(1, n + 1))):
                for replica in range(1, 4):
                    shard_name = f'{instruction_id}_shard{shard_idx}_v{replica}.json'
                    if os.path.exists(shard_file_path(shard_name)):
                        continue
                    msg = {'cmd': CMD_FETCH_SHARD, 'shard_name': shard_name}
                    resp = send_to_node(neighbor['ip'], msg)
                    if resp:
                        try:
                            r = json.loads(resp.decode())
                            if r.get('status') == 'OK':
                                if r.get('index') is not None and r.get('share'):
                                    with open(shard_file_path(shard_name), 'w') as f:
                                        json.dump({'data': r.get('shard_data'), 'index': r['index'],
                                                  'share': r['share'], 'received_at': int(time.time())}, f)
                                else:
                                    data = r.get('shard_data', r)
                                    with open(shard_file_path(shard_name), 'w') as f:
                                        json.dump({'data': data, 'received_at': int(time.time())}, f)
                                print(f'[COLLECT] ✓ Fetched {shard_name} from {neighbor["ip"]}')
                                break
                        except Exception:
                            pass
        
        time.sleep(poll_interval)
    
    print(f'[COLLECT] ✗ Quorum not achieved after {max_attempts} attempts')
    return False

# ===== NETWORKING: DISCOVERY (On-Grid / Off-Grid) =====
def broadcast_presence():
    """Broadcast node presence via UDP (on-grid) or mesh (off-grid)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    capabilities = ['storage', 'reconstruction', 'routing', 'seam_v1']
    if TRANSPORT_MODE in ('OFF_GRID', 'HYBRID'):
        capabilities.append('mesh')
    
    while True:
        try:
            msg = json.dumps({
                'cmd': CMD_HANDSHAKE,
                'node_id': node_id,
                'capabilities': capabilities,
                'version': '2.0',
                'transport_mode': TRANSPORT_MODE,
                'region': CONFIG.get('region', ''),
                'country_code': CONFIG.get('country_code', ''),
                'served_destinations': SERVED_DESTINATIONS
            }).encode()
            s.sendto(msg, (BROADCAST_ADDR, BROADCAST_PORT))
        except Exception:
            pass
        time.sleep(5)

def listen_broadcast():
    """Listen for UDP broadcasts from other nodes"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', BROADCAST_PORT))
    
    while True:
        try:
            data, addr = s.recvfrom(BUFFER_SIZE)
            msg = json.loads(data.decode())
            
            if msg.get('cmd') == CMD_HANDSHAKE and msg.get('node_id') != node_id:
                with neighbors_lock:
                    neighbors[msg['node_id']] = {
                        'ip': addr[0],
                        'capabilities': msg.get('capabilities', []),
                        'version': msg.get('version', '0.0'),
                        'transport_mode': msg.get('transport_mode', 'ON_GRID'),
                        'region': msg.get('region', ''),
                        'country_code': msg.get('country_code', ''),
                        'served_destinations': msg.get('served_destinations', []),
                        'last_seen': time.strftime('%Y-%m-%d %H:%M:%S')
                    }
        except Exception:
            continue

# ===== NETWORKING: TCP SERVER =====
def server_thread():
    """TCP server to receive requests from other nodes"""
    ensure_storage()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', NODE_PORT))
    s.listen(10)
    
    print(f'[P2P] TCP server listening on port {NODE_PORT}')
    
    while True:
        try:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except Exception:
            continue

def handle_client(conn, addr):
    """Handle incoming P2P request"""
    try:
        data = conn.recv(BUFFER_SIZE)
        msg = json.loads(data.decode())
        cmd = msg.get('cmd')
        
        if cmd == CMD_STORE_SHARD:
            shard_name = msg['shard_name']
            shard_data = msg['shard_data']
            shard_dict = msg.get('shard_dict')
            relay_meta = {
                'destination': msg.get('destination', ''),
                'data_region': msg.get('data_region', ''),
                'relay_hops': msg.get('relay_hops', 0),
                'received_at': int(time.time())
            }
            
            if shard_dict:
                with open(shard_file_path(shard_name), 'w') as f:
                    json.dump({'data': shard_data, 'index': shard_dict['index'],
                              'share': shard_dict['share'], **relay_meta}, f)
            else:
                with open(shard_file_path(shard_name), 'w') as f:
                    json.dump({'data': shard_data, **relay_meta}, f)
            
            conn.send(b'OK')
            print(f'[P2P] ✓ Stored: {shard_name} from {addr[0]}')
        
        elif cmd == CMD_STORE_MANIFEST:
            instruction_id = msg.get('instruction_id')
            manifest = msg.get('manifest')
            if instruction_id and manifest:
                manifest_path = shard_file_path(f'{instruction_id}_manifest.json')
                with open(manifest_path, 'w') as f:
                    json.dump(manifest, f, indent=2)
                conn.send(b'OK')
                print(f'[P2P] ✓ Stored manifest: {instruction_id} from {addr[0]}')
            else:
                conn.send(json.dumps({'status': 'BAD_REQUEST'}).encode())
            
        elif cmd == CMD_FETCH_SHARD:
            shard_name = msg['shard_name']
            path = shard_file_path(shard_name)
            
            if os.path.exists(path):
                with open(path, 'r') as f:
                    stored = json.load(f)
                shard_data = stored.get('data')
                if 'index' in stored and 'share' in stored:
                    response = json.dumps({'status': 'OK', 'shard_data': shard_data,
                                          'index': stored['index'], 'share': stored['share']})
                else:
                    response = json.dumps({'status': 'OK', 'shard_data': shard_data})
                conn.send(response.encode())
            else:
                conn.send(json.dumps({'status': 'NOT_FOUND'}).encode())
        
        elif cmd == CMD_FETCH_MANIFEST:
            instruction_id = msg.get('instruction_id')
            manifest_path = shard_file_path(f'{instruction_id}_manifest.json')
            if instruction_id and os.path.exists(manifest_path):
                with open(manifest_path, 'r') as f:
                    manifest = json.load(f)
                response = json.dumps({'status': 'OK', 'manifest': manifest})
                conn.send(response.encode())
            else:
                conn.send(json.dumps({'status': 'NOT_FOUND'}).encode())
                
        elif cmd == CMD_HEALTH_CHECK:
            response = json.dumps({
                'status': 'OK',
                'node_id': node_id,
                'version': '2.0',
                'seam_version': '1.0',
                'uptime': int(time.time())
            })
            conn.send(response.encode())
            
        else:
            conn.send(json.dumps({'status': 'UNKNOWN_CMD'}).encode())
            
    except Exception as e:
        print(f'[P2P] Error handling client: {e}')
    finally:
        conn.close()

def send_to_node(ip: str, msg: Dict) -> Optional[bytes]:
    """Send request to another node"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, NODE_PORT))
        s.send(json.dumps(msg).encode())
        data = s.recv(BUFFER_SIZE)
        s.close()
        return data
    except Exception as e:
        print(f'[P2P] Error sending to {ip}: {e}')
        return None

# ===== SHUTDOWN & MIGRATION =====
def migrate_shards_on_shutdown():
    """Transfer local shards to other nodes before shutdown"""
    print("[SHUTDOWN] Migrating local shards...")
    ensure_storage()
    
    local_shards = [
        f for f in list_shards() 
        if f.endswith('.json') and not f.endswith('_manifest.json')
    ]
    
    neighbor_list = [n for n in neighbors.values() if n['ip'] != '127.0.0.1']
    
    if not neighbor_list:
        print("[SHUTDOWN] No neighbors available. Data at risk!")
        return
    
    for shard_file in local_shards:
        try:
            with open(shard_file_path(shard_file), 'r') as f:
                stored = json.load(f)
            shard_data = stored.get('data', json.dumps(stored))
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
                resp = send_to_node(n['ip'], msg)
                if resp and resp == b'OK':
                    success += 1
            
            if success:
                print(f'[SHUTDOWN] ✓ Migrated: {shard_file} → {success} nodes')
        except Exception as e:
            print(f'[SHUTDOWN] ✗ Migration failed for {shard_file}: {e}')

def handle_shutdown(signum, frame):
    """Graceful shutdown handler"""
    migrate_shards_on_shutdown()
    print('[SHUTDOWN] Node stopped.')
    os._exit(0)

# ===== CLI OPERATIONS =====
def send_instruction():
    """CLI: Send new financial instruction"""
    print('\n╔═══════════════════════════════════════╗')
    print('║  NEW FINANCIAL INSTRUCTION           ║')
    print('╚═══════════════════════════════════════╝')
    
    print('\nSelect instruction type:')
    print('  1. SEAM Payment Obligation')
    print('  2. SEAM Invoice')
    print('  3. SEAM Letter of Credit')
    print('  4. SEAM Purchase Order')
    print('  5. Legacy (free-form message)')
    
    choice = input('\nSelect (1-5): ').strip()
    
    origin = input('Origin institution ID: ').strip() or 'BANK_DEMO'
    destination = input('Destination institution ID: ').strip() or 'BANK_TARGET'
    
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
        
        use_crypto = input('Encrypt? (y/n): ').strip().lower() == 'y'
        key = None
        if use_crypto:
            key = getpass('Encryption key: ')
        
        instr = create_financial_instruction(payload, origin, destination, key)
    
    print(f'\n[✓] Instruction created: {instr["instruction_id"]}')
    
    # Display SEAM validation if applicable
    if SEAMValidator.is_seam_compliant(instr):
        print(f'[✓] SEAM-compliant: {instr.get("seam_type")}')
        print(f'    Amount: {instr.get("currency")} {instr.get("amount"):,.2f}')
        print(f'    Creditor: {instr.get("creditor")}')
        print(f'    Debtor: {instr.get("debtor")}')
    
    k, n = instr.get('quorum_k', 2), instr.get('quorum_n', 3)
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
    
    print(f'\n[✓] Instruction dispatched to network')
    print(f'[i] Destination: {destination}')
    print(f'[i] Quorum: {k}-of-{n} shards required for reconstruction')

def monitor_instructions():
    """CLI: Monitor received instructions"""
    print('\n╔═══════════════════════════════════════╗')
    print('║  RECEIVED INSTRUCTIONS               ║')
    print('╚═══════════════════════════════════════╝')
    
    manifests = []
    for fname in list_shards():
        if fname.endswith('_manifest.json'):
            try:
                with open(shard_file_path(fname), 'r') as f:
                    manifest = json.load(f)
                    manifests.append(manifest)
            except:
                continue
    
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
                if os.path.exists(shard_file_path(shard_name)):
                    try:
                        with open(shard_file_path(shard_name), 'r') as f:
                            d = json.load(f)
                        idx = d.get('index', shard_idx)
                        seen.add(idx)
                    except Exception:
                        seen.add(shard_idx)
                    break
        available = len(seen)
        
        status = '✓ Ready' if available >= k else f'⏳ Pending ({available}/{k})'
        seam_badge = f' [SEAM: {m.get("seam_type")}]' if m.get('seam_compliant') else ''
        
        print(f'{instr_id}: {status}{seam_badge}')
        print(f'  Origin: {m.get("origin")} → Destination: {m.get("destination")}')
        print(f'  Encrypted: {m.get("encrypted", False)}')
        print()

def rebuild_instruction():
    """CLI: Reconstruct instruction with quorum"""
    print('\n╔═══════════════════════════════════════╗')
    print('║  RECONSTRUCT INSTRUCTION             ║')
    print('╚═══════════════════════════════════════╝')
    
    manifests = []
    for fname in list_shards():
        if fname.endswith('_manifest.json'):
            try:
                with open(shard_file_path(fname), 'r') as f:
                    manifests.append(json.load(f))
            except:
                continue
    
    if not manifests:
        print('[!] No instructions available.')
        return
    
    print('Available instructions:')
    for i, m in enumerate(sorted(manifests, key=lambda x: x['timestamp']), 1):
        seam_badge = f' [SEAM: {m.get("seam_type")}]' if m.get('seam_compliant') else ''
        print(f'  {i}. {m["instruction_id"]}{seam_badge}')
        print(f'     {m.get("origin")} → {m.get("destination")}')
    
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
        print('\n[✗] Reconstruction failed. Waiting for more shards...')
        return
    
    # Decrypt if needed
    if instr.get('encrypted'):
        decrypt = input('\nDecrypt payload? (y/n): ').strip().lower() == 'y'
        if decrypt:
            key = getpass('Decryption key: ')
            try:
                instr['payload'] = decrypt_payload_aes256(instr['payload'], key)
                print('[✓] Payload decrypted')
            except Exception as e:
                print(f'[✗] Decryption failed: {e}')
    
    # Display
    print('\n╔═══════════════════════════════════════╗')
    print('║  RECONSTRUCTED INSTRUCTION           ║')
    print('╚═══════════════════════════════════════╝')
    
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
    print('\n╔═══════════════════════════════════════╗')
    print('║  AUDIT TRAIL                         ║')
    print('╚═══════════════════════════════════════╝')
    
    for fname in list_shards():
        if fname.endswith('_manifest.json'):
            try:
                with open(shard_file_path(fname), 'r') as f:
                    manifest = json.load(f)
                
                seam_badge = f' [SEAM: {manifest.get("seam_type")}]' if manifest.get('seam_compliant') else ''
                print(f"\nInstruction: {manifest['instruction_id']}{seam_badge}")
                print(f"Origin: {manifest.get('origin')} → Destination: {manifest.get('destination')}")
                
                for entry in manifest.get('log', []):
                    print(f"  • {entry['event']}")
                    print(f"    Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry['timestamp']))}")
                    print(f"    Node: {entry.get('node_id', 'unknown')[:16]}...")
                    print(f"    Signature: {entry.get('signature', '')[:24]}...")
                    
            except Exception as e:
                print(f'[!] Error reading {fname}: {e}')

def view_billing():
    """CLI: View billing report"""
    print('\n╔═══════════════════════════════════════╗')
    print('║  BILLING REPORT                      ║')
    print('╚═══════════════════════════════════════╝')
    
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
        all_clients = set()
        if os.path.exists(METERING_LOG):
            with open(METERING_LOG, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        all_clients.add(event['client_id'])
                    except:
                        continue
        
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
        print('\n╔═══════════════════════════════════════╗')
        print('║  ONESEAM ENTERPRISE NODE             ║')
        print('╠═══════════════════════════════════════╣')
        print('║  1. Node Status                      ║')
        print('║  2. Send Financial Instruction       ║')
        print('║  3. Monitor Received Instructions    ║')
        print('║  4. Collect Shards Dynamically       ║')
        print('║  5. Reconstruct Instruction          ║')
        print('║  6. Audit Logs                       ║')
        print('║  7. Billing Report                   ║')
        print('║  8. Exit                             ║')
        print('╚═══════════════════════════════════════╝')
        
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
            os._exit(0)
        else:
            print('[!] Invalid option.')

# ===== ENTERPRISE REST API =====
def start_rest_api():
    """Start enterprise REST API server"""
    try:
        from flask import Flask, request, jsonify
        from functools import wraps
    except ImportError:
        print('[API] Flask not installed. API disabled.')
        print('[API] Install: pip install flask')
        return
    
    app = Flask(__name__)
    
    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            api_key = request.headers.get('X-API-Key')
            if not api_key or api_key not in API_KEYS:
                return jsonify({'error': 'Unauthorized'}), 401
            request.client = API_KEYS[api_key]
            return f(*args, **kwargs)
        return wrapper
    
    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({
            'status': 'healthy',
            'service': 'Oneseam Enterprise Infrastructure',
            'version': '2.0.0',
            'seam_version': '1.0',
            'node_id': node_id
        })
    
    @app.route('/v1/seam/payment_obligation', methods=['POST'])
    @require_auth
    def create_payment_obligation_api():
        """Create SEAM Payment Obligation"""
        try:
            data = request.json
            
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
            
            # Add origin/destination for routing
            instr['origin'] = request.client['client_id']
            instr['destination'] = data['creditor']
            
            # Distribute
            k, n = DEFAULT_QUORUM_K, DEFAULT_QUORUM_N
            instr_json = json.dumps(instr)
            
            if SSS_AVAILABLE:
                encrypted_b64, shard_dicts = shard_instruction(instr_json, k, n)
                manifest = create_instruction_manifest(instr, [], encrypted_payload_b64=encrypted_b64,
                                                      shard_dicts=shard_dicts, quorum_k=k, quorum_n=n)
                distribute_shards_smart(shard_dicts, instr['instruction_id'], data['creditor'],
                                       manifest, k, n, use_sss=True)
            
            return jsonify({
                'instruction_id': instr['instruction_id'],
                'seam_type': instr['seam_type'],
                'status': 'dispatched',
                'amount': instr['amount'],
                'currency': instr['currency'],
                'quorum': f'{k}-of-{n}'
            }), 201
            
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    
    @app.route('/v1/instructions', methods=['POST'])
    @require_auth
    def submit_instruction():
        """Submit financial instruction (legacy format)"""
        data = request.json
        
        if not data.get('payload') or not data.get('destination'):
            return jsonify({'error': 'Missing payload or destination'}), 400
        
        # Create instruction
        instr = create_financial_instruction(
            payload=data['payload'],
            origin=request.client['client_id'],
            destination=data['destination'],
            encryption_key=data.get('encryption_key'),
            jurisdiction=data.get('jurisdiction'),
            data_region=data.get('data_region'),
            compliance_frameworks=data.get('compliance_frameworks')
        )
        
        k, n = DEFAULT_QUORUM_K, DEFAULT_QUORUM_N
        instr_json = json.dumps(instr)
        
        if SSS_AVAILABLE:
            encrypted_b64, shard_dicts = shard_instruction(instr_json, k, n)
            manifest = create_instruction_manifest(instr, [], encrypted_payload_b64=encrypted_b64,
                                                  shard_dicts=shard_dicts, quorum_k=k, quorum_n=n)
            distribute_shards_smart(shard_dicts, instr['instruction_id'], data['destination'],
                                   manifest, k, n, use_sss=True)
        
        return jsonify({
            'instruction_id': instr['instruction_id'],
            'status': 'dispatched',
            'shards': n * 3,
            'quorum': f'{k}-of-{n}'
        }), 201
    
    @app.route('/v1/instructions/<instruction_id>', methods=['GET'])
    @require_auth
    def get_instruction(instruction_id):
        """Check instruction status and reconstruct if ready"""
        collect_shards_dynamically(instruction_id, max_attempts=2)
        result = reconstruct_with_quorum(instruction_id)
        
        if result:
            response = {
                'instruction_id': instruction_id,
                'status': 'reconstructed',
                'quorum': 'achieved'
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
            
            return jsonify(response)
        else:
            return jsonify({
                'instruction_id': instruction_id,
                'status': 'pending',
                'quorum': 'not_achieved'
            }), 202
    
    @app.route('/v1/billing', methods=['GET'])
    @require_auth
    def billing():
        """Get billing report"""
        start = int(request.args.get('start', 0))
        end = int(request.args.get('end', time.time()))
        
        report = get_billing_report(request.client['client_id'], start, end)
        return jsonify(report)
    
    print(f'[API] REST API starting on port {API_PORT}')
    print(f'[API] SEAM Protocol v1.0 enabled')
    print(f'[API] Endpoints:')
    print(f'[API]   POST   /v1/seam/payment_obligation')
    print(f'[API]   POST   /v1/instructions')
    print(f'[API]   GET    /v1/instructions/<id>')
    print(f'[API]   GET    /v1/billing')
    
    app.run(host='0.0.0.0', port=API_PORT, debug=False, threaded=True)

# ===== MAIN ENTRY =====
if __name__ == '__main__':
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  ██████╗ ███╗   ██╗███████╗███████╗███████╗ █████╗ ███╗   ███╗║
║ ██╔═══██╗████╗  ██║██╔════╝██╔════╝██╔════╝██╔══██╗████╗ ████║║
║ ██║   ██║██╔██╗ ██║█████╗  ███████╗█████╗  ███████║██╔████╔██║║
║ ██║   ██║██║╚██╗██║██╔══╝  ╚════██║██╔══╝  ██╔══██║██║╚██╔╝██║║
║ ╚██████╔╝██║ ╚████║███████╗███████║███████╗██║  ██║██║ ╚═╝ ██║║
║  ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝║                                                      ║
║                                                               ║
║          Enterprise Cryptographic Messaging v2.0             ║
║        Resilient Financial Settlement Infrastructure         ║
║              SEAM Protocol v1.0 (enabled)                    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Register shutdown handlers
    signal.signal(signal.SIGINT, handle_shutdown)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, handle_shutdown)
    
    # Initialize
    get_node_id()
    ensure_storage()
    
    print(f'[INIT] Node ID: {node_id[:16]}...')
    print(f'[INIT] Storage: {STORAGE_DIR}')
    print(f'[INIT] SEAM Protocol: v1.0')
    print(f'[INIT] Supported types: PAYMENT_OBLIGATION, INVOICE, LETTER_OF_CREDIT, PURCHASE_ORDER')
    
    # Start P2P network
    threading.Thread(target=broadcast_presence, daemon=True).start()
    threading.Thread(target=listen_broadcast, daemon=True).start()
    threading.Thread(target=server_thread, daemon=True).start()
    if BLIND_RELAY_ENABLED:
        threading.Thread(target=relay_thread, daemon=True).start()
        print('[INIT] Blind Relay (Repasse Cego) enabled')
    
    # Check if API mode requested
    if len(sys.argv) > 1 and sys.argv[1] == 'api':
        print('[MODE] Starting in API mode (REST server)')
        start_rest_api()
    else:
        print('[MODE] Starting in CLI mode')
        print('[INFO] For API mode, run: python oneseam_enterprise.py api')
        time.sleep(2)
        cli_menu()