"""Cryptographic Primitives for Kerberos AS Exchange Simulation.

Educational Implementation Note:
This module provides cryptographic routines using the standard Python `cryptography`
library. For educational clarity, simplicity, and modern security:
- Key Derivation Function (KDF): PBKDF2-HMAC-SHA256 (100,000 iterations)
- Authenticated Encryption: AES-256-GCM with unique 96-bit (12-byte) nonces
- Session Key Generation: Cryptographically secure pseudo-random number generator (secrets)

LIMITATIONS & RFC 4120 NOTICE:
This is an educational simulation created for academic demonstration (Course: BCS703).
It does NOT claim wire-level or cryptographic interoperability with RFC 4120 (which historically
used DES/3DES or Kerberos-specific RFC 3961 profiles like aes256-cts-hmac-sha1-96).
Passwords and secret keys are never exposed in API payloads or logged.
"""

import base64
import json
import secrets
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants for Educational Cryptographic Profile
KDF_ITERATIONS = 100_000
KEY_LENGTH_BYTES = 32  # 256-bit AES key
NONCE_LENGTH_BYTES = 12  # 96-bit standard AES-GCM nonce


def derive_key_from_password(password: str, salt: str) -> bytes:
    """Derives a 256-bit symmetric encryption key from a user password and salt using PBKDF2-HMAC-SHA256.

    Kerberos string-to-key analogy: In Kerberos, client keys are derived from
    user passwords using a realm-and-username based salt (e.g. REALMusername).
    """
    if not password:
        raise ValueError("Password cannot be empty")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH_BYTES,
        salt=salt.encode("utf-8"),
        iterations=KDF_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def generate_session_key() -> str:
    """Generates a cryptographically secure random session key (256-bit, base64 encoded).

    Used for K_C,TGS (Client-to-TGS session key).
    """
    random_bytes = secrets.token_bytes(KEY_LENGTH_BYTES)
    return base64.b64encode(random_bytes).decode("utf-8")


def generate_nonce() -> int:
    """Generates a cryptographically secure random integer nonce for replay prevention."""
    return secrets.randbelow(2**31 - 1) + 1


def encrypt_aes_gcm(
    key: bytes,
    plaintext_data: Any,
    associated_data: Optional[bytes] = None,
) -> Tuple[str, str]:
    """Encrypts plaintext data (dict, str, or bytes) using AES-256-GCM.

    A unique 12-byte nonce is generated for every single encryption operation.

    Returns:
        Tuple[str, str]: (ciphertext_b64, nonce_b64)
    """
    if isinstance(plaintext_data, dict):
        raw_bytes = json.dumps(plaintext_data, sort_keys=True).encode("utf-8")
    elif isinstance(plaintext_data, str):
        raw_bytes = plaintext_data.encode("utf-8")
    elif isinstance(plaintext_data, bytes):
        raw_bytes = plaintext_data
    else:
        raise TypeError(f"Unsupported plaintext data type: {type(plaintext_data)}")

    # Unique 12-byte nonce per encryption operation
    nonce = secrets.token_bytes(NONCE_LENGTH_BYTES)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, raw_bytes, associated_data)

    ciphertext_b64 = base64.b64encode(ciphertext_with_tag).decode("utf-8")
    nonce_b64 = base64.b64encode(nonce).decode("utf-8")

    return ciphertext_b64, nonce_b64


def decrypt_aes_gcm(
    key: bytes,
    ciphertext_b64: str,
    nonce_b64: str,
    associated_data: Optional[bytes] = None,
    as_json: bool = True,
) -> Any:
    """Decrypts AES-256-GCM ciphertext using the supplied key and nonce.

    Args:
        key: 32-byte AES key
        ciphertext_b64: Base64-encoded ciphertext (with tag)
        nonce_b64: Base64-encoded 12-byte nonce
        associated_data: Optional authenticated associated data
        as_json: If True, parses decrypted UTF-8 bytes into a JSON dict

    Returns:
        Decrypted payload (dict, str, or raw bytes).

    Raises:
        InvalidTag: If decryption or authentication fails (wrong key or tampering).
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)

    aesgcm = AESGCM(key)
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data)

    if as_json:
        return json.loads(decrypted_bytes.decode("utf-8"))
    return decrypted_bytes.decode("utf-8")
