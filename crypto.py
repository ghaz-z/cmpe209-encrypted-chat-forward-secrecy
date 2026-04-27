import os
import base64
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag  # re-exported for callers
from cryptography.hazmat.primitives import hashes

NONCE_SIZE = 12  # bytes, GCM standard
KEY_SIZE = 32    # bytes, AES-256
TAG_SIZE = 16    # bytes, GCM authentication tag (appended automatically by AESGCM)


def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)


def encrypt(plaintext: str, key: bytes, aad: Optional[bytes] = None) -> str:
    """
    Encrypt a UTF-8 string with AES-256-GCM.

    Returns a URL-safe base64 string encoding nonce || ciphertext || tag.
    Safe to embed directly in JSON as a string value.

    aad (additional authenticated data) is authenticated but not encrypted —
    it is not included in the token, so the caller must supply the same value
    to decrypt(). Passing the sender's username here cryptographically binds
    identity to the ciphertext without encrypting it.

    Raises ValueError if key is not KEY_SIZE (32) bytes.
    """
    _validate_key(key)
    nonce = os.urandom(NONCE_SIZE)
    # AESGCM.encrypt returns ciphertext || tag (tag is the last TAG_SIZE bytes).
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return _encode(nonce + ct)


def decrypt(token: str, key: bytes, aad: Optional[bytes] = None) -> str:
    """
    Decrypt a token produced by encrypt().

    aad must match the value passed to encrypt(); a mismatch raises InvalidTag.

    Raises ValueError for bad key size or a token too short to be valid.
    Raises cryptography.exceptions.InvalidTag on authentication failure
    (tampered ciphertext, wrong key, or mismatched AAD).
    """
    _validate_key(key)
    raw = _decode(token)
    # Minimum valid blob is nonce (12 B) + tag (16 B) with zero-length ciphertext.
    if len(raw) < NONCE_SIZE + TAG_SIZE:
        raise ValueError(
            f"Token too short: decoded to {len(raw)} bytes, need at least {NONCE_SIZE + TAG_SIZE}"
        )
    nonce = raw[:NONCE_SIZE]
    ct = raw[NONCE_SIZE:]  # ciphertext + tag combined; AESGCM splits them internally
    # Raises InvalidTag if aad doesn't match what was used during encryption.
    return AESGCM(key).decrypt(nonce, ct, aad).decode("utf-8")


def _validate_key(key: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode(s: str) -> bytes:
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)

def sha256_hex(data: bytes) -> str:
    """
    Computing te sha256 digest of the input data

    Returning a hexadecimal string rep of the 256 bit hash

    The hash is used to verify the message integrity (if it's been tampered with) by allowing the receiving user to 
    recompute the hash and compare it the digest that was sent by the sender.

    While it doesn't provide authentication/confidentiality, it does allow us to detect tampering of the message content.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()
