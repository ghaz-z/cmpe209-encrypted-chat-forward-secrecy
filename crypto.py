import os
import base64
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# 
from cryptography.exceptions import InvalidTag  
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

# Ed25519 (EdDSA) 
# why Ed25519? because we already used x25519 for DH key agreement
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

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


def chat_signing_bytes(username: str, content: str) -> bytes:
    """
    function combines username and message into one string and then encodes it to UTF -8 bytes
    both sender and reciever uses this format for signing and verification
    """
    return f"{username}:{content}".encode("utf-8")


def ed25519_generate_private_key() -> Ed25519PrivateKey:
    """
    create a new Ed25519 private key for signing
    used by client to sign outgoing messages (remains secret)
    public key can be derived from the private key and shared with other users for verification
    returns a new private key object
    """
    return Ed25519PrivateKey.generate()


def ed25519_public_to_b64(public_key: Ed25519PublicKey) -> str:
    """
    convert the public key to a base64 string so it can be sent over the network
    """
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("utf-8")


def ed25519_public_from_b64(data: str) -> Ed25519PublicKey:
    """
    Parse base64 from JSON back into an Ed25519PublicKey for verify().
    """
    raw = base64.b64decode(data.encode("utf-8"))
    return Ed25519PublicKey.from_public_bytes(raw)


def ed25519_sign(private_key: Ed25519PrivateKey, message: bytes) -> str:
    """
    Sign message bytes with the caller's private key.
    Args:
            private_key: The sender's Ed25519 private key.
            message: The exact byte sequence to sign (must match verification step).

    Returns:
            A base64-encoded signature string that can be sent over the network
    """
    sig = private_key.sign(message)
    return _encode(sig)


def ed25519_verify(public_key: Ed25519PublicKey, message: bytes, signature_token: str) -> bool:
    """
    Verify a signature over message using the sender's public key.
    Returns False on bad signature; does not raise for normal verify failures.
    """
    try:
        sig = _decode(signature_token)
        public_key.verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False
