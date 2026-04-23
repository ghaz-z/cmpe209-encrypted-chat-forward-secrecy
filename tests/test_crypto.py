import base64
import os

import pytest

from crypto import (
    KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    InvalidTag,
    decrypt,
    encrypt,
    generate_key,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flip_byte(data: bytes, index: int) -> bytes:
    ba = bytearray(data)
    ba[index] ^= 0xFF
    return bytes(ba)


def _tamper_token(token: str, byte_index: int) -> str:
    raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    raw = _flip_byte(raw, byte_index)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_token(token: str) -> bytes:
    return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))


# ---------------------------------------------------------------------------
# Roundtrip / Happy Path
# ---------------------------------------------------------------------------

def test_roundtrip_basic():
    key = generate_key()
    msg = "Hello, chat room!"
    assert decrypt(encrypt(msg, key), key) == msg


def test_roundtrip_empty_string():
    key = generate_key()
    assert decrypt(encrypt("", key), key) == ""


def test_roundtrip_unicode():
    key = generate_key()
    msg = "Hello 世界 🌍"
    assert decrypt(encrypt(msg, key), key) == msg


def test_roundtrip_long_message():
    key = generate_key()
    msg = "A" * 10_000
    assert decrypt(encrypt(msg, key), key) == msg


def test_roundtrip_json_payload():
    key = generate_key()
    msg = '{"sender": "alice", "content": "hi", "timestamp": "12:00:00 PST"}'
    assert decrypt(encrypt(msg, key), key) == msg


# ---------------------------------------------------------------------------
# Output Format
# ---------------------------------------------------------------------------

def test_output_is_string():
    assert isinstance(encrypt("test", generate_key()), str)


def test_output_is_json_safe():
    token = encrypt("test", generate_key())
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    assert all(c in allowed for c in token)


def test_output_minimum_length():
    raw = _decode_token(encrypt("", generate_key()))
    assert len(raw) >= NONCE_SIZE + TAG_SIZE


# ---------------------------------------------------------------------------
# Nonce Uniqueness
# ---------------------------------------------------------------------------

def test_nonce_uniqueness():
    key = generate_key()
    msg = "same message"
    assert encrypt(msg, key) != encrypt(msg, key)


def test_different_nonces_in_blobs():
    key = generate_key()
    msg = "same message"
    nonce_a = _decode_token(encrypt(msg, key))[:NONCE_SIZE]
    nonce_b = _decode_token(encrypt(msg, key))[:NONCE_SIZE]
    assert nonce_a != nonce_b


# ---------------------------------------------------------------------------
# Tamper Detection
# ---------------------------------------------------------------------------

def test_tampered_ciphertext_raises():
    key = generate_key()
    token = encrypt("secret", key)
    with pytest.raises(InvalidTag):
        decrypt(_tamper_token(token, NONCE_SIZE), key)


def test_tampered_nonce_raises():
    key = generate_key()
    token = encrypt("secret", key)
    with pytest.raises(InvalidTag):
        decrypt(_tamper_token(token, 0), key)


def test_tampered_tag_raises():
    key = generate_key()
    token = encrypt("secret", key)
    raw = _decode_token(token)
    tampered_raw = _flip_byte(raw, len(raw) - 1)
    tampered = base64.urlsafe_b64encode(tampered_raw).rstrip(b"=").decode("ascii")
    with pytest.raises(InvalidTag):
        decrypt(tampered, key)


def test_truncated_token_raises():
    key = generate_key()
    short_raw = os.urandom(NONCE_SIZE + TAG_SIZE - 1)
    short_token = base64.urlsafe_b64encode(short_raw).rstrip(b"=").decode("ascii")
    with pytest.raises(ValueError):
        decrypt(short_token, key)


def test_empty_token_raises():
    with pytest.raises(ValueError):
        decrypt("", generate_key())


# ---------------------------------------------------------------------------
# Key Validation
# ---------------------------------------------------------------------------

def test_wrong_key_raises():
    key = generate_key()
    token = encrypt("secret", key)
    with pytest.raises(InvalidTag):
        decrypt(token, generate_key())


def test_short_key_encrypt_raises():
    with pytest.raises(ValueError):
        encrypt("msg", b"tooshort")


def test_long_key_encrypt_raises():
    with pytest.raises(ValueError):
        encrypt("msg", os.urandom(KEY_SIZE + 1))


def test_short_key_decrypt_raises():
    key = generate_key()
    token = encrypt("msg", key)
    with pytest.raises(ValueError):
        decrypt(token, b"tooshort")


def test_empty_key_raises():
    with pytest.raises(ValueError):
        encrypt("msg", b"")


def test_16_byte_key_raises():
    with pytest.raises(ValueError):
        encrypt("msg", os.urandom(16))


# ---------------------------------------------------------------------------
# AAD (Additional Authenticated Data)
# ---------------------------------------------------------------------------

def test_aad_roundtrip():
    key = generate_key()
    aad = b"alice"
    msg = "Hello, chat room!"
    assert decrypt(encrypt(msg, key, aad), key, aad) == msg


def test_aad_mismatched_raises():
    key = generate_key()
    token = encrypt("secret", key, aad=b"alice")
    with pytest.raises(InvalidTag):
        decrypt(token, key, aad=b"bob")


def test_aad_present_on_encrypt_missing_on_decrypt_raises():
    key = generate_key()
    token = encrypt("secret", key, aad=b"alice")
    with pytest.raises(InvalidTag):
        decrypt(token, key, aad=None)


def test_aad_missing_on_encrypt_present_on_decrypt_raises():
    key = generate_key()
    token = encrypt("secret", key, aad=None)
    with pytest.raises(InvalidTag):
        decrypt(token, key, aad=b"alice")


def test_aad_does_not_appear_in_token():
    # AAD is authenticated but never embedded in the ciphertext blob.
    key = generate_key()
    aad = b"sensitive-sender-identity"
    token = encrypt("msg", key, aad)
    assert aad not in base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))


# ---------------------------------------------------------------------------
# generate_key()
# ---------------------------------------------------------------------------

def test_generate_key_length():
    assert len(generate_key()) == KEY_SIZE


def test_generate_key_is_bytes():
    assert isinstance(generate_key(), bytes)


def test_generate_key_uniqueness():
    assert generate_key() != generate_key()


def test_generate_key_works_with_encrypt():
    encrypt("test", generate_key())  # must not raise
