import pytest
from client import build_encrypted_message, decrypt_incoming_message
from crypto import generate_key
from cryptography.exceptions import InvalidTag

# Test 1: Compromised Long-Term Key (Forward Secrecy)
def test_forward_secrecy_long_term_key_compromise():
    """
    Simulate an attacker who compromises a user's long-term key but cannot decrypt past messages due to forward secrecy.
    """
    alice_key1 = generate_key()
    bob_key1 = generate_key()
    # Alice and Bob exchange messages with session keys
    msg1 = build_encrypted_message("alice", "hello bob", {"bob": bob_key1})
    # Session keys are rotated (ephemeral)
    alice_key2 = generate_key()
    bob_key2 = generate_key()
    msg2 = build_encrypted_message("alice", "new session", {"bob": bob_key2})
    # Attacker compromises bob_key2 (current session)
    # Attacker should NOT be able to decrypt msg1 (old session)
    with pytest.raises(InvalidTag):
        decrypt_incoming_message(msg1, "bob", {"alice": bob_key2})
    # Attacker CAN decrypt msg2 (current session)
    assert decrypt_incoming_message(msg2, "bob", {"alice": bob_key2}) == "new session"

# Test 2: Compromised Session Key (No Future Messages)
def test_forward_secrecy_session_key_compromise():
    """
    Simulate an attacker who compromises a session key; they can only decrypt messages from that session, not future ones.
    """
    alice_key1 = generate_key()
    bob_key1 = generate_key()
    msg1 = build_encrypted_message("alice", "session1", {"bob": bob_key1})
    # Attacker gets bob_key1
    assert decrypt_incoming_message(msg1, "bob", {"alice": bob_key1}) == "session1"
    # Session keys rotate
    alice_key2 = generate_key()
    bob_key2 = generate_key()
    msg2 = build_encrypted_message("alice", "session2", {"bob": bob_key2})
    # Attacker CANNOT decrypt future messages
    with pytest.raises(InvalidTag):
        decrypt_incoming_message(msg2, "bob", {"alice": bob_key1})

# Test 3: Replay Attack
def test_forward_secrecy_replay_attack():
    """
    Simulate an attacker replaying an old encrypted message after session keys have rotated.
    The recipient should not be able to decrypt with the new session key.
    """
    alice_key1 = generate_key()
    bob_key1 = generate_key()
    msg1 = build_encrypted_message("alice", "replay test", {"bob": bob_key1})
    # Session keys rotate
    alice_key2 = generate_key()
    bob_key2 = generate_key()
    # Attacker replays old message
    with pytest.raises(InvalidTag):
        decrypt_incoming_message(msg1, "bob", {"alice": bob_key2})

# Test 4: Tampering Attack
def test_forward_secrecy_tampering_attack():
    """
    Simulate an attacker tampering with the ciphertext (modifying a byte).
    The recipient should detect tampering and raise an error.
    """
    alice_key = generate_key()
    bob_key = generate_key()
    msg = build_encrypted_message("alice", "tamper test", {"bob": bob_key})
    # Tamper with ciphertext
    tampered = dict(msg)
    ct = tampered["ciphertexts"]["bob"]
    # Flip a byte in the ciphertext
    tampered_ct = ct[:-1] + ("A" if ct[-1] != "A" else "B")
    tampered["ciphertexts"]["bob"] = tampered_ct
    with pytest.raises(InvalidTag):
        decrypt_incoming_message(tampered, "bob", {"alice": bob_key})
