import sys
import traceback
from client import build_encrypted_message, decrypt_incoming_message
from crypto import generate_key
from cryptography.exceptions import InvalidTag

# Utility for colored output
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_demo(title, func):
    print(f"{bcolors.HEADER}{title}{bcolors.ENDC}")
    try:
        func()
        print(f"{bcolors.OKGREEN}✔ Success{bcolors.ENDC}\n")
    except Exception as e:
        print(f"{bcolors.FAIL}✘ Failed: {e}{bcolors.ENDC}")
        traceback.print_exc()
        print()

def print_message_flow(sender, recipient, plaintext, ciphertext, session_key, scenario=None):
    print(f"{bcolors.OKBLUE}--- Message Flow ---{bcolors.ENDC}")
    if scenario:
        print(f"{bcolors.BOLD}Scenario: {scenario}{bcolors.ENDC}")
    print(f"{bcolors.OKCYAN}[{sender}] sends to [{recipient}]: '{plaintext}'{bcolors.ENDC}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Session key (hex): {session_key.hex() if hasattr(session_key, 'hex') else session_key}")
    print(f"{bcolors.OKBLUE}--------------------{bcolors.ENDC}\n")

def explain_attack_failure(scenario):
    explanations = {
        "Session key compromise (past session)": (
            "Forward secrecy ensures that compromising a new session key does NOT allow decryption of past messages. "
            "Each session uses a unique ephemeral key, so old ciphertexts cannot be decrypted with new keys."
        ),
        "Session key compromise (future message)": (
            "Forward secrecy ensures that compromising a session key only exposes messages from that session. "
            "Future messages use new keys, so old keys cannot decrypt them."
        ),
        "Replay attack": (
            "The replayed ciphertext was encrypted under a different session key. "
            "Since each session uses a new key, the receiver cannot decrypt the old ciphertext. "
            "Note: Real replay protection typically requires nonces or sequence numbers."
        ),
        "Tampering attack": (
            "Authenticated encryption (AES-GCM) detects any modification to the ciphertext. "
            "Tampering changes the authentication tag, causing decryption to fail."
        ),
    }
    print(f"{bcolors.WARNING}Reason: {explanations.get(scenario, 'Security properties prevent this attack.')}{bcolors.ENDC}\n")

def print_decryption_debug(ciphertext, key, aad=None, label=None):
    from crypto import _decode, NONCE_SIZE, TAG_SIZE
    try:
        raw = _decode(ciphertext)
        nonce = raw[:NONCE_SIZE]
        tag = raw[-TAG_SIZE:]
        if label:
            print(f"  --- {label} ---")
        print(f"  Nonce: {nonce.hex()}")
        print(f"  Tag:   {tag.hex()}")
        print(f"  Key:   {key.hex() if hasattr(key, 'hex') else key}")
        if aad:
            print(f"  AAD:   {aad}")
    except Exception as e:
        print(f"  [debug] Could not decode ciphertext: {e}")

def demo_long_term_key_compromise():
    print("Simulating session key compromise (past session)...")
    alice_key1 = generate_key()
    bob_key1 = generate_key()
    msg1 = build_encrypted_message("alice", "hello bob", {"bob": bob_key1})
    print_message_flow("alice", "bob", "hello bob", msg1["ciphertexts"]["bob"], bob_key1,
                       scenario="Session key compromise (past session)")
    
    alice_key2 = generate_key()
    bob_key2 = generate_key()
    msg2 = build_encrypted_message("alice", "new session", {"bob": bob_key2})
    print_message_flow("alice", "bob", "new session", msg2["ciphertexts"]["bob"], bob_key2,
                       scenario="Session key compromise (new session)")

    print("Attacker tries to decrypt old message with new key (should fail)...")
    print_decryption_debug(msg1["ciphertexts"]["bob"], bob_key1, aad="alice", label="Original (correct key)")
    try:
        decrypt_incoming_message(msg1, "bob", {"alice": bob_key2})
        print(f"{bcolors.FAIL}✘ Attack succeeded (should fail!){bcolors.ENDC}")
    except InvalidTag:
        print_decryption_debug(msg1["ciphertexts"]["bob"], bob_key2, aad="alice", label="Attack (wrong key)")
        print(f"{bcolors.OKGREEN}✔ Attack failed as expected (forward secrecy holds){bcolors.ENDC}")
        explain_attack_failure("Session key compromise (past session)")

    print("Attacker decrypts current message with current key (should succeed)...")
    assert decrypt_incoming_message(msg2, "bob", {"alice": bob_key2}) == "new session"
    print(f"{bcolors.OKGREEN}✔ Current session decrypts as expected{bcolors.ENDC}")

def demo_session_key_compromise():
    print("Simulating session key compromise (future session)...")
    alice_key1 = generate_key()
    bob_key1 = generate_key()
    msg1 = build_encrypted_message("alice", "session1", {"bob": bob_key1})
    print_message_flow("alice", "bob", "session1", msg1["ciphertexts"]["bob"], bob_key1,
                       scenario="Session key compromise (session1)")

    print("Attacker decrypts message with compromised session key (should succeed)...")
    print_decryption_debug(msg1["ciphertexts"]["bob"], bob_key1, aad="alice", label="Original (correct key)")
    assert decrypt_incoming_message(msg1, "bob", {"alice": bob_key1}) == "session1"
    print(f"{bcolors.OKGREEN}✔ Session message decrypted as expected{bcolors.ENDC}")

    alice_key2 = generate_key()
    bob_key2 = generate_key()
    msg2 = build_encrypted_message("alice", "session2", {"bob": bob_key2})
    print_message_flow("alice", "bob", "session2", msg2["ciphertexts"]["bob"], bob_key2,
                       scenario="Session key compromise (session2)")

    print("Attacker tries to decrypt future message with old key (should fail)...")
    print_decryption_debug(msg2["ciphertexts"]["bob"], bob_key2, aad="alice", label="Original (correct key)")
    try:
        decrypt_incoming_message(msg2, "bob", {"alice": bob_key1})
        print(f"{bcolors.FAIL}✘ Attack succeeded (should fail!){bcolors.ENDC}")
    except InvalidTag:
        print_decryption_debug(msg2["ciphertexts"]["bob"], bob_key1, aad="alice", label="Attack (old key)")
        print(f"{bcolors.OKGREEN}✔ Attack failed as expected (forward secrecy holds){bcolors.ENDC}")
        explain_attack_failure("Session key compromise (future message)")

def demo_replay_attack():
    print("Simulating replay attack...")
    alice_key1 = generate_key()
    bob_key1 = generate_key()
    msg1 = build_encrypted_message("alice", "replay test", {"bob": bob_key1})
    print_message_flow("alice", "bob", "replay test", msg1["ciphertexts"]["bob"], bob_key1,
                       scenario="Replay attack (original session)")

    alice_key2 = generate_key()
    bob_key2 = generate_key()
    print_message_flow("alice", "bob", "replay test", msg1["ciphertexts"]["bob"], bob_key2,
                       scenario="Replay attack (replayed with new session key)")

    print("Attacker replays old message with new session key (should fail)...")
    print_decryption_debug(msg1["ciphertexts"]["bob"], bob_key1, aad="alice", label="Original (correct key)")
    try:
        decrypt_incoming_message(msg1, "bob", {"alice": bob_key2})
        print(f"{bcolors.FAIL}✘ Replay succeeded (should fail!){bcolors.ENDC}")
    except InvalidTag:
        print_decryption_debug(msg1["ciphertexts"]["bob"], bob_key2, aad="alice", label="Attack (wrong key)")
        print(f"{bcolors.OKGREEN}✔ Replay failed as expected{bcolors.ENDC}")
        explain_attack_failure("Replay attack")

def demo_tampering_attack():
    print("Simulating tampering attack...")
    alice_key = generate_key()
    bob_key = generate_key()
    msg = build_encrypted_message("alice", "tamper test", {"bob": bob_key})
    print_message_flow("alice", "bob", "tamper test", msg["ciphertexts"]["bob"], bob_key,
                       scenario="Tampering attack (original)")

    print_decryption_debug(msg["ciphertexts"]["bob"], bob_key, aad="alice", label="Original (untampered)")

    tampered = dict(msg)
    ct = tampered["ciphertexts"]["bob"]
    tampered_ct = ct[:-1] + ("A" if ct[-1] != "A" else "B")
    tampered["ciphertexts"]["bob"] = tampered_ct

    print(f"Ciphertext after tampering: {tampered_ct}")
    print("Attacker tampers with ciphertext (should fail)...")
    try:
        decrypt_incoming_message(tampered, "bob", {"alice": bob_key})
        print(f"{bcolors.FAIL}✘ Tampering succeeded (should fail!){bcolors.ENDC}")
    except InvalidTag:
        print_decryption_debug(tampered_ct, bob_key, aad="alice", label="Attack (tampered)")
        print(f"{bcolors.OKGREEN}✔ Tampering detected as expected{bcolors.ENDC}")
        explain_attack_failure("Tampering attack")

def main():
    print_demo("[1] Session Key Compromise (Past Session)", demo_long_term_key_compromise)
    print_demo("[2] Session Key Compromise (Future Session)", demo_session_key_compromise)
    print_demo("[3] Replay Attack", demo_replay_attack)
    print_demo("[4] Tampering Attack", demo_tampering_attack)

if __name__ == "__main__":
    main()