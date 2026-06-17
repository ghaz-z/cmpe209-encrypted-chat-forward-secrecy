import asyncio
import base64
import datetime
import json

import websockets

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag
from crypto import (
    decrypt,
    encrypt,
    sha256_hex,
    chat_signing_bytes,
    ed25519_generate_private_key,
    ed25519_public_to_b64,
    ed25519_public_from_b64,
    ed25519_sign,
    ed25519_verify,
)

# flags for demo (can toggle on (showhashdebug) to show the hash computation one time and then turn off)
SHOW_HASH_DEBUG = True
hash_demo_shown = False

# used for demo purposes to show the hash and signature verification
SHOW_DEMO_OUTPUT = True
# for demo purposes will print an additional lines for: DH derived key and Ed25519 public key + fingerprint + hash verified and sig verified lines
demo_verify_shown = False
# if false means demos over and wont print those extra lines of code

# after DH exchange store the shared secret, each entry in this associates a username to the shared secret (not per-message key)
session_keys = {}

# store each user's Ed25519 signing key,keys will be announces and used for verification
ed25519_keys = {}

# message counter per peer for key ratcheting
message_counters = {}

# ephemeral DH public private keypair per client session

# since we're using x25519, it's a better idea to use Ed25519 for signing compared to RSA,
dh_private_key = x25519.X25519PrivateKey.generate()
dh_public_key = dh_private_key.public_key()

# create the user's singing keypair, the private key is used to sign any chat messages going out, public key shared with other user of message to verify signature
ed25519_private_key = ed25519_generate_private_key()
ed25519_public_key = ed25519_private_key.public_key()

# Grabbing the function from server.py to ensure consistent timestamps across client and server
def get_pst_timestamp():
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    pst = datetime.timezone(datetime.timedelta(hours=-8), name="PST")
    now = utc_now.astimezone(pst)
    return now.strftime('%Y-%m-%d %H:%M:%S PST')
    
# Convert public key bytes to base64 for JSON 
def public_key_to_b64(public_key):
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode("utf-8")

# Convert base64 to bytes
def b64_to_public_key(data):
    raw = base64.b64decode(data.encode("utf-8"))
    return x25519.X25519PublicKey.from_public_bytes(raw)

def derive_shared_secret(my_private_key, peer_public_key):
    shared_secret = my_private_key.exchange(peer_public_key)

    return shared_secret

def derive_message_key(shared_secret, counter):
    # Derive a per-message key using HKDF with counter
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"chat-message-{counter}".encode("utf-8"),
    ).derive(shared_secret)
    return derived

def serialize_ciphertexts(ciphertexts):
    return json.dumps(ciphertexts, sort_keys=True, separators=(",", ":"))

def build_encrypted_message(sender, plaintext, peer_shared_secrets, message_counters):
    if not peer_shared_secrets:
        raise ValueError("No shared secrets established")

    aad = sender.encode("utf-8")
    ciphertexts = {}
    counters = {}
    for peer, shared_secret in peer_shared_secrets.items():
        counter = message_counters[peer]
        key = derive_message_key(shared_secret, counter)
        ciphertexts[peer] = encrypt(plaintext, key, aad=aad)
        counters[peer] = counter
        message_counters[peer] += 1  # increment for next message

    serialized_ciphertexts = serialize_ciphertexts(ciphertexts)
    to_sign = chat_signing_bytes(sender, serialized_ciphertexts)
    return {
        "type": "chat",
        "sender": sender,
        "ciphertexts": ciphertexts,
        "counters": counters,  # include counters used for this message
        "hash": sha256_hex(serialized_ciphertexts.encode("utf-8")),
        "signature": ed25519_sign(ed25519_private_key, to_sign),
    }

def decrypt_incoming_message(message, recipient, peer_shared_secrets):
    sender = message["sender"]
    shared_secret = peer_shared_secrets[sender]
    counter = message["counters"][recipient]
    key = derive_message_key(shared_secret, counter)
    ciphertext = message["ciphertexts"][recipient]
    return decrypt(ciphertext, key, aad=sender.encode("utf-8"))

async def announce_dh_key(websocket):
    payload = {
        "type": "dh_public",
        "public_key": public_key_to_b64(dh_public_key)
    }
    await websocket.send(json.dumps(payload))


async def announce_ed25519_key(websocket):
    """
    state the user's public signing key to the server
    then server adds the username of the user and sends the key to the other user on the chat. 

    only public key is sent, private is kept local and never shared
    """
    payload = {
        "type": "ed25519_public",
        "public_key": ed25519_public_to_b64(ed25519_public_key),
    }
    await websocket.send(json.dumps(payload))

async def send_messages(websocket, username):
    """
    Read user input from the console and send it to the server as JSON.

    Each message is turned into a json obj and contains:
    - type: tell us the message is a chat payload type
    - content: the actual message content (raw content)
    - hash: sha256 digest of the message content
    - signature: Ed25519 signature over chat_signing_bytes(username, content)

    Hash supports integrity checks; the signature proves origin (non-repudiation) when peers have the sender's public key.

    /leave command closes Websoekcet (existsed in previous version of this code)
    """
    
    loop = asyncio.get_event_loop()

    while True:
        timestamp = get_pst_timestamp()
        msg = await loop.run_in_executor(None, input, f"\n[{timestamp}] {username}: ")

        # Leave command
        if msg.strip().lower() == "/leave":
            print("👋 Leaving chat...")
            await websocket.close()
            break

        try:
            payload = build_encrypted_message(username, msg, session_keys, message_counters)
        except ValueError:
            print("⚠️ No shared secrets established yet. Wait for another client to complete key exchange.")
            continue

        await websocket.send(json.dumps(payload))

async def receive_messages(websocket, username):
    """
    Continuously get messages from server

    This function handles several kinds of incoming messages:

    1. Diffie-Hellman key exchange ("dh_public"):
       - Receives a peer's public key
       - Derives a shared session key 
       - Stores the resulting session key per peer

    2. Ed25519 public key ("ed25519_public"):
       - Receives a peer's signing public key
       - Stores it so we can verify signatures on chat from that peer

    3. Chat messages ("chat"):
       - Extracts content, SHA-256 hash, and optional Ed25519 signature
       - Verifies hash and (when present) signature using the sender's registered public key

    If hashes or signatures fail verification the message rejected w a warning

    The debug flag allows us during the demo to show the hashing process in action
    We can turn it off to avoid clutter by turning to false as listed in the comment on top of it
    """
    global hash_demo_shown, demo_verify_shown

    try:
        while True:
            msg = await websocket.recv()
            data = json.loads(msg)

            # handle DH public key messages
            if data.get("type") == "dh_public":
                peer = data["sender"]

                if peer == username:
                    continue

                peer_public_key = b64_to_public_key(data["public_key"])
                shared_secret = derive_shared_secret(dh_private_key, peer_public_key)
                session_keys[peer] = shared_secret
                message_counters[peer] = 0

                print(f"\n[DH] Session key established with {peer}")
                if SHOW_DEMO_OUTPUT:
                    # Show the shared secret (not the final key, since keys are per-message now)
                    print(f"[DH] Derived shared secret with {peer} (hex): {shared_secret.hex()}")
                print(f"{username}: ", end="", flush=True)
                continue

            # first checks if the data is a public key, then checks who is sending the key
            # needs to make sure that server doesn't send you your own public key (this is the continue part in line 191), then you convert from base64 str to Ed25519PublicKey and store it
            # then messge prints to say that the key has been registered for the user
            if data.get("type") == "ed25519_public":
                peer = data["sender"]
                if peer == username:
                    continue
                ed25519_keys[peer] = ed25519_public_from_b64(data["public_key"])
                print(f"\n[Sig] Verification key registered for {peer}")
                if SHOW_DEMO_OUTPUT:
                    # Show the other user's Ed25519 public key (what we use to verify their signatures).
                    print(f"[Sig] {peer}'s Ed25519 public key (base64): {data['public_key']}")
                    raw = ed25519_keys[peer].public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                    print(
                        f"[Sig] Fingerprint SHA256(raw Ed25519 pubkey): {sha256_hex(raw)[:32]}…"
                    )
                print(f"{username}: ", end="", flush=True)
                continue

            if data.get("type") == "chat":
                sender = data["sender"]
                if username not in data["ciphertexts"]:
                    continue

                serialized_ciphertexts = serialize_ciphertexts(data["ciphertexts"])
                received_hash = data.get("hash")
                computed_hash = sha256_hex(serialized_ciphertexts.encode("utf-8"))

                if computed_hash != received_hash:
                    print(f"\n⚠️ Integrity check failed for encrypted message from {sender}\n{username}: ", end="", flush=True)
                    continue

                sig_b64 = data.get("signature")
                if not sig_b64:
                    print(f"\n⚠️ Missing signature for encrypted message from {sender}\n{username}: ", end="", flush=True)
                    continue

                pk = ed25519_keys.get(sender)
                if pk is None:
                    print(f"\n⚠️ No Ed25519 public key yet for {sender}; cannot verify signature\n{username}: ", end="", flush=True)
                    continue

                payload_bytes = chat_signing_bytes(sender, serialized_ciphertexts)
                if not ed25519_verify(pk, payload_bytes, sig_b64):
                    print(f"\n⚠️ Signature verification failed for encrypted message from {sender}\n{username}: ", end="", flush=True)
                    continue

                if SHOW_DEMO_OUTPUT and not demo_verify_shown:
                    print("\n✅ Hash verified + signature verified (first encrypted message received)")
                    print("   - Hash matches recomputed SHA-256 over ciphertext bundle")
                    print(f"   - Signature verifies using {sender}'s Ed25519 public key")
                    demo_verify_shown = True

                try:
                    plaintext = decrypt_incoming_message(data, username, session_keys)
                except KeyError:
                    print("\n⚠️ Missing session key for encrypted message.")
                    print(f"{username}: ", end="", flush=True)
                    continue
                except (InvalidTag, ValueError):
                    print("\n⚠️ Failed to authenticate encrypted message.")
                    print(f"{username}: ", end="", flush=True)
                    continue

                print(
                    f"\n📩 [{data['timestamp']}] {data['sender']}: {plaintext}\n{username}: ",
                    end="",
                    flush=True,
                )
                continue

    except websockets.exceptions.ConnectionClosed:
        print("\n🔌 Disconnected from server.")




async def main():
    uri = "ws://127.0.0.1:8000/ws"
    username = input("Enter your username: ").strip()

    if not username:
        username = "Anonymous"

    try:
        async with websockets.connect(uri) as websocket:
            print("✅ Connected to server")

            # Send username first
            await websocket.send(username)

            # announce ephemeral DH public key for session
            await announce_dh_key(websocket)
            # announce Ed25519 public key so peers can verify our chat signatures
            await announce_ed25519_key(websocket)
            if SHOW_DEMO_OUTPUT:
                print(
                    f"[Sig] Our Ed25519 public key (others verify our signatures with this): "
                    f"{ed25519_public_to_b64(ed25519_public_key)}"
                )

            await asyncio.gather(
                send_messages(websocket, username),
                receive_messages(websocket, username)
            )

    except Exception as e:
        print("❌ Connection error:", e)

if __name__ == "__main__":
    asyncio.run(main())
