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
    sha256_hex,
    chat_signing_bytes,
    ed25519_generate_private_key,
    ed25519_public_to_b64,
    ed25519_public_from_b64,
    ed25519_sign,
    ed25519_verify,
    decrypt,
    encrypt,
)

# flags for demo (can toggle on (showhashdebug) to show the hash computation one time and then turn off)
SHOW_HASH_DEBUG = True
hash_demo_shown = False

# after DH exchange store the shared session key, each entry in this associates a username to the appropriate session key
session_keys = {}

# store each user's Ed25519 signing key,keys will be announces and used for verification
ed25519_keys = {}

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

def derive_session_key(my_private_key, peer_public_key):
    shared_secret = my_private_key.exchange(peer_public_key)

    # HMAC-based Key Derivation Function
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"chat-session".encode("utf-8"),
    ).derive(shared_secret)

    return derived

def build_encrypted_message(sender, plaintext, peer_session_keys):
    if not peer_session_keys:
        raise ValueError("No session keys established")

    aad = sender.encode("utf-8")
    ciphertexts = {
        peer: encrypt(plaintext, key, aad=aad)
        for peer, key in peer_session_keys.items()
    }
    return {
        "type": "encrypted_chat",
        "sender": sender,
        "ciphertexts": ciphertexts,
    }

def decrypt_incoming_message(message, recipient, peer_session_keys):
    sender = message["sender"]
    key = peer_session_keys[sender]
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

        # Send both encrypted and signed/hashed message
        # Signed/hashed message
        to_sign = chat_signing_bytes(username, msg)
        signed_payload = {
            "type": "chat",
            "content": msg,
            "hash": sha256_hex(msg.encode("utf-8")),
            "signature": ed25519_sign(ed25519_private_key, to_sign),
        }
        await websocket.send(json.dumps(signed_payload))

        # Encrypted message (if session keys exist)
        if session_keys:
            try:
                encrypted_payload = build_encrypted_message(username, msg, session_keys)
                await websocket.send(json.dumps(encrypted_payload))
            except ValueError:
                pass

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
    global hash_demo_shown


    # Track displayed messages to avoid duplicates
    displayed = set()
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
                session_key = derive_session_key(dh_private_key, peer_public_key)
                session_keys[peer] = session_key
                print(f"\n[DH] Session key established with {peer}")
                print(f"{username}: ", end="", flush=True)
                continue

            # handle Ed25519 public key messages
            if data.get("type") == "ed25519_public":
                peer = data["sender"]
                if peer == username:
                    continue
                ed25519_keys[peer] = ed25519_public_from_b64(data["public_key"])
                print(f"\n[Sig] Verification key registered for {peer}")
                print(f"{username}: ", end="", flush=True)
                continue

            # handle encrypted chat messages
            if data.get("type") == "encrypted_chat":
                if username not in data.get("ciphertexts", {}):
                    continue
                key = (data["sender"], data.get("timestamp"))
                if key in displayed:
                    continue
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
                displayed.add(key)
                continue

            # handle hashed chat messages (and optional Ed25519 signature)
            if data.get("type") == "chat":
                received_content = data["content"]
                received_hash = data["hash"]
                sender = data["sender"]
                key = (sender, data.get("timestamp"))
                if key in displayed:
                    continue
                computed_hash = sha256_hex(received_content.encode("utf-8"))
                if computed_hash != received_hash:
                    print(f"\n⚠️ Integrity check failed for message from {sender}\n{username}: ", end="", flush=True)
                    continue
                sig_ok = None
                sig_b64 = data.get("signature")
                if sig_b64:
                    pk = ed25519_keys.get(sender)
                    if pk is None:
                        print(f"\n⚠️ No Ed25519 public key yet for {sender}; cannot verify signature\n{username}: ", end="", flush=True)
                        continue
                    payload_bytes = chat_signing_bytes(sender, received_content)
                    sig_ok = ed25519_verify(pk, payload_bytes, sig_b64)
                    if not sig_ok:
                        print(f"\n⚠️ Signature verification failed for message from {sender}\n{username}: ", end="", flush=True)
                        continue
                if SHOW_HASH_DEBUG and not hash_demo_shown:
                    print("\n🔍 HASH DEBUG MODE")
                    print(f"Message:        {received_content}")
                    print(f"Sent hash:      {received_hash}")
                    print(f"Computed hash:  {computed_hash}")
                    print("✅ Hashes match → integrity verified\n")
                    hash_demo_shown = True
                print(f"\n📩 [{data['timestamp']}] {sender}: {received_content}\n{username}: ", end="", flush=True)
                displayed.add(key)
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

            await asyncio.gather(
                send_messages(websocket, username),
                receive_messages(websocket, username)
            )

    except Exception as e:
        print("❌ Connection error:", e)

if __name__ == "__main__":
    asyncio.run(main())
