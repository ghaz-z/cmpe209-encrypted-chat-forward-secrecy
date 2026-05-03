import asyncio
import base64
import datetime
import json

import websockets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto import (
    chat_signing_bytes,
    decrypt,
    ed25519_generate_private_key,
    ed25519_public_from_b64,
    ed25519_public_to_b64,
    ed25519_sign,
    ed25519_verify,
    encrypt,
    sha256_hex,
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


def get_pst_timestamp():
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    pst = datetime.timezone(datetime.timedelta(hours=-8), name="PST")
    now = utc_now.astimezone(pst)
    return now.strftime("%Y-%m-%d %H:%M:%S PST")


def public_key_to_b64(public_key):
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("utf-8")


def b64_to_public_key(data):
    raw = base64.b64decode(data.encode("utf-8"))
    return x25519.X25519PublicKey.from_public_bytes(raw)


def derive_session_key(my_private_key, peer_public_key):
    shared_secret = my_private_key.exchange(peer_public_key)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"chat-session",
    ).derive(shared_secret)
    return derived


def build_encrypted_message(sender, plaintext, peer_session_keys, *, message_hash=None, signature=None):
    if not peer_session_keys:
        raise ValueError("No session keys established")

    aad = sender.encode("utf-8")
    ciphertexts = {
        peer: encrypt(plaintext, key, aad=aad)
        for peer, key in peer_session_keys.items()
    }
    payload = {
        "type": "chat",
        "sender": sender,
        "ciphertexts": ciphertexts,
    }
    if message_hash is not None:
        payload["hash"] = message_hash
    if signature is not None:
        payload["signature"] = signature
    return payload


def decrypt_incoming_message(message, recipient, peer_session_keys):
    sender = message["sender"]
    key = peer_session_keys[sender]
    ciphertext = message["ciphertexts"][recipient]
    return decrypt(ciphertext, key, aad=sender.encode("utf-8"))


async def announce_dh_key(websocket):
    payload = {
        "type": "dh_public",
        "public_key": public_key_to_b64(dh_public_key),
    }
    await websocket.send(json.dumps(payload))


async def announce_ed25519_key(websocket):
    payload = {
        "type": "ed25519_public",
        "public_key": ed25519_public_to_b64(ed25519_public_key),
    }
    await websocket.send(json.dumps(payload))


async def send_messages(websocket, username):
    loop = asyncio.get_event_loop()

    while True:
        timestamp = get_pst_timestamp()
        msg = await loop.run_in_executor(None, input, f"\n[{timestamp}] {username}: ")

        if msg.strip().lower() == "/leave":
            print("👋 Leaving chat...")
            await websocket.close()
            break

        to_sign = chat_signing_bytes(username, msg)

        try:
            payload = build_encrypted_message(
                username,
                msg,
                session_keys,
                message_hash=sha256_hex(msg.encode("utf-8")),
                signature=ed25519_sign(ed25519_private_key, to_sign),
            )
        except ValueError:
            print("⚠️ No session keys established yet. Wait for another client to complete key exchange.")
            continue

        await websocket.send(json.dumps(payload))


async def receive_messages(websocket, username):
    global hash_demo_shown

    try:
        while True:
            msg = await websocket.recv()
            data = json.loads(msg)

            if data.get("type") == "dh_public":
                peer = data["sender"]

                if peer == username:
                    continue

                peer_public_key = b64_to_public_key(data["public_key"])
                session_keys[peer] = derive_session_key(dh_private_key, peer_public_key)

                print(f"\n[DH] Session key established with {peer}")
                print(f"{username}: ", end="", flush=True)
                continue

            if data.get("type") == "ed25519_public":
                peer = data["sender"]
                if peer == username:
                    continue

                ed25519_keys[peer] = ed25519_public_from_b64(data["public_key"])
                print(f"\n[Sig] Verification key registered for {peer}")
                print(f"{username}: ", end="", flush=True)
                continue

            if data.get("type") == "chat":
                if username not in data.get("ciphertexts", {}):
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

                sender = data["sender"]
                received_hash = data.get("hash")
                if received_hash is None:
                    print(f"\n⚠️ Missing integrity hash for encrypted message from {sender}\n{username}: ", end="", flush=True)
                    continue

                computed_hash = sha256_hex(plaintext.encode("utf-8"))
                if computed_hash != received_hash:
                    print(f"\n⚠️ Integrity check failed for message from {sender}\n{username}: ", end="", flush=True)
                    continue

                sig_b64 = data.get("signature")
                if sig_b64:
                    pk = ed25519_keys.get(sender)
                    if pk is None:
                        print(f"\n⚠️ No Ed25519 public key yet for {sender}; cannot verify signature\n{username}: ", end="", flush=True)
                        continue
                    payload_bytes = chat_signing_bytes(sender, plaintext)
                    if not ed25519_verify(pk, payload_bytes, sig_b64):
                        print(f"\n⚠️ Signature verification failed for message from {sender}\n{username}: ", end="", flush=True)
                        continue

                if SHOW_HASH_DEBUG and not hash_demo_shown:
                    print("\n🔍 HASH DEBUG MODE")
                    print(f"Message:        {plaintext}")
                    print(f"Sent hash:      {received_hash}")
                    print(f"Computed hash:  {computed_hash}")
                    print("✅ Hashes match → integrity verified\n")
                    hash_demo_shown = True

                print(f"\n📩 [{data['timestamp']}] {sender}: {plaintext}\n{username}: ", end="", flush=True)
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
            await websocket.send(username)
            await announce_dh_key(websocket)
            await announce_ed25519_key(websocket)
            await asyncio.gather(
                send_messages(websocket, username),
                receive_messages(websocket, username),
            )
    except Exception as e:
        print("❌ Connection error:", e)


if __name__ == "__main__":
    asyncio.run(main())
