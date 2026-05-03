import asyncio
import base64
import datetime
import json

import websockets

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag
from crypto import decrypt, encrypt

session_keys = {}

# ephemeral DH public private keypair per client session
dh_private_key = x25519.X25519PrivateKey.generate()
dh_public_key = dh_private_key.public_key()

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

async def send_messages(websocket, username):

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
            payload = build_encrypted_message(username, msg, session_keys)
        except ValueError:
            print("⚠️ No session keys established yet. Wait for another client to complete key exchange.")
            continue

        await websocket.send(json.dumps(payload))

async def receive_messages(websocket, username):
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

            if data.get("type") == "encrypted_chat":
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

                print(
                    f"\n📩 [{data['timestamp']}] {data['sender']}: {plaintext}\n{username}: ",
                    end="",
                    flush=True,
                )
                continue


            print(f"\n📩 [{data['timestamp']}] {data['sender']}: {data['content']}\n{username}: ", end="", flush=True)

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

            await asyncio.gather(
                send_messages(websocket, username),
                receive_messages(websocket, username)
            )

    except Exception as e:
        print("❌ Connection error:", e)

if __name__ == "__main__":
    asyncio.run(main())
