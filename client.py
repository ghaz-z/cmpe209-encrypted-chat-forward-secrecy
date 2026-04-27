import asyncio
import websockets
import json
import datetime
import base64

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from crypto import sha256_hex

# flags for demo (can toggle on (showhashdebug) to show the hash computation one time and then turn off)
SHOW_HASH_DEBUG = True
hash_demo_shown = False


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

def derive_session_key(my_private_key, peer_public_key, peer_username):
    shared_secret = my_private_key.exchange(peer_public_key)

    # HMAC-based Key Derivation Function
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"chat-session".encode("utf-8"),
    ).derive(shared_secret)

    return base64.b64encode(derived).decode("utf-8")

async def announce_dh_key(websocket):
    payload = {
        "type": "dh_public",
        "public_key": public_key_to_b64(dh_public_key)
    }
    await websocket.send(json.dumps(payload))

async def send_messages(websocket, username):
    """
    Read user input from the console and send it to the server as JSON.

    Each message is turned into a json obj and contains:
    - type: tell us the message is a chat payload type
    - content: the actual message content (raw content)
    - hash: sha256 digest of the message content

    Hash is included with the plaintext, it allows users to independently verify the integroty of the message through recomputation
    This is also useful for our demo purposes

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

        payload = {
            "type": "chat",
            "content": msg,
            "hash": sha256_hex(msg.encode("utf-8"))
        }
        await websocket.send(json.dumps(payload))



async def receive_messages(websocket, username):
    """
    Continuously get messages from server

    This function handles two types of incoming messages:

    1. Diffie-Hellman key exchange ("dh_public"):
       - Receives a peer's public key
       - Derives a shared session key 
       - Stores the resulting session key per peer

    2. Chat messages ("chat"):
       - Extracts the message content and accompanying SHA-256 hash
       - Recomputes the hash over the received content
       - Compares the computed hash with the transmitted hash to verify integrity

    If hashes do not match then message is rejected and there will be a warning displayed

    The debug flag allows us during the demo to show the hashing process in action
    We can turn it off to avoid clutter by turning to false as listed in the comment on top of it

    Successful messages have a "hash verified" message printed 
    """
    global hash_demo_shown

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
                session_key = derive_session_key(dh_private_key, peer_public_key, peer)
                session_keys[peer] = session_key

                print(f"\n[DH] Session key established with {peer}")
                print(f"[DH] Derived key for {peer}: {session_key}")
                print(f"{username}: ", end="", flush=True)
                continue

            # handle hashed chat messages
            if data.get("type") == "chat":
                received_content = data["content"]
                received_hash = data["hash"]

                computed_hash = sha256_hex(received_content.encode("utf-8"))

                if computed_hash != received_hash:
                    print(f"\n⚠️ Integrity check failed for message from {data['sender']}\n{username}: ", end="", flush=True)
                    continue

                # Debug mode: show full hashing details ONCE
                if SHOW_HASH_DEBUG and not hash_demo_shown:
                    print("\n🔍 HASH DEBUG MODE")
                    print(f"Message:        {received_content}")
                    print(f"Sent hash:      {received_hash}")
                    print(f"Computed hash:  {computed_hash}")
                    print("✅ Hashes match → integrity verified\n")

                    hash_demo_shown = True

                print(f"\n📩 [{data['timestamp']}] {data['sender']}: {received_content} [hash verified]\n{username}: ", end="", flush=True)
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

            await asyncio.gather(
                send_messages(websocket, username),
                receive_messages(websocket, username)
            )

    except Exception as e:
        print("❌ Connection error:", e)

asyncio.run(main())
