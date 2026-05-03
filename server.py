import json
from fastapi import FastAPI, WebSocket
import json
import datetime

app = FastAPI()

# Store connected users: {websocket: username}
clients = {}
# Want to ensure users have unique usernames, so we can also maintain a set of usernames
users = set()
# Store messages (in-memory)
messages = []

dh_public_keys = {}

# store each users ed25519 publi c key as base64 string
ed25519_public_keys = {}

def get_pst_timestamp():
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=-8)
    return now.strftime('%Y-%m-%d %H:%M:%S PST')

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    try:
        # First message = username
        username = await websocket.receive_text()
        username = username.strip()
        if username in users or not username:
            await websocket.send_text(json.dumps({
                    "sender": "System",
                    "content": "Username already taken or is empty. Disconnecting."
                }))
            await websocket.close()
            return

        users.add(username)
        clients[websocket] = username

        print(f"{username} connected")

        # Send chat history to the new user
        for msg in messages:
            await websocket.send_text(json.dumps(msg))

        # Both parties need to have the same session key
        for other_username, public_key in dh_public_keys.items():
            if other_username != username:
                await websocket.send_text(json.dumps({
                "type": "dh_public",
                "sender": other_username,
                "public_key": public_key,
                "timestamp": get_pst_timestamp()
                }))
        # when 2nd user joins chat, send them the other user's (user A's) public key to verify their signatures
        # important because without this feature userB would be able to get the messages in the chat but wouldn't be able to verify the signatures/userA
        for other_username, public_key in ed25519_public_keys.items():
            if other_username != username:
                await websocket.send_text(json.dumps({
                    "type": "ed25519_public",
                    "sender": other_username,
                    "public_key": public_key,
                    "timestamp": get_pst_timestamp(),
                }))
        """
        Main message handling loop for each connected WebSocket client.

        This loop processes three categories of incoming data:

        1. Diffie-Hellman key exchange messages ("dh_public"):
        - Stores the sender's public key
        - Broadcasts the key to all other connected clients
        - Enables peers to independently derive shared session keys

        2. Ed25519 signing public key ("ed25519_public"):
        - Stores the sender's signing public key (base64)
        - Broadcasts it so peers can verify chat signatures from that username

        3. Structured chat messages ("chat"):
        - Expects JSON input containing message content and a SHA-256 hash (and optional signature)
        - Wraps the message with server-side metadata (sender, timestamp)
        - Preserves hash and signature for clients to verify integrity and authenticity
        - Broadcasts the message to all other clients

        4. Fallback (plain text messages):
        - Handles legacy or non-JSON input
        - Assigns a null hash value
        - Still broadcasts the message to maintain compatibility

        All messages are stored in-memory and relayed to other connected clients.
        """

        while True:
            data = await websocket.receive_text()

            # try parsing JSON for DH handshake messages
            try:
                incoming = json.loads(data)
            except json.JSONDecodeError:
                incoming = None

            if isinstance(incoming, dict) and incoming.get("type") == "dh_public":
                dh_public_keys[username] = incoming["public_key"]
                relay = {
                    "type": "dh_public",
                    "sender": username,
                    "public_key": incoming["public_key"],
                    "timestamp": get_pst_timestamp()
                }

                for client in clients:
                    if client != websocket:
                        await client.send_text(json.dumps(relay))
                continue

            # this is process of server sending the user's public key to the other user on the chat (does not store the key, just sends it to the other user)
            # after connecting user send's its public key which gets stores with their username and sent to the other user in the chat
            if isinstance(incoming, dict) and incoming.get("type") == "ed25519_public":
                ed25519_public_keys[username] = incoming["public_key"]
                relay = {
                    "type": "ed25519_public",
                    "sender": username,
                    "public_key": incoming["public_key"],
                    "timestamp": get_pst_timestamp(),
                }
                # state public key to the other clients in the chat while making sure ot to send a user their own key
                for client in clients:
                    if client != websocket:
                        await client.send_text(json.dumps(relay))
                continue

            if isinstance(incoming, dict) and incoming.get("type") == "chat":
                # Create structured message (signature passthrough from client — server does not verify it)
                msg_obj = {
                    "type": "chat",
                    "sender": username,
                    "content": incoming["content"],
                    "hash": incoming.get("hash"),
                    "signature": incoming.get("signature"),
                    "timestamp": get_pst_timestamp()
                }

                # Store message
                messages.append(msg_obj)

                print(f"{username}: {incoming['content']}")

                # Broadcast to all other clients
                for client in clients:
                    if client != websocket:
                        await client.send_text(json.dumps(msg_obj))
                continue

            msg_obj = {
                "type": "chat",
                "sender": username,
                "content": data,
                "hash": None,
                "timestamp": get_pst_timestamp()
            }

            # Store message
            messages.append(msg_obj)

            print(f"{username}: {data}")

            # Broadcast to all other clients
            for client in clients:
                if client != websocket:
                    await client.send_text(json.dumps(msg_obj))




    except Exception as e:
        # identify which user left chat
        leaving_user = clients.get(websocket, "Unknown")
        print(f"{leaving_user} disconnected")

        # system generated message to inform nother users in chat that a user has left
        leave_msg = {
            "sender": "System",
            "content": f"{leaving_user} left the chat",
            "timestamp": get_pst_timestamp()
        }

        # broadcast message to remaining users still connected
        for client in clients:
            if client != websocket:
                await client.send_text(json.dumps(leave_msg))

        # clean up the user from the clients list and users set (since disconnected)
        if websocket in clients:
            uname = clients.pop(websocket)
            # remove username from set of active users
            if uname in users:
                users.remove(uname)
            # remove any stored keys for the user from the dictionaries (prevention of expired keys from being reused if another person with the same username tries to reconnect)
            dh_public_keys.pop(uname, None)
            ed25519_public_keys.pop(uname, None)
