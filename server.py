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
        """
        Main message handling loop for each connected WebSocket client.

        This loop processes three categories of incoming data:

        1. Diffie-Hellman key exchange messages ("dh_public"):
        - Stores the sender's public key
        - Broadcasts the key to all other connected clients
        - Enables peers to independently derive shared session keys

        2. Structured chat messages ("chat"):
        - Expects JSON input containing message content and a SHA-256 hash
        - Wraps the message with server-side metadata (sender, timestamp)
        - Preserves the provided hash for end-to-end integrity verification
        - Broadcasts the message to all other clients

        3. Fallback (plain text messages):
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

            if isinstance(incoming, dict) and incoming.get("type") == "chat":
                # Create structured message
                msg_obj = {
                    "type": "chat",
                    "sender": username,
                    "content": incoming["content"],
                    "hash": incoming.get("hash"),
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
        username = clients.get(websocket, "Unknown")
        print(f"{username} disconnected")

        # Create system message
        leave_msg = {
            "sender": "System",
            "content": f"{username} left the chat",
            "timestamp": get_pst_timestamp()
        }

        # Send to all remaining clients
        for client in clients:
            if client != websocket:
                await client.send_text(json.dumps(leave_msg))

        # Remove user
        if websocket in clients:
            del clients[websocket]
            username = clients.get(websocket, None)

        if username and username in users:
            users.remove(username)
