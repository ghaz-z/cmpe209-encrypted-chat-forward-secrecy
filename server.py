import json
import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

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

            if isinstance(incoming, dict) and incoming.get("type") == "encrypted_chat":
                msg_obj = {
                    "type": "encrypted_chat",
                    "sender": username,
                    "ciphertexts": incoming.get("ciphertexts", {}),
                    "timestamp": get_pst_timestamp(),
                }

                messages.append(msg_obj)

                print(f"{username}: [encrypted message]")

                for client in clients:
                    if client != websocket:
                        await client.send_text(json.dumps(msg_obj))
                continue


            # Create structured message
            msg_obj = {
                "sender": username,
                "content": data,
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
            username = clients[websocket]
            del clients[websocket]

        if username and username in users:
            users.remove(username)

        if username in dh_public_keys:
            del dh_public_keys[username]
