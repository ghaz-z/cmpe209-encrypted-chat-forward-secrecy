import datetime
import json

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

app = FastAPI()

# Store connected users: {websocket: username}
clients = {}
users = set()
messages = []
dh_public_keys = {}
ed25519_public_keys = {}


def get_pst_timestamp():
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=-8)
    return now.strftime("%Y-%m-%d %H:%M:%S PST")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    try:
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

        for msg in messages:
            await websocket.send_text(json.dumps(msg))

        for other_username, public_key in dh_public_keys.items():
            if other_username != username:
                await websocket.send_text(json.dumps({
                    "type": "dh_public",
                    "sender": other_username,
                    "public_key": public_key,
                    "timestamp": get_pst_timestamp()
                }))

        for other_username, public_key in ed25519_public_keys.items():
            if other_username != username:
                await websocket.send_text(json.dumps({
                    "type": "ed25519_public",
                    "sender": other_username,
                    "public_key": public_key,
                    "timestamp": get_pst_timestamp(),
                }))

        while True:
            data = await websocket.receive_text()

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

            if isinstance(incoming, dict) and incoming.get("type") == "ed25519_public":
                ed25519_public_keys[username] = incoming["public_key"]
                relay = {
                    "type": "ed25519_public",
                    "sender": username,
                    "public_key": incoming["public_key"],
                    "timestamp": get_pst_timestamp(),
                }

                for client in clients:
                    if client != websocket:
                        await client.send_text(json.dumps(relay))
                continue

            if isinstance(incoming, dict) and incoming.get("type") == "chat":
                msg_obj = {
                    "type": "chat",
                    "sender": username,
                    "ciphertexts": incoming.get("ciphertexts", {}),
                    "hash": incoming.get("hash"),
                    "signature": incoming.get("signature"),
                    "timestamp": get_pst_timestamp(),
                }

                messages.append(msg_obj)
                print(f"{username}: [encrypted message]")

                for client in clients:
                    if client != websocket:
                        await client.send_text(json.dumps(msg_obj))
                continue

            continue

    except WebSocketDisconnect:
        leaving_user = clients.get(websocket, "Unknown")
        print(f"{leaving_user} disconnected")

        leave_msg = {
            "sender": "System",
            "content": f"{leaving_user} left the chat",
            "timestamp": get_pst_timestamp()
        }

        for client in clients:
            if client != websocket:
                await client.send_text(json.dumps(leave_msg))

        if websocket in clients:
            username = clients.pop(websocket)
            if username in users:
                users.remove(username)
            dh_public_keys.pop(username, None)
            ed25519_public_keys.pop(username, None)
