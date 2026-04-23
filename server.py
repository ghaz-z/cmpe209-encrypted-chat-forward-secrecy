import json
from fastapi import FastAPI, WebSocket
import json
import datetime

app = FastAPI()

# Store connected users: {websocket: username}
clients = {}

# Store messages (in-memory)
messages = []


def get_pst_timestamp():
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=-8)
    return now.strftime('%Y-%m-%d %H:%M:%S PST')

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    try:
        # First message = username
        username = await websocket.receive_text()
        clients[websocket] = username

        print(f"{username} connected")

        # Send chat history to the new user
        for msg in messages:
            await websocket.send_text(json.dumps(msg))

        while True:
            data = await websocket.receive_text()

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
            del clients[websocket]