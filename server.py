from fastapi import FastAPI
from fastapi import WebSocket
app = FastAPI()
clients = []

# WebSocket endpoint to handle real-time communication
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            for client in clients:
                await client.send_text(f"Message text was: {data}")
    except:
        clients.remove(websocket)