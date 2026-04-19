import asyncio
import websockets

async def send_messages(websocket):
    loop = asyncio.get_event_loop()
    while True:
        msg = await loop.run_in_executor(None, input, "You: ")
        await websocket.send(msg)

async def receive_messages(websocket):
    while True:
        msg = await websocket.recv()
        print(f"Received: {msg}\nYou: ", end="", flush=True)

async def main():
    uri = "ws://127.0.0.1:8000/ws"
    
    try:
        async with websockets.connect(uri) as websocket:
            print("✅ Connected to server")
            await asyncio.gather(
                send_messages(websocket),
                receive_messages(websocket)
            )
    except Exception as e:
        print("ERROR: Connection error:", e)

asyncio.run(main())