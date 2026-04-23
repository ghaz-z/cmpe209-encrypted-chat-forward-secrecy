import websockets
import json
import time

import asyncio
import websockets
import json
import datetime

async def send_messages(websocket, username):

    loop = asyncio.get_event_loop()

    def get_pst_timestamp():
        utc_now = datetime.datetime.now(datetime.timezone.utc)
        pst = datetime.timezone(datetime.timedelta(hours=-8), name="PST")
        now = utc_now.astimezone(pst)
        return now.strftime('%Y-%m-%d %H:%M:%S PST')

    while True:
        timestamp = get_pst_timestamp()
        msg = await loop.run_in_executor(None, input, f"\n[{timestamp}] {username}: ")

        # Leave command
        if msg.strip().lower() == "/leave":
            print("👋 Leaving chat...")
            await websocket.close()
            break

        await websocket.send(msg)

async def receive_messages(websocket, username):
    try:
        while True:
            msg = await websocket.recv()
            data = json.loads(msg)

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

            await asyncio.gather(
                send_messages(websocket, username),
                receive_messages(websocket, username)
            )

    except Exception as e:
        print("❌ Connection error:", e)

asyncio.run(main())