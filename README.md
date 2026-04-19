# cmpe209-encrypted-chat-forward-secrecy

Currently to run everything and see messages:
- Start the server: uvicorn server:app --reload
- Open two terminals and in each terminal: python client.py 

NOTE: Right now there's no distinction or "users" - we need to add something to distinguish them; probably for the time being it might be a JSON file that gets wrote to eventually?