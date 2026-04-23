# cmpe209-encrypted-chat-forward-secrecy

Currently to run everything and see messages:
- Start the server: uvicorn server:app --reload
- Open two terminals and in each terminal: python client.py 

NOTE: Right now there's no distinction or "users" - we need to add something to distinguish them; probably for the time being it might be a JSON file that gets wrote to eventually?

## Steps for Project Completion
- 1. Server and client setup (complete)
- 2. Add user identity (partially complete! Will add more later to maybe have "permanent" users or even just simulate a login but there are distinguishing differences between users now)
- 3. Implement encryption of messages (AES-256-GCM)
- 4. Add key exchange (in our case Diffie-Hellman) for session keys
- 5. Add forward secrecy (ephemeral session keys to ensure forward secrecy)
- 6. Writing attack tests
