# cmpe209-encrypted-chat-forward-secrecy

Currently to run everything and see messages:
- Start the server: uvicorn server:app --reload
- Open two terminals and in each terminal: python client.py 

For client.py:
- /leave will allow the user to disconnect; message will be sent showing the user has disconnected

## Steps for Project Completion
- 1. Server and client setup (complete)
- 2. Add user identity (partially complete! Will add more later to maybe have "permanent" users or even just simulate a login but there are distinguishing differences between users now)
- 3. Implement encryption of messages (AES-256-GCM) (complete)
- 4. Add key exchange (in our case Diffie-Hellman) for session keys
- 5. Add forward secrecy (ephemeral session keys to ensure forward secrecy)
- 6. Hashing + a digital sig algo (done)
- 7. Writing attack tests


#Hashing + Digital Sig Demo + Flow

Enter your username: laura *user must pick a unique name*
✅ Connected to server *successfully opened websocket connection*
[Sig] Our Ed25519 public key (others verify our signatures with this): LdZ8Pp/L2KMuvcyrGz1difRvz/L1FvxrbP2O/QjZJLA= *client generates ed25519 key pair, public key gets shared after encoded in base64, private key used to sign outgoing messages and doesnt get shared*

[2026-05-04 10:42:32 PST] laura:
[DH] Session key established with kirthana *laura received kirthana's DH public key which was sent by server -> combined laura private key and kirthana public key to make shared secret -> run sha256 to dervce 32byte shared symmetric key*
[DH] Derived AES-256 session key with kirthana (hex): a633ffd1dcb6ec2c6e23761241457f4ad76e77b14110a321ae78019a9d1b97df *prints that derived key in hex -> demo: if kirthana prints same hex as laura then its proof both sides derviced same key and DH worked* **THIS IS IMPORTANT**
laura:
[Sig] Verification key registered for kirthana *laura received kirthana's public key and stored it in ed25519_keys[kirthana]*
[Sig] kirthana's Ed25519 public key (base64): nfMbAY1H5ibxCHLvnA7JH8/rfCQ31PG6jZtGu9gB7qA= *prints kirthana's public key encoded in base64 -> use for sig validation*
[Sig] Fingerprint SHA256(raw Ed25519 pubkey): 0c3b8d0a2e8c84b06d21f0d110c5f464… *short hash of the public key for easy visual comparison*
laura: hi *user sends a message; client encrypts, hashes ciphertext bundle, signs it, then sends*

[2026-05-04 10:42:50 PST] laura:
✅ Hash verified + signature verified (first encrypted message received) *integrity + authenticity checks passed*
   - Hash matches recomputed SHA-256 over ciphertext bundle
   - Signature verifies using kirthana's Ed25519 public key

## This is a simple demo flow 

laura -> runs `python client.py` -> enters username `laura` -> connects to server

kirthana -> runs `python client.py` -> enters username `kirthana` -> connects to server

server -> relays DH public keys + Ed25519 public keys between laura and kirthana

laura <-> kirthana -> `[DH] Session key established ...` -> both derive the same AES-256 session key (compare the hex values on both terminals)

laura <-> kirthana -> `[Sig] Verification key registered ...` -> both store each other’s Ed25519 public key for verifying signatures

laura -> sends `hi` -> client encrypts with AES-GCM -> hashes the ciphertext bundle (SHA-256) -> signs it (Ed25519) -> sends to server

server -> broadcasts the encrypted bundle + hash + signature

kirthana -> recomputes hash -> verifies signature using laura’s Ed25519 public key -> decrypts -> prints plaintext



