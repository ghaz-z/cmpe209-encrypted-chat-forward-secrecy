# Chat Exchange Sequence Diagram (Per-Message Session with Key Ratchet)

This diagram shows the updated exchange flow with per-message key derivation:
- WebSocket connect and username registration
- X25519 DH shared secret exchange (established once per peer connection)
- Ed25519 signing key sharing
- **Each message is treated as its own session with unique derived key**
- Per-message counter-based key ratcheting
- Verification + decryption with message-specific keys

```mermaid
sequenceDiagram
    participant Alice as Client A
    participant Server as Server
    participant Bob as Client B

    Alice->>Server: websocket connect
    Alice->>Server: send username
    Server-->>Alice: accept + history + existing public keys

    Alice->>Server: {type: dh_public, public_key: A_pub}
    Server->>Server: store A_pub
    Server-->>Bob: relay dh_public A_pub (if Bob connected)

    Alice->>Server: {type: ed25519_public, public_key: A_ed25519}
    Server->>Server: store A_ed25519
    Server-->>Bob: relay ed25519_public A_ed25519 (if Bob connected)

    Bob->>Server: websocket connect
    Bob->>Server: send username
    Server-->>Bob: accept + history
    Server-->>Bob: relay A_pub + A_ed25519

    Bob->>Server: {type: dh_public, public_key: B_pub}
    Server->>Server: store B_pub
    Server-->>Alice: relay dh_public B_pub

    Bob->>Server: {type: ed25519_public, public_key: B_ed25519}
    Server->>Server: store B_ed25519
    Server-->>Alice: relay ed25519_public B_ed25519

    Note over Alice,Bob: Derive shared secret (once per peer connection)
    Alice->>Alice: derive shared secret S_AB from A_priv and B_pub
    Bob->>Bob: derive shared secret S_BA from B_priv and A_pub
    Alice->>Alice: initialize counter_AB = 0
    Bob->>Bob: initialize counter_BA = 0

    Note over Alice,Bob: Message 1: Each message is its own session
    Alice->>Alice: message_key_1 = HKDF(S_AB, info="chat-message-0")
    Alice->>Alice: counter_AB becomes 1
    Alice->>Server: {type: chat, ciphertexts: {bob: C1}, counters: {bob: 0}, hash, signature}
    Server-->>Bob: relay chat message + counter

    Bob->>Bob: message_key_1 = HKDF(S_BA, info="chat-message-0")
    Bob->>Bob: verify hash and signature using A_ed25519
    Bob->>Bob: decrypt C1 using message_key_1 (unique to this message)
    Bob->>Bob: counter_BA becomes 1
    Bob-->>Bob: display plaintext
    Note over Bob: Message 1 key now discarded

    Note over Alice,Bob: Message 2: New session, new key
    Alice->>Alice: message_key_2 = HKDF(S_AB, info="chat-message-1")
    Alice->>Alice: counter_AB becomes 2
    Alice->>Server: {type: chat, ciphertexts: {bob: C2}, counters: {bob: 1}, hash, signature}
    Server-->>Bob: relay chat message + counter

    Bob->>Bob: message_key_2 = HKDF(S_BA, info="chat-message-1")
    Bob->>Bob: verify hash and signature using A_ed25519
    Bob->>Bob: decrypt C2 using message_key_2 (different from message 1)
    Bob->>Bob: counter_BA becomes 2
    Bob-->>Bob: display plaintext
    Note over Bob: Message 1 key no longer accessible

    Note over Alice,Bob: Message 3: Continues ratcheting
    Alice->>Alice: message_key_3 = HKDF(S_AB, info="chat-message-2")
    Alice->>Alice: counter_AB becomes 3
    Alice->>Server: {type: chat, ciphertexts: {bob: C3}, counters: {bob: 2}, hash, signature}
    Server-->>Bob: relay chat message + counter

    Bob->>Bob: message_key_3 = HKDF(S_BA, info="chat-message-2")
    Bob->>Bob: verify hash and signature using A_ed25519
    Bob->>Bob: decrypt C3 using message_key_3 (unique key)
    Bob->>Bob: counter_BA becomes 3
    Bob-->>Bob: display plaintext

    Bob->>Server: disconnect
    Server->>Server: remove B_pub, B_ed25519, shared secrets
    Server-->>Alice: notify disconnect
```

**Key Security Properties:**
- Shared secret (S_AB, S_BA) established once per peer connection
- Each message derives a unique encryption key using counter-based KDF
- Compromising one message key does NOT expose other messages
- Old counters cannot decrypt new messages (forward secrecy)
- Message keys are ephemeral and discarded after use