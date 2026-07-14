# Mitt v1 wire protocol

This document records the compatibility surface shared with released Zig mitt
clients and servers. All integers are unsigned big-endian values. The protocol
runs directly over one TCP connection per transfer.

## Request

```text
+----------------------+------------------------------------------+
| Field                | Encoding                                 |
+----------------------+------------------------------------------+
| filename length      | u16                                      |
| filename             | filename length bytes                    |
| ciphertext length    | u64                                      |
| nonce                | 24 bytes                                 |
| authentication tag   | 16 bytes                                 |
| ciphertext           | ciphertext length bytes                  |
+----------------------+------------------------------------------+
```

XChaCha20-Poly1305 does not expand the ciphertext portion, so ciphertext length
equals plaintext length; the 16-byte tag is sent separately. Associated data is
empty. The filename and both lengths are therefore visible and are not
cryptographically bound to the payload.

The symmetric key is:

```text
Argon2id(password, salt="mitt-v1-salt-24!", time=3,
         memory=65536 KiB, lanes=4, output=32 bytes)
```

Production nonces come from the operating-system CSPRNG and must never be reused
with the same key.

## Response

On a successful authenticated save/write, the receiver sends one byte with
value `0`. Legacy-compatible rejection paths generally close the connection
without an acknowledgment; senders must treat EOF, timeout, or a nonzero byte as
failure.

## Limits

- Sender filename field: 1–65,535 bytes.
- Go receiver filename limit: 1,024 bytes, followed by strict sanitization.
- Hard payload cap: 1 GiB.
- Default receive cap: 100 MiB.
- Transfer deadline: 120 seconds at the receiver; 30 seconds at the sender by
  default.

The receiver binds only to loopback. Bore forwarding changes reachability, not
this framing or cryptography.
