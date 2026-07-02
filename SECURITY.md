# Security

Cauldron's tools are small, ephemeral, peer-to-peer CLIs. This document states
what they protect, what they don't, and the assumptions behind those claims so
you can decide whether they fit your threat model.

## Shared design

- **Transport.** Apps connect over a [bore](https://github.com/ekzhang/bore)
  tunnel to the public `bore.pub` relay. The relay sees only ciphertext. The
  local server binds `127.0.0.1`; bore forwards from localhost.
- **Encryption.** XChaCha20-Poly1305 (AEAD) with a random 192-bit nonce per
  message. The key is derived from a shared password with Argon2id
  (64 MiB, t=3, p=4). Key derivation is **fail-closed**: if Argon2id cannot
  run it aborts rather than downgrading to a weaker hash.
- **Passwords.** Auto-generated passwords are three words plus a number drawn
  from the system CSPRNG (~35 bits of entropy against the bundled 787-word
  list). You can supply your own; longer is stronger.
- **Signatures / identity** (omen, covenant). Ed25519. A passphrase-derived
  identity is stretched through Argon2id before seeding the key, so a weak
  passphrase is not trivially brute-forced into your signing key.
- **Memory.** Keys and plaintext are zeroed after use where practical.

## What is protected

- **Confidentiality/integrity in transit.** Someone who can observe or run the
  `bore.pub` relay, or is otherwise on the network path, sees only AEAD
  ciphertext and cannot read or undetectably modify messages **without the
  password**.
- **Vote integrity** (omen). Given the recorded roster, every participant can
  verify — live and later, via `omen verify` — that each commitment is signed
  by a roster key, each reveal opens exactly one commitment, and the tally
  matches the reveals. The host cannot forge, alter, or drop a recorded vote
  without detection.
- **Membership attestation** (covenant). Every member signs the same roster
  hash; altering any member invalidates the signatures. `covenant verify`
  checks all of them.

## What is NOT protected — assumptions and limitations

- **Password strength is the whole game.** Confidentiality rests entirely on
  the shared password. The relay is public and the first handshake frame
  encrypts a fixed known string, so an attacker who captures traffic can mount
  an **offline dictionary attack**. Argon2id makes each guess expensive, but a
  weak or low-entropy password can still be broken offline, after which all
  traffic for that session is readable. Use a strong password for anything
  sensitive, and share it over a separate trusted channel.
- **Sybil / ballot stuffing** (omen). Without `--roster`, anyone who has the
  room password can join multiple times and vote multiple times, and a
  malicious host can add phantom voters to the roster. Independent verification
  proves the recorded votes are internally consistent — **not** that the voters
  were distinct or eligible. For a vote whose result must be trustworthy,
  restrict it to a covenant roster with `--roster`; then only holders of a
  rostered identity passphrase can be counted.
- **`omen verify` scope.** It proves the artifact is the host's and was not
  altered after signing, and that the recorded votes are internally consistent.
  It cannot prove voter eligibility unless the vote used `--roster`. It also
  assumes the artifact bytes are unmodified formatting-wise (it is machine
  generated on a single line).
- **Malicious host during a live vote.** A host could withhold protocol
  messages from a targeted client. Clients refuse to display a tally they could
  not verify, but a host can still deny service.
- **Endpoint trust.** These tools assume your own machine is not compromised.
  Anything with your identity passphrase can impersonate you; anything reading
  your process memory can read keys.
- **Denial of service.** Servers cap participants and time out stalled
  handshakes, but a determined attacker with the password can still disrupt a
  session. There is no anti-abuse layer beyond that.
- **Metadata.** The relay and network observers can see connection timing,
  volume, and that the tools are in use, even though contents are encrypted.

## Reporting

These are hobby tools with no formal support or guarantee. If you find a
vulnerability, open an issue describing the impact and a reproduction; avoid
including live secrets.
