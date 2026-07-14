# Security

Cauldron is a collection of small peer-to-peer command-line tools. It has not
received a formal security audit. This document describes the v1 protocols and
their limits so you can decide whether they fit your threat model.

## Shared design

- **Transport:** hosts bind only to `127.0.0.1`. For public sessions they spawn
  the external [`bore`](https://github.com/ekzhang/bore) client, which forwards
  TCP through the third-party `bore.pub` relay.
- **Encryption:** XChaCha20-Poly1305 with a fresh random 192-bit nonce. Shared
  keys use Argon2id with 64 MiB of memory, three iterations, four lanes, and an
  app-specific fixed salt. Key derivation fails closed.
- **Passwords:** generated room passwords contain three independently selected
  words and a number, about 35 bits with the bundled word list. User-supplied
  passwords may be stronger.
- **Identity and signatures:** omen and covenant derive deterministic Ed25519
  keys from an Argon2id-stretched identity passphrase. They use BLAKE2b-256 for
  commitments and roster hashes.
- **Resource limits:** listeners cap frames, artifacts, participants, and
  concurrent work; stalled handshakes and transfers have deadlines. These
  controls reduce accidental exhaustion but are not a complete denial-of-service
  defense.
- **Memory handling:** owned sensitive slices and keys are overwritten when
  practical. This is best effort only. Go may copy values in stacks, heap
  growth, library internals, or garbage-collector-managed memory, so Cauldron
  cannot guarantee complete erasure.
- **Terminal output:** protocol text is rendered without stripping ANSI/control
  sequences for v1 compatibility. A malicious room participant, host, or
  artifact can therefore emit terminal escape sequences through messages,
  nicknames, questions, options, or metadata. Use these tools only with trusted
  participants/artifacts in a terminal whose escape-sequence behavior you
  understand.

## What the encryption protects

An observer or relay without the shared password cannot decrypt or silently
alter an AEAD-protected payload. A captured session does, however, give an
attacker a fixed known-plaintext handshake with which to test password guesses
offline. Argon2id makes guesses expensive; it does not rescue a weak password.

Share passwords through a separate trusted channel. Prefer the environment
variables documented in the README over command-line secrets, which are often
visible in shell history and process listings.

Omen/covenant public keys also expose a verifier for deterministic identity
passphrases: an attacker can derive a candidate key and compare it with the
published roster key offline. Their Argon2id step raises the cost but does not
make a weak or reused identity phrase safe.

## Metadata and unauthenticated headers

The v1 wire formats do not encrypt everything:

- The shared seance/omen/covenant envelope exposes message type, timestamp,
  sender nickname, and payload length.
- Mitt exposes the filename and encrypted payload size.
- The relay and network observers see endpoint addresses, timing, duration, and
  traffic volume.

The v1 envelope headers and mitt filename are not included as AEAD associated
data. An active relay or participant can therefore alter those fields without
invalidating the encrypted payload. Most ceremony state is revalidated at a
higher layer, but seance peers display the relayed sender/timestamp header, so
those labels are spoofable. Do not treat a seance nickname as authenticated
identity.

## App-specific guarantees and limits

### Mitt

File contents are encrypted and authenticated. Filenames are visible and not
cryptographically bound to the contents. The receiver sanitizes names, creates
files exclusively with mode `0600`, and chooses collision suffixes atomically.
The implementation buffers one complete payload for one-shot AEAD and enforces a
hard 1 GiB cap (100 MiB by default); memory use can still be substantial.

### Seance

Chat contents are encrypted under one room password and are not persisted by
Cauldron. There is no forward secrecy: compromise of the room password permits
decryption of captured traffic. Every participant shares the same symmetric key,
so any participant can create valid ciphertext and spoof clear sender headers.
The host can observe, omit, reorder, or selectively relay messages and can deny
service. Nicknames are convenience labels, not identities.

Bot mode retains at most 10,000 received events in process memory and exposes
them on an unauthenticated HTTP API bound to loopback. Any local process able to
connect to that port can read events, send messages, or disconnect the bot
client; loopback binding is not per-user authentication.

### Familiar

Familiar sends seance conversation context to Anthropic's API. Enabling it means
messages are no longer confined to the room participants and bore transport;
Anthropic's service terms and retention policy also apply. Familiar reads
`ANTHROPIC_API_KEY` from the environment and does not intentionally persist it.

### Covenant

Each member signs the canonical roster hash. Verification rejects duplicate
keys/JSON members, stale counts, noncanonical ordering, hash mismatches, and bad
signatures. Altering a nickname or public key breaks the roster signatures.

The v1 member signatures bind only the roster. They do **not** bind
`group_name`, `created_at`, `session_id`, or `covenant_version`; those metadata
fields can be relabeled without invalidating the member signatures. A
self-contained covenant proves that the listed private keys signed one roster,
not that the nicknames correspond to particular people. Compare fingerprints
through an authenticated out-of-band channel using the full keys from
`covenant members`; the short prefixes in ceremony/verification displays are
only visual labels.

### Omen

Omen verifies that, for the artifact's recorded roster:

- every roster slot has exactly one correctly signed commitment;
- every reveal opens exactly one commitment and every commitment is opened;
- choices are valid and the tally/winner match the reveals; and
- the host signature authenticates the serialized artifact prefix.

This provides internal consistency, not anonymity or real-world eligibility.
Omen v1 is **linkable**: a reveal contains the vote and blinding value, so anyone
can recompute its commitment and map it to the signed roster slot/public key.
Reveal shuffling does not hide that mapping.

Without `--roster`, anyone with the room password—including the host—can create
multiple identities. With `--roster`, the live Go implementation strictly
verifies a covenant and admits each roster key at most once, but the saved v1
omen artifact does not contain a cryptographic link to that covenant. An offline
artifact verifier can prove only the consistency of the roster it was given.

Voter commitment signatures bind the roster hash and commitment, but not the
session ID, question, or options. The host signature binds those artifact fields,
and live clients compare final state with what they observed, but voters have not
individually attested that metadata. A malicious host may also exclude someone
before freezing the roster or withhold messages; clients fail rather than accept
an unverifiable result, but cannot prevent denial of service.

## Endpoint compromise

Cauldron assumes the endpoint machines are trusted. Malware or another process
with sufficient access can read passphrases, API keys, plaintext, or process
memory and can impersonate that endpoint. Cryptography does not protect against
that threat.

## Reporting vulnerabilities

Open a GitHub issue with impact and reproduction details, omitting live secrets.
For a vulnerability whose public disclosure would put users at immediate risk,
use GitHub's private vulnerability-reporting mechanism if it is available for
the repository.
