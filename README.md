# Cauldron

Encrypted CLI tools written in Zig. No accounts, no cloud, no history.

## Apps

### mitt - encrypted file transfer
One party opens a mitt (a publicly reachable inbox), others send files to it. Everything is end-to-end encrypted and tunneled through bore.

```bash
# Receive files
mitt open

# Send a file
mitt send bore.pub:54321 file.txt --password fuzzy-planet-cat
```

### seance - ephemeral encrypted group chat
One person hosts a room, others join with a shared password. Messages are end-to-end encrypted and vanish when the room closes. Nothing touches disk.

```bash
# Host a room
seance host

# Join a room
seance join bore.pub:54321 --password fuzzy-planet-42

# Join with an AI participant (Claude)
seance join bore.pub:54321 --password fuzzy-planet-42 --familiar

# Bot mode - HTTP API for programmatic access
seance join bore.pub:54321 --password fuzzy-planet-42 --bot --api-port 9999
```

### omen - anonymous encrypted voting
One person hosts a vote with a question and options, others join to cast ballots. Votes are committed, then revealed — every participant independently verifies the tally. Nothing touches disk unless you pipe the artifact.

```bash
# Host a vote
omen host "What should we name the release?" --options alpha,beta,gamma

# Join a vote
omen join bore.pub:54321 --password misty-raven-42

# Simple yes/no (default options)
omen host "Ship today?"

# Save the cryptographic proof artifact
omen host "Ship today?" > result.json

# Verify a saved artifact
omen verify result.json
```

**Security**: commit-reveal protocol with BLAKE2b commitments, Ed25519 signatures, and Fisher-Yates shuffled reveals. Every participant verifies all signatures, checks the bijection between reveals and commitments, and tallies independently. The host cannot forge, alter, add, or remove votes without detection.

### familiar - AI chat bot for seance rooms
Autonomous Claude-powered daemon that joins a seance room and responds to messages. Uses your Claude Max subscription via OAuth token (same credentials as Claude Code).

```bash
# One-liner: seance spawns familiar automatically
seance join bore.pub:54321 --password fuzzy-planet-42 --familiar

# Or run separately
familiar --api-port 9999
```

See [apps/familiar/README.md](apps/familiar/README.md) for configuration options.

## Installation

### Homebrew (macOS/Linux)

```bash
brew tap no-way-labs/cauldron
brew install mitt
brew install seance
```

### Prebuilt Binaries

Download from [GitHub Releases](https://github.com/no-way-labs/cauldron/releases):

```bash
curl -L https://github.com/no-way-labs/cauldron/releases/latest/download/seance-linux-x86_64.tar.gz | tar xz
./seance host
```

### From Source

Requires **Zig 0.15.x** (0.15.2 recommended). Will not compile with Zig 0.16+.

```bash
zig build
```

Install all apps to `~/.local/bin`:
```bash
INSTALL_DIR=~/.local/bin ./install.sh
```

## Security

All apps share the same cryptographic foundation:

- **XChaCha20-Poly1305** authenticated encryption
- **Argon2id** key derivation (64 MiB memory, 3 iterations)
- Constant-time authentication
- Memory zeroing of plaintext after use
- Rate limiting and DoS protection
- No secrets stored on disk (familiar reads tokens from env or keychain)

## Project Structure

```
cauldron/
├── apps/
│   ├── mitt/              # Encrypted file transfer
│   ├── seance/            # Encrypted group chat
│   ├── omen/              # Anonymous encrypted voting
│   └── familiar/          # Claude chat bot for seance
└── build.zig
```

## License

MIT
