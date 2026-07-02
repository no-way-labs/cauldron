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

# Restrict voting to a covenant roster
omen host "Ship today?" --roster team.json --identity "my secret phrase"
omen join bore.pub:54321 --password misty-raven-42 --identity "my secret phrase"
```

**Security**: commit-reveal protocol with BLAKE2b commitments, Ed25519 signatures, and Fisher-Yates shuffled reveals. Every participant verifies all signatures, checks the bijection between reveals and commitments, and tallies independently, so the host cannot forge, alter, or drop a recorded vote without detection. Preventing ballot stuffing (a host or peer adding extra identities) additionally requires restricting the vote to a covenant roster with `--roster` — without it, anyone who has the room password can cast multiple ballots. `omen verify <file.json>` re-checks all of this offline. See [SECURITY.md](SECURITY.md) for the full threat model.

### covenant - membership signing ceremony
One person hosts a signing ceremony for a group, others join with their identity passphrase. Everyone exchanges public keys and co-signs the roster. The output is a multi-signed JSON artifact proving mutual agreement on membership.

```bash
# Host a signing ceremony
covenant host "Engineering Team" --identity "my secret phrase"

# Join a ceremony
covenant join bore.pub:54321 --password misty-raven-42 --identity "my secret phrase"

# Verify a saved covenant
covenant verify team.json

# List members
covenant members team.json
```

**Security**: deterministic Ed25519 identity derived from your passphrase via Argon2id, mutual attestation (every member signs the same roster hash), tamper-evident (modifying any member invalidates all signatures). No files, no accounts — your identity lives in your memory. Choose a strong passphrase: it is the only thing between an attacker and your signing key.

### familiar - AI chat bot for seance rooms
Autonomous Claude-powered daemon that joins a seance room and responds to messages. Authenticates to the Claude API with an API key read from the `ANTHROPIC_API_KEY` environment variable (never written to disk, never passed on the command line).

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

Requires **Zig 0.16.0**. Will not compile with 0.15.x or earlier (the codebase uses the 0.16 `std.Io` interface).

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
- **Argon2id** key derivation (64 MiB, 3 iterations), fail-closed — never downgrades to a weaker hash
- Auto-generated passwords use the system CSPRNG (three words + a number)
- Constant-time authentication tag and magic comparison
- Memory zeroing of keys and plaintext after use
- Servers listen on localhost only; traffic reaches them through the bore tunnel
- No secrets on disk; `familiar` reads its API key from `ANTHROPIC_API_KEY`

Secrets can be supplied via environment variables instead of command-line flags
(where they would otherwise be visible in `ps` and shell history):
`MITT_PASSWORD`, `SEANCE_PASSWORD`, `OMEN_PASSWORD` / `OMEN_IDENTITY`,
`COVENANT_PASSWORD` / `COVENANT_IDENTITY`.

See [SECURITY.md](SECURITY.md) for the threat model and known limitations.

## Project Structure

```
cauldron/
├── apps/
│   ├── mitt/              # Encrypted file transfer
│   ├── seance/            # Encrypted group chat
│   ├── omen/              # Anonymous encrypted voting
│   ├── covenant/          # Membership signing ceremony
│   └── familiar/          # Claude chat bot for seance
└── build.zig
```

## License

MIT
