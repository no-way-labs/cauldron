# Cauldron

A monorepo for various CLI applications written in Zig.

## Structure

```
cauldron/
├── apps/
│   ├── mitt/            # Encrypted file transfer CLI
│   │   ├── src/
│   │   │   ├── main.zig
│   │   │   ├── server.zig
│   │   │   ├── client.zig
│   │   │   ├── crypto.zig
│   │   │   └── ...
│   │   └── README.md
│   └── seance/          # Ephemeral encrypted P2P chat
│       └── src/
│           ├── main.zig
│           ├── server.zig
│           ├── client.zig
│           ├── crypto.zig
│           ├── protocol.zig
│           ├── display.zig
│           └── ...
└── build.zig            # Root build file (builds all apps)
```

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
# Example: seance on Linux x86_64
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

## Running (without installing)

Run from the root:
```bash
# Run default app (mitt)
zig build run -- open

# Run specific app
zig build mitt -- open
zig build seance -- host --local
```

Run from app directory:
```bash
cd apps/mitt
zig build run -- open
```

## Apps

### mitt
An encrypted file transfer CLI tool. One party opens a "mitt" (a publicly reachable inbox), others send to it.

**Features:**
- End-to-end encryption using XChaCha20-Poly1305
- Argon2id key derivation for strong password protection
- Rate limiting and DoS protection
- Tunneling via bore (optional)
- File filtering by extension and size
- Raw TCP for fast transfers

**Security:**
- Argon2id-based key derivation (64 MiB memory, 3 iterations)
- Rate limiting (10 connections/min per IP)
- Filename sanitization (prevents path traversal)
- Constant-time authentication
- Memory security (plaintext zeroed)

```bash
# Receiver
mitt open

# Sender
mitt send bore.pub:54321 file.txt --password fuzzy-planet-cat
```

See [apps/mitt/README.md](apps/mitt/README.md) for full documentation.

**Note**: mitt is designed for trusted peer-to-peer transfers. Use over VPNs or trusted networks for sensitive data.

### seance
Ephemeral encrypted group chat. No accounts, no history, no cloud. One person hosts a room, others join with a shared password. Everything is end-to-end encrypted and vanishes when the room closes. Messages never touch disk.

**Features:**
- End-to-end encryption using XChaCha20-Poly1305
- Argon2id key derivation with domain-separated salt
- Auto-generated passwords (word-word-number format)
- NAT traversal via bore tunneling (enabled by default)
- Colored nicknames with deterministic hashing
- Participant list on join
- Rate limiting (10 msg/sec per peer)
- Nick collision resolution
- Memory security (plaintext zeroed after use)

```bash
# Host a room (auto-generates password, tunnels via bore)
seance host

# Host a local-only room (no tunnel)
seance host --local

# Join a room
seance join bore.pub:54321 --password fuzzy-planet-42

# Bot mode - HTTP API instead of stdin/stdout
seance join bore.pub:54321 --password fuzzy-planet-42 --bot --api-port 9999
curl -X POST localhost:9999/send -d "hello from a script"
curl localhost:9999/messages?since=0&wait=30

# Custom options
seance host --port 9000 --nick alice --max-peers 4
seance join 192.168.1.5:9000 --password mypass --nick bob
```

## Adding New Apps

To add a new CLI app:

1. Create a new directory under `apps/`:
   ```bash
   mkdir -p apps/my-new-app/src
   ```

2. Add your Zig source files in `apps/my-new-app/src/main.zig`

3. Update the root `build.zig` to include your new app (add module, executable, and test steps)

## License

MIT