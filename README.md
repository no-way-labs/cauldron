# Cauldron

Encrypted command-line tools written in Go. The peer-to-peer apps require no
Cauldron account and run no hosted Cauldron service. Public sessions use the
third-party `bore.pub` relay; local-only operation is available for every
networked app. Familiar is optional and requires an Anthropic API account/key.

## Apps

### mitt — encrypted file transfer

One person opens a temporary inbox and another sends a file, stdin, or literal
text to it.

```bash
# Receive files (uses bore when available)
mitt open

# Send a file
mitt send bore.pub:54321 file.txt --password fuzzy-planet-cat

# Stay entirely on loopback
mitt open --local --port 8080 --password local-test
```

See the [mitt guide](docs/mitt.md) and [v1 wire protocol](docs/mitt-protocol.md).

### seance — ephemeral encrypted group chat

One person hosts a room and others join with its shared password. Messages are
kept in memory and disappear when the processes exit.

```bash
seance host
seance join bore.pub:54321 --password fuzzy-planet-42

# Expose a loopback-only HTTP API for a bot
seance join bore.pub:54321 --password fuzzy-planet-42 --bot --api-port 9999

# Start the bundled Claude participant alongside that API
seance join bore.pub:54321 --password fuzzy-planet-42 --familiar
```

### omen — encrypted, verifiable voting

Omen runs a commit-reveal vote. Participants verify signatures, commitment
coverage, reveals, and the tally, and can save the result as a JSON artifact.

```bash
omen host "What should we name the release?" --options alpha,beta,gamma
omen join bore.pub:54321 --password misty-raven-42

omen host "Ship today?" --output result.json
omen verify result.json

# Restrict the live vote to a strictly verified covenant roster
omen host "Ship today?" --roster team.json --identity "my secret phrase"
omen join bore.pub:54321 --password misty-raven-42 --identity "my secret phrase"
```

Omen v1 is **not anonymous**. Every revealed vote can be matched to its signed
commitment and therefore to a roster slot/public key. Shuffling the reveal order
does not break that link. Without `--roster`, anyone with the room password can
vote under multiple identities. A restricted live vote enforces a verified
covenant, but the resulting v1 omen artifact does not itself prove which
covenant supplied its roster. See [SECURITY.md](SECURITY.md).

### covenant — membership signing ceremony

Participants derive Ed25519 identities from passphrases and co-sign one
canonical membership roster.

```bash
covenant host "Engineering Team" --identity "my secret phrase" --output team.json
covenant join bore.pub:54321 --password misty-raven-42 --identity "my secret phrase"

covenant verify team.json
covenant members team.json
```

Choose strong identity passphrases and exchange public-key fingerprints through
a trusted channel. Use `covenant members team.json` for the full keys; abbreviated
console prefixes are not identity checks. A valid self-contained artifact proves
control of its listed keys, not real-world identity.

### familiar — Claude participant for seance

Familiar polls a seance bot API and posts Claude responses. Its API key is read
from `ANTHROPIC_API_KEY`, never from a command-line flag.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
seance join bore.pub:54321 --password fuzzy-planet-42 --familiar

# Or, with a separately running `seance --bot` client:
familiar --api-port 9999
```

See the [familiar guide](docs/familiar.md).

## Installation

### Homebrew (macOS/Linux)

```bash
brew tap no-way-labs/cauldron
brew install mitt seance familiar omen covenant
```

### Prebuilt binaries

Each [GitHub release](https://github.com/no-way-labs/cauldron/releases) contains
macOS and Linux archives for arm64 (`aarch64`) and amd64 (`x86_64`), plus SHA-256
sidecars. Archives also carry the project license and
`THIRD_PARTY_NOTICES`. Releases are app-specific, so select the tag for the app
you want.

### From source

Go 1.26 or newer is required.

```bash
git clone https://github.com/no-way-labs/cauldron.git
cd cauldron
INSTALL_DIR="$HOME/.local/bin" ./install.sh
```

For development:

```bash
go test -race ./...
go build ./...
```

Hosts use the external [`bore`](https://github.com/ekzhang/bore) CLI to obtain a
public relay address. If it is missing or unavailable, the apps report the
failure and continue in local-only mode. Joiners and mitt senders do not need
`bore`.

## Security summary

- XChaCha20-Poly1305 authenticated encryption with random 192-bit nonces.
- Argon2id password derivation using 64 MiB, three iterations, and four lanes.
- Ed25519 identities and signatures for omen and covenant.
- Loopback-only listeners, bounded frames/artifacts, handshake deadlines, and
  participant/rate limits.
- Strict offline artifact verification that rejects duplicate JSON keys and
  inconsistent counts, rosters, commitments, signatures, or tallies.
- Best-effort clearing of sensitive byte slices. Go's runtime and garbage
  collector make complete memory erasure impossible to guarantee.

Passwords may be supplied through `MITT_PASSWORD`, `SEANCE_PASSWORD`,
`OMEN_PASSWORD`, `OMEN_IDENTITY`, `COVENANT_PASSWORD`, and
`COVENANT_IDENTITY`, avoiding exposure in shell history and process listings.
Read [SECURITY.md](SECURITY.md) before relying on these tools for sensitive use.

## Repository layout

```text
cauldron/
├── cmd/                 # five CLI entry points
├── internal/            # protocols, crypto wrappers, servers, clients, and tests
├── docs/                # app guides and stable protocol documentation
├── testdata/compat/     # deterministic legacy-compatibility vectors
├── PORT.md              # audited Zig-to-Go migration specification
├── THIRD_PARTY_NOTICES  # notices shipped with release binaries
└── install.sh
```

## License

Cauldron is licensed under the [MIT License](LICENSE).
