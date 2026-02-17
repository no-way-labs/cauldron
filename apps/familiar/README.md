# familiar

Autonomous Claude-powered chat bot daemon for [seance](../seance/) rooms.

Polls a seance bot's HTTP API for new messages, sends them to Claude, and posts responses back to the room. Uses your Claude Max subscription via OAuth token (same as Claude Code).

## Usage

**One-liner** (recommended) — seance starts familiar automatically with woven logs:
```
seance join bore.pub:12345 --password mysecret --familiar
```

**Manual** — run bot and familiar separately:
```
# Terminal 1: join with bot mode
seance join bore.pub:12345 --password mysecret --bot --api-port 9999

# Terminal 2: start familiar
familiar --api-port 9999
```

familiar detects its nick via the `/nick` endpoint and starts responding to messages.

## Options

```
familiar [options]
  --api-port PORT   Seance bot API port (default: 9999)
  --api-host HOST   Seance bot API host (default: 127.0.0.1)
  --system PROMPT   Additional personality/instructions
  --context N       Messages to keep as context (default: 50)
  --model MODEL     Claude model (default: claude-sonnet-4-5-20250929)
  --cooldown SECS   Min seconds between responses (default: 2)
  -h, --help        Show help
  -v, --version     Show version
```

## Authentication

familiar needs a Claude OAuth token. It checks these sources in order:

1. `CLAUDE_CODE_OAUTH_TOKEN` environment variable
2. macOS Keychain (`security find-generic-password -s "Claude Code-credentials" -w`)

To set up a token, run `claude` (Claude Code CLI) and authenticate, then familiar will automatically pick up the stored credential.

## Building

From the repo root:

```
zig build
./zig-out/bin/familiar --help
```
