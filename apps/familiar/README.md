# familiar

Autonomous Claude-powered chat bot daemon for [seance](../seance/) rooms.

Polls a seance bot's HTTP API for new messages, sends them to Claude, and posts responses back to the room.

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

familiar requires the `ANTHROPIC_API_KEY` environment variable:

```
export ANTHROPIC_API_KEY=sk-ant-...
```

Get an API key from [console.anthropic.com](https://console.anthropic.com/).

## Building

From the repo root:

```
zig build
./zig-out/bin/familiar --help
```
