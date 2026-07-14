# familiar

Familiar is a Claude-powered participant for a seance room. It polls the
loopback bot API for new chat messages, sends recent context to Anthropic, and
posts the response back to the room.

## Embedded mode

Set the API key and ask seance to start Familiar alongside its bot client:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
seance join bore.pub:12345 --password mysecret --familiar
```

If embedded Familiar cannot start or later stops, it logs the error without
disconnecting the seance client.

## Separate mode

```bash
# Terminal 1
seance join bore.pub:12345 --password mysecret --bot --api-port 9999

# Terminal 2
export ANTHROPIC_API_KEY=sk-ant-...
familiar --api-port 9999
```

Options:

```text
--api-port PORT  Seance bot API port (default: 9999)
--api-host HOST  Seance bot API host (default: 127.0.0.1)
--system PROMPT  System prompt/personality (replaces the default)
--context N      Messages retained as Claude context (default: 50)
--model MODEL    Anthropic model identifier
--cooldown SECS  Minimum delay after a response (default: 2)
-h, --help       Show help
-v, --version    Show version
```

Familiar retries the seance `/health` endpoint at startup, discovers its own
nickname through `/nick`, and long-polls `/messages`. Consecutive room messages
with the same role are merged before the Claude request. On an HTTP 401 it
re-reads `ANTHROPIC_API_KEY` once, allowing credential refresh without putting a
key on the command line.

Enabling Familiar sends room conversation context to Anthropic. Review
[SECURITY.md](../SECURITY.md) and Anthropic's applicable service/retention terms
before using it with sensitive content.

## Build and test

```bash
go build -o ./bin/familiar ./cmd/familiar
go test -race ./internal/familiarcore ./cmd/familiar
```
