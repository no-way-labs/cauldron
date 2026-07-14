# mitt

Mitt transfers one file, stdin stream, or literal string to a temporary
loopback-bound receiver. Payload contents are encrypted with
XChaCha20-Poly1305; a public session uses an external bore tunnel.

![mitt terminal demonstration](assets/mitt_sml.gif)

## Receive

```bash
# Save to ./inbox and create a bore tunnel when possible
mitt open

# Local testing with an explicit password and port
mitt open --local --port 8080 --password testpass

# Save elsewhere and accept only selected suffixes
mitt open --dir ~/Downloads --accept '*.txt,*.json'

# Reject selected suffixes and lower the default 100 MiB limit
mitt open --reject '*.exe,*.sh' --max-size 10485760

# Write payload bytes to stdout instead of files
mitt open --stdout
```

`--bore-port` requests a specific public relay port. If that port is already in
use, mitt retries with a random one. If bore is missing or tunnel startup fails,
the receiver reports the error and continues on localhost. `--quiet` suppresses
the password and send instructions, which is useful in integration scripts.

## Send

```bash
mitt send bore.pub:54321 document.pdf --password fuzzy-planet-cat
mitt send localhost:8080 --text 'Hello, world!' --password testpass
cat data.json | mitt send localhost:8080 - --password testpass
mitt send localhost:8080 file.txt --password testpass --timeout 60
```

`MITT_PASSWORD` may replace `--password` for either command. The sender exits
zero after receiving the success acknowledgment and exits 2 for timeout,
rejection, authentication failure, or another transfer error.

## Filters and storage

Accept/reject entries are comma-separated exact names or `*.suffix` patterns.
Reject rules run before accept rules. Incoming filenames are reduced to a base
name and must contain only ASCII letters, digits, `-`, `_`, and `.`; hidden names
and names containing `..` are rejected.

Files are created with mode `0600` using exclusive creation. A collision such as
`report.txt` becomes `report_1.txt`, selected atomically even under concurrent
transfers. At most five transfers are handled simultaneously, with ten admitted
connections per source address per minute.

Mitt uses one-shot authenticated encryption, so the complete payload is held in
memory at each endpoint. The default receive limit is 100 MiB and the hard
sender/receiver cap is 1 GiB.

## Build and test

From the repository root with Go 1.26 or newer:

```bash
go build -o ./bin/mitt ./cmd/mitt
go test -race ./internal/mitt ./cmd/mitt
```

The exact interoperable v1 framing is documented in
[mitt-protocol.md](mitt-protocol.md).
