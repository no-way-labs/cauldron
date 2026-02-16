# mitt

<img src="assets/mitt_sml.gif" alt="mitt" width="400"/>

A CLI tool for ephemeral, encrypted file/data transfer. One party opens a "mitt" (a publicly reachable inbox), others send to it.

## Features

- End-to-end encryption using XChaCha20-Poly1305
- Password-based authentication
- No accounts or central server required
- Tunneling via bore (optional, falls back to local-only)
- File filtering by extension and size
- Send files, stdin, or text
- Raw TCP for fast, efficient transfers

## Installation

### Homebrew (macOS/Linux)

```bash
brew tap no-way-labs/cauldron
brew install mitt
```

### From Source

Prerequisites:
- Zig 0.15.0 or later

```bash
cd apps/mitt
zig build
```

The binary will be at `zig-out/bin/mitt`.

## Optional: bore CLI

[bore](https://github.com/ekzhang/bore) is optional and only needed by receivers for public access:

```bash
# Via Homebrew
brew install bore-cli

# Or via Cargo
cargo install bore-cli
```

**Note**: Only the receiver needs bore to create a public tunnel. Senders just need the mitt binary - they connect directly to the receiver's address without needing bore installed.

If bore is not installed, mitt will automatically fall back to local-only mode.

## Usage

### Open a mitt (receive files)

```bash
# Basic usage - receive files to ./inbox
mitt open

# Specify custom directory
mitt open --dir ~/downloads

# Accept only specific file types
mitt open --accept "*.txt,*.json,*.csv"

# Reject specific file types
mitt open --reject "*.exe,*.sh"

# Limit file size (in bytes)
mitt open --max-size 10485760  # 10MB

# Print received data to stdout instead of saving
mitt open --stdout

# Use specific local port
mitt open --port 8080

# Request specific remote bore port (if available)
# Note: You'll be notified if the requested port is unavailable
mitt open --bore-port 9000

# Set custom password
mitt open --password mysecretpass

# Local mode (no tunnel, for testing)
mitt open --port 8080 --local
```

When you run `mitt open`, you'll see output like:

```
🔐 Password: fuzzy-planet-cat
Local: localhost:54321

Public: bore.pub:54321

To send a file:
  mitt send bore.pub:54321 <file> --password fuzzy-planet-cat

Waiting for files...
```

If you request a specific bore port that's already in use, mitt will automatically fall back to a random port:

```
🔐 Password: fuzzy-planet-cat
Local: localhost:54321

Bore port 9000 is already in use, trying random port...
Public: bore.pub:43210

To send a file:
  mitt send bore.pub:43210 <file> --password fuzzy-planet-cat

Waiting for files...
```

If bore is not installed or unavailable, it will automatically fall back:

```
🔐 Password: fuzzy-planet-cat
Local: localhost:54321

Warning: Could not establish tunnel (...)
Running in local-only mode.

To send a file:
  mitt send localhost:54321 <file> --password fuzzy-planet-cat

Waiting for files...
```

### Send files to a mitt

```bash
# Send a file
mitt send bore.pub:54321 ./document.pdf --password fuzzy-planet-cat

# Send to localhost (local testing)
mitt send localhost:54321 ./file.txt --password mysecretpass

# Send from stdin
cat data.txt | mitt send bore.pub:54321 - --password fuzzy-planet-cat

# Send literal text
mitt send bore.pub:54321 --text 'Hello, World!' --password fuzzy-planet-cat

# Send JSON data
mitt send bore.pub:54321 --text '{"hello": "world", "foo": "bar"}' --password fuzzy-planet-cat

# With custom timeout (seconds)
mitt send bore.pub:54321 ./file.txt --password fuzzy-planet-cat --timeout 60
```

## Example Session

Terminal 1 (receiver):
```bash
$ mitt open --accept "*.txt,*.json" --max-size 10485760

🔐 Password: happy-ocean-wolf
Local: localhost:54321

Public: bore.pub:54321

To send a file:
  mitt send bore.pub:54321 <file> --password happy-ocean-wolf

Waiting for files...

Received: notes.txt (421 bytes) -> ./inbox/notes.txt
```

Terminal 2 (sender):
```bash
$ mitt send bore.pub:54321 ./notes.txt --password happy-ocean-wolf
Delivered.

$ mitt send bore.pub:54321 ./huge.zip --password happy-ocean-wolf
Failed: file too large

$ mitt send bore.pub:54321 ./notes.txt --password wrongpassword
Failed: Server rejected transfer
```

## Architecture

```
mitt/
├── src/
│   ├── main.zig              # Entry point, arg parsing, subcommand dispatch
│   ├── server.zig            # TCP server for receiving encrypted data
│   ├── client.zig            # TCP client for sending encrypted data
│   ├── crypto.zig            # XChaCha20-Poly1305 encryption/decryption
│   ├── tunnel.zig            # Bore tunnel support
│   ├── id.zig                # Human-readable password generation
│   ├── filter.zig            # Accept/reject logic (extension, size)
│   ├── storage.zig           # Write incoming files to disk
│   ├── config.zig            # Config file parsing, defaults
│   ├── test_integration.zig  # Integration tests
│   └── wordlist.txt          # Words for password generation (embedded at compile time)
```

### Protocol

Raw TCP with binary framing:

```
[filename_len: u16][filename: bytes][encrypted_size: u64]
[nonce: 24 bytes][tag: 16 bytes][encrypted_data: bytes]
[ack: 1 byte]
```

- Client encrypts file data using XChaCha20-Poly1305 with password-derived key
- Server decrypts and validates using the same key
- Authentication tag ensures integrity and authenticity

## Testing

### Running Unit Tests

```bash
zig build test
```

This runs the unit tests for individual modules:
- `crypto.zig` - Encryption/decryption
- `id.zig` - Password generation
- `filter.zig` - File filtering logic (extensions, size limits)
- `storage.zig` - File saving and collision handling

### Integration Testing

#### 1. Test local encrypted file transfer

Terminal 1:
```bash
# Start server on a specific port with custom password
zig-out/bin/mitt open --port 8080 --password testpass --dir ./test-inbox --local
```

Terminal 2:
```bash
# Create a test file
echo "Hello, World!" > test.txt

# Send to localhost
zig-out/bin/mitt send localhost:8080 test.txt --password testpass
```

Check that `./test-inbox/test.txt` contains the expected content.

#### 2. Test wrong password rejection

Terminal 1:
```bash
zig-out/bin/mitt open --port 8080 --password correctpass --dir ./test-inbox --local
```

Terminal 2:
```bash
# This should fail with "Server rejected transfer"
zig-out/bin/mitt send localhost:8080 test.txt --password wrongpass
```

#### 3. Test filtering

Terminal 1:
```bash
# Start with accept filter
zig-out/bin/mitt open --port 8080 --password testpass --accept "*.txt" --dir ./test-inbox --local
```

Terminal 2:
```bash
echo "Allowed" > allowed.txt
echo "Blocked" > blocked.exe

# This should succeed
zig-out/bin/mitt send localhost:8080 allowed.txt --password testpass

# This should be rejected
zig-out/bin/mitt send localhost:8080 blocked.exe --password testpass
```

#### 4. Test stdout mode

Terminal 1:
```bash
zig-out/bin/mitt open --port 8080 --password testpass --stdout --local
```

Terminal 2:
```bash
echo "Hello, World!" | zig-out/bin/mitt send localhost:8080 - --password testpass
```

Verify that "Hello, World!" appears in terminal 1.

#### 5. Test file collision handling

Terminal 1:
```bash
zig-out/bin/mitt open --port 8080 --password testpass --dir ./test-inbox --local
```

Terminal 2:
```bash
# Send the same filename multiple times
echo "First" > duplicate.txt
zig-out/bin/mitt send localhost:8080 duplicate.txt --password testpass

echo "Second" > duplicate.txt
zig-out/bin/mitt send localhost:8080 duplicate.txt --password testpass

echo "Third" > duplicate.txt
zig-out/bin/mitt send localhost:8080 duplicate.txt --password testpass
```

Verify that `./test-inbox` contains:
- `duplicate.txt` (content: "First")
- `duplicate_1.txt` (content: "Second")
- `duplicate_2.txt` (content: "Third")

#### 6. End-to-end test with bore tunnel

This requires bore to be installed.

Terminal 1:
```bash
# Start mitt with bore tunnel
zig-out/bin/mitt open --dir ./test-inbox
# Note the password and address from output
```

Terminal 2:
```bash
# Create test file
echo "Remote test" > remote.txt

# Send via bore tunnel using the password from terminal 1
zig-out/bin/mitt send bore.pub:PORT remote.txt --password PASSWORD
```

Verify that `./test-inbox/remote.txt` exists with correct content.

### Cleanup

After testing, remove test artifacts:
```bash
rm -rf ./test-inbox test.txt remote.txt allowed.txt blocked.exe duplicate.txt
```

## Security

### Cryptography
- **End-to-end encryption**: All file data is encrypted with XChaCha20-Poly1305 before transmission
- **Strong key derivation**: Keys are derived using Argon2id (3 iterations, 64 MiB memory, 4 threads)
- **Authentication**: AEAD provides both confidentiality and authenticity
- **Memory security**: Plaintext is securely zeroed before being freed
- **No plaintext transmission**: File contents never leave your machine unencrypted

### Protection Mechanisms
- **Rate limiting**: Maximum 10 connections per minute per IP address
- **Connection limits**: Maximum 5 concurrent connections
- **Size validation**: Files limited to 5GB maximum to prevent memory exhaustion
- **Filename sanitization**: Path traversal attacks prevented through strict filename validation
- **Constant-time authentication**: Password validation uses constant-time operations to prevent timing attacks

### Security Model & Limitations

**⚠️ Important Considerations:**

1. **No TLS/Transport Security**: mitt uses raw TCP connections without TLS. While data is encrypted end-to-end, this means:
   - No forward secrecy (compromised password decrypts past traffic)
   - No server identity verification
   - Metadata (file sizes, timing) may be visible to network observers
   - **Recommendation**: Use mitt over trusted networks, VPNs, or SSH tunnels

2. **Password Security**:
   - Use strong, unique passwords for each transfer
   - Passwords are auto-generated by default (3-word phrases with numbers)
   - Use `--quiet` flag to prevent password display in terminal scrollback
   - Passwords should be shared through secure out-of-band channels

3. **Trust Model**:
   - mitt is designed for trusted peer-to-peer transfers
   - Both parties must trust each other and the network path
   - Not suitable for untrusted or hostile networks without additional protection

4. **Tunnel Security**:
   - When using bore or other tunnels, traffic passes through third-party servers
   - Tunnel providers can see connection metadata (not content)
   - Use `--local` for transfers on trusted local networks

### Best Practices

✅ **Do:**
- Use strong, auto-generated passwords
- Transfer over VPNs or trusted networks
- Use `--quiet` to hide passwords from terminal logs
- Share passwords through secure channels (Signal, encrypted messaging)
- Verify file integrity after transfer
- Use `--accept` and `--reject` filters to control file types

❌ **Don't:**
- Reuse passwords across multiple transfers
- Share passwords over the same network as the transfer
- Use on untrusted public networks without a VPN
- Transfer highly sensitive data without additional protection layers
- Leave the server running unattended for extended periods

### Reporting Security Issues

If you discover a security vulnerability, please report it to the project maintainers through GitHub's security advisory feature.

## Exit Codes

- `0` - Success (delivered)
- `1` - Invalid usage
- `2` - Failed (rejected, timeout, or connection error)

## License

See the main Cauldron project license.
