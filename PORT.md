# Cauldron: Zig → Go Port Plan and Compatibility Record

**Status:** Working-tree implementation complete 2026-07-13; tag/release rollout
requires the operator checklist; retained as the compatibility/design record
**Target toolchain:** Go 1.26 (current stable 1.26.5, 2026-07-07)
**Scope:** All five apps (~11k lines of Zig), build system, CI, release automation
**Canonical Zig baseline:** commit `d929c18` (the current source when this review was
completed). Golden vectors and live interop tests pin this commit; release tags are
legacy-compatibility inputs, not the source of truth.
**Author's note:** Every wire format, crypto parameter, and byte layout in this document
was extracted from the Zig source at the canonical commit. If this record disagrees
with that archived source, the archived source defines legacy compatibility — update
this document.

---

## 1. Executive summary

Cauldron's five apps (mitt, seance, omen, covenant, familiar) were ported from Zig
0.16 to Go 1.26, one app per phase. Both implementations coexisted during live
compatibility testing; Phase 6 then removed the legacy source. The port preserves:

- **Wire compatibility** — a Go mitt can talk to a Zig mitt, a Go seance client can
  join a Zig seance room, and vice versa.
- **Artifact compatibility for honest artifacts** — Go `omen verify` / `covenant
  verify` accept well-formed artifacts produced by the canonical Zig baseline, and the
  canonical Zig verifiers accept Go-produced artifacts. The Go verifiers intentionally
  reject exploit-shaped artifacts that the Zig verifiers incorrectly accept (§6.4,
  §9).
- **CLI compatibility** — same commands, flags, env vars, exit codes, and
  stdout/stderr split, so scripts and muscle memory keep working.
- **Release compatibility** — same tag conventions, artifact names, and Homebrew
  formula structure; the tap automation keeps working while correcting Omen's
  stale description. The project and existing formula metadata consistently use
  the MIT license following the repository owner's decision.

Motivation: Zig is pre-1.0 and its API churn is a recurring tax (the 0.15→0.16
`std.Io` overhaul forced a repo-wide migration in July 2026), model/tooling support
for Zig is comparatively weak, and Go's compatibility promise plus first-class
crypto/networking libraries fit this portfolio (network daemons, HTTP APIs, crypto
CLIs) almost exactly. The entire Zig codebase has **zero source-level third-party
dependencies**. The Go port has only two direct module dependencies,
`golang.org/x/crypto` and `golang.org/x/term`; their pinned transitive modules (notably
`x/sys`) remain recorded in `go.sum`.

## 2. Goals and non-goals

### Goals

1. Behavior parity: every documented command, flag, env var, prompt, exit code, and
   machine-parsable output line survives the port unchanged, with current behavior
   captured rather than inferred (exceptions listed in §9).
2. Wire and artifact compatibility as defined above, proven by golden vectors and
   cross-implementation interop tests, not by inspection.
3. Deduplicate the copied-file "shared code" (id/wordlist/crypto/tunnel/frame are
   copy-pasted across apps in Zig) into real Go packages.
4. Keep the release machinery naming-compatible: same tags (`v*` for mitt,
   `<app>-v*` for the rest), same tarball names (`<app>-<os>-<arch>.tar.gz` with
   `aarch64`/`x86_64` spelling), same `.sha256` sidecars, so `release.yml`'s
   formula-update sed and all five Homebrew formulas need no structural changes.
   Archives add `LICENSE` and `THIRD_PARTY_NOTICES` beside the binary to satisfy
   notices for the newly linked Go components.
5. Equal or better test coverage per app than the Zig code has today, plus coverage
   for the areas the Zig code never tested (seance framing/relay/bot API,
   familiar core).

### Non-goals

- No protocol redesign. The known protocol limitations (no forward secrecy in seance,
  plaintext/unauthenticated frame headers, no version negotiation, and unfiltered
  terminal control sequences in protocol text) are preserved as-is and documented
  in `SECURITY.md`. Fixing them is future work that should happen *after* the port,
  behind version bumps, in one language.
- No new features during the port. Feature freeze per app from the start of its
  phase until its Go release ships.
- No bug-for-bug reproduction of unsafe verifier, eligibility, duplicate-identity,
  overflow, or payload-size behavior (§6.4 and §9).
- No replacement of the external `bore` dependency (§7). Embedding a native Go bore
  client is attractive follow-up work, not port scope.

## 3. Why Go (decision record)

Considered: Go, Rust. Chosen: **Go**, because for this portfolio the decisive factors
are AI-agent fluency (largest, most stable training corpus of any systems-adjacent
language; APIs covered by the Go 1 compatibility promise), a stdlib +
`x/` ecosystem that covers 100% of cauldron's needs (`crypto/ed25519`,
`x/crypto/chacha20poly1305`, `x/crypto/argon2`, `x/crypto/blake2b`, `net/http`,
`x/term`), goroutines mapping directly onto the multi-client servers, and trivial
static cross-compilation (`CGO_ENABLED=0` + `GOOS`/`GOARCH`)
that drops straight into the existing four-target release matrix. Rust would buy
no-GC and stricter compile-time guarantees at the cost of a slower port and weaker
agent throughput; nothing in cauldron is latency- or memory-bound enough to want
that trade.

Accepted regressions relative to Zig are listed in §9. The two that matter are
binary size (Go binaries will be a few MB instead of a few hundred KB) and
best-effort rather than guaranteed key zeroization (§6.5).

## 4. Current-state inventory

### 4.1 Apps

| App | LOC (Zig) | Purpose | Released | Source version | Tag scheme |
|---|---|---|---|---|---|
| mitt | ~1,700 | one-shot E2E-encrypted file transfer over TCP | v0.4.2 | *(none embedded)* | `v*` |
| seance | ~2,200 | ephemeral E2E-encrypted group chat, star relay, bot API | seance-v0.2.8 | 0.2.8 | `seance-v*` |
| omen | ~3,400 | encrypted verifiable voting, commit–reveal, signed JSON artifact | omen-v0.1.0 | 0.1.0 | `omen-v*` |
| covenant | ~2,200 | membership signing ceremony, signed roster artifact | covenant-v0.1.0 | 0.1.0 | `covenant-v*` |
| familiar | ~650 | Claude chatbot daemon for seance rooms | familiar-v0.2.0 | 0.2.0 | `familiar-v*` |

Known versioning defects the port fixes (§8.3): mitt embeds no version at all and has
no `--version` flag; omen and covenant each hardcode their version a *second* time
inside `artifact.zig`. `familiar-v0.2.0` exists and matches the source; the earlier
claim that 0.1.3 was latest was a tag-inventory error.

All latest app tags predate commit `86a2a9c`, which changed deterministic omen /
covenant identities from Blake2b (`covenant-id-v1`) to Argon2id
(`covenant-id-v2!!`) and made traffic KDF failure fail closed. Therefore downloaded
release binaries are not the canonical current-source interop baseline. Tests build
the pinned commit above, while legacy release binaries get a separate best-effort
compatibility lane with the expected v1/v2 identity discontinuity documented.

### 4.2 Copied-not-shared code (Zig) → shared packages (Go)

| Zig files | Identical across | Go home |
|---|---|---|
| `id.zig` + `wordlist.txt` (787 words) | mitt, seance, omen, covenant (byte-identical) | `internal/ident` |
| `tunnel.zig` (bore subprocess) | mitt, seance, omen, covenant (byte-identical) | `internal/tunnel` |
| `crypto.zig` symmetric base | all four networked apps — differs **only** in Argon2 salt | `internal/secretbox` |
| `crypto.zig` Ed25519/Blake2b extension | omen, covenant (near-identical) | `internal/sigcrypto` |
| frame layout in `protocol.zig` | seance, omen, covenant — **identical byte layout**, different magic + message-type enums | `internal/frame` |
| `familiar/src/core.zig` | compiled into both familiar and seance (`--familiar`) | `internal/familiarcore` |

### 4.3 Runtime dependencies

- **`bore`** (external binary in PATH): all four networked apps spawn
  `bore local <port> --to bore.pub [--port <n>]`, scrape `listening at bore.pub:PORT`
  from its stdout, detect "address already in use" on stderr, and run a monitor
  thread that reconnects with exponential backoff (1,2,4,…30s cap, 10 attempts).
  Absence of bore → local-only fallback. The observable contract is preserved; process
  supervision bugs are fixed (§7).
- **Anthropic API** (familiar): `POST /v1/messages`, `anthropic-version: 2023-06-01`,
  `x-api-key` from `ANTHROPIC_API_KEY`, non-streaming.

## 5. Target architecture

### 5.1 Repository layout

One Go module and one binary per app:

```
go.mod                          module github.com/no-way-labs/cauldron  (go 1.26)
cmd/
  mitt/main.go                  CLI parsing, presentation, and dispatch
  seance/main.go
  seance/terminal.go            raw-mode editor and ANSI renderer
  omen/main.go
  covenant/main.go
  familiar/main.go
internal/
  cli/                          strict shared argv/secret/address parsing
  ident/                        passphrase + nick generation (embed wordlist.txt via go:embed)
  secretbox/                    Argon2id key derivation + XChaCha20-Poly1305 detached-tag AEAD
  sigcrypto/                    Ed25519 identity derivation, Blake2b commitments/hashes
  frame/                        the shared u8/u64/u8-len/u32-len/nonce/tag/ct frame codec
  jsonstrict/                   duplicate-key rejection + physical JSON member scanning
  tunnel/                       bore subprocess management + monitor goroutine
  familiarcore/                 poll loop + Claude client (shared by familiar and seance --familiar)
  mitt/, seance/, omen/, covenant/   app-specific logic (server/client/verify/artifact)
  compat/, itest/               frozen vectors/artifacts + real-binary workflows
docs/                           stable app and protocol documentation
testdata/                       frozen compatibility vectors and mixed artifacts
```

Rules: protocol, cryptographic, persistence, and network state-machine logic lives
under `internal/`; `cmd/*` owns argv, prompts, terminal rendering, and process exit
mapping. No public Go API surface (`internal/` everywhere) — cauldron ships binaries,
not a library.

**Direct dependencies:** `golang.org/x/crypto` (argon2, chacha20poly1305, blake2b),
`golang.org/x/term` (raw mode). Nothing else direct. Normal transitive modules are
allowed only through these two dependencies and are pinned in `go.sum`; adding another
direct dependency requires editing this document first.

Pinned `staticcheck` and `govulncheck` modules are build-tool dependencies declared in
the `tool` block; they are not linked into application binaries.

### 5.2 Concurrency mapping

| Zig construct | Go replacement |
|---|---|
| `std.Thread.spawn` per connection (seance/omen/covenant) | goroutine per connection |
| mitt's currently synchronous accept/handle loop | goroutine per connection, making its documented five-connection cap real (§9) |
| `std.atomic.Value(bool)` running flags | `context.Context` cancellation (one root ctx per server/client) |
| `std.Io.Mutex` around peer list / stream writes | `sync.Mutex` |
| hand-rolled SpinLock around terminal input state (seance) | `sync.Mutex` |
| unblocking `accept` via `listener.deinit` from another thread | `listener.Close()` + ctx |
| server `SO_RCVTIMEO=30s` during JOIN, cleared after admission | `SetReadDeadline` for JOIN, then `SetReadDeadline(time.Time{})` — **the clear-to-infinite step is load-bearing** |
| client timeout behavior | mitt keeps the requested deadline for send/ack; seance currently applies it only around JOIN send then clears it; omen/covenant parse but never use it. Go makes each `--timeout` bound dial + initial JOIN write, then clears deadlines for admitted long-lived sessions (§9) |
| no connect timeout (Zig 0.16 panics on connect-with-timeout) | a 30s default `net.Dialer` timeout, overridden by the command's `--timeout` where present (§9) |
| `getsockname`/`boundPort` posix shims | `listener.Addr().(*net.TCPAddr).Port` — shims deleted |
| raw `posix.read(STDIN)` line prompts (omen/covenant hosts) | bounded `bufio.Reader` line reads; avoid Scanner's implicit 64 KiB token behavior |
| `std.process.exit(0)` to kill detached stdin thread | ctx cancellation; `os.Exit` only from `main` |

### 5.3 I/O and output parity

Almost all human-facing output in the Zig apps goes to **stderr** (via
`std.debug.print`), including password banners and ANSI-colored chat rendering;
stdout is reserved for machine-consumable payloads (mitt `--stdout` payload,
omen/covenant artifact JSON when no `--output`). `Delivered.` is written by
`std.debug.print`, so it is **stderr**, not stdout. The Go port preserves this
split exactly — it is scripting API. Every `fmt.Fprintf(os.Stderr, ...)` vs
`os.Stdout` decision is dictated by the Zig behavior, and §8.2's golden-output tests
pin the lines scripts are known to parse.

## 6. Cryptography: exact mapping and compatibility surfaces

This section is normative. Interop dies on any deviation.

### 6.1 Key derivation — Argon2id

All four networked traffic keys plus the shared omen/covenant identity seed use
Argon2id: **t=3 iterations, m=65536 KiB (64 MiB), p=4 lanes, 32-byte key**, 16-byte
ASCII salts, fail-closed on error (never downgrade, exit 1).

Go: `argon2.IDKey(password, salt, 3, 64*1024, 4, 32)` — `x/crypto/argon2` takes
memory in KiB, matching Zig's `m=65536` directly.

| Purpose | Salt (exactly 16 bytes) |
|---|---|
| mitt traffic key | `mitt-v1-salt-24!` |
| seance room key | `seance-v1-salt!!` |
| omen room key | `omen-v1-salt---!` |
| covenant room key | `covenant-v1-salt` |
| **shared** Ed25519 identity seed (omen + covenant) | `covenant-id-v2!!` |

The shared identity salt is intentional: the same `--identity` phrase yields the same
Ed25519 keypair in omen and covenant, which is what lets omen consume covenant
rosters. Preserve it.

### 6.2 AEAD — XChaCha20-Poly1305, detached tag, empty AAD

All encrypted payloads: XChaCha20-Poly1305, 32-byte key, **24-byte random nonce per
message** (system CSPRNG), **16-byte detached tag**, **empty AAD**. Wire order in
every protocol: `nonce ‖ tag ‖ ciphertext` — the tag travels *before* the
ciphertext, and declared lengths count ciphertext only (== plaintext length; the tag
is not included).

Go's `chacha20poly1305.NewX(key)` produces/consumes *attached* tags
(`Seal` appends the tag). The `internal/secretbox` package owns the split:

```go
// Seal: sealed := aead.Seal(nil, nonce, plaintext, nil)
//        tag = sealed[len(sealed)-16:], ct = sealed[:len(sealed)-16]
// Open: aead.Open(nil, nonce, append(ct, tag...), nil)
```

No other package may touch nonce/tag layout. Frame headers (msg type, timestamp,
sender nick, lengths) are plaintext and unauthenticated in the current design;
the port reproduces this (non-goal to fix, §2).

### 6.3 Signatures and hashes (omen, covenant)

- Ed25519: stdlib `crypto/ed25519`. Deterministic identity:
  `ed25519.NewKeyFromSeed(argon2Seed)`. Signing is pure Ed25519 (no prehash, no
  context) → `ed25519.Sign`.
- Blake2b-256: `x/crypto/blake2b.New256(nil)`.
- **omen** commitment: `Blake2b256(voteIndex[1] ‖ blinding[32])`.
- **omen** roster hash: Blake2b256 over peers **in the supplied slice order**
  (`slot[1] ‖ nickLen[1] ‖ nick ‖ pubkey[32]` per peer). The server's canonical
  construction is contiguous slot order with host at slot 0; the hash function itself
  does not sort or enforce this, so verifiers must validate that invariant separately.
- **omen** commitment signature: Ed25519 over `rosterHash[32] ‖ commitment[32]`.
- **omen** commit-set hash: Blake2b256 over commitments in canonical slot order
  (`slot[1] ‖ commitment[32]` per commitment). Signatures are not included.
- **covenant** roster hash: Blake2b256 over members **sorted by pubkey**
  (`pubkey[32] ‖ nickLen[1] ‖ nick` per member). Different field order AND different
  sort discipline than omen — the two must not share a roster-hash implementation.
- **covenant** member signature: Ed25519 over the raw 32-byte roster hash, no domain
  separation.
- Constant-time comparisons (`MAGIC` check on JOIN): `crypto/subtle.ConstantTimeCompare`.
- omen's reveal-set shuffle: Fisher–Yates driven by `crypto/rand` (the exact
  permutation need not match Zig).

**Privacy correction:** the shuffle does not provide voter anonymity or unlinkability.
Each reveal publishes `voteIndex ‖ blinding`; anyone can recompute its commitment and
match it to the slot-tagged commitment and roster key. `verifyRevealSet` necessarily
performs this matching. The host can also observe network identities and unshuffled
reveals. The v1 port preserves the wire format but must describe omen as encrypted in
transit and publicly verifiable, **not anonymous**. Real ballot unlinkability requires
a redesigned protocol and is deferred to v2.

### 6.4 Signed JSON artifacts — the hardest compatibility surface

omen and covenant emit hand-built JSON with **exact key order, no whitespace, and
custom escaping** (only `"` `\` `\n` `\r` `\t` escaped, control chars < 0x20 as
`\uXXXX`, raw UTF-8 passthrough). omen's `host_signature` is Ed25519 over
`Blake2b256(bytes of the JSON document up to the literal "host_signature" key)` —
the signature covers physical bytes, so **`encoding/json` cannot be used to produce
omen artifacts**. Covenant signatures cover the semantic roster hash rather than the
physical document, but its manual writer is retained for output/golden compatibility.
The Go port implements a small manual JSON writer in
`internal/omen/artifact.go` / `internal/covenant/artifact.go` mirroring the Zig
builders field-for-field, including the embedded `omen_version` / `covenant_version`
fields (sourced from the single build-injected version, §8.3).

For **reading/verifying**, Go uses a strict layer over `encoding/json`: reject duplicate
object keys, trailing JSON values, wrong types, out-of-range integers, overlong fields,
count mismatches, and invalid UTF-8 before semantic verification. `encoding/json`
alone is not strict enough because it accepts duplicate keys with last-value-wins
semantics. Unknown extension fields may be retained/ignored only when they do not
duplicate a defined field. Artifact file reads retain the Zig source's 1 MiB cap.

For omen, locate the actual top-level `host_signature` member with a token-aware raw
scanner and hash the bytes before that member. Do not use `bytes.Index`: the Zig
verifier accidentally selects an earlier `"host_signature"` occurrence inside a
question/option/string and can reject an artifact emitted by its own writer. Fixing
that is a deliberate verifier divergence.

**Covenant verification requirements:** parse real JSON; require the stated
`member_count` to equal the members array length and be in the honest ceremony range
2..255; require unique public keys; sort a copy by public key; recompute the roster hash
from the current semantic nick/pubkey
pairs; compare it to the stated hash; then verify every member signature over that
recomputed hash. The Zig verifier currently trusts the stated hash and therefore
accepts renamed/added members; reproducing that bug is forbidden. `group_name`,
`created_at`, `session_id`, and `covenant_version` are not bound by the v1 signatures,
so verification must label them unauthenticated metadata. Binding them requires an
artifact-v2 format and is deferred.

**Omen verification requirements:** require one canonical roster entry for every
contiguous slot `0..n-1` with 2..255 entries, host at slot 0, unique roster public keys,
2..255 uniquely named non-empty options, and
`host_pubkey == roster[0].pubkey`; recompute the roster hash; require exactly one valid
commitment for every roster slot (unique slots and exact coverage, not length equality);
require a reveal↔commitment bijection; require every revealed vote index to address an
option; reject duplicate option names; validate `voter_count`; recompute the exact
tally and winner; and verify the host signature over the byte prefix. The Zig verifier
currently accepts a duplicate signed commitment in place of another member's vote;
reproducing that bug is forbidden.

Omen commitment signatures bind only `roster_hash ‖ commitment`: they do not bind the
session id, question, or options. This replay/session-binding limitation remains a v1
protocol limitation and must be documented. In particular, a malicious host can
rename/reorder option labels for the same numeric vote indices and produce a standalone
artifact that is internally valid but does not represent the ballot voters saw. Go
live clients reject a final artifact that differs from their locally received ballot,
but offline verification cannot recover that missing voter attestation. Fixing it
requires protocol v2.

Neither artifact format supplies an external trust anchor. A valid covenant proves
that the private keys corresponding to its listed public keys signed one roster; it
does not prove real-world identities. A valid omen proves internal consistency and a
signature by the artifact's slot-0 key; verifiers must display that fingerprint rather
than call it a known host unless the caller supplied an expected key out of band.
Moreover, the v1 omen artifact neither embeds nor hashes a source covenant, so offline
`omen verify` **cannot prove that `--roster` was used or establish voter eligibility**.
The Go live server enforces restricted admission, but durable covenant linkage requires
artifact v2. Documentation and verifier output must keep these claims separate.

### 6.5 Zeroization (accepted weakening)

Zig `secureZero`s keys and received plaintext. Go cannot guarantee erasure: argv and
environment values begin as immutable strings, the GC/compiler may copy buffers, and
`ed25519.NewKeyFromSeed` allocates private-key material. Policy: minimize conversions,
copy secrets into owned byte buffers promptly, zero owned key/plaintext buffers on
teardown (best effort), and keep symmetric keys in fixed `[32]byte` arrays passed by
pointer. Do not claim immutable process inputs or stdlib-internal copies were erased.
Document this in SECURITY.md as a residual-memory caveat.

### 6.6 Passphrase generation

3 words from the embedded 787-word list + a 0–99 number, `word-word-word-N`
(the number is not zero-padded; ~35 bits). Go: `go:embed wordlist.txt` in
`internal/ident`, indices from
`crypto/rand`. One wordlist for all apps (they are byte-identical today).

## 7. Wire protocols and the bore tunnel

### 7.1 mitt (one-shot transfer)

Single TCP request → 1-byte ack. Big-endian framing:

```
filenameLen u16 | filename | ciphertextLen u64 | nonce[24] | tag[16] | ciphertext
```

Bounds in Zig are asymmetric: the sender reads at most **1 GiB**, the receiver has an
absolute **5 GiB** cap, and `mitt open` defaults to a **100 MiB** filter cap
(overridable with `--max-size`). A one-shot AEAD receive requires ciphertext and
plaintext resident together, so accepting 5 GiB is an OOM/DoS surface that the
canonical sender cannot exercise. Go intentionally hard-caps both sides and
`--max-size` at **1 GiB** (§9). Filename length is 1–1024 bytes on receive. **Ack
semantics are
load-bearing:**
success = single `0x00` byte; *every* rejection (bad filename, filter, decrypt
failure, size) = close the connection without sending anything. The Go server must
not write error bytes. Preserve: server binds 127.0.0.1 only (bore provides
reachability), 120s connection read deadline, 10 conns/min/IP rate limit, the
receive-side filename sanitizer (first strip both `/` and `\` path components, then
reject the resulting basename on `..`, leading `.`, or chars outside
`[A-Za-z0-9._-]`), collision suffixing
(`name_1.ext`…), and the ~100ms sleep on decrypt failure. mitt's dead `config.zig`
is not ported. The Zig server handles accepted connections synchronously, making its
`active_connections < 5` check ineffective; Go intentionally serves concurrently and
enforces the five-active-connection cap and rate limiter under one race-safe policy.
Concurrent saves select names with atomic exclusive creation (no check-then-truncate
race); `--stdout` deliveries are serialized so payload bytes never interleave.

### 7.2 seance / omen / covenant shared frame

Identical byte layout in all three (one `internal/frame` codec, parameterized by
magic + message-type enum):

```
msgType u8 | timestamp u64 BE | senderLen u8 | sender | payloadLen u32 BE | nonce[24] | tag[16] | ciphertext
```

Caps: nick ≤ 32 bytes, payload ≤ 65536. CLI and decoders reject overlong/invalid UTF-8
nicks rather than relying on the Zig writer's truncation (which can also trap above
255 bytes). The shared writer rejects oversized plaintext /
ciphertext before emitting any bytes; hosts preflight serialized ballot, roster,
commit-set, reveal-set, and artifact payloads before changing phase. This matters
because advertised maximum participant counts can otherwise produce artifacts larger
than one frame. Every structured payload decoder also requires exact consumption (no
ignored trailing bytes), valid counts, and canonical field ranges. JOIN authentication
= the app magic
(`SEANCE_HELLO` / `OMEN_HELLO` / `COVENANT_HELLO`) sent *encrypted* as the JOIN
payload; server decrypts and constant-time-compares; wrong password = silent
connection drop (no error frame). Server handshake read deadline is 30s, cleared to
infinite after admission. There is no admission-ack frame, so clients can only bound
dial/JOIN write, not prove admission during `connect`.

App-specific invariants:

- **seance:** the server relays `msg` frames **verbatim** — same nonce, tag,
  ciphertext, plaintext sender — to all other peers; it never re-encrypts. Nick
  collision suffixing (`nick_2`…`_99`), `nick_list` payload = encrypted
  newline-separated nicks with host first, announces are `"<nick> joined"` /
  `"<nick> left"` (the bot API derives message `type` from these suffixes — they are
  API surface). Rate limit 10 msg/s/peer. The decoder rejects unknown numeric frame
  types and the read loop disconnects; only known-but-unhandled enum values are ignored.
  Peer-limit check, collision resolution, and insertion are one atomic admission
  transaction in Go; the Zig server separates those locks and can exceed the limit or
  allocate duplicate resolved nicks under concurrent joins.
  A current Zig quirk remains explicit: the server records a collision-resolved nick
  but relays the client's original plaintext `frame.sender`, and there is no admission
  response telling the client its suffix. Remote sender/timestamp/type headers are
  therefore spoofable and must never be presented as authenticated; fixing this
  coherently belongs with authenticated headers in protocol v2.
- **omen:** full commit–reveal state machine (lobby→commit→reveal→tally→done),
  payload layouts as implemented in `protocol.zig` (ballot, peer_list,
  phase = `phaseId[1] ‖ rosterHash[32]`, commitment = `commitment[32] ‖ sig[64]`,
  commit_set, reveal = `voteIndex[1] ‖ blinding[32]`, reveal_set without slot ids,
  tally = artifact JSON). Host = slot 0. Clients must refuse to tally without a
  verified commit set, and abort on roster-hash mismatch. `--max-voters` means remote
  voters and is clamped to 1–254 so the host-inclusive u8 counts never wrap. Restricted
  votes additionally freeze a unique, fully-keyed roster before commit (§7.2.1).
  Clients find their slot by their unique public key, not nick (collision suffixes make
  nick lookup ambiguous), apply the exact-coverage checks to the live commit set, and
  verify/bind the final artifact to their locally verified ballot, roster, commitments,
  reveal multiset, and tally before saving it.
- **covenant:** lobby→seal→done; phase payload is **1 byte** (no roster hash —
  differs from omen); the group name is delivered to joiners via a `phase`-typed
  frame while the client's roster is still null (state-based disambiguation — port
  this quirk faithfully); roster payload `count[1] | (nickLen[1]‖nick‖pubkey[32])*`;
  `--max-members` clamped 1–254 (u8 slot arithmetic). Before signing, every client
  requires canonical unique members and its own public key exactly once. Before saving
  the final covenant, it runs strict verification and requires the roster hash and
  own signature/key to match the ceremony it observed.

#### 7.2.1 Restricted omen roster admission

`omen host --roster` must first run the strict covenant verification from §6.4; merely
extracting the `members[].pubkey` array is not eligibility verification. Reject an
invalid covenant, duplicate member key, or roster that does not contain the host's
identity. During admission, reserve each allowed public key at most once under the
server lock; a second connection presenting the same key is rejected. `/start` is
refused until every connected voter supplied a unique allowed key. The roster and its
connection membership are frozen for commit/reveal; disconnects abort the vote rather
than silently changing the signed roster. Phase transitions use once-only guarded
state changes so duplicate frames cannot complete a phase twice.

### 7.3 seance bot API

Reimplemented on `net/http` (the Zig side is a hand-rolled HTTP/1.1 server).
Compatible because all known clients (familiar, curl scripts) send
`Connection: close` and read to EOF. Endpoint contract, preserved exactly:

- `POST /send` — body is raw message text → `{"status":"sent"}` / 400 empty / 500.
- `GET /messages?since=<u64>&wait=<secs>` — long-poll (wait capped at 120s), returns
  `[{"id":u64,"timestamp":u64,"sender":str,"content":str,"type":"msg|join|leave|announce"}]`,
  monotonic ids from 1.
- `GET /peers` — JSON array of nicks. `GET /nick` — `{"nick":...}`.
- `POST /quit`, `GET /health`.

Long-poll may be implemented with channels/condvars instead of the Zig 200ms sleep
loop — observable semantics (return early on new message, at deadline otherwise) are
what's pinned. The server keeps loopback-only binding and explicit HTTP timeouts; caps
request headers + body at the Zig server's 8192-byte request envelope and additionally
rejects `/send` content above the 65536-byte frame limit. Responses use normal JSON
escaping (including `/nick`) and tests compare decoded JSON rather than depending on
Go's default HTML escaping or automatically-added HTTP headers. The in-memory message
buffer receives a documented bounded retention policy; the Zig buffer is unbounded.

### 7.4 bore tunnel contract (`internal/tunnel`)

Preserve the external contract: spawn `bore local <port> --to bore.pub [--port <n>]`
via `os/exec`; parse `listening at bore.pub:<PORT>` from stdout (real 10s context
deadline); treat
"address already in use" on stderr as port-conflict (host retries with random port);
monitor goroutine detects bore death (stdout EOF) and reconnects, exponential
backoff 1→30s, 10 attempts, preferring the previously assigned public port; missing
`bore` binary → clean local-only fallback with the same user messaging.

The Zig startup loop's apparent 10s cap is not effective because its stdout/stderr
reads are blocking and sequential. Go concurrently drains both pipes, enforces the
context deadline, calls `Wait` exactly once, and synchronizes monitor/shutdown/reconnect
ownership. This is an explicit hang/zombie-process fix, not byte-for-byte internals
parity.

### 7.5 familiar ↔ Claude

`internal/familiarcore` preserves: `/health` ×10 startup retry, `/nick` self-nick
detection, `GET /messages?since=<last>&wait=30` poll loop (5s sleep on poll error),
history bounded by `--context` (default 50) with **strict user/assistant role
alternation** (consecutive same-role messages merged with `\n` — required by the
Messages API), other senders prefixed `"<nick>: "` in user content, own messages as
assistant role, only `type=="msg"` ingested. Claude request: `max_tokens: 4096`,
`system` as a content-block array (not bare string), non-streaming,
`anthropic-version: 2023-06-01`, `x-api-key` auth, 401 → re-read
`ANTHROPIC_API_KEY` and continue, single retry on stale-connection errors, default
model `claude-sonnet-4-5-20250929` (updating the default model is out of port
scope; do it as a normal feature change after). Use `net/http` with a fresh request
per call. JSON decoding of untrusted bot-API input must be type-tolerant (mirror
Zig's null-returning accessors — never panic on shape mismatch); apply the same rule to
the Claude response, where the Zig source still asserts JSON shapes. Add response-body
limits and request/overall timeouts for both local bot calls and the Anthropic call.
Unlike Zig's numeric-IP-only raw bot client, Go may resolve a hostname supplied via
`--api-host`; this fixes the documented flag rather than preserving the parser bug.

## 8. Behavior parity specification

### 8.1 CLI surface

Every command, flag (names, defaults, value syntax), positional argument, env-var
fallback (`MITT_PASSWORD`, `SEANCE_PASSWORD`, `OMEN_PASSWORD`, `OMEN_IDENTITY`,
`COVENANT_PASSWORD`, `COVENANT_IDENTITY`, `ANTHROPIC_API_KEY` — with
empty environment values treated as unset), and interactive prompt (`/start`,
`/abort`, `/seal`, `/quit`, vote-number entry) is preserved. Explicit empty secret
flags are rejected (§9) rather than treated as valid credentials.

The standard Go `flag` package accepts both `-flag` and `--flag`; that is not the
problem. It stops parsing at the first positional and does not match these CLIs' argv
ordering and error behavior. `cmd/*` therefore uses a small shared, table-driven argv
scanner in `internal/cli` that accepts only the documented spellings and preserves
flags after positionals. Address parsing keeps the current quirks: mitt splits
`host:port` on the *first* `:`, seance/omen/covenant on the *last*. IPv6 literal
support is not silently invented during the port.

The canonical Zig CLI snapshot (all listed output is stderr) is:

| invocation | mitt | seance | omen | covenant | familiar |
|---|---:|---:|---:|---:|---:|
| no arguments | usage, 0 | usage, 0 | usage, 0 | usage, 0 | starts daemon; missing key is logged but 0 |
| `--help` | unknown + usage, 1 | unknown + usage, 1 | usage, 0 | usage, 0 | usage, 0 |
| `--version` | unknown + usage, 1 | version, 0 | version, 0 | version, 0 | version, 0 |
| unknown top-level token | usage, 1 | usage, 1 | usage, 1 | usage, 1 | usage, 1 |

Within otherwise valid commands, mitt/seance/omen/covenant currently ignore many
unknown flags and flags missing a value; familiar rejects them. The Go port
intentionally rejects unknown flags, missing values, and empty explicit secrets with
exit 1 for every app because silently ignoring a misspelled `--roster`, `--identity`,
or `--password` can weaken security. Other exit behavior remains pinned: mitt 0
delivered / 1 usage / 2 failed-timeout-rejected; omen/covenant `verify` 0 valid / 1
invalid. `--help` quirks remain for parity, and mitt's new `--version` is the additive
exception already listed in §9.

### 8.2 Golden outputs

Script-parsed lines that must survive byte-for-byte (modulo values):
`🔐 Password: {p}` · `Local: localhost:{port}` · `Public: {host}:{port}` ·
`Received: {name} ({n} bytes) -> {path}` · `Delivered.` / `Failed: {msg}` /
`Timeout: server did not respond` · seance/omen/covenant "To join:" blocks ·
covenant `members` two-column output · artifact JSON to stdout iff no `--output`.
The canonical implementation was exercised before deletion and the stable contracts
are asserted in `cmd/*` subprocess tests plus the real-binary `internal/itest` harness
(ANSI is treated as incidental where rendering is not scripting API). Frozen crypto
bytes live in `testdata/compat`; byte-identical mixed ceremony/vote artifacts from both
host directions live in `testdata/interop` and are continuously re-verified.

### 8.3 Versioning (fixed in the port)

One version string per app, injected at build:
`go build -ldflags "-X main.version=..."` from the git tag in CI into a mutable string
variable (dev builds default to `0.0.0-dev`). The build job strips both the app prefix
and the leading `v` before injection. Banners add their own display `v`, while artifact
fields receive the normalized bare semantic version. Injecting `v0.x.y` would produce
`vv0.x.y` banners and change signed artifact bytes. This fixes mitt gaining
`--version` (additive change, allowed) and omen/covenant's double-hardcoded version
(artifact writers take the version as a parameter — single source of truth).
First Go releases bump minor per app: **mitt v0.5.0, seance v0.3.0, omen v0.2.0,
covenant v0.2.0, familiar v0.3.0**.

## 9. Deliberate changes (the complete list)

Everything not listed here is parity. Each item below is an intentional divergence:

1. **Connect and initial-write timeouts work** — Zig has no dial timeout; omen and
   covenant parse `--timeout` but never use it, and seance clears it immediately after
   writing JOIN. Go bounds dial + initial write, then clears long-lived deadlines.
2. **mitt gains `--version`** (it never had one).
3. **CLI configuration fails closed** — all apps reject unknown options, missing flag
   values, and explicitly empty password/identity/API-key values instead of silently
   ignoring them or deriving a public empty secret (§8.1).
4. **Covenant verification is semantic and strict** — real JSON, duplicate-key
   rejection, recomputed roster hash, count/uniqueness checks, and signatures checked
   against the recomputed hash. This intentionally rejects member-renaming/addition
   artifacts the Zig verifier incorrectly accepts (§6.4).
5. **Omen verification enforces exact slot coverage and canonical structure** — it
   rejects duplicate/missing slots, duplicate identities/options, invalid vote indices,
   count mismatches, an unbound host key, and ambiguous raw `host_signature` matches.
   Live clients locate themselves by key and bind the final artifact to locally
   verified state. This intentionally rejects artifacts the Zig verifier incorrectly
   accepts (§6.4).
6. **Restricted omen admission verifies and consumes eligibility** — verify the
   covenant first, require the host, reserve each identity once, freeze the roster,
   and guard phase completion (§7.2.1).
7. **Count and payload bounds fail before serialization** — omen remote voters are
   capped at 254, nicks/option counts/lengths are validated, and all writers/preflight
   checks enforce the 65536-byte frame limit. Mitt's receiver cap drops from its
   unreachable/unsafe 5 GiB to the canonical sender's 1 GiB. Oversized bot messages
   and ceremony artifacts return explicit errors instead of OOM, wrapping u8 counts,
   or sending frames peers cannot read.
8. **mitt's concurrency controls become real** — goroutine-per-connection plus a
   synchronized five-active-connection/rate limit replaces the synchronous Zig loop
   whose counter could never exceed one. Saves use exclusive-create collision handling
   and stdout delivery is serialized.
9. **Bot API is served by `net/http` with limits** — standard HTTP behavior, valid JSON
   escaping, explicit timeouts/request caps, and bounded message retention; compatible
   at the documented endpoint/decoded-JSON level, not raw response-header bytes.
10. **Long-poll wakes event-driven** instead of a 200ms sleep loop — faster delivery,
    same semantics.
11. **Tunnel process management is actually bounded** — concurrent pipe drains, a
    real startup deadline, one waiter, and synchronized teardown replace blocking
    sequential reads that can hang despite the Zig loop's nominal timeout.
12. **Familiar hard failures are failures** — standalone missing credentials,
    unreachable bot, or unrecoverable startup errors exit nonzero; embedded familiar
    logs and returns without killing seance. Hostnames work for `--api-host`, untrusted
    Claude JSON is type-checked, and HTTP bodies/times are bounded.
13. **Ceremony clients verify what they sign/save** — covenant clients require their
    own key in the roster before signing and verify the final artifact against local
    state; the Zig clients currently trust those host messages.
14. **Seance admission is atomic** — peer cap, nick collision resolution, and append
    share one critical section, eliminating concurrent over-admission/duplicate names.
15. **Key zeroization becomes best-effort** (§6.5) — documented accurately in
    SECURITY.md.
16. **Binary size** grows from ~hundreds of KB to single-digit MB (`-ldflags "-s -w"`,
    `CGO_ENABLED=0`).
17. **Signal handling**: Go installs a SIGINT/SIGTERM handler for graceful teardown
    (terminal restore, bore child kill). Zig relied on raw-mode byte-3 interception
    and default kill behavior; the observable improvement is that seance does not
    leave the terminal in raw mode after a handled signal.
18. **Shutdown and slow-peer lifetime bugs are fixed** — covenant delivery writes
    have bounded deadlines; a stale seance peer cannot terminate the host when the
    host speaks; and the Go seance host retains a departing nick until after its leave
    announcement. The canonical Zig host frees that nick first, producing visibly
    corrupted departure announcements under normal mixed-room churn.

## 10. Migration sequencing

The phases below are the intended release/soak sequence. The working-tree port
implemented and verified all phases before any tag was pushed; no release, remote CI
run, or external formula mutation is claimed by this record. Those operator gates
remain in `RELEASE_CHECKLIST.md`. Within the implementation, Zig and Go coexisted
until Phase 6. The order de-risks the work: familiar proves the toolchain with zero
crypto; mitt proves the crypto/wire-interop methodology on the simplest protocol;
covenant then omen prove artifact byte-exactness (omen consumes covenant rosters);
seance — the largest and only TUI app — goes last, inheriting every shared package
and the already-ported familiar core.

**Phase 0 — Scaffolding + golden vectors** *(no releases)*
`go.mod`, `internal/` skeleton, `internal/cli`, CI gains a Go job alongside Zig.
Critically, **capture the compatibility corpus while the Zig binaries still build**:
Argon2id derived keys for all five salts, sealed frames with known nonces, roster /
commitment / commit-set hashes, complete signed omen + covenant artifacts (valid and
tampered variants), and CLI output contracts. Deterministic fixture helpers take an
injected nonce and clock; live encryption/artifact APIs do not. Immutable legacy
outputs live in `testdata/`; tampering, duplicate omen slots, renamed/added covenant
members, duplicate JSON keys, duplicate identities/options, invalid votes, an option
containing `host_signature`, host-relabeled ballots, reveal-to-slot linkability,
oversized frames/artifacts, and stale counts are generated and asserted in Go tests
so the rejection condition remains readable. Build the Zig side from pinned commit
`d929c18` with full git history;
do not download the older release tags as ground truth. This corpus is the port's
ground truth; nothing Zig is deleted before it exists.
*Exit: `go test ./...` green in CI; corpus committed.*

**Phase 1 — familiar** (~650 lines; no crypto, pure HTTP)
Port `familiarcore` + `cmd/familiar`. Test against a live Zig `seance --bot`.
Release `familiar-v0.3.0` through the existing release.yml (§11) — this end-to-end
validates build matrix, artifact naming, checksums, formula automation.
*Exit: Go familiar chats in a Zig-hosted room; formula updated by CI; Zig familiar
`main.zig` deleted. Keep `apps/familiar/src/core.zig` and its build module until Zig
seance is retired in Phase 5; seance imports it today.*

**Phase 2 — mitt** (simplest protocol, best existing tests)
Port `secretbox`, `ident`, `tunnel`, `frame`-adjacent framing, mitt server/client.
Interop matrix in CI while both implementations exist: Zig send→Go open, Go send→Zig
open, ×{file, stdin, text, filters, oversize, wrong password}. Release `v0.5.0`.
*Exit: interop matrix green; golden outputs matched; Zig mitt deleted.*

**Phase 3 — covenant** (introduces `sigcrypto`, artifacts)
Port identity derivation, roster hashing (sorted-by-pubkey), ceremony state machine,
artifact writer + strict verifier. Cross-checks: Go `covenant verify` accepts honest
Zig-produced covenants and vice versa; exploit fixtures are rejected by Go; mixed
ceremonies (Zig host + Go members, and inverse).
Release `covenant-v0.2.0`.
*Exit: cross-verification green both directions; Zig covenant deleted.*

**Phase 4 — omen** (hardest artifact: prefix signature; consumes covenant rosters)
Port the commit–reveal state machine, prefix-signed artifact writer, and all verification
and security invariants in §6.4/§7.2.1. Cross-checks: Go `omen verify`
on honest Zig artifacts and inverse; exploit fixtures rejected by Go; mixed votes;
Go omen `--roster` consuming both Zig- and Go-produced covenants. Release
`omen-v0.2.0`. *Exit: as Phase 3, plus roster interop; Zig omen deleted.*

**Phase 5 — seance** (largest; TUI + relay + bot API + embedded familiar core)
Port `termui` (x/term raw mode, ANSI redraw: `\r\x1b[2K`, prompt `› ` in 256-color
141, per-nick color hash — the 12-color `*31+%` hash must match so nick colors don't
change across versions), relay server, client, `botapi`. Mixed-room interop: Zig
client in Go room and inverse (verbatim relay makes this work if framing is right).
`--familiar` runs `familiarcore` as a goroutine, replacing the compiled-in Zig
module. Release `seance-v0.3.0`. *Exit: mixed rooms stable under peer churn; bot API
contract tests green; automated golden/non-TTY tests pass; the release operator runs
the manual TUI checklist (arrows/home/end/delete, Ctrl+U/A/E, Ctrl+C, resize) on
macOS Terminal and Linux before tagging; Zig seance deleted.*

Term UI golden details: nick hashing uses wrapping uint32 `h = h*31 + byte` before
modulo 12; displayed `HH:MM` is derived from `timestamp % 86400` (not local-time
conversion); current cursor/edit positions are byte-oriented, so do not accidentally
promise rune/grapheme editing during the port. Put cleanup in a returning `run()` and
call `os.Exit` only after it returns, because `os.Exit` skips deferred terminal and
child-process cleanup.

**Phase 6 — Decommission Zig**
Delete `build.zig`, `build.zig.zon`, `apps/`, Zig CI steps, setup-zig actions.
Before deleting `apps/`, move `apps/mitt/assets`, app-specific README/spec material,
and the familiar README content to stable documentation paths and repair root links.
Rewrite `install.sh` (`go build ./cmd/...` into `$INSTALL_DIR`, keep ReleaseSafe's
spirit: no `-gcflags` funny business, default hardened build). Update README
(install-from-source now needs Go 1.26), RELEASE_CHECKLIST ("bump version" step →
"tag; version is ldflags-injected"), SECURITY.md (zeroization caveat, same crypto
parameters, and explicit omen non-anonymity), CHANGELOG. Remove/reword every README,
CLI, release-note, and security claim that the v1 reveal shuffle anonymizes ballots.
*Exit: repo contains no Zig; docs consistent.*

Rollback story: never move or reuse a published tag. Because each app keeps its Zig
implementation and pinned baseline until its Go release has soaked, rollback means
building the known-good Zig commit and issuing a **new patch-version tag**, then letting
the normal formula automation point at that immutable release.

## 11. Build, CI, and release migration

### 11.1 ci.yml

During Phases 0–5, keep both toolchains. Add `actions/setup-go` using `go.mod`; fail if
`gofmt -l` prints any path (printing alone is not a failing check); run `go vet ./...`,
`go build ./...`, and `go test -race ./...` on ubuntu-latest + macos-latest. Pin
`staticcheck` and `govulncheck` as Go tool dependencies in `go.mod`/`go.sum` and invoke
them through `go tool`, rather than assuming setup-go installs them. `-race` is
non-negotiable given the goroutine-per-connection servers. Add a real `schedule:`
trigger and dedicated weekly `govulncheck ./...` job. Fuzz smoke jobs invoke one
package/fuzz target per command with a short `-fuzztime`; `go test -fuzz` is not a
single all-packages command. Each phase removes only the completed app from the Zig
build/test matrix; Zig seance retains familiar core through Phase 5.

### 11.2 release.yml — keep the machinery, swap the compiler

The externally consumed pipeline shape (tag-prefix gating, 20-entry matrix, artifact
names, SHA-256 sidecars, release notes, and formula sed/push through
`HOMEBREW_TAP_TOKEN`) is preserved because the formulas depend on its naming. During
mixed-language phases, per-app dispatch can select Zig or Go. Phase 6 removes that
dispatch: the final metadata job validates one immutable tag, resolves exactly one app
and a bare semantic version, and every matrix step is conditioned on that app. The Go
build is:

```yaml
env:
  APP: ${{ matrix.app }}
  VERSION: ${{ needs.metadata.outputs.version }}
  GOOS: ${{ matrix.goos }}
  GOARCH: ${{ matrix.goarch }}
  CGO_ENABLED: "0"
run: |
  go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o dist/${APP} ./cmd/${APP}
```

The metadata job rejects anything except the five documented tag forms and checks out
that exact tag for both manual and push-triggered runs. The Linux/amd64 build executes
`--version` before packaging. Each archive contains the app binary, the MIT project
`LICENSE`, and `THIRD_PARTY_NOTICES`; the added notice files do not change the archive
name or formula install path.

The workflow uses a matrix mapping to preserve artifact spelling — **GOARCH says `arm64`/`amd64`
but the tarballs must stay `aarch64`/`x86_64`** (the formulas and the sed step key on
those exact strings):

| artifact target | GOOS | GOARCH |
|---|---|---|
| `<app>-macos-aarch64` | darwin | arm64 |
| `<app>-macos-x86_64` | darwin | amd64 |
| `<app>-linux-aarch64` | linux | arm64 |
| `<app>-linux-x86_64` | linux | amd64 |

Bonus available immediately: Go cross-compiles all four targets from one
ubuntu-latest runner, so the macOS runners can be dropped from the release matrix
(keep macos-latest in ci.yml for test coverage). Optional later consolidation to
goreleaser is explicitly deferred — it would churn artifact naming, release notes,
and formula automation simultaneously, which is exactly the blast radius this plan
avoids.

### 11.3 Homebrew tap

**No structural changes.** Formulas already install prebuilt binaries from release
tarballs; language is invisible to them. Each phase's release flows through the
existing sed automation and replaces Omen's false "Anonymous" description. It does
not mutate license metadata: the project `LICENSE`, README, and all five formula
declarations consistently identify MIT. The formula `test do` blocks keep passing
because CLI surfaces are preserved. Fetch and run the external tap's actual `test do`
blocks in a release dry run; do not infer their expectations. Mitt retains the
`--help` exit-1 quirk and gains a successful `--version` suitable for a formula smoke
test.

## 12. Testing strategy

1. **Golden crypto vectors** (Phase 0, `testdata/`): every derived key, hash,
   commitment, sealed box, and signed artifact, produced by deterministic helpers
   against canonical Zig commit `d929c18`. Inject clock and nonce into fixture-only
   paths so exact bytes are reproducible. Go unit tests assert byte equality. This
   converts "should be compatible" into "is compatible" before any protocol code is
   written.
2. **Cross-implementation interop in CI** (Phases 2–5): with full git history, build
   the Zig side from pinned canonical commit `d929c18` in an isolated worktree and run
   live exchanges against the Go build (send/receive, join/chat, ceremony, vote).
   Separately smoke the last released binaries where their v1 identity behavior is not
   expected to match. Never substitute old release tags for the canonical baseline.
   Live interop jobs may be deleted with Phase 6 after their evidence is archived;
   golden vectors and regression fixtures stay.
3. **Ported fuzzers → native Go fuzzing**: frame reader, mitt filename sanitizer,
   omen payload deserializers + `verifyArtifact`, covenant `verifyCovenant` /
   roster deserializer. Seed corpora translated from the Zig `Smith` corpora.
   One-target-at-a-time `go test -run=^$ -fuzz=<Name> -fuzztime=<short>` smoke in CI,
   long runs ad hoc.
4. **New coverage where Zig had none**: seance framing/relay/handshake (unit),
   bot API (contract tests against `net/http` server), familiar core (poll loop,
   role merging, 401 refresh — against a stub Claude server), tunnel (against a fake
   bore script). The Zig port's zero-test areas are where port regressions would
   otherwise hide.
5. **Integration harness** (`internal/itest`): spawns real binaries on loopback,
   drives full flows, asserts golden outputs and exit codes. Replaces mitt's
   `test_integration.zig` (which never actually spawned processes) with tests that do.
6. **Race detector** everywhere in CI; the seance relay under churn (join/leave/msg
   storm) is the dedicated stress test.

## 13. Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| Stale release binaries used as compatibility truth | v1/v2 deterministic identities disagree and hardening regresses | pin/build `d929c18`; keep legacy tags in a labeled secondary lane |
| Crypto parameter drift (salt, Argon2 params, nonce/tag order) | silent total incompatibility | golden vectors (Phase 0) + interop CI; §6 is normative |
| Zig verifiers accept forged structure | a “compatible” Go port would bless dropped/renamed members | strict semantic requirements and exploit regressions in §6.4 |
| Restricted omen roster is parsed but not verified/consumed | invalid covenant or one identity can cast multiple ballots | verify first, unique reservation, host membership, frozen roster (§7.2.1) |
| omen artifact prefix-signature mismatch from JSON encoding | Go can't verify Zig artifacts or vice versa | manual JSON writer, token-aware top-level prefix location, awkward-string vectors both directions |
| Duplicate JSON keys / duplicate option names | parser disagreement or tally-key collisions | reject duplicates before semantic verification |
| v1 signatures omit covenant metadata and omen session/ballot context | replay, group relabeling, or host option relabeling is mistaken for voter-attested content | live clients bind final state; verifier/docs state the limit; protocol/artifact v2 follow-up |
| Omen reveal preimages map directly to slot-tagged commitments | users rely on a false anonymity promise | remove anonymity claims from CLI/docs/security model; design real unlinkability only in protocol v2 |
| Self-contained artifacts are mistaken for real-world identity/eligibility proof | “valid” is overclaimed without an out-of-band trust anchor or linked covenant | show fingerprints and verification scope; state that v1 omen artifacts cannot prove roster use |
| u8 participant counts or 64 KiB payloads overflow | panic, truncated count, or peers reject final artifacts | clamp remote count to 254, writer hard limits, phase preflight |
| mitt's 5 GiB receive allowance exhausts memory | unauthenticated sender can force multi-GiB one-shot AEAD allocation | hard-cap Go sender/receiver/config at 1 GiB; retain 100 MiB default |
| Deadline semantics wrong (handshake clear-to-infinite) | idle peers dropped in long chats | explicit tests with >35s idle peers |
| seance TUI regressions (redraw, cursor math, raw-mode restore) | UX breakage, wedged terminals | x/term, golden ANSI transcripts, manual checklist, signal-safe restore |
| bore contract drift (output parsing, backoff) | tunnels silently stop reconnecting | fake-bore test double + one real bore.pub smoke test per release |
| Mixed compiler dispatch builds the wrong implementation | a phase release silently ships stale Zig or incomplete Go | central tag/app/version validation, conditioned matrix entries, dry-run all 20 artifacts |
| Leading `v` injected as the application version | `vv` banners and changed signed artifact bytes | normalize once in build job; golden version tests |
| Homebrew sed breaks on renamed artifacts | formula updates stop | artifact names frozen (§11.2 table); tap changes require editing this doc |
| Go HTTP server behavioral differences break unknown bot-API clients | third-party scripts fail | contract tests pin documented behavior; `Connection: close` clients unaffected |
| Relay changes nonce/tag/ciphertext | mixed Zig/Go rooms fail to decrypt | preserve encrypted byte slices even when framing them for another stream; interop room tests |
| Zeroization regression | keys linger in memory longer | §6.5 policy + SECURITY.md disclosure; threat model already assumes trusted endpoints |
| Two implementations drift during long transition | doubled maintenance | feature freeze per app from phase start; phases sized ≤ one app |

## 14. Effort estimate

Go LOC lands near parity or slightly below Zig (buffered-I/O and posix-shim
boilerplate disappears; `net/http` replaces the hand-rolled servers):

| Phase | Scope | Estimate |
|---|---|---|
| 0 | scaffolding + deterministic golden/exploit corpus + pinned Zig harness | 2–3 days |
| 1 | familiar | 1–2 days |
| 2 | mitt + shared packages | 3 days |
| 3 | covenant + verifier hardening | 3 days |
| 4 | omen + eligibility/verifier/state hardening | 4–5 days |
| 5 | seance | 4–5 days |
| 6 | decommission + asset/doc migration | 2 days |

These are planning ranges, not a release promise; re-estimate after Phase 0 exposes the
actual interop surface. The earlier ~2-week estimate omitted the pinned baseline,
security regressions, mixed-compiler release work, and soak time. Every phase still
ships a usable, brew-installable binary before the next begins.

## 15. Open questions

1. **bore.pub dependency**: port-scope keeps the subprocess. Post-port, embed a
   native Go bore client (the protocol is simple and open) and drop the external
   binary requirement? Recommended, as follow-up.
2. **familiar default model**: `claude-sonnet-4-5-20250929` is preserved for parity;
   bump to a current model in the first post-port feature release?
3. **Protocol/artifact v2**: authenticated frame headers via AAD, forward secrecy for
   seance, covenant signatures binding metadata, omen commitment signatures binding
   session + ballot context, and an actually unlinkable ballot design (the v1 reveal
   shuffle is not anonymous) are now tractable in one language with clean shared
   packages — schedule after the port settles.
