# Changelog

Notable changes to all Cauldron applications are recorded here.

## Unreleased — Go port

### Changed

- Reimplemented mitt, seance, familiar, omen, and covenant in Go 1.26 while
  preserving the published v1 network protocols, cryptographic parameters,
  artifact encodings, command surfaces, and release archive names.
- Replaced the Zig build with Go builds, dual-OS race-tested CI, native fuzz
  smoke tests, pinned static analysis/vulnerability tools, and static
  cross-compiled release binaries.
- Moved stable mitt and familiar documentation under `docs/` and retired the
  legacy Zig source tree.
- Corrected all claims that omen v1 provides anonymous voting. Reveals are
  directly linkable to signed roster slots.
- Relicensed the project under MIT at the owner's direction, resolving the
  pre-existing mismatch with the README and Homebrew formulas. Release
  automation also replaces Omen's stale anonymity claim in its formula
  description.

### Added

- Strict covenant and omen JSON/artifact verification, including duplicate-key,
  canonical-order, complete-slot, stale-count, signature, reveal-bijection,
  tally, and winner checks.
- Strict covenant-roster enforcement for live restricted omen votes.
- Bounded seance bot-message retention and event-driven long polling.
- Environment-variable secret inputs, graceful SIGINT/SIGTERM shutdown, bounded
  frame/artifact/request sizes, and handshake/write deadlines.
- Project and pinned Go dependency notices in every release archive.
- Deterministic compatibility vectors and live Zig/Go cross-implementation test
  coverage captured before decommissioning the legacy implementation.

### Fixed

- Made seance peer admission and nickname collision resolution atomic.
- Made mitt receive concurrency/rate limits effective and filename collision
  saves exclusive and race-safe.
- Prevented malformed or adversarial ceremony artifacts from being accepted via
  duplicate fields, missing slots, duplicate identities/options, or stale
  derived values.
- Made tunnel startup and teardown bounded and drained child output
  concurrently, with synchronized status snapshots during reconnects.
- Isolated slow or failed peers in seance, covenant, and omen so one blocked
  connection cannot pin a relay slot or serially consume every ceremony
  participant's write deadline.

### Security

- Documented that v1 cleartext frame headers and mitt filenames are not bound as
  AEAD associated data, that Go memory clearing is best effort, and that
  Familiar sends conversation context to Anthropic.
- Documented that untrusted protocol/artifact text can carry terminal control
  sequences because v1-compatible display output is not escape-filtered.
- Documented the exact limits of covenant member signatures and omen voter
  signatures, self-contained roster eligibility, offline password attacks, and
  endpoint compromise.

## mitt 0.4.1 — 2025-12-03

### Fixed

- Improved bore port-conflict detection via stderr monitoring.
- Added automatic retry with a random port when a requested bore port is
  unavailable.
- Improved tunnel failure diagnostics.

## mitt 0.4.0 — 2025-12-03

### Added

- Added `--bore-port` to request a specific remote bore port.
- Added bore-port input validation.

## mitt 0.3.0 — 2025-12-02

### Fixed

- Fixed `--text` parsing so literal text no longer requires a positional file.

## mitt 0.2.0

- Initial public release with XChaCha20-Poly1305 transfer encryption, Argon2id
  password derivation, bore tunneling, filters, and file/stdin/text payloads.
