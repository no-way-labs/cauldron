# Mixed-implementation artifact fixtures

These four honest artifacts were captured on 2026-07-13 before the legacy tree
was removed. Each ceremony/vote had one Go process and one canonical Zig
`d929c18972089c612a6dfc9f512fe3452388ca6f` process:

- `covenant-zig-host.json`: Zig host, Go member.
- `covenant-go-host.json`: Go host, Zig member.
- `omen-zig-host.json`: Zig host, Go voter.
- `omen-go-host.json`: Go host, Zig voter.

In each run both implementations emitted byte-identical copies of the final
artifact, and both offline verifiers accepted it. The checked-in Go tests keep
verifying all four artifacts and reject signature/roster tampering. These files
contain public keys, signatures, commitments, and reveal preimages from test-only
identities; they contain no room passwords or private identity phrases.
