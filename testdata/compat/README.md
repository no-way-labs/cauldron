# Compatibility fixtures

`vectors.txt` was captured from canonical legacy commit `d929c18` before the Zig
implementation was decommissioned. The one-time generator used fixed passwords,
inputs, clocks, and nonces; it was fixture tooling and never replaced production
entropy.

The Go compatibility tests parse this immutable file and assert exact derived
keys, sealed-box bytes, public keys, commitments, roster hashes, commit-set
hashes, and signatures. Change a vector only as part of an explicitly versioned
protocol migration with independent output from the historical implementation.
