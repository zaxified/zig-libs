# drand

Client core for the drand randomness beacon: parse chain-info, decode a beacon
round, and BLS-verify a round's threshold signature against the chain public
key (via `bls12_381`, reusing the quicknet ciphersuite `tlock` pins). Transport-
agnostic — the caller fetches the bytes (drand is HTTPS; TLS is caller's job).

**Status:** gap (placeholder — implementation pending).
