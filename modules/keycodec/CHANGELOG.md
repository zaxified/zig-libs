# `keycodec` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-06** — **Tests:** every OpenSSL ML-KEM key (seed, expanded, both; 512/768/1024) loads into the zig-libs `mlkem` module with OpenSSL's public key, and an `mlkem` key written through keycodec is OpenSSL's bytes (`src/mlkem_test.zig`, test dependency `mlkem`). tlsserver and acme now read keys through keycodec.
- **2026-11-05** — **NO CONSUMER-VISIBLE CHANGE:** fuzz harness on the deterministic driver (`src/fuzz.zig`, `KEYCODEC_FUZZ`): round trip of random keys of every algorithm and encoding, an independent scalar-range model, write/read fixpoint of mutated DER and PEM; 2000 seeds in every test run, 24M clean in the verdict run.
- **2026-11-05** — Independent review fixes: a PKCS#8 v2 RSA public key is checked (and written back); a one-line PEM followed by a comment with a `:` reads; PKCS#1 is strict by version (v0: eight INTEGERs, v1: non-empty `otherPrimeInfos`), no INTEGER is empty, PKCS#8 attributes must be Attribute SEQUENCEs; a PKCS#8 EC key without a curve in its AlgorithmIdentifier takes the inner `[0]` (Go's fallback); the PKCS#1 writer checks its fields; a failed write zeroes what it wrote; a stray `-----BEGIN ` in comment text is skipped; the writer's stack burn reaches past its 16 KiB buffer. New `writeRsaPublicKeyPem` (PKCS#1 `RSA PUBLIC KEY`).
- **2026-11-05** — New module: PKCS#8, SEC1, PKCS#1 and SPKI key encodings with constant-time PEM, for EC (P-256/384/521, secp256k1), Ed25519/Ed448, X25519/X448, RSA/RSASSA-PSS, ML-DSA and ML-KEM; type-agnostic (a key is its algorithm plus slices of the caller's DER), so `jwt`, `acme`, `tlsserver` and `mlkem` can share one reader instead of carrying four. Anchored on 33 OpenSSL 3.5.5 keys read into the parts OpenSSL prints and written back byte for byte.
