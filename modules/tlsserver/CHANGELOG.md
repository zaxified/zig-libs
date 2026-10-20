# `tlsserver` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-20** — New module: a TLS 1.3 server, under construction; first piece the record
  layer (`record`: header, per-direction in-place `Protection.seal` / `open` for the AES-128-GCM,
  AES-256-GCM and ChaCha20-Poly1305 suites). Verified against the seven protected records of RFC
  8448 §3 and OpenSSL-sealed AES-256-GCM / ChaCha20-Poly1305 records; fuzz harness
  `tlsserver-record` (12,000,000-run verdict clean, five planted mutants caught) and a ReleaseFast
  stack probe.
