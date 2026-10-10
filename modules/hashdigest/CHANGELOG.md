# hashdigest — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — tools: comparative benchmark `tools/bench.zig` + `tools/go_bench/` + `tools/c_bench/foreign_bench.c` (`zig build bench-hashdigest`) against Go 1.26.0 (reference) and OpenSSL 3.5.5 / libsodium 1.0.18; card Performance filled (0.84–1.40×, fastest 1.60× OpenSSL), SPEC "Performance" section and the lever in the backlog.
- **2026-10-04** — **Tests:** mutation run (11 schemata mutants, 9 killed, 2 equivalent; one new
  test pins the `ShortBuffer` edge of `hex` and `MultiHasher.finalHex`). No code change.

- **2026-07-18** — Security audit: no findings. Modeled on OpenSSL / BLAKE3-C (design
  reference, not a test anchor).
- **2026-07-07** — New module: Streaming digests — one-shot / incremental / file
  (EOF-read, size-0 `/proc` safe); SHA-256 convenience + a multi-algorithm layer
  (SHA-2/SHA-3/BLAKE2b/BLAKE3).
