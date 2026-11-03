# hashdigest — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-02** — **ADDITIVE:** goal-3 grade-2 work. (1) `checksum` namespace: `sha256sum -c` style parse (`Iterator`, `parseLine`, GNU text/binary lines, BSD `ALGO (name) = hex` tags, `\`-escaped names, comments, CRLF) and verify (`verifyEntry`, `verifyAll`, `Summary`), plus `hashFileIn` (`hashFile` relative to a `std.Io.Dir`). (2) `xof` (SHAKE128/256, BLAKE3, any output length), `blake3Keyed`, `blake3DeriveKey`. (3) `blake2b256` now runs on a row-vectorised in-module BLAKE2b-256 (`src/blake2b.zig`), byte-identical to std's. Tests: cross-implementation goldens from Python hashlib and GNU coreutils (`tools/gen_golden.py`), deterministic fuzz driver for the parser (`HASHDIGEST_FUZZ`), sweep HD-3.

- **2026-10-30** — **CONSUMER-VISIBLE (fixes only):** no-panic sweep + blind review (§ GS). `Hasher.finalHex`/`MultiHasher.finalHex` finalise a zeroed-after-use copy of the state, so `update` may continue and `finalHex` may repeat (SHA-3 panicked in std on update-after-final, SHA-2 silently gave a wrong digest). Docs: `sha256File`/`hashFile` have no size or time limit (a FIFO or /dev/zero never ends) and use 128 KiB of stack; `matches`/`matchesAlgo` are not constant-time. Tests: `src/sweep_test.zig`.
- **2026-10-10** — tools: comparative benchmark `tools/bench.zig` + `tools/go_bench/` + `tools/c_bench/foreign_bench.c` (`zig build bench-hashdigest`) against Go 1.26.0 (reference) and OpenSSL 3.5.5 / libsodium 1.0.18; card Performance filled (0.84–1.40×, fastest 1.60× OpenSSL), SPEC "Performance" section and the lever in the backlog.
- **2026-10-04** — **Tests:** mutation run (11 schemata mutants, 9 killed, 2 equivalent; one new
  test pins the `ShortBuffer` edge of `hex` and `MultiHasher.finalHex`). No code change.

- **2026-07-18** — Security audit: no findings. Modeled on OpenSSL / BLAKE3-C (design
  reference, not a test anchor).
- **2026-07-07** — New module: Streaming digests — one-shot / incremental / file
  (EOF-read, size-0 `/proc` safe); SHA-256 convenience + a multi-algorithm layer
  (SHA-2/SHA-3/BLAKE2b/BLAKE3).
