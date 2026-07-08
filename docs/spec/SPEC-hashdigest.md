# SPEC — `hashdigest`

**Purpose** — Streaming cryptographic digests: one-shot / incremental / whole-file hashing with a
SHA-256 convenience path and a multi-algorithm layer (SHA-2 family, SHA-3, BLAKE2b, BLAKE3). For
file verification, content-addressing, and integrity checks. A thin, ergonomic layer over
`std.crypto.hash`.

**Model after / Seed** — Go `crypto/sha256` streaming ergonomics, generalized to a multi-algorithm
API over `std.crypto.hash`. Extracted from the authors' axp `digest.zig` / `task.zig` (Apache-2.0,
relicensed MIT). The constructions are the published hash standards; std provides the primitives.

**Design & invariants**
- **Three shapes:** one-shot (`sha256Hex`/`hex`), incremental (`Hasher`/`MultiHasher` — `update`
  then `final`), and file (`hashFile`, reads to EOF). The file path is **size-0 `/proc`-safe** —
  it reads to EOF rather than trusting `stat` size, so `/proc`/`/sys` pseudo-files (which report
  size 0) hash correctly.
- `Algorithm` enum with `digestLength`/`hexLength`; comptime `HexOf` for fixed-size hex buffers;
  runtime `MultiHasher` for algorithm chosen at runtime.
- **Allocation discipline:** the one-shot and incremental hashing paths are allocation-free; only
  the `*Alloc` hex helpers and file reads use the caller's allocator/reader (via `std.Io`).
- Reentrant for the pure one-shot fns; `Hasher`/`MultiHasher` instances are single-owner.

**Threat model / out of scope**
- Provides **integrity/fingerprinting**, not authentication — a bare digest is not a MAC; an
  attacker who can change the data can change the digest. Use `webhooksig` (HMAC) or a signature for
  authenticated integrity.
- Algorithm choice is the caller's: MD5/SHA-1 are **not** offered (only collision-resistant
  families); still, don't use a plain digest where a KDF or MAC is required.
- **Out of scope:** HMAC/keyed hashing, KDFs, streaming over a network, and constant-time digest
  comparison (a digest is public; compare with `std.mem.eql` — unlike a secret MAC).

**Verification** — Official empty-string and `"abc"` known-answer vectors for all 9 algorithms;
incremental-equals-one-shot; the `/proc`-style size-0 file read. 17 tests.

**Status** — `extract · any · util · reentrant` · deps: none (`std.crypto` only).
