# sha2 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-07** — Tests only (pilot): instruction-count cases in `src/count.zig`, skipped unless
  `ZIGLIBS_COUNT` names one, held by `scripts/count-insns sha2` to `tools/count.tsv` (instructions per
  round under cachegrind, ReleaseFast, `-mcpu=x86_64_v3`): `sha256-1KiB` 29 686, `sha512-1KiB` 21 079.

- **2026-10-03** — Audit (review + 54-mutant schemata run): no defect, no surviving
  mutant that is not equivalent (two, with reasons in SPEC). No source change.
- **2026-09-29** — New module: SHA-224/256/384/512 (FIPS 180-4) as a drop-in for
  `std.crypto.hash.sha2` (same declarations; works under std's `Hmac`/`Hkdf`), with an
  AVX2 multi-block message schedule that makes runs of two or more blocks 1.24–1.40×
  std on x86-64 without SHA-NI, a portable scalar path elsewhere, and std's own
  hardware path for SHA-256 where the target has SHA-NI or ARMv8 `sha2`. Anchored to
  the FIPS 180-4 / NIST example vectors, RFC 4231 (HMAC) and RFC 5869 (HKDF), and
  differentially to std. Requested by qap's performance audit (candidate P3).
