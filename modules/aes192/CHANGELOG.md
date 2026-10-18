# aes192 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Docs: README/SPEC statements about std AES (128/256 only, no CBC) and the two std software-backend defects re-checked against the 0.17.0 std (both defects are still there).

- **2026-10-11** — Performance P3 → P2 (grade 3 → 2): comparative bench `tools/bench.zig`
  (`zig build bench-aes192`) against OpenSSL 3.5.5 EVP AES-192 — ECB both ways, CBC, CTR at
  0.97–1.01×, key setup 0.74–0.81×. Key setup was 1.65–1.81× before: the key-schedule burn is
  now 512 bytes instead of 4 KiB (the body dirties ≤ 256 B; stack probe green), and the
  expansion runs on little-endian `u32` words instead of `[4]u8` (same FIPS-197 §5.2 schedule;
  all vectors, model fuzz and ctgrind unchanged). Audit A1 → A2: the mutation run was over the
  previous text.

- **2026-10-10** — Audit (review + mutation schemata), no code change. Review: key expansion
  (Nk = 6 RotWord/SubWord/Rcon schedule, rcon index 0..7), the equivalent-inverse schedule and the
  round sequences match FIPS-197; clean. LOW, kept: `Aes192DecryptCtx.initFromEnc` takes and returns
  the schedule by value with no burn — std's `AesDecryptCtx.initFromEnc` shape; `initInto` is the
  dead-stack-clean way to a decryption context. Mutation 21/22: the survivor (`subWord` reading
  column 1 instead of 0) is equivalent — all four columns hold the same word and ShiftRows is the
  identity on such a state. Card: audit A4 → A1 (`src 510d8447160244b9`), grade 4 → 3.

- **2026-10-10** — Scope survey (OpenSSL reference, Go `crypto/aes`, RustCrypto `aes`, Zig std):
  `parity`; `## Compared with` table added; grade 4 (no longer provisional). Docs only.
- **2026-10-10** — New module: the AES-192 block cipher std 0.16 lacks, shaped like std's
  `Aes128`/`Aes256` (`Aes192`, `Aes192EncryptCtx`, `Aes192DecryptCtx`, `*Into` twins, `wipe`).
  Own FIPS-197 §5.2 key expansion (SubWord through std's `Block.encryptLast`), std's round
  primitive on every backend. Anchored on FIPS-197 C.2/A.2, all 720 CAVP AESAVS AES-192 ECB
  vectors and SP 800-38A; textbook-model fuzz harness (`AES192_FUZZ`); ctgrind `enc`/`dec`
  (0 in-file on AES-NI); dead-stack burn on the key-schedule entry points with a stack probe.
  Not yet wired into any mode module.
