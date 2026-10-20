# aes192 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-20** — **New:** `Aes192EncryptCtx.ctr(dst, src, iv)` — CTR with the whole block as a 128-bit big-endian counter, byte for byte `std.crypto.core.modes.ctr(…, .big)`. On Zig 0.17 std's `ctr` writes each counter with a byte-by-byte `mem.writeInt(u128)` (#36256): 2.32× OpenSSL EVP AES-192-CTR at 16 KiB; this one is 0.96×. Tests: SP 800-38A F.5.5/F.5.6 through it, every length over two wide batches and the half-carry / full-wrap counters against std, a `ctr_mode`/`ctr_carry` fuzz check; ctgrind `enc` covers it.

- **2026-10-20** — **Security fix:** without AES hardware (x86-64 without AES-NI or AVX,
  arm64 without the Crypto Extensions, other architectures) the rounds now run on std 0.17's
  bitsliced constant-time core (`src/bitsliced.zig`, a copy — std keeps it private) whenever
  `side_channels_mitigations != .none`, as std's own `Aes128`/`Aes256` do; until now they were
  std's cache-line-masked table lookups (audit 2026-10-19, O5-1). Same API and outputs; on that
  backend a context also carries the 13 packed round keys (`packed_keys`, 3.3 KiB on 64-bit,
  cleared by `wipe`), the init burn is 8 KiB, and a one-block call costs a 16-block batch, as in
  std. Hardware backends unchanged (identical ctgrind output digests). Evidence: suite, stack
  probe and 200 000-run model fuzz on `-Dcpu=x86_64`; new ctgrind row `bitsliced` 0 in-file;
  consumers aesgcm/aeskw/aescbc green on `-Dcpu=x86_64`. New `NOTICE` (Zig's MIT terms).

- **2026-10-19** — **Fix:** Docs (security claim): the *Constant-time contract* said the
  software backend has "exactly std's `Aes128`/`Aes256` posture, no worse" and that neither std
  nor this module has a bitsliced AES; the 2026-10-18 entry below said this was re-checked on
  0.17.0. It is false on Zig 0.17: std's soft `Aes128`/`Aes256` contexts are bitsliced when
  `side_channels_mitigations != .none`, this module's rounds still use the masked table
  lookups, so on targets without hardware AES (0.17 also requires AVX on x86-64) AES-192 is
  weaker than std's siblings. SPEC/README corrected (affected targets listed); the bitsliced
  backend is a *Backlog / deferred* entry. No code change.

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
