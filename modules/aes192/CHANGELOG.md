# aes192 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — Scope survey (OpenSSL reference, Go `crypto/aes`, RustCrypto `aes`, Zig std):
  `parity`; `## Compared with` table added; grade 4 (no longer provisional). Docs only.
- **2026-10-10** — New module: the AES-192 block cipher std 0.16 lacks, shaped like std's
  `Aes128`/`Aes256` (`Aes192`, `Aes192EncryptCtx`, `Aes192DecryptCtx`, `*Into` twins, `wipe`).
  Own FIPS-197 §5.2 key expansion (SubWord through std's `Block.encryptLast`), std's round
  primitive on every backend. Anchored on FIPS-197 C.2/A.2, all 720 CAVP AESAVS AES-192 ECB
  vectors and SP 800-38A; textbook-model fuzz harness (`AES192_FUZZ`); ctgrind `enc`/`dec`
  (0 in-file on AES-NI); dead-stack burn on the key-schedule entry points with a stack probe.
  Not yet wired into any mode module.
