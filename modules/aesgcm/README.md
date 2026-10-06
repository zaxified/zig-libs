# aesgcm

**AES-GCM** (AES-128 and AES-256, 96-bit nonce, 128-bit tag) that is a
drop-in for `std.crypto.aead.aes_gcm` and faster than it in two ways: a
**stateful `Context`** holds the expanded key and the GHASH key powers, so a
TLS connection derives them once per key instead of once per record; and on
x86-64 with AES-NI and PCLMULQDQ a **one-pass, stitched kernel** runs the AES
rounds of eight counter blocks while it multiplies eight ciphertext blocks
into GHASH, where std makes two passes. 1.6–1.8× std on 16 KiB records, 2.0–2.2× on
480-byte ones, ~3× on 64-byte ones; on par with OpenSSL's AES-NI code on the
development machine (table below).

- **Status:** gap — std's AES-GCM is two-pass and stateless; in qap's TLS
  server it was ~35 % of all CPU on 32 KiB responses (CTR 20–22 %, GHASH
  13–14 %), and ~5 % on 480-byte ones, much of that per-record setup.
- **Model after:** OpenSSL/BoringSSL `aesni-gcm` (the stitched loop), the
  Gueron–Kounavis Intel CLMUL GCM white paper (representation, shifted H,
  two-phase reduction, aggregated reduction), std's `aes_gcm` (the API).
- **Platform:** any. x86-64 gets the kernel, picked at run time (CPUID) unless
  the build target already guarantees AES-NI, PCLMULQDQ and SSSE3; every other
  target, arm64 included, runs std's AES/GHASH primitives (hardware on arm64
  when the target has `aes`) with the key schedule cached. **Role:** codec.
  **Concurrency:** reentrant; a `Context` is read-only after `init` and may be
  shared by threads. **Allocation:** none.

```zig
const aesgcm = @import("aesgcm");
const Gcm = aesgcm.Aes256Gcm; // or Aes128Gcm

// Once per key (per TLS traffic key and direction):
var ctx = Gcm.init(key);
defer ctx.wipe(); // the context holds the key schedule: wipe it when retired

ctx.encrypt(ciphertext, &tag, plaintext, ad, nonce);
try ctx.decrypt(plaintext, ciphertext, tag, ad, nonce); // error.AuthenticationFailed

// std's stateless shape, same constants and error, for a drop-in swap:
Gcm.encrypt(ciphertext, &tag, plaintext, ad, nonce, key);
try Gcm.decrypt(plaintext, ciphertext, tag, ad, nonce, key);

_ = aesgcm.backend(); // .aesni or .generic
```

- **In place:** the output may be the input (the same slice), or start
  *before* it in the same buffer — e.g. a TLS record decrypted over its own
  5-byte header, which `tls.zig`'s client does. Both work with std too (its CTR
  runs front to back); here they are tested. An output starting *after* the
  input and overlapping it is not supported.
- **On authentication failure** every byte of the output is zeroed (the x86
  kernel decrypts in the same pass as it authenticates, so plaintext was
  written); in place, the ciphertext is gone with it — as with std, whose
  output is `undefined` then.
- **Lengths:** `c.len == m.len` and `m.len ≤ 2³⁶ − 32` bytes are asserted, as
  std asserts them.
- **Size:** a `Context` is ≤ 320 bytes (AES-128) / ≤ 384 (AES-256).
- `Gcm.initWith(.generic, key)` / `aesgcm.available(b)` pick a backend
  explicitly, for comparisons.

## Speed

MB/s, ReleaseFast, pinned to one core (`taskset -c 1`) of the development
notebook (i7-7920HQ, Kaby Lake: AES-NI, PCLMULQDQ, AVX2, no VAES), best of 25
interleaved rounds, 13-byte AD; OpenSSL 3.5.5 `openssl speed -evp -bytes N`,
best of 5, same core, same session (2026-09-28, a loaded machine — read the
ratios). Encryption unless marked.

| | bytes | std | `Gcm.encrypt` (stateless) | `Context.encrypt` | `Context.decrypt` | OpenSSL |
|---|---:|---:|---:|---:|---:|---:|
| AES-128 | 64 | 418 | 719 | 1 352 | 1 432 | 162 |
| | 480 | 1 550 | 2 425 | 3 402 | 3 833 | 1 283 |
| | 1 024 | 1 983 | 3 643 | 4 536 | 4 816 | 1 966 |
| | 16 384 | 3 037 | 5 362 | 5 414 | 5 326 | 4 971 |
| AES-256 | 64 | 355 | 592 | 1 032 | 1 172 | 170 |
| | 480 | 1 320 | 2 059 | 2 667 | 2 886 | 787 |
| | 1 024 | 1 515 | 2 861 | 3 354 | 3 606 | 1 592 |
| | 16 384 | 2 467 | 4 013 | 4 016 | 4 069 | 3 656 |

OpenSSL's small-size figures include its EVP per-call overhead (nonce reset,
`EVP_EncryptFinal`), so compare at 16 KiB, where both are bound by the AES
unit (AES-128: 80 `aesenc` per 128 bytes, one per cycle).

Provenance: original work of the zig-libs authors (MIT). The construction
follows NIST SP 800-38D and the published descriptions named in *Model after*
(the Intel white papers on AES-NI key expansion and CLMUL GCM); no third-party
source was read for or translated into this code. Test
vectors: the McGrew–Viega GCM test cases are the specification's own published
examples; `src/testdata/openssl_kat.zig` is generated data from our own tooling
(`tools/openssl_kat.py`), which runs OpenSSL as a black-box oracle over inputs
of our choosing; `src/testdata/wycheproof.zig` reproduces 133 Wycheproof
vectors, Apache-2.0 test data — see [NOTICE](NOTICE), which must travel with
the module.
