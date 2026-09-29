# sha2

**SHA-224, SHA-256, SHA-384 and SHA-512 (FIPS 180-4)**, a drop-in for
`std.crypto.hash.sha2` that is faster wherever a message is hashed in runs of
two or more blocks (from 128 bytes for SHA-256, 256 for SHA-384/512): 1.24–1.40×
std from 1 KiB up on an AVX2 CPU without SHA-NI (below). The types have std's
declarations — `block_length`, `digest_length`, `Options`, `init`, `update`,
`peek`, `final`, `finalResult`, `hash` — so a consumer changes the type and
nothing else, including under std's generic `Hmac` and `Hkdf`.

- **Status:** gap — std's SHA-2 computes the message schedule with scalar code
  (on x86-64 without SHA-NI), which on the development notebook put it at
  1.48× behind OpenSSL for both SHA-256 and SHA-384; qap's TLS handshake lane
  spent 15.9 % of its CPU in SHA-2 rounds.
- **Model after:** FIPS 180-4; the vectorized message schedule of Intel's
  "Fast SHA-256 Implementations on Intel Architecture Processors" (Guilford et
  al., 2012) and Gulley et al.'s SHA-512 counterpart, applied across blocks.
- **Platform:** any (the SIMD schedule on x86-64 with AVX2, a portable scalar
  path everywhere else). **Role:** util. **Concurrency:** reentrant.
  **Allocation:** none.

```zig
const sha2 = @import("sha2");

var digest: [sha2.Sha256.digest_length]u8 = undefined;
sha2.Sha256.hash(bytes, &digest, .{});          // == std.crypto.hash.sha2.Sha256.hash

var h = sha2.Sha384.init(.{});                  // streaming, as std
h.update(part1);
h.update(part2);
const d384 = h.finalResult();

// std's generic constructions take it unchanged:
const HmacSha256 = std.crypto.auth.hmac.Hmac(sha2.Sha256);
const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.Hmac(sha2.Sha384));

_ = sha2.Sha256.backend();                      // .simd / .scalar / .stdlib
```

**Which path runs is fixed at compile time** by the target: `.simd` on x86-64
with AVX2 (built with LLVM), `.stdlib` for SHA-224/256 where std itself uses
SHA hardware instructions (x86-64 SHA-NI, ARMv8 `sha2`) — there std is the
faster one and this module hands it the blocks — and `.scalar` anywhere else.
A build for baseline x86-64 therefore takes the scalar path even on an AVX2
CPU; build with `-mcpu=native` (the default for a native build) or name the
CPU model to get the SIMD schedule.

**Where the gain is, and where it is not.** The speed-up comes from computing
the message schedules of up to 8 SHA-256 blocks (4 SHA-512 blocks) together,
so it applies to `update` calls that carry two or more whole blocks. A lone
block — a short message, the padding block of `final`, each of HMAC's key-pad
blocks — runs the scalar rounds at std's speed: on this CPU the rounds are
bound by instruction count, not by the schedule. Short messages are therefore
no slower than std, and not faster either.

## Speed

MB/s, best of 5, ReleaseFast, one-shot `hash`, on the development notebook
(2026-09-29, i7-7920HQ Kaby Lake: AVX2, BMI2, no SHA-NI; a loaded machine,
so read the ratios). `scalar` is this module's fallback forced on the same
CPU. Re-measure with `src/bench.zig` (its header has the command).

| hash | bytes | std | sha2 | × std | scalar |
|---|---:|---:|---:|---:|---:|
| SHA-256 | 64 | 134 | 136 | 1.01 | 138 |
| SHA-256 | 1 KiB | 270 | 369 | 1.37 | 270 |
| SHA-256 | 16 KiB | 290 | 405 | 1.40 | 290 |
| SHA-256 | 1 MiB | 294 | 403 | 1.37 | 299 |
| SHA-384 | 64 | 205 | 215 | 1.05 | 217 |
| SHA-384 | 1 KiB | 403 | 502 | 1.24 | 402 |
| SHA-384 | 16 KiB | 456 | 589 | 1.29 | 459 |
| SHA-384 | 1 MiB | 450 | 597 | 1.33 | 470 |

A second run the same day gave 1.03 / 1.39 / 1.37 / 1.41 (SHA-256) and
1.13 / 1.30 / 1.26 / 1.35 (SHA-384) — run-to-run noise is about ±5 %. SHA-384
at exactly 1 KiB is 8 message blocks plus a lone padding block, which caps it
near 1.25–1.3×. For scale, OpenSSL on the same machine: SHA-256 418 MB/s,
SHA-384 640 MB/s.

Provenance: original work of the zig-libs authors (MIT), clean-room from FIPS
180-4 and the published algorithm descriptions named above; the round and IV
constants are derived in the source from their definitions (cube and square
roots of primes) and checked against the standard's tables. No third-party
source was ported or translated, so no `NOTICE` entry is required (root
[`NOTICE`](../../NOTICE) §0).
