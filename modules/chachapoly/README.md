# chachapoly — SIMD ChaCha20-Poly1305 AEAD (RFC 8439)

A **throughput-specialized** reimplementation of the ChaCha20 stream cipher and
the ChaCha20-Poly1305 AEAD that `std.crypto` already ships. It exists purely for
speed: `std.crypto.stream.chacha` vectorises *within* a single block (the
diagonal `@shuffle` layout) but gates its AVX2 / AVX-512 lanes behind
`builtin.cpu.has(.x86, .avx2)`, so at the default `baseline` x86-64 target it
collapses to one 128-bit lane and runs ~3.9× slower than OpenSSL's AVX2 ChaCha
(measured framing: std ~478 MB/s vs OpenSSL ~1852 MB/s at 8 KiB). We can't patch
`std`, so this is our own zero-C, `@Vector`-SIMD alternative.

It is **byte-exact** to `std` and to RFC 8439 — verified both against the RFC
known-answer vectors and differentially against
`std.crypto.aead.chacha_poly.ChaCha20Poly1305` (the oracle). See `SPEC.md` for
the design; metadata lives in `src/root.zig`'s `pub const meta`.

## What it provides

- `ChaCha20` — the IETF ChaCha20 stream cipher (32-byte key, 12-byte nonce,
  32-bit block counter). `xor(out, in, counter, key, nonce)` and
  `stream(out, counter, key, nonce)`, API-compatible with
  `std.crypto.stream.chacha.ChaCha20IETF`.
- `ChaCha20Poly1305` — the AEAD. `encrypt(c, tag, m, ad, npub, k)` and
  `decrypt(m, c, tag, ad, npub, k) AuthenticationError!void`, byte-for-byte
  compatible with `std.crypto.aead.chacha_poly.ChaCha20Poly1305` (`tag_length`
  16, `nonce_length` 12, `key_length` 32).

Because the shapes match `std`, a consumer that speaks the std AEAD API
(`signal`, `noise`, `wireguard`, `hpke`, `quic-crypto`, `bolt8`) can swap this in
without touching call sites.

## Use

```zig
const cp = @import("chachapoly");

// AEAD seal / open
var c: [msg.len]u8 = undefined;
var tag: [16]u8 = undefined;
cp.ChaCha20Poly1305.encrypt(&c, &tag, msg, ad, nonce, key);

var m: [msg.len]u8 = undefined;
try cp.ChaCha20Poly1305.decrypt(&m, &c, tag, ad, nonce, key); // error.AuthenticationFailed on tamper

// Raw ChaCha20 keystream (NOT authenticated on its own)
cp.ChaCha20.xor(out, in, 1, key, nonce);
```

## Performance (this host, ReleaseFast)

Reproduce with:

```
CHACHAPOLY_BENCH=1 scripts/capped zig build test-chachapoly -Doptimize=ReleaseFast
```

Measured on an i7-7920HQ (AVX2, no AVX-512), 8 KiB working set, ReleaseFast,
median of three runs:

| what | ours | std | |
|---|---:|---:|---:|
| ChaCha20 keystream | 2355 MB/s | 1450 MB/s | **1.6×** |
| ChaCha20 xor (fused) | 2383 MB/s | 718 MB/s | **3.3×** |
| Poly1305 MAC | 3892 MB/s | 1443 MB/s | **2.7×** |
| full AEAD encrypt | 1406 MB/s | 502 MB/s | **2.8×** |
| AEAD, 1420 B packet | 1127 MB/s | 441 MB/s | **2.6×** |

(Re-measured 2026-08-10 on the same host: 1.66× / 3.18× / 2.47× / 2.90× / 2.48×.
Run-to-run spread on these lines is a few percent — read them as ratios.)

Poly1305 is lane-parallel above a size threshold and std's scalar core below it,
so the MAC speedup is size-dependent. Below the threshold the executed code *is*
std's, so those columns are parity by construction and the ±2–3% there is timer
noise, not a difference:

| message | 32 B | 128 B | 256 B | 512 B | 1420 B | 4 KiB | 8 KiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| ours vs std | 1.0× | 1.0× | 1.06× | 1.5× | 2.0× | 2.4× | 2.5× |

**Short AEAD calls run std, not this module.** When `message + AD ≤ 128 bytes`
the whole AEAD is handed to `std.crypto.aead.chacha_poly`, and when a ChaCha run
(or its post-group tail) is ≤ 64 bytes the cipher is handed to
`std.crypto.stream.chacha`. So a WireGuard keepalive, a tunnelled ACK or a short
handshake payload gets exactly std's speed — by design, so that no size loses.
The wins above start at 144 B. Both branches are on lengths only, never on key
or plaintext; see `SPEC.md`.

**The XOR is fused.** `ChaCha20.xor` used to stage the keystream into a stack
buffer and then XOR it byte-wise; that loop was not vectorised at all (LLVM could
not prove `out` does not alias `in`, and emitted one `movzbl`/`xor`/`mov` per
byte), so `xor` ran at 1102 MB/s against 2219 for `stream`. Each block group is
now transposed straight out of the `@Vector` state into 64-byte vectors, XORed
against unaligned loads and stored — no intermediate keystream bytes. `xor` went
1102 → 2383 MB/s, the 8 KiB AEAD 845 → 1406, and a 1420-byte packet 542 → 1127.

Cipher (~2.4 GB/s) and MAC (~3.9 GB/s) in series predict ~1.47 GB/s, which is
what the AEAD measures — neither side has slack left. Further gains need a wider
block group (AVX-512) or interleaving the two passes, not another local fix.

## Verify

```
zig build test-chachapoly                          # Debug
zig build test-chachapoly -Doptimize=ReleaseFast   # ReleaseFast (UB checks)
```

Tests cover the RFC 8439 §2.3.2 / §2.4.2 / §2.5.2 / §2.8.2 KATs, the eleven
RFC 8439 §A.3 Poly1305 vectors at every lane width, a differential against the
`std` AEAD across block-boundary edge lengths (seal/open/cross-decrypt /
tamper-reject), a `>8`-block counter-increment boundary case, a byte-exact
ChaCha20 `xor`/`stream` differential against `std` for **every** length 0..1024
(the fused path's tail can be any of 0..511 bytes), the in-place case
(`out == in`) at every one of those lengths plus in-place AEAD, an
unaligned-offset sweep over all 64×64 input/output offset pairs, and a
length-by-length Poly1305 differential against `std` for **every** length
0..2048 at L ∈ {1,2,4,8}.

## Provenance

Clean-room from RFC 8439 (ChaCha20-Poly1305), a public IETF spec — the
construction itself needs no attribution (merger doctrine, root `NOTICE` §0).
Two std relationships are recorded instead:

1. **Design reference** — Zig std `std/crypto/chacha20.zig` (MIT) was studied
   for the `@Vector` quarter-round shape; this module uses a different,
   block-parallel (transpose) SIMD layout, no source ported.
2. **Component** — the Poly1305 MAC is `std.crypto.onetimeauth.Poly1305` (Zig
   std, MIT) reused verbatim, not reimplemented.

`std.crypto.aead.chacha_poly.ChaCha20Poly1305` and
`std.crypto.stream.chacha.ChaCha20IETF` (both Zig std, MIT) are ALSO used as
byte-exact black-box correctness oracles (differential tests), not as design
references — the black-box-oracle relationship root `NOTICE` §0 describes. The
RFC 8439 §2.3.2/§2.4.2/§2.5.2/§2.8.2 test vectors are public IETF spec
artifacts (a test oracle under §0, needing no attribution).