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
| ChaCha20 keystream | 2165 MB/s | 1402 MB/s | **1.5×** |
| Poly1305 MAC | 3653 MB/s | 1440 MB/s | **2.6×** |
| full AEAD encrypt | 808 MB/s | 460 MB/s | **1.8×** |

Poly1305 is lane-parallel above a size threshold and std's scalar core below it,
so the MAC speedup is size-dependent — and deliberately never a *loss*:

| message | 32 B | 128 B | 256 B | 512 B | 1420 B | 4 KiB | 8 KiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| ours vs std | 1.0× | 0.98× | 1.06× | 1.53× | 2.0× | 2.4× | 2.5× |

**The AEAD's own bottleneck has moved.** With the MAC at 3.6 GB/s the limiter is
now `ChaCha20.xor`, which stages the keystream through a stack buffer and XORs it
byte-wise (1056 MB/s, against 2165 for `stream` writing straight to the output).
Fusing that is the next AEAD-throughput item, not more MAC work.

## Verify

```
zig build test-chachapoly                          # Debug
zig build test-chachapoly -Doptimize=ReleaseFast   # ReleaseFast (UB checks)
```

Tests cover the RFC 8439 §2.3.2 / §2.4.2 / §2.5.2 / §2.8.2 KATs, the eleven
RFC 8439 §A.3 Poly1305 vectors at every lane width, a differential against the
`std` AEAD across block-boundary edge lengths (seal/open/cross-decrypt /
tamper-reject), a `>8`-block counter-increment boundary case, and a
length-by-length Poly1305 differential against `std` for **every** length
0..2048 at L ∈ {1,2,4,8}.

## Provenance

Clean-room from RFC 8439 (a public spec — no NOTICE entry required for the
construction itself). The block-parallel `@Vector` layout and the use of
`std.crypto.onetimeauth.Poly1305` as the Poly1305 serial core are recorded in the
repo `NOTICE`;
`std.crypto.aead.chacha_poly.ChaCha20Poly1305` is used as a black-box correctness
oracle (a test relationship, not a design reference).
