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

ChaCha20 keystream + full AEAD-encrypt throughput vs `std.crypto`:

| target | size | keystream (ours / std) | AEAD (ours / std) |
|---|---:|---:|---:|
| AVX2 (`-mcpu=native`) | 8 KiB | 2374 / 1486 MB/s — **1.6×** | 662 / 507 MB/s — **1.3×** |
| baseline (SSE2) | 8 KiB | 1113 / 673 MB/s — **1.65×** | 489 / 364 MB/s — **1.34×** |

The keystream (**2374 MB/s** on AVX2) exceeds the cited OpenSSL AVX2 ChaCha
number (1852 MB/s). The full-AEAD speedup is smaller (**~1.3×**) because Poly1305
is scalar (`std.crypto.onetimeauth.Poly1305`, reused verbatim) and dominates once
the ChaCha keystream is fast — a SIMD Poly1305 is a documented backlog item.

## Verify

```
zig build test-chachapoly                          # Debug
zig build test-chachapoly -Doptimize=ReleaseFast   # ReleaseFast (UB checks)
```

Tests cover the RFC 8439 §2.3.2 / §2.4.2 / §2.5.2 / §2.8.2 KATs and a differential
against the `std` AEAD across block-boundary edge lengths (seal/open/cross-decrypt
/ tamper-reject), plus a `>8`-block counter-increment boundary case.

## Provenance

Clean-room from RFC 8439 (a public spec — no NOTICE entry required for the
construction itself). The block-parallel `@Vector` layout and the reuse of
`std.crypto.onetimeauth.Poly1305` as the MAC are recorded in the repo `NOTICE`;
`std.crypto.aead.chacha_poly.ChaCha20Poly1305` is used as a black-box correctness
oracle (a test relationship, not a design reference).
