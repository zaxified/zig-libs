# chachapoly — design & threat model (SPEC)

Auditor/design reference. Consumer usage lives in `README.md`; metadata lives in
`src/root.zig`'s `pub const meta`; this file does not restate either.

## What this module is

A performance-specialized ChaCha20 stream cipher + ChaCha20-Poly1305 AEAD,
per **RFC 8439**. It duplicates capability that `std.crypto` already ships
(`std.crypto.stream.chacha`, `std.crypto.aead.chacha_poly`) — a deliberate
exception to the prefer-std rule, justified by throughput.

## Why it exists (the dedup justification)

`std`'s ChaCha is already vectorised, but *within* a single block: the diagonal
layout spreads one 64-byte block across four `@Vector(4·degree, u32)` rows and
rotates the columns with `@shuffle`. Crucially it selects `degree` at comptime
from `builtin.cpu.has(.x86, .avx2)` / `avx512f`. On the default `baseline`
x86-64 target (the target `zig build` uses unless `-Dcpu` is passed) neither is
present, so `std` runs at `degree = 1` — a single 128-bit lane, one block at a
time. That is the ~3.9×-slower-than-OpenSSL path the task measured (std ~478 MB/s
vs OpenSSL AVX2 ~1852 MB/s at 8 KiB). We cannot patch `std`, so we ship our own.

The data-plane case is real: WireGuard authenticates every packet, and
TLS/Noise bulk transfer is AEAD-bound. A 1.3–1.6× win on the AEAD hot path is
worth a specialized duplicate.

## Design — the block-parallel (transpose) layout

Instead of `std`'s within-block diagonal SIMD, this module uses the **transpose**
layout: process `N` consecutive counter blocks at once, holding each of the 16
ChaCha state words in its own `@Vector(N, u32)` whose lane `j` is that word for
block `counter +% j`. Then:

- A quarter-round (`add / xor / rotl` on words `a,b,c,d`) becomes the identical
  op on four vectors — **N-way data-parallel, and with no in-block `@shuffle`**,
  because the parallelism is *across* blocks, not across the 4 columns of one
  block. The column and diagonal rounds are just different `(a,b,c,d)` index
  quadruples over the same 16 vectors.
- After 20 rounds we add the original state (`x[i] +%= s[i]`, the counter add
  landing per-lane via the initial `splat(counter) +% iota`), then **transpose**
  the 16 word-major vectors back to `N` block-major 64-byte little-endian
  outputs.

`N = wide = 8`. A `@Vector(8, u32)` lowers to one 256-bit AVX2 register when the
target enables AVX2 (`-Dcpu=native` or any `x86_64_v3`+ target), and to a pair of
128-bit SSE2 registers on `baseline` — correct either way, faster when AVX2 is
on. The `<8`-block tail (including the final partial block) runs the **same
generic engine instantiated at `N = 1`**, so there is exactly one keystream code
path, just at two widths.

**Counter semantics.** IETF ChaCha20 has a 32-bit block counter; this module
increments it with wrapping (`+%`). `std` *asserts* the stream stays within
`64·(2^32 − counter)` bytes and does not wrap — so the differential tests stay
inside that domain (wrap past 2^32 blocks is out of `std`'s and RFC's defined
range and is not diffed).

## Poly1305 — lane-parallel above a threshold, std's scalar core below it

Lives in `src/poly1305.zig`; that file's doc comment is the primary reference
and is not restated here. The construction around it is unchanged and is exactly
what RFC 8439 §2.8 requires (one-time key = ChaCha20 keystream block at counter
0; MAC over `ad ‖ pad16 ‖ ciphertext ‖ pad16 ‖ le64(ad.len) ‖ le64(ct.len)`;
ciphertext at counter 1).

The shape, in one paragraph: Poly1305 is `H = Σ mᵢ·r^(n−i+1)` in GF(2^130−5), so
`L` blocks can be absorbed per multiply by running one Horner recurrence per lane
with the shared multiplier `r^L` and folding the lanes at the end against
`(r^L, …, r^1)`. That needs a limb layout SIMD can multiply — five 26-bit limbs,
because the widest integer multiply x86 vectors have is `PMULUDQ`'s 32×32→64.
`lanes` is picked at comptime (AVX-512F → 8, AVX2 → 4, otherwise 1).

**It is a hybrid, and that is the load-bearing design decision.** The power table
`r^1..r^L` costs `L−1` field multiplies up front, and the 26-bit layout is
*worse* than std's 2×64 when run one block at a time. A pure-vector version
measured **0.47× std at 64 bytes** — a real regression on the short-packet
traffic (WireGuard keepalives, handshakes) this module exists to serve. So
`Generic(L)` embeds `std.crypto.onetimeauth.Poly1305`, delegates the key, the
leftover buffer, the tail, the final reduction and the tag to it, and intercepts
only runs of ≥ `wide_min_groups` whole lane groups. Below the threshold the
executed code is std's.

The seam reads and writes three of std's public fields — `h` (the
partially-reduced accumulator), `r` (the clamped key half) and `leftover`. That
coupling is deliberate and is pinned by the every-length differential below: if
any of those meanings drifted, the sweep would fail rather than silently forge.

Measured on an i7-7920HQ (AVX2), ReleaseFast: MAC 1.0× at 32 B, 0.98× at 128 B,
1.06× at 256 B, 1.5× at 512 B, 2.0× at 1420 B, 2.5× at 8 KiB; full AEAD 1.8× at
8 KiB. With the MAC at 3.6 GB/s the AEAD's limiter is now `ChaCha20.xor`'s
stack-buffer-plus-bytewise-XOR loop (1.06 GB/s vs 2.17 GB/s for `stream`), not
the MAC.

## Constant-time

ChaCha and Poly1305 are inherently constant-time: only add / xor / rotate /
(Poly1305) multiply / mask, no secret-indexed memory access and no data-dependent
branches. The lane-parallel MAC adds only arithmetic of that same shape; every
branch it introduces is on message length or buffer occupancy, both public, and
the lane count is a comptime constant rather than a runtime dispatch. The `@Vector` ops preserve this (SIMD lanes are data-oblivious). The
byte-serialization transpose indexes vectors by **comptime** lane/word indices
only. Tag verification uses `std.crypto.timing_safe.eql`, and a failed `decrypt`
`secureZero`s the computed tag and `@memset`s the plaintext buffer before
returning `error.AuthenticationFailed` — a caller must not read `m` on error.

This is a *structural* CT argument (no secret-dependent control flow exists in
the source), not a machine-checked-disassembly audit like `montint`/`k256`.

## Verification

- **RFC 8439 KATs**, byte-exact, Debug + ReleaseFast: §2.3.2 (ChaCha20 block /
  keystream at counter 1), §2.4.2 (the "sunscreen" encryption), §2.5.2 (Poly1305
  tag), §2.8.2 (AEAD encrypt: ciphertext + tag).
- **RFC 8439 §A.3 Poly1305 vectors** — all eleven, at every lane width
  L ∈ {1,2,4,8}. These are the ones written to break a wrong implementation:
  r = 0, s = 0, r = 2^130−6, the two "imperfect carry propagation" pairs, and a
  127-byte message that lands mid-lane at every width.
- **Poly1305 differential vs `std` for EVERY length 0..2048**, at every lane
  width, plus a random-key stress, an all-0xff key/message worst case for the
  deferred-carry bound, and every `update` split point (the streaming path the
  AEAD actually drives). The partial-final-block and lane-boundary-straddle
  cases are where parallel Poly1305 implementations break, so they are swept
  exhaustively rather than sampled.
- **Differential vs the `std` oracle** across block-boundary edge lengths
  `{0,1,15,16,17,31,63,64,65,127,128,129,255,256,257,511,512,513,1000,4096}`:
  our `ChaCha20.stream`/`.xor` equal `std`'s byte-for-byte at several counters;
  our AEAD ciphertext **and** tag equal `std`'s, `decrypt(encrypt)` is identity,
  our AEAD opens `std`'s ciphertext and `std` opens ours (cross-decrypt), and
  both tag-tamper and ciphertext-tamper are rejected. `std` is the authority — a
  divergence in any edge length fails the build.
- A `>8`-block (20-block) case exercises two wide passes + a 4-block tail and the
  per-lane counter increment across the boundary, byte-exact vs `std`.

The `std` differential is what makes the SIMD safe: correctness of the transpose
layout + tail handling + counter carry is pinned to `std`'s scalar/diagonal
implementation at every awkward length, so a wrong keystream cannot ship.

## Non-goals / backlog

- **Fusing `ChaCha20.xor`'s keystream generation with the XOR** — now the AEAD's
  actual bottleneck (see the throughput note above), worth more than further MAC
  work.
- **AVX-512 (L = 8) is correctness-tested but perf-unmeasured** — no AVX-512
  hardware here. The selection is comptime, so a host that has it takes the
  8-lane path untested for *speed*; it is not untested for *correctness*.
- **2-lane SSE2 / NEON Poly1305** — deliberately not taken: two 26-bit lanes do
  not beat one 64×64→128 scalar multiply, so those targets stay on std.
- **XChaCha20 / XChaCha20-Poly1305** (24-byte extended nonce, HChaCha20) — not
  needed by current consumers; add if a consumer wants it.
- Machine-checked CT disassembly audit (as done for the asm field modules).
- Consumer rewiring (`signal`/`noise`/`wireguard`/`hpke`/`quic-crypto`/`bolt8`)
  is a separate follow-up, conditional on the S1b userland-WireGuard direction.
