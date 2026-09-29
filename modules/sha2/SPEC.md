# `sha2` — specification

Purpose and usage: [README](README.md).

## What this module is, and what it is not

SHA-224, SHA-256, SHA-384 and SHA-512 with the public declarations of
`std.crypto.hash.sha2`'s types of the same names, and a faster compression
function on x86-64 without SHA-NI. It is **not**:

- a home for std's other SHA-2 variants — `Sha256T192`, `Sha512T224`,
  `Sha512T256`, `Sha512_224`, `Sha512_256` are not provided (deferred, see
  *Backlog*; each is a one-line instantiation if a consumer asks);
- an HMAC or HKDF: std's generic `Hmac(H)` and `Hkdf(Hmac)` instantiate over
  these types unchanged (tested), so there is nothing to add;
- a multi-message (multi-buffer) hasher: every speed-up here is within one
  message.

## Algorithm

FIPS 180-4 §6.2 (SHA-256), §6.4 (SHA-512), §6.3/§6.5 (the truncated
SHA-224/SHA-384 with their own initial values, §5.3.2/§5.3.4), padding §5.1.

- **Constants.** `K` (§4.2.2, §4.2.3) and the initial values (§5.3) are
  computed at compile time from their definitions: the first 32/64 bits of
  the fractional part of the cube (`K`) or square (initial values) root of the
  first primes, as the exact integer root of `p · 2^(r·w)` (`fracRoot`).
  SHA-224's initial values are the low halves of SHA-384's (§5.3.2 lists
  exactly those numbers). A test pins the first and last entries of each
  table to the standard's printed values and checks that SHA-256's `K` are the
  high halves of SHA-512's.
- **Rounds.** Straight from §6.2.2 step 3 / §6.4.2 step 3, fully unrolled,
  with the eight working variables renamed per round rather than moved
  (`round`). Two rewrites, both identities over bits: `Maj(a,b,c) =
  ((a ^ b) & (b ^ c)) ^ b`, carrying `b ^ c` as the previous round's `a ^ b`;
  `Ch(e,f,g) = (e & f) ^ (~e & g)`, which LLVM lowers to `and`/`andn`/`or`.
  With BMI2 the rotations are `rorx`. `T1` is summed as `((h + W_t+K_t) + Ch)
  + Σ1`, putting the value that depends on `e` last.
- **Schedule, scalar.** §6.2.2 step 1 in a 16-word ring, computed inline
  between rounds (`compressScalar`).
- **Schedule, SIMD** (`scheduleSimd`). For `n` = 2 … `lanes` consecutive
  whole blocks (`lanes` = 8 for 32-bit words, 4 for 64-bit: one 256-bit
  vector), load each block's 16 words as `16 / lanes` row vectors, byte-swap,
  and transpose each `lanes × lanes` tile (log2(lanes) stages of block swaps,
  `@shuffle`) so vector `W[t]` holds word `t` of every block, one block per
  lane. Run the recurrence `W_t = σ1(W_{t−2}) + W_{t−7} + σ0(W_{t−15}) +
  W_{t−16}` on those vectors, add `K_t`, and store the `rounds × lanes` table;
  lanes past `n` duplicate the last block and are never read. Then each block
  runs the scalar rounds reading its column (`roundsFromTable`), in order,
  chaining the state. This is legal because the schedule is a function of the
  block alone. Intel's whitepaper vectorizes four words of ONE block per
  vector and needs a two-step fix-up for `σ1`'s distance-2 dependency; lane
  per block has no such dependency and serves both word sizes with one
  generic body.
- **Padding and length** (`final`): `0x80`, zeros, then the bit count as a
  64-bit (SHA-224/256) or 128-bit (SHA-384/512) big-endian integer. The byte
  counter has the counter's width, as in std; bits shifted out of `total_len
  << 3` are dropped, which only matters past the standard's own message-size
  bound.

## Dispatch

Compile time only, per word size (`Engine(Word).default_backend`):

1. **`.stdlib`** — 32-bit words, and std has SHA hardware for the target:
   x86-64 with SHA-NI **and** AVX2 (std's own condition), or arm64 with
   `sha2`; not under the C backend (std's condition too). Whole blocks are
   handed to a `std.crypto.hash.sha2.Sha256` whose public `s` field is set to
   our state and read back — std's `update` over whole blocks with an empty
   buffer is exactly its compression. std's SHA-512 has no hardware path on
   any target, so 64-bit words never take this.
2. **`.simd`** — x86-64 with AVX2, **and** the LLVM backend. The self-hosted
   backends are excluded because they are for the edit loop only (every gate
   builds with LLVM) and were not asked to lower 256-bit shuffles; a Debug
   build with `-fno-llvm` therefore takes `.scalar`, never a compile error.
   There is no inline assembly anywhere in the module, so the crc32 class of
   defect (asm the backend cannot encode) does not arise.
3. **`.scalar`** — everything else, including evaluation at compile time
   (`@inComptime()`).

Within `.simd`, a run of ≥ 2 whole blocks goes through the SIMD schedule in
batches of up to `lanes`; a remaining single block, and every block `final`
compresses, go through `compressScalar` (a full-width schedule for one block
costs more instructions than the scalar schedule).

There is **no run-time CPU detection**: a build for baseline x86-64 on an AVX2
machine runs `.scalar`. Zig 0.16 has no per-function target features, so a
run-time-selected AVX2 path would need hand-written inline assembly for the
whole schedule; see *Backlog*.

**Test-only switch.** `test_hooks.forced` exists only when `builtin.is_test`
(outside tests `test_hooks` is an empty struct), and overrides the backend so
one test run holds `.stdlib`, `.simd` (where compiled) and `.scalar` to the
same vectors and to std. It is a module-level variable, read only in test
builds; no production path can see it.

## Constant-time contract

SHA-2 itself has no secret-dependent control flow or memory access, and this
implementation adds none: no table indexed by data, no branch on data, the
batch size and the scalar/SIMD choice depend only on the **length** of the
input. Lengths are public in every protocol this is used in (TLS records,
HMAC key/message sizes). That is the whole claim; it rests on reading the
code, not on a ctgrind harness. When the input is secret (HMAC keys, HKDF
PRKs, TLS transcript secrets), the working state is Z3 storage in
`CONVENTIONS.md` §2.1's sense — the transform's internal state, not wiped,
exactly as std does not wipe it; the SIMD schedule table on the stack is the
same class.

## Limits and refusals

None beyond FIPS 180-4's: any length, any split of `update` calls, any
alignment (loads are unaligned; `@ptrCast` to `*align(1)` vectors).
`buf_len` is a `u8`, which holds both block sizes.

## Anchoring

- **External.** The FIPS 180-4 / NIST example messages (empty, `"abc"`, the
  448-bit and 896-bit strings) and one million `'a'` for all four digests;
  RFC 4231 test cases 1, 2, 6 and 7 for HMAC-SHA-256/384/512 through std's
  `Hmac`; RFC 5869 A.1–A.3 (PRK and OKM) for HKDF-SHA-256 through std's
  `Hkdf`. Every vector was cross-checked against CPython's `hashlib`/`hmac`
  (OpenSSL) when written, 2026-09-29. HKDF-SHA-384 has no RFC vectors; its
  expected PRK/OKM for A.1's inputs were computed with CPython's `hmac` — a
  foreign implementation — and the test also compares against std's
  HKDF-SHA-384.
- **Re-derived.** `std.crypto.hash.sha2`, an independent implementation, for
  every backend: every length 0 … 1024 one-shot and split at a block edge; 24
  lengths up to 64 KiB each fed in random pieces biased to block edges (±1,
  whole multiples); every SIMD batch size 1 … 2·lanes+1 behind every prefix
  length 0 … block−1; byte-at-a-time with `peek` after each byte; one million
  `'a'` in uneven pieces; and a `testing.fuzz` harness (arbitrary bytes, an
  arbitrary cut, all digests, all backends).
- **Dispatch.** A test fails if an x86-64 AVX2 LLVM build without SHA-NI does
  not report `.simd`, so a regression that silently fell back to scalar is red
  rather than merely slower.
- **Not exercised on real hardware here:** `.stdlib` as the *default* (no
  SHA-NI on the development CPU; the delegation itself is tested by forcing
  it, where std runs its scalar code) and the arm64 build.

**Anchor grade:** class B · oracle MIXED

## Speed

Table and machine in the README. Instruction counts from the ReleaseFast
build (2026-09-29): one round is 24 instructions (6 `rorx`, no spills); the
scalar schedule adds ~13 per word; the SIMD schedule costs ~1 670 vector
instructions per batch, i.e. ~5 per round per block at full width. The model
"instructions per block / 4 per cycle" predicts the measured ratios (1.29–1.33
for SHA-384 over long inputs, 1.24 at 1 KiB where one of nine blocks is the
lone padding block), which is why lone blocks are left scalar: an in-block
vector schedule would save about one instruction per word.

## What is deliberately not done

- **SHA-NI kernel of our own** — not now: std already uses SHA-NI when the
  target has it, and this module defers to std there (`.stdlib`). A kernel of
  our own could only be tested on a CPU this project does not have.
- **In-block vector schedule for lone blocks** (Intel's single-buffer form) —
  not now: measured model above says ≈ 3 % for a single block on this CPU.
- **AVX-512 (`vprorq`, 16/8 lanes)** — not now: no consumer CPU with it.

## Open

- The speed-up for qap's TLS handshake is smaller than the bulk numbers:
  transcript updates and HMAC/HKDF calls are mostly lone blocks, which run at
  std speed. Measure there before claiming a handshake gain.

## Backlog / deferred

- **Run-time AVX2 dispatch for baseline-x86-64 builds.** Needs the schedule
  in inline assembly (Zig 0.16 has no per-function target features), gated
  like crc32's `pclmul_emittable`. Deferred until a consumer ships a baseline
  build.
- **std's truncated variants** (`Sha256T192`, `Sha512T224`, `Sha512T256`,
  `Sha512_224`, `Sha512_256`) — instantiations of the same engine; add on
  request (the non-byte-multiple digest of `Sha512T*` needs the partial-word
  output std has).
- **SHA-NI** — see above; revisit if std's path regresses or a SHA-NI CI
  runner appears.
