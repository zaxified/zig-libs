# `aesgcm` — specification

How to use it: [README](README.md).

## What this module is, and what it is not

AES-GCM with AES-128 and AES-256 keys, a 96-bit nonce and a 128-bit tag — the
two TLS 1.2/1.3 AES-GCM suites and std's `crypto.aead.aes_gcm` types, nothing
wider. A stateful `Context` per key, plus std's stateless shape. It is **not**:

- **other nonce or tag lengths** (SP 800-38D allows any IV length via GHASH of
  the IV, and tags down to 32 bits). Refused: std has neither, TLS uses
  neither, and a non-96-bit IV is the construction's weak spot (nonce
  collisions after GHASH).
- **AES-192.** Not now: no TLS suite uses it; std's `aes_gcm` has no type for
  it either.
- **a streaming (incremental) AEAD.** Refused: GCM's decrypt must not release
  plaintext before the tag is checked, so a streaming decrypt is an unsafe API
  shape; records are the unit here.
- **AES-GCM-SIV, CCM, a raw GHASH export.** Different constructions or a
  primitive std already exports (`crypto.onetimeauth.Ghash`).

## Algorithm

NIST SP 800-38D with a 96-bit IV: `H = E(K, 0¹²⁸)`, `J0 = IV ‖ 0³¹1`,
`C = GCTR(K, inc32(J0), P)`, `S = GHASH_H(A ‖ 0^v ‖ C ‖ 0^u ‖ [len(A)]64 ‖ [len(C)]64)`,
`T = E(K, J0) ⊕ S` (§7.1). Decryption computes `S` over the received `C` and
compares tags before returning success (§7.2).

**`.aesni` (x86-64 AES-NI + PCLMULQDQ + SSSE3).**

- *Key schedule*: FIPS-197 §5.2, with SubWord done by `aesenclast` on a state
  whose four columns are all RotWord(w₃) (or w₃ for AES-256's odd steps):
  ShiftRows leaves such a state unchanged, so the instruction yields
  SubWord(RotWord(w₃)) ⊕ rcon in every column. The running XOR of the previous
  round key's words is two shifts and two XORs.
- *GHASH representation* (Gueron–Kounavis, "Intel Carry-Less Multiplication
  Instruction and its Usage for Computing the GCM Mode", rev. 2.02; the same
  one std's `ghash_polyval` uses): each block is byte-reversed (`pshufb`) into
  a 128-bit integer. The carry-less product of two such values is the
  reflected product shifted by one bit; instead of shifting products, H is
  stored as H·x (shifted with the conditional reduction `0xC2…01`), and so is
  each power, because `f(u,v) = reduce(u·v)` maps `(X, H·x)` to `X·H` and
  `(Hᵃ·x, Hᵇ·x)` to `Hᵃ⁺ᵇ·x`. Products are schoolbook (four `pclmulqdq`), the
  256-bit result reduced by two multiplications with `0xC2 << 56` (the paper's
  two-phase reduction).
- *Aggregated reduction*: eight blocks `X₀…X₇` are folded as
  `(acc ⊕ X₀)·H⁸ ⊕ X₁·H⁷ ⊕ … ⊕ X₇·H` with a single reduction; a group of
  `n < 8` blocks uses `Hⁿ…H`. The context stores `H…H⁸`.
- *Counters*: kept byte-reversed, so the 32-bit big-endian counter is the low
  dword and `paddd` is inc32 exactly (mod 2³², upper 96 bits untouched); one
  `pshufb` turns it into the block to encrypt.
- *Stitching*: the main step runs eight counter blocks through the AES rounds
  and, between rounds 1…8, multiplies one of eight ciphertext blocks into the
  GHASH accumulator. Encryption hashes the batch *behind* (its ciphertext
  exists only after its own AES); the first batch is AES-only and the last is
  hashed on its own. Decryption hashes the batch *ahead* — never the one being
  decrypted, which let the compiler merge the two loads of each block and
  spill across the rounds (measured: half the speed), and never the one behind,
  which is already plaintext when `m` is `c`.
- *Tail*: fewer than 128 remaining bytes are copied into a zeroed 128-byte
  buffer, CTR'd block by block, and the ciphertext (padding re-zeroed) is
  hashed together with the length block as one group when they fit in eight
  blocks (else two). A **short** message — `⌈|A|/16⌉ + ⌈|C|/16⌉ < 8`, e.g. a
  TLS 1.3 record up to 96 bytes — puts its AD in front of them in the same
  buffer, so the whole GHASH is one aggregated group and one reduction instead
  of three serial ones.
- *Assembly*: one instruction per `asm` statement, register operands only (the
  self-hosted Debug backend cannot size SSE memory operands); VEX encodings
  when the build target has AVX, legacy SSE otherwise. The compiler schedules
  and allocates registers.

**`.generic`**: std's `crypto.core.aes` context (kept), `crypto.core.modes.ctr`
and `crypto.onetimeauth.Ghash.initForBlockCount` per message from the kept H —
std's `aes_gcm` code path minus the key expansion and the `E(K, 0)`.

**Dispatch**: `.aesni` is fixed at compile time when the target has `aes`,
`pclmul` and `ssse3`; otherwise the first call reads CPUID leaf 1 ECX (AES bit
25, PCLMULQDQ bit 1, SSSE3 bit 9) and caches the answer in an atomic byte
(idempotent, so a race stores the same value). Not x86-64, or the C backend
(which cannot pass vectors to inline assembly): `.generic`. arm64 is not
detected at run time: std's primitives there are hardware exactly when the
build target has `aes`, as for std itself.

**Stateless functions** build a context on the stack for the call — on
`.aesni` with only the GHASH powers the lengths need (`powersFor`: the largest
aggregated group, ≤ 8) — and wipe it. `.generic` stateless calls std directly.

**In-place**: the output may equal the input, or start before it in the same
buffer (`out.ptr < in.ptr`, a forward shift — `tls.zig`'s client decrypts a
record over its own header this way), in both directions and on both
backends; test `the output may start before the input` pins shifts of 1, 5, 16
and 17 bytes across every path. It holds because every step reads the input
blocks it needs before it writes output at or below them: a batch loads block
j of the input only after storing block j − 1 of the output, the decrypt
read-ahead touches only input beyond the batch being written, and the tail is
copied into a local buffer first. An output starting after the input and
overlapping it is not supported (nor is it by std's `modes.ctr`).

## Constant-time contract

Secret: the key, everything derived from it (round keys, H and its powers, the
keystream, `E(K, J0)`), the plaintext. Public: lengths, nonce, AD, ciphertext,
tag, and whether the tag verified.

- `.aesni`: every operation on secrets is an AES-NI, PCLMULQDQ, SSE integer or
  vector-shuffle instruction; there are no tables, no secret-dependent branches
  or addresses. The only branches are on lengths and the counter of loop
  iterations. The key schedule uses `aesenclast` for SubWord (no S-box table),
  the H·x shift uses a mask (`0 -% (h >> 127)`), not a branch.
- Tag comparison: `std.crypto.timing_safe.eql`. On failure the output buffer is
  zeroed in full (a `.aesni` decrypt has already written plaintext into it) —
  the time that takes depends on the length only.
- `.generic` inherits std's properties: hardware AES/GHASH where std has them
  (x86-64 with `aes`+`avx` in the target, arm64 with `aes`); on other targets
  std's software AES and GHASH, whose side-channel posture is std's.

This rests on reading the code and the generated assembly
(`zig build-obj -femit-asm`, ReleaseFast, 2026-09-28: the stitched loop is
`vaesenc`/`vpclmulqdq`/`vpshufb`/`vpxor` and loads/stores with no branch
inside); there is no ctgrind harness yet (see *Open*).

**Wiping** (`CONVENTIONS.md` §2.1): a `Context` is Z2 — the caller's, wiped by
`wipe()`, which zeroes every byte of it. The stateless path's stack context
and every tail buffer holding plaintext or keystream are Z1 and are wiped with
volatile 16-byte stores (`wipeBlocks`; a bytewise `secureZero` of the 128-byte
tail buffer cost more than a 64-byte message). Test `wipe zeroes the whole
context` checks `wipe()` with a non-vacuity precondition; stack wipes are by
review, as §2.1 says they must be.

## Limits and refusals

- `m.len ≤ 16·(2³² − 2)` bytes (SP 800-38D §5.2.1.1 with a 96-bit IV: the
  32-bit counter starts at 2): asserted, as std asserts it. Consequently the
  counter never wraps through the API; the kernel's wrap behaviour (inc32,
  mod 2³²) is still tested directly (below).
- `c.len == m.len`: asserted.
- AD length: unbounded in practice (the length block is 64-bit bits).
- `Context`: ≤ 320 bytes (AES-128) / ≤ 384 bytes (AES-256) — pinned by test
  `backend picks AES-NI when the CPU has it`, because a TLS server holds two per
  connection.

## Anchoring

- **External** — McGrew–Viega GCM test cases 1–4 (AES-128) and 13–16
  (AES-256): empty P and A, one zero block, 64-byte P, 60-byte P with 20-byte
  A, 96-bit IV (test `McGrew–Viega …`). These reach only the tail path, so a
  second set comes from **OpenSSL 3.5.5** through Python `cryptography`:
  17 lengths × both key sizes from 0 to 19 999 bytes with AD 0…1000, covering
  tail only, one batch plus the delayed GHASH, and the stitched loop with and
  without a partial block (test `long messages agree with OpenSSL`). Recipe:
  `tools/openssl_kat.py`, output `src/testdata/openssl_kat.zig` (tag and
  SHA-256 of the ciphertext; inputs are regenerated from a formula).
- **Re-derived** — std's `aes_gcm` (independent code: two-pass, 128-bit
  counter, its own GHASH): every length 0…300 with AD 0…64 and 1 500 random
  cases up to 20 000 bytes with AD up to 128, half near batch boundaries, both
  key sizes, stateless and every backend, out-of-place and in-place, decrypt
  both ways. The x86 key expansion against std's AES block cipher and the x86
  GHASH (1…20 blocks) against std's `Ghash`, 50 random keys each. The counter
  wrap against a CTR built on std's AES from counters `2³² − 16 … 2³² − 1`
  through the batch and tail paths.
- **Rejection** — every single-bit change of tag, ciphertext and AD refused,
  with the output zeroed, for message lengths 0, 1, 17, 130 and 300, per
  backend (and the stateless path at a stride); a wrong nonce refused.
- **Mutation** (2026-09-28, schemata over a copy, one ReleaseSafe build): 31
  mutants — reduction constant and second phase, a dropped middle product, the
  counter lane, a wrong H power in the batch, the delayed and the read-ahead
  GHASH, the tail padding, swapped lengths, the tag check bypassed, no wipe on
  failure (both backends), the H·x carry, rcon and the AES-256 odd step, the
  stateless power count (short and long), H⁵ and H⁸, the tail counter, the
  batch counter advance, where `acc` enters a batch, the AD partial block,
  J0's counter, the CPUID mask, the length block's byte order and its loss,
  the short path's AD offset, hashing plaintext in the decrypt tail — all
  killed. (Moving the short/long threshold or the fold-in-the-length-block
  threshold is equivalent — the longer path is also correct — and was not
  counted.)
- Run natively in ReleaseSafe, ReleaseFast and Debug (self-hosted backend), in
  ReleaseSafe with `-Dcpu=x86_64` (run-time CPUID, legacy SSE encodings,
  `pshufb` by assembly) and `-Dcpu=x86_64_v2` (run-time CPUID, compiler
  `pshufb`), and on aarch64 under `qemu-aarch64` with the generic CPU and with
  `+aes` (the generic backend, x86-only tests skipped).

**Anchor grade:** class B · oracle MIXED

## What is deliberately not done

- **VAES / VPCLMULQDQ (256/512-bit) and AVX-512 kernels.** Not now: the
  development machine (Kaby Lake) has neither, so such a kernel could not be
  measured or even run here; on CPUs with them it would roughly double
  throughput again. The dispatch has room for another backend.
- **An arm64 stitched kernel** (AESE/AESMC + PMULL). Not now: arm64 runs std's
  hardware primitives two-pass, with the key schedule cached; no arm64 hardware
  to measure on, only qemu.
- **A run-time HWCAP check on arm64.** Not now: with no arm64 kernel of our own
  there is nothing to switch to; std's choice is compile-time.
- **Karatsuba multiplication.** Measured reasoning, not taste: on Skylake-class
  cores `pclmulqdq` and the shuffle Karatsuba needs share port 5, so 3 + 1 is
  no cheaper than 4, and schoolbook needs no stored `hi ⊕ lo` per power.
- **The big-endian counter trick** (adding to the top byte while no carry can
  occur, saving the per-block `pshufb`). Not now: AES-128's loop is bound by
  the AES unit (port 0), not by the shuffles (port 5).
- **Translating OpenSSL/BoringSSL perlasm.** Refused (licence policy and
  clarity): the construction is from the published papers above; the code is
  original.

## Open

- A ctgrind harness (`src/ctgrind_harness.zig`) marking key and plaintext
  undefined through one seal/open, to turn the constant-time review above into
  a measurement.
- The x86 path on a CPU without AVX has been exercised only by building for
  `-Dcpu=x86_64` on an AVX machine (the legacy encodings ran; the absence of
  AVX elsewhere in the binary was not tested on real pre-AVX hardware).
