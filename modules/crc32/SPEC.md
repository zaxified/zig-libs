# `crc32` — specification

## What this module is, and what it is not

CRC-32 (the IEEE/zlib/gzip/PNG one) and nothing else: one-shot, streaming
(`Crc32`, the shape of `std.hash.Crc32`), `extend` from a known prefix
checksum, and `combine` of two checksums without their bytes. It is **not** a
general CRC engine — CRC-32C lives in the sibling `crc32c`, other polynomials
in `std.hash.crc`.

## Algorithm

CRC-32/ISO-HDLC: polynomial 0x04C11DB7, reflected (0xEDB88320), initial
register 0xFFFFFFFF, final XOR 0xFFFFFFFF (ISO 3309, RFC 1952 §8). All
backends compute the register update `reg(bytes, r)` without the
conditioning; `extend(c, b) = ~reg(b, ~c)`.

- **`.table`** — slicing-by-8: eight 256-entry tables, `t[0]` the bytewise
  table and `t[k][i] = (t[k−1][i] >> 8) ⊕ t[0][t[k−1][i] & 0xff]`; eight
  bytes per step, the rest bytewise.
- **`.pclmul`** (x86-64) — carry-less multiplication folding, the reflected
  construction of Intel's white paper (Gopal et al., "Fast CRC Computation
  for Generic Polynomials Using PCLMULQDQ Instruction", 2009), as zlib's and
  Linux's `crc32-pclmul` use it. Below `pclmul_min` (32) bytes the table
  runs instead. Otherwise the register is XORed into the first four bytes,
  and:
  1. four 16-byte lanes are folded forward by 512 bits per 64 bytes;
  2. the four are folded into one by 128 bits each, then the remaining
     whole 16-byte blocks one at a time;
  3. the final block X (whose register is X·x³² mod P) is reduced 128 → 96 →
     64 bits by two more multiplies, and the last 64 bits V = V₁·x³² + V₀
     become the register as `zeros4(V₁) ⊕ V₀`, where `zeros4` is four table
     lookups (the register after four zero bytes);
  4. the last 0…15 bytes go through the table.

  The derivation — bit order, the extra factor of x a reflected carry-less
  product carries, and the two constant forms — is written out above
  `fold_consts` in `src/root.zig`. The six constants are computed at compile
  time from `xPow` (x^n mod P by square-and-multiply) and not written down
  anywhere as literals; a test recomputes each one a multiplication by x at a
  time.
- **`.armv8`** — the `crc32x` instruction, 8 bytes at a time, in the same
  three-stream construction as `crc32c` (three chains over 3 × 8192, then
  3 × 256 bytes, joined by shift tables built from `multModP`), then single
  8-byte steps, and the last 0…7 bytes by `crc32w/h/b`.
- **`combine(a, b, n)`** = `multModP(x^(8n) mod P, a) ⊕ b`, as zlib ≥ 1.2.12.
  `x^(2^k)` is tabled for k < 32 and indexed mod 32, which is valid because
  x^(2^32) ≡ x mod P for this polynomial (tested).

**Dispatch.** If the build target has `pclmul` (x86-64) or `crc` (aarch64),
that backend is fixed at compile time. Otherwise the first call detects it —
CPUID leaf 1 ECX bit 1 (PCLMULQDQ), or `getauxval(AT_HWCAP)` bit 7
`HWCAP_CRC32` on Linux arm64 — and caches it in one atomic byte (a race
stores the same value twice). The exception is the self-hosted x86_64
backend (the Debug default) on a target without `pclmul`: it encodes only
what the target CPU model has, so that build has no PCLMUL path and is the
table (`pclmul_emittable`; LLVM builds keep the run-time path). Zig 0.16 has no per-function target features,
so every hardware instruction is inline assembly. On x86-64 each
`pclmulqdq` is its own asm statement with register operands only: the
self-hosted x86 backend (the Debug default) rejects an SSE memory operand
without a size ("unknown size: '(%r8)'"), so the loads, XORs and loop are
Zig, on SSE2 vectors that baseline x86-64 already has.

## Limits and refusals

None: every length, every alignment (loads are unaligned `readInt`s), and
`combine` for any `u64` length.

## Anchoring

- **External** — the check value of CRC-32/ISO-HDLC in the reveng CRC
  catalogue (`"123456789"` → 0xCBF43926), and eight vectors computed with
  CPython's `zlib.crc32` (zlib 1.3), a foreign implementation, through every
  backend this CPU has. Test `published vectors`.
- **Re-derived** — `std.hash.Crc32`, an independent bytewise implementation,
  over every length 0 … 847 at all 64 alignments (every threshold of the
  folding kernel: < 64, the four-lane loop, the one-lane tail, the 0…15 byte
  table tail), then ±24 bytes around one, three and six 8 KiB blocks at every
  ninth alignment, per available backend; streaming and `extend` split at
  fixed and random points; `combine` at several cuts. The folding constants
  are also recomputed bit by bit, and `zeros4`/the shift tables are held to
  the plain table update over real zero bytes.
- **The hardware paths** run on x86-64 natively (target-guaranteed with the
  default native CPU, and run-time detected in a `-mcpu=baseline` build), and
  on arm64 under `qemu-aarch64 -cpu max` (the `generic` arm64 CPU has no
  `crc`, so that build takes the run-time `HWCAP` path; a `generic+crc` build
  the static one; 2026-09-28). The test fails if an x86-64 or arm64 run never
  took a hardware path.

**Anchor grade:** class B · oracle MIXED

## Speed

See README. The folding kernel reaches ~10× std from 1 KiB up; below
`pclmul_min` its fixed cost (the two reduction multiplies) loses to the
table.

## What is deliberately not done

- **VPCLMULQDQ / AVX-512 folding** (256/512-bit lanes). Needs AVX-512 or
  VAES-class CPUs the known consumers do not have, and VEX/EVEX encodings the
  run-time dispatch would have to gate separately.
- **PMULL folding on arm64.** The three-stream `crc32x` path is simple and
  already at instruction throughput; PMULL would add a second arm64 kernel
  for a gain only on long inputs.
- **VEX-encoded (`vpclmulqdq`) forms on AVX targets.** The legacy-SSE
  encoding runs everywhere the CPUID bit is set; on AVX-capable CPUs the
  compiler's `vzeroupper` at function boundaries keeps it free of
  transition penalties.

## Open

- A caller wanting to force the table path (benchmarks, bit-exact audits)
  uses `hashWith(.table, …)`; there is no global override.

## Backlog / deferred

- ~~**Baseline x86_64 Debug build fails**~~ — **FIXED 2026-09-29** (the
  PCLMUL path exists only where the backend can emit it, see *Dispatch*;
  crc32c's SSE4.2 path and aesgcm's AES-NI kernel had the same defect and the
  same fix). The check half is still open: no gate builds a module for a
  baseline x86_64 target under the self-hosted backend, so the class can come
  back unnoticed. Measured 2026-09-29 over the 13 modules with inline asm: only
  these three failed. Was:
- **Baseline x86_64 Debug build fails (found 2026-09-29 by qap's
  `scripts/check-portable.sh`, `-Dtarget=x86_64-linux`).** The PCLMUL path is
  chosen at run time (`cpuidPclmul`), so `pclmulUpdate`'s inline
  `pclmulqdq` is compiled for every x86_64 target; Zig 0.16's self-hosted
  x86_64 backend (Debug) cannot encode it for a CPU model without `pclmul`
  (`error(x86_64_encoder): no encoding found for: none pclmulqdq`). LLVM
  builds are unaffected. Fix: compile the runtime-dispatched PCLMUL path only
  where the backend can emit it (`builtin.zig_backend != .stage2_x86_64`, or
  the target already has `pclmul`), else the table -- and add a Debug
  `-Dtarget=x86_64-linux` build of the module to its checks.
