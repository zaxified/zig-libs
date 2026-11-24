# `crc64` — specification

## Maturity

**Grade:** *(written by `zig build gen-catalog` — never by hand)*

**Scope:** parity — liblzma 5.8.1 `lzma_crc64` (surveyed 2026-11-21)

**Audit:** review 2026-11-24 · mutation 2026-11-24 (18/24, 6 eq) · src 76944a542effe233

**Hardening:** fuzz none · ct n/a — checksum only, no secret · panic n/a — every length is a valid input; no cast, unwrap or assert on a data path

**Performance:** not measured


**Known defects:** none recorded

**Downstream consumer:** no

## Compared with

Surveyed 2026-11-21 per `SURVEY-PLAYBOOK.md`; the sources of the projects other than liblzma were not read.

| Project | Language | Licence | Stars | Last release / push | What a user notices against this module |
|---|---|---|--:|---|---|
| [XZ Utils / liblzma 5.8.1](https://tukaani.org/xz/) — **reference** | C | 0BSD | 1 688 | 5.8.4 (2026-09-09) | `lzma_crc64(buf, size, crc)` is what `extend` mirrors; its PCLMULQDQ kernel is the one translated here. |
| Go `hash/crc64` | Go | BSD-3-Clause | — | Go stdlib | `crc64.ECMA` is this polynomial; table-driven, no carry-less multiply on amd64 *(inferred)*. |
| Zig `std.hash.crc` `CRC-64/XZ` | Zig | MIT | — | Zig 0.17 | Same value; a bytewise table. |

**Where we are ahead:** of `std`, which is bytewise. **Where we are behind:** no CRC-64 combine, no other polynomials, no arm64 path (→ *What is deliberately not done*).

## What this module is, and what it is not

CRC-64/XZ and nothing else: one-shot (`Crc64.hash`), streaming (`Crc64`) and `extend` from a known prefix
checksum. It is not a general CRC engine; other polynomials are in `std.hash.crc`.

## Wire format / algorithm

CRC-64/XZ: polynomial 0x42F0E1EBA9EA3693, reflected (0xC96C5795D7870F42), initial register all ones, final XOR all
ones; check value 0x995DC9BBDF1939FA for "123456789". `extend(c, b) = ~reg(b, ~c)`.

- **table** — slicing-by-8 (eight 256-entry tables built at compile time), the rest bytewise.
- **pclmul** (x86-64) — liblzma's carry-less multiplication folding: four 128-bit lanes folded 512 bits at a time,
  then lane by lane, then a 128-to-64-bit reduction with Barrett's. Used for the largest multiple of 16 bytes of an
  input of at least 16 bytes; the table finishes the tail. The CPU feature is read once with CPUID unless the build
  target guarantees it.

## Limits and refusals

None: every input length is valid, the functions neither allocate nor fail.

## Anchoring

External: values computed by liblzma (read from the check field of an `.xz` stream made by Python's `lzma`,
recipe `tools/gen_kat.py`), at lengths on both sides of every fold boundary (1, 15, 16, 17, 63, 64, 65, 1000, 65536,
100003), and the catalogue check value. Re-derived: `std` CRC-64/XZ at every length 0..600 and several splits, and
the table path alone against the kernel.

**Anchor grade:** class A · oracle EXTERNAL

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle EXTERNAL** — frozen values captured from liblzma; no live interop program.

## Verification

Run: `scripts/modtest crc64`. A `std.testing.fuzz` harness compares any bytes at any split with `std` (no driver run recorded). The kernel test is skipped where the CPU or the backend has no PCLMULQDQ (the table
path is then the only one). The card's `**Audit:**` line is the current score.

- **Review:** the whole of `src/root.zig` read against liblzma's kernel shape: the dispatch takes the kernel only
  for a multiple of 16 bytes and leaves the tail to the tables; the register is inverted once on entry and once on
  exit; the detection cache is idempotent, so a race between two threads stores the same value. No finding.
- **Mutation:** a whole-module schemata run, built for the baseline `x86_64` CPU so that the run-time detection
  path executes (on a native build it is compiled out). The survivors: five are cost-only (the kernel bypassed or
  the detection re-run, the 8-, 48- and 64-byte thresholds at `>`: the bytes left over take the next path, which
  gives the same value) and one is unobservable here (CPUID bit 0 for bit 1: alive because the test CPU has both
  SSE3 and PCLMULQDQ; it needs a pre-Westmere CPU). The detection test was added for this run: without it a
  detection that always said "no" left every long input on the table path, five times slower, with no failure.

## What is deliberately not done

- **CRC-64 combine** (zlib's `crc32_combine` shape): no consumer; the reference (`lzma_crc64`) has none.
- **arm64 / ARMv8 carry-less path:** liblzma's CRC-64 has a PMULL kernel; this module uses the table there.

## Open

The kernel is checked on x86-64 only.

## Backlog / deferred

None open.
