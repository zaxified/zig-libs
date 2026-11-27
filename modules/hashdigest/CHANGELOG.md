# hashdigest — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-27** — **HARDENING (dead stack, no API change):** `blake3Keyed` and `blake3DeriveKey` ran the BLAKE3 hasher (key-derived chaining values) inline in the frame they burn from, above the burned region. Their bodies are `noinline fn blake3KeyedBody` / `blake3DeriveKeyBody` now, one frame down. Rule `burnframe` of `check-secret-api.py` (CONVENTIONS §2.1.1 D4). Stack probe green with `-Dtest-filter=STACKPROBE` in ReleaseFast, native and CI's `-Dcpu`.
- **2026-11-26** — Fix (secret residue): a keyed `blake2bVar` left the MAC key on the dead stack. std's `Blake2b512.init` builds the padded key block as a local in `blake2bVar`'s own frame, and the deferred burn zeroed only below that frame. The body now runs in a `noinline` function and the burn follows its return (a ReleaseFast stack probe found the key 600 B deep before, nothing after).
- **2026-11-21** — **NO CONSUMER-VISIBLE CHANGE:** a ctgrind harness (`src/ctgrind_harness.zig`, run by `scripts/checks/ctgrind.sh hashdigest`) for `blake3Keyed`, `blake3DeriveKey` and keyed `blake2bVar` (0 secret-dependent branches in-file); no library code changed.
- **2026-11-21** — ADDED `blake2bVar(out, data, params)` with `Blake2bParams` and `Blake2bError`: BLAKE2b with a key (up to 64 bytes), a salt and a personalisation string (up to 16 bytes, zero-padded) and any output size 1..64 bytes, on std's engine, checked against OpenSSL's BLAKE2b; tests: all 35 input lengths of the official BLAKE3 vectors and XOF prefix agreement, the stack-burn probe on aarch64, arm, mips, mipsel, riscv64 and x86-32 under qemu-user.

- **2026-11-19** — Additive: bounded file hashing. `hashFileMax`, `hashFileInMax`, `sha256FileMax` take an optional `max_bytes` and return `error.FileTooLarge` past it; `checksum.Options.max_file_bytes` adds `Status.too_large` and `Summary.too_large` (a new enum member: an exhaustive `switch` over `Status` needs the arm; `Summary.allOk` counts it). Defaults stay unlimited, existing signatures unchanged.
- **2026-11-02** — **CONSUMER-VISIBLE (additive; the checksum API is new the same day and unreleased):** review round. `verifyEntry`/`verifyAll` take `Options` and refuse absolute and `..` names (`Status.unsafe_name`, `Summary.unsafe_name`) and non-regular files (`unreadable`); `Summary.allOk` needs at least one verified entry; `\r` is an accepted name escape; the BLAKE2b-512 tag is `UnknownTag` (use `b2sum -l 256`). Engines are chosen by target: `sha2` only on x86-64, the vectorised BLAKE2b only with AVX2, std elsewhere (MIPS32 and ARM32 tests pass under qemu). Burn raised to 16 KiB after a stack probe. Tests: official BLAKE3 vectors (hash, keyed, derive), GNU coreutils 9.7 next to uutils 0.10 in `sums.txt`, stack probe, fuzz escape round trip.

- **2026-11-02** — **New production dependency (approved by the coordinator, conditional on 32-bit targets, see the review-round entry above):** SHA-224/256/384/512 and SHA-512/256 now run on the sibling `sha2` module (`deps = sha2`, `meta.deps`), as `Algorithm.Impl`/`Hasher`/`sha256Hex` types. Digests are unchanged (same goldens and KATs). Measured with `zig build bench-hashdigest`: bulk SHA-2 1.32-1.40x Go before, 0.84-0.89x now; whole table ref 0.79-1.00x, fastest 1.10x. SPEC survey, Compared with, Performance, Verification, Backlog and anchor grade rewritten (class A, EXTERNAL).

- **2026-11-02** — **ADDITIVE:** goal-3 grade-2 work. (1) `checksum` namespace: `sha256sum -c` style parse (`Iterator`, `parseLine`, GNU text/binary lines, BSD `ALGO (name) = hex` tags, `\`-escaped names, comments, CRLF) and verify (`verifyEntry`, `verifyAll`, `Summary`), plus `hashFileIn` (`hashFile` relative to a `std.Io.Dir`). (2) `xof` (SHAKE128/256, BLAKE3, any output length), `blake3Keyed`, `blake3DeriveKey`. (3) `blake2b256` now runs on a row-vectorised in-module BLAKE2b-256 (`src/blake2b.zig`), byte-identical to std's. Tests: cross-implementation goldens from Python hashlib and GNU coreutils (`tools/gen_golden.py`), deterministic fuzz driver for the parser (`HASHDIGEST_FUZZ`), sweep HD-3.

- **2026-10-30** — **CONSUMER-VISIBLE (fixes only):** no-panic sweep + blind review (§ GS). `Hasher.finalHex`/`MultiHasher.finalHex` finalise a zeroed-after-use copy of the state, so `update` may continue and `finalHex` may repeat (SHA-3 panicked in std on update-after-final, SHA-2 silently gave a wrong digest). Docs: `sha256File`/`hashFile` have no size or time limit (a FIFO or /dev/zero never ends) and use 128 KiB of stack; `matches`/`matchesAlgo` are not constant-time. Tests: `src/sweep_test.zig`.
- **2026-10-10** — tools: comparative benchmark `tools/bench.zig` + `tools/go_bench/` + `tools/c_bench/foreign_bench.c` (`zig build bench-hashdigest`) against Go 1.26.0 (reference) and OpenSSL 3.5.5 / libsodium 1.0.18; card Performance filled (0.84–1.40×, fastest 1.60× OpenSSL), SPEC "Performance" section and the lever in the backlog.
- **2026-10-04** — **Tests:** mutation run (11 schemata mutants, 9 killed, 2 equivalent; one new
  test pins the `ShortBuffer` edge of `hex` and `MultiHasher.finalHex`). No code change.

- **2026-07-18** — Security audit: no findings. Modeled on OpenSSL / BLAKE3-C (design
  reference, not a test anchor).
- **2026-07-07** — New module: Streaming digests — one-shot / incremental / file
  (EOF-read, size-0 `/proc` safe); SHA-256 convenience + a multi-algorithm layer
  (SHA-2/SHA-3/BLAKE2b/BLAKE3).
