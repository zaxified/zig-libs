# ebpf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — `possibleCpuCount()` and `countCpuList()` are added (`perfbuf.zig`, re-exported from the module root). They report `/sys/devices/system/cpu/possible`, which is the number the kernel sizes **every per-CPU map's syscall transfer** by (`round_up(value_size, 8) * num_possible_cpus()`). ⛔ Deliberately distinct from the existing `onlineCpus`: a caller that sizes a per-CPU buffer from *online* CPUs — or from `std.Thread.getCpuCount()`, which is also online — under-allocates by the difference and the kernel writes past the end. Measured under QEMU on 2026-09-09 against `xdp-classifier`, whose 4-byte buffer took 8 bytes at 1 vCPU and 32 at 4. `countCpuList` is allocation-free because the callers that need it are sizing a buffer and have no allocator to hand; it is tested against `parseCpuList` on both accepted and rejected inputs, so the two cannot drift apart.

- **2026-09-09** — Docs: the seven `src/testdata/*.bpf.c` fixtures had no
  `SPDX-License-Identifier`; added (MIT — they are this repository's own BPF programs). Note
  that these files also set `_license = "GPL"`, which is a value the kernel's BPF verifier
  reads to decide which helpers a program may call, not a copyright notice — see this
  module's README and the root `NOTICE`. `zig build check-catalog` now enforces the SPDX
  header on every shipped source file.
- **2026-09-07** — All five fuzz targets were replaying one fixed input, and the module's most
  dangerous parser had no target at all. `btf.parse`, `btfext.parseExt` and `elfsym.openImage`
  built a synthetic blob and then drew both a truncation length and a byte-flip count with
  `valueRangeAtMost`; a ranged draw reads eight input octets as a little-endian u64 and returns
  the range minimum when fewer remain, so outside `--fuzz` the length was 0 and the flip count 0
  — the one input each ever ran was the empty slice, refused at the magic. `attach`'s
  `parseConfigShift` had the `bytes`-then-ranged-length shape (and cannot fail, so the collapse
  read as 100% healthy). `ringbuf` opened with a ranged draw and every later knob was its minimum
  too: a 64-octet all-zero ring with `producer_pos == consumer_pos == 0`, which walks **zero
  records**, so the bounds assertion the harness is built around was never evaluated. Each target
  now draws bytes first — `smith.slice`, or `testkit.fuzz.Cursor` for the ring's shape — carries a
  corpus, and is pinned by a guard counting work done rather than acceptance. Knobs that were
  drawn after the byte draw and were therefore 0 on every seed now travel in the seed's tail:
  `btf`'s type id (0 is the void pseudo-type, so `byId` returned null and the six accessors the
  harness exists to drive were never called), and `elfsym`'s section index and entry index — the
  latter is the unbounded domain whose own doc comment says being unbounded "is the point", and it
  had never once been unbounded.

- **2026-09-07** — **`object.zig` had no fuzz target**, and `check-fuzz-reach` could not say so:
  that gate judges the draw of the targets that exist, so a parser with no harness is invisible
  to it. `open()` is this module's documented untrusted-input entry point, needs no privilege,
  and is where the 2026-09-05 CRITICAL lived — a symbol's raw `st_size` summed into a bound that
  wrapped, reaching a `@memcpy` of 2^64-8 bytes (an out-of-bounds WRITE in ReleaseFast).
  `elfsym`'s target stops one layer below, at the section table. `fuzzOpenObject` now drives
  `open` over the seven real clang objects this module owns plus hostile variants built by the
  same patches the `hostile:` tests apply, and walks `relocateProgram`, `applyCoreRelos` and
  `fixupDatasecs` on what comes back. Verified by mutation: reverting the range check to its
  pre-fix `r.off + size > data.len` is caught, and so is weakening the instruction-section
  alignment check from `% 8` to `% 4`.

- **2026-09-04** — **Two live tests reported PASS where they meant SKIP**, and
  printed unconditionally while doing it (breaking the "a passing test stays
  silent" rule the driver enforces): the tracepoint legacy-path attach and
  `LINK_GET_FD_BY_ID`, both bare `return;` with the assertions below them
  un-run. Both are `return testkit.skip(...)` now. Latent on a host without
  CAP_BPF, where an earlier guard already skips the whole test. Found by the
  first audit of `testkit`.

- **2026-09-02** — Security audit: `findMember`/`findPath` are now bounded by the
  WORK they do, not only by how deep they recurse (new
  `TypeError.TypeSearchTooWide`, `max_member_visits`). `max_resolve_depth`
  bounded the stack; nothing bounded the breadth, and the search descends once
  per anonymous composite member — so a chain of 30 structs each holding two
  anonymous members of the level below is a 2^30-node tree, walked in full
  whenever the name is absent, which is the ordinary "this kernel does not have
  that field" answer CO-RE depends on. A blob under 4 KB was enough: with the
  bound removed again the new regression test does not finish in 45 seconds.
  No cycle is involved — the depth bound always caught those.

- **2026-09-02** — Security audit: **an attacker-supplied object file could reach a
  `@memcpy` of 2^64-8 bytes**. `splitProgramSection` bounded a symbol's `st_value`
  against the section but never its `st_size`, and wrote the range check as
  `r.off + size > data.len`, which wraps. `st_value = 8` with
  `st_size = 0xFFFF_FFFF_FFFF_FFF8` — a multiple of 8, so the alignment check
  ahead of it passes — sums to zero and was accepted. Measured on a crafted
  object: `integer overflow` panic in Debug and ReleaseSafe; in ReleaseFast,
  which has no overflow check at all, an out-of-bounds **write** (SIGSEGV).
  `open()` is the documented untrusted-input entry point and needs no privilege.
  Re-phrased by subtraction, the discipline `elfsym.entryOffset` already used.
- **2026-09-02** — Security audit: CO-RE field offsets no longer wrap. Four sites
  computed `index * size * 8` on two unbounded wire values — the index parsed
  from a BTF access string, the size the struct's raw `size` word. In
  ReleaseFast that is not a crash but a wrong `bit_offset` patched into a loaded
  BPF program, which is the worse outcome. All four now share one checked
  helper (new `CoreError.FieldOffsetOverflow`) so a fifth caller cannot omit it.

- **2026-08-11** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on libbpf (C)
  — program-builder + load API shape (design reference, not a test anchor).
- **2026-07-15** — New module: eBPF program generation over `std.os.linux.bpf`.
