# ebpf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
