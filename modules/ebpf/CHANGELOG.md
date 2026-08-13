# ebpf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-11** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on libbpf (C)
  — program-builder + load API shape (design reference, not a test anchor).
- **2026-07-15** — New module: eBPF program generation over `std.os.linux.bpf`.
