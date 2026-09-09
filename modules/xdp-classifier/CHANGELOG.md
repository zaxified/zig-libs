# xdp-classifier — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — **BREAKING (buffer overflow fix):** `readScratchClass` handed the kernel a **4-byte stack buffer** for a `BPF_MAP_TYPE_PERCPU_ARRAY` lookup. A per-CPU `bpf(2)` transfer is always `round_up(value_size, 8) * num_possible_cpus()` bytes, and `std.os.linux.BPF.map_lookup_elem` passes only `value.ptr` — the slice length never reaches the kernel, so nothing clamped the write. ⛔⛔ Measured as real root under QEMU: the kernel wrote **8 bytes at 1 vCPU and 32 at 4 vCPU** into those four, and it scales linearly, so an 8-CPU host overflows by 60. It now sizes the buffer from `/sys/devices/system/cpu/possible` (**not** online CPUs and not `std.Thread.getCpuCount()`, which is also online — that difference is exactly what the bug was made of) and returns `error.CpuEnumerationFailed` rather than guessing, or `error.TooManyCpus` above `scratch_max_stack_cpus` (1024). ⚠ Breaking only in its error set; the signature and the returned value (CPU 0's slot) are unchanged. New: `readScratchClassAll` returns **every** CPU's slot — which is what a control-plane poller actually wants, because the generated program writes the slot of the CPU that handled the packet and that is usually not CPU 0 — plus `writeScratchClassAll`, `scratchTransferLen` and the `scratch_percpu_stride` constant. ⛔ The doc comment on the old function asserted the opposite of all of this twice, claiming `map_lookup_elem` "already handles" the sizing and that the helper covered "the common single-CPU-slot case"; there is no single-CPU-slot case on the syscall path, and that comment is why the defect survived review — it is quoted in the new one rather than deleted. The module's own round-trip test carried the SAME defect on the update side (a 4-byte buffer that `map_update_elem` over-READS), and it is one of the root-gated skips, so nothing ever ran it; it now uses `writeScratchClassAll`. A new test covers the sizing arithmetic **without root**, which is the gap that let this through. ⚠ Not done: `BPF_F_CPU`/`BPF_F_ALL_CPUS` are still not passed (`std`'s wrapper does not accept flags); they would let a caller ask for one CPU's slot instead of sizing for all, which is an optimisation, not the fix.

- **2026-09-09** — Docs: the `NOTICE` pointer in ``src/root.zig`` resolved to `modules/NOTICE`,
  a path that has never existed in this repository. Now ``../../../NOTICE``. No code or data
  changed. `zig build check-catalog` gained a check that resolves every relative NOTICE
  link under `modules/**`, so this cannot come back silently.
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Verified: The real anchor is
  the CAP_BPF load-verify test (`classifier.zig:544`) that builds the program with live
  LPM+scratch maps and submits to the kernel verifier.
- **2026-07-15** — New module: XDP packet classifier for a LibreQoS-style edge shaper.
