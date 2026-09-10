# xdp-classifier — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **NO CONSUMER-VISIBLE CHANGE beyond the additions already
  listed below:** `maps.zig` gained four new `pub` items as part of the F5
  work in the entry directly below (`ruleValueBytes`, `scratch_map_type`,
  `scratch_key_bytes`, and `lpmTrieCreateAttr` is `pub`-visible for testing
  but not re-exported from `root.zig`) — additive only, no existing
  signature changed. Split into its own line because it lands in a separate
  commit from the rest of the F4/F5/F6/F7/F9 work; see that entry for detail.
- **2026-09-10** — A1 fix campaign, F4/F5/F6/F7/F9 (audit `~/CML/20260901-zig-libs-audit/A1/xdp-classifier.md`):
  - **F4 (userspace LPM reference disagreed with the kernel trie in two
    documented cases).** `lookupReference`'s tie-break used `>`, so a
    duplicate `(addr, prefix_len)` picked the FIRST-loaded rule; the kernel's
    `map_update_elem` lets the LATER write silently overwrite the earlier
    one. Now `>=`. Separately, `prefixMatches` clamped `prefix_len > 32` to
    an exact `/32` match instead of "no match" — but `RuleSet.validate`
    rejects `prefix_len > 32` outright, so such a rule can never reach the
    kernel map either, and the reference was answering for a rule that (by
    the module's own contract) does not exist. Both are userspace-tooling
    fixes only; the generated eBPF bytecode and the kernel-facing map
    encodings are unchanged.
  - **F5 (mutation-surviving gaps in `maps.zig`'s CAP_BPF-gated tests).**
    Six defect shapes named by the audit (dropped `BPF_F_NO_PREALLOC`,
    `percpu_array`→`array`, `populateRule`'s value byte order, the scratch
    map's key encoding, `prefixMatches`'/`isCanonical`'s bit boundaries) were
    only checked by tests that skip without `CAP_BPF`/root. The map-flags,
    map-type, and value-encoding decisions are now pulled into small pure
    functions (`lpmTrieCreateAttr`, `scratch_map_type`, `ruleValueBytes`,
    `scratch_key_bytes`) with unprivileged pinning tests, plus explicit
    bit-boundary tests for `prefixMatches`/`isCanonical`. Verified by
    mutating each of the six shapes in turn and confirming the new,
    unprivileged test catches it (RED), then reverting (GREEN) — see the
    audit record's disposition for the exact counts.
  - **F6 (stale/overclaiming docs).** `root.zig` claimed "every test...
    passes; nothing is gated behind a stub", true of the stub claim, false of
    the gating (six tests skip without `CAP_BPF`/root). `README.md`'s "Tier
    verdict" undercounted the gated tests as "the CAP_BPF/root-gated real-load
    checks" (two tests) when four more are kernel-map round-trips that never
    call `ebpf.load`. Both corrected.
  - **F7 (privilege gate shut out a documented-valid configuration).**
    `hasBpfCapability()` gated every privileged test on `geteuid() == 0`
    BEFORE attempting any syscall — so a process with `CAP_BPF` but no root
    (the configuration this module's own docs recommend, "CAP_BPF (or root
    pre-5.8)") skipped every one of the six gated tests without ever trying.
    Removed: every call already attempts the real syscall and treats
    `PermissionDenied` as `SkipZigTest`, which is the correct test and was
    already present as the second layer. ⏸ Live confirmation that a
    CAP_BPF-without-root process now actually RUNS these tests needs either
    the `scripts/vm/` lane or a capability grant this worktree does not have
    — deferred, not measured here; the change itself is a pure deletion of a
    redundant, incorrect pre-check, and the existing six-skip/thirty-nine-pass
    baseline is unchanged on this (fully unprivileged) host.
  - **F9 (VLAN-tagged traffic silently unclassified).** Not previously
    documented. README "Scope (v1)" and `SPEC.md`'s backlog now name it
    explicitly, with the measured behavior (802.1Q/802.1ad frames fall to
    the default class in full) and the additive `vlan_depth` extension shape
    that would add support. Documentation only — no behavior change.
  - F2 (CPUMAP size vs. `cpu_count` mismatch) and F3 (`RuleSet.validate` is
    O(n²)) are left OPEN: both need a choice between two legitimate,
    behavior-changing postures (see the audit record) rather than an input
    hardening or documentation call the 0-consumer P1 rule covers on its
    own.
  - `scripts/modtest xdp-classifier`: 39/45 (6 skip), Debug and
    `-Doptimize=ReleaseFast`, both green.

- **2026-09-09** — **BREAKING (buffer overflow fix):** `readScratchClass` handed the kernel a **4-byte stack buffer** for a `BPF_MAP_TYPE_PERCPU_ARRAY` lookup. A per-CPU `bpf(2)` transfer is always `round_up(value_size, 8) * num_possible_cpus()` bytes, and `std.os.linux.BPF.map_lookup_elem` passes only `value.ptr` — the slice length never reaches the kernel, so nothing clamped the write. ⛔⛔ Measured as real root under QEMU: the kernel wrote **8 bytes at 1 vCPU and 32 at 4 vCPU** into those four, and it scales linearly, so an 8-CPU host overflows by 60. It now sizes the buffer from `/sys/devices/system/cpu/possible` (**not** online CPUs and not `std.Thread.getCpuCount()`, which is also online — that difference is exactly what the bug was made of) and returns `error.CpuEnumerationFailed` rather than guessing, or `error.TooManyCpus` above `scratch_max_stack_cpus` (1024). ⚠ Breaking only in its error set; the signature and the returned value (CPU 0's slot) are unchanged. New: `readScratchClassAll` returns **every** CPU's slot — which is what a control-plane poller actually wants, because the generated program writes the slot of the CPU that handled the packet and that is usually not CPU 0 — plus `writeScratchClassAll`, `scratchTransferLen` and the `scratch_percpu_stride` constant. ⛔ The doc comment on the old function asserted the opposite of all of this twice, claiming `map_lookup_elem` "already handles" the sizing and that the helper covered "the common single-CPU-slot case"; there is no single-CPU-slot case on the syscall path, and that comment is why the defect survived review — it is quoted in the new one rather than deleted. The module's own round-trip test carried the SAME defect on the update side (a 4-byte buffer that `map_update_elem` over-READS), and it is one of the root-gated skips, so nothing ever ran it; it now uses `writeScratchClassAll`. A new test covers the sizing arithmetic **without root**, which is the gap that let this through. ⚠ Not done: `BPF_F_CPU`/`BPF_F_ALL_CPUS` are still not passed (`std`'s wrapper does not accept flags); they would let a caller ask for one CPU's slot instead of sizing for all, which is an optimisation, not the fix.

- **2026-09-09** — Docs: the `NOTICE` pointer in ``src/root.zig`` resolved to `modules/NOTICE`,
  a path that has never existed in this repository. Now ``../../../NOTICE``. No code or data
  changed. `zig build check-catalog` gained a check that resolves every relative NOTICE
  link under `modules/**`, so this cannot come back silently.
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Verified on a `CAP_BPF`/root
  host by `classifier.zig`'s `load: buildClassifierProgram passes the in-kernel verifier`
  test, which builds the program with live LPM+scratch maps and submits it to the kernel
  verifier. ⚠ F6 (2026-09-10): this entry used to say "Verified: The real anchor is..."
  and cite a line number (`classifier.zig:544`) that had already drifted stale and named
  a test that SKIPS on every unprivileged host — including CI. Read "verified" here as
  "verified on a host that had the capability", not as a claim about what any ordinary
  `zig build test-xdp-classifier` run demonstrates.
- **2026-07-15** — New module: XDP packet classifier for a LibreQoS-style edge shaper.
