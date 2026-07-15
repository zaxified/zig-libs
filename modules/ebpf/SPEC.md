# ebpf — SPEC

See `README.md` for what this module is, its API, and the std-primitive
inventory. This file is the auditor/design view: why the pieces are shaped
the way they are, what the verifier actually demands, and how to validate
an eventual `programs.zig` implementation offline.

## Threat model / what can go wrong

This module has an unusual risk shape compared to most of this repo's
codecs and clients: the "adversary" is not a remote peer sending malicious
bytes, it's **the in-kernel eBPF verifier itself**, whose acceptance
criteria are:

1. Not fully documented in one place (the closest is
   `Documentation/bpf/verifier.rst` plus the verifier's own source,
   `kernel/bpf/verifier.c` — this module's stub doc comments summarize the
   RELEVANT slice, not the whole model).
2. Version-dependent — the verifier gets strictly more permissive over
   kernel releases (e.g. bounded-loop support, better scalar-range
   tracking) but never less permissive for a given program shape, so a
   program that verifies on an old kernel keeps verifying on a newer one,
   not vice versa. `programs.zig`'s builders should target the MINIMUM
   verifier sophistication reasonably assumable (roughly: no bounded-loop
   reliance, no relying on any post-5.x scalar-range refinement) so the
   resulting programs are portable across the kernel versions this repo's
   other Linux-only modules already assume.
3. Silent at the Zig-compile level — every stub in this module compiles
   fine with a `@panic` body; the FIRST time a mis-designed instruction
   sequence is caught is either `BPF_PROG_LOAD` returning
   `error.UnsafeProgram` (with a verifier log, if `loadWithLog` was used)
   or, worse, a program that loads but misbehaves because the verifier
   didn't need to reject it to make it wrong (see `xdpFilter`'s XDP
   return-value note in `programs.zig` — an unenforced ABI convention, not
   a verifier check).

Secondary, more conventional risk: everything past `programs.zig` runs with
elevated privilege (`CAP_BPF` minimum, `CAP_NET_ADMIN` for XDP/cgroup
attach) — the usual discipline applies (attach/load handles are
caller-owned and explicitly closed, no ambient global state, gated tests
skip rather than silently no-op under insufficient privilege so a
CI/sandbox run can't be mistaken for "verified").

## Golden vectors — offline validation methodology

`programs.zig`'s builders are pure functions (`Insn` slice in, `Insn` slice
out, no I/O) specifically so they can be validated **without a kernel** via
byte-exact comparison against a golden vector, the same "pure means
golden-testable" pattern this repo already uses for wire codecs (see
`genetlink`'s `buildGetFamilyRequest` golden test). The trick specific to
eBPF: the golden vector doesn't come from a spec document (there is no eBPF
"RFC"), it comes from a REFERENCE COMPILER — clang's BPF backend, whose
output the real in-kernel verifier is known to accept for equivalent C.

To obtain a golden vector for one of the three programs once its builder is
implemented:

1. Write the equivalent program in C using the same helper calls the Zig
   builder targets, e.g. for `kprobe-counter`:
   ```c
   SEC("kprobe/do_sys_openat2")
   int counter(struct pt_regs *ctx) {
       __u32 key = 0;
       __u64 *val = bpf_map_lookup_elem(&counter_map, &key);
       if (val) __sync_fetch_and_add(val, 1);
       return 0;
   }
   ```
2. `clang -target bpf -O2 -g -c prog.c -o prog.o` — compiles straight to a
   BPF ELF object; `-O2` matters, `-O0` emits verifier-unfriendly bytecode
   clang itself doesn't recommend for BPF targets.
3. `llvm-objdump -d prog.o` — disassembles the `.text` (or named `SEC()`)
   section. Hand-transcribe each line's opcode/dst/src/off/imm fields into
   an `Insn{ .code = ..., .dst = ..., .src = ..., .off = ..., .imm = ... }`
   literal, cross-referencing `std.os.linux.BPF`'s opcode constants
   (`ADD`/`MOV`/`JEQ`/`CALL`/… — the same names `Insn`'s builder methods use
   internally) to translate the disassembly's mnemonics back to the packed
   field values.
4. **Stronger cross-check**: `bpftool prog load prog.o /sys/fs/bpf/prog &&
   bpftool prog dump xlated pinned /sys/fs/bpf/prog` — this shows the
   VERIFIER'S OWN post-rewrite view of the program (dead-code eliminated,
   some pseudo-instructions expanded), proving the kernel actually accepted
   this exact shape, not just that clang emitted something plausible-looking
   that might still be rejected. Requires `CAP_BPF` to run, same as this
   module's own gated tests.
5. Paste the transcribed instructions into `programs.zig`'s
   `golden_kprobe_counter`/`golden_xdp_filter`/`golden_ringbuf_emit`
   placeholder constants and un-skip the corresponding
   `test "golden: ..."` (remove the `return error.SkipZigTest;` and call the
   now-implemented builder for the comparison — see each test's inline
   comment for the exact replacement body). From then on, `zig build
   test-ebpf` catches any REGRESSION in the encoder's output byte-for-byte,
   without needing `CAP_BPF` in CI — only obtaining the vector the first
   time needs a privileged/kernel environment; verifying it thereafter does
   not.

Note the two validation questions this answers are DIFFERENT and both
matter: the golden-byte test proves the Zig encoder is DETERMINISTIC and
matches what was once confirmed to load; it does NOT by itself prove a
FUTURE kernel still accepts those bytes (verifier behavior can only get more
permissive, per the threat-model section above, so this is a one-directional
risk — a vector golden today stays loadable, never stops being loadable).
Confirming ACTUAL current-kernel acceptance is what the gated,
privilege-checked integration tests in `load.zig`/`ringbuf.zig` are for
(they skip rather than fail without `CAP_BPF`, so they degrade gracefully
in CI/sandboxes but still assert something real wherever they DO run).

## Backlog / deliberately out of scope

- `programs.zig`'s three `TODO(fable/core)` bodies — the actual bytecode
  generation, see difficulty verdict in `README.md`.
- `attach.zig`'s three `TODO(opus)` bodies (kprobe/XDP/cgroup) and
  `ringbuf.zig`'s four `TODO(opus)` bodies (open/close/poll/next+advance).
- Once the above land: a fourth program kind was intentionally NOT added
  to keep this scaffold's surface to exactly what was asked for
  (kprobe-counter / xdp-filter / ringbuf-emit) — see README's "Out of
  scope" list for the categories (tracepoints, uprobes, tc/classifier
  programs, BTF/CO-RE, ELF-skeleton loading) a future pass might extend
  into, each additive rather than a redesign of what's here.
