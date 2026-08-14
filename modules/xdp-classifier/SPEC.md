# xdp-classifier — SPEC

See `README.md` for what this module is, its scope, and its API. This file
is the auditor/design view: the tier verdict argument in full, the threat
model, the golden-vector methodology, and what's deliberately out of scope.

## Tier verdict: no Fable core (full argument)

The scaffolding brief for this module explicitly asked for an honest
assessment: does verifier-passing XDP-classifier bytecode generation have a
genuinely irreducible, hardest-tier algorithmic core, or is it mechanical
composition of already-solved patterns? The precedent this module follows is
`ethfrag` (see its own `SPEC.md`'s "Backlog / deferred" section) — a prior
module where the scaffolder correctly concluded no Fable core was needed and
built the whole thing, saving scarce Fable budget. This module reaches the
same conclusion, for a different but analogous reason: **`ethfrag` had no
Fable core because its hard part (RFC 5722 overlap/teardrop rejection) is
protocol/state-machine logic against a well-specified reference, not novel
math. `xdp-classifier` has no Fable core because its hard part (verifier-safe
XDP bytecode) was ALREADY DONE by a prior Fable pass, in the sibling `ebpf`
module — this module only needed to SEQUENCE that already-proven work.**

Concretely, `src/classifier.zig`'s `buildClassifierProgram` needs exactly
three verifier-hard patterns, and all three are pre-existing, proven code
this module reuses rather than re-derives:

1. **`ctx->data`/`ctx->data_end` retyping + bounds-check dominance.**
   `ebpf.programs.zig`'s `xdpFilter` doc comment names this "the single most
   commonly cited 'why won't my XDP program load' verifier subtlety" and
   implements it (golden-tested, CAP_BPF-load-verified). `buildClassifierProgram`
   uses the IDENTICAL instruction shape — `ldx data_end; ldx data; mov r3,r1;
   add r3,<width>; jgt r3,r2,->fail` — just for a wider region (34 bytes
   covering Ethernet+IPv4 instead of `xdpFilter`'s one fixed field) so that
   ONE check still dominates every downstream read (EtherType, IHL, the
   src/dst address bytes). This is the same pattern at a different constant,
   not a new one.
2. **Map-lookup pseudo-fd/initialized-key/null-check-before-deref.**
   `ebpf.kprobeCounter` and `xdpFilter` both implement and golden-test this
   exact sequence (`ld_map_fd1`/`ld_map_fd2`, an `r10`-relative stack key
   written before the call, `jeq r0,0,->fail` before any deref).
   `buildClassifierProgram` uses it TWICE (once for the LPM lookup, once for
   the scratch-map write-back) — literally the same instruction template,
   parameterized by a different map fd and key.
3. **Byte-wise packet-to-stack key copy.** `xdpFilter`'s doc comment
   explains why this is alignment-safe for any key size; `buildClassifierProgram`
   reuses it unchanged for the 4-byte IPv4 address, just at a caller-selected
   offset (26 for src, 30 for dst) instead of `xdpFilter`'s fixed offset.

The one thing genuinely new to this module — the specific bounds-check +
EtherType + IHL parse sequence for Ethernet+IPv4 (not present anywhere in
`ebpf`, since `xdpFilter` reads one arbitrary fixed-offset field and never
parses a real header) — is exactly the part this module's development
process independently verified against a REFERENCE COMPILER rather than
reasoning about it by analogy: see "Golden vectors" below. That cross-check
came back an exact structural match to what was independently derived from
the BPF ISA, which is itself further evidence there was no hidden verifier
subtlety being glossed over — a genuinely novel verifier-hard pattern would
be unlikely to fall out of a straightforward C-to-bytecode compile with no
special handling.

**What would have made this Fable-tier, for contrast** (none of these are
true of this module, but naming them sharpens the verdict): if the LPM key
needed a variable-length prefix computed from packet content (it doesn't —
prefixlen is always the fixed constant 32, see point 4 in
`classifier.buildClassifierProgram`'s doc comment); if IPv4 options required
a dynamic, packet-derived pointer offset into a bounds-checked region (out of
scope for v1, see README "Scope" — this WOULD be a legitimate candidate for
a future Fable-tier pass, since dynamic scalar-range-tracked pointer
arithmetic is a genuinely subtler verifier interaction than anything in this
module); or if the class handle needed to survive a MORE complex control-flow
shape than "one register, two sequential calls" (it doesn't — see point 6 in
the same doc comment for why a plain callee-saved register suffices here,
unlike `ebpf.ringbufEmit`'s whole-CFG reference-release liveness property,
which is a genuinely different and harder class of constraint).

## Threat model / what can go wrong

Same unusual risk shape `ebpf`'s own `SPEC.md` describes: the "adversary" is
the in-kernel eBPF verifier, not a remote peer. This module inherits that
framing without repeating it — see `../ebpf/SPEC.md`'s "Threat model / what
can go wrong" section for the general argument (verifier acceptance
criteria are undocumented-in-one-place, version-monotonically-permissive,
and silent at the Zig-compile level). Two additions specific to this module:

- **Rule-table validation is a SEPARATE, conventional (non-verifier) attack
  surface**: `rules.RuleSet.validate` guards against malformed prefix
  lengths, non-canonical (host-bits-set) prefixes, duplicate entries, and
  table-vs-map-capacity overflow — all before any rule reaches
  `map_update_elem`. None of this affects verifier acceptance (the generated
  bytecode is ruleset-agnostic, see README "Design notes"); it protects
  against a caller loading a self-contradictory or oversized rule table,
  which would otherwise fail late (a kernel `E2BIG`/`EINVAL` from
  `map_update_elem`) or silently misbehave (two rules that differ only in
  don't-care bits look distinct in the Zig-side table but are
  indistinguishable to the trie).
- **The two key encodings (populate-time and runtime) must agree
  byte-for-byte.** `rules.LpmKey.toBytes` (used by `maps.populateRule`) and
  `classifier.buildClassifierProgram`'s in-program key construction (point 4
  of its doc comment) independently produce the same 8-byte layout
  (native-endian `u32` prefixlen + 4 wire-order address bytes) — a
  divergence between the two would silently misclassify every packet rather
  than fail loudly (a `map_lookup_elem` with a wrong-shaped key just returns
  "not found", not an error distinguishable from a genuine ruleset miss).
  `maps.zig`'s CAP_BPF-gated round-trip test (`populateRule` then a real
  kernel `map_lookup_elem`) is the strongest available check that the two
  sides actually agree; the offline golden test in `classifier.zig` fixes
  the runtime side's byte layout as a regression guard between real-kernel
  runs.

## Golden vectors — offline validation methodology

Same two-question split `ebpf/SPEC.md` establishes (a golden-byte test
proves the encoder is deterministic and matches a known-good shape; only a
CAP_BPF/root-gated real load proves current-kernel acceptance) — see that
file for the general methodology. This module's specific provenance:

- **Instructions 0-17** (`ctx` decode, the single bounds check, EtherType +
  IHL checks, the 4-byte key copy) were cross-checked against
  `clang -O2 -target bpf -c` disassembly (`llvm-objdump -d`) of the
  equivalent C fragment — see `src/classifier.zig`'s golden-test provenance
  comment for the exact C and the resulting instruction shapes compared.
  Documented, intentional divergence: this builder keeps clang's own 64-bit
  ALU/JMP opcodes throughout, where `-O2` narrows several of clang's own
  choices to 32-bit sub-register forms — both are verifier-accepted and
  semantically identical here (every compared value originates from a
  zero-extending byte/half-word load), this builder simply stays consistent
  with the 64-bit style `ebpf.programs.zig`'s existing goldens already use.
- **Instructions 18-37** (LPM key/prefixlen construction, both map lookups,
  the class-register handoff, the scratch write, the XDP return) are
  REUSED, instruction-for-instruction, from `ebpf.programs.zig`'s
  `kprobeCounter`/`xdpFilter` goldens (see the tier-verdict argument above)
  — no fresh clang cross-check was needed or attempted for this portion,
  since it isn't new: it's the same already-validated pattern.
- To re-derive or extend the golden vector (e.g. after adding IPv6 support),
  follow `ebpf/SPEC.md`'s clang/`llvm-objdump`/`bpftool prog dump xlated`
  procedure directly — nothing about that methodology is specific to
  `ebpf`'s own three programs.

## CPUMAP steering (`buildCpumapSteerProgram` + `createCpuMap`/`populateCpu`)

The classifier stashes a class handle and returns `XDP_PASS`; the steer
program is the piece that actually **routes** a flow — the last LibreQoS shaper
primitive, `XDP bpf_redirect_map(&cpumap, cpu) → BPF_MAP_TYPE_CPUMAP → per-CPU
tc MQ/HTB tree`. It is the same tier verdict as the classifier — **no Fable
core** — and for the same reason: it reuses this module's own already-proven
`ctx`-decode + single-bounds-check + EtherType/IHL parse + LPM-lookup sequence
verbatim (instructions 0-24 of its golden are byte-identical to
`golden_classifier`'s), and appends a `bpf_redirect_map` (BPF helper id 51,
confirmed against `std.os.linux.BPF.Helper.redirect_map` and the UAPI
`enum bpf_func_id`) tail. The one genuinely new fragment — load the matched
class into the redirect key register and reduce it `% cpu_count` (`BPF_ALU64 |
BPF_MOD | BPF_K`) — is trivial scalar arithmetic, not a verifier-hard pattern.

- **CPU-selection policy — class-reduced, per-subscriber, NOT per-flow.** CPU =
  `class % cpu_count`. Real LibreQoS derives the CPU from a per-subscriber
  prefix lookup, so every packet of a subscriber's prefix lands on ONE CPU's
  HTB tree; a per-flow 5-tuple RSS hash would split a subscriber across CPUs and
  break that invariant. This is the design decision the flow→CPU invariant
  hinges on: **the steer program's `class → CPU` map and `tcplan`'s per-CPU HTB
  tree are two halves of one guarantee** — a subscriber's traffic must be
  shapeable on exactly one CPU's queue, which requires it to be steered to
  exactly one CPU. `cpu_count == 0` is rejected at build (`InvalidCpuCount`) —
  it is also a verifier rejection (`BPF_MOD` by zero), so guarding it early
  turns a load-time failure into a caller-visible build error.
- **`struct bpf_cpumap_val` layout (UAPI `include/uapi/linux/bpf.h`).** 8 bytes:
  `u32 qsize` at offset 0, then a 4-byte union (`int fd` on write / `u32 id` on
  read) at offset 4. `maps.CpumapVal` is an `extern struct` matching that C ABI
  byte-for-byte; its size (8) and field offsets (0, 4) are pinned by a
  non-privileged `smoke` test — the CPUMAP analogue of the classifier's LPM-key
  layout anchor. The kernel accepts a CPUMAP `value_size` of 4 or 8; this module
  always uses 8 so `populateCpu` can carry the optional per-CPU program.
- **Fallback.** Any parse/bounds failure or LPM miss returns `XDP_PASS` (packet
  continues up the stack); a hit returns the `bpf_redirect_map` result. The
  `% cpu_count` reduction keeps the redirect index in range, so a fully
  populated CPUMAP never misses; `redirect_flags` (default 0) may be set to
  `XDP_PASS` on kernels with the redirect-fallback-action feature (≥ 5.15) for a
  defensive fallback on an unpopulated slot — the program never depends on it.

## Verification harness

- **Offline, unprivileged (always runs):** `src/classifier.zig`'s golden
  byte-exact test; structural invariant tests (every packet-derived read
  dominated by the bounds check; both map lookups null-checked before
  deref; exactly one `exit`, last instruction, valid XDP return value; every
  stack store stays within the 8-byte key region; the class register `r6`
  never appears in any role but the three expected ones); an edge-case test
  for a default class `>= 0x8000_0000` (the `@bitCast`-not-`@intCast`
  correctness point, see `classifier.zig` point on the DEFAULT block).
  `src/rules.zig`'s rule-table validation tests (well-formed/invalid-prefix/
  non-canonical/duplicate/over-capacity) plus a seeded hostile sweep across
  `u6`'s full `prefix_len` range (0..63, so 33..63 deliberately
  out-of-spec) crossed with pseudo-random address/class bytes and ruleset
  sizes 0..8 — asserts no panic, any declared error or success is
  acceptable.
- **Privileged, CAP_BPF/root-gated (skips otherwise, matching `ebpf`'s own
  discipline):** `classifier.zig`'s real-load test hands the built program
  to the live in-kernel verifier via `ebpf.load`; `maps.zig`'s tests create
  both real map types, populate a rule, and confirm a REAL
  `bpf_map_lookup_elem` round-trip (both the single-rule and
  whole-`RuleSet` population paths), cross-checked against
  `rules.lookupReference`'s userspace prediction for the same ruleset.
- **CPUMAP steering, offline (always runs):** a byte-exact golden for
  `buildCpumapSteerProgram` (its parse/lookup prefix reused verbatim from the
  classifier golden); structural tests (redirect_map with helper id 51,
  cpumap referenced via a pseudo `ld_map_fd`, key reduced `% cpu_count`, every
  non-hit path falling through to a single trailing `XDP_PASS`); the
  `key_field = .dst` offset check; the `cpu_count == 0` build-error check; and a
  **permanent positive-control test** that corrupts the redirect helper id in a
  copy of a real program and asserts the structural predicate flips to false
  (guarding against a vacuous check). The `CpumapVal` size/offset `smoke` test
  is likewise unprivileged.
- **CPUMAP steering, CAP_BPF/root-gated:** `createCpuMap` + `populateCpu` +
  real `bpf_map_lookup_elem` round-trip of a `CpumapVal`; and a real
  `ebpf.load` of `buildCpumapSteerProgram` against a live CPUMAP fd, asserting
  the in-kernel verifier accepts it (loaded under `"GPL"` to sidestep any
  gpl-only-helper ambiguity for `bpf_redirect_map`). Skips cleanly unprivileged.
- Green in Debug and `-Doptimize=ReleaseFast`.

## Backlog / deliberately out of scope

- **IPv6.** A second bounds-check-and-parse block (EtherType `0x86DD`, a
  40-byte fixed header, a 128-bit LPM key) following this module's existing
  pattern — additive, not a redesign.
- **Variable-length IPv4 options.** Would need a DYNAMIC, packet-derived
  pointer offset (IHL nibble × 4, bounds-checked before use) — genuinely a
  step up in verifier-interaction complexity from anything in this module
  (dynamic scalar-range-tracked pointer arithmetic vs. this module's fixed
  compile-time offsets throughout) and the most plausible future Fable-tier
  candidate if this module is extended, per the tier-verdict section above.
- **CPUMAP steering is now built** (`buildCpumapSteerProgram`, see the CPUMAP
  section above) — the production output path that redirects a matched flow to
  a per-CPU `tc` MQ/HTB tree. Still out of scope: a `bpf_xdp_adjust_meta`-based
  per-packet metadata handoff to a downstream `tc` classifier (a different
  mechanism — passing the class inline in packet metadata rather than steering
  by CPU), and a per-flow (rather than per-subscriber) output keying, which the
  CPU-selection note above argues against for a LibreQoS-style shaper.
- A DROP-on-no-match program variant (README "Scope") — a one-instruction
  change, not built since it's not what LibreQoS-style classify-then-shape
  wants by default.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** Classifier bytecode cross-checked against
clang's own emission (EXTERNAL). The CAP_BPF kernel-load path — `createLpmTrieMap`
+ `populateRule` + a real lookup round-trip, judged by the kernel's own verifier
and map implementation — runs in the privileged VM lane and SKIPS everywhere else.
The rule-compilation and packet-classification layers above it are self-anchored.

**How it got there.** Anchored with: `scripts/test.sh vm xdp-classifier` (real root
in a qemu Debian guest, the same lane the sibling `ebpf` uses). Closed 2026-08-14.
It had been recorded as BLOCKED on `kernel.unprivileged_bpf_disabled=2` making
`bpf()` return EPERM even as mapped-root, and that was wrong twice over: the sysctl
restricts UNPRIVILEGED bpf and the lane runs as real root, and the lane already
existed. ⚠ On any host without it the live test SKIPS, and a Zig skip is a pass —
demonstrated rather than assumed: injecting a forced failure into that test makes
the VM lane report `36 passed; 0 skipped; 1 failed`, while `zig build
test-xdp-classifier` on the host stays green with the same mutation in place. Read
a green host run as "the kernel never judged this".
