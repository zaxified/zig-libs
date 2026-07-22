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

## Attach mechanisms and their lifetime rules

Three hooks are supported. The single thing to get right is that they do
**not** share a lifetime model — two of the three outlive the attaching
process:

| hook | syscall path | detach | survives process exit? |
|---|---|---|---|
| kprobe / kretprobe | `perf_event_open` on the kprobe PMU + `ioctl(PERF_EVENT_IOC_SET_BPF)` + `ioctl(PERF_EVENT_IOC_ENABLE)` | close the perf fd | **no** |
| XDP | netlink `RTM_SETLINK` + nested `IFLA_XDP` | `RTM_SETLINK` with `IFLA_XDP_FD = -1` | **yes** |
| cgroup | `bpf(BPF_PROG_ATTACH)` | `bpf(BPF_PROG_DETACH)` | **yes** |

`Link` is the uniform handle over all three (`Link.detach()` reports
failures, `Link.deinit()` is the `defer`-friendly best-effort form); the
per-hook handles (`KprobeHandle`/`XdpHandle`/`CgroupHandle`) expose the same
two methods and are idempotent. Every fd a handle does not itself create
(`prog_fd`, a cgroup directory fd) is **borrowed**, matching `load.zig`'s
rule that the caller closes what the caller created — the borrowed fds must
outlive the handle, because `detach()` names them.

Consequences worth stating explicitly:

- Dropping a `KprobeHandle` without detaching leaks a file descriptor and
  nothing else: the kernel tears the dynamic probe and the BPF attachment
  down when the last reference to the perf fd goes away, including at
  process exit.
- Dropping an `XdpHandle` or `CgroupHandle` without detaching leaks a **live
  kernel attachment** — a program still filtering packets on a NIC, or still
  running for a cgroup subtree, with no handle left to name it (recovery is
  `ip link set dev X xdp off` / `bpftool cgroup detach`).

### Why netlink and not `BPF_LINK_CREATE` for XDP

Both paths exist on modern kernels. This module takes the netlink
`RTM_SETLINK` + `IFLA_XDP` one because (a) it works on every kernel with XDP
at all, while `BPF_LINK_CREATE`+`BPF_XDP` needs >= 5.7, and (b) it produces
the attachment shape `ip link`/`bpftool net` show, which is what an operator
inspecting a machine expects. The cost is precisely the lifetime asymmetry
above: a `BPF_LINK_CREATE` link would be an fd whose close detaches, whereas
a netlink attachment persists. That tradeoff is the reason `XdpHandle`
carries an explicit `detach()` rather than being a pure RAII wrapper.

The `IFLA_XDP` container is written **without** the `NLA_F_NESTED` type bit,
matching iproute2 and libbpf: `do_setlink` parses it with
`nla_parse_nested_deprecated` (liberal validation), which neither requires
nor rejects the bit — but only the flagless encoding is field-proven across
kernel versions.

### Mode flags are not optional in practice

`XDP_FLAGS_SKB_MODE`/`_DRV_MODE`/`_HW_MODE` are mutually exclusive
(`XdpFlags.validate` rejects more than one; the kernel answers EINVAL).
Passing **none** is legal and means "kernel picks", which silently falls
back from native to generic XDP on a driver without native support — a large
throughput regression that looks exactly like success. `XdpFlags` therefore
makes the mode an explicit choice, and `XDP_FLAGS_UPDATE_IF_NOEXIST` /
`XDP_FLAGS_REPLACE` (with `IFLA_XDP_EXPECTED_FD`) are exposed so an attach
can refuse to clobber another owner's program.

For cgroups, the `BPF_F_ALLOW_OVERRIDE` / `BPF_F_ALLOW_MULTI` distinction is
likewise semantic, not cosmetic: it decides whether a descendant cgroup may
attach a program of the same type and whether it *replaces* or *adds to*
this one. The default (neither flag) is exclusive ownership of the slot.

## Ring-buffer consumer: ABI and barrier discipline

### mmap layout

`BPF_MAP_TYPE_RINGBUF` grants exactly two mappings (kernel
`ringbuf_map_mmap_user`):

- **pgoff 0**, `PROT_READ|PROT_WRITE`, exactly one page: the consumer page.
  Its first 8 bytes are `consumer_pos`. A writable mapping of any other
  offset or length is refused with `EPERM`.
- **pgoff 1**, `PROT_READ`, `page_size + 2 * max_entries` bytes: the
  producer page (first 8 bytes = `producer_pos`) followed by the data area.

The data area is **double-mapped by the kernel itself** — its page array
aliases each data page at both `i` and `i + nr_data_pages` — so a record
that physically wraps the ring's end is still one contiguous byte range.
This module therefore does *not* perform the userspace "reserve `2*len`
`PROT_NONE`, then `MAP_FIXED`-overlay two copies" trick that `io_uring`-style
SPSC rings need; doing so would map the same physical pages a third and
fourth time for no benefit. (This is also what libbpf's `ring_buffer__add`
does: two mmaps, no `MAP_FIXED`.)

### Record framing

Each record has an 8-byte header (`struct bpf_ringbuf_hdr { u32 len; u32
pg_off; }`) followed by the payload, the whole thing rounded up to 8 bytes.
The header's `len` carries two flags in its top bits:

- `BPF_RINGBUF_BUSY_BIT` (1<<31): reserved but not yet submitted. The
  consumer **stops** here — it must not skip ahead, because records commit
  in ring order and everything behind a busy record is equally unreadable.
- `BPF_RINGBUF_DISCARD_BIT` (1<<30): `bpf_ringbuf_discard` was called. The
  space is released immediately and the record is never surfaced to a
  caller (matching `ring_buffer__consume`).

### Barrier discipline

Three atomics, three orderings, each pairing with a specific kernel-side
one. This is the part where a missing barrier is a *real* data race, not a
theoretical one:

1. **`producer_pos`: acquire load** — pairs with the kernel's
   `smp_store_release(&rb->producer_pos, ...)`. Without acquire, the record
   bytes written before the position was published may not be visible on
   this CPU even though the new position is: the consumer reads stale or
   partially-written payloads.
2. **record header `len`: acquire load** — pairs with the kernel's
   `smp_store_release(&hdr->len, new_len)` in `bpf_ringbuf_commit()`, which
   is what clears `BUSY`. Observing a cleared BUSY bit must therefore also
   imply observing the payload; a relaxed load here is the classic "contents
   lag the flag" bug.
3. **`consumer_pos`: release store** — pairs with the kernel's
   `smp_load_acquire(&rb->consumer_pos)` in `__bpf_ringbuf_reserve`. It must
   not become visible before this side has finished *reading* the record, or
   the kernel may hand that space to a new reservation while the caller
   still holds a `Record` slice into it.

The consumer position is additionally cached in the `Reader` (only this
thread writes it), so ordinary reads of the cache need no atomic.

### Untrusted framing

Every header field is kernel-supplied and is treated as untrusted input: a
length exceeding the ring, a length running past `producer_pos`, a producer
position behind the consumer, or a consumer position off the 8-byte granule
each produce a typed `ConsumeError` (`CorruptRecord` /
`InconsistentPositions`). Nothing in the record walk can panic or read out
of bounds on hostile bytes, and `consume()` takes a `max_records` bound so a
producer faster than the consumer cannot starve the caller's loop.

## Validation layering (privilege-aware)

Two layers, deliberately split so a CI run without `CAP_BPF` still asserts
something real:

1. **Unprivileged, always run.** The exact bytes and struct fields each path
   hands the kernel: the `perf_event_attr` a kprobe attach builds (including
   the `config1`/`config2` union offsets and the retprobe bit position), the
   `RTM_SETLINK`+`IFLA_XDP` message as golden bytes (attach, detach and
   `XDP_FLAGS_REPLACE` variants, re-parsed through the sibling `netlink`
   codec), the `BPF_PROG_ATTACH` attr union layout with the `BPF_F_ALLOW_*`
   encodings, and — the backbone — the ring-buffer consumer driven over a
   **hand-built in-memory fake ring** that reproduces the kernel's three
   regions, its data-area aliasing, and its release-store publication order.
   The fake-ring tests cover multi-record walks, wrap-around across the ring
   end (asserting the returned slice really does start in the first copy and
   end in the second), discard skipping, busy-record stalling and resumption
   after commit, zero-length records, `max_records`/stop-action bounds, and
   six hostile-header cases.
2. **Privileged, gracefully skipped.** Real attach/detach round trips and a
   real `BPF_MAP_TYPE_RINGBUF` mmap+consume: load `ringbufEmit`, attach it
   to a kprobe, trigger it, and read the record back; attach/detach a
   `cgroup_skb` program in a throwaway child cgroup. Each prints a
   `SKIPPED:` line and **passes** when the capability is missing, mirroring
   the `opcua` module's podman-gated live tests — a sandboxed run can never
   be mistaken for "verified", but it also never fails for lack of
   privilege.

Privileges required, per operation: `CAP_BPF` (or root) for map creation,
program load and cgroup attach; additionally `CAP_PERFMON`/`CAP_SYS_ADMIN`
for the kprobe PMU; `CAP_NET_ADMIN` for XDP.

## Backlog / deliberately out of scope

- **`BPF_MAP_TYPE_PERF_EVENT_ARRAY` (perfbuf)** — the older, per-CPU
  predecessor of the ring buffer, with a different mmap layout (a
  `perf_event_mmap_page` control page per CPU), its own record types
  (`PERF_RECORD_SAMPLE`/`_LOST`) and a per-CPU fd fan-out. Not a variation
  on `ringbuf.zig`; a separate consumer.
- **uprobe / tracepoint / raw-tracepoint attach** — uprobes reuse the same
  `perf_event_open` shape as `attachKprobe` (a different PMU id, with
  `config1` = a *path* rather than a symbol), tracepoints go through
  `/sys/kernel/tracing/events/.../id` + `PERF_TYPE_TRACEPOINT`, and
  raw-tracepoints use `bpf(BPF_RAW_TRACEPOINT_OPEN)`. Each is additive.
- **`BPF_LINK_CREATE`-based attachment** (XDP links, `tcx`, `netkit`,
  fentry/fexit) — the modern, fd-lifetimed alternative; see the XDP
  rationale above for why the netlink path was chosen first.
- **cpumap/devmap attach** (`BPF_XDP_CPUMAP`/`BPF_XDP_DEVMAP` programs
  attached via map entries rather than to an interface).
- **`bpf(BPF_PROG_QUERY)`** — enumerating what is already attached to a
  cgroup or interface; useful for a "detach whatever is there" tool, not
  needed by the attach/detach pairs here.
- A fourth program kind was intentionally NOT added, to keep the surface to
  exactly `kprobe-counter` / `xdp-filter` / `ringbuf-emit` — see README's
  "Out of scope" list (BTF/CO-RE, ELF-skeleton loading, tc/classifier
  programs), each additive rather than a redesign.
