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

Six hooks are supported. The single thing to get right is that they do
**not** share a lifetime model — two of them outlive the attaching process:

| hook | syscall path | detach | survives process exit? |
|---|---|---|---|
| kprobe / kretprobe | `perf_event_open` on the kprobe PMU + link-or-`ioctl(PERF_EVENT_IOC_SET_BPF)` + `ioctl(PERF_EVENT_IOC_ENABLE)` | close the fd(s) | **no** |
| uprobe / uretprobe | `perf_event_open` on the uprobe PMU (`config1` = a **path**, `config2` = a **file offset**) + the same binding step | close the fd(s) | **no** |
| tracepoint | `<tracefs>/events/<cat>/<name>/id` + `perf_event_open(PERF_TYPE_TRACEPOINT)` + the same binding step | close the fd(s) | **no** |
| raw tracepoint | `bpf(BPF_RAW_TRACEPOINT_OPEN)` — no perf event at all | close the fd | **no** |
| XDP | netlink `RTM_SETLINK` + nested `IFLA_XDP`, **or** `bpf(BPF_LINK_CREATE)` | `IFLA_XDP_FD = -1` / close the link fd | **yes** (netlink) / **no** (link) |
| cgroup | `bpf(BPF_PROG_ATTACH)`, **or** `bpf(BPF_LINK_CREATE)` | `bpf(BPF_PROG_DETACH)` / close the link fd | **yes** (PROG_ATTACH) / **no** (link) |

`Link` is the uniform handle over all of them (`Link.detach()` reports
failures, `Link.deinit()` is the `defer`-friendly best-effort form); the
per-hook handles (`KprobeHandle`/`PerfEventHandle`/`RawTracepointHandle`/
`XdpHandle`/`CgroupHandle`/`bpflink.LinkHandle`) expose the same two methods
and are idempotent. Every fd a handle does not itself create (`prog_fd`, a
cgroup directory fd) is **borrowed**, matching `load.zig`'s rule that the
caller closes what the caller created — the borrowed fds must outlive the
handle, because `detach()` names them.

### uprobes: the vaddr-vs-file-offset trap

A uprobe is registered by **(inode, file offset)**, not by address: the
kernel installs the breakpoint in the file so that every process mapping
that inode is probed. The symbol table, however, stores a **virtual
address** (`st_value`). For an object whose text is mapped 1:1 the two
numbers coincide — which is exactly why treating them as interchangeable
survives casual testing and then produces a probe on the wrong bytes for the
first symbol in a skewed segment.

`elfsym.zig` therefore does the conversion explicitly: find the `PT_LOAD`
whose **file-backed** range covers the address
(`p_vaddr <= v < p_vaddr + p_filesz`) and return `p_offset + (v - p_vaddr)`.
Checking `p_filesz` rather than `p_memsz` is deliberate: the tail between the
two is `.bss`, which has no bytes in the file at all, so a symbol there is
`error.NoFileMapping` rather than an offset naming some unrelated later
section.

On the machine this was written on the skew is real and easy to reproduce:
`libc.so.6`'s writable `PT_LOAD` maps file offset `0x20db98` at vaddr
`0x20eb98`, so `stdout` (vaddr `0x213668`, per `readelf -sW`) has file offset
`0x212668`, and `environ` (vaddr `0x219de8`) falls past `p_filesz` entirely.
`malloc`, in the 1:1 text segment, has offset == vaddr — the case that hides
the bug.

The reader is ELF64-only, host byte order, `.symtab` first then `.dynsym`,
with `name@VERSION` suffixes matched by their bare name. Every count read out
of the file (`e_shnum`, `sh_size`, …) is bounded, so a corrupt object is a
typed error rather than a multi-gigabyte allocation.

### tracepoints vs. raw tracepoints

A `PERF_TYPE_TRACEPOINT` attachment hands the program the **formatted trace
event record** whose layout is described by
`<tracefs>/events/<cat>/<name>/format`; a raw tracepoint
(`BPF_RAW_TRACEPOINT_OPEN`) hands it the tracepoint's **raw arguments**
(`struct bpf_raw_tracepoint_args`). The raw form is cheaper (no record
formatting) and closer to the kernel's own types; the formatted form has a
stable, self-describing field layout. Both are implemented; neither is a
wrapper over the other, and only the first involves a perf event.

Tracepoint category/name components are pasted into a path, so they are
**validated, not sanitized**: `/`, `..`, NUL, over-long and non
`[A-Za-z0-9_.:-]` components are refused up front.

### `BPF_LINK_CREATE` and why the fallback is visible

Links replace the per-hook ownership rules with one: the attachment lives
exactly as long as its fd. That is what makes `BPF_LINK_UPDATE` possible —
atomically swapping the program behind a live attachment, with no window in
which nothing is attached — and it is why a link cannot be clobbered (or
cleaned up) by anyone but its owner.

The catch is availability: cgroup/raw-tracepoint links need 5.7, XDP 5.9,
**perf-event links 5.15**, tcx/netkit 6.6/6.7. An older kernel answers plain
`EINVAL`, because `attach_type` is validated before anything else is even
looked at — indistinguishable from "you passed bad arguments". So:

- `bpflink.errnoToLinkError` maps `EINVAL`/`EOPNOTSUPP`/`ENOSYS` alike to
  `error.LinkNotSupported`, documented as "retry the legacy path".
- Every entry point that can take either path reports an **`AttachPath`**
  (`.bpf_link` or `.legacy`), and takes a **`LinkPreference`**
  (`.auto` / `.link_only` / `.legacy_only`) so both branches are reachable
  from a test on any kernel. A silent fallback would leave a caller
  reasoning about the wrong lifetime model.
- `bpflink.perfLinkSupport()` is the libbpf-style feature probe: attempt a
  create with deliberately invalid fds; `EBADF` means the attach type exists
  (validation got past it), `EINVAL` means it does not.

Two defaults are deliberate rather than uniform:

- kprobe/uprobe/tracepoint default to `.auto` — the link is strictly better
  and invisible to operators either way.
- `attachXdp` keeps the **netlink** path and gets a separate opt-in
  `attachXdpAuto`. A netlink attach is what `ip link show` / `bpftool net`
  display and what `ip link set dev X xdp off` can remove; an XDP link is
  neither. Changing the default would silently change what an operator sees.

A `bpf_cookie` (readable in-program via `bpf_get_attach_cookie()`) exists
only in the link ABI. Requesting one while falling back would drop it
silently, so `bindPerfEvent` refuses instead: cookie + no link =
`error.LinkNotSupported`.

`std.os.linux.BPF.LinkCreateAttr` stops after `flags` (16 bytes), predating
every per-attach-type extension, so `bpflink.zig` declares the extended
`bpf_attr.link_create` itself (the union carrying `perf_event.bpf_cookie`,
`tracing.{target_btf_id,cookie}`, `tcx.*`, `netfilter.*`). Passing a
**shorter** `size` than the kernel's own struct is ABI-safe in both
directions — `bpf()` zero-fills the tail it did not receive — and the layout
is pinned by golden byte tests.

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

## Perf-buffer consumer: how it differs from the ring buffer

`BPF_MAP_TYPE_PERF_EVENT_ARRAY` is the per-CPU predecessor of the ring
buffer, still the only option before 5.8 and still the right one when
per-CPU attribution matters. It is **not** a variation on `ringbuf.zig`;
four things differ, and each is a place a naive port breaks:

| | ring buffer | perf buffer |
|---|---|---|
| rings | ONE, shared by all CPUs (MPSC) | ONE PER CPU, each with its own perf fd |
| wrap | the kernel **double-maps** the data pages, so a wrapping record is contiguous | **no** double mapping — a wrapping record must be reassembled |
| commit | per-record `BUSY` bit in the record header | none: `data_head` alone publishes the record |
| loss | impossible (a full ring fails the reservation in-program) | `PERF_RECORD_LOST` records, which must be surfaced |

### mmap layout

One mapping of `(1 + 2^n) * page_size` at offset 0, `PROT_READ|PROT_WRITE`
(the write is for `data_tail`): page 0 is the `perf_event_mmap_page` control
page, the rest is the data area. `data_head` sits at byte 1024 of the
control page and `data_tail` at 1032 — the struct pads itself "to 1k"
precisely so the two positions land on their own cache lines. Both offsets
are asserted against `std.os.linux.perf_event_mmap_page` in the tests.

### Barrier discipline

Two atomics rather than the ring buffer's three, because there is no
per-record commit flag:

1. **`data_head`: acquire load** — pairs with the kernel's
   `smp_store_release(&rb->user_page->data_head, head)` at the end of
   `perf_output_end`. The release store happens *after* the whole record is
   written, so ONE acquire load orders every byte below it. That is exactly
   why no per-record acquire is needed here and one is mandatory in
   `ringbuf.zig`.
2. **`data_tail`: release store** — pairs with the kernel's
   `smp_load_acquire(&rb->user_page->data_tail)` in `perf_output_begin`. It
   must not become visible before this side has finished reading the record,
   or the kernel may overwrite bytes a caller still holds a slice into.

### Records and losses

`PERF_RECORD_SAMPLE` with `sample_type = PERF_SAMPLE_RAW` is
`{ header; u32 size; char data[size] }`. The kernel rounds `size` so that
`4 + size` is a multiple of 8, so a payload may carry up to 4 bytes of
trailing zero padding — surfaced as-is, matching what libbpf hands its
`sample_cb`.

`PERF_RECORD_LOST` (`{ header; u64 id; u64 lost }`) is surfaced as
`Event.lost` **and** accumulated in `Reader.lost_records` /
`PerfBuffer.lostRecords()`. It is never silently skipped: "my numbers are
slightly wrong" is the failure mode a tracing tool most needs to know about
and least often notices. Record types this consumer does not decode are
skipped but counted in `unknown_records`.

Because there is no double mapping, a record whose payload crosses the ring
end is reassembled into a per-CPU scratch buffer sized to the ring (so
`error.RecordTooLarge` is unreachable through `PerfBuffer`; a hand-built
`Reader` with a smaller buffer gets the typed error). The 8-byte record
header itself can never split — perf record sizes are multiples of 8 and
positions stay 8-aligned — but everything after it can, so the header/length
reads go through a wrapping `copyOut`.

### Untrusted framing

A record size that is zero, not a multiple of 8, larger than the ring or
larger than what the producer published; a `PERF_RECORD_SAMPLE` whose raw
length runs past its own record; a `PERF_RECORD_LOST` too short for its two
`u64`s; a head behind the tail; a tail off the 8-byte granule — each is a
typed `ConsumeError`, never a panic and never an out-of-bounds read. (A
zero size is the one that would otherwise spin the walk forever.)

## BTF: the parser, and why bounds safety is the whole design

`btf.zig` exists because `std.os.linux.BPF.btf` ships the **wire structs**
and nothing that walks them. Three properties drive its shape.

### 1. A BTF blob is untrusted input

`/sys/kernel/btf/vmlinux` is trustworthy; a `.BTF` section lifted out of an
arbitrary object file, or read off a wire, is not. Every one of these is a
typed error rather than a crash or a wrong answer:

| malformation | result |
|---|---|
| bad magic / byte-swapped magic / `version != 1` | `NotBtf` / `UnsupportedBtf` |
| `hdr_len` below `sizeof(btf_header)` or past the blob | `MalformedBtf` |
| `type_off+type_len` or `str_off+str_len` past the blob | `MalformedBtf` (added in `u64`, so it cannot wrap) |
| `type_off` not 4-byte aligned | `MalformedBtf` |
| a `vlen` the type section cannot hold | `MalformedBtf` |
| a truncated record (12-byte header, or an `INT`'s trailing word) | `MalformedBtf` |
| an unknown `BTF_KIND_*` (or `KIND_UNKN`) | `MalformedBtf` |
| a string section not NUL-framed | `MalformedBtf` |
| a type id past the end | `TypeIdOutOfRange` |
| a `name_off` past the string section | `str()` -> `null` |
| a typedef cycle / self-referential array | `TypeChainTooDeep` |
| a `DATASEC` naming a nonexistent VAR | `validateReferences` -> `TypeIdOutOfRange` |

The structural guarantee: **`parse` walks the entire type section once,
sizing every record**, and records each type's byte offset. A `vlen` that
does not fit is rejected there, so every kind-specific accessor afterwards
indexes an already-validated slice and cannot read out of bounds. Type-id
*references* are checked when followed (`byId`), or exhaustively up front by
the optional `validateReferences` pass.

### 2. Cycles must terminate

`typedef A -> const A` is not expressible in C but is trivially expressible
in a BTF blob. `skipModifiers`, `sizeOf` and `findMember` are all bounded by
`max_resolve_depth` (32, the same ceiling libbpf uses); an array's element
size recursion carries the same budget, so `array[1] of array[1] of …`
cannot exhaust the stack.

### 3. std's enums are too narrow to parse into

Fields are read with `std.mem.readInt` at asserted offsets, never by
`@ptrCast`ing the blob onto `std.os.linux.BPF.btf.Type`. Two concrete
reasons, beyond `elfsym.zig`'s general one:

- `btf.Type.info.kind` is `enum(u5)` with 20 values — kinds 20..31 are
  representable in the wire field and would be an invalid enum value in a
  safety-checked build.
- `btf.IntInfo.encoding` is `enum(u4)` with exactly three values
  (`signed`/`char`/`boolean`). A plain `unsigned int` — of which
  `/sys/kernel/btf/vmlinux` has many — encodes as **0**, which is not one of
  them. A `@ptrCast` parse would trip on the first one it met.

### `FUNC`'s `vlen` is a linkage, not a count

The single most dangerous field in the format for a parser: `BTF_KIND_FUNC`
stores its `btf_func_linkage` in `vlen`, and has **no trailing data**. Sizing
a `FUNC` record as `8 * vlen` (the `FUNC_PROTO` rule) desynchronizes the
entire remainder of the type section — and `/sys/kernel/btf/vmlinux` is ~40%
`FUNC` records, so the damage is total rather than local.

### `KFLAG` bitfield offsets

When a `STRUCT`/`UNION` has `BTF_INFO_KFLAG` set, each member's 32-bit
`offset` word is `(bitfield_size << 24) | bit_offset`. Reading it as a plain
bit offset gives `struct sk_buff`'s `fclone` an offset of ~50 million
instead of 1010. `Btf.member` applies the split; the non-KFLAG case reports
`bitfield_size == 0`.

### Split BTF

`/sys/kernel/btf/<module>` continues the base blob: its first type id is
`base.endId()`, and a `name_off` below `base.str_len` addresses the *base's*
string section. Parsing one alone would resolve every id and every name to
something wrong but plausible, so `parse` **detects** it — a base blob's
string section starts with `"\0"` (that is what makes `name_off == 0` the
empty name); a split blob's does not — and refuses with
`SplitBtfNeedsBase` unless a base was supplied.

## BTF-typed attach: where the id has to go

For a plain kernel-function `fentry`/`fexit`, the kernel matches on
`bpf_attr.prog_load.attach_btf_id`, set at **load** time. At link time
`bpf_tracing_prog_attach` enforces `!!tgt_prog_fd != !!btf_id -> -EINVAL`, so
passing a `target_btf_id` with `target_fd == 0` is an error, not a second
chance to name the target. `tracing.zig` therefore:

- resolves the name at attach purely to convert a typo into
  `error.AttachTargetNotFound` instead of a bare `EINVAL`, and to *report*
  the id it resolved (`TracingLink.attach_btf_id`);
- issues the link with the zero pair;
- offers `loadTracing`, which resolves the id and loads the program already
  targeted at it — the call that makes attach-by-name real end to end;
- exposes the non-zero pair only through `attachExt`, the
  `BPF_PROG_TYPE_EXT` case where it is meaningful.

Name-to-BTF-kind mapping (verified against this machine's vmlinux BTF, which
has 1060 `btf_trace_*` **typedefs** and zero `btf_trace_*` funcs):

| hook | kind | name |
|---|---|---|
| `fentry` / `fexit` / `fmod_ret` | `FUNC` | the function |
| `tp_btf` | **`TYPEDEF`** | `btf_trace_<name>` |
| LSM | `FUNC` | `bpf_lsm_<hook>` |
| iter | `FUNC` | `bpf_iter_<name>` |

## CO-RE: what is implemented, and what is not

Implemented and tested against genuine `clang -target bpf -O2 -g` output
(embedded as a byte fixture) and against `/sys/kernel/btf/vmlinux`:

- the `.BTF.ext` container — header including the *optional* `core_relo`
  tail older producers omit, per-sub-section `rec_size`, the
  `{sec_name_off, num_info, records…}` framing, and forward-compatible
  over-long records (the known prefix is read, the tail ignored);
- access-spec parsing (`"0:2:0"`) and the local spec walk, which records
  each step's member **name** — the thing CO-RE exists to depend on instead
  of an index;
- target matching: the root type by flavor-stripped name + kind, then every
  named step re-resolved by name in the target (descending anonymous
  members, which `struct sk_buff` requires);
- all six `BPF_CORE_FIELD_*` values, including the bitfield load-widening
  (1 -> 2 -> 4 -> 8 bytes until the bits fit an aligned load) that makes
  `LSHIFT_U64`/`RSHIFT_U64` correct.

**Not** implemented, and not claimed:

- **instruction patching** — `computeFieldRelo` returns the value; nothing
  rewrites a `[]Insn`. That needs a BPF-object loader (section-to-program
  mapping, map relocation, `fd_array`) this module does not have;
- **multi-candidate matching / ambiguity detection** — libbpf collects every
  target with a matching name, relocates against each, and errors when they
  disagree. This takes the first match;
- the **non-field** relocation kinds (`TYPE_ID_LOCAL`/`_TARGET`,
  `TYPE_EXISTS`, `TYPE_SIZE`, `TYPE_MATCHES`, `ENUMVAL_EXISTS`,
  `ENUMVAL_VALUE`) — parsed, then refused with
  `error.UnsupportedReloKind`;
- `.rel.BTF.ext` relocation of the section-name offsets, and BPF-object ELF
  loading generally.

## Validation layering (privilege-aware)

Two layers, deliberately split so a CI run without `CAP_BPF` still asserts
something real:

1. **Unprivileged, always run.** The exact bytes and struct fields each path
   hands the kernel:
   - the `perf_event_attr` a kprobe attach builds (the `config1`/`config2`
     union offsets and the retprobe bit position) and the **uprobe** one
     (path in `config1`, file offset in `config2`, the USDT `ref_ctr_offset`
     in `config`'s high half, and the `"config:N"`/`"config:N-M"` PMU
     `format/*` grammar);
   - the tracepoint attr (static `PERF_TYPE_TRACEPOINT`, nothing in
     `config1`/`config2`) and the tracepoint-name validation that keeps a
     category/name from escaping the `events/` directory;
   - the `BPF_RAW_TRACEPOINT_OPEN` attr union layout;
   - the extended `bpf_attr.link_create` as **golden bytes** for the
     perf-event / XDP / cgroup / tracing cases, plus the `bpf_link_info`
     prefix and the errno mapping;
   - the `RTM_SETLINK`+`IFLA_XDP` message as golden bytes (attach, detach and
     `XDP_FLAGS_REPLACE` variants, re-parsed through the sibling `netlink`
     codec) and the `BPF_PROG_ATTACH` attr union with its `BPF_F_ALLOW_*`
     encodings;
   - `elfsym`: the pure vaddr -> file-offset conversion over hand-written
     segments (including the skewed and `.bss` cases), a **synthetic ELF64**
     built byte-by-byte in the test and resolved from a temp file (exact
     expected offsets, not host-dependent ones), malformed-input cases, and
     a **real `libc.so.6`** cross-checked against an *independent*
     derivation — the section headers (`sh_addr`/`sh_offset`) rather than
     the program headers the module uses. Two tables that must agree;
   - the `BPF_BTF_LOAD` attr as golden bytes (including the zero tail past
     what an older kernel knows) and the **extended `bpf_attr.prog_load`**
     field-for-field against the UAPI offsets — `attach_btf_id` at 108,
     `prog_btf_fd` at 72, `func_info` at 80, `line_info` at 96 — plus
     against std's shorter declaration for every field it does have. Getting
     `attach_btf_id` wrong by four bytes would attach an fentry program to
     whatever type id sits next door;
   - `btf`: a **synthetic blob exercising every `BTF_KIND_*`** with exact
     expected offsets (including the `KFLAG` bitfield split, an anonymous
     nested struct, and an `INT` with `encoding == 0`), a battery of hostile
     blobs (see the table in the BTF section above — each asserted as a
     typed error), a hand-built **split** blob proving ids continue and
     names resolve out of the second string section, and the **real
     `/sys/kernel/btf/vmlinux`** asserted structurally (a member exists, a
     kind is what it must be) rather than numerically. That last one was
     additionally cross-checked by hand against `bpftool btf dump file
     /sys/kernel/btf/vmlinux format raw`: the per-kind type histogram
     matched across all ~170 000 types, as did `task_struct` (size 9920,
     272 members), `sk_buff` (size 232, 28 members), `task_struct.pid`
     (bits_offset 22400) and `sk_buff.fclone` (bits_offset 1010,
     bitfield_size 2). None of those numbers are asserted in the tests —
     they change with every kernel build;
   - `btfext`: synthetic `.BTF.ext` blobs (well-formed, hostile, and the
     pre-5.16 short header), plus a **real `clang -target bpf -O2 -g`
     object's `.BTF` + `.BTF.ext` embedded as a byte fixture** whose four
     `core_relo` records are genuine compiler output. Those records are
     relocated (a) against the fixture itself, where the expected offsets
     and shifts are exact constants, and (b) against the running kernel's
     vmlinux BTF — the local `task_struct.pid` is at byte 0 and the
     kernel's is thousands of bytes in, so a relocation that quietly did
     nothing fails immediately;
   - `tracing`: the prefix/BTF-kind table, name validation (a libbpf-style
     `"fentry/vfs_read"` is refused rather than looked up literally), and
     `attach_btf_id` resolution against real kernel BTF for `fentry`,
     `tp_btf` (asserting the result is a **TYPEDEF**, which is what a
     `FUNC` lookup would have missed) and LSM;
   - and — the backbone — both consumers driven over **hand-built in-memory
     fake rings**. `ringbuf`'s reproduces the kernel's three regions, its
     data-area aliasing and its release-store publication order (multi-record
     walks, wrap-around asserting the slice starts in the first copy and ends
     in the second, discard skipping, busy-record stalling and resumption,
     zero-length records, `max_records`/stop bounds, six hostile headers).
     `perfbuf`'s reproduces the control page and — deliberately — the
     *absence* of a double mapping (multi-record walks, a record split across
     the ring end asserting it came from the reassembly buffer, a wrapping
     raw-length field, `PERF_RECORD_LOST` surfaced and accumulated, unknown
     record types skipped-but-counted, a head that moves mid-iteration,
     `max_records`/stop bounds, and ten hostile-header cases including the
     zero-size spin and an over-large wrapping record).
2. **Privileged, gracefully skipped.** Real attach/detach round trips and
   real mmap+consume: a `ringbufEmit` program on a kprobe, read back through
   the ring buffer; a **uprobe** on a symbol in the test binary itself
   (exported only in test builds), triggered and counted; a **tracepoint** on
   `syscalls/sys_enter_write` attached over BOTH the link and the forced
   legacy path; a **raw tracepoint** on `sys_enter`; a **perf buffer** across
   every online CPU fed by a tracepoint program; and cgroup attach via both
   `BPF_PROG_ATTACH` and `BPF_LINK_CREATE`, including `BPF_LINK_UPDATE`
   (plain and `BPF_F_REPLACE`) and `BPF_LINK_GET_FD_BY_ID`. Since BTF
   landed, also: `BPF_BTF_LOAD` of a blob this module's `Builder` produced
   (plus a deliberately invalid one the kernel must reject), an **`fentry`
   program loaded with a resolved `attach_btf_id` and attached by name**
   (asserting the link reports `LinkType.tracing` and that the id the attach
   resolved equals the one the load used), and the same for a **`tp_btf`**
   program. Each prints a
   `SKIPPED:` line and **passes** when the capability is missing, mirroring
   the `opcua` module's podman-gated live tests — a sandboxed run can never
   be mistaken for "verified", but it also never fails for lack of
   privilege. Note that `unshare -r` is NOT sufficient: `geteuid() == 0`
   inside a user namespace is not `CAP_BPF` in the init user namespace, so
   `bpf()` still fails; the live tests fall through their inner
   `catch { print SKIPPED; return; }` guards in that case rather than
   failing.

Privileges required, per operation: `CAP_BPF` (or root) for map creation,
program load, `BPF_BTF_LOAD` and cgroup attach; additionally
`CAP_PERFMON`/`CAP_SYS_ADMIN` for the kprobe PMU; `CAP_NET_ADMIN` for XDP.
**Reading** BTF is the exception: `/sys/kernel/btf/*` is mode 0444, so
parsing vmlinux and resolving an `attach_btf_id` need no capability at all —
which is why the BTF tests are in the unprivileged layer and only the
attach that follows them is gated.

## Backlog / deliberately out of scope

Implemented since the first cut (moved out of this list): the perf-buffer
consumer, uprobe/uretprobe, tracepoint, raw tracepoint,
`BPF_LINK_CREATE`/`_UPDATE`/`_DETACH`/`_GET_FD_BY_ID`/`_GET_NEXT_ID`, and —
most recently — **BTF**: the parser (`btf.zig`), kernel and split module
BTF, `attach_btf_id` resolution, attach-by-name for
`fentry`/`fexit`/`fmod_ret`/`tp_btf`/LSM (`tracing.zig`), `BPF_BTF_LOAD`
plus the extended `BPF_PROG_LOAD` carrying `prog_btf_fd`/`func_info`/
`line_info`, and the field-offset slice of CO-RE (`btfext.zig`).

Still deferred, honestly:

- **The rest of CO-RE** — instruction patching, multi-candidate matching and
  ambiguity detection, and the non-field relocation kinds. See the "CO-RE:
  what is implemented, and what is not" section above for the exact line;
  the container and field-offset relocation ARE done, the rest is not, and
  `error.UnsupportedReloKind` is how a caller finds out rather than getting
  a wrong number.
- **BPF-object ELF loading.** `elfsym.zig` reads section headers but not
  section *names*, so nothing here lifts `.BTF`/`.BTF.ext`/`maps`/program
  sections out of a `clang -target bpf` object. That is the missing piece
  between "this module can relocate a `.BTF.ext` record" and "this module
  can load a CO-RE object" — it also needs map creation from BTF-typed map
  definitions and `fd_array` relocation.
- **BTF-typed map definitions** (`struct { __uint(type, …); }` in a
  `.maps` DATASEC) — the parser can read the DATASEC and the VARs; nothing
  turns them into `BPF_MAP_CREATE` calls with
  `btf_key_type_id`/`btf_value_type_id`.
- **`BPF_BTF_GET_FD_BY_ID` / `BPF_BTF_GET_NEXT_ID`** — reading back the BTF
  a loaded program or map carries (what `bpftool btf dump id N` does).
  `BPF_BTF_LOAD` is implemented; the retrieval side is not.
- **A name index over kernel BTF.** `findByNameKind` is a linear scan of
  ~170 000 types. One lookup is microseconds; thousands would want a hash
  built once. Deliberately not built (it would allocate proportional to the
  blob for every caller, including those doing a single attach).
- **`kprobe_multi` / `uprobe_multi`** (`bpf(BPF_LINK_CREATE)` with the
  `kprobe_multi`/`uprobe_multi` union arms) — attaching one program to
  thousands of symbols in a single call, the mechanism behind `retsnoop`'s
  and `bpftrace`'s fast mass-attach. The attr arms are declared in
  `bpflink.CreateExtra`; the symbol/address array marshalling and the
  kallsyms-glob resolution are not.
- **`tcx` / `netkit` attach** — declared in `CreateExtra` (including the
  `relative_fd`/`expected_revision` ordering fields) but not driven by an
  entry point; needs 6.6+/6.7+ and has no consumer here yet.
- **USDT probe discovery.** `UprobeOptions.ref_ctr_offset` carries the
  semaphore a USDT probe needs, but finding it means parsing the
  `.note.stapsdt` ELF notes (provider/name/location/base/semaphore, plus the
  argument descriptor string) — a separate parser on top of `elfsym`.
- **32-bit and cross-endian ELF** in `elfsym` — refused with
  `error.UnsupportedElf` rather than mis-parsed. A uprobe is registered
  against a file the host can execute, so a foreign-class object is a caller
  mistake.
- **Symbol demangling and DWARF line lookup** — `elfsym` resolves names as
  they appear in the symbol table; probing "file:line" or a C++ source name
  needs debug info this module does not read.
- **`bpf(BPF_PROG_QUERY)`** — enumerating what is already attached to a
  cgroup or interface; useful for a "detach whatever is there" tool.
  (`bpflink.linkNextId` covers the link half of that question.)
- **cpumap/devmap attach** (`BPF_XDP_CPUMAP`/`BPF_XDP_DEVMAP` programs
  attached via map entries rather than to an interface).
- **AUX/ITRACE perf areas** — the perf-buffer consumer reads the data area
  only; `aux_head`/`aux_tail` (Intel PT and friends) are a different
  consumer entirely.
- A fourth *program* kind was intentionally NOT added, to keep the builder
  surface to exactly `kprobe-counter` / `xdp-filter` / `ringbuf-emit` — see
  README's "Out of scope" list (BTF/CO-RE, ELF-skeleton loading,
  tc/classifier programs), each additive rather than a redesign. The live
  perf-buffer test's `bpf_perf_event_output` producer is deliberately
  test-local for the same reason: a public builder would need its own
  clang-derived golden vector.
