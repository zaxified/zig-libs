# ebpf

Pure-Zig **eBPF program generation, loading, attaching, and ring-buffer
consumption** for a fixed, named set of small programs
(`kprobe-counter`, `xdp-filter`, `ringbuf-emit`) — built on
`std.os.linux.BPF`'s instruction encoders and `bpf()` syscall wrapper, plus
the sibling `netlink` module for the XDP attach path.

- No maintained pure-Zig eBPF program-authoring library exists (`std` gives
  you the instruction-encoding primitives and the raw `bpf()` syscall, not a
  higher-level "build a program, load it, attach it, read its output" API).
- **Model after:** libbpf (C) — API shape only (program builder → load →
  attach → ring-buffer consumer, the same four-part flow), no source ported.
- **Platform:** linux (raw `std.os.linux` errno-encoded syscalls — a
  conscious ceiling). **Role:** util. **Concurrency:** single_owner (one
  `RingbufReader`/attach handle per owner; mmap'd ring state and perf/epoll
  fds are not internally synchronized).
- **Deps:** `netlink` — its nlmsghdr/nlattr codec is reused for the XDP
  attach path's `RTM_SETLINK` message.
- **Privileges:** everything past program encoding needs `CAP_BPF` (or
  root) at minimum; the kprobe/uprobe/tracepoint attaches additionally need
  `CAP_PERFMON`/`CAP_SYS_ADMIN`, and `attachXdp` needs `CAP_NET_ADMIN`.
  Nothing that touches the kernel works unprivileged — every gated test
  either skips (`error.SkipZigTest`) or prints a `SKIPPED:` line and passes,
  never fails, without it. (`unshare -r` does **not** help: `geteuid() == 0`
  in a user namespace is not `CAP_BPF` in the init user namespace.) The pure
  encoding/parsing layers — program builders, the netlink message builder,
  the ELF symbol reader, and both consumers' record walks — are fully tested
  with no privilege at all.

## Status: complete

All parts are implemented — see `modules/ebpf/src/*.zig` doc comments for
the authoritative, per-function constraint lists and `SPEC.md` for the
attach lifetime rules, the uprobe offset trap, and both consumers' barrier
discipline.

| File | Tier | Status |
|---|---|---|
| `src/programs.zig` | **FABLE** | bytecode generation, golden-vector tested |
| `src/load.zig` | — | thin wrapper (std already implements `BPF_PROG_LOAD`) |
| `src/attach.zig` | **OPUS** | kprobe/kretprobe, uprobe/uretprobe, tracepoint, raw tracepoint, XDP (netlink `IFLA_XDP`), cgroup (`BPF_PROG_ATTACH`) — one uniform `Link` handle, link-preferring where the kernel allows it |
| `src/bpflink.zig` | **OPUS** | `BPF_LINK_CREATE`/`_UPDATE`/`_DETACH`/`_GET_FD_BY_ID`/`_GET_NEXT_ID`, the extended `bpf_attr.link_create`, a libbpf-style feature probe |
| `src/elfsym.zig` | **OPUS** | minimal ELF64 `.symtab`/`.dynsym` reader + the vaddr -> **file offset** conversion a uprobe needs |
| `src/ringbuf.zig` | **OPUS** | mmap + acquire/release `BPF_MAP_TYPE_RINGBUF` consumer with `epoll` polling |
| `src/perfbuf.zig` | **OPUS** | per-CPU `BPF_MAP_TYPE_PERF_EVENT_ARRAY` consumer: `data_head`/`data_tail` barriers, wrap reassembly, explicit `PERF_RECORD_LOST` |

### Honest difficulty verdict

Generating verifier-passing bytecode for these three programs **is
genuinely Fable-tier**, not Opus-tier boilerplate dressed up as hard — but
the three programs are not equally hard, and it's worth being precise about
why:

- **`kprobe-counter`** is the closest of the three to boilerplate: no context
  decoding, one map lookup, one atomic increment. Its verifier constraints
  (initialized stack key, null-check before dereference, atomic
  increment) are real but are the exact same handful of patterns that show
  up in nearly every "hello world" eBPF tutorial — well-trodden, low
  novelty per instance.
- **`xdp-filter`** is genuinely hard: the bounds-check-DOMINANCE rule for
  direct packet access (the comparison must precede the access on every
  path, against the same register, with the pointer derived by a traceable
  ADD) is the single most commonly cited "why won't my XDP program load"
  verifier subtlety in the wild, and getting it wrong produces a rejection
  whose error message ("invalid access to packet") gives little guidance
  toward the actual fix.
- **`ringbuf-emit`** is arguably the hardest: `bpf_ringbuf_reserve`'s
  reference-state tracking is a **whole-CFG liveness property** (every path
  from a successful reserve to `exit()` must release the reference via
  submit or discard), not a local instruction-shape check — this is a
  newer, less-documented corner of the verifier's model than the
  pointer-typing rules the other two programs exercise.

Net: this is a constraint-satisfaction problem against the verifier's
abstract interpreter (register-type lattice, scalar-range tracking,
stack-slot liveness, reference-state tracking), not a fixed small set of
straightforward instruction sequences — the "Fable" framing holds, with the
caveat that `kprobe-counter` alone would not have justified it on its own.

## API

```zig
const ebpf = @import("ebpf");
const std = @import("std");

// 1. Create the map(s) a program needs — std.os.linux.BPF.map_create is
//    already real, working code; nothing here wraps it further.
const map_fd = try std.os.linux.BPF.map_create(.array, 4, 8, 1);

// 2. Build a program.
const prog: ebpf.Program = .{
    .prog_type = .kprobe,
    .insns = ebpf.kprobeCounter(map_fd),
};

// 3. Load it.
const prog_fd = try ebpf.load(prog, "MIT");
defer _ = std.os.linux.close(prog_fd);

// 4. Attach it. Closing the perf fd detaches a kprobe; an XDP or cgroup
//    attachment instead PERSISTS until detach() — see SPEC.md.
var kp = try ebpf.attachKprobe(gpa, "do_sys_openat2", prog_fd);
defer kp.detach();

// 5. For ringbuf-emit programs, consume the output.
var rb = try ebpf.RingbufReader.open(ringbuf_map_fd);
defer rb.close();
while (try rb.poll(-1)) {
    while (try rb.next()) |rec| {
        // handle rec.data
        rb.advance();
    }
}

// ...or the callback form, which also handles the discard/busy bits:
fn onSample(ctx: ?*anyopaque, data: []const u8) ebpf.RingbufAction {
    _ = ctx;
    _ = data;
    return .proceed;
}
_ = try rb.pollAndConsume(1000, null, onSample, 64);
```

### Userspace probes, tracepoints and raw tracepoints

```zig
// uprobe: the symbol is resolved to a FILE OFFSET (not its virtual
// address) — see SPEC.md for why that distinction bites.
var up = try ebpf.attachUprobe(gpa, "/lib/x86_64-linux-gnu/libc.so.6", "malloc", prog_fd);
defer up.detach();
// ...or a uretprobe, or an explicit offset / USDT semaphore:
var ur = try ebpf.attachUprobeOpts(gpa, path, "malloc", prog_fd, .{
    .retprobe = true,
    .ref_ctr_offset = 0,          // USDT semaphore file offset, 0 = none
    .bpf_cookie = 0x1234,         // readable in-program; needs a BPF link
});
defer ur.detach();

// Just the offset, e.g. to feed some other tool:
const off = try ebpf.resolveFuncOffset(gpa, path, "malloc");

// static tracepoint (reads <tracefs>/events/syscalls/sys_enter_write/id):
var tp = try ebpf.attachTracepoint(gpa, "syscalls", "sys_enter_write", tp_prog_fd);
defer tp.detach();

// raw tracepoint — a plain bpf() command, no perf event involved:
var rt = try ebpf.attachRawTracepoint(gpa, "sys_enter", raw_prog_fd);
defer rt.detach();
```

### Perf buffer (the per-CPU predecessor of the ring buffer)

```zig
// key = u32 cpu, value = u32 perf fd
const map_fd = try std.os.linux.BPF.map_create(.perf_event_array, 4, 4, 8);
var pb = try ebpf.PerfBuffer.open(gpa, map_fd, .{ .pages = 8 });
defer pb.close();

fn onSample(ctx: ?*anyopaque, cpu: u32, data: []const u8) ebpf.perfbuf.Action { ... }
fn onLost(ctx: ?*anyopaque, cpu: u32, lost: u64) ebpf.perfbuf.Action { ... }

_ = try pb.pollAndConsume(1000, null, onSample, onLost, 64);
std.debug.print("dropped so far: {d}\n", .{pb.lostRecords()});
```

Losses are surfaced, never swallowed: `PERF_RECORD_LOST` reaches `onLost`
*and* accumulates in `lostRecords()`.

### `BPF_LINK_CREATE`, and seeing which path an attach took

```zig
// Prefer the modern fd-lifetimed link, fall back to the legacy syscall —
// and report which one actually happened.
var out = try ebpf.attachCgroupAuto(cgroup_fd, prog_fd, .cgroup_inet_egress, .{}, .auto);
defer out.link.deinit();
switch (out.path) {
    .bpf_link => {},  // dies with this process
    .legacy   => {},  // survives it: detach explicitly
}

// Force either branch (useful in tests, and on kernels you must not guess about):
_ = ebpf.attachXdpAuto(gpa, ifindex, prog_fd, .{ .drv_mode = true }, .link_only);

// The raw link API is available directly, including atomic program swap:
var link = try ebpf.linkCreatePerfEvent(prog_fd, perf_fd, 0);
defer link.detach();
try link.update(new_prog_fd, prog_fd);   // BPF_F_REPLACE: conditional swap
```

Other attach entry points: `attachKretprobe` / `attachKprobeOpts`,
`attachXdp` / `attachXdpAuto` / `detachXdp` (with `XdpFlags` selecting
SKB/DRV/HW mode plus `XDP_FLAGS_UPDATE_IF_NOEXIST` / `XDP_FLAGS_REPLACE`),
and `attachCgroup` / `attachCgroupOpts` / `attachCgroupAuto` /
`detachCgroup` (with `BPF_F_ALLOW_MULTI`/`_OVERRIDE` semantics). Every
handle converts to the uniform `ebpf.Link` via `.link()`.

**Which default does what**: kprobe/uprobe/tracepoint default to
`LinkPreference.auto` (link if the kernel has it, `ioctl` otherwise).
`attachXdp` deliberately keeps the netlink path as its default — that is
what `ip link show` / `bpftool net` display and what `ip link set dev X xdp
off` can remove; `attachXdpAuto` is the opt-in link-preferring variant.

Low-level, for building custom programs (all `pub`): `ebpf.Insn` (re-export
of `std.os.linux.BPF.Insn` — every opcode builder needed lives there
already, see "std inventory" below), `ebpf.Program` (the
`{prog_type, insns}` pair `load`/`attach` expect).

## std inventory — what's already free

`std.os.linux.BPF` (`lib/std/os/linux/bpf.zig` in this Zig 0.16 toolchain)
already ships, and this module does **not** duplicate:

- **Instruction encoders**: `Insn` (a `packed struct` matching the kernel's
  8-byte wire encoding 1:1) with `mov`/`add`/`sub`/`mul`/`div`/`alu_or`/
  `alu_and`/`lsh`/`rsh`/`neg`/`mod`/`xor`/`arsh` (ALU ops), `jmp`/`ja`/`jeq`/
  `jgt`/`jge`/`jlt`/`jle`/`jset`/`jne`/`jsgt`/`jsge`/`jslt`/`jsle` (branches),
  `ld_abs`/`ld_ind`/`ldx`/`st`/`stx`/`xadd` (memory), `ld_dw1`/`ld_dw2`/
  `ld_map_fd1`/`ld_map_fd2` (64-bit immediate / map-fd pseudo-relocation
  loads), `le`/`be` (endian swap), `call`/`exit`.
- **The `bpf()` syscall wrapper** (`std.os.linux.bpf(cmd, attr, size)`) and
  its `Cmd` enum (`map_create`, `prog_load`, `prog_attach`, `link_create`,
  …), `Attr` union, and every per-command attr struct
  (`MapCreateAttr`/`ProgLoadAttr`/`ProgAttachAttr`/`LinkCreateAttr`/…).
- **Working high-level wrappers**: `map_create`, `map_lookup_elem`,
  `map_update_elem`, `map_delete_elem`, `map_get_next_key`, `prog_load` —
  all fully implemented and exercised by std's own tests against a real
  kernel.
- **Type enums**: `MapType` (incl. `.ringbuf`), `ProgType` (incl. `.kprobe`,
  `.xdp`), `AttachType` (incl. `.cgroup_inet_egress`, `.xdp`), `Helper` (the
  full `bpf_*` in-program helper-function id list).

What `std` does **not** ship (the actual gap this module fills):
- Any pre-built program (the encoders are free, the SEQUENCES are not).
- A wrapper for `Cmd.prog_attach`/`prog_detach` (types exist, function
  doesn't — see `attach.zig`'s `attachCgroup`).
- The `PERF_EVENT_IOC_*` ioctl request numbers, or any kprobe/uprobe-PMU
  sysfs handling (`perf_event_attr`, `perf_event_mmap_page` and the
  `perf_event_open` syscall wrapper ARE in std; the two ioctl numbers are
  hand-derived from `_IO`/`_IOW` in `attach.zig`, and the PMU type ids /
  retprobe bit / `ref_ctr_offset` shift are read from
  `/sys/bus/event_source/devices/{kprobe,uprobe}/`).
- Tracepoint id lookup (`<tracefs>/events/<cat>/<name>/id`, with the legacy
  `debugfs` fallback) and the name validation that keeps a category/name
  from escaping that directory.
- The **extended** `bpf_attr.link_create`: std's `LinkCreateAttr` stops
  after `flags` and has no per-attach-type union
  (`perf_event.bpf_cookie`, `tracing.{target_btf_id,cookie}`, `tcx.*`,
  `netfilter.*`) — see `bpflink.zig`. Nor does std wrap `link_create`,
  `link_update`, `link_detach`, `link_get_fd_by_id` or `link_get_next_id`
  (the `Cmd` values and `LinkUpdateAttr`/`GetIdAttr` types exist; the
  functions do not), nor `raw_tracepoint_open`.
- ELF symbol resolution to a **file offset**. `std.elf` supplies the types
  and constants (used here for exactly that), but nothing that walks
  `.symtab`/`.dynsym` for a name and converts `st_value` through the
  containing `PT_LOAD` — see `elfsym.zig`, and `SPEC.md` for why that
  conversion is not optional.
- The perf-buffer (`PERF_EVENT_ARRAY`) consumer: the per-CPU fd fan-out,
  `data_head`/`data_tail` barrier discipline, `PERF_RECORD_SAMPLE`/`_LOST`
  parsing and wrap reassembly. (`perf_event_mmap_page` is in std; nothing
  that uses it is.)
- Netlink `IFLA_XDP` attribute handling (needed for XDP attach — see
  `attach.zig`'s `attachXdp`; the underlying nlmsghdr/nlattr codec itself IS
  covered, by the sibling `netlink` module, not by `std`).
- A wrapper for `Cmd.obj_get_info_by_fd`, or a `bpf_map_info` struct — both
  needed to read a ring buffer's `max_entries` back (`ringbuf.zig`'s
  `MapInfo`/`mapInfo`).
- Ring-buffer mmap layout / consumer logic (`std.os.linux.mmap`/`munmap`/
  `epoll_ctl`/`epoll_wait` are present as raw syscalls; the ringbuf-specific
  record framing, position barriers and mapping offsets on top are not —
  see `ringbuf.zig`).

There is also a SEPARATE, unrelated free capability worth noting so it
isn't confused with this module's approach: `std.os.linux.bpf.kern`
(`lib/std/os/linux/bpf/kern.zig`) + `bpf/helpers.zig` let you write
KERNEL-SIDE eBPF program logic AS ZIG SOURCE, cross-compiled with
`-target bpfel-freestanding` through LLVM's BPF backend, calling BPF
helpers as ordinary Zig function calls resolved to fixed helper-id function
pointers. This module deliberately does NOT use that route: it would need a
second compilation unit (a different target triple than the rest of this
repo), an ELF object parser to pull the resulting `.text`/maps sections back
out (BPF program ELF objects use section-based map/prog discovery — this is
most of what `libbpf`'s "skeleton" loader does), and BTF handling for modern
map definitions — meaningfully MORE machinery than hand-building `Insn`
arrays for three fixed, small programs and loading them directly via
`BPF_PROG_LOAD`. Worth revisiting if this module ever needs to generate
large or many programs; not worth it for three.

## Design notes

- **Program type travels with its instructions** (`Program{prog_type,
  insns}`), not as a separate caller-supplied argument to `load` — the
  verifier's context-access whitelist and allowed-helper set both key off
  the program type, so decoupling them invites a mismatch bug.
- **`load.zig` is the thinnest layer here** — `std.os.linux.BPF.prog_load`
  already does everything it needs; wrapping it further would be exactly the
  "reimplementing what std already provides" this repo's conventions rule
  out. Its own tests (gated on `CAP_BPF`/root) load a hand-written trivial
  `socket_filter` program and confirm both the accept and reject paths
  work against a real kernel.
- **Golden vectors validate `programs.zig` offline** (no kernel needed for
  the byte-exact check — a kernel IS still needed to confirm the verifier
  accepts the result) — see `SPEC.md`.
- **Attach lifetimes are not uniform** — a kprobe dies with its perf fd, an
  XDP or cgroup attachment persists until explicitly detached. `Link` gives
  them one `detach()`/`deinit()` API, but the *consequence* of forgetting to
  call it differs (a leaked fd vs. a live kernel attachment). `SPEC.md` has
  the table.
- **Attach/consume validation is layered by privilege** — struct/byte-layout
  tests and a hand-built fake ring run everywhere; real attach and real
  `mmap`+consume tests print `SKIPPED:` and pass when `CAP_BPF` is absent,
  so a sandbox run is never mistaken for a verified one.
- **A fallback is never silent.** Where both a `BPF_LINK_CREATE` and a
  legacy path exist, the entry point returns which one it used
  (`AttachPath`) and accepts a `LinkPreference` that can force either — a
  caller that silently got the legacy path would be reasoning about the
  wrong lifetime model, and a test that cannot force a branch never covers
  it. A `bpf_cookie` (link-only) plus a fallback is a typed refusal rather
  than a dropped cookie.
- **`elfsym` is a uprobe helper, not an ELF library.** It reads what a
  probe needs (`.symtab`/`.dynsym` + `PT_LOAD`) and refuses everything else
  (32-bit, foreign-endian) rather than guessing.
- **Out of scope (deliberate)**: BTF parsing — and therefore
  fentry/fexit/`tp_btf`/LSM attach by name, `kprobe_multi`/`uprobe_multi`
  mass-attach, and CO-RE (Compile Once – Run Everywhere) relocation —
  plus USDT `.note.stapsdt` discovery, `tcx`/`netkit` attach entry points,
  `BPF_PROG_QUERY`, cpumap/devmap attach, perf AUX/ITRACE areas, DWARF/line
  and symbol demangling, tc/classifier programs, BTF-typed maps, and the
  `bpftool`-style ELF-skeleton loading route noted above. The three named
  programs and the six attach mechanisms are the whole surface this module
  commits to; extending to a new program or attach kind is additive (a new
  function following the same doc-comment discipline), not a redesign.
  `SPEC.md`'s backlog section says what each deferred item would actually
  take.
