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
  root) at minimum; `attachKprobe` additionally needs
  `CAP_PERFMON`/`CAP_SYS_ADMIN`, and `attachXdp` needs `CAP_NET_ADMIN`.
  Nothing that touches the kernel works unprivileged — every gated test
  either skips (`error.SkipZigTest`) or prints a `SKIPPED:` line and passes,
  never fails, without it. The pure encoding/parsing layers (program
  builders, the netlink message builder, the ring-buffer record walk) are
  fully tested with no privilege at all.

## Status: complete

All four parts are implemented — see `modules/ebpf/src/*.zig` doc comments
for the authoritative, per-function constraint lists and `SPEC.md` for the
attach lifetime rules and the ring-buffer barrier discipline.

| File | Tier | Status |
|---|---|---|
| `src/programs.zig` | **FABLE** | bytecode generation, golden-vector tested |
| `src/load.zig` | — | thin wrapper (std already implements `BPF_PROG_LOAD`) |
| `src/attach.zig` | **OPUS** | kprobe/kretprobe (perf PMU), XDP (netlink `IFLA_XDP`), cgroup (`BPF_PROG_ATTACH`), one uniform `Link` handle |
| `src/ringbuf.zig` | **OPUS** | mmap + acquire/release ring-buffer consumer with `epoll` polling |

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

Other attach entry points: `attachKretprobe` / `attachKprobeOpts`,
`attachXdp` / `detachXdp` (with `XdpFlags` selecting SKB/DRV/HW mode plus
`XDP_FLAGS_UPDATE_IF_NOEXIST` / `XDP_FLAGS_REPLACE`), and `attachCgroup` /
`attachCgroupOpts` / `detachCgroup` (with `BPF_F_ALLOW_MULTI`/`_OVERRIDE`
semantics). All three return a handle convertible to the uniform
`ebpf.Link` via `.link()`.

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
- The `PERF_EVENT_IOC_*` ioctl request numbers, or any kprobe-PMU sysfs
  handling (`perf_event_attr` and the `perf_event_open` syscall wrapper ARE
  in std; the two ioctl numbers are hand-derived from `_IO`/`_IOW` in
  `attach.zig`, and the PMU type id / retprobe bit are read from
  `/sys/bus/event_source/devices/kprobe/`).
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
- **Out of scope (deliberate)**: perfbuf
  (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`), tracepoints, uprobes,
  `BPF_LINK_CREATE`-based attachment, cpumap/devmap attach, tc/classifier
  programs, BTF-typed maps, CO-RE (Compile Once – Run Everywhere) relocation,
  and the `bpftool`-style ELF-skeleton loading route noted above. The three
  named programs and their three attach mechanisms are the whole surface
  this module commits to; extending to a new program or attach kind is
  additive (a new function following the same doc-comment discipline), not
  a redesign. `SPEC.md`'s backlog section says what each deferred item
  would actually take.
