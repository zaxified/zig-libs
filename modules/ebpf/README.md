# ebpf

Pure-Zig **eBPF program generation, object-file loading, attaching, and
ring-buffer consumption** — built on `std.os.linux.BPF`'s instruction
encoders and `bpf()` syscall wrapper, plus the sibling `netlink` module for
the XDP attach path. Two ways in: hand-built programs for a fixed, named set
(`kprobe-counter`, `xdp-filter`, `ringbuf-emit`), or a real
`clang -target bpf` `.o` opened, relocated (including CO-RE) and loaded by
`src/object.zig`.

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

Provenance: clean-room from the kernel UAPI headers (`linux/bpf.h`,
`linux/btf.h`, `linux/perf_event.h`, `linux/if_link.h`) — only the
uncopyrightable ABI facts they document are used (struct layouts, constants,
instruction encoding), under the same Linux-syscall-note exception `netlink` /
`genetlink` / `wireguard` / `tc` rely on. `libbpf` is a **design reference** for
API shape only, no source ported or read while implementing. Both recorded in
the root [`NOTICE`](../../NOTICE).

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
| `src/btf.zig` | **OPUS** | BTF parser: header/strings/type section, every `BTF_KIND_*`, `KFLAG` bitfield offsets, cycle-safe resolution, kernel BTF (`/sys/kernel/btf/vmlinux`), **split** module BTF, `BPF_BTF_LOAD`, a minimal blob `Builder` |
| `src/btfext.zig` | **OPUS** | `.BTF.ext` (`func_info`/`line_info`/`core_relos`) + **partial CO-RE**: field-offset relocation against kernel BTF (see "How much of CO-RE is real" below) |
| `src/tracing.zig` | **OPUS** | attach-by-name for `fentry`/`fexit`/`fmod_ret`/`tp_btf`/LSM, plus the extended `BPF_PROG_LOAD` (`expected_attach_type`, `attach_btf_id`, `prog_btf_fd`, `func_info`, `line_info`) |
| `src/elfsym.zig` | **OPUS** | minimal ELF64 `.symtab`/`.dynsym` reader + the vaddr -> **file offset** conversion a uprobe needs; plus an in-memory `Image` that enumerates sections **by name** (`e_shstrndx`), reads symbols and `SHT_REL` relocations |
| `src/object.zig` | **OPUS** | **BPF object-file loader**: `clang -target bpf` `.o` -> section classification, BTF-defined **and** legacy map specs, map/global-data relocations, **CO-RE instruction patching**, `BPF_MAP_CREATE`/`BPF_MAP_FREEZE`/`BPF_BTF_LOAD`/`BPF_PROG_LOAD` |
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

### BTF: `fentry` / `fexit` / `tp_btf` / LSM attach **by name**

The kernel matches these hooks by BTF type id, not by string. Parsing
`/sys/kernel/btf/vmlinux` is what turns a name into that id — and reading it
needs **no privilege at all** (it is mode 0444); only the attach does.

```zig
// Parse the kernel's own type graph once and keep it: it is ~7 MiB and
// ~170 000 types, so re-reading it per attach is real cost.
var vmlinux = try ebpf.loadKernelBtf(gpa);
defer vmlinux.deinit();

// The id every tracing attach is matched by.
const id = try ebpf.resolveAttachId(&vmlinux, .fentry, "vfs_read");

// Load a program ALREADY TARGETED at it — this is the step that matters:
// the kernel reads `attach_btf_id` at BPF_PROG_LOAD time, not at attach
// time (see src/tracing.zig's header for the exact kernel check).
var log: [8192]u8 = undefined;
var loaded = try ebpf.loadTracing(gpa, .fentry, "vfs_read", &insns, .{
    .attach_btf_id = id,
    .log = &log,
});
defer loaded.close();

// Then attach. The name is re-resolved here only so a typo is a typed
// error instead of a bare EINVAL; the returned id is reported.
var out = try ebpf.attachFentryOpts(gpa, loaded.fd, "vfs_read", .{ .btf = &vmlinux });
defer out.detach();
```

`attachFexit`, `attachModifyReturn`, `attachTpBtf` and `attachLsm` are the
same shape. Pass **bare** names: the `btf_trace_` (for `tp_btf`) and
`bpf_lsm_` (for LSM) prefixes are added for you — and `tp_btf` looks the
result up as a **`BTF_KIND_TYPEDEF`**, not a `FUNC`, which is the one place
a hand-rolled lookup usually goes wrong.

Type-graph queries are available directly:

```zig
const task = vmlinux.findByNameKind("task_struct", .@"struct").?;
const f = (try vmlinux.findMember(task, "pid")).?;   // descends anonymous members
const size = try vmlinux.sizeOf(task);
```

Module (split) BTF needs its base, and says so rather than mis-resolving:

```zig
var mod = try ebpf.loadModuleBtf(gpa, "nf_tables", &vmlinux);
defer mod.deinit();   // ids continue from vmlinux's; base names still resolve
```

Program-side BTF, end to end:

```zig
var b = ebpf.BtfBuilder.init(gpa);
defer b.deinit();
const int_id = try b.addInt("int", 4, 32, 0b001);
const proto  = try b.addFuncProto(int_id, &.{});
_ = try b.addFunc("my_prog", proto, .global);
const blob = try b.finish();
defer gpa.free(blob);

const btf_fd = try ebpf.loadBtfIntoKernel(blob, null);   // BPF_BTF_LOAD
const prog_fd = try ebpf.loadProgram(.tracing, &insns, .{
    .prog_btf_fd = btf_fd,
    .func_info = &.{.{ .insn_off = 0, .type_id = 3 }},
});
```

### How much of CO-RE is real

`.BTF.ext` parsing and **field-offset relocation against kernel BTF** are
implemented and tested against genuine `clang -target bpf -O2 -g` output:

```zig
const ext = try ebpf.parseBtfExt(btf_ext_bytes);
var it = ext.coreRelos();
const sec = it.next().?;
const res = try ebpf.computeCoreFieldRelo(&local_btf, &vmlinux, sec.coreRelo(0));
// res.value = the byte offset THIS kernel puts the field at
// res.field.?.{byte_size, lshift_u64, rshift_u64, signed} for bitfields

// …or with no .BTF.ext at all:
const f = (try ebpf.btfFieldByName(&vmlinux, "task_struct", &.{"pid"})).?;
```

Covered: the container format (including the optional `core_relo` header
tail), access-spec parsing, the local spec walk, name-based candidate
matching with `___flavor` suffixes stripped and anonymous-member descent,
and all six `BPF_CORE_FIELD_*` values including the bitfield load-widening
that makes `LSHIFT_U64`/`RSHIFT_U64` correct.

**Instruction patching is now real too** (`src/object.zig`): the value is no
longer merely returned, it is written back into the instruction — the `off`
field of an `LDX`/`ST`/`STX`, the `imm` of an `ALU`/`ALU64`, both halves of
an `LD_IMM64` pair, and for `FIELD_BYTE_SIZE` the **size bits of the
opcode** itself.

```zig
var obj = try ebpf.openObjectFile(gpa, "probe.bpf.o", .{});
defer obj.deinit();
var vmlinux = try ebpf.loadKernelBtf(gpa);
defer vmlinux.deinit();
const p = obj.findProgram("trace_pid").?;
_ = try ebpf.applyCoreRelos(p, &obj.btf.?, &vmlinux);
// p.insns now reference THIS kernel's field offsets.
```

**Still** not covered, and not pretended: multi-candidate matching and
ambiguity detection (the first name match wins), and the non-field
relocation kinds (`TYPE_ID_*`, `TYPE_EXISTS`, `TYPE_SIZE`, `TYPE_MATCHES`,
`ENUMVAL_*`) — those are parsed and refused with
`error.UnsupportedReloKind`, never computed wrong. See `src/btfext.zig`'s
header and `SPEC.md`'s backlog.

### Loading a real `clang -target bpf` object

```zig
var obj = try ebpf.openObjectFile(gpa, "probe.bpf.o", .{});
defer obj.deinit();          // closes every fd it created

// Inspect before touching the kernel — this whole layer is unprivileged.
for (obj.programs) |p|
    std.debug.print("{s} in {s}: {d} insns, {d} relos\n",
        .{ p.name, p.sec_name, p.insns.len, p.relos.len });
for (obj.maps) |m|
    std.debug.print("{s}: {t} {d}x{d}\n",
        .{ m.name, m.map_type, m.key_size, m.value_size });

// Create maps (seeding + freezing .rodata), BPF_BTF_LOAD the object's BTF,
// relocate, and BPF_PROG_LOAD everything.
ebpf.loadObject(&obj, .{}) catch |e| {
    std.debug.print("{s} rejected: {s}\n", .{ obj.failed_program, obj.verifier_log });
    return e;
};

// Attaching stays the existing surface.
const fd = obj.programFd("count_open").?;
var kp = try ebpf.attachKprobe(gpa, "do_sys_openat2", fd);
defer kp.detach();

const map_fd = obj.mapFd("counts").?;
```

What it handles: program sections named by attach type (the full
section-name -> `prog_type`/`expected_attach_type` table, longest-prefix
match, so `xdp/devmap` does not degrade to `xdp`), `.maps` BTF-defined map
definitions (`__uint`/`__type`, whose values come out of the **BTF type
graph** — `__uint(max_entries, 1024)` is a pointer to an array of 1024
ints), the legacy `maps` section (which libbpf 1.0 dropped entirely),
`license`, `version`, `.BTF`/`.BTF.ext`, `.rodata`/`.data`/`.bss` as
internal single-entry `ARRAY` maps, `.rel<section>` map-fd and
global-data relocations, per-program `func_info`/`line_info` slicing with
`insn_off` rebased from ELF byte offsets to instruction indices, the
`DATASEC` size/offset fixup `BPF_BTF_LOAD` requires, and a verifier log
grown from `log_true_size` so it is never truncated.

What it refuses with a typed error naming the symbol, rather than emitting a
silently broken program: `error.SubprogramCallsUnsupported` (a
`R_BPF_64_32` call into `.text`), `error.ExternSymbolUnsupported` (kfuncs,
extern kconfig/ksym), `error.MapInMapUnsupported` (a `values` member),
`error.PinningUnsupported`.

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
  `.xdp`), `AttachType` (incl. `.cgroup_inet_egress`, `.xdp`, `.trace_fentry`,
  `.trace_raw_tp`, `.lsm_mac`), `Helper` (the full `bpf_*` in-program
  helper-function id list).
- **The BTF *wire structs***: `std.os.linux.BPF.btf` declares `Header`,
  `Type`, `Kind`, `Member`, `Array`, `Enum`, `Enum64`, `Param`, `Var`,
  `VarSecInfo`, `DeclTag` (and `btf.ext` declares the short `.BTF.ext`
  header + `InfoSec`). `btf.zig` reuses `Kind` directly and asserts the rest
  against std's layout instead of restating them.

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
- Any BTF **parser**. std has the structs (above) and nothing that walks
  them: no type-id index, no string-section lookup, no
  `/sys/kernel/btf/vmlinux` reader, no split-BTF handling, no bounds
  checking — and its `btf.Type.info.kind` / `btf.IntInfo.encoding` are
  `enum`s too narrow to hold real kernel BTF (`encoding == 0`, a plain
  `unsigned int`, is not one of `IntInfo.encoding`'s three values), so a
  `@ptrCast` onto them is not a safe parse. See `btf.zig`.
- `.BTF.ext` beyond the pre-5.16 header: std's `btf.ext.Header` has no
  `core_relo_off`/`_len`, no `bpf_func_info`/`bpf_line_info`/`bpf_core_relo`
  record structs, and no framing walk. See `btfext.zig`.
- The **extended** `bpf_attr.prog_load`: std's `ProgLoadAttr` stops at
  `attach_prog_id`, so `core_relo*`, `fd_array`, `log_true_size` and
  `prog_token_fd` are missing and there is no way to send them. See
  `tracing.zig`.
- A wrapper for `Cmd.btf_load` (`BtfLoadAttr` exists and stops at
  `btf_log_level`; the function does not exist at all).
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
repo) and a per-object build step. The other half of that objection —
"an ELF object parser to pull the resulting `.text`/maps sections back out,
plus BTF handling for modern map definitions" — **no longer applies**:
`src/object.zig` is exactly that loader, so a Zig-source BPF program would
now only need the second compilation unit, not the loading machinery. Still
not worth a second target triple for three fixed programs; worth revisiting
if this module ever needs to generate large or many programs.

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
- **`elfsym` is a uprobe helper plus a BPF-object reader, not an ELF
  library.** It reads what a probe needs (`.symtab`/`.dynsym` + `PT_LOAD`),
  and — since the object loader landed — what a relocatable `.o` needs
  (section names via `e_shstrndx`, symbols, `SHT_REL` entries). It still
  refuses everything else (32-bit, foreign-endian) rather than guessing.
  There is **one** ELF decoder shared by both, not two: the section-header
  decode and the field-offset constants are the same code.
- **`object.zig` classifies before it creates.** Parsing, map-spec
  extraction, relocation classification, `.BTF.ext` slicing and instruction
  patching all happen with no syscall at all, so the exact bytes handed to
  `bpf()` are asserted in unprivileged tests against real clang objects. The
  syscalls are the only untested surface on a box without `CAP_BPF`.
- **A `.rodata` map is created, seeded, and then FROZEN.** That order is not
  cosmetic: `BPF_F_RDONLY_PROG` plus `BPF_MAP_FREEZE` is what lets the
  verifier treat the array's contents as known constants, which is the whole
  mechanism behind `const volatile` configuration globals.
- **BTF is untrusted input, and treated as such.** `/sys/kernel/btf/vmlinux`
  is trustworthy; a `.BTF` section out of somebody's object file is not.
  `btf.parse` walks the whole type section once, sizing every record, so no
  later accessor can read out of bounds; every resolving walk is bounded by
  `max_resolve_depth` so a cyclic typedef terminates; and split BTF is
  *detected* (a base blob's string section starts with `"\0"`, a split one's
  does not) rather than silently mis-resolved. `SPEC.md` has the full list.
- **A BTF id that matters is set at LOAD time, not attach time.** For
  fentry/fexit the kernel reads `attach_btf_id` from `BPF_PROG_LOAD` and
  rejects a link that also carries one (`!!tgt_prog_fd != !!btf_id` ->
  `EINVAL`). `tracing.zig` therefore resolves the name at attach *for the
  error message and for reporting*, and `loadTracing` is the call that
  actually targets the program. Anything else would look like it worked and
  attach nowhere.
- **Out of scope (deliberate)**: the rest of CO-RE —
  multi-candidate/ambiguity matching and the non-field relocation kinds (see
  "How much of CO-RE is real" above; **instruction patching moved OUT of
  this list**) — plus, inside the object loader, sub-program (`.text`) call
  linking, kfunc/extern/ksym resolution, `struct_ops` map value population,
  map-in-map (`values`) initialization, bpffs pinning, and `mmap`-able
  global-data maps with a generated skeleton struct. Outside it:
  `kprobe_multi`/`uprobe_multi` mass-attach, USDT `.note.stapsdt` discovery,
  `tcx`/`netkit` attach entry points, `BPF_PROG_QUERY`, cpumap/devmap
  attach, perf AUX/ITRACE areas, DWARF/line and symbol demangling, and
  tc/classifier program builders. Every one of the loader's gaps is a typed
  error naming the symbol, not a silent mis-load. `SPEC.md`'s backlog
  section says what each deferred item would actually take.
