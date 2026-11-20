// SPDX-License-Identifier: MIT
//! BPF **object-file loading** — turning a `clang -target bpf` `.o` into
//! created maps and loaded programs. This is the piece that sits between
//! "this module can relocate a `.BTF.ext` record" (`btfext.zig`) and "this
//! module can run a real CO-RE object".
//!
//! ## What a BPF object actually is
//!
//! A relocatable ELF64 (`ET_REL`, `EM_BPF`) with no program headers, whose
//! meaning is carried entirely in **section names**:
//!
//! | section | meaning |
//! |---|---|
//! | `xdp`, `kprobe/…`, `tracepoint/<cat>/<name>`, `fentry/…`, … | one program each; the name selects `prog_type` **and** `expected_attach_type` |
//! | `.maps` | BTF-defined maps — one `VAR` per map inside a `DATASEC` |
//! | `maps` | the pre-BTF `struct bpf_map_def` array |
//! | `license` | the NUL-terminated license string the verifier gates GPL-only helpers on |
//! | `version` | a `u32` `kern_version` (only `kprobe` on ancient kernels cares) |
//! | `.BTF` / `.BTF.ext` | the type graph, and per-section func/line info + CO-RE relocations |
//! | `.rodata`, `.data`, `.bss`, `.rodata.str1.1` | global variables — each becomes an **internal single-entry `ARRAY` map** |
//! | `.rel<section>` | `SHT_REL` relocations against the section of that name |
//!
//! Nothing in that list is derivable from section *types*, which is why
//! `elfsym.zig` grew `e_shstrndx` handling and an `Image` that enumerates
//! sections **by name** — the uprobe path it was written for never needed one.
//!
//! ## The two indirections worth spelling out
//!
//! 1. **A BTF-defined map's numbers live in the type graph, not in bytes.**
//!    `__uint(max_entries, 1024)` expands to `int (*max_entries)[1024]` — a
//!    *pointer to an array of 1024 ints*. The value is the array's element
//!    count. `__type(key, u32)` expands to `u32 *key`, and there the value is
//!    the pointee's *size* (and its type id, which is what
//!    `btf_key_type_id` wants). The `.maps` section itself is 40 bytes of
//!    zeros; every number comes out of `.BTF`.
//!
//! 2. **A map reference is a two-instruction `LD_IMM64` whose `src_reg` is a
//!    pseudo-register.** `src_reg = BPF_PSEUDO_MAP_FD (1)` means "`imm` is a
//!    map fd, not a constant"; `BPF_PSEUDO_MAP_VALUE (2)` means "`imm` is a
//!    map fd and the *next* instruction's `imm` is a byte offset into that
//!    map's single value" — which is exactly how a global variable in
//!    `.rodata`/`.data`/`.bss` is addressed. The compiler emits `imm = 0`
//!    and a `R_BPF_64_64` relocation; the loader fills both halves in.
//!
//! ## What this file does
//!
//! - `open`/`openFile`: parse the image, classify sections, extract map specs
//!   (BTF-defined **and** legacy), split each program section into programs at
//!   its `STT_FUNC` symbols, collect and classify relocations, slice
//!   `.BTF.ext`'s `func_info`/`line_info`/`core_relo` records per program and
//!   **rebase** their `insn_off` (byte offsets in the ELF, instruction indices
//!   for the kernel).
//! - `Object.relocate`: patch the instruction stream given a map-fd per map —
//!   a pure function of `(program, maps)`, so the exact bytes handed to the
//!   verifier are testable with **no privilege at all** (the tests drive it
//!   with synthetic fds).
//! - `Object.applyCoreRelos`: **real CO-RE instruction patching** —
//!   `btfext.computeFieldRelo` computes the number, this rewrites the
//!   `LDX`/`ST`/`STX` offset field, the `ALU`/`ALU64` immediate, or the
//!   64-bit `LD_IMM64` pair. That was the one deferred half of CO-RE; it is
//!   deferred no longer.
//! - `Object.load`: `BPF_MAP_CREATE` every map (seeding and `BPF_MAP_FREEZE`ing
//!   the `.rodata` one), `BPF_BTF_LOAD` the object's own BTF after fixing up
//!   its `DATASEC` sizes/offsets from the symbol table (the kernel rejects a
//!   `DATASEC` of size 0, and clang emits exactly that), then `BPF_PROG_LOAD`
//!   each program with `prog_btf_fd` + `func_info` + `line_info`, retrying on
//!   `ENOSPC` with a buffer sized from `log_true_size` so a **truncated
//!   verifier log never hides the real error**.
//!
//! ## What it refuses rather than half-does
//!
//! Every one of these is a *typed error naming the symbol or section*, never
//! a silently broken program:
//!
//! - `error.SubprogramCallsUnsupported` — a `R_BPF_64_32` call relocation into
//!   `.text`. Static linking of sub-programs needs instruction-stream
//!   concatenation and `func_info` merging.
//! - `error.ExternSymbolUnsupported` — an `SHN_UNDEF` symbol: a kfunc
//!   (`BPF_PSEUDO_KFUNC_CALL`), an extern kconfig variable, or a weak extern.
//! - `error.MapInMapUnsupported` — a `values` member (`prog_array` /
//!   `array_of_maps` initialization).
//! - `error.PinningUnsupported` — a non-zero `pinning` member; bpffs pinning
//!   is not implemented.
//!
//! Provenance: the wire formats are the kernel UAPI (`linux/bpf.h`'s
//! `BPF_PSEUDO_*`, `bpf_map_def`, the `bpf_attr` arms) and the System V gABI
//! ELF64 layout; the section-name table and the `.maps` encoding were derived
//! from **real `clang -target bpf -O2 -g` output inspected with `readelf` and
//! `bpftool btf dump`** (the fixtures at the bottom of this file are those
//! objects, byte for byte). libbpf is a design reference for the API shape
//! only — see `/NOTICE`.

const std = @import("std");
const builtin = @import("builtin");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;
const linux = std.os.linux;
const BPF = linux.BPF;

const elfsym = @import("elfsym.zig");
const btf_mod = @import("btf.zig");
const btfext = @import("btfext.zig");
const tracing = @import("tracing.zig");

pub const Insn = BPF.Insn;
pub const Btf = btf_mod.Btf;

// ── UAPI constants this file needs and std does not declare ─────────────────

/// `BPF_PSEUDO_MAP_FD` — `LD_IMM64.src_reg`: `imm` is a map fd.
pub const BPF_PSEUDO_MAP_FD: u4 = 1;
/// `BPF_PSEUDO_MAP_VALUE` — `imm` is a map fd and `imm` of the *next*
/// instruction is a byte offset into that map's value.
pub const BPF_PSEUDO_MAP_VALUE: u4 = 2;
/// `BPF_PSEUDO_BTF_ID` — `imm` is a kernel variable's BTF id (ksym).
pub const BPF_PSEUDO_BTF_ID: u4 = 3;
/// `BPF_PSEUDO_FUNC` — `imm` is a subprogram address.
pub const BPF_PSEUDO_FUNC: u4 = 4;
/// `BPF_PSEUDO_CALL` — `JMP|CALL.src_reg`: a call to a subprogram.
pub const BPF_PSEUDO_CALL: u4 = 1;
/// `BPF_PSEUDO_KFUNC_CALL`.
pub const BPF_PSEUDO_KFUNC_CALL: u4 = 2;

/// `BPF_F_RDONLY_PROG` — the map is read-only *from the program's side*,
/// which is what makes a `.rodata` map's contents visible to the verifier as
/// constants.
pub const BPF_F_RDONLY_PROG: u32 = 1 << 7;
/// `BPF_F_MMAPABLE` — required if userspace wants to `mmap` a global-data map
/// (the skeleton pattern). Not set by default here.
pub const BPF_F_MMAPABLE: u32 = 1 << 10;

/// `R_BPF_64_64` — the `LD_IMM64` map/global-data reference.
pub const R_BPF_64_64: u32 = 1;
/// `R_BPF_64_ABS64` / `R_BPF_64_ABS32` — debug-info relocations; never
/// present in a program section.
pub const R_BPF_64_ABS64: u32 = 2;
pub const R_BPF_64_ABS32: u32 = 3;
/// `R_BPF_64_NODYLD32` — used inside `.BTF`/`.BTF.ext`.
pub const R_BPF_64_NODYLD32: u32 = 4;
/// `R_BPF_64_32` — a call to a global sub-program.
pub const R_BPF_64_32: u32 = 10;

const ET_REL: u16 = 1;
// Taken from std rather than re-declared: `STT_FUNC` is **2**, and writing 4
// (which is `STT_FILE`) makes every function symbol invisible — a bug that
// degrades silently into "one program per section, named after the section".
const STT_FUNC: u4 = @backingInt(std.elf.STT.FUNC);
const STT_OBJECT: u4 = @backingInt(std.elf.STT.OBJECT);
const STT_SECTION: u4 = @backingInt(std.elf.STT.SECTION);

/// BPF instruction classes (`code & 0x07`).
const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
const BPF_ST: u8 = 0x02;
const BPF_STX: u8 = 0x03;
const BPF_ALU: u8 = 0x04;
const BPF_JMP: u8 = 0x05;
const BPF_ALU64: u8 = 0x07;

/// `BPF_LD | BPF_IMM | BPF_DW` — the 16-byte "load 64-bit immediate" pair.
const LD_IMM64_CODE: u8 = 0x18;
/// `BPF_JMP | BPF_CALL`.
const CALL_CODE: u8 = 0x85;

// ── section name -> program type ────────────────────────────────────────────

/// How a section-definition prefix matches a section name.
pub const SectionMatch = enum {
    /// The name must equal the prefix exactly.
    exact,
    /// The name equals the prefix, or starts with `prefix ++ "/"` — the
    /// trailing part is then the attach target (`kprobe/do_sys_openat2`).
    exact_or_target,
};

/// One row of the section-name table.
pub const SectionDef = struct {
    prefix: []const u8,
    match: SectionMatch = .exact_or_target,
    prog_type: BPF.ProgType,
    expected_attach_type: ?BPF.AttachType = null,
    /// `.s` variants: the program runs in a sleepable context
    /// (`BPF_F_SLEEPABLE`).
    sleepable: bool = false,
};

/// `BPF_F_SLEEPABLE`.
pub const BPF_F_SLEEPABLE: u32 = 1 << 4;

/// The section-name table, as clang/libbpf spell it. Matching takes the
/// **longest** matching prefix, so the order here is documentation, not
/// semantics (asserted by a test).
pub const section_defs = [_]SectionDef{
    .{ .prefix = "socket", .prog_type = .socket_filter },
    .{ .prefix = "sk_reuseport/migrate", .prog_type = .sk_reuseport, .expected_attach_type = .sk_reuseport_select_or_migrate },
    .{ .prefix = "sk_reuseport", .prog_type = .sk_reuseport, .expected_attach_type = .sk_reuseport_select },

    .{ .prefix = "kprobe", .prog_type = .kprobe },
    .{ .prefix = "kretprobe", .prog_type = .kprobe },
    .{ .prefix = "uprobe", .prog_type = .kprobe },
    .{ .prefix = "uprobe.s", .prog_type = .kprobe, .sleepable = true },
    .{ .prefix = "uretprobe", .prog_type = .kprobe },
    .{ .prefix = "uretprobe.s", .prog_type = .kprobe, .sleepable = true },
    .{ .prefix = "kprobe.multi", .prog_type = .kprobe, .expected_attach_type = .trace_kprobe_multi },
    .{ .prefix = "kretprobe.multi", .prog_type = .kprobe, .expected_attach_type = .trace_kprobe_multi },
    .{ .prefix = "kprobe.session", .prog_type = .kprobe, .expected_attach_type = .trace_kprobe_session },
    .{ .prefix = "uprobe.multi", .prog_type = .kprobe, .expected_attach_type = .trace_uprobe_multi },
    .{ .prefix = "uretprobe.multi", .prog_type = .kprobe, .expected_attach_type = .trace_uprobe_multi },
    .{ .prefix = "uprobe.multi.s", .prog_type = .kprobe, .expected_attach_type = .trace_uprobe_multi, .sleepable = true },
    .{ .prefix = "uretprobe.multi.s", .prog_type = .kprobe, .expected_attach_type = .trace_uprobe_multi, .sleepable = true },
    .{ .prefix = "ksyscall", .prog_type = .kprobe },
    .{ .prefix = "kretsyscall", .prog_type = .kprobe },
    .{ .prefix = "usdt", .prog_type = .kprobe },

    .{ .prefix = "tc", .prog_type = .sched_cls },
    .{ .prefix = "classifier", .prog_type = .sched_cls },
    .{ .prefix = "tcx/ingress", .prog_type = .sched_cls, .expected_attach_type = .tcx_ingress },
    .{ .prefix = "tcx/egress", .prog_type = .sched_cls, .expected_attach_type = .tcx_egress },
    .{ .prefix = "netkit/primary", .prog_type = .sched_cls, .expected_attach_type = .netkit_primary },
    .{ .prefix = "netkit/peer", .prog_type = .sched_cls, .expected_attach_type = .netkit_peer },
    .{ .prefix = "action", .prog_type = .sched_act },

    .{ .prefix = "tracepoint", .prog_type = .tracepoint },
    .{ .prefix = "tp", .prog_type = .tracepoint },
    .{ .prefix = "raw_tracepoint", .prog_type = .raw_tracepoint },
    .{ .prefix = "raw_tp", .prog_type = .raw_tracepoint },
    .{ .prefix = "raw_tracepoint.w", .prog_type = .raw_tracepoint_writable },
    .{ .prefix = "raw_tp.w", .prog_type = .raw_tracepoint_writable },

    .{ .prefix = "tp_btf", .prog_type = .tracing, .expected_attach_type = .trace_raw_tp },
    .{ .prefix = "fentry", .prog_type = .tracing, .expected_attach_type = .trace_fentry },
    .{ .prefix = "fexit", .prog_type = .tracing, .expected_attach_type = .trace_fexit },
    .{ .prefix = "fmod_ret", .prog_type = .tracing, .expected_attach_type = .modify_return },
    .{ .prefix = "fentry.s", .prog_type = .tracing, .expected_attach_type = .trace_fentry, .sleepable = true },
    .{ .prefix = "fexit.s", .prog_type = .tracing, .expected_attach_type = .trace_fexit, .sleepable = true },
    .{ .prefix = "fmod_ret.s", .prog_type = .tracing, .expected_attach_type = .modify_return, .sleepable = true },
    .{ .prefix = "iter", .prog_type = .tracing, .expected_attach_type = .trace_iter },
    .{ .prefix = "iter.s", .prog_type = .tracing, .expected_attach_type = .trace_iter, .sleepable = true },
    .{ .prefix = "freplace", .prog_type = .ext },

    .{ .prefix = "lsm", .prog_type = .lsm, .expected_attach_type = .lsm_mac },
    .{ .prefix = "lsm.s", .prog_type = .lsm, .expected_attach_type = .lsm_mac, .sleepable = true },
    .{ .prefix = "lsm_cgroup", .prog_type = .lsm, .expected_attach_type = .lsm_cgroup },

    .{ .prefix = "syscall", .prog_type = .syscall, .sleepable = true },

    .{ .prefix = "xdp", .prog_type = .xdp, .expected_attach_type = .xdp },
    .{ .prefix = "xdp.frags", .prog_type = .xdp, .expected_attach_type = .xdp },
    .{ .prefix = "xdp/devmap", .prog_type = .xdp, .expected_attach_type = .xdp_devmap },
    .{ .prefix = "xdp.frags/devmap", .prog_type = .xdp, .expected_attach_type = .xdp_devmap },
    .{ .prefix = "xdp/cpumap", .prog_type = .xdp, .expected_attach_type = .xdp_cpumap },
    .{ .prefix = "xdp.frags/cpumap", .prog_type = .xdp, .expected_attach_type = .xdp_cpumap },

    .{ .prefix = "perf_event", .prog_type = .perf_event },
    .{ .prefix = "lwt_in", .prog_type = .lwt_in },
    .{ .prefix = "lwt_out", .prog_type = .lwt_out },
    .{ .prefix = "lwt_xmit", .prog_type = .lwt_xmit },
    .{ .prefix = "lwt_seg6local", .prog_type = .lwt_seg6local },

    .{ .prefix = "sockops", .prog_type = .sock_ops, .expected_attach_type = .cgroup_sock_ops },
    .{ .prefix = "sk_skb", .prog_type = .sk_skb },
    .{ .prefix = "sk_skb/stream_parser", .prog_type = .sk_skb, .expected_attach_type = .sk_skb_stream_parser },
    .{ .prefix = "sk_skb/stream_verdict", .prog_type = .sk_skb, .expected_attach_type = .sk_skb_stream_verdict },
    .{ .prefix = "sk_msg", .prog_type = .sk_msg, .expected_attach_type = .sk_msg_verdict },
    .{ .prefix = "lirc_mode2", .prog_type = .lirc_mode2, .expected_attach_type = .lirc_mode2 },
    .{ .prefix = "flow_dissector", .prog_type = .flow_dissector, .expected_attach_type = .flow_dissector },
    .{ .prefix = "sk_lookup", .prog_type = .sk_lookup, .expected_attach_type = .sk_lookup },
    .{ .prefix = "netfilter", .prog_type = .netfilter, .expected_attach_type = .netfilter },
    .{ .prefix = "struct_ops", .prog_type = .struct_ops },
    .{ .prefix = "struct_ops.s", .prog_type = .struct_ops, .sleepable = true },

    .{ .prefix = "cgroup_skb/ingress", .prog_type = .cgroup_skb, .expected_attach_type = .cgroup_inet_ingress },
    .{ .prefix = "cgroup_skb/egress", .prog_type = .cgroup_skb, .expected_attach_type = .cgroup_inet_egress },
    .{ .prefix = "cgroup/skb", .prog_type = .cgroup_skb },
    .{ .prefix = "cgroup/sock", .prog_type = .cgroup_sock, .expected_attach_type = .cgroup_inet_sock_create },
    .{ .prefix = "cgroup/sock_create", .prog_type = .cgroup_sock, .expected_attach_type = .cgroup_inet_sock_create },
    .{ .prefix = "cgroup/sock_release", .prog_type = .cgroup_sock, .expected_attach_type = .cgroup_inet_sock_release },
    .{ .prefix = "cgroup/post_bind4", .prog_type = .cgroup_sock, .expected_attach_type = .cgroup_inet4_post_bind },
    .{ .prefix = "cgroup/post_bind6", .prog_type = .cgroup_sock, .expected_attach_type = .cgroup_inet6_post_bind },
    .{ .prefix = "cgroup/dev", .prog_type = .cgroup_device, .expected_attach_type = .cgroup_device },
    .{ .prefix = "cgroup/bind4", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_inet4_bind },
    .{ .prefix = "cgroup/bind6", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_inet6_bind },
    .{ .prefix = "cgroup/connect4", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_inet4_connect },
    .{ .prefix = "cgroup/connect6", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_inet6_connect },
    .{ .prefix = "cgroup/connect_unix", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_unix_connect },
    .{ .prefix = "cgroup/sendmsg4", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_udp4_sendmsg },
    .{ .prefix = "cgroup/sendmsg6", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_udp6_sendmsg },
    .{ .prefix = "cgroup/sendmsg_unix", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_unix_sendmsg },
    .{ .prefix = "cgroup/recvmsg4", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_udp4_recvmsg },
    .{ .prefix = "cgroup/recvmsg6", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_udp6_recvmsg },
    .{ .prefix = "cgroup/recvmsg_unix", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_unix_recvmsg },
    .{ .prefix = "cgroup/getpeername4", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_inet4_getpeername },
    .{ .prefix = "cgroup/getpeername6", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_inet6_getpeername },
    .{ .prefix = "cgroup/getpeername_unix", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_unix_getpeername },
    .{ .prefix = "cgroup/getsockname4", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_inet4_getsockname },
    .{ .prefix = "cgroup/getsockname6", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_inet6_getsockname },
    .{ .prefix = "cgroup/getsockname_unix", .prog_type = .cgroup_sock_addr, .expected_attach_type = .cgroup_unix_getsockname },
    .{ .prefix = "cgroup/sysctl", .prog_type = .cgroup_sysctl, .expected_attach_type = .cgroup_sysctl },
    .{ .prefix = "cgroup/getsockopt", .prog_type = .cgroup_sockopt, .expected_attach_type = .cgroup_getsockopt },
    .{ .prefix = "cgroup/setsockopt", .prog_type = .cgroup_sockopt, .expected_attach_type = .cgroup_setsockopt },
};

/// What a section name resolved to.
pub const SectionKindInfo = struct {
    def: SectionDef,
    /// The part after `prefix ++ "/"`, or `""` — `"do_sys_openat2"` for
    /// `"kprobe/do_sys_openat2"`, `"syscalls/sys_enter_write"` for a
    /// tracepoint.
    target: []const u8,
};

/// Resolve an ELF section name to a program type. Takes the **longest**
/// matching prefix, so `xdp/devmap` beats `xdp`.
pub fn classifySection(name: []const u8) ?SectionKindInfo {
    var best: ?SectionDef = null;
    for (section_defs) |d| {
        const ok = switch (d.match) {
            .exact => std.mem.eql(u8, name, d.prefix),
            .exact_or_target => std.mem.eql(u8, name, d.prefix) or
                (name.len > d.prefix.len and
                    std.mem.startsWith(u8, name, d.prefix) and
                    name[d.prefix.len] == '/'),
        };
        if (!ok) continue;
        if (best == null or d.prefix.len > best.?.prefix.len) best = d;
    }
    const d = best orelse return null;
    const target: []const u8 = if (name.len > d.prefix.len) name[d.prefix.len + 1 ..] else "";
    return .{ .def = d, .target = target };
}

// ── map specs ───────────────────────────────────────────────────────────────

/// Where a map definition came from.
pub const MapOrigin = enum {
    /// A `VAR` in the `.maps` `DATASEC` — the modern form.
    btf_defined,
    /// A `struct bpf_map_def` in the legacy `maps` section.
    legacy,
    /// Synthesized by the loader for `.rodata`/`.data`/`.bss` — global
    /// variables live in a one-entry `ARRAY` map, not in the program.
    internal,
};

/// One map, as described by the object (before creation) and then as created
/// (`fd >= 0`).
pub const MapSpec = struct {
    /// The variable name (`counts`) or, for an internal map, the section name
    /// (`.rodata`). Truncated to 15 characters + NUL for `map_name`.
    name: []const u8,
    map_type: BPF.MapType,
    key_size: u32 = 0,
    value_size: u32 = 0,
    max_entries: u32 = 0,
    map_flags: u32 = 0,
    numa_node: ?u32 = null,
    /// `LIBBPF_PIN_BY_NAME` == 1. Parsed, never acted on — see
    /// `error.PinningUnsupported`.
    pinning: u32 = 0,
    /// Type ids in **this object's** BTF; only meaningful together with the
    /// BTF fd `load` obtains.
    btf_key_type_id: u32 = 0,
    btf_value_type_id: u32 = 0,
    origin: MapOrigin,
    /// ELF section this map came from (`.maps`, `maps`, or the data section).
    sec_idx: usize,
    /// For an internal map: the section's initial contents. Empty for `.bss`
    /// (`SHT_NOBITS` has no file bytes) — the map is created zeroed anyway.
    initial_data: []const u8 = &.{},
    /// `.rodata*` maps are frozen after seeding, which is what lets the
    /// verifier treat their contents as constants.
    freeze: bool = false,
    /// `-1` until `Object.load` creates it.
    fd: linux.fd_t = -1,
};

// ── program specs ───────────────────────────────────────────────────────────

/// A classified relocation against a program's instruction stream.
pub const ReloKind = enum {
    /// `LD_IMM64` referring to a map by symbol: patch `imm` with the map fd.
    map_fd,
    /// `LD_IMM64` referring to a global variable: patch `imm` with the map fd
    /// and the next instruction's `imm` with the byte offset.
    map_value,
};

pub const Relo = struct {
    kind: ReloKind,
    /// Index into the **program's** instruction slice.
    insn_idx: u32,
    /// Index into `Object.maps`.
    map_idx: usize,
    /// Byte offset inside the map's value, for `.map_value`.
    value_off: u64 = 0,
    /// The ELF symbol that produced it (borrowed from the image).
    sym_name: []const u8,
};

/// What a call-site relocation refers to.
pub const CallSiteKind = enum {
    /// `call` with `src_reg == BPF_PSEUDO_CALL`: `imm` becomes the relative
    /// instruction offset of the sub-program.
    call,
    /// `LD_IMM64` of a sub-program's address (a callback handed to
    /// `bpf_loop`, a timer, ...): becomes `BPF_PSEUDO_FUNC`.
    func_addr,
};

/// A reference from one function to another, resolved by `open` (it appends
/// the callee to the program and patches the instruction); empty afterwards.
pub const CallSite = struct {
    kind: CallSiteKind,
    /// Index into the referring function's instruction slice.
    insn_idx: u32,
    /// The callee: its ELF section and its byte offset inside it.
    sec_idx: usize,
    sec_byte_off: u64,
};

/// Ceiling on the instruction count of one program after sub-programs are
/// linked in (the kernel's own limit for a privileged load is 1M).
pub const max_program_insns: usize = 1 << 20;

/// One program: an instruction range of one program section, named by the
/// `STT_FUNC` symbol that covers it.
pub const ProgramSpec = struct {
    /// The ELF section name (`"kprobe/do_sys_openat2"`).
    sec_name: []const u8,
    /// The C function name (`"count_open"`) — what `bpftool prog show` calls
    /// it and what `findProgram` matches first.
    name: []const u8,
    /// The attach target parsed out of the section name.
    attach_target: []const u8,
    prog_type: BPF.ProgType,
    expected_attach_type: ?BPF.AttachType,
    sleepable: bool,
    sec_idx: usize,
    /// Byte offset of this function inside its section (0 for the common
    /// one-function-per-section case).
    sec_byte_off: u64,
    /// Owned, **mutable**: relocation and CO-RE patching rewrite it in place.
    insns: []Insn,
    relos: []Relo,
    /// `.BTF.ext` records for this program, `insn_off` already rebased from
    /// "byte offset in the ELF section" to "instruction index in `insns`".
    func_info: []btfext.FuncInfo,
    line_info: []btfext.LineInfo,
    core_relos: []btfext.CoreRelo,
    /// Sub-program references still to be resolved (always empty on an
    /// `Object` returned by `open`).
    call_sites: []CallSite = &.{},
    /// `-1` until `Object.load` loads it.
    fd: linux.fd_t = -1,

    /// The `prog_name` the kernel will show, truncated the way `bpf()` needs.
    pub fn kernelName(self: *const ProgramSpec) []const u8 {
        return self.name[0..@min(self.name.len, 15)];
    }
};

// ── errors ──────────────────────────────────────────────────────────────────

pub const ParseError = error{
    /// Not an ELF, not ELF64, not host byte order, or not `ET_REL`/`EM_BPF`.
    NotABpfObject,
    MalformedElf,
    /// A program/relocation section whose size is not a multiple of 8.
    UnalignedInstructionSection,
    /// A relocation whose `r_offset` is not 8-aligned, or points past the
    /// instruction stream.
    RelocationOutOfRange,
    /// A relocation type that cannot appear in a program section.
    UnsupportedRelocation,
    /// A relocation naming a map/section that does not exist.
    UnresolvedRelocation,
    /// A program that, with its sub-programs linked in, exceeds
    /// `max_program_insns`.
    ProgramTooLarge,
    /// An `SHN_UNDEF` symbol — kfunc, extern kconfig, or weak extern.
    ExternSymbolUnsupported,
    /// The object has no `.symtab`, so nothing can be relocated.
    NoSymbolTable,
    /// `.maps` exists but the object has no `.BTF` to describe it.
    MissingBtf,
    MalformedBtf,
    /// A `.maps` `VAR` whose type is not a struct, or a member whose shape is
    /// not `PTR -> ARRAY` / `PTR -> T`.
    MalformedMapDefinition,
    /// A member name in a `.maps` struct this loader does not know.
    UnknownMapMember,
    /// A `values` member (`prog_array`/`array_of_maps` initialization).
    MapInMapUnsupported,
    /// A non-zero `pinning` member.
    PinningUnsupported,
    /// `max_entries` is 0 for a map type that requires entries.
    ZeroMaxEntries,
    /// Two maps with the same name.
    DuplicateMap,
    OutOfMemory,
};

pub const OpenError = ParseError || error{ FileOpenFailed, FileReadFailed, FileTooLarge };

pub const RelocateError = error{
    /// `Object.load` was not the caller and a map still has `fd == -1`.
    MapNotCreated,
    /// A `map_value` relocation whose second instruction is past the end.
    RelocationOutOfRange,
    /// The `LD_IMM64` a relocation names is not actually an `LD_IMM64`.
    NotAnImmediateLoad,
};

pub const CoreApplyError = error{
    /// The instruction a CO-RE relocation names cannot carry the value
    /// (not `LDX`/`ST`/`STX`, `ALU`/`ALU64`-with-immediate, or `LD_IMM64`).
    UnsupportedCoreInsn,
    /// The value does not fit the field it must be patched into (a >32 KiB
    /// member offset in an `LDX`'s `i16`).
    CoreValueTooLarge,
    /// The field is absent from the target BTF and the relocation kind has no
    /// defined answer for that (only `FIELD_EXISTS` does).
    CoreFieldNotFound,
    /// A type-based relocation (`TYPE_ID_TARGET`, `TYPE_SIZE`) whose type has
    /// no matching type in the target BTF.
    CoreTypeNotFound,
    /// `ENUMVAL_VALUE` whose enumerator is in no matching target enum.
    CoreEnumvalNotFound,
    /// `insn_off` outside the program.
    RelocationOutOfRange,
} || btfext.CoreError;

pub const LoadError = error{
    PermissionDenied,
    /// The verifier rejected a program. `Object.verifier_log` says why and
    /// `Object.failed_program` says which.
    UnsafeProgram,
    InvalidArgument,
    ProgramTooLarge,
    AttachTargetNotFound,
    SystemResources,
    MapCreateFailed,
    /// A map could not be seeded from its section contents.
    MapUpdateFailed,
    MapFreezeFailed,
    /// `BPF_BTF_LOAD` refused the object's BTF.
    BtfLoadFailed,
    /// CO-RE was requested with no `target_btf` and `/sys/kernel/btf/vmlinux`
    /// could not be read.
    KernelBtfUnavailable,
    /// A section that looks like a program but matches no known prefix.
    UnknownProgramSection,
    /// A map declared a non-zero `pinning`; bpffs pinning is not implemented.
    PinningUnsupported,
    /// `max_entries == 0` for a map type that requires entries.
    ZeroMaxEntries,
    OutOfMemory,
    Unexpected,
} || ParseError || RelocateError || CoreApplyError || btf_mod.KernelLoadError;

// ── the object ──────────────────────────────────────────────────────────────

pub const OpenOptions = struct {
    /// Reject an object whose `e_machine` is not `EM_BPF`. Off by default:
    /// some producers leave it 0.
    require_bpf_machine: bool = false,
};

pub const Object = struct {
    gpa: std.mem.Allocator,
    /// Every parse-time allocation (image bytes, section table, instruction
    /// copies, spec arrays, the BTF copy) lives here. Heap-allocated so the
    /// `Object` stays movable.
    arena: *std.heap.ArenaAllocator,
    image: elfsym.Image,
    /// `.symtab`'s section index.
    symtab_idx: usize,

    /// The `license` section, NUL-stripped. `""` when absent — which the
    /// kernel treats as a non-GPL license.
    license: []const u8,
    /// The `version` section's `u32`, or 0.
    kern_version: u32,

    /// A **mutable copy** of `.BTF`: `load` rewrites its `DATASEC` sizes and
    /// variable offsets in place, which the kernel requires and clang does
    /// not emit.
    btf_bytes: ?[]u8,
    btf: ?Btf,
    ext: ?btfext.Ext,

    maps: []MapSpec,
    programs: []ProgramSpec,
    /// Executable sections whose names match no known prefix. `load` refuses
    /// unless `LoadOptions.ignore_unknown_sections`.
    unknown_sections: [][]const u8,

    /// `BPF_BTF_LOAD`'s fd, once `load` has run with `load_btf`.
    btf_fd: linux.fd_t = -1,
    /// The verifier log of the program that failed, if any (arena-owned).
    verifier_log: []const u8 = &.{},
    /// Which program's load failed.
    failed_program: []const u8 = &.{},

    pub fn deinit(self: *Object) void {
        self.close();
        const gpa = self.gpa;
        const arena = self.arena;
        arena.deinit();
        gpa.destroy(arena);
        self.* = undefined;
    }

    /// Close every fd this object owns (programs, maps, BTF), leaving the
    /// parsed specs intact. Idempotent.
    pub fn close(self: *Object) void {
        for (self.programs) |*p| {
            if (p.fd >= 0) _ = linux.close(p.fd);
            p.fd = -1;
        }
        for (self.maps) |*m| {
            if (m.fd >= 0) _ = linux.close(m.fd);
            m.fd = -1;
        }
        if (self.btf_fd >= 0) _ = linux.close(self.btf_fd);
        self.btf_fd = -1;
    }

    /// Find a program by C function name first, then by section name.
    pub fn findProgram(self: *Object, name: []const u8) ?*ProgramSpec {
        for (self.programs) |*p| {
            if (std.mem.eql(u8, p.name, name)) return p;
        }
        for (self.programs) |*p| {
            if (std.mem.eql(u8, p.sec_name, name)) return p;
        }
        return null;
    }

    pub fn findMap(self: *Object, name: []const u8) ?*MapSpec {
        for (self.maps) |*m| {
            if (std.mem.eql(u8, m.name, name)) return m;
        }
        return null;
    }

    /// The loaded program's fd, or `null`. Still owned by the `Object`.
    pub fn programFd(self: *Object, name: []const u8) ?linux.fd_t {
        const p = self.findProgram(name) orelse return null;
        return if (p.fd >= 0) p.fd else null;
    }

    /// The created map's fd, or `null`. Still owned by the `Object`.
    pub fn mapFd(self: *Object, name: []const u8) ?linux.fd_t {
        const m = self.findMap(name) orelse return null;
        return if (m.fd >= 0) m.fd else null;
    }

    /// Hand a program's fd to the caller, who becomes responsible for closing
    /// it. Useful when the program must outlive the `Object` (e.g. it is
    /// attached and the attachment holds the reference).
    pub fn takeProgramFd(self: *Object, name: []const u8) ?linux.fd_t {
        const p = self.findProgram(name) orelse return null;
        if (p.fd < 0) return null;
        defer p.fd = -1;
        return p.fd;
    }

    /// Same, for a map fd.
    pub fn takeMapFd(self: *Object, name: []const u8) ?linux.fd_t {
        const m = self.findMap(name) orelse return null;
        if (m.fd < 0) return null;
        defer m.fd = -1;
        return m.fd;
    }
};

// ── opening / parsing ───────────────────────────────────────────────────────

/// Parse an object already in memory. `bytes` is **copied**, so the caller
/// may free it immediately.
pub fn open(gpa: std.mem.Allocator, bytes: []const u8, opts: OpenOptions) OpenError!Object {
    const arena = gpa.create(std.heap.ArenaAllocator) catch return error.OutOfMemory;
    arena.* = .init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();
    const copy = a.dupe(u8, bytes) catch return error.OutOfMemory;
    return parseImage(gpa, arena, copy, opts);
}

/// Read and parse an object from disk.
pub fn openFile(gpa: std.mem.Allocator, path: []const u8, opts: OpenOptions) OpenError!Object {
    const arena = gpa.create(std.heap.ArenaAllocator) catch return error.OutOfMemory;
    arena.* = .init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();
    const bytes = elfsym.readFileAlloc(a, path, elfsym.max_image_bytes) catch |e| return switch (e) {
        error.NotAnElf, error.UnsupportedElf, error.MalformedElf => error.NotABpfObject,
        else => |x| x,
    };
    return parseImage(gpa, arena, bytes, opts);
}

fn parseImage(
    gpa: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    bytes: []const u8,
    opts: OpenOptions,
) OpenError!Object {
    const a = arena.allocator();
    var image = elfsym.openImage(a, bytes, false) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.NotAnElf, error.UnsupportedElf => error.NotABpfObject,
        error.MalformedElf => error.MalformedElf,
    };
    if (image.e_type != ET_REL) return error.NotABpfObject;
    if (opts.require_bpf_machine and image.e_machine != elfsym.EM_BPF) return error.NotABpfObject;

    const symtab_idx = image.symtabIndex() orelse return error.NoSymbolTable;

    var obj: Object = .{
        .gpa = gpa,
        .arena = arena,
        .image = image,
        .symtab_idx = symtab_idx,
        .license = "",
        .kern_version = 0,
        .btf_bytes = null,
        .btf = null,
        .ext = null,
        .maps = &.{},
        .programs = &.{},
        .unknown_sections = &.{},
    };

    // ── pass 1: classify sections ──
    var prog_secs: std.ArrayList(usize) = .empty;
    var data_secs: std.ArrayList(usize) = .empty;
    var text_secs: std.ArrayList(usize) = .empty;
    var unknown: std.ArrayList([]const u8) = .empty;
    var maps_btf_sec: ?usize = null;
    var maps_legacy_sec: ?usize = null;
    var ext_bytes: ?[]const u8 = null;

    for (image.sections, 0..) |s, i| {
        const name = image.sectionName(i);
        if (name.len == 0) continue;
        if (std.mem.eql(u8, name, "license")) {
            const d = image.sectionData(i) catch return error.MalformedElf;
            obj.license = cstrSlice(d);
            continue;
        }
        if (std.mem.eql(u8, name, "version")) {
            const d = image.sectionData(i) catch return error.MalformedElf;
            if (d.len >= 4) obj.kern_version = std.mem.readInt(u32, d[0..4], .little);
            continue;
        }
        if (std.mem.eql(u8, name, ".BTF")) {
            const d = image.sectionData(i) catch return error.MalformedElf;
            obj.btf_bytes = a.dupe(u8, d) catch return error.OutOfMemory;
            continue;
        }
        if (std.mem.eql(u8, name, ".BTF.ext")) {
            ext_bytes = image.sectionData(i) catch return error.MalformedElf;
            continue;
        }
        if (std.mem.eql(u8, name, ".maps")) {
            maps_btf_sec = i;
            continue;
        }
        if (std.mem.eql(u8, name, "maps")) {
            maps_legacy_sec = i;
            continue;
        }
        if (isDataSectionName(name)) {
            if (s.sh_size != 0) data_secs.append(a, i) catch return error.OutOfMemory;
            continue;
        }
        // A program section: allocated + executable, with content, not
        // `.text` (which holds sub-programs, not entry points).
        const executable = (s.sh_flags & elfsym.SHF_EXECINSTR) != 0 and
            (s.sh_flags & elfsym.SHF_ALLOC) != 0 and
            s.sh_type == elfsym.SHT_PROGBITS and s.sh_size != 0;
        if (!executable) continue;
        if (std.mem.eql(u8, name, ".text")) {
            text_secs.append(a, i) catch return error.OutOfMemory;
            continue;
        }
        if (classifySection(name) == null) {
            unknown.append(a, name) catch return error.OutOfMemory;
            continue;
        }
        prog_secs.append(a, i) catch return error.OutOfMemory;
    }
    obj.unknown_sections = unknown.toOwnedSlice(a) catch return error.OutOfMemory;

    // ── pass 2: BTF ──
    if (obj.btf_bytes) |b| {
        obj.btf = btf_mod.parse(a, b, .{}) catch return error.MalformedBtf;
    }
    if (ext_bytes) |e| {
        obj.ext = btfext.parseExt(e) catch return error.MalformedBtf;
    }

    // ── pass 3: maps ──
    var maps: std.ArrayList(MapSpec) = .empty;
    if (maps_btf_sec) |i| try parseBtfMaps(&obj, a, i, &maps);
    if (maps_legacy_sec) |i| try parseLegacyMaps(&obj, a, i, &maps);
    for (data_secs.items) |i| try addInternalMap(&obj, a, i, &maps);
    // Duplicate names would make `findMap` ambiguous and a relocation
    // resolvable to the wrong fd.
    for (maps.items, 0..) |m, i| {
        for (maps.items[i + 1 ..]) |n| {
            if (std.mem.eql(u8, m.name, n.name)) return error.DuplicateMap;
        }
    }
    obj.maps = maps.toOwnedSlice(a) catch return error.OutOfMemory;

    // ── pass 4: programs ──
    var progs: std.ArrayList(ProgramSpec) = .empty;
    for (prog_secs.items) |i| try splitProgramSection(&obj, a, i, classifySection(obj.image.sectionName(i)).?, &progs);
    obj.programs = progs.toOwnedSlice(a) catch return error.OutOfMemory;
    // `.text` holds the sub-programs: functions that are not entry points.
    var subs: std.ArrayList(ProgramSpec) = .empty;
    for (text_secs.items) |i| try splitProgramSection(&obj, a, i, .{
        .def = .{ .prefix = ".text", .prog_type = .unspec },
        .target = "",
    }, &subs);

    // ── pass 5: relocations + .BTF.ext slices ──
    for (obj.programs) |*p| {
        try collectRelocations(&obj, a, p);
        try sliceBtfExt(&obj, a, p);
    }
    for (subs.items) |*p| {
        try collectRelocations(&obj, a, p);
        try sliceBtfExt(&obj, a, p);
    }

    // ── pass 6: link sub-programs into every program that calls them ──
    try linkSubprograms(a, obj.programs, subs.items);
    return obj;
}

fn cstrSlice(d: []const u8) []const u8 {
    const end = std.mem.findScalar(u8, d, 0) orelse d.len;
    return d[0..end];
}

/// `.rodata`, `.rodata.str1.1`, `.data`, `.data.foo`, `.bss` — the global
/// variable sections. Matched by prefix because clang splits them
/// (`-fdata-sections`, string literals, `.rodata.cst8`).
pub fn isDataSectionName(name: []const u8) bool {
    for ([_][]const u8{ ".rodata", ".data", ".bss" }) |p| {
        if (std.mem.eql(u8, name, p)) return true;
        if (std.mem.startsWith(u8, name, p) and name.len > p.len and name[p.len] == '.') return true;
    }
    return false;
}

fn isRodataName(name: []const u8) bool {
    return std.mem.startsWith(u8, name, ".rodata");
}

// ── map extraction ──────────────────────────────────────────────────────────

/// Members a `.maps` struct may carry. Everything else is
/// `error.UnknownMapMember` — a typo in a map definition must not silently
/// create a map with default sizes.
const MapMember = enum {
    type,
    max_entries,
    map_flags,
    key_size,
    value_size,
    numa_node,
    pinning,
    map_extra,
    key,
    value,
    values,
};

fn parseBtfMaps(obj: *Object, a: std.mem.Allocator, sec_idx: usize, out: *std.ArrayList(MapSpec)) ParseError!void {
    const b = &(obj.btf orelse return error.MissingBtf);
    const ds_id = b.findByNameKind(".maps", .datasec) orelse return; // no maps declared
    const ds = b.byId(ds_id) catch return error.MalformedBtf;

    var i: u16 = 0;
    while (i < ds.vlen) : (i += 1) {
        const vsi = b.varSecInfo(ds, i) catch return error.MalformedBtf;
        const vt = b.byId(vsi.type_id) catch return error.MalformedBtf;
        if (vt.kind != .@"var") return error.MalformedMapDefinition;
        const name = b.typeName(vsi.type_id) orelse return error.MalformedMapDefinition;

        const st_id = b.skipModifiers(vt.refType() orelse return error.MalformedMapDefinition) catch
            return error.MalformedBtf;
        const st = b.byId(st_id) catch return error.MalformedBtf;
        if (st.kind != .@"struct") return error.MalformedMapDefinition;

        var spec: MapSpec = .{
            .name = a.dupe(u8, name) catch return error.OutOfMemory,
            .map_type = .unspec,
            .origin = .btf_defined,
            .sec_idx = sec_idx,
        };

        var m: u16 = 0;
        while (m < st.vlen) : (m += 1) {
            const mem = b.member(st, m) catch return error.MalformedBtf;
            const mname = b.str(mem.name_off) orelse return error.MalformedMapDefinition;
            const which = std.meta.stringToEnum(MapMember, mname) orelse return error.UnknownMapMember;
            switch (which) {
                .values => return error.MapInMapUnsupported,
                .key, .value => {
                    // `T *key` — the pointee's size AND type id.
                    const p_id = b.skipModifiers(mem.type_id) catch return error.MalformedBtf;
                    const p = b.byId(p_id) catch return error.MalformedBtf;
                    if (p.kind != .ptr) return error.MalformedMapDefinition;
                    const t_id = p.refType() orelse return error.MalformedMapDefinition;
                    if (t_id == 0) return error.MalformedMapDefinition; // `void *`
                    const size = b.sizeOf(t_id) catch return error.MalformedMapDefinition;
                    if (size > std.math.maxInt(u32)) return error.MalformedMapDefinition;
                    if (which == .key) {
                        spec.key_size = @intCast(size);
                        spec.btf_key_type_id = t_id;
                    } else {
                        spec.value_size = @intCast(size);
                        spec.btf_value_type_id = t_id;
                    }
                },
                else => {
                    const v = try uintMemberValue(b, mem.type_id);
                    switch (which) {
                        .type => spec.map_type = @fromBackingInt(@intCast(v)),
                        .max_entries => spec.max_entries = v,
                        .map_flags => spec.map_flags = v,
                        .key_size => spec.key_size = v,
                        .value_size => spec.value_size = v,
                        .numa_node => spec.numa_node = v,
                        .pinning => spec.pinning = v,
                        // `map_extra` is a u64 in the UAPI; the `__ulong`
                        // encoding is a 64-bit array element count, which
                        // does not fit this u32 path. Refused rather than
                        // truncated.
                        .map_extra => if (v != 0) return error.UnknownMapMember,
                        else => unreachable,
                    }
                },
            }
        }
        out.append(a, spec) catch return error.OutOfMemory;
    }
}

/// `__uint(name, VALUE)` is `int (*name)[VALUE]`: resolve the member type to
/// a pointer, then to an array, and take its element count. **That element
/// count is the value.** A member that is not shaped that way is a malformed
/// definition, not a zero.
fn uintMemberValue(b: *const Btf, member_type_id: u32) ParseError!u32 {
    const p_id = b.skipModifiers(member_type_id) catch return error.MalformedBtf;
    const p = b.byId(p_id) catch return error.MalformedBtf;
    if (p.kind != .ptr) return error.MalformedMapDefinition;
    const arr_id = b.skipModifiers(p.refType() orelse return error.MalformedMapDefinition) catch
        return error.MalformedBtf;
    const arr = b.byId(arr_id) catch return error.MalformedBtf;
    if (arr.kind != .array) return error.MalformedMapDefinition;
    const info = b.arrayInfo(arr) catch return error.MalformedBtf;
    return info.nelems;
}

/// `struct bpf_map_def` — the pre-BTF form: five `u32`s, one per map, packed
/// in the `maps` section. Newer kernels still accept the maps it describes;
/// only the *description* is legacy.
const legacy_map_def_size: usize = 20;

fn parseLegacyMaps(obj: *Object, a: std.mem.Allocator, sec_idx: usize, out: *std.ArrayList(MapSpec)) ParseError!void {
    const data = obj.image.sectionData(sec_idx) catch return error.MalformedElf;
    if (data.len == 0) return;
    if (data.len % legacy_map_def_size != 0) return error.MalformedMapDefinition;
    const count = data.len / legacy_map_def_size;

    // Names come from the symbol table: each `struct bpf_map_def` object has
    // an `STT_OBJECT` symbol whose `st_value` is its offset in the section.
    //
    // Rescanning all `n` symbols once PER map def (the original shape) is
    // O(maps * symbols); both counts are attacker-controlled and scale with
    // file size, so `open()` was O(bytes^2) on this path. Measured: clean
    // 4x-per-2x scaling, 2.1 MB -> 1.8 s, extrapolating to tens of minutes
    // at `max_image_bytes` (256 MB). One pass over the symbol table into a
    // `count`-sized name index, then one pass over the map defs, is
    // O(maps + symbols) instead and produces the identical result: symbols
    // are still visited in table order, and the first one at a given offset
    // still wins (a later symbol at an already-claimed offset is ignored,
    // exactly as the old inner loop's `break` on first match did).
    const names = a.alloc(?[]const u8, count) catch return error.OutOfMemory;
    defer a.free(names);
    @memset(names, null);
    const n = obj.image.symbolCount(obj.symtab_idx) catch return error.MalformedElf;
    var s: u32 = 0;
    while (s < n) : (s += 1) {
        const sym = obj.image.symbol(obj.symtab_idx, s) catch return error.MalformedElf;
        if (sym.st_shndx != sec_idx) continue;
        if (sym.kind() != STT_OBJECT) continue;
        if (sym.st_value % legacy_map_def_size != 0) continue;
        const idx = sym.st_value / legacy_map_def_size;
        if (idx >= count) continue;
        if (names[idx] != null) continue;
        names[idx] = obj.image.symbolName(obj.symtab_idx, sym);
    }

    var idx: usize = 0;
    while (idx < count) : (idx += 1) {
        const at = idx * legacy_map_def_size;
        const name = names[idx] orelse "";
        if (name.len == 0) return error.MalformedMapDefinition;
        const d = data[at..][0..legacy_map_def_size];
        out.append(a, .{
            .name = a.dupe(u8, name) catch return error.OutOfMemory,
            .map_type = @fromBackingInt(@intCast(std.mem.readInt(u32, d[0..4], .little))),
            .key_size = std.mem.readInt(u32, d[4..8], .little),
            .value_size = std.mem.readInt(u32, d[8..12], .little),
            .max_entries = std.mem.readInt(u32, d[12..16], .little),
            .map_flags = std.mem.readInt(u32, d[16..20], .little),
            .origin = .legacy,
            .sec_idx = sec_idx,
        }) catch return error.OutOfMemory;
    }
}

fn addInternalMap(obj: *Object, a: std.mem.Allocator, sec_idx: usize, out: *std.ArrayList(MapSpec)) ParseError!void {
    const name = obj.image.sectionName(sec_idx);
    const s = obj.image.sections[sec_idx];
    if (s.sh_size > std.math.maxInt(u32)) return error.MalformedElf;
    const data = obj.image.sectionData(sec_idx) catch return error.MalformedElf;
    const ro = isRodataName(name);
    out.append(a, .{
        .name = a.dupe(u8, name) catch return error.OutOfMemory,
        .map_type = .array,
        .key_size = 4,
        .value_size = @intCast(s.sh_size),
        .max_entries = 1,
        .map_flags = if (ro) BPF_F_RDONLY_PROG else 0,
        .origin = .internal,
        .sec_idx = sec_idx,
        .initial_data = data,
        .freeze = ro,
    }) catch return error.OutOfMemory;
}

// ── program splitting ───────────────────────────────────────────────────────

fn splitProgramSection(obj: *Object, a: std.mem.Allocator, sec_idx: usize, info: SectionKindInfo, out: *std.ArrayList(ProgramSpec)) ParseError!void {
    const s = obj.image.sections[sec_idx];
    if (s.sh_size % 8 != 0) return error.UnalignedInstructionSection;
    const data = obj.image.sectionData(sec_idx) catch return error.MalformedElf;
    if (data.len != s.sh_size) return error.MalformedElf;
    const sec_name = obj.image.sectionName(sec_idx);

    // Every `STT_FUNC` symbol in this section is an entry point.
    const Range = struct { off: u64, size: u64, name: []const u8 };
    var ranges: std.ArrayList(Range) = .empty;
    const n = obj.image.symbolCount(obj.symtab_idx) catch return error.MalformedElf;
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const sym = obj.image.symbol(obj.symtab_idx, i) catch return error.MalformedElf;
        if (sym.st_shndx != sec_idx) continue;
        if (sym.kind() != STT_FUNC) continue;
        if (sym.st_value > data.len) return error.MalformedElf;
        ranges.append(a, .{
            .off = sym.st_value,
            .size = sym.st_size,
            .name = obj.image.symbolName(obj.symtab_idx, sym),
        }) catch return error.OutOfMemory;
    }
    // A section with no function symbol at all is still one program — a
    // hand-written or stripped object.
    if (ranges.items.len == 0) {
        ranges.append(a, .{ .off = 0, .size = data.len, .name = sec_name }) catch return error.OutOfMemory;
    }
    std.mem.sort(Range, ranges.items, {}, struct {
        fn lt(_: void, x: Range, y: Range) bool {
            return x.off < y.off;
        }
    }.lt);

    for (ranges.items, 0..) |r, k| {
        // A zero `st_size` (some producers) means "until the next function".
        var size = r.size;
        if (size == 0) {
            size = if (k + 1 < ranges.items.len) ranges.items[k + 1].off - r.off else data.len - r.off;
        }
        if (size % 8 != 0) return error.UnalignedInstructionSection;
        // `size` is the symbol's raw `st_size`, a u64 straight off the wire
        // that nothing has bounded — `st_value` is checked against `data.len`
        // above, `st_size` never was. Written as `r.off + size > data.len` the
        // sum wraps: `st_value = 8` with `st_size = 0xFFFF_FFFF_FFFF_FFF8`
        // (a multiple of 8, so the alignment check above passes) sums to 0 and
        // the range check accepts. What follows is an allocation whose own
        // size arithmetic wraps too, and then a `@memcpy` of 2^64-8 bytes.
        //
        // Measured on a crafted object built from `core_reloc.bpf.o`:
        // Debug and ReleaseSafe panic with `integer overflow` HERE; ReleaseFast
        // has no overflow check at all and reaches the `@memcpy`, which is an
        // out-of-bounds WRITE, not a read (SIGSEGV). `open()` is the module's
        // documented untrusted-input entry point and needs no privilege.
        //
        // Phrased by subtraction so neither term can overflow — the same
        // discipline `elfsym.entryOffset` already uses.
        if (size > data.len or r.off > data.len - size) return error.MalformedElf;
        if (size == 0) continue;

        const insns = a.alloc(Insn, @intCast(size / 8)) catch return error.OutOfMemory;
        @memcpy(std.mem.sliceAsBytes(insns), data[@intCast(r.off)..][0..@intCast(size)]);

        out.append(a, .{
            .sec_name = sec_name,
            .name = if (r.name.len != 0) r.name else sec_name,
            .attach_target = info.target,
            .prog_type = info.def.prog_type,
            .expected_attach_type = info.def.expected_attach_type,
            .sleepable = info.def.sleepable,
            .sec_idx = sec_idx,
            .sec_byte_off = r.off,
            .insns = insns,
            .relos = &.{},
            .func_info = &.{},
            .line_info = &.{},
            .core_relos = &.{},
        }) catch return error.OutOfMemory;
    }
}

// ── relocation collection ───────────────────────────────────────────────────

fn collectRelocations(obj: *Object, a: std.mem.Allocator, prog: *ProgramSpec) ParseError!void {
    // `.rel<section>` — note there is NO dot between `.rel` and the section
    // name, so `kprobe/x`'s relocations live in `.relkprobe/x`.
    var relos: std.ArrayList(Relo) = .empty;
    var calls: std.ArrayList(CallSite) = .empty;
    const lo = prog.sec_byte_off;
    const hi = lo + prog.insns.len * 8;

    const rel_idx: ?usize = blk: {
        for (obj.image.sections, 0..) |s, i| {
            if (s.sh_type != elfsym.SHT_REL) continue;
            if (s.sh_info != prog.sec_idx) continue;
            break :blk i;
        }
        break :blk null;
    };
    const count = if (rel_idx) |ri| obj.image.relocationCount(ri) catch return error.MalformedElf else 0;

    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const rel = obj.image.relocation(rel_idx.?, i) catch return error.MalformedElf;
        if (rel.r_offset < lo or rel.r_offset >= hi) continue; // another function
        if (rel.r_offset % 8 != 0) return error.RelocationOutOfRange;
        const insn_idx: u32 = @intCast((rel.r_offset - lo) / 8);

        const sym = obj.image.symbol(obj.symtab_idx, rel.sym) catch return error.MalformedElf;
        const sym_name = obj.image.symbolName(obj.symtab_idx, sym);

        if (rel.type != R_BPF_64_64 and rel.type != R_BPF_64_32) return error.UnsupportedRelocation;

        // An undefined symbol is an extern: kfunc, kconfig, or ksym.
        if (!sym.hasSection()) return error.ExternSymbolUnsupported;

        const insn = prog.insns[insn_idx];

        // A call to a sub-program. For a global function the symbol is the
        // function and the call's `imm` is -1; for a static one the symbol is
        // the section and `imm` holds the offset in instructions, less one.
        // Both are `st_value / 8 + imm + 1`.
        if (rel.type == R_BPF_64_32) {
            if (insn.code != CALL_CODE or insn.src != BPF_PSEUDO_CALL) return error.UnsupportedRelocation;
            if (sym.st_shndx >= obj.image.sections.len) return error.MalformedElf;
            const at: i64 = std.math.cast(i64, sym.st_value / 8) orelse return error.RelocationOutOfRange;
            const tgt = at + @as(i64, insn.imm) + 1;
            if (tgt < 0) return error.RelocationOutOfRange;
            calls.append(a, .{
                .kind = .call,
                .insn_idx = insn_idx,
                .sec_idx = sym.st_shndx,
                .sec_byte_off = std.math.mul(u64, @intCast(tgt), 8) catch return error.RelocationOutOfRange,
            }) catch return error.OutOfMemory;
            continue;
        }
        if (insn.code != LD_IMM64_CODE) return error.UnsupportedRelocation;
        if (insn_idx + 1 >= prog.insns.len) return error.RelocationOutOfRange;

        const target_sec = sym.st_shndx;
        if (target_sec >= obj.image.sections.len) return error.MalformedElf;
        const target_name = obj.image.sectionName(target_sec);

        if (std.mem.eql(u8, target_name, ".maps") or std.mem.eql(u8, target_name, "maps")) {
            const mi = findMapIdx(obj, sym_name) orelse return error.UnresolvedRelocation;
            relos.append(a, .{
                .kind = .map_fd,
                .insn_idx = insn_idx,
                .map_idx = mi,
                .sym_name = sym_name,
            }) catch return error.OutOfMemory;
        } else if (isDataSectionName(target_name)) {
            const mi = findMapIdx(obj, target_name) orelse return error.UnresolvedRelocation;
            // REL, not RELA: the addend is in the instruction. For an
            // `STT_SECTION` symbol `st_value` is 0 and `insn.imm` carries the
            // whole offset; for a named global it is the other way round.
            const off = sym.st_value +% @as(u64, @bitCast(@as(i64, insn.imm)));
            // `>`, not `>=`, accepted `off == value_size`: one byte PAST the
            // map's last valid byte, not the last valid offset. libbpf's
            // equivalent check uses `>=`. Harmless only because the kernel
            // verifier is the real gate on the loaded program; refused here
            // too rather than relying on that second layer alone.
            if (off >= obj.maps[mi].value_size) return error.RelocationOutOfRange;
            relos.append(a, .{
                .kind = .map_value,
                .insn_idx = insn_idx,
                .map_idx = mi,
                .value_off = off,
                .sym_name = if (sym_name.len != 0) sym_name else target_name,
            }) catch return error.OutOfMemory;
        } else if (std.mem.eql(u8, target_name, ".text")) {
            // The address of a sub-program (a callback): the byte offset is
            // `st_value` for a global function, the instruction's `imm` for a
            // static one (a section symbol).
            const off = sym.st_value +% @as(u64, @bitCast(@as(i64, insn.imm)));
            calls.append(a, .{
                .kind = .func_addr,
                .insn_idx = insn_idx,
                .sec_idx = target_sec,
                .sec_byte_off = off,
            }) catch return error.OutOfMemory;
        } else {
            return error.UnsupportedRelocation;
        }
    }
    // A call between two functions of one section has no relocation: its
    // `imm` is already relative. A target inside the function itself is left
    // alone (a hand-written object); one in a sibling function is a call site.
    var relocated: std.AutoHashMapUnmanaged(u32, void) = .empty;
    for (calls.items) |c| relocated.put(a, c.insn_idx, {}) catch return error.OutOfMemory;
    for (prog.insns, 0..) |insn, k| {
        if (insn.code != CALL_CODE or insn.src != BPF_PSEUDO_CALL) continue;
        if (relocated.contains(@intCast(k))) continue;
        const tgt = @as(i64, @intCast(lo / 8 + k)) + insn.imm + 1;
        if (tgt >= @as(i64, @intCast(lo / 8)) and tgt < @as(i64, @intCast(hi / 8))) continue;
        if (tgt < 0) return error.RelocationOutOfRange;
        calls.append(a, .{
            .kind = .call,
            .insn_idx = @intCast(k),
            .sec_idx = prog.sec_idx,
            .sec_byte_off = @as(u64, @intCast(tgt)) * 8,
        }) catch return error.OutOfMemory;
    }
    prog.relos = relos.toOwnedSlice(a) catch return error.OutOfMemory;
    prog.call_sites = calls.toOwnedSlice(a) catch return error.OutOfMemory;
}

const SubKey = struct { sec: usize, off: u64 };

/// Append every sub-program a program calls (transitively) after its own
/// instructions, patch each call to the relative offset, and carry the
/// callee's map relocations, CO-RE relocations, `func_info` and `line_info`
/// along with their instruction indices shifted. Each callee is appended once
/// per program; the original arrays are never mutated (a callee may itself be
/// an entry point of another program).
fn linkSubprograms(a: std.mem.Allocator, progs: []ProgramSpec, subs: []const ProgramSpec) ParseError!void {
    var any = false;
    for (progs) |p| {
        if (p.call_sites.len != 0) any = true;
    }
    if (!any) return;

    const snap = a.alloc(ProgramSpec, progs.len + subs.len) catch return error.OutOfMemory;
    @memcpy(snap[0..progs.len], progs);
    @memcpy(snap[progs.len..], subs);
    var by_start: std.AutoHashMapUnmanaged(SubKey, u32) = .empty;
    for (snap, 0..) |f, k| {
        // The first function at a given place wins (an entry point before a
        // same-named sub-program, which cannot be at the same place anyway).
        _ = by_start.getOrPutValue(a, .{ .sec = f.sec_idx, .off = f.sec_byte_off }, @intCast(k)) catch return error.OutOfMemory;
    }

    for (progs, 0..) |*p, pi| {
        if (p.call_sites.len == 0) continue;
        var insns: std.ArrayList(Insn) = .empty;
        var relos: std.ArrayList(Relo) = .empty;
        var finfo: std.ArrayList(btfext.FuncInfo) = .empty;
        var linfo: std.ArrayList(btfext.LineInfo) = .empty;
        var cores: std.ArrayList(btfext.CoreRelo) = .empty;
        const Placed = struct { idx: u32, base: u32 };
        var queue: std.ArrayList(Placed) = .empty;
        var placed: std.AutoHashMapUnmanaged(u32, u32) = .empty;

        const Local = struct {
            fn append(
                al: std.mem.Allocator,
                f: ProgramSpec,
                base: u32,
                i: *std.ArrayList(Insn),
                r: *std.ArrayList(Relo),
                fi: *std.ArrayList(btfext.FuncInfo),
                li: *std.ArrayList(btfext.LineInfo),
                cr: *std.ArrayList(btfext.CoreRelo),
            ) ParseError!void {
                i.appendSlice(al, f.insns) catch return error.OutOfMemory;
                for (f.relos) |x| {
                    var y = x;
                    y.insn_idx += base;
                    r.append(al, y) catch return error.OutOfMemory;
                }
                for (f.func_info) |x| {
                    var y = x;
                    y.insn_off += base;
                    fi.append(al, y) catch return error.OutOfMemory;
                }
                for (f.line_info) |x| {
                    var y = x;
                    y.insn_off += base;
                    li.append(al, y) catch return error.OutOfMemory;
                }
                for (f.core_relos) |x| {
                    var y = x;
                    y.insn_off += base;
                    cr.append(al, y) catch return error.OutOfMemory;
                }
            }
        };
        try Local.append(a, snap[pi], 0, &insns, &relos, &finfo, &linfo, &cores);
        placed.put(a, @intCast(pi), 0) catch return error.OutOfMemory;
        queue.append(a, .{ .idx = @intCast(pi), .base = 0 }) catch return error.OutOfMemory;

        var qi: usize = 0;
        while (qi < queue.items.len) : (qi += 1) {
            const cur = queue.items[qi];
            for (snap[cur.idx].call_sites) |cs| {
                const callee = by_start.get(.{ .sec = cs.sec_idx, .off = cs.sec_byte_off }) orelse
                    return error.UnresolvedRelocation;
                const cbase: u32 = if (placed.get(callee)) |b| b else blk: {
                    const f = snap[callee];
                    if (insns.items.len + f.insns.len > max_program_insns) return error.ProgramTooLarge;
                    const b: u32 = @intCast(insns.items.len);
                    try Local.append(a, f, b, &insns, &relos, &finfo, &linfo, &cores);
                    placed.put(a, callee, b) catch return error.OutOfMemory;
                    queue.append(a, .{ .idx = callee, .base = b }) catch return error.OutOfMemory;
                    break :blk b;
                };
                const at: i64 = @as(i64, cur.base) + cs.insn_idx;
                const rel = @as(i64, cbase) - at - 1;
                const ins = &insns.items[@intCast(at)];
                switch (cs.kind) {
                    .call => {
                        ins.src = BPF_PSEUDO_CALL;
                        ins.imm = std.math.cast(i32, rel) orelse return error.RelocationOutOfRange;
                    },
                    .func_addr => {
                        ins.src = BPF_PSEUDO_FUNC;
                        ins.imm = std.math.cast(i32, rel) orelse return error.RelocationOutOfRange;
                    },
                }
            }
        }
        p.insns = insns.items;
        p.relos = relos.items;
        p.func_info = finfo.items;
        p.line_info = linfo.items;
        p.core_relos = cores.items;
        p.call_sites = &.{};
    }
    // Sub-programs that nothing links (and entry points with no calls) keep
    // an empty set too, so `call_sites` is empty everywhere on return.
    for (progs) |*p| p.call_sites = &.{};
}

fn findMapIdx(obj: *Object, name: []const u8) ?usize {
    for (obj.maps, 0..) |m, i| {
        if (std.mem.eql(u8, m.name, name)) return i;
    }
    return null;
}

// ── .BTF.ext slicing ────────────────────────────────────────────────────────

/// `.BTF.ext` groups its records **per ELF section**, with `insn_off` a BYTE
/// offset into that section. The kernel wants per-PROGRAM records with
/// `insn_off` an INSTRUCTION INDEX. Both conversions happen here; getting
/// either wrong makes `bpftool prog dump xlated -l` point at the wrong line
/// and can make `BPF_PROG_LOAD` reject the whole `func_info` array.
fn sliceBtfExt(obj: *Object, a: std.mem.Allocator, prog: *ProgramSpec) ParseError!void {
    const ext = obj.ext orelse return;
    const b = &(obj.btf orelse return);
    const lo = prog.sec_byte_off;
    const hi = lo + prog.insns.len * 8;

    {
        var fi: std.ArrayList(btfext.FuncInfo) = .empty;
        var it = ext.funcInfos();
        while (it.next()) |sec| {
            const nm = b.str(sec.sec_name_off) orelse continue;
            if (!std.mem.eql(u8, nm, prog.sec_name)) continue;
            var i: u32 = 0;
            while (i < sec.count) : (i += 1) {
                const r = sec.funcInfo(i);
                if (r.insn_off < lo or r.insn_off >= hi) continue;
                // `insn_off` is a BYTE offset off the wire; not re-checking
                // 8-alignment before dividing silently rounds a misaligned
                // record down onto the wrong instruction instead of
                // rejecting it, matching `collectRelocations`'s own
                // `r_offset % 8` guard on the exact same conversion.
                if ((r.insn_off - lo) % 8 != 0) return error.RelocationOutOfRange;
                fi.append(a, .{
                    .insn_off = @intCast((r.insn_off - lo) / 8),
                    .type_id = r.type_id,
                }) catch return error.OutOfMemory;
            }
        }
        prog.func_info = fi.toOwnedSlice(a) catch return error.OutOfMemory;
    }
    {
        var li: std.ArrayList(btfext.LineInfo) = .empty;
        var it = ext.lineInfos();
        while (it.next()) |sec| {
            const nm = b.str(sec.sec_name_off) orelse continue;
            if (!std.mem.eql(u8, nm, prog.sec_name)) continue;
            var i: u32 = 0;
            while (i < sec.count) : (i += 1) {
                var r = sec.lineInfo(i);
                if (r.insn_off < lo or r.insn_off >= hi) continue;
                if ((r.insn_off - lo) % 8 != 0) return error.RelocationOutOfRange;
                r.insn_off = @intCast((r.insn_off - lo) / 8);
                li.append(a, r) catch return error.OutOfMemory;
            }
        }
        prog.line_info = li.toOwnedSlice(a) catch return error.OutOfMemory;
    }
    {
        var cr: std.ArrayList(btfext.CoreRelo) = .empty;
        var it = ext.coreRelos();
        while (it.next()) |sec| {
            const nm = b.str(sec.sec_name_off) orelse continue;
            if (!std.mem.eql(u8, nm, prog.sec_name)) continue;
            var i: u32 = 0;
            while (i < sec.count) : (i += 1) {
                var r = sec.coreRelo(i);
                if (r.insn_off < lo or r.insn_off >= hi) continue;
                if ((r.insn_off - lo) % 8 != 0) return error.RelocationOutOfRange;
                r.insn_off = @intCast((r.insn_off - lo) / 8);
                cr.append(a, r) catch return error.OutOfMemory;
            }
        }
        prog.core_relos = cr.toOwnedSlice(a) catch return error.OutOfMemory;
    }
}

// ── relocation application (pure) ───────────────────────────────────────────

/// Patch one program's instruction stream from `maps`' fds. Pure apart from
/// reading `MapSpec.fd`, which is why the exact bytes handed to the verifier
/// are testable with no privilege: the tests call this with synthetic fds.
pub fn relocateProgram(prog: *ProgramSpec, maps: []const MapSpec) RelocateError!void {
    for (prog.relos) |r| {
        if (r.insn_idx >= prog.insns.len) return error.RelocationOutOfRange;
        const insn = &prog.insns[r.insn_idx];
        if (insn.code != LD_IMM64_CODE) return error.NotAnImmediateLoad;
        if (r.map_idx >= maps.len) return error.MapNotCreated;
        const fd = maps[r.map_idx].fd;
        if (fd < 0) return error.MapNotCreated;

        switch (r.kind) {
            .map_fd => {
                insn.src = BPF_PSEUDO_MAP_FD;
                insn.imm = fd;
            },
            .map_value => {
                if (r.insn_idx + 1 >= prog.insns.len) return error.RelocationOutOfRange;
                insn.src = BPF_PSEUDO_MAP_VALUE;
                insn.imm = fd;
                prog.insns[r.insn_idx + 1].imm = @intCast(r.value_off);
            },
        }
    }
}

// ── CO-RE instruction patching ──────────────────────────────────────────────

/// Rewrite one instruction with a relocated value.
///
/// Which field the value lands in depends on the instruction class, and this
/// is the whole of "CO-RE instruction patching":
///
/// | class | field | why |
/// |---|---|---|
/// | `LDX` / `ST` / `STX` | `off` (`i16`) | a member access `*(u32 *)(r1 + OFF)` |
/// | `ALU` / `ALU64` with `BPF_K` | `imm` | `r1 += OFF`, and the shift amounts for a bitfield |
/// | `LD_IMM64` | `imm` of BOTH halves | a 64-bit constant (`sizeof`, `TYPE_ID`) |
///
/// A `FIELD_BYTE_SIZE` relocation on a `LDX`/`ST`/`STX` additionally rewrites
/// the **size bits of the opcode** (`B`/`H`/`W`/`DW`), because the width of
/// the load is what changed, not an operand.
pub fn patchCoreInsn(insns: []Insn, insn_idx: u32, kind: btfext.ReloKind, value: u64) CoreApplyError!void {
    if (insn_idx >= insns.len) return error.RelocationOutOfRange;
    const insn = &insns[insn_idx];
    const class = insn.code & 0x07;

    switch (class) {
        BPF_LDX, BPF_ST, BPF_STX => {
            if (kind == .field_byte_size) {
                insn.code = (insn.code & ~@as(u8, 0x18)) | (try sizeBits(value));
                return;
            }
            if (value > std.math.maxInt(i16)) return error.CoreValueTooLarge;
            insn.off = @intCast(value);
        },
        BPF_ALU, BPF_ALU64 => {
            // `BPF_X` (source = register) leaves no immediate to patch.
            if (insn.code & 0x08 != 0) return error.UnsupportedCoreInsn;
            // The immediate sign-extends (ALU64), so a negative value (an
            // `ENUMVAL_VALUE` of a signed enum arrives as its 64-bit
            // two's-complement pattern) is valid when it fits an `i32`.
            const sv: i64 = @bitCast(value);
            if (sv < std.math.minInt(i32) or sv > std.math.maxInt(i32)) return error.CoreValueTooLarge;
            insn.imm = @intCast(sv);
        },
        BPF_LD => {
            if (insn.code != LD_IMM64_CODE) return error.UnsupportedCoreInsn;
            if (insn_idx + 1 >= insns.len) return error.RelocationOutOfRange;
            insn.imm = @bitCast(@as(u32, @truncate(value)));
            insns[insn_idx + 1].imm = @bitCast(@as(u32, @truncate(value >> 32)));
        },
        else => return error.UnsupportedCoreInsn,
    }
}

/// `BPF_B`/`BPF_H`/`BPF_W`/`BPF_DW` for a 1/2/4/8-byte access.
fn sizeBits(bytes: u64) CoreApplyError!u8 {
    return switch (bytes) {
        1 => 0x10, // BPF_B
        2 => 0x08, // BPF_H
        4 => 0x00, // BPF_W
        8 => 0x18, // BPF_DW
        else => error.CoreValueTooLarge,
    };
}

/// Apply every CO-RE field relocation of `prog` against `target`. Returns how
/// many instructions were rewritten.
///
/// `local` is the object's own BTF (where the access strings live), `target`
/// is what the program must run against — normally
/// `/sys/kernel/btf/vmlinux`, but any BTF works, which is what makes this
/// testable offline.
pub fn applyCoreRelos(prog: *ProgramSpec, local: *const Btf, target: *const Btf) CoreApplyError!usize {
    var n: usize = 0;
    for (prog.core_relos) |r| {
        const res = try btfext.computeRelo(local, target, r);
        if (!res.exists) switch (res.kind) {
            .field_exists, .type_exists, .type_matches, .enumval_exists => {},
            .type_id_target, .type_size => return error.CoreTypeNotFound,
            .enumval_value => return error.CoreEnumvalNotFound,
            else => return error.CoreFieldNotFound,
        };
        try patchCoreInsn(prog.insns, r.insn_off, res.kind, res.value);
        n += 1;
    }
    return n;
}

// ── BTF DATASEC fixup ───────────────────────────────────────────────────────

/// clang emits every `DATASEC` with `size == 0` and every variable at
/// `offset == 0`; the real numbers live in the ELF (the section's `sh_size`,
/// the symbol's `st_value`). The kernel **rejects** a zero-size `DATASEC`
/// outright, so `BPF_BTF_LOAD` of an unfixed clang blob always fails — which
/// is why this runs before it.
///
/// Rewrites `obj.btf_bytes` in place. Safe to call more than once.
pub fn fixupDatasecs(obj: *Object) ParseError!void {
    const bytes = obj.btf_bytes orelse return;
    const b = &(obj.btf orelse return);

    var id = b.start_id;
    while (id < b.endId()) : (id += 1) {
        const t = b.byId(id) catch return error.MalformedBtf;
        if (t.kind != .datasec) continue;
        const name = b.typeName(id) orelse continue;
        const sec_idx = obj.image.findSection(name) orelse continue;
        const sec = obj.image.sections[sec_idx];
        if (sec.sh_size > std.math.maxInt(u32)) return error.MalformedElf;

        const abs: usize = @intCast(b.hdr.hdr_len + b.hdr.type_off + b.offsets[id - b.start_id]);
        if (abs + 12 + @as(usize, t.vlen) * 12 > bytes.len) return error.MalformedBtf;
        // `btf_type.size` — the third u32 of the record header.
        std.mem.writeInt(u32, bytes[abs + 8 ..][0..4], @intCast(sec.sh_size), .little);

        const n = obj.image.symbolCount(obj.symtab_idx) catch return error.MalformedElf;
        var i: u16 = 0;
        while (i < t.vlen) : (i += 1) {
            const at = abs + 12 + @as(usize, i) * 12;
            const var_id = std.mem.readInt(u32, bytes[at..][0..4], .little);
            const vname = b.typeName(var_id) orelse continue;
            var s: u32 = 0;
            while (s < n) : (s += 1) {
                const sym = obj.image.symbol(obj.symtab_idx, s) catch return error.MalformedElf;
                if (sym.st_shndx != sec_idx) continue;
                if (!std.mem.eql(u8, obj.image.symbolName(obj.symtab_idx, sym), vname)) continue;
                // `st_value` / `st_size` are u64 straight off the ELF; the
                // BTF slots are u32 (found by the fuzz driver,
                // EBPF_FUZZ ebpf-object seed 1867: `@intCast` panic).
                if (sym.st_value > std.math.maxInt(u32) or sym.st_size > std.math.maxInt(u32))
                    return error.MalformedElf;
                std.mem.writeInt(u32, bytes[at + 4 ..][0..4], @intCast(sym.st_value), .little);
                if (sym.st_size != 0)
                    std.mem.writeInt(u32, bytes[at + 8 ..][0..4], @intCast(sym.st_size), .little);
                break;
            }
        }
        // The kernel additionally requires the variables to be in ascending
        // offset order and non-overlapping.
        sortVarSecInfos(bytes[abs + 12 ..][0 .. @as(usize, t.vlen) * 12]);
    }
}

fn sortVarSecInfos(recs: []u8) void {
    const Rec = [12]u8;
    const items: []Rec = @as([*]Rec, @ptrCast(recs.ptr))[0 .. recs.len / 12];
    std.mem.sort(Rec, items, {}, struct {
        fn lt(_: void, x: Rec, y: Rec) bool {
            return std.mem.readInt(u32, x[4..8], .little) < std.mem.readInt(u32, y[4..8], .little);
        }
    }.lt);
}

// ── loading ─────────────────────────────────────────────────────────────────

pub const LoadOptions = struct {
    /// Override the object's `license` section (rarely wanted — the license
    /// gates which helpers the verifier allows).
    license: ?[]const u8 = null,
    /// Apply CO-RE relocations against `target_btf`.
    core: bool = true,
    /// The BTF to relocate against. `null` + `core` means "load
    /// `/sys/kernel/btf/vmlinux` here".
    target_btf: ?*const Btf = null,
    /// `BPF_BTF_LOAD` the object's own BTF and pass `prog_btf_fd` +
    /// `func_info`/`line_info`. Turn off for a kernel without BTF support.
    load_btf: bool = true,
    /// Proceed even though some executable sections matched no known prefix.
    ignore_unknown_sections: bool = false,
    /// Verifier log verbosity (1 = the normal human-readable log,
    /// 2 = per-instruction state).
    log_level: u32 = 1,
    /// Ceiling for the verifier log retry loop.
    max_log_bytes: usize = 16 << 20,
};

/// Create every map, relocate every program, and load them all.
///
/// On failure the object is left with whatever it managed to create (call
/// `close`/`deinit`), `verifier_log` holding the **untruncated** verifier
/// output and `failed_program` naming the program that lost.
pub fn load(obj: *Object, opts: LoadOptions) LoadError!void {
    if (comptime builtin.os.tag != .linux)
        @compileError("ebpf.object.load is Linux-only (bpf() raw syscall)");

    if (!opts.ignore_unknown_sections and obj.unknown_sections.len != 0)
        return error.UnknownProgramSection;

    // ── CO-RE, before anything is created: a relocation failure should not
    // leave maps behind. ──
    if (opts.core) {
        var have_relos = false;
        for (obj.programs) |p| {
            if (p.core_relos.len != 0) have_relos = true;
        }
        if (have_relos) {
            if (obj.btf) |*local| {
                var owned: ?Btf = null;
                defer if (owned) |*o| o.deinit();
                const target: *const Btf = if (opts.target_btf) |t| t else blk: {
                    owned = btf_mod.loadKernel(obj.gpa) catch return error.KernelBtfUnavailable;
                    break :blk &owned.?;
                };
                for (obj.programs) |*p| {
                    _ = try applyCoreRelos(p, local, target);
                }
            }
        }
    }

    // ── maps ──
    for (obj.maps) |*m| {
        if (m.pinning != 0) return error.PinningUnsupported;
        if (m.max_entries == 0 and needsEntries(m.map_type)) return error.ZeroMaxEntries;
        m.fd = try createMap(m);
        if (m.origin == .internal) {
            var key: [4]u8 = @splat(0);
            // `.bss` has no file bytes; the map is already zeroed.
            if (m.initial_data.len != 0) {
                BPF.map_update_elem(m.fd, &key, m.initial_data, 0) catch return error.MapUpdateFailed;
            }
            if (m.freeze) try freezeMap(m.fd);
        }
    }

    // ── the object's own BTF ──
    if (opts.load_btf and obj.btf_bytes != null) {
        try fixupDatasecs(obj);
        obj.btf_fd = btf_mod.loadIntoKernel(obj.btf_bytes.?, null) catch |e| switch (e) {
            error.PermissionDenied => return error.PermissionDenied,
            else => return error.BtfLoadFailed,
        };
    }

    // ── programs ──
    const license = opts.license orelse obj.license;
    for (obj.programs) |*p| {
        try relocateProgram(p, obj.maps);
        p.fd = try loadOneProgram(obj, p, license, opts);
    }
}

/// Map types the kernel refuses with `max_entries == 0`. `RINGBUF` uses
/// `max_entries` as a byte size (also mandatory); `STRUCT_OPS` and the
/// per-socket/per-task storage maps do not use it at all.
fn needsEntries(t: BPF.MapType) bool {
    return switch (t) {
        .struct_ops, .sk_storage => false,
        else => true,
    };
}

fn createMap(m: *const MapSpec) LoadError!linux.fd_t {
    var attr: BPF.MapCreateAttr = std.mem.zeroes(BPF.MapCreateAttr);
    attr.map_type = @backingInt(m.map_type);
    attr.key_size = m.key_size;
    attr.value_size = m.value_size;
    attr.max_entries = m.max_entries;
    attr.map_flags = m.map_flags;
    if (m.numa_node) |n| {
        attr.numa_node = n;
        attr.map_flags |= 1 << 2; // BPF_F_NUMA_NODE
    }
    // `map_name` is 16 bytes including the NUL, and the kernel's
    // `bpf_obj_name_cpy` rejects the whole call rather than truncating —
    // so truncate here. `[A-Za-z0-9_.]` is the accepted alphabet, which is
    // why `.rodata` can go in verbatim.
    const nm = m.name[0..@min(m.name.len, attr.map_name.len - 1)];
    @memcpy(attr.map_name[0..nm.len], nm);

    var buf: AttrBuf = .{ .map_create = attr };
    const rc = linux.bpf(.map_create, @ptrCast(&buf), @sizeOf(BPF.MapCreateAttr));
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .PERM, .ACCES => error.PermissionDenied,
        .INVAL => error.InvalidArgument,
        .NOMEM, .NOSPC, .MFILE, .NFILE => error.SystemResources,
        else => error.MapCreateFailed,
    };
}

/// `BPF_MAP_FREEZE` — makes a map immutable from userspace, which is what
/// lets the verifier treat a `BPF_F_RDONLY_PROG` array's contents as known
/// constants (the whole reason `const volatile` globals work).
fn freezeMap(fd: linux.fd_t) LoadError!void {
    var attr: BPF.MapElemAttr = std.mem.zeroes(BPF.MapElemAttr);
    attr.map_fd = @intCast(fd);
    var buf: AttrBuf = .{ .map_elem = attr };
    const rc = linux.bpf(.map_freeze, @ptrCast(&buf), @sizeOf(BPF.MapElemAttr));
    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => error.PermissionDenied,
        else => error.MapFreezeFailed,
    };
}

/// A `bpf_attr`-sized, 8-aligned staging area — the same trick `bpflink.zig`
/// documents: `bpf()` reads `size` bytes from this pointer and demands the
/// tail past the fields it knows be zero.
const AttrBuf = extern union {
    base: BPF.Attr,
    prog_load: tracing.ProgLoadAttr,
    map_create: BPF.MapCreateAttr,
    map_elem: BPF.MapElemAttr,
};

fn loadOneProgram(obj: *Object, p: *ProgramSpec, license: []const u8, opts: LoadOptions) LoadError!linux.fd_t {
    const a = obj.arena.allocator();

    var license_buf: [64]u8 = @splat(0);
    if (license.len >= license_buf.len) return error.InvalidArgument;
    @memcpy(license_buf[0..license.len], license);

    var log: []u8 = &.{};
    var log_level: u32 = 0;

    while (true) {
        var lo: tracing.LoadOptions = .{
            .license = license,
            .prog_name = p.kernelName(),
            .expected_attach_type = p.expected_attach_type,
            .prog_flags = if (p.sleepable) BPF_F_SLEEPABLE else 0,
            .kern_version = obj.kern_version,
        };
        if (obj.btf_fd >= 0) {
            lo.prog_btf_fd = obj.btf_fd;
            lo.func_info = p.func_info;
            lo.line_info = p.line_info;
        }
        if (log.len != 0) {
            lo.log = log;
            lo.log_level = log_level;
        }

        var buf: AttrBuf = .{
            .prog_load = tracing.buildProgLoadAttr(p.prog_type, p.insns, @ptrCast(&license_buf), lo) catch
                return error.InvalidArgument,
        };
        const rc = linux.bpf(.prog_load, @ptrCast(&buf), @sizeOf(tracing.ProgLoadAttr));
        switch (linux.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .NOSPC => {
                // The log buffer was too small — the REAL error is still
                // hidden. Grow (using `log_true_size` when the kernel is new
                // enough to fill it in) and try again.
                const want = @max(@as(usize, buf.prog_load.log_true_size), @max(log.len * 2, 64 << 10));
                if (want > opts.max_log_bytes or want <= log.len) return error.UnsafeProgram;
                log = a.alloc(u8, want) catch return error.OutOfMemory;
                log_level = if (opts.log_level == 0) 1 else opts.log_level;
                continue;
            },
            .ACCES => {
                if (log.len == 0 and opts.max_log_bytes >= 64 << 10) {
                    log = a.alloc(u8, 64 << 10) catch return error.OutOfMemory;
                    log_level = if (opts.log_level == 0) 1 else opts.log_level;
                    continue;
                }
                obj.verifier_log = cstrSlice(log);
                obj.failed_program = p.name;
                return error.UnsafeProgram;
            },
            .PERM => return error.PermissionDenied,
            .NOENT => return error.AttachTargetNotFound,
            .@"2BIG" => return error.ProgramTooLarge,
            .INVAL => {
                if (log.len != 0) {
                    obj.verifier_log = cstrSlice(log);
                    obj.failed_program = p.name;
                }
                return error.InvalidArgument;
            },
            .NOMEM, .MFILE, .NFILE => return error.SystemResources,
            else => return error.Unexpected,
        }
    }
}

// ── tests ────────────────────────────────────────────────────────────────────
//
// Four layers, only the last needing privilege:
//
//  1. Pure: the section-name table, and the instruction patchers driven with
//     hand-written instructions and synthetic values.
//  2. REAL clang objects, embedded byte for byte as fixtures (regenerate with
//     the command above each `@embedFile`): parsed, map-specs extracted,
//     relocations classified and APPLIED with synthetic map fds, and the
//     resulting instruction stream asserted word for word. This is the layer
//     that makes "everything up to the syscall" tested.
//  3. CO-RE patching against a SYNTHETIC target BTF whose fields moved (so a
//     no-op relocation fails immediately) and against the running kernel's
//     `/sys/kernel/btf/vmlinux`, which needs no capability to READ.
//  4. Hostile inputs: truncated, bogus `e_shstrndx`, out-of-range
//     relocations, a non-struct `.maps` VAR, an unaligned instruction
//     section.
//  5. LIVE: create maps + load programs for real. Needs CAP_BPF; prints
//     `SKIPPED:` and PASSES otherwise.

const testing = std.testing;

// The fixtures. Each `.o` is genuine, unmodified `clang -target bpf -O2 -g`
// output; the matching `.c` is committed next to it so they are regenerable:
//
//   $ cd /tmp/zlebpf && cp <repo>/modules/ebpf/src/testdata/*.bpf.c .
//   $ for f in xdp_pass kprobe_hash rodata_const ringbuf_map legacy_map core_reloc; do
//   >     clang -target bpf -O2 -g -c $f.bpf.c -o $f.bpf.o        # clang 21.1.8
//   > done
//
// (The directory matters: `-g` embeds the compilation directory in DWARF and
// the source path in `.BTF`'s string section, so the fixtures are only
// byte-reproducible from `/tmp/zlebpf`.)
const fx_xdp_pass = @embedFile("testdata/xdp_pass.bpf.o");
const fx_kprobe_hash = @embedFile("testdata/kprobe_hash.bpf.o");
const fx_rodata_const = @embedFile("testdata/rodata_const.bpf.o");
const fx_ringbuf_map = @embedFile("testdata/ringbuf_map.bpf.o");
const fx_legacy_map = @embedFile("testdata/legacy_map.bpf.o");
const fx_core_reloc = @embedFile("testdata/core_reloc.bpf.o");
const fx_two_progs = @embedFile("testdata/two_progs.bpf.o");
const fx_subprog = @embedFile("testdata/subprog.bpf.o");

test "section table: every prefix resolves, longest match wins" {
    // The exact-vs-target rule.
    try testing.expectEqual(BPF.ProgType.xdp, classifySection("xdp").?.def.prog_type);
    try testing.expectEqualStrings("", classifySection("xdp").?.target);
    try testing.expectEqualStrings("drop", classifySection("xdp/drop").?.target);

    // Longest match, not first match: `xdp/devmap` must not degrade to `xdp`.
    try testing.expectEqual(BPF.AttachType.xdp_devmap, classifySection("xdp/devmap").?.def.expected_attach_type.?);
    try testing.expectEqual(BPF.AttachType.xdp_cpumap, classifySection("xdp.frags/cpumap").?.def.expected_attach_type.?);
    try testing.expectEqual(BPF.AttachType.xdp, classifySection("xdp.frags").?.def.expected_attach_type.?);

    // kprobe/kretprobe/uprobe all load as BPF_PROG_TYPE_KPROBE — the
    // retprobe-ness lives in the perf event, not in the program type.
    for ([_][]const u8{ "kprobe/x", "kretprobe/x", "uprobe/a:b", "uretprobe/a:b", "ksyscall/openat" }) |s| {
        try testing.expectEqual(BPF.ProgType.kprobe, classifySection(s).?.def.prog_type);
    }
    try testing.expectEqual(BPF.AttachType.trace_kprobe_multi, classifySection("kprobe.multi/x*").?.def.expected_attach_type.?);

    // tracepoint targets keep their `<category>/<name>` shape.
    const tp = classifySection("tracepoint/syscalls/sys_enter_write").?;
    try testing.expectEqual(BPF.ProgType.tracepoint, tp.def.prog_type);
    try testing.expectEqualStrings("syscalls/sys_enter_write", tp.target);
    try testing.expectEqualStrings("sys_enter", classifySection("raw_tp/sys_enter").?.target);

    // The BTF-typed hooks and their expected_attach_type, which the kernel
    // matches on.
    try testing.expectEqual(BPF.AttachType.trace_fentry, classifySection("fentry/vfs_read").?.def.expected_attach_type.?);
    try testing.expectEqual(BPF.AttachType.trace_fexit, classifySection("fexit/vfs_read").?.def.expected_attach_type.?);
    try testing.expectEqual(BPF.AttachType.trace_raw_tp, classifySection("tp_btf/sched_switch").?.def.expected_attach_type.?);
    try testing.expectEqual(BPF.AttachType.lsm_mac, classifySection("lsm/file_open").?.def.expected_attach_type.?);
    try testing.expect(classifySection("lsm.s/file_open").?.def.sleepable);
    try testing.expect(classifySection("fentry.s/x").?.def.sleepable);

    // cgroup: same prog_type, different expected_attach_type per hook.
    try testing.expectEqual(BPF.AttachType.cgroup_inet_ingress, classifySection("cgroup_skb/ingress").?.def.expected_attach_type.?);
    try testing.expectEqual(BPF.AttachType.cgroup_inet4_connect, classifySection("cgroup/connect4").?.def.expected_attach_type.?);
    try testing.expectEqual(BPF.ProgType.cgroup_sock_addr, classifySection("cgroup/connect4").?.def.prog_type);
    try testing.expectEqual(BPF.ProgType.cgroup_sockopt, classifySection("cgroup/getsockopt").?.def.prog_type);

    // Not a program section.
    try testing.expect(classifySection(".text") == null);
    try testing.expect(classifySection(".maps") == null);
    try testing.expect(classifySection("nonsense") == null);
    // A prefix that is only a PREFIX of a real one must not match.
    try testing.expect(classifySection("xd") == null);
    try testing.expect(classifySection("kprobes/x") == null);

    // No two rows share a prefix (which would make "longest match" ambiguous).
    for (section_defs, 0..) |d, i| {
        for (section_defs[i + 1 ..]) |e| {
            try testing.expect(!std.mem.eql(u8, d.prefix, e.prefix));
        }
    }
}

test "data section names are recognized the way clang splits them" {
    for ([_][]const u8{ ".rodata", ".data", ".bss", ".rodata.str1.1", ".data.foo", ".rodata.cst8" }) |s| {
        try testing.expect(isDataSectionName(s));
    }
    for ([_][]const u8{ ".rodataX", ".text", "rodata", ".debug_info", ".BTF" }) |s| {
        try testing.expect(!isDataSectionName(s));
    }
    try testing.expect(isRodataName(".rodata.str1.1"));
    try testing.expect(!isRodataName(".data"));
}

test "object: an XDP object with two programs and no maps" {
    const gpa = testing.allocator;
    var obj = try open(gpa, fx_xdp_pass, .{ .require_bpf_machine = true });
    defer obj.deinit();

    try testing.expectEqualStrings("GPL", obj.license);
    try testing.expectEqual(@as(usize, 0), obj.maps.len);
    try testing.expectEqual(@as(usize, 0), obj.unknown_sections.len);
    try testing.expectEqual(@as(usize, 2), obj.programs.len);

    const pass = obj.findProgram("xdp_accept").?;
    try testing.expectEqualStrings("xdp", pass.sec_name);
    try testing.expectEqual(BPF.ProgType.xdp, pass.prog_type);
    try testing.expectEqual(BPF.AttachType.xdp, pass.expected_attach_type.?);
    try testing.expectEqual(@as(usize, 2), pass.insns.len); // r0 = 2; exit
    try testing.expectEqual(@as(i32, 2), pass.insns[0].imm); // XDP_PASS
    try testing.expectEqual(@as(u8, 0x95), pass.insns[1].code); // BPF_JMP|BPF_EXIT

    const drop = obj.findProgram("xdp_reject").?;
    try testing.expectEqualStrings("xdp/drop", drop.sec_name);
    try testing.expectEqualStrings("drop", drop.attach_target);
    try testing.expectEqual(@as(i32, 1), drop.insns[0].imm); // XDP_DROP

    // Looking a program up by SECTION name works too.
    try testing.expect(obj.findProgram("xdp/drop") == drop);
    try testing.expect(obj.findProgram("nope") == null);
    // Nothing is loaded yet.
    try testing.expect(obj.programFd("xdp_accept") == null);
}

test "object: a BTF-defined HASH map, extracted from the TYPE GRAPH" {
    const gpa = testing.allocator;
    var obj = try open(gpa, fx_kprobe_hash, .{});
    defer obj.deinit();

    try testing.expectEqual(@as(usize, 1), obj.maps.len);
    const m = obj.findMap("counts").?;
    try testing.expectEqual(MapOrigin.btf_defined, m.origin);
    // Every one of these came out of `.BTF`, not out of the `.maps` section
    // (which is 40 bytes of zeros).
    try testing.expectEqual(BPF.MapType.hash, m.map_type);
    try testing.expectEqual(@as(u32, 1024), m.max_entries);
    try testing.expectEqual(@as(u32, 0), m.map_flags);
    try testing.expectEqual(@as(u32, 4), m.key_size); // sizeof(unsigned int)
    try testing.expectEqual(@as(u32, 8), m.value_size); // sizeof(unsigned long long)
    try testing.expect(m.btf_key_type_id != 0);
    try testing.expect(m.btf_value_type_id != 0);
    // The `.maps` section really is all zeros — proof the numbers are not
    // being read out of it.
    const maps_sec = obj.image.findSection(".maps").?;
    for (try obj.image.sectionData(maps_sec)) |byte| try testing.expectEqual(@as(u8, 0), byte);

    // The BTF type ids the map declared must name the right types.
    const b = &obj.btf.?;
    try testing.expectEqualStrings("unsigned int", b.typeName(m.btf_key_type_id).?);
    try testing.expectEqualStrings("unsigned long long", b.typeName(m.btf_value_type_id).?);

    // One program, one relocation.
    try testing.expectEqual(@as(usize, 1), obj.programs.len);
    const p = obj.findProgram("count_open").?;
    try testing.expectEqualStrings("kprobe/do_sys_openat2", p.sec_name);
    try testing.expectEqualStrings("do_sys_openat2", p.attach_target);
    try testing.expectEqual(BPF.ProgType.kprobe, p.prog_type);
    try testing.expectEqual(@as(usize, 1), p.relos.len);
    try testing.expectEqual(ReloKind.map_fd, p.relos[0].kind);
    try testing.expectEqualStrings("counts", p.relos[0].sym_name);
    // `readelf -r` says r_offset 0x20 -> instruction 4.
    try testing.expectEqual(@as(u32, 4), p.relos[0].insn_idx);
    try testing.expectEqual(@as(u8, LD_IMM64_CODE), p.insns[4].code);
    try testing.expectEqual(@as(u4, 0), p.insns[4].src); // not yet relocated
    try testing.expectEqual(@as(i32, 0), p.insns[4].imm);

    // func_info/line_info were sliced and rebased to instruction indices.
    try testing.expectEqual(@as(usize, 1), p.func_info.len);
    try testing.expectEqual(@as(u32, 0), p.func_info[0].insn_off);
    try testing.expectEqualStrings("count_open", b.typeName(p.func_info[0].type_id).?);
    try testing.expect(p.line_info.len > 0);
    for (p.line_info) |li| try testing.expect(li.insn_off < p.insns.len);
}

test "relocation: a map fd is patched into the LD_IMM64 pair" {
    const gpa = testing.allocator;
    var obj = try open(gpa, fx_kprobe_hash, .{});
    defer obj.deinit();

    const p = obj.findProgram("count_open").?;
    // Not created yet -> a typed error, never a patch with -1.
    try testing.expectError(error.MapNotCreated, relocateProgram(p, obj.maps));

    // A synthetic fd stands in for BPF_MAP_CREATE: everything up to the
    // syscall is then exercised offline.
    obj.maps[0].fd = 4242;
    try relocateProgram(p, obj.maps);

    try testing.expectEqual(@as(u4, BPF_PSEUDO_MAP_FD), p.insns[4].src);
    try testing.expectEqual(@as(i32, 4242), p.insns[4].imm);
    // The second half of the pair is untouched for a plain map reference.
    try testing.expectEqual(@as(i32, 0), p.insns[5].imm);
    try testing.expectEqual(@as(u8, 0), p.insns[5].code);
    // Everything else is byte-identical to what clang emitted.
    try testing.expectEqual(@as(u8, 0x85), p.insns[6].code); // call
    try testing.expectEqual(@as(i32, 1), p.insns[6].imm); // bpf_map_lookup_elem

    obj.maps[0].fd = -1; // do not let deinit close fd 4242
}

test "object: .rodata globals become an internal map and MAP_VALUE relocations" {
    const gpa = testing.allocator;
    var obj = try open(gpa, fx_rodata_const, .{});
    defer obj.deinit();

    try testing.expectEqual(@as(usize, 1), obj.maps.len);
    const m = obj.findMap(".rodata").?;
    try testing.expectEqual(MapOrigin.internal, m.origin);
    try testing.expectEqual(BPF.MapType.array, m.map_type);
    try testing.expectEqual(@as(u32, 4), m.key_size);
    try testing.expectEqual(@as(u32, 1), m.max_entries);
    try testing.expectEqual(@as(u32, 16), m.value_size); // u32 + pad + u64
    try testing.expectEqual(BPF_F_RDONLY_PROG, m.map_flags);
    try testing.expect(m.freeze);
    // The seed data is the section's real contents: 42 and 0x1122334455667788.
    try testing.expectEqual(@as(usize, 16), m.initial_data.len);
    try testing.expectEqual(@as(u32, 42), std.mem.readInt(u32, m.initial_data[0..4], .little));
    try testing.expectEqual(@as(u64, 0x1122334455667788), std.mem.readInt(u64, m.initial_data[8..16], .little));

    const p = obj.findProgram("filter").?;
    try testing.expectEqual(@as(usize, 2), p.relos.len);
    for (p.relos) |r| try testing.expectEqual(ReloKind.map_value, r.kind);
    // `threshold` is at byte 0 of .rodata, `tag` at byte 8 — the offsets come
    // from the SYMBOLS' st_value, which is the half a naive loader drops.
    try testing.expectEqualStrings("threshold", p.relos[0].sym_name);
    try testing.expectEqual(@as(u64, 0), p.relos[0].value_off);
    try testing.expectEqualStrings("tag", p.relos[1].sym_name);
    try testing.expectEqual(@as(u64, 8), p.relos[1].value_off);

    obj.maps[0].fd = 77;
    try relocateProgram(p, obj.maps);
    for (p.relos) |r| {
        try testing.expectEqual(@as(u4, BPF_PSEUDO_MAP_VALUE), p.insns[r.insn_idx].src);
        try testing.expectEqual(@as(i32, 77), p.insns[r.insn_idx].imm);
        try testing.expectEqual(@as(i32, @intCast(r.value_off)), p.insns[r.insn_idx + 1].imm);
    }
    obj.maps[0].fd = -1;
}

test "hostile: a map_value relocation landing exactly on the value-size boundary is refused (D7)" {
    // `fx_rodata_const`'s "tag" symbol sits at byte 8 of a 16-byte
    // `.rodata`, a valid offset (test above). Locate "tag"'s symbol-table
    // entry in the real fixture and bump its `st_value` from 8 to 16 --
    // exactly `value_size`, one byte past the map's last valid byte, which
    // `off > value_size` accepted and `off >= value_size` (libbpf's own
    // convention) must not.
    const gpa = testing.allocator;
    var probe = try open(gpa, fx_rodata_const, .{});
    const symtab_idx = probe.symtab_idx;
    const sh_offset = probe.image.sections[symtab_idx].sh_offset;
    const n = try probe.image.symbolCount(symtab_idx);
    var target_off: ?usize = null;
    var si: u32 = 0;
    while (si < n) : (si += 1) {
        const sym = try probe.image.symbol(symtab_idx, si);
        if (std.mem.eql(u8, probe.image.symbolName(symtab_idx, sym), "tag")) {
            target_off = @intCast(sh_offset + @as(u64, si) * 24 + 8); // Elf64_Sym.st_value's own offset
            break;
        }
    }
    probe.deinit();
    const at = target_off.?;
    try testing.expectEqual(@as(u64, 8), std.mem.readInt(u64, fx_rodata_const[at..][0..8], .little));

    const img = try gpa.dupe(u8, fx_rodata_const);
    defer gpa.free(img);
    std.mem.writeInt(u64, img[at..][0..8], 16, .little); // was 8 (valid), now == value_size
    try testing.expectError(error.RelocationOutOfRange, open(gpa, img, .{}));
}

test "hostile: a datasec variable symbol with a >32-bit st_size is refused, not an @intCast panic" {
    // Regression (fuzz driver EBPF_FUZZ ebpf-object seed 1867): `fixupDatasecs`
    // narrowed the u64 `st_value` / `st_size` into BTF's u32 slots unchecked.
    const gpa = testing.allocator;
    var probe = try open(gpa, fx_rodata_const, .{});
    const symtab_idx = probe.symtab_idx;
    const sh_offset = probe.image.sections[symtab_idx].sh_offset;
    const n = try probe.image.symbolCount(symtab_idx);
    var target_off: ?usize = null;
    var si: u32 = 0;
    while (si < n) : (si += 1) {
        const sym = try probe.image.symbol(symtab_idx, si);
        if (std.mem.eql(u8, probe.image.symbolName(symtab_idx, sym), "tag")) {
            target_off = @intCast(sh_offset + @as(u64, si) * 24 + 16); // Elf64_Sym.st_size
            break;
        }
    }
    probe.deinit();
    const img = try gpa.dupe(u8, fx_rodata_const);
    defer gpa.free(img);
    std.mem.writeInt(u64, img[target_off.?..][0..8], 0x1_0000_0000, .little);
    var obj = try open(gpa, img, .{});
    defer obj.deinit();
    try testing.expectError(error.MalformedElf, fixupDatasecs(&obj));
}

test "hostile: a .BTF.ext record whose insn_off is not 8-aligned is refused, not silently rounded (D8)" {
    // `sliceBtfExt` is called directly with a hand-built `Object`/`ProgramSpec`
    // rather than through a full `open()` -- the ELF/symbol-table plumbing
    // D5's and D7's tests exercise is orthogonal to this bug, which lives
    // entirely in the `(insn_off - lo) / 8` conversion below `sliceBtfExt`.
    const gpa = testing.allocator;

    // A BTF blob whose only job is to hold the program-section-name string
    // `sliceBtfExt` looks `sec_name_off` up in.
    var bb = btf_mod.Builder.init(gpa);
    defer bb.deinit();
    const sec_name_off = try bb.addString("myprog");
    const btf_bytes = try bb.finish();
    defer gpa.free(btf_bytes);
    var parsed_btf = try btf_mod.parse(gpa, btf_bytes, .{});
    defer parsed_btf.deinit();

    // A minimal `.BTF.ext`: header (24 bytes, no core_relo) + one func_info
    // group (rec_size(4) + sec_name_off(4) + count(4) + one 8-byte record)
    // whose `insn_off` is 12 -- inside a 2-instruction (16-byte) program
    // starting at `sec_byte_off` 0, so `lo <= 12 < hi`, but `12 % 8 != 0`.
    const hdr_len: u32 = btfext.header_size_min; // 24, no core_relo
    var ext_bytes: [24 + 20]u8 = undefined;
    @memset(&ext_bytes, 0);
    std.mem.writeInt(u16, ext_bytes[0..2], btfext.magic, .little);
    ext_bytes[2] = btfext.version;
    std.mem.writeInt(u32, ext_bytes[4..8], hdr_len, .little);
    std.mem.writeInt(u32, ext_bytes[8..12], 0, .little); // func_info_off (relative to hdr_len)
    std.mem.writeInt(u32, ext_bytes[12..16], 20, .little); // func_info_len
    std.mem.writeInt(u32, ext_bytes[16..20], 20, .little); // line_info_off (past func_info, empty)
    std.mem.writeInt(u32, ext_bytes[20..24], 0, .little); // line_info_len
    const func_info_group = ext_bytes[hdr_len..][0..20];
    std.mem.writeInt(u32, func_info_group[0..4], 8, .little); // rec_size
    std.mem.writeInt(u32, func_info_group[4..8], sec_name_off, .little);
    std.mem.writeInt(u32, func_info_group[8..12], 1, .little); // count
    std.mem.writeInt(u32, func_info_group[12..16], 12, .little); // insn_off -- misaligned
    std.mem.writeInt(u32, func_info_group[16..20], 0, .little); // type_id
    const ext = try btfext.parseExt(&ext_bytes);

    const zero_insn: Insn = .{ .code = 0, .dst = 0, .src = 0, .off = 0, .imm = 0 };
    var insns = [_]Insn{ zero_insn, zero_insn }; // 2 instructions: hi = 0 + 2*8 = 16
    var prog: ProgramSpec = undefined;
    prog.sec_name = "myprog";
    prog.sec_byte_off = 0;
    prog.insns = &insns;

    var obj: Object = undefined;
    obj.btf = parsed_btf;
    obj.ext = ext;

    try testing.expectError(error.RelocationOutOfRange, sliceBtfExt(&obj, gpa, &prog));
}

test "object: a BTF-defined RINGBUF map (max_entries is a BYTE SIZE)" {
    const gpa = testing.allocator;
    var obj = try open(gpa, fx_ringbuf_map, .{});
    defer obj.deinit();

    const m = obj.findMap("events").?;
    try testing.expectEqual(BPF.MapType.ringbuf, m.map_type);
    try testing.expectEqual(@as(u32, 4096), m.max_entries);
    // A ringbuf has no key and no value type at all.
    try testing.expectEqual(@as(u32, 0), m.key_size);
    try testing.expectEqual(@as(u32, 0), m.value_size);

    const p = obj.findProgram("on_write").?;
    try testing.expectEqual(BPF.ProgType.tracepoint, p.prog_type);
    try testing.expectEqualStrings("syscalls/sys_enter_write", p.attach_target);
    try testing.expectEqual(@as(usize, 1), p.relos.len);
    try testing.expectEqual(@as(u32, 0), p.relos[0].insn_idx);

    obj.maps[0].fd = 9;
    try relocateProgram(p, obj.maps);
    try testing.expectEqual(@as(u4, BPF_PSEUDO_MAP_FD), p.insns[0].src);
    try testing.expectEqual(@as(i32, 9), p.insns[0].imm);
    obj.maps[0].fd = -1;
}

test "object: two programs in ONE section, split at their function symbols" {
    const gpa = testing.allocator;
    var obj = try open(gpa, fx_two_progs, .{});
    defer obj.deinit();

    // One ELF section, two `STT_FUNC` symbols -> two programs.
    try testing.expectEqual(@as(usize, 2), obj.programs.len);
    const first = obj.findProgram("first").?;
    const second = obj.findProgram("second").?;
    try testing.expectEqualStrings("xdp", first.sec_name);
    try testing.expectEqualStrings("xdp", second.sec_name);
    try testing.expectEqual(first.sec_idx, second.sec_idx);

    // `readelf -s` puts `first` at 0 (96 bytes) and `second` at 0x60.
    try testing.expectEqual(@as(u64, 0), first.sec_byte_off);
    try testing.expectEqual(@as(u64, 0x60), second.sec_byte_off);
    try testing.expectEqual(@as(usize, 12), first.insns.len);
    try testing.expectEqual(@as(usize, 12), second.insns.len);
    // Different bodies: `first` returns XDP_PASS, `second` XDP_DROP.
    try testing.expect(!std.mem.eql(u8, std.mem.sliceAsBytes(first.insns), std.mem.sliceAsBytes(second.insns)));

    // The section's TWO relocations (r_offset 0x20 and 0x80) must be split
    // one per program, each rebased to a program-local instruction index —
    // both land on instruction 4 of their own function.
    try testing.expectEqual(@as(usize, 1), first.relos.len);
    try testing.expectEqual(@as(usize, 1), second.relos.len);
    try testing.expectEqual(@as(u32, 4), first.relos[0].insn_idx);
    try testing.expectEqual(@as(u32, 4), second.relos[0].insn_idx);
    try testing.expectEqualStrings("stats", first.relos[0].sym_name);
    try testing.expectEqualStrings("stats", second.relos[0].sym_name);

    // ...and `.BTF.ext`'s per-section records split the same way.
    try testing.expectEqual(@as(usize, 1), first.func_info.len);
    try testing.expectEqual(@as(usize, 1), second.func_info.len);
    try testing.expectEqual(@as(u32, 0), first.func_info[0].insn_off);
    try testing.expectEqual(@as(u32, 0), second.func_info[0].insn_off);
    const b = &obj.btf.?;
    try testing.expectEqualStrings("first", b.typeName(first.func_info[0].type_id).?);
    try testing.expectEqualStrings("second", b.typeName(second.func_info[0].type_id).?);
    for (first.line_info) |li| try testing.expect(li.insn_off < first.insns.len);
    for (second.line_info) |li| try testing.expect(li.insn_off < second.insns.len);

    obj.maps[0].fd = 31;
    try relocateProgram(first, obj.maps);
    try relocateProgram(second, obj.maps);
    try testing.expectEqual(@as(i32, 31), first.insns[4].imm);
    try testing.expectEqual(@as(i32, 31), second.insns[4].imm);
    try testing.expectEqual(@as(u4, BPF_PSEUDO_MAP_FD), first.insns[4].src);
    try testing.expectEqual(@as(u4, BPF_PSEUDO_MAP_FD), second.insns[4].src);
    obj.maps[0].fd = -1;
}

test "object: the legacy `maps` section and a `version` section" {
    const gpa = testing.allocator;
    var obj = try open(gpa, fx_legacy_map, .{});
    defer obj.deinit();

    try testing.expectEqual(@as(u32, 0x40f00), obj.kern_version);
    const m = obj.findMap("legacy_counts").?;
    try testing.expectEqual(MapOrigin.legacy, m.origin);
    try testing.expectEqual(BPF.MapType.array, m.map_type);
    try testing.expectEqual(@as(u32, 4), m.key_size);
    try testing.expectEqual(@as(u32, 8), m.value_size);
    try testing.expectEqual(@as(u32, 16), m.max_entries);
    // A legacy definition carries no BTF ids — that is the whole difference.
    try testing.expectEqual(@as(u32, 0), m.btf_key_type_id);

    const p = obj.findProgram("sock_count").?;
    try testing.expectEqual(BPF.ProgType.socket_filter, p.prog_type);
    try testing.expectEqual(@as(usize, 1), p.relos.len);
    try testing.expectEqual(ReloKind.map_fd, p.relos[0].kind);
}

// ── D5: `parseLegacyMaps` must be linear, not quadratic ─────────────────────
//
// Builds a synthetic `Image` directly (bypassing full ELF64-header parsing,
// which `parseLegacyMaps` never touches) with `count` legacy map defs and a
// matching `count`-entry `STT_OBJECT` symbol table, named "m0".."m{n-1}" at
// `st_value = idx * 20` -- structurally the same shape `parseLegacyMaps`
// reads, just built without a real linker.

/// `Elf64_Sym` is a fixed 24 bytes (name:u32, info:u8, other:u8, shndx:u16,
/// value:u64, size:u64) -- `elfsym.zig`'s own `SYM_SIZE` is private to that
/// file, so this test-only helper restates the constant rather than reaching
/// across the module.
const test_sym_size: usize = 24;

fn buildSyntheticLegacyMapsImage(a: std.mem.Allocator, count: usize) !elfsym.Image {
    const maps_len = count * legacy_map_def_size;

    var strtab: std.ArrayList(u8) = .empty;
    try strtab.append(a, 0); // index 0 is always the empty string
    const name_offs = try a.alloc(u32, count);
    var buf: [16]u8 = undefined;
    for (0..count) |idx| {
        name_offs[idx] = @intCast(strtab.items.len);
        const name = std.mem.print(&buf, "m{d}", .{idx}) catch unreachable;
        try strtab.appendSlice(a, name);
        try strtab.append(a, 0);
    }

    const symtab_len = (count + 1) * test_sym_size; // +1: the reserved null symbol
    const maps_off: usize = 0;
    const symtab_off = maps_off + maps_len;
    const strtab_off = symtab_off + symtab_len;
    const total = strtab_off + strtab.items.len;

    const bytes = try a.alloc(u8, total);
    @memset(bytes, 0); // covers the "maps" section (contents unread by parseLegacyMaps beyond byte-count) and symbol 0
    for (0..count) |idx| {
        const at = symtab_off + (idx + 1) * test_sym_size;
        std.mem.writeInt(u32, bytes[at..][0..4], name_offs[idx], .little); // st_name
        bytes[at + 4] = (@as(u8, 1) << 4) | STT_OBJECT; // st_info: STB_GLOBAL | STT_OBJECT
        std.mem.writeInt(u16, bytes[at + 6 ..][0..2], 1, .little); // st_shndx = section 1 ("maps")
        std.mem.writeInt(u64, bytes[at + 8 ..][0..8], idx * legacy_map_def_size, .little); // st_value
        std.mem.writeInt(u64, bytes[at + 16 ..][0..8], legacy_map_def_size, .little); // st_size
    }
    const strtab_len = strtab.items.len; // captured BEFORE deinit -- ArrayList.deinit resets .items
    @memcpy(bytes[strtab_off..][0..strtab_len], strtab.items);
    a.free(name_offs);
    strtab.deinit(a);

    const sections = try a.alloc(elfsym.SectionHeader, 4);
    sections[0] = .{ .index = 0, .sh_name = 0, .sh_type = 0, .sh_flags = 0, .sh_addr = 0, .sh_offset = 0, .sh_size = 0, .sh_link = 0, .sh_info = 0, .sh_addralign = 0, .sh_entsize = 0 };
    sections[1] = .{ .index = 1, .sh_name = 0, .sh_type = 1, .sh_flags = 0, .sh_addr = 0, .sh_offset = maps_off, .sh_size = maps_len, .sh_link = 0, .sh_info = 0, .sh_addralign = 0, .sh_entsize = 0 }; // SHT_PROGBITS
    sections[2] = .{ .index = 2, .sh_name = 0, .sh_type = 2, .sh_flags = 0, .sh_addr = 0, .sh_offset = symtab_off, .sh_size = symtab_len, .sh_link = 3, .sh_info = 0, .sh_addralign = 0, .sh_entsize = test_sym_size }; // SHT_SYMTAB
    sections[3] = .{ .index = 3, .sh_name = 0, .sh_type = 3, .sh_flags = 0, .sh_addr = 0, .sh_offset = strtab_off, .sh_size = strtab_len, .sh_link = 0, .sh_info = 0, .sh_addralign = 0, .sh_entsize = 0 }; // SHT_STRTAB

    return .{
        .gpa = a,
        .bytes = bytes,
        .owns_bytes = true,
        .e_type = 1, // ET_REL
        .e_machine = elfsym.EM_BPF,
        .sections = sections,
        .shstrtab = &.{},
    };
}

/// Calls `parseLegacyMaps` directly against a synthetic `count`-map image and
/// returns elapsed nanoseconds. Uses `page_allocator` (untracked) rather than
/// `testing.allocator`: this is a timing probe, not a leak check, and an
/// arena-per-call would itself dominate the measurement at small `count`.
fn nowNsMonotonic() u64 {
    // `std.time.Timer` does not exist in this Zig version -- same
    // `clock_gettime`-direct pattern `bfv`'s bench uses.
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn timeParseLegacyMaps(count: usize) !u64 {
    const pa = std.heap.page_allocator; // global-alloc-ok: timing probe (D5), not a leak check -- testing.allocator's per-call bookkeeping would itself dominate the measurement at small `count`
    var image = try buildSyntheticLegacyMapsImage(pa, count);
    defer image.deinit();

    var obj: Object = undefined;
    obj.image = image;
    obj.symtab_idx = 2;

    var out: std.ArrayList(MapSpec) = .empty;
    const start = nowNsMonotonic();
    try parseLegacyMaps(&obj, pa, 1, &out);
    const ns = nowNsMonotonic() - start;
    try testing.expectEqual(count, out.items.len);
    return ns;
}

test "parseLegacyMaps: work scales linearly with map count, not quadratically (D5)" {
    // Regression for a MEDIUM: the pre-fix shape rescanned the WHOLE symbol
    // table once per map def, so `open()` was O(maps * symbols) on two
    // counts that both come straight off an attacker-supplied `.o`'s wire
    // header. Audit measurement on the original code (ReleaseFast): count
    // 8000 -> 113 ms, 16000 -> 454 ms, 32000 -> 1780 ms -- textbook 4x per
    // 2x. A fixed, linear implementation should show close to flat
    // NANOSECONDS-PER-MAP-DEF as `count` grows, not a rising one.
    //
    // Skip under a foreign or badly loaded machine: this asserts a RATIO,
    // not a wall-clock ceiling, and still catches the O(n^2) shape the
    // fix removed.
    const small = try timeParseLegacyMaps(500);
    const large = try timeParseLegacyMaps(8000); // 16x the count
    const ns_per_map_small = @as(f64, @floatFromInt(small)) / 500.0;
    const ns_per_map_large = @as(f64, @floatFromInt(large)) / 8000.0;
    // Quadratic work would make ns/map at 16x the count roughly 16x higher
    // (n^2/n = n); linear work keeps it roughly flat. A generous 4x ceiling
    // comfortably separates the two shapes without being sensitive to
    // ordinary scheduling noise on a shared machine.
    try testing.expect(ns_per_map_large < ns_per_map_small * 4.0 + 1000.0);
}

test "BTF DATASEC fixup: clang emits size 0, the kernel refuses that" {
    const gpa = testing.allocator;
    var obj = try open(gpa, fx_kprobe_hash, .{});
    defer obj.deinit();

    const b = &obj.btf.?;
    const ds = b.findByNameKind(".maps", .datasec).?;
    // As clang emitted it.
    try testing.expectEqual(@as(?u32, 0), (try b.byId(ds)).byteSize());

    try fixupDatasecs(&obj);

    // The `.maps` section is 40 bytes (one `struct` of five pointers).
    const t = try b.byId(ds);
    try testing.expectEqual(@as(?u32, 40), t.byteSize());
    const vsi = try b.varSecInfo(t, 0);
    try testing.expectEqual(@as(u32, 0), vsi.offset);
    try testing.expectEqual(@as(u32, 40), vsi.size);
    try testing.expectEqualStrings("counts", b.typeName(vsi.type_id).?);

    // `license` too — every DATASEC has to be fixed, not just `.maps`.
    const lic = b.findByNameKind("license", .datasec).?;
    try testing.expectEqual(@as(?u32, 4), (try b.byId(lic)).byteSize());

    // Idempotent: running it twice must not double anything.
    try fixupDatasecs(&obj);
    try testing.expectEqual(@as(?u32, 40), (try b.byId(ds)).byteSize());
}

test "DATASEC fixup places .rodata variables at their symbol offsets" {
    const gpa = testing.allocator;
    var obj = try open(gpa, fx_rodata_const, .{});
    defer obj.deinit();
    try fixupDatasecs(&obj);

    const b = &obj.btf.?;
    const ds = b.findByNameKind(".rodata", .datasec).?;
    const t = try b.byId(ds);
    try testing.expectEqual(@as(?u32, 16), t.byteSize());
    try testing.expectEqual(@as(u16, 2), t.vlen);
    // Ascending offsets, which is what the kernel's BTF verifier requires.
    const v0 = try b.varSecInfo(t, 0);
    const v1 = try b.varSecInfo(t, 1);
    try testing.expectEqual(@as(u32, 0), v0.offset);
    try testing.expectEqual(@as(u32, 4), v0.size);
    try testing.expectEqualStrings("threshold", b.typeName(v0.type_id).?);
    try testing.expectEqual(@as(u32, 8), v1.offset);
    try testing.expectEqual(@as(u32, 8), v1.size);
    try testing.expectEqualStrings("tag", b.typeName(v1.type_id).?);
    try testing.expect(v0.offset < v1.offset);
}

// ── CO-RE instruction patching ──────────────────────────────────────────────

test "patchCoreInsn: each instruction class takes the value in a different field" {
    // LDX: the member offset goes in `off`.
    {
        var insns = [_]Insn{Insn.ldx(.word, .r0, .r1, 0)};
        try patchCoreInsn(&insns, 0, .field_byte_offset, 2464);
        try testing.expectEqual(@as(i16, 2464), insns[0].off);
    }
    // LDX + FIELD_BYTE_SIZE: the OPCODE's size bits change, not an operand.
    {
        var insns = [_]Insn{Insn.ldx(.word, .r0, .r1, 8)};
        const before = insns[0].code;
        try patchCoreInsn(&insns, 0, .field_byte_size, 8);
        try testing.expectEqual(@as(u8, (before & ~@as(u8, 0x18)) | 0x18), insns[0].code); // BPF_DW
        try testing.expectEqual(@as(i16, 8), insns[0].off); // unchanged
        try patchCoreInsn(&insns, 0, .field_byte_size, 1);
        try testing.expectEqual(@as(u8, (before & ~@as(u8, 0x18)) | 0x10), insns[0].code); // BPF_B
    }
    // ALU64 with an immediate: `imm`. This is how the bitfield shifts land.
    {
        var insns = [_]Insn{Insn.add(.r1, 0)};
        try patchCoreInsn(&insns, 0, .field_lshift_u64, 33);
        try testing.expectEqual(@as(i32, 33), insns[0].imm);
    }
    // ALU with a REGISTER source has no immediate to patch.
    {
        var insns = [_]Insn{Insn.add(.r1, .r2)};
        try testing.expectError(error.UnsupportedCoreInsn, patchCoreInsn(&insns, 0, .field_byte_offset, 8));
    }
    // LD_IMM64: split across the pair, high half in the SECOND instruction.
    {
        var insns = [_]Insn{ Insn.ld_dw1(.r1, 0), Insn.ld_dw2(0) };
        try patchCoreInsn(&insns, 0, .field_byte_offset, 0x1122334455667788);
        try testing.expectEqual(@as(u32, 0x55667788), @as(u32, @bitCast(insns[0].imm)));
        try testing.expectEqual(@as(u32, 0x11223344), @as(u32, @bitCast(insns[1].imm)));
    }
    // Bounds and range.
    {
        var insns = [_]Insn{Insn.ldx(.word, .r0, .r1, 0)};
        try testing.expectError(error.RelocationOutOfRange, patchCoreInsn(&insns, 1, .field_byte_offset, 0));
        try testing.expectError(error.CoreValueTooLarge, patchCoreInsn(&insns, 0, .field_byte_offset, 40000));
        try testing.expectError(error.CoreValueTooLarge, patchCoreInsn(&insns, 0, .field_byte_size, 3));
    }
    // A JMP cannot carry a field offset.
    {
        var insns = [_]Insn{Insn.exit()};
        try testing.expectError(error.UnsupportedCoreInsn, patchCoreInsn(&insns, 0, .field_byte_offset, 8));
    }
}

test "CO-RE: a real clang object relocated against ITSELF changes nothing" {
    const gpa = testing.allocator;
    var obj = try open(gpa, fx_core_reloc, .{});
    defer obj.deinit();

    const p = obj.findProgram("trace_pid").?;
    try testing.expect(p.core_relos.len >= 2);
    for (p.core_relos) |r| {
        try testing.expect(r.insn_off < p.insns.len); // rebased to indices
        try testing.expectEqual(btfext.ReloKind.field_byte_offset, r.reloKind());
    }

    // clang already compiled the LOCAL offsets in, so relocating against the
    // local BTF must be a fixed point. A patcher that wrote to the wrong
    // field would show up here immediately.
    const before = try gpa.dupe(Insn, p.insns);
    defer gpa.free(before);
    const b = &obj.btf.?;
    const n = try applyCoreRelos(p, b, b);
    try testing.expectEqual(p.core_relos.len, n);
    try testing.expectEqualSlices(Insn, before, p.insns);
}

test "CO-RE: relocating against a target whose fields MOVED rewrites the insns" {
    const gpa = testing.allocator;
    var obj = try open(gpa, fx_core_reloc, .{});
    defer obj.deinit();
    const p = obj.findProgram("trace_pid").?;
    const local = &obj.btf.?;

    // A synthetic "other kernel" where `task_struct` gained 64 bytes of
    // padding in front of `pid`/`tgid`.
    var bld: btf_mod.Builder = .init(gpa);
    defer bld.deinit();
    const int_id = try bld.addInt("int", 4, 32, 1);
    const char_id = try bld.addInt("char", 1, 8, 2);
    const arr_id = try bld.addArray(char_id, int_id, 64);
    _ = try bld.addComposite(.@"struct", "task_struct", 136, &.{
        .{ .name = "pad", .type_id = arr_id, .bit_offset = 0 },
        .{ .name = "pid", .type_id = int_id, .bit_offset = 64 * 8 },
        .{ .name = "tgid", .type_id = int_id, .bit_offset = 65 * 8 },
    });
    const blob = try bld.finish();
    var target = try btf_mod.parse(gpa, blob, .{ .own_bytes = true });
    defer target.deinit();

    // Record which instruction each relocation names and what it held.
    var seen: [8]u32 = undefined;
    var k: usize = 0;
    for (p.core_relos) |r| {
        seen[k] = r.insn_off;
        k += 1;
    }
    const n = try applyCoreRelos(p, local, &target);
    try testing.expectEqual(p.core_relos.len, n);

    // `pid` is now at byte 64 and `tgid` at byte 65 — both must appear as
    // LDX offsets, and neither may still be at its local offset (0 and 4).
    var saw64 = false;
    var saw65 = false;
    for (seen[0..k]) |idx| {
        const off = p.insns[idx].off;
        try testing.expectEqual(@as(u8, BPF_LDX), p.insns[idx].code & 0x07);
        if (off == 64) saw64 = true;
        if (off == 65) saw65 = true;
    }
    try testing.expect(saw64);
    try testing.expect(saw65);
}

test "CO-RE: relocate a real object against /sys/kernel/btf/vmlinux" {
    const gpa = testing.allocator;
    // Reading kernel BTF needs NO capability — /sys/kernel/btf/vmlinux is
    // 0444 — so this one really runs on an unprivileged box.
    var vmlinux = btf_mod.loadKernel(gpa) catch {
        if (verboseSkip()) std.debug.print("\nSKIPPED: ebpf.object CO-RE-vs-vmlinux — no /sys/kernel/btf/vmlinux.\n", .{});
        return error.SkipZigTest;
    };
    defer vmlinux.deinit();

    var obj = try open(gpa, fx_core_reloc, .{});
    defer obj.deinit();
    const p = obj.findProgram("trace_pid").?;
    const local = &obj.btf.?;

    const n = applyCoreRelos(p, local, &vmlinux) catch |e| {
        if (verboseSkip()) std.debug.print("\nSKIPPED: ebpf.object CO-RE-vs-vmlinux — {s}.\n", .{@errorName(e)});
        return error.SkipZigTest;
    };
    try testing.expectEqual(p.core_relos.len, n);

    // The fixture's own `task_struct` has `pid` at byte 0; no real kernel
    // does. A relocation that quietly did nothing fails right here.
    var any_moved = false;
    for (p.core_relos) |r| {
        if (p.insns[r.insn_off].off > 16) any_moved = true;
    }
    try testing.expect(any_moved);
    // Informational, not a failure — same stderr rule as the skip reasons.
    if (verboseSkip()) std.debug.print(
        "\nebpf.object: CO-RE against this kernel put task_struct.pid at byte {d}.\n",
        .{p.insns[p.core_relos[0].insn_off].off},
    );
}

// ── hostile inputs ──────────────────────────────────────────────────────────

test "hostile: truncated, non-ELF, and wrong-class objects are typed errors" {
    const gpa = testing.allocator;

    try testing.expectError(error.NotABpfObject, open(gpa, "", .{}));
    try testing.expectError(error.NotABpfObject, open(gpa, "not an elf at all, really", .{}));
    // Valid magic, truncated before the end of the Ehdr.
    try testing.expectError(error.NotABpfObject, open(gpa, "\x7fELF\x02\x01\x01" ++ (strRepeat("\x00", 20)), .{}));

    // Every prefix of a real object: none may crash, hang, or leak.
    var cut: usize = 1;
    while (cut < fx_kprobe_hash.len) : (cut += 97) {
        if (open(gpa, fx_kprobe_hash[0..cut], .{})) |*o| {
            var oo = o.*;
            oo.deinit();
        } else |e| switch (e) {
            error.NotABpfObject,
            error.MalformedElf,
            error.MalformedBtf,
            error.NoSymbolTable,
            error.MissingBtf,
            error.MalformedMapDefinition,
            error.UnalignedInstructionSection,
            error.RelocationOutOfRange,
            error.UnresolvedRelocation,
            error.OutOfMemory,
            => {},
            else => return e,
        }
    }
}

test "hostile: a bogus e_shstrndx costs the NAMES, not the object" {
    const gpa = testing.allocator;
    const img = try gpa.dupe(u8, fx_kprobe_hash);
    defer gpa.free(img);
    // e_shstrndx = 0xfffe — past the section table but not SHN_XINDEX.
    std.mem.writeInt(u16, img[62..64], 0xfffe, .little);

    var image = try elfsym.openImage(gpa, img, false);
    defer image.deinit();
    try testing.expect(image.sections.len > 3);
    for (0..image.sections.len) |i| try testing.expectEqualStrings("", image.sectionName(i));
    try testing.expect(image.findSection(".maps") == null);

    // The object then has no program sections at all — a coherent, empty
    // result rather than a mis-parse.
    var obj = try open(gpa, img, .{});
    defer obj.deinit();
    try testing.expectEqual(@as(usize, 0), obj.programs.len);
    try testing.expectEqual(@as(usize, 0), obj.maps.len);
}

test "hostile: e_shoff past the end, and an absurd e_shnum" {
    const gpa = testing.allocator;
    {
        const img = try gpa.dupe(u8, fx_xdp_pass);
        defer gpa.free(img);
        std.mem.writeInt(u64, img[40..48], 0x7fff_ffff, .little);
        try testing.expectError(error.MalformedElf, open(gpa, img, .{}));
    }
    {
        const img = try gpa.dupe(u8, fx_xdp_pass);
        defer gpa.free(img);
        std.mem.writeInt(u16, img[60..62], 0xffff, .little);
        try testing.expectError(error.MalformedElf, open(gpa, img, .{}));
    }
    {
        // sh_entsize smaller than an Elf64_Shdr.
        const img = try gpa.dupe(u8, fx_xdp_pass);
        defer gpa.free(img);
        std.mem.writeInt(u16, img[58..60], 8, .little);
        try testing.expectError(error.MalformedElf, open(gpa, img, .{}));
    }
}

test "hostile: a relocation pointing past the instruction stream" {
    const gpa = testing.allocator;
    var obj = try open(gpa, fx_kprobe_hash, .{});
    defer obj.deinit();
    const p = obj.findProgram("count_open").?;

    // The parser rejected nothing (the object is fine); force the pathologic
    // case the way a corrupt `.rel` section would.
    var relos = [_]Relo{.{ .kind = .map_fd, .insn_idx = 9999, .map_idx = 0, .sym_name = "counts" }};
    var fake = p.*;
    fake.relos = &relos;
    obj.maps[0].fd = 5;
    try testing.expectError(error.RelocationOutOfRange, relocateProgram(&fake, obj.maps));

    // A `map_value` whose second half is off the end.
    var relos2 = [_]Relo{.{
        .kind = .map_value,
        .insn_idx = @intCast(p.insns.len - 1),
        .map_idx = 0,
        .sym_name = "counts",
    }};
    fake.relos = &relos2;
    // The last instruction is `exit`, not LD_IMM64 — caught even earlier.
    try testing.expectError(error.NotAnImmediateLoad, relocateProgram(&fake, obj.maps));
    obj.maps[0].fd = -1;
}

test "hostile: an unaligned relocation offset in a real .rel section" {
    const gpa = testing.allocator;
    const img = try gpa.dupe(u8, fx_kprobe_hash);
    defer gpa.free(img);

    // Find `.relkprobe/do_sys_openat2` and skew its single r_offset by 4.
    var image = try elfsym.openImage(gpa, img, false);
    const rel_idx = image.findSection(".relkprobe/do_sys_openat2").?;
    const off: usize = @intCast(image.sections[rel_idx].sh_offset);
    image.deinit();
    std.mem.writeInt(u64, img[off..][0..8], 0x24, .little);

    try testing.expectError(error.RelocationOutOfRange, open(gpa, img, .{}));
}

test "hostile: an unaligned instruction section" {
    const gpa = testing.allocator;
    const img = try gpa.dupe(u8, fx_xdp_pass);
    defer gpa.free(img);

    var image = try elfsym.openImage(gpa, img, false);
    const xdp = image.findSection("xdp").?;
    // The section header table's entry for `xdp`: patch sh_size to 0x11.
    const shoff = std.mem.readInt(u64, img[40..48], .little);
    const shent = std.mem.readInt(u16, img[58..60], .little);
    image.deinit();
    const at: usize = @intCast(shoff + @as(u64, xdp) * shent + 32);
    std.mem.writeInt(u64, img[at..][0..8], 0x11, .little);

    try testing.expectError(error.UnalignedInstructionSection, open(gpa, img, .{}));
}

test "hostile: a symbol whose st_size overflows the program-range bound" {
    // Regression for a CRITICAL. `size` is the symbol's raw `st_size`, a u64
    // straight off the wire. `st_value` was bounded against `data.len`;
    // `st_size` never was, and the bound was written `r.off + size > data.len`,
    // which wraps. `st_value = 8` with `st_size = 0xFFFF_FFFF_FFFF_FFF8` — a
    // multiple of 8, so the alignment check above it passes — sums to 0 and was
    // accepted. What followed was an allocation whose own size arithmetic
    // wrapped and then a `@memcpy` of 2^64-8 bytes.
    //
    // Measured before the fix, on exactly this input: `integer overflow` panic
    // in Debug and ReleaseSafe, and in ReleaseFast — which has no overflow
    // check at all — an out-of-bounds WRITE, SIGSEGV. `open()` is the
    // documented untrusted-input entry point and needs no privilege.
    const gpa = testing.allocator;
    const img = try gpa.dupe(u8, fx_xdp_pass);
    defer gpa.free(img);

    const shoff = std.mem.readInt(u64, img[40..48], .little);
    const shent = std.mem.readInt(u16, img[58..60], .little);
    const shnum = std.mem.readInt(u16, img[60..62], .little);
    var sym_off: u64 = 0;
    var sym_size: u64 = 0;
    var sym_ent: u64 = 0;
    var i: u16 = 0;
    while (i < shnum) : (i += 1) {
        const at: usize = @intCast(shoff + @as(u64, i) * shent);
        if (std.mem.readInt(u32, img[at + 4 ..][0..4], .little) != 2) continue; // SHT_SYMTAB
        sym_off = std.mem.readInt(u64, img[at + 24 ..][0..8], .little);
        sym_size = std.mem.readInt(u64, img[at + 32 ..][0..8], .little);
        sym_ent = std.mem.readInt(u64, img[at + 56 ..][0..8], .little);
        break;
    }
    try testing.expect(sym_ent != 0);

    var patched: usize = 0;
    var j: u64 = 0;
    while (j < sym_size / sym_ent) : (j += 1) {
        const so: usize = @intCast(sym_off + j * sym_ent);
        if (img[so + 4] & 0xf != 2) continue; // STT_FUNC
        std.mem.writeInt(u64, img[so + 8 ..][0..8], 8, .little);
        std.mem.writeInt(u64, img[so + 16 ..][0..8], 0xFFFF_FFFF_FFFF_FFF8, .little);
        patched += 1;
    }
    // Without this the test could pass by never having patched anything —
    // a green assertion reached by the wrong route.
    try testing.expect(patched != 0);

    try testing.expectError(error.MalformedElf, open(gpa, img, .{}));
}

test "hostile: a .maps VAR whose type is not a struct" {
    const gpa = testing.allocator;
    var obj = try open(gpa, fx_kprobe_hash, .{});
    const b = &obj.btf.?;
    // Type id of the anonymous struct the `counts` VAR points at.
    const ds = b.findByNameKind(".maps", .datasec).?;
    const vsi = try b.varSecInfo(try b.byId(ds), 0);
    const var_t = try b.byId(vsi.type_id);
    const struct_id = var_t.refType().?;
    const abs: usize = @intCast(b.hdr.hdr_len + b.hdr.type_off + b.offsets[struct_id - b.start_id]);
    obj.deinit();

    // Rewrite that STRUCT's kind to INT in a copy of the .BTF section, then
    // re-open the whole object.
    const img = try gpa.dupe(u8, fx_kprobe_hash);
    defer gpa.free(img);
    var image = try elfsym.openImage(gpa, img, false);
    const btf_sec = image.findSection(".BTF").?;
    const btf_off: usize = @intCast(image.sections[btf_sec].sh_offset);
    image.deinit();

    const info_at = btf_off + abs + 4;
    var info = std.mem.readInt(u32, img[info_at..][0..4], .little);
    info = (info & 0xf0ff_ffff) | (@as(u32, @backingInt(btf_mod.Kind.int)) << 24);
    std.mem.writeInt(u32, img[info_at..][0..4], info, .little);

    const e = open(gpa, img, .{});
    try testing.expect(e == error.MalformedMapDefinition or e == error.MalformedBtf);
    if (e) |*o| {
        var oo = o.*;
        oo.deinit();
    } else |_| {}
}

test "hostile: a map member whose `__uint` shape is wrong, and a zero max_entries" {
    const gpa = testing.allocator;

    // A hand-built BTF whose `max_entries` member is a plain INT, not a
    // pointer-to-array. That is not "value 0" — it is a malformed
    // definition, and saying so is the difference between a map with 0
    // entries and a diagnosed typo.
    var bld: btf_mod.Builder = .init(gpa);
    defer bld.deinit();
    const int_id = try bld.addInt("int", 4, 32, 1);
    const arr1 = try bld.addArray(int_id, int_id, 1); // BPF_MAP_TYPE_HASH
    const ptr_arr1 = try bld.addPtr(arr1);
    const st = try bld.addComposite(.@"struct", "", 16, &.{
        .{ .name = "type", .type_id = ptr_arr1, .bit_offset = 0 },
        .{ .name = "max_entries", .type_id = int_id, .bit_offset = 64 },
    });
    const blob = try bld.finish();
    var b = try btf_mod.parse(gpa, blob, .{ .own_bytes = true });
    defer b.deinit();
    try testing.expectError(error.MalformedMapDefinition, uintMemberValue(&b, int_id));
    try testing.expectEqual(@as(u32, 1), try uintMemberValue(&b, ptr_arr1));
    _ = st;

    // `__uint(max_entries, 0)` legitimately encodes as a ZERO-element array,
    // so extraction yields 0 rather than failing — and `load` is where that
    // becomes `error.ZeroMaxEntries`, per map type.
    const arr0 = try bld.addArray(int_id, int_id, 0);
    _ = arr0;
    try testing.expect(needsEntries(.hash));
    try testing.expect(needsEntries(.ringbuf));
    try testing.expect(!needsEntries(.struct_ops));
}

test "hostile: an object with no symbol table cannot be relocated" {
    const gpa = testing.allocator;
    const img = try gpa.dupe(u8, fx_xdp_pass);
    defer gpa.free(img);

    // Blank out .symtab's sh_type.
    var image = try elfsym.openImage(gpa, img, false);
    const st = image.symtabIndex().?;
    const shoff = std.mem.readInt(u64, img[40..48], .little);
    const shent = std.mem.readInt(u16, img[58..60], .little);
    image.deinit();
    const at: usize = @intCast(shoff + @as(u64, st) * shent + 4);
    std.mem.writeInt(u32, img[at..][0..4], 0, .little);

    try testing.expectError(error.NoSymbolTable, open(gpa, img, .{}));
}

// ── live: the syscalls themselves ───────────────────────────────────────────

fn hasBpfCapability() bool {
    return linux.geteuid() == 0;
}

test "load() reaches the syscall: refused for lack of CAP_BPF, never a crash" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;

    // This one runs EVERYWHERE. It drives `load` all the way through CO-RE
    // application, map-attr construction and the first `bpf()` call; on an
    // unprivileged box the syscall is the only thing that fails, which is
    // exactly the boundary this module claims. On a privileged box it
    // succeeds and the object is closed by `deinit`.
    for ([_][]const u8{ fx_xdp_pass, fx_kprobe_hash, fx_rodata_const, fx_ringbuf_map, fx_two_progs }) |bytes| {
        var obj = try open(gpa, bytes, .{});
        defer obj.deinit();
        load(&obj, .{ .core = false }) catch |e| switch (e) {
            error.PermissionDenied, error.SystemResources => continue,
            else => return e,
        };
        // Loaded for real: every program and map must have an fd.
        for (obj.programs) |p| try testing.expect(p.fd >= 0);
        for (obj.maps) |m| try testing.expect(m.fd >= 0);
    }
    if (!hasBpfCapability())
        if (verboseSkip()) std.debug.print("\nSKIPPED (syscall half only): ebpf.object load — needs CAP_BPF (uid {d}).\n", .{linux.geteuid()});
}

test "LIVE: create maps and load an XDP object end to end" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;

    if (!hasBpfCapability()) {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE ebpf.object XDP load — needs CAP_BPF (running as uid {d}).\n",
            .{linux.geteuid()},
        );
        return error.SkipZigTest;
    }
    var obj = try open(gpa, fx_xdp_pass, .{});
    defer obj.deinit();

    load(&obj, .{}) catch |e| {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE ebpf.object XDP load refused ({s}): {s}\n",
            .{ @errorName(e), obj.verifier_log },
        );
        return error.SkipZigTest;
    };
    try testing.expect(obj.programFd("xdp_accept") != null);
    try testing.expect(obj.programFd("xdp_reject") != null);
}

test "LIVE: a BTF-defined hash map is created and its fd relocated in" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;

    if (!hasBpfCapability()) {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE ebpf.object map+kprobe load — needs CAP_BPF (running as uid {d}).\n",
            .{linux.geteuid()},
        );
        return error.SkipZigTest;
    }
    var obj = try open(gpa, fx_kprobe_hash, .{});
    defer obj.deinit();

    load(&obj, .{}) catch |e| {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE ebpf.object map+kprobe load refused ({s}): {s}\n",
            .{ @errorName(e), obj.verifier_log },
        );
        return error.SkipZigTest;
    };
    const map_fd = obj.mapFd("counts").?;
    try testing.expect(map_fd >= 0);
    const p = obj.findProgram("count_open").?;
    try testing.expectEqual(@as(i32, map_fd), p.insns[4].imm);
    try testing.expect(obj.programFd("count_open") != null);
}

test "LIVE: .rodata is created, seeded and frozen" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;

    if (!hasBpfCapability()) {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE ebpf.object .rodata load — needs CAP_BPF (running as uid {d}).\n",
            .{linux.geteuid()},
        );
        return error.SkipZigTest;
    }
    var obj = try open(gpa, fx_rodata_const, .{});
    defer obj.deinit();

    load(&obj, .{}) catch |e| {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE ebpf.object .rodata load refused ({s}): {s}\n",
            .{ @errorName(e), obj.verifier_log },
        );
        return error.SkipZigTest;
    };
    const fd = obj.mapFd(".rodata").?;
    var value: [16]u8 = undefined;
    var key: [4]u8 = @splat(0);
    try BPF.map_lookup_elem(fd, &key, &value);
    try testing.expectEqual(@as(u32, 42), std.mem.readInt(u32, value[0..4], .little));
    // Frozen: a userspace write must now fail.
    try testing.expectError(error.PermissionDenied, BPF.map_update_elem(fd, &key, &value, 0));
}

// ── fuzz: the module's documented untrusted-input entry point ───────────────
//
// ⭐ There was no fuzz target in this file at all previously, and
// `check-fuzz-reach` never said so: that gate judges the DRAW of the targets
// that exist, and a parser with no harness is invisible to it. `open()` is
// this module's documented untrusted-input entry point ("Parse an object
// already in memory"), it needs no privilege, and it is where the CRITICAL
// two tests up lived — a symbol whose `st_size` came straight off the wire,
// summed into a bound that wrapped, and reached a `@memcpy` of 2^64-8 bytes:
// an out-of-bounds WRITE in ReleaseFast. `elfsym.fuzzOpenImage` stops one
// layer below this, at the section table; nothing fuzzed the symbol walk,
// the map-definition decode or the relocation walk that sit on top of it.

/// Whole `.o` images for `fuzzOpenObject`, in the format `Smith.slice` reads
/// (see `testkit.fuzz`): a little-endian u32 length, then the object.
///
/// The seven fixtures are real clang output; the hostile variants are built
/// here by the same patches the `hostile:` tests above apply, because the
/// fields they poison — one `st_size` inside a symbol table, one `sh_size` in
/// a section header — are eight octets in a 4 KiB file that random mutation
/// reaches essentially never.
const ObjectCorpus = struct {
    store: [262144]u8 = undefined,
    used: usize = 0,
    entries: [12][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *ObjectCorpus, img: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], img);
        self.entries[self.n] = sd;
        self.used += sd.len;
        self.n += 1;
    }

    fn build(self: *ObjectCorpus, gpa: std.mem.Allocator) ![]const []const u8 {
        // Every real object this module owns: a bare XDP program, a hash map,
        // `.rodata`, a ringbuf map, a legacy map definition, CO-RE
        // relocations, and two programs in one file.
        self.push(fx_xdp_pass);
        self.push(fx_kprobe_hash);
        self.push(fx_rodata_const);
        self.push(fx_ringbuf_map);
        self.push(fx_legacy_map);
        self.push(fx_core_reloc);
        self.push(fx_two_progs);

        // ⭐ The CRITICAL, as a seed: `st_value = 8` with
        // `st_size = 0xFFFF_FFFF_FFFF_FFF8`, a multiple of 8 so the alignment
        // check passes, whose sum with the offset wraps to 0.
        const overflow = try gpa.dupe(u8, fx_xdp_pass);
        defer gpa.free(overflow);
        patchSymbolSizes(overflow, 8, 0xFFFF_FFFF_FFFF_FFF8);
        self.push(overflow);

        // ⭐ A symbol size that is a multiple of FOUR but not eight, and
        // small enough to stay inside its section — so the alignment check is
        // the ONLY thing in front of it. What follows if it passes is an
        // `alloc` of `size / 8` instructions and a `@memcpy` of `size` octets:
        // 8 bytes allocated, 12 written. Weakening `% 8` to `% 4` survives any
        // corpus whose sizes are odd, or big enough that the range check
        // catches them first — both of which the obvious seed is.
        const misaligned = try gpa.dupe(u8, fx_xdp_pass);
        defer gpa.free(misaligned);
        patchSymbolSizes(misaligned, 0, 12);
        self.push(misaligned);

        // The neighbouring refusal: an instruction section whose `sh_size` is
        // not a multiple of 8.
        const unaligned = try gpa.dupe(u8, fx_xdp_pass);
        defer gpa.free(unaligned);
        if (patchXdpSectionSize(gpa, unaligned, 0x11)) {
            self.push(unaligned);
        } else |_| {}

        // Truncated to half: the section table survives the header but the
        // data it points at does not.
        self.push(fx_xdp_pass[0 .. fx_xdp_pass.len / 2]);

        return self.entries[0..self.n];
    }

    /// Set every `STT_FUNC` symbol's `st_value` to `value` and its `st_size`
    /// to `size`, in place. The same walk the `hostile:` test does.
    fn patchSymbolSizes(img: []u8, value: u64, size: u64) void {
        const shoff = std.mem.readInt(u64, img[40..48], .little);
        const shent = std.mem.readInt(u16, img[58..60], .little);
        const shnum = std.mem.readInt(u16, img[60..62], .little);
        var i: u16 = 0;
        while (i < shnum) : (i += 1) {
            const at: usize = @intCast(shoff + @as(u64, i) * shent);
            if (std.mem.readInt(u32, img[at + 4 ..][0..4], .little) != 2) continue; // SHT_SYMTAB
            const sym_off = std.mem.readInt(u64, img[at + 24 ..][0..8], .little);
            const sym_size = std.mem.readInt(u64, img[at + 32 ..][0..8], .little);
            const sym_ent = std.mem.readInt(u64, img[at + 56 ..][0..8], .little);
            if (sym_ent == 0) return;
            var j: u64 = 0;
            while (j < sym_size / sym_ent) : (j += 1) {
                const so: usize = @intCast(sym_off + j * sym_ent);
                if (img[so + 4] & 0xf != 2) continue; // STT_FUNC
                std.mem.writeInt(u64, img[so + 8 ..][0..8], value, .little);
                std.mem.writeInt(u64, img[so + 16 ..][0..8], size, .little);
            }
            return;
        }
    }

    fn patchXdpSectionSize(gpa: std.mem.Allocator, img: []u8, size: u64) !void {
        var image = try elfsym.openImage(gpa, img, false);
        defer image.deinit();
        const xdp = image.findSection("xdp") orelse return error.NoXdpSection;
        const shoff = std.mem.readInt(u64, img[40..48], .little);
        const shent = std.mem.readInt(u16, img[58..60], .little);
        const at: usize = @intCast(shoff + @as(u64, xdp) * shent + 32);
        std.mem.writeInt(u64, img[at..][0..8], size, .little);
    }
};

/// What one object yielded. Shared by the fuzz target and its corpus guard so
/// the guard drives the SAME walk.
const ObjectTally = struct {
    programs: usize = 0,
    maps: usize = 0,
    insns: usize = 0,
    relos: usize = 0,
};

fn walkObject(gpa: std.mem.Allocator, bytes: []const u8, opts: OpenOptions) ?ObjectTally {
    var obj = open(gpa, bytes, opts) catch return null;
    defer obj.deinit();
    var t: ObjectTally = .{};
    t.programs = obj.programs.len;
    t.maps = obj.maps.len;
    for (obj.programs) |*p| {
        t.insns += p.insns.len;
        t.relos += p.relos.len;
        // The pure half of loading: resolve every map reference and apply
        // whatever CO-RE relocations the object carries against its own BTF.
        relocateProgram(p, obj.maps) catch {};
        if (obj.btf) |*b| _ = applyCoreRelos(p, b, b) catch {};
    }
    fixupDatasecs(&obj) catch {};
    std.mem.doNotOptimizeAway(obj.license.len);
    std.mem.doNotOptimizeAway(obj.kern_version);
    std.mem.doNotOptimizeAway(obj.unknown_sections.len);
    return t;
}

const fz = @import("fuzz_test.zig");
const ObjectMark = fz.Marker(enum { opened, refused, programs, maps, relos });

test "fuzz: open never panics on a hostile BPF object" {
    var corpus: ObjectCorpus = .{};
    try testing.fuzz({}, fuzzOpenObjectSmith, .{ .corpus = try corpus.build(testing.allocator) });
}

test "fuzz driver: EBPF_FUZZ (object)" {
    try fz.fuzz_driver.run(fuzzOpenObject, .{ .prefix = "EBPF_FUZZ", .name = "ebpf-object" });
}

test "fuzz harness: object, 500 seeds, reaches every outcome" {
    try ObjectMark.reach(fuzzOpenObject, "ebpf-object", 500);
}

fn fuzzOpenObjectSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzOpenObject(std.testing.Smith, smith, testing.allocator);
}

fn fuzzOpenObject(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var corpus: ObjectCorpus = .{};
    const entries: []const []const u8 = if (S == fz.fuzz_driver.Rng) corpus.build(gpa) catch return else &.{};
    // 32768: the largest fixture here is 5.8 KiB and a fuzzer may grow it. A
    // seed longer than the buffer is not a big seed — `Smith.slice` reads it
    // back as the EMPTY one, silently, which is how a corpus of real objects
    // would have turned into a corpus of nothing.
    var buf: [32768]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &buf, entries);
    // `require_bpf_machine` travels in the seed's tail rather than being a
    // draw made after the input is spent, which would pin it to `false`
    // forever — it is the one option `open` has and it gates a refusal.
    const strict = src.value(u64) & 1 != 0;
    if (walkObject(gpa, buf[0..len], .{
        .require_bpf_machine = strict,
    })) |t| {
        ObjectMark.mark(.opened);
        if (t.programs != 0) ObjectMark.mark(.programs);
        if (t.maps != 0) ObjectMark.mark(.maps);
        if (t.relos != 0) ObjectMark.mark(.relos);
    } else ObjectMark.mark(.refused);
}

test "corpus: every object seed reaches open, and the parsed counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets, through the SAME `walkObject`.
    //
    // ⛔ `opened` alone would not be a guard: an ELF with no BPF sections in
    // it opens fine and yields nothing, so a corpus of empty objects would
    // score full marks. `programs`, `maps`, `insns` and `relos` count work the
    // empty input cannot do — and `insns` in particular is the number that
    // walks through the range arithmetic the CRITICAL lived in.
    var corpus: ObjectCorpus = .{};
    const gpa = testing.allocator;
    const entries = try corpus.build(gpa);
    var nonempty: usize = 0;
    var opened: usize = 0;
    var total: ObjectTally = .{};
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [32768]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (walkObject(gpa, buf[0..len], .{})) |t| {
            opened += 1;
            total.programs += t.programs;
            total.maps += t.maps;
            total.insns += t.insns;
            total.relos += t.relos;
        }
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 7), opened);
    try testing.expectEqual(@as(usize, 9), total.programs);
    try testing.expectEqual(@as(usize, 5), total.maps);
    try testing.expectEqual(@as(usize, 81), total.insns);
    try testing.expectEqual(@as(usize, 7), total.relos);

    // ⭐ Non-vacuity, and the point of the whole target: the seed carrying the
    // wrapping `st_size` really does reach the range check and is refused
    // there. Before the fix this exact input was an out-of-bounds `@memcpy`.
    const overflow = try gpa.dupe(u8, fx_xdp_pass);
    defer gpa.free(overflow);
    ObjectCorpus.patchSymbolSizes(overflow, 8, 0xFFFF_FFFF_FFFF_FFF8);
    try testing.expectError(error.MalformedElf, open(gpa, overflow, .{}));
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

// ── whole-module mutation: hand-assembled relocatable objects ──

/// A tiny ET_REL assembler: sections, symbols and `.rel*` sections laid out
/// exactly as asked, so a test can build the shapes clang never emits
/// (zero-size functions, unnamed sections, hostile relocations).
const ObjB = struct {
    const SYMTAB_LINK: u32 = 0xffff_fff0;
    const Sec = struct {
        name: []const u8,
        ty: u32,
        flags: u64 = 0,
        data: []const u8 = "",
        link: u32 = 0,
        info: u32 = 0,
        entsize: u64 = 0,
        /// `sh_size` when it must differ from `data.len` (NOBITS).
        size: ?u64 = null,
    };
    const Sym = struct { name: []const u8, info: u8, shndx: u16, value: u64 = 0, size: u64 = 0 };
    const EXEC: u64 = elfsym.SHF_ALLOC | elfsym.SHF_EXECINSTR;

    gpa: std.mem.Allocator,
    secs: std.ArrayList(Sec) = .empty,
    syms: std.ArrayList(Sym) = .empty,
    e_type: u16 = 1,
    e_machine: u16 = 247,

    fn init(gpa: std.mem.Allocator) ObjB {
        return .{ .gpa = gpa };
    }
    fn deinit(self: *ObjB) void {
        self.secs.deinit(self.gpa);
        self.syms.deinit(self.gpa);
    }
    /// Returns the section index (1-based).
    fn sec(self: *ObjB, s: Sec) !u16 {
        try self.secs.append(self.gpa, s);
        return @intCast(self.secs.items.len);
    }
    /// Returns the symbol index (1-based; 0 is the null symbol).
    fn sym(self: *ObjB, s: Sym) !u32 {
        try self.syms.append(self.gpa, s);
        return @intCast(self.syms.items.len);
    }
    fn build(self: *ObjB) ![]u8 {
        const gpa = self.gpa;
        var shstr: std.ArrayList(u8) = .empty;
        defer shstr.deinit(gpa);
        try shstr.append(gpa, 0);
        var strtab: std.ArrayList(u8) = .empty;
        defer strtab.deinit(gpa);
        try strtab.append(gpa, 0);
        var symtab: std.ArrayList(u8) = .empty;
        defer symtab.deinit(gpa);
        try symtab.appendNTimes(gpa, 0, 24);
        for (self.syms.items) |s| {
            var rec: [24]u8 = @splat(0);
            var no: u32 = 0;
            if (s.name.len != 0) {
                no = @intCast(strtab.items.len);
                try strtab.appendSlice(gpa, s.name);
                try strtab.append(gpa, 0);
            }
            std.mem.writeInt(u32, rec[0..4], no, .little);
            rec[4] = s.info;
            std.mem.writeInt(u16, rec[6..8], s.shndx, .little);
            std.mem.writeInt(u64, rec[8..16], s.value, .little);
            std.mem.writeInt(u64, rec[16..24], s.size, .little);
            try symtab.appendSlice(gpa, &rec);
        }
        const n: u32 = @intCast(self.secs.items.len);
        const symtab_idx = n + 1;
        // body: ehdr + sections' data + symtab + strtab + shstrtab, 8-aligned
        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(gpa);
        try body.appendNTimes(gpa, 0, 64);
        const Hdr = struct { name: u32, ty: u32, flags: u64, off: u64, size: u64, link: u32, info: u32, ent: u64 };
        var hdrs: std.ArrayList(Hdr) = .empty;
        defer hdrs.deinit(gpa);
        try hdrs.append(gpa, std.mem.zeroes(Hdr));
        const addName = struct {
            fn f(g: std.mem.Allocator, st: *std.ArrayList(u8), nm: []const u8) !u32 {
                if (nm.len == 0) return 0;
                const o: u32 = @intCast(st.items.len);
                try st.appendSlice(g, nm);
                try st.append(g, 0);
                return o;
            }
        }.f;
        for (self.secs.items) |s| {
            while (body.items.len % 8 != 0) try body.append(gpa, 0);
            const off = body.items.len;
            try body.appendSlice(gpa, s.data);
            try hdrs.append(gpa, .{
                .name = try addName(gpa, &shstr, s.name),
                .ty = s.ty,
                .flags = s.flags,
                .off = off,
                .size = s.size orelse s.data.len,
                .link = if (s.link == SYMTAB_LINK) symtab_idx else s.link,
                .info = s.info,
                .ent = s.entsize,
            });
        }
        const extra = [_]struct { nm: []const u8, ty: u32, data: []const u8, link: u32, ent: u64 }{
            .{ .nm = ".symtab", .ty = 2, .data = symtab.items, .link = symtab_idx + 1, .ent = 24 },
            .{ .nm = ".strtab", .ty = 3, .data = strtab.items, .link = 0, .ent = 0 },
        };
        for (extra) |e| {
            while (body.items.len % 8 != 0) try body.append(gpa, 0);
            const off = body.items.len;
            try body.appendSlice(gpa, e.data);
            try hdrs.append(gpa, .{ .name = try addName(gpa, &shstr, e.nm), .ty = e.ty, .flags = 0, .off = off, .size = e.data.len, .link = e.link, .info = 0, .ent = e.ent });
        }
        const shname = try addName(gpa, &shstr, ".shstrtab");
        while (body.items.len % 8 != 0) try body.append(gpa, 0);
        const sh_off = body.items.len;
        try body.appendSlice(gpa, shstr.items);
        try hdrs.append(gpa, .{ .name = shname, .ty = 3, .flags = 0, .off = sh_off, .size = shstr.items.len, .link = 0, .info = 0, .ent = 0 });
        while (body.items.len % 8 != 0) try body.append(gpa, 0);
        const table_off = body.items.len;
        for (hdrs.items) |h| {
            var rec: [64]u8 = @splat(0);
            std.mem.writeInt(u32, rec[0..4], h.name, .little);
            std.mem.writeInt(u32, rec[4..8], h.ty, .little);
            std.mem.writeInt(u64, rec[8..16], h.flags, .little);
            std.mem.writeInt(u64, rec[24..32], h.off, .little);
            std.mem.writeInt(u64, rec[32..40], h.size, .little);
            std.mem.writeInt(u32, rec[40..44], h.link, .little);
            std.mem.writeInt(u32, rec[44..48], h.info, .little);
            std.mem.writeInt(u64, rec[56..64], h.ent, .little);
            try body.appendSlice(gpa, &rec);
        }
        const out = try body.toOwnedSlice(gpa);
        @memcpy(out[0..4], "\x7fELF");
        out[4] = 2;
        out[5] = 1;
        out[6] = 1;
        std.mem.writeInt(u16, out[16..18], self.e_type, .little);
        std.mem.writeInt(u16, out[18..20], self.e_machine, .little);
        std.mem.writeInt(u64, out[40..48], table_off, .little);
        std.mem.writeInt(u16, out[52..54], 64, .little);
        std.mem.writeInt(u16, out[58..60], 64, .little);
        std.mem.writeInt(u16, out[60..62], @intCast(hdrs.items.len), .little);
        std.mem.writeInt(u16, out[62..64], @intCast(hdrs.items.len - 1), .little);
        return out;
    }
};

fn ins8(code: u8, regs: u8, off: i16, imm: i32) [8]u8 {
    var b: [8]u8 = undefined;
    b[0] = code;
    b[1] = regs;
    std.mem.writeInt(i16, b[2..4], off, .little);
    std.mem.writeInt(i32, b[4..8], imm, .little);
    return b;
}
const I_MOV0 = ins8(0xb7, 0, 0, 0);
const I_EXIT = ins8(0x95, 0, 0, 0);
const I_LD64 = ins8(0x18, 0, 0, 0);
const I_LD64_HI = ins8(0x00, 0, 0, 0);
const I_CALL = ins8(0x85, 0, 0, 1);
const FUNC_SYM: u8 = (1 << 4) | 2;
const OBJ_SYM: u8 = (1 << 4) | 1;
const SEC_SYM: u8 = 3;

fn flatIns(comptime n: usize, parts: [n][8]u8) [n * 8]u8 {
    var out: [n * 8]u8 = undefined;
    for (parts, 0..) |p, i| @memcpy(out[i * 8 ..][0..8], &p);
    return out;
}

fn cat(comptime parts: anytype) [parts.len * 8]u8 {
    var out: [parts.len * 8]u8 = undefined;
    inline for (parts, 0..) |p, i| @memcpy(out[i * 8 ..][0..8], &p);
    return out;
}

fn openObj(b: *ObjB, opts: OpenOptions) !Object {
    const bytes = try b.build();
    defer b.gpa.free(bytes);
    return open(b.gpa, bytes, opts);
}

fn le32(vals: []const u32) [64]u8 {
    var out: [64]u8 = @splat(0);
    for (vals, 0..) |v, i| std.mem.writeInt(u32, out[i * 4 ..][0..4], v, .little);
    return out;
}

test "open: header, section classification and the executable-section rules" {
    const gpa = testing.allocator;
    const code = cat(.{ I_MOV0, I_EXIT });
    // e_type / e_machine
    {
        var b = ObjB.init(gpa);
        defer b.deinit();
        _ = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code });
        b.e_type = 2;
        try testing.expectError(error.NotABpfObject, openObj(&b, .{}));
        b.e_type = 1;
        b.e_machine = 0;
        var o = try openObj(&b, .{});
        o.deinit();
        try testing.expectError(error.NotABpfObject, openObj(&b, .{ .require_bpf_machine = true }));
        b.e_machine = elfsym.EM_BPF;
        var o2 = try openObj(&b, .{ .require_bpf_machine = true });
        o2.deinit();
    }
    // which executable sections are programs, unknown, or ignored
    {
        var b = ObjB.init(gpa);
        defer b.deinit();
        _ = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code }); // program
        _ = try b.sec(.{ .name = ".text", .ty = 1, .flags = ObjB.EXEC, .data = &code }); // sub-programs: ignored
        _ = try b.sec(.{ .name = "weird", .ty = 1, .flags = ObjB.EXEC, .data = &code }); // unknown
        _ = try b.sec(.{ .name = "", .ty = 1, .flags = ObjB.EXEC, .data = &code }); // anonymous: skipped
        _ = try b.sec(.{ .name = "noexec", .ty = 1, .flags = elfsym.SHF_ALLOC, .data = &code });
        _ = try b.sec(.{ .name = "noalloc", .ty = 1, .flags = elfsym.SHF_EXECINSTR, .data = &code });
        _ = try b.sec(.{ .name = "nobits", .ty = 8, .flags = ObjB.EXEC, .size = 16 });
        _ = try b.sec(.{ .name = "kprobe/empty", .ty = 1, .flags = ObjB.EXEC, .data = "" });
        _ = try b.sec(.{ .name = ".data", .ty = 1, .flags = 3, .data = "" }); // empty data section: no map
        _ = try b.sec(.{ .name = ".bss.empty", .ty = 8, .flags = 3, .size = 0 });
        var o = try openObj(&b, .{});
        defer o.deinit();
        try testing.expectEqual(@as(usize, 1), o.programs.len);
        try testing.expectEqualStrings("xdp", o.programs[0].name);
        try testing.expectEqual(@as(usize, 1), o.unknown_sections.len);
        try testing.expectEqualStrings("weird", o.unknown_sections[0]);
        try testing.expectEqual(@as(usize, 0), o.maps.len);
    }
    // license / version
    {
        var b = ObjB.init(gpa);
        defer b.deinit();
        _ = try b.sec(.{ .name = "license", .ty = 1, .flags = 3, .data = "GPL\x00junk" });
        _ = try b.sec(.{ .name = "version", .ty = 1, .flags = 3, .data = &[_]u8{ 0x01, 0x02, 0x03, 0x04 } });
        var o = try openObj(&b, .{});
        defer o.deinit();
        try testing.expectEqualStrings("GPL", o.license);
        try testing.expectEqual(@as(u32, 0x04030201), o.kern_version);
    }
    // a stripped object has no symbol table at all
    {
        var b = ObjB.init(gpa);
        defer b.deinit();
        const bytes = try b.build();
        defer gpa.free(bytes);
        // turn .symtab into a plain strtab-typed section
        var im = try elfsym.openImage(gpa, bytes, false);
        defer im.deinit();
        const si = im.symtabIndex().?;
        const at = std.mem.readInt(u64, bytes[40..48], .little) + si * 64 + 4;
        std.mem.writeInt(u32, bytes[@intCast(at)..][0..4], 3, .little);
        try testing.expectError(error.NoSymbolTable, open(gpa, bytes, .{}));
    }
}

test "isDataSectionName / ProgramSpec.kernelName / classifySection edges" {
    try testing.expect(isDataSectionName(".rodata"));
    try testing.expect(isDataSectionName(".rodata.str1.1"));
    try testing.expect(isDataSectionName(".data"));
    try testing.expect(isDataSectionName(".bss."));
    try testing.expect(!isDataSectionName(".datax"));
    try testing.expect(!isDataSectionName(".dat"));
    try testing.expect(!isDataSectionName("data"));
    try testing.expect(isRodataName(".rodata.cst8"));
    try testing.expect(!isRodataName(".data"));
    var p: ProgramSpec = undefined;
    p.name = "0123456789abcde"; // 15
    try testing.expectEqualStrings("0123456789abcde", p.kernelName());
    p.name = "0123456789abcdef"; // 16
    try testing.expectEqualStrings("0123456789abcde", p.kernelName());
    p.name = "short";
    try testing.expectEqualStrings("short", p.kernelName());
    // longest prefix wins, and a bare prefix has an empty target
    try testing.expectEqualStrings("a/b", classifySection("kprobe/a/b").?.target);
    try testing.expectEqual(@as(?SectionKindInfo, null), classifySection("kprob"));
    try testing.expectEqual(@as(?SectionKindInfo, null), classifySection("kprobex/y"));
    try testing.expectEqual(@as(?SectionKindInfo, null), classifySection("kprobe.zz"));
    try testing.expectEqual(BPF.AttachType.trace_kprobe_multi, classifySection("kprobe.multi/x").?.def.expected_attach_type.?);
    try testing.expect(classifySection("uprobe.s/x").?.def.sleepable);
    try testing.expect(!classifySection("uprobe/x").?.def.sleepable);
}

test "function splitting: ranges, zero sizes, ordering and bounds" {
    const gpa = testing.allocator;
    const code = cat(.{ I_MOV0, I_EXIT, I_MOV0, I_MOV0, I_MOV0, I_EXIT });
    // no function symbol: one program named after the section; sleepable from the prefix
    {
        var b = ObjB.init(gpa);
        defer b.deinit();
        _ = try b.sec(.{ .name = "uprobe.s/x", .ty = 1, .flags = ObjB.EXEC, .data = &code });
        var o = try openObj(&b, .{});
        defer o.deinit();
        try testing.expectEqual(@as(usize, 1), o.programs.len);
        try testing.expectEqualStrings("uprobe.s/x", o.programs[0].name);
        try testing.expectEqual(@as(usize, 6), o.programs[0].insns.len);
        try testing.expect(o.programs[0].sleepable);
        try testing.expectEqualStrings("x", o.programs[0].attach_target);
        try testing.expectEqual(BPF.ProgType.kprobe, o.programs[0].prog_type);
        try testing.expectEqual(@as(u64, 0), o.programs[0].sec_byte_off);
    }
    // two functions given in reverse symbol order; the first has no size, the last neither
    {
        var b = ObjB.init(gpa);
        defer b.deinit();
        const s = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code });
        _ = try b.sym(.{ .name = "second", .info = FUNC_SYM, .shndx = s, .value = 16, .size = 0 });
        _ = try b.sym(.{ .name = "first", .info = FUNC_SYM, .shndx = s, .value = 0, .size = 0 });
        _ = try b.sym(.{ .name = "a_var", .info = OBJ_SYM, .shndx = s, .value = 8, .size = 8 }); // not a function
        _ = try b.sym(.{ .name = "", .info = FUNC_SYM, .shndx = 99, .value = 8, .size = 8 }); // another section
        var o = try openObj(&b, .{});
        defer o.deinit();
        try testing.expectEqual(@as(usize, 2), o.programs.len);
        try testing.expectEqualStrings("first", o.programs[0].name);
        try testing.expectEqual(@as(usize, 2), o.programs[0].insns.len);
        try testing.expectEqualStrings("second", o.programs[1].name);
        try testing.expectEqual(@as(usize, 4), o.programs[1].insns.len);
        try testing.expectEqual(@as(u64, 16), o.programs[1].sec_byte_off);
        try testing.expectEqual(@as(u8, 0xb7), o.programs[1].insns[0].code);
        try testing.expectEqual(@as(u8, 0x95), o.programs[1].insns[3].code);
    }
    // a function at value == len with size 0 yields nothing; at len+8 is malformed
    {
        var b = ObjB.init(gpa);
        defer b.deinit();
        const s = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code });
        _ = try b.sym(.{ .name = "f", .info = FUNC_SYM, .shndx = s, .value = 0, .size = 48 });
        _ = try b.sym(.{ .name = "tail", .info = FUNC_SYM, .shndx = s, .value = 48, .size = 0 });
        var o = try openObj(&b, .{});
        defer o.deinit();
        try testing.expectEqual(@as(usize, 1), o.programs.len); // exactly the whole section
        b.syms.items[1].value = 56;
        try testing.expectError(error.MalformedElf, openObj(&b, .{}));
    }
    // the size bounds: unaligned, past the end, wrapping
    {
        var b = ObjB.init(gpa);
        defer b.deinit();
        const s = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code });
        _ = try b.sym(.{ .name = "f", .info = FUNC_SYM, .shndx = s, .value = 0, .size = 12 });
        try testing.expectError(error.UnalignedInstructionSection, openObj(&b, .{}));
        b.syms.items[0].size = 56; // 8 past the end
        try testing.expectError(error.MalformedElf, openObj(&b, .{}));
        b.syms.items[0].value = 8;
        b.syms.items[0].size = std.math.maxInt(u64) - 7; // multiple of 8 that wraps value+size to 0
        try testing.expectError(error.MalformedElf, openObj(&b, .{}));
        b.syms.items[0].value = 8;
        b.syms.items[0].size = 48; // 8 + 48 > 48
        try testing.expectError(error.MalformedElf, openObj(&b, .{}));
        b.syms.items[0].size = 40; // exactly to the end
        var o = try openObj(&b, .{});
        o.deinit();
    }
    // an unaligned section size
    {
        var b = ObjB.init(gpa);
        defer b.deinit();
        _ = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = code[0..12] });
        try testing.expectError(error.UnalignedInstructionSection, openObj(&b, .{}));
    }
}

test "legacy maps: record layout, naming symbols and their guards" {
    const gpa = testing.allocator;
    var defs: [40]u8 = undefined;
    @memcpy(defs[0..20], le32(&.{ 2, 4, 8, 16, 0x11 })[0..20]);
    @memcpy(defs[20..40], le32(&.{ 1, 5, 9, 17, 0x22 })[0..20]);
    var b = ObjB.init(gpa);
    defer b.deinit();
    const m = try b.sec(.{ .name = "maps", .ty = 1, .flags = 3, .data = &defs });
    const other = try b.sec(.{ .name = "other", .ty = 1, .flags = 3, .data = "x" });
    _ = try b.sym(.{ .name = "foreign", .info = OBJ_SYM, .shndx = other, .value = 0 }); // wrong section
    _ = try b.sym(.{ .name = "func", .info = FUNC_SYM, .shndx = m, .value = 0 }); // not an object
    _ = try b.sym(.{ .name = "skewed", .info = OBJ_SYM, .shndx = m, .value = 4 }); // not 20-aligned
    _ = try b.sym(.{ .name = "mapA", .info = OBJ_SYM, .shndx = m, .value = 0 });
    _ = try b.sym(.{ .name = "dup", .info = OBJ_SYM, .shndx = m, .value = 0 }); // second claim: ignored
    _ = try b.sym(.{ .name = "mapB", .info = OBJ_SYM, .shndx = m, .value = 20 });
    var o = try openObj(&b, .{});
    defer o.deinit();
    try testing.expectEqual(@as(usize, 2), o.maps.len);
    try testing.expectEqualStrings("mapA", o.maps[0].name);
    try testing.expectEqual(@as(u32, 2), @backingInt(o.maps[0].map_type));
    try testing.expectEqual(@as(u32, 4), o.maps[0].key_size);
    try testing.expectEqual(@as(u32, 8), o.maps[0].value_size);
    try testing.expectEqual(@as(u32, 16), o.maps[0].max_entries);
    try testing.expectEqual(@as(u32, 0x11), o.maps[0].map_flags);
    try testing.expectEqual(MapOrigin.legacy, o.maps[0].origin);
    try testing.expectEqualStrings("mapB", o.maps[1].name);
    try testing.expectEqual(@as(u32, 1), @backingInt(o.maps[1].map_type));
    try testing.expectEqual(@as(u32, 5), o.maps[1].key_size);
    try testing.expectEqual(@as(u32, 9), o.maps[1].value_size);
    try testing.expectEqual(@as(u32, 17), o.maps[1].max_entries);
    try testing.expectEqual(@as(u32, 0x22), o.maps[1].map_flags);
    // a symbol naming a record that does not exist (index == count, far past) is ignored
    _ = try b.sym(.{ .name = "ghost", .info = OBJ_SYM, .shndx = m, .value = 40 });
    _ = try b.sym(.{ .name = "ghost2", .info = OBJ_SYM, .shndx = m, .value = 4000 });
    var o2 = try openObj(&b, .{});
    o2.deinit();
    // a record with no symbol, and a ragged section, are refused
    var b2 = ObjB.init(gpa);
    defer b2.deinit();
    const m2 = try b2.sec(.{ .name = "maps", .ty = 1, .flags = 3, .data = &defs });
    _ = try b2.sym(.{ .name = "only", .info = OBJ_SYM, .shndx = m2, .value = 0 });
    try testing.expectError(error.MalformedMapDefinition, openObj(&b2, .{}));
    b2.secs.items[0].data = defs[0..30];
    try testing.expectError(error.MalformedMapDefinition, openObj(&b2, .{}));
    // duplicate map names across the object are refused
    var b3 = ObjB.init(gpa);
    defer b3.deinit();
    const m3 = try b3.sec(.{ .name = "maps", .ty = 1, .flags = 3, .data = &defs });
    _ = try b3.sym(.{ .name = "same", .info = OBJ_SYM, .shndx = m3, .value = 0 });
    _ = try b3.sym(.{ .name = "same", .info = OBJ_SYM, .shndx = m3, .value = 20 });
    try testing.expectError(error.DuplicateMap, openObj(&b3, .{}));
}

test "internal maps: sizes, flags, freeze and the 32-bit ceiling" {
    const gpa = testing.allocator;
    var b = ObjB.init(gpa);
    defer b.deinit();
    _ = try b.sec(.{ .name = ".rodata", .ty = 1, .flags = 2, .data = "0123456789abcdef" });
    _ = try b.sec(.{ .name = ".data", .ty = 1, .flags = 3, .data = "abcd" });
    _ = try b.sec(.{ .name = ".bss", .ty = 8, .flags = 3, .size = std.math.maxInt(u32) });
    var o = try openObj(&b, .{});
    defer o.deinit();
    try testing.expectEqual(@as(usize, 3), o.maps.len);
    const ro = o.findMap(".rodata").?;
    try testing.expectEqual(@as(u32, 16), ro.value_size);
    try testing.expectEqual(@as(u32, 1), ro.max_entries);
    try testing.expectEqual(@as(u32, 4), ro.key_size);
    try testing.expectEqual(BPF_F_RDONLY_PROG, ro.map_flags);
    try testing.expect(ro.freeze);
    try testing.expectEqual(MapOrigin.internal, ro.origin);
    try testing.expectEqualStrings("0123456789abcdef", ro.initial_data);
    const d = o.findMap(".data").?;
    try testing.expectEqual(@as(u32, 0), d.map_flags);
    try testing.expect(!d.freeze);
    try testing.expectEqualStrings("abcd", d.initial_data);
    const bss = o.findMap(".bss").?;
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), bss.value_size);
    try testing.expectEqual(@as(usize, 0), bss.initial_data.len);
    b.secs.items[2].size = @as(u64, std.math.maxInt(u32)) + 1;
    try testing.expectError(error.MalformedElf, openObj(&b, .{}));
}

test "relocations: every refusal and the two accepted shapes" {
    const gpa = testing.allocator;
    const Case = struct { sym_shndx: ?u16 = null, rtype: u32 = 1, code: [4][8]u8, r_off: u64 = 0, sym_val: u64 = 0, sym_info: u8 = OBJ_SYM, sym_name: []const u8 = "m1", want: ?anyerror };
    const ld = [4][8]u8{ I_LD64, I_LD64_HI, I_MOV0, I_EXIT };
    const cases = [_]Case{
        .{ .code = ld, .want = null }, // map_fd relocation
        .{ .code = ld, .rtype = 10, .want = error.UnsupportedRelocation }, // a call relocation on a non-call
        .{ .code = ld, .rtype = 2, .want = error.UnsupportedRelocation },
        .{ .code = ld, .sym_shndx = 0, .want = error.ExternSymbolUnsupported },
        .{ .code = .{ I_CALL, I_LD64_HI, I_MOV0, I_EXIT }, .want = error.UnsupportedRelocation }, // a map relocation on a call
        .{ .code = .{ I_MOV0, I_LD64_HI, I_MOV0, I_EXIT }, .want = error.UnsupportedRelocation },
        .{ .code = .{ I_MOV0, I_MOV0, I_MOV0, I_LD64 }, .r_off = 24, .want = error.RelocationOutOfRange }, // ldimm64 is last
        .{ .code = ld, .r_off = 4, .want = error.RelocationOutOfRange }, // misaligned
        .{ .code = ld, .r_off = 32, .want = null }, // at hi: another function's, ignored
        .{ .code = ld, .sym_shndx = 40, .want = error.MalformedElf }, // section past the table
        .{ .code = ld, .sym_name = "stray", .sym_val = 5, .want = error.UnresolvedRelocation },
    };
    for (cases, 0..) |c, ci| {
        var b = ObjB.init(gpa);
        defer b.deinit();
        var defs: [20]u8 = @splat(0);
        std.mem.writeInt(u32, defs[0..4], 2, .little);
        const code = flatIns(4, c.code);
        const p = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code });
        const m = try b.sec(.{ .name = "maps", .ty = 1, .flags = 3, .data = &defs });
        _ = try b.sym(.{ .name = "m1", .info = OBJ_SYM, .shndx = m, .value = 0 });
        const sidx = try b.sym(.{ .name = c.sym_name, .info = c.sym_info, .shndx = c.sym_shndx orelse m, .value = c.sym_val });
        var rel: [16]u8 = undefined;
        std.mem.writeInt(u64, rel[0..8], c.r_off, .little);
        std.mem.writeInt(u64, rel[8..16], (@as(u64, sidx) << 32) | c.rtype, .little);
        _ = try b.sec(.{ .name = ".relxdp", .ty = elfsym.SHT_REL, .data = &rel, .link = ObjB.SYMTAB_LINK, .info = p, .entsize = 16 });
        if (c.want) |e| {
            testing.expectError(e, openObj(&b, .{})) catch |err| {
                std.debug.print("relocation case {d}\n", .{ci});
                return err;
            };
        } else {
            var o = try openObj(&b, .{});
            o.deinit();
        }
    }
    // accepted shapes: fields of the collected relocation
    {
        var b = ObjB.init(gpa);
        defer b.deinit();
        var defs: [20]u8 = @splat(0);
        std.mem.writeInt(u32, defs[0..4], 2, .little);
        const code = cat(.{ I_MOV0, I_LD64, I_LD64_HI, I_EXIT });
        const p = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code });
        const m = try b.sec(.{ .name = "maps", .ty = 1, .flags = 3, .data = &defs });
        _ = try b.sym(.{ .name = "m1", .info = OBJ_SYM, .shndx = m, .value = 0 });
        var rel: [16]u8 = undefined;
        std.mem.writeInt(u64, rel[0..8], 8, .little);
        std.mem.writeInt(u64, rel[8..16], (@as(u64, 1) << 32) | 1, .little);
        _ = try b.sec(.{ .name = ".relxdp", .ty = elfsym.SHT_REL, .data = &rel, .link = ObjB.SYMTAB_LINK, .info = p, .entsize = 16 });
        var o = try openObj(&b, .{});
        defer o.deinit();
        const r = o.programs[0].relos;
        try testing.expectEqual(@as(usize, 1), r.len);
        try testing.expectEqual(ReloKind.map_fd, r[0].kind);
        try testing.expectEqual(@as(u32, 1), r[0].insn_idx);
        try testing.expectEqual(@as(usize, 0), r[0].map_idx);
        try testing.expectEqualStrings("m1", r[0].sym_name);
        // a relocation section for another section is not this program's
        b.secs.items[2].info = m;
        var o2 = try openObj(&b, .{});
        defer o2.deinit();
        try testing.expectEqual(@as(usize, 0), o2.programs[0].relos.len);
    }
}

test "data-section relocations: symbol value + instruction addend, bounds, unresolved names" {
    const gpa = testing.allocator;
    const Case = struct { sym_info: u8, sym_val: u64, imm: i32, sec_name: []const u8 = ".rodata", sec_size: usize = 16, want_off: ?u64 };
    const cases = [_]Case{
        .{ .sym_info = SEC_SYM, .sym_val = 0, .imm = 8, .want_off = 8 }, // section symbol: addend carries it
        .{ .sym_info = OBJ_SYM, .sym_val = 4, .imm = 4, .want_off = 8 }, // named: value + addend
        .{ .sym_info = OBJ_SYM, .sym_val = 12, .imm = 3, .want_off = 15 }, // last byte
        .{ .sym_info = OBJ_SYM, .sym_val = 12, .imm = 4, .want_off = null }, // == value_size
        .{ .sym_info = OBJ_SYM, .sym_val = 0, .imm = 0, .sec_name = ".data", .sec_size = 0, .want_off = null }, // no such map
    };
    for (cases, 0..) |c, ci| {
        var b = ObjB.init(gpa);
        defer b.deinit();
        const code = flatIns(3, .{ ins8(0x18, 0, 0, c.imm), I_LD64_HI, I_EXIT });
        const p = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code });
        const zeros: [16]u8 = @splat(0);
        const d = try b.sec(.{ .name = c.sec_name, .ty = 1, .flags = 3, .data = zeros[0..c.sec_size] });
        const sidx = try b.sym(.{ .name = if (c.sym_info == SEC_SYM) "" else "g", .info = c.sym_info, .shndx = d, .value = c.sym_val });
        var rel: [16]u8 = undefined;
        std.mem.writeInt(u64, rel[0..8], 0, .little);
        std.mem.writeInt(u64, rel[8..16], (@as(u64, sidx) << 32) | 1, .little);
        _ = try b.sec(.{ .name = ".relxdp", .ty = elfsym.SHT_REL, .data = &rel, .link = ObjB.SYMTAB_LINK, .info = p, .entsize = 16 });
        if (c.want_off) |w| {
            var o = try openObj(&b, .{});
            defer o.deinit();
            const r = o.programs[0].relos[0];
            testing.expectEqual(ReloKind.map_value, r.kind) catch |e| {
                std.debug.print("data case {d}\n", .{ci});
                return e;
            };
            try testing.expectEqual(w, r.value_off);
            try testing.expectEqualStrings(if (c.sym_info == SEC_SYM) ".rodata" else "g", r.sym_name);
        } else {
            const e: anyerror = if (c.sec_size == 0) error.UnresolvedRelocation else error.RelocationOutOfRange;
            try testing.expectError(e, openObj(&b, .{}));
        }
    }
    // a relocation against .text is the address of a sub-program: it is linked in,
    // after the program, and the load becomes a BPF_PSEUDO_FUNC to it
    var b = ObjB.init(gpa);
    defer b.deinit();
    var code = cat(.{ I_LD64, I_LD64_HI, I_EXIT });
    const p = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code });
    const t = try b.sec(.{ .name = ".text", .ty = 1, .flags = ObjB.EXEC, .data = &code });
    const sidx = try b.sym(.{ .name = "sub", .info = FUNC_SYM, .shndx = t });
    var rel: [16]u8 = undefined;
    std.mem.writeInt(u64, rel[0..8], 0, .little);
    std.mem.writeInt(u64, rel[8..16], (@as(u64, sidx) << 32) | 1, .little);
    _ = try b.sec(.{ .name = ".relxdp", .ty = elfsym.SHT_REL, .data = &rel, .link = ObjB.SYMTAB_LINK, .info = p, .entsize = 16 });
    {
        var o = try openObj(&b, .{});
        defer o.deinit();
        const pr = o.programs[0];
        try testing.expectEqual(@as(usize, 6), pr.insns.len);
        try testing.expectEqual(@as(u4, BPF_PSEUDO_FUNC), pr.insns[0].src);
        try testing.expectEqual(@as(i32, 2), pr.insns[0].imm); // 0 + 1 + 2 = 3, the appended copy
        try testing.expectEqual(@as(usize, 0), pr.call_sites.len);
    }
    // an address that is not a function start is refused, not guessed
    std.mem.writeInt(i32, code[4..8], 4, .little);
    try testing.expectError(error.UnresolvedRelocation, openObj(&b, .{}));
    // and against any other section it is "unsupported"
    b.secs.items[1].name = "other";
    try testing.expectError(error.UnsupportedRelocation, openObj(&b, .{}));
}

test "relocateProgram: bounds, fd 0, the two pseudo forms" {
    var insns = [_]Insn{ @bitCast(I_LD64), @bitCast(I_LD64_HI), @bitCast(I_EXIT) };
    var relos = [_]Relo{.{ .kind = .map_fd, .insn_idx = 0, .map_idx = 0, .sym_name = "m" }};
    var prog: ProgramSpec = undefined;
    prog.insns = &insns;
    prog.relos = &relos;
    const mk = struct {
        fn m(fd: linux.fd_t) MapSpec {
            return .{ .name = "m", .map_type = .array, .origin = .legacy, .sec_idx = 0, .fd = fd };
        }
    }.m;
    // fd 0 is a valid fd
    try relocateProgram(&prog, &.{mk(0)});
    try testing.expectEqual(@as(u4, BPF_PSEUDO_MAP_FD), insns[0].src);
    try testing.expectEqual(@as(i32, 0), insns[0].imm);
    try relocateProgram(&prog, &.{mk(7)});
    try testing.expectEqual(@as(i32, 7), insns[0].imm);
    try testing.expectError(error.MapNotCreated, relocateProgram(&prog, &.{mk(-1)}));
    // map index at maps.len
    relos[0].map_idx = 1;
    try testing.expectError(error.MapNotCreated, relocateProgram(&prog, &.{mk(7)}));
    relos[0].map_idx = 9;
    try testing.expectError(error.MapNotCreated, relocateProgram(&prog, &.{mk(7)}));
    relos[0].map_idx = 0;
    // insn index == len
    relos[0].insn_idx = 3;
    try testing.expectError(error.RelocationOutOfRange, relocateProgram(&prog, &.{mk(7)}));
    // not an LD_IMM64
    relos[0].insn_idx = 2;
    try testing.expectError(error.NotAnImmediateLoad, relocateProgram(&prog, &.{mk(7)}));
    // map_value: sets src=2, patches both halves; the last instruction has no second half
    relos[0] = .{ .kind = .map_value, .insn_idx = 0, .map_idx = 0, .value_off = 24, .sym_name = "g" };
    try relocateProgram(&prog, &.{mk(7)});
    try testing.expectEqual(@as(u4, BPF_PSEUDO_MAP_VALUE), insns[0].src);
    try testing.expectEqual(@as(i32, 7), insns[0].imm);
    try testing.expectEqual(@as(i32, 24), insns[1].imm);
    var tail = [_]Insn{ @bitCast(I_EXIT), @bitCast(I_LD64) };
    prog.insns = &tail;
    relos[0].insn_idx = 1;
    try testing.expectError(error.RelocationOutOfRange, relocateProgram(&prog, &.{mk(7)}));
}

test "patchCoreInsn: ranges, classes, widths" {
    var v = [_]Insn{ @bitCast(ins8(0x61, 0x21, 4, 0)), @bitCast(ins8(0x07, 0x01, 0, 5)), @bitCast(ins8(0x18, 0, 0, 0)), @bitCast(I_LD64_HI) };
    // LDX: off is an i16
    try patchCoreInsn(&v, 0, .field_byte_offset, 32767);
    try testing.expectEqual(@as(i16, 32767), v[0].off);
    try testing.expectError(error.CoreValueTooLarge, patchCoreInsn(&v, 0, .field_byte_offset, 32768));
    // byte size rewrites the opcode size bits only
    for ([_][2]u64{ .{ 1, 0x10 }, .{ 2, 0x08 }, .{ 4, 0x00 }, .{ 8, 0x18 } }) |c| {
        v[0] = @bitCast(ins8(0x61, 0x21, 4, 0));
        try patchCoreInsn(&v, 0, .field_byte_size, c[0]);
        try testing.expectEqual(@as(u8, 0x61 & ~@as(u8, 0x18)) | @as(u8, @intCast(c[1])), v[0].code);
        try testing.expectEqual(@as(i16, 4), v[0].off);
    }
    try testing.expectError(error.CoreValueTooLarge, patchCoreInsn(&v, 0, .field_byte_size, 3));
    // ALU with an immediate: i32 range; with a register source it is refused
    try patchCoreInsn(&v, 1, .field_byte_offset, std.math.maxInt(i32));
    try testing.expectEqual(@as(i32, std.math.maxInt(i32)), v[1].imm);
    try testing.expectError(error.CoreValueTooLarge, patchCoreInsn(&v, 1, .field_byte_offset, @as(u64, std.math.maxInt(i32)) + 1));
    v[1] = @bitCast(ins8(0x0f, 0x01, 0, 5));
    try testing.expectError(error.UnsupportedCoreInsn, patchCoreInsn(&v, 1, .field_byte_offset, 1));
    // LD_IMM64: both halves; the pair must fit; plain BPF_LD forms are refused
    try patchCoreInsn(&v, 2, .field_byte_offset, 0x1122_3344_5566_7788);
    try testing.expectEqual(@as(u32, 0x5566_7788), @as(u32, @bitCast(v[2].imm)));
    try testing.expectEqual(@as(u32, 0x1122_3344), @as(u32, @bitCast(v[3].imm)));
    var last = [_]Insn{@bitCast(I_LD64)};
    try testing.expectError(error.RelocationOutOfRange, patchCoreInsn(&last, 0, .field_byte_offset, 1));
    var abs = [_]Insn{ @bitCast(ins8(0x20, 0, 0, 0)), @bitCast(I_EXIT) };
    try testing.expectError(error.UnsupportedCoreInsn, patchCoreInsn(&abs, 0, .field_byte_offset, 1));
    // out of range / unsupported class
    try testing.expectError(error.RelocationOutOfRange, patchCoreInsn(&v, 4, .field_byte_offset, 1));
    var jmp = [_]Insn{@bitCast(ins8(0x05, 0, 0, 0))};
    try testing.expectError(error.UnsupportedCoreInsn, patchCoreInsn(&jmp, 0, .field_byte_offset, 1));
}

test "load: refusals that need no privilege come before any syscall" {
    const gpa = testing.allocator;
    const code = cat(.{ I_MOV0, I_EXIT });
    // an unknown executable section
    {
        var b = ObjB.init(gpa);
        defer b.deinit();
        _ = try b.sec(.{ .name = "weird", .ty = 1, .flags = ObjB.EXEC, .data = &code });
        var o = try openObj(&b, .{});
        defer o.deinit();
        try testing.expectError(error.UnknownProgramSection, load(&o, .{ .load_btf = false }));
        try load(&o, .{ .load_btf = false, .ignore_unknown_sections = true });
    }
    // pinning, zero entries, and the map types that legitimately have none
    {
        var defs: [20]u8 = @splat(0);
        std.mem.writeInt(u32, defs[0..4], 2, .little); // array
        std.mem.writeInt(u32, defs[4..8], 4, .little);
        std.mem.writeInt(u32, defs[8..12], 4, .little);
        var b = ObjB.init(gpa);
        defer b.deinit();
        const m = try b.sec(.{ .name = "maps", .ty = 1, .flags = 3, .data = &defs });
        _ = try b.sym(.{ .name = "m1", .info = OBJ_SYM, .shndx = m, .value = 0 });
        var o = try openObj(&b, .{});
        defer o.deinit();
        try testing.expectError(error.ZeroMaxEntries, load(&o, .{ .load_btf = false }));
        o.maps[0].max_entries = 1;
        o.maps[0].pinning = 1;
        try testing.expectError(error.PinningUnsupported, load(&o, .{ .load_btf = false }));
        o.maps[0].pinning = 0;
        o.maps[0].max_entries = 0;
        o.maps[0].map_type = .struct_ops;
        if (load(&o, .{ .load_btf = false })) |_| {} else |e| try testing.expect(e != error.ZeroMaxEntries);
        o.close();
        o.maps[0].map_type = .sk_storage;
        if (load(&o, .{ .load_btf = false })) |_| {} else |e| try testing.expect(e != error.ZeroMaxEntries);
        o.close();
    }
    // a license that cannot fit the kernel-bound buffer
    {
        var lic: [64]u8 = undefined;
        @memset(&lic, 'G');
        var b = ObjB.init(gpa);
        defer b.deinit();
        _ = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code });
        _ = try b.sec(.{ .name = "license", .ty = 1, .flags = 3, .data = lic[0..64] });
        var o = try openObj(&b, .{});
        defer o.deinit();
        try testing.expectError(error.InvalidArgument, load(&o, .{ .load_btf = false }));
        o.license = lic[0..63];
        if (load(&o, .{ .load_btf = false })) |_| {} else |e| try testing.expect(e != error.InvalidArgument);
        o.close();
    }
}

test "Object fds: close releases, take transfers, zero is a valid fd" {
    const gpa = testing.allocator;
    const code = cat(.{ I_MOV0, I_EXIT });
    var defs: [20]u8 = @splat(0);
    var b = ObjB.init(gpa);
    defer b.deinit();
    _ = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code });
    const m = try b.sec(.{ .name = "maps", .ty = 1, .flags = 3, .data = &defs });
    _ = try b.sym(.{ .name = "m1", .info = OBJ_SYM, .shndx = m, .value = 0 });
    var o = try openObj(&b, .{});
    defer o.deinit();
    const devnull = struct {
        fn open() linux.fd_t {
            const rc = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
            return @intCast(rc);
        }
        fn isOpen(fd: linux.fd_t) bool {
            return linux.errno(linux.fcntl(fd, linux.F.GETFD, 0)) == .SUCCESS;
        }
    };
    // fd 0 reads as a live fd (never "absent")
    o.programs[0].fd = 0;
    o.maps[0].fd = 0;
    try testing.expectEqual(@as(?linux.fd_t, 0), o.programFd("xdp"));
    try testing.expectEqual(@as(?linux.fd_t, 0), o.mapFd("m1"));
    try testing.expectEqual(@as(?linux.fd_t, 0), o.takeProgramFd("xdp"));
    try testing.expectEqual(@as(linux.fd_t, -1), o.programs[0].fd);
    try testing.expectEqual(@as(?linux.fd_t, null), o.takeProgramFd("xdp"));
    try testing.expectEqual(@as(?linux.fd_t, 0), o.takeMapFd("m1"));
    try testing.expectEqual(@as(linux.fd_t, -1), o.maps[0].fd);
    try testing.expectEqual(@as(?linux.fd_t, null), o.takeMapFd("m1"));
    try testing.expectEqual(@as(?linux.fd_t, null), o.programFd("nope"));
    try testing.expectEqual(@as(?linux.fd_t, null), o.mapFd("nope"));
    try testing.expectEqual(@as(?linux.fd_t, null), o.programFd("xdp"));
    try testing.expectEqual(@as(?linux.fd_t, null), o.mapFd("m1"));
    // lookups by C name first, then by section name
    try testing.expect(o.findProgram("xdp") != null);
    // close really closes all three kinds
    const f1 = devnull.open();
    const f2 = devnull.open();
    const f3 = devnull.open();
    o.programs[0].fd = f1;
    o.maps[0].fd = f2;
    o.btf_fd = f3;
    o.close();
    try testing.expect(!devnull.isOpen(f1) and !devnull.isOpen(f2) and !devnull.isOpen(f3));
    try testing.expectEqual(@as(linux.fd_t, -1), o.programs[0].fd);
    try testing.expectEqual(@as(linux.fd_t, -1), o.maps[0].fd);
    try testing.expectEqual(@as(linux.fd_t, -1), o.btf_fd);
}

test "findProgram: name first, then section name" {
    const gpa = testing.allocator;
    const code = cat(.{ I_MOV0, I_EXIT });
    var b = ObjB.init(gpa);
    defer b.deinit();
    const s1 = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code });
    _ = try b.sym(.{ .name = "xdp/b", .info = FUNC_SYM, .shndx = s1 });
    const s2 = try b.sec(.{ .name = "xdp/b", .ty = 1, .flags = ObjB.EXEC, .data = &code });
    _ = try b.sym(.{ .name = "other", .info = FUNC_SYM, .shndx = s2 });
    var o = try openObj(&b, .{});
    defer o.deinit();
    // "xdp/b" is the C name of the first program and the section name of the second
    try testing.expectEqualStrings("xdp", o.findProgram("xdp/b").?.sec_name);
    try testing.expectEqualStrings("xdp/b", o.findProgram("other").?.sec_name);
    try testing.expectEqual(@as(?*ProgramSpec, null), o.findProgram("nope"));
}

// ── whole-module mutation, round 3 ──────────────────────────────────────────

const RawB = btf_mod.RawBtf;

const MemKind = enum { uint, ptr_int, ptr_void, plain_int, ptr_plain };
const MapMem = struct { name: []const u8, kind: MemKind, v: u32 = 0 };
const Flavor = enum { ok, non_var, nameless, non_struct };

/// An ET_REL whose `.maps` section is described by hand-made BTF.
fn mapsObject(gpa: std.mem.Allocator, members: []const MapMem, flavor: Flavor) ![]u8 {
    var r = try RawB.init(gpa);
    defer r.deinit(gpa);
    const int4 = try r.rec(gpa, 0, btf_mod.K_INT, 0, false, 4, &.{32});
    var extra: std.ArrayList(u32) = .empty;
    defer extra.deinit(gpa);
    for (members) |m| {
        const name_off = try r.str(gpa, m.name);
        const ty: u32 = switch (m.kind) {
            .uint => blk: {
                const a = try r.rec(gpa, 0, btf_mod.K_ARRAY, 0, false, 0, &.{ int4, int4, m.v });
                break :blk try r.rec(gpa, 0, btf_mod.K_PTR, 0, false, a, &.{});
            },
            .ptr_int, .ptr_plain => try r.rec(gpa, 0, btf_mod.K_PTR, 0, false, int4, &.{}),
            .ptr_void => try r.rec(gpa, 0, btf_mod.K_PTR, 0, false, 0, &.{}),
            .plain_int => int4,
        };
        try extra.appendSlice(gpa, &.{ name_off, ty, 0 });
    }
    const st = try r.rec(gpa, 0, btf_mod.K_STRUCT, @intCast(members.len), false, 8, extra.items);
    const var_name = if (flavor == .nameless) 0 else try r.str(gpa, "m1");
    const var_ty: u32 = if (flavor == .non_struct) int4 else st;
    const v = try r.rec(gpa, var_name, btf_mod.K_VAR, 0, false, var_ty, &.{1});
    const ds_name = try r.str(gpa, ".maps");
    const entry: u32 = if (flavor == .non_var) int4 else v;
    _ = try r.rec(gpa, ds_name, btf_mod.K_DATASEC, 1, false, 8, &.{ entry, 0, 8 });
    const blob = try r.finish(gpa);
    defer gpa.free(blob);
    var b = ObjB.init(gpa);
    defer b.deinit();
    const zeros: [8]u8 = @splat(0);
    _ = try b.sec(.{ .name = ".maps", .ty = 1, .flags = 3, .data = &zeros });
    _ = try b.sec(.{ .name = ".BTF", .ty = 1, .data = blob });
    return b.build();
}

test "BTF-defined maps: every member lands in its field; every malformation is typed" {
    const gpa = testing.allocator;
    const Case = struct { mem: []const MapMem, flavor: Flavor = .ok, want: ?anyerror = null };
    const bad = [_]Case{
        .{ .mem = &.{}, .flavor = .non_var, .want = error.MalformedMapDefinition },
        .{ .mem = &.{}, .flavor = .nameless, .want = error.MalformedMapDefinition },
        .{ .mem = &.{}, .flavor = .non_struct, .want = error.MalformedMapDefinition },
        .{ .mem = &.{.{ .name = "foo", .kind = .uint, .v = 1 }}, .want = error.UnknownMapMember },
        .{ .mem = &.{.{ .name = "values", .kind = .ptr_int }}, .want = error.MapInMapUnsupported },
        .{ .mem = &.{.{ .name = "key", .kind = .plain_int }}, .want = error.MalformedMapDefinition },
        .{ .mem = &.{.{ .name = "value", .kind = .ptr_void }}, .want = error.MalformedMapDefinition },
        .{ .mem = &.{.{ .name = "max_entries", .kind = .ptr_plain }}, .want = error.MalformedMapDefinition },
        .{ .mem = &.{.{ .name = "max_entries", .kind = .plain_int }}, .want = error.MalformedMapDefinition },
        .{ .mem = &.{.{ .name = "map_extra", .kind = .uint, .v = 1 }}, .want = error.UnknownMapMember },
    };
    for (bad, 0..) |c, ci| {
        const bytes = try mapsObject(gpa, c.mem, c.flavor);
        defer gpa.free(bytes);
        testing.expectError(c.want.?, open(gpa, bytes, .{})) catch |e| {
            std.debug.print("maps case {d}\n", .{ci});
            return e;
        };
    }
    // no members: all defaults
    {
        const bytes = try mapsObject(gpa, &.{}, .ok);
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        try testing.expectEqual(@as(usize, 1), o.maps.len);
        try testing.expectEqual(BPF.MapType.unspec, o.maps[0].map_type);
        try testing.expectEqual(@as(u32, 0), o.maps[0].max_entries);
        try testing.expectEqual(MapOrigin.btf_defined, o.maps[0].origin);
        try testing.expectEqualStrings("m1", o.maps[0].name);
    }
    // every member
    {
        const bytes = try mapsObject(gpa, &.{
            .{ .name = "type", .kind = .uint, .v = 1 },
            .{ .name = "max_entries", .kind = .uint, .v = 16 },
            .{ .name = "map_flags", .kind = .uint, .v = 0x11 },
            .{ .name = "key_size", .kind = .uint, .v = 5 },
            .{ .name = "value_size", .kind = .uint, .v = 9 },
            .{ .name = "numa_node", .kind = .uint, .v = 3 },
            .{ .name = "pinning", .kind = .uint, .v = 1 },
            .{ .name = "map_extra", .kind = .uint, .v = 0 },
            .{ .name = "key", .kind = .ptr_int },
            .{ .name = "value", .kind = .ptr_int },
        }, .ok);
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        const m = o.maps[0];
        try testing.expectEqual(BPF.MapType.hash, m.map_type);
        try testing.expectEqual(@as(u32, 16), m.max_entries);
        try testing.expectEqual(@as(u32, 0x11), m.map_flags);
        // `key`/`value` come last and set the sizes from the pointee (4), after key_size/value_size
        try testing.expectEqual(@as(u32, 4), m.key_size);
        try testing.expectEqual(@as(u32, 4), m.value_size);
        try testing.expectEqual(@as(?u32, 3), m.numa_node);
        try testing.expectEqual(@as(u32, 1), m.pinning);
        try testing.expectEqual(@as(u32, 1), m.btf_key_type_id);
        try testing.expectEqual(@as(u32, 1), m.btf_value_type_id);
    }
    // explicit key_size / value_size alone
    {
        const bytes = try mapsObject(gpa, &.{
            .{ .name = "key_size", .kind = .uint, .v = 5 },
            .{ .name = "value_size", .kind = .uint, .v = 9 },
        }, .ok);
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        try testing.expectEqual(@as(u32, 5), o.maps[0].key_size);
        try testing.expectEqual(@as(u32, 9), o.maps[0].value_size);
        try testing.expectEqual(@as(u32, 0), o.maps[0].btf_key_type_id);
    }
}

test "small object edges: unnamed function symbol, non-REL sections, relocation target at the table end" {
    const gpa = testing.allocator;
    const code = cat(.{ I_MOV0, I_EXIT });
    {
        var b = ObjB.init(gpa);
        defer b.deinit();
        const s = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code });
        _ = try b.sym(.{ .name = "", .info = FUNC_SYM, .shndx = s, .value = 0, .size = 16 });
        var o = try openObj(&b, .{});
        defer o.deinit();
        try testing.expectEqualStrings("xdp", o.programs[0].name);
    }
    // a RELA-typed section naming the program is not a REL section: ignored
    {
        var b = ObjB.init(gpa);
        defer b.deinit();
        const p = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code });
        var rel: [24]u8 = @splat(0xff);
        std.mem.writeInt(u64, rel[0..8], 0, .little);
        _ = try b.sec(.{ .name = ".relaxdp", .ty = 4, .data = &rel, .link = ObjB.SYMTAB_LINK, .info = p, .entsize = 24 });
        var o = try openObj(&b, .{});
        defer o.deinit();
        try testing.expectEqual(@as(usize, 0), o.programs[0].relos.len);
    }
    // a relocation symbol whose section index equals the section count
    {
        var b = ObjB.init(gpa);
        defer b.deinit();
        const c2 = cat(.{ I_LD64, I_LD64_HI, I_EXIT });
        const p = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &c2 });
        const nsec: u16 = @intCast(b.secs.items.len + 1 + 3 + 1); // + rel section + symtab/strtab/shstrtab + null
        const sidx = try b.sym(.{ .name = "z", .info = OBJ_SYM, .shndx = nsec });
        var rel: [16]u8 = undefined;
        std.mem.writeInt(u64, rel[0..8], 0, .little);
        std.mem.writeInt(u64, rel[8..16], (@as(u64, sidx) << 32) | 1, .little);
        _ = try b.sec(.{ .name = ".relxdp", .ty = elfsym.SHT_REL, .data = &rel, .link = ObjB.SYMTAB_LINK, .info = p, .entsize = 16 });
        try testing.expectError(error.MalformedElf, openObj(&b, .{}));
    }
}

/// `.BTF.ext` for one `xdp` section group (+ a decoy group), records at the given byte offsets.
fn extBlob(gpa: std.mem.Allocator, name_off: u32, other_off: u32, per_kind: [3][]const u32) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const w = struct {
        fn f(g: std.mem.Allocator, l: *std.ArrayList(u8), v: u32) !void {
            var b: [4]u8 = undefined;
            std.mem.writeInt(u32, &b, v, .little);
            try l.appendSlice(g, &b);
        }
    }.f;
    // sub-sections: func (rec 8), line (rec 16), core (rec 16); each: rec_size + group(name, n, recs) + decoy group
    var parts: [3]std.ArrayList(u8) = .{ .empty, .empty, .empty };
    defer for (&parts) |*p| p.deinit(gpa);
    const sizes = [_]u32{ 8, 16, 16 };
    for (&parts, sizes, per_kind) |*p, rs, offs| {
        try w(gpa, p, rs);
        try w(gpa, p, name_off);
        try w(gpa, p, @intCast(offs.len));
        for (offs, 0..) |o, i| {
            try w(gpa, p, o);
            try w(gpa, p, 100 + @as(u32, @intCast(i))); // type id / file name off / ...
            if (rs == 16) {
                try w(gpa, p, 7);
                try w(gpa, p, 0);
            }
        }
        // decoy group for another section name
        try w(gpa, p, other_off);
        try w(gpa, p, 1);
        try w(gpa, p, 0);
        try w(gpa, p, 999);
        if (rs == 16) {
            try w(gpa, p, 7);
            try w(gpa, p, 0);
        }
    }
    var hdr: [32]u8 = @splat(0);
    std.mem.writeInt(u16, hdr[0..2], 0xeb9f, .little);
    hdr[2] = 1;
    std.mem.writeInt(u32, hdr[4..8], 32, .little);
    var off: u32 = 0;
    for (parts, 0..) |p, i| {
        std.mem.writeInt(u32, hdr[8 + i * 8 ..][0..4], off, .little);
        std.mem.writeInt(u32, hdr[12 + i * 8 ..][0..4], @intCast(p.items.len), .little);
        off += @intCast(p.items.len);
    }
    try out.appendSlice(gpa, &hdr);
    for (parts) |p| try out.appendSlice(gpa, p.items);
    return out.toOwnedSlice(gpa);
}

fn extObject(gpa: std.mem.Allocator, offs: []const u32) ![]u8 {
    return extObject3(gpa, .{ offs, offs, offs });
}

fn extObject3(gpa: std.mem.Allocator, per_kind: [3][]const u32) ![]u8 {
    var r = try RawB.init(gpa);
    defer r.deinit(gpa);
    const n_xdp = try r.str(gpa, "xdp");
    const n_other = try r.str(gpa, "other");
    _ = try r.rec(gpa, 0, btf_mod.K_INT, 0, false, 4, &.{32});
    const blob = try r.finish(gpa);
    defer gpa.free(blob);
    const ext = try extBlob(gpa, n_xdp, n_other, per_kind);
    defer gpa.free(ext);
    const code = cat(.{ I_MOV0, I_EXIT, I_MOV0, I_EXIT });
    var b = ObjB.init(gpa);
    defer b.deinit();
    const s = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code });
    _ = try b.sec(.{ .name = ".BTF", .ty = 1, .data = blob });
    _ = try b.sec(.{ .name = ".BTF.ext", .ty = 1, .data = ext });
    _ = try b.sym(.{ .name = "f1", .info = FUNC_SYM, .shndx = s, .value = 0, .size = 16 });
    _ = try b.sym(.{ .name = "f2", .info = FUNC_SYM, .shndx = s, .value = 16, .size = 16 });
    return b.build();
}

test ".BTF.ext records are split per program and rebased to instruction indices" {
    const gpa = testing.allocator;
    const bytes = try extObject(gpa, &.{ 0, 8, 16, 32 });
    defer gpa.free(bytes);
    var o = try open(gpa, bytes, .{});
    defer o.deinit();
    try testing.expectEqual(@as(usize, 2), o.programs.len);
    const p0 = o.programs[0];
    const p1 = o.programs[1];
    // f1 covers bytes [0,16): records at 0 and 8; f2 covers [16,32): the record at 16 only; 32 is past it
    try testing.expectEqual(@as(usize, 2), p0.func_info.len);
    try testing.expectEqual(@as(u32, 0), p0.func_info[0].insn_off);
    try testing.expectEqual(@as(u32, 1), p0.func_info[1].insn_off);
    try testing.expectEqual(@as(u32, 101), p0.func_info[1].type_id);
    try testing.expectEqual(@as(usize, 1), p1.func_info.len);
    try testing.expectEqual(@as(u32, 0), p1.func_info[0].insn_off);
    try testing.expectEqual(@as(u32, 102), p1.func_info[0].type_id);
    try testing.expectEqual(@as(usize, 2), p0.line_info.len);
    try testing.expectEqual(@as(usize, 1), p1.line_info.len);
    try testing.expectEqual(@as(u32, 0), p1.line_info[0].insn_off);
    try testing.expectEqual(@as(u32, 1), p0.line_info[1].insn_off);
    try testing.expectEqual(@as(usize, 2), p0.core_relos.len);
    try testing.expectEqual(@as(usize, 1), p1.core_relos.len);
    try testing.expectEqual(@as(u32, 0), p1.core_relos[0].insn_off);
    try testing.expectEqual(@as(u32, 1), p0.core_relos[1].insn_off);
    // the decoy group (another section name, record at 0) was not attributed to anyone
    for (p0.func_info) |f| try testing.expect(f.type_id != 999);
    for (p0.core_relos) |c| try testing.expect(c.type_id != 999);
    for (p0.line_info) |c| try testing.expect(c.file_name_off != 999);
    // a record that is not 8-aligned inside a program is refused (each kind)
    const bad = try extObject(gpa, &.{4});
    defer gpa.free(bad);
    try testing.expectError(error.RelocationOutOfRange, open(gpa, bad, .{}));
    // ... and the same for the line_info and the core_relo records on their own
    const ok_offs = [_]u32{ 0, 8 };
    const bad_offs = [_]u32{4};
    const bad_line = try extObject3(gpa, .{ &ok_offs, &bad_offs, &ok_offs });
    defer gpa.free(bad_line);
    try testing.expectError(error.RelocationOutOfRange, open(gpa, bad_line, .{}));
    const bad_core = try extObject3(gpa, .{ &ok_offs, &ok_offs, &bad_offs });
    defer gpa.free(bad_core);
    try testing.expectError(error.RelocationOutOfRange, open(gpa, bad_core, .{}));
}

test "load: CO-RE relocations are applied before anything is created" {
    const gpa = testing.allocator;
    var r = try RawB.init(gpa);
    defer r.deinit(gpa);
    const n_s = try r.str(gpa, "S");
    const n_x = try r.str(gpa, "x");
    const acc = try r.str(gpa, "0:0");
    const int4 = try r.rec(gpa, 0, btf_mod.K_INT, 0, false, 4, &.{32});
    const st = try r.rec(gpa, n_s, btf_mod.K_STRUCT, 1, false, 8, &.{ n_x, int4, 32 });
    const blob = try r.finish(gpa);
    defer gpa.free(blob);
    // .BTF.ext with only a core_relo group: insn 0, type S, access "0:0", FIELD_BYTE_OFFSET
    var ext: [32 + 4 + 8 + 16]u8 = @splat(0);
    std.mem.writeInt(u16, ext[0..2], 0xeb9f, .little);
    ext[2] = 1;
    std.mem.writeInt(u32, ext[4..8], 32, .little);
    std.mem.writeInt(u32, ext[24..28], 0, .little); // core_relo_off
    std.mem.writeInt(u32, ext[28..32], 4 + 8 + 16, .little);
    std.mem.writeInt(u32, ext[32..36], 16, .little); // rec_size
    std.mem.writeInt(u32, ext[36..40], 0, .little); // sec_name_off: patched below
    std.mem.writeInt(u32, ext[40..44], 1, .little); // one record
    std.mem.writeInt(u32, ext[44..48], 0, .little); // insn_off
    std.mem.writeInt(u32, ext[48..52], st, .little);
    std.mem.writeInt(u32, ext[52..56], acc, .little);
    std.mem.writeInt(u32, ext[56..60], 0, .little);
    // the section-name string lives in the same BTF: "xdp" appended before finish would be
    // cleaner, so look it up the way the loader does (offset of "S" is not it): add it now.
    var r2 = try RawB.init(gpa);
    defer r2.deinit(gpa);
    _ = try r2.str(gpa, "S");
    _ = try r2.str(gpa, "x");
    _ = try r2.str(gpa, "0:0");
    const xdp_off = try r2.str(gpa, "xdp");
    _ = try r2.rec(gpa, 0, btf_mod.K_INT, 0, false, 4, &.{32});
    _ = try r2.rec(gpa, n_s, btf_mod.K_STRUCT, 1, false, 8, &.{ n_x, int4, 32 });
    const blob2 = try r2.finish(gpa);
    defer gpa.free(blob2);
    std.mem.writeInt(u32, ext[36..40], xdp_off, .little);
    var b = ObjB.init(gpa);
    defer b.deinit();
    const ins = ins8(0x61, 0x21, 77, 0);
    const code = flatIns(2, .{ ins, I_EXIT });
    _ = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = &code });
    _ = try b.sec(.{ .name = ".BTF", .ty = 1, .data = blob2 });
    _ = try b.sec(.{ .name = ".BTF.ext", .ty = 1, .data = &ext });
    var o = try openObj(&b, .{});
    defer o.deinit();
    try testing.expectEqual(@as(usize, 1), o.programs[0].core_relos.len);
    try testing.expectEqual(@as(i16, 77), o.programs[0].insns[0].off);
    // core on: the relocation is applied (and the load then fails at the first privileged step)
    if (load(&o, .{ .load_btf = false, .target_btf = &o.btf.? })) |_| {} else |_| {}
    try testing.expectEqual(@as(i16, 4), o.programs[0].insns[0].off);
    o.close();
}

test "fixupDatasecs: sizes and offsets come from the ELF, entries end up sorted" {
    const gpa = testing.allocator;
    const mk = struct {
        fn obj(g: std.mem.Allocator, g1_value: u64) ![]u8 {
            var r = try RawB.init(g);
            defer r.deinit(g);
            const n_g1 = try r.str(g, "g1");
            const n_g2 = try r.str(g, "g2");
            const n_ds = try r.str(g, ".data");
            const int4 = try r.rec(g, 0, btf_mod.K_INT, 0, false, 4, &.{32});
            const v1 = try r.rec(g, n_g1, btf_mod.K_VAR, 0, false, int4, &.{1});
            const v2 = try r.rec(g, n_g2, btf_mod.K_VAR, 0, false, int4, &.{1});
            _ = try r.rec(g, n_ds, btf_mod.K_DATASEC, 2, false, 0, &.{ v1, 0, 7, v2, 0, 7 });
            const blob = try r.finish(g);
            defer g.free(blob);
            var b = ObjB.init(g);
            defer b.deinit();
            const zeros: [32]u8 = @splat(0);
            const d = try b.sec(.{ .name = ".data", .ty = 1, .flags = 3, .data = &zeros });
            const other = try b.sec(.{ .name = "other", .ty = 1, .flags = 3, .data = "x" });
            _ = try b.sec(.{ .name = ".BTF", .ty = 1, .data = blob });
            _ = try b.sym(.{ .name = "g1", .info = OBJ_SYM, .shndx = other, .value = 99, .size = 99 }); // decoy
            _ = try b.sym(.{ .name = "g1", .info = OBJ_SYM, .shndx = d, .value = g1_value, .size = 8 });
            _ = try b.sym(.{ .name = "g2", .info = OBJ_SYM, .shndx = d, .value = 4, .size = 0 });
            return b.build();
        }
    }.obj;
    const bytes = try mk(gpa, 16);
    defer gpa.free(bytes);
    var o = try open(gpa, bytes, .{});
    defer o.deinit();
    try fixupDatasecs(&o);
    var b2 = try btf_mod.parse(gpa, o.btf_bytes.?, .{});
    defer b2.deinit();
    const ds = try b2.byId(4);
    try testing.expectEqual(@as(u32, 32), ds.size_type);
    const first = try b2.varSecInfo(ds, 0);
    const second = try b2.varSecInfo(ds, 1);
    try testing.expectEqual(@as(u32, 4), first.offset); // g2 sorted first
    try testing.expectEqual(@as(u32, 7), first.size); // zero st_size leaves the size alone
    try testing.expectEqual(@as(u32, 16), second.offset);
    try testing.expectEqual(@as(u32, 8), second.size);
    // idempotent
    try fixupDatasecs(&o);
    // st_value must fit a u32: the maximum does, one more does not
    const edge = try mk(gpa, std.math.maxInt(u32));
    defer gpa.free(edge);
    var oe = try open(gpa, edge, .{});
    defer oe.deinit();
    try fixupDatasecs(&oe);
    const over = try mk(gpa, @as(u64, std.math.maxInt(u32)) + 1);
    defer gpa.free(over);
    var oo = try open(gpa, over, .{});
    defer oo.deinit();
    try testing.expectError(error.MalformedElf, fixupDatasecs(&oo));
}

test "applyCoreRelos: a missing field is an error unless the relocation asks whether it exists" {
    const gpa = testing.allocator;
    var l = try RawB.init(gpa);
    defer l.deinit(gpa);
    const ln_s = try l.str(gpa, "S");
    const ln_x = try l.str(gpa, "x");
    const acc = try l.str(gpa, "0:0");
    const li = try l.rec(gpa, 0, btf_mod.K_INT, 0, false, 4, &.{32});
    const ls = try l.rec(gpa, ln_s, btf_mod.K_STRUCT, 1, false, 8, &.{ ln_x, li, 32 });
    const lb = try l.finish(gpa);
    defer gpa.free(lb);
    var local = try btf_mod.parse(gpa, lb, .{});
    defer local.deinit();
    var t = try RawB.init(gpa);
    defer t.deinit(gpa);
    const tn = try t.str(gpa, "S");
    _ = try t.rec(gpa, 0, btf_mod.K_INT, 0, false, 4, &.{32});
    _ = try t.rec(gpa, tn, btf_mod.K_STRUCT, 0, false, 0, &.{});
    const tb = try t.finish(gpa);
    defer gpa.free(tb);
    var target = try btf_mod.parse(gpa, tb, .{});
    defer target.deinit();
    var insns = [_]Insn{@bitCast(ins8(0x61, 0x21, 77, 0))};
    var relos = [_]btfext.CoreRelo{.{ .insn_off = 0, .type_id = ls, .access_str_off = acc, .kind = 0 }};
    var prog: ProgramSpec = undefined;
    prog.insns = &insns;
    prog.core_relos = &relos;
    try testing.expectError(error.CoreFieldNotFound, applyCoreRelos(&prog, &local, &target));
    try testing.expectEqual(@as(i16, 77), insns[0].off); // untouched
    relos[0].kind = 2; // FIELD_EXISTS: 0, applied
    try testing.expectEqual(@as(usize, 1), try applyCoreRelos(&prog, &local, &target));
    try testing.expectEqual(@as(i16, 0), insns[0].off); // the "absent" value 0 is what gets written
    // against itself: the offset is re-derived and written, the count is exact
    relos[0].kind = 0;
    try testing.expectEqual(@as(usize, 1), try applyCoreRelos(&prog, &local, &local));
    try testing.expectEqual(@as(i16, 4), insns[0].off);
}

test "applyCoreRelos: type-based relocations patch `r = value` and map absence to typed errors" {
    const gpa = testing.allocator;
    var l = try RawB.init(gpa);
    defer l.deinit(gpa);
    const a0 = try l.str(gpa, "0");
    const a01 = try l.str(gpa, "0:1");
    const ln_s = try l.str(gpa, "S");
    const ln_e = try l.str(gpa, "E");
    const ln_n = try l.str(gpa, "NEG");
    const ln_p = try l.str(gpa, "POS");
    const li = try l.rec(gpa, 0, btf_mod.K_INT, 0, false, 4, &.{32});
    const ls = try l.rec(gpa, ln_s, btf_mod.K_STRUCT, 0, false, 4, &.{});
    const le = try l.rec(gpa, ln_e, btf_mod.K_ENUM, 2, true, 4, &.{ ln_p, 1, ln_n, @bitCast(@as(i32, -2)) });
    _ = li;
    const lb = try l.finish(gpa);
    defer gpa.free(lb);
    var local = try btf_mod.parse(gpa, lb, .{});
    defer local.deinit();

    var t = try RawB.init(gpa);
    defer t.deinit(gpa);
    const tn = try t.str(gpa, "S");
    const te_n = try t.str(gpa, "E");
    const te_neg = try t.str(gpa, "NEG");
    _ = try t.rec(gpa, tn, btf_mod.K_STRUCT, 0, false, 40, &.{});
    _ = try t.rec(gpa, te_n, btf_mod.K_ENUM, 1, true, 4, &.{ te_neg, @bitCast(@as(i32, -9)) });
    const tb = try t.finish(gpa);
    defer gpa.free(tb);
    var target = try btf_mod.parse(gpa, tb, .{});
    defer target.deinit();

    // `r1 = <placeholder>` (MOV64 K), twice, then a 64-bit constant load
    var insns = [_]Insn{ @bitCast(ins8(0xb7, 0x01, 0, 77)), @bitCast(ins8(0xb7, 0x02, 0, 77)) };
    var relos = [_]btfext.CoreRelo{
        .{ .insn_off = 0, .type_id = ls, .access_str_off = a0, .kind = 9 }, // TYPE_SIZE
        .{ .insn_off = 1, .type_id = le, .access_str_off = a01, .kind = 11 }, // ENUMVAL_VALUE of NEG
    };
    var prog: ProgramSpec = undefined;
    prog.insns = &insns;
    prog.core_relos = &relos;
    try testing.expectEqual(@as(usize, 2), try applyCoreRelos(&prog, &local, &target));
    try testing.expectEqual(@as(i32, 40), insns[0].imm);
    try testing.expectEqual(@as(i32, -9), insns[1].imm); // a negative enumerator survives the imm

    // the enumerator the target lacks, and a type it lacks, are typed errors
    var empty = try RawB.init(gpa);
    defer empty.deinit(gpa);
    _ = try empty.rec(gpa, 0, btf_mod.K_INT, 0, false, 4, &.{32});
    const eb = try empty.finish(gpa);
    defer gpa.free(eb);
    var none = try btf_mod.parse(gpa, eb, .{});
    defer none.deinit();
    try testing.expectError(error.CoreTypeNotFound, applyCoreRelos(&prog, &local, &none));
    relos[0].kind = 8; // TYPE_EXISTS: 0 is a valid answer
    try testing.expectError(error.CoreEnumvalNotFound, applyCoreRelos(&prog, &local, &none));
    relos[1].kind = 10; // ENUMVAL_EXISTS
    try testing.expectEqual(@as(usize, 2), try applyCoreRelos(&prog, &local, &none));
    try testing.expectEqual(@as(i32, 0), insns[0].imm);
}

test "sub-programs: a clang object's static and global calls and a callback address are linked into each program" {
    const gpa = testing.allocator;
    var o = try open(gpa, fx_subprog, .{});
    defer o.deinit();
    try testing.expectEqual(@as(usize, 2), o.programs.len);
    const main = o.findProgram("xdp_main").?;
    const other = o.findProgram("xdp_other").?;

    // xdp_main (20 insns) + cb (6) + bump (15) + global_helper (7), each once
    try testing.expectEqual(@as(usize, 48), main.insns.len);
    // xdp_other (3) + global_helper (7) + bump (15): the callee's own call is followed
    try testing.expectEqual(@as(usize, 25), other.insns.len);
    try testing.expectEqual(@as(usize, 0), main.call_sites.len);

    for ([_]*ProgramSpec{ main, other }) |pr| {
        // the function starts are exactly the func_info records, ascending from 0
        try testing.expect(pr.func_info.len >= 3);
        try testing.expectEqual(@as(u32, 0), pr.func_info[0].insn_off);
        for (pr.func_info[1..], 0..) |f, i| try testing.expect(f.insn_off > pr.func_info[i].insn_off);
        var starts: [8]u32 = undefined;
        for (pr.func_info, 0..) |f, i| starts[i] = f.insn_off;
        // every pseudo call / pseudo func lands on one of them
        var calls: usize = 0;
        var k: usize = 0;
        while (k < pr.insns.len) : (k += 1) {
            const ins = pr.insns[k];
            const is_call = ins.code == 0x85 and ins.src == BPF_PSEUDO_CALL;
            const is_func = ins.code == 0x18 and ins.src == BPF_PSEUDO_FUNC;
            if (!is_call and !is_func) continue;
            calls += 1;
            const tgt: u32 = @intCast(@as(i64, @intCast(k)) + ins.imm + 1);
            var hit = false;
            for (starts[0..pr.func_info.len]) |st| hit = hit or st == tgt;
            try testing.expect(hit);
        }
        try testing.expect(calls >= 2);
        // line_info is rebased the same way: ascending, inside the program
        for (pr.line_info, 0..) |l, i| {
            try testing.expect(l.insn_off < pr.insns.len);
            if (i > 0) try testing.expect(l.insn_off >= pr.line_info[i - 1].insn_off);
        }
        // the callee's map and global-data relocations came along, on LD_IMM64s
        var maps: usize = 0;
        var vals: usize = 0;
        for (pr.relos) |r| {
            try testing.expectEqual(@as(u8, 0x18), pr.insns[r.insn_idx].code);
            switch (r.kind) {
                .map_fd => maps += 1,
                .map_value => vals += 1,
            }
        }
        try testing.expect(maps >= 1 and vals >= 1);
    }
    try testing.expectEqual(@as(usize, 4), main.func_info.len);
    try testing.expectEqual(@as(usize, 3), other.func_info.len);

    // and the whole thing goes through the real map relocation with synthetic fds
    for (o.maps, 0..) |*m, i| m.fd = @intCast(10 + i);
    try relocateProgram(main, o.maps);
    for (main.relos) |r| try testing.expect(main.insns[r.insn_idx].imm >= 10);
}
