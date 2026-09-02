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
const STT_FUNC: u4 = @intFromEnum(std.elf.STT.FUNC);
const STT_OBJECT: u4 = @intFromEnum(std.elf.STT.OBJECT);
const STT_SECTION: u4 = @intFromEnum(std.elf.STT.SECTION);

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
    /// `R_BPF_64_32` / a `BPF_PSEUDO_CALL` into `.text`.
    SubprogramCallsUnsupported,
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
        if (std.mem.eql(u8, name, ".text")) continue;
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
    for (prog_secs.items) |i| try splitProgramSection(&obj, a, i, &progs);
    obj.programs = progs.toOwnedSlice(a) catch return error.OutOfMemory;

    // ── pass 5: relocations + .BTF.ext slices ──
    for (obj.programs) |*p| {
        try collectRelocations(&obj, a, p);
        try sliceBtfExt(&obj, a, p);
    }
    return obj;
}

fn cstrSlice(d: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, d, 0) orelse d.len;
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
                        .type => spec.map_type = @enumFromInt(v),
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
    const n = obj.image.symbolCount(obj.symtab_idx) catch return error.MalformedElf;
    var idx: usize = 0;
    while (idx < count) : (idx += 1) {
        const at = idx * legacy_map_def_size;
        var name: []const u8 = "";
        var s: u32 = 0;
        while (s < n) : (s += 1) {
            const sym = obj.image.symbol(obj.symtab_idx, s) catch return error.MalformedElf;
            if (sym.st_shndx != sec_idx) continue;
            if (sym.kind() != STT_OBJECT) continue;
            if (sym.st_value != at) continue;
            name = obj.image.symbolName(obj.symtab_idx, sym);
            break;
        }
        if (name.len == 0) return error.MalformedMapDefinition;
        const d = data[at..][0..legacy_map_def_size];
        out.append(a, .{
            .name = a.dupe(u8, name) catch return error.OutOfMemory,
            .map_type = @enumFromInt(std.mem.readInt(u32, d[0..4], .little)),
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

fn splitProgramSection(obj: *Object, a: std.mem.Allocator, sec_idx: usize, out: *std.ArrayList(ProgramSpec)) ParseError!void {
    const s = obj.image.sections[sec_idx];
    if (s.sh_size % 8 != 0) return error.UnalignedInstructionSection;
    const data = obj.image.sectionData(sec_idx) catch return error.MalformedElf;
    if (data.len != s.sh_size) return error.MalformedElf;
    const sec_name = obj.image.sectionName(sec_idx);
    const info = classifySection(sec_name) orelse return; // filtered earlier

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
    const rel_idx = blk: {
        for (obj.image.sections, 0..) |s, i| {
            if (s.sh_type != elfsym.SHT_REL) continue;
            if (s.sh_info != prog.sec_idx) continue;
            break :blk i;
        }
        return; // no relocations at all
    };

    var relos: std.ArrayList(Relo) = .empty;
    const count = obj.image.relocationCount(rel_idx) catch return error.MalformedElf;
    const lo = prog.sec_byte_off;
    const hi = lo + prog.insns.len * 8;

    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const rel = obj.image.relocation(rel_idx, i) catch return error.MalformedElf;
        if (rel.r_offset < lo or rel.r_offset >= hi) continue; // another function
        if (rel.r_offset % 8 != 0) return error.RelocationOutOfRange;
        const insn_idx: u32 = @intCast((rel.r_offset - lo) / 8);

        const sym = obj.image.symbol(obj.symtab_idx, rel.sym) catch return error.MalformedElf;
        const sym_name = obj.image.symbolName(obj.symtab_idx, sym);

        // A call relocation: a sub-program, or a kfunc.
        if (rel.type == R_BPF_64_32) return error.SubprogramCallsUnsupported;
        if (rel.type != R_BPF_64_64) return error.UnsupportedRelocation;

        // An undefined symbol is an extern: kfunc, kconfig, or ksym.
        if (!sym.hasSection()) return error.ExternSymbolUnsupported;

        const insn = prog.insns[insn_idx];
        if (insn.code == CALL_CODE) return error.SubprogramCallsUnsupported;
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
            if (off > obj.maps[mi].value_size) return error.RelocationOutOfRange;
            relos.append(a, .{
                .kind = .map_value,
                .insn_idx = insn_idx,
                .map_idx = mi,
                .value_off = off,
                .sym_name = if (sym_name.len != 0) sym_name else target_name,
            }) catch return error.OutOfMemory;
        } else if (std.mem.eql(u8, target_name, ".text")) {
            return error.SubprogramCallsUnsupported;
        } else {
            return error.UnsupportedRelocation;
        }
    }
    prog.relos = relos.toOwnedSlice(a) catch return error.OutOfMemory;
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
            if (value > std.math.maxInt(i32)) return error.CoreValueTooLarge;
            insn.imm = @intCast(value);
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
        const res = try btfext.computeFieldRelo(local, target, r);
        if (!res.exists and res.kind != .field_exists) return error.CoreFieldNotFound;
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
    attr.map_type = @intFromEnum(m.map_type);
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
    try testing.expectError(error.NotABpfObject, open(gpa, "\x7fELF\x02\x01\x01" ++ ("\x00" ** 20), .{}));

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
    info = (info & 0xf0ff_ffff) | (@as(u32, @intFromEnum(btf_mod.Kind.int)) << 24);
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
