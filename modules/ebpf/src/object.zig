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
//! - `error.ExternSymbolUnsupported` — an `SHN_UNDEF` symbol the object's BTF
//!   does not describe as a `.kconfig` / `.ksyms` extern.
//! - `error.PinningUnsupported` — a `pinning` member that is neither none nor
//!   by-name.
//! - `error.MalformedMapDefinition`, `error.UnknownMapMember`,
//!   `error.UnknownProgramSection` — a map or section the loader cannot
//!   describe exactly.
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
const bpfsys = @import("bpfsys.zig");
const bpflink = @import("bpflink.zig");
const btfsanitize = @import("btfsanitize.zig");
const kconfig_mod = @import("kconfig.zig");

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

/// `BPF_F_LINK` — a struct_ops map attached through a link.
pub const BPF_F_LINK: u32 = 1 << 13;
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
const STB_WEAK: u4 = 2;
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
    /// A variable of the `.struct_ops` / `.struct_ops.link` section: a
    /// `BPF_MAP_TYPE_STRUCT_OPS` map (see `Object.attachStructOps`).
    struct_ops,
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
    /// `LIBBPF_PIN_NONE` (0) or `LIBBPF_PIN_BY_NAME` (1): with the latter `load`
    /// reuses the map pinned at `<pin_root>/<name>` when there is one (after
    /// checking it has the same type, sizes and flags) and otherwise creates
    /// the map and pins it there. Any other value is `error.PinningUnsupported`.
    pinning: u32 = 0,
    /// An explicit pin path, set by the caller before `load`: the map is
    /// reused from / pinned at exactly this path, whatever `pinning` says
    /// (libbpf's `bpf_map__set_pin_path`).
    pin_path: []const u8 = "",
    /// Set by `load` when the map was opened from its pin rather than created.
    reused: bool = false,
    /// `ARRAY_OF_MAPS` / `HASH_OF_MAPS`: the inner map's definition, from the
    /// element type of the `values` member. `load` creates a template inner
    /// map from it (its fd goes in `inner_map_fd` of the outer's create).
    inner: ?*const MapSpec = null,
    /// A `values` member is present (also true for a `PROG_ARRAY`'s).
    has_values: bool = false,
    /// Byte offset of the `values` member in the map's variable.
    values_off: u32 = 0,
    /// Pre-filled slots (`.values = { &inner_a, [2] = &prog }`): `load`
    /// stores the target's fd under key `index` once everything exists.
    init_slots: []const InitSlot = &.{},
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
    /// Set by `load` for an internal data map created with `BPF_F_MMAPABLE`
    /// (see `Object.mapData`).
    mmapable: bool = false,
    /// `.struct_ops.link`: attached with a link (`BPF_LINK_CREATE`) instead of
    /// by registering through `BPF_MAP_UPDATE_ELEM`.
    struct_ops_link: bool = false,
    /// Which program fills which function-pointer member of the variable
    /// (from `.rel.struct_ops`).
    struct_ops_progs: []const StructOpsProg = &.{},
    /// Set by `load`: the member translation to the kernel's layout, and the
    /// kernel-layout value (`bpf_struct_ops_<name>`) with the program fds in.
    struct_ops_plan: ?StructOpsPlan = null,
    struct_ops_value: []u8 = &.{},
};

/// A `.struct_ops` function-pointer slot filled by a program.
pub const StructOpsProg = struct {
    /// Byte offset of the member in the variable.
    member_off: u32,
    /// Index into `Object.programs`.
    program: usize,
};

/// One member copied from the object's struct into the kernel's value.
pub const StructOpsMember = struct {
    local_off: u32,
    /// Offset in the kernel VALUE (the `data` offset already added).
    kern_off: u32,
    size: u32,
    /// Index of the member in the kernel's struct: the `expected_attach_type`
    /// of a program that implements it.
    kern_index: u16,
    is_func: bool,
};

/// How the object's struct maps onto `bpf_struct_ops_<name>` of a kernel.
pub const StructOpsPlan = struct {
    /// `btf_vmlinux_value_type_id` of the map: `bpf_struct_ops_<name>`.
    value_type_id: u32,
    /// Id of the kernel's `struct <name>` (the programs' `attach_btf_id`).
    kern_type_id: u32,
    /// `sizeof(bpf_struct_ops_<name>)`: the map's value size.
    value_size: u32,
    members: []const StructOpsMember,
};

/// A global variable of a `.data` / `.rodata` / `.bss` section, as the object's
/// BTF `DATASEC` describes it.
pub const Variable = struct {
    name: []const u8,
    /// Byte offset in the section's map value.
    offset: u32,
    size: u32,
    /// The variable's type id in the object's BTF (the `VAR`'s own type, not
    /// the `VAR` record).
    type_id: u32,
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

/// What an `extern ... __kconfig` / `__ksym` declaration is.
pub const ExternKind = enum {
    /// A kernel configuration value (`CONFIG_*`, `LINUX_KERNEL_VERSION`): a
    /// field of the synthesized `.kconfig` map.
    kconfig,
    /// A kernel variable (`extern const struct rq runqueues __ksym`).
    ksym_var,
    /// A kernel function: a kfunc call, or its address.
    ksym_func,
};

/// One `extern` of the object, from the BTF `.kconfig` / `.ksyms` DATASECs.
pub const Extern = struct {
    name: []const u8,
    kind: ExternKind,
    /// `__weak`: absent from the kernel is a value of 0 (a dead call), not an
    /// error.
    weak: bool,
    /// The VAR or FUNC record in the object's BTF.
    btf_id: u32,
    /// The variable's type, or the function's prototype.
    type_id: u32,
    /// A `ksym_var` of type `void` (`extern const void x __ksym`): resolved
    /// to an address through `/proc/kallsyms`, not a BTF id.
    typeless: bool = false,
    /// `kconfig`: offset and size in the `.kconfig` map value.
    value_off: u32 = 0,
    size: u32 = 0,
    // ── set by `load` ──
    resolved: bool = false,
    /// The id in the kernel BTF (or the module's, see `fd_index`).
    kernel_btf_id: u32 = 0,
    /// 0 = vmlinux; otherwise the index of the module's BTF fd in the
    /// program's `fd_array` (the `off` of a kfunc call).
    fd_index: u16 = 0,
    /// A typeless ksym's address.
    addr: u64 = 0,
};

/// An instruction that refers to an `Extern`.
pub const ExternRef = struct {
    insn_idx: u32,
    extern_idx: usize,
    /// A `call` (kfunc) rather than an `LD_IMM64`.
    call: bool,
};

/// The `imm` an unresolved weak kfunc call carries: far outside any BTF id,
/// so a verifier that still reaches it reports the call, and one that proves
/// it dead removes it (libbpf's `POISON_CALL_KFUNC_BASE`).
pub const poison_call_kfunc_base: i32 = 2002000000;

/// A slot of a map-in-map or `PROG_ARRAY` initializer.
pub const InitSlot = struct {
    /// The array index: the map key the fd is stored under.
    index: u32,
    target: union(enum) {
        /// Index into `Object.maps`.
        map: usize,
        /// Index into `Object.programs`.
        program: usize,
    },
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
    /// Extern references (kfunc calls, ksym loads) still to be resolved by
    /// `load`; carried along when a sub-program is linked in.
    extern_refs: []ExternRef = &.{},
    /// BTF id of the attach target (`struct_ops`: the kernel struct), set by
    /// `load`; 0 for a program with none.
    attach_btf_id: u32 = 0,
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
    /// An `SHN_UNDEF` symbol the object's BTF does not describe as a
    /// `.kconfig` / `.ksyms` extern (a hand-written object, or a producer
    /// that left the BTF out).
    ExternSymbolUnsupported,
    /// A `__kconfig` extern whose BTF type cannot hold a configuration value
    /// (not bool, tristate, char, char array or a 1/2/4/8-byte integer).
    UnsupportedExternType,
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
    /// A map declared a `pinning` mode other than none / by-name.
    PinningUnsupported,
    /// `BPF_OBJ_PIN` of a freshly created map failed (no bpffs there, a
    /// missing directory, the path exists as something else).
    PinFailed,
    /// A `strong` extern (`__kconfig`, `__ksym`) the kernel does not have: no
    /// such configuration option, kernel variable or kfunc (a `__weak` one is
    /// 0 instead).
    ExternNotFound,
    /// An extern whose declared type does not fit what the kernel has: a
    /// configuration value of another kind or out of range for the variable,
    /// or a kernel variable / kfunc prototype of an incompatible type.
    ExternTypeMismatch,
    /// The running kernel's BTF has no `struct <name>` / `bpf_struct_ops_<name>`
    /// for a `.struct_ops` variable (vmlinux only; a module's is not read).
    StructOpsTypeNotFound,
    /// A `.struct_ops` member that the kernel struct lacks, or whose size
    /// differs, or a function pointer where the kernel has something else.
    StructOpsMemberMismatch,
    /// The map pinned at the map's pin path does not have the type, sizes or
    /// flags this object declares, so it cannot be reused.
    PinnedMapMismatch,
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
    /// `extern` declarations (`.kconfig`, `.ksyms`) the programs use.
    externs: []Extern = &.{},
    /// BTF fds of the kernel modules whose kfuncs/ksyms the programs call,
    /// opened by `load`; `fd_array[i + 1]` of every program (index 0 is
    /// vmlinux).
    module_btf_fds: []linux.fd_t = &.{},
    /// Executable sections whose names match no known prefix. `load` refuses
    /// unless `LoadOptions.ignore_unknown_sections`.
    unknown_sections: [][]const u8,

    /// `BPF_BTF_LOAD`'s fd, once `load` has run with `load_btf`.
    btf_fd: linux.fd_t = -1,
    /// `fd_array` handed to every program: index 0 unused (vmlinux), then the
    /// modules' BTF fds (`module_btf_fds`).
    fd_array: []i32 = &.{},
    /// False when `load` had to downgrade the BTF for a kernel without `FUNC`
    /// support: the programs' `func_info` then names functions that are
    /// typedefs, so it is not passed.
    btf_func_info: bool = true,
    /// `load` downgraded the BTF (`btfsanitize`) to get it accepted.
    btf_sanitized: bool = false,
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

    /// Close every fd this object owns (programs, maps, BTF, the kernel
    /// modules' BTF that `load` opened for kfuncs/ksyms), leaving the parsed
    /// specs intact. Idempotent.
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
        // 2026-11-27: these were never closed, one fd leaked per module a
        // load used. `fd_array` points at the same fds: dropped with them.
        for (self.module_btf_fds) |*fd| {
            if (fd.* >= 0) _ = linux.close(fd.*);
            fd.* = -1;
        }
        self.module_btf_fds = &.{};
        self.fd_array = &.{};
    }

    /// Activate a loaded `.struct_ops` map: register it with the kernel (a TCP
    /// congestion control becomes selectable, ...). A `.struct_ops` variable is
    /// registered by `BPF_MAP_UPDATE_ELEM` and unregistered by deleting the
    /// element; a `.struct_ops.link` one by `BPF_LINK_CREATE`, whose fd's
    /// lifetime is the registration. `StructOpsAttachment.detach` undoes it.
    pub fn attachStructOps(self: *Object, name: []const u8) StructOpsError!StructOpsAttachment {
        const m = self.findMap(name) orelse return error.NoSuchMap;
        if (m.origin != .struct_ops) return error.NotStructOps;
        if (m.fd < 0 or m.struct_ops_value.len == 0) return error.NotLoaded;
        if (m.struct_ops_link) {
            const h = bpflink.linkCreate(m.fd, 0, .struct_ops, .{}) catch |e| return switch (e) {
                error.PermissionDenied => error.PermissionDenied,
                error.AlreadyAttached => error.AlreadyAttached,
                error.LinkNotSupported => error.NotSupported,
                error.SystemResources => error.SystemResources,
                else => error.Unexpected,
            };
            return .{ .link = h };
        }
        var key: [4]u8 = @splat(0);
        var elem: BPF.MapElemAttr = .{
            .map_fd = m.fd,
            .key = @intFromPtr(&key),
            .result = .{ .value = @intFromPtr(m.struct_ops_value.ptr) },
            .flags = 0,
        };
        const rc = linux.bpf(.map_update_elem, @ptrCast(&elem), @sizeOf(BPF.MapElemAttr));
        return switch (linux.errno(rc)) {
            .SUCCESS => .{ .registered = m.fd },
            .PERM, .ACCES => error.PermissionDenied,
            .EXIST, .BUSY => error.AlreadyAttached,
            .INVAL, .BADF => error.InvalidArgument,
            .NOMEM, .NOSPC => error.SystemResources,
            else => error.Unexpected,
        };
    }

    /// The global variables of a data section (`".rodata"`, `".data"`,
    /// `".bss"`, or a split one like `".data.foo"`), from the BTF `DATASEC`:
    /// name, byte offset in the map value, size and type id. Offsets and sizes
    /// are the ELF's (`fixupDatasecs`), not clang's zeros. Empty when the
    /// object has no BTF or no such section. The slice is arena-owned.
    pub fn dataVariables(self: *Object, sec_name: []const u8) ParseError![]const Variable {
        const b = &(self.btf orelse return &.{});
        // `.kconfig` is the loader's: its variables are the `__kconfig` externs
        // at the offsets the loader gave them, `.ksyms` has no storage
        if (std.mem.eql(u8, sec_name, ".ksyms")) return &.{};
        if (std.mem.eql(u8, sec_name, ".kconfig")) {
            const a = self.arena.allocator();
            var list: std.ArrayList(Variable) = .empty;
            for (self.externs) |e| {
                if (e.kind != .kconfig) continue;
                list.append(a, .{ .name = e.name, .offset = e.value_off, .size = e.size, .type_id = e.type_id }) catch return error.OutOfMemory;
            }
            return list.toOwnedSlice(a) catch return error.OutOfMemory;
        }
        try fixupDatasecs(self);
        const id = b.findByNameKind(sec_name, .datasec) orelse return &.{};
        const ds = b.byId(id) catch return error.MalformedBtf;
        const a = self.arena.allocator();
        const out = a.alloc(Variable, ds.vlen) catch return error.OutOfMemory;
        var n: usize = 0;
        var i: u16 = 0;
        while (i < ds.vlen) : (i += 1) {
            const vsi = b.varSecInfo(ds, i) catch return error.MalformedBtf;
            const vt = b.byId(vsi.type_id) catch return error.MalformedBtf;
            if (vt.kind != .@"var") continue;
            out[n] = .{
                .name = b.typeName(vsi.type_id) orelse continue,
                .offset = vsi.offset,
                .size = vsi.size,
                .type_id = vt.refType() orelse continue,
            };
            n += 1;
        }
        return out[0..n];
    }

    /// The seed contents of an internal data map, mutable, **before `load`**:
    /// edit a `const volatile` configuration here and the program sees it
    /// (`.rodata` is frozen after seeding). The bytes are the object's own
    /// copy of the section, not the caller's buffer. `null` for a map that is
    /// not an internal data map.
    pub fn initialData(self: *Object, map_name: []const u8) ?[]u8 {
        const m = self.findMap(map_name) orelse return null;
        if (m.origin != .internal or m.initial_data.len == 0) return null;
        // `initial_data` points into the arena copy of the image `open` made
        // (see `Object.arena`): writable memory behind a const slice type.
        return @constCast(m.initial_data);
    }

    /// Map the created internal data map `name` into this process: the live
    /// `.data` / `.bss` of the running program, read and written without a
    /// syscall (`.rodata` is frozen, so its mapping is read-only). Needs
    /// `load` to have run and the map to have been created `BPF_F_MMAPABLE`.
    pub fn mapData(self: *Object, name: []const u8) MapDataError!MappedData {
        const m = self.findMap(name) orelse return error.NoSuchMap;
        if (m.fd < 0) return error.NotLoaded;
        if (!m.mmapable) return error.NotMmapable;
        const len = std.math.mul(usize, m.value_size, m.max_entries) catch return error.NotMmapable;
        return MappedData.map(m.fd, len, m.value_size, !m.freeze);
    }

    /// `BPF_OBJ_PIN` every created map (not the internal data maps) at
    /// `<dir>/<name>`, and `unpinMaps` the reverse. `dir` is a bpffs directory.
    /// A map already pinned at its path (an explicit `pin_path`, or one that
    /// `load` pinned) is skipped.
    pub fn pinMaps(self: *Object, dir: []const u8) bpfsys.Error!void {
        const a = self.arena.allocator();
        for (self.maps) |*m| {
            if (m.fd < 0 or m.origin == .internal or m.reused) continue;
            const path = a.print("{s}/{s}", .{ dir, m.name }) catch return error.OutOfMemory;
            try bpfsys.objPin(m.fd, path);
        }
    }

    /// `BPF_OBJ_PIN` every loaded program at `<dir>/<program name>`.
    pub fn pinPrograms(self: *Object, dir: []const u8) bpfsys.Error!void {
        const a = self.arena.allocator();
        for (self.programs) |*p| {
            if (p.fd < 0) continue;
            const path = a.print("{s}/{s}", .{ dir, p.name }) catch return error.OutOfMemory;
            try bpfsys.objPin(p.fd, path);
        }
    }

    /// Remove the pins `pinMaps(dir)` made (a missing one is not an error).
    pub fn unpinMaps(self: *Object, dir: []const u8) bpfsys.Error!void {
        const a = self.arena.allocator();
        for (self.maps) |*m| {
            if (m.origin == .internal) continue;
            const path = a.print("{s}/{s}", .{ dir, m.name }) catch return error.OutOfMemory;
            bpfsys.objUnpin(path) catch |e| if (e != error.NotFound) return e;
        }
    }

    /// Remove the pins `pinPrograms(dir)` made (a missing one is not an error).
    pub fn unpinPrograms(self: *Object, dir: []const u8) bpfsys.Error!void {
        const a = self.arena.allocator();
        for (self.programs) |*p| {
            const path = a.print("{s}/{s}", .{ dir, p.name }) catch return error.OutOfMemory;
            bpfsys.objUnpin(path) catch |e| if (e != error.NotFound) return e;
        }
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

pub const StructOpsError = error{
    NoSuchMap,
    /// The map is not a `.struct_ops` variable.
    NotStructOps,
    /// `load` has not run.
    NotLoaded,
    AlreadyAttached,
    NotSupported,
    PermissionDenied,
    InvalidArgument,
    SystemResources,
    Unexpected,
};

/// A live struct_ops registration.
pub const StructOpsAttachment = union(enum) {
    /// Registered by `BPF_MAP_UPDATE_ELEM`: the map's fd (still the
    /// `Object`'s).
    registered: linux.fd_t,
    link: bpflink.LinkHandle,

    /// Unregister: delete the element, or close the link.
    pub fn detach(self: *StructOpsAttachment) void {
        switch (self.*) {
            .registered => |fd| {
                var key: [4]u8 = @splat(0);
                var elem: BPF.MapElemAttr = .{ .map_fd = fd, .key = @intFromPtr(&key), .result = .{ .value = 0 }, .flags = 0 };
                _ = linux.bpf(.map_delete_elem, @ptrCast(&elem), @sizeOf(BPF.MapElemAttr));
                self.* = .{ .registered = -1 };
            },
            .link => |*l| l.detach(),
        }
    }
};

pub const MapDataError = error{
    NoSuchMap,
    /// `load` has not created the map yet.
    NotLoaded,
    /// The map was created without `BPF_F_MMAPABLE` (not an internal data
    /// map, an older kernel, or `LoadOptions.mmap_data = false`).
    NotMmapable,
    PermissionDenied,
    MmapFailed,
    SizeMismatch,
    Unexpected,
};

/// An internal data map mapped into this process. `deinit` unmaps; the
/// pointers it hands out are invalid afterwards.
pub const MappedData = struct {
    /// The whole mapping (page-rounded).
    mapping: []align(std.heap.page_size_min) u8,
    /// The map value's length: the part of `mapping` that holds data.
    len: usize,
    writable: bool,

    fn map(fd: linux.fd_t, map_bytes: usize, value_len: usize, writable: bool) MapDataError!MappedData {
        const page = std.heap.pageSize();
        const total = std.mem.alignForward(usize, @max(map_bytes, 1), page);
        const prot: linux.PROT = if (writable) .{ .READ = true, .WRITE = true } else .{ .READ = true };
        const rc = linux.mmap(null, total, prot, .{ .TYPE = .SHARED }, fd, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.PermissionDenied,
            .INVAL, .NODEV, .NOMEM, .AGAIN => return error.MmapFailed,
            else => return error.Unexpected,
        }
        const ptr: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(rc);
        return .{ .mapping = ptr[0..total], .len = value_len, .writable = writable };
    }

    pub fn deinit(self: *MappedData) void {
        _ = linux.munmap(self.mapping.ptr, self.mapping.len);
        self.* = undefined;
    }

    /// The map value's bytes.
    pub fn bytes(self: MappedData) []u8 {
        return self.mapping[0..self.len];
    }

    /// The value as a `T` (an `extern struct` mirroring the section: the
    /// variables in offset order). `T` may be smaller than the value, never
    /// larger.
    pub fn view(self: MappedData, comptime T: type) MapDataError!*T {
        if (@sizeOf(T) > self.len) return error.SizeMismatch;
        return @ptrCast(@alignCast(self.mapping.ptr));
    }

    /// One variable's bytes.
    pub fn variable(self: MappedData, v: Variable) MapDataError![]u8 {
        if (v.offset > self.len or v.size > self.len - v.offset) return error.SizeMismatch;
        return self.mapping[v.offset..][0..v.size];
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

    // ── pass 3b: externs (`.kconfig`, `.ksyms`) and the `.kconfig` map ──
    try collectExterns(&obj, a);

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

    // ── pass 4b: map-in-map / prog_array initial slots (`.rel.maps`) ──
    if (maps_btf_sec) |i| try collectMapSlots(&obj, a, i);

    // ── pass 4c: struct_ops maps (`.struct_ops`, `.struct_ops.link`) ──
    try collectStructOps(&obj, a);

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
        try parseMapDef(b, a, st, &spec, 0);
        out.append(a, spec) catch return error.OutOfMemory;
    }
}

/// Fill `spec` from the members of a map-definition struct. `depth` is 0 for a
/// `.maps` variable and 1 for an inner map definition, which may not itself
/// have a `values` member (the kernel has no map-in-map-in-map).
fn parseMapDef(b: *const Btf, a: std.mem.Allocator, st: btf_mod.Type, spec: *MapSpec, depth: u8) ParseError!void {
    var values_mem: ?btf_mod.Member = null;
    var m: u16 = 0;
    while (m < st.vlen) : (m += 1) {
        const mem = b.member(st, m) catch return error.MalformedBtf;
        const mname = b.str(mem.name_off) orelse return error.MalformedMapDefinition;
        const which = std.meta.stringToEnum(MapMember, mname) orelse return error.UnknownMapMember;
        switch (which) {
            .values => values_mem = mem,
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

    // `values` is `typeof(T) *values[]`: an array of pointers to T. For a map
    // in map T is the inner map's definition struct; for a `PROG_ARRAY` it is
    // a function type. It is judged after the loop: `type` may follow it.
    if (values_mem) |vm| {
        if (depth != 0) return error.MalformedMapDefinition;
        const arr_id = b.skipModifiers(vm.type_id) catch return error.MalformedBtf;
        const arr = b.byId(arr_id) catch return error.MalformedBtf;
        if (arr.kind != .array) return error.MalformedMapDefinition;
        const ai = b.arrayInfo(arr) catch return error.MalformedBtf;
        const p_id = b.skipModifiers(ai.elem_type) catch return error.MalformedBtf;
        const p = b.byId(p_id) catch return error.MalformedBtf;
        if (p.kind != .ptr) return error.MalformedMapDefinition;
        const t_id = p.refType() orelse return error.MalformedMapDefinition;
        if (t_id == 0) return error.MalformedMapDefinition;
        const t = b.resolve(t_id) catch return error.MalformedBtf;
        spec.has_values = true;
        spec.values_off = vm.bit_offset / 8;
        switch (spec.map_type) {
            .array_of_maps, .hash_of_maps => {
                if (t.kind != .@"struct") return error.MalformedMapDefinition;
                const inner = a.create(MapSpec) catch return error.OutOfMemory;
                inner.* = .{
                    .name = "inner",
                    .map_type = .unspec,
                    .origin = .btf_defined,
                    .sec_idx = spec.sec_idx,
                };
                try parseMapDef(b, a, t, inner, 1);
                spec.inner = inner;
            },
            .prog_array => if (t.kind != .func_proto) return error.MalformedMapDefinition,
            else => return error.MalformedMapDefinition,
        }
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
    var externs: std.ArrayList(ExternRef) = .empty;
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

        const insn = prog.insns[insn_idx];

        // An undefined symbol is an extern: kfunc, kconfig, or ksym.
        if (!sym.hasSection()) {
            const ei = findExternIdx(obj, sym_name) orelse return error.ExternSymbolUnsupported;
            const ext = obj.externs[ei];
            if (rel.type == R_BPF_64_32) {
                if (insn.code != CALL_CODE or ext.kind != .ksym_func) return error.UnsupportedRelocation;
                externs.append(a, .{ .insn_idx = insn_idx, .extern_idx = ei, .call = true }) catch return error.OutOfMemory;
                continue;
            }
            if (insn.code != LD_IMM64_CODE) return error.UnsupportedRelocation;
            if (insn_idx + 1 >= prog.insns.len) return error.RelocationOutOfRange;
            switch (ext.kind) {
                // a `.kconfig` field is a read of the synthesized map's value
                .kconfig => relos.append(a, .{
                    .kind = .map_value,
                    .insn_idx = insn_idx,
                    .map_idx = findMapIdx(obj, ".kconfig") orelse return error.UnresolvedRelocation,
                    .value_off = ext.value_off,
                    .sym_name = ext.name,
                }) catch return error.OutOfMemory,
                .ksym_var, .ksym_func => externs.append(a, .{ .insn_idx = insn_idx, .extern_idx = ei, .call = false }) catch return error.OutOfMemory,
            }
            continue;
        }

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
    prog.extern_refs = externs.toOwnedSlice(a) catch return error.OutOfMemory;
}

/// The `extern` declarations of the object: the VARs and FUNCs of the
/// `.kconfig` and `.ksyms` DATASECs that BTF marks `extern`. The `__kconfig`
/// ones get a private layout (declaration order, natural alignment) in a
/// synthesized `.kconfig` map, which `load` fills from the kernel configuration.
fn collectExterns(obj: *Object, a: std.mem.Allocator) ParseError!void {
    const b = &(obj.btf orelse return);
    var list: std.ArrayList(Extern) = .empty;
    var kcfg_off: u32 = 0;
    var kcfg_max_align: u32 = 1;
    for ([_][]const u8{ ".kconfig", ".ksyms" }) |sec_name| {
        const id = b.findByNameKind(sec_name, .datasec) orelse continue;
        const ds = b.byId(id) catch return error.MalformedBtf;
        var i: u16 = 0;
        while (i < ds.vlen) : (i += 1) {
            const vsi = b.varSecInfo(ds, i) catch return error.MalformedBtf;
            const t = b.byId(vsi.type_id) catch return error.MalformedBtf;
            const name = b.typeName(vsi.type_id) orelse continue;
            var ext: Extern = undefined;
            switch (t.kind) {
                .@"var" => {
                    const link = b.varLinkage(t) catch return error.MalformedBtf;
                    if (link != .global_extern) continue;
                    const ty = t.refType() orelse return error.MalformedBtf;
                    ext = .{ .name = name, .kind = .kconfig, .weak = false, .btf_id = vsi.type_id, .type_id = ty };
                    if (std.mem.eql(u8, sec_name, ".ksyms")) {
                        ext.kind = .ksym_var;
                        // `void` (after any qualifiers): resolved by address
                        const strip = skipQualifiers(b, ty) catch return error.MalformedBtf;
                        ext.typeless = strip == 0;
                    } else {
                        const sa = kconfig_mod.sizeAlign(b, ty) catch return error.UnsupportedExternType;
                        kcfg_off = std.mem.alignForward(u32, kcfg_off, sa.align_);
                        ext.value_off = kcfg_off;
                        ext.size = sa.size;
                        kcfg_off = std.math.add(u32, kcfg_off, sa.size) catch return error.UnsupportedExternType;
                        kcfg_max_align = @max(kcfg_max_align, sa.align_);
                    }
                },
                .func => {
                    if (t.funcLinkage() != .external) continue;
                    ext = .{ .name = name, .kind = .ksym_func, .weak = false, .btf_id = vsi.type_id, .type_id = t.refType() orelse return error.MalformedBtf };
                },
                else => continue,
            }
            // `__weak` is a property of the ELF symbol, not of the BTF
            ext.weak = externIsWeak(obj, name);
            list.append(a, ext) catch return error.OutOfMemory;
        }
    }
    if (list.items.len == 0) return;
    obj.externs = list.toOwnedSlice(a) catch return error.OutOfMemory;

    if (kcfg_off != 0) {
        var maps: std.ArrayList(MapSpec) = .empty;
        maps.appendSlice(a, obj.maps) catch return error.OutOfMemory;
        const data = a.alloc(u8, kcfg_off) catch return error.OutOfMemory;
        @memset(data, 0);
        maps.append(a, .{
            .name = ".kconfig",
            .map_type = .array,
            .key_size = 4,
            .value_size = kcfg_off,
            .max_entries = 1,
            .map_flags = BPF_F_RDONLY_PROG,
            .origin = .internal,
            .sec_idx = obj.image.findSection(".kconfig") orelse 0,
            .initial_data = data,
            .freeze = true,
        }) catch return error.OutOfMemory;
        for (maps.items[0 .. maps.items.len - 1]) |m| {
            if (std.mem.eql(u8, m.name, ".kconfig")) return error.DuplicateMap;
        }
        obj.maps = maps.toOwnedSlice(a) catch return error.OutOfMemory;
    }
}

fn skipQualifiers(b: *const Btf, id: u32) btf_mod.TypeError!u32 {
    var cur = id;
    var n: u32 = 0;
    while (cur != 0 and n < btf_mod.max_resolve_depth) : (n += 1) {
        const t = try b.byId(cur);
        if (!t.isModifier()) return cur;
        cur = t.size_type;
    }
    return cur;
}

fn externIsWeak(obj: *Object, name: []const u8) bool {
    const n = obj.image.symbolCount(obj.symtab_idx) catch return false;
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const sym = obj.image.symbol(obj.symtab_idx, i) catch continue;
        if (sym.hasSection()) continue;
        if (!std.mem.eql(u8, obj.image.symbolName(obj.symtab_idx, sym), name)) continue;
        return sym.bind() == STB_WEAK;
    }
    return false;
}

fn findExternIdx(obj: *const Object, name: []const u8) ?usize {
    for (obj.externs, 0..) |e, i| {
        if (std.mem.eql(u8, e.name, name)) return i;
    }
    return null;
}

/// `.struct_ops` / `.struct_ops.link`: each `VAR` of the `DATASEC` is a
/// `struct <kernel ops>` initializer and becomes a `BPF_MAP_TYPE_STRUCT_OPS`
/// map named after it. Its bytes are the section's, with the function-pointer
/// members zero and filled by `R_BPF_64_ABS64` relocations in `.rel<section>`
/// against the implementing programs.
fn collectStructOps(obj: *Object, a: std.mem.Allocator) ParseError!void {
    if (obj.btf == null) return;
    var maps: std.ArrayList(MapSpec) = .empty;
    maps.appendSlice(a, obj.maps) catch return error.OutOfMemory;
    const first_new = maps.items.len;
    for ([_][]const u8{ ".struct_ops", ".struct_ops.link" }) |sec_name| {
        const sec_idx = obj.image.findSection(sec_name) orelse continue;
        const data = obj.image.sectionData(sec_idx) catch return error.MalformedElf;
        const vars = try obj.dataVariables(sec_name);
        const link = std.mem.eql(u8, sec_name, ".struct_ops.link");
        const base = maps.items.len;
        for (vars) |v| {
            if (v.offset > data.len or v.size > data.len - v.offset) return error.MalformedElf;
            maps.append(a, .{
                .name = a.dupe(u8, v.name) catch return error.OutOfMemory,
                .map_type = .struct_ops,
                .key_size = 4,
                .value_size = v.size,
                .max_entries = 1,
                .btf_value_type_id = v.type_id,
                .origin = .struct_ops,
                .sec_idx = sec_idx,
                .initial_data = data[v.offset..][0..v.size],
                .struct_ops_link = link,
            }) catch return error.OutOfMemory;
        }
        // relocations: the program behind each function-pointer member
        const rel_idx: usize = blk: {
            for (obj.image.sections, 0..) |sh, i| {
                if (sh.sh_type == elfsym.SHT_REL and sh.sh_info == sec_idx) break :blk i;
            }
            continue;
        };
        const count = obj.image.relocationCount(rel_idx) catch return error.MalformedElf;
        const lists = a.alloc(std.ArrayList(StructOpsProg), vars.len) catch return error.OutOfMemory;
        for (lists) |*l| l.* = .empty;
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            const rel = obj.image.relocation(rel_idx, i) catch return error.MalformedElf;
            if (rel.type != R_BPF_64_ABS64 and rel.type != R_BPF_64_64) return error.UnsupportedRelocation;
            // the variable holding `r_offset`: the last one starting at or before it
            var lo: usize = 0;
            var hi: usize = vars.len;
            while (lo < hi) {
                const mid = lo + (hi - lo) / 2;
                if (vars[mid].offset <= rel.r_offset) lo = mid + 1 else hi = mid;
            }
            if (lo == 0) return error.RelocationOutOfRange;
            const v = vars[lo - 1];
            if (rel.r_offset - v.offset >= v.size) return error.RelocationOutOfRange;
            const sym = obj.image.symbol(obj.symtab_idx, rel.sym) catch return error.MalformedElf;
            if (sym.kind() != STT_FUNC) return error.UnresolvedRelocation;
            const prog = for (obj.programs, 0..) |p, k| {
                if (p.sec_idx == sym.st_shndx and p.sec_byte_off == sym.st_value) break k;
            } else return error.UnresolvedRelocation;
            lists[lo - 1].append(a, .{
                .member_off = @intCast(rel.r_offset - v.offset),
                .program = prog,
            }) catch return error.OutOfMemory;
        }
        for (lists, 0..) |*l, k| {
            maps.items[base + k].struct_ops_progs = l.toOwnedSlice(a) catch return error.OutOfMemory;
        }
    }
    if (maps.items.len == first_new) return;
    // a variable name must not collide with another map's
    for (maps.items[first_new..], first_new..) |m, i| {
        for (maps.items[0..i]) |n| {
            if (std.mem.eql(u8, m.name, n.name)) return error.DuplicateMap;
        }
    }
    obj.maps = maps.toOwnedSlice(a) catch return error.OutOfMemory;
}

/// Plan how `local`'s `struct <ops>` (type `local_type_id`) maps onto the
/// kernel's `bpf_struct_ops_<ops>` in `kern`: members are matched by NAME and
/// must have the same size; a member of the object that the kernel lacks is an
/// error (a typo must not silently load a no-op), the kernel's extra members
/// stay zero (the kernel fills `owner`, `list`, ...). A function pointer must
/// face a function pointer. Pure over the two BTFs.
pub fn planStructOps(a: std.mem.Allocator, local: *const Btf, local_type_id: u32, kern: *const Btf) LoadError!StructOpsPlan {
    const lt = local.resolve(local_type_id) catch return error.StructOpsMemberMismatch;
    if (lt.kind != .@"struct") return error.StructOpsMemberMismatch;
    const raw_name = local.str(lt.name_off) orelse return error.StructOpsTypeNotFound;
    if (raw_name.len == 0) return error.StructOpsTypeNotFound;
    const name = btfext.stripFlavor(raw_name);

    const kern_type_id = kern.findByNameKind(name, .@"struct") orelse return error.StructOpsTypeNotFound;
    var vname_buf: [128]u8 = undefined;
    const vname = std.mem.print(&vname_buf, "bpf_struct_ops_{s}", .{name}) catch return error.StructOpsTypeNotFound;
    const value_type_id = kern.findByNameKind(vname, .@"struct") orelse return error.StructOpsTypeNotFound;
    const vt = kern.byId(value_type_id) catch return error.StructOpsTypeNotFound;
    // the kernel struct sits at `data` in the value wrapper
    var data_off: ?u32 = null;
    var vi: u16 = 0;
    while (vi < vt.vlen) : (vi += 1) {
        const m = kern.member(vt, vi) catch return error.StructOpsTypeNotFound;
        const mn = kern.str(m.name_off) orelse continue;
        if (std.mem.eql(u8, mn, "data")) data_off = m.bit_offset / 8;
    }
    const doff = data_off orelse return error.StructOpsTypeNotFound;
    const kt = kern.byId(kern_type_id) catch return error.StructOpsTypeNotFound;
    const value_size = kern.sizeOf(value_type_id) catch return error.StructOpsTypeNotFound;
    if (value_size > std.math.maxInt(u32)) return error.StructOpsTypeNotFound;

    var members: std.ArrayList(StructOpsMember) = .empty;
    var i: u16 = 0;
    while (i < lt.vlen) : (i += 1) {
        const lm = local.member(lt, i) catch return error.StructOpsMemberMismatch;
        const mname = local.str(lm.name_off) orelse return error.StructOpsMemberMismatch;
        if (mname.len == 0) continue; // an anonymous member cannot be matched by name
        if (lm.bitfield_size != 0 or lm.bit_offset % 8 != 0) return error.StructOpsMemberMismatch;
        var found: ?struct { m: btf_mod.Member, idx: u16 } = null;
        var k: u16 = 0;
        while (k < kt.vlen) : (k += 1) {
            const km = kern.member(kt, k) catch return error.StructOpsMemberMismatch;
            const kn = kern.str(km.name_off) orelse continue;
            if (std.mem.eql(u8, kn, mname)) {
                found = .{ .m = km, .idx = k };
                break;
            }
        }
        const f = found orelse return error.StructOpsMemberMismatch;
        if (f.m.bitfield_size != 0 or f.m.bit_offset % 8 != 0) return error.StructOpsMemberMismatch;
        const lsz = local.sizeOf(lm.type_id) catch return error.StructOpsMemberMismatch;
        const ksz = kern.sizeOf(f.m.type_id) catch return error.StructOpsMemberMismatch;
        if (lsz != ksz or lsz > std.math.maxInt(u32)) return error.StructOpsMemberMismatch;
        const l_func = isFuncPtr(local, lm.type_id);
        if (l_func != isFuncPtr(kern, f.m.type_id)) return error.StructOpsMemberMismatch;
        members.append(a, .{
            .local_off = lm.bit_offset / 8,
            .kern_off = std.math.add(u32, doff, f.m.bit_offset / 8) catch return error.StructOpsMemberMismatch,
            .size = @intCast(lsz),
            .kern_index = f.idx,
            .is_func = l_func,
        }) catch return error.OutOfMemory;
    }
    return .{
        .value_type_id = value_type_id,
        .kern_type_id = kern_type_id,
        .value_size = @intCast(value_size),
        .members = members.toOwnedSlice(a) catch return error.OutOfMemory,
    };
}

fn isFuncPtr(b: *const Btf, type_id: u32) bool {
    const t = b.resolve(type_id) catch return false;
    if (t.kind != .ptr) return false;
    const target = t.refType() orelse return false;
    if (target == 0) return false;
    const ft = b.resolve(target) catch return false;
    return ft.kind == .func_proto;
}

/// The kernel-layout value for a planned `.struct_ops` map: zeros, the
/// object's scalar members copied in, and each function-pointer member set to
/// the fd of the program that implements it (`prog_fds[k]` is the fd of
/// `Object.programs[k]`). A function pointer nobody implements stays NULL.
pub fn buildStructOpsValue(
    a: std.mem.Allocator,
    plan: StructOpsPlan,
    initial: []const u8,
    progs: []const StructOpsProg,
    prog_fds: []const linux.fd_t,
) LoadError![]u8 {
    const out = a.alloc(u8, plan.value_size) catch return error.OutOfMemory;
    @memset(out, 0);
    for (plan.members) |m| {
        if (m.local_off > initial.len or m.size > initial.len - m.local_off) return error.StructOpsMemberMismatch;
        if (m.kern_off > out.len or m.size > out.len - m.kern_off) return error.StructOpsMemberMismatch;
        if (m.is_func) {
            for (progs) |p| {
                if (p.member_off != m.local_off) continue;
                if (p.program >= prog_fds.len or prog_fds[p.program] < 0) return error.MapNotCreated;
                std.mem.writeInt(u64, out[m.kern_off..][0..8], @intCast(prog_fds[p.program]), builtin.cpu.arch.endian());
            }
        } else {
            @memcpy(out[m.kern_off..][0..m.size], initial[m.local_off..][0..m.size]);
        }
    }
    return out;
}

/// `.rel.maps` carries the initializer of a map-in-map or `PROG_ARRAY`
/// (`.values = { &inner_a, [2] = &prog }`): one `R_BPF_64_ABS64` per filled
/// slot, at `<variable offset> + <values member offset> + 8 * index`, against
/// the target's symbol — a `.maps` variable (a map) or a function (a program).
fn collectMapSlots(obj: *Object, a: std.mem.Allocator, maps_sec: usize) ParseError!void {
    var any = false;
    for (obj.maps) |m| {
        if (m.has_values and m.origin == .btf_defined and m.sec_idx == maps_sec) any = true;
    }
    if (!any) return;

    // Where each map's variable sits in `.maps`: from its `STT_OBJECT` symbol.
    const Var = struct { off: u64, size: u64, map: usize };
    var vars: std.ArrayList(Var) = .empty;
    const n = obj.image.symbolCount(obj.symtab_idx) catch return error.MalformedElf;
    var si: u32 = 0;
    while (si < n) : (si += 1) {
        const sym = obj.image.symbol(obj.symtab_idx, si) catch return error.MalformedElf;
        if (sym.st_shndx != maps_sec or sym.kind() != STT_OBJECT) continue;
        const mi = findMapIdx(obj, obj.image.symbolName(obj.symtab_idx, sym)) orelse continue;
        if (!obj.maps[mi].has_values) continue;
        vars.append(a, .{ .off = sym.st_value, .size = sym.st_size, .map = mi }) catch return error.OutOfMemory;
    }
    std.mem.sort(Var, vars.items, {}, struct {
        fn lt(_: void, x: Var, y: Var) bool {
            return x.off < y.off;
        }
    }.lt);

    const rel_idx: usize = blk: {
        for (obj.image.sections, 0..) |s, i| {
            if (s.sh_type == elfsym.SHT_REL and s.sh_info == maps_sec) break :blk i;
        }
        return; // no initializers at all
    };
    const count = obj.image.relocationCount(rel_idx) catch return error.MalformedElf;

    const Slots = std.ArrayList(InitSlot);
    const lists = a.alloc(Slots, obj.maps.len) catch return error.OutOfMemory;
    for (lists) |*l| l.* = .empty;

    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const rel = obj.image.relocation(rel_idx, i) catch return error.MalformedElf;
        if (rel.type != R_BPF_64_ABS64) return error.UnsupportedRelocation;
        // The variable whose range holds `r_offset`: the last one starting at or before it.
        var lo: usize = 0;
        var hi: usize = vars.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (vars.items[mid].off <= rel.r_offset) lo = mid + 1 else hi = mid;
        }
        if (lo == 0) return error.RelocationOutOfRange;
        const v = vars.items[lo - 1];
        const m = &obj.maps[v.map];
        const rel_in_var = rel.r_offset - v.off;
        if (rel_in_var >= v.size or rel_in_var < m.values_off) return error.RelocationOutOfRange;
        const slot_off = rel_in_var - m.values_off;
        if (slot_off % 8 != 0) return error.RelocationOutOfRange;
        const index = slot_off / 8;
        if (index >= m.max_entries) return error.RelocationOutOfRange;

        const sym = obj.image.symbol(obj.symtab_idx, rel.sym) catch return error.MalformedElf;
        const sym_name = obj.image.symbolName(obj.symtab_idx, sym);
        const target: @FieldType(InitSlot, "target") = switch (m.map_type) {
            .array_of_maps, .hash_of_maps => .{ .map = blk: {
                if (sym.st_shndx != maps_sec) return error.UnresolvedRelocation;
                break :blk findMapIdx(obj, sym_name) orelse return error.UnresolvedRelocation;
            } },
            .prog_array => .{ .program = blk: {
                if (sym.kind() != STT_FUNC) return error.UnresolvedRelocation;
                for (obj.programs, 0..) |p, k| {
                    if (p.sec_idx == sym.st_shndx and p.sec_byte_off == sym.st_value) break :blk k;
                }
                return error.UnresolvedRelocation;
            } },
            else => return error.UnresolvedRelocation,
        };
        lists[v.map].append(a, .{ .index = @intCast(index), .target = target }) catch return error.OutOfMemory;
    }
    for (lists, 0..) |*l, k| {
        if (l.items.len != 0) obj.maps[k].init_slots = l.toOwnedSlice(a) catch return error.OutOfMemory;
    }
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
        var exts: std.ArrayList(ExternRef) = .empty;
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
                ex: *std.ArrayList(ExternRef),
            ) ParseError!void {
                i.appendSlice(al, f.insns) catch return error.OutOfMemory;
                for (f.extern_refs) |x| {
                    var y = x;
                    y.insn_idx += base;
                    ex.append(al, y) catch return error.OutOfMemory;
                }
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
        try Local.append(a, snap[pi], 0, &insns, &relos, &finfo, &linfo, &cores, &exts);
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
                    try Local.append(a, f, b, &insns, &relos, &finfo, &linfo, &cores, &exts);
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
        p.extern_refs = exts.items;
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
    /// When the kernel's BTF verifier rejects the object's BTF, probe which
    /// kinds it knows and retry with the unknown ones downgraded
    /// (`btfsanitize`: `FLOAT`, `DECL_TAG`, `TYPE_TAG`, `ENUM64`, `FUNC`,
    /// `DATASEC`...), as libbpf does. Off: a rejected BTF is
    /// `error.BtfLoadFailed` (and `load_btf = false` the escape hatch).
    sanitize_btf: bool = true,
    /// Create the internal data maps (`.data`, `.bss`, `.rodata`) with
    /// `BPF_F_MMAPABLE`, so `Object.mapData` can map them (libbpf does). A
    /// kernel older than 5.5 refuses the flag; `load` then retries without it
    /// and `MapSpec.mmapable` stays false.
    mmap_data: bool = true,
    /// The kernel configuration `__kconfig` externs read, as the text of a
    /// `.config`; `null` reads the running kernel's (`/proc/config.gz`, then
    /// `/boot/config-<release>`).
    kconfig: ?[]const u8 = null,
    /// The value of `LINUX_KERNEL_VERSION`; `null` is the running kernel's.
    kernel_version: ?u32 = null,
    /// Look for a kfunc or ksym the vmlinux BTF lacks in the loaded kernel
    /// modules' BTF (needs privilege: `BPF_BTF_GET_NEXT_ID`).
    search_modules: bool = true,
    /// Where `pinning = LIBBPF_PIN_BY_NAME` maps live: `<pin_root>/<map name>`.
    /// The directory must exist on a bpffs.
    pin_root: []const u8 = "/sys/fs/bpf",
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

    // The kernel's BTF, read at most once: CO-RE and struct_ops both need it.
    var kernel_owned: ?Btf = null;
    defer if (kernel_owned) |*o| o.deinit();

    // ── CO-RE, before anything is created: a relocation failure should not
    // leave maps behind. ──
    if (opts.core) {
        var have_relos = false;
        for (obj.programs) |p| {
            if (p.core_relos.len != 0) have_relos = true;
        }
        if (have_relos) {
            if (obj.btf) |*local| {
                const target = try kernelBtf(obj, opts, &kernel_owned);
                for (obj.programs) |*p| {
                    _ = try applyCoreRelos(p, local, target);
                }
            }
        }
    }

    // ── struct_ops: plan each map against the kernel's types, and tell the
    // programs which member they implement (before they are loaded). ──
    for (obj.maps) |*m| {
        if (m.origin != .struct_ops) continue;
        const local = &(obj.btf orelse return error.StructOpsTypeNotFound);
        const target = try kernelBtf(obj, opts, &kernel_owned);
        const plan = try planStructOps(obj.arena.allocator(), local, m.btf_value_type_id, target);
        m.struct_ops_plan = plan;
        for (plan.members) |mem| {
            if (!mem.is_func) continue;
            for (m.struct_ops_progs) |sp| {
                if (sp.member_off != mem.local_off) continue;
                const p = &obj.programs[sp.program];
                p.attach_btf_id = plan.kern_type_id;
                p.expected_attach_type = @fromBackingInt(mem.kern_index);
            }
        }
    }

    // ── externs: fill the `.kconfig` map, resolve kernel variables / kfuncs ──
    if (obj.externs.len != 0) try prepareExterns(obj, opts, &kernel_owned);

    // ── maps ──
    for (obj.maps) |*m| {
        if (m.origin == .struct_ops) {
            m.fd = try createStructOpsMap(m);
            continue;
        }
        if (m.pinning > 1) return error.PinningUnsupported;
        if (m.max_entries == 0 and needsEntries(m.map_type)) return error.ZeroMaxEntries;
        const pin: ?[]const u8 = if (m.pin_path.len != 0)
            m.pin_path
        else if (m.pinning == 1 and m.origin != .internal)
            obj.arena.allocator().print("{s}/{s}", .{ opts.pin_root, m.name }) catch return error.OutOfMemory
        else
            null;
        if (pin) |path| {
            if (bpfsys.objGet(path, 0)) |fd| {
                errdefer _ = linux.close(fd);
                try checkPinnedMap(m, fd);
                m.fd = fd;
                m.reused = true;
                continue;
            } else |e| switch (e) {
                error.NotFound => {},
                error.PermissionDenied => return error.PermissionDenied,
                error.PathTooLong, error.InvalidArgument => return error.InvalidArgument,
                else => return error.PinFailed,
            }
        }
        if (m.origin == .internal and opts.mmap_data) {
            if (createMap(m, 0, BPF_F_MMAPABLE)) |fd| {
                m.fd = fd;
                m.mmapable = true;
            } else |e| {
                if (e != error.InvalidArgument) return e;
                m.fd = try createMap(m, 0, 0);
            }
        } else m.fd = try createMapWithInner(m);
        if (pin) |path| bpfsys.objPin(m.fd, path) catch return error.PinFailed;
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
        // `extern` VARs/FUNCs and the `.kconfig`/`.ksyms` DATASECs are the
        // loader's business; the kernel's BTF verifier refuses them.
        const neutral = btfsanitize.neutralizeExterns(obj.gpa, obj.btf_bytes.?) catch return error.BtfLoadFailed;
        defer if (neutral) |n| obj.gpa.free(n);
        const blob = neutral orelse obj.btf_bytes.?;
        obj.btf_fd = btf_mod.loadIntoKernel(blob, null) catch |e| switch (e) {
            error.PermissionDenied => return error.PermissionDenied,
            error.InvalidBtf => if (opts.sanitize_btf) try loadSanitizedBtf(obj, blob) else return error.BtfLoadFailed,
            else => return error.BtfLoadFailed,
        };
    }

    // ── programs ──
    const license = opts.license orelse obj.license;
    for (obj.programs) |*p| {
        // A struct_ops program no map uses has no attach target: not loaded
        // (libbpf skips it as well).
        if (p.prog_type == .struct_ops and p.attach_btf_id == 0) continue;
        try relocateProgram(p, obj.maps);
        try patchExterns(p, obj.externs);
        p.fd = try loadOneProgram(obj, p, license, opts);
    }
    try fillInitSlots(obj);
    try buildStructOpsValues(obj);
}

/// A map found at its pin must be the map this object declares; the check is
/// libbpf's (`map_info` against the definition): type, key and value size,
/// `max_entries` and flags. A mismatch closes nothing here: the caller owns
/// the fd and drops it.
fn checkPinnedMap(m: *const MapSpec, fd: linux.fd_t) LoadError!void {
    var info: bpfsys.MapInfo = std.mem.zeroes(bpfsys.MapInfo);
    bpfsys.objInfo(fd, std.mem.asBytes(&info)) catch |e| return switch (e) {
        error.PermissionDenied => error.PermissionDenied,
        else => error.PinFailed,
    };
    if (!pinnedMapMatches(m, info)) return error.PinnedMapMismatch;
}

/// Pure half of `checkPinnedMap`. A `numa_node` / kernel-added flag bit does
/// not make a map different; the creation flags that change what the map
/// *is* do.
pub fn pinnedMapMatches(m: *const MapSpec, info: bpfsys.MapInfo) bool {
    const keep: u32 = ~@as(u32, 1 << 2); // BPF_F_NUMA_NODE says where, not what
    return info.type == @backingInt(m.map_type) and
        info.key_size == m.key_size and
        info.value_size == m.value_size and
        info.max_entries == m.max_entries and
        (info.map_flags & keep) == (m.map_flags & keep);
}

/// The kernel refused the BTF as written: ask it which kinds it knows, rewrite
/// the rest into ones it does (`btfsanitize.sanitize`) and load that.
fn loadSanitizedBtf(obj: *Object, blob: []const u8) LoadError!linux.fd_t {
    const feats = btfsanitize.probeFeatures() catch |e| return switch (e) {
        error.PermissionDenied => error.PermissionDenied,
        else => error.BtfLoadFailed,
    };
    const rewritten = (btfsanitize.sanitize(obj.gpa, blob, feats) catch return error.BtfLoadFailed) orelse
        return error.BtfLoadFailed; // nothing the kernel lacks: it refused for another reason
    defer obj.gpa.free(rewritten);
    const fd = btf_mod.loadIntoKernel(rewritten, null) catch |e| return switch (e) {
        error.PermissionDenied => error.PermissionDenied,
        else => error.BtfLoadFailed,
    };
    obj.btf_sanitized = true;
    obj.btf_func_info = feats.func;
    return fd;
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

/// Give every `extern` a value or a kernel id before anything is loaded.
fn prepareExterns(obj: *Object, opts: LoadOptions, kernel_owned: *?Btf) LoadError!void {
    // `__kconfig`: the configuration is only read when a CONFIG_ option is asked for
    var needs_cfg = false;
    var has_ksym = false;
    for (obj.externs) |e| {
        if (e.kind == .kconfig and !std.mem.eql(u8, e.name, "LINUX_KERNEL_VERSION")) needs_cfg = true;
        if (e.kind != .kconfig) has_ksym = true;
    }
    var cfg: ?kconfig_mod.Config = null;
    defer if (cfg) |*c| c.deinit();
    if (needs_cfg) {
        cfg = if (opts.kconfig) |text|
            kconfig_mod.parse(obj.gpa, text) catch return error.ExternTypeMismatch
        else
            kconfig_mod.readKernelConfig(obj.gpa) catch null;
    }
    try fillKconfig(obj, if (cfg) |*c| c else null, opts.kernel_version orelse kconfig_mod.runningKernelVersion());
    if (has_ksym) {
        const kernel = try kernelBtf(obj, opts, kernel_owned);
        try resolveKernelExterns(obj, kernel, opts);
    }
}

/// Write each `__kconfig` extern's value into the `.kconfig` map's seed.
/// `LINUX_KERNEL_VERSION` comes from `version`, everything else from `cfg`; an
/// option absent from `cfg` (`# CONFIG_X is not set` is absent) is 0 for a
/// `__weak` extern and `error.ExternNotFound` otherwise.
pub fn fillKconfig(obj: *Object, cfg: ?*const kconfig_mod.Config, version: ?u32) LoadError!void {
    const mi = findMapIdx(obj, ".kconfig") orelse return;
    const b = &(obj.btf orelse return);
    // the seed is memory this object allocated for itself (`collectExterns`)
    const data: []u8 = @constCast(obj.maps[mi].initial_data);
    for (obj.externs) |e| {
        if (e.kind != .kconfig) continue;
        const out = data[e.value_off..][0..e.size];
        const value: kconfig_mod.Value = if (std.mem.eql(u8, e.name, "LINUX_KERNEL_VERSION")) blk: {
            const v = version orelse {
                if (e.weak) continue;
                return error.ExternNotFound;
            };
            break :blk .{ .int = .{ .negative = false, .magnitude = v } };
        } else blk: {
            const c = cfg orelse {
                if (e.weak) continue;
                return error.ExternNotFound;
            };
            break :blk c.get(e.name) orelse {
                if (e.weak) continue;
                return error.ExternNotFound;
            };
        };
        kconfig_mod.fill(b, e.type_id, value, out) catch return error.ExternTypeMismatch;
    }
}

/// Resolve every `__ksym` extern against the kernel's BTF (variables and
/// functions by name and kind, checked for type compatibility), a typeless
/// one against `/proc/kallsyms`, and, for what vmlinux lacks, the loaded
/// modules' BTF. An absent `__weak` extern stays unresolved (it reads 0).
pub fn resolveKernelExterns(obj: *Object, kernel: *const Btf, opts: LoadOptions) LoadError!void {
    const local = &(obj.btf orelse return);
    var mods: ?ModuleBtfs = null;
    defer if (mods) |*m| m.deinit(obj);
    var kallsyms: ?[]u8 = null;
    defer if (kallsyms) |k| obj.gpa.free(k);

    for (obj.externs) |*e| {
        switch (e.kind) {
            .kconfig => continue,
            .ksym_var => if (e.typeless) {
                if (kallsyms == null) kallsyms = elfsym.readFileStreaming(obj.gpa, "/proc/kallsyms", 64 << 20) catch null;
                const addr = if (kallsyms) |k| kconfig_mod.kallsymsAddress(k, e.name) else null;
                if (addr) |ad| {
                    e.addr = ad;
                    e.resolved = true;
                } else if (!e.weak) return error.ExternNotFound;
                continue;
            },
            .ksym_func => {},
        }
        const want: btf_mod.Kind = if (e.kind == .ksym_var) .@"var" else .func;
        var found: ?struct { btf: *const Btf, id: u32, fd_index: u16 } = null;
        if (kernel.findByNameKind(e.name, want)) |id| found = .{ .btf = kernel, .id = id, .fd_index = 0 };
        if (found == null and opts.search_modules) {
            if (mods == null) mods = ModuleBtfs.load(obj, kernel);
            if (mods) |*m| {
                if (m.find(e.name, want)) |f| found = .{ .btf = f.btf, .id = f.id, .fd_index = f.fd_index };
            }
        }
        const f = found orelse {
            if (e.weak) continue;
            return error.ExternNotFound;
        };
        // the declared type must be compatible with the kernel's
        const kt = f.btf.byId(f.id) catch return error.ExternTypeMismatch;
        const kernel_type = kt.refType() orelse return error.ExternTypeMismatch;
        const compat = btfext.typesAreCompat(local, e.type_id, f.btf, kernel_type) catch return error.ExternTypeMismatch;
        if (!compat) return error.ExternTypeMismatch;
        e.kernel_btf_id = f.id;
        e.fd_index = f.fd_index;
        e.resolved = true;
    }
    if (mods) |*m| try m.commit(obj);
}

/// The loaded kernel modules' BTF, read lazily for a kfunc / ksym that
/// vmlinux does not have. Each module's fd is what a program's `fd_array`
/// carries; `commit` moves the ones that were used into the `Object`.
const ModuleBtfs = struct {
    const Entry = struct { fd: linux.fd_t, btf: Btf, used: bool = false };
    entries: std.ArrayList(Entry) = .empty,

    fn load(obj: *Object, base: *const Btf) ?ModuleBtfs {
        var self: ModuleBtfs = .{};
        var id: u32 = 0;
        while (bpfsys.btfNextId(id) catch return null) |next| {
            id = next;
            const fd = bpfsys.btfFdById(next) catch continue;
            var name_buf: [64]u8 = undefined;
            const info = bpfsys.btfNameInfo(fd, &name_buf) catch {
                _ = linux.close(fd);
                continue;
            };
            if (!info.kernel_btf or std.mem.eql(u8, info.name, "vmlinux")) {
                _ = linux.close(fd);
                continue;
            }
            const blob = bpfsys.btfBlob(obj.gpa, fd) catch {
                _ = linux.close(fd);
                continue;
            };
            const parsed = btf_mod.parse(obj.gpa, blob, .{ .base = base, .own_bytes = true }) catch {
                obj.gpa.free(blob);
                _ = linux.close(fd);
                continue;
            };
            self.entries.append(obj.gpa, .{ .fd = fd, .btf = parsed }) catch {
                var p = parsed;
                p.deinit();
                _ = linux.close(fd);
                continue;
            };
        }
        return self;
    }

    const Found = struct { btf: *const Btf, id: u32, fd_index: u16 };

    fn find(self: *ModuleBtfs, name: []const u8, kind: btf_mod.Kind) ?Found {
        for (self.entries.items, 0..) |*e, i| {
            // a split BTF's own types only: vmlinux's were searched already
            var k: u32 = 0;
            while (k < e.btf.typeCount()) : (k += 1) {
                const id = e.btf.start_id + k;
                const t = e.btf.byId(id) catch continue;
                if (t.kind != kind) continue;
                const n = e.btf.str(t.name_off) orelse continue;
                if (!std.mem.eql(u8, n, name)) continue;
                e.used = true;
                return .{ .btf = &e.btf, .id = id, .fd_index = @intCast(i + 1) };
            }
        }
        return null;
    }

    /// Keep the fds the externs refer to (as `fd_array[index]`); close the rest.
    fn commit(self: *ModuleBtfs, obj: *Object) LoadError!void {
        const a = obj.arena.allocator();
        const arr = a.alloc(i32, self.entries.items.len + 1) catch return error.OutOfMemory;
        @memset(arr, 0);
        var used_any = false;
        var kept: std.ArrayList(linux.fd_t) = .empty;
        for (self.entries.items, 0..) |*e, i| {
            if (e.used) {
                arr[i + 1] = e.fd;
                kept.append(a, e.fd) catch return error.OutOfMemory;
                e.fd = -1;
                used_any = true;
            }
        }
        if (used_any) {
            obj.fd_array = arr;
            obj.module_btf_fds = kept.toOwnedSlice(a) catch return error.OutOfMemory;
        }
    }

    fn deinit(self: *ModuleBtfs, obj: *Object) void {
        for (self.entries.items) |*e| {
            if (e.fd >= 0) _ = linux.close(e.fd);
            e.btf.deinit();
        }
        self.entries.deinit(obj.gpa);
    }
};

/// Patch a program's extern references with what `load` resolved: a kfunc call
/// becomes `BPF_PSEUDO_KFUNC_CALL` (`imm` the BTF id, `off` the module's
/// `fd_array` index), a typed ksym load `BPF_PSEUDO_BTF_ID`, a typeless one a
/// plain 64-bit address, and anything unresolved (a `__weak` the kernel lacks)
/// a 0 / a poisoned call the verifier reports only if it is reachable.
pub fn patchExterns(prog: *ProgramSpec, externs: []const Extern) RelocateError!void {
    for (prog.extern_refs) |r| {
        if (r.insn_idx >= prog.insns.len or r.extern_idx >= externs.len) return error.RelocationOutOfRange;
        const ext = externs[r.extern_idx];
        const insn = &prog.insns[r.insn_idx];
        if (r.call) {
            if (insn.code != CALL_CODE) return error.NotAnImmediateLoad;
            if (ext.resolved) {
                insn.src = BPF_PSEUDO_KFUNC_CALL;
                insn.imm = @intCast(ext.kernel_btf_id);
                insn.off = @intCast(ext.fd_index);
            } else {
                // a helper-style call (src 0) to an id no helper has: the
                // compiler marked the call `BPF_PSEUDO_CALL`, which the verifier
                // would resolve as a sub-program call even in dead code
                insn.src = 0;
                insn.imm = poison_call_kfunc_base +% @as(i32, @intCast(@min(r.extern_idx, 1 << 20)));
            }
            continue;
        }
        if (insn.code != LD_IMM64_CODE) return error.NotAnImmediateLoad;
        if (r.insn_idx + 1 >= prog.insns.len) return error.RelocationOutOfRange;
        if (ext.resolved and !ext.typeless) {
            insn.src = BPF_PSEUDO_BTF_ID;
            insn.imm = @intCast(ext.kernel_btf_id);
            prog.insns[r.insn_idx + 1].imm = @intCast(ext.fd_index);
        } else {
            // a plain 64-bit constant: whatever pseudo marker the compiler left
            // on the load must go, or the kernel would read the immediate as a
            // map fd / BTF id
            const addr: u64 = if (ext.resolved) ext.addr else 0;
            insn.src = 0;
            insn.imm = @bitCast(@as(u32, @truncate(addr)));
            prog.insns[r.insn_idx + 1].imm = @bitCast(@as(u32, @truncate(addr >> 32)));
        }
    }
}

/// The kernel's BTF for CO-RE and struct_ops: the caller's `target_btf`, or
/// `/sys/kernel/btf/vmlinux`, read once into `owned`.
fn kernelBtf(obj: *Object, opts: LoadOptions, owned: *?Btf) LoadError!*const Btf {
    if (opts.target_btf) |t| return t;
    if (owned.* == null) owned.* = btf_mod.loadKernel(obj.gpa) catch return error.KernelBtfUnavailable;
    return &owned.*.?;
}

/// `BPF_MAP_TYPE_STRUCT_OPS`: sized by the kernel's `bpf_struct_ops_<name>`,
/// typed by `btf_vmlinux_value_type_id`. The BTF key/value type ids must stay
/// zero (the kernel refuses both at once).
fn createStructOpsMap(m: *const MapSpec) LoadError!linux.fd_t {
    const plan = m.struct_ops_plan orelse return error.StructOpsTypeNotFound;
    var attr: BPF.MapCreateAttr = std.mem.zeroes(BPF.MapCreateAttr);
    attr.map_type = @backingInt(BPF.MapType.struct_ops);
    attr.key_size = 4;
    attr.value_size = plan.value_size;
    attr.max_entries = 1;
    attr.map_flags = if (m.struct_ops_link) BPF_F_LINK else 0;
    attr.btf_vmlinux_value_type_id = plan.value_type_id;
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

/// With every program loaded, build each struct_ops map's kernel-layout value
/// (the program fds go in as the function pointers).
fn buildStructOpsValues(obj: *Object) LoadError!void {
    const a = obj.arena.allocator();
    var fds: std.ArrayList(linux.fd_t) = .empty;
    defer fds.deinit(obj.gpa);
    for (obj.maps) |*m| {
        if (m.origin != .struct_ops) continue;
        if (fds.items.len == 0) {
            for (obj.programs) |p| fds.append(obj.gpa, p.fd) catch return error.OutOfMemory;
        }
        m.struct_ops_value = try buildStructOpsValue(a, m.struct_ops_plan.?, m.initial_data, m.struct_ops_progs, fds.items);
    }
}

/// Create `m`, first creating its inner-map template when it is a
/// map-in-map: the kernel fixes the inner type, sizes and flags from the fd
/// handed in `inner_map_fd`, and the template is not needed afterwards.
fn createMapWithInner(m: *const MapSpec) LoadError!linux.fd_t {
    const outer = switch (m.map_type) {
        .array_of_maps, .hash_of_maps => true,
        else => false,
    };
    if (!outer) return createMap(m, 0, 0);
    const inner = m.inner orelse return error.InvalidArgument;
    if (inner.max_entries == 0 and needsEntries(inner.map_type)) return error.ZeroMaxEntries;
    const tmpl = try createMap(inner, 0, 0);
    defer _ = linux.close(tmpl);
    return createMap(m, tmpl, 0);
}

/// Fill the pre-initialized slots of every map-in-map and `PROG_ARRAY`
/// (`BPF_MAP_UPDATE_ELEM`, key = the slot index, value = the target's fd).
/// Runs after every map exists and every program is loaded.
fn fillInitSlots(obj: *Object) LoadError!void {
    for (obj.maps) |*m| {
        if (m.reused or m.init_slots.len == 0) continue;
        for (m.init_slots) |sl| {
            const target_fd: linux.fd_t = switch (sl.target) {
                .map => |k| obj.maps[k].fd,
                .program => |k| obj.programs[k].fd,
            };
            if (target_fd < 0) return error.MapNotCreated;
            var key: [4]u8 = undefined;
            std.mem.writeInt(u32, &key, sl.index, builtin.cpu.arch.endian());
            var val: [4]u8 = undefined;
            std.mem.writeInt(u32, &val, @intCast(target_fd), builtin.cpu.arch.endian());
            BPF.map_update_elem(m.fd, &key, &val, 0) catch return error.MapUpdateFailed;
        }
    }
}

fn createMap(m: *const MapSpec, inner_fd: linux.fd_t, extra_flags: u32) LoadError!linux.fd_t {
    var attr: BPF.MapCreateAttr = std.mem.zeroes(BPF.MapCreateAttr);
    attr.map_type = @backingInt(m.map_type);
    attr.key_size = m.key_size;
    attr.value_size = m.value_size;
    attr.max_entries = m.max_entries;
    attr.map_flags = m.map_flags | extra_flags;
    attr.inner_map_fd = inner_fd;
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
            .attach_btf_id = p.attach_btf_id,
            .prog_flags = if (p.sleepable) BPF_F_SLEEPABLE else 0,
            .kern_version = obj.kern_version,
            .fd_array = obj.fd_array,
        };
        if (obj.btf_fd >= 0) {
            lo.prog_btf_fd = obj.btf_fd;
            if (obj.btf_func_info) lo.func_info = p.func_info;
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
const fx_mapinmap = @embedFile("testdata/mapinmap.bpf.o");

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
        o.maps[0].pinning = 2; // neither none nor by-name
        try testing.expectError(error.PinningUnsupported, load(&o, .{ .load_btf = false }));
        // by-name pinning reaches bpffs: no permission, or no such directory to pin into
        o.maps[0].pinning = 1;
        if (load(&o, .{ .load_btf = false, .pin_root = "/nonexistent-bpffs-root" })) |_| {
            return error.TestUnexpectedResult;
        } else |e| try testing.expect(e == error.PermissionDenied or e == error.PinFailed);
        o.close();
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
    var mods = [_]linux.fd_t{ devnull.open(), devnull.open() };
    var arr = [_]i32{ 0, mods[0], mods[1] };
    o.module_btf_fds = &mods;
    o.fd_array = &arr;
    o.close();
    try testing.expect(!devnull.isOpen(f1) and !devnull.isOpen(f2) and !devnull.isOpen(f3));
    // the kernel modules' BTF fds `load` kept for kfuncs/ksyms (they leaked before 2026-11-27)
    try testing.expect(!devnull.isOpen(mods[0]) and !devnull.isOpen(mods[1]));
    try testing.expectEqual(@as(usize, 0), o.module_btf_fds.len);
    try testing.expectEqual(@as(usize, 0), o.fd_array.len);
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
        .{ .mem = &.{.{ .name = "values", .kind = .ptr_int }}, .want = error.MalformedMapDefinition }, // not an array of pointers
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

test "pinnedMapMatches: type, sizes and flags decide, the NUMA bit does not" {
    var m: MapSpec = .{ .name = "m", .map_type = .hash, .key_size = 4, .value_size = 8, .max_entries = 16, .map_flags = 1, .origin = .legacy, .sec_idx = 0 };
    var info: bpfsys.MapInfo = std.mem.zeroes(bpfsys.MapInfo);
    info.type = @backingInt(BPF.MapType.hash);
    info.key_size = 4;
    info.value_size = 8;
    info.max_entries = 16;
    info.map_flags = 1;
    try testing.expect(pinnedMapMatches(&m, info));
    info.map_flags = 1 | (1 << 2); // the kernel reports BPF_F_NUMA_NODE: same map
    try testing.expect(pinnedMapMatches(&m, info));
    info.map_flags = 0;
    try testing.expect(!pinnedMapMatches(&m, info));
    info.map_flags = 1;
    for ([_]u2{ 0, 1, 2, 3 }) |which| {
        var bad = info;
        switch (which) {
            0 => bad.type = @backingInt(BPF.MapType.array),
            1 => bad.key_size = 8,
            2 => bad.value_size = 4,
            3 => bad.max_entries = 17,
        }
        try testing.expect(!pinnedMapMatches(&m, bad));
    }
    m.pin_path = "/x"; // a pin path does not take part in the comparison
    try testing.expect(pinnedMapMatches(&m, info));
}

test "pin paths: an unreachable pin is a typed error and pins nothing" {
    const gpa = testing.allocator;
    var o = try open(gpa, fx_ringbuf_map, .{});
    defer o.deinit();
    // programs/maps that were never loaded have nothing to pin; unpin of absent pins is not an error
    try o.pinMaps("/nonexistent-bpffs-root");
    try o.pinPrograms("/nonexistent-bpffs-root");
    try o.unpinMaps("/nonexistent-bpffs-root");
    try o.unpinPrograms("/nonexistent-bpffs-root");
}

test "map-in-map and prog_array: inner definitions and initial slots come out of a clang object" {
    const gpa = testing.allocator;
    var o = try open(gpa, fx_mapinmap, .{});
    defer o.deinit();

    const outer = o.findMap("outer").?;
    try testing.expectEqual(BPF.MapType.array_of_maps, outer.map_type);
    try testing.expectEqual(@as(u32, 4), outer.max_entries);
    try testing.expectEqual(@as(u32, 4), outer.key_size);
    try testing.expect(outer.has_values);
    const inner = outer.inner.?;
    try testing.expectEqual(BPF.MapType.array, inner.map_type);
    try testing.expectEqual(@as(u32, 8), inner.max_entries);
    try testing.expectEqual(@as(u32, 4), inner.key_size);
    try testing.expectEqual(@as(u32, 8), inner.value_size);

    // `.values = { &inner_a, &inner_b }`: slots 0 and 1, pointing at the maps by index
    try testing.expectEqual(@as(usize, 2), outer.init_slots.len);
    for (outer.init_slots, 0..) |sl, k| {
        try testing.expectEqual(@as(u32, @intCast(k)), sl.index);
        try testing.expectEqualStrings(if (k == 0) "inner_a" else "inner_b", o.maps[sl.target.map].name);
    }
    try testing.expect(o.findMap("inner_a").?.inner == null);

    // a hash-of-maps with a definition and no initializer
    const hmap = o.findMap("hmap").?;
    try testing.expectEqual(BPF.MapType.hash_of_maps, hmap.map_type);
    try testing.expect(hmap.inner != null);
    try testing.expectEqual(@as(usize, 0), hmap.init_slots.len);

    // `.values = { [1] = &target }` of a prog_array names a program, not a map
    const jumps = o.findMap("jumps").?;
    try testing.expectEqual(BPF.MapType.prog_array, jumps.map_type);
    try testing.expect(jumps.inner == null);
    try testing.expectEqual(@as(usize, 1), jumps.init_slots.len);
    try testing.expectEqual(@as(u32, 1), jumps.init_slots[0].index);
    try testing.expectEqualStrings("target", o.programs[jumps.init_slots[0].target.program].name);
}

test "dataVariables: the DATASEC's variables, with the ELF's offsets, and a writable seed" {
    const gpa = testing.allocator;
    var obj = try open(gpa, fx_rodata_const, .{});
    defer obj.deinit();
    const vars = try obj.dataVariables(".rodata");
    try testing.expectEqual(@as(usize, 2), vars.len);
    try testing.expectEqualStrings("threshold", vars[0].name);
    try testing.expectEqual(@as(u32, 0), vars[0].offset);
    try testing.expectEqual(@as(u32, 4), vars[0].size);
    try testing.expectEqualStrings("tag", vars[1].name);
    try testing.expectEqual(@as(u32, 8), vars[1].offset);
    try testing.expectEqual(@as(u32, 8), vars[1].size);
    // the type id is the variable's type (a volatile-qualified int), resolvable
    try testing.expectEqual(@as(u64, 4), try obj.btf.?.sizeOf(vars[0].type_id));
    try testing.expectEqual(@as(usize, 0), (try obj.dataVariables(".data")).len);

    // editing the seed is how a `const volatile` is configured before load
    const seed = obj.initialData(".rodata").?;
    std.mem.writeInt(u32, seed[vars[0].offset..][0..4], 99, .little);
    try testing.expectEqual(@as(u32, 99), std.mem.readInt(u32, obj.findMap(".rodata").?.initial_data[0..4], .little));
    try testing.expectEqual(@as(?[]u8, null), obj.initialData("nope"));
    // a map that is not an internal data map has no seed
    var o2 = try open(gpa, fx_ringbuf_map, .{});
    defer o2.deinit();
    try testing.expectEqual(@as(?[]u8, null), o2.initialData(o2.maps[0].name));
}

test "mapData: refuses before load and on a map not created mmapable; the view helpers" {
    const gpa = testing.allocator;
    var obj = try open(gpa, fx_rodata_const, .{});
    defer obj.deinit();
    try testing.expectError(error.NoSuchMap, obj.mapData("nope"));
    try testing.expectError(error.NotLoaded, obj.mapData(".rodata"));
    obj.maps[0].fd = 5;
    try testing.expectError(error.NotMmapable, obj.mapData(".rodata"));
    obj.maps[0].fd = -1;

    // the MappedData helpers over an anonymous mapping (no BPF needed)
    const page = std.heap.pageSize();
    const rc = linux.mmap(null, page, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    const ptr: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(rc);
    var md: MappedData = .{ .mapping = ptr[0..page], .len = 16, .writable = true };
    defer md.deinit();
    const Cfg = extern struct { threshold: u32, _pad: u32, tag: u64 };
    const c = try md.view(Cfg);
    c.threshold = 7;
    c.tag = 0x1122;
    try testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, md.bytes()[0..4], .little));
    const v = try md.variable(.{ .name = "tag", .offset = 8, .size = 8, .type_id = 1 });
    try testing.expectEqual(@as(u64, 0x1122), std.mem.readInt(u64, v[0..8], .little));
    try testing.expectError(error.SizeMismatch, md.variable(.{ .name = "x", .offset = 12, .size = 8, .type_id = 1 }));
    try testing.expectError(error.SizeMismatch, md.variable(.{ .name = "x", .offset = 17, .size = 0, .type_id = 1 }));
    const Big = extern struct { a: [3]u64 };
    try testing.expectError(error.SizeMismatch, md.view(Big));
}

const fx_struct_ops = @embedFile("testdata/struct_ops.bpf.o");

/// A kernel BTF with `tcp_congestion_ops { cong_avoid; ssthresh; undo_cwnd; name[N] }`
/// and its `bpf_struct_ops_` wrapper (`common` 8 bytes, then `data`).
fn structOpsKernelBlob(gpa: std.mem.Allocator, with_undo: bool, name_len: u32, name_is_func: bool) ![]u8 {
    var r = try RawB.init(gpa);
    defer r.deinit(gpa);
    const n_ops = try r.str(gpa, "tcp_congestion_ops");
    const n_vt = try r.str(gpa, "bpf_struct_ops_tcp_congestion_ops");
    const n_ca = try r.str(gpa, "cong_avoid");
    const n_ss = try r.str(gpa, "ssthresh");
    const n_un = try r.str(gpa, "undo_cwnd");
    const n_nm = try r.str(gpa, "name");
    const n_common = try r.str(gpa, "common");
    const n_data = try r.str(gpa, "data");
    const u32_t = try r.rec(gpa, 0, btf_mod.K_INT, 0, false, 4, &.{32}); // 1
    const chr = try r.rec(gpa, 0, btf_mod.K_INT, 0, false, 1, &.{8}); // 2
    const arr = try r.rec(gpa, 0, btf_mod.K_ARRAY, 0, false, 0, &.{ chr, u32_t, name_len }); // 3
    const proto = try r.rec(gpa, 0, btf_mod.K_FUNC_PROTO, 0, false, 0, &.{}); // 4
    const fptr = try r.rec(gpa, 0, btf_mod.K_PTR, 0, false, proto, &.{}); // 5
    const name_ty: u32 = if (name_is_func) fptr else arr;
    const ops = if (with_undo)
        try r.rec(gpa, n_ops, btf_mod.K_STRUCT, 4, false, 24 + name_len, &.{ n_ca, fptr, 0, n_ss, fptr, 64, n_un, fptr, 128, n_nm, name_ty, 192 })
    else
        try r.rec(gpa, n_ops, btf_mod.K_STRUCT, 3, false, 16 + name_len, &.{ n_ca, fptr, 0, n_ss, fptr, 64, n_nm, name_ty, 128 });
    const common = try r.rec(gpa, 0, btf_mod.K_STRUCT, 0, false, 8, &.{});
    _ = try r.rec(gpa, n_vt, btf_mod.K_STRUCT, 2, false, 8 + 24 + name_len, &.{ n_common, common, 0, n_data, ops, 64 });
    return r.finish(gpa);
}

test "struct_ops: a clang object's .struct_ops and .struct_ops.link variables become maps with their programs" {
    const gpa = testing.allocator;
    var o = try open(gpa, fx_struct_ops, .{});
    defer o.deinit();
    try testing.expectEqual(@as(usize, 2), o.maps.len);
    const cc = o.findMap("zl_cc").?;
    try testing.expectEqual(MapOrigin.struct_ops, cc.origin);
    try testing.expectEqual(BPF.MapType.struct_ops, cc.map_type);
    try testing.expectEqual(@as(u32, 4), cc.key_size);
    try testing.expectEqual(@as(u32, 1), cc.max_entries);
    try testing.expectEqual(@as(u32, 40), cc.value_size); // the object's own struct size
    try testing.expect(!cc.struct_ops_link);
    try testing.expectEqualStrings("zl_test", std.mem.sliceTo(cc.initial_data[0..16], 0));
    try testing.expectEqual(@as(usize, 3), cc.struct_ops_progs.len);
    // each function-pointer slot names its program
    for (cc.struct_ops_progs) |sp| {
        const want: []const u8 = switch (sp.member_off) {
            16 => "zl_ssthresh",
            24 => "zl_undo_cwnd",
            32 => "zl_cong_avoid",
            else => unreachable,
        };
        try testing.expectEqualStrings(want, o.programs[sp.program].name);
        try testing.expectEqual(BPF.ProgType.struct_ops, o.programs[sp.program].prog_type);
    }
    const lk = o.findMap("zl_cc_link").?;
    try testing.expect(lk.struct_ops_link);
    try testing.expectEqual(@as(usize, 1), lk.struct_ops_progs.len);
    try testing.expectEqual(@as(u32, 16), lk.struct_ops_progs[0].member_off);
}

test "struct_ops: members are matched by name and size against the kernel's, and the value is laid out in its wrapper" {
    const gpa = testing.allocator;
    var o = try open(gpa, fx_struct_ops, .{});
    defer o.deinit();
    const cc = o.findMap("zl_cc").?;
    const blob = try structOpsKernelBlob(gpa, true, 16, false);
    defer gpa.free(blob);
    var kern = try btf_mod.parse(gpa, blob, .{});
    defer kern.deinit();

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const plan = try planStructOps(a, &o.btf.?, cc.btf_value_type_id, &kern);
    try testing.expectEqual(@as(u32, 8), plan.value_type_id); // bpf_struct_ops_tcp_congestion_ops
    try testing.expectEqual(@as(u32, 6), plan.kern_type_id); // tcp_congestion_ops
    try testing.expectEqual(@as(u32, 48), plan.value_size);
    try testing.expectEqual(@as(usize, 4), plan.members.len);
    for (plan.members) |m| {
        const want: struct { kern_off: u32, idx: u16, func: bool } = switch (m.local_off) {
            0 => .{ .kern_off = 32, .idx = 3, .func = false }, // name[16]: after common (8) + 3 pointers
            16 => .{ .kern_off = 16, .idx = 1, .func = true }, // ssthresh
            24 => .{ .kern_off = 24, .idx = 2, .func = true }, // undo_cwnd
            32 => .{ .kern_off = 8, .idx = 0, .func = true }, // cong_avoid
            else => unreachable,
        };
        try testing.expectEqual(want.kern_off, m.kern_off);
        try testing.expectEqual(want.idx, m.kern_index);
        try testing.expectEqual(want.func, m.is_func);
    }

    // program fds go in at the function-pointer members, the name is copied
    var fds: [3]linux.fd_t = undefined;
    for (o.programs, 0..) |p, k| fds[k] = if (std.mem.eql(u8, p.name, "zl_ssthresh")) 31 else if (std.mem.eql(u8, p.name, "zl_undo_cwnd")) 32 else 33;
    const v = try buildStructOpsValue(a, plan, cc.initial_data, cc.struct_ops_progs, &fds);
    try testing.expectEqual(@as(usize, 48), v.len);
    try testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, v[0..8], .little)); // `common`: the kernel's
    try testing.expectEqual(@as(u64, 33), std.mem.readInt(u64, v[8..16], .little)); // cong_avoid
    try testing.expectEqual(@as(u64, 31), std.mem.readInt(u64, v[16..24], .little)); // ssthresh
    try testing.expectEqual(@as(u64, 32), std.mem.readInt(u64, v[24..32], .little)); // undo_cwnd
    try testing.expectEqualStrings("zl_test", std.mem.sliceTo(v[32..48], 0));
    // a program that was not loaded cannot be a function pointer
    fds[0] = -1;
    try testing.expect(blk: {
        _ = buildStructOpsValue(a, plan, cc.initial_data, cc.struct_ops_progs, &fds) catch |e| break :blk e == error.MapNotCreated;
        break :blk false;
    });
    // the link variable implements only ssthresh: its other pointers stay NULL
    const lk = o.findMap("zl_cc_link").?;
    const lv = try buildStructOpsValue(a, plan, lk.initial_data, lk.struct_ops_progs, &[_]linux.fd_t{ 31, 32, 33 });
    try testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, lv[8..16], .little));
    try testing.expectEqual(@as(u64, 31), std.mem.readInt(u64, lv[16..24], .little));
}

test "struct_ops: every way the object and the kernel can disagree is typed" {
    const gpa = testing.allocator;
    var o = try open(gpa, fx_struct_ops, .{});
    defer o.deinit();
    const cc = o.findMap("zl_cc").?;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const Case = struct { undo: bool, name_len: u32, name_func: bool, want: anyerror };
    for ([_]Case{
        .{ .undo = false, .name_len = 16, .name_func = false, .want = error.StructOpsMemberMismatch }, // no undo_cwnd in the kernel
        .{ .undo = true, .name_len = 8, .name_func = false, .want = error.StructOpsMemberMismatch }, // name[8] vs name[16]
        .{ .undo = true, .name_len = 16, .name_func = true, .want = error.StructOpsMemberMismatch }, // a pointer where the object has bytes
    }) |c| {
        const blob = try structOpsKernelBlob(gpa, c.undo, c.name_len, c.name_func);
        defer gpa.free(blob);
        var kern = try btf_mod.parse(gpa, blob, .{});
        defer kern.deinit();
        try testing.expectError(c.want, planStructOps(a, &o.btf.?, cc.btf_value_type_id, &kern));
    }
    // a kernel BTF that has neither type
    var e = try RawB.init(gpa);
    defer e.deinit(gpa);
    _ = try e.rec(gpa, 0, btf_mod.K_INT, 0, false, 4, &.{32});
    const eb = try e.finish(gpa);
    defer gpa.free(eb);
    var none = try btf_mod.parse(gpa, eb, .{});
    defer none.deinit();
    try testing.expectError(error.StructOpsTypeNotFound, planStructOps(a, &o.btf.?, cc.btf_value_type_id, &none));
    // attach before load / on a map that is not struct_ops
    try testing.expectError(error.NotLoaded, o.attachStructOps("zl_cc"));
    try testing.expectError(error.NoSuchMap, o.attachStructOps("nope"));
    var m2 = try open(gpa, fx_mapinmap, .{});
    defer m2.deinit();
    try testing.expectError(error.NotStructOps, m2.attachStructOps("outer"));
}

test "struct_ops: planning against THIS machine's vmlinux BTF (skipped where it cannot be read)" {
    const gpa = testing.allocator;
    var kern = btf_mod.loadKernel(gpa) catch return error.SkipZigTest;
    defer kern.deinit();
    if (kern.findByNameKind("tcp_congestion_ops", .@"struct") == null) return error.SkipZigTest;
    var o = try open(gpa, fx_struct_ops, .{});
    defer o.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const plan = try planStructOps(arena.allocator(), &o.btf.?, o.findMap("zl_cc").?.btf_value_type_id, &kern);
    try testing.expectEqual(@as(usize, 4), plan.members.len);
    try testing.expect(plan.value_size > 100);
    // the member indices agree with the kernel's own struct, found by name
    const kt = try kern.byId(plan.kern_type_id);
    for (plan.members) |m| {
        if (!m.is_func) continue;
        const km = try kern.member(kt, m.kern_index);
        const nm = kern.str(km.name_off).?;
        try testing.expect(std.mem.eql(u8, nm, "ssthresh") or std.mem.eql(u8, nm, "undo_cwnd") or std.mem.eql(u8, nm, "cong_avoid"));
    }
}

const fx_externs = @embedFile("testdata/externs.bpf.o");

test "externs: a clang object's kconfig, ksym and kfunc declarations and the .kconfig map layout" {
    const gpa = testing.allocator;
    var o = try open(gpa, fx_externs, .{});
    defer o.deinit();
    try testing.expectEqual(@as(usize, 10), o.externs.len);
    const find = struct {
        fn f(obj: *Object, name: []const u8) Extern {
            return obj.externs[findExternIdx(obj, name).?];
        }
    }.f;
    // `.kconfig`: declaration order, natural alignment
    const expect = [_]struct { n: []const u8, off: u32, size: u32, weak: bool }{
        .{ .n = "LINUX_KERNEL_VERSION", .off = 0, .size = 4, .weak = false },
        .{ .n = "CONFIG_HZ", .off = 4, .size = 4, .weak = false },
        .{ .n = "CONFIG_BPF", .off = 8, .size = 1, .weak = false },
        .{ .n = "CONFIG_TUN", .off = 12, .size = 4, .weak = false },
        .{ .n = "CONFIG_DEFAULT_HOSTNAME", .off = 16, .size = 16, .weak = false },
        .{ .n = "CONFIG_ZL_NOT_THERE", .off = 32, .size = 8, .weak = true },
    };
    for (expect) |e| {
        const x = find(&o, e.n);
        try testing.expectEqual(ExternKind.kconfig, x.kind);
        try testing.expectEqual(e.off, x.value_off);
        try testing.expectEqual(e.size, x.size);
        try testing.expectEqual(e.weak, x.weak);
    }
    const km = o.findMap(".kconfig").?;
    try testing.expectEqual(@as(u32, 40), km.value_size);
    try testing.expect(km.freeze);
    try testing.expectEqual(BPF_F_RDONLY_PROG, km.map_flags);
    // `.ksyms`
    try testing.expectEqual(ExternKind.ksym_var, find(&o, "bpf_prog_active").kind);
    try testing.expect(!find(&o, "bpf_prog_active").typeless);
    try testing.expect(find(&o, "bpf_untyped_sym").typeless);
    try testing.expect(find(&o, "bpf_untyped_sym").weak);
    try testing.expectEqual(ExternKind.ksym_func, find(&o, "bpf_rcu_read_lock").kind);
    try testing.expect(!find(&o, "bpf_rcu_read_lock").weak);
    try testing.expect(find(&o, "bpf_zl_missing_kfunc").weak);

    // the program: kconfig reads are map_value relocations into `.kconfig`, the rest are extern refs
    const p = o.findProgram("probe").?;
    var kcfg: usize = 0;
    for (p.relos) |r| {
        try testing.expectEqual(ReloKind.map_value, r.kind);
        try testing.expectEqualStrings(".kconfig", o.maps[r.map_idx].name);
        kcfg += 1;
    }
    try testing.expectEqual(@as(usize, 6), kcfg);
    var calls: usize = 0;
    var loads: usize = 0;
    for (p.extern_refs) |r| {
        if (r.call) calls += 1 else loads += 1;
    }
    try testing.expectEqual(@as(usize, 2), calls); // bpf_rcu_read_lock, bpf_zl_missing_kfunc
    try testing.expectEqual(@as(usize, 3), loads); // bpf_prog_active, the weak kfunc's address, bpf_untyped_sym
}

test "fillKconfig: values come from the configuration and the version, typed by the declaration" {
    const gpa = testing.allocator;
    var o = try open(gpa, fx_externs, .{});
    defer o.deinit();
    var cfg = try kconfig_mod.parse(gpa,
        \\CONFIG_HZ=250
        \\CONFIG_BPF=y
        \\CONFIG_TUN=m
        \\CONFIG_DEFAULT_HOSTNAME="zlhost"
        \\
    );
    defer cfg.deinit();
    try fillKconfig(&o, &cfg, (6 << 16) + (8 << 8) + 1);
    const d = o.findMap(".kconfig").?.initial_data;
    try testing.expectEqual(@as(u32, (6 << 16) + (8 << 8) + 1), std.mem.readInt(u32, d[0..4], .little));
    try testing.expectEqual(@as(i32, 250), std.mem.readInt(i32, d[4..8], .little));
    try testing.expectEqual(@as(u8, 1), d[8]);
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, d[12..16], .little)); // tristate m
    try testing.expectEqualStrings("zlhost", std.mem.sliceTo(d[16..32], 0));
    try testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, d[32..40], .little)); // the weak one that is absent

    // a strong option the configuration lacks
    var no_bpf = try kconfig_mod.parse(gpa, "CONFIG_HZ=250\nCONFIG_TUN=y\nCONFIG_DEFAULT_HOSTNAME=\"x\"\n");
    defer no_bpf.deinit();
    try testing.expectError(error.ExternNotFound, fillKconfig(&o, &no_bpf, 1));
    // no configuration at all, and no version
    try testing.expectError(error.ExternNotFound, fillKconfig(&o, null, 1));
    try testing.expectError(error.ExternNotFound, fillKconfig(&o, &cfg, null));
    // a value of the wrong kind for the declared type
    var bad = try kconfig_mod.parse(gpa, "CONFIG_HZ=\"fast\"\nCONFIG_BPF=y\nCONFIG_TUN=y\nCONFIG_DEFAULT_HOSTNAME=\"x\"\n");
    defer bad.deinit();
    try testing.expectError(error.ExternTypeMismatch, fillKconfig(&o, &bad, 1));
    var big = try kconfig_mod.parse(gpa, "CONFIG_HZ=4294967296\nCONFIG_BPF=y\nCONFIG_TUN=y\nCONFIG_DEFAULT_HOSTNAME=\"x\"\n");
    defer big.deinit();
    try testing.expectError(error.ExternTypeMismatch, fillKconfig(&o, &big, 1));
}

test "externs: resolved against THIS machine's vmlinux BTF and patched into the instructions" {
    const gpa = testing.allocator;
    var kern = btf_mod.loadKernel(gpa) catch return error.SkipZigTest;
    defer kern.deinit();
    if (kern.findByNameKind("bpf_rcu_read_lock", .func) == null or kern.findByNameKind("bpf_prog_active", .@"var") == null)
        return error.SkipZigTest;
    var o = try open(gpa, fx_externs, .{});
    defer o.deinit();
    try resolveKernelExterns(&o, &kern, .{ .search_modules = false });
    const rcu = o.externs[findExternIdx(&o, "bpf_rcu_read_lock").?];
    try testing.expect(rcu.resolved);
    try testing.expectEqual(kern.findByNameKind("bpf_rcu_read_lock", .func).?, rcu.kernel_btf_id);
    const act = o.externs[findExternIdx(&o, "bpf_prog_active").?];
    try testing.expect(act.resolved and !act.typeless);
    try testing.expectEqual(kern.findByNameKind("bpf_prog_active", .@"var").?, act.kernel_btf_id);
    // a weak kfunc the kernel lacks stays unresolved
    try testing.expect(!o.externs[findExternIdx(&o, "bpf_zl_missing_kfunc").?].resolved);

    const p = o.findProgram("probe").?;
    try patchExterns(p, o.externs);
    for (p.extern_refs) |r| {
        const ins = p.insns[r.insn_idx];
        const ext = o.externs[r.extern_idx];
        if (r.call and ext.resolved) {
            try testing.expectEqual(@as(u4, BPF_PSEUDO_KFUNC_CALL), ins.src);
            try testing.expectEqual(@as(i32, @intCast(ext.kernel_btf_id)), ins.imm);
            try testing.expectEqual(@as(i16, 0), ins.off); // vmlinux
        } else if (r.call) {
            try testing.expectEqual(@as(u4, 0), ins.src);
            try testing.expect(ins.imm >= poison_call_kfunc_base); // reported only if reachable
        } else if (ext.resolved and !ext.typeless) {
            try testing.expectEqual(@as(u4, BPF_PSEUDO_BTF_ID), ins.src);
            try testing.expectEqual(@as(i32, @intCast(ext.kernel_btf_id)), ins.imm);
            try testing.expectEqual(@as(i32, 0), p.insns[r.insn_idx + 1].imm);
        } else {
            // unresolved weak: a constant 0
            try testing.expectEqual(@as(u4, 0), ins.src);
            try testing.expectEqual(@as(i32, 0), ins.imm);
        }
    }
    // a strong extern the kernel lacks is an error
    o.externs[findExternIdx(&o, "bpf_zl_missing_kfunc").?].weak = false;
    try testing.expectError(error.ExternNotFound, resolveKernelExterns(&o, &kern, .{ .search_modules = false }));
}

// ── mutation 2026-11-27: map initializer slots, sub-program linking, CO-RE immediates, data accessors ──

const mt_rel_maps = 0xd18; // .rel.maps of mapinmap.bpf.o: three 16-byte entries
const mt_shoff = 0x11a0; // its section header table

fn mtPatchRel(copy: []u8, k: usize, r_offset: ?u64, sym: ?u32, typ: ?u32) void {
    const at = mt_rel_maps + k * 16;
    if (r_offset) |o| std.mem.writeInt(u64, copy[at..][0..8], o, .little);
    if (sym != null or typ != null) {
        const old = std.mem.readInt(u64, copy[at + 8 ..][0..8], .little);
        const s: u64 = sym orelse @intCast(old >> 32);
        const t: u64 = typ orelse @intCast(old & 0xffff_ffff);
        std.mem.writeInt(u64, copy[at + 8 ..][0..8], (s << 32) | t, .little);
    }
}

test "mutation 2026-11-27: the initializer relocations of .maps, and what refuses them" {
    const gpa = testing.allocator;
    const copy = try gpa.dupe(u8, fx_mapinmap);
    defer gpa.free(copy);
    {
        // the untouched object has its two + one slots
        var o = try open(gpa, copy, .{});
        defer o.deinit();
        try testing.expectEqual(@as(usize, 2), o.findMap("outer").?.init_slots.len);
    }
    {
        // .rel.maps that is no REL section, or relocates another section, is not looked at
        const c = try gpa.dupe(u8, copy);
        defer gpa.free(c);
        std.mem.writeInt(u32, c[mt_shoff + 5 * 64 + 4 ..][0..4], 1, .little); // sh_type PROGBITS
        var o = try open(gpa, c, .{});
        defer o.deinit();
        try testing.expectEqual(@as(usize, 0), o.findMap("outer").?.init_slots.len);
    }
    {
        const c = try gpa.dupe(u8, copy);
        defer gpa.free(c);
        std.mem.writeInt(u32, c[mt_shoff + 5 * 64 + 44 ..][0..4], 3, .little); // sh_info: relocates `xdp`
        var o = try open(gpa, c, .{});
        defer o.deinit();
        try testing.expectEqual(@as(usize, 0), o.findMap("outer").?.init_slots.len);
    }
    const Case = struct { k: usize, off: ?u64, sym: ?u32, typ: ?u32, want: ParseError };
    for ([_]Case{
        .{ .k = 0, .off = 0, .sym = null, .typ = null, .want = error.RelocationOutOfRange }, // before every map with values
        .{ .k = 0, .off = 92, .sym = null, .typ = null, .want = error.RelocationOutOfRange }, // not 8-aligned in the slot array
        .{ .k = 0, .off = 72, .sym = null, .typ = null, .want = error.RelocationOutOfRange }, // before the `values` member
        .{ .k = 0, .off = null, .sym = null, .typ = 1, .want = error.UnsupportedRelocation }, // R_BPF_64_64
        .{ .k = 0, .off = null, .sym = 10, .typ = null, .want = error.UnresolvedRelocation }, // a map of maps points into .maps
        .{ .k = 2, .off = null, .sym = 12, .typ = null, .want = error.UnresolvedRelocation }, // a prog_array points at a function
    }) |c| {
        const p = try gpa.dupe(u8, copy);
        defer gpa.free(p);
        mtPatchRel(p, c.k, c.off, c.sym, c.typ);
        try testing.expectError(c.want, open(gpa, p, .{}));
    }
    {
        // a prog_array slot is the program at the symbol's own offset: `entry` is at 16 of its section
        const c = try gpa.dupe(u8, copy);
        defer gpa.free(c);
        mtPatchRel(c, 2, null, 11, null);
        var o = try open(gpa, c, .{});
        defer o.deinit();
        const j = o.findMap("jumps").?;
        try testing.expectEqual(@as(usize, 1), j.init_slots.len);
        try testing.expectEqualStrings("entry", o.programs[j.init_slots[0].target.program].name);
    }
}

fn mtSpec(name: []const u8, sec: usize, insns: []Insn) ProgramSpec {
    return .{
        .sec_name = name,
        .name = name,
        .attach_target = "",
        .prog_type = .xdp,
        .expected_attach_type = null,
        .sleepable = false,
        .sec_idx = sec,
        .sec_byte_off = 0,
        .insns = insns,
        .relos = &.{},
        .func_info = &.{},
        .line_info = &.{},
        .core_relos = &.{},
    };
}

test "mutation 2026-11-27: linking a sub-program carries its records, shifted, and patches the call" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var caller_insns = [_]Insn{ std.mem.zeroes(Insn), std.mem.zeroes(Insn) };
    var sub_insns = [_]Insn{ std.mem.zeroes(Insn), std.mem.zeroes(Insn), std.mem.zeroes(Insn) };
    var progs = [_]ProgramSpec{mtSpec("caller", 1, &caller_insns)};
    progs[0].call_sites = try a.dupe(CallSite, &.{.{ .kind = .call, .insn_idx = 0, .sec_idx = 2, .sec_byte_off = 0 }});
    progs[0].extern_refs = try a.dupe(ExternRef, &.{.{ .insn_idx = 1, .extern_idx = 0, .call = false }});
    var sub = mtSpec("sub", 2, &sub_insns);
    sub.extern_refs = try a.dupe(ExternRef, &.{.{ .insn_idx = 1, .extern_idx = 0, .call = false }});
    sub.core_relos = try a.dupe(btfext.CoreRelo, &.{.{ .insn_off = 2, .type_id = 1, .access_str_off = 0, .kind = 0 }});
    sub.line_info = try a.dupe(btfext.LineInfo, &.{.{ .insn_off = 1, .file_name_off = 0, .line_off = 0, .line_col = 0 }});
    try linkSubprograms(a, &progs, &.{sub});
    const p = progs[0];
    try testing.expectEqual(@as(usize, 5), p.insns.len);
    try testing.expectEqual(BPF_PSEUDO_CALL, p.insns[0].src);
    try testing.expectEqual(@as(i32, 1), p.insns[0].imm); // callee at 2, call at 0: 2 - 0 - 1
    try testing.expectEqual(@as(usize, 2), p.extern_refs.len);
    try testing.expectEqual(@as(u32, 1), p.extern_refs[0].insn_idx);
    try testing.expectEqual(@as(u32, 3), p.extern_refs[1].insn_idx);
    try testing.expectEqual(@as(usize, 1), p.core_relos.len);
    try testing.expectEqual(@as(u32, 4), p.core_relos[0].insn_off);
    try testing.expectEqual(@as(usize, 1), p.line_info.len);
    try testing.expectEqual(@as(u32, 3), p.line_info[0].insn_off);
    try testing.expectEqual(@as(usize, 0), p.call_sites.len);
}

test "mutation 2026-11-27: a function address is BPF_PSEUDO_FUNC, a callee is placed once, the size limit is inclusive" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var caller_insns = [_]Insn{ std.mem.zeroes(Insn), std.mem.zeroes(Insn) };
    var sub_insns = [_]Insn{ std.mem.zeroes(Insn), std.mem.zeroes(Insn) };
    var progs = [_]ProgramSpec{mtSpec("caller", 1, &caller_insns)};
    progs[0].call_sites = try a.dupe(CallSite, &.{
        .{ .kind = .func_addr, .insn_idx = 0, .sec_idx = 2, .sec_byte_off = 0 },
        .{ .kind = .call, .insn_idx = 1, .sec_idx = 2, .sec_byte_off = 0 },
    });
    const sub = mtSpec("sub", 2, &sub_insns);
    try linkSubprograms(a, &progs, &.{sub});
    try testing.expectEqual(@as(usize, 4), progs[0].insns.len); // the callee once, though called twice
    try testing.expectEqual(BPF_PSEUDO_FUNC, progs[0].insns[0].src);
    try testing.expectEqual(@as(i32, 1), progs[0].insns[0].imm); // 2 - 0 - 1
    try testing.expectEqual(BPF_PSEUDO_CALL, progs[0].insns[1].src);
    try testing.expectEqual(@as(i32, 0), progs[0].insns[1].imm); // 2 - 1 - 1

    // 1 + (limit - 1) instructions is exactly the limit; one more is too many
    const big = try testing.allocator.alloc(Insn, max_program_insns);
    defer testing.allocator.free(big);
    @memset(big, std.mem.zeroes(Insn));
    var one = [_]Insn{std.mem.zeroes(Insn)};
    var p2 = [_]ProgramSpec{mtSpec("caller", 1, &one)};
    p2[0].call_sites = try a.dupe(CallSite, &.{.{ .kind = .call, .insn_idx = 0, .sec_idx = 2, .sec_byte_off = 0 }});
    try linkSubprograms(a, &p2, &.{mtSpec("sub", 2, big[0 .. max_program_insns - 1])});
    try testing.expectEqual(max_program_insns, p2[0].insns.len);
    var p3 = [_]ProgramSpec{mtSpec("caller", 1, &one)};
    p3[0].call_sites = try a.dupe(CallSite, &.{.{ .kind = .call, .insn_idx = 0, .sec_idx = 2, .sec_byte_off = 0 }});
    try testing.expectError(error.ProgramTooLarge, linkSubprograms(a, &p3, &.{mtSpec("sub", 2, big)}));
}

test "mutation 2026-11-27: an ALU immediate takes any i32, a bigger one is refused, either sign" {
    var insns = [_]Insn{.{ .code = 0x07, .dst = 0, .src = 0, .off = 0, .imm = 0 }}; // ALU64 | K | ADD
    try patchCoreInsn(&insns, 0, .enumval_value, @bitCast(@as(i64, std.math.minInt(i32))));
    try testing.expectEqual(@as(i32, std.math.minInt(i32)), insns[0].imm);
    try patchCoreInsn(&insns, 0, .enumval_value, @bitCast(@as(i64, std.math.maxInt(i32))));
    try testing.expectEqual(@as(i32, std.math.maxInt(i32)), insns[0].imm);
    try testing.expectError(error.CoreValueTooLarge, patchCoreInsn(&insns, 0, .enumval_value, @bitCast(@as(i64, std.math.minInt(i32)) - 1)));
    try testing.expectError(error.CoreValueTooLarge, patchCoreInsn(&insns, 0, .enumval_value, @as(u64, std.math.maxInt(i32)) + 1));
}

test "mutation 2026-11-27: dataVariables of .ksyms and .kconfig, the mapping helpers, and what unpinning leaves" {
    const gpa = testing.allocator;
    var o = try open(gpa, fx_externs, .{});
    defer o.deinit();
    try testing.expectEqual(@as(usize, 0), (try o.dataVariables(".ksyms")).len);
    var n_kconfig: usize = 0;
    for (o.externs) |e| {
        if (e.kind == .kconfig) n_kconfig += 1;
    }
    try testing.expect(n_kconfig > 0 and n_kconfig < o.externs.len);
    try testing.expectEqual(n_kconfig, (try o.dataVariables(".kconfig")).len);

    // MappedData over a memfd: a zero-length map still takes a page, a writable one can be written, bounds are checked
    const rc = linux.memfd_create("ebpf-mt", 0);
    try testing.expect(linux.errno(rc) == .SUCCESS);
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    try testing.expect(linux.errno(linux.ftruncate(fd, 4096)) == .SUCCESS);
    var empty = try MappedData.map(fd, 0, 0, false);
    empty.deinit();
    var md = try MappedData.map(fd, 64, 64, true);
    defer md.deinit();
    md.bytes()[0] = 7;
    try testing.expectEqual(@as(u8, 7), md.bytes()[0]);
    try testing.expectError(error.SizeMismatch, md.variable(.{ .name = "v", .offset = 65, .size = 0, .type_id = 0 }));
    try testing.expectError(error.SizeMismatch, md.variable(.{ .name = "v", .offset = 60, .size = 5, .type_id = 0 }));
    try testing.expectEqual(@as(usize, 4), (try md.variable(.{ .name = "v", .offset = 60, .size = 4, .type_id = 0 })).len);
    try testing.expectEqual(@as(usize, 0), (try md.variable(.{ .name = "v", .offset = 64, .size = 0, .type_id = 0 })).len);
    const W = extern struct { a: [64]u8 };
    const Big = extern struct { a: [65]u8 };
    _ = try md.view(W);
    try testing.expectError(error.SizeMismatch, md.view(Big));
}

test "mutation 2026-11-27: unpinMaps leaves an internal data map's name alone" {
    const gpa = testing.allocator;
    var o = try open(gpa, fx_rodata_const, .{});
    defer o.deinit();
    var dir_buf: [64]u8 = undefined;
    const dir = try std.fmt.bufPrintSentinel(&dir_buf, "/tmp/ebpf-mt-{d}", .{linux.getpid()}, 0);
    try testing.expect(linux.errno(linux.mkdir(dir, 0o700)) == .SUCCESS);
    defer _ = linux.rmdir(dir);
    var path_buf: [96]u8 = undefined;
    const path = try std.fmt.bufPrintSentinel(&path_buf, "{s}/.rodata", .{dir}, 0);
    const rc = linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o600);
    try testing.expect(linux.errno(rc) == .SUCCESS);
    _ = linux.close(@intCast(rc));
    defer _ = linux.unlink(path);
    try o.unpinMaps(dir); // the internal map is skipped: its (here: ordinary) file stays
    try testing.expect(linux.errno(linux.access(path, 0)) == .SUCCESS);
}

// ── mutation 2026-11-27 (D35): externs, struct_ops, map definitions, call relocations, load() ──

const MtSym = enum { kver, config_a, config_b, ksym_i, kfn, ksym_void };
const MtRel = struct { off: u64, sym: MtSym, typ: u32 };
const MtKcfg = enum { normal, bad_type, empty, huge };
const MtExt = struct {
    weak_kfn: bool = false,
    decoy: bool = false,
    legacy_map: ?[]const u8 = null,
    kcfg: MtKcfg = .normal,
    no_kconfig: bool = false,
    /// the kfunc's prototype takes a function pointer whose prototype takes a parameter
    deep: bool = false,
};

/// An object with one XDP program, hand-made BTF `.kconfig` / `.ksyms` DATASECs and the matching
/// undefined symbols. Symbol order: LINUX_KERNEL_VERSION, CONFIG_A, CONFIG_B, ksym_i, kfn, ksym_void.
fn mtExtObject(gpa: std.mem.Allocator, code: []const u8, rels: []const MtRel, o: MtExt) ![]u8 {
    var r = try RawB.init(gpa);
    defer r.deinit(gpa);
    const n_int = try r.str(gpa, "int");
    const n_ver = try r.str(gpa, "LINUX_KERNEL_VERSION");
    const n_a = try r.str(gpa, "CONFIG_A");
    const n_b = try r.str(gpa, "CONFIG_B");
    const n_si = try r.str(gpa, "ksym_i");
    const n_sv = try r.str(gpa, "ksym_void");
    const n_kf = try r.str(gpa, "kfn");
    const n_st = try r.str(gpa, "static_v");
    const n_sf = try r.str(gpa, "sfn");
    const n_kc = try r.str(gpa, ".kconfig");
    const n_ks = try r.str(gpa, ".ksyms");
    const n_ch = try r.str(gpa, "char");
    const int4 = try r.rec(gpa, n_int, btf_mod.K_INT, 0, false, 4, &.{32});
    const proto = try r.rec(gpa, 0, btf_mod.K_FUNC_PROTO, 0, false, 0, &.{});
    var kproto = proto;
    if (o.deep) {
        const p2 = try r.rec(gpa, 0, btf_mod.K_FUNC_PROTO, 1, false, 0, &.{ 0, int4 });
        const pp = try r.rec(gpa, 0, btf_mod.K_PTR, 0, false, p2, &.{});
        kproto = try r.rec(gpa, 0, btf_mod.K_FUNC_PROTO, 1, false, 0, &.{ 0, pp });
    }
    const chr = try r.rec(gpa, n_ch, btf_mod.K_INT, 0, false, 1, &.{8});
    const empty_arr = try r.rec(gpa, 0, btf_mod.K_ARRAY, 0, false, 0, &.{ chr, int4, 0 });
    const huge_arr = try r.rec(gpa, 0, btf_mod.K_ARRAY, 0, false, 0, &.{ chr, int4, 0x8000_0000 });
    const ty_a: u32 = switch (o.kcfg) {
        .normal => int4,
        .bad_type => proto,
        .empty => empty_arr,
        .huge => huge_arr,
    };
    const v_ver = try r.rec(gpa, n_ver, btf_mod.K_VAR, 0, false, if (o.kcfg == .huge) huge_arr else int4, &.{2});
    const v_a = try r.rec(gpa, n_a, btf_mod.K_VAR, 0, false, ty_a, &.{2});
    const v_b = try r.rec(gpa, n_b, btf_mod.K_VAR, 0, false, int4, &.{2});
    const v_si = try r.rec(gpa, n_si, btf_mod.K_VAR, 0, false, int4, &.{2});
    const v_sv = try r.rec(gpa, n_sv, btf_mod.K_VAR, 0, false, 0, &.{2});
    const f_kf = try r.rec(gpa, n_kf, btf_mod.K_FUNC, 2, false, kproto, &.{});
    const v_static = try r.rec(gpa, n_st, btf_mod.K_VAR, 0, false, int4, &.{0});
    const f_global = try r.rec(gpa, n_sf, btf_mod.K_FUNC, 1, false, proto, &.{});
    if (!o.no_kconfig) switch (o.kcfg) {
        .normal, .bad_type => _ = try r.rec(gpa, n_kc, btf_mod.K_DATASEC, 3, false, 12, &.{ v_ver, 0, 4, v_a, 4, 4, v_b, 8, 4 }),
        .empty => _ = try r.rec(gpa, n_kc, btf_mod.K_DATASEC, 1, false, 0, &.{ v_a, 0, 0 }),
        .huge => _ = try r.rec(gpa, n_kc, btf_mod.K_DATASEC, 2, false, 0, &.{ v_ver, 0, 0, v_a, 0, 0 }),
    };
    _ = try r.rec(gpa, n_ks, btf_mod.K_DATASEC, 5, false, 8, &.{ v_si, 0, 4, v_sv, 0, 0, f_kf, 0, 0, v_static, 0, 4, f_global, 0, 0 });
    const blob = try r.finish(gpa);
    defer gpa.free(blob);

    var b = ObjB.init(gpa);
    defer b.deinit();
    const px = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = code });
    _ = try b.sec(.{ .name = ".BTF", .ty = 1, .data = blob });
    var relb: [8 * 16]u8 = undefined;
    for (rels, 0..) |rel, k| {
        const idx: u64 = @as(u64, @backingInt(rel.sym)) + 1 + @intFromBool(o.decoy);
        std.mem.writeInt(u64, relb[k * 16 ..][0..8], rel.off, .little);
        std.mem.writeInt(u64, relb[k * 16 + 8 ..][0..8], (idx << 32) | rel.typ, .little);
    }
    _ = try b.sec(.{ .name = ".relxdp", .ty = elfsym.SHT_REL, .data = relb[0 .. rels.len * 16], .link = ObjB.SYMTAB_LINK, .info = px, .entsize = 16 });
    _ = try b.sec(.{ .name = ".kconfig", .ty = 8, .flags = 3, .size = 12 });
    const defs: [20]u8 = @splat(0);
    if (o.legacy_map != null) _ = try b.sec(.{ .name = "maps", .ty = 1, .flags = 3, .data = &defs });
    const maps_sec: u16 = if (o.legacy_map != null) 5 else 0;
    if (o.decoy) _ = try b.sym(.{ .name = "kfn", .info = OBJ_SYM, .shndx = px });
    const glob: u8 = 0x10;
    const weak: u8 = 0x20;
    _ = try b.sym(.{ .name = "LINUX_KERNEL_VERSION", .info = glob, .shndx = 0 });
    _ = try b.sym(.{ .name = "CONFIG_A", .info = glob, .shndx = 0 });
    _ = try b.sym(.{ .name = "CONFIG_B", .info = glob, .shndx = 0 });
    _ = try b.sym(.{ .name = "ksym_i", .info = glob, .shndx = 0 });
    _ = try b.sym(.{ .name = "kfn", .info = if (o.weak_kfn) weak else glob, .shndx = 0 });
    _ = try b.sym(.{ .name = "ksym_void", .info = weak, .shndx = 0 });
    if (o.legacy_map) |nm| _ = try b.sym(.{ .name = nm, .info = OBJ_SYM, .shndx = maps_sec });
    return b.build();
}

/// A kernel BTF with `int ksym_i`, `void kfn(void)` and `int ksym_void`.
fn mtKernBtf(gpa: std.mem.Allocator, bad: bool, deep: bool) ![]u8 {
    var r = try RawB.init(gpa);
    defer r.deinit(gpa);
    const n_int = try r.str(gpa, "int");
    const n_si = try r.str(gpa, "ksym_i");
    const n_kf = try r.str(gpa, "kfn");
    const n_sv = try r.str(gpa, "ksym_void");
    const int4 = try r.rec(gpa, n_int, btf_mod.K_INT, 0, false, 4, &.{32});
    const ptr = try r.rec(gpa, 0, btf_mod.K_PTR, 0, false, 0, &.{});
    _ = try r.rec(gpa, n_si, btf_mod.K_VAR, 0, false, if (bad) ptr else int4, &.{1});
    var proto = try r.rec(gpa, 0, btf_mod.K_FUNC_PROTO, 0, false, 0, &.{});
    if (deep) {
        const p2 = try r.rec(gpa, 0, btf_mod.K_FUNC_PROTO, 1, false, 0, &.{ 0, int4 });
        const pp = try r.rec(gpa, 0, btf_mod.K_PTR, 0, false, p2, &.{});
        proto = try r.rec(gpa, 0, btf_mod.K_FUNC_PROTO, 1, false, 0, &.{ 0, pp });
    }
    _ = try r.rec(gpa, n_kf, btf_mod.K_FUNC, 1, false, proto, &.{});
    _ = try r.rec(gpa, n_sv, btf_mod.K_VAR, 0, false, int4, &.{1});
    return r.finish(gpa);
}

/// Declarations of `.ksyms` variables behind qualifiers: `int` (2 bytes), `const void`, `const const void`,
/// and with `cyc` a `const` that is its own target.
fn mtQualObject(gpa: std.mem.Allocator, cyc: bool) ![]u8 {
    var r = try RawB.init(gpa);
    defer r.deinit(gpa);
    const n_i = try r.str(gpa, "int");
    const n_vi = try r.str(gpa, "v_int");
    const n_vc = try r.str(gpa, "v_cc");
    const n_vv = try r.str(gpa, "v_cv");
    const n_cy = try r.str(gpa, "v_cyc");
    const n_ks = try r.str(gpa, ".ksyms");
    const int2 = try r.rec(gpa, n_i, btf_mod.K_INT, 0, false, 2, &.{16}); // id 1: its size (2) is the id of the next record
    const cv = try r.rec(gpa, 0, 10, 0, false, 0, &.{}); // id 2: const void
    const cc = try r.rec(gpa, 0, 10, 0, false, cv, &.{});
    const v_i = try r.rec(gpa, n_vi, btf_mod.K_VAR, 0, false, int2, &.{2});
    const v_c = try r.rec(gpa, n_vc, btf_mod.K_VAR, 0, false, cc, &.{2});
    const v_v = try r.rec(gpa, n_vv, btf_mod.K_VAR, 0, false, cv, &.{2});
    var ents: [4 * 3]u32 = .{ v_i, 0, 0, v_c, 0, 0, v_v, 0, 0, 0, 0, 0 };
    var n: u16 = 3;
    if (cyc) {
        const loop = try r.rec(gpa, 0, 10, 0, false, r.count + 1, &.{});
        const v_y = try r.rec(gpa, n_cy, btf_mod.K_VAR, 0, false, loop, &.{2});
        ents[9] = v_y;
        n = 4;
    }
    _ = try r.rec(gpa, n_ks, btf_mod.K_DATASEC, n, false, 0, ents[0 .. n * 3]);
    const blob = try r.finish(gpa);
    defer gpa.free(blob);
    var b = ObjB.init(gpa);
    defer b.deinit();
    _ = try b.sec(.{ .name = ".BTF", .ty = 1, .data = blob });
    return b.build();
}

test "mutation 2026-11-27: every extern declaration lands in its own fields; weak is a property of the undefined symbol" {
    const gpa = testing.allocator;
    const code = cat(.{ I_LD64, I_LD64_HI, I_LD64, I_LD64_HI, I_CALL, I_EXIT });
    const bytes = try mtExtObject(gpa, &code, &.{
        .{ .off = 0, .sym = .config_b, .typ = R_BPF_64_64 },
        .{ .off = 16, .sym = .ksym_i, .typ = R_BPF_64_64 },
        .{ .off = 32, .sym = .kfn, .typ = R_BPF_64_32 },
    }, .{ .weak_kfn = true, .decoy = true, .legacy_map = "m1" });
    defer gpa.free(bytes);
    var o = try open(gpa, bytes, .{});
    defer o.deinit();
    const b = &o.btf.?;
    // static / global declarations in `.ksyms` are not externs
    try testing.expectEqual(@as(usize, 6), o.externs.len);
    const want = [_]struct { n: []const u8, kind: ExternKind, off: u32 = 0, weak: bool = false, typeless: bool = false }{
        .{ .n = "LINUX_KERNEL_VERSION", .kind = .kconfig, .off = 0 },
        .{ .n = "CONFIG_A", .kind = .kconfig, .off = 4 },
        .{ .n = "CONFIG_B", .kind = .kconfig, .off = 8 },
        .{ .n = "ksym_i", .kind = .ksym_var },
        .{ .n = "ksym_void", .kind = .ksym_var, .weak = true, .typeless = true },
        .{ .n = "kfn", .kind = .ksym_func, .weak = true },
    };
    for (want, o.externs) |w, e| {
        try testing.expectEqualStrings(w.n, e.name);
        try testing.expectEqual(w.kind, e.kind);
        try testing.expectEqual(w.weak, e.weak);
        try testing.expectEqual(w.typeless, e.typeless);
        try testing.expectEqual(w.off, e.value_off);
        if (e.kind == .kconfig) try testing.expectEqual(@as(u32, 4), e.size);
    }
    // the VAR / FUNC record and the type behind it
    const int4 = b.findByNameKind("int", .int).?;
    try testing.expectEqual(b.findByNameKind("ksym_i", .@"var").?, o.externs[3].btf_id);
    try testing.expectEqual(int4, o.externs[3].type_id);
    try testing.expectEqual(b.findByNameKind("CONFIG_B", .@"var").?, o.externs[2].btf_id);
    try testing.expectEqual(int4, o.externs[2].type_id);
    const kf = b.findByNameKind("kfn", .func).?;
    try testing.expectEqual(kf, o.externs[5].btf_id);
    try testing.expectEqual((try b.byId(kf)).refType().?, o.externs[5].type_id);
    // the synthesized .kconfig map, after the object's own
    try testing.expectEqual(@as(usize, 2), o.maps.len);
    try testing.expectEqualStrings("m1", o.maps[0].name);
    const km = o.maps[1];
    try testing.expectEqualStrings(".kconfig", km.name);
    try testing.expectEqual(BPF.MapType.array, km.map_type);
    try testing.expectEqual(@as(u32, 4), km.key_size);
    try testing.expectEqual(@as(u32, 12), km.value_size);
    try testing.expectEqual(@as(u32, 1), km.max_entries);
    try testing.expectEqual(BPF_F_RDONLY_PROG, km.map_flags);
    try testing.expectEqual(MapOrigin.internal, km.origin);
    try testing.expect(km.freeze);
    try testing.expect(km.sec_idx != 0);
    try testing.expectEqual(o.image.findSection(".kconfig").?, km.sec_idx);
    try testing.expectEqual(@as(usize, 12), km.initial_data.len);
    for (km.initial_data) |byte| try testing.expectEqual(@as(u8, 0), byte);
    // the program: a kconfig read is a map_value into that map, the rest are extern references
    const p = o.programs[0];
    try testing.expectEqual(@as(usize, 1), p.relos.len);
    try testing.expectEqual(ReloKind.map_value, p.relos[0].kind);
    try testing.expectEqual(@as(usize, 1), p.relos[0].map_idx);
    try testing.expectEqual(@as(u64, 8), p.relos[0].value_off);
    try testing.expectEqualStrings("CONFIG_B", p.relos[0].sym_name);
    try testing.expectEqual(@as(usize, 2), p.extern_refs.len);
    try testing.expectEqual(@as(u32, 2), p.extern_refs[0].insn_idx);
    try testing.expectEqual(@as(usize, 3), p.extern_refs[0].extern_idx);
    try testing.expect(!p.extern_refs[0].call);
    try testing.expectEqual(@as(u32, 4), p.extern_refs[1].insn_idx);
    try testing.expectEqual(@as(usize, 5), p.extern_refs[1].extern_idx);
    try testing.expect(p.extern_refs[1].call);
}

test "mutation 2026-11-27: an object with only ksyms gets no .kconfig map; a legacy map of that name collides" {
    const gpa = testing.allocator;
    {
        const code = cat(.{ I_LD64, I_LD64_HI, I_EXIT });
        const bytes = try mtExtObject(gpa, &code, &.{.{ .off = 0, .sym = .ksym_i, .typ = R_BPF_64_64 }}, .{ .no_kconfig = true });
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        try testing.expectEqual(@as(usize, 3), o.externs.len);
        try testing.expectEqual(@as(usize, 0), o.maps.len);
    }
    {
        const code = cat(.{ I_MOV0, I_EXIT });
        const bytes = try mtExtObject(gpa, &code, &.{}, .{ .legacy_map = ".kconfig" });
        defer gpa.free(bytes);
        try testing.expectError(error.DuplicateMap, open(gpa, bytes, .{}));
    }
}

test "mutation 2026-11-27: extern relocations: what each kind may sit on, and what the kconfig layout refuses" {
    const gpa = testing.allocator;
    const Case = struct { code: []const [8]u8, rel: MtRel, kcfg: MtKcfg = .normal, want: anyerror };
    const cases = [_]Case{
        .{ .code = &.{ I_MOV0, I_EXIT }, .rel = .{ .off = 0, .sym = .kfn, .typ = R_BPF_64_32 }, .want = error.UnsupportedRelocation }, // a kfunc reloc on a non-call
        .{ .code = &.{ I_CALL, I_EXIT }, .rel = .{ .off = 0, .sym = .config_a, .typ = R_BPF_64_32 }, .want = error.UnsupportedRelocation }, // a call to a kconfig value
        .{ .code = &.{ I_MOV0, I_EXIT }, .rel = .{ .off = 0, .sym = .ksym_i, .typ = R_BPF_64_64 }, .want = error.UnsupportedRelocation }, // an address load on a mov
        .{ .code = &.{ I_MOV0, I_LD64 }, .rel = .{ .off = 8, .sym = .ksym_i, .typ = R_BPF_64_64 }, .want = error.RelocationOutOfRange }, // LD_IMM64 is the last instruction
        .{ .code = &.{ I_LD64, I_LD64_HI, I_EXIT }, .rel = .{ .off = 0, .sym = .config_a, .typ = R_BPF_64_64 }, .kcfg = .empty, .want = error.UnresolvedRelocation }, // a zero-size value makes no .kconfig map
        .{ .code = &.{ I_MOV0, I_EXIT }, .rel = .{ .off = 0, .sym = .kver, .typ = R_BPF_64_64 }, .kcfg = .bad_type, .want = error.UnsupportedExternType },
        .{ .code = &.{ I_MOV0, I_EXIT }, .rel = .{ .off = 0, .sym = .kver, .typ = R_BPF_64_64 }, .kcfg = .huge, .want = error.UnsupportedExternType }, // 2 GiB + 2 GiB overflows u32
    };
    for (cases, 0..) |c, ci| {
        var code: [4][8]u8 = undefined;
        for (c.code, 0..) |ins, k| code[k] = ins;
        const bytes = try mtExtObject(gpa, std.mem.sliceAsBytes(code[0..c.code.len]), &.{c.rel}, .{ .kcfg = c.kcfg });
        defer gpa.free(bytes);
        testing.expectError(c.want, open(gpa, bytes, .{})) catch |e| {
            std.debug.print("extern case {d}\n", .{ci});
            return e;
        };
    }
}

test "mutation 2026-11-27: typeless is `void` behind any number of qualifiers, and nothing else" {
    const gpa = testing.allocator;
    {
        const bytes = try mtQualObject(gpa, false);
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        try testing.expectEqual(@as(usize, 3), o.externs.len);
        try testing.expect(!o.externs[0].typeless); // a 2-byte int whose size is the id of a `const void`
        try testing.expect(o.externs[1].typeless); // const const void
        try testing.expect(o.externs[2].typeless); // const void
    }
    {
        // a qualifier that is its own target must end the walk, whatever it answers
        const bytes = try mtQualObject(gpa, true);
        defer gpa.free(bytes);
        if (open(gpa, bytes, .{})) |o| {
            var oo = o;
            oo.deinit();
        } else |_| {}
    }
}

const MtOps = struct {
    no_btf: bool = false,
    decoy_rel: bool = false,
    legacy_map: ?[]const u8 = null,
    v2_off: u64 = 32,
    v2_size: u64 = 16,
    /// symbol 6: an object symbol at the start of p1
    obj_alias: bool = false,
};
const MtOpsRel = struct { off: u64, sym: u32, typ: u32 };

/// An object with a `.struct_ops` section holding two `struct ops { int a; void (*fp)(void); }` variables
/// (`v1` at 8, `v2` at `v2_off`), programs p1 + p3 (section 1, offsets 0 and 16) and p2 (section 2), and
/// relocations given by symbol index: 1 v1, 2 v2, 3 p1, 4 p3, 5 p2.
fn mtOpsObject(gpa: std.mem.Allocator, rels: []const MtOpsRel, o: MtOps) ![]u8 {
    var r = try RawB.init(gpa);
    defer r.deinit(gpa);
    const n_int = try r.str(gpa, "int");
    const n_ops = try r.str(gpa, "ops");
    const n_a = try r.str(gpa, "a");
    const n_fp = try r.str(gpa, "fp");
    const n_v1 = try r.str(gpa, "v1");
    const n_v2 = try r.str(gpa, "v2");
    const n_so = try r.str(gpa, ".struct_ops");
    const int4 = try r.rec(gpa, n_int, btf_mod.K_INT, 0, false, 4, &.{32});
    const proto = try r.rec(gpa, 0, btf_mod.K_FUNC_PROTO, 0, false, 0, &.{});
    const fp = try r.rec(gpa, 0, btf_mod.K_PTR, 0, false, proto, &.{});
    const st = try r.rec(gpa, n_ops, btf_mod.K_STRUCT, 2, false, 16, &.{ n_a, int4, 0, n_fp, fp, 64 });
    const v1 = try r.rec(gpa, n_v1, btf_mod.K_VAR, 0, false, st, &.{1});
    const v2 = try r.rec(gpa, n_v2, btf_mod.K_VAR, 0, false, st, &.{1});
    _ = try r.rec(gpa, n_so, btf_mod.K_DATASEC, 2, false, 48, &.{ v1, 8, 16, v2, 32, 16 });
    const blob = try r.finish(gpa);
    defer gpa.free(blob);

    var b = ObjB.init(gpa);
    defer b.deinit();
    const code4 = cat(.{ I_MOV0, I_EXIT, I_MOV0, I_EXIT });
    const code2 = cat(.{ I_MOV0, I_EXIT });
    _ = try b.sec(.{ .name = "struct_ops/p1", .ty = 1, .flags = ObjB.EXEC, .data = &code4 });
    _ = try b.sec(.{ .name = "struct_ops/p2", .ty = 1, .flags = ObjB.EXEC, .data = &code2 });
    var data: [48]u8 = undefined;
    for (&data, 0..) |*d, i| d.* = if (i >= 32) 0x22 else if (i >= 8) 0x11 else 0;
    const so = try b.sec(.{ .name = ".struct_ops", .ty = 1, .flags = 3, .data = &data });
    if (!o.no_btf) _ = try b.sec(.{ .name = ".BTF", .ty = 1, .data = blob });
    if (o.decoy_rel) _ = try b.sec(.{ .name = ".decoy", .ty = 1, .data = &data, .info = so });
    var relb: [8 * 16]u8 = undefined;
    for (rels, 0..) |rel, k| {
        std.mem.writeInt(u64, relb[k * 16 ..][0..8], rel.off, .little);
        std.mem.writeInt(u64, relb[k * 16 + 8 ..][0..8], (@as(u64, rel.sym) << 32) | rel.typ, .little);
    }
    _ = try b.sec(.{ .name = ".rel.struct_ops", .ty = elfsym.SHT_REL, .data = relb[0 .. rels.len * 16], .link = ObjB.SYMTAB_LINK, .info = so, .entsize = 16 });
    const defs: [20]u8 = @splat(0);
    const mapsec: u16 = if (o.legacy_map != null) try b.sec(.{ .name = "maps", .ty = 1, .flags = 3, .data = &defs }) else 0;
    _ = try b.sym(.{ .name = "v1", .info = OBJ_SYM, .shndx = so, .value = 8, .size = 16 });
    _ = try b.sym(.{ .name = "v2", .info = OBJ_SYM, .shndx = so, .value = o.v2_off, .size = o.v2_size });
    _ = try b.sym(.{ .name = "p1", .info = FUNC_SYM, .shndx = 1, .value = 0, .size = 16 });
    _ = try b.sym(.{ .name = "p3", .info = FUNC_SYM, .shndx = 1, .value = 16, .size = 16 });
    _ = try b.sym(.{ .name = "p2", .info = FUNC_SYM, .shndx = 2, .value = 0, .size = 16 });
    if (o.obj_alias) _ = try b.sym(.{ .name = "p1o", .info = OBJ_SYM, .shndx = 1, .value = 0 });
    if (o.legacy_map) |nm| _ = try b.sym(.{ .name = nm, .info = OBJ_SYM, .shndx = mapsec });
    return b.build();
}

test "mutation 2026-11-27: struct_ops variables: their own bytes, the program behind each pointer, other maps kept" {
    const gpa = testing.allocator;
    const bytes = try mtOpsObject(gpa, &.{
        .{ .off = 16, .sym = 4, .typ = R_BPF_64_ABS64 }, // v1.fp -> p3
        .{ .off = 40, .sym = 5, .typ = R_BPF_64_ABS64 }, // v2.fp -> p2
        .{ .off = 32, .sym = 3, .typ = R_BPF_64_ABS64 }, // the first byte of v2 -> p1
    }, .{ .decoy_rel = true, .legacy_map = "m1" });
    defer gpa.free(bytes);
    var o = try open(gpa, bytes, .{});
    defer o.deinit();
    try testing.expectEqual(@as(usize, 3), o.programs.len);
    try testing.expectEqualStrings("p1", o.programs[0].name);
    try testing.expectEqualStrings("p3", o.programs[1].name);
    try testing.expectEqualStrings("p2", o.programs[2].name);
    try testing.expectEqual(@as(usize, 3), o.maps.len);
    try testing.expectEqualStrings("m1", o.maps[0].name);
    const st = o.btf.?.findByNameKind("ops", .@"struct").?;
    const want = [_]struct { name: []const u8, fill: u8 }{ .{ .name = "v1", .fill = 0x11 }, .{ .name = "v2", .fill = 0x22 } };
    for (want, o.maps[1..]) |w, m| {
        try testing.expectEqualStrings(w.name, m.name);
        try testing.expectEqual(BPF.MapType.struct_ops, m.map_type);
        try testing.expectEqual(MapOrigin.struct_ops, m.origin);
        try testing.expectEqual(@as(u32, 4), m.key_size);
        try testing.expectEqual(@as(u32, 16), m.value_size);
        try testing.expectEqual(@as(u32, 1), m.max_entries);
        try testing.expectEqual(st, m.btf_value_type_id);
        try testing.expect(!m.struct_ops_link);
        try testing.expectEqual(@as(usize, 16), m.initial_data.len);
        try testing.expectEqual(w.fill, m.initial_data[0]);
        try testing.expectEqual(w.fill, m.initial_data[15]);
    }
    const v1 = o.maps[1].struct_ops_progs;
    try testing.expectEqual(@as(usize, 1), v1.len);
    try testing.expectEqual(@as(u32, 8), v1[0].member_off);
    try testing.expectEqual(@as(usize, 1), v1[0].program);
    const v2 = o.maps[2].struct_ops_progs;
    try testing.expectEqual(@as(usize, 2), v2.len);
    try testing.expectEqual(@as(u32, 8), v2[0].member_off);
    try testing.expectEqual(@as(usize, 2), v2[0].program);
    try testing.expectEqual(@as(u32, 0), v2[1].member_off); // `<=`: a relocation on the first byte belongs to this variable
    try testing.expectEqual(@as(usize, 0), v2[1].program);
}

test "mutation 2026-11-27: struct_ops relocations and variables: every refusal, and a relocation type that is accepted" {
    const gpa = testing.allocator;
    const Case = struct { rels: []const MtOpsRel = &.{}, o: MtOps = .{}, want: ?anyerror };
    const cases = [_]Case{
        .{ .rels = &.{.{ .off = 16, .sym = 4, .typ = R_BPF_64_32 }}, .want = error.UnsupportedRelocation },
        .{ .rels = &.{.{ .off = 16, .sym = 4, .typ = R_BPF_64_64 }}, .want = null }, // R_BPF_64_64 is accepted as well
        .{ .rels = &.{.{ .off = 0, .sym = 4, .typ = R_BPF_64_ABS64 }}, .want = error.RelocationOutOfRange }, // before the first variable
        .{ .rels = &.{.{ .off = 26, .sym = 4, .typ = R_BPF_64_ABS64 }}, .want = error.RelocationOutOfRange }, // in the gap between two
        .{ .rels = &.{.{ .off = 16, .sym = 1, .typ = R_BPF_64_ABS64 }}, .want = error.UnresolvedRelocation }, // an object symbol is no program
        .{ .rels = &.{.{ .off = 16, .sym = 6, .typ = R_BPF_64_ABS64 }}, .o = .{ .obj_alias = true }, .want = error.UnresolvedRelocation }, // an object symbol at a program's offset is no program
        .{ .o = .{ .v2_off = 100 }, .want = error.MalformedElf }, // a variable past the section
        .{ .o = .{ .v2_off = 40 }, .want = error.MalformedElf }, // a variable that ends past it
        .{ .o = .{ .legacy_map = "v1" }, .want = error.DuplicateMap },
        .{ .o = .{ .legacy_map = "v2" }, .want = error.DuplicateMap },
    };
    for (cases, 0..) |c, ci| {
        const bytes = try mtOpsObject(gpa, c.rels, c.o);
        defer gpa.free(bytes);
        if (c.want) |e| {
            testing.expectError(e, open(gpa, bytes, .{})) catch |err| {
                std.debug.print("struct_ops case {d}\n", .{ci});
                return err;
            };
        } else {
            var o = try open(gpa, bytes, .{});
            o.deinit();
        }
    }
    // without BTF there are no variables to describe, and a relocation in the section is not an error
    const bytes = try mtOpsObject(gpa, &.{.{ .off = 16, .sym = 4, .typ = R_BPF_64_ABS64 }}, .{ .no_btf = true });
    defer gpa.free(bytes);
    var o = try open(gpa, bytes, .{});
    defer o.deinit();
    try testing.expectEqual(@as(usize, 0), o.maps.len);
}

/// A BTF with `struct <name> { members }` (id 6) and, as the kernel's, `struct bpf_struct_ops_<name> { data }` (id 7, `data` at byte 8).
fn mtOpsBtf(gpa: std.mem.Allocator, name: []const u8, members: []const MtM, kflag: bool, wrapper: bool) ![]u8 {
    var r = try RawB.init(gpa);
    defer r.deinit(gpa);
    const n_int = try r.str(gpa, "int");
    const int4 = try r.rec(gpa, n_int, btf_mod.K_INT, 0, false, 4, &.{32});
    const proto = try r.rec(gpa, 0, btf_mod.K_FUNC_PROTO, 0, false, 0, &.{});
    const fp = try r.rec(gpa, 0, btf_mod.K_PTR, 0, false, proto, &.{});
    const chr = try r.rec(gpa, 0, btf_mod.K_INT, 0, false, 1, &.{8});
    const huge = try r.rec(gpa, 0, btf_mod.K_ARRAY, 0, false, 0, &.{ int4, int4, 0x4000_0001 });
    const ids = [_]u32{ 0, int4, 0, fp, chr, huge };
    var extra: [8 * 3]u32 = undefined;
    for (members, 0..) |m, k| {
        extra[k * 3] = if (m.name.len == 0) 0 else try r.str(gpa, m.name);
        extra[k * 3 + 1] = ids[m.ty];
        extra[k * 3 + 2] = m.off;
    }
    const st = try r.rec(gpa, try r.str(gpa, name), btf_mod.K_STRUCT, @intCast(members.len), kflag, 64, extra[0 .. members.len * 3]);
    if (wrapper) {
        var buf: [64]u8 = undefined;
        const wn = try std.fmt.bufPrint(&buf, "bpf_struct_ops_{s}", .{name});
        _ = try r.rec(gpa, try r.str(gpa, wn), btf_mod.K_STRUCT, 1, false, 72, &.{ try r.str(gpa, "data"), st, 64 });
    }
    return r.finish(gpa);
}
const MtM = struct { name: []const u8, ty: u32, off: u32 };

test "mutation 2026-11-27: planning struct_ops against a kernel type: flavors, anonymous members, bit fields, sizes" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const Case = struct {
        lname: []const u8 = "ops",
        lm: []const MtM,
        lflag: bool = false,
        km: []const MtM,
        kflag: bool = false,
        want: ?anyerror = null,
        local_id: u32 = 6,
    };
    const ab = [_]MtM{ .{ .name = "a", .ty = 1, .off = 0 }, .{ .name = "b", .ty = 3, .off = 64 } };
    const cases = [_]Case{
        .{ .lm = &ab, .km = &ab },
        .{ .lname = "ops___v2", .lm = &ab, .km = &ab }, // a CO-RE flavor suffix names the same kernel type
        .{ .lm = &.{ .{ .name = "", .ty = 1, .off = 0 }, .{ .name = "a", .ty = 1, .off = 32 } }, .km = &.{.{ .name = "a", .ty = 1, .off = 0 }} },
        .{ .lm = &.{.{ .name = "a", .ty = 1, .off = (3 << 24) | 0 }}, .lflag = true, .km = &.{.{ .name = "a", .ty = 1, .off = 0 }}, .want = error.StructOpsMemberMismatch },
        .{ .lm = &.{.{ .name = "a", .ty = 1, .off = 4 }}, .km = &.{.{ .name = "a", .ty = 1, .off = 0 }}, .want = error.StructOpsMemberMismatch },
        .{ .lm = &.{.{ .name = "a", .ty = 1, .off = 0 }}, .km = &.{.{ .name = "a", .ty = 1, .off = (3 << 24) | 0 }}, .kflag = true, .want = error.StructOpsMemberMismatch },
        .{ .lm = &.{.{ .name = "a", .ty = 1, .off = 0 }}, .km = &.{.{ .name = "a", .ty = 1, .off = 4 }}, .want = error.StructOpsMemberMismatch },
        .{ .lm = &.{.{ .name = "a", .ty = 5, .off = 0 }}, .km = &.{.{ .name = "a", .ty = 5, .off = 0 }}, .want = error.StructOpsMemberMismatch }, // equal sizes beyond u32
        .{ .lm = &ab, .km = &ab, .local_id = 1, .want = error.StructOpsMemberMismatch }, // `int` is no struct
    };
    for (cases, 0..) |c, ci| {
        const lb = try mtOpsBtf(gpa, c.lname, c.lm, c.lflag, false);
        defer gpa.free(lb);
        const kb = try mtOpsBtf(gpa, "ops", c.km, c.kflag, true);
        defer gpa.free(kb);
        var local = try btf_mod.parse(gpa, lb, .{});
        defer local.deinit();
        var kern = try btf_mod.parse(gpa, kb, .{});
        defer kern.deinit();
        if (c.want) |e| {
            testing.expectError(e, planStructOps(a, &local, c.local_id, &kern)) catch |err| {
                std.debug.print("plan case {d}\n", .{ci});
                return err;
            };
            continue;
        }
        const plan = try planStructOps(a, &local, c.local_id, &kern);
        try testing.expectEqual(@as(u32, 7), plan.value_type_id);
        try testing.expectEqual(@as(u32, 6), plan.kern_type_id);
        try testing.expectEqual(@as(u32, 72), plan.value_size);
        switch (ci) {
            0, 1 => {
                try testing.expectEqual(@as(usize, 2), plan.members.len);
                try testing.expectEqual(StructOpsMember{ .local_off = 0, .kern_off = 8, .size = 4, .kern_index = 0, .is_func = false }, plan.members[0]);
                try testing.expectEqual(StructOpsMember{ .local_off = 8, .kern_off = 16, .size = 8, .kern_index = 1, .is_func = true }, plan.members[1]);
            },
            else => { // the anonymous member is skipped, not matched against the kernel's names
                try testing.expectEqual(@as(usize, 1), plan.members.len);
                try testing.expectEqual(StructOpsMember{ .local_off = 4, .kern_off = 8, .size = 4, .kern_index = 0, .is_func = false }, plan.members[0]);
            },
        }
    }
}

test "mutation 2026-11-27: the kernel-layout value: bounds on both sides, the copied offsets, an absent program" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const initial = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const mk = struct {
        fn plan(al: std.mem.Allocator, m: StructOpsMember) !StructOpsPlan {
            return .{ .value_type_id = 1, .kern_type_id = 2, .value_size = 16, .members = try al.dupe(StructOpsMember, &.{m}) };
        }
    }.plan;
    // a scalar member: initial[4..8] goes to value[8..12], the rest stays zero
    const v = try buildStructOpsValue(a, try mk(a, .{ .local_off = 4, .kern_off = 8, .size = 4, .kern_index = 0, .is_func = false }), &initial, &.{}, &.{});
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 5, 6, 7, 8, 0, 0, 0, 0 }, v);
    const bad = [_]StructOpsMember{
        .{ .local_off = 100, .kern_off = 0, .size = 4, .kern_index = 0, .is_func = false }, // starts past the object's bytes
        .{ .local_off = 6, .kern_off = 0, .size = 4, .kern_index = 0, .is_func = false }, // ends past them
        .{ .local_off = 0, .kern_off = 100, .size = 4, .kern_index = 0, .is_func = false }, // starts past the value
        .{ .local_off = 0, .kern_off = 14, .size = 4, .kern_index = 0, .is_func = false }, // ends past it
    };
    for (bad) |m| try testing.expectError(error.StructOpsMemberMismatch, buildStructOpsValue(a, try mk(a, m), &initial, &.{}, &.{}));
    // a function pointer whose program is not in the list of fds
    const f: StructOpsMember = .{ .local_off = 0, .kern_off = 8, .size = 8, .kern_index = 0, .is_func = true };
    try testing.expectError(error.MapNotCreated, buildStructOpsValue(a, try mk(a, f), &initial, &.{.{ .member_off = 0, .program = 5 }}, &.{3}));
}

test "mutation 2026-11-27: load plans struct_ops maps and tells the programs which member they implement" {
    const gpa = testing.allocator;
    const blob = try structOpsKernelBlob(gpa, true, 16, false);
    defer gpa.free(blob);
    var kern = try btf_mod.parse(gpa, blob, .{});
    defer kern.deinit();
    const kt = kern.findByNameKind("tcp_congestion_ops", .@"struct").?;
    const Idx = struct { n: []const u8, idx: u16 };
    const idxs = [_]Idx{ .{ .n = "zl_cong_avoid", .idx = 0 }, .{ .n = "zl_ssthresh", .idx = 1 }, .{ .n = "zl_undo_cwnd", .idx = 2 } };
    {
        var o = try open(gpa, fx_struct_ops, .{});
        defer o.deinit();
        // load fails at the first privileged step; the planning has been done by then
        load(&o, .{ .load_btf = false, .core = false, .target_btf = &kern }) catch {};
        for (o.maps) |m| {
            const plan = m.struct_ops_plan.?;
            try testing.expectEqual(kt, plan.kern_type_id);
            try testing.expectEqual(kern.findByNameKind("bpf_struct_ops_tcp_congestion_ops", .@"struct").?, plan.value_type_id);
            try testing.expectEqual(@as(usize, 4), plan.members.len);
        }
        for (idxs) |x| {
            const p = o.findProgram(x.n).?;
            try testing.expectEqual(kt, p.attach_btf_id);
            const want: ?BPF.AttachType = @fromBackingInt(x.idx);
            try testing.expectEqual(want, p.expected_attach_type);
        }
        // the value is built once every program has an fd: with fake ones, for every struct_ops map among others
        for (o.programs, 0..) |*p, k| p.fd = @intCast(31 + k);
        defer for (o.programs) |*p| {
            p.fd = -1;
        };
        const orig = o.maps;
        const maps2 = try gpa.alloc(MapSpec, orig.len + 1);
        defer gpa.free(maps2);
        maps2[0] = .{ .name = "x", .map_type = .array, .origin = .legacy, .sec_idx = 0 };
        @memcpy(maps2[1..], orig);
        o.maps = maps2;
        defer o.maps = orig;
        try buildStructOpsValues(&o);
        const cc = o.findMap("zl_cc").?;
        try testing.expectEqual(@as(usize, 48), cc.struct_ops_value.len);
        const fdOf = struct {
            fn f(obj: *Object, name: []const u8) u64 {
                return @intCast(obj.findProgram(name).?.fd);
            }
        }.f;
        try testing.expectEqual(fdOf(&o, "zl_cong_avoid"), std.mem.readInt(u64, cc.struct_ops_value[8..16], .little));
        try testing.expectEqual(fdOf(&o, "zl_ssthresh"), std.mem.readInt(u64, cc.struct_ops_value[16..24], .little));
        try testing.expectEqual(fdOf(&o, "zl_undo_cwnd"), std.mem.readInt(u64, cc.struct_ops_value[24..32], .little));
        try testing.expectEqualStrings("zl_test", std.mem.sliceTo(cc.struct_ops_value[32..48], 0));
    }
    {
        // a relocation on a member that is not a function pointer implements nothing
        var o0 = try open(gpa, fx_struct_ops, .{});
        defer o0.deinit();
        const so = o0.image.findSection(".struct_ops").?;
        var ri: usize = 0;
        for (o0.image.sections, 0..) |s, i| {
            if (s.sh_type == elfsym.SHT_REL and s.sh_info == so) ri = i;
        }
        var at: ?usize = null;
        var k: u32 = 0;
        while (k < try o0.image.relocationCount(ri)) : (k += 1) {
            if ((try o0.image.relocation(ri, k)).r_offset == 32) at = @intCast(o0.image.sections[ri].sh_offset + k * 16);
        }
        const copy = try gpa.dupe(u8, fx_struct_ops);
        defer gpa.free(copy);
        std.mem.writeInt(u64, copy[at.?..][0..8], 0, .little);
        var o = try open(gpa, copy, .{});
        defer o.deinit();
        load(&o, .{ .load_btf = false, .core = false, .target_btf = &kern }) catch {};
        const p = o.findProgram("zl_cong_avoid").?;
        try testing.expectEqual(@as(u32, 0), p.attach_btf_id);
        try testing.expectEqual(@as(?BPF.AttachType, null), p.expected_attach_type);
        try testing.expectEqual(kt, o.findProgram("zl_ssthresh").?.attach_btf_id);
    }
    {
        // a struct_ops program that no map uses has no attach target and is not loaded
        var o = try open(gpa, fx_struct_ops, .{});
        defer o.deinit();
        o.maps = &.{};
        try load(&o, .{ .load_btf = false, .core = false });
        for (o.programs) |p| try testing.expectEqual(@as(linux.fd_t, -1), p.fd);
    }
}

fn mtUint(r: *RawB, gpa: std.mem.Allocator, int4: u32, v: u32) !u32 {
    const arr = try r.rec(gpa, 0, btf_mod.K_ARRAY, 0, false, 0, &.{ int4, int4, v });
    return r.rec(gpa, 0, btf_mod.K_PTR, 0, false, arr, &.{});
}

const MtMapCase = enum {
    key_proto,
    entries_proto,
    key_huge,
    mim_ok,
    mim_elem_int,
    prog_elem_struct,
    prog_ok,
    array_with_values,
    nested_values,
    void_elem,
    elem_proto,
};

/// An object whose `.maps` holds one variable `m1`, a map definition shaped by `c`.
fn mtMapCaseObject(gpa: std.mem.Allocator, c: MtMapCase) ![]u8 {
    var r = try RawB.init(gpa);
    defer r.deinit(gpa);
    const n_type = try r.str(gpa, "type");
    const n_max = try r.str(gpa, "max_entries");
    const n_ks = try r.str(gpa, "key_size");
    const n_vs = try r.str(gpa, "value_size");
    const n_key = try r.str(gpa, "key");
    const n_values = try r.str(gpa, "values");
    const int4 = try r.rec(gpa, 0, btf_mod.K_INT, 0, false, 4, &.{32});
    const proto = try r.rec(gpa, 0, btf_mod.K_FUNC_PROTO, 0, false, 0, &.{});
    const proto_int = try r.rec(gpa, 0, btf_mod.K_FUNC_PROTO, 0, false, int4, &.{});
    const arr7 = try r.rec(gpa, 0, btf_mod.K_ARRAY, 0, false, 0, &.{ int4, int4, 7 });
    const proto_arr = try r.rec(gpa, 0, btf_mod.K_FUNC_PROTO, 0, false, arr7, &.{});
    const huge = try r.rec(gpa, 0, btf_mod.K_ARRAY, 0, false, 0, &.{ int4, int4, 0x4000_0001 });
    const huge_ptr = try r.rec(gpa, 0, btf_mod.K_PTR, 0, false, huge, &.{});
    const t2 = try mtUint(&r, gpa, int4, 2);
    const t3 = try mtUint(&r, gpa, int4, 3);
    const t4 = try mtUint(&r, gpa, int4, 4);
    const t8 = try mtUint(&r, gpa, int4, 8);
    const t12 = try mtUint(&r, gpa, int4, 12);
    const inner = try r.rec(gpa, 0, btf_mod.K_STRUCT, 4, false, 32, &.{ n_type, t2, 0, n_ks, t4, 64, n_vs, t4, 128, n_max, t8, 192 });
    // an inner definition that itself has `values`
    const proto_ptr = try r.rec(gpa, 0, btf_mod.K_PTR, 0, false, proto, &.{});
    const pp_arr = try r.rec(gpa, 0, btf_mod.K_ARRAY, 0, false, 0, &.{ proto_ptr, int4, 0 });
    const inner2 = try r.rec(gpa, 0, btf_mod.K_STRUCT, 2, false, 16, &.{ n_type, t3, 0, n_values, pp_arr, 64 });
    const proto_inner = try r.rec(gpa, 0, btf_mod.K_FUNC_PROTO, 0, false, inner, &.{});

    const map_type: u32 = switch (c) {
        .prog_elem_struct, .prog_ok => t3,
        .array_with_values => t2,
        else => t12,
    };
    const target: u32 = switch (c) {
        .mim_ok, .prog_elem_struct => inner,
        .mim_elem_int => int4,
        .prog_ok, .array_with_values => proto,
        .nested_values => inner2,
        else => 0,
    };
    const elem: u32 = if (c == .elem_proto) proto_inner else try r.rec(gpa, 0, btf_mod.K_PTR, 0, false, target, &.{});
    const vals = try r.rec(gpa, 0, btf_mod.K_ARRAY, 0, false, 0, &.{ elem, int4, 0 });
    const st = switch (c) {
        .key_proto => try r.rec(gpa, 0, btf_mod.K_STRUCT, 1, false, 8, &.{ n_key, proto_int, 0 }),
        .entries_proto => try r.rec(gpa, 0, btf_mod.K_STRUCT, 1, false, 8, &.{ n_max, proto_arr, 0 }),
        .key_huge => try r.rec(gpa, 0, btf_mod.K_STRUCT, 1, false, 8, &.{ n_key, huge_ptr, 0 }),
        else => try r.rec(gpa, 0, btf_mod.K_STRUCT, 3, false, 24, &.{ n_type, map_type, 0, n_max, t4, 64, n_values, vals, 128 }),
    };
    const v = try r.rec(gpa, try r.str(gpa, "m1"), btf_mod.K_VAR, 0, false, st, &.{1});
    _ = try r.rec(gpa, try r.str(gpa, ".maps"), btf_mod.K_DATASEC, 1, false, 8, &.{ v, 0, 8 });
    const blob = try r.finish(gpa);
    defer gpa.free(blob);
    var b = ObjB.init(gpa);
    defer b.deinit();
    const zeros: [8]u8 = @splat(0);
    _ = try b.sec(.{ .name = ".maps", .ty = 1, .flags = 3, .data = &zeros });
    _ = try b.sec(.{ .name = ".BTF", .ty = 1, .data = blob });
    return b.build();
}

test "mutation 2026-11-27: map-in-map and prog_array definitions: the inner map, and every shape that is refused" {
    const gpa = testing.allocator;
    {
        const bytes = try mtMapCaseObject(gpa, .mim_ok);
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        const m = o.maps[0];
        try testing.expectEqual(BPF.MapType.array_of_maps, m.map_type);
        try testing.expectEqual(@as(u32, 4), m.max_entries);
        try testing.expect(m.has_values);
        try testing.expectEqual(@as(u32, 16), m.values_off);
        const inner = m.inner.?;
        try testing.expectEqual(BPF.MapType.array, inner.map_type);
        try testing.expectEqual(@as(u32, 4), inner.key_size);
        try testing.expectEqual(@as(u32, 4), inner.value_size);
        try testing.expectEqual(@as(u32, 8), inner.max_entries);
        try testing.expectEqual(MapOrigin.btf_defined, inner.origin);
        try testing.expect(!inner.has_values);
    }
    {
        const bytes = try mtMapCaseObject(gpa, .prog_ok);
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        try testing.expectEqual(BPF.MapType.prog_array, o.maps[0].map_type);
        try testing.expect(o.maps[0].has_values);
        try testing.expect(o.maps[0].inner == null);
    }
    for ([_]MtMapCase{ .key_proto, .entries_proto, .key_huge, .mim_elem_int, .prog_elem_struct, .array_with_values, .nested_values, .void_elem, .elem_proto }) |c| {
        const bytes = try mtMapCaseObject(gpa, c);
        defer gpa.free(bytes);
        testing.expectError(error.MalformedMapDefinition, open(gpa, bytes, .{})) catch |e| {
            std.debug.print("map case {s}\n", .{@tagName(c)});
            return e;
        };
    }
}

// ── relocations that make calls ──

/// An XDP section `xdp` (section 1), a `.text` (section 2) and a `.relxdp` with at most one entry against symbol 1 (`gf`).
fn mtCallObject(gpa: std.mem.Allocator, xdp: []const u8, text: []const u8, rel: ?MtOpsRel, gf: ObjB.Sym, extra: []const ObjB.Sym) ![]u8 {
    var b = ObjB.init(gpa);
    defer b.deinit();
    const px = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = xdp });
    _ = try b.sec(.{ .name = ".text", .ty = 1, .flags = ObjB.EXEC, .data = text });
    var relb: [16]u8 = undefined;
    if (rel) |x| {
        std.mem.writeInt(u64, relb[0..8], x.off, .little);
        std.mem.writeInt(u64, relb[8..16], (@as(u64, x.sym) << 32) | x.typ, .little);
        _ = try b.sec(.{ .name = ".relxdp", .ty = elfsym.SHT_REL, .data = &relb, .link = ObjB.SYMTAB_LINK, .info = px, .entsize = 16 });
    }
    _ = try b.sym(gf);
    for (extra) |s| _ = try b.sym(s);
    return b.build();
}

fn mtMov(imm: i32) [8]u8 {
    return ins8(0xb7, 0, 0, imm);
}

test "mutation 2026-11-27: calls and function addresses: what the relocation may sit on, where it points, and what it refuses" {
    const gpa = testing.allocator;
    const text = cat(.{ mtMov(7), I_EXIT, mtMov(9), I_EXIT });
    const other: ObjB.Sym = .{ .name = "other", .info = FUNC_SYM, .shndx = 2, .value = 0, .size = 16 };
    const gf: ObjB.Sym = .{ .name = "gf", .info = FUNC_SYM, .shndx = 2, .value = 16, .size = 16 };
    const call = comptime ins8(0x85, 0x10, 0, -1);
    // a call to the global function `gf`: appended once, the call patched to reach it
    {
        const xdp = cat(.{ call, I_EXIT });
        const bytes = try mtCallObject(gpa, &xdp, &text, .{ .off = 0, .sym = 1, .typ = R_BPF_64_32 }, gf, &.{other});
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        const p = o.programs[0];
        try testing.expectEqual(@as(usize, 4), p.insns.len);
        try testing.expectEqual(BPF_PSEUDO_CALL, p.insns[0].src);
        try testing.expectEqual(@as(i32, 1), p.insns[0].imm);
        try testing.expectEqual(@as(i32, 9), p.insns[2].imm);
    }
    // the address of `gf` as a callback: the symbol's value, not the instruction's immediate, names the function
    {
        const xdp = cat(.{ I_LD64, I_LD64_HI, I_EXIT });
        const bytes = try mtCallObject(gpa, &xdp, &text, .{ .off = 0, .sym = 1, .typ = R_BPF_64_64 }, gf, &.{other});
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        const p = o.programs[0];
        try testing.expectEqual(@as(usize, 5), p.insns.len);
        try testing.expectEqual(BPF_PSEUDO_FUNC, p.insns[0].src);
        try testing.expectEqual(@as(i32, 2), p.insns[0].imm);
        try testing.expectEqual(@as(i32, 9), p.insns[3].imm);
    }
    // a static call: the section symbol, the offset in the instruction's immediate
    {
        const text6 = cat(.{ I_MOV0, I_EXIT, I_MOV0, I_EXIT, mtMov(5), I_EXIT });
        const xdp = cat(.{ ins8(0x85, 0x10, 0, 3), I_EXIT });
        const bytes = try mtCallObject(gpa, &xdp, &text6, .{ .off = 0, .sym = 1, .typ = R_BPF_64_32 }, .{ .name = "", .info = SEC_SYM, .shndx = 2, .value = 0 }, &.{
            .{ .name = "pad", .info = FUNC_SYM, .shndx = 2, .value = 0, .size = 32 },
            .{ .name = "sub", .info = FUNC_SYM, .shndx = 2, .value = 32, .size = 16 },
        });
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        const p = o.programs[0];
        try testing.expectEqual(@as(usize, 4), p.insns.len);
        try testing.expectEqual(@as(i32, 1), p.insns[0].imm);
        try testing.expectEqual(@as(i32, 5), p.insns[2].imm);
    }
    const Case = struct { insn: [8]u8 = call, sym: ObjB.Sym = gf, want: anyerror };
    const cases = [_]Case{
        .{ .insn = ins8(0xb7, 0x10, 0, -1), .want = error.UnsupportedRelocation }, // a call relocation on a mov
        .{ .insn = ins8(0x85, 0x00, 0, -1), .want = error.UnsupportedRelocation }, // on a helper call
        .{ .sym = .{ .name = "gf", .info = FUNC_SYM, .shndx = 0x4000, .value = 16, .size = 16 }, .want = error.MalformedElf },
        .{ .insn = ins8(0x85, 0x10, 0, -100), .sym = .{ .name = "", .info = SEC_SYM, .shndx = 2, .value = 0 }, .want = error.RelocationOutOfRange }, // before the section
        .{ .insn = ins8(0x85, 0x10, 0, 1), .sym = .{ .name = "gf", .info = OBJ_SYM, .shndx = 2, .value = 0xFFFF_FFFF_FFFF_FFF8 }, .want = error.RelocationOutOfRange }, // byte offset overflows u64
    };
    for (cases, 0..) |c, ci| {
        const xdp = flatIns(2, .{ c.insn, I_EXIT });
        const bytes = try mtCallObject(gpa, &xdp, &text, .{ .off = 0, .sym = 1, .typ = R_BPF_64_32 }, c.sym, &.{other});
        defer gpa.free(bytes);
        testing.expectError(c.want, open(gpa, bytes, .{})) catch |e| {
            std.debug.print("call case {d}\n", .{ci});
            return e;
        };
    }
}

test "mutation 2026-11-27: calls between functions of one section have no relocation: sibling targets are linked, the rest left alone" {
    const gpa = testing.allocator;
    const mk = struct {
        fn obj(g: std.mem.Allocator, xdp: []const u8, funcs: []const ObjB.Sym) ![]u8 {
            var b = ObjB.init(g);
            defer b.deinit();
            _ = try b.sec(.{ .name = "xdp", .ty = 1, .flags = ObjB.EXEC, .data = xdp });
            for (funcs) |f| _ = try b.sym(f);
            return b.build();
        }
    }.obj;
    // f2 (at 2) calls f1 (at 0): the target is outside f2, inside the section, so f1 is appended to f2
    {
        const xdp = cat(.{ mtMov(7), I_EXIT, ins8(0x85, 0x10, 0, -3), I_EXIT });
        const bytes = try mk(gpa, &xdp, &.{
            .{ .name = "f1", .info = FUNC_SYM, .shndx = 1, .value = 0, .size = 16 },
            .{ .name = "f2", .info = FUNC_SYM, .shndx = 1, .value = 16, .size = 16 },
        });
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        try testing.expectEqual(@as(usize, 2), o.programs[0].insns.len);
        const f2 = o.findProgram("f2").?;
        try testing.expectEqual(@as(usize, 4), f2.insns.len);
        try testing.expectEqual(@as(i32, 1), f2.insns[0].imm); // f1 sits at 2: 2 - 0 - 1
        try testing.expectEqual(@as(i32, 7), f2.insns[2].imm);
    }
    // a register move whose source register happens to be 1 is no call, whatever its immediate says
    {
        const xdp = cat(.{ ins8(0xbf, 0x10, 0, 40), I_EXIT });
        const bytes = try mk(gpa, &xdp, &.{});
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        try testing.expectEqual(@as(usize, 2), o.programs[0].insns.len);
        try testing.expectEqual(@as(i32, 40), o.programs[0].insns[0].imm);
    }
    // a call to the function's own first instruction (a hand-written object) stays as written
    {
        const xdp = cat(.{ ins8(0x85, 0x10, 0, -1), I_EXIT });
        const bytes = try mk(gpa, &xdp, &.{});
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        try testing.expectEqual(@as(usize, 2), o.programs[0].insns.len);
        try testing.expectEqual(@as(i32, -1), o.programs[0].insns[0].imm);
    }
    // a target before the section
    {
        const xdp = cat(.{ ins8(0x85, 0x10, 0, -5), I_EXIT });
        const bytes = try mk(gpa, &xdp, &.{});
        defer gpa.free(bytes);
        try testing.expectError(error.RelocationOutOfRange, open(gpa, bytes, .{}));
    }
}

/// True where creating a map is refused for lack of privilege (EPERM before any argument is looked at).
fn mtBpfRefused() bool {
    var m: MapSpec = .{ .name = "probe", .map_type = .array, .origin = .legacy, .sec_idx = 0, .key_size = 4, .value_size = 4, .max_entries = 1 };
    if (createMap(&m, 0, 0)) |fd| {
        _ = linux.close(fd);
        return false;
    } else |e| return e == error.PermissionDenied;
}

fn mtBlob(gpa: std.mem.Allocator, name: []const u8, kind: u5) ![]u8 {
    var r = try RawB.init(gpa);
    defer r.deinit(gpa);
    const n_int = try r.str(gpa, "int");
    const n = try r.str(gpa, name);
    const int4 = try r.rec(gpa, n_int, btf_mod.K_INT, 0, false, 4, &.{32});
    const proto = try r.rec(gpa, 0, btf_mod.K_FUNC_PROTO, 0, false, 0, &.{});
    if (kind == btf_mod.K_VAR) {
        _ = try r.rec(gpa, n, btf_mod.K_VAR, 0, false, int4, &.{1});
    } else {
        _ = try r.rec(gpa, n, btf_mod.K_FUNC, 1, false, proto, &.{});
    }
    return r.finish(gpa);
}

test "mutation 2026-11-27: module BTFs: lookup by name and kind, the fd_array positions, which fds are kept" {
    const gpa = testing.allocator;
    var o = try open(gpa, fx_xdp_pass, .{});
    defer o.deinit();
    var mb: ModuleBtfs = .{};
    // 0: func kv, 1: var kv, 2: func kg
    const spec = [_]struct { name: []const u8, kind: u5 }{
        .{ .name = "kv", .kind = btf_mod.K_FUNC },
        .{ .name = "kv", .kind = btf_mod.K_VAR },
        .{ .name = "kg", .kind = btf_mod.K_FUNC },
    };
    var fds: [3]linux.fd_t = undefined;
    for (spec, 0..) |s, i| {
        const blob = try mtBlob(gpa, s.name, s.kind);
        const parsed = try btf_mod.parse(gpa, blob, .{ .own_bytes = true });
        fds[i] = @intCast(linux.dup(0));
        try mb.entries.append(gpa, .{ .fd = fds[i], .btf = parsed });
    }
    {
        // after a failed lookup nothing is marked used
        try testing.expect(mb.find("zz", .func) == null);
        try testing.expect(mb.find("kv", .datasec) == null);
        for (mb.entries.items) |e| try testing.expect(!e.used);
    }
    const kv = mb.find("kv", .@"var").?; // the var, not the function of the same name
    try testing.expectEqual(@as(u16, 2), kv.fd_index);
    try testing.expectEqual(@as(u32, 3), kv.id);
    try testing.expect(!mb.entries.items[0].used and mb.entries.items[1].used and !mb.entries.items[2].used);
    const kg = mb.find("kg", .func).?; // the last type of the last entry
    try testing.expectEqual(@as(u16, 3), kg.fd_index);
    try testing.expect(mb.entries.items[2].used);

    try mb.commit(&o);
    try testing.expectEqualSlices(i32, &.{ 0, 0, fds[1], fds[2] }, o.fd_array);
    try testing.expectEqualSlices(linux.fd_t, &.{ fds[1], fds[2] }, o.module_btf_fds);
    try testing.expectEqual(fds[0], mb.entries.items[0].fd);
    try testing.expectEqual(@as(linux.fd_t, -1), mb.entries.items[1].fd);
    try testing.expectEqual(@as(linux.fd_t, -1), mb.entries.items[2].fd);
    for (o.module_btf_fds) |f| _ = linux.close(f);
    o.module_btf_fds = &.{};
    mb.deinit(&o); // closes the one fd that was not kept, frees every BTF
    try testing.expect(linux.errno(linux.fcntl(fds[0], linux.F.GETFD, 0)) == .BADF);

    // nothing used: nothing is published
    var none: ModuleBtfs = .{};
    const blob = try mtBlob(gpa, "kv", btf_mod.K_VAR);
    const parsed = try btf_mod.parse(gpa, blob, .{ .own_bytes = true });
    try none.entries.append(gpa, .{ .fd = -1, .btf = parsed });
    var o2 = try open(gpa, fx_xdp_pass, .{});
    defer o2.deinit();
    try none.commit(&o2);
    try testing.expectEqual(@as(usize, 0), o2.fd_array.len);
    try testing.expectEqual(@as(usize, 0), o2.module_btf_fds.len);
    none.deinit(&o2);
}

test "mutation 2026-11-27: kernel externs are resolved by name and kind, type-checked, and patched into the instructions" {
    const gpa = testing.allocator;
    const kb = try mtKernBtf(gpa, false, false);
    defer gpa.free(kb);
    var kern = try btf_mod.parse(gpa, kb, .{});
    defer kern.deinit();
    const code = cat(.{ I_LD64, I_LD64_HI, I_CALL, I_EXIT });
    const bytes = try mtExtObject(gpa, &code, &.{
        .{ .off = 0, .sym = .ksym_i, .typ = R_BPF_64_64 },
        .{ .off = 16, .sym = .kfn, .typ = R_BPF_64_32 },
    }, .{ .no_kconfig = true });
    defer gpa.free(bytes);
    var o = try open(gpa, bytes, .{});
    defer o.deinit();
    // ksym_i, ksym_void (typeless, weak), kfn
    try testing.expectEqual(@as(usize, 3), o.externs.len);
    try resolveKernelExterns(&o, &kern, .{ .search_modules = false });
    try testing.expect(o.externs[0].resolved);
    try testing.expectEqual(kern.findByNameKind("ksym_i", .@"var").?, o.externs[0].kernel_btf_id);
    try testing.expect(o.externs[2].resolved);
    try testing.expectEqual(kern.findByNameKind("kfn", .func).?, o.externs[2].kernel_btf_id);
    // typeless means kallsyms, even though the kernel BTF has a variable of that name
    try testing.expect(!o.externs[1].resolved);
    // and a strong one that kallsyms lacks is an error
    o.externs[1].weak = false;
    try testing.expectError(error.ExternNotFound, resolveKernelExterns(&o, &kern, .{ .search_modules = false }));
    o.externs[1].weak = true;
    // a symbol kallsyms does list (when it is readable at all) resolves by address
    if (elfsym.readFileStreaming(gpa, "/proc/kallsyms", 64 << 20)) |ks| {
        defer gpa.free(ks);
        if (kconfig_mod.kallsymsAddress(ks, "init_task")) |addr| {
            o.externs[1].name = "init_task";
            try resolveKernelExterns(&o, &kern, .{ .search_modules = false });
            try testing.expect(o.externs[1].resolved);
            try testing.expectEqual(addr, o.externs[1].addr);
        }
    } else |_| {}
    // a kernel variable of another kind does not match the declaration
    const kb8 = try mtKernBtf(gpa, true, false);
    defer gpa.free(kb8);
    var kern8 = try btf_mod.parse(gpa, kb8, .{});
    defer kern8.deinit();
    try testing.expectError(error.ExternTypeMismatch, resolveKernelExterns(&o, &kern8, .{ .search_modules = false }));
    // a strong extern the kernel lacks
    o.externs[2].name = "no_such_kfunc";
    o.externs[2].weak = false;
    try testing.expectError(error.ExternNotFound, resolveKernelExterns(&o, &kern, .{ .search_modules = false }));
}

fn mtSetRefs(p: *ProgramSpec, buf: *[2]ExternRef, refs: []const ExternRef) void {
    @memcpy(buf[0..refs.len], refs);
    p.extern_refs = buf[0..refs.len];
}

test "mutation 2026-11-27: patchExterns writes each reference its own fields and refuses what is not an instruction of the right shape" {
    var ld = [_]Insn{
        .{ .code = 0x18, .dst = 0, .src = BPF_PSEUDO_MAP_VALUE, .off = 0, .imm = 99 },
        .{ .code = 0, .dst = 0, .src = 0, .off = 0, .imm = 99 },
        .{ .code = 0x85, .dst = 0, .src = 0, .off = 0, .imm = -1 },
        .{ .code = 0x95, .dst = 0, .src = 0, .off = 0, .imm = 0 },
    };
    const base = Extern{ .name = "x", .kind = .ksym_var, .weak = false, .btf_id = 0, .type_id = 0 };
    var ex = [_]Extern{ base, base, base };
    ex[0].resolved = true;
    ex[0].kernel_btf_id = 77;
    ex[0].fd_index = 3;
    ex[1].kind = .ksym_func;
    ex[1].resolved = true;
    ex[1].kernel_btf_id = 55;
    ex[1].fd_index = 5;
    ex[2].typeless = true;
    ex[2].resolved = true;
    ex[2].addr = 0x1122_3344_5566_7788;
    var p = mtSpec("p", 1, &ld);
    var refbuf: [2]ExternRef = undefined;
    mtSetRefs(&p, &refbuf, &.{ .{ .insn_idx = 0, .extern_idx = 0, .call = false }, .{ .insn_idx = 2, .extern_idx = 1, .call = true } });
    try patchExterns(&p, &ex);
    try testing.expectEqual(BPF_PSEUDO_BTF_ID, ld[0].src);
    try testing.expectEqual(@as(i32, 77), ld[0].imm);
    try testing.expectEqual(@as(i32, 3), ld[1].imm);
    try testing.expectEqual(BPF_PSEUDO_KFUNC_CALL, ld[2].src);
    try testing.expectEqual(@as(i32, 55), ld[2].imm);
    try testing.expectEqual(@as(i16, 5), ld[2].off);
    // typeless and resolved: the address in both halves, the pseudo marker gone
    ld[0].src = BPF_PSEUDO_MAP_VALUE;
    mtSetRefs(&p, &refbuf, &.{.{ .insn_idx = 0, .extern_idx = 2, .call = false }});
    try patchExterns(&p, &ex);
    try testing.expectEqual(@as(u4, 0), ld[0].src);
    try testing.expectEqual(@as(i32, 0x55667788), ld[0].imm);
    try testing.expectEqual(@as(i32, 0x11223344), ld[1].imm);
    // unresolved: a zero constant, or a call to an id no helper has
    ex[2].resolved = false;
    ex[2].addr = 5; // not used while unresolved
    ld[0].src = BPF_PSEUDO_MAP_VALUE;
    try patchExterns(&p, &ex);
    try testing.expectEqual(@as(u4, 0), ld[0].src);
    try testing.expectEqual(@as(i32, 0), ld[0].imm);
    try testing.expectEqual(@as(i32, 0), ld[1].imm);
    ex[1].resolved = false;
    ld[2].src = BPF_PSEUDO_CALL;
    mtSetRefs(&p, &refbuf, &.{.{ .insn_idx = 2, .extern_idx = 1, .call = true }});
    try patchExterns(&p, &ex);
    try testing.expectEqual(@as(u4, 0), ld[2].src);
    try testing.expectEqual(poison_call_kfunc_base + 1, ld[2].imm);
    // refusals
    mtSetRefs(&p, &refbuf, &.{.{ .insn_idx = 4, .extern_idx = 0, .call = false }});
    try testing.expectError(error.RelocationOutOfRange, patchExterns(&p, &ex));
    mtSetRefs(&p, &refbuf, &.{.{ .insn_idx = 0, .extern_idx = 3, .call = false }});
    try testing.expectError(error.RelocationOutOfRange, patchExterns(&p, &ex));
    mtSetRefs(&p, &refbuf, &.{.{ .insn_idx = 0, .extern_idx = 1, .call = true }}); // a call on an LD_IMM64
    try testing.expectError(error.NotAnImmediateLoad, patchExterns(&p, &ex));
    mtSetRefs(&p, &refbuf, &.{.{ .insn_idx = 2, .extern_idx = 0, .call = false }}); // a load on a call
    try testing.expectError(error.NotAnImmediateLoad, patchExterns(&p, &ex));
    ld[3].code = 0x18;
    mtSetRefs(&p, &refbuf, &.{.{ .insn_idx = 3, .extern_idx = 0, .call = false }}); // an LD_IMM64 with no second half
    try testing.expectError(error.RelocationOutOfRange, patchExterns(&p, &ex));
}

test "mutation 2026-11-27: load fills the kconfig seed, resolves the ksyms and patches the instructions before it fails" {
    const gpa = testing.allocator;
    const kb = try mtKernBtf(gpa, false, false);
    defer gpa.free(kb);
    var kern = try btf_mod.parse(gpa, kb, .{});
    defer kern.deinit();
    const opts: LoadOptions = .{
        .load_btf = false,
        .core = false,
        .target_btf = &kern,
        .kconfig = "CONFIG_A=5\nCONFIG_B=7\n",
        .kernel_version = 0x010203,
        .search_modules = false,
    };
    {
        const code = cat(.{ I_LD64, I_LD64_HI, I_LD64, I_LD64_HI, I_CALL, I_EXIT });
        const bytes = try mtExtObject(gpa, &code, &.{
            .{ .off = 0, .sym = .config_b, .typ = R_BPF_64_64 },
            .{ .off = 16, .sym = .ksym_i, .typ = R_BPF_64_64 },
            .{ .off = 32, .sym = .kfn, .typ = R_BPF_64_32 },
        }, .{});
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        load(&o, opts) catch {}; // the first map creation is where an unprivileged load stops
        const d = o.maps[0].initial_data;
        try testing.expectEqual(@as(u32, 0x010203), std.mem.readInt(u32, d[0..4], .little));
        try testing.expectEqual(@as(u32, 5), std.mem.readInt(u32, d[4..8], .little));
        try testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, d[8..12], .little));
        try testing.expect(o.externs[3].resolved); // ksym_i
        try testing.expect(o.externs[5].resolved); // kfn
    }
    {
        // with no maps to create, the program's instructions are patched before its load is attempted
        const code = cat(.{ I_LD64, I_LD64_HI, I_CALL, I_EXIT });
        const bytes = try mtExtObject(gpa, &code, &.{
            .{ .off = 0, .sym = .ksym_i, .typ = R_BPF_64_64 },
            .{ .off = 16, .sym = .kfn, .typ = R_BPF_64_32 },
        }, .{ .no_kconfig = true });
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        load(&o, opts) catch {};
        const p = o.programs[0];
        try testing.expectEqual(BPF_PSEUDO_BTF_ID, p.insns[0].src);
        try testing.expectEqual(BPF_PSEUDO_KFUNC_CALL, p.insns[2].src);
    }
    {
        // a map relocation with no map behind it is refused before the program is loaded
        const code = cat(.{ I_LD64, I_LD64_HI, I_EXIT });
        const bytes = try mtExtObject(gpa, &code, &.{.{ .off = 0, .sym = .config_b, .typ = R_BPF_64_64 }}, .{});
        defer gpa.free(bytes);
        var o = try open(gpa, bytes, .{});
        defer o.deinit();
        o.maps = &.{};
        try testing.expectError(error.MapNotCreated, load(&o, opts));
    }
}

test "mutation 2026-11-27: creating maps: inner templates, initial slots, and the one errno that can be provoked" {
    const gpa = testing.allocator;
    var m: MapSpec = .{ .name = "outer", .map_type = .array_of_maps, .origin = .legacy, .sec_idx = 0, .max_entries = 1, .key_size = 4, .value_size = 4 };
    try testing.expectError(error.InvalidArgument, createMapWithInner(&m)); // an outer map with no inner definition
    var inner: MapSpec = .{ .name = "i", .map_type = .array, .origin = .legacy, .sec_idx = 0, .key_size = 4, .value_size = 4 };
    m.inner = &inner;
    try testing.expectError(error.ZeroMaxEntries, createMapWithInner(&m));
    try testing.expectError(error.StructOpsTypeNotFound, createStructOpsMap(&m));
    if (mtBpfRefused()) {
        inner.map_type = .sk_storage; // a type that legitimately has no entries: the kernel decides, not this check
        if (createMapWithInner(&m)) |fd| {
            _ = linux.close(fd);
        } else |e| try testing.expect(e == error.InvalidArgument or e == error.PermissionDenied);
        const plan: StructOpsPlan = .{ .value_type_id = 1, .kern_type_id = 2, .value_size = 8, .members = &.{} };
        var so: MapSpec = .{ .name = "so", .map_type = .struct_ops, .origin = .struct_ops, .sec_idx = 0, .struct_ops_plan = plan };
        if (createStructOpsMap(&so)) |fd| {
            _ = linux.close(fd);
        } else |e| try testing.expect(e == error.InvalidArgument or e == error.PermissionDenied);
    }

    // initial slots: a reused map keeps what it has, a missing target is refused, a failing update is an error
    var o = try open(gpa, fx_xdp_pass, .{});
    defer o.deinit();
    const orig = o.maps;
    const progs = o.programs;
    var maps2 = [_]MapSpec{
        .{ .name = "outer", .map_type = .array_of_maps, .origin = .legacy, .sec_idx = 0, .fd = 0, .init_slots = &.{.{ .index = 0, .target = .{ .map = 1 } }} },
        .{ .name = "t", .map_type = .array, .origin = .legacy, .sec_idx = 0, .fd = -1 },
    };
    o.maps = &maps2;
    defer o.maps = orig;
    maps2[0].reused = true;
    try fillInitSlots(&o); // reused: untouched, though the target has no fd
    maps2[0].reused = false;
    try testing.expectError(error.MapNotCreated, fillInitSlots(&o));
    maps2[1].fd = 0;
    try testing.expectError(error.MapUpdateFailed, fillInitSlots(&o)); // fd 0 is no map: the update fails
    maps2[0].init_slots = &.{.{ .index = 0, .target = .{ .program = 0 } }};
    maps2[1].fd = 0;
    try testing.expect(progs[0].fd == -1);
    try testing.expectError(error.MapNotCreated, fillInitSlots(&o)); // the program has no fd, whatever the map at that index has
}

test "mutation 2026-11-27: pinning: where a pin is looked for, and what is refused before any syscall" {
    if (!mtBpfRefused()) return error.SkipZigTest;
    const gpa = testing.allocator;
    const big = try gpa.alloc(u8, 5000);
    defer gpa.free(big);
    @memset(big, 'a');
    var defs: [20]u8 = @splat(0);
    std.mem.writeInt(u32, defs[0..4], 2, .little);
    std.mem.writeInt(u32, defs[4..8], 4, .little);
    std.mem.writeInt(u32, defs[8..12], 4, .little);
    std.mem.writeInt(u32, defs[12..16], 1, .little);
    var b = ObjB.init(gpa);
    defer b.deinit();
    const ms = try b.sec(.{ .name = "maps", .ty = 1, .flags = 3, .data = &defs });
    _ = try b.sym(.{ .name = "m1", .info = OBJ_SYM, .shndx = ms, .value = 0 });
    var o = try openObj(&b, .{});
    defer o.deinit();
    // an explicit pin path too long to name: refused as an invalid argument, whatever `pinning` says
    o.maps[0].pin_path = big;
    try testing.expectError(error.InvalidArgument, load(&o, .{ .load_btf = false }));
    o.maps[0].pin_path = "";
    // no pinning requested: the pin root is never looked at
    try testing.expectError(error.PermissionDenied, load(&o, .{ .load_btf = false, .pin_root = big }));
    // by name: the path is `<root>/<name>`, which is too long here
    o.maps[0].pinning = 1;
    try testing.expectError(error.InvalidArgument, load(&o, .{ .load_btf = false, .pin_root = big }));
    // by name, a short path: looking it up needs bpf()
    try testing.expectError(error.PermissionDenied, load(&o, .{ .load_btf = false, .pin_root = "/ebpf-mt-no-bpffs" }));
    o.close();
    o.maps[0].pinning = 0;
    o.maps[0].pin_path = "/ebpf-mt-no-bpffs/m1";
    try testing.expectError(error.PermissionDenied, load(&o, .{ .load_btf = false }));
    o.close();
    // a path whose parent is not a directory is none of the answered errnos: a failed pin lookup
    o.maps[0].pin_path = "/dev/null/m1";
    if (load(&o, .{ .load_btf = false })) |_| {
        return error.TestUnexpectedResult;
    } else |e| try testing.expect(e == error.PinFailed or e == error.PermissionDenied);
    o.close();
    // an internal data map is never pinned by name
    var ro = try open(gpa, fx_rodata_const, .{});
    defer ro.deinit();
    for (ro.maps) |*m| m.pinning = 1;
    try testing.expectError(error.PermissionDenied, load(&ro, .{ .load_btf = false, .pin_root = big }));
}

test "mutation 2026-11-27: attaching a struct_ops map reports the errno of the registration" {
    const gpa = testing.allocator;
    var o = try open(gpa, fx_struct_ops, .{});
    defer o.deinit();
    var value: [8]u8 = @splat(0);
    for (o.maps) |*m| {
        m.fd = 0; // not a map: the kernel answers EBADF / EINVAL (or EPERM where bpf() is refused outright)
        m.struct_ops_value = &value;
    }
    defer for (o.maps) |*m| {
        m.fd = -1;
        m.struct_ops_value = &.{};
    };
    if (o.attachStructOps("zl_cc")) |_| {
        return error.TestUnexpectedResult;
    } else |e| try testing.expect(e == error.InvalidArgument or e == error.PermissionDenied);
}

test "mutation 2026-11-27: a DATASEC fixup refuses a section the BTF cannot size" {
    const gpa = testing.allocator;
    var r = try RawB.init(gpa);
    defer r.deinit(gpa);
    const n_int = try r.str(gpa, "int");
    const n_v = try r.str(gpa, "v");
    const n_s = try r.str(gpa, ".custom");
    const int4 = try r.rec(gpa, n_int, btf_mod.K_INT, 0, false, 4, &.{32});
    const v = try r.rec(gpa, n_v, btf_mod.K_VAR, 0, false, int4, &.{1});
    _ = try r.rec(gpa, n_s, btf_mod.K_DATASEC, 1, false, 4, &.{ v, 0, 4 });
    const blob = try r.finish(gpa);
    defer gpa.free(blob);
    var b = ObjB.init(gpa);
    defer b.deinit();
    _ = try b.sec(.{ .name = ".custom", .ty = 8, .flags = 3, .size = 1 << 32 });
    _ = try b.sec(.{ .name = ".BTF", .ty = 1, .data = blob });
    var o = try openObj(&b, .{});
    defer o.deinit();
    try testing.expectError(error.MalformedElf, fixupDatasecs(&o));
}

test "mutation 2026-11-27: the kernel's BTF is read once" {
    const gpa = testing.allocator;
    var o = try open(gpa, fx_xdp_pass, .{});
    defer o.deinit();
    var owned: ?Btf = null;
    defer if (owned) |*k| k.deinit();
    const first = kernelBtf(&o, .{}, &owned) catch return error.SkipZigTest;
    const second = try kernelBtf(&o, .{}, &owned);
    try testing.expect(first == second);
}

test "mutation 2026-11-27: a weak kconfig extern reads as zero when there is no configuration or no version" {
    const gpa = testing.allocator;
    const code = cat(.{ I_MOV0, I_EXIT });
    const bytes = try mtExtObject(gpa, &code, &.{}, .{});
    defer gpa.free(bytes);
    var o = try open(gpa, bytes, .{});
    defer o.deinit();
    for (o.externs[0..3]) |*e| e.weak = true; // LINUX_KERNEL_VERSION, CONFIG_A, CONFIG_B
    try fillKconfig(&o, null, null);
    for (o.maps[0].initial_data) |byte| try testing.expectEqual(@as(u8, 0), byte);
    // only the version is weak: a configuration without a version is fine
    o.externs[1].weak = false;
    o.externs[2].weak = false;
    var cfg = try kconfig_mod.parse(gpa, "CONFIG_A=5\nCONFIG_B=7\n");
    defer cfg.deinit();
    try fillKconfig(&o, &cfg, null);
    try testing.expectEqual(@as(u32, 5), std.mem.readInt(u32, o.maps[0].initial_data[4..8], .little));
    // only the options are weak: a version without a configuration is fine
    o.externs[1].weak = true;
    o.externs[2].weak = true;
    o.externs[0].weak = false;
    try fillKconfig(&o, null, 9);
    try testing.expectEqual(@as(u32, 9), std.mem.readInt(u32, o.maps[0].initial_data[0..4], .little));
}

test "mutation 2026-11-27: an extern whose prototype is too deep to compare is a type mismatch, not a match" {
    const gpa = testing.allocator;
    const kb = try mtKernBtf(gpa, false, true);
    defer gpa.free(kb);
    var kern = try btf_mod.parse(gpa, kb, .{});
    defer kern.deinit();
    const code = cat(.{ I_CALL, I_EXIT });
    const bytes = try mtExtObject(gpa, &code, &.{.{ .off = 0, .sym = .kfn, .typ = R_BPF_64_32 }}, .{ .no_kconfig = true, .deep = true });
    defer gpa.free(bytes);
    var o = try open(gpa, bytes, .{});
    defer o.deinit();
    try testing.expectError(error.ExternTypeMismatch, resolveKernelExterns(&o, &kern, .{ .search_modules = false }));
}
