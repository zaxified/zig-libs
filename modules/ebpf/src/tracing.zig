// SPDX-License-Identifier: MIT
//! BTF-typed attachment: `fentry`, `fexit`, `modify_return`, `tp_btf` and
//! LSM — the hooks the kernel matches **by BTF type id** instead of by name,
//! plus the extended `BPF_PROG_LOAD` that carries that id (and a program's own
//! BTF) in the first place.
//!
//! ## Where the id actually has to go
//!
//! This is the part that is easy to get subtly wrong. For a plain
//! kernel-function `fentry`, the target is **fixed at `BPF_PROG_LOAD` time**,
//! in `bpf_attr.prog_load.attach_btf_id`. `BPF_LINK_CREATE` then attaches
//! that already-targeted program, and the kernel enforces
//!
//! ```c
//! if (!!tgt_prog_fd != !!btf_id) return -EINVAL;   /* bpf_tracing_prog_attach */
//! ```
//!
//! — so passing a `target_btf_id` at link time with `target_fd == 0` is not a
//! second chance to name the target, it is an **error**. The link-time pair
//! exists only for the `BPF_PROG_TYPE_EXT` case (replacing a function inside
//! another loaded BPF program), which `attachExt` exposes separately.
//!
//! Consequence for the API: `attachFentry(gpa, prog_fd, "vfs_read")` resolves
//! the name so that a typo is `error.AttachTargetNotFound` here rather than a
//! bare `EINVAL` from the kernel, **reports the id it resolved**, and then
//! creates the link with the zero pair. The program must already have been
//! loaded with that same id — which is what `loadTracing` does in one step.
//!
//! ## Which BTF kind each hook is named by
//!
//! | hook | BTF kind | name looked up |
//! |---|---|---|
//! | `fentry` / `fexit` / `modify_return` | `FUNC` | the function itself |
//! | `tp_btf` (`BPF_TRACE_RAW_TP`) | **`TYPEDEF`** | `btf_trace_<name>` |
//! | LSM (`BPF_LSM_MAC`) | `FUNC` | `bpf_lsm_<hook>` |
//! | iter | `FUNC` | `bpf_iter_<name>` |
//!
//! The `tp_btf` row is the surprise: `btf_trace_sched_switch` is a **typedef**
//! of a pointer-to-function-prototype, not a `FUNC`. Looking it up as a `FUNC`
//! finds nothing on any kernel — verified on this machine, whose
//! `/sys/kernel/btf/vmlinux` has 1060 `btf_trace_*` typedefs and zero
//! `btf_trace_*` funcs.
//!
//! ## Program-side BTF, end to end
//!
//! `loadProgram` is the extended `BPF_PROG_LOAD`: `std.os.linux.BPF.prog_load`
//! stops at `attach_prog_id`, so it cannot express `expected_attach_type`,
//! `attach_btf_id`, `prog_btf_fd`, `func_info` or `line_info` at all. All of
//! those are wired here, and `btf.Builder` + `btf.loadIntoKernel` produce the
//! blob and fd the first three need — so a hand-built program can carry its
//! own BTF without an external toolchain.
//!
//! ```zig
//! var vmlinux = try ebpf.btf.loadKernel(gpa);
//! defer vmlinux.deinit();
//! const prog_fd = try ebpf.tracing.loadProgram(.tracing, &insns, .{
//!     .expected_attach_type = .trace_fentry,
//!     .attach_btf_id = try ebpf.tracing.resolveAttachId(&vmlinux, .fentry, "vfs_read"),
//! });
//! var out = try ebpf.tracing.attachFentryOpts(gpa, prog_fd, "vfs_read", .{ .btf = &vmlinux });
//! defer out.link.detach();
//! ```
//!
//! Provenance: `include/uapi/linux/bpf.h` for the attr layout and attach
//! types; the `btf_trace_`/`bpf_lsm_`/`bpf_iter_` naming conventions are
//! stated in kernel `Documentation/bpf/` and were re-verified against this
//! machine's `/sys/kernel/btf/vmlinux`.

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

const btf = @import("btf.zig");
const btfext = @import("btfext.zig");
const bpflink = @import("bpflink.zig");
const programs = @import("programs.zig");

const native_endian = builtin.cpu.arch.endian();

const Btf = btf.Btf;
pub const Insn = BPF.Insn;
pub const Program = programs.Program;

// ── the hooks ───────────────────────────────────────────────────────────────

/// Which BTF-typed hook a name refers to. The prefix and BTF kind differ per
/// hook — see the table in this file's header.
pub const TargetKind = enum {
    /// `fentry/<func>` — runs before the kernel function.
    fentry,
    /// `fexit/<func>` — runs after it, with the return value.
    fexit,
    /// `fmod_ret/<func>` — may *override* the return value (error injection).
    modify_return,
    /// `tp_btf/<tracepoint>` — a raw tracepoint with BTF-typed arguments.
    tp_btf,
    /// `lsm/<hook>` — an LSM hook (needs CONFIG_BPF_LSM and the hook to be
    /// in the `bpf` LSM's list).
    lsm,
    /// `iter/<type>` — a BPF iterator program.
    iter,

    /// The string prepended to the caller's name before the BTF lookup.
    pub fn prefix(self: TargetKind) []const u8 {
        return switch (self) {
            .fentry, .fexit, .modify_return => "",
            .tp_btf => "btf_trace_",
            .lsm => "bpf_lsm_",
            .iter => "bpf_iter_",
        };
    }

    /// The BTF kind the (prefixed) name must have. `tp_btf` is a **typedef**;
    /// everything else is a `FUNC`.
    pub fn btfKind(self: TargetKind) btf.Kind {
        return switch (self) {
            .tp_btf => .typedef,
            else => .func,
        };
    }

    /// The `expected_attach_type` a program for this hook must be loaded
    /// with, and the `attach_type` its link is created with.
    pub fn attachType(self: TargetKind) BPF.AttachType {
        return switch (self) {
            .fentry => .trace_fentry,
            .fexit => .trace_fexit,
            .modify_return => .modify_return,
            .tp_btf => .trace_raw_tp,
            .lsm => .lsm_mac,
            .iter => .trace_iter,
        };
    }

    /// The `prog_type` such a program is loaded as.
    pub fn progType(self: TargetKind) BPF.ProgType {
        return switch (self) {
            .lsm => .lsm,
            else => .tracing,
        };
    }
};

/// Longest name this module will look up (prefix included). The kernel's own
/// limit on a BTF name is 128; this leaves room for the longest prefix.
pub const max_name_len: usize = 112;

pub const ResolveError = error{
    /// The name is empty, over-long, or contains a NUL or `/`.
    InvalidName,
    /// No `BTF_KIND_FUNC`/`_TYPEDEF` by that (prefixed) name in the BTF —
    /// a typo, a function the kernel inlined away, or a hook this build does
    /// not have.
    AttachTargetNotFound,
};

/// Build the name the BTF lookup actually uses (`"vfs_read"`,
/// `"btf_trace_sched_switch"`, `"bpf_lsm_file_open"`). Pure, so the prefix
/// rules are testable without any BTF at all.
pub fn targetName(kind: TargetKind, name: []const u8, buf: []u8) ResolveError![]const u8 {
    if (name.len == 0) return error.InvalidName;
    if (std.mem.indexOfScalar(u8, name, 0) != null) return error.InvalidName;
    if (std.mem.indexOfScalar(u8, name, '/') != null) return error.InvalidName;
    const p = kind.prefix();
    if (p.len + name.len > max_name_len) return error.InvalidName;
    if (p.len + name.len > buf.len) return error.InvalidName;
    @memcpy(buf[0..p.len], p);
    @memcpy(buf[p.len..][0..name.len], name);
    return buf[0 .. p.len + name.len];
}

/// Resolve `name` to the `attach_btf_id` the kernel matches this hook by.
/// This is the single missing input `bpflink.linkCreateTracing` was written
/// against.
pub fn resolveAttachId(b: *const Btf, kind: TargetKind, name: []const u8) ResolveError!u32 {
    var buf: [max_name_len]u8 = undefined;
    const full = try targetName(kind, name, &buf);
    return b.findByNameKind(full, kind.btfKind()) orelse error.AttachTargetNotFound;
}

/// `resolveAttachId` against `/sys/kernel/btf/vmlinux`, loading and freeing it
/// for this one lookup. Parsing the kernel's BTF costs a ~7 MiB read and a
/// full type-section walk, so a caller resolving more than one name should
/// `btf.loadKernel` once and use `resolveAttachId` directly.
pub fn resolveKernelAttachId(
    gpa: std.mem.Allocator,
    kind: TargetKind,
    name: []const u8,
) (ResolveError || btf.LoadError)!u32 {
    var k = try btf.loadKernel(gpa);
    defer k.deinit();
    return resolveAttachId(&k, kind, name);
}

// ── attach ──────────────────────────────────────────────────────────────────

pub const AttachError = ResolveError || btf.LoadError || bpflink.LinkError;

/// A BTF-typed attachment: the link, plus the id the name resolved to (so a
/// caller can see — and log, and re-use at load time — what it actually
/// attached to instead of trusting a name).
pub const TracingLink = struct {
    link: bpflink.LinkHandle,
    /// The `attach_btf_id` the name resolved to.
    attach_btf_id: u32,
    kind: TargetKind,

    pub fn detach(self: *TracingLink) void {
        self.link.detach();
    }
    pub fn deinit(self: *TracingLink) void {
        self.link.detach();
    }
};

pub const AttachOptions = struct {
    /// Already-parsed kernel BTF, to avoid re-reading 7 MiB per attach. When
    /// `null` the vmlinux BTF is loaded and freed for this call.
    btf: ?*const Btf = null,
    /// `bpf_get_attach_cookie()` value.
    cookie: u64 = 0,
    /// **Only** for `BPF_PROG_TYPE_EXT` (see `attachExt`): the loaded program
    /// being extended, and the id inside it. For a kernel-function target
    /// both must stay 0 — the kernel rejects `(0, non-zero)` and
    /// `(non-zero, 0)` alike.
    target_fd: linux.fd_t = 0,
    target_btf_id: u32 = 0,
};

/// Attach `prog_fd` to the BTF-typed hook `kind`/`name`.
///
/// The name is resolved **here** purely so that a bad name is a typed error
/// instead of the kernel's undifferentiated `EINVAL`; the id the kernel
/// matches on is the one baked into the program at load time (see this file's
/// header). The resolved id is returned so a caller can assert they agree.
pub fn attachTracingByName(
    gpa: std.mem.Allocator,
    prog_fd: linux.fd_t,
    kind: TargetKind,
    name: []const u8,
    opts: AttachOptions,
) AttachError!TracingLink {
    if (comptime builtin.os.tag != .linux)
        @compileError("ebpf.tracing is Linux-only (bpf() raw syscall)");

    const id = blk: {
        if (opts.btf) |b| break :blk try resolveAttachId(b, kind, name);
        var k = try btf.loadKernel(gpa);
        defer k.deinit();
        break :blk try resolveAttachId(&k, kind, name);
    };

    const link = try bpflink.linkCreateTracing(
        prog_fd,
        opts.target_fd,
        kind.attachType(),
        opts.target_btf_id,
        opts.cookie,
    );
    return .{ .link = link, .attach_btf_id = id, .kind = kind };
}

/// Attach to a kernel function's entry (`fentry/<func>`).
pub fn attachFentry(gpa: std.mem.Allocator, prog_fd: linux.fd_t, func: []const u8) AttachError!TracingLink {
    return attachTracingByName(gpa, prog_fd, .fentry, func, .{});
}

/// `attachFentry` with every knob exposed.
pub fn attachFentryOpts(gpa: std.mem.Allocator, prog_fd: linux.fd_t, func: []const u8, opts: AttachOptions) AttachError!TracingLink {
    return attachTracingByName(gpa, prog_fd, .fentry, func, opts);
}

/// Attach to a kernel function's return (`fexit/<func>`) — unlike a
/// kretprobe, an fexit program still sees the ARGUMENTS as well as the
/// return value, because the trampoline keeps the frame alive.
pub fn attachFexit(gpa: std.mem.Allocator, prog_fd: linux.fd_t, func: []const u8) AttachError!TracingLink {
    return attachTracingByName(gpa, prog_fd, .fexit, func, .{});
}

pub fn attachFexitOpts(gpa: std.mem.Allocator, prog_fd: linux.fd_t, func: []const u8, opts: AttachOptions) AttachError!TracingLink {
    return attachTracingByName(gpa, prog_fd, .fexit, func, opts);
}

/// Attach a `fmod_ret` program, which may replace the function's return
/// value. Only functions on the kernel's error-injection allowlist accept
/// one.
pub fn attachModifyReturn(gpa: std.mem.Allocator, prog_fd: linux.fd_t, func: []const u8) AttachError!TracingLink {
    return attachTracingByName(gpa, prog_fd, .modify_return, func, .{});
}

/// Attach to a raw tracepoint with BTF-typed arguments (`tp_btf/<name>`).
/// Pass the BARE tracepoint name (`"sched_switch"`); the `btf_trace_` prefix
/// and the TYPEDEF lookup are this function's job.
pub fn attachTpBtf(gpa: std.mem.Allocator, prog_fd: linux.fd_t, tracepoint: []const u8) AttachError!TracingLink {
    return attachTracingByName(gpa, prog_fd, .tp_btf, tracepoint, .{});
}

pub fn attachTpBtfOpts(gpa: std.mem.Allocator, prog_fd: linux.fd_t, tracepoint: []const u8, opts: AttachOptions) AttachError!TracingLink {
    return attachTracingByName(gpa, prog_fd, .tp_btf, tracepoint, opts);
}

/// Attach an LSM program (`lsm/<hook>`). Pass the BARE hook name
/// (`"file_open"`); the `bpf_lsm_` prefix is added here.
pub fn attachLsm(gpa: std.mem.Allocator, prog_fd: linux.fd_t, hook: []const u8) AttachError!TracingLink {
    return attachTracingByName(gpa, prog_fd, .lsm, hook, .{});
}

pub fn attachLsmOpts(gpa: std.mem.Allocator, prog_fd: linux.fd_t, hook: []const u8, opts: AttachOptions) AttachError!TracingLink {
    return attachTracingByName(gpa, prog_fd, .lsm, hook, opts);
}

/// The one case where the link-time `(target_fd, target_btf_id)` pair is
/// meaningful: a `BPF_PROG_TYPE_EXT` program replacing a global function
/// inside `target_prog_fd`. `target_btf_id` names that function in the target
/// program's OWN BTF (not vmlinux's), so it cannot be resolved from
/// `/sys/kernel/btf/vmlinux` and must be supplied.
pub fn attachExt(
    prog_fd: linux.fd_t,
    target_prog_fd: linux.fd_t,
    target_btf_id: u32,
    cookie: u64,
) bpflink.LinkError!bpflink.LinkHandle {
    if (target_prog_fd == 0 or target_btf_id == 0) return error.InvalidTarget;
    // BPF_PROG_TYPE_EXT programs are loaded with expected_attach_type 0 and
    // attach through the same command; the kernel derives everything from
    // the pair.
    return bpflink.linkCreateTracing(prog_fd, target_prog_fd, .trace_fentry, target_btf_id, cookie);
}

// ── the extended BPF_PROG_LOAD ──────────────────────────────────────────────

/// `bpf_attr.prog_load`, extended past what std declares.
/// `BPF.ProgLoadAttr` stops at `attach_prog_id` (offset 112) — it has no
/// `core_relo*`, no `fd_array`, no `log_true_size`, and misspells
/// `attach_btf_id` as `attact_btf_id`. Passing a longer attr is ABI-safe in
/// both directions as long as the tail is zero (same rule `bpflink.zig`
/// documents).
pub const ProgLoadAttr = extern struct {
    prog_type: u32 = 0,
    insn_cnt: u32 = 0,
    insns: u64 = 0,
    license: u64 = 0,
    log_level: u32 = 0,
    log_size: u32 = 0,
    log_buf: u64 = 0,
    kern_version: u32 = 0,
    prog_flags: u32 = 0,
    prog_name: [16]u8 = @splat(0),
    prog_ifindex: u32 = 0,
    /// Must match the hook for `tracing`/`lsm`/`cgroup_*` programs — the
    /// verifier's context-access rules key off it.
    expected_attach_type: u32 = 0,
    /// An fd from `BPF_BTF_LOAD` describing this program's own types.
    prog_btf_fd: i32 = 0,
    func_info_rec_size: u32 = 0,
    func_info: u64 = 0,
    func_info_cnt: u32 = 0,
    line_info_rec_size: u32 = 0,
    line_info: u64 = 0,
    line_info_cnt: u32 = 0,
    /// The BTF type id of the attach target — the whole point of `btf.zig`.
    attach_btf_id: u32 = 0,
    /// A union in the kernel: `attach_prog_fd` (extending another program) or
    /// `attach_btf_obj_fd` (a MODULE's BTF object fd; 0 = vmlinux).
    attach_btf_obj_fd: u32 = 0,
    core_relo_cnt: u32 = 0,
    fd_array: u64 = 0,
    core_relos: u64 = 0,
    core_relo_rec_size: u32 = 0,
    /// Output: the log size the kernel would have written.
    log_true_size: u32 = 0,
    prog_token_fd: i32 = 0,
    /// Explicit tail padding. `extern struct` rounds the size up to the
    /// 8-byte alignment anyway; declaring the four bytes makes them **zero**
    /// instead of undefined, which is not cosmetic — `bpf()` rejects an attr
    /// whose bytes past the fields it knows are non-zero
    /// (`bpf_check_uarg_tail_zero`), so uninitialized padding would make
    /// every load fail with `E2BIG` on some kernels and succeed on others.
    _tail_pad: u32 = 0,
};

/// A `bpf_attr`-sized staging area (see `bpflink.AttrBuf` for why).
const AttrBuf = extern union {
    base: BPF.Attr,
    prog_load: ProgLoadAttr,
};

pub const LoadOptions = struct {
    /// The kernel enforces the GPL-only helper subset for anything that is
    /// not `"GPL"`. Most tracing helpers (`bpf_probe_read_kernel`,
    /// `bpf_get_current_task`) are GPL-only, hence the default.
    license: []const u8 = "GPL",
    /// Up to 15 characters; shows up in `bpftool prog show`.
    prog_name: ?[]const u8 = null,
    expected_attach_type: ?BPF.AttachType = null,
    attach_btf_id: u32 = 0,
    /// A module BTF object fd when the attach target is in a module, or an
    /// `attach_prog_fd` for `BPF_PROG_TYPE_EXT`. 0 = vmlinux.
    attach_btf_obj_fd: u32 = 0,
    /// An fd from `btf.loadIntoKernel`. Required if `func_info` or
    /// `line_info` is non-empty — their `type_id`s index THIS BTF.
    prog_btf_fd: ?linux.fd_t = null,
    func_info: []const btfext.FuncInfo = &.{},
    line_info: []const btfext.LineInfo = &.{},
    prog_flags: u32 = 0,
    kern_version: u32 = 0,
    /// Verifier log buffer. Level 0 with a buffer means "level 1".
    log: ?[]u8 = null,
    log_level: u32 = 0,
};

pub const LoadProgError = error{
    /// The verifier rejected the program (`EACCES`). `opts.log` says why.
    UnsafeProgram,
    PermissionDenied,
    /// Bad arguments — including an `attach_btf_id` that does not name a
    /// function this program type may attach to.
    InvalidArgument,
    /// The attach target named by `attach_btf_id` does not exist.
    AttachTargetNotFound,
    ProgramTooLarge,
    SystemResources,
    /// `func_info`/`line_info` given without a `prog_btf_fd`.
    MissingProgBtf,
    /// A `prog_name` over 15 characters, or a license with an interior NUL.
    InvalidArgumentLocal,
    Unexpected,
};

/// Build the attr an extended `BPF_PROG_LOAD` sends — pure, so the layout is
/// golden-testable without `CAP_BPF`. `license_z`, `insns`, `log`,
/// `func_info` and `line_info` must all outlive the syscall.
pub fn buildProgLoadAttr(
    prog_type: BPF.ProgType,
    insns: []const Insn,
    license_z: [*:0]const u8,
    opts: LoadOptions,
) LoadProgError!ProgLoadAttr {
    if (opts.func_info.len != 0 or opts.line_info.len != 0) {
        if (opts.prog_btf_fd == null) return error.MissingProgBtf;
    }
    var attr: ProgLoadAttr = .{
        .prog_type = @intFromEnum(prog_type),
        .insn_cnt = @intCast(insns.len),
        .insns = @intFromPtr(insns.ptr),
        .license = @intFromPtr(license_z),
        .kern_version = opts.kern_version,
        .prog_flags = opts.prog_flags,
        .expected_attach_type = if (opts.expected_attach_type) |t| @intFromEnum(t) else 0,
        .prog_btf_fd = opts.prog_btf_fd orelse 0,
        .attach_btf_id = opts.attach_btf_id,
        .attach_btf_obj_fd = opts.attach_btf_obj_fd,
    };
    if (opts.log) |l| {
        attr.log_buf = @intFromPtr(l.ptr);
        attr.log_size = @intCast(l.len);
        attr.log_level = if (opts.log_level == 0) 1 else opts.log_level;
    }
    if (opts.prog_name) |n| {
        if (n.len > attr.prog_name.len - 1) return error.InvalidArgumentLocal;
        @memcpy(attr.prog_name[0..n.len], n);
    }
    if (opts.func_info.len != 0) {
        attr.func_info = @intFromPtr(opts.func_info.ptr);
        attr.func_info_cnt = @intCast(opts.func_info.len);
        attr.func_info_rec_size = @sizeOf(btfext.FuncInfo);
    }
    if (opts.line_info.len != 0) {
        attr.line_info = @intFromPtr(opts.line_info.ptr);
        attr.line_info_cnt = @intCast(opts.line_info.len);
        attr.line_info_rec_size = @sizeOf(btfext.LineInfo);
    }
    return attr;
}

/// `bpf(BPF_PROG_LOAD)` with everything std's wrapper cannot express. Returns
/// the program fd; the caller closes it.
pub fn loadProgram(
    prog_type: BPF.ProgType,
    insns: []const Insn,
    opts: LoadOptions,
) LoadProgError!linux.fd_t {
    if (comptime builtin.os.tag != .linux)
        @compileError("ebpf.tracing.loadProgram is Linux-only (bpf() raw syscall)");

    var license_buf: [64]u8 = undefined;
    if (opts.license.len >= license_buf.len) return error.InvalidArgumentLocal;
    if (std.mem.indexOfScalar(u8, opts.license, 0) != null) return error.InvalidArgumentLocal;
    @memcpy(license_buf[0..opts.license.len], opts.license);
    license_buf[opts.license.len] = 0;

    var buf: AttrBuf = .{ .prog_load = try buildProgLoadAttr(prog_type, insns, @ptrCast(&license_buf), opts) };
    const rc = linux.bpf(.prog_load, @ptrCast(&buf), @sizeOf(ProgLoadAttr));
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .ACCES => error.UnsafeProgram,
        .PERM => error.PermissionDenied,
        .NOENT => error.AttachTargetNotFound,
        .@"2BIG" => error.ProgramTooLarge,
        .INVAL => error.InvalidArgument,
        .NOMEM, .NOSPC, .MFILE, .NFILE => error.SystemResources,
        else => error.Unexpected,
    };
}

/// A program loaded for a BTF-typed hook, with the id it was targeted at.
pub const LoadedTracing = struct {
    fd: linux.fd_t,
    attach_btf_id: u32,
    kind: TargetKind,

    pub fn close(self: *LoadedTracing) void {
        if (self.fd < 0) return;
        _ = linux.close(self.fd);
        self.fd = -1;
    }
};

/// Load a program **already targeted** at `name` — resolve the id, set the
/// matching `prog_type`/`expected_attach_type`, and load. This is the one
/// call that makes attach-by-name real end to end: the kernel matches on
/// exactly this `attach_btf_id`, and `attachFentry` afterwards only creates
/// the link.
pub fn loadTracing(
    gpa: std.mem.Allocator,
    kind: TargetKind,
    name: []const u8,
    insns: []const Insn,
    opts: LoadOptions,
) (LoadProgError || ResolveError || btf.LoadError)!LoadedTracing {
    const id = blk: {
        if (opts.attach_btf_id != 0) break :blk opts.attach_btf_id;
        var k = try btf.loadKernel(gpa);
        defer k.deinit();
        break :blk try resolveAttachId(&k, kind, name);
    };
    var o = opts;
    o.attach_btf_id = id;
    o.expected_attach_type = kind.attachType();
    const fd = try loadProgram(kind.progType(), insns, o);
    return .{ .fd = fd, .attach_btf_id = id, .kind = kind };
}

// ── tests ────────────────────────────────────────────────────────────────────
//
// Three layers, matching the rest of this module:
//  1. PURE: the prefix/kind table, name validation, and the extended
//     `bpf_attr.prog_load` as GOLDEN BYTES against the documented UAPI
//     offsets (and field-for-field against std's shorter declaration).
//  2. REAL KERNEL BTF, unprivileged: resolve `fentry`, `tp_btf` and LSM
//     names against `/sys/kernel/btf/vmlinux` — reading BTF needs no
//     capability at all, only attaching does. Cross-checked with
//       bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep ...
//  3. PRIVILEGED, gracefully skipped: load a real fentry program with a
//     resolved `attach_btf_id` and attach it. Prints `SKIPPED:` and PASSES
//     without CAP_BPF, exactly like the rest of this module.

const testing = std.testing;

fn hasBpfCapability() bool {
    return linux.geteuid() == 0;
}

fn kernelBtfAvailable() bool {
    const rc = linux.open(btf.sysfs_vmlinux, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

test "TargetKind: prefix, BTF kind, attach type and prog type" {
    try testing.expectEqualStrings("", TargetKind.fentry.prefix());
    try testing.expectEqualStrings("", TargetKind.fexit.prefix());
    try testing.expectEqualStrings("btf_trace_", TargetKind.tp_btf.prefix());
    try testing.expectEqualStrings("bpf_lsm_", TargetKind.lsm.prefix());
    try testing.expectEqualStrings("bpf_iter_", TargetKind.iter.prefix());

    // The trap this table exists for: tp_btf is a TYPEDEF, not a FUNC.
    try testing.expectEqual(btf.Kind.typedef, TargetKind.tp_btf.btfKind());
    try testing.expectEqual(btf.Kind.func, TargetKind.fentry.btfKind());
    try testing.expectEqual(btf.Kind.func, TargetKind.lsm.btfKind());
    try testing.expectEqual(btf.Kind.func, TargetKind.iter.btfKind());

    try testing.expectEqual(BPF.AttachType.trace_fentry, TargetKind.fentry.attachType());
    try testing.expectEqual(BPF.AttachType.trace_fexit, TargetKind.fexit.attachType());
    try testing.expectEqual(BPF.AttachType.modify_return, TargetKind.modify_return.attachType());
    try testing.expectEqual(BPF.AttachType.trace_raw_tp, TargetKind.tp_btf.attachType());
    try testing.expectEqual(BPF.AttachType.lsm_mac, TargetKind.lsm.attachType());
    try testing.expectEqual(BPF.AttachType.trace_iter, TargetKind.iter.attachType());

    try testing.expectEqual(BPF.ProgType.tracing, TargetKind.fentry.progType());
    try testing.expectEqual(BPF.ProgType.lsm, TargetKind.lsm.progType());

    // The UAPI numbers those attach types must have.
    try testing.expectEqual(@as(u32, 24), @intFromEnum(BPF.AttachType.trace_fentry));
    try testing.expectEqual(@as(u32, 25), @intFromEnum(BPF.AttachType.trace_fexit));
    try testing.expectEqual(@as(u32, 23), @intFromEnum(BPF.AttachType.trace_raw_tp));
    try testing.expectEqual(@as(u32, 27), @intFromEnum(BPF.AttachType.lsm_mac));
}

test "targetName builds the prefixed name and refuses what cannot be one" {
    var buf: [max_name_len]u8 = undefined;
    try testing.expectEqualStrings("vfs_read", try targetName(.fentry, "vfs_read", &buf));
    try testing.expectEqualStrings("btf_trace_sched_switch", try targetName(.tp_btf, "sched_switch", &buf));
    try testing.expectEqualStrings("bpf_lsm_file_open", try targetName(.lsm, "file_open", &buf));
    try testing.expectEqualStrings("bpf_iter_task", try targetName(.iter, "task", &buf));

    try testing.expectError(error.InvalidName, targetName(.fentry, "", &buf));
    try testing.expectError(error.InvalidName, targetName(.fentry, "a\x00b", &buf));
    // A libbpf-style SEC() string must be split by the caller, not passed
    // whole — otherwise "fentry/vfs_read" would be looked up literally.
    try testing.expectError(error.InvalidName, targetName(.fentry, "fentry/vfs_read", &buf));
    try testing.expectError(error.InvalidName, targetName(.fentry, "x" ** (max_name_len + 1), &buf));
    // The prefix counts toward the limit.
    try testing.expectError(error.InvalidName, targetName(.tp_btf, "x" ** (max_name_len - 5), &buf));
}

test "golden: the extended BPF_PROG_LOAD attr layout" {
    // Offsets straight out of `include/uapi/linux/bpf.h`. Getting
    // `attach_btf_id` wrong by four bytes would silently attach an fentry
    // program to whatever type id happens to sit next door.
    try testing.expectEqual(@as(usize, 0), @offsetOf(ProgLoadAttr, "prog_type"));
    try testing.expectEqual(@as(usize, 4), @offsetOf(ProgLoadAttr, "insn_cnt"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(ProgLoadAttr, "insns"));
    try testing.expectEqual(@as(usize, 16), @offsetOf(ProgLoadAttr, "license"));
    try testing.expectEqual(@as(usize, 24), @offsetOf(ProgLoadAttr, "log_level"));
    try testing.expectEqual(@as(usize, 28), @offsetOf(ProgLoadAttr, "log_size"));
    try testing.expectEqual(@as(usize, 32), @offsetOf(ProgLoadAttr, "log_buf"));
    try testing.expectEqual(@as(usize, 40), @offsetOf(ProgLoadAttr, "kern_version"));
    try testing.expectEqual(@as(usize, 44), @offsetOf(ProgLoadAttr, "prog_flags"));
    try testing.expectEqual(@as(usize, 48), @offsetOf(ProgLoadAttr, "prog_name"));
    try testing.expectEqual(@as(usize, 64), @offsetOf(ProgLoadAttr, "prog_ifindex"));
    try testing.expectEqual(@as(usize, 68), @offsetOf(ProgLoadAttr, "expected_attach_type"));
    try testing.expectEqual(@as(usize, 72), @offsetOf(ProgLoadAttr, "prog_btf_fd"));
    try testing.expectEqual(@as(usize, 76), @offsetOf(ProgLoadAttr, "func_info_rec_size"));
    try testing.expectEqual(@as(usize, 80), @offsetOf(ProgLoadAttr, "func_info"));
    try testing.expectEqual(@as(usize, 88), @offsetOf(ProgLoadAttr, "func_info_cnt"));
    try testing.expectEqual(@as(usize, 92), @offsetOf(ProgLoadAttr, "line_info_rec_size"));
    try testing.expectEqual(@as(usize, 96), @offsetOf(ProgLoadAttr, "line_info"));
    try testing.expectEqual(@as(usize, 104), @offsetOf(ProgLoadAttr, "line_info_cnt"));
    try testing.expectEqual(@as(usize, 108), @offsetOf(ProgLoadAttr, "attach_btf_id"));
    try testing.expectEqual(@as(usize, 112), @offsetOf(ProgLoadAttr, "attach_btf_obj_fd"));
    try testing.expectEqual(@as(usize, 116), @offsetOf(ProgLoadAttr, "core_relo_cnt"));
    try testing.expectEqual(@as(usize, 120), @offsetOf(ProgLoadAttr, "fd_array"));
    try testing.expectEqual(@as(usize, 128), @offsetOf(ProgLoadAttr, "core_relos"));
    try testing.expectEqual(@as(usize, 136), @offsetOf(ProgLoadAttr, "core_relo_rec_size"));
    try testing.expectEqual(@as(usize, 140), @offsetOf(ProgLoadAttr, "log_true_size"));
    try testing.expectEqual(@as(usize, 144), @offsetOf(ProgLoadAttr, "prog_token_fd"));
    try testing.expectEqual(@as(usize, 152), @sizeOf(ProgLoadAttr));

    // std's shorter declaration must agree on every field it does have.
    const S = BPF.ProgLoadAttr;
    try testing.expectEqual(@offsetOf(S, "prog_type"), @offsetOf(ProgLoadAttr, "prog_type"));
    try testing.expectEqual(@offsetOf(S, "insns"), @offsetOf(ProgLoadAttr, "insns"));
    try testing.expectEqual(@offsetOf(S, "license"), @offsetOf(ProgLoadAttr, "license"));
    try testing.expectEqual(@offsetOf(S, "log_buf"), @offsetOf(ProgLoadAttr, "log_buf"));
    try testing.expectEqual(@offsetOf(S, "prog_name"), @offsetOf(ProgLoadAttr, "prog_name"));
    try testing.expectEqual(@offsetOf(S, "expected_attach_type"), @offsetOf(ProgLoadAttr, "expected_attach_type"));
    try testing.expectEqual(@offsetOf(S, "prog_btf_fd"), @offsetOf(ProgLoadAttr, "prog_btf_fd"));
    try testing.expectEqual(@offsetOf(S, "func_info"), @offsetOf(ProgLoadAttr, "func_info"));
    try testing.expectEqual(@offsetOf(S, "line_info"), @offsetOf(ProgLoadAttr, "line_info"));
    // std spells it `attact_btf_id`; the offset is what matters.
    try testing.expectEqual(@offsetOf(S, "attact_btf_id"), @offsetOf(ProgLoadAttr, "attach_btf_id"));
    try testing.expectEqual(@offsetOf(S, "attach_prog_id"), @offsetOf(ProgLoadAttr, "attach_btf_obj_fd"));

    try testing.expect(@sizeOf(AttrBuf) >= @sizeOf(BPF.Attr));
    try testing.expect(@sizeOf(AttrBuf) >= @sizeOf(ProgLoadAttr));
}

test "golden: an fentry prog_load attr's bytes" {
    if (native_endian != .little) return error.SkipZigTest;

    const insns = [_]Insn{ Insn.mov(.r0, 0), Insn.exit() };
    const license = "GPL";
    var lz: [8]u8 = @splat(0);
    @memcpy(lz[0..3], license);

    const fi = [_]btfext.FuncInfo{.{ .insn_off = 0, .type_id = 7 }};
    const li = [_]btfext.LineInfo{.{ .insn_off = 0, .file_name_off = 1, .line_off = 2, .line_col = 3 }};

    const attr = try buildProgLoadAttr(.tracing, &insns, @ptrCast(&lz), .{
        .expected_attach_type = .trace_fentry,
        .attach_btf_id = 0x2_8f30,
        .prog_name = "zl_fentry",
        .prog_btf_fd = 9,
        .func_info = &fi,
        .line_info = &li,
    });
    const bytes = std.mem.asBytes(&attr);

    try testing.expectEqual(@as(u32, @intFromEnum(BPF.ProgType.tracing)), std.mem.readInt(u32, bytes[0..4], .little));
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, bytes[4..8], .little));
    try testing.expectEqual(@as(u64, @intFromPtr(&insns)), std.mem.readInt(u64, bytes[8..16], .little));
    try testing.expectEqual(@as(u64, @intFromPtr(&lz)), std.mem.readInt(u64, bytes[16..24], .little));
    try testing.expectEqualStrings("zl_fentry", std.mem.sliceTo(bytes[48..64], 0));
    try testing.expectEqual(@as(u32, 24), std.mem.readInt(u32, bytes[68..72], .little)); // trace_fentry
    try testing.expectEqual(@as(u32, 9), std.mem.readInt(u32, bytes[72..76], .little)); // prog_btf_fd
    try testing.expectEqual(@as(u32, 8), std.mem.readInt(u32, bytes[76..80], .little)); // func_info_rec_size
    try testing.expectEqual(@as(u64, @intFromPtr(&fi)), std.mem.readInt(u64, bytes[80..88], .little));
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, bytes[88..92], .little));
    try testing.expectEqual(@as(u32, 16), std.mem.readInt(u32, bytes[92..96], .little)); // line_info_rec_size
    try testing.expectEqual(@as(u64, @intFromPtr(&li)), std.mem.readInt(u64, bytes[96..104], .little));
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, bytes[104..108], .little));
    try testing.expectEqual(@as(u32, 0x2_8f30), std.mem.readInt(u32, bytes[108..112], .little));
    // The tail the kernel may not know about must be all zero.
    try testing.expectEqualSlices(u8, &@as([36]u8, @splat(0)), bytes[116..152]);

    // A minimal load leaves every BTF field at zero — so this attr is a
    // superset of what std's `prog_load` would have sent.
    {
        const bare = try buildProgLoadAttr(.socket_filter, &insns, @ptrCast(&lz), .{});
        try testing.expectEqual(@as(u32, 0), bare.expected_attach_type);
        try testing.expectEqual(@as(u32, 0), bare.attach_btf_id);
        try testing.expectEqual(@as(i32, 0), bare.prog_btf_fd);
        try testing.expectEqual(@as(u32, 0), bare.func_info_cnt);
        try testing.expectEqual(@as(u32, 0), bare.log_level);
    }
    // A verifier log implies level 1.
    {
        var log: [16]u8 = undefined;
        const a = try buildProgLoadAttr(.tracing, &insns, @ptrCast(&lz), .{ .log = &log });
        try testing.expectEqual(@as(u32, 1), a.log_level);
        try testing.expectEqual(@as(u32, 16), a.log_size);
    }
    // func_info/line_info without a prog_btf_fd is a refusal, not a load the
    // kernel would reject with a confusing EINVAL.
    try testing.expectError(
        error.MissingProgBtf,
        buildProgLoadAttr(.tracing, &insns, @ptrCast(&lz), .{ .func_info = &fi }),
    );
    try testing.expectError(
        error.MissingProgBtf,
        buildProgLoadAttr(.tracing, &insns, @ptrCast(&lz), .{ .line_info = &li }),
    );
    // An over-long prog_name.
    try testing.expectError(
        error.InvalidArgumentLocal,
        buildProgLoadAttr(.tracing, &insns, @ptrCast(&lz), .{ .prog_name = "0123456789abcdef" }),
    );
}

test "resolveAttachId against real kernel BTF" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!kernelBtfAvailable()) {
        if (verboseSkip()) std.debug.print("\nSKIPPED: ebpf.tracing resolve test — no /sys/kernel/btf/vmlinux.\n", .{});
        return;
    }
    const gpa = testing.allocator;
    var k = try btf.loadKernel(gpa);
    defer k.deinit();

    // fentry/fexit: a FUNC by its bare name. Cross-checked with
    //   bpftool btf dump file /sys/kernel/btf/vmlinux format raw \
    //     | grep -w "FUNC 'vfs_read'"
    // which on this machine printed `[164596] FUNC 'vfs_read' ... linkage=static`.
    // The ID IS NOT ASSERTED — only that it resolves, and to a FUNC.
    var resolved: usize = 0;
    for ([_][]const u8{ "vfs_read", "vfs_write", "do_sys_openat2", "tcp_v4_connect" }) |name| {
        const id = resolveAttachId(&k, .fentry, name) catch continue;
        resolved += 1;
        try testing.expectEqual(btf.Kind.func, (try k.byId(id)).kind);
        try testing.expectEqualStrings(name, k.typeName(id).?);
        // fexit resolves identically — same FUNC, different attach type.
        try testing.expectEqual(id, try resolveAttachId(&k, .fexit, name));
        try testing.expectEqual(id, try resolveAttachId(&k, .modify_return, name));
    }
    try testing.expect(resolved > 0);

    // A name that is definitely not a kernel function.
    try testing.expectError(
        error.AttachTargetNotFound,
        resolveAttachId(&k, .fentry, "zig_libs_no_such_kernel_function"),
    );

    // tp_btf: the prefixed TYPEDEF. This is the assertion that would fail if
    // the lookup used BTF_KIND_FUNC — there are no `btf_trace_*` FUNCs at all.
    {
        var seen: usize = 0;
        for ([_][]const u8{ "sched_switch", "sys_enter", "kfree_skb", "sched_process_exec" }) |tp| {
            const id = resolveAttachId(&k, .tp_btf, tp) catch continue;
            seen += 1;
            const t = try k.byId(id);
            try testing.expectEqual(btf.Kind.typedef, t.kind);
            var namebuf: [max_name_len]u8 = undefined;
            try testing.expectEqualStrings(try targetName(.tp_btf, tp, &namebuf), k.typeName(id).?);
            // The same bare name as a FUNC must NOT be what we found.
            if (k.findByNameKind(tp, .func)) |func_id| try testing.expect(func_id != id);
        }
        if (seen == 0) {
            std.debug.print("\nebpf.tracing: no btf_trace_* typedefs on this kernel — tp_btf unavailable.\n", .{});
        }
    }

    // LSM: the `bpf_lsm_` prefixed FUNC (absent without CONFIG_BPF_LSM).
    {
        var seen: usize = 0;
        for ([_][]const u8{ "file_open", "bprm_check_security", "socket_connect", "task_alloc" }) |hook| {
            const id = resolveAttachId(&k, .lsm, hook) catch continue;
            seen += 1;
            try testing.expectEqual(btf.Kind.func, (try k.byId(id)).kind);
            var namebuf: [max_name_len]u8 = undefined;
            try testing.expectEqualStrings(try targetName(.lsm, hook, &namebuf), k.typeName(id).?);
        }
        if (seen == 0) std.debug.print("\nebpf.tracing: no bpf_lsm_* funcs — CONFIG_BPF_LSM=n on this kernel.\n", .{});
    }

    // The whole-BTF convenience path agrees with the pre-loaded one.
    if (k.findByNameKind("vfs_read", .func)) |want| {
        try testing.expectEqual(want, try resolveKernelAttachId(gpa, .fentry, "vfs_read"));
    }
}

test "LIVE: load and attach an fentry program by name" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!kernelBtfAvailable()) {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE ebpf.tracing fentry — no kernel BTF.\n", .{});
        return;
    }
    if (!hasBpfCapability()) {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE ebpf.tracing fentry attach — needs CAP_BPF (running as uid {d}).\n",
            .{linux.geteuid()},
        );
        return;
    }
    const gpa = testing.allocator;
    var k = btf.loadKernel(gpa) catch {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE ebpf.tracing fentry — kernel BTF unparseable.\n", .{});
        return;
    };
    defer k.deinit();

    // `do_unlinkat` / `vfs_read` are ordinary, non-inlined kernel functions
    // that any kernel with BTF can host an fentry on.
    const target: []const u8 = for ([_][]const u8{ "do_unlinkat", "vfs_read", "vfs_write" }) |n| {
        if (resolveAttachId(&k, .fentry, n)) |_| break n else |_| {}
    } else {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE ebpf.tracing fentry — no candidate function in this kernel's BTF.\n", .{});
        return;
    };

    const insns = [_]Insn{ Insn.mov(.r0, 0), Insn.exit() };
    var log: [8192]u8 = undefined;
    var loaded = loadTracing(gpa, .fentry, target, &insns, .{
        .attach_btf_id = try resolveAttachId(&k, .fentry, target),
        .log = &log,
    }) catch |e| {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE ebpf.tracing fentry BPF_PROG_LOAD refused ({s}): {s}\n",
            .{ @errorName(e), std.mem.sliceTo(&log, 0) },
        );
        return;
    };
    defer loaded.close();
    try testing.expect(loaded.fd >= 0);
    try testing.expectEqual(try resolveAttachId(&k, .fentry, target), loaded.attach_btf_id);

    var out = attachFentryOpts(gpa, loaded.fd, target, .{ .btf = &k }) catch |e| {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE ebpf.tracing fentry BPF_LINK_CREATE refused ({s}).\n", .{@errorName(e)});
        return;
    };
    defer out.detach();
    try testing.expect(out.link.fd >= 0);
    try testing.expectEqual(loaded.attach_btf_id, out.attach_btf_id);

    const info = try out.link.info();
    try testing.expectEqual(bpflink.LinkType.tracing, info.linkType());

    out.detach();
    try testing.expectEqual(@as(linux.fd_t, -1), out.link.fd);
    out.detach(); // idempotent
}

test "LIVE: a tp_btf program attaches through the same path" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!kernelBtfAvailable() or !hasBpfCapability()) {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE ebpf.tracing tp_btf — needs CAP_BPF and kernel BTF (uid {d}).\n",
            .{linux.geteuid()},
        );
        return;
    }
    const gpa = testing.allocator;
    var k = try btf.loadKernel(gpa);
    defer k.deinit();

    const tp: []const u8 = for ([_][]const u8{ "sched_switch", "sys_enter", "kfree_skb" }) |n| {
        if (resolveAttachId(&k, .tp_btf, n)) |_| break n else |_| {}
    } else {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE ebpf.tracing tp_btf — no btf_trace_* typedef found.\n", .{});
        return;
    };

    const insns = [_]Insn{ Insn.mov(.r0, 0), Insn.exit() };
    var log: [8192]u8 = undefined;
    var loaded = loadTracing(gpa, .tp_btf, tp, &insns, .{
        .attach_btf_id = try resolveAttachId(&k, .tp_btf, tp),
        .log = &log,
    }) catch |e| {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE ebpf.tracing tp_btf BPF_PROG_LOAD refused ({s}): {s}\n",
            .{ @errorName(e), std.mem.sliceTo(&log, 0) },
        );
        return;
    };
    defer loaded.close();

    var out = attachTpBtfOpts(gpa, loaded.fd, tp, .{ .btf = &k }) catch |e| {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE ebpf.tracing tp_btf BPF_LINK_CREATE refused ({s}).\n", .{@errorName(e)});
        return;
    };
    defer out.detach();
    try testing.expect(out.link.fd >= 0);
}

test "attachExt refuses the pair the kernel would reject" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // The kernel enforces `!!tgt_prog_fd == !!btf_id`; both halves of a
    // half-filled pair are refused here, before any syscall.
    try testing.expectError(error.InvalidTarget, attachExt(3, 0, 7, 0));
    try testing.expectError(error.InvalidTarget, attachExt(3, 5, 0, 0));
}
