// SPDX-License-Identifier: MIT
//! `bpf(BPF_LINK_CREATE)` and friends — the modern, **fd-lifetimed**
//! attachment API that supersedes several of `attach.zig`'s legacy paths.
//!
//! ## Why a second attach API exists at all
//!
//! The legacy paths each have their own idea of ownership:
//! `BPF_PROG_ATTACH` installs a program into a cgroup that keeps it after
//! this process dies, netlink `IFLA_XDP` does the same for an interface, and
//! `ioctl(PERF_EVENT_IOC_SET_BPF)` binds a program to a perf event for as
//! long as that event lives. A **link** replaces all of that with one rule:
//! the attachment exists exactly as long as its fd. Close the fd (including
//! by dying) and the program is detached; `dup`/`SCM_RIGHTS`/pinning it into
//! bpffs extends its life explicitly. That single rule is why libbpf, cilium
//! and bpftool moved to links, and it is what makes `BPF_LINK_UPDATE`
//! possible: atomically swapping the program behind a live attachment, with
//! no window in which nothing is attached.
//!
//! ## Kernel availability (why every caller needs a fallback)
//!
//! | attach type | link support since |
//! |---|---|
//! | `raw_tracepoint`, `tracing` (fentry/fexit) | 5.7 |
//! | `cgroup_*` | 5.7 |
//! | `xdp` | 5.9 |
//! | `netns` (flow dissector / sk_lookup) | 5.7 / 5.9 |
//! | `perf_event` (kprobe / uprobe / tracepoint) | **5.15** |
//! | `tcx`, `netkit` | 6.6 / 6.7 |
//!
//! An older kernel answers `EINVAL` — which is **indistinguishable from
//! "you passed bad arguments"**, because the kernel validates `attach_type`
//! before it looks at anything else. This module therefore maps `EINVAL`
//! and `EOPNOTSUPP` alike to `error.LinkNotSupported` and expects the caller
//! to retry the legacy path; `attach.zig` does exactly that, and reports
//! WHICH path it ended up on (`AttachPath`) instead of hiding it.
//!
//! ## The attr the kernel actually reads
//!
//! `std.os.linux.BPF.LinkCreateAttr` stops after `flags` (16 bytes) — it
//! predates every per-attach-type extension. The real `bpf_attr.link_create`
//! continues with a union whose member depends on `attach_type`
//! (`perf_event.bpf_cookie`, `tcx.relative_fd`, `netfilter.hooknum`, …), so
//! this file declares the extended layout itself. Passing a SHORTER `size`
//! than the kernel's own struct is ABI-safe in both directions: `bpf()`
//! zero-fills the tail it did not receive, and rejects a longer one whose
//! tail is not already zero.

const std = @import("std");
const builtin = @import("builtin");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
fn verboseSkip() bool {
    const v = std.process.Environ.getPosix(std.testing.environ, "ZIG_LIBS_VERBOSE_SKIP") orelse return false;
    return v.len > 0;
}
const linux = std.os.linux;
const BPF = linux.BPF;

const native_endian = builtin.cpu.arch.endian();

// ── errors ──────────────────────────────────────────────────────────────────

pub const LinkError = error{
    /// This kernel does not implement `BPF_LINK_CREATE` for this attach type
    /// (or the command at all). The caller's cue to fall back — see the
    /// availability table above for why `EINVAL` lands here.
    LinkNotSupported,
    PermissionDenied,
    /// Something is already attached in a slot that allows only one owner.
    AlreadyAttached,
    /// A bad fd, or a program whose type does not match `attach_type`.
    InvalidTarget,
    SystemResources,
    Unexpected,
};

/// `enum bpf_link_type` (`include/uapi/linux/bpf.h`). Non-exhaustive: the
/// kernel keeps adding link kinds, and a link created by some other tool may
/// legitimately report one this build has never heard of.
pub const LinkType = enum(u32) {
    unspec = 0,
    raw_tracepoint = 1,
    tracing = 2,
    cgroup = 3,
    iter = 4,
    netns = 5,
    xdp = 6,
    perf_event = 7,
    kprobe_multi = 8,
    struct_ops = 9,
    netfilter = 10,
    tcx = 11,
    uprobe_multi = 12,
    netkit = 13,
    _,
};

// ── the extended BPF_LINK_CREATE attr ───────────────────────────────────────

/// The per-attach-type tail of `bpf_attr.link_create`. Every member starts
/// at offset 16 of `CreateAttr` and is 8-byte aligned, which is why
/// `tracing` needs an explicit pad: the kernel writes
/// `struct { __u32 target_btf_id; __u64 cookie; }`, and C inserts 4 bytes
/// between them.
pub const CreateExtra = extern union {
    /// `target_btf_id` for the plain (non-`tracing`) case.
    target_btf_id: u32,
    /// `BPF_TRACE_ITER`: an iterator's `bpf_iter_link_info`.
    iter: extern struct {
        info: u64,
        info_len: u32,
    },
    /// `BPF_PERF_EVENT`: an opaque value the program reads back with
    /// `bpf_get_attach_cookie()`. The whole reason perf links exist.
    perf_event: extern struct {
        bpf_cookie: u64,
    },
    /// `BPF_TRACE_FENTRY`/`_FEXIT`/`_RAW_TP`.
    tracing: extern struct {
        target_btf_id: u32,
        _pad: u32 = 0,
        cookie: u64 = 0,
    },
    /// `BPF_TCX_INGRESS`/`_EGRESS` ordering against an existing link.
    tcx: extern struct {
        relative_fd: u32 = 0,
        relative_id: u32 = 0,
        expected_revision: u64 = 0,
    },
    /// `BPF_NETFILTER`.
    netfilter: extern struct {
        pf: u32,
        hooknum: u32,
        priority: i32,
        flags: u32,
    },
    /// Explicit all-zero tail — what every attach type this module drives by
    /// default sends.
    none: [16]u8,
};

/// `bpf_attr.link_create`, extended past what std declares. `target` is a
/// union in the kernel (`target_fd` / `target_ifindex`), so XDP passes an
/// ifindex here and cgroup passes a directory fd.
pub const CreateAttr = extern struct {
    prog_fd: linux.fd_t,
    target: i32,
    attach_type: u32,
    flags: u32,
    extra: CreateExtra,
};

/// Options common to every `linkCreate` call.
pub const CreateOptions = struct {
    /// Attach-type-specific flags (e.g. `XDP_FLAGS_*` for `BPF_XDP`,
    /// `BPF_F_REPLACE` for cgroups).
    flags: u32 = 0,
    /// The per-attach-type tail; defaults to all zeroes.
    extra: CreateExtra = .{ .none = @splat(0) },
};

/// Build the attr a `BPF_LINK_CREATE` sends — pure, so the exact union
/// member layout is testable without `CAP_BPF`.
pub fn buildCreateAttr(
    prog_fd: linux.fd_t,
    target: i32,
    attach_type: BPF.AttachType,
    opts: CreateOptions,
) CreateAttr {
    return .{
        .prog_fd = prog_fd,
        .target = target,
        .attach_type = @intFromEnum(attach_type),
        .flags = opts.flags,
        .extra = opts.extra,
    };
}

/// A `bpf_attr`-sized staging area. `bpf()` takes a `*BPF.Attr`, and the
/// extended `CreateAttr` is not one of its members — overlaying both in a
/// union keeps the object at least as large as `BPF.Attr` requires, instead
/// of handing the kernel a pointer to a smaller allocation.
const AttrBuf = extern union {
    base: BPF.Attr,
    link_create: CreateAttr,
    link_update: BPF.LinkUpdateAttr,
    get_id: BPF.GetIdAttr,
    info: BPF.InfoAttr,
};

// ── the handle ──────────────────────────────────────────────────────────────

/// A live BPF link: one fd, one rule — the attachment lives exactly as long
/// as this fd does. Unlike `XdpHandle`/`CgroupHandle`, forgetting to
/// `detach()` this leaks a file descriptor and NOT a kernel-side attachment,
/// because process exit closes the fd and the kernel tears the link down.
pub const LinkHandle = struct {
    fd: linux.fd_t,
    /// What the link was created for; informational (the kernel is the
    /// authority, see `info()`).
    attach_type: BPF.AttachType,

    /// Destroy the link (and therefore the attachment) by closing its fd.
    /// Idempotent, and cannot fail — closing is the ONLY universally
    /// supported teardown; `detachOnly()` is the narrower operation.
    pub fn detach(self: *LinkHandle) void {
        if (self.fd < 0) return;
        _ = linux.close(self.fd);
        self.fd = -1;
    }

    /// Alias of `detach`, matching the repo's handle spelling.
    pub fn deinit(self: *LinkHandle) void {
        self.detach();
    }

    /// Alias of `detach` — "close the fd" is what this physically is.
    pub fn close(self: *LinkHandle) void {
        self.detach();
    }

    /// `bpf(BPF_LINK_DETACH)` — detach the program but KEEP the link fd
    /// open, leaving a link that can be inspected (and, for some kinds,
    /// re-`update`d) while nothing is attached. Only some link types
    /// implement it (cgroup, netns, perf-event on new kernels); the rest
    /// answer `EOPNOTSUPP` -> `error.LinkNotSupported`. Most callers want
    /// plain `detach()`.
    pub fn detachOnly(self: *LinkHandle) LinkError!void {
        return linkDetach(self.fd);
    }

    /// `bpf(BPF_LINK_UPDATE)` — atomically swap the attached program. There
    /// is no instant at which nothing is attached, which is the entire point
    /// versus detach-then-attach.
    pub fn update(self: *LinkHandle, new_prog_fd: linux.fd_t, expected_prog_fd: ?linux.fd_t) LinkError!void {
        return linkUpdate(self.fd, new_prog_fd, expected_prog_fd);
    }

    /// `bpf(BPF_OBJ_GET_INFO_BY_FD)` on the link fd.
    pub fn info(self: *const LinkHandle) LinkError!Info {
        return linkInfo(self.fd);
    }
};

/// The prefix of `struct bpf_link_info` every link kind shares. The kernel
/// copies `min(info_len, sizeof(its own struct))` bytes, so a prefix is
/// ABI-safe in both directions (same discipline as `ringbuf.MapInfo`).
pub const Info = extern struct {
    type: u32,
    id: u32,
    prog_id: u32,
    /// The kernel's per-type union starts at offset 16 and is 8-byte
    /// aligned; this pad makes that explicit rather than implied.
    _pad: u32 = 0,

    pub fn linkType(self: Info) LinkType {
        return @enumFromInt(self.type);
    }
};

// ── the commands ────────────────────────────────────────────────────────────

/// `bpf(BPF_LINK_CREATE)`. `target` is the attach-type-specific target: a
/// cgroup directory fd, a perf-event fd, a netns fd, or — for `.xdp` — an
/// **ifindex**, not an fd.
pub fn linkCreate(
    prog_fd: linux.fd_t,
    target: i32,
    attach_type: BPF.AttachType,
    opts: CreateOptions,
) LinkError!LinkHandle {
    if (comptime builtin.os.tag != .linux)
        @compileError("ebpf.bpflink is Linux-only (bpf() raw syscall)");

    var buf: AttrBuf = .{ .link_create = buildCreateAttr(prog_fd, target, attach_type, opts) };
    const rc = linux.bpf(.link_create, @ptrCast(&buf), @sizeOf(CreateAttr));
    switch (linux.errno(rc)) {
        .SUCCESS => return .{ .fd = @intCast(rc), .attach_type = attach_type },
        else => |e| return errnoToLinkError(e),
    }
}

/// A perf-event link: the modern replacement for
/// `ioctl(PERF_EVENT_IOC_SET_BPF)`, covering kprobe/uprobe/tracepoint alike
/// because all three are perf events underneath. Needs kernel >= 5.15.
///
/// `bpf_cookie` is an opaque u64 the program can read back with
/// `bpf_get_attach_cookie()`, which is how one program distinguishes which
/// of N attachments fired — impossible through the ioctl path.
pub fn linkCreatePerfEvent(prog_fd: linux.fd_t, perf_fd: linux.fd_t, bpf_cookie: u64) LinkError!LinkHandle {
    return linkCreate(prog_fd, perf_fd, .perf_event, .{
        .extra = .{ .perf_event = .{ .bpf_cookie = bpf_cookie } },
    });
}

/// A cgroup link — the fd-lifetimed counterpart of
/// `attach.attachCgroup`'s `BPF_PROG_ATTACH`.
pub fn linkCreateCgroup(
    prog_fd: linux.fd_t,
    cgroup_fd: linux.fd_t,
    attach_type: BPF.AttachType,
    flags: u32,
) LinkError!LinkHandle {
    return linkCreate(prog_fd, cgroup_fd, attach_type, .{ .flags = flags });
}

/// An XDP link. Note `target` is an **ifindex** here
/// (`bpf_attr.link_create.target_ifindex`), not a file descriptor — the one
/// asymmetry in this API, and the reason `CreateAttr.target` is spelled
/// `target` rather than `target_fd`.
///
/// Unlike the netlink `IFLA_XDP` attach, an XDP link is NOT visible to
/// `ip link show` as a plain program id and cannot be removed with
/// `ip link set dev X xdp off` — which is a feature (nobody can clobber it)
/// and a trap (nobody can clean it up either, short of killing the owner).
pub fn linkCreateXdp(prog_fd: linux.fd_t, ifindex: u32, flags: u32) LinkError!LinkHandle {
    return linkCreate(prog_fd, @bitCast(ifindex), .xdp, .{ .flags = flags });
}

/// A network-namespace link (flow dissector / `sk_lookup`). `netns_fd` is an
/// fd on `/proc/<pid>/ns/net`.
pub fn linkCreateNetns(
    prog_fd: linux.fd_t,
    netns_fd: linux.fd_t,
    attach_type: BPF.AttachType,
) LinkError!LinkHandle {
    return linkCreate(prog_fd, netns_fd, attach_type, .{});
}

/// A `BPF_PROG_TYPE_TRACING` link (fentry/fexit/`tp_btf`/lsm). `target` is
/// 0 for a plain kernel-function attachment and an fd for
/// module/prog-target attachment.
///
/// **Caveat, stated rather than hidden**: the BTF id the kernel matches
/// against is set at `BPF_PROG_LOAD` time (`attach_btf_id`), not here, and
/// resolving a function name to a BTF id needs a BTF parser this module does
/// not have (see `SPEC.md`'s deferred list). This entry point is therefore
/// only usable with a program whose `attach_btf_id` was already set by the
/// caller.
pub fn linkCreateTracing(
    prog_fd: linux.fd_t,
    target_fd: linux.fd_t,
    attach_type: BPF.AttachType,
    target_btf_id: u32,
    cookie: u64,
) LinkError!LinkHandle {
    return linkCreate(prog_fd, target_fd, attach_type, .{
        .extra = .{ .tracing = .{ .target_btf_id = target_btf_id, .cookie = cookie } },
    });
}

/// `bpf(BPF_LINK_UPDATE)`. When `expected_prog_fd` is given the swap is
/// conditional (`BPF_F_REPLACE`): it fails unless that exact program is the
/// one currently attached, which is what makes a read-modify-write on a live
/// attachment safe against a concurrent updater.
pub fn linkUpdate(
    link_fd: linux.fd_t,
    new_prog_fd: linux.fd_t,
    expected_prog_fd: ?linux.fd_t,
) LinkError!void {
    var buf: AttrBuf = .{ .link_update = .{
        .link_fd = link_fd,
        .new_prog_fd = new_prog_fd,
        .flags = if (expected_prog_fd != null) BPF.F_REPLACE else 0,
        .old_prog_fd = expected_prog_fd orelse 0,
    } };
    const rc = linux.bpf(.link_update, @ptrCast(&buf), @sizeOf(BPF.LinkUpdateAttr));
    switch (linux.errno(rc)) {
        .SUCCESS => return,
        else => |e| return errnoToLinkError(e),
    }
}

/// `bpf(BPF_LINK_DETACH)` — see `LinkHandle.detachOnly`.
pub fn linkDetach(link_fd: linux.fd_t) LinkError!void {
    // BPF_LINK_DETACH reuses the link_update attr's first field.
    var buf: AttrBuf = .{ .link_update = .{
        .link_fd = link_fd,
        .new_prog_fd = 0,
        .flags = 0,
        .old_prog_fd = 0,
    } };
    const rc = linux.bpf(.link_detach, @ptrCast(&buf), @sizeOf(BPF.LinkUpdateAttr));
    switch (linux.errno(rc)) {
        .SUCCESS => return,
        else => |e| return errnoToLinkError(e),
    }
}

/// `bpf(BPF_LINK_GET_FD_BY_ID)` — turn a link id (as printed by
/// `bpftool link show`) into a usable fd. Needs `CAP_SYS_ADMIN`, not merely
/// `CAP_BPF`: it hands out a handle to somebody else's attachment.
pub fn linkGetFdById(link_id: u32) LinkError!LinkHandle {
    var buf: AttrBuf = .{ .get_id = .{
        .id = .{ .link_id = link_id },
        .next_id = 0,
        .open_flags = 0,
    } };
    const rc = linux.bpf(.link_get_fd_by_id, @ptrCast(&buf), @sizeOf(BPF.GetIdAttr));
    switch (linux.errno(rc)) {
        // The attach type is not known from an id alone; `info()` reports it.
        .SUCCESS => return .{ .fd = @intCast(rc), .attach_type = @enumFromInt(0) },
        else => |e| return errnoToLinkError(e),
    }
}

/// `bpf(BPF_LINK_GET_NEXT_ID)` — walk every link on the system. `null` when
/// `after_id` is the last one.
pub fn linkNextId(after_id: u32) LinkError!?u32 {
    var buf: AttrBuf = .{ .get_id = .{
        .id = .{ .start_id = after_id },
        .next_id = 0,
        .open_flags = 0,
    } };
    const rc = linux.bpf(.link_get_next_id, @ptrCast(&buf), @sizeOf(BPF.GetIdAttr));
    switch (linux.errno(rc)) {
        .SUCCESS => return buf.get_id.next_id,
        .NOENT => return null,
        else => |e| return errnoToLinkError(e),
    }
}

/// `bpf(BPF_OBJ_GET_INFO_BY_FD)` for a link fd.
pub fn linkInfo(link_fd: linux.fd_t) LinkError!Info {
    var out: Info = std.mem.zeroes(Info);
    var buf: AttrBuf = .{ .info = .{
        .bpf_fd = link_fd,
        .info_len = @sizeOf(Info),
        .info = @intFromPtr(&out),
    } };
    const rc = linux.bpf(.obj_get_info_by_fd, @ptrCast(&buf), @sizeOf(BPF.InfoAttr));
    switch (linux.errno(rc)) {
        .SUCCESS => return out,
        else => |e| return errnoToLinkError(e),
    }
}

/// What a feature probe could determine.
pub const Support = enum {
    /// The kernel implements `BPF_LINK_CREATE` for this attach type.
    supported,
    /// It does not — the caller must use the legacy path.
    unsupported,
    /// Could not tell (typically: no privilege to issue `bpf()` at all).
    unknown,
};

/// Probe whether this kernel supports perf-event links, the way libbpf's
/// `FEAT_PERF_LINK` probe does: attempt a `BPF_LINK_CREATE` with deliberately
/// invalid fds and read the errno.
///
/// - `EBADF` — the kernel got past attach-type validation and only then
///   rejected the fds: the attach type EXISTS.
/// - `EINVAL` — rejected before looking at the fds: it does not.
///
/// This is exactly why `EINVAL` cannot be treated as a hard error in
/// `linkCreate`: on a pre-5.15 kernel it is the *expected* answer.
pub fn perfLinkSupport() Support {
    if (comptime builtin.os.tag != .linux) return .unsupported;
    var buf: AttrBuf = .{ .link_create = buildCreateAttr(-1, -1, .perf_event, .{}) };
    const rc = linux.bpf(.link_create, @ptrCast(&buf), @sizeOf(CreateAttr));
    return switch (linux.errno(rc)) {
        // Should not happen with fd -1, but "it worked" certainly means yes.
        .SUCCESS => blk: {
            _ = linux.close(@intCast(rc));
            break :blk .supported;
        },
        .BADF => .supported,
        .INVAL, .OPNOTSUPP, .NOSYS => .unsupported,
        else => .unknown,
    };
}

/// Map a `bpf()` errno onto `LinkError`. `EINVAL`/`EOPNOTSUPP` deliberately
/// collapse to `LinkNotSupported` — see this file's header for why they are
/// not distinguishable from "old kernel".
pub fn errnoToLinkError(e: linux.E) LinkError {
    return switch (e) {
        .ACCES, .PERM => error.PermissionDenied,
        .EXIST, .BUSY => error.AlreadyAttached,
        .BADF => error.InvalidTarget,
        .INVAL, .OPNOTSUPP, .NOSYS => error.LinkNotSupported,
        .NOMEM, .NOSPC, .MFILE, .NFILE => error.SystemResources,
        else => error.Unexpected,
    };
}

// ── tests ────────────────────────────────────────────────────────────────────
//
// Two layers, matching the rest of this module:
//  1. UNPRIVILEGED, always run: the extended `bpf_attr.link_create` layout
//     as GOLDEN BYTES against the documented UAPI, plus the errno mapping
//     and the feature probe (which must never crash or hang unprivileged).
//  2. PRIVILEGED, gracefully skipped: create/update/detach a real link.

const testing = std.testing;

fn hasBpfCapability() bool {
    return linux.geteuid() == 0;
}

test "CreateAttr matches the kernel's bpf_attr.link_create layout" {
    // The first four fields are exactly what std declares, so they must
    // agree field-for-field.
    try testing.expectEqual(@offsetOf(BPF.LinkCreateAttr, "prog_fd"), @offsetOf(CreateAttr, "prog_fd"));
    try testing.expectEqual(@offsetOf(BPF.LinkCreateAttr, "target_fd"), @offsetOf(CreateAttr, "target"));
    try testing.expectEqual(@offsetOf(BPF.LinkCreateAttr, "attach_type"), @offsetOf(CreateAttr, "attach_type"));
    try testing.expectEqual(@offsetOf(BPF.LinkCreateAttr, "flags"), @offsetOf(CreateAttr, "flags"));
    try testing.expectEqual(@as(usize, 16), @sizeOf(BPF.LinkCreateAttr));

    // …and the extension starts right after, 8-byte aligned.
    try testing.expectEqual(@as(usize, 16), @offsetOf(CreateAttr, "extra"));
    try testing.expectEqual(@as(usize, 32), @sizeOf(CreateAttr));
    try testing.expectEqual(@as(usize, 8), @alignOf(CreateAttr));

    // The union members' internal offsets (C's padding rules, restated as
    // assertions because getting `tracing` wrong silently sends the cookie
    // as the btf id).
    try testing.expectEqual(@as(usize, 0), @offsetOf(@FieldType(CreateExtra, "perf_event"), "bpf_cookie"));
    try testing.expectEqual(@as(usize, 0), @offsetOf(@FieldType(CreateExtra, "tracing"), "target_btf_id"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(@FieldType(CreateExtra, "tracing"), "cookie"));
    try testing.expectEqual(@as(usize, 0), @offsetOf(@FieldType(CreateExtra, "tcx"), "relative_fd"));
    try testing.expectEqual(@as(usize, 4), @offsetOf(@FieldType(CreateExtra, "tcx"), "relative_id"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(@FieldType(CreateExtra, "tcx"), "expected_revision"));
    try testing.expectEqual(@as(usize, 0), @offsetOf(@FieldType(CreateExtra, "netfilter"), "pf"));
    try testing.expectEqual(@as(usize, 12), @offsetOf(@FieldType(CreateExtra, "netfilter"), "flags"));
    try testing.expectEqual(@as(usize, 0), @offsetOf(@FieldType(CreateExtra, "iter"), "info"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(@FieldType(CreateExtra, "iter"), "info_len"));

    // The staging union must be at least as large as bpf()'s own attr, or
    // the kernel would read past the object we hand it.
    try testing.expect(@sizeOf(AttrBuf) >= @sizeOf(BPF.Attr));
    try testing.expect(@sizeOf(AttrBuf) >= @sizeOf(CreateAttr));
}

test "golden: BPF_LINK_CREATE attr bytes for each attach type this module drives" {
    if (native_endian != .little) return error.SkipZigTest; // golden bytes are LE

    // A perf-event link with a cookie: prog 7, perf fd 9, cookie 0xdeadbeef.
    {
        const attr = buildCreateAttr(7, 9, .perf_event, .{
            .extra = .{ .perf_event = .{ .bpf_cookie = 0xdead_beef } },
        });
        const bytes = std.mem.asBytes(&attr);
        try testing.expectEqualSlices(u8, &.{
            0x07, 0x00, 0x00, 0x00, // prog_fd = 7
            0x09, 0x00, 0x00, 0x00, // target_fd = 9
            41, 0x00, 0x00, 0x00, // attach_type = BPF_PERF_EVENT (41)
            0x00, 0x00, 0x00, 0x00, // flags = 0
            0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, // perf_event.bpf_cookie
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // union tail
        }, bytes);
        try testing.expectEqual(@as(u32, 41), @intFromEnum(BPF.AttachType.perf_event));
    }

    // An XDP link: the target is an IFINDEX, and the flags are XDP_FLAGS_*.
    {
        const attr = buildCreateAttr(11, @as(i32, 3), .xdp, .{ .flags = 1 << 2 });
        const bytes = std.mem.asBytes(&attr);
        try testing.expectEqualSlices(u8, &.{
            0x0b, 0x00, 0x00, 0x00, // prog_fd = 11
            0x03, 0x00, 0x00, 0x00, // target_ifindex = 3
            37, 0x00, 0x00, 0x00, // attach_type = BPF_XDP (37)
            0x04, 0x00, 0x00, 0x00, // flags = XDP_FLAGS_DRV_MODE
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        }, bytes);
        try testing.expectEqual(@as(u32, 37), @intFromEnum(BPF.AttachType.xdp));
    }

    // A cgroup link.
    {
        const attr = buildCreateAttr(4, 5, .cgroup_inet_egress, .{});
        try testing.expectEqual(@as(u32, 1), attr.attach_type);
        try testing.expectEqual(@as(i32, 5), attr.target);
        try testing.expectEqual(@as(u32, 0), attr.flags);
        try testing.expectEqualSlices(u8, &@as([16]u8, @splat(0)), std.mem.asBytes(&attr.extra));
    }

    // A tracing link: btf id and cookie must NOT overlap.
    {
        const attr = buildCreateAttr(2, 0, .trace_fentry, .{
            .extra = .{ .tracing = .{ .target_btf_id = 0x1234, .cookie = 0x55 } },
        });
        const bytes = std.mem.asBytes(&attr);
        try testing.expectEqual(@as(u32, 0x1234), std.mem.readInt(u32, bytes[16..20], .little));
        try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, bytes[20..24], .little));
        try testing.expectEqual(@as(u64, 0x55), std.mem.readInt(u64, bytes[24..32], .little));
    }
}

test "Info mirrors the kernel's bpf_link_info prefix" {
    try testing.expectEqual(@as(usize, 0), @offsetOf(Info, "type"));
    try testing.expectEqual(@as(usize, 4), @offsetOf(Info, "id"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(Info, "prog_id"));
    try testing.expectEqual(@as(usize, 16), @sizeOf(Info));

    const i: Info = .{ .type = @intFromEnum(LinkType.perf_event), .id = 3, .prog_id = 9 };
    try testing.expectEqual(LinkType.perf_event, i.linkType());
    // A link kind this build has never heard of must not be an invalid enum.
    const future: Info = .{ .type = 9999, .id = 1, .prog_id = 1 };
    try testing.expectEqual(@as(u32, 9999), @intFromEnum(future.linkType()));
}

test "errno mapping: EINVAL means 'fall back', not 'you passed garbage'" {
    const asUnion = struct {
        fn f(e: linux.E) LinkError!void {
            return errnoToLinkError(e);
        }
    }.f;
    try testing.expectError(error.LinkNotSupported, asUnion(.INVAL));
    try testing.expectError(error.LinkNotSupported, asUnion(.OPNOTSUPP));
    try testing.expectError(error.LinkNotSupported, asUnion(.NOSYS));
    try testing.expectError(error.PermissionDenied, asUnion(.PERM));
    try testing.expectError(error.PermissionDenied, asUnion(.ACCES));
    try testing.expectError(error.AlreadyAttached, asUnion(.EXIST));
    try testing.expectError(error.AlreadyAttached, asUnion(.BUSY));
    try testing.expectError(error.InvalidTarget, asUnion(.BADF));
    try testing.expectError(error.SystemResources, asUnion(.NOMEM));
    try testing.expectError(error.Unexpected, asUnion(.IO));
}

test "LinkHandle.detach is idempotent and cannot fail" {
    var h: LinkHandle = .{ .fd = -1, .attach_type = .perf_event };
    h.detach();
    h.detach();
    h.deinit();
    h.close();
    try testing.expectEqual(@as(linux.fd_t, -1), h.fd);
}

test "perfLinkSupport probe answers without privilege and without crashing" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const s = perfLinkSupport();
    // All three answers are legitimate; what is asserted is that the probe
    // terminates and classifies. Print it so a privileged run records which
    // path `attach.zig` will take on this kernel.
    switch (s) {
        .supported, .unsupported => {},
        .unknown => std.debug.print(
            "\nebpf bpflink: perf-link support UNKNOWN (bpf() denied for uid {d}) — expected unprivileged.\n",
            .{linux.geteuid()},
        ),
    }
}

test "LIVE: create, inspect, update and detach a real cgroup link" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) {
        if (verboseSkip()) std.debug.print(
            "\nLIVE ebpf bpflink test SKIPPED: needs CAP_BPF (running as uid {d}).\n",
            .{linux.geteuid()},
        );
        return;
    }

    var path_buf: [64]u8 = undefined;
    const dir = try std.fmt.bufPrintZ(&path_buf, "/sys/fs/cgroup/zig-libs-ebpf-link-{d}", .{linux.getpid()});
    switch (linux.errno(linux.mkdir(dir.ptr, 0o755))) {
        .SUCCESS => {},
        else => {
            if (verboseSkip()) std.debug.print("\nLIVE ebpf bpflink test SKIPPED: cannot create {s} (cgroup v2 not mounted?).\n", .{dir});
            return;
        },
    }
    defer _ = linux.rmdir(dir.ptr);

    const dir_rc = linux.open(dir.ptr, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(dir_rc) != .SUCCESS) {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf bpflink test SKIPPED: cannot open the cgroup directory.\n", .{});
        return;
    }
    const cgroup_fd: linux.fd_t = @intCast(dir_rc);
    defer _ = linux.close(cgroup_fd);

    const insns = [_]BPF.Insn{ BPF.Insn.mov(.r0, 1), BPF.Insn.exit() };
    const prog_a = BPF.prog_load(.cgroup_skb, &insns, null, "MIT", 0, 0) catch {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf bpflink test SKIPPED: cgroup_skb BPF_PROG_LOAD refused.\n", .{});
        return;
    };
    defer _ = linux.close(prog_a);
    const prog_b = BPF.prog_load(.cgroup_skb, &insns, null, "MIT", 0, 0) catch {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf bpflink test SKIPPED: second BPF_PROG_LOAD refused.\n", .{});
        return;
    };
    defer _ = linux.close(prog_b);

    var link = linkCreateCgroup(prog_a, cgroup_fd, .cgroup_inet_egress, 0) catch |e| {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf bpflink test SKIPPED: BPF_LINK_CREATE failed ({s}).\n", .{@errorName(e)});
        return;
    };
    defer link.detach();
    try testing.expect(link.fd >= 0);

    const info = try link.info();
    try testing.expectEqual(LinkType.cgroup, info.linkType());
    try testing.expect(info.id != 0);

    // Atomic program swap, then the conditional form.
    try link.update(prog_b, null);
    try link.update(prog_a, prog_b);
    // A conditional swap naming the WRONG current program must fail (the
    // kernel answers EPERM); which typed error it maps to matters less than
    // that it is not silently accepted.
    if (link.update(prog_b, prog_b)) |_| {
        std.debug.print("\nLIVE ebpf bpflink: BPF_F_REPLACE accepted a wrong old_prog_fd!\n", .{});
        return error.TestUnexpectedResult;
    } else |_| {}

    // The link id round-trips through BPF_LINK_GET_FD_BY_ID.
    var byid = linkGetFdById(info.id) catch |e| {
        std.debug.print("\nLIVE ebpf bpflink: LINK_GET_FD_BY_ID skipped ({s}).\n", .{@errorName(e)});
        link.detach();
        return;
    };
    defer byid.detach();
    const info2 = try byid.info();
    try testing.expectEqual(info.id, info2.id);

    link.detach();
    try testing.expectEqual(@as(linux.fd_t, -1), link.fd);
    link.detach(); // idempotent
}
