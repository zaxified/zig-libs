// SPDX-License-Identifier: MIT
//! Attach mechanisms — syscall plumbing wiring an already-loaded `prog_fd`
//! (from `load.zig`) to a kernel hook. Nothing here is a verifier problem:
//! every constraint below is "which syscalls, in which order, with which
//! struct fields", unlike `programs.zig`'s bytecode generation.
//!
//! Six hooks are implemented, each with its own lifetime rule — the single
//! most important thing to get right, because two of them OUTLIVE this
//! process if not explicitly torn down:
//!
//! | hook | syscall path | detach | survives process exit? |
//! |---|---|---|---|
//! | kprobe / kretprobe | `perf_event_open` (kprobe PMU) + link-or-`ioctl(SET_BPF)` + `ioctl(ENABLE)` | close the fd(s) | **no** — the kernel tears the probe down with the fd |
//! | uprobe / uretprobe | `perf_event_open` (uprobe PMU, `config1` = a PATH, `config2` = a FILE OFFSET) + same binding step | close the fd(s) | **no** |
//! | tracepoint | `/sys/kernel/tracing/events/<cat>/<name>/id` + `perf_event_open(PERF_TYPE_TRACEPOINT)` + same binding step | close the fd(s) | **no** |
//! | raw tracepoint | `bpf(BPF_RAW_TRACEPOINT_OPEN)` — no perf event at all | close the fd | **no** |
//! | XDP | netlink `RTM_SETLINK` + nested `IFLA_XDP`, **or** `bpf(BPF_LINK_CREATE)` | `IFLA_XDP_FD = -1` / close the link fd | **yes** for netlink, **no** for a link |
//! | cgroup | `bpf(BPF_PROG_ATTACH)`, **or** `bpf(BPF_LINK_CREATE)` | `bpf(BPF_PROG_DETACH)` / close the link fd | **yes** for PROG_ATTACH, **no** for a link |
//!
//! So `KprobeHandle`/`PerfEventHandle`/`RawTracepointHandle` are pure RAII fd
//! wrappers, while `XdpHandle` and `CgroupHandle` describe attachments that
//! persist in the kernel until someone asks for them to go away: dropping one
//! without `detach()` leaks a live attachment (an XDP program on a NIC / a
//! filter on a cgroup), not just a file descriptor. `Link` unifies all six
//! behind one `detach()`.
//!
//! ## Legacy path vs. `BPF_LINK_CREATE`
//!
//! Four of the six hooks have a modern, fd-lifetimed alternative (see
//! `bpflink.zig`). Where both exist this module **prefers the link** and
//! falls back to the legacy path — but never silently: every such entry
//! point reports an `AttachPath` (`.bpf_link` or `.legacy`), and
//! `LinkPreference` lets a caller force either one so both branches are
//! reachable from a test. The fallback matters because perf-event links need
//! kernel >= 5.15 and answer plain `EINVAL` before that, which is
//! indistinguishable from "bad arguments" (see `bpflink.zig`'s header).
//!
//! The one place the default is deliberately NOT the link is `attachXdp`:
//! its netlink attachment is what `ip link show`/`bpftool net` display, and
//! changing that default would change what an operator sees. `attachXdpAuto`
//! is the opt-in link-preferring variant.
//!
//! Everything here needs privilege: `CAP_BPF` at minimum, plus
//! `CAP_PERFMON`/`CAP_SYS_ADMIN` for the kprobe/uprobe PMUs and tracepoints,
//! and `CAP_NET_ADMIN` for XDP. Every gated test in this file SKIPS
//! (printing why) rather than failing when the privilege is absent.

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
const netlink = @import("netlink");
const codec = netlink.codec;
const bpflink = @import("bpflink.zig");
const elfsym = @import("elfsym.zig");

const native_endian = builtin.cpu.arch.endian();

// ── wire constants not present in std ───────────────────────────────────────

/// `linux/perf_event.h` ioctl request numbers. std's `os/linux.zig` defines
/// `perf_event_attr` and the `perf_event_open` syscall wrapper but NOT these,
/// so they are derived here from the kernel's `_IO`/`_IOW` macros:
/// `_IOC(dir, type, nr, size) = (dir << 30) | (size << 16) | (type << 8) | nr`
/// with `dir` = 0 for `_IO` and 1 (`_IOC_WRITE`) for `_IOW`, `type` = `'$'`
/// (0x24). Same hand-encoding discipline the repo's other ioctl users follow.
pub const PERF_EVENT_IOC = struct {
    fn io(nr: u32) u32 {
        return (0x24 << 8) | nr;
    }
    fn iow(nr: u32, comptime T: type) u32 {
        return (1 << 30) | (@as(u32, @sizeOf(T)) << 16) | (0x24 << 8) | nr;
    }

    /// `_IO('$', 0)` — arm the event.
    pub const ENABLE: u32 = io(0);
    /// `_IO('$', 1)` — disarm the event.
    pub const DISABLE: u32 = io(1);
    /// `_IOW('$', 8, __u32)` — attach a BPF program fd to the event.
    pub const SET_BPF: u32 = iow(8, u32);
};

/// `PERF_FLAG_FD_CLOEXEC` (`1 << 3`) — `perf_event_open`'s only flag this
/// module uses; without it the perf fd leaks across `exec`.
pub const PERF_FLAG_FD_CLOEXEC: usize = 1 << 3;

const kprobe_pmu_type_path = "/sys/bus/event_source/devices/kprobe/type";
const kprobe_retprobe_fmt_path = "/sys/bus/event_source/devices/kprobe/format/retprobe";
const uprobe_pmu_type_path = "/sys/bus/event_source/devices/uprobe/type";
const uprobe_retprobe_fmt_path = "/sys/bus/event_source/devices/uprobe/format/retprobe";
const uprobe_ref_ctr_fmt_path = "/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset";

/// Where the kernel exposes static tracepoints. The first is the modern
/// mount (`tracefs`, since 4.1); the second is the historical location under
/// `debugfs`, still what a kernel with only `CONFIG_DEBUG_FS` tracing offers
/// and what plenty of older distros mount. Tried in this order.
const tracefs_roots = [_][]const u8{
    "/sys/kernel/tracing",
    "/sys/kernel/debug/tracing",
};

/// `RTM_SETLINK` (`linux/rtnetlink.h`) — not re-exported by the sibling
/// `netlink` module (which only needs the `RTM_GET*`/`RTM_NEW*` pairs).
pub const RTM_SETLINK: u16 = 19;

/// `IFLA_XDP` (`linux/if_link.h`) — the nested attribute carrying the XDP
/// attach request inside an `RTM_SETLINK` message.
pub const IFLA_XDP: u16 = 43;

/// `IFLA_XDP`'s child attribute ids (`enum { IFLA_XDP_UNSPEC, ... }`).
pub const IFLA_XDP_ATTR = struct {
    pub const FD: u16 = 1;
    pub const ATTACHED: u16 = 2;
    pub const FLAGS: u16 = 3;
    pub const PROG_ID: u16 = 4;
    pub const DRV_PROG_ID: u16 = 5;
    pub const SKB_PROG_ID: u16 = 6;
    pub const HW_PROG_ID: u16 = 7;
    pub const EXPECTED_FD: u16 = 8;
};

/// `XDP_FLAGS_*` (`linux/if_link.h`).
pub const XDP_FLAGS = struct {
    pub const UPDATE_IF_NOEXIST: u32 = 1 << 0;
    pub const SKB_MODE: u32 = 1 << 1;
    pub const DRV_MODE: u32 = 1 << 2;
    pub const HW_MODE: u32 = 1 << 3;
    pub const REPLACE: u32 = 1 << 4;
    pub const MODES: u32 = SKB_MODE | DRV_MODE | HW_MODE;
};

// ── the uniform attachment handle ───────────────────────────────────────────

/// Errors any `Link.detach()` can produce (the union of the per-hook detach
/// error sets; kprobe/perf-event/raw-tracepoint/BPF-link detaches are all
/// just `close()` and cannot fail).
pub const DetachError = XdpAttachError || CgroupAttachError;

/// Which of the two attach mechanisms an entry point ended up using. Returned
/// rather than inferred so a fallback is observable — a silent fallback is
/// how a caller ends up with an attachment whose lifetime rules are not the
/// ones it reasoned about.
pub const AttachPath = enum {
    /// `bpf(BPF_LINK_CREATE)` — fd-lifetimed, dies with this process.
    bpf_link,
    /// The pre-link syscall for this hook (`ioctl(SET_BPF)`, netlink
    /// `IFLA_XDP`, `BPF_PROG_ATTACH`).
    legacy,
};

/// How hard to try for a `BPF_LINK_CREATE` attachment.
pub const LinkPreference = enum {
    /// Try the link; fall back to the legacy path if the kernel says no.
    auto,
    /// Link or nothing (`error.LinkNotSupported` on an older kernel). Makes
    /// the link branch testable in isolation.
    link_only,
    /// Never attempt a link. Makes the fallback branch testable in isolation
    /// even on a kernel that does support links.
    legacy_only,
};

/// A live attachment, whatever its kind. Always either `detach()`ed (which
/// reports failures) or `deinit()`ed (best-effort, for `defer`) — see the
/// lifetime table at the top of this file for what leaks if you do neither.
pub const Link = union(enum) {
    kprobe: KprobeHandle,
    xdp: XdpHandle,
    cgroup: CgroupHandle,
    /// uprobe / uretprobe / tracepoint (and any other perf-event-backed
    /// probe) — see `PerfEventHandle`.
    perf_event: PerfEventHandle,
    /// `BPF_RAW_TRACEPOINT_OPEN`.
    raw_tracepoint: RawTracepointHandle,
    /// A `bpf(BPF_LINK_CREATE)` link, whatever it points at.
    bpf_link: bpflink.LinkHandle,

    /// Tear the attachment down, reporting failures. Idempotent: a second
    /// call on an already-detached link is a no-op.
    pub fn detach(self: *Link) DetachError!void {
        switch (self.*) {
            .kprobe => |*h| h.detach(),
            .xdp => |*h| try h.detach(),
            .cgroup => |*h| try h.detach(),
            .perf_event => |*h| h.detach(),
            .raw_tracepoint => |*h| h.detach(),
            .bpf_link => |*h| h.detach(),
        }
    }

    /// `defer`-friendly detach: best effort, errors dropped. Prefer
    /// `detach()` where the caller can act on a failure.
    pub fn deinit(self: *Link) void {
        self.detach() catch {};
    }

    /// Wrap a raw `bpflink.LinkHandle` (e.g. one obtained from
    /// `bpflink.linkGetFdById`) in the uniform handle.
    pub fn fromBpfLink(h: bpflink.LinkHandle) Link {
        return .{ .bpf_link = h };
    }
};

// ── kprobe attach (perf_event_open + ioctl) ─────────────────────────────────

pub const KprobeAttachError = error{
    /// /sys/bus/event_source/devices/kprobe/type is missing (kernel built
    /// without CONFIG_KPROBE_EVENTS) or unreadable.
    KprobePmuUnavailable,
    SymbolNotFound,
    /// `symbol` is empty or contains an interior NUL (it is passed to the
    /// kernel as a C string via `perf_event_attr.config1`).
    InvalidSymbol,
    PermissionDenied,
    OutOfMemory,
    SystemResources,
    /// `link_preference = .link_only` but this kernel has no perf-event
    /// links (needs >= 5.15), or a non-zero `bpf_cookie` was requested and
    /// the attach had to fall back to the cookie-less legacy path.
    LinkNotSupported,
    Unexpected,
};

/// Knobs for `attachKprobeOpts`. The defaults are the system-wide
/// function-entry probe `attachKprobe` installs.
pub const KprobeOptions = struct {
    /// Probe the function's RETURN instead of its entry (kretprobe). Encoded
    /// as a bit in `perf_event_attr.config` whose position is read from the
    /// kprobe PMU's `format/retprobe` sysfs file (`"config:N"`), exactly as
    /// libbpf does — the bit is ABI-stable at 0 in every kernel shipped so
    /// far, but it is declared by the kernel, so read it rather than assume.
    retprobe: bool = false,
    /// Byte offset from the symbol; 0 = function entry. Non-zero offsets are
    /// only valid for entry probes and only where the kernel can prove the
    /// address is an instruction boundary.
    offset: u64 = 0,
    /// `-1` (default) = system-wide: probe every task. A non-negative pid
    /// restricts the perf event to that task.
    pid: i32 = -1,
    /// CPU the perf event is opened on when `pid == -1`. ONE fd is enough for
    /// a system-wide kprobe even though it names a single CPU: the BPF
    /// program is attached by `ioctl(PERF_EVENT_IOC_SET_BPF)` to the
    /// event's underlying *trace event*, which is global, not to the per-CPU
    /// perf event — so the program runs on every CPU that hits the probe.
    /// (This is exactly what libbpf's `perf_event_open_probe` does: pid -1,
    /// cpu 0, one fd. Per-CPU fd fan-out is needed for perf *sampling*
    /// buffers, not for BPF kprobe attachment.)
    cpu: i32 = 0,
    /// Prefer `BPF_LINK_CREATE` (kernel >= 5.15) over
    /// `ioctl(PERF_EVENT_IOC_SET_BPF)`, falling back when unavailable. The
    /// resulting `KprobeHandle.path` says which one happened.
    link_preference: LinkPreference = .auto,
    /// An opaque value the program reads back with `bpf_get_attach_cookie()`
    /// — how one program tells N attachments apart. Only the link path can
    /// carry it, so a non-zero cookie turns a fallback into
    /// `error.LinkNotSupported` rather than silently dropping it.
    bpf_cookie: u64 = 0,
};

/// An attached kprobe: the open perf-event fd (plus, when the modern path
/// was taken, the BPF link fd that binds the program to it). Detach = close
/// them — the kernel tears down the dynamic probe AND the BPF attachment
/// together, and does so automatically if the process dies, so this handle
/// cannot leak a kernel-side attachment (only fds).
pub const KprobeHandle = struct {
    perf_fd: linux.fd_t,
    /// The `BPF_LINK_CREATE` fd binding the program to `perf_fd`, or `-1`
    /// when the legacy `ioctl(PERF_EVENT_IOC_SET_BPF)` path was used.
    /// Defaulted so pre-existing `.{ .perf_fd = … }` literals still compile.
    link_fd: linux.fd_t = -1,
    /// Which binding path this attachment actually took.
    path: AttachPath = .legacy,

    /// Disable and close the perf event (and the link, if any). Idempotent.
    pub fn detach(self: *KprobeHandle) void {
        // Close the link FIRST: it holds a reference to the perf event, and
        // dropping the binding before the event is the order that leaves no
        // window in which a half-torn-down attachment is observable.
        if (self.link_fd >= 0) {
            _ = linux.close(self.link_fd);
            self.link_fd = -1;
        }
        if (self.perf_fd < 0) return;
        _ = linux.ioctl(self.perf_fd, PERF_EVENT_IOC.DISABLE, 0);
        _ = linux.close(self.perf_fd);
        self.perf_fd = -1;
    }

    /// Alias of `detach` (no failure mode) — matches the `deinit` spelling
    /// the rest of this repo's handles use.
    pub fn deinit(self: *KprobeHandle) void {
        self.detach();
    }

    /// Alias of `detach`, kept because "close the perf fd" is what this
    /// physically is.
    pub fn close(self: *KprobeHandle) void {
        self.detach();
    }

    pub fn link(self: KprobeHandle) Link {
        return .{ .kprobe = self };
    }
};

/// Attach `prog_fd` to kernel function `symbol`'s entry via a dynamic kprobe
/// on the kernel's `kprobe` PMU. `prog_fd` must have been loaded with
/// `prog_type = .kprobe`.
///
/// Sequence (all five steps are in `attachKprobeOpts`):
///  1. Read the kprobe PMU's kernel-assigned numeric `type` id from
///     `/sys/bus/event_source/devices/kprobe/type` — kprobes are a *dynamic*
///     PMU, not one of the static `PERF.TYPE` values.
///  2. Build a `perf_event_attr` naming the probe through the
///     `config1`/`config2` union fields (`kprobe_func` = a C string pointer to
///     the symbol, `probe_offset`), not through `config` (which only carries
///     the retprobe bit here).
///  3. `perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC)`.
///  4. `ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd)`.
///  5. `ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0)`.
///
/// The returned handle owns the perf fd; `prog_fd` stays owned by the caller
/// (the kernel takes its own reference for the duration of the attachment).
pub fn attachKprobe(gpa: std.mem.Allocator, symbol: []const u8, prog_fd: linux.fd_t) KprobeAttachError!KprobeHandle {
    return attachKprobeOpts(gpa, symbol, prog_fd, .{});
}

/// `attachKprobe` with `retprobe = true`: fire on the probed function's
/// RETURN. Same lifetime rules as `attachKprobe`.
pub fn attachKretprobe(gpa: std.mem.Allocator, symbol: []const u8, prog_fd: linux.fd_t) KprobeAttachError!KprobeHandle {
    return attachKprobeOpts(gpa, symbol, prog_fd, .{ .retprobe = true });
}

/// `attachKprobe` with every knob exposed — see `KprobeOptions`.
pub fn attachKprobeOpts(
    gpa: std.mem.Allocator,
    symbol: []const u8,
    prog_fd: linux.fd_t,
    opts: KprobeOptions,
) KprobeAttachError!KprobeHandle {
    if (comptime builtin.os.tag != .linux)
        @compileError("ebpf.attachKprobe is Linux-only (perf_event_open + BPF)");

    if (symbol.len == 0) return error.InvalidSymbol;
    if (std.mem.indexOfScalar(u8, symbol, 0) != null) return error.InvalidSymbol;

    const pmu_type = try kprobePmuType();
    const retprobe_bit = kprobeRetprobeBit();

    const sym_z = try gpa.dupeZ(u8, symbol);
    defer gpa.free(sym_z);

    var attr = buildKprobeAttr(pmu_type, retprobe_bit, opts.retprobe, sym_z.ptr, opts.offset);

    // libbpf's convention: a system-wide probe is (pid = -1, cpu = N); a
    // task-scoped one is (pid = N, cpu = -1). Passing both as "any" is
    // rejected by the kernel with EINVAL.
    const pid: linux.pid_t = if (opts.pid < 0) -1 else opts.pid;
    const cpu: i32 = if (opts.pid < 0) opts.cpu else -1;

    const rc = linux.perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        // An unknown kernel symbol surfaces as ENOENT on most kernels and as
        // EINVAL on some older ones (the kprobe registration path changed
        // which code rejects it); both mean "that symbol is not probeable".
        .NOENT, .INVAL => return error.SymbolNotFound,
        .OPNOTSUPP, .NODEV => return error.KprobePmuUnavailable,
        .MFILE, .NFILE, .NOMEM, .NOSPC => return error.SystemResources,
        else => return error.Unexpected,
    }
    const perf_fd: linux.fd_t = @intCast(rc);
    var handle: KprobeHandle = .{ .perf_fd = perf_fd };
    errdefer handle.detach();

    const binding = try bindPerfEvent(perf_fd, prog_fd, opts.link_preference, opts.bpf_cookie);
    handle.link_fd = binding.link_fd;
    handle.path = binding.path;
    return handle;
}

// ── binding a program to an already-open perf event ─────────────────────────

/// The result of `bindPerfEvent`: which path was taken and, when it was the
/// link path, the link fd the caller now owns.
pub const PerfBinding = struct {
    /// `-1` on the legacy path.
    link_fd: linux.fd_t = -1,
    path: AttachPath,
};

/// Errors the shared perf-event binding step can produce. A subset of every
/// perf-backed hook's error set, so `attachKprobe`/`attachUprobe`/
/// `attachTracepoint` can all funnel through one implementation.
pub const PerfAttachError = error{
    PermissionDenied,
    SystemResources,
    /// `.link_only` was requested on a kernel without perf-event links, or a
    /// `bpf_cookie` was requested and the link path was unavailable.
    LinkNotSupported,
    Unexpected,
};

/// Attach `prog_fd` to an already-open perf event fd and arm the event.
///
/// This is the single place the "prefer link, fall back to ioctl" decision
/// lives, shared by kprobe, uprobe and tracepoint — all three are perf
/// events underneath, and libbpf likewise routes them through one
/// `bpf_program__attach_perf_event_opts`. The order matters and matches
/// libbpf's: bind first (link OR ioctl), then `PERF_EVENT_IOC_ENABLE` in
/// BOTH cases — an event armed before it has a program attached would run
/// the probe with nothing behind it.
pub fn bindPerfEvent(
    perf_fd: linux.fd_t,
    prog_fd: linux.fd_t,
    pref: LinkPreference,
    bpf_cookie: u64,
) PerfAttachError!PerfBinding {
    var link_fd: linux.fd_t = -1;
    var path: AttachPath = .legacy;

    if (pref != .legacy_only) {
        if (bpflink.linkCreatePerfEvent(prog_fd, perf_fd, bpf_cookie)) |h| {
            link_fd = h.fd;
            path = .bpf_link;
        } else |err| switch (err) {
            // The only genuinely retryable case: an old kernel (or one that
            // rejects the attach type) — see bpflink.zig on why this is
            // EINVAL and therefore ambiguous.
            error.LinkNotSupported, error.InvalidTarget, error.AlreadyAttached, error.Unexpected => {
                if (pref == .link_only) return error.LinkNotSupported;
            },
            error.PermissionDenied => return error.PermissionDenied,
            error.SystemResources => return error.SystemResources,
        }
    }

    if (path == .legacy) {
        // A cookie only exists in the link ABI; falling back would drop it
        // without the caller ever knowing, so refuse instead.
        if (bpf_cookie != 0) return error.LinkNotSupported;
        // `@bitCast` rather than `@intCast`: the ioctl argument is a plain
        // machine word, and a caller-supplied negative fd must reach the
        // kernel as EBADF, not trip a safety panic on the way there.
        const arg: usize = @bitCast(@as(isize, prog_fd));
        switch (linux.errno(linux.ioctl(perf_fd, PERF_EVENT_IOC.SET_BPF, arg))) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.PermissionDenied,
            .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
    }

    switch (linux.errno(linux.ioctl(perf_fd, PERF_EVENT_IOC.ENABLE, 0))) {
        .SUCCESS => {},
        .ACCES, .PERM => {
            if (link_fd >= 0) _ = linux.close(link_fd);
            return error.PermissionDenied;
        },
        else => {
            if (link_fd >= 0) _ = linux.close(link_fd);
            return error.Unexpected;
        },
    }
    return .{ .link_fd = link_fd, .path = path };
}

/// The `perf_event_attr` a kprobe attach hands to `perf_event_open` — split
/// out as a pure function so its layout is testable without any privilege.
///
/// `symbol_z` must stay alive across the `perf_event_open` call: `config1`
/// holds a raw pointer to it (`kprobe_func`), which the kernel copies in
/// during the syscall.
pub fn buildKprobeAttr(
    pmu_type: u32,
    retprobe_bit: u6,
    retprobe: bool,
    symbol_z: [*:0]const u8,
    offset: u64,
) linux.perf_event_attr {
    var attr: linux.perf_event_attr = .{
        // The kprobe PMU's dynamic id, NOT a static PERF.TYPE value; the enum
        // is non-exhaustive precisely so dynamic PMUs fit.
        .type = @enumFromInt(pmu_type),
        .size = @sizeOf(linux.perf_event_attr),
        .config = 0,
    };
    if (retprobe) attr.config |= @as(u64, 1) << retprobe_bit;
    // config1 = kprobe_func (C string), config2 = probe_offset. This union
    // aliasing is why the probe is NOT named through `config`.
    attr.config1 = @intFromPtr(symbol_z);
    attr.config2 = offset;
    return attr;
}

/// Read the kprobe PMU's kernel-assigned `type` id.
fn kprobePmuType() KprobeAttachError!u32 {
    var buf: [32]u8 = undefined;
    const raw = readSmallFile(kprobe_pmu_type_path, &buf) orelse return error.KprobePmuUnavailable;
    const text = std.mem.trim(u8, raw, " \t\r\n");
    return std.fmt.parseInt(u32, text, 10) catch error.KprobePmuUnavailable;
}

/// Read the bit position of the retprobe flag inside `perf_event_attr.config`
/// from the PMU's `format/retprobe` file, whose contents are `"config:N"`.
/// Falls back to 0 (the value every shipped kernel uses) if the file is
/// missing or unparseable — a wrong bit here would silently install an entry
/// probe where a return probe was asked for, so parse it strictly.
fn kprobeRetprobeBit() u6 {
    var buf: [64]u8 = undefined;
    const raw = readSmallFile(kprobe_retprobe_fmt_path, &buf) orelse return 0;
    const text = std.mem.trim(u8, raw, " \t\r\n");
    const prefix = "config:";
    if (!std.mem.startsWith(u8, text, prefix)) return 0;
    return std.fmt.parseInt(u6, text[prefix.len..], 10) catch 0;
}

/// Read at most `buf.len` bytes of a small sysfs file. `null` on any failure
/// (missing file, no permission, read error) — every caller treats "could not
/// read" as "this kernel feature is unavailable", never as a hard error.
fn readSmallFile(path: [*:0]const u8, buf: []u8) ?[]u8 {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => return null,
    }
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);

    var n: usize = 0;
    while (n < buf.len) {
        const r = linux.read(fd, buf.ptr + n, buf.len - n);
        switch (linux.errno(r)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return null,
        }
        if (r == 0) break;
        n += r;
    }
    return buf[0..n];
}

// ── the perf-event-backed probe handle (uprobe / tracepoint) ────────────────

/// A perf-event-backed attachment that is not a kprobe: a uprobe,
/// uretprobe or static tracepoint. Same lifetime rule as `KprobeHandle` —
/// closing the fds detaches, and process exit does it for you — kept as its
/// own type because `kprobe` is the wrong word for a userspace probe and a
/// handle that lies about what it holds is a documentation bug waiting to
/// happen.
pub const PerfEventHandle = struct {
    perf_fd: linux.fd_t,
    /// The `BPF_LINK_CREATE` fd, or `-1` on the legacy ioctl path.
    link_fd: linux.fd_t = -1,
    path: AttachPath = .legacy,
    kind: Kind,

    pub const Kind = enum { uprobe, uretprobe, tracepoint, perf_event };

    /// Disable and close the perf event (and the link, if any). Idempotent.
    pub fn detach(self: *PerfEventHandle) void {
        if (self.link_fd >= 0) {
            _ = linux.close(self.link_fd);
            self.link_fd = -1;
        }
        if (self.perf_fd < 0) return;
        _ = linux.ioctl(self.perf_fd, PERF_EVENT_IOC.DISABLE, 0);
        _ = linux.close(self.perf_fd);
        self.perf_fd = -1;
    }

    pub fn deinit(self: *PerfEventHandle) void {
        self.detach();
    }

    pub fn close(self: *PerfEventHandle) void {
        self.detach();
    }

    pub fn link(self: PerfEventHandle) Link {
        return .{ .perf_event = self };
    }
};

// ── uprobe / uretprobe attach ───────────────────────────────────────────────

pub const UprobeAttachError = error{
    /// `/sys/bus/event_source/devices/uprobe/type` is missing (a kernel
    /// without `CONFIG_UPROBE_EVENTS`) or unreadable.
    UprobePmuUnavailable,
    /// `binary_path` is empty or contains an interior NUL.
    InvalidPath,
    /// Neither a `symbol` nor an explicit `offset` was given.
    NoProbeSite,
    /// The kernel refused the (inode, offset) pair — typically an offset
    /// that is not an instruction boundary, or a file it cannot probe.
    ProbeSiteRejected,
    PermissionDenied,
    SystemResources,
    LinkNotSupported,
    OutOfMemory,
    Unexpected,
} || elfsym.ResolveError;

pub const UprobeOptions = struct {
    /// Probe the function's RETURN instead of its entry (uretprobe).
    retprobe: bool = false,
    /// Skip symbol resolution and probe this **file offset** directly. When
    /// null, the `symbol` argument is resolved through `elfsym`. Exactly one
    /// of the two must be present.
    offset: ?u64 = null,
    /// Extra bytes past the resolved symbol's start (ignored when `offset`
    /// is given, which is already absolute).
    symbol_offset: u64 = 0,
    /// USDT "semaphore" address: the file offset of a `unsigned short` the
    /// kernel increments while the probe is installed, so an instrumented
    /// program can cheaply skip building arguments when nobody is listening.
    /// 0 = none. Encoded into `perf_event_attr.config`'s high bits at the
    /// position the uprobe PMU declares in `format/ref_ctr_offset`.
    ref_ctr_offset: u64 = 0,
    /// `-1` = every process that maps the file; a pid restricts it to one.
    pid: i32 = -1,
    /// CPU for the system-wide case — same reasoning as `KprobeOptions.cpu`.
    cpu: i32 = 0,
    link_preference: LinkPreference = .auto,
    bpf_cookie: u64 = 0,
};

/// Attach `prog_fd` to the entry of `symbol` in the executable or shared
/// library at `binary_path`. `prog_fd` must have been loaded with
/// `prog_type = .kprobe` (uprobes reuse `BPF_PROG_TYPE_KPROBE`; there is no
/// separate uprobe program type).
///
/// The one non-obvious step is that the kernel wants a **file offset**, not
/// the symbol's virtual address — see `elfsym.zig`, which exists entirely
/// for that conversion.
pub fn attachUprobe(
    gpa: std.mem.Allocator,
    binary_path: []const u8,
    symbol: []const u8,
    prog_fd: linux.fd_t,
) UprobeAttachError!PerfEventHandle {
    return attachUprobeOpts(gpa, binary_path, symbol, prog_fd, .{});
}

/// `attachUprobe` with `retprobe = true`: fire on the probed function's
/// return.
pub fn attachUretprobe(
    gpa: std.mem.Allocator,
    binary_path: []const u8,
    symbol: []const u8,
    prog_fd: linux.fd_t,
) UprobeAttachError!PerfEventHandle {
    return attachUprobeOpts(gpa, binary_path, symbol, prog_fd, .{ .retprobe = true });
}

/// `attachUprobe` with every knob exposed. `symbol` may be empty when
/// `opts.offset` is given.
pub fn attachUprobeOpts(
    gpa: std.mem.Allocator,
    binary_path: []const u8,
    symbol: []const u8,
    prog_fd: linux.fd_t,
    opts: UprobeOptions,
) UprobeAttachError!PerfEventHandle {
    if (comptime builtin.os.tag != .linux)
        @compileError("ebpf.attachUprobe is Linux-only (perf_event_open + BPF)");

    if (binary_path.len == 0) return error.InvalidPath;
    if (std.mem.indexOfScalar(u8, binary_path, 0) != null) return error.InvalidPath;
    if (opts.offset == null and symbol.len == 0) return error.NoProbeSite;

    const offset: u64 = if (opts.offset) |o| o else blk: {
        const sym = try elfsym.resolveFunc(gpa, binary_path, symbol);
        break :blk sym.file_offset + opts.symbol_offset;
    };

    const pmu_type = try uprobePmuType();
    const retprobe_bit = uprobeRetprobeBit();
    const ref_ctr_shift = uprobeRefCtrShift();

    const path_z = gpa.dupeZ(u8, binary_path) catch return error.OutOfMemory;
    defer gpa.free(path_z);

    var attr = buildUprobeAttr(
        pmu_type,
        retprobe_bit,
        opts.retprobe,
        path_z.ptr,
        offset,
        opts.ref_ctr_offset,
        ref_ctr_shift,
    );

    const pid: linux.pid_t = if (opts.pid < 0) -1 else opts.pid;
    const cpu: i32 = if (opts.pid < 0) opts.cpu else -1;

    const rc = linux.perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        // A path the kernel cannot probe, or an offset it rejects.
        .NOENT, .INVAL, .BADF, .ISDIR => return error.ProbeSiteRejected,
        .OPNOTSUPP, .NODEV => return error.UprobePmuUnavailable,
        .MFILE, .NFILE, .NOMEM, .NOSPC => return error.SystemResources,
        else => return error.Unexpected,
    }
    const perf_fd: linux.fd_t = @intCast(rc);
    var handle: PerfEventHandle = .{
        .perf_fd = perf_fd,
        .kind = if (opts.retprobe) .uretprobe else .uprobe,
    };
    errdefer handle.detach();

    const binding = try bindPerfEvent(perf_fd, prog_fd, opts.link_preference, opts.bpf_cookie);
    handle.link_fd = binding.link_fd;
    handle.path = binding.path;
    return handle;
}

/// The `perf_event_attr` a uprobe attach hands to `perf_event_open` — pure,
/// so its layout is testable without any privilege.
///
/// The union aliasing differs from the kprobe case in WHAT the fields mean,
/// not where they are: `config1` is `uprobe_path` (a C string pointer to the
/// **binary**, not a symbol) and `config2` is `probe_offset` (a **file
/// offset**, not a delta from a symbol). `config` carries the retprobe bit
/// and, in its high half, the `ref_ctr_offset`.
///
/// `path_z` must stay alive across the `perf_event_open` call: the kernel
/// copies the string in during the syscall.
pub fn buildUprobeAttr(
    pmu_type: u32,
    retprobe_bit: u6,
    retprobe: bool,
    path_z: [*:0]const u8,
    offset: u64,
    ref_ctr_offset: u64,
    ref_ctr_shift: u6,
) linux.perf_event_attr {
    var attr: linux.perf_event_attr = .{
        .type = @enumFromInt(pmu_type),
        .size = @sizeOf(linux.perf_event_attr),
        .config = 0,
    };
    if (retprobe) attr.config |= @as(u64, 1) << retprobe_bit;
    if (ref_ctr_offset != 0) attr.config |= ref_ctr_offset << ref_ctr_shift;
    attr.config1 = @intFromPtr(path_z);
    attr.config2 = offset;
    return attr;
}

/// Read the uprobe PMU's kernel-assigned `type` id.
fn uprobePmuType() UprobeAttachError!u32 {
    var buf: [32]u8 = undefined;
    const raw = readSmallFile(uprobe_pmu_type_path, &buf) orelse return error.UprobePmuUnavailable;
    const text = std.mem.trim(u8, raw, " \t\r\n");
    return std.fmt.parseInt(u32, text, 10) catch error.UprobePmuUnavailable;
}

/// Bit position of the retprobe flag inside `config` (`"config:N"`).
fn uprobeRetprobeBit() u6 {
    return configShift(uprobe_retprobe_fmt_path, 0);
}

/// Low bit of the `ref_ctr_offset` field inside `config`
/// (`"config:32-63"` on every kernel that has the feature).
fn uprobeRefCtrShift() u6 {
    return configShift(uprobe_ref_ctr_fmt_path, 32);
}

/// Parse a PMU `format/*` file of the form `"config:N"` or `"config:N-M"`
/// and return `N`. Falls back to `default` when the file is missing or
/// unparseable — every kernel that has ever shipped these uses the same
/// positions, but the kernel DECLARES them, so read rather than assume.
fn configShift(path: [*:0]const u8, default: u6) u6 {
    var buf: [64]u8 = undefined;
    const raw = readSmallFile(path, &buf) orelse return default;
    return parseConfigShift(raw, default);
}

/// The parsing half of `configShift`, split out so the `"config:N"` /
/// `"config:N-M"` grammar is testable without sysfs.
pub fn parseConfigShift(raw: []const u8, default: u6) u6 {
    const text = std.mem.trim(u8, raw, " \t\r\n");
    const prefix = "config:";
    if (!std.mem.startsWith(u8, text, prefix)) return default;
    const rest = text[prefix.len..];
    const end = std.mem.indexOfScalar(u8, rest, '-') orelse rest.len;
    return std.fmt.parseInt(u6, rest[0..end], 10) catch default;
}

// ── static tracepoint attach (PERF_TYPE_TRACEPOINT) ─────────────────────────

pub const TracepointAttachError = error{
    /// No tracefs is mounted (`/sys/kernel/tracing` and the legacy
    /// `/sys/kernel/debug/tracing` are both absent or unreadable).
    TracingUnavailable,
    /// The `<category>/<name>` pair has no `id` file.
    TracepointNotFound,
    /// A category/name containing `/`, `..` or a NUL — refused before it can
    /// be pasted into a path.
    InvalidName,
    PermissionDenied,
    SystemResources,
    LinkNotSupported,
    Unexpected,
};

pub const TracepointOptions = struct {
    pid: i32 = -1,
    cpu: i32 = 0,
    link_preference: LinkPreference = .auto,
    bpf_cookie: u64 = 0,
};

/// Attach `prog_fd` to the static tracepoint `<category>/<name>` (e.g.
/// `"syscalls"`, `"sys_enter_write"`). `prog_fd` must have been loaded with
/// `prog_type = .tracepoint`.
///
/// Unlike a kprobe there is no dynamic probe to create: the tracepoint
/// already exists and merely has to be named by its kernel-assigned numeric
/// id, read from `<tracefs>/events/<category>/<name>/id`. That id goes in
/// `config` of a `PERF_TYPE_TRACEPOINT` event — a STATIC perf type, so
/// unlike the kprobe/uprobe PMUs nothing has to be looked up in
/// `/sys/bus/event_source/`.
pub fn attachTracepoint(
    gpa: std.mem.Allocator,
    category: []const u8,
    name: []const u8,
    prog_fd: linux.fd_t,
) TracepointAttachError!PerfEventHandle {
    return attachTracepointOpts(gpa, category, name, prog_fd, .{});
}

/// `attachTracepoint` with every knob exposed.
pub fn attachTracepointOpts(
    gpa: std.mem.Allocator,
    category: []const u8,
    name: []const u8,
    prog_fd: linux.fd_t,
    opts: TracepointOptions,
) TracepointAttachError!PerfEventHandle {
    if (comptime builtin.os.tag != .linux)
        @compileError("ebpf.attachTracepoint is Linux-only (perf_event_open + BPF)");
    _ = gpa; // no allocation needed: the id path fits a fixed buffer

    const id = try tracepointId(category, name);
    var attr = buildTracepointAttr(id);

    const pid: linux.pid_t = if (opts.pid < 0) -1 else opts.pid;
    const cpu: i32 = if (opts.pid < 0) opts.cpu else -1;

    const rc = linux.perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        .NOENT, .INVAL => return error.TracepointNotFound,
        .MFILE, .NFILE, .NOMEM, .NOSPC => return error.SystemResources,
        else => return error.Unexpected,
    }
    const perf_fd: linux.fd_t = @intCast(rc);
    var handle: PerfEventHandle = .{ .perf_fd = perf_fd, .kind = .tracepoint };
    errdefer handle.detach();

    const binding = try bindPerfEvent(perf_fd, prog_fd, opts.link_preference, opts.bpf_cookie);
    handle.link_fd = binding.link_fd;
    handle.path = binding.path;
    return handle;
}

/// The `perf_event_attr` a tracepoint attach builds. `sample_period = 1` and
/// `wakeup_events = 1` are what libbpf sends; they are irrelevant to a BPF
/// attachment (no samples are read from THIS event — a program's output goes
/// to a ringbuf/perfbuf map) but a period of 0 makes the kernel treat the
/// event as a counter, which is not what a tracepoint attach wants.
pub fn buildTracepointAttr(id: u64) linux.perf_event_attr {
    var attr: linux.perf_event_attr = .{
        .type = .TRACEPOINT,
        .size = @sizeOf(linux.perf_event_attr),
        .config = id,
    };
    attr.sample_period_or_freq = 1;
    attr.wakeup_events_or_watermark = 1;
    return attr;
}

/// Read a tracepoint's kernel-assigned numeric id from tracefs. Tries the
/// modern mount first, then the legacy debugfs location.
pub fn tracepointId(category: []const u8, name: []const u8) TracepointAttachError!u64 {
    try validateTracepointComponent(category);
    try validateTracepointComponent(name);

    var saw_root = false;
    for (tracefs_roots) |root| {
        var path_buf: [512]u8 = undefined;
        const path = std.fmt.bufPrintZ(
            &path_buf,
            "{s}/events/{s}/{s}/id",
            .{ root, category, name },
        ) catch return error.InvalidName;

        var buf: [32]u8 = undefined;
        const raw = readSmallFile(path.ptr, &buf) orelse continue;
        saw_root = true;
        const text = std.mem.trim(u8, raw, " \t\r\n");
        return std.fmt.parseInt(u64, text, 10) catch error.TracepointNotFound;
    }
    // Distinguish "no tracefs at all" (which is a system configuration
    // problem) from "that tracepoint does not exist" (a caller problem).
    for (tracefs_roots) |root| {
        var path_buf: [512]u8 = undefined;
        const probe = std.fmt.bufPrintZ(&path_buf, "{s}/events", .{root}) catch continue;
        const rc = linux.open(probe.ptr, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        if (linux.errno(rc) == .SUCCESS) {
            _ = linux.close(@intCast(rc));
            return error.TracepointNotFound;
        }
    }
    return error.TracingUnavailable;
}

/// A tracepoint category/name is pasted straight into a path, so anything
/// that could escape the `events/` directory — or truncate the string — is
/// refused rather than sanitized.
fn validateTracepointComponent(s: []const u8) TracepointAttachError!void {
    if (s.len == 0 or s.len > 128) return error.InvalidName;
    if (std.mem.indexOfScalar(u8, s, 0) != null) return error.InvalidName;
    if (std.mem.indexOfScalar(u8, s, '/') != null) return error.InvalidName;
    if (std.mem.eql(u8, s, ".") or std.mem.eql(u8, s, "..")) return error.InvalidName;
    for (s) |c| {
        const ok = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or c == '_' or c == '-' or c == '.' or c == ':';
        if (!ok) return error.InvalidName;
    }
}

// ── raw tracepoint attach (BPF_RAW_TRACEPOINT_OPEN) ─────────────────────────

pub const RawTracepointAttachError = error{
    /// No tracepoint by that name, or the program's type/expected attach
    /// target does not match it.
    TracepointNotFound,
    /// The name is empty, over-long, or contains an interior NUL.
    InvalidName,
    PermissionDenied,
    AlreadyAttached,
    SystemResources,
    OutOfMemory,
    Unexpected,
};

/// A raw-tracepoint attachment: one fd from `bpf(BPF_RAW_TRACEPOINT_OPEN)`.
/// **No perf event is involved at all** — this is the one probe hook that is
/// a plain `bpf()` command. Closing the fd detaches; process exit does it
/// for you.
pub const RawTracepointHandle = struct {
    fd: linux.fd_t,

    /// Close the fd. Idempotent.
    pub fn detach(self: *RawTracepointHandle) void {
        if (self.fd < 0) return;
        _ = linux.close(self.fd);
        self.fd = -1;
    }

    pub fn deinit(self: *RawTracepointHandle) void {
        self.detach();
    }

    pub fn close(self: *RawTracepointHandle) void {
        self.detach();
    }

    pub fn link(self: RawTracepointHandle) Link {
        return .{ .raw_tracepoint = self };
    }
};

/// Attach `prog_fd` to the raw tracepoint `name` (the bare tracepoint name,
/// e.g. `"sys_enter"` — no category prefix, unlike `attachTracepoint`).
///
/// Raw tracepoints hand the program the tracepoint's ARGUMENTS as a
/// `struct bpf_raw_tracepoint_args { __u64 args[0]; }` instead of the
/// pre-formatted, ABI-frozen trace-event record a `PERF_TYPE_TRACEPOINT`
/// program sees; they are therefore cheaper (no record formatting) and
/// closer to the kernel's own types, at the cost of no stable field layout.
///
/// Program types this accepts:
/// - `.raw_tracepoint` — read-only args.
/// - `.raw_tracepoint_writable` (`raw_tp.w` in libbpf's section naming) —
///   the last argument is a writable buffer, for tracepoints declared with
///   `DECLARE_TRACE_WRITABLE`. Same syscall, same handle; only the program
///   type at load time differs, which is why it costs nothing extra here.
/// - `.tracing` with `expected_attach_type = trace_raw_tp` (BTF-typed
///   `tp_btf`) — accepted by the kernel through this same command, but the
///   program must already carry an `attach_btf_id` set at load time, which
///   needs a BTF parser this module does not have (see `SPEC.md`).
pub fn attachRawTracepoint(
    gpa: std.mem.Allocator,
    name: []const u8,
    prog_fd: linux.fd_t,
) RawTracepointAttachError!RawTracepointHandle {
    if (comptime builtin.os.tag != .linux)
        @compileError("ebpf.attachRawTracepoint is Linux-only (bpf() raw syscall)");

    if (name.len == 0 or name.len > 128) return error.InvalidName;
    if (std.mem.indexOfScalar(u8, name, 0) != null) return error.InvalidName;

    const name_z = gpa.dupeZ(u8, name) catch return error.OutOfMemory;
    defer gpa.free(name_z);

    var attr = buildRawTracepointAttr(name_z.ptr, prog_fd);
    const rc = linux.bpf(.raw_tracepoint_open, &attr, @sizeOf(BPF.RawTracepointAttr));
    switch (linux.errno(rc)) {
        .SUCCESS => return .{ .fd = @intCast(rc) },
        .ACCES, .PERM => return error.PermissionDenied,
        .EXIST, .BUSY => return error.AlreadyAttached,
        .NOENT, .INVAL, .BADF => return error.TracepointNotFound,
        .NOMEM, .MFILE, .NFILE => return error.SystemResources,
        else => return error.Unexpected,
    }
}

/// The `BPF_RAW_TRACEPOINT_OPEN` attr — pure, so the union member layout is
/// testable without `CAP_BPF`. `name_z` must outlive the syscall.
pub fn buildRawTracepointAttr(name_z: [*:0]const u8, prog_fd: linux.fd_t) BPF.Attr {
    var attr: BPF.Attr = .{ .raw_tracepoint = std.mem.zeroes(BPF.RawTracepointAttr) };
    attr.raw_tracepoint = .{
        .name = @intFromPtr(name_z),
        .prog_fd = prog_fd,
    };
    return attr;
}

// ── XDP attach (netlink RTM_SETLINK) ────────────────────────────────────────

pub const XdpFlags = struct {
    /// XDP_FLAGS_SKB_MODE — generic/software XDP, works on any NIC driver.
    skb_mode: bool = false,
    /// XDP_FLAGS_DRV_MODE — native driver XDP, needs driver support.
    drv_mode: bool = false,
    /// XDP_FLAGS_HW_MODE — full hardware offload, needs NIC + driver
    /// support; mutually exclusive with the above in practice.
    hw_mode: bool = false,
    /// XDP_FLAGS_UPDATE_IF_NOEXIST — fail with EBUSY instead of silently
    /// replacing a program another owner already attached. Recommended.
    update_if_noexist: bool = false,
    /// XDP_FLAGS_REPLACE — atomically swap only if the currently attached
    /// program is exactly `replace_fd`; the expected fd travels in the
    /// `IFLA_XDP_EXPECTED_FD` child attribute. Mutually exclusive with
    /// `update_if_noexist`.
    replace_fd: ?linux.fd_t = null,

    /// The `XDP_FLAGS_*` bitmask this option set encodes. Mode bits only —
    /// `REPLACE` is added by the message builder when `replace_fd` is set.
    pub fn modeBits(self: XdpFlags) u32 {
        var bits: u32 = 0;
        if (self.skb_mode) bits |= XDP_FLAGS.SKB_MODE;
        if (self.drv_mode) bits |= XDP_FLAGS.DRV_MODE;
        if (self.hw_mode) bits |= XDP_FLAGS.HW_MODE;
        if (self.update_if_noexist) bits |= XDP_FLAGS.UPDATE_IF_NOEXIST;
        return bits;
    }

    /// At most one mode bit, and REPLACE/UPDATE_IF_NOEXIST are exclusive.
    /// Getting this wrong is the classic XDP attach failure: two mode bits
    /// is a flat EINVAL, and *no* mode bit means "kernel picks", which
    /// silently falls back from native to generic XDP on drivers without
    /// native support — a 10x throughput cliff that looks like success.
    pub fn validate(self: XdpFlags) XdpAttachError!void {
        const modes = @as(u32, @intFromBool(self.skb_mode)) +
            @intFromBool(self.drv_mode) + @intFromBool(self.hw_mode);
        if (modes > 1) return error.InvalidFlags;
        if (self.replace_fd != null and self.update_if_noexist) return error.InvalidFlags;
    }
};

pub const XdpAttachError = error{
    NoSuchInterface,
    AlreadyAttached,
    /// More than one of skb/drv/hw mode, or REPLACE together with
    /// UPDATE_IF_NOEXIST.
    InvalidFlags,
    /// The driver does not support the requested mode (typically
    /// `drv_mode`/`hw_mode` on a NIC without native XDP support).
    ModeNotSupported,
    PermissionDenied,
    SendFailed,
    RecvFailed,
    MalformedReply,
    OutOfMemory,
    /// `link_preference = .link_only` but this kernel has no XDP links
    /// (needs >= 5.9).
    LinkNotSupported,
    Unexpected,
};

/// A live XDP attachment. **Persists in the kernel after this process
/// exits** — the netlink attach makes the interface hold a reference to the
/// program, so dropping this handle without `detach()` leaves the program
/// filtering traffic with no way to identify it short of `ip link`/`bpftool`.
pub const XdpHandle = struct {
    gpa: std.mem.Allocator,
    ifindex: u32,
    /// The mode bits the attach used — the detach must repeat them so the
    /// kernel removes the program from the same mode slot.
    flags: XdpFlags,
    detached: bool = false,

    /// `RTM_SETLINK` with `IFLA_XDP_FD = -1`. Idempotent.
    pub fn detach(self: *XdpHandle) XdpAttachError!void {
        if (self.detached) return;
        // Never carry REPLACE/UPDATE_IF_NOEXIST into the removal: the fd
        // being installed is -1, so there is nothing to compare against.
        const mode: XdpFlags = .{
            .skb_mode = self.flags.skb_mode,
            .drv_mode = self.flags.drv_mode,
            .hw_mode = self.flags.hw_mode,
        };
        try setLinkXdp(self.gpa, self.ifindex, -1, mode);
        self.detached = true;
    }

    /// `defer`-friendly best-effort detach.
    pub fn deinit(self: *XdpHandle) void {
        self.detach() catch {};
    }

    pub fn link(self: XdpHandle) Link {
        return .{ .xdp = self };
    }
};

/// Attach `prog_fd` as the XDP program on interface `ifindex` (e.g. from
/// `netlink.Socket.links()`'s `Link.index`).
///
/// **Mechanism: the netlink `RTM_SETLINK` + `IFLA_XDP` path**, not
/// `bpf(BPF_LINK_CREATE)`. Both exist in modern kernels; this module picks
/// netlink because (a) it works on every kernel that has XDP at all, while
/// `BPF_LINK_CREATE` with `BPF_XDP` needs >= 5.7, and (b) it is the
/// attachment `ip link set dev X xdp obj ...` and libbpf's
/// `bpf_xdp_attach()` produce, so `ip link show` and `bpftool net` see it in
/// the shape operators expect. The tradeoff is that a netlink attachment is
/// NOT auto-detached when this process exits (a `BPF_LINK_CREATE` link fd
/// would be) — hence the explicit `XdpHandle.detach()` discipline.
///
/// Message layout (one `RTM_SETLINK`, `NLM_F_REQUEST | NLM_F_ACK`):
/// ```text
/// nlmsghdr(16) | ifinfomsg(16, family=AF_UNSPEC, index=ifindex)
///   | IFLA_XDP nest
///       | IFLA_XDP_FD          (i32 prog_fd, -1 to detach)
///       | IFLA_XDP_FLAGS       (u32 XDP_FLAGS_*)
///       [ | IFLA_XDP_EXPECTED_FD (i32) when XDP_FLAGS_REPLACE is set ]
/// ```
/// The `IFLA_XDP` type is written WITHOUT the `NLA_F_NESTED` bit, matching
/// iproute2/libbpf: `do_setlink` parses it with
/// `nla_parse_nested_deprecated`, i.e. liberal validation that neither
/// requires nor rejects the bit — but only the flagless encoding is
/// field-proven across kernel versions.
pub fn attachXdp(
    gpa: std.mem.Allocator,
    ifindex: u32,
    prog_fd: linux.fd_t,
    flags: XdpFlags,
) XdpAttachError!XdpHandle {
    try flags.validate();
    try setLinkXdp(gpa, ifindex, prog_fd, flags);
    return .{ .gpa = gpa, .ifindex = ifindex, .flags = flags };
}

/// One attachment plus the mechanism that produced it. Returned by the
/// `*Auto` entry points so a caller can see — and assert on — which of the
/// two lifetime models it actually got.
pub const AttachOutcome = struct {
    link: Link,
    path: AttachPath,
};

/// `attachXdp`, but preferring `bpf(BPF_LINK_CREATE)` and falling back to
/// the netlink path.
///
/// This is a SEPARATE entry point rather than a new default on `attachXdp`
/// for one reason: the two produce attachments an operator sees differently.
/// A netlink attach shows up in `ip link show` as a program id and can be
/// removed with `ip link set dev X xdp off`; an XDP *link* cannot be removed
/// by anyone but its owner, which is exactly what you want for a production
/// data path and exactly what you do not want for an ad-hoc experiment.
/// Changing `attachXdp`'s behaviour would silently change what operators
/// see, so the choice is explicit.
///
/// `flags` mode bits are passed through to both paths; `replace_fd` /
/// `update_if_noexist` are netlink-only and force the legacy path.
pub fn attachXdpAuto(
    gpa: std.mem.Allocator,
    ifindex: u32,
    prog_fd: linux.fd_t,
    flags: XdpFlags,
    pref: LinkPreference,
) XdpAttachError!AttachOutcome {
    try flags.validate();

    // XDP links take only the mode bits; the netlink-only semantics
    // (EXPECTED_FD / UPDATE_IF_NOEXIST) have no link equivalent, so asking
    // for them means the legacy path.
    const link_capable = flags.replace_fd == null and !flags.update_if_noexist;

    if (pref != .legacy_only and link_capable) {
        if (bpflink.linkCreateXdp(prog_fd, ifindex, flags.modeBits())) |h| {
            return .{ .link = .{ .bpf_link = h }, .path = .bpf_link };
        } else |err| switch (err) {
            error.LinkNotSupported, error.Unexpected => {
                if (pref == .link_only) return error.LinkNotSupported;
            },
            error.PermissionDenied => return error.PermissionDenied,
            error.AlreadyAttached => return error.AlreadyAttached,
            error.InvalidTarget => return error.NoSuchInterface,
            error.SystemResources => return error.OutOfMemory,
        }
    } else if (pref == .link_only) {
        return error.LinkNotSupported;
    }

    const h = try attachXdp(gpa, ifindex, prog_fd, flags);
    return .{ .link = .{ .xdp = h }, .path = .legacy };
}

/// Remove whatever XDP program is attached to `ifindex` in the mode named by
/// `flags`. Standalone counterpart to `XdpHandle.detach` — useful for
/// cleaning up an attachment this process did not create.
pub fn detachXdp(gpa: std.mem.Allocator, ifindex: u32, flags: XdpFlags) XdpAttachError!void {
    try flags.validate();
    return setLinkXdp(gpa, ifindex, -1, .{
        .skb_mode = flags.skb_mode,
        .drv_mode = flags.drv_mode,
        .hw_mode = flags.hw_mode,
    });
}

/// Encode one `RTM_SETLINK`+`IFLA_XDP` message. Pure (allocator in, bytes
/// out, no syscalls) so the exact nested-attribute byte layout is testable
/// without `CAP_NET_ADMIN`. Caller frees with `gpa.free`.
pub fn buildSetLinkXdpMessage(
    gpa: std.mem.Allocator,
    seq: u32,
    ifindex: u32,
    prog_fd: linux.fd_t,
    flags: XdpFlags,
) error{OutOfMemory}![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);

    const hdr_at = try codec.appendHeader(
        gpa,
        &msg,
        RTM_SETLINK,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        seq,
        0,
    );

    // ifinfomsg: u8 family | u8 pad | u16 type | i32 index | u32 flags |
    // u32 change. Only family (AF_UNSPEC = 0) and index are meaningful for a
    // "change one property" SETLINK; `change = 0` means "touch no IFF_ bits".
    var ifi: [netlink.ifinfomsg_len]u8 = @splat(0);
    std.mem.writeInt(i32, ifi[4..8], @bitCast(ifindex), native_endian);
    try codec.appendPadded(gpa, &msg, &ifi);

    // The nest: build the children into their own buffer, then emit them as
    // ONE attribute payload. `appendAttr` writes the parent's length field
    // over the finished child bytes, which is the same length-prefix-then-
    // patch discipline `appendHeader`/`finishHeader` use one level up.
    var nest: std.ArrayList(u8) = .empty;
    defer nest.deinit(gpa);

    var fd_bytes: [4]u8 = undefined;
    std.mem.writeInt(i32, &fd_bytes, prog_fd, native_endian);
    try appendAttrChecked(gpa, &nest, IFLA_XDP_ATTR.FD, &fd_bytes);

    var bits = flags.modeBits();
    if (flags.replace_fd != null) bits |= XDP_FLAGS.REPLACE;
    try codec.appendAttrU32(gpa, &nest, IFLA_XDP_ATTR.FLAGS, bits);

    if (flags.replace_fd) |expected| {
        var exp_bytes: [4]u8 = undefined;
        std.mem.writeInt(i32, &exp_bytes, expected, native_endian);
        try appendAttrChecked(gpa, &nest, IFLA_XDP_ATTR.EXPECTED_FD, &exp_bytes);
    }

    try appendAttrChecked(gpa, &msg, IFLA_XDP, nest.items);

    codec.finishHeader(&msg, hdr_at);
    return msg.toOwnedSlice(gpa);
}

/// `codec.appendAttr` with its `AttrTooLong` case discharged: every payload
/// this module writes is at most a few dozen bytes.
fn appendAttrChecked(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    data: []const u8,
) error{OutOfMemory}!void {
    codec.appendAttr(gpa, list, attr_type, data) catch |err| switch (err) {
        error.AttrTooLong => unreachable, // bounded by construction
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// Send one `RTM_SETLINK`+`IFLA_XDP` message on a private rtnetlink socket
/// and wait for its ACK. `prog_fd = -1` detaches.
fn setLinkXdp(gpa: std.mem.Allocator, ifindex: u32, prog_fd: linux.fd_t, flags: XdpFlags) XdpAttachError!void {
    if (comptime builtin.os.tag != .linux)
        @compileError("ebpf.attachXdp is Linux-only (AF_NETLINK raw syscalls)");

    // A fixed non-zero sequence number is enough: this socket is private to
    // this one transaction, so there is no older reply to disambiguate from.
    const seq: u32 = 1;
    const msg = try buildSetLinkXdpMessage(gpa, seq, ifindex, prog_fd, flags);
    defer gpa.free(msg);

    var conn = try NetlinkConn.open();
    defer conn.close();
    try conn.send(msg);
    return conn.waitAck(seq);
}

/// A minimal private `NETLINK_ROUTE` socket: open, send one message, read its
/// ACK, close. Deliberately NOT the sibling `netlink` module's `Socket` —
/// that one only exposes typed DUMP queries (`links()`/`routes()`/…) and owns
/// a growable receive buffer for multi-part replies, neither of which a
/// single request/ACK transaction needs.
const NetlinkConn = struct {
    fd: linux.fd_t,
    portid: u32,

    fn open() XdpAttachError!NetlinkConn {
        const rc = linux.socket(
            linux.AF.NETLINK,
            linux.SOCK.RAW | linux.SOCK.CLOEXEC,
            linux.NETLINK.ROUTE,
        );
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.PermissionDenied,
            else => return error.Unexpected,
        }
        const fd: linux.fd_t = @intCast(rc);
        errdefer _ = linux.close(fd);

        const sa: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        switch (linux.errno(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.nl)))) {
            .SUCCESS => {},
            else => return error.Unexpected,
        }
        var bound: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        var blen: linux.socklen_t = @sizeOf(linux.sockaddr.nl);
        switch (linux.errno(linux.getsockname(fd, @ptrCast(&bound), &blen))) {
            .SUCCESS => {},
            else => return error.Unexpected,
        }
        return .{ .fd = fd, .portid = bound.pid };
    }

    fn close(self: *NetlinkConn) void {
        _ = linux.close(self.fd);
        self.* = undefined;
    }

    fn send(self: *NetlinkConn, msg: []const u8) XdpAttachError!void {
        const dst: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        while (true) {
            const rc = linux.sendto(
                self.fd,
                msg.ptr,
                msg.len,
                0,
                @ptrCast(&dst),
                @sizeOf(linux.sockaddr.nl),
            );
            switch (linux.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .ACCES, .PERM => return error.PermissionDenied,
                else => return error.SendFailed,
            }
        }
    }

    /// Read datagrams until the ACK for `seq` shows up. Bounded: at most
    /// `max_datagrams` unrelated datagrams are skipped before giving up, so a
    /// chatty multicast group cannot wedge this loop.
    fn waitAck(self: *NetlinkConn, seq: u32) XdpAttachError!void {
        const max_datagrams = 16;
        var buf: [4096]u8 = undefined;
        var seen: usize = 0;
        while (seen < max_datagrams) : (seen += 1) {
            var src: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
            var slen: linux.socklen_t = @sizeOf(linux.sockaddr.nl);
            const rc = linux.recvfrom(self.fd, &buf, buf.len, 0, @ptrCast(&src), &slen);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return error.RecvFailed,
            }
            if (slen >= @sizeOf(linux.sockaddr.nl) and src.pid != 0) continue; // not the kernel

            var it: codec.MessageIterator = .{ .buf = buf[0..rc] };
            while (it.next() catch return error.MalformedReply) |m| {
                if (m.pid != self.portid or m.seq != seq) continue;
                if (m.type != codec.NLMSG_ERROR) continue;
                const code = m.errorCode() catch return error.MalformedReply;
                if (code == 0) return; // plain ACK
                return errnoToXdpError(code);
            }
        }
        return error.RecvFailed;
    }
};

/// Map an `NLMSG_ERROR` negative errno onto `XdpAttachError`.
pub fn errnoToXdpError(code: i32) XdpAttachError {
    if (code >= 0 or code == std.math.minInt(i32)) return error.Unexpected;
    return switch (@as(u32, @intCast(-code))) {
        @intFromEnum(linux.E.PERM), @intFromEnum(linux.E.ACCES) => error.PermissionDenied,
        @intFromEnum(linux.E.NODEV), @intFromEnum(linux.E.NXIO) => error.NoSuchInterface,
        @intFromEnum(linux.E.BUSY), @intFromEnum(linux.E.EXIST) => error.AlreadyAttached,
        @intFromEnum(linux.E.OPNOTSUPP) => error.ModeNotSupported,
        @intFromEnum(linux.E.INVAL) => error.InvalidFlags,
        @intFromEnum(linux.E.NOMEM), @intFromEnum(linux.E.NOBUFS) => error.OutOfMemory,
        else => error.Unexpected,
    };
}

// ── cgroup attach (BPF_PROG_ATTACH) ─────────────────────────────────────────

pub const CgroupAttachError = error{
    PermissionDenied,
    AlreadyAttached,
    /// `cgroup_fd` is not an open directory fd on a cgroup-v2 directory, or
    /// the program's type does not match `attach_type`.
    InvalidTarget,
    SystemResources,
    /// `link_preference = .link_only` but this kernel has no cgroup links
    /// (needs >= 5.7).
    LinkNotSupported,
    Unexpected,
};

/// `BPF_F_ALLOW_*` semantics for a cgroup attachment. The three modes are
/// mutually exclusive per (cgroup, attach_type) slot and are what decides
/// whether a CHILD cgroup may install its own program:
///  - default (neither flag): exclusive. A descendant cgroup's attach of the
///    same type fails, and this program alone runs for the subtree.
///  - `allow_override`: a descendant MAY attach, and when it does, its
///    program runs INSTEAD of this one (this one yields).
///  - `allow_multi`: descendants may attach, and all programs in the chain
///    run, effective-first — this is the only mode where more than one
///    program of a type executes, and the only one where `replace_fd` is
///    meaningful.
pub const CgroupAttachFlags = struct {
    allow_override: bool = false,
    allow_multi: bool = false,
    /// `BPF_F_REPLACE` — swap exactly this previously-attached program
    /// (only valid together with `allow_multi`).
    replace_fd: ?linux.fd_t = null,

    pub fn bits(self: CgroupAttachFlags) u32 {
        var b: u32 = 0;
        if (self.allow_override) b |= BPF.F_ALLOW_OVERRIDE;
        if (self.allow_multi) b |= BPF.F_ALLOW_MULTI;
        if (self.replace_fd != null) b |= BPF.F_REPLACE;
        return b;
    }
};

/// A live cgroup attachment. **Persists after this process exits** — the
/// cgroup holds a reference to the program, so this handle must be
/// `detach()`ed (or the cgroup removed) or the filter stays installed.
///
/// Both fds are BORROWED, matching `load.zig`'s convention that the caller
/// owns every fd it created: they must stay open for as long as `detach()`
/// might be called.
pub const CgroupHandle = struct {
    cgroup_fd: linux.fd_t,
    prog_fd: linux.fd_t,
    attach_type: BPF.AttachType,
    detached: bool = false,

    /// `bpf(BPF_PROG_DETACH)`. Idempotent.
    pub fn detach(self: *CgroupHandle) CgroupAttachError!void {
        if (self.detached) return;
        try detachCgroup(self.cgroup_fd, self.prog_fd, self.attach_type);
        self.detached = true;
    }

    /// `defer`-friendly best-effort detach.
    pub fn deinit(self: *CgroupHandle) void {
        self.detach() catch {};
    }

    pub fn link(self: CgroupHandle) Link {
        return .{ .cgroup = self };
    }
};

/// Attach `prog_fd` to `cgroup_fd` (an open fd on the cgroup's directory,
/// e.g. `open("/sys/fs/cgroup/...", O_DIRECTORY|O_RDONLY)`) for `attach_type`
/// (e.g. `.cgroup_inet_egress`), in exclusive mode.
///
/// `std.os.linux.BPF` already defines every TYPE involved (`Cmd.prog_attach`,
/// `ProgAttachAttr`, `Attr`) — it just never grew the wrapper FUNCTION the
/// way it did for `map_create`/`prog_load`; this is that wrapper, with the
/// same errno-switch shape those use.
pub fn attachCgroup(
    cgroup_fd: linux.fd_t,
    prog_fd: linux.fd_t,
    attach_type: BPF.AttachType,
) CgroupAttachError!CgroupHandle {
    return attachCgroupOpts(cgroup_fd, prog_fd, attach_type, .{});
}

/// `attachCgroup` with explicit `BPF_F_ALLOW_*` semantics — see
/// `CgroupAttachFlags`.
pub fn attachCgroupOpts(
    cgroup_fd: linux.fd_t,
    prog_fd: linux.fd_t,
    attach_type: BPF.AttachType,
    flags: CgroupAttachFlags,
) CgroupAttachError!CgroupHandle {
    if (comptime builtin.os.tag != .linux)
        @compileError("ebpf.attachCgroup is Linux-only (bpf() raw syscall)");

    var attr = buildProgAttachAttr(cgroup_fd, prog_fd, attach_type, flags);
    const rc = linux.bpf(.prog_attach, &attr, @sizeOf(BPF.ProgAttachAttr));
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        .EXIST, .BUSY => return error.AlreadyAttached,
        .INVAL, .BADF => return error.InvalidTarget,
        .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    }
    return .{ .cgroup_fd = cgroup_fd, .prog_fd = prog_fd, .attach_type = attach_type };
}

/// `attachCgroup`, but preferring `bpf(BPF_LINK_CREATE)` and falling back to
/// `BPF_PROG_ATTACH`.
///
/// The lifetime difference is the whole point: a cgroup LINK dies with this
/// process, a `BPF_PROG_ATTACH` survives it and must be detached explicitly
/// (or the cgroup removed). `AttachOutcome.path` says which one you got, so
/// a caller can decide whether it still needs teardown-on-crash handling.
///
/// `BPF_F_ALLOW_MULTI`/`_OVERRIDE`/`_REPLACE` have no link equivalent (a
/// link is always its own slot), so any non-zero `CgroupAttachFlags` forces
/// the legacy path.
pub fn attachCgroupAuto(
    cgroup_fd: linux.fd_t,
    prog_fd: linux.fd_t,
    attach_type: BPF.AttachType,
    flags: CgroupAttachFlags,
    pref: LinkPreference,
) CgroupAttachError!AttachOutcome {
    const link_capable = flags.bits() == 0;

    if (pref != .legacy_only and link_capable) {
        if (bpflink.linkCreateCgroup(prog_fd, cgroup_fd, attach_type, 0)) |h| {
            return .{ .link = .{ .bpf_link = h }, .path = .bpf_link };
        } else |err| switch (err) {
            error.LinkNotSupported, error.Unexpected => {
                if (pref == .link_only) return error.LinkNotSupported;
            },
            error.PermissionDenied => return error.PermissionDenied,
            error.AlreadyAttached => return error.AlreadyAttached,
            error.InvalidTarget => return error.InvalidTarget,
            error.SystemResources => return error.SystemResources,
        }
    } else if (pref == .link_only) {
        return error.LinkNotSupported;
    }

    const h = try attachCgroupOpts(cgroup_fd, prog_fd, attach_type, flags);
    return .{ .link = .{ .cgroup = h }, .path = .legacy };
}

/// `bpf(BPF_PROG_DETACH)` — the mirror of `attachCgroup`. Standalone
/// counterpart to `CgroupHandle.detach`, for removing an attachment this
/// process did not create.
pub fn detachCgroup(
    cgroup_fd: linux.fd_t,
    prog_fd: linux.fd_t,
    attach_type: BPF.AttachType,
) CgroupAttachError!void {
    var attr = buildProgAttachAttr(cgroup_fd, prog_fd, attach_type, .{});
    const rc = linux.bpf(.prog_detach, &attr, @sizeOf(BPF.ProgAttachAttr));
    switch (linux.errno(rc)) {
        .SUCCESS => return,
        .ACCES, .PERM => return error.PermissionDenied,
        .INVAL, .BADF, .NOENT => return error.InvalidTarget,
        .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    }
}

/// The `BPF_PROG_ATTACH`/`_DETACH` attr — pure, so the union member layout is
/// testable without `CAP_BPF`.
pub fn buildProgAttachAttr(
    cgroup_fd: linux.fd_t,
    prog_fd: linux.fd_t,
    attach_type: BPF.AttachType,
    flags: CgroupAttachFlags,
) BPF.Attr {
    var attr: BPF.Attr = .{ .prog_attach = std.mem.zeroes(BPF.ProgAttachAttr) };
    attr.prog_attach = .{
        .target_fd = cgroup_fd,
        .attach_bpf_fd = prog_fd,
        .attach_type = @intFromEnum(attach_type),
        .attach_flags = flags.bits(),
        // The kernel reads replace_bpf_fd only when BPF_F_REPLACE is set; 0
        // (not -1) keeps the unused case a plain zeroed field, matching what
        // libbpf sends.
        .replace_bpf_fd = flags.replace_fd orelse 0,
    };
    return attr;
}

// ── tests ────────────────────────────────────────────────────────────────────
//
// Two layers, per this module's SPEC.md:
//  1. UNPRIVILEGED, always run: the exact bytes/struct fields each attach path
//     hands the kernel (perf_event_attr layout, the IFLA_XDP nested-attribute
//     encoding, the BPF_PROG_ATTACH attr union) — no syscall, no capability.
//  2. PRIVILEGED, gracefully skipped: real attach/detach round trips. These
//     print a SKIPPED line and PASS when the capability is missing, mirroring
//     the opcua module's podman-gated live tests.

const testing = std.testing;

fn hasBpfCapability() bool {
    return linux.geteuid() == 0;
}

test "XdpFlags / attach error sets have the expected shape" {
    const f: XdpFlags = .{ .drv_mode = true };
    try testing.expect(f.drv_mode);
    try testing.expect(!f.skb_mode);
    try testing.expect(!f.hw_mode);

    // Checks that these error sets exist with the names the doc comments
    // above promise (a mistyped error name here would be a compile error).
    // Routed through a function + expectError, rather than assigning and
    // discarding an error-set value directly, since Zig treats a discarded
    // error-set value as a likely-swallowed-error bug and rejects it.
    const returnsKprobeErr = struct {
        fn call() KprobeAttachError!void {
            return error.SymbolNotFound;
        }
    }.call;
    const returnsXdpErr = struct {
        fn call() XdpAttachError!void {
            return error.NoSuchInterface;
        }
    }.call;
    const returnsCgroupErr = struct {
        fn call() CgroupAttachError!void {
            return error.AlreadyAttached;
        }
    }.call;
    try testing.expectError(error.SymbolNotFound, returnsKprobeErr());
    try testing.expectError(error.NoSuchInterface, returnsXdpErr());
    try testing.expectError(error.AlreadyAttached, returnsCgroupErr());
}

test "perf ioctl request numbers match the kernel _IO/_IOW encoding" {
    // _IO('$', 0) = (0x24 << 8) | 0
    try testing.expectEqual(@as(u32, 0x2400), PERF_EVENT_IOC.ENABLE);
    try testing.expectEqual(@as(u32, 0x2401), PERF_EVENT_IOC.DISABLE);
    // _IOW('$', 8, __u32) = (1 << 30) | (4 << 16) | (0x24 << 8) | 8
    try testing.expectEqual(@as(u32, 0x4004_2408), PERF_EVENT_IOC.SET_BPF);
    try testing.expectEqual(@as(usize, 8), PERF_FLAG_FD_CLOEXEC);
}

test "perf_event_attr layout: the kprobe attr names the probe via config1/config2" {
    // UAPI offsets (include/uapi/linux/perf_event.h) — a shifted field here
    // would make the kernel read the symbol pointer as something else.
    try testing.expectEqual(@as(usize, 0), @offsetOf(linux.perf_event_attr, "type"));
    try testing.expectEqual(@as(usize, 4), @offsetOf(linux.perf_event_attr, "size"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(linux.perf_event_attr, "config"));
    try testing.expectEqual(@as(usize, 56), @offsetOf(linux.perf_event_attr, "config1"));
    try testing.expectEqual(@as(usize, 64), @offsetOf(linux.perf_event_attr, "config2"));

    const sym: [:0]const u8 = "do_sys_openat2";

    // Entry probe: config carries NO retprobe bit.
    const entry = buildKprobeAttr(7, 0, false, sym.ptr, 0);
    try testing.expectEqual(@as(u32, 7), @intFromEnum(entry.type));
    try testing.expectEqual(@as(u32, @sizeOf(linux.perf_event_attr)), entry.size);
    try testing.expectEqual(@as(u64, 0), entry.config);
    try testing.expectEqual(@intFromPtr(sym.ptr), entry.config1);
    try testing.expectEqual(@as(u64, 0), entry.config2);
    // Nothing else may be set: a stray `disabled`/`inherit` bit changes the
    // event's semantics silently.
    try testing.expectEqual(@as(u64, 0), @as(u64, @bitCast(entry.flags)));
    try testing.expectEqual(@as(u64, 0), entry.sample_type);

    // Return probe: exactly one bit, at the position the PMU declared.
    const ret0 = buildKprobeAttr(7, 0, true, sym.ptr, 0);
    try testing.expectEqual(@as(u64, 1), ret0.config);
    const ret3 = buildKprobeAttr(7, 3, true, sym.ptr, 0);
    try testing.expectEqual(@as(u64, 8), ret3.config);

    // Offsets land in config2 (probe_offset), never in config.
    const off = buildKprobeAttr(7, 0, false, sym.ptr, 0x40);
    try testing.expectEqual(@as(u64, 0x40), off.config2);
    try testing.expectEqual(@as(u64, 0), off.config);
}

test "golden: RTM_SETLINK + nested IFLA_XDP byte layout" {
    if (native_endian != .little) return error.SkipZigTest; // golden bytes are LE
    const gpa = testing.allocator;

    const msg = try buildSetLinkXdpMessage(gpa, 1, 3, 9, .{ .drv_mode = true });
    defer gpa.free(msg);

    try testing.expectEqualSlices(u8, &.{
        // nlmsghdr: len = 52
        0x34, 0x00, 0x00, 0x00,
        0x13, 0x00, // type = RTM_SETLINK (19)
        0x05, 0x00, // flags = NLM_F_REQUEST | NLM_F_ACK
        0x01, 0x00, 0x00, 0x00, // seq = 1
        0x00, 0x00, 0x00, 0x00, // pid = 0 (kernel routes by socket)
        // ifinfomsg (16 bytes): family = AF_UNSPEC, type = 0, index = 3,
        // flags = 0, change = 0
        0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        // IFLA_XDP nest: len = 20 (4 header + 16 of children), type = 43,
        // no NLA_F_NESTED bit (iproute2/libbpf-compatible encoding)
        0x14, 0x00, 0x2b, 0x00,
        // IFLA_XDP_FD = 9
        0x08, 0x00, 0x01, 0x00,
        0x09, 0x00, 0x00, 0x00,
        // IFLA_XDP_FLAGS = XDP_FLAGS_DRV_MODE (4)
        0x08, 0x00, 0x03, 0x00,
        0x04, 0x00, 0x00, 0x00,
    }, msg);
}

test "golden: IFLA_XDP detach message and the REPLACE variant" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;

    // Detach = the identical message with IFLA_XDP_FD = -1.
    const off = try buildSetLinkXdpMessage(gpa, 7, 1, -1, .{ .skb_mode = true });
    defer gpa.free(off);
    try testing.expectEqual(@as(usize, 52), off.len);
    // IFLA_XDP_FD payload sits at 16 (nlmsghdr) + 16 (ifinfomsg) + 4 (nest
    // header) + 4 (child header) = 40.
    try testing.expectEqual(@as(i32, -1), std.mem.readInt(i32, off[40..][0..4], native_endian));
    // XDP_FLAGS_SKB_MODE = 2 at 48.
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, off[48..][0..4], native_endian));

    // REPLACE adds IFLA_XDP_EXPECTED_FD and sets the REPLACE bit.
    const repl = try buildSetLinkXdpMessage(gpa, 8, 1, 12, .{ .drv_mode = true, .replace_fd = 11 });
    defer gpa.free(repl);
    try testing.expectEqual(@as(usize, 60), repl.len);
    // flags = DRV_MODE | REPLACE = 4 | 16 = 20
    try testing.expectEqual(@as(u32, 20), std.mem.readInt(u32, repl[48..][0..4], native_endian));
    // IFLA_XDP_EXPECTED_FD(8) header then the fd.
    try testing.expectEqual(@as(u16, 8), std.mem.readInt(u16, repl[52..][0..2], native_endian));
    try testing.expectEqual(IFLA_XDP_ATTR.EXPECTED_FD, std.mem.readInt(u16, repl[54..][0..2], native_endian));
    try testing.expectEqual(@as(i32, 11), std.mem.readInt(i32, repl[56..][0..4], native_endian));

    // The whole thing must also parse back through the sibling codec, nest
    // and all — a length field that covers the wrong span would show up here
    // even if the raw bytes above were transcribed consistently wrong.
    var it: codec.MessageIterator = .{ .buf = repl };
    const m = (try it.next()).?;
    try testing.expectEqual(RTM_SETLINK, m.type);
    var attrs = try m.attrs(netlink.ifinfomsg_len);
    const nest = (try attrs.next()).?;
    try testing.expectEqual(IFLA_XDP, nest.type);
    var kids = nest.nested();
    try testing.expectEqual(@as(i32, 12), try (try kids.next()).?.asI32());
    try testing.expectEqual(@as(u32, 20), try (try kids.next()).?.asU32());
    try testing.expectEqual(@as(i32, 11), try (try kids.next()).?.asI32());
    try testing.expectEqual(@as(?codec.Attr, null), try kids.next());
    try testing.expectEqual(@as(?codec.Attr, null), try attrs.next());
}

test "XdpFlags: mode-bit encoding and mutual exclusion" {
    try testing.expectEqual(@as(u32, 0), (XdpFlags{}).modeBits());
    try testing.expectEqual(XDP_FLAGS.SKB_MODE, (XdpFlags{ .skb_mode = true }).modeBits());
    try testing.expectEqual(XDP_FLAGS.DRV_MODE, (XdpFlags{ .drv_mode = true }).modeBits());
    try testing.expectEqual(XDP_FLAGS.HW_MODE, (XdpFlags{ .hw_mode = true }).modeBits());
    try testing.expectEqual(
        XDP_FLAGS.SKB_MODE | XDP_FLAGS.UPDATE_IF_NOEXIST,
        (XdpFlags{ .skb_mode = true, .update_if_noexist = true }).modeBits(),
    );

    try (XdpFlags{ .skb_mode = true }).validate();
    try testing.expectError(error.InvalidFlags, (XdpFlags{ .skb_mode = true, .drv_mode = true }).validate());
    try testing.expectError(error.InvalidFlags, (XdpFlags{ .drv_mode = true, .hw_mode = true }).validate());
    try testing.expectError(
        error.InvalidFlags,
        (XdpFlags{ .drv_mode = true, .update_if_noexist = true, .replace_fd = 3 }).validate(),
    );
}

test "netlink errno mapping covers the XDP-specific failures" {
    // `errnoToXdpError` returns an error VALUE; route it through an error
    // union so `expectError` (which needs one) can consume it.
    const asUnion = struct {
        fn f(code: i32) XdpAttachError!void {
            return errnoToXdpError(code);
        }
    }.f;
    try testing.expectError(error.PermissionDenied, asUnion(-@as(i32, @intFromEnum(linux.E.PERM))));
    try testing.expectError(error.PermissionDenied, asUnion(-@as(i32, @intFromEnum(linux.E.ACCES))));
    try testing.expectError(error.NoSuchInterface, asUnion(-@as(i32, @intFromEnum(linux.E.NODEV))));
    try testing.expectError(error.NoSuchInterface, asUnion(-@as(i32, @intFromEnum(linux.E.NXIO))));
    try testing.expectError(error.AlreadyAttached, asUnion(-@as(i32, @intFromEnum(linux.E.BUSY))));
    try testing.expectError(error.AlreadyAttached, asUnion(-@as(i32, @intFromEnum(linux.E.EXIST))));
    try testing.expectError(error.ModeNotSupported, asUnion(-@as(i32, @intFromEnum(linux.E.OPNOTSUPP))));
    try testing.expectError(error.InvalidFlags, asUnion(-@as(i32, @intFromEnum(linux.E.INVAL))));
    // Previously untested arm: NOMEM/NOBUFS both map to OutOfMemory.
    try testing.expectError(error.OutOfMemory, asUnion(-@as(i32, @intFromEnum(linux.E.NOMEM))));
    try testing.expectError(error.OutOfMemory, asUnion(-@as(i32, @intFromEnum(linux.E.NOBUFS))));
    // A non-negative code is not an errno at all.
    try testing.expectError(error.Unexpected, asUnion(0));
    try testing.expectError(error.Unexpected, asUnion(5));
    try testing.expectError(error.Unexpected, asUnion(std.math.minInt(i32)));
}

test "BPF_PROG_ATTACH attr union layout and BPF_F_ALLOW_* encoding" {
    // UAPI layout of `struct { __u32 target_fd; __u32 attach_bpf_fd; __u32
    // attach_type; __u32 attach_flags; __u32 replace_bpf_fd; }`.
    try testing.expectEqual(@as(usize, 0), @offsetOf(BPF.ProgAttachAttr, "target_fd"));
    try testing.expectEqual(@as(usize, 4), @offsetOf(BPF.ProgAttachAttr, "attach_bpf_fd"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(BPF.ProgAttachAttr, "attach_type"));
    try testing.expectEqual(@as(usize, 12), @offsetOf(BPF.ProgAttachAttr, "attach_flags"));
    try testing.expectEqual(@as(usize, 16), @offsetOf(BPF.ProgAttachAttr, "replace_bpf_fd"));
    try testing.expectEqual(@as(usize, 20), @sizeOf(BPF.ProgAttachAttr));

    const plain = buildProgAttachAttr(4, 5, .cgroup_inet_egress, .{});
    try testing.expectEqual(@as(linux.fd_t, 4), plain.prog_attach.target_fd);
    try testing.expectEqual(@as(linux.fd_t, 5), plain.prog_attach.attach_bpf_fd);
    try testing.expectEqual(
        @as(u32, @intFromEnum(BPF.AttachType.cgroup_inet_egress)),
        plain.prog_attach.attach_type,
    );
    try testing.expectEqual(@as(u32, 0), plain.prog_attach.attach_flags);
    try testing.expectEqual(@as(linux.fd_t, 0), plain.prog_attach.replace_bpf_fd);

    const multi = buildProgAttachAttr(4, 5, .cgroup_inet_ingress, .{ .allow_multi = true });
    try testing.expectEqual(@as(u32, BPF.F_ALLOW_MULTI), multi.prog_attach.attach_flags);

    const over = buildProgAttachAttr(4, 5, .cgroup_inet_ingress, .{ .allow_override = true });
    try testing.expectEqual(@as(u32, BPF.F_ALLOW_OVERRIDE), over.prog_attach.attach_flags);

    const repl = buildProgAttachAttr(4, 5, .cgroup_inet_ingress, .{ .allow_multi = true, .replace_fd = 6 });
    try testing.expectEqual(@as(u32, BPF.F_ALLOW_MULTI | BPF.F_REPLACE), repl.prog_attach.attach_flags);
    try testing.expectEqual(@as(linux.fd_t, 6), repl.prog_attach.replace_bpf_fd);
}

test "Link: the uniform handle detaches each kind and is idempotent" {
    // No kernel involved: a kprobe handle with an already-closed fd, an XDP
    // handle marked detached, and a cgroup handle marked detached all take
    // the early-return path — proving detach()/deinit() are idempotent and
    // that the union dispatches to the right arm.
    var kp: Link = .{ .kprobe = .{ .perf_fd = -1 } };
    try kp.detach();
    try kp.detach();
    kp.deinit();
    try testing.expectEqual(@as(linux.fd_t, -1), kp.kprobe.perf_fd);

    var xdp: Link = .{ .xdp = .{
        .gpa = testing.allocator,
        .ifindex = 1,
        .flags = .{ .skb_mode = true },
        .detached = true,
    } };
    try xdp.detach();
    xdp.deinit();
    try testing.expect(xdp.xdp.detached);

    var cg: Link = .{ .cgroup = .{
        .cgroup_fd = -1,
        .prog_fd = -1,
        .attach_type = .cgroup_inet_egress,
        .detached = true,
    } };
    try cg.detach();
    cg.deinit();
    try testing.expect(cg.cgroup.detached);
}

test "attachKprobe rejects a symbol it can never encode as a C string" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // Both checks run before any syscall, so they need no privilege.
    try testing.expectError(error.InvalidSymbol, attachKprobe(testing.allocator, "", 3));
    try testing.expectError(error.InvalidSymbol, attachKprobe(testing.allocator, "bad\x00sym", 3));
}

test "LIVE: kprobe attach + detach against a real kernel" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) {
        if (verboseSkip()) std.debug.print(
            "\nLIVE ebpf kprobe attach test SKIPPED: needs CAP_BPF+CAP_PERFMON (running as uid {d}).\n",
            .{linux.geteuid()},
        );
        return;
    }

    const programs = @import("programs.zig");
    const load = @import("load.zig").load;

    const map_fd = BPF.map_create(.array, 4, 8, 1) catch {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf kprobe attach test SKIPPED: BPF_MAP_CREATE refused.\n", .{});
        return;
    };
    defer _ = linux.close(map_fd);

    const prog: programs.Program = .{
        .prog_type = .kprobe,
        .insns = programs.kprobeCounter(map_fd),
    };
    const prog_fd = load(prog, "MIT") catch {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf kprobe attach test SKIPPED: BPF_PROG_LOAD refused.\n", .{});
        return;
    };
    defer _ = linux.close(prog_fd);

    // Try a couple of long-lived, commonly-probed symbols: which one exists
    // depends on the kernel version and arch.
    const candidates = [_][]const u8{ "do_sys_openat2", "vfs_read", "do_sys_open" };
    var handle: ?KprobeHandle = null;
    for (candidates) |sym| {
        handle = attachKprobe(testing.allocator, sym, prog_fd) catch continue;
        break;
    }
    var kp = handle orelse {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf kprobe attach test SKIPPED: no probeable symbol among the candidates.\n", .{});
        return;
    };
    defer kp.detach();

    try testing.expect(kp.perf_fd >= 0);

    // Trigger the probe, then check the counter moved. (A miss here would
    // mean the ioctl(SET_BPF) silently did nothing.)
    for (0..8) |_| {
        const fd = linux.open("/proc/self/status", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(fd) == .SUCCESS) _ = linux.close(@intCast(fd));
    }

    var key: [4]u8 = @splat(0);
    var value: [8]u8 = @splat(0);
    try BPF.map_lookup_elem(map_fd, &key, &value);
    const count = std.mem.readInt(u64, &value, native_endian);
    try testing.expect(count > 0);

    // Detaching twice must be safe.
    kp.detach();
    try testing.expectEqual(@as(linux.fd_t, -1), kp.perf_fd);
}

// ── uprobe / tracepoint / raw-tracepoint / link tests ───────────────────────

test "perf_event_attr layout: the uprobe attr names a PATH and a FILE OFFSET" {
    // Same union slots as the kprobe attr, different MEANING: config1 is the
    // binary's path (not a symbol) and config2 is a file offset (not a delta
    // from a symbol). A mix-up here is silent — the kernel happily probes
    // whatever byte the offset names.
    const path: [:0]const u8 = "/usr/lib/x86_64-linux-gnu/libc.so.6";

    const entry = buildUprobeAttr(9, 0, false, path.ptr, 0xb5110, 0, 32);
    try testing.expectEqual(@as(u32, 9), @intFromEnum(entry.type));
    try testing.expectEqual(@as(u32, @sizeOf(linux.perf_event_attr)), entry.size);
    try testing.expectEqual(@as(u64, 0), entry.config);
    try testing.expectEqual(@intFromPtr(path.ptr), entry.config1);
    try testing.expectEqual(@as(u64, 0xb5110), entry.config2);
    try testing.expectEqual(@as(u64, 0), @as(u64, @bitCast(entry.flags)));
    try testing.expectEqual(@as(u64, 0), entry.sample_type);

    // uretprobe: exactly one bit, at the position the PMU declared.
    const ret = buildUprobeAttr(9, 0, true, path.ptr, 0x40, 0, 32);
    try testing.expectEqual(@as(u64, 1), ret.config);
    const ret5 = buildUprobeAttr(9, 5, true, path.ptr, 0x40, 0, 32);
    try testing.expectEqual(@as(u64, 32), ret5.config);

    // A USDT semaphore goes in the HIGH half of config and must not disturb
    // the retprobe bit.
    const sema = buildUprobeAttr(9, 0, true, path.ptr, 0x40, 0xabcd, 32);
    try testing.expectEqual(@as(u64, (0xabcd << 32) | 1), sema.config);
    try testing.expectEqual(@as(u64, 0x40), sema.config2);
    // Zero means "no semaphore" — not "a semaphore at offset 0".
    const none = buildUprobeAttr(9, 0, false, path.ptr, 0x40, 0, 32);
    try testing.expectEqual(@as(u64, 0), none.config);
}

test "PMU format files: the config:N / config:N-M grammar" {
    try testing.expectEqual(@as(u6, 0), parseConfigShift("config:0\n", 63));
    try testing.expectEqual(@as(u6, 3), parseConfigShift("config:3", 0));
    try testing.expectEqual(@as(u6, 32), parseConfigShift("config:32-63\n", 0));
    // Anything unparseable falls back to the caller's documented default
    // rather than silently encoding at bit 0.
    try testing.expectEqual(@as(u6, 32), parseConfigShift("garbage", 32));
    try testing.expectEqual(@as(u6, 7), parseConfigShift("config1:4", 7));
    try testing.expectEqual(@as(u6, 7), parseConfigShift("config:999", 7));
    try testing.expectEqual(@as(u6, 7), parseConfigShift("", 7));
}

test "attachUprobe rejects inputs it can never encode" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // All of these fail before any syscall, so they need no privilege.
    try testing.expectError(error.InvalidPath, attachUprobe(testing.allocator, "", "malloc", 3));
    try testing.expectError(error.InvalidPath, attachUprobe(testing.allocator, "/bin\x00/sh", "malloc", 3));
    try testing.expectError(
        error.NoProbeSite,
        attachUprobeOpts(testing.allocator, "/bin/sh", "", 3, .{}),
    );
    // A path that does not exist surfaces as an ELF-resolution failure, not
    // as a mysterious perf error.
    try testing.expectError(
        error.FileOpenFailed,
        attachUprobe(testing.allocator, "/nonexistent/zig-libs-ebpf", "malloc", 3),
    );
}

test "perf_event_attr layout: the tracepoint attr uses a STATIC perf type" {
    const attr = buildTracepointAttr(742);
    try testing.expectEqual(linux.PERF.TYPE.TRACEPOINT, attr.type);
    try testing.expectEqual(@as(u32, 2), @intFromEnum(attr.type)); // PERF_TYPE_TRACEPOINT
    try testing.expectEqual(@as(u64, 742), attr.config);
    try testing.expectEqual(@as(u64, 1), attr.sample_period_or_freq);
    try testing.expectEqual(@as(u32, 1), attr.wakeup_events_or_watermark);
    // Unlike the probe PMUs, nothing travels in config1/config2.
    try testing.expectEqual(@as(u64, 0), attr.config1);
    try testing.expectEqual(@as(u64, 0), attr.config2);
    try testing.expectEqual(@as(u64, 0), @as(u64, @bitCast(attr.flags)));
}

test "tracepoint names are validated before they reach a path" {
    // The category/name are pasted into `<tracefs>/events/<cat>/<name>/id`,
    // so a traversal attempt must be refused, not sanitized.
    try testing.expectError(error.InvalidName, tracepointId("..", "x"));
    try testing.expectError(error.InvalidName, tracepointId("sys/../..", "x"));
    try testing.expectError(error.InvalidName, tracepointId("syscalls", "a/b"));
    try testing.expectError(error.InvalidName, tracepointId("", "x"));
    try testing.expectError(error.InvalidName, tracepointId("syscalls", ""));
    try testing.expectError(error.InvalidName, tracepointId("syscalls", "sys\x00enter"));
    try testing.expectError(error.InvalidName, tracepointId("sys calls", "x"));
    try testing.expectError(error.InvalidName, tracepointId("syscalls", "a" ** 129));
}

test "tracepointId reads a real id, or explains why it cannot" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // tracefs is root-only on most distros, so this is informational: it
    // asserts the SUCCESS shape when readable and never fails otherwise.
    const id = tracepointId("syscalls", "sys_enter_write") catch |e| {
        if (verboseSkip()) std.debug.print(
            "\nebpf tracepointId SKIPPED: {s} (tracefs is typically root-only; uid {d}).\n",
            .{ @errorName(e), linux.geteuid() },
        );
        return;
    };
    try testing.expect(id > 0);
    // A tracepoint that certainly does not exist must be a typed miss.
    try testing.expectError(
        error.TracepointNotFound,
        tracepointId("syscalls", "sys_enter_definitely_not_a_syscall"),
    );
}

test "BPF_RAW_TRACEPOINT_OPEN attr layout and validation" {
    // UAPI layout of `struct { __u64 name; __u32 prog_fd; }`.
    try testing.expectEqual(@as(usize, 0), @offsetOf(BPF.RawTracepointAttr, "name"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(BPF.RawTracepointAttr, "prog_fd"));

    const name: [:0]const u8 = "sys_enter";
    const attr = buildRawTracepointAttr(name.ptr, 12);
    try testing.expectEqual(@intFromPtr(name.ptr), attr.raw_tracepoint.name);
    try testing.expectEqual(@as(linux.fd_t, 12), attr.raw_tracepoint.prog_fd);

    if (builtin.os.tag != .linux) return;
    try testing.expectError(error.InvalidName, attachRawTracepoint(testing.allocator, "", 3));
    try testing.expectError(error.InvalidName, attachRawTracepoint(testing.allocator, "a\x00b", 3));
    try testing.expectError(error.InvalidName, attachRawTracepoint(testing.allocator, "n" ** 200, 3));
}

test "bindPerfEvent: a cookie cannot survive the legacy fallback" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // `.legacy_only` + a non-zero cookie is refused BEFORE any syscall: the
    // ioctl ABI has nowhere to put a cookie, and dropping it silently would
    // make `bpf_get_attach_cookie()` return 0 with no indication why.
    try testing.expectError(error.LinkNotSupported, bindPerfEvent(-1, -1, .legacy_only, 0x1234));
    // Without a cookie the same call proceeds to the ioctl, which fails on a
    // bogus fd — proving the cookie check is the thing that short-circuited.
    try testing.expectError(error.Unexpected, bindPerfEvent(-1, -1, .legacy_only, 0));
}

test "the *Auto entry points refuse link-only where no link semantics exist" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // XDP: EXPECTED_FD / UPDATE_IF_NOEXIST are netlink-only, so a link-only
    // request naming them is a typed refusal, not a silent legacy attach.
    try testing.expectError(error.LinkNotSupported, attachXdpAuto(
        testing.allocator,
        1,
        3,
        .{ .drv_mode = true, .replace_fd = 4 },
        .link_only,
    ));
    try testing.expectError(error.LinkNotSupported, attachXdpAuto(
        testing.allocator,
        1,
        3,
        .{ .skb_mode = true, .update_if_noexist = true },
        .link_only,
    ));
    // Flag validation still runs first.
    try testing.expectError(error.InvalidFlags, attachXdpAuto(
        testing.allocator,
        1,
        3,
        .{ .skb_mode = true, .drv_mode = true },
        .auto,
    ));

    // cgroup: BPF_F_ALLOW_MULTI has no link equivalent (a link is its own
    // slot), so the same rule applies.
    try testing.expectError(error.LinkNotSupported, attachCgroupAuto(
        -1,
        -1,
        .cgroup_inet_egress,
        .{ .allow_multi = true },
        .link_only,
    ));
    try testing.expectError(error.LinkNotSupported, attachCgroupAuto(
        -1,
        -1,
        .cgroup_inet_egress,
        .{ .allow_override = true },
        .link_only,
    ));
}

test "Link: the uniform handle covers the new hooks and stays idempotent" {
    var pe: Link = .{ .perf_event = .{ .perf_fd = -1, .kind = .uprobe } };
    try pe.detach();
    try pe.detach();
    pe.deinit();
    try testing.expectEqual(@as(linux.fd_t, -1), pe.perf_event.perf_fd);
    try testing.expectEqual(@as(linux.fd_t, -1), pe.perf_event.link_fd);
    try testing.expectEqual(AttachPath.legacy, pe.perf_event.path);

    var rt: Link = .{ .raw_tracepoint = .{ .fd = -1 } };
    try rt.detach();
    rt.deinit();
    try testing.expectEqual(@as(linux.fd_t, -1), rt.raw_tracepoint.fd);

    var bl = Link.fromBpfLink(.{ .fd = -1, .attach_type = .perf_event });
    try bl.detach();
    bl.deinit();
    try testing.expectEqual(@as(linux.fd_t, -1), bl.bpf_link.fd);

    // The handle types' own `.link()` helpers agree with the union tags.
    const h: PerfEventHandle = .{ .perf_fd = -1, .kind = .tracepoint };
    try testing.expectEqual(std.meta.Tag(Link).perf_event, std.meta.activeTag(h.link()));
    const r: RawTracepointHandle = .{ .fd = -1 };
    try testing.expectEqual(std.meta.Tag(Link).raw_tracepoint, std.meta.activeTag(r.link()));

    // A kprobe handle carrying a link fd still detaches idempotently.
    var kp: KprobeHandle = .{ .perf_fd = -1, .link_fd = -1, .path = .bpf_link };
    kp.detach();
    kp.detach();
    try testing.expectEqual(AttachPath.bpf_link, kp.path);
}

test "LIVE: uprobe on a real binary fires and can be detached" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) {
        if (verboseSkip()) std.debug.print(
            "\nLIVE ebpf uprobe test SKIPPED: needs CAP_BPF+CAP_PERFMON (running as uid {d}).\n",
            .{linux.geteuid()},
        );
        return;
    }

    const programs = @import("programs.zig");
    const load = @import("load.zig").load;

    // Probe a symbol in THIS test binary: it is guaranteed to exist, is
    // guaranteed to be called (the test calls it below), and needs no
    // helper process.
    var exe_buf: [256]u8 = undefined;
    const exe_len = linux.readlink("/proc/self/exe", &exe_buf, exe_buf.len);
    if (linux.errno(exe_len) != .SUCCESS) {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf uprobe test SKIPPED: cannot read /proc/self/exe.\n", .{});
        return;
    }
    const exe = exe_buf[0..exe_len];

    const sym = elfsym.resolveFunc(testing.allocator, exe, uprobe_target_symbol) catch |e| {
        if (verboseSkip()) std.debug.print(
            "\nLIVE ebpf uprobe test SKIPPED: '{s}' not resolvable in the test binary ({s}).\n",
            .{ uprobe_target_symbol, @errorName(e) },
        );
        return;
    };

    const map_fd = BPF.map_create(.array, 4, 8, 1) catch {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf uprobe test SKIPPED: BPF_MAP_CREATE refused.\n", .{});
        return;
    };
    defer _ = linux.close(map_fd);

    // uprobes reuse BPF_PROG_TYPE_KPROBE — there is no uprobe program type.
    const prog_fd = load(.{
        .prog_type = .kprobe,
        .insns = programs.kprobeCounter(map_fd),
    }, "MIT") catch {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf uprobe test SKIPPED: BPF_PROG_LOAD refused.\n", .{});
        return;
    };
    defer _ = linux.close(prog_fd);

    var up = attachUprobeOpts(testing.allocator, exe, uprobe_target_symbol, prog_fd, .{
        .offset = sym.file_offset,
    }) catch |e| {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf uprobe test SKIPPED: uprobe attach failed ({s}).\n", .{@errorName(e)});
        return;
    };
    defer up.detach();
    std.debug.print("\nLIVE ebpf uprobe attached via the {s} path.\n", .{@tagName(up.path)});

    // Fire the probe.
    var acc: u64 = 0;
    for (0..64) |i| acc +%= uprobeTarget(i);
    try testing.expect(acc != std.math.maxInt(u64));

    var key: [4]u8 = @splat(0);
    var value: [8]u8 = @splat(0);
    try BPF.map_lookup_elem(map_fd, &key, &value);
    try testing.expect(std.mem.readInt(u64, &value, native_endian) > 0);

    up.detach();
    try testing.expectEqual(@as(linux.fd_t, -1), up.perf_fd);
    up.detach(); // idempotent
}

/// The function the live uprobe test probes. `noinline` keeps it from being
/// folded into its only caller (which would leave nothing to probe), and the
/// symbol is exported **only in test builds** — a library module must not
/// add names to a consumer's symbol table, but a uprobe needs a name in
/// `.symtab`/`.dynsym` to resolve.
const uprobe_target_symbol = "zig_libs_ebpf_uprobe_target";

noinline fn uprobeTarget(x: u64) callconv(.c) u64 {
    return x *% 2654435761;
}

comptime {
    if (builtin.is_test) @export(&uprobeTarget, .{
        .name = uprobe_target_symbol,
        .linkage = .strong,
    });
}

test "LIVE: tracepoint attach + detach against a real kernel" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) {
        if (verboseSkip()) std.debug.print(
            "\nLIVE ebpf tracepoint test SKIPPED: needs CAP_BPF+CAP_PERFMON (running as uid {d}).\n",
            .{linux.geteuid()},
        );
        return;
    }

    // The smallest valid tracepoint program: r0 = 0; exit.
    const insns = [_]BPF.Insn{ BPF.Insn.mov(.r0, 0), BPF.Insn.exit() };
    const prog_fd = BPF.prog_load(.tracepoint, &insns, null, "MIT", 0, 0) catch {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf tracepoint test SKIPPED: tracepoint BPF_PROG_LOAD refused.\n", .{});
        return;
    };
    defer _ = linux.close(prog_fd);

    var tp = attachTracepoint(testing.allocator, "syscalls", "sys_enter_write", prog_fd) catch |e| {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf tracepoint test SKIPPED: attach failed ({s}).\n", .{@errorName(e)});
        return;
    };
    defer tp.detach();
    try testing.expect(tp.perf_fd >= 0);
    try testing.expectEqual(PerfEventHandle.Kind.tracepoint, tp.kind);
    std.debug.print("\nLIVE ebpf tracepoint attached via the {s} path.\n", .{@tagName(tp.path)});

    // Force the legacy branch too, so BOTH paths are exercised wherever this
    // test actually runs.
    var legacy = attachTracepointOpts(
        testing.allocator,
        "syscalls",
        "sys_enter_write",
        prog_fd,
        .{ .link_preference = .legacy_only },
    ) catch |e| {
        std.debug.print("\nLIVE ebpf tracepoint legacy-path attach failed ({s}).\n", .{@errorName(e)});
        return;
    };
    defer legacy.detach();
    try testing.expectEqual(AttachPath.legacy, legacy.path);
    try testing.expectEqual(@as(linux.fd_t, -1), legacy.link_fd);

    tp.detach();
    try testing.expectEqual(@as(linux.fd_t, -1), tp.perf_fd);
    tp.detach(); // idempotent
}

test "LIVE: raw tracepoint attach + detach" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) {
        if (verboseSkip()) std.debug.print(
            "\nLIVE ebpf raw-tracepoint test SKIPPED: needs CAP_BPF (running as uid {d}).\n",
            .{linux.geteuid()},
        );
        return;
    }

    const insns = [_]BPF.Insn{ BPF.Insn.mov(.r0, 0), BPF.Insn.exit() };
    const prog_fd = BPF.prog_load(.raw_tracepoint, &insns, null, "MIT", 0, 0) catch {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf raw-tracepoint test SKIPPED: raw_tracepoint BPF_PROG_LOAD refused.\n", .{});
        return;
    };
    defer _ = linux.close(prog_fd);

    var rt = attachRawTracepoint(testing.allocator, "sys_enter", prog_fd) catch |e| {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf raw-tracepoint test SKIPPED: attach failed ({s}).\n", .{@errorName(e)});
        return;
    };
    defer rt.detach();
    try testing.expect(rt.fd >= 0);

    // A tracepoint that does not exist must be a typed miss, not a hang.
    try testing.expectError(
        error.TracepointNotFound,
        attachRawTracepoint(testing.allocator, "definitely_not_a_tracepoint", prog_fd),
    );

    rt.detach();
    try testing.expectEqual(@as(linux.fd_t, -1), rt.fd);
    rt.detach(); // idempotent
}

test "LIVE: cgroup attach prefers a BPF link and reports which path it took" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) {
        if (verboseSkip()) std.debug.print(
            "\nLIVE ebpf cgroup-link test SKIPPED: needs CAP_BPF (running as uid {d}).\n",
            .{linux.geteuid()},
        );
        return;
    }

    var path_buf: [64]u8 = undefined;
    const dir = try std.fmt.bufPrintZ(&path_buf, "/sys/fs/cgroup/zig-libs-ebpf-auto-{d}", .{linux.getpid()});
    switch (linux.errno(linux.mkdir(dir.ptr, 0o755))) {
        .SUCCESS => {},
        else => {
            if (verboseSkip()) std.debug.print("\nLIVE ebpf cgroup-link test SKIPPED: cannot create {s}.\n", .{dir});
            return;
        },
    }
    defer _ = linux.rmdir(dir.ptr);

    const dir_rc = linux.open(dir.ptr, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(dir_rc) != .SUCCESS) {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf cgroup-link test SKIPPED: cannot open the cgroup directory.\n", .{});
        return;
    }
    const cgroup_fd: linux.fd_t = @intCast(dir_rc);
    defer _ = linux.close(cgroup_fd);

    const insns = [_]BPF.Insn{ BPF.Insn.mov(.r0, 1), BPF.Insn.exit() };
    const prog_fd = BPF.prog_load(.cgroup_skb, &insns, null, "MIT", 0, 0) catch {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf cgroup-link test SKIPPED: cgroup_skb BPF_PROG_LOAD refused.\n", .{});
        return;
    };
    defer _ = linux.close(prog_fd);

    // .auto: whichever the kernel supports, reported honestly.
    var auto = attachCgroupAuto(cgroup_fd, prog_fd, .cgroup_inet_egress, .{}, .auto) catch |e| {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf cgroup-link test SKIPPED: attach failed ({s}).\n", .{@errorName(e)});
        return;
    };
    std.debug.print("\nLIVE ebpf cgroup attach took the {s} path.\n", .{@tagName(auto.path)});
    try auto.link.detach();

    // .legacy_only must always work and must always report `.legacy`.
    var legacy = try attachCgroupAuto(cgroup_fd, prog_fd, .cgroup_inet_egress, .{}, .legacy_only);
    try testing.expectEqual(AttachPath.legacy, legacy.path);
    try testing.expectEqual(std.meta.Tag(Link).cgroup, std.meta.activeTag(legacy.link));
    try legacy.link.detach();
}

test "LIVE: cgroup attach + detach in a throwaway cgroup" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) {
        if (verboseSkip()) std.debug.print(
            "\nLIVE ebpf cgroup attach test SKIPPED: needs CAP_BPF+CAP_NET_ADMIN (running as uid {d}).\n",
            .{linux.geteuid()},
        );
        return;
    }

    // A private child cgroup so nothing system-wide is touched even briefly.
    var path_buf: [64]u8 = undefined;
    const dir = try std.fmt.bufPrintZ(&path_buf, "/sys/fs/cgroup/zig-libs-ebpf-{d}", .{linux.getpid()});
    switch (linux.errno(linux.mkdir(dir.ptr, 0o755))) {
        .SUCCESS => {},
        else => {
            if (verboseSkip()) std.debug.print("\nLIVE ebpf cgroup attach test SKIPPED: cannot create {s} (cgroup v2 not mounted?).\n", .{dir});
            return;
        },
    }
    defer _ = linux.rmdir(dir.ptr);

    const dir_rc = linux.open(dir.ptr, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(dir_rc) != .SUCCESS) {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf cgroup attach test SKIPPED: cannot open the cgroup directory.\n", .{});
        return;
    }
    const cgroup_fd: linux.fd_t = @intCast(dir_rc);
    defer _ = linux.close(cgroup_fd);

    // The smallest valid cgroup_skb program: r0 = 1 (allow), exit.
    const insns = [_]BPF.Insn{ BPF.Insn.mov(.r0, 1), BPF.Insn.exit() };
    const prog_fd = BPF.prog_load(.cgroup_skb, &insns, null, "MIT", 0, 0) catch {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf cgroup attach test SKIPPED: cgroup_skb BPF_PROG_LOAD refused.\n", .{});
        return;
    };
    defer _ = linux.close(prog_fd);

    var cg = attachCgroup(cgroup_fd, prog_fd, .cgroup_inet_egress) catch |e| {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf cgroup attach test SKIPPED: BPF_PROG_ATTACH failed ({s}).\n", .{@errorName(e)});
        return;
    };
    defer cg.deinit();

    try testing.expect(!cg.detached);
    try cg.detach();
    try testing.expect(cg.detached);
    // Idempotent.
    try cg.detach();
}

// ── fuzz: the one text parser in this file ──────────────────────────────────
//
// Everything else in this file is a syscall wrapper (perf_event_open,
// ioctl, netlink, bpf()) — there is no "parse untrusted bytes" surface to
// fuzz there; the errno-to-error-set mappings are pure switches over a
// small enumerable domain, already exhaustively covered by the deterministic
// tests above. The netlink ACK reply IS parsed (`waitAck`, via the sibling
// `netlink` module's `codec.MessageIterator`), but that parser is already a
// fuzz target in `netlink`'s own test suite (`codec.zig`'s "fuzz: walkers
// never panic...", `root.zig`'s "fuzz: typed parsers...") — refuzzing the
// same code here through this module's thin wrapper would add no new
// coverage.
//
// `parseConfigShift` is the one exception: a small hand-rolled text parser
// (`"config:N"` / `"config:N-M"`) reading a kernel sysfs file. The file is
// trusted in practice (root-owned, mode 0444), but it is still BYTES READ
// FROM DISK rather than a value this process constructed, and the function
// is explicitly `pub` and split out "so the ... grammar is testable without
// sysfs" per its own doc comment — so it is fuzzed here for the same reason
// its existing edge-case tests exist.

test "fuzz: parseConfigShift never panics on arbitrary sysfs-file bytes" {
    try testing.fuzz({}, fuzzParseConfigShift, .{});
}

fn fuzzParseConfigShift(_: void, smith: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    const default: u6 = smith.value(u6);
    // The u6 return type already makes "out of range" unrepresentable; the
    // property under test is that arbitrary bytes (short reads, embedded
    // NULs, non-ASCII, digit strings far longer than any real shift value,
    // a bare "config:" with nothing after it, multiple '-' separators, …)
    // never trip an unreachable/overflow/index-out-of-bounds path.
    _ = parseConfigShift(buf[0..len], default);
}
