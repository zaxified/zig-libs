// SPDX-License-Identifier: MIT
//! Attach mechanisms — OPUS-tier syscall plumbing wiring an already-loaded
//! `prog_fd` (from `load.zig`) to a kernel hook. Nothing here is a verifier
//! problem: every constraint below is "which syscalls, in which order, with
//! which struct fields" — mechanical once you have the kernel UAPI in front
//! of you, unlike `programs.zig`'s FABLE-tier bytecode generation. Each
//! function is a `TODO(opus)` `@panic` stub; see each doc comment for the
//! exact sequence and which pieces `std` is missing (spoiler: most of it —
//! `std.os.linux` gives you `perf_event_open`/`ioctl`/`bpf()` as raw
//! syscalls but none of the higher-level BPF-attach wiring on top).

const std = @import("std");
const linux = std.os.linux;
const BPF = linux.BPF;
const netlink = @import("netlink");

// ── kprobe attach (perf_event_open + ioctl) ─────────────────────────────────

pub const KprobeAttachError = error{
    /// /sys/bus/event_source/devices/kprobe/type is missing (kernel built
    /// without CONFIG_KPROBE_EVENTS) or unreadable.
    KprobePmuUnavailable,
    SymbolNotFound,
    PermissionDenied,
    Unexpected,
};

/// An attached kprobe: the open perf-event fd. Detach = close it (the
/// kernel tears down the probe + BPF attachment together).
pub const KprobeHandle = struct { perf_fd: linux.fd_t };

/// Attach `prog_fd` to kernel function `symbol`'s entry via a dynamic
/// kprobe on the kernel's `kprobe` PMU.
///
/// TODO(opus): the full sequence is:
///  1. Read the kprobe PMU's numeric `type` id from
///     `/sys/bus/event_source/devices/kprobe/type` (plain text file, one
///     decimal integer — a regular `open`+`read`, no ioctl). Needed because
///     `perf_event_attr.type` must name a *specific* PMU by its
///     kernel-assigned dynamic id; kprobes are not one of the static
///     `PERF_TYPE_*` values `std.os.linux.PERF.TYPE` enumerates.
///  2. Build a `perf_event_attr` (NOT currently in `std.os.linux` — must be
///     hand-declared per `include/uapi/linux/perf_event.h`) with `.type` =
///     the id from step 1, `.size = @sizeOf(perf_event_attr)`, and the probe
///     identified via the struct's `kprobe_func`/`probe_offset` union
///     fields (a `[*:0]const u8` pointer to `symbol` plus an offset of 0 for
///     "function entry") rather than the numeric `.config` field ordinary
///     hardware/software events use.
///  3. `perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC)` — `pid ==
///     -1, cpu >= 0` attaches to one specific CPU; libbpf's convention is
///     one perf fd PER ONLINE CPU for a system-wide kprobe (so a full
///     implementation loops `sched_getaffinity`/`/sys/devices/system/cpu/
///     online` and opens one fd per CPU, not just one). `std.os.linux.
///     perf_event_open` already exists as the raw syscall wrapper — this is
///     the one primitive this attach path does NOT need to hand-roll.
///  4. `ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, @as(usize, @intCast(prog_fd)))`
///     to attach the program to the perf event.
///  5. `ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0)` to arm it.
///  `PERF_EVENT_IOC_SET_BPF` and `PERF_EVENT_IOC_ENABLE`'s ioctl request
///  numbers are NOT in `std.os.linux` (grep `os/linux.zig` for
///  `PERF_EVENT_IOC` — absent); they must be derived by hand from the
///  `_IO`/`_IOW` macros in `linux/perf_event.h` (`_IOW('$', 8, __u32)` and
///  `_IO('$', 0)` respectively as of the upstream UAPI header) and encoded
///  the same way this repo's other ioctl-using modules do (see `rawsock`'s
///  `SIOCSIFFLAGS` usage for the local pattern).
pub fn attachKprobe(gpa: std.mem.Allocator, symbol: []const u8, prog_fd: linux.fd_t) KprobeAttachError!KprobeHandle {
    _ = gpa;
    _ = symbol;
    _ = prog_fd;
    @panic("TODO(opus): attach kprobe via perf_event_open + ioctl(PERF_EVENT_IOC_SET_BPF, PERF_EVENT_IOC_ENABLE) — read the kprobe PMU type from /sys/bus/event_source/devices/kprobe/type, hand-declare perf_event_attr's kprobe_func/probe_offset union (not in std), derive the two ioctl request numbers by hand (not in std.os.linux). See this function's doc comment for the full 5-step sequence.");
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
};

pub const XdpAttachError = error{
    NoSuchInterface,
    AlreadyAttached,
    PermissionDenied,
    SendFailed,
    RecvFailed,
    MalformedReply,
    Unexpected,
};

/// Attach `prog_fd` as the XDP program on interface `ifindex` (e.g. from
/// `netlink.Socket.links()`'s `Link.index`).
///
/// TODO(opus): build one `RTM_SETLINK` message: an `ifinfomsg` header
/// (`ifi_family = AF_UNSPEC`, `ifi_index = ifindex`, rest zeroed — reuse
/// `netlink`'s `ifinfomsg_len`/framing helpers, this module already depends
/// on the sibling `netlink` module for exactly this) followed by ONE NESTED
/// `IFLA_XDP` attribute (`linux/if_link.h`) whose payload is itself a
/// TLV list of child attributes:
///   - `IFLA_XDP_FD` (i32 = `prog_fd`) — required.
///   - `IFLA_XDP_FLAGS` (u32, `XDP_FLAGS_*` bits from `opts`) — optional,
///     selects skb/driver/hardware mode; omitting it lets the kernel pick.
/// Nesting: `netlink.codec.appendAttr*` writes ONE flat length-prefixed TLV;
/// a nested attribute needs the same length-prefix-then-patch-later
/// discipline `netlink.codec.appendHeader`/`finishHeader` already use for
/// the outer `nlmsghdr` — apply it one level deeper around the two child
/// attrs, remembering the parent `IFLA_XDP` attr's own length field must be
/// patched to include its children's bytes. Send with
/// `NLM_F_REQUEST|NLM_F_ACK` over a `netlink.Socket`, then read the
/// `NLMSG_ERROR` ack the same way `netlink.Socket`'s own write paths do.
/// Detach = the identical message with `IFLA_XDP_FD = -1`.
pub fn attachXdp(gpa: std.mem.Allocator, ifindex: u32, prog_fd: linux.fd_t, flags: XdpFlags) XdpAttachError!void {
    _ = gpa;
    _ = ifindex;
    _ = prog_fd;
    _ = flags;
    @panic("TODO(opus): attach XDP via netlink RTM_SETLINK + a nested IFLA_XDP{IFLA_XDP_FD,IFLA_XDP_FLAGS} attribute — reuse the sibling netlink module's nlmsghdr/nlattr codec (this module already depends on it); the only new piece is the ONE extra level of length-prefix nesting for IFLA_XDP's child TLVs. See this function's doc comment for the exact attribute layout.");
}

// ── cgroup attach (BPF_PROG_ATTACH) ─────────────────────────────────────────

pub const CgroupAttachError = error{
    PermissionDenied,
    AlreadyAttached,
    Unexpected,
};

/// Attach `prog_fd` to `cgroup_fd` (an open fd on the cgroup's directory,
/// e.g. from `open("/sys/fs/cgroup/...", O_DIRECTORY)`) for `attach_type`
/// (e.g. `.cgroup_inet_egress`).
///
/// TODO(opus): this is the most mechanical of the three attach paths —
/// `std.os.linux.BPF` already defines every TYPE involved
/// (`Cmd.prog_attach`, `ProgAttachAttr`, `Attr`), it just never grew a
/// wrapper FUNCTION for this command the way it did for `map_create`/
/// `prog_load`/the `map_*_elem` family. The missing wrapper is:
/// ```
/// var attr = BPF.Attr{ .prog_attach = std.mem.zeroes(BPF.ProgAttachAttr) };
/// attr.prog_attach = .{
///     .target_fd = cgroup_fd,
///     .attach_bpf_fd = prog_fd,
///     .attach_type = @intFromEnum(attach_type),
///     .attach_flags = 0,
///     .replace_bpf_fd = -1,
/// };
/// const rc = linux.bpf(.prog_attach, &attr, @sizeOf(BPF.ProgAttachAttr));
/// ```
/// then the usual `linux.errno(rc)` switch (`.SUCCESS` / `.PERM` ->
/// `PermissionDenied` / `.EXIST` -> `AlreadyAttached` / default ->
/// `Unexpected`) that every other wrapper in `std.os.linux.BPF` already
/// follows — copy that pattern exactly (see `BPF.map_create` in
/// `lib/std/os/linux/bpf.zig` for the template). Detach mirrors this with
/// `Cmd.prog_detach`.
pub fn attachCgroup(cgroup_fd: linux.fd_t, prog_fd: linux.fd_t, attach_type: BPF.AttachType) CgroupAttachError!void {
    _ = cgroup_fd;
    _ = prog_fd;
    _ = attach_type;
    @panic("TODO(opus): attach cgroup via BPF_PROG_ATTACH — std already defines every type (Cmd.prog_attach/ProgAttachAttr/Attr), only the errno-mapping wrapper function is missing; template it on std.os.linux.BPF.map_create's error-switch shape. See this function's doc comment for the exact Attr fill.");
}

// ── tests ────────────────────────────────────────────────────────────────────
//
// Every function above panics until implemented, and even implemented,
// attach needs CAP_BPF/CAP_NET_ADMIN + a loaded prog_fd (itself needing
// programs.zig's TODO(fable/core) builders). Nothing here calls into any of
// them; these are structural-only checks that the error sets / option
// structs compile and have the field names load.zig/root.zig expect.

const testing = std.testing;

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
