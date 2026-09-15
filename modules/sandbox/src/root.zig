// SPDX-License-Identifier: MIT
//! sandbox — Linux process self-hardening for an internet-facing server.
//!
//! A server that has already `bind(2)`/`listen(2)`'d needs almost none of the
//! kernel's attack surface. This module is the set of composable, opt-in steps
//! it calls at startup — *after* it has acquired every privileged resource — to
//! shrink that surface to what a request loop actually touches. Each step is
//! independent; a caller picks the ones it wants and applies them in order.
//!
//! The five steps, weakest-precondition first:
//!
//!  1. `noNewPrivs` — `prctl(PR_SET_NO_NEW_PRIVS)`. Makes execve() unable to
//!     grant new privileges (setuid bits, file caps) and is the precondition
//!     for installing a seccomp filter without `CAP_SYS_ADMIN`.
//!  2. `dropPrivileges` — `setgroups([]) → setgid → setuid`, in that exact
//!     order (the classic hole is setuid *before* setgid — once uid 0 is gone
//!     you can no longer setgid), then a read-back that the drop actually
//!     stuck. Optional `dropCapabilityBoundingSet` / `clearCapabilities`.
//!  3. rlimits — `setrlimit` helpers, incl. `disableCoreDumps` (RLIMIT_CORE=0)
//!     so a crash can't spill in-memory keys to disk.
//!  4. `Landlock` — an unprivileged filesystem allow-list (kernel ≥ 5.13),
//!     with ABI-version negotiation and a typed "kernel too old" error.
//!  5. `seccomp` — a classic-BPF syscall **allow-list** installed via
//!     `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`, with a configurable action
//!     for denied calls (kill the process, or fail with an errno).
//!
//! Linux-only by design: raw `std.os.linux` syscalls, zero C, no libc (the same
//! conscious ceiling as `netlink` / `rawsock`). Every failure is a typed error,
//! never a panic — a server must be able to log "hardening step X unavailable"
//! and decide policy, not crash. All ABI constants here are clean-room from the
//! kernel UAPI (`prctl.h`, `seccomp.h`, `landlock.h`, `capability.h`); see
//! SPEC.md for the citation.
//!
//! Basic usage (order matters — do this last, after bind/listen, and BEFORE
//! spawning worker threads: Landlock's `restrictSelf` and the prctl-form
//! `seccomp.install` confine the calling thread only, and Landlock has no
//! TSYNC equivalent at all):
//!
//! ```zig
//! const sandbox = @import("sandbox");
//!
//! try sandbox.noNewPrivs();
//! try sandbox.disableCoreDumps();
//! // Bounding set FIRST — it needs CAP_SETPCAP, which the uid drop below
//! // takes away (after setuid to a non-root uid every capability is gone).
//! sandbox.dropCapabilityBoundingSet() catch {};
//! try sandbox.dropPrivileges(.{ .uid = 65534, .gid = 65534 });
//!
//! // Landlock: `init()` handles EVERY filesystem right the kernel knows
//! // (deny-by-default), and `allowPath` grants what a tree may be used for.
//! var ll = try sandbox.Landlock.init();
//! defer ll.deinit();
//! try ll.allowPath("/var/www", sandbox.Landlock.access.read_only);
//! try ll.restrictSelf();
//!
//! const prog = try sandbox.seccomp.buildDefault(gpa, .kill_process);
//! defer gpa.free(prog);
//! try sandbox.seccomp.install(prog);
//! ```

const std = @import("std");
const builtin = @import("builtin");

const linux = std.os.linux;
const E = linux.E;
const Allocator = std.mem.Allocator;

comptime {
    if (builtin.os.tag != .linux)
        @compileError("sandbox is Linux-only (raw prctl/seccomp/landlock syscalls, no portable fallback)");
}

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Process self-hardening for an internet-facing server — privilege drop, `setrlimit`/no core dumps, Landlock fs allow-list, seccomp-bpf.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "**linux**",
    .targets = .{.linux64},
    .platform = .linux,
    .role = .util,
    .concurrency = .single_owner, // applied once at startup by the owning thread
    .model_after = "Linux kernel UAPI (prctl/seccomp/landlock/capability) + OpenSSH/systemd sandboxing shape",
    .deps = .{},
};

// ── 1. no-new-privs ───────────────────────────────────────────────────────────

pub const NoNewPrivsError = error{PrctlFailed};

/// `prctl(PR_SET_NO_NEW_PRIVS, 1)`. After this, no execve() in this process (or
/// any descendant) can grant privileges it did not already hold — setuid/setgid
/// bits and file capabilities are neutralised. Required before a seccomp filter
/// can be installed without `CAP_SYS_ADMIN`, so a server normally calls this
/// first. The bit is a one-way latch: it cannot be cleared. Never fails on a
/// kernel ≥ 3.5; the typed error exists only for the theoretical older kernel.
pub fn noNewPrivs() NoNewPrivsError!void {
    const rc = linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0);
    if (linux.errno(rc) != .SUCCESS) return error.PrctlFailed;
}

// ── 2. privilege drop ─────────────────────────────────────────────────────────

pub const Credentials = struct {
    uid: linux.uid_t,
    gid: linux.gid_t,
};

pub const DropError = error{
    /// A setgroups/setgid/setuid call returned an error (typically EPERM — the
    /// process is not privileged enough to change to the target ids).
    SetIdFailed,
    /// The calls "succeeded" but a read-back shows the ids did not actually
    /// change to the requested values. Treat as fatal — never keep running.
    DropNotEffective,
};

/// Permanently drop to `creds`, in the only safe order:
///   `setgroups([]) → setgid(gid) → setuid(uid)`.
/// Doing setuid *before* setgid is the classic bug: dropping uid 0 first
/// removes the privilege that setgid and setgroups themselves require, so the
/// supplementary groups / gid silently stay elevated. We also verify with a
/// read-back that the drop is TOTAL: real, effective AND saved uid/gid
/// (`getresuid`/`getresgid` — the saved id is exactly what `seteuid(2)`
/// climbs back up through, so checking only real+effective left the door it
/// guards untested), and that the supplementary group list is empty
/// (`getgroups` — `setgroups` returning success is not the same as the list
/// being empty). Any mismatch is `error.DropNotEffective`: a partial or
/// spoofed drop is fatal, never tolerated. Call `noNewPrivs()` first if you
/// also want execve() locked, and drop the capability bounding set BEFORE
/// this call — it needs `CAP_SETPCAP`, which a non-root uid no longer holds.
pub fn dropPrivileges(creds: Credentials) DropError!void {
    // 1. Clear supplementary groups — must happen while still privileged.
    const no_groups = [_]linux.gid_t{};
    if (linux.errno(linux.setgroups(0, &no_groups)) != .SUCCESS) return error.SetIdFailed;

    // 2. Real+effective+saved gid. setgid sets all three when privileged.
    if (linux.errno(linux.setgid(creds.gid)) != .SUCCESS) return error.SetIdFailed;

    // 3. Real+effective+saved uid, LAST — this is the point of no return.
    if (linux.errno(linux.setuid(creds.uid)) != .SUCCESS) return error.SetIdFailed;

    // 4. Read back: the drop must be total — real, effective AND saved ids,
    //    and no supplementary group left behind.
    var ruid: linux.uid_t = undefined;
    var euid: linux.uid_t = undefined;
    var suid: linux.uid_t = undefined;
    if (linux.errno(linux.getresuid(&ruid, &euid, &suid)) != .SUCCESS) return error.DropNotEffective;
    if (ruid != creds.uid or euid != creds.uid or suid != creds.uid) return error.DropNotEffective;
    var rgid: linux.gid_t = undefined;
    var egid: linux.gid_t = undefined;
    var sgid: linux.gid_t = undefined;
    if (linux.errno(linux.getresgid(&rgid, &egid, &sgid)) != .SUCCESS) return error.DropNotEffective;
    if (rgid != creds.gid or egid != creds.gid or sgid != creds.gid) return error.DropNotEffective;
    // getgroups(0, NULL) returns the number of supplementary groups.
    const ngroups = linux.getgroups(0, null);
    if (linux.errno(ngroups) != .SUCCESS or ngroups != 0) return error.DropNotEffective;
}

pub const CapabilityError = error{
    /// prctl(PR_CAPBSET_DROP)/capset returned EPERM — needs CAP_SETPCAP.
    PermissionDenied,
    /// The syscall failed for another reason.
    CapFailed,
};

/// Number of capabilities we probe when draining the bounding set. The real
/// `CAP_LAST_CAP` grows over kernels; PR_CAPBSET_DROP returns EINVAL for an
/// unknown cap, which we treat as "past the end" and stop — so this only needs
/// to be an over-estimate.
const cap_probe_ceiling = 64;

/// Drop every capability from the *bounding set* via `prctl(PR_CAPBSET_DROP)`.
/// The bounding set caps what a process can ever regain (e.g. through a file
/// with a permitted-cap set on a later execve), so draining it is belt-and-
/// braces on top of a uid drop + no-new-privs. Requires `CAP_SETPCAP`; a
/// non-privileged caller gets `error.PermissionDenied` and should skip it.
pub fn dropCapabilityBoundingSet() CapabilityError!void {
    var cap: usize = 0;
    while (cap < cap_probe_ceiling) : (cap += 1) {
        const rc = linux.prctl(@intFromEnum(linux.PR.CAPBSET_DROP), cap, 0, 0, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INVAL => break, // unknown capability number — past CAP_LAST_CAP
            .PERM => return error.PermissionDenied,
            else => return error.CapFailed,
        }
    }
}

// _LINUX_CAPABILITY_VERSION_3 — the current 64-bit-capable header version.
const linux_capability_version_3: u32 = 0x20080522;

/// Zero the effective, permitted and inheritable capability sets of the calling
/// thread via `capset(2)` (UAPI v3, two 32-bit words for caps 0..63). This
/// removes caps the process currently *holds*, complementing the bounding-set
/// drop (which only limits what could be regained). Requires privilege to be a
/// no-op-or-error rather than a silent partial clear.
pub fn clearCapabilities() CapabilityError!void {
    var hdr = extern struct { version: u32, pid: c_int }{
        .version = linux_capability_version_3,
        .pid = 0, // 0 == the calling thread
    };
    // v3 requires an array of two data words (low caps 0..31, high 32..63).
    var data = [2]extern struct { effective: u32, permitted: u32, inheritable: u32 }{
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
    };
    const rc = linux.syscall2(.capset, @intFromPtr(&hdr), @intFromPtr(&data));
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM => return error.PermissionDenied,
        else => return error.CapFailed,
    }
}

// ── 3. rlimits ────────────────────────────────────────────────────────────────

pub const RlimitError = error{SetrlimitFailed};

/// The kernel's "no limit" sentinel (`RLIM_INFINITY`), for a hard limit you do
/// not want to cap.
pub const rlim_infinity: linux.rlim_t = linux.RLIM.INFINITY;

/// Set both the soft and hard limit of `resource`. A non-privileged process may
/// only *lower* its hard limit (and raise the soft up to the hard) — attempting
/// to raise a hard limit yields EPERM, surfaced as `error.SetrlimitFailed`.
pub fn setLimit(resource: linux.rlimit_resource, soft: linux.rlim_t, hard: linux.rlim_t) RlimitError!void {
    const rl = linux.rlimit{ .cur = soft, .max = hard };
    if (linux.errno(linux.setrlimit(resource, &rl)) != .SUCCESS) return error.SetrlimitFailed;
}

/// RLIMIT_CORE = 0. Disables core dumps entirely — a crash of a server holding
/// private keys / session secrets in memory must not be able to write them to a
/// world- or admin-readable core file.
pub fn disableCoreDumps() RlimitError!void {
    return setLimit(.CORE, 0, 0);
}

/// RLIMIT_NOFILE — cap the highest file-descriptor number the process can open.
/// A tight bound blunts fd-exhaustion amplification and stops a compromised
/// path from opening thousands of descriptors.
pub fn limitOpenFiles(n: linux.rlim_t) RlimitError!void {
    return setLimit(.NOFILE, n, n);
}

/// RLIMIT_NPROC — cap the number of processes/threads for this real uid. Blunts
/// fork-bomb style amplification from a compromised worker.
pub fn limitProcesses(n: linux.rlim_t) RlimitError!void {
    return setLimit(.NPROC, n, n);
}

/// RLIMIT_AS — cap total virtual address space (bytes). A ceiling on runaway
/// allocation; note it counts mappings, so size it generously above the real
/// working set.
pub fn limitAddressSpace(bytes: linux.rlim_t) RlimitError!void {
    return setLimit(.AS, bytes, bytes);
}

// ── 4. Landlock (filesystem allow-list, kernel ≥ 5.13) ─────────────────────────

// UAPI: linux/landlock.h. Syscall numbers come from std.os.linux.SYS.

/// `struct landlock_ruleset_attr` — the set of access rights this ruleset will
/// *handle* (i.e. deny unless a rule re-allows). ABI 4 added a net field; we
/// only model the filesystem field (a trailing unmodelled field is fine — we
/// pass our own `size`).
const RulesetAttr = extern struct {
    handled_access_fs: u64,
};

/// `struct landlock_path_beneath_attr` — packed in the UAPI (u64 then s32, 12
/// bytes, no tail padding), so each field is byte-aligned to reproduce the C
/// `__attribute__((packed))` layout exactly.
const PathBeneathAttr = extern struct {
    allowed_access: u64 align(1),
    parent_fd: i32 align(1),
};

const landlock_rule_path_beneath: u32 = 1;
const landlock_create_ruleset_version: u32 = 1 << 0;

fn sys_landlock_create_ruleset(attr: ?*const RulesetAttr, size: usize, flags: u32) usize {
    return linux.syscall3(.landlock_create_ruleset, @intFromPtr(attr), size, flags);
}
fn sys_landlock_add_rule(ruleset_fd: i32, rule_type: u32, rule_attr: *const anyopaque, flags: u32) usize {
    return linux.syscall4(
        .landlock_add_rule,
        @as(usize, @bitCast(@as(isize, ruleset_fd))),
        rule_type,
        @intFromPtr(rule_attr),
        flags,
    );
}
fn sys_landlock_restrict_self(ruleset_fd: i32, flags: u32) usize {
    return linux.syscall2(
        .landlock_restrict_self,
        @as(usize, @bitCast(@as(isize, ruleset_fd))),
        flags,
    );
}

pub const LandlockError = error{
    /// Kernel does not implement Landlock at all (< 5.13, or CONFIG_SECURITY_
    /// LANDLOCK=n) — `landlock_create_ruleset` returned ENOSYS.
    NotSupported,
    /// Landlock is compiled in but disabled at boot (no "landlock" LSM) —
    /// EOPNOTSUPP.
    Disabled,
    /// A path handed to `allowPath` could not be opened.
    PathOpenFailed,
    /// The final component of a path handed to `allowPath` is a symlink.
    /// `allowPath` opens with `O_NOFOLLOW` so the tree a rule grants is the
    /// one the configuration names, not whatever a symlink — writable by
    /// anyone with write access to its parent — points at today (the A1 audit
    /// granted the whole filesystem through one `link_to_root -> /`).
    /// Resolve the link yourself and pass the target if that is what you mean.
    /// Intermediate components are still followed (`O_NOFOLLOW` applies to
    /// the last one only), so `/var/run/app` on a system where `/var/run` is
    /// a symlink keeps working.
    PathIsSymlink,
    /// A landlock syscall failed unexpectedly.
    RulesetFailed,
    /// `restrictSelf` needs PR_SET_NO_NEW_PRIVS set first (or CAP_SYS_ADMIN).
    NoNewPrivsRequired,
};

/// Query the Landlock ABI version the running kernel supports. Returns ≥ 1 on
/// success; `error.NotSupported` on a pre-5.13 kernel and `error.Disabled` when
/// the LSM is present but off. Callers can branch on this to decide whether to
/// harden or to log-and-continue.
pub fn landlockAbiVersion() LandlockError!i32 {
    const rc = sys_landlock_create_ruleset(null, 0, landlock_create_ruleset_version);
    switch (linux.errno(rc)) {
        .SUCCESS => return @intCast(@as(isize, @bitCast(rc))),
        .NOSYS => return error.NotSupported,
        .OPNOTSUPP => return error.Disabled,
        else => return error.RulesetFailed,
    }
}

/// A Landlock ruleset under construction: create it, `allowPath` the directories
/// (or files) a server legitimately needs, then `restrictSelf`. Everything not
/// explicitly allowed becomes inaccessible for the handled access rights. The
/// ruleset's `handled` mask is intersected with what the running ABI supports,
/// so the same code degrades cleanly across kernels instead of failing with
/// EINVAL on an unknown access bit.
pub const Ruleset = struct {
    fd: i32,
    abi: i32,
    handled: u64,

    /// Filesystem access-right bits (UAPI `LANDLOCK_ACCESS_FS_*`) plus a few
    /// convenience unions for the common server shapes.
    pub const access = struct {
        pub const execute: u64 = 1 << 0;
        pub const write_file: u64 = 1 << 1;
        pub const read_file: u64 = 1 << 2;
        pub const read_dir: u64 = 1 << 3;
        pub const remove_dir: u64 = 1 << 4;
        pub const remove_file: u64 = 1 << 5;
        pub const make_char: u64 = 1 << 6;
        pub const make_dir: u64 = 1 << 7;
        pub const make_reg: u64 = 1 << 8;
        pub const make_sock: u64 = 1 << 9;
        pub const make_fifo: u64 = 1 << 10;
        pub const make_block: u64 = 1 << 11;
        pub const make_sym: u64 = 1 << 12;
        pub const refer: u64 = 1 << 13; // ABI 2+
        pub const truncate: u64 = 1 << 14; // ABI 3+
        pub const ioctl_dev: u64 = 1 << 15; // ABI 5+

        /// Read a file's contents and list a directory.
        pub const read_only: u64 = read_file | read_dir;
        /// Read + write + create/remove regular files (a typical data dir).
        pub const read_write: u64 = read_file | read_dir | write_file |
            make_reg | remove_file | truncate;
        /// Every filesystem right this module knows (bits 0..15). `init()`
        /// handles this set — clamped to what the running ABI understands —
        /// so that a right nobody `allowPath`s is DENIED. Landlock only ever
        /// restricts rights that are handled; a right left out of the
        /// handled mask stays unrestricted everywhere, which is why the
        /// `read_only`/`read_write` unions are for `allowPath`, never for
        /// the ruleset itself.
        pub const all: u64 = (1 << 16) - 1;
    };

    /// Bits of `access` a given ABI version understands. Passing a bit the ABI
    /// does not know makes `landlock_create_ruleset` fail with EINVAL, so the
    /// handled mask must be intersected with this.
    fn accessMaskForAbi(abi: i32) u64 {
        var m: u64 = 0;
        // ABI 1: EXECUTE(0) .. MAKE_SYM(12).
        var bit: u6 = 0;
        while (bit <= 12) : (bit += 1) m |= @as(u64, 1) << bit;
        if (abi >= 2) m |= access.refer;
        if (abi >= 3) m |= access.truncate;
        if (abi >= 5) m |= access.ioctl_dev;
        return m;
    }

    /// Create a ruleset that handles — denies unless a rule re-allows —
    /// EVERY filesystem right the running kernel's Landlock ABI knows
    /// (`access.all` clamped by `accessMaskForAbi`). This is the shape a
    /// sandbox wants: `allowPath` then says what each tree may be used for,
    /// and anything not granted anywhere is refused.
    ///
    /// Why there is no argument: the earlier `init(handled)` invited passing
    /// the same `access.read_only` here and to `allowPath`, and every piece of
    /// this module's documentation did exactly that. A ruleset that handles
    /// only `read_file|read_dir` leaves the other 14 rights — write, create,
    /// unlink, mkdir, symlink, truncate, … — completely unrestricted
    /// everywhere, so a process "confined to a read-only tree" could still
    /// create and overwrite any file its DAC permissions reached (measured by
    /// the A1 audit: create/truncate/mkdir/symlink/unlink outside the
    /// allow-list all SUCCESS). `initHandling` keeps the explicit form for
    /// the rare case that genuinely wants some right left unhandled.
    pub fn init() LandlockError!Ruleset {
        return initHandling(access.all);
    }

    /// Create a ruleset that handles exactly `handled_access` (clamped to the
    /// ABI). ⚠ A right NOT in this mask is not denied anywhere — it is
    /// unrestricted, for every path, forever. Use `init()` unless you are
    /// deliberately leaving a right unrestricted (e.g. `execute` for a process
    /// that must be able to exec anything), and never pass a convenience
    /// union meant for `allowPath` here.
    pub fn initHandling(handled_access: u64) LandlockError!Ruleset {
        const abi = try landlockAbiVersion();
        const handled = handled_access & accessMaskForAbi(abi);
        const attr = RulesetAttr{ .handled_access_fs = handled };
        const rc = sys_landlock_create_ruleset(&attr, @sizeOf(RulesetAttr), 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .NOSYS => return error.NotSupported,
            .OPNOTSUPP => return error.Disabled,
            else => return error.RulesetFailed,
        }
        return .{ .fd = @intCast(@as(isize, @bitCast(rc))), .abi = abi, .handled = handled };
    }

    /// Allow `allowed_access` on everything beneath `path` (a directory or a
    /// single file). The access is clamped to the ruleset's handled set — you
    /// cannot allow a right the ruleset does not deny in the first place.
    pub fn allowPath(self: *Ruleset, path: [*:0]const u8, allowed_access: u64) LandlockError!void {
        // O_PATH|O_CLOEXEC: we only need a handle to name the tree, not to
        // read it. O_NOFOLLOW: the rule must attach to what the configuration
        // names, not to a symlink's current target (see `PathIsSymlink`).
        const ofd = linux.open(path, .{ .PATH = true, .CLOEXEC = true, .NOFOLLOW = true, .DIRECTORY = false }, 0);
        if (linux.errno(ofd) != .SUCCESS) return error.PathOpenFailed;
        const parent_fd: i32 = @intCast(@as(isize, @bitCast(ofd)));
        defer _ = linux.close(parent_fd);
        // With O_NOFOLLOW an O_PATH open of a symlink SUCCEEDS and refers to
        // the link itself; refuse it by name rather than let the kernel's
        // add_rule report an opaque failure.
        var st: linux.Statx = undefined;
        const at_empty_path: u32 = 0x1000; // AT_EMPTY_PATH: operate on `parent_fd` itself
        if (linux.errno(linux.statx(parent_fd, "", at_empty_path, .{ .TYPE = true }, &st)) != .SUCCESS) return error.PathOpenFailed;
        if (linux.S.ISLNK(st.mode)) return error.PathIsSymlink;

        const attr = PathBeneathAttr{
            .allowed_access = allowed_access & self.handled,
            .parent_fd = parent_fd,
        };
        const rc = sys_landlock_add_rule(self.fd, landlock_rule_path_beneath, &attr, 0);
        if (linux.errno(rc) != .SUCCESS) return error.RulesetFailed;
    }

    /// Enforce the ruleset on the CALLING THREAD and everything it later
    /// forks/spawns. Irreversible. Requires PR_SET_NO_NEW_PRIVS (call
    /// `noNewPrivs()` first) unless the process holds `CAP_SYS_ADMIN`.
    ///
    /// ⚠ Per-thread, like the prctl-form seccomp install — and unlike
    /// seccomp, Landlock offers NO `TSYNC`-style flag that would reach threads
    /// already running. A worker spawned before this call stays unconfined
    /// (measured: main thread EACCES, pre-existing worker SUCCESS on the same
    /// path). Restrict before spawning workers; there is no later fix-up.
    pub fn restrictSelf(self: *Ruleset) LandlockError!void {
        const rc = sys_landlock_restrict_self(self.fd, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .PERM => return error.NoNewPrivsRequired,
            else => return error.RulesetFailed,
        }
    }

    /// Close the ruleset fd. Safe (and expected) to call after `restrictSelf` —
    /// enforcement persists once applied; the fd only matters during building.
    pub fn deinit(self: *Ruleset) void {
        _ = linux.close(self.fd);
    }
};

/// Convenience alias so callers can write `sandbox.Landlock`.
pub const Landlock = Ruleset;

// ── 5. seccomp-bpf (syscall allow-list) ────────────────────────────────────────

/// One classic-BPF instruction — `struct sock_filter`, 8 bytes, fixed layout.
pub const SockFilter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

/// `struct sock_fprog` — the (len, filter*) pair handed to the kernel.
const SockFprog = extern struct {
    len: u16,
    filter: [*]const SockFilter,
};

/// Classic-BPF opcode building blocks (`<linux/bpf_common.h>` values). A `code`
/// is an OR of an instruction class with a size/mode or a jump op/source.
pub const bpf = struct {
    // class
    pub const ld: u16 = 0x00; // load into accumulator
    pub const alu: u16 = 0x04; // arithmetic/logic on the accumulator
    pub const jmp: u16 = 0x05; // conditional jump
    pub const ret: u16 = 0x06; // return an action
    // load size / mode
    pub const w: u16 = 0x00; // 32-bit word
    pub const abs: u16 = 0x20; // fixed offset into the seccomp_data struct
    // jump op / source
    pub const jeq: u16 = 0x10; // A == k
    pub const k: u16 = 0x00; // constant operand
    // ALU op
    pub const and_: u16 = 0x50; // A = A & k

    pub fn stmt(code: u16, imm: u32) SockFilter {
        return .{ .code = code, .jt = 0, .jf = 0, .k = imm };
    }
    pub fn jump(code: u16, imm: u32, jt: u8, jf: u8) SockFilter {
        return .{ .code = code, .jt = jt, .jf = jf, .k = imm };
    }
};

/// The kernel's `AUDIT_ARCH_*` token for the target — `EM_<arch>` OR'd with the
/// 64-bit and little-endian flags. Computed clean-room from the UAPI (audit.h /
/// elf.h EM numbers) rather than via `std.os.linux.AUDIT.ARCH`, whose enum body
/// is unbuildable in this std (a bad `elf.EM.FRV` member). The seccomp filter
/// checks `seccomp_data.arch` against this so a syscall entered through a
/// FOREIGN ABI's entry point cannot alias an allowed number: on x86-64 the
/// i386 `int $0x80` entry reports `AUDIT_ARCH_I386`, where nr 39 is `mkdir`
/// while the allow-listed x86-64 nr 39 is `getpid` (measured: without the
/// guard a getpid-only filter created a directory). NB the x32 ABI is NOT
/// what this guard stops — x32 reports `AUDIT_ARCH_X86_64` too; what stops it
/// is default-deny, because an x32 number carries `__X32_SYSCALL_BIT`
/// (0x40000000) and so never equals a bare allow-listed `nr`.
const audit_arch: u32 = blk: {
    const bit64: u32 = 0x8000_0000;
    const le: u32 = 0x4000_0000;
    break :blk switch (builtin.cpu.arch) {
        .x86_64 => 62 | bit64 | le,
        .aarch64 => 183 | bit64 | le,
        .x86 => 3 | le,
        .arm => 40 | le,
        .riscv64 => 243 | bit64 | le,
        .powerpc64le => 21 | bit64 | le,
        .s390x => 22 | bit64,
        .mips64el => 8 | bit64 | le,
        .loongarch64 => 258 | bit64 | le,
        else => @compileError("sandbox: add this arch's AUDIT_ARCH value for the seccomp arch guard"),
    };
};

pub const seccomp = struct {
    /// What the kernel does to a syscall that is NOT on the allow-list.
    pub const Action = union(enum) {
        /// SIGSYS-kill the whole process (the safe default for a hard sandbox).
        kill_process,
        /// SIGSYS-kill only the offending thread.
        kill_thread,
        /// Let the call return `-errno` instead of running — softer, lets a
        /// program feature-probe without dying. Common choice: EPERM. Must
        /// be in `1..4095`: `0` would make a DENIED syscall return 0, i.e.
        /// report success to the caller (`build` refuses it with
        /// `error.InvalidErrno`), and the kernel clamps anything above 4095
        /// to 4095, so a larger value is a mistake, not an errno.
        errno: u16,
        /// Raise SIGSYS so a handler can decide (used by tracing sandboxes).
        trap,
    };

    // seccomp_data field offsets — the "packet" the filter inspects.
    const off_nr = @offsetOf(linux.SECCOMP.data, "nr");
    const off_arch = @offsetOf(linux.SECCOMP.data, "arch");

    /// Low/high 32-bit half of a 64-bit `seccomp_data.argN` field, endian-
    /// aware: classic BPF only has 32-bit loads, so a 64-bit syscall argument
    /// needs two `ld [k]` instructions, and which half is "low" swaps on a
    /// big-endian target (this module's arch table includes s390x). See
    /// `std.os.linux.SECCOMP`'s doc comment for the same point made against
    /// OpenSSH's filter.
    fn argHalves(comptime field: []const u8) struct { lo: u32, hi: u32 } {
        const base = @offsetOf(linux.SECCOMP.data, field);
        return switch (builtin.cpu.arch.endian()) {
            .little => .{ .lo = base, .hi = base + 4 },
            .big => .{ .lo = base + 4, .hi = base },
        };
    }
    const arg2 = argHalves("arg2"); // mmap/mprotect/pkey_mprotect: (ptr, len, prot, ...)

    // Return-action words (UAPI SECCOMP_RET_*).
    const ret_allow = linux.SECCOMP.RET.ALLOW;
    const ret_kill_process = linux.SECCOMP.RET.KILL_PROCESS;
    const ret_kill_thread = linux.SECCOMP.RET.KILL_THREAD;
    const ret_errno = linux.SECCOMP.RET.ERRNO;
    const ret_trap = linux.SECCOMP.RET.TRAP;
    const ret_data_mask = linux.SECCOMP.RET.DATA;

    fn actionWord(a: Action) u32 {
        return switch (a) {
            .kill_process => ret_kill_process,
            .kill_thread => ret_kill_thread,
            .errno => |e| ret_errno | (@as(u32, e) & ret_data_mask),
            .trap => ret_trap,
        };
    }

    pub const BuildError = Allocator.Error || error{
        /// More than 255 allowed syscalls — a single JEQ's jump offset (`jt`)
        /// is a u8, so the allow-list cannot be encoded in this flat shape.
        /// (Split into ranges / a binary search if you ever hit this.)
        TooManySyscalls,
        /// An `Action.errno` outside `1..4095` — see `Action.errno`.
        InvalidErrno,
    };

    /// The largest errno the kernel will hand back through `SECCOMP_RET_ERRNO`
    /// (`SECCOMP_RET_DATA` is 16 bits, but errnos are `< 4096` and the kernel
    /// clamps the value there).
    pub const max_errno: u16 = 4095;

    fn validateAction(a: Action) BuildError!void {
        switch (a) {
            .errno => |e| if (e == 0 or e > max_errno) return error.InvalidErrno,
            else => {},
        }
    }

    /// `SECCOMP_GET_ACTION_AVAIL` (UAPI seccomp.h, operation 2).
    const seccomp_get_action_avail: u32 = 2;

    /// True when this kernel can install a seccomp-bpf filter at all
    /// (`CONFIG_SECCOMP_FILTER`, and the `seccomp(2)` syscall). Probed with
    /// `SECCOMP_GET_ACTION_AVAIL`, which needs no privilege and changes
    /// nothing. Callers — and this module's own tests — use it to decide UP
    /// FRONT whether a filter can exist; a failing `install` after this said
    /// yes is then a real failure, never something to skip past.
    pub fn available() bool {
        const action: u32 = ret_kill_process;
        const rc = linux.syscall3(.seccomp, seccomp_get_action_avail, 0, @intFromPtr(&action));
        return linux.errno(rc) == .SUCCESS;
    }

    pub const InstallError = error{
        /// prctl(PR_SET_SECCOMP) returned an error. Almost always: no
        /// PR_SET_NO_NEW_PRIVS and no CAP_SYS_ADMIN (EACCES), or the kernel
        /// lacks CONFIG_SECCOMP_FILTER (EINVAL).
        SeccompFailed,
    };

    /// Build a classic-BPF program that ALLOWS exactly the syscalls in `allowed`
    /// and applies `on_deny` to everything else. Layout:
    ///
    ///   ld  arch                     ; reject a foreign syscall ABI outright —
    ///   jeq <this arch> → +1         ;   a mismatched arch means the `nr`
    ///   ret KILL_PROCESS             ;   numbers below would be meaningless
    ///   ld  nr
    ///   jeq nr₀ → ALLOW              ; one compare per allowed syscall, each
    ///   jeq nr₁ → ALLOW             ;   jumping forward to the ALLOW leaf
    ///   …
    ///   ret <deny action>            ; fell through — not on the list
    ///   ret ALLOW
    ///
    /// The arch guard is critical: on x86-64 the x32 ABI reuses `nr` values, so
    /// a filter that skips the arch check can be bypassed. Denied arch is always
    /// KILL, independent of `on_deny`. Caller owns the returned slice.
    pub fn build(gpa: Allocator, allowed: []const linux.SYS, on_deny: Action) BuildError![]SockFilter {
        if (allowed.len > 255) return error.TooManySyscalls;
        try validateAction(on_deny);
        const m: u8 = @intCast(allowed.len);

        var list: std.ArrayList(SockFilter) = .empty;
        errdefer list.deinit(gpa);
        // 3 (arch guard) + 1 (ld nr) + m compares + 2 leaves — known up front.
        try list.ensureTotalCapacityPrecise(gpa, 6 + allowed.len);

        // Arch check.
        try list.append(gpa, bpf.stmt(bpf.ld | bpf.w | bpf.abs, off_arch));
        try list.append(gpa, bpf.jump(bpf.jmp | bpf.jeq | bpf.k, audit_arch, 1, 0));
        try list.append(gpa, bpf.stmt(bpf.ret | bpf.k, ret_kill_process));

        // Load the syscall number.
        try list.append(gpa, bpf.stmt(bpf.ld | bpf.w | bpf.abs, off_nr));

        // One JEQ per allowed nr. For the j-th compare (0-based), the ALLOW leaf
        // sits `m - j` instructions ahead (m-1-j remaining compares + the deny
        // leaf), so jt = m - j, jf = 0 (fall through to the next compare).
        for (allowed, 0..) |sysno, j| {
            const jt: u8 = @intCast(m - @as(u8, @intCast(j)));
            const nr: u32 = @intCast(@intFromEnum(sysno));
            try list.append(gpa, bpf.jump(bpf.jmp | bpf.jeq | bpf.k, nr, jt, 0));
        }

        // Deny leaf (no match), then the ALLOW leaf the matches jump to.
        try list.append(gpa, bpf.stmt(bpf.ret | bpf.k, actionWord(on_deny)));
        try list.append(gpa, bpf.stmt(bpf.ret | bpf.k, ret_allow));

        return list.toOwnedSlice(gpa);
    }

    /// Install a built program with `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`.
    /// Requires `noNewPrivs()` to have run first (or CAP_SYS_ADMIN). Irreversible
    /// and inherited across fork/execve. This form only filters the calling
    /// thread — exactly what a single-threaded startup path wants, but a
    /// no-op for any worker thread already running. See `installTsync` for
    /// the `seccomp(2)` + `TSYNC` form that also covers those.
    pub fn install(prog: []const SockFilter) InstallError!void {
        if (prog.len == 0 or prog.len > std.math.maxInt(u16)) return error.SeccompFailed;
        const fprog = SockFprog{ .len = @intCast(prog.len), .filter = prog.ptr };
        const rc = linux.prctl(
            @intFromEnum(linux.PR.SET_SECCOMP),
            linux.SECCOMP.MODE.FILTER,
            @intFromPtr(&fprog),
            0,
            0,
        );
        if (linux.errno(rc) != .SUCCESS) return error.SeccompFailed;
    }

    pub const TsyncError = error{
        /// `seccomp(2)` failed outright — decoded as a normal negative errno
        /// (bad program, no `PR_SET_NO_NEW_PRIVS`/`CAP_SYS_ADMIN`, kernel
        /// lacks `CONFIG_SECCOMP_FILTER`, and so on).
        SeccompFailed,
        /// `TSYNC` could not synchronize the filter onto every thread of the
        /// process. Per `seccomp(2)`, on *this specific* failure the return
        /// value is not a negated errno at all — it is the positive tid of
        /// the first thread the sync failed for (typically because that
        /// thread hasn't set `no_new_privs` and the process lacks
        /// `CAP_SYS_ADMIN`). `linux.errno()` only decodes values in
        /// `(-4096, 0)` as an error, so a positive tid reads as `.SUCCESS` to
        /// a caller that reuses `install`'s plain error check — that
        /// mis-check is exactly the bug this variant exists to prevent.
        ThreadSyncFailed,
    };

    /// Install `prog` via the `seccomp(2)` syscall (not `prctl`) with
    /// `SECCOMP_FILTER_FLAG_TSYNC`, applying it to every thread of the
    /// calling process — not just the caller — in one atomic step. Use this
    /// instead of `install()` once the process is already multi-threaded by
    /// the time it hardens; `install()`'s prctl form only ever affects the
    /// calling thread, leaving any worker spawned earlier unfiltered. Every
    /// thread still needs `PR_SET_NO_NEW_PRIVS` set (do it before spawning
    /// workers) or `CAP_SYS_ADMIN`, or the sync fails for that thread.
    pub fn installTsync(prog: []const SockFilter) TsyncError!void {
        if (prog.len == 0 or prog.len > std.math.maxInt(u16)) return error.SeccompFailed;
        const fprog = SockFprog{ .len = @intCast(prog.len), .filter = prog.ptr };
        const rc = linux.syscall3(
            .seccomp,
            linux.SECCOMP.SET_MODE_FILTER,
            linux.SECCOMP.FILTER_FLAG.TSYNC,
            @intFromPtr(&fprog),
        );
        if (linux.errno(rc) != .SUCCESS) return error.SeccompFailed;
        // See ThreadSyncFailed: a nonzero-but-not-decoded-as-errno return
        // here is the tid of the first thread whose sync failed, not proof
        // of success.
        if (rc != 0) return error.ThreadSyncFailed;
    }

    /// Candidate syscall names for a generic non-blocking network server's hot
    /// loop. Filtered at comptime by `@hasField` so the list stays valid across
    /// architectures that spell (or omit) some of these differently. This is a
    /// **starting point** — profile your own binary (e.g. `strace -f -c`) and
    /// trim or extend it; too tight bricks the process, too loose defeats the
    /// purpose. Deliberately excludes execve/fork/ptrace/mount/etc.
    const default_names = [_][:0]const u8{
        // core I/O
        "read",            "write",        "readv",           "writev",
        "pread64",         "pwrite64",     "recvfrom",        "sendto",
        "recvmsg",         "sendmsg",      "sendmmsg",        "recvmmsg",
        // socket lifecycle (accept only; server already bound/listened)
        "accept",          "accept4",      "shutdown",        "getsockname",
        "getpeername",     "getsockopt",   "setsockopt",
        // fd lifecycle
             "close",
        "dup",             "dup2",         "dup3",            "fcntl",
        // syscall 262 is spelled `newfstatat` on some arches' tables and
        // `fstatat64` on others (x86-64 in std) — list both so the intent
        // ("stat by path") survives `@hasField`'s silent filter.
        "fstat",           "newfstatat",   "fstatat64",       "statx",
        "lseek",           "pipe2",        "eventfd2",
        // readiness / timers
               "epoll_create1",
        "epoll_ctl",       "epoll_wait",   "epoll_pwait",     "poll",
        "ppoll",           "pselect6",     "timerfd_create",  "timerfd_settime",
        "timerfd_gettime",
        // scheduling / sync
        "futex",        "sched_yield",     "restart_syscall",
        "membarrier",      "nanosleep",    "clock_nanosleep",
        // time / entropy
        "clock_gettime",
        "gettimeofday",    "getrandom",
        // memory
           "mmap",            "munmap",
        "mremap",          "mprotect",     "madvise",         "brk",
        // signals
        "rt_sigreturn",    "rt_sigaction", "rt_sigprocmask",  "sigaltstack",
        // process identity / exit
        "getpid",          "gettid",       "getuid",          "getgid",
        "geteuid",         "getegid",      "exit",            "exit_group",
        "tgkill",
        // Audit S11: calls a libc or language runtime makes on its own, which
        // killed a process under this list. Each checked for grant: none
        // reaches beyond the process's own state or an fd it already holds.
        "rseq", // registers the calling thread's restartable-sequence area
        "set_robust_list", // the calling thread's robust-futex list head
        "getdents64", // reads a directory fd already held; opens nothing
        "epoll_pwait2", // epoll_pwait with a timespec timeout
        "clock_getres",
        "sched_getaffinity", // read-only
        "getrusage", // self/children/thread usage, read-only
        "uname", // discloses the kernel release; grants nothing
        "sysinfo", // discloses RAM/uptime/load; grants nothing
        "close_range", // closes (or marks CLOEXEC) the caller's own fds
        "faccessat2", // path probe; `newfstatat`/`statx` above already reveal as much
        "rt_sigtimedwait", // waits for the caller's own pending signals
        // Deliberately NOT added although the audit listed them: `prlimit64`
        // sets limits of OTHER same-uid processes too, and both it and
        // `setrlimit` let sandboxed code raise a soft limit this module's
        // `limit*` helpers lowered before the filter went on. That is a new
        // grant; a binary that needs getrlimit adds `prlimit64` itself.
    };

    /// The default network-server allow-list, resolved to concrete `linux.SYS`
    /// values for the target arch at comptime (names the arch lacks are dropped).
    pub const default_allowlist: []const linux.SYS = blk: {
        var arr: [default_names.len]linux.SYS = undefined;
        var n: usize = 0;
        for (default_names) |name| {
            if (@hasField(linux.SYS, name)) {
                arr[n] = @field(linux.SYS, name);
                n += 1;
            }
        }
        const final = arr[0..n].*;
        break :blk &final;
    };

    /// Build the default allow-list program. Caller owns + frees the slice.
    pub fn buildDefault(gpa: Allocator, on_deny: Action) BuildError![]SockFilter {
        return build(gpa, default_allowlist, on_deny);
    }

    // ── W^X preset (argument-filtered mmap/mprotect/pkey_mprotect) ──────────

    /// `PROT_WRITE` / `PROT_EXEC` (UAPI `mman-common.h`). Identical bit values
    /// on every Linux arch — like the `prctl`/`seccomp` constants already
    /// hardcoded in this file, these are clean-room from the merger-doctrine
    /// UAPI, not std's per-arch `linux.PROT` packed-struct shape (whose field
    /// order isn't a stable ABI contract to lean on inside a BPF program).
    const prot_write: u32 = 0x2;
    const prot_exec: u32 = 0x4;
    const prot_write_exec: u32 = prot_write | prot_exec;

    /// A syscall the W^X preset gives an extra check to: mmap/mprotect/
    /// pkey_mprotect all share the shape `(ptr, len, int prot, ...)`, so
    /// their protection flags sit at `arg2` on every arch.
    const WxRule = struct { sysno: linux.SYS, mask: u32 };

    /// Instructions per W^X block (the 9-instruction shape `buildWx` emits).
    pub const wx_block_len: usize = 9;

    const wx_names = [_][:0]const u8{ "mmap", "mprotect", "pkey_mprotect" };

    /// W^X-guarded syscalls present on this arch's `linux.SYS`
    /// (`pkey_mprotect`, Linux 4.9+, isn't modelled for every arch), built the
    /// same comptime-filtered way as `default_allowlist`.
    const wx_arg_rules: []const WxRule = blk: {
        var arr: [wx_names.len]WxRule = undefined;
        var n: usize = 0;
        for (wx_names) |name| {
            if (@hasField(linux.SYS, name)) {
                arr[n] = .{ .sysno = @field(linux.SYS, name), .mask = prot_write_exec };
                n += 1;
            }
        }
        const final = arr[0..n].*;
        break :blk &final;
    };

    fn containsSyscall(list: []const linux.SYS, needle: linux.SYS) bool {
        for (list) |s| if (s == needle) return true;
        return false;
    }

    /// Build an allow-list program identical in shape to `build`, except that
    /// any of `{mmap, mprotect, pkey_mprotect}` present in `allowed` gets an
    /// extra, self-contained argument check on its `prot` (`arg2`) *before*
    /// the plain nr dispatch below ever sees it: if `PROT_WRITE` and
    /// `PROT_EXEC` are BOTH set, the call is denied via `wx_action` —
    /// independent of `on_deny`, the same way an arch mismatch is always
    /// `KILL_PROCESS` regardless of the caller's chosen deny action, because
    /// W^X is a hard invariant here, not a soft "missed the allow-list" case.
    /// A syscall not in `allowed` at all gets no special treatment — it falls
    /// through to the plain deny leaf like any other unlisted nr, exactly as
    /// in `build`.
    ///
    /// Two correctness points that are easy to get wrong in a BPF W^X filter:
    ///  - The check is a **bitmask test**, not an equality: `prot ==
    ///    (WRITE|EXEC)` would miss `READ|WRITE|EXEC`. `(prot & (WRITE|EXEC))
    ///    == (WRITE|EXEC)` catches the combination regardless of what other
    ///    bits ride along (implemented as an ALU `AND` then a `JEQ`).
    ///  - `prot` is a 64-bit seccomp argument register but classic BPF only
    ///    compares 32-bit words, so both halves are checked: the low 32 bits
    ///    against the mask, and the high 32 bits against zero. PROT_* flags
    ///    fit in the low word, but a raw syscall (bypassing libc's normal
    ///    int-argument zero-extension) can put anything in the high half of
    ///    the register the kernel reads as `prot`; a filter that inspects
    ///    only the low word is checking a different, attacker-controlled
    ///    64-bit value than the one it thinks it is. A non-zero high word is
    ///    treated as a violation here (fail closed), never silently ignored.
    pub fn buildWx(gpa: Allocator, allowed: []const linux.SYS, on_deny: Action, wx_action: Action) BuildError![]SockFilter {
        if (allowed.len > 255) return error.TooManySyscalls;
        try validateAction(on_deny);
        try validateAction(wx_action);
        const m: u8 = @intCast(allowed.len);

        var list: std.ArrayList(SockFilter) = .empty;
        errdefer list.deinit(gpa);
        var wx_blocks: usize = 0;
        for (wx_arg_rules) |rule| {
            if (containsSyscall(allowed, rule.sysno)) wx_blocks += 1;
        }
        try list.ensureTotalCapacityPrecise(gpa, 6 + allowed.len + wx_block_len * wx_blocks);

        // Arch check (identical to `build`).
        try list.append(gpa, bpf.stmt(bpf.ld | bpf.w | bpf.abs, off_arch));
        try list.append(gpa, bpf.jump(bpf.jmp | bpf.jeq | bpf.k, audit_arch, 1, 0));
        try list.append(gpa, bpf.stmt(bpf.ret | bpf.k, ret_kill_process));

        // One self-contained 9-instruction block per W^X-guarded syscall
        // that is actually in `allowed`. Every jump inside a block is a
        // LOCAL offset (0, 1, 3 or 7 instructions ahead), so blocks compose
        // without knowing the total program length or each other's
        // position — unlike the plain nr chain below, which needs the
        // overall count to compute descending jt offsets.
        //
        //   ld  nr
        //   jeq this_sysno  jt=0 jf=7   ; no match -> skip the whole block
        //   ld  arg2_hi
        //   jeq 0           jt=0 jf=3   ; hi != 0 -> violation, deny
        //   ld  arg2_lo
        //   and mask
        //   jeq mask        jt=0 jf=1   ; masked bits all set -> violation
        //   ret wx_action                ; violation leaf
        //   ret ALLOW                    ; clean leaf
        for (wx_arg_rules) |rule| {
            if (!containsSyscall(allowed, rule.sysno)) continue;
            const nr: u32 = @intCast(@intFromEnum(rule.sysno));

            try list.append(gpa, bpf.stmt(bpf.ld | bpf.w | bpf.abs, off_nr));
            try list.append(gpa, bpf.jump(bpf.jmp | bpf.jeq | bpf.k, nr, 0, 7));
            try list.append(gpa, bpf.stmt(bpf.ld | bpf.w | bpf.abs, arg2.hi));
            try list.append(gpa, bpf.jump(bpf.jmp | bpf.jeq | bpf.k, 0, 0, 3));
            try list.append(gpa, bpf.stmt(bpf.ld | bpf.w | bpf.abs, arg2.lo));
            try list.append(gpa, bpf.stmt(bpf.alu | bpf.and_ | bpf.k, rule.mask));
            try list.append(gpa, bpf.jump(bpf.jmp | bpf.jeq | bpf.k, rule.mask, 0, 1));
            try list.append(gpa, bpf.stmt(bpf.ret | bpf.k, actionWord(wx_action)));
            try list.append(gpa, bpf.stmt(bpf.ret | bpf.k, ret_allow));
        }

        // Plain nr dispatch — identical to `build`. A wx-guarded syscall
        // whose block above matched already RET'd and never reaches here; a
        // non-wx-guarded syscall, or one whose block was skipped because its
        // nr didn't match, is handled exactly as in the non-wx `build`.
        try list.append(gpa, bpf.stmt(bpf.ld | bpf.w | bpf.abs, off_nr));
        for (allowed, 0..) |sysno, j| {
            const jt: u8 = @intCast(m - @as(u8, @intCast(j)));
            const nr: u32 = @intCast(@intFromEnum(sysno));
            try list.append(gpa, bpf.jump(bpf.jmp | bpf.jeq | bpf.k, nr, jt, 0));
        }
        try list.append(gpa, bpf.stmt(bpf.ret | bpf.k, actionWord(on_deny)));
        try list.append(gpa, bpf.stmt(bpf.ret | bpf.k, ret_allow));

        return list.toOwnedSlice(gpa);
    }

    /// `buildWx` over `default_allowlist` — the network-server preset with a
    /// W^X guard on mmap/mprotect/pkey_mprotect layered in.
    pub fn buildDefaultWx(gpa: Allocator, on_deny: Action, wx_action: Action) BuildError![]SockFilter {
        return buildWx(gpa, default_allowlist, on_deny, wx_action);
    }
};

// ────────────────────────────────────────────────────────────────────────────
// Tests
//
// Pure/logic tests run everywhere. The "real" enforcement tests fork a child,
// apply a restriction, and assert the child dies / EPERMs exactly as configured
// while a control child without the restriction succeeds — the only honest way
// to verify a security boundary. seccomp + landlock + rlimit tests need no
// privileges (any process may set no-new-privs / install a seccomp filter /
// lower an rlimit / build a landlock ruleset), so they run in a normal `zig
// build test`. Privilege-drop + capability tests need to *start* as root and
// skip cleanly otherwise (like the repo's other root-gated tests).
// ────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Result of running a function in a forked child.
const ChildResult = struct {
    status: u32,
    fn exitedWith(self: ChildResult, code: u8) bool {
        return linux.W.IFEXITED(self.status) and linux.W.EXITSTATUS(self.status) == code;
    }
    fn killedBy(self: ChildResult, sig: linux.SIG) bool {
        return linux.W.IFSIGNALED(self.status) and linux.W.TERMSIG(self.status) == sig;
    }
};

/// Fork, run `child` (which must end by calling `linux.exit`), wait, and report
/// how it terminated. `child` runs in a COW copy of our address space, so any
/// program bytes / paths we built before the fork are readable inside it.
fn runInChild(child: *const fn () void) !ChildResult {
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.ForkFailed;
    const pid: i32 = @intCast(@as(isize, @bitCast(rc)));
    if (pid == 0) {
        child();
        linux.exit(0); // child forgot to exit — treat as "did not enforce"
    }
    var status: u32 = 0;
    // A failed waitpid must not leave `status = 0` — which `exitedWith(0)`
    // would read as the child having PASSED.
    while (true) {
        const wrc = linux.waitpid(pid, &status, 0);
        switch (linux.errno(wrc)) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    return .{ .status = status };
}

// ── pure/logic ─────────────────────────────────────────────────────────────

test "struct sizes match the kernel ABI" {
    try testing.expectEqual(@as(usize, 8), @sizeOf(SockFilter)); // sock_filter
    try testing.expectEqual(@as(usize, 12), @sizeOf(PathBeneathAttr)); // packed: u64+s32
    try testing.expectEqual(@as(usize, 8), @sizeOf(RulesetAttr));
    // seccomp_data: nr at 0, arch at 4.
    try testing.expectEqual(@as(usize, 0), seccomp.off_nr);
    try testing.expectEqual(@as(usize, 4), seccomp.off_arch);
}

test "seccomp.build emits arch-guard + one compare per syscall + allow/deny leaves" {
    const allowed = [_]linux.SYS{ .read, .write, .exit_group };
    const prog = try seccomp.build(testing.allocator, &allowed, .{ .errno = @intFromEnum(E.PERM) });
    defer testing.allocator.free(prog);

    // 3 (arch guard) + 1 (ld nr) + 3 (compares) + 2 (deny, allow) = 9.
    try testing.expectEqual(@as(usize, 9), prog.len);

    // Arch guard — including the jump TARGETS: `jf: 0 -> 1` keeps the
    // opcode and `k` intact yet makes the KILL leaf unreachable (audit S2, a
    // mutation this test used to survive; the escape it enables is the
    // `int $0x80` test below).
    try testing.expectEqual(@as(u16, bpf.ld | bpf.w | bpf.abs), prog[0].code);
    try testing.expectEqual(@as(u32, seccomp.off_arch), prog[0].k);
    try testing.expectEqual(@as(u16, bpf.jmp | bpf.jeq | bpf.k), prog[1].code);
    try testing.expectEqual(audit_arch, prog[1].k);
    try testing.expectEqual(@as(u8, 1), prog[1].jt);
    try testing.expectEqual(@as(u8, 0), prog[1].jf);
    try testing.expectEqual(@as(u16, bpf.ret | bpf.k), prog[2].code);
    try testing.expectEqual(@as(u32, seccomp.ret_kill_process), prog[2].k);

    // ld nr.
    try testing.expectEqual(@as(u32, seccomp.off_nr), prog[3].k);

    // Three compares with descending jt (m, m-1, …, 1) so each reaches ALLOW.
    try testing.expectEqual(@as(u8, 3), prog[4].jt);
    try testing.expectEqual(@as(u32, @intCast(@intFromEnum(linux.SYS.read))), prog[4].k);
    try testing.expectEqual(@as(u8, 2), prog[5].jt);
    try testing.expectEqual(@as(u8, 1), prog[6].jt);

    // Leaves: deny (ERRNO|EPERM) then ALLOW.
    try testing.expectEqual(seccomp.ret_errno | @as(u32, @intFromEnum(E.PERM)), prog[7].k);
    try testing.expectEqual(@as(u32, seccomp.ret_allow), prog[8].k);
}

test "seccomp default allow-list is non-empty and reasonable" {
    try testing.expect(seccomp.default_allowlist.len >= 30);
    const prog = try seccomp.buildDefault(testing.allocator, .kill_process);
    defer testing.allocator.free(prog);
    try testing.expectEqual(seccomp.default_allowlist.len + 6, prog.len);
}

test "seccomp default allow-list: named CONTENT, and no silent drop by @hasField (audit S8)" {
    // The only tests on this list used to be its length; 38 of 68 names could
    // be deleted with the suite green, and `newfstatat` — spelled `fstatat64`
    // in std's x86-64 table — was silently filtered out, so C code's stat(2)
    // died of SIGSYS under a list whose author had allowed it.
    const must_have = [_]linux.SYS{ .read, .write, .close, .epoll_wait, .accept4, .futex, .mmap, .exit_group, .rt_sigreturn, .getrandom } ++ s11_added;
    for (must_have) |s| try testing.expect(seccomp.containsSyscall(seccomp.default_allowlist, s));
    // `prlimit64`/`setrlimit`: audit S11 listed them, and they stay out on
    // purpose (see `default_names`).
    const must_not = [_]linux.SYS{ .execve, .fork, .clone, .ptrace, .mount, .openat, .socket, .connect, .ioctl, .prctl, .seccomp, .setuid, .prlimit64, .setrlimit };
    for (must_not) |s| try testing.expect(!seccomp.containsSyscall(seccomp.default_allowlist, s));
    if (builtin.cpu.arch == .x86_64) {
        // stat-by-path (262) is present under std's spelling …
        try testing.expect(seccomp.containsSyscall(seccomp.default_allowlist, .fstatat64));
        // … and `newfstatat` is the ONLY name the arch filter drops here.
        try testing.expectEqual(seccomp.default_names.len - 1, seccomp.default_allowlist.len);
    }
}

test "seccomp.build/buildWx refuse an errno of 0 or above 4095 (audit S9)" {
    // `.errno = 0` made a DENIED syscall return 0 — success — to the caller
    // (the audit's probe with it looped at 100 % CPU on a std print path that
    // kept retrying a "successful" refused write). Above 4095 the kernel
    // clamps, so 65535 meant -4095, not EINVAL.
    const allowed = [_]linux.SYS{ .exit_group, .getpid };
    try testing.expectError(error.InvalidErrno, seccomp.build(testing.allocator, &allowed, .{ .errno = 0 }));
    try testing.expectError(error.InvalidErrno, seccomp.build(testing.allocator, &allowed, .{ .errno = 4096 }));
    try testing.expectError(error.InvalidErrno, seccomp.build(testing.allocator, &allowed, .{ .errno = 65535 }));
    try testing.expectError(error.InvalidErrno, seccomp.buildWx(testing.allocator, &allowed, .kill_process, .{ .errno = 0 }));
    try testing.expectError(error.InvalidErrno, seccomp.buildWx(testing.allocator, &allowed, .{ .errno = 0 }, .kill_process));
    const ok1 = try seccomp.build(testing.allocator, &allowed, .{ .errno = 1 });
    testing.allocator.free(ok1);
    const ok2 = try seccomp.build(testing.allocator, &allowed, .{ .errno = seccomp.max_errno });
    testing.allocator.free(ok2);
}

test "seccomp.build/buildWx refuse more than 255 allowed syscalls (audit S19)" {
    // A single JEQ's jump offset (`jt`) is a `u8`, so 256 compares cannot be
    // encoded in the flat allow/deny shape `build` emits — `TooManySyscalls`
    // exists for exactly this. No test constructed the boundary before.
    // `linux.SYS` has far fewer than 256 distinct members below one screen's
    // worth of the enum, so the same syscall repeated is fine here — `build`
    // only ever reads `allowed.len`.
    var many: [256]linux.SYS = @splat(.getpid);
    try testing.expectError(error.TooManySyscalls, seccomp.build(testing.allocator, &many, .kill_process));
    try testing.expectError(error.TooManySyscalls, seccomp.buildWx(testing.allocator, &many, .kill_process, .kill_process));

    // Positive control: exactly 255 is the documented limit, not off by one.
    const ok = try seccomp.build(testing.allocator, many[0..255], .kill_process);
    testing.allocator.free(ok);
    const okwx = try seccomp.buildWx(testing.allocator, many[0..255], .kill_process, .kill_process);
    testing.allocator.free(okwx);
}

test "seccomp.buildWx structure: arch guard with its jump targets, one 9-instruction block per guarded syscall, then the plain chain (audit S3)" {
    // `buildWx` had no structural test at all — its arch guard could be
    // deleted outright (91 -> 88 instructions) or weakened (`jf` 0 -> 1) with
    // the suite green, and either let the i386 `int $0x80` alias through.
    const allowed = [_]linux.SYS{ .exit, .exit_group, .mmap, .mprotect, .read };
    const prog = try seccomp.buildWx(testing.allocator, &allowed, .{ .errno = @intFromEnum(E.PERM) }, .kill_process);
    defer testing.allocator.free(prog);

    // 3 (arch) + 2 blocks x 9 + 1 (ld nr) + 5 compares + 2 leaves.
    var guarded: usize = 0;
    for (allowed) |s| {
        if (s == .mmap or s == .mprotect) guarded += 1;
    }
    try testing.expectEqual(@as(usize, 2), guarded);
    try testing.expectEqual(6 + allowed.len + seccomp.wx_block_len * guarded, prog.len);

    // Arch guard, identical to `build` — targets included.
    try testing.expectEqual(@as(u16, bpf.ld | bpf.w | bpf.abs), prog[0].code);
    try testing.expectEqual(@as(u32, seccomp.off_arch), prog[0].k);
    try testing.expectEqual(@as(u16, bpf.jmp | bpf.jeq | bpf.k), prog[1].code);
    try testing.expectEqual(audit_arch, prog[1].k);
    try testing.expectEqual(@as(u8, 1), prog[1].jt);
    try testing.expectEqual(@as(u8, 0), prog[1].jf);
    try testing.expectEqual(@as(u16, bpf.ret | bpf.k), prog[2].code);
    try testing.expectEqual(@as(u32, seccomp.ret_kill_process), prog[2].k);

    // Each block: ld nr / jeq nr (0,7) / ld hi / jeq 0 (0,3) / ld lo / and mask / jeq mask (0,1) / ret wx / ret ALLOW.
    var pos: usize = 3;
    var seen_mmap = false;
    var seen_mprotect = false;
    while (pos < 3 + seccomp.wx_block_len * guarded) : (pos += seccomp.wx_block_len) {
        const b = prog[pos..][0..seccomp.wx_block_len];
        try testing.expectEqual(@as(u16, bpf.ld | bpf.w | bpf.abs), b[0].code);
        try testing.expectEqual(@as(u32, seccomp.off_nr), b[0].k);
        try testing.expectEqual(@as(u16, bpf.jmp | bpf.jeq | bpf.k), b[1].code);
        if (b[1].k == @as(u32, @intCast(@intFromEnum(linux.SYS.mmap)))) seen_mmap = true;
        if (b[1].k == @as(u32, @intCast(@intFromEnum(linux.SYS.mprotect)))) seen_mprotect = true;
        try testing.expectEqual(@as(u8, 0), b[1].jt);
        try testing.expectEqual(@as(u8, 7), b[1].jf);
        try testing.expectEqual(@as(u32, seccomp.arg2.hi), b[2].k);
        try testing.expectEqual(@as(u32, 0), b[3].k);
        try testing.expectEqual(@as(u8, 3), b[3].jf);
        try testing.expectEqual(@as(u32, seccomp.arg2.lo), b[4].k);
        try testing.expectEqual(@as(u16, bpf.alu | bpf.and_ | bpf.k), b[5].code);
        try testing.expectEqual(seccomp.prot_write_exec, b[5].k);
        try testing.expectEqual(seccomp.prot_write_exec, b[6].k);
        try testing.expectEqual(@as(u8, 1), b[6].jf);
        try testing.expectEqual(@as(u32, seccomp.ret_kill_process), b[7].k); // wx_action
        try testing.expectEqual(@as(u32, seccomp.ret_allow), b[8].k);
    }
    try testing.expect(seen_mmap and seen_mprotect);

    // Plain chain: ld nr, descending jt, deny leaf (ERRNO|EPERM), ALLOW leaf.
    try testing.expectEqual(@as(u32, seccomp.off_nr), prog[pos].k);
    try testing.expectEqual(@as(u8, 5), prog[pos + 1].jt);
    try testing.expectEqual(@as(u8, 1), prog[pos + 5].jt);
    try testing.expectEqual(seccomp.ret_errno | @as(u32, @intFromEnum(E.PERM)), prog[pos + 6].k);
    try testing.expectEqual(@as(u32, seccomp.ret_allow), prog[pos + 7].k);
}

test "landlock access mask grows monotonically with ABI" {
    const m1 = Ruleset.accessMaskForAbi(1);
    const m3 = Ruleset.accessMaskForAbi(3);
    const m5 = Ruleset.accessMaskForAbi(5);
    try testing.expect(m1 & Ruleset.access.truncate == 0); // ABI 1 has no TRUNCATE
    try testing.expect(m3 & Ruleset.access.truncate != 0); // ABI 3 does
    try testing.expect(m5 & Ruleset.access.ioctl_dev != 0); // ABI 5 adds IOCTL_DEV
    try testing.expect(m1 == m1 & m3 and m3 == m3 & m5); // strictly grows
}

// ── real: seccomp (fork children) ────────────────────────────────────────────

// A minimal set that lets a child install a filter and then exit cleanly, but
// deliberately OMITS getpid — the syscall we probe. exit_group must be present
// or the child cannot even terminate.
const seccomp_min_no_getpid = [_]linux.SYS{ .exit, .exit_group, .write };
// The control set: identical but WITH getpid, so the probe is allowed.
const seccomp_min_with_getpid = [_]linux.SYS{ .exit, .exit_group, .write, .getpid };

// Program slices are built once in the parent (see build funcs) and read by the
// child through COW memory; test bodies stash them in these file-scope vars so
// the bare `fn () void` child callbacks can reach them.
var g_kill_prog: []const SockFilter = &.{};
var g_errno_prog: []const SockFilter = &.{};
var g_allow_prog: []const SockFilter = &.{};

fn childSeccompKill() void {
    noNewPrivs() catch linux.exit(101);
    seccomp.install(g_kill_prog) catch linux.exit(102);
    _ = linux.getpid(); // not on the list → SIGSYS kills the process
    linux.exit(0); // unreachable if the filter works
}

fn childSeccompErrno() void {
    noNewPrivs() catch linux.exit(101);
    seccomp.install(g_errno_prog) catch linux.exit(102);
    const rc = linux.syscall0(.getpid); // raw: observe the raw -errno return
    const e = linux.errno(rc);
    linux.exit(if (e == .PERM) 0 else 42); // ERRNO action → EPERM
}

fn childSeccompControl() void {
    noNewPrivs() catch linux.exit(101);
    seccomp.install(g_allow_prog) catch linux.exit(102);
    _ = linux.getpid(); // allowed → runs fine
    linux.exit(7);
}

// Audit S5: a skip must be decided BEFORE the code under test runs, from a
// probe of the kernel ("the mechanism is not here"), never from that code's
// own failure exit. The earlier `if (res.exitedWith(102)) return
// error.SkipZigTest` turned a broken `install` (or a no-op `noNewPrivs`) into
// a green suite: a mutation that disabled Landlock entirely left "15 pass /
// 3 skip", exit 0.
fn requireSeccompFilter() !void {
    if (!seccomp.available()) return error.SkipZigTest; // no CONFIG_SECCOMP_FILTER / seccomp(2)
}

test "seccomp.available agrees with a real install attempt" {
    // If the probe says filters exist, installing one in a child must not
    // fail; the two must never disagree, or every skip decision is wrong.
    try requireSeccompFilter();
    g_allow_prog = try seccomp.build(testing.allocator, &seccomp_min_with_getpid, .kill_process);
    defer testing.allocator.free(g_allow_prog);
    const control = try runInChild(childSeccompControl);
    try testing.expect(control.exitedWith(7));
}

test "seccomp KILL_PROCESS: denied syscall kills the child; control survives" {
    try requireSeccompFilter();
    g_kill_prog = try seccomp.build(testing.allocator, &seccomp_min_no_getpid, .kill_process);
    defer testing.allocator.free(g_kill_prog);
    g_allow_prog = try seccomp.build(testing.allocator, &seccomp_min_with_getpid, .kill_process);
    defer testing.allocator.free(g_allow_prog);

    const killed = try runInChild(childSeccompKill);
    try testing.expect(!killed.exitedWith(101)); // noNewPrivs failed — the module, not the kernel
    try testing.expect(!killed.exitedWith(102)); // install failed although `available()` said yes
    try testing.expect(killed.killedBy(.SYS)); // SIGSYS

    const control = try runInChild(childSeccompControl);
    try testing.expect(control.exitedWith(7));
}

/// Audit S11: the syscalls added to `default_names`.
const s11_added = [_]linux.SYS{
    .rseq,      .set_robust_list, .getdents64, .epoll_pwait2, .clock_getres, .sched_getaffinity,
    .getrusage, .uname,           .sysinfo,    .close_range,  .faccessat2,   .rt_sigtimedwait,
};

var g_default_prog: []const SockFilter = &.{};

/// Every S11 syscall under the default filter, with arguments that make it
/// fail harmlessly (a bad fd, a null pointer, an empty range). The result is
/// ignored: only reaching `exit(0)` instead of SIGSYS matters.
fn childDefaultAllowsS11() void {
    noNewPrivs() catch linux.exit(101);
    seccomp.install(g_default_prog) catch linux.exit(102);
    const bad_fd: usize = @bitCast(@as(isize, -1));
    _ = linux.syscall4(.rseq, 0, 0, 0, 0);
    _ = linux.syscall2(.set_robust_list, 0, 0);
    _ = linux.syscall3(.getdents64, bad_fd, 0, 0);
    _ = linux.syscall6(.epoll_pwait2, bad_fd, 0, 0, 0, 0, 0);
    _ = linux.syscall2(.clock_getres, 0, 0);
    _ = linux.syscall3(.sched_getaffinity, 0, 0, 0);
    _ = linux.syscall2(.getrusage, 0, 0);
    _ = linux.syscall1(.uname, 0);
    _ = linux.syscall1(.sysinfo, 0);
    _ = linux.syscall3(.close_range, 0xFFFF_FF00, 0xFFFF_FFFF, 0);
    _ = linux.syscall4(.faccessat2, bad_fd, 0, 0, 0);
    _ = linux.syscall4(.rt_sigtimedwait, 0, 0, 0, 8);
    linux.exit(0);
}

fn childDefaultPrlimit() void {
    noNewPrivs() catch linux.exit(101);
    seccomp.install(g_default_prog) catch linux.exit(102);
    _ = linux.syscall4(.prlimit64, 0, 7, 0, 0); // read-only query, still refused
    linux.exit(0);
}

fn childDefaultSetrlimit() void {
    noNewPrivs() catch linux.exit(101);
    seccomp.install(g_default_prog) catch linux.exit(102);
    _ = linux.syscall2(.setrlimit, 7, 0);
    linux.exit(0);
}

test "seccomp default allow-list, installed: the S11 runtime syscalls run, prlimit64/setrlimit are killed (audit S11)" {
    try requireSeccompFilter();
    g_default_prog = try seccomp.buildDefault(testing.allocator, .kill_process);
    defer testing.allocator.free(g_default_prog);

    const allowed = try runInChild(childDefaultAllowsS11);
    try testing.expect(allowed.exitedWith(0));

    // The same program kills a call it does not list, so the pass above is
    // not a filter that allows everything.
    for ([_]*const fn () void{ childDefaultPrlimit, childDefaultSetrlimit }) |child| {
        const killed = try runInChild(child);
        try testing.expect(!killed.exitedWith(101));
        try testing.expect(!killed.exitedWith(102));
        try testing.expect(killed.killedBy(.SYS));
    }
}

test "seccomp ERRNO: denied syscall returns -EPERM instead of dying" {
    try requireSeccompFilter();
    g_errno_prog = try seccomp.build(testing.allocator, &seccomp_min_no_getpid, .{ .errno = @intFromEnum(E.PERM) });
    defer testing.allocator.free(g_errno_prog);

    const res = try runInChild(childSeccompErrno);
    try testing.expect(res.exitedWith(0)); // getpid saw EPERM, not a signal (101/102/42 are all failures)
}

// ── real: the arch guard's actual job — the i386 `int $0x80` entry (x86-64) ──
//
// On x86-64 the 32-bit compat entry reports `AUDIT_ARCH_I386`, where the same
// number means a different syscall: nr 39 is `getpid` on x86-64 and `mkdir`
// on i386. A filter allowing only `getpid` therefore lets a process create
// directories — unless the arch guard KILLs first. The A1 audit showed both
// `build` and `buildWx` losing this to a `jf: 0 -> 1` mutation with the
// suite green; these children pin the guard by the escape it prevents.
const X86Alias = if (builtin.cpu.arch == .x86_64) struct {
    const low_page: usize = 0x10_0000; // below 4 GiB: reachable from a 32-bit ebx
    const i386_nr_getpid: usize = 20;
    const i386_nr_mkdir: usize = 39; // == x86-64 getpid, allow-listed below
    const dir_name = "zig_sandbox_i386_alias_dir\x00";

    fn int80(nr: usize, a1: usize, a2: usize) usize {
        return asm volatile ("int $0x80"
            : [ret] "={eax}" (-> usize),
            : [nr] "{eax}" (nr),
              [a1] "{ebx}" (a1),
              [a2] "{ecx}" (a2),
            : .{ .memory = true });
    }

    /// Control: does this kernel even take `int $0x80` (CONFIG_IA32_EMULATION)?
    fn childProbeEmulation() void {
        const rc = int80(i386_nr_getpid, 0, 0);
        // A pid is positive and small; ENOSYS/SIGSEGV paths never get here with one.
        linux.exit(if (@as(isize, @bitCast(rc)) > 0) 0 else 3);
    }

    /// Map a low page holding the directory name (the compat entry sees only
    /// 32-bit pointers), install `prog`, then try to mkdir through the i386
    /// alias of an allow-listed x86-64 number. With the guard: SIGSYS. Without:
    /// the directory appears and the child exits 0.
    fn childAliasEscape(prog: []const SockFilter) void {
        const m = linux.mmap(@ptrFromInt(low_page), 4096, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED = true }, -1, 0);
        if (linux.errno(m) != .SUCCESS) linux.exit(110);
        const path: [*]u8 = @ptrFromInt(low_page);
        @memcpy(path[0..dir_name.len], dir_name);
        noNewPrivs() catch linux.exit(101);
        seccomp.install(prog) catch linux.exit(102);
        _ = int80(i386_nr_mkdir, low_page, 0o700); // guard present: never returns
        linux.exit(0);
    }
    fn childBuild() void {
        childAliasEscape(g_alias_prog);
    }
    fn childWx() void {
        childAliasEscape(g_alias_wx_prog);
    }
} else struct {};

var g_alias_prog: []const SockFilter = &.{};
var g_alias_wx_prog: []const SockFilter = &.{};

fn expectAliasKilled(res: ChildResult) !void {
    // Clean up first so a RED run does not leave the directory behind.
    const created = linux.errno(linux.rmdir("zig_sandbox_i386_alias_dir")) == .SUCCESS;
    try testing.expect(!created); // a directory means the alias went THROUGH the filter
    try testing.expect(!res.exitedWith(101) and !res.exitedWith(102) and !res.exitedWith(110));
    try testing.expect(res.killedBy(.SYS));
}

test "seccomp arch guard (build): the i386 int $0x80 alias of an allowed number is KILLED, not executed (audit S2)" {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            try requireSeccompFilter();
            const probe = try runInChild(X86Alias.childProbeEmulation);
            if (!probe.exitedWith(0)) return error.SkipZigTest; // no CONFIG_IA32_EMULATION here
            g_alias_prog = try seccomp.build(testing.allocator, &seccomp_min_with_getpid, .kill_process);
            defer testing.allocator.free(g_alias_prog);
            try expectAliasKilled(try runInChild(X86Alias.childBuild));
        },
        else => return error.SkipZigTest,
    }
}

test "seccomp arch guard (buildWx): the same i386 alias is KILLED through the W^X-shaped program too (audit S3)" {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            try requireSeccompFilter();
            const probe = try runInChild(X86Alias.childProbeEmulation);
            if (!probe.exitedWith(0)) return error.SkipZigTest;
            // nr 39 must not collide with a W^X block (an i386 nr aliasing
            // mmap/mprotect would be killed by the block's hi-word check, not
            // by the arch guard — the audit's first probe measured exactly
            // that false CAUGHT), so the allow-list has getpid AND the guarded
            // pair.
            const allowed = [_]linux.SYS{ .exit, .exit_group, .write, .getpid, .mmap, .mprotect };
            g_alias_wx_prog = try seccomp.buildWx(testing.allocator, &allowed, .kill_process, .{ .errno = @intFromEnum(E.PERM) });
            defer testing.allocator.free(g_alias_wx_prog);
            try expectAliasKilled(try runInChild(X86Alias.childWx));
        },
        else => return error.SkipZigTest,
    }
}

// ── real: seccomp W^X preset (fork children) ─────────────────────────────────

var g_wx_prog: []const SockFilter = &.{};

fn childWx() void {
    // A valid RW page, mapped BEFORE the filter goes on, reused by every
    // check below (mmap is itself W^X-guarded too, but PROT_READ|PROT_WRITE
    // never trips the guard).
    const len: usize = 4096;
    const map_rc = linux.mmap(null, len, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
    if (linux.errno(map_rc) != .SUCCESS) linux.exit(110);
    const addr: [*]u8 = @ptrFromInt(map_rc);

    noNewPrivs() catch linux.exit(101);
    seccomp.install(g_wx_prog) catch linux.exit(102);

    // 1. Safe combo (no EXEC) must still work.
    if (linux.errno(linux.mprotect(addr, len, .{ .READ = true, .WRITE = true })) != .SUCCESS) linux.exit(30);

    // 2. The actual W^X violation must be denied by our guard: EPERM (our
    //    configured wx_action), not a SIGSYS/crash — so it's distinguishable
    //    from the process just dying for some unrelated reason.
    const bad_rc = linux.mprotect(addr, len, .{ .READ = true, .WRITE = true, .EXEC = true });
    if (linux.errno(bad_rc) != .PERM) linux.exit(31);

    // 3. A crafted prot register whose LOW 32 bits alone are just PROT_READ
    //    (would sail past a naive low-word-only AND-mask check) but whose
    //    HIGH 32 bits are non-zero must ALSO be denied by our filter, not
    //    reach the real kernel mprotect (which would answer EINVAL for an
    //    unrecognized prot value, not our EPERM) — proves the hi-word
    //    compare is load-bearing, not decorative.
    const crafted: usize = (@as(usize, 1) << 32) | @as(usize, 1); // hi=1, lo=PROT_READ
    const crafted_rc = linux.syscall3(.mprotect, @intFromPtr(addr), len, crafted);
    if (linux.errno(crafted_rc) != .PERM) linux.exit(32);

    // 4. mmap's own guard: requesting an executable+writable mapping
    //    directly must also be denied (both mmap and mprotect share it).
    const bad_mmap_rc = linux.mmap(null, len, .{ .READ = true, .WRITE = true, .EXEC = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
    if (linux.errno(bad_mmap_rc) != .PERM) linux.exit(33);

    linux.exit(0);
}

test "seccomp W^X guard: RW mprotect/mmap allowed, RWX and crafted hi-word denied" {
    try requireSeccompFilter();
    const allowed = [_]linux.SYS{ .exit, .exit_group, .mmap, .mprotect };
    g_wx_prog = try seccomp.buildWx(testing.allocator, &allowed, .kill_process, .{ .errno = @intFromEnum(E.PERM) });
    defer testing.allocator.free(g_wx_prog);

    const res = try runInChild(childWx);
    try testing.expect(res.exitedWith(0));
}

// ── real: seccomp(2) + TSYNC (fork children, incl. cross-thread) ────────────

var g_tsync_kill_prog: []const SockFilter = &.{};
var g_tsync_allow_prog: []const SockFilter = &.{};

fn childTsyncKill() void {
    noNewPrivs() catch linux.exit(101);
    seccomp.installTsync(g_tsync_kill_prog) catch |e| switch (e) {
        error.SeccompFailed => linux.exit(102),
        error.ThreadSyncFailed => linux.exit(103),
    };
    _ = linux.getpid(); // not on the list → SIGSYS kills the process
    linux.exit(0); // unreachable if the filter works
}

fn childTsyncControl() void {
    noNewPrivs() catch linux.exit(101);
    seccomp.installTsync(g_tsync_allow_prog) catch |e| switch (e) {
        error.SeccompFailed => linux.exit(102),
        error.ThreadSyncFailed => linux.exit(103),
    };
    _ = linux.getpid(); // allowed → runs fine
    linux.exit(7);
}

test "seccomp(2)+TSYNC: denied syscall kills the child; control survives (single thread)" {
    try requireSeccompFilter();
    g_tsync_kill_prog = try seccomp.build(testing.allocator, &seccomp_min_no_getpid, .kill_process);
    defer testing.allocator.free(g_tsync_kill_prog);
    g_tsync_allow_prog = try seccomp.build(testing.allocator, &seccomp_min_with_getpid, .kill_process);
    defer testing.allocator.free(g_tsync_allow_prog);

    const killed = try runInChild(childTsyncKill);
    // 102/103 here are failures of installTsync on a single thread that has
    // set no_new_privs — nothing to skip past.
    try testing.expect(killed.killedBy(.SYS));

    const control = try runInChild(childTsyncControl);
    try testing.expect(control.exitedWith(7));
}

// The real point of TSYNC: a filter installed on the MAIN thread must also
// reach a WORKER thread that was already running beforehand — the prctl form
// (`install`) provably does not (it only ever touches the calling thread).
// Allow-list needed for the harness itself to keep working *after* install:
// futex + munmap (std.Thread.join's internals) and nanosleep (our busy-wait).
// getpid is the one deliberately denied call.
const tsync_prop_allowed = [_]linux.SYS{ .exit, .exit_group, .futex, .munmap, .nanosleep };
var g_tsync_prop_prog: []const SockFilter = &.{};

fn tsyncWorker(ready: *std.atomic.Value(bool), release: *std.atomic.Value(bool)) void {
    ready.store(true, .release);
    while (!release.load(.acquire)) {
        var ts = linux.timespec{ .sec = 0, .nsec = 1_000_000 }; // 1ms
        _ = linux.nanosleep(&ts, null);
    }
    _ = linux.getpid(); // denied by the filter installed on the MAIN thread
    // Only reached if TSYNC failed to propagate to this thread.
    linux.exit(1);
}

/// `SIGALRM` after `seconds`, whatever the process is doing.
///
/// ⚠ NOT `alarm(2)`. That syscall exists only in the x86 tables; the "generic"
/// syscall ABI every other architecture uses (arm64 included) has no
/// `SYS_alarm` at all, so `linux.syscall1(.alarm, …)` is not a portability
/// wart — it fails to COMPILE on arm64 with "enum 'Arm64' has no member named
/// 'alarm'". Caught by the arm64 lane on 2026-08-15, the first run of this
/// module on anything but x86_64. `setitimer(ITIMER_REAL, …)` is the portable
/// spelling and is what glibc's `alarm()` itself calls there.
///
/// ⚠ The syscall is issued directly rather than through `linux.setitimer`,
/// which declares `*const itimerspec` — NANOseconds. The kernel reads
/// `struct itimerval` — MICROseconds. Both are two pairs of longs, so they
/// agree byte for byte only while the sub-second field is zero; through that
/// declaration any future sub-second value would silently mean 1000× less.
fn armWatchdog(seconds: isize) void {
    const itimerval = extern struct { interval: linux.timeval, value: linux.timeval };
    var it: itimerval = .{
        .interval = .{ .sec = 0, .usec = 0 },
        .value = .{ .sec = seconds, .usec = 0 },
    };
    _ = linux.syscall3(.setitimer, @intCast(@intFromEnum(linux.ITIMER.REAL)), @intFromPtr(&it), 0);
}

fn childTsyncPropagation() void {
    // Watchdog: if the join/propagation logic below ever wedges, self-
    // terminate rather than hang the test runner's waitpid forever.
    armWatchdog(5);

    var ready = std.atomic.Value(bool).init(false);
    var release = std.atomic.Value(bool).init(false);
    const worker = std.Thread.spawn(.{}, tsyncWorker, .{ &ready, &release }) catch linux.exit(120);

    while (!ready.load(.acquire)) {
        var ts = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&ts, null);
    }

    noNewPrivs() catch linux.exit(101);
    // KILL_PROCESS + TSYNC: if the sync reaches the worker, its getpid()
    // below brings down the WHOLE process (not just that one thread) — an
    // unambiguous, race-free signal that doesn't depend on cross-thread
    // messaging surviving the kill.
    seccomp.installTsync(g_tsync_prop_prog) catch |e| switch (e) {
        error.SeccompFailed => linux.exit(102),
        error.ThreadSyncFailed => linux.exit(103),
    };
    release.store(true, .release);
    worker.join(); // only returns if the worker survived getpid() (no propagation)
    linux.exit(55); // reached only when TSYNC did NOT propagate to the worker
}

test "seccomp(2)+TSYNC: filter installed on main thread also kills a pre-existing worker thread" {
    g_tsync_prop_prog = try seccomp.build(testing.allocator, &tsync_prop_allowed, .kill_process);
    defer testing.allocator.free(g_tsync_prop_prog);

    try requireSeccompFilter();
    const res = try runInChild(childTsyncPropagation);
    if (res.exitedWith(120)) return error.SkipZigTest; // couldn't even spawn a thread here — not the module's code
    try testing.expect(res.killedBy(.SYS)); // TSYNC propagated: whole process died (102/103/55 are failures)
}

// Audit S16: `ThreadSyncFailed`'s whole reason to exist — a POSITIVE return
// from the TSYNC syscall, which `linux.errno()` decodes as `.SUCCESS` because
// it only recognizes values in `(-4096, 0)` as errors — had no witness.
// Reproduced 2026-09-10 by probe (`.zig-cache/probe/tsync_probe2.zig`, since
// discarded): TSYNC fails for a sibling thread whose OWN filter chain has
// already diverged from the caller's — concretely, a worker that installed
// its own single-thread filter via `install()` BEFORE the main thread calls
// `installTsync()`. Measured raw: `seccomp(TSYNC)` returned the worker's tid
// (236337 in that run) and `linux.errno()` on it read `.SUCCESS`.
var g_tsync_collision_worker_prog: []const SockFilter = &.{};
var g_tsync_collision_main_prog: []const SockFilter = &.{};

fn tsyncCollisionWorker(ready: *std.atomic.Value(bool), release: *std.atomic.Value(bool)) void {
    noNewPrivs() catch linux.exit(101);
    // The worker's OWN single-thread install — NOT through TSYNC. This is
    // what makes its filter chain diverge from the main thread's.
    seccomp.install(g_tsync_collision_worker_prog) catch linux.exit(102);
    ready.store(true, .release);
    while (!release.load(.acquire)) {
        var ts = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&ts, null);
    }
}

fn childTsyncCollision() void {
    armWatchdog(5);
    var ready = std.atomic.Value(bool).init(false);
    var release = std.atomic.Value(bool).init(false);
    const worker = std.Thread.spawn(.{}, tsyncCollisionWorker, .{ &ready, &release }) catch linux.exit(120);

    while (!ready.load(.acquire)) {
        var ts = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&ts, null);
    }

    noNewPrivs() catch linux.exit(101);
    const result = seccomp.installTsync(g_tsync_collision_main_prog);
    release.store(true, .release);
    worker.join();

    if (result) |_| {
        // The bug this test exists to catch: a positive-tid return silently
        // read as success.
        linux.exit(200);
    } else |e| switch (e) {
        error.ThreadSyncFailed => linux.exit(0), // correctly detected
        error.SeccompFailed => linux.exit(201),
    }
}

test "seccomp(2)+TSYNC: a sibling thread with its own prior, different filter is reported as ThreadSyncFailed, not silently as success (audit S16)" {
    try requireSeccompFilter();
    // Both need futex + munmap + nanosleep to keep `std.Thread.spawn`/`.join`
    // itself working once a filter is live on that thread — same reasoning as
    // `tsync_prop_allowed` above. Byte-identical program CONTENT is fine: two
    // SEPARATE `install()` calls still diverge as kernel objects, which is
    // the actual condition TSYNC's sync check is sensitive to, not content.
    g_tsync_collision_worker_prog = try seccomp.build(testing.allocator, &tsync_prop_allowed, .kill_process);
    defer testing.allocator.free(g_tsync_collision_worker_prog);
    g_tsync_collision_main_prog = try seccomp.build(testing.allocator, &tsync_prop_allowed, .kill_process);
    defer testing.allocator.free(g_tsync_collision_main_prog);

    const res = try runInChild(childTsyncCollision);
    if (res.exitedWith(120)) return error.SkipZigTest; // couldn't spawn a thread here
    if (res.exitedWith(200)) return error.PositiveTidReadAsSuccess;
    try testing.expect(res.exitedWith(0));
}

// ── real: landlock (fork children) ───────────────────────────────────────────

// Absolute paths shared with the child via COW memory. Filled by the test body
// before forking.
var g_ll_allowed_dir: [:0]const u8 = "";
var g_ll_allowed_file: [:0]const u8 = "";
const ll_forbidden_file: [:0]const u8 = "/etc/passwd"; // exists, outside the allow-list

fn openReadonly(path: [*:0]const u8) E {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    const e = linux.errno(rc);
    if (e == .SUCCESS) _ = linux.close(@intCast(@as(isize, @bitCast(rc))));
    return e;
}

fn childLandlock() void {
    var rs = Ruleset.init() catch linux.exit(80);
    defer rs.deinit();
    rs.allowPath(g_ll_allowed_dir.ptr, Ruleset.access.read_only) catch linux.exit(81);
    noNewPrivs() catch linux.exit(82);
    rs.restrictSelf() catch linux.exit(83);

    // Forbidden read must now be blocked (EACCES).
    const forbidden = openReadonly(ll_forbidden_file.ptr);
    if (forbidden != .ACCES and forbidden != .PERM) linux.exit(30);
    // Allowed read must still work.
    if (openReadonly(g_ll_allowed_file.ptr) != .SUCCESS) linux.exit(31);
    linux.exit(0);
}

// Paths for the write-denial test: a second directory OUTSIDE the allow-list
// holding an existing victim file, and names for things the child must fail
// to create.
var g_ll_outside_victim: [:0]const u8 = "";
var g_ll_outside_new: [:0]const u8 = "";
var g_ll_outside_dir: [:0]const u8 = "";
var g_ll_inside_new: [:0]const u8 = "";

fn expectDenied(e: E) bool {
    return e == .ACCES or e == .PERM;
}

/// Audit S1: with `init()` handling every right, a tree allowed `read_only`
/// is read-only, and the rest of the filesystem is closed for WRITING too —
/// not just for reading. Before, `init(access.read_only)` handled only
/// read_file|read_dir, so create/truncate/mkdir/symlink/unlink outside the
/// allow-list (and writes INSIDE the "read-only" tree) all succeeded.
fn childLandlockDeniesWrites() void {
    var rs = Ruleset.init() catch linux.exit(80);
    defer rs.deinit();
    rs.allowPath(g_ll_allowed_dir.ptr, Ruleset.access.read_only) catch linux.exit(81);
    noNewPrivs() catch linux.exit(82);
    rs.restrictSelf() catch linux.exit(83);

    // Reading the allowed file still works (the ruleset is not simply "deny everything").
    if (openReadonly(g_ll_allowed_file.ptr) != .SUCCESS) linux.exit(31);
    // CREATE a new file outside the allow-list.
    if (!expectDenied(linux.errno(linux.open(g_ll_outside_new.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true }, 0o600)))) linux.exit(40);
    // OVERWRITE an existing file outside.
    if (!expectDenied(linux.errno(linux.open(g_ll_outside_victim.ptr, .{ .ACCMODE = .WRONLY, .TRUNC = true, .CLOEXEC = true }, 0)))) linux.exit(41);
    // MKDIR outside.
    if (!expectDenied(linux.errno(linux.mkdir(g_ll_outside_dir.ptr, 0o700)))) linux.exit(42);
    // SYMLINK outside.
    if (!expectDenied(linux.errno(linux.symlink("/etc/shadow", g_ll_outside_dir.ptr)))) linux.exit(43);
    // UNLINK outside.
    if (!expectDenied(linux.errno(linux.unlink(g_ll_outside_victim.ptr)))) linux.exit(44);
    // And a WRITE inside the read-only tree is denied too — read_only grants reading.
    if (!expectDenied(linux.errno(linux.open(g_ll_inside_new.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true }, 0o600)))) linux.exit(45);
    linux.exit(0);
}

/// Positive control for the above: `read_write` on the allowed tree does
/// permit creating a file there, so `init()` did not brick the process.
fn childLandlockReadWriteTree() void {
    var rs = Ruleset.init() catch linux.exit(80);
    defer rs.deinit();
    rs.allowPath(g_ll_allowed_dir.ptr, Ruleset.access.read_write) catch linux.exit(81);
    noNewPrivs() catch linux.exit(82);
    rs.restrictSelf() catch linux.exit(83);
    const rc = linux.open(g_ll_inside_new.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true }, 0o600);
    if (linux.errno(rc) != .SUCCESS) linux.exit(46);
    _ = linux.close(@intCast(@as(isize, @bitCast(rc))));
    if (linux.errno(linux.unlink(g_ll_inside_new.ptr)) != .SUCCESS) linux.exit(47);
    // Still no reaching outside.
    if (!expectDenied(linux.errno(linux.open(g_ll_outside_new.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true }, 0o600)))) linux.exit(40);
    linux.exit(0);
}

const LandlockFixture = struct {
    dir_buf: [64]u8 = undefined,
    file_buf: [80]u8 = undefined,
    out_dir_buf: [80]u8 = undefined,
    out_victim_buf: [96]u8 = undefined,
    out_new_buf: [96]u8 = undefined,
    out_sub_buf: [96]u8 = undefined,
    in_new_buf: [96]u8 = undefined,
    dir: [:0]const u8 = "",
    file: [:0]const u8 = "",
    out_dir: [:0]const u8 = "",
    out_victim: [:0]const u8 = "",
    out_new: [:0]const u8 = "",
    out_sub: [:0]const u8 = "",
    in_new: [:0]const u8 = "",

    /// Skip decisions are made HERE, before any child runs: no Landlock, no
    /// /etc/passwd, or no writable /tmp are all "the mechanism/fixture is not
    /// here" — a child later failing is the module failing.
    fn setup(f: *LandlockFixture) !void {
        _ = landlockAbiVersion() catch return error.SkipZigTest; // pre-5.13 / disabled
        if (openReadonly(ll_forbidden_file) != .SUCCESS) return error.SkipZigTest; // no /etc/passwd
        const pid = linux.getpid();
        f.dir = try std.fmt.bufPrintZ(&f.dir_buf, "/tmp/zig_sandbox_ll_{d}", .{pid});
        f.file = try std.fmt.bufPrintZ(&f.file_buf, "{s}/ok.txt", .{f.dir});
        f.out_dir = try std.fmt.bufPrintZ(&f.out_dir_buf, "/tmp/zig_sandbox_ll_{d}_outside", .{pid});
        f.out_victim = try std.fmt.bufPrintZ(&f.out_victim_buf, "{s}/victim.txt", .{f.out_dir});
        f.out_new = try std.fmt.bufPrintZ(&f.out_new_buf, "{s}/created.txt", .{f.out_dir});
        f.out_sub = try std.fmt.bufPrintZ(&f.out_sub_buf, "{s}/newdir", .{f.out_dir});
        f.in_new = try std.fmt.bufPrintZ(&f.in_new_buf, "{s}/written.txt", .{f.dir});
        _ = linux.mkdir(f.dir.ptr, 0o700); // ignore EEXIST from a prior run
        _ = linux.mkdir(f.out_dir.ptr, 0o700);
        for ([_][:0]const u8{ f.file, f.out_victim }) |p| {
            const fd_rc = linux.open(p.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true }, 0o600);
            if (linux.errno(fd_rc) != .SUCCESS) return error.SkipZigTest; // /tmp not writable
            const fd: i32 = @intCast(@as(isize, @bitCast(fd_rc)));
            _ = linux.write(fd, "allowed\n", 8);
            _ = linux.close(fd);
        }
        g_ll_allowed_dir = f.dir;
        g_ll_allowed_file = f.file;
        g_ll_outside_dir = f.out_sub;
        g_ll_outside_victim = f.out_victim;
        g_ll_outside_new = f.out_new;
        g_ll_inside_new = f.in_new;
    }

    fn teardown(f: *LandlockFixture) void {
        _ = linux.unlink(f.in_new.ptr);
        _ = linux.unlink(f.file.ptr);
        _ = linux.rmdir(f.dir.ptr);
        _ = linux.unlink(f.out_new.ptr);
        _ = linux.unlink(f.out_victim.ptr);
        _ = linux.unlink(f.out_sub.ptr); // a symlink, if the child managed one
        _ = linux.rmdir(f.out_sub.ptr);
        _ = linux.rmdir(f.out_dir.ptr);
    }
};

test "landlock: child restricted to a temp dir cannot read /etc/passwd, can read allowed" {
    var f: LandlockFixture = .{};
    try f.setup();
    defer f.teardown();
    const res = try runInChild(childLandlock);
    // 80 (init failed) is a FAILURE here: landlockAbiVersion said Landlock exists.
    try testing.expect(res.exitedWith(0));
}

test "landlock: init() + allowPath(read_only) denies create/overwrite/mkdir/symlink/unlink outside AND writes inside (audit S1)" {
    var f: LandlockFixture = .{};
    try f.setup();
    defer f.teardown();
    const res = try runInChild(childLandlockDeniesWrites);
    try testing.expect(res.exitedWith(0));
}

test "landlock: init() + allowPath(read_write) still permits creating a file in the allowed tree (positive control)" {
    var f: LandlockFixture = .{};
    try f.setup();
    defer f.teardown();
    const res = try runInChild(childLandlockReadWriteTree);
    try testing.expect(res.exitedWith(0));
}

test "landlock: initHandling(read_only) is the explicit, weaker form — access.all is what init() handles" {
    _ = landlockAbiVersion() catch return error.SkipZigTest;
    var narrow = try Ruleset.initHandling(Ruleset.access.read_only);
    defer narrow.deinit();
    try testing.expectEqual(Ruleset.access.read_only, narrow.handled);
    var full = try Ruleset.init();
    defer full.deinit();
    try testing.expectEqual(Ruleset.accessMaskForAbi(full.abi), full.handled);
    try testing.expect(full.handled & Ruleset.access.write_file != 0);
    try testing.expect(full.handled & Ruleset.access.make_dir != 0);
    try testing.expect(full.handled & Ruleset.access.make_sym != 0);
    try testing.expect(full.handled & Ruleset.access.remove_file != 0);
    try testing.expectEqual(@as(u64, (1 << 16) - 1), Ruleset.access.all);
}

test "landlock: allowPath refuses a symlink by name instead of granting its target (audit S10)" {
    _ = landlockAbiVersion() catch return error.SkipZigTest;
    var link_buf: [64]u8 = undefined;
    const link_z = try std.fmt.bufPrintZ(&link_buf, "/tmp/zig_sandbox_ll_{d}_link", .{linux.getpid()});
    _ = linux.unlink(link_z.ptr);
    if (linux.errno(linux.symlink("/", link_z.ptr)) != .SUCCESS) return error.SkipZigTest; // /tmp not writable
    defer _ = linux.unlink(link_z.ptr);
    var rs = try Ruleset.init();
    defer rs.deinit();
    try testing.expectError(error.PathIsSymlink, rs.allowPath(link_z.ptr, Ruleset.access.read_only));
    // The real directory behind an intermediate symlink component is fine:
    // O_NOFOLLOW applies to the final component only.
    try rs.allowPath("/tmp", Ruleset.access.read_only);
}

// Audit S4: `landlock_restrict_self` confines the calling thread; there is no
// TSYNC for Landlock. This pins the measured kernel behaviour so the docs'
// "restrict BEFORE spawning workers" is a tested statement, not a hope.
var g_ll_worker_result: std.atomic.Value(u32) = .init(0);

fn landlockWorker(release: *std.atomic.Value(bool)) void {
    while (!release.load(.acquire)) {
        var ts = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&ts, null);
    }
    g_ll_worker_result.store(if (openReadonly(ll_forbidden_file.ptr) == .SUCCESS) 1 else 2, .release);
}

fn childLandlockThreads() void {
    armWatchdog(5);
    var release = std.atomic.Value(bool).init(false);
    const worker = std.Thread.spawn(.{}, landlockWorker, .{&release}) catch linux.exit(120);
    var rs = Ruleset.init() catch linux.exit(80);
    defer rs.deinit();
    rs.allowPath(g_ll_allowed_dir.ptr, Ruleset.access.read_only) catch linux.exit(81);
    noNewPrivs() catch linux.exit(82);
    rs.restrictSelf() catch linux.exit(83);
    // Main thread: confined.
    if (!expectDenied(openReadonly(ll_forbidden_file.ptr))) linux.exit(30);
    release.store(true, .release);
    worker.join();
    // Worker spawned BEFORE restrictSelf: NOT confined (1). 2 would mean the
    // kernel now propagates — a change worth knowing about by name.
    linux.exit(if (g_ll_worker_result.load(.acquire) == 1) 0 else 50);
}

test "landlock: restrictSelf confines the calling thread only — a worker spawned before it is not confined (audit S4)" {
    var f: LandlockFixture = .{};
    try f.setup();
    defer f.teardown();
    const res = try runInChild(childLandlockThreads);
    if (res.exitedWith(120)) return error.SkipZigTest; // could not spawn a thread here
    try testing.expect(res.exitedWith(0));
}

// ── real: rlimit (fork children) ─────────────────────────────────────────────

fn childRlimitBites() void {
    // Cap open files hard at a small number, then exhaust it.
    limitOpenFiles(16) catch linux.exit(60);
    var opened: usize = 0;
    while (opened < 4096) : (opened += 1) {
        const rc = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(rc) != .SUCCESS) {
            // Hitting EMFILE at/under the cap proves the limit is enforced.
            if (linux.errno(rc) == .MFILE and opened <= 16) linux.exit(0);
            linux.exit(61);
        }
    }
    linux.exit(62); // opened 4096 fds under a cap of 16 — not enforced
}

fn childRlimitCannotRaise() void {
    // The property is "a NON-privileged process cannot raise it" (`setLimit`'s
    // doc). Root holds CAP_SYS_RESOURCE, which raises a hard limit legitimately,
    // so as root this test failed for the wrong reason — first seen when
    // `scripts/vm/run.sh sandbox` ran it as real root (2026-09-15). Shed the
    // capabilities first; the property under test is then the one documented.
    if (linux.geteuid() == 0) clearCapabilities() catch linux.exit(72);
    limitOpenFiles(64) catch linux.exit(70); // lowers the hard limit to 64
    // A non-privileged process must NOT be able to raise the hard limit back up.
    setLimit(.NOFILE, 4096, 4096) catch linux.exit(0); // expected: EPERM → success
    linux.exit(71); // raise succeeded → limit not really enforced
}

test "rlimit: RLIMIT_NOFILE is enforced and cannot be raised back" {
    const bites = try runInChild(childRlimitBites);
    try testing.expectEqual(@as(u32, 0), bites.status);

    const no_raise = try runInChild(childRlimitCannotRaise);
    try testing.expectEqual(@as(u32, 0), no_raise.status);
}

test "disableCoreDumps sets RLIMIT_CORE to zero in the child" {
    const Local = struct {
        fn child() void {
            disableCoreDumps() catch linux.exit(50);
            // Read it back: the function returning success is not the limit
            // being zero (audit S15 — a mutation leaving RLIMIT_CORE
            // unlimited passed this test).
            var rl: linux.rlimit = undefined;
            if (linux.errno(linux.getrlimit(.CORE, &rl)) != .SUCCESS) linux.exit(51);
            if (rl.cur != 0 or rl.max != 0) linux.exit(52);
            linux.exit(0);
        }
    };
    const res = try runInChild(Local.child);
    try testing.expect(res.exitedWith(0));
}

// limitProcesses / limitAddressSpace are thin `setLimit` wrappers with no
// enforcement test of their own (NPROC/AS enforcement is awkward to probe
// deterministically without disturbing the test host) — so nothing caught a
// wrong resource constant. This reads the rlimit back via getrlimit to prove
// each wrapper actually targets its named resource, not some other one.
fn childLimitProcessesSetsNproc() void {
    limitProcesses(4321) catch linux.exit(63);
    var rl: linux.rlimit = undefined;
    if (linux.errno(linux.getrlimit(.NPROC, &rl)) != .SUCCESS) linux.exit(64);
    if (rl.cur != 4321 or rl.max != 4321) linux.exit(65);
    linux.exit(0);
}

test "limitProcesses sets RLIMIT_NPROC to the requested value" {
    const res = try runInChild(childLimitProcessesSetsNproc);
    try testing.expect(res.exitedWith(0));
}

fn childLimitAddressSpaceSetsAs() void {
    const bytes: linux.rlim_t = 512 * 1024 * 1024;
    limitAddressSpace(bytes) catch linux.exit(66);
    var rl: linux.rlimit = undefined;
    if (linux.errno(linux.getrlimit(.AS, &rl)) != .SUCCESS) linux.exit(67);
    if (rl.cur != bytes or rl.max != bytes) linux.exit(68);
    linux.exit(0);
}

test "limitAddressSpace sets RLIMIT_AS to the requested value" {
    const res = try runInChild(childLimitAddressSpaceSetsAs);
    try testing.expect(res.exitedWith(0));
}

// ── injected errnos: the typed failure branches a healthy kernel never takes ──
//
// Audit S17/S18. `install`/`installTsync` never failed, and `landlockAbiVersion`
// never saw ENOSYS or EOPNOTSUPP, on any machine this suite ran on. So every
// typed error branch was a mutant nobody could kill. A seccomp filter installed
// in a child makes the REAL syscall return the chosen errno through the real
// kernel entry path, and the code under test cannot tell that from a kernel that
// refuses. The filters are installed with raw syscalls, not through the module,
// so a broken `install` cannot break its own test's setup.
//
// The errno is not invented: EOPNOTSUPP is what a kernel booted without the
// Landlock LSM returns. `scripts/vm/run.sh sandbox debian --kernel-append
// lsm=apparmor` measures it with no injection at all (the
// SANDBOX_EXPECT_LANDLOCK test below).

fn rawNoNewPrivs() bool {
    return linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) == .SUCCESS;
}

fn rawInstallPrctl(prog: []const SockFilter) bool {
    const fprog = SockFprog{ .len = @intCast(prog.len), .filter = prog.ptr };
    const rc = linux.prctl(@intFromEnum(linux.PR.SET_SECCOMP), linux.SECCOMP.MODE.FILTER, @intFromPtr(&fprog), 0, 0);
    return linux.errno(rc) == .SUCCESS;
}

fn rawInstallSeccomp(prog: []const SockFilter) bool {
    const fprog = SockFprog{ .len = @intCast(prog.len), .filter = prog.ptr };
    const rc = linux.syscall3(.seccomp, linux.SECCOMP.SET_MODE_FILTER, 0, @intFromPtr(&fprog));
    return linux.errno(rc) == .SUCCESS;
}

/// Allow everything, except `nr`, which returns `-errno` without running.
fn errnoOneSyscall(nr: linux.SYS, errno: E) [4]SockFilter {
    return .{
        bpf.stmt(bpf.ld | bpf.w | bpf.abs, seccomp.off_nr),
        bpf.jump(bpf.jmp | bpf.jeq | bpf.k, @intCast(@intFromEnum(nr)), 0, 1),
        bpf.stmt(bpf.ret | bpf.k, seccomp.ret_errno | @as(u32, @intFromEnum(errno))),
        bpf.stmt(bpf.ret | bpf.k, seccomp.ret_allow),
    };
}

/// Like `errnoOneSyscall(.landlock_create_ruleset, errno)`, but only for a real
/// ruleset creation (`flags == 0`). The ABI-version query
/// (`flags == LANDLOCK_CREATE_RULESET_VERSION`) still reaches the kernel, which
/// is the only way to get past `initHandling`'s first line into its own copy of
/// the errno mapping.
fn errnoLandlockCreateOnly(errno: E) [6]SockFilter {
    return .{
        bpf.stmt(bpf.ld | bpf.w | bpf.abs, seccomp.off_nr),
        bpf.jump(bpf.jmp | bpf.jeq | bpf.k, @intCast(@intFromEnum(linux.SYS.landlock_create_ruleset)), 0, 3),
        bpf.stmt(bpf.ld | bpf.w | bpf.abs, seccomp.arg2.lo),
        bpf.jump(bpf.jmp | bpf.jeq | bpf.k, 0, 0, 1),
        bpf.stmt(bpf.ret | bpf.k, seccomp.ret_errno | @as(u32, @intFromEnum(errno))),
        bpf.stmt(bpf.ret | bpf.k, seccomp.ret_allow),
    };
}

const allow_all_prog = [_]SockFilter{bpf.stmt(bpf.ret | bpf.k, seccomp.ret_allow)};

/// Positive control: a refused syscall that `install`/`installTsync` do not
/// make leaves both of them working, so the two failure children below fail
/// for the syscall they target and not because a pre-filter exists at all.
fn childInstallControl() void {
    if (!rawNoNewPrivs()) linux.exit(101);
    const pre = errnoOneSyscall(.getppid, .INVAL);
    if (!rawInstallSeccomp(&pre)) linux.exit(102);
    seccomp.install(&allow_all_prog) catch linux.exit(3);
    seccomp.installTsync(&allow_all_prog) catch linux.exit(4);
    linux.exit(0);
}

fn childInstallSeesPrctlFailure() void {
    if (!rawNoNewPrivs()) linux.exit(101);
    const pre = errnoOneSyscall(.prctl, .INVAL);
    if (!rawInstallSeccomp(&pre)) linux.exit(102);
    seccomp.install(&allow_all_prog) catch |e| switch (e) {
        error.SeccompFailed => linux.exit(0),
    };
    linux.exit(1); // reported success for a prctl the kernel refused
}

fn childInstallTsyncSeesSeccompFailure() void {
    if (!rawNoNewPrivs()) linux.exit(101);
    const pre = errnoOneSyscall(.seccomp, .INVAL);
    if (!rawInstallPrctl(&pre)) linux.exit(102);
    seccomp.installTsync(&allow_all_prog) catch |e| switch (e) {
        error.SeccompFailed => linux.exit(0),
        error.ThreadSyncFailed => linux.exit(2), // a plain -errno misread as a tid
    };
    linux.exit(1);
}

test "seccomp.install / installTsync: a syscall the kernel refuses surfaces as SeccompFailed, not success (audit S17)" {
    try requireSeccompFilter();
    // `status` rather than `exitedWith(0)`, so a failure prints which exit code.
    try testing.expectEqual(@as(u32, 0), (try runInChild(childInstallControl)).status);
    try testing.expectEqual(@as(u32, 0), (try runInChild(childInstallSeesPrctlFailure)).status);
    try testing.expectEqual(@as(u32, 0), (try runInChild(childInstallTsyncSeesSeccompFailure)).status);
}

var g_inj_errno: E = .NOSYS;

fn injectedLandlockError() LandlockError {
    return switch (g_inj_errno) {
        .NOSYS => error.NotSupported,
        .OPNOTSUPP => error.Disabled,
        else => unreachable,
    };
}

fn childLandlockVersionUnderErrno() void {
    const want = injectedLandlockError();
    if (!rawNoNewPrivs()) linux.exit(101);
    const pre = errnoOneSyscall(.landlock_create_ruleset, g_inj_errno);
    if (!rawInstallPrctl(&pre)) linux.exit(102);
    if (landlockAbiVersion()) |_| linux.exit(1) else |e| if (e != want) linux.exit(2);
    if (Ruleset.init()) |_| linux.exit(3) else |e| if (e != want) linux.exit(4);
    linux.exit(0);
}

fn childLandlockCreateUnderErrno() void {
    const want = injectedLandlockError();
    if (!rawNoNewPrivs()) linux.exit(101);
    const pre = errnoLandlockCreateOnly(g_inj_errno);
    if (!rawInstallPrctl(&pre)) linux.exit(102);
    // The version query must still succeed, or this child tests nothing new.
    _ = landlockAbiVersion() catch linux.exit(5);
    if (Ruleset.init()) |_| linux.exit(3) else |e| if (e != want) linux.exit(4);
    linux.exit(0);
}

test "landlock: ENOSYS / EOPNOTSUPP from the version query map to NotSupported / Disabled (audit S18)" {
    try requireSeccompFilter();
    for ([_]E{ .NOSYS, .OPNOTSUPP }) |errno| {
        g_inj_errno = errno;
        try testing.expectEqual(@as(u32, 0), (try runInChild(childLandlockVersionUnderErrno)).status);
    }
}

test "landlock: ENOSYS / EOPNOTSUPP from the ruleset creation itself map the same way — initHandling's own copy (audit S18)" {
    try requireSeccompFilter();
    // Past the version query means a kernel whose Landlock actually answers.
    _ = landlockAbiVersion() catch return error.SkipZigTest;
    for ([_]E{ .NOSYS, .OPNOTSUPP }) |errno| {
        g_inj_errno = errno;
        try testing.expectEqual(@as(u32, 0), (try runInChild(childLandlockCreateUnderErrno)).status);
    }
}

test "landlock: a kernel booted without the Landlock LSM reports error.Disabled, no injection (VM lane, audit S18)" {
    // Set only by `scripts/vm/run.sh sandbox`'s guest setup, and only when the
    // guest's active LSM list really lacks landlock. Everywhere else: skip.
    const expect = testing.environ.getPosix("SANDBOX_EXPECT_LANDLOCK") orelse return error.SkipZigTest;
    try testing.expectEqualStrings("disabled", expect);
    try testing.expectError(error.Disabled, landlockAbiVersion());
    try testing.expectError(error.Disabled, Ruleset.init());
}

// ── real: privilege drop (root-gated, skips cleanly) ─────────────────────────
//
// Run for real by `scripts/vm/run.sh sandbox` (disposable guest, real root).
// Each exit code names one property, so a mutant's failure says which.

const nobody_uid: linux.uid_t = 65534;
const nobody_gid: linux.gid_t = 65534;

fn childDropThenTryRegain() void {
    // Precondition: hold a supplementary group. A root login shell can have
    // none, and then a drop that skipped `setgroups` would be invisible (S14).
    const extra = [_]linux.gid_t{4242};
    if (linux.errno(linux.setgroups(extra.len, &extra)) != .SUCCESS) linux.exit(89);
    if (linux.getgroups(0, null) != 1) linux.exit(88);

    dropPrivileges(.{ .uid = nobody_uid, .gid = nobody_gid }) catch linux.exit(90);
    if (linux.getuid() != nobody_uid) linux.exit(91);
    // gid too — the classic setuid-first hole leaves gid 0 behind while uid
    // reads as nobody (audit S13: the old check was uid-only).
    if (linux.getgid() != nobody_gid or linux.getegid() != nobody_gid) linux.exit(93);
    var ruid: linux.uid_t = 0;
    var euid: linux.uid_t = 0;
    var suid: linux.uid_t = 0;
    _ = linux.getresuid(&ruid, &euid, &suid);
    if (suid != nobody_uid) linux.exit(94); // saved uid is the seteuid ladder back up
    var rgid: linux.gid_t = 0;
    var egid: linux.gid_t = 0;
    var sgid: linux.gid_t = 0;
    _ = linux.getresgid(&rgid, &egid, &sgid);
    if (sgid != nobody_gid) linux.exit(97);
    if (linux.getgroups(0, null) != 0) linux.exit(96); // group 4242 must be gone
    // Must not be able to climb back to uid 0.
    if (linux.errno(linux.setuid(0)) == .SUCCESS) linux.exit(92); // regained root!
    if (linux.errno(linux.setgid(0)) == .SUCCESS) linux.exit(95);
    linux.exit(0);
}

test "privilege drop: child drops to nobody and cannot regain uid 0 (needs root)" {
    if (linux.geteuid() != 0) return error.SkipZigTest; // not privileged — nothing to drop
    const res = try runInChild(childDropThenTryRegain);
    try testing.expectEqual(@as(u32, 0), res.status);
}

fn capBoundingSetHas(cap: usize) ?bool {
    const rc = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), cap, 0, 0, 0);
    return switch (linux.errno(rc)) {
        .SUCCESS => rc != 0,
        else => null, // EINVAL: past CAP_LAST_CAP
    };
}

fn childDropBoundingSet() void {
    // Precondition: root starts with CAP_CHOWN (0) in its bounding set, or a
    // drop that removes nothing would look the same as one that works.
    if (capBoundingSetHas(0) != true) linux.exit(99);
    // Root holds CAP_SETPCAP, so PermissionDenied here is a failure, not a skip.
    dropCapabilityBoundingSet() catch linux.exit(95);
    // Read the set back (audit S13, M25): a drop loop whose body did nothing
    // still returned success, and the old test accepted that.
    var cap: usize = 0;
    while (cap < cap_probe_ceiling) : (cap += 1) {
        const has = capBoundingSetHas(cap) orelse break;
        if (has) linux.exit(96);
    }
    if (cap == 0) linux.exit(98);
    linux.exit(0);
}

test "capability bounding-set drop empties the set, read back via PR_CAPBSET_READ (needs root)" {
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const res = try runInChild(childDropBoundingSet);
    try testing.expectEqual(@as(u32, 0), res.status);
}

// clearCapabilities zeros a set the calling process already holds (or lacks),
// which — unlike the bounding-set drop — needs no privilege: reducing your own
// effective/permitted/inheritable sets to nothing is always allowed. So this
// runs unconditionally (no root gate) and reads the sets back via `capget` to
// prove they actually became zero, not just that the syscall returned success.
fn childClearCapabilities() void {
    // Reducing your own capability sets to nothing is a kernel-guaranteed
    // no-privilege-required operation (you can always give capabilities up),
    // so — unlike the bounding-set drop — this must always succeed here; no
    // PermissionDenied escape hatch to accidentally swallow a real break.
    clearCapabilities() catch linux.exit(96);
    var hdr = extern struct { version: u32, pid: c_int }{
        .version = linux_capability_version_3,
        .pid = 0,
    };
    var data = [2]extern struct { effective: u32, permitted: u32, inheritable: u32 }{
        .{ .effective = 1, .permitted = 1, .inheritable = 1 }, // poisoned; capget must overwrite
        .{ .effective = 1, .permitted = 1, .inheritable = 1 },
    };
    const rc = linux.syscall2(.capget, @intFromPtr(&hdr), @intFromPtr(&data));
    if (linux.errno(rc) != .SUCCESS) linux.exit(97);
    if (data[0].effective != 0 or data[0].permitted != 0 or data[0].inheritable != 0) linux.exit(98);
    if (data[1].effective != 0 or data[1].permitted != 0 or data[1].inheritable != 0) linux.exit(99);
    linux.exit(0);
}

test "clearCapabilities: effective/permitted/inheritable read back as zero" {
    const res = try runInChild(childClearCapabilities);
    try testing.expect(res.exitedWith(0));
}

// Dark-tests aggregator (CONVENTIONS.md §6 step 3): single-file module, but
// refAllDecls keeps every pub decl (and its doc examples) compiled + linked.
test {
    testing.refAllDecls(@This());
}
