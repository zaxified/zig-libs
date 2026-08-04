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
//! Basic usage (order matters — do this last, after bind/listen):
//!
//! ```zig
//! const sandbox = @import("sandbox");
//!
//! try sandbox.noNewPrivs();
//! try sandbox.disableCoreDumps();
//! try sandbox.dropPrivileges(.{ .uid = 65534, .gid = 65534 });
//!
//! var ll = try sandbox.Landlock.init(sandbox.Landlock.access.read_only);
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
/// read-back (`getuid`/`geteuid`/`getgid`/`getegid`) that the real *and*
/// effective ids all became the requested values — a defence against a partial
/// or spoofed drop. Call `noNewPrivs()` first if you also want execve() locked.
pub fn dropPrivileges(creds: Credentials) DropError!void {
    // 1. Clear supplementary groups — must happen while still privileged.
    const no_groups = [_]linux.gid_t{};
    if (linux.errno(linux.setgroups(0, &no_groups)) != .SUCCESS) return error.SetIdFailed;

    // 2. Real+effective+saved gid. setgid sets all three when privileged.
    if (linux.errno(linux.setgid(creds.gid)) != .SUCCESS) return error.SetIdFailed;

    // 3. Real+effective+saved uid, LAST — this is the point of no return.
    if (linux.errno(linux.setuid(creds.uid)) != .SUCCESS) return error.SetIdFailed;

    // 4. Read back: the drop must be total, not just the real ids.
    if (linux.getuid() != creds.uid) return error.DropNotEffective;
    if (linux.geteuid() != creds.uid) return error.DropNotEffective;
    if (linux.getgid() != creds.gid) return error.DropNotEffective;
    if (linux.getegid() != creds.gid) return error.DropNotEffective;
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

    /// Create a ruleset that *handles* (denies-by-default) `handled_access`,
    /// after negotiating the kernel's ABI version and clamping the mask to it.
    pub fn init(handled_access: u64) LandlockError!Ruleset {
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
        // O_PATH|O_CLOEXEC: we only need a handle to name the tree, not to read it.
        const ofd = linux.open(path, .{ .PATH = true, .CLOEXEC = true, .DIRECTORY = false }, 0);
        if (linux.errno(ofd) != .SUCCESS) return error.PathOpenFailed;
        const parent_fd: i32 = @intCast(@as(isize, @bitCast(ofd)));
        defer _ = linux.close(parent_fd);

        const attr = PathBeneathAttr{
            .allowed_access = allowed_access & self.handled,
            .parent_fd = parent_fd,
        };
        const rc = sys_landlock_add_rule(self.fd, landlock_rule_path_beneath, &attr, 0);
        if (linux.errno(rc) != .SUCCESS) return error.RulesetFailed;
    }

    /// Enforce the ruleset on the calling thread and all future children.
    /// Irreversible. Requires PR_SET_NO_NEW_PRIVS (call `noNewPrivs()` first)
    /// unless the process holds `CAP_SYS_ADMIN`.
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
/// checks `seccomp_data.arch` against this so a foreign ABI (e.g. x86-64's x32,
/// which reuses syscall numbers) cannot slip past a number-only allow-list.
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
        /// program feature-probe without dying. Common choice: EPERM.
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
    };

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
        const m: u8 = @intCast(allowed.len);

        var list: std.ArrayList(SockFilter) = .empty;
        errdefer list.deinit(gpa);

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
        "read",         "write",           "readv",           "writev",
        "pread64",      "pwrite64",        "recvfrom",        "sendto",
        "recvmsg",      "sendmsg",         "sendmmsg",        "recvmmsg",
        // socket lifecycle (accept only; server already bound/listened)
        "accept",       "accept4",         "shutdown",        "getsockname",
        "getpeername",  "getsockopt",      "setsockopt",
        // fd lifecycle
             "close",
        "dup",          "dup2",            "dup3",            "fcntl",
        "fstat",        "newfstatat",      "statx",           "lseek",
        "pipe2",        "eventfd2",
        // readiness / timers
               "epoll_create1",   "epoll_ctl",
        "epoll_wait",   "epoll_pwait",     "poll",            "ppoll",
        "pselect6",     "timerfd_create",  "timerfd_settime", "timerfd_gettime",
        // scheduling / sync
        "futex",        "sched_yield",     "restart_syscall", "membarrier",
        "nanosleep",    "clock_nanosleep",
        // time / entropy
        "clock_gettime",   "gettimeofday",
        "getrandom",
        // memory
           "mmap",            "munmap",          "mremap",
        "mprotect",     "madvise",         "brk",
        // signals
                    "rt_sigreturn",
        "rt_sigaction", "rt_sigprocmask",  "sigaltstack",
        // process identity / exit
            "getpid",
        "gettid",       "getuid",          "getgid",          "geteuid",
        "getegid",      "exit",            "exit_group",      "tgkill",
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
        const m: u8 = @intCast(allowed.len);

        var list: std.ArrayList(SockFilter) = .empty;
        errdefer list.deinit(gpa);

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
    _ = linux.waitpid(pid, &status, 0);
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

    // Arch guard.
    try testing.expectEqual(@as(u16, bpf.ld | bpf.w | bpf.abs), prog[0].code);
    try testing.expectEqual(@as(u32, seccomp.off_arch), prog[0].k);
    try testing.expectEqual(@as(u16, bpf.jmp | bpf.jeq | bpf.k), prog[1].code);
    try testing.expectEqual(audit_arch, prog[1].k);
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

test "seccomp KILL_PROCESS: denied syscall kills the child; control survives" {
    g_kill_prog = try seccomp.build(testing.allocator, &seccomp_min_no_getpid, .kill_process);
    defer testing.allocator.free(g_kill_prog);
    g_allow_prog = try seccomp.build(testing.allocator, &seccomp_min_with_getpid, .kill_process);
    defer testing.allocator.free(g_allow_prog);

    const killed = try runInChild(childSeccompKill);
    if (killed.exitedWith(102)) return error.SkipZigTest; // kernel lacks CONFIG_SECCOMP_FILTER
    try testing.expect(killed.killedBy(.SYS)); // SIGSYS

    const control = try runInChild(childSeccompControl);
    try testing.expect(control.exitedWith(7));
}

test "seccomp ERRNO: denied syscall returns -EPERM instead of dying" {
    g_errno_prog = try seccomp.build(testing.allocator, &seccomp_min_no_getpid, .{ .errno = @intFromEnum(E.PERM) });
    defer testing.allocator.free(g_errno_prog);

    const res = try runInChild(childSeccompErrno);
    if (res.exitedWith(102)) return error.SkipZigTest; // no seccomp filter support
    try testing.expect(res.exitedWith(0)); // getpid saw EPERM, not a signal
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
    const allowed = [_]linux.SYS{ .exit, .exit_group, .mmap, .mprotect };
    g_wx_prog = try seccomp.buildWx(testing.allocator, &allowed, .kill_process, .{ .errno = @intFromEnum(E.PERM) });
    defer testing.allocator.free(g_wx_prog);

    const res = try runInChild(childWx);
    if (res.exitedWith(102)) return error.SkipZigTest; // kernel lacks CONFIG_SECCOMP_FILTER
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
    g_tsync_kill_prog = try seccomp.build(testing.allocator, &seccomp_min_no_getpid, .kill_process);
    defer testing.allocator.free(g_tsync_kill_prog);
    g_tsync_allow_prog = try seccomp.build(testing.allocator, &seccomp_min_with_getpid, .kill_process);
    defer testing.allocator.free(g_tsync_allow_prog);

    const killed = try runInChild(childTsyncKill);
    if (killed.exitedWith(102) or killed.exitedWith(103)) return error.SkipZigTest; // no seccomp(2)/TSYNC
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

fn childTsyncPropagation() void {
    // Watchdog: if the join/propagation logic below ever wedges, self-
    // terminate rather than hang the test runner's waitpid forever.
    _ = linux.syscall1(.alarm, 5);

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

    const res = try runInChild(childTsyncPropagation);
    if (res.exitedWith(102) or res.exitedWith(103)) return error.SkipZigTest; // no seccomp(2)/TSYNC
    if (res.exitedWith(120)) return error.SkipZigTest; // couldn't even spawn a thread here
    try testing.expect(res.killedBy(.SYS)); // TSYNC propagated: whole process died
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
    var rs = Ruleset.init(Ruleset.access.read_only) catch linux.exit(80);
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

test "landlock: child restricted to a temp dir cannot read /etc/passwd, can read allowed" {
    _ = landlockAbiVersion() catch return error.SkipZigTest; // pre-5.13 / disabled
    if (openReadonly(ll_forbidden_file) != .SUCCESS) return error.SkipZigTest; // no /etc/passwd

    // Build a real allowed dir + file with raw syscalls (consistent with the
    // module; sidesteps the churning std.Io.Dir API). Unique per pid.
    var dir_buf: [64]u8 = undefined;
    const dir_z = try std.fmt.bufPrintZ(&dir_buf, "/tmp/zig_sandbox_ll_{d}", .{linux.getpid()});
    var file_buf: [80]u8 = undefined;
    const file_z = try std.fmt.bufPrintZ(&file_buf, "{s}/ok.txt", .{dir_z});

    _ = linux.mkdir(dir_z.ptr, 0o700); // ignore EEXIST from a prior run
    const fd_rc = linux.open(file_z.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true }, 0o600);
    if (linux.errno(fd_rc) != .SUCCESS) return error.SkipZigTest; // /tmp not writable
    const fd: i32 = @intCast(@as(isize, @bitCast(fd_rc)));
    _ = linux.write(fd, "allowed\n", 8);
    _ = linux.close(fd);
    defer {
        _ = linux.unlink(file_z.ptr);
        _ = linux.rmdir(dir_z.ptr);
    }

    g_ll_allowed_dir = dir_z;
    g_ll_allowed_file = file_z;

    const res = try runInChild(childLandlock);
    if (res.exitedWith(80)) return error.SkipZigTest; // ruleset create failed (ABI edge)
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
    limitOpenFiles(64) catch linux.exit(70); // lowers the hard limit to 64
    // A non-privileged process must NOT be able to raise the hard limit back up.
    setLimit(.NOFILE, 4096, 4096) catch linux.exit(0); // expected: EPERM → success
    linux.exit(71); // raise succeeded → limit not really enforced
}

test "rlimit: RLIMIT_NOFILE is enforced and cannot be raised back" {
    const bites = try runInChild(childRlimitBites);
    try testing.expect(bites.exitedWith(0));

    const no_raise = try runInChild(childRlimitCannotRaise);
    try testing.expect(no_raise.exitedWith(0));
}

test "disableCoreDumps sets RLIMIT_CORE to zero in the child" {
    const Local = struct {
        fn child() void {
            disableCoreDumps() catch linux.exit(50);
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

// ── real: privilege drop (root-gated, skips cleanly) ─────────────────────────

const nobody_uid: linux.uid_t = 65534;
const nobody_gid: linux.gid_t = 65534;

fn childDropThenTryRegain() void {
    dropPrivileges(.{ .uid = nobody_uid, .gid = nobody_gid }) catch linux.exit(90);
    if (linux.getuid() != nobody_uid) linux.exit(91);
    // Must not be able to climb back to uid 0.
    if (linux.errno(linux.setuid(0)) == .SUCCESS) linux.exit(92); // regained root!
    linux.exit(0);
}

test "privilege drop: child drops to nobody and cannot regain uid 0 (needs root)" {
    if (linux.geteuid() != 0) return error.SkipZigTest; // not privileged — nothing to drop
    const res = try runInChild(childDropThenTryRegain);
    try testing.expect(res.exitedWith(0));
}

fn childDropBoundingSet() void {
    dropCapabilityBoundingSet() catch |e| switch (e) {
        error.PermissionDenied => linux.exit(0), // acceptable if we lack CAP_SETPCAP
        else => linux.exit(95),
    };
    linux.exit(0);
}

test "capability bounding-set drop succeeds or cleanly reports EPERM (needs root)" {
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const res = try runInChild(childDropBoundingSet);
    try testing.expect(res.exitedWith(0));
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
