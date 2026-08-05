// SPDX-License-Identifier: MIT
//! Program loading — NOT a TODO stub. `std.os.linux.BPF.prog_load` already
//! implements the whole `BPF_PROG_LOAD` path end-to-end (Attr encoding, the
//! `bpf()` syscall, errno-to-error mapping) and is exercised by std's own
//! `"prog_load"` test against a real kernel. This file adds nothing but the
//! `programs.Program` -> `prog_load` argument translation and an optional
//! verifier-log convenience path — genuinely mechanical, so it is written
//! for real rather than stubbed, matching this repo's rule of not
//! reimplementing what std already provides.

const std = @import("std");
const linux = std.os.linux;
const BPF = linux.BPF;
const programs = @import("programs.zig");

pub const Program = programs.Program;
pub const Insn = programs.Insn;

/// Load `prog` under `license` (the kernel enforces which helpers a program
/// may call based on this string — `"GPL"` unlocks GPL-only helpers,
/// anything else including `"MIT"` is treated as a proprietary license and
/// restricted to the non-GPL helper subset; none of the three builders in
/// `programs.zig` need a GPL-only helper, so `"MIT"` load-tests fine).
/// Returns the loaded program's fd (caller closes it, e.g. via
/// `std.os.linux.close`).
pub fn load(prog: Program, license: []const u8) !linux.fd_t {
    return BPF.prog_load(prog.prog_type, prog.insns, null, license, 0, 0);
}

/// Same as `load`, but captures the verifier's human-readable log into
/// `log_buf` (pass `linux.BPF.F_STRICT_ALIGNMENT`-style flags via `flags` if
/// needed). Useful while iterating on a `programs.zig` builder —
/// `BPF_PROG_LOAD`'s verifier log is the primary offline-adjacent debugging
/// tool short of a full golden-vector cross-check (see `../SPEC.md`).
pub fn loadWithLog(prog: Program, license: []const u8, log_buf: []u8, flags: u32) !linux.fd_t {
    var log: BPF.Log = .{ .level = 1, .buf = log_buf };
    return BPF.prog_load(prog.prog_type, prog.insns, &log, license, 0, flags);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const builtin = @import("builtin");

/// True if the calling process can plausibly reach BPF_PROG_LOAD (CAP_BPF or
/// the older CAP_SYS_ADMIN gate, approximated the same way the rest of this
/// repo gates privileged tests — see `tc`/`rawsock`: attempt the real
/// syscall and treat AccessDenied/PermissionDenied as "skip", not "fail").
fn hasBpfCapability() bool {
    return linux.geteuid() == 0;
}

test "load: a hand-written trivial socket_filter program loads (needs CAP_BPF/root)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) return error.SkipZigTest;

    // Deliberately NOT one of programs.zig's builders — a minimal,
    // hand-verified-safe program exercising only
    // this file's real, non-stub code path: `r0 = 0; exit;` is the same
    // "good_prog" shape std's own bpf.zig test uses.
    const insns = [_]Insn{
        Insn.mov(.r0, 0),
        Insn.exit(),
    };
    const prog: Program = .{ .prog_type = .socket_filter, .insns = &insns };

    const fd = load(prog, "MIT") catch |e| switch (e) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return e,
    };
    defer _ = linux.close(fd);
    try testing.expect(fd >= 0);
}

test "load: an unsafe program (no r0 set before exit) is rejected by the verifier" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) return error.SkipZigTest;

    const insns = [_]Insn{
        Insn.exit(), // r0 never initialized
    };
    const prog: Program = .{ .prog_type = .socket_filter, .insns = &insns };

    if (load(prog, "MIT")) |fd| {
        _ = linux.close(fd);
        return error.TestUnexpectedResult; // the verifier must NOT accept this
    } else |e| switch (e) {
        error.UnsafeProgram => {},
        // `geteuid() == 0` inside a user namespace (`unshare -r`) is not
        // CAP_BPF in the INIT user namespace, so `bpf()` is refused before
        // the verifier ever runs. Skip rather than fail: the point of this
        // test is what the verifier does, not what the capability check does.
        error.PermissionDenied => return error.SkipZigTest,
        else => return e,
    }
}

test "loadWithLog: a rejected program's verifier log is actually captured, not just EINVAL" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) return error.SkipZigTest;

    // Same rejection shape as the test above (`load`), but through the log-
    // capturing path: a bare `error.UnsafeProgram` says the verifier said no,
    // not WHY. `loadWithLog` exists specifically so a caller iterating on a
    // `programs.zig` builder can read the verifier's own explanation (see
    // ../SPEC.md's "golden vectors" section) -- this test is the only thing
    // in the module that confirms the kernel actually WRITES into `log_buf`
    // on rejection, rather than the buffer sitting there always empty and
    // `loadWithLog` silently degrading to plain `load`'s worth of signal.
    const insns = [_]Insn{
        Insn.exit(), // r0 never initialized
    };
    const prog: Program = .{ .prog_type = .socket_filter, .insns = &insns };

    var log_buf: [4096]u8 = undefined;
    if (loadWithLog(prog, "MIT", &log_buf, 0)) |fd| {
        _ = linux.close(fd);
        return error.TestUnexpectedResult; // the verifier must NOT accept this
    } else |e| switch (e) {
        error.UnsafeProgram => {
            const msg = std.mem.sliceTo(&log_buf, 0);
            if (msg.len == 0) {
                std.debug.print(
                    "\nLIVE ebpf load test: verifier rejected the program but log_buf stayed empty -- loadWithLog is not actually capturing anything.\n",
                    .{},
                );
                return error.TestUnexpectedResult;
            }
        },
        error.PermissionDenied => return error.SkipZigTest,
        else => return e,
    }
}
