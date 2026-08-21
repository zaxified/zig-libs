// SPDX-License-Identifier: MIT

//! What an internet-facing server does with `sandbox` at startup, right
//! after it has `bind(2)`/`listen(2)`'d and no longer needs most of its
//! privilege: lock further privilege escalation, disable core dumps, cap
//! open files, confine the filesystem view with Landlock, and build (but,
//! here, not install — see below) a seccomp syscall allow-list.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.
//!
//! Note on scope: this example applies every step that is safe to apply to
//! *this* process without terminating it (no-new-privs, rlimits, Landlock).
//! It stops short of calling `seccomp.install` on the running process itself
//! — a real allow-list is specific to one binary's actual syscall footprint,
//! and installing the wrong one here would kill the example instead of
//! demonstrating the API. It still builds and frees a real program via
//! `seccomp.buildDefault`, which is the part a consumer needs the published
//! API to support.

const std = @import("std");
const sandbox = @import("sandbox");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // Step 1: latch no-new-privs. Precondition for Landlock's restrictSelf
    // without CAP_SYS_ADMIN, and for a future seccomp install.
    try sandbox.noNewPrivs();
    std.debug.print("no_new_privs latched\n", .{});

    // Step 2 (optional): drop to an unprivileged uid/gid. A dev box running
    // this example is almost never root, so the expected outcome here is the
    // named permission error, not success — a real server run as root would
    // see this branch succeed instead.
    sandbox.dropPrivileges(.{ .uid = 65534, .gid = 65534 }) catch |err| switch (err) {
        error.SetIdFailed => std.debug.print("privilege drop skipped: not running as root\n", .{}),
        error.DropNotEffective => return err,
    };

    // Step 3: rlimits. A crash must not spill secrets to a core file, and an
    // exhaustion bug must not be free to open unbounded descriptors.
    try sandbox.disableCoreDumps();
    try sandbox.limitOpenFiles(1024);
    std.debug.print("core dumps disabled, open-file limit set to 1024\n", .{});

    // Step 4: Landlock — allow only what the request loop actually touches.
    // Probe the running kernel's ABI first; a pre-5.13 kernel or a disabled
    // LSM must be a reportable condition, not a crash.
    const abi = sandbox.landlockAbiVersion() catch |err| switch (err) {
        error.NotSupported => {
            std.debug.print("landlock unavailable: kernel predates 5.13\n", .{});
            return;
        },
        error.Disabled => {
            std.debug.print("landlock unavailable: LSM disabled at boot\n", .{});
            return;
        },
        else => return err,
    };
    std.debug.print("landlock ABI version {d}\n", .{abi});

    var ruleset = try sandbox.Landlock.init(sandbox.Landlock.access.read_only);
    defer ruleset.deinit();

    // A path that does not exist must fail by name, not by crashing the
    // caller's startup sequence — a typo'd config path is a routine mistake.
    ruleset.allowPath("/this/path/does/not/exist/for/the/example", sandbox.Landlock.access.read_only) catch |err| switch (err) {
        error.PathOpenFailed => std.debug.print("rejected missing allow-path as expected\n", .{}),
        else => return err,
    };

    // The real allow-list entry: a request loop that only ever reads static
    // assets from /tmp needs nothing more than this.
    try ruleset.allowPath("/tmp", sandbox.Landlock.access.read_only);
    try ruleset.restrictSelf();
    std.debug.print("landlock restricted to read-only /tmp\n", .{});

    // Step 5: build the default network-server seccomp allow-list. Built and
    // freed here to exercise the allocator path end to end (see the module
    // doc comment for the full noNewPrivs -> seccomp.install sequence a
    // real, single-purpose server binary runs once it knows its own syscall
    // footprint).
    const prog = try sandbox.seccomp.buildDefault(gpa, .kill_process);
    defer gpa.free(prog);
    std.debug.print("seccomp default allow-list: {d} syscalls, {d} BPF instructions\n", .{ sandbox.seccomp.default_allowlist.len, prog.len });
}
