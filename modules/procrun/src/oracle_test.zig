// SPDX-License-Identifier: MIT
//! External evidence for procrun: replay of Python `subprocess` results.
//!
//! `oracle_scenarios.json` is the scenario table; `oracle_results.json` is the
//! FROZEN output of `tools/oracle/run_python.py` (Python's `subprocess.run`
//! driven through the very same table). This test runs every scenario through
//! procrun and compares field by field. Python is not needed at test time;
//! re-freeze with `python3 -I tools/oracle/run_python.py` only when the table
//! changes, and read the diff of the results file.
//!
//! Scenario fields (all optional but `name`/`argv`):
//!   argv            program + args; `{FD}` is replaced by the marker fd number
//!   stdin           "default" (procrun's default; Python side: DEVNULL) | "pipe"
//!   stdin_len       pipe body: that many bytes of the pattern byte(i) = i*31+7
//!   stdin_text      pipe body: literal text
//!   merge_stderr    stderr into stdout (`.stdout` / `stderr=STDOUT`)
//!   env_mode        "inherit" | "clear" | "merge"; env = overlay variables
//!   cwd             working directory (relative paths resolve against the parent's)
//!   cap             `max_output_bytes`; Python has no cap, so the frozen result
//!                   holds the SHA-256 of its first `cap` bytes and procrun must
//!                   return exactly that prefix, flagged `truncated_*`
//!   timeout_ms      `runTimeout` / Python `timeout=`
//!   new_group       `new_process_group` / Python `process_group=0`
//!   marker          "inheritable" | "cloexec": the harness opens a file and the
//!                   child probes /proc/self/fd/{FD}
//!   pass_marker     `pass_fds` / Python `pass_fds`
//!   py_close_fds    Python's `close_fds` (default true; procrun has no such knob)
//!   post            "nul_set" (stdout = sorted NUL-separated items, filtered by
//!                   `prefix`) | "cwd_parent" (stdout equal to the parent's cwd
//!                   becomes "PARENT")
//!   diff            a DELIBERATE difference to Python, with the reason; requires
//!                   `procrun_override`, the value procrun is expected to give
//!                   (and the test checks it really differs from Python's)
//! Python-only quirks of the driver are documented in run_python.py.

const std = @import("std");
const builtin = @import("builtin");
const procrun = @import("root.zig");
const testing = std.testing;

const scenarios_json = @embedFile("oracle_scenarios.json");
const results_json = @embedFile("oracle_results.json");

const Override = struct {
    kind: ?[]const u8 = null,
    code: ?i64 = null,
    err: ?[]const u8 = null,
    stdout_text: ?[]const u8 = null,
    stderr_text: ?[]const u8 = null,
};

const Scenario = struct {
    name: []const u8,
    argv: []const []const u8,
    stdin: []const u8 = "default",
    stdin_len: ?usize = null,
    stdin_text: []const u8 = "",
    merge_stderr: bool = false,
    env_mode: []const u8 = "inherit",
    env: std.json.ArrayHashMap([]const u8) = .{},
    cwd: ?[]const u8 = null,
    cap: ?usize = null,
    timeout_ms: ?u64 = null,
    new_group: bool = false,
    marker: []const u8 = "none",
    pass_marker: bool = false,
    py_close_fds: bool = true,
    post: []const u8 = "none",
    prefix: []const u8 = "",
    diff: ?[]const u8 = null,
    procrun_override: ?Override = null,
};

const Result = struct {
    kind: []const u8,
    code: i64 = 0,
    err: []const u8 = "",
    timed_out: bool = false,
    stdout_len: u64 = 0,
    stdout_sha256: []const u8 = "",
    stdout_cap_sha256: []const u8 = "",
    stdout_text: ?[]const u8 = null,
    stderr_len: u64 = 0,
    stderr_sha256: []const u8 = "",
    stderr_text: ?[]const u8 = null,
};

const Scenarios = struct { scenarios: []const Scenario };
const Results = struct {
    python: []const u8,
    results: std.json.ArrayHashMap(Result),
};

fn shaHex(data: []const u8) [64]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &h, .{});
    return std.fmt.bytesToHex(h, .lower);
}

fn monoNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// The same post-processing as `post()` in run_python.py.
fn postProcess(arena: std.mem.Allocator, sc: Scenario, data: []const u8, parent_cwd: []const u8) ![]const u8 {
    if (std.mem.eql(u8, sc.post, "nul_set")) {
        var items: std.ArrayList([]const u8) = .empty;
        var it = std.mem.splitScalar(u8, data, 0);
        while (it.next()) |item| {
            if (item.len == 0 or !std.mem.startsWith(u8, item, sc.prefix)) continue;
            try items.append(arena, item);
        }
        std.mem.sort([]const u8, items.items, {}, struct {
            fn lt(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lt);
        return std.mem.join(arena, "\n", items.items);
    }
    if (std.mem.eql(u8, sc.post, "cwd_parent")) {
        if (std.mem.eql(u8, std.mem.trimEnd(u8, data, "\n"), parent_cwd)) return "PARENT\n";
    }
    return data;
}

const Checker = struct {
    name: []const u8,
    failures: *usize,

    fn expect(c: Checker, ok: bool, comptime fmt: []const u8, args: anytype) void {
        if (ok) return;
        c.failures.* += 1;
        std.debug.print("oracle mismatch [{s}]: " ++ fmt ++ "\n", .{c.name} ++ args);
    }
};

fn checkStream(
    c: Checker,
    comptime which: []const u8,
    got: []const u8,
    truncated: bool,
    cap: ?usize,
    exp_len: u64,
    exp_sha: []const u8,
    exp_cap_sha: []const u8,
    exp_text: ?[]const u8,
    override_text: ?[]const u8,
) void {
    if (override_text) |t| { // deliberate difference: compare the text only
        c.expect(std.mem.eql(u8, got, t), which ++ " differs from the documented override: got {d} bytes", .{got.len});
        return;
    }
    if (cap) |n| {
        const want_len = @min(@as(u64, n), exp_len);
        c.expect(got.len == want_len, which ++ " length {d} != capped {d}", .{ got.len, want_len });
        c.expect(truncated == (exp_len > n), which ++ " truncated flag {} for python length {d}, cap {d}", .{ truncated, exp_len, n });
        if (std.mem.eql(u8, which, "stdout")) {
            const h = shaHex(got);
            c.expect(std.mem.eql(u8, &h, exp_cap_sha), which ++ " capped prefix is not the prefix of python's output", .{});
        }
        return;
    }
    c.expect(!truncated, which ++ " unexpectedly truncated", .{});
    c.expect(got.len == exp_len, which ++ " length {d} != python {d}", .{ got.len, exp_len });
    const h = shaHex(got);
    c.expect(std.mem.eql(u8, &h, exp_sha), which ++ " sha256 differs (length {d})", .{got.len});
    if (exp_text) |t| c.expect(std.mem.eql(u8, got, t), which ++ " text differs: got \"{s}\" want \"{s}\"", .{ got, t });
}

fn runScenario(
    gpa: std.mem.Allocator,
    io: std.Io,
    sc: Scenario,
    exp: Result,
    parent_cwd: []const u8,
    failures: *usize,
) !void {
    const c: Checker = .{ .name = sc.name, .failures = failures };
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Marker fd (fd_* scenarios).
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var marker: ?std.Io.File = null;
    defer if (marker) |f| f.close(io);
    if (!std.mem.eql(u8, sc.marker, "none")) {
        try tmp.dir.writeFile(io, .{ .sub_path = "orc_marker", .data = "marker" });
        const f = try tmp.dir.openFile(io, "orc_marker", .{}); // O_CLOEXEC
        marker = f;
        if (std.mem.eql(u8, sc.marker, "inheritable")) {
            // The deliberate leak: a descriptor the caller forgot to mark CLOEXEC.
            const rc = std.posix.system.fcntl(f.handle, std.posix.F.SETFD, @as(u32, 0));
            try testing.expectEqual(std.posix.E.SUCCESS, std.posix.errno(rc));
        }
    }

    var fd_buf: [16]u8 = undefined;
    const fd_text = if (marker) |f| try std.fmt.bufPrint(&fd_buf, "{d}", .{f.handle}) else "";
    const argv = try arena.alloc([]const u8, sc.argv.len);
    for (sc.argv, 0..) |a, i| argv[i] = try std.mem.replaceOwned(u8, arena, a, "{FD}", fd_text);

    var env_map = std.process.Environ.Map.init(arena);
    var it = sc.env.map.iterator();
    while (it.next()) |e| try env_map.put(e.key_ptr.*, e.value_ptr.*);

    const piped = std.mem.eql(u8, sc.stdin, "pipe");
    var body: []const u8 = sc.stdin_text;
    if (sc.stdin_len) |n| {
        const buf = try arena.alloc(u8, n);
        for (buf, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
        body = buf;
    }

    const pass = [_]std.Io.File{if (marker) |f| f else undefined};
    const spec: procrun.Spec = .{
        .argv = argv,
        .env = &env_map,
        .env_mode = if (std.mem.eql(u8, sc.env_mode, "clear")) .clear else if (std.mem.eql(u8, sc.env_mode, "merge")) .merge else .inherit,
        .cwd = sc.cwd,
        .stdin = if (piped) .pipe else .ignore, // = the default, spelled out
        .stderr = if (sc.merge_stderr) .stdout else .pipe,
        .max_output_bytes = sc.cap orelse procrun.default_max_output_bytes,
        .new_process_group = sc.new_group,
        .pass_fds = if (sc.pass_marker) pass[0..1] else &.{},
    };

    const t0 = monoNs();
    var out = (if (sc.timeout_ms) |t|
        procrun.runTimeout(gpa, io, spec, body, t * std.time.ns_per_ms)
    else
        procrun.run(gpa, io, spec, body)) catch |e| {
        // An error outcome: compare its name.
        const want_kind = if (sc.procrun_override) |o| (o.kind orelse exp.kind) else exp.kind;
        const want_err = if (sc.procrun_override) |o| (o.err orelse exp.err) else exp.err;
        c.expect(std.mem.eql(u8, want_kind, "error"), "procrun failed with error.{s} but python did not (kind {s})", .{ @errorName(e), want_kind });
        c.expect(std.mem.eql(u8, want_err, @errorName(e)), "error.{s} != expected {s}", .{ @errorName(e), want_err });
        return;
    };
    defer out.deinit(gpa);
    const elapsed = monoNs() - t0;

    const ov: Override = sc.procrun_override orelse .{};
    const want_kind = ov.kind orelse exp.kind;
    const want_code = ov.code orelse exp.code;
    c.expect(!std.mem.eql(u8, want_kind, "error"), "python/expected error.{s} but procrun ran the child (term {any})", .{ exp.err, out.term });
    if (std.mem.eql(u8, want_kind, "exited")) {
        c.expect(out.term == .exited and out.term.exited == want_code, "term {any} != exited {d}", .{ out.term, want_code });
    } else if (std.mem.eql(u8, want_kind, "signal")) {
        c.expect(out.term == .signal and @as(i64, @backingInt(out.term.signal)) == want_code, "term {any} != signal {d}", .{ out.term, want_code });
    }
    if (std.mem.startsWith(u8, sc.name, "sig_") and out.term == .signal) {
        // WCOREDUMP is host policy (a piped core_pattern sets it even with
        // RLIMIT_CORE 0), so the ground truth is an independent reap of the
        // same command, not the frozen Python file (Python has no such field).
        const truth = try rawCoreFlag(io, argv);
        c.expect(out.core_dumped == truth, "core_dumped {} but the raw wait status says {}", .{ out.core_dumped, truth });
    } else {
        c.expect(!out.core_dumped, "core_dumped set without a core-dumping signal", .{});
    }
    c.expect(out.timed_out == exp.timed_out, "timed_out {} != python {}", .{ out.timed_out, exp.timed_out });
    c.expect(!out.canceled, "canceled set without a token", .{});
    if (sc.timeout_ms) |t| c.expect(elapsed < (t + 3000) * std.time.ns_per_ms, "took {d} ms past a {d} ms timeout", .{ elapsed / std.time.ns_per_ms, t });
    if (out.term == .exited or out.term == .signal) c.expect(out.rusage != null, "no rusage after a normal reap", .{});

    const so = try postProcess(arena, sc, out.stdout, parent_cwd);
    checkStream(c, "stdout", so, out.truncated_stdout, sc.cap, exp.stdout_len, exp.stdout_sha256, exp.stdout_cap_sha256, exp.stdout_text, ov.stdout_text);
    checkStream(c, "stderr", out.stderr, out.truncated_stderr, sc.cap, exp.stderr_len, exp.stderr_sha256, "", exp.stderr_text, ov.stderr_text);
}

/// Spawn `argv` through std and reap it with a bare `wait4`, returning the
/// kernel's WCOREDUMP bit: ground truth that does not share code with procrun.
fn rawCoreFlag(io: std.Io, argv: []const []const u8) !bool {
    const child = try std.process.spawn(io, .{ .argv = argv, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore });
    var status: i32 = undefined;
    while (true) {
        const rc = std.os.linux.wait4(child.id.?, &status, 0, null);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
    const st: u32 = @bitCast(status);
    return std.posix.W.IFSIGNALED(st) and (st & 0x80) != 0;
}

fn countZombieChildren(io: std.Io, gpa: std.mem.Allocator) !usize {
    var dir = try std.Io.Dir.openDirAbsolute(io, "/proc", .{ .iterate = true });
    defer dir.close(io);
    const me = std.os.linux.getpid();
    var n: usize = 0;
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        _ = std.fmt.parseInt(u32, e.name, 10) catch continue;
        const path = try std.fmt.allocPrint(gpa, "/proc/{s}/stat", .{e.name});
        defer gpa.free(path);
        const stat = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(4096)) catch continue;
        defer gpa.free(stat);
        // "pid (comm) S ppid ...": comm may contain anything, so cut at the LAST ')'.
        const close = std.mem.lastIndexOfScalar(u8, stat, ')') orelse continue;
        var f = std.mem.tokenizeScalar(u8, stat[close + 1 ..], ' ');
        const state = f.next() orelse continue;
        const ppid = std.fmt.parseInt(i32, f.next() orelse continue, 10) catch continue;
        if (ppid == me and state[0] == 'Z') n += 1;
    }
    return n;
}

fn countOpenFds(io: std.Io) !usize {
    var dir = try std.Io.Dir.openDirAbsolute(io, "/proc/self/fd", .{ .iterate = true });
    defer dir.close(io);
    var n: usize = 0;
    var it = dir.iterate();
    while (try it.next(io)) |_| n += 1;
    return n;
}

test "oracle: procrun agrees with the frozen Python subprocess results" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var sp = try std.json.parseFromSlice(Scenarios, gpa, scenarios_json, .{});
    defer sp.deinit();
    var rp = try std.json.parseFromSlice(Results, gpa, results_json, .{});
    defer rp.deinit();

    const parent_cwd = try std.process.currentPathAlloc(io, gpa);
    defer gpa.free(parent_cwd);

    var failures: usize = 0;
    var seen: usize = 0;
    for (sp.value.scenarios) |sc| {
        const exp = rp.value.results.map.get(sc.name) orelse {
            std.debug.print("oracle: scenario {s} has no frozen result -- re-run tools/oracle/run_python.py\n", .{sc.name});
            failures += 1;
            continue;
        };
        // A documented difference must be real, or the table has gone stale.
        if (sc.diff != null) {
            const ov = sc.procrun_override orelse {
                std.debug.print("oracle: {s} has `diff` without `procrun_override`\n", .{sc.name});
                failures += 1;
                continue;
            };
            const same = (ov.stdout_text != null and exp.stdout_text != null and std.mem.eql(u8, ov.stdout_text.?, exp.stdout_text.?)) or
                (ov.kind != null and std.mem.eql(u8, ov.kind.?, exp.kind) and ov.code == null);
            if (same) {
                std.debug.print("oracle: {s} is listed as a difference but the override equals python's value\n", .{sc.name});
                failures += 1;
            }
        } else if (sc.procrun_override != null) {
            std.debug.print("oracle: {s} has an override without a `diff` reason\n", .{sc.name});
            failures += 1;
        }
        try runScenario(gpa, io, sc, exp, parent_cwd, &failures);
        seen += 1;
    }
    try testing.expect(seen >= 50);
    try testing.expectEqual(@as(usize, 0), failures);
}

test "oracle invariants: no zombie children and a stable fd count over many runs" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Case = struct {
        fn one(g: std.mem.Allocator, jo: std.Io, n: usize) !void {
            switch (n % 5) {
                0 => {
                    var o = try procrun.run(g, jo, .{ .argv = &.{ "/bin/sh", "-c", "echo out; echo err >&2" } }, "");
                    o.deinit(g);
                },
                1 => {
                    var o = try procrun.run(g, jo, .{ .argv = &.{"/bin/cat"}, .stdin = .pipe, .stderr = .stdout }, "payload");
                    o.deinit(g);
                },
                2 => {
                    var o = try procrun.runTimeout(g, jo, .{ .argv = &.{ "/usr/bin/sleep", "30" }, .new_process_group = true }, "", 20 * std.time.ns_per_ms);
                    o.deinit(g);
                },
                3 => try testing.expectError(error.FileNotFound, procrun.run(g, jo, .{ .argv = &.{"/nonexistent/orc_prog"} }, "")),
                else => {
                    var o = try procrun.run(g, jo, .{ .argv = &.{"/bin/true"}, .stdout = .ignore, .stderr = .ignore }, "");
                    o.deinit(g);
                },
            }
        }
    };

    // Warm-up: lazily created process-wide descriptors must not count as a leak.
    for (0..10) |i| try Case.one(gpa, io, i);
    const zombies_before = try countZombieChildren(io, gpa);
    var leaks: usize = 0;
    for (0..5) |kind| {
        const before = try countOpenFds(io);
        for (0..20) |r| try Case.one(gpa, io, kind + 5 * r);
        const after = try countOpenFds(io);
        if (after != before) {
            std.debug.print("fd leak in case {d}: {d} -> {d} over 20 runs\n", .{ kind, before, after });
            leaks += 1;
        }
    }
    const zombies_after = try countZombieChildren(io, gpa);

    try testing.expectEqual(@as(usize, 0), leaks);
    try testing.expectEqual(zombies_before, zombies_after);
    try testing.expectEqual(@as(usize, 0), zombies_after);
}
