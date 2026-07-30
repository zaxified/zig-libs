// SPDX-License-Identifier: MIT
//! The external anchor: **yaml-test-suite**, run in full against a committed
//! ledger.
//!
//! Every other test in this module was written by the same hands that wrote the
//! parser, so all of them share whatever this code misreads about YAML 1.2.
//! This one does not: `github.com/yaml/yaml-test-suite` (`data` branch) ships
//! 402 cases, each with a byte-exact expected event dump produced by a parser
//! that has never seen this code, and 94 inputs that must be *rejected*.
//!
//! The suite is not vendored — it is a separate repository with its own
//! history, and pinning a copy here would turn a live oracle into a stale one.
//! Fetch it and point `ZIG_LIBS_YAML_SUITE` at the checkout:
//!
//! ```
//! git clone -b data --depth 1 https://github.com/yaml/yaml-test-suite \
//!     ~/.cache/zig-libs-yaml/yaml-test-suite-data
//! ```
//!
//! Without it these tests **skip loudly** (`SKIPPED: …` + `error.SkipZigTest`),
//! never silently.
//!
//! ## Why a ledger and not just a pass count
//!
//! A count can be met by a parser that passes a different 402 cases than it did
//! yesterday. `testdata/ledger.txt` names every case and the outcome claimed for
//! it, and the assertion runs in both directions: a listed pass that fails is
//! red, and a known-fail that starts passing is red too. The id set must equal
//! the suite's exactly, so a case added or removed upstream is red as well. A
//! ledger that is allowed to be approximately true is worse than no ledger.

const std = @import("std");
const testing = std.testing;
const yaml = @import("root.zig");

const ledger_text = @embedFile("testdata/ledger.txt");

const default_suite = ".cache/zig-libs-yaml/yaml-test-suite-data";

/// One ledger line.
const Expect = enum {
    /// Parses; the event dump must equal `test.event` byte for byte.
    event,
    /// The suite marks the input invalid; we must return an error.
    reject,
    /// Known-fail: the case must NOT reach the outcome the suite asks for.
    fail,
};

const Entry = struct {
    id: []const u8,
    expect: Expect,
    reason: []const u8,
};

fn parseLedger(gpa: std.mem.Allocator) ![]Entry {
    var out: std.ArrayList(Entry) = .empty;
    errdefer out.deinit(gpa);
    var lines = std.mem.splitScalar(u8, ledger_text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var it = std.mem.tokenizeAny(u8, line, " \t");
        const kind = it.next() orelse return error.MalformedLedger;
        const id = it.next() orelse return error.MalformedLedger;
        const expect: Expect = if (std.mem.eql(u8, kind, "event"))
            .event
        else if (std.mem.eql(u8, kind, "reject"))
            .reject
        else if (std.mem.eql(u8, kind, "fail"))
            .fail
        else
            return error.MalformedLedger;
        const reason = std.mem.trim(u8, it.rest(), " \t");
        // A known-fail with no specific reason is exactly the rot this file
        // exists to prevent.
        if (expect == .fail and reason.len == 0) return error.KnownFailNeedsReason;
        try out.append(gpa, .{ .id = id, .expect = expect, .reason = reason });
    }
    return out.toOwnedSlice(gpa);
}

fn hasInput(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, name: []const u8) !bool {
    const p = try std.fmt.allocPrint(gpa, "{s}/in.yaml", .{name});
    defer gpa.free(p);
    dir.access(io, p, .{}) catch return false;
    return true;
}

/// Case directories are those containing `in.yaml`. Most are one level down
/// (`229Q/`), but 69 are nested one deeper (`UKK6/00/`), so both depths are
/// collected rather than assuming a fixed shape.
fn collectCases(gpa: std.mem.Allocator, io: std.Io, root: std.Io.Dir, out: *std.ArrayList([]u8)) !void {
    var dir = try root.openDir(io, ".", .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .directory) continue;
        if (try hasInput(gpa, io, root, e.name)) {
            try out.append(gpa, try gpa.dupe(u8, e.name));
            continue;
        }
        var sub = root.openDir(io, e.name, .{ .iterate = true }) catch continue;
        defer sub.close(io);
        var sit = sub.iterate();
        while (try sit.next(io)) |se| {
            if (se.kind != .directory) continue;
            if (try hasInput(gpa, io, sub, se.name))
                try out.append(gpa, try std.fmt.allocPrint(gpa, "{s}/{s}", .{ e.name, se.name }));
        }
    }
}

fn suitePath(gpa: std.mem.Allocator) !?[]u8 {
    const env = testing.environ;
    if (std.process.Environ.getPosix(env, "ZIG_LIBS_YAML_SUITE")) |p| {
        if (p.len > 0) return try gpa.dupe(u8, p);
    }
    const home = std.process.Environ.getPosix(env, "HOME") orelse return null;
    return try std.fs.path.join(gpa, &.{ home, default_suite });
}

fn openSuite(gpa: std.mem.Allocator, io: std.Io) !?std.Io.Dir {
    const path = (try suitePath(gpa)) orelse {
        std.debug.print("\nSKIPPED: yaml-test-suite anchor: neither ZIG_LIBS_YAML_SUITE nor HOME is set.\n", .{});
        return null;
    };
    defer gpa.free(path);
    return std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch {
        std.debug.print(
            "\nSKIPPED: yaml-test-suite anchor: no suite at '{s}'.\n" ++
                "  git clone -b data --depth 1 https://github.com/yaml/yaml-test-suite ~/{s}\n" ++
                "  (or set ZIG_LIBS_YAML_SUITE to an existing checkout)\n",
            .{ path, default_suite },
        );
        return null;
    };
}

fn readCaseFile(gpa: std.mem.Allocator, io: std.Io, root: std.Io.Dir, id: []const u8, name: []const u8) ![]u8 {
    const p = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ id, name });
    defer gpa.free(p);
    return root.readFileAlloc(io, p, gpa, .limited(1 << 20));
}

fn caseIsError(gpa: std.mem.Allocator, io: std.Io, root: std.Io.Dir, id: []const u8) !bool {
    const p = try std.fmt.allocPrint(gpa, "{s}/error", .{id});
    defer gpa.free(p);
    root.access(io, p, .{}) catch return false;
    return true;
}

fn lessThanSlice(_: void, a: []u8, b: []u8) bool {
    return std.mem.lessThan(u8, a, b);
}

test "yaml-test-suite: every case reaches exactly its ledger outcome" {
    const gpa = testing.allocator;
    const io = testing.io;

    const entries = try parseLedger(gpa);
    defer gpa.free(entries);

    var root = (try openSuite(gpa, io)) orelse return error.SkipZigTest;
    defer root.close(io);

    var ids: std.ArrayList([]u8) = .empty;
    defer {
        for (ids.items) |i| gpa.free(i);
        ids.deinit(gpa);
    }
    try collectCases(gpa, io, root, &ids);
    std.mem.sort([]u8, ids.items, {}, lessThanSlice);

    // ── direction 1: the id sets must be equal ──────────────────────────────
    // Without this the ledger could go stale by omission: a case the suite
    // gains would simply never run, and one it loses would never be noticed.
    var listed: std.StringHashMapUnmanaged(Entry) = .empty;
    defer listed.deinit(gpa);
    for (entries) |e| {
        const prev = try listed.fetchPut(gpa, e.id, e);
        if (prev != null) {
            std.debug.print("ledger lists '{s}' twice\n", .{e.id});
            return error.DuplicateLedgerEntry;
        }
    }
    var set_bad: usize = 0;
    for (ids.items) |id| {
        if (listed.get(id) == null) {
            std.debug.print("suite case '{s}' is not in the ledger\n", .{id});
            set_bad += 1;
        }
    }
    for (entries) |e| {
        const found = for (ids.items) |id| {
            if (std.mem.eql(u8, id, e.id)) break true;
        } else false;
        if (!found) {
            std.debug.print("ledger lists '{s}', which the suite does not have\n", .{e.id});
            set_bad += 1;
        }
    }
    if (set_bad != 0) return error.LedgerIdSetMismatch;

    // ── direction 2: every case reaches exactly its listed outcome ──────────
    var off_ledger: usize = 0;
    var unexpectedly_passing: usize = 0;
    for (ids.items) |id| {
        const entry = listed.get(id).?;

        const src = try readCaseFile(gpa, io, root, id, "in.yaml");
        defer gpa.free(src);
        const must_error = try caseIsError(gpa, io, root, id);

        // The ledger's own event/reject classification is checked against the
        // suite too, so an upstream case that flips from valid to invalid
        // cannot hide behind a still-green assertion.
        if (entry.expect != .fail and (entry.expect == .reject) != must_error) {
            std.debug.print("{s}: ledger says {s}, suite says {s}\n", .{
                id,
                @tagName(entry.expect),
                if (must_error) "must-reject" else "must-parse",
            });
            off_ledger += 1;
            continue;
        }

        const got: ?[]u8 = yaml.dumpEvents(gpa, src) catch null;
        defer if (got) |g| gpa.free(g);

        const reached: bool = if (must_error) got == null else blk: {
            const g = got orelse break :blk false;
            const want = try readCaseFile(gpa, io, root, id, "test.event");
            defer gpa.free(want);
            break :blk std.mem.eql(u8, g, want);
        };

        switch (entry.expect) {
            .event, .reject => if (!reached) {
                std.debug.print("{s}: ledger says {s}, but the case does not pass\n", .{ id, @tagName(entry.expect) });
                off_ledger += 1;
            },
            // A known-fail that starts passing is as red as a regression:
            // silently-improving ledgers are how a ledger becomes a lie.
            .fail => if (reached) {
                std.debug.print("{s}: ledger says KNOWN-FAIL ({s}) but it passes now — update the ledger\n", .{ id, entry.reason });
                unexpectedly_passing += 1;
            },
        }
    }

    if (off_ledger != 0 or unexpectedly_passing != 0) {
        std.debug.print("\nyaml-test-suite: {d} case(s) off the ledger, {d} known-fail(s) now passing, of {d}\n", .{ off_ledger, unexpectedly_passing, ids.items.len });
        return error.LedgerMismatch;
    }
}

test "the ledger itself is well formed" {
    const gpa = testing.allocator;
    const entries = try parseLedger(gpa);
    defer gpa.free(entries);
    // Guards the harness against a ledger truncated to nothing, which would
    // make every assertion above vacuously true.
    try testing.expect(entries.len >= 400);
    var rejects: usize = 0;
    for (entries) |e| {
        try testing.expect(e.id.len > 0);
        if (e.expect == .reject) rejects += 1;
        if (e.expect == .fail) try testing.expect(e.reason.len > 0);
    }
    try testing.expect(rejects >= 90);
}
