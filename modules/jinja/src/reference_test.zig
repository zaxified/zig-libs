// SPDX-License-Identifier: MIT
//! LIVE interop against the reference implementation: **Python Jinja2 3.1.x**,
//! rendering the same corpus in a subprocess and compared byte for byte.
//!
//! A template engine that only agrees with itself is nearly worthless as
//! evidence, because the interesting defects are *consistent*: get Python's
//! floor semantics for `%` on negatives wrong in the evaluator and every
//! self-written expectation in this repository still passes while every
//! template ported from a real Jinja deployment renders a different
//! configuration. Only an implementation that has never seen this code sees
//! that, which is why this file — and not the unit tests — is the anchor.
//!
//! Python is a **test oracle run as a subprocess**. Nothing links against it
//! and the library has no dependency on it; the module builds and its unit
//! tests pass on a host with no Python at all (the golden file keeps the
//! conformance assertion alive there).
//!
//! Every test **skips loudly** when python3 or jinja2 is missing — never
//! silently, never as a failure. Set `ZIG_LIBS_VERBOSE_SKIP` to see the reason.
//! To close the gap: `pip install jinja2`.

const std = @import("std");
const testing = std.testing;
const corpus = @import("corpus.zig");
const conform = @import("conform.zig");

fn verboseSkip() bool {
    const v = std.process.Environ.getPosix(std.testing.environ, "ZIG_LIBS_VERBOSE_SKIP") orelse return false;
    return v.len > 0;
}

fn skip(comptime reason: []const u8) error{SkipZigTest} {
    if (verboseSkip()) std.debug.print("SKIPPED: " ++ reason ++ "\n", .{});
    return error.SkipZigTest;
}

fn requireJinja(io: std.Io) error{SkipZigTest}!void {
    var child = std.process.spawn(io, .{
        .argv = &.{ "python3", "-c", "import jinja2" },
        .stdin = .close,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return skip("python3 not found — the live Jinja2 oracle needs it");
    const term = child.wait(io) catch return skip("python3 could not be waited on");
    switch (term) {
        .exited => |code| if (code != 0) return skip("python3 has no `jinja2` module (pip install jinja2)"),
        else => return skip("python3 terminated abnormally"),
    }
}

const driver = @embedFile("testdata/reference.py");

/// Runs the reference over the whole corpus once and returns its raw JSON.
fn runReference(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
    try requireJinja(io);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const corpus_json = try corpus.toJson(gpa);
    defer gpa.free(corpus_json);
    try tmp.dir.writeFile(io, .{ .sub_path = "corpus.json", .data = corpus_json });

    var child = try std.process.spawn(io, .{
        .argv = &.{ "python3", "-c", driver, "corpus.json", "out.json" },
        .cwd = .{ .dir = tmp.dir },
        .stdin = .close,
        .stdout = .ignore,
        .stderr = .pipe,
    });
    var err_buf: [8192]u8 = undefined;
    var err_reader = child.stderr.?.reader(io, &err_buf);
    const stderr = try err_reader.interface.allocRemaining(gpa, .limited(1 << 20));
    defer gpa.free(stderr);
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) {
            std.debug.print("\nreference driver failed:\n{s}\n", .{stderr});
            return error.ReferenceDriverFailed;
        },
        else => return error.ReferenceDriverCrashed,
    }

    const out = try tmp.dir.readFileAlloc(io, "out.json", gpa, .limited(8 << 20));
    errdefer gpa.free(out);

    // Regeneration hook: this is exactly how testdata/golden.json is produced,
    // so the two oracles can never be produced by different procedures.
    if (std.process.Environ.getPosix(std.testing.environ, "ZIG_LIBS_JINJA_REGEN")) |path| {
        if (path.len > 0) {
            var f = try std.Io.Dir.cwd().createFile(io, path, .{});
            defer f.close(io);
            var buf: [4096]u8 = undefined;
            var w = f.writer(io, &buf);
            try w.interface.writeAll(out);
            try w.interface.flush();
            std.debug.print("\nregenerated golden file at {s} ({d} bytes)\n", .{ path, out.len });
        }
    }
    return out;
}

test "reference: every corpus case matches Python Jinja2 byte for byte" {
    const gpa = testing.allocator;
    const raw = try runReference(gpa, testing.io);
    defer gpa.free(raw);

    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, raw, .{});
    defer parsed.deinit();
    const cases = parsed.value.object.get("cases").?;

    var failures: usize = 0;
    var checked: usize = 0;
    for (corpus.cases) |c| {
        const ref = conform.refOutcome(cases, c.name) orelse return error.ReferenceSkippedCase;
        checked += 1;
        conform.expectMatch(gpa, c, ref, "live") catch {
            failures += 1;
        };
    }
    if (failures != 0) {
        std.debug.print("\nlive reference: {d} of {d} cases failed\n", .{ failures, checked });
        return error.ReferenceMismatch;
    }
    try testing.expectEqual(corpus.cases.len, checked);
}

test "reference: the committed golden file still matches the live reference" {
    const gpa = testing.allocator;
    const raw = try runReference(gpa, testing.io);
    defer gpa.free(raw);

    var live = try std.json.parseFromSlice(std.json.Value, gpa, raw, .{});
    defer live.deinit();
    var stored = try std.json.parseFromSlice(std.json.Value, gpa, @import("golden_test.zig").golden_json, .{});
    defer stored.deinit();

    const live_cases = live.value.object.get("cases").?;
    const stored_cases = stored.value.object.get("cases").?;

    var mismatches: usize = 0;
    for (corpus.cases) |c| {
        const a = conform.refOutcome(live_cases, c.name).?;
        const b = conform.refOutcome(stored_cases, c.name) orelse {
            std.debug.print("\ngolden has no entry for '{s}'\n", .{c.name});
            mismatches += 1;
            continue;
        };
        if (a.ok != b.ok or !std.mem.eql(u8, a.out, b.out)) {
            std.debug.print("\ngolden drifted from the live reference for '{s}'\n", .{c.name});
            mismatches += 1;
        }
    }
    if (mismatches != 0) return error.GoldenDrift;
}
