// SPDX-License-Identifier: MIT
//! The Python Jinja2 oracle behind `src/reference_replay_test.zig` — the
//! instrument that TAKES the conformance anchor, kept outside the module.
//!
//! ## Why this is a program and not a test
//!
//! A template engine that only agrees with itself is nearly worthless as
//! evidence, because the interesting defects are *consistent*: get Python's
//! floor semantics for `%` on negatives wrong in the evaluator and every
//! self-written expectation in this repository still passes while every
//! template ported from a real Jinja deployment renders a different
//! configuration. Only an implementation that has never seen this code sees
//! that — so the anchor matters, and it needs a `python3` with `jinja2`.
//!
//! A module in this repository is standalone Zig with no external dependency.
//! Until 2026-09-06 those two facts were reconciled by `@embedFile`ing the
//! Python driver into module source and spawning it from inside
//! `zig build test-jinja`, which skipped loudly when the peer was missing. A
//! skip is not an assertion, and CI's peer install is `continue-on-error`, so
//! the arrangement cost every consumer a copy of foreign source and still might
//! assert nothing.
//!
//! The split, per `build.zig`'s interop mechanism:
//!
//!   * this program renders `tools/corpus.zig` with the reference and CAPTURES
//!     every case — inputs *and* output — into `src/testdata/golden.json`;
//!   * `src/reference_replay_test.zig` replays that file with no Python
//!     anywhere, which is where the anchor's value now runs;
//!   * `zig build check-interop` compiles this file and runs nothing, so the
//!     instrument cannot rot unnoticed.
//!
//! ## What only this program can find
//!
//! The replay test compares *this engine* against the transcript. What it
//! cannot see is the reference CHANGING — a Jinja2 upgrade, a different
//! MarkupSafe, a fix upstream that moves a rendered byte. That is what the live
//! mode here is for, and why it is a pre-release check rather than a
//! per-commit one.
//!
//! ## Usage
//!
//! ```sh
//! zig build interop-jinja                # live: reference vs the committed
//!                                        # transcript, exit 1 on drift
//! zig build interop-jinja -- --capture   # re-take the transcript
//! ```
//!
//! Needs `python3` with `jinja2`; without it the program exits non-zero and
//! says so, which is the difference between an instrument and a skip.

const std = @import("std");
const corpus = @import("corpus.zig");

const default_fixture = "modules/jinja/src/testdata/golden.json";
const default_driver = "modules/jinja/tools/reference.py";
const default_scratch = ".zig-cache/interop-jinja";

/// Pinned in the child's environment and recorded in the transcript header, so
/// a capture is reproducible rather than a function of whoever ran it.
const pinned_env = [_][2][]const u8{
    // Hash randomisation: irrelevant to Jinja's insertion-ordered dicts today,
    // pinned so that "today" is a claim the artifact records rather than one
    // this comment makes.
    .{ "PYTHONHASHSEED", "0" },
    .{ "LC_ALL", "C" },
    .{ "LANG", "C" },
    .{ "TZ", "UTC" },
};

const usage =
    \\usage: zig build interop-jinja [-- <options>]
    \\
    \\  (no options)        render the corpus with Python Jinja2 and diff it
    \\                      against the committed transcript; exit 1 on drift
    \\  --capture           render and rewrite the transcript
    \\  --fixture <path>    transcript path (default modules/jinja/src/testdata/…)
    \\  --driver <path>     the Python driver (default modules/jinja/tools/…)
    \\  --scratch <dir>     scratch directory (default .zig-cache/interop-jinja)
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var capture = false;
    var fixture_path: []const u8 = default_fixture;
    var driver_path: []const u8 = default_driver;
    var scratch: []const u8 = default_scratch;

    var args = init.args.iterate();
    _ = args.next(); // argv[0]
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--capture")) {
            capture = true;
        } else if (std.mem.eql(u8, a, "--fixture")) {
            fixture_path = args.next() orelse return usageError();
        } else if (std.mem.eql(u8, a, "--driver")) {
            driver_path = args.next() orelse return usageError();
        } else if (std.mem.eql(u8, a, "--scratch")) {
            scratch = args.next() orelse return usageError();
        } else {
            return usageError();
        }
    }

    const produced = runReference(gpa, io, init, driver_path, scratch) catch |e| switch (e) {
        error.NoPeer => return 1,
        else => return e,
    };
    defer gpa.free(produced);

    if (capture) {
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = fixture_path, .data = produced });
        std.debug.print("captured {d} cases ({d} bytes) to {s}\n", .{ corpus.cases.len, produced.len, fixture_path });
        return 0;
    }

    const stored = std.Io.Dir.cwd().readFileAlloc(io, fixture_path, gpa, .limited(32 << 20)) catch |e| {
        std.debug.print("cannot read {s}: {t} (run with --capture to create it)\n", .{ fixture_path, e });
        return 1;
    };
    defer gpa.free(stored);

    return compare(gpa, produced, stored, fixture_path);
}

/// Renders the whole corpus with the reference. Returns the driver's JSON.
fn runReference(
    gpa: std.mem.Allocator,
    io: std.Io,
    init: std.process.Init.Minimal,
    driver: []const u8,
    scratch: []const u8,
) ![]u8 {
    try std.Io.Dir.cwd().createDirPath(io, scratch);
    const in_path = try std.fmt.allocPrint(gpa, "{s}/corpus.json", .{scratch});
    defer gpa.free(in_path);
    const out_path = try std.fmt.allocPrint(gpa, "{s}/out.json", .{scratch});
    defer gpa.free(out_path);

    const corpus_json = try corpus.toJson(gpa);
    defer gpa.free(corpus_json);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = in_path, .data = corpus_json });
    std.Io.Dir.cwd().deleteFile(io, out_path) catch {};

    var env = try std.process.Environ.createMap(init.environ, gpa);
    defer env.deinit();
    for (pinned_env) |kv| try env.put(kv[0], kv[1]);

    var child = std.process.spawn(io, .{
        .argv = &.{ "python3", driver, in_path, out_path },
        .environ_map = &env,
        .stdin = .close,
        .stdout = .ignore,
        .stderr = .pipe,
    }) catch |e| {
        std.debug.print(
            "cannot run `python3 {s}`: {t}\n" ++
                "This program needs python3 with jinja2 (pip install jinja2), and it must\n" ++
                "be run from the repository root so the driver path resolves.\n",
            .{ driver, e },
        );
        return error.NoPeer;
    };
    var err_buf: [8192]u8 = undefined;
    var err_reader = child.stderr.?.reader(io, &err_buf);
    const stderr = try err_reader.interface.allocRemaining(gpa, .limited(1 << 20));
    defer gpa.free(stderr);
    switch (try child.wait(io)) {
        .exited => |code| if (code != 0) {
            std.debug.print("reference driver failed:\n{s}\n", .{stderr});
            return error.NoPeer;
        },
        else => return error.ReferenceCrashed,
    }
    return std.Io.Dir.cwd().readFileAlloc(io, out_path, gpa, .limited(32 << 20));
}

/// Diffs a fresh reference run against the committed transcript. Everything is
/// compared: the inputs (so a corpus edit shows up as coverage that is not
/// captured yet) and the outcome (so a moved byte shows up at all).
fn compare(gpa: std.mem.Allocator, produced: []const u8, stored: []const u8, path: []const u8) !u8 {
    var live = try std.json.parseFromSlice(std.json.Value, gpa, produced, .{});
    defer live.deinit();
    var old = try std.json.parseFromSlice(std.json.Value, gpa, stored, .{});
    defer old.deinit();

    inline for (.{ "jinja2", "markupsafe", "python" }) |key| {
        const a = live.value.object.get(key).?.string;
        const b = old.value.object.get(key) orelse std.json.Value{ .string = "(absent)" };
        if (!std.mem.eql(u8, a, b.string)) std.debug.print(
            "note: {s} is {s} here, {s} when the transcript was taken\n",
            .{ key, a, b.string },
        );
    }

    const live_cases = live.value.object.get("cases").?.array.items;
    const old_cases = old.value.object.get("cases").?.array.items;

    var stale: usize = 0;
    for (old_cases) |o| {
        const name = o.object.get("name").?.string;
        if (findCase(live_cases, name) == null) {
            std.debug.print("transcript has '{s}', which the corpus no longer defines\n", .{name});
            stale += 1;
        }
    }

    var uncaptured: usize = 0;
    var drift: usize = 0;
    var msg_only: usize = 0;
    for (live_cases) |l| {
        const name = l.object.get("name").?.string;
        const o = findCase(old_cases, name) orelse {
            std.debug.print("corpus case '{s}' is not in the transcript yet\n", .{name});
            uncaptured += 1;
            continue;
        };
        var differing_field: ?[]const u8 = null;
        var it = l.object.iterator();
        while (it.next()) |e| {
            const k = e.key_ptr.*;
            const b = o.object.get(k) orelse {
                differing_field = k;
                break;
            };
            if (jsonEql(e.value_ptr.*, b)) continue;
            // The exception message is Python's prose, not a rendered byte —
            // worth seeing, not worth failing on.
            if (std.mem.eql(u8, k, "msg")) {
                msg_only += 1;
                continue;
            }
            differing_field = k;
            break;
        }
        if (differing_field) |k| {
            std.debug.print("case '{s}': field '{s}' differs from the transcript\n", .{ name, k });
            drift += 1;
        }
    }

    if (msg_only != 0) std.debug.print("\n{d} case(s) differ only in the reference's exception TEXT.\n", .{msg_only});
    if (uncaptured != 0 or stale != 0) std.debug.print(
        "\n{d} corpus case(s) not captured, {d} stale transcript entry/entries — re-capture.\n",
        .{ uncaptured, stale },
    );
    if (drift != 0) {
        std.debug.print(
            "\n{d} divergence(s): the reference no longer renders what {s} records.\n" ++
                "Investigate before re-capturing — a moved byte is a finding, not a chore.\n",
            .{ drift, path },
        );
    }
    if (drift != 0 or uncaptured != 0 or stale != 0) return 1;
    std.debug.print("\n{d} cases: Python Jinja2 still renders exactly what the transcript records.\n", .{live_cases.len});
    return 0;
}

fn findCase(cases: []const std.json.Value, name: []const u8) ?std.json.Value {
    for (cases) |c| {
        if (std.mem.eql(u8, c.object.get("name").?.string, name)) return c;
    }
    return null;
}

fn jsonEql(a: std.json.Value, b: std.json.Value) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .null => true,
        .bool => a.bool == b.bool,
        .integer => a.integer == b.integer,
        .float => a.float == b.float,
        .string => std.mem.eql(u8, a.string, b.string),
        .number_string => std.mem.eql(u8, a.number_string, b.number_string),
        .array => blk: {
            if (a.array.items.len != b.array.items.len) break :blk false;
            for (a.array.items, b.array.items) |x, y| {
                if (!jsonEql(x, y)) break :blk false;
            }
            break :blk true;
        },
        .object => blk: {
            if (a.object.count() != b.object.count()) break :blk false;
            var it = a.object.iterator();
            while (it.next()) |e| {
                const other = b.object.get(e.key_ptr.*) orelse break :blk false;
                if (!jsonEql(e.value_ptr.*, other)) break :blk false;
            }
            break :blk true;
        },
    };
}

fn usageError() u8 {
    std.debug.print("{s}", .{usage});
    return 2;
}
