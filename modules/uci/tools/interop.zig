// SPDX-License-Identifier: MIT

//! The real `libuci` as a black-box oracle for this module's parser AND
//! serializer, and the recorder that freezes it into
//! `src/testdata/libuci_capture.zig`, replayed by `src/libuci_oracle_test.zig`
//! with no libuci.
//!
//!     modules/uci/tools/build-oracle.sh     # libuci (pinned) -> oracle_dump + corpus.json
//!     zig build interop-uci                 # check that every input still captures
//!     zig build interop-uci -- --check      # ...and that the result IS the committed capture
//!     zig build interop-uci -- --capture    # ...or rewrite the transcript
//!
//! Needs `oracle_dump` built against libuci and the corpus, both produced by
//! `build-oracle.sh` (tools/README.md, "Building the reference oracle") under
//! `.zig-cache/uci-differential/`. ⚠ Only `--check` proves anything: a plain run
//! merely shows that every input still goes through the oracle.
//!
//! For each corpus input: libuci's dump of it; and, when this module parses
//! it, this module's `serialize` output and libuci's dump of THAT -- whether
//! the real parser reads what this module writes as the model it wrote.

const std = @import("std");
const uci = @import("uci");

const base = ".zig-cache/uci-differential";
const oracle = base ++ "/out/oracle_dump";
const confdir = base ++ "/ref/root/etc/config";
const corpus_path = base ++ "/corpus.json";
const transcript_path = "modules/uci/src/testdata/libuci_capture.zig";

/// Every child gets a deadline: a wedged oracle must fail the lane, not hang it.
const run_timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(30), .clock = .awake } };

/// One line naming the recipe, instead of a raw FileNotFound deep in a call.
fn preflight(io: std.Io) error{OracleNotBuilt}!void {
    inline for (.{ oracle, corpus_path, confdir }) |path| {
        std.Io.Dir.cwd().access(io, path, .{}) catch {
            std.debug.print("interop-uci: {s} is missing; run modules/uci/tools/build-oracle.sh first\n", .{path});
            return error.OracleNotBuilt;
        };
    }
}

fn dumpWithLibuci(gpa: std.mem.Allocator, io: std.Io, text: []const u8) ![]u8 {
    var dir = try std.Io.Dir.cwd().openDir(io, confdir, .{});
    defer dir.close(io);
    try dir.writeFile(io, .{ .sub_path = "fz", .data = text });
    const r = try std.process.run(gpa, io, .{
        .argv = &.{ oracle, confdir, "fz" },
        .timeout = run_timeout,
    });
    defer gpa.free(r.stderr);
    // oracle_dump reports a config libuci rejects as an `ERR ...` line on stdout
    // and still exits 0 (tools/oracle_dump.c), so a non-zero status is never
    // "libuci said no" -- it is usage (2), allocation (3) or a crash, and
    // recording it as a dump would freeze garbage into the capture.
    switch (r.term) {
        .exited => |code| if (code == 0) return r.stdout,
        else => {},
    }
    gpa.free(r.stdout);
    std.debug.print("interop-uci: oracle_dump failed ({any}); stderr:\n{s}\n", .{ r.term, r.stderr });
    return error.OracleFailed;
}

/// Byte-for-byte comparison against the committed transcript; prints the first
/// differing case (one case per line) and returns false on mismatch.
fn matchesCommitted(arena: std.mem.Allocator, io: std.Io, fresh: []const u8) !bool {
    const committed = try std.Io.Dir.cwd().readFileAlloc(io, transcript_path, arena, .limited(64 << 20));
    if (std.mem.eql(u8, committed, fresh)) return true;
    const n = @min(committed.len, fresh.len);
    var at: usize = 0;
    while (at < n and committed[at] == fresh[at]) at += 1;
    var line: usize = 1;
    var case: usize = 0; // cases completed before the differing line
    var line_start: usize = 0;
    for (committed[0..at], 0..) |c, i| if (c == '\n') {
        if (std.mem.startsWith(u8, committed[line_start..], "    .{ .input")) case += 1;
        line += 1;
        line_start = i + 1;
    };
    const in_case = std.mem.startsWith(u8, committed[line_start..], "    .{ .input") or
        std.mem.startsWith(u8, fresh[line_start..], "    .{ .input");
    std.debug.print("interop-uci: capture differs from {s} at byte {d} (line {d}", .{ transcript_path, at, line });
    if (in_case) std.debug.print(", case index {d}", .{case});
    std.debug.print(")\n", .{});
    const end_c = std.mem.indexOfScalarPos(u8, committed, at, '\n') orelse committed.len;
    const end_f = std.mem.indexOfScalarPos(u8, fresh, at, '\n') orelse fresh.len;
    std.debug.print("  committed: {s}\n  fresh    : {s}\n", .{ committed[line_start..end_c], fresh[line_start..end_f] });
    return false;
}

fn zigString(gpa: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
    try out.append(gpa, '"');
    for (s) |c| switch (c) {
        '"' => try out.appendSlice(gpa, "\\\""),
        '\\' => try out.appendSlice(gpa, "\\\\"),
        '\n' => try out.appendSlice(gpa, "\\n"),
        '\t' => try out.appendSlice(gpa, "\\t"),
        0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try out.append(gpa, c),
        else => try out.print(gpa, "\\x{x:0>2}", .{c}),
    };
    try out.append(gpa, '"');
}

fn optString(gpa: std.mem.Allocator, out: *std.ArrayList(u8), s: ?[]const u8) !void {
    if (s) |v| try zigString(gpa, out, v) else try out.appendSlice(gpa, "null");
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    const gpa = da.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var capture = false;
    var check = false;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--capture")) capture = true else if (std.mem.eql(u8, a, "--check")) check = true else {
            std.debug.print("usage: zig build interop-uci [-- --check | --capture]\n", .{});
            return 2;
        }
    }
    if (capture and check) {
        std.debug.print("usage: zig build interop-uci [-- --check | --capture]\n", .{});
        return 2;
    }
    try preflight(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const corpus_text = try std.Io.Dir.cwd().readFileAlloc(io, corpus_path, arena, .limited(16 << 20));
    const corpus = try std.json.parseFromSliceLeaky([]const []const u8, arena, corpus_text, .{});

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try out.appendSlice(gpa, "// SPDX-License-Identifier: MIT\n" ++
        "// Generated by `zig build interop-uci -- --capture` (modules/uci/tools/interop.zig): the\n" ++
        "// real libuci's dump of each input, and of this module's `serialize` of it. Replayed by\n" ++
        "// src/libuci_oracle_test.zig. Do not edit by hand.\n\n" ++
        "pub const Case = struct { input: []const u8, libuci: []const u8, serialized: ?[]const u8, libuci_serialized: ?[]const u8 };\n\n" ++
        "pub const cases = [_]Case{\n");

    var parsed: usize = 0;
    for (corpus) |hex| {
        const input = try arena.alloc(u8, hex.len / 2);
        _ = try std.fmt.hexToBytes(input, hex);
        const theirs = try dumpWithLibuci(arena, io, input);
        var ser: ?[]const u8 = null;
        var theirs_ser: ?[]const u8 = null;
        if (uci.parse(arena, input)) |pkg| {
            parsed += 1;
            if (uci.serialize(arena, &pkg)) |text| {
                ser = text;
                theirs_ser = try dumpWithLibuci(arena, io, text);
            } else |e| {
                // A value libuci itself would not write back (SerializeError):
                // recorded, and the replay requires the same refusal.
                theirs_ser = try std.fmt.allocPrint(arena, "SERIALIZE-ERROR {t}", .{e});
            }
        } else |_| {}
        try out.appendSlice(gpa, "    .{ .input = ");
        try zigString(gpa, &out, input);
        try out.appendSlice(gpa, ", .libuci = ");
        try zigString(gpa, &out, theirs);
        try out.appendSlice(gpa, ", .serialized = ");
        try optString(gpa, &out, ser);
        try out.appendSlice(gpa, ", .libuci_serialized = ");
        try optString(gpa, &out, theirs_ser);
        try out.appendSlice(gpa, " },\n");
    }
    try out.appendSlice(gpa, "};\n");
    std.debug.print("interop-uci: {d} inputs, {d} parsed by this module\n", .{ corpus.len, parsed });
    if (check) {
        if (!try matchesCommitted(arena, io, out.items)) return 1;
        std.debug.print("interop-uci: matches the committed capture ({d} cases)\n", .{corpus.len});
    }
    if (capture) {
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = transcript_path, .data = out.items });
        std.debug.print("interop-uci: transcript written to {s}\n", .{transcript_path});
    }
    return 0;
}
