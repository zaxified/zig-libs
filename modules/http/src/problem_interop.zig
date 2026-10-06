// SPDX-License-Identifier: MIT

//! LIVE third-party check of `problem.write` (RFC 9457): CPython reads what
//! this module writes.
//!
//!   * every document must pass `json.loads` on its strict UTF-8 decoding
//!     (RFC 8259: no raw control character, valid UTF-8), with each standard
//!     member of the type RFC 9457 §3.1 gives it;
//!   * `detail` must decode to exactly what CPython's
//!     `bytes.decode("utf-8", "replace")` makes of the input bytes — the
//!     Unicode §3.9 "maximal subpart" substitution this module claims, judged
//!     by an implementation that does it independently (Unicode table 3-8,
//!     overlongs, surrogates, > U+10FFFF, every C0 control, and 600
//!     pseudo-random byte strings);
//!   * the `title` an `about:blank` problem gets for each status 100..599
//!     must be `http.HTTPStatus`'s phrase, or the difference judged below.
//!
//! Teeth, every run: CPython must refuse a document with a raw control
//! character and one with a raw invalid UTF-8 byte.
//!
//! Skips loudly (`SKIPPED: …`) when python3 is missing.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const problem = @import("problem.zig");
const testkit = @import("testkit");

const checker =
    \\import json, sys
    \\from http import HTTPStatus
    \\mode = sys.argv[1]
    \\if mode == "refuse":
    \\    for line in open(sys.argv[2], "rb").read().split(b"\n")[:-1]:
    \\        try:
    \\            json.loads(line.decode("utf-8"))
    \\        except Exception:
    \\            continue
    \\        print("ACCEPTED", line); sys.exit(1)
    \\    sys.exit(0)
    \\ins = [bytes.fromhex(h) for h in open("in.txt").read().split("\n")[:-1]]
    \\docs = open("docs.jsonl", "rb").read().split(b"\n")[:-1]
    \\bad = 0
    \\types = {"type": str, "status": int, "title": str, "detail": str, "instance": str}
    \\def parse(i, d):
    \\    global bad
    \\    try:
    \\        o = json.loads(d.decode("utf-8"))
    \\    except Exception as e:
    \\        print("PARSE", i, e); bad += 1; return None
    \\    for k, t in types.items():
    \\        if k in o and type(o[k]) is not t:
    \\            print("TYPE", i, k); bad += 1
    \\    return o
    \\if len(ins) != len(docs): print("COUNT", len(ins), len(docs)); bad += 1
    \\for i, (b, d) in enumerate(zip(ins, docs)):
    \\    o = parse(i, d)
    \\    if o is not None and o.get("detail") != b.decode("utf-8", "replace"):
    \\        print("DETAIL", i, b.hex(), ascii(o.get("detail"))); bad += 1
    \\for d in open("phrases.jsonl", "rb").read().split(b"\n")[:-1]:
    \\    o = parse("phrase", d)
    \\    if o is None: continue
    \\    code = o["status"]
    \\    theirs = HTTPStatus(code).phrase if code in HTTPStatus._value2member_map_ else None
    \\    if o.get("title") != theirs:
    \\        print("PHRASE", code, o.get("title"), "|", theirs)
    \\sys.exit(1 if bad else 0)
;

/// Where our default title differs from CPython's `HTTPStatus` phrase:
/// `status`, ours ("" = no title written), CPython's, and why ours stands.
const PhraseDivergence = struct { status: u16, ours: []const u8, theirs: []const u8, why: []const u8 };

const phrase_divergences = [_]PhraseDivergence{
    .{ .status = 418, .ours = "", .theirs = "I'm a Teapot", .why = "RFC 9110 §15.5.19 and the IANA registry: 418 is \"(Unused)\", reserved, with no phrase" },
    .{ .status = 510, .ours = "", .theirs = "Not Extended", .why = "the IANA registry marks 510 OBSOLETED (RFC 2774 is Historic)" },
};

/// The byte strings `detail` is written from.
fn fixedInputs() []const []const u8 {
    return &.{
        "",                                     "plain ASCII",                      "quote \" backslash \\ slash /",
        "\x00\x01\x02\x03\x04\x05\x06\x07",     "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", "\x10\x11\x12\x13\x14\x15\x16\x17",
        "\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f", "line\u{2028}sep\u{2029}para",      "\u{1F600} emoji, \u{10FFFF} max",
        "\u{FEFF}bom",                          "\xc4\x8d\xc5\xa1 2-byte",
        "a\xF1\x80\x80\xE1\x80\xC2b", // Unicode table 3-8
        "\xC0\xAF\xE0\x80\xBF\xF0\x81\x82\x41", // overlongs
        "\xED\xA0\x80\xED\xBF\xBF\x41", // surrogates
        "\xF4\x90\x80\x80\x41", // > U+10FFFF
        "\xF5\xF8\xFC\xFE\xFF\x41", // never-valid lead bytes
        "\x80\xBF\x80", // lone continuations
        "\xC2", "\xE1\x80", "\xF1\x80\x80", // truncated at the end
        "\xE0\xA0", "\xF0\x90\x80", "\xED\x9F", // truncated, valid prefix
        "\xC2\x41\xE1\x80\x41", // a lead followed by ASCII
    };
}

const random_inputs = 600;

fn randomInput(prng: *std.Random.DefaultPrng, buf: []u8) []const u8 {
    const r = prng.random();
    const len = r.uintLessThan(usize, buf.len);
    for (buf[0..len]) |*b| {
        // Mostly the bytes that make UTF-8 interesting, some ASCII.
        b.* = switch (r.uintLessThan(u8, 8)) {
            0 => r.uintLessThan(u8, 0x80),
            1 => 0xC0 + r.uintLessThan(u8, 0x20),
            2 => 0xE0 + r.uintLessThan(u8, 0x10),
            3 => 0xF0 + r.uintLessThan(u8, 0x10),
            else => 0x80 + r.uintLessThan(u8, 0x40),
        };
    }
    return buf[0..len];
}

fn run(io: std.Io, dir: std.Io.Dir, argv: []const []const u8, out_name: []const u8) !u8 {
    const out = try dir.createFile(io, out_name, .{});
    defer out.close(io);
    var child = std.process.spawn(io, .{
        .argv = argv,
        .cwd = .{ .dir = dir },
        .stdin = .ignore,
        .stdout = .{ .file = out },
        .stderr = .ignore,
    }) catch return testkit.skip("LIVE http problem interop: no `{s}` on PATH", .{argv[0]});
    return switch (try child.wait(io)) {
        .exited => |code| code,
        else => 255,
    };
}

fn writeDoc(w: *std.Io.Writer, p: problem.Problem) !void {
    try problem.write(w, p, .{});
    try w.writeByte('\n');
}

test "LIVE problem: CPython parses every document, decodes detail as it would, and agrees on titles" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var ins: std.Io.Writer.Allocating = .init(gpa);
    defer ins.deinit();
    var docs: std.Io.Writer.Allocating = .init(gpa);
    defer docs.deinit();
    var prng = std.Random.DefaultPrng.init(0x9457);
    var rbuf: [24]u8 = undefined;
    for (0..fixedInputs().len + random_inputs) |i| {
        const input = if (i < fixedInputs().len) fixedInputs()[i] else randomInput(&prng, &rbuf);
        try ins.writer.print("{x}\n", .{input});
        try writeDoc(&docs.writer, .{ .type = "https://example.com/p", .status = 400, .detail = input, .instance = input });
    }
    var phrases: std.Io.Writer.Allocating = .init(gpa);
    defer phrases.deinit();
    for (100..600) |code| try writeDoc(&phrases.writer, .{ .status = @intCast(code) });

    try tmp.dir.writeFile(io, .{ .sub_path = "in.txt", .data = ins.written() });
    try tmp.dir.writeFile(io, .{ .sub_path = "docs.jsonl", .data = docs.written() });
    try tmp.dir.writeFile(io, .{ .sub_path = "phrases.jsonl", .data = phrases.written() });
    const code = try run(io, tmp.dir, &.{ "python3", "-c", checker, "check" }, "report.txt");
    const report = try tmp.dir.readFileAlloc(io, "report.txt", gpa, .limited(1 << 20));
    defer gpa.free(report);

    var bad: usize = 0;
    var used = [_]bool{false} ** phrase_divergences.len;
    var lines = std.mem.splitScalar(u8, report, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "PHRASE ")) {
            var f = std.mem.splitScalar(u8, line["PHRASE ".len..], ' ');
            const status = try std.fmt.parseInt(u16, f.next().?, 10);
            const listed = for (phrase_divergences, 0..) |d, i| {
                if (d.status == status) break i;
            } else null;
            if (listed) |i| {
                used[i] = true;
                continue;
            }
        }
        std.debug.print("problem: {s}\n", .{line});
        bad += 1;
    }
    for (phrase_divergences, used) |d, u| if (!u) {
        std.debug.print("problem: phrase divergence for {d} now agrees\n", .{d.status});
        bad += 1;
    };
    try testing.expectEqual(@as(usize, 0), bad);
    try testing.expectEqual(@as(u8, 0), code);

    // Teeth: the same parser refuses what a broken writer would emit.
    try tmp.dir.writeFile(io, .{ .sub_path = "bad.jsonl", .data = "{\"type\":\"a\",\"detail\":\"x\x01y\"}\n{\"type\":\"a\",\"detail\":\"x\xC0y\"}\n{\"type\":\"a\",\"detail\":\"x\xED\xA0\x80y\"}\n" });
    try testing.expectEqual(@as(u8, 0), try run(io, tmp.dir, &.{ "python3", "-c", checker, "refuse", "bad.jsonl" }, "refuse.txt"));
}
