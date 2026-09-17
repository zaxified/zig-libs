// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: audit F3 was not found by comparing this module to a test.
// It was found by canonicalizing a document with `xmldsig`'s C14N and holding
// the bytes against `xmllint --c14n`. A comment containing CR came out as
// `0d 0a` here and `0a` there -- different bytes, different digest, a signature
// that validates on one stack and not the other.
//
// That is a question no unit test in `modules/xml` can ask, because both sides
// of a self-comparison share the same reader. This is the seam.
//
// ⚠ It reaches ACROSS modules on purpose: `xml` produces the tree, `xmldsig`'s
// `c14n` serialises it. The instrument belongs to `xml` (the bytes under test
// are the parser's), but it needs `c14n` to express the question.
//
// WHAT IT PRODUCES: the canonical form as hex, for byte comparison against
//     xmllint --c14n <file>            (inclusive)
//     xmllint --c14n-with-comments     (inclusive_with_comments)
//
// Build (⚠ against the LIVE modules, never copies):
//   zig build-exe -O ReleaseSafe --dep xml --dep c14n \
//       -Mmain=probe_c14n.zig \
//       -Mc14n=../../xmldsig/src/c14n.zig --dep xml \
//       -Mxml=../src/root.zig \
//       --cache-dir <scratch>/zc-c14n -femit-bin=<scratch>/probe_c14n
//
//   probe_c14n <file> [exc|wc]

const std = @import("std");
const xml = @import("xml");
const c14n = @import("c14n");

pub fn main(init: std.process.Init) !void {
    const gpa = std.heap.smp_allocator;
    const io = init.io;
    var argl: std.ArrayList([]const u8) = .empty;
    defer argl.deinit(gpa);
    var it = init.minimal.args.iterate();
    while (it.next()) |a| try argl.append(gpa, a);
    const args = argl.items;
    if (args.len < 2) {
        std.debug.print("usage: probe_c14n <file> [exc|wc]\n", .{});
        return;
    }
    const path = args[1];
    const mode: c14n.Mode = if (args.len > 2 and std.mem.eql(u8, args[2], "exc"))
        .exclusive
    else if (args.len > 2 and std.mem.eql(u8, args[2], "wc"))
        .inclusive_with_comments
    else
        .inclusive;

    const src = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 28));
    defer gpa.free(src);
    var doc = xml.parse(gpa, src, .{}) catch |e| {
        std.debug.print("PARSE-FAILED {t}\n", .{e});
        return;
    };
    defer doc.deinit();
    const out = c14n.canonicalize(gpa, doc.root, .{ .mode = mode }) catch |e| {
        std.debug.print("C14N-FAILED {t}\n", .{e});
        return;
    };
    defer gpa.free(out);
    std.debug.print("{x}\n", .{out});
}
