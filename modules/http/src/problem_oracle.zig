// SPDX-License-Identifier: MIT

//! OFFLINE anchor for `problem` (RFC 9457) and `Server.reasonPhrase`, taken by
//! `zig build interop-http -- --phase problem` (`tools/oracles.zig`): CPython
//! parsed every document in `problem_oracle_vectors.zig` with `json.loads`,
//! found each standard member of its RFC 9457 type, and decoded `detail`
//! exactly as its `bytes.decode("utf-8", "replace")` decodes the input — the
//! Unicode "maximal subpart" U+FFFD substitution this module claims — across
//! Unicode table 3-8, overlongs, surrogates, every C0 control and 200 random
//! byte strings. Teeth, at capture: CPython refuses a raw control character
//! and raw invalid UTF-8. Here the same inputs must still produce exactly
//! those documents, and every status's default title must be CPython's
//! `http.HTTPStatus` phrase or a judged difference.

const std = @import("std");
const testing = std.testing;
const problem = @import("problem.zig");
const reasonPhrase = @import("Server.zig").reasonPhrase;
const vectors = @import("problem_oracle_vectors.zig");

test "problem oracle: every document CPython accepted is what problem.write still writes" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    for (vectors.inputs) |input| {
        // `problemFor` in tools/oracles.zig.
        try problem.write(&out.writer, .{ .type = "https://example.com/p", .status = 400, .detail = input, .instance = input }, .{});
        try out.writer.writeByte('\n');
    }
    try testing.expectEqualStrings(vectors.docs, out.written());
}

/// Where our phrase differs from CPython's, and why ours stands.
const phrase_divergences = [_]struct { status: u16, why: []const u8 }{
    .{ .status = 418, .why = "RFC 9110 §15.5.19 and the IANA registry: 418 is \"(Unused)\", reserved, with no phrase; CPython says \"I'm a Teapot\"" },
    .{ .status = 510, .why = "the IANA registry marks 510 OBSOLETED (RFC 2774 is Historic); CPython keeps \"Not Extended\"" },
};

test "problem oracle: reasonPhrase is CPython's http.HTTPStatus phrase, or the difference is judged" {
    var bad: usize = 0;
    for (100..600) |code| {
        const status: u16 = @intCast(code);
        const theirs: []const u8 = for (vectors.phrases) |p| {
            if (p.status == status) break p.phrase;
        } else "";
        const agrees = std.mem.eql(u8, reasonPhrase(status), theirs);
        const listed = for (phrase_divergences) |d| {
            if (d.status == status) break true;
        } else false;
        if (agrees != listed) continue;
        bad += 1;
        std.debug.print("phrase {d}: ours \"{s}\", CPython \"{s}\"{s}\n", .{ status, reasonPhrase(status), theirs, if (listed) " (listed, agrees now)" else "" });
    }
    try testing.expectEqual(@as(usize, 0), bad);
}
