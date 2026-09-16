// SPDX-License-Identifier: MIT
//
// WHAT THIS ASKS. Given a real seed, how many bytes does a fuzz harness
// actually hand its parser — and how much does that depend on the two lines it
// opens with? Three shapes, driven over the same corpus, counted side by side.
//
// WHY THIS EXISTS. Until 2026-09-07 every fuzz target in `http` opened with:
//
//     smith.bytes(&buf);
//     const len = smith.valueRangeAtMost(u16, 0, buf.len);
//
// A seed is `[u32 little-endian length][frame]` (see `testkit.fuzz.seed`).
// `Smith.bytes` consumes `min(buf.len, input.len)` octets — the WHOLE seed,
// length prefix included — and the ranged draw then wants eight MORE bytes,
// finds none, and returns the range MINIMUM. So the drawn length was 0 for
// every seed: the parser got an empty slice while the frame sat unread in
// `buf`. Twelve harnesses did this for their whole life. They ran, they passed,
// and they tested nothing. Commit `5929cc81` replaced the opening with
// `smith.slice(&buf)`, which reads the prefix as the length, and gave each
// harness a corpus; all twelve now carry `.corpus = &…_seeds`.
//
// WHY THIS IS A PROBE AND NOT A UNIT TEST. A harness fed zero bytes PASSES —
// that is the whole trap. No assertion a harness makes about its own subject
// can see it. What exposes it is instrumentation across shapes: the same seed,
// three openings, three byte counts. An assertion of `len > 0` would have
// caught this one instance; the table is what makes the next variant of the
// mistake recognisable.
//
// ⚠ ARM A KEEPS THE BROKEN OPENING ON PURPOSE. It is the control that shows the
// degeneration is real, not a description of what this module ships today —
// every live harness uses arm C. Do not "fix" arm A; that deletes the evidence.
//
// ⚠ ARM B IS NOT A REPAIR EITHER — that is the result worth keeping. Drawing
// the length FIRST and then filling that many bytes still yields 0 for every
// seed here: only `Smith.slice` reads the seed's u32 prefix as the length.
// Measured 2026-09-16 over the five frames below: arm A max 0 B, arm B max
// 0 B, arm C max 55 B. WHY the ranged draw yields 0 while input remains is
// recorded here as OBSERVED, not explained — do not repeat a mechanism for it
// that has not been derived.
//
// ⚠ IT DRIVES `Smith` DIRECTLY, and does not call `std.testing.fuzz`. A plain
// `zig test` with no fuzzer runs a body ONCE with an EMPTY input, so every
// draw returns its minimum and all three arms read 0 — which says nothing about
// any of them. An earlier version of this file asserted on arm C under exactly
// those conditions and reported a module regression that did not exist. Seeding
// `Smith.in` by hand is the same idiom `h1.zig`'s "every request-head seed
// reaches the parser" test uses, and it makes the comparison deterministic.
//
// WHAT IT NEEDS. Nothing: no module graph, no network, no peer, no corpus file.
//
//     zig test probe_fuzz_shape.zig
//
// WHAT IT PRODUCES. Bytes delivered per seed per arm, and a verdict. Exit
// non-zero only if arm C — the SHIPPED shape — stops delivering bytes, which
// would mean every harness in this module is back to testing nothing.
const std = @import("std");
const testing = std.testing;

/// The seed encoding `testkit.fuzz.seed` produces: a u32 little-endian length
/// prefix followed by the frame. Reproduced here rather than imported so this
/// probe needs no module graph at all.
fn seed(comptime frame: []const u8) []const u8 {
    return &struct {
        const bytes = std.mem.toBytes(@as(u32, @intCast(frame.len))) ++ frame[0..frame.len].*;
    }.bytes;
}

const corpus = [_][]const u8{
    seed("GET /x/y?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n"),
    seed("POST /submit HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n"),
    seed("PUT /up HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n"),
    seed("GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n"),
    seed("OPTIONS * HTTP/1.1\r\nHost: h\r\n"),
};

const Arm = enum { a_bytes_then_range, b_range_then_bytes, c_slice };

/// Run one opening against one seed and report how many bytes it would hand a
/// parser.
fn draw(arm: Arm, input: []const u8, buf: []u8) usize {
    var smith: std.testing.Smith = .{ .in = input };
    return switch (arm) {
        .a_bytes_then_range => blk: {
            smith.bytes(buf);
            break :blk smith.valueRangeAtMost(u16, 0, @intCast(buf.len));
        },
        .b_range_then_bytes => blk: {
            const n: usize = smith.valueRangeAtMost(u16, 0, @intCast(buf.len));
            smith.bytes(buf[0..n]);
            break :blk n;
        },
        .c_slice => smith.slice(buf),
    };
}

fn report(arm: Arm, label: []const u8) usize {
    var buf: [512]u8 = undefined;
    var total: usize = 0;
    var max: usize = 0;
    std.debug.print("\n {s}\n", .{label});
    for (corpus, 0..) |sd, i| {
        const frame_len = sd.len - 4; // the seed minus its u32 prefix
        const n = draw(arm, sd, &buf);
        total += n;
        max = @max(max, n);
        std.debug.print("   seed {d}: frame {d:>3} B -> parser got {d:>3} B\n", .{ i, frame_len, n });
    }
    std.debug.print("   total {d} B across {d} seeds, max {d} B\n", .{ total, corpus.len, max });
    return max;
}

test "the opening two lines decide whether a fuzz harness sees anything at all" {
    const a = report(.a_bytes_then_range, "arm A  smith.bytes(&buf) then valueRangeAtMost   [SUPERSEDED]");
    const b = report(.b_range_then_bytes, "arm B  valueRangeAtMost then bytes(buf[0..len])");
    const c = report(.c_slice, "arm C  smith.slice(&buf)                        [SHIPPED]");

    std.debug.print("\n arm A max={d}  arm B max={d}  arm C max={d}\n", .{ a, b, c });

    // Arm A drawing 0 is the FINDING, reproduced — not a failure of this run.
    if (a != 0) {
        std.debug.print(" note: arm A now draws {d} B; `Smith`'s accounting changed. The\n" ++
            " historical defect stands (A1 http, 5929cc81) but this control no\n" ++
            " longer reproduces it, so re-derive it before relying on it.\n", .{a});
    }

    // The one thing worth failing on: the SHIPPED opening must hand the parser
    // the frame. If it stops, all twelve harnesses in this module are testing
    // nothing again and no other check would say so.
    try testing.expect(c > 0);
    // And it must beat the superseded shape, which is the entire point of the
    // change that replaced it.
    try testing.expect(c > a);
}
