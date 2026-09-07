// SPDX-License-Identifier: MIT

//! Hostile-input tests for the parts of this module an attacker controls: the
//! five bytes in front of every message, and the header/trailer field values.
//!
//! The headline defect for a length-prefixed protocol is always the same
//! shape — *a number read from the input used to size an allocation before
//! anything has been verified*. Five bytes here can claim a 4 GiB message, so
//! that claim is exercised on purpose, from several directions: at the
//! default limit, with the limit raised to its maximum (where "check the
//! limit" is no defence at all and only the no-allocation invariant is left),
//! split across pushes so the check cannot be a one-shot, and repeated so a
//! per-message failure cannot leak.
//!
//! Then the smaller ones a fuzzer would find, and the fuzzers themselves.

const std = @import("std");
const testing = std.testing;
const frame = @import("frame.zig");
const status = @import("status.zig");
const metadata = @import("metadata.zig");
const call = @import("call.zig");

// ── the headline case: a length that is a lie ───────────────────────────────

test "hostile: five bytes claiming 4 GiB allocate nothing and fail cleanly" {
    const gpa = testing.allocator;
    var d: frame.Deframer = .{};
    defer d.deinit(gpa);
    try testing.expectError(
        error.MessageTooLarge,
        d.push(gpa, &.{ 0x00, 0xff, 0xff, 0xff, 0xff }),
    );
    try testing.expectEqual(@as(usize, 5), d.buf.items.len);
}

test "hostile: with the limit at its maximum, the lie STILL allocates nothing" {
    const gpa = testing.allocator;
    // The limit is the first line of defence; this test removes it entirely,
    // so what remains is the real invariant: the declared length never sizes
    // an allocation. A deframer that pre-reserved `length` would try for
    // 4 GiB right here, and the testing allocator would say so.
    var d: frame.Deframer = .{ .max_recv_message_size = std.math.maxInt(u32) };
    defer d.deinit(gpa);
    try d.push(gpa, &.{ 0x00, 0xff, 0xff, 0xff, 0xff });
    try d.push(gpa, "ten bytes!");
    try testing.expectEqual(@as(usize, 15), d.buf.items.len);
    try testing.expect(d.buf.capacity < 1024);
    // …and it is still not a message, because 4 GiB of it never arrived.
    try testing.expectEqual(@as(?[]const u8, null), try d.next());
    try testing.expectError(error.TruncatedMessage, d.endOfStream());
}

test "hostile: the check is not one-shot — a lie split across pushes still fails" {
    const gpa = testing.allocator;
    // No single push ever contains a whole header.
    var d: frame.Deframer = .{ .max_recv_message_size = 1024 };
    defer d.deinit(gpa);
    try d.push(gpa, &.{ 0x00, 0x7f, 0xff, 0xff });
    try testing.expectError(error.MessageTooLarge, d.push(gpa, &.{0xff}));
}

test "hostile: a run of oversized headers fails every time, not just the first" {
    const gpa = testing.allocator;
    for (0..64) |_| {
        var d: frame.Deframer = .{ .max_recv_message_size = 8 };
        defer d.deinit(gpa);
        try testing.expectError(
            error.MessageTooLarge,
            d.push(gpa, &.{ 0x00, 0x00, 0x00, 0x00, 0x09 }),
        );
    }
}

test "hostile: a valid message followed by a lying one fails at the second" {
    const gpa = testing.allocator;
    var d: frame.Deframer = .{ .max_recv_message_size = 8 };
    defer d.deinit(gpa);
    try d.push(gpa, &.{ 0x00, 0x00, 0x00, 0x00, 0x02, 'o', 'k' });
    try testing.expectEqualStrings("ok", (try d.next()).?);
    try testing.expectError(
        error.MessageTooLarge,
        d.push(gpa, &.{ 0x00, 0xff, 0xff, 0xff, 0xff }),
    );
}

test "hostile: a flood of zero-length messages does not grow the buffer" {
    const gpa = testing.allocator;
    var d: frame.Deframer = .{};
    defer d.deinit(gpa);
    for (0..100_000) |_| {
        try d.push(gpa, &.{ 0, 0, 0, 0, 0 });
        try testing.expectEqualStrings("", (try d.next()).?);
    }
    try testing.expect(d.buf.capacity < 1024);
}

test "hostile: off-by-one — one byte short is not a message" {
    const gpa = testing.allocator;
    var d: frame.Deframer = .{};
    defer d.deinit(gpa);
    try d.push(gpa, &.{ 0x00, 0x00, 0x00, 0x00, 0x04, 'a', 'b', 'c' });
    try testing.expectEqual(@as(?[]const u8, null), try d.next());
    try d.push(gpa, &.{'d'});
    try testing.expectEqualStrings("abcd", (try d.next()).?);
}

test "hostile: every nonzero value of the flag byte means compressed" {
    const gpa = testing.allocator;
    // Not just 0x01 — a peer (or an attacker) may set any bit, and treating
    // anything but 0x01 as "not compressed" would hand a compressed payload
    // to the protobuf decoder as if it were plaintext.
    var v: u8 = 1;
    while (v != 0) : (v +%= 1) {
        var d: frame.Deframer = .{};
        defer d.deinit(gpa);
        try testing.expectError(
            error.CompressedUnsupported,
            d.push(gpa, &.{ v, 0x00, 0x00, 0x00, 0x01, 0x00 }),
        );
    }
}

// ── field values ───────────────────────────────────────────────────────────

test "hostile: a grpc-status that is not a bare decimal never reads as OK" {
    const bad = [_][]const u8{
        "",           " ",   "0x0", "99999999999999999999",
        "4294967296", "+1",  "-1",  "1.0",
        "1 ",         " 1",  "\t0", "0\n",
        "٠",
        "０",
        "1e3",        "0;0",
    };
    for (bad) |b| try testing.expectEqual(@as(?status.Status, null), status.parse(b));
    // Leading zeros ARE a bare decimal, and must not be rejected.
    try testing.expectEqual(status.Status.ok, status.parse("00").?);
    try testing.expectEqual(status.Status.not_found, status.parse("005").?);
}

test "hostile: grpc-message decoding survives every truncation of an escape" {
    const value = "a%E2%98%83b%0A%";
    var buf: [64]u8 = undefined;
    for (0..value.len + 1) |n| {
        const out = status.decodeMessage(value[0..n], &buf);
        try testing.expect(out.len <= n);
    }
}

test "hostile: a -bin value of arbitrary junk is an error, never partial garbage" {
    const gpa = testing.allocator;
    const junk = [_][]const u8{
        "!!!!", "A", "AB=C", "====", "\x00\x01\x02\x03", "AAAAA",
    };
    for (junk) |j| {
        const r = metadata.decodeValue(gpa, "x-bin", j) catch |e| {
            try testing.expectEqual(error.InvalidBinaryValue, e);
            continue;
        };
        // If it did decode, it must round trip — a decoder that silently
        // accepted a broken value would be worse than one that rejected it.
        defer r.deinit(gpa);
        var enc: [64]u8 = undefined;
        const back = metadata.encodeValue(.{ .name = "x-bin", .value = r.bytes }, &enc);
        try testing.expectEqualStrings(std.mem.trimEnd(u8, j, "="), back);
    }
}

test "hostile: a grpc-timeout value outside the grammar is rejected" {
    const bad = [_][]const u8{
        "", "S", "1", "1X",
        "999999999S", // nine digits: one more than the grammar allows
        "-1S",
        "1.5S",
        " 1S",
        "1S ",
        "1s", // lowercase 's' is not a unit; 'S' is
        "0000000001S",
        "١S",
    };
    for (bad) |b| try testing.expectEqual(@as(?call.Timeout, null), call.Timeout.parse(b));
}

// ── fuzz ───────────────────────────────────────────────────────────────────

/// `testkit.fuzz.seedHex`, aliased so the corpora below read as the streams
/// they are. A corpus entry is not the frame: `Smith.slice` reads a
/// little-endian u32 length first (see `testkit/src/fuzz.zig`).
const seed = @import("testkit").fuzz.seedHex;
const testkit = @import("testkit");

/// What a stream did to the deframer, so the guard below can measure the
/// corpus rather than assert it merely ran.
const DeframeOutcome = struct {
    messages: usize = 0,
    refused: bool = false,
};

/// The body of `fuzzDeframerNeverPanics`, factored out so the harness and the
/// corpus guard drive the SAME deframer over the same octets and the same
/// chunk size.
fn runDeframeStream(bytes: []const u8, chunk: usize) !DeframeOutcome {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var out: DeframeOutcome = .{};
    var d: frame.Deframer = .{ .max_recv_message_size = 4096 };
    var i: usize = 0;
    while (i < bytes.len) {
        const end = @min(bytes.len, i + chunk);
        d.push(a, bytes[i..end]) catch {
            out.refused = true;
            return out;
        };
        while (d.next() catch {
            out.refused = true;
            return out;
        }) |_| out.messages += 1;
        i = end;
    }
    d.endOfStream() catch {
        out.refused = true;
    };
    return out;
}

/// Length-prefixed message streams paired with the chunk size they are fed in,
/// in the format `Smith` reads: `slice` framing for the stream, then an
/// eight-octet word for the chunk.
///
/// ⚠ The chunk is not decoration. The test's name promises "however they are
/// chopped", and the chunk used to be a `valueRangeAtMost(u16, 1, 64)` drawn
/// AFTER the byte draw — i.e. after the input was exhausted — so it was the
/// range minimum, **1**, on every replay. One octet at a time is the single
/// chopping that never puts a header boundary anywhere interesting.
const DeframeCorpus = struct {
    store: [8192]u8 = undefined,
    used: usize = 0,
    entries: [16][]const u8 = undefined,
    chunks: [16]usize = undefined,
    n: usize = 0,

    fn push(self: *DeframeCorpus, stream: []const u8, chunk: u16) void {
        const head = testkit.fuzz.seedInto(self.store[self.used..], stream);
        // ⚠ `chunk - 1`, because the harness reads the word as `% 64 + 1`.
        std.mem.writeInt(u64, self.store[self.used + head.len ..][0..8], chunk - 1, .little);
        self.entries[self.n] = self.store[self.used..][0 .. head.len + 8];
        self.chunks[self.n] = chunk;
        self.used += head.len + 8;
        self.n += 1;
    }

    fn pushHex(self: *DeframeCorpus, comptime h: []const u8, chunk: u16) void {
        var stream: [h.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&stream, h) catch unreachable;
        self.push(&stream, chunk);
    }

    fn build(self: *DeframeCorpus) []const []const u8 {
        // One message, delivered whole and then one octet at a time.
        self.pushHex("00" ++ "00000005" ++ "68656c6c6f", 64);
        self.pushHex("00" ++ "00000005" ++ "68656c6c6f", 1);
        // Two back to back, chopped at 7 — a boundary inside the second header.
        self.pushHex("00" ++ "00000005" ++ "68656c6c6f" ++ "00" ++ "00000003" ++ "626172", 7);
        // A zero-length message: a legal frame that carries nothing.
        self.pushHex("00" ++ "00000000", 64);
        // 200 octets, so the payload spans several 64-octet pushes.
        self.pushHex("00" ++ "000000C8" ++ ("AA" ** 200), 64);
        // Truncated: a header with no body, and a body one octet short.
        self.pushHex("00" ++ "000000", 64);
        self.pushHex("00" ++ "00000005" ++ "68656c", 64);
        // The compressed flag with no encoding negotiated.
        self.pushHex("01" ++ "00000005" ++ "68656c6c6f", 64);
        // 8192 declared against a 4096 ceiling: refused before the body arrives.
        self.pushHex("00" ++ "00002000", 64);
        // One whole message followed by a truncated second.
        self.pushHex("00" ++ "00000005" ++ "68656c6c6f" ++ "00" ++ "000000", 64);
        // 512 zero octets: an accidental stream of empty messages, five octets
        // each, with two left over that `endOfStream` refuses.
        self.pushHex("00" ** 512, 64);
        return self.entries[0..self.n];
    }
};

test "fuzz: the deframer never panics on arbitrary bytes, however they are chopped" {
    var corpus: DeframeCorpus = .{};
    try std.testing.fuzz({}, fuzzDeframerNeverPanics, .{ .corpus = corpus.build() });
}

fn fuzzDeframerNeverPanics(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM.
    // And `len` here is not merely the end of the slice — it is the bound of
    // the loop that pushes into the deframer, so the body never executed and
    // `push` was **never called**: this harness fed the deframer nothing at
    // all. `check-fuzz-reach` only learned to see that shape on 2026-09-07.
    // Measured over the corpus above: **0 of 11 seeds reached `push` and 0
    // messages were deframed before, 11 of 11 and 109 messages after.**
    const len: usize = smith.slice(&buf);
    // ⚠ `value(u64)` and a `%`, not `valueRangeAtMost(u16, 1, 64)`: a ranged
    // draw taken after the bytes is its minimum, so every stream was chopped
    // one octet at a time. See `DeframeCorpus`.
    const chunk: usize = @intCast(smith.value(u64) % 64 + 1);
    _ = try runDeframeStream(buf[0..len], chunk);
}

test "corpus: every deframer seed reaches push with the chunk size it was written for" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets. `messages` is the second number and the
    // one an empty stream cannot produce; `chunks` pins that the chopping word
    // arrived as written, without which the "however they are chopped" half of
    // the harness silently goes back to one octet at a time.
    var corpus: DeframeCorpus = .{};
    const entries = corpus.build();
    var nonempty: usize = 0;
    var chunks: usize = 0;
    var messages: usize = 0;
    var refusals: usize = 0;
    for (entries, corpus.chunks[0..corpus.n]) |sd, want_chunk| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const chunk: usize = @intCast(smith.value(u64) % 64 + 1);
        if (chunk == want_chunk) chunks += 1;
        const out = try runDeframeStream(buf[0..len], chunk);
        messages += out.messages;
        if (out.refused) refusals += 1;
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(entries.len, chunks);
    try testing.expectEqual(@as(usize, 109), messages);
    try testing.expectEqual(@as(usize, 6), refusals);
}

/// Field values, in the format `Smith.slice` reads. These are header values,
/// not frames: `grpc-status`, `grpc-timeout` and `grpc-message` off the wire,
/// plus the base64 a `-bin` metadata key carries.
///
/// ⛔ A corpus of refusals is not enough here and neither is `accepted > 0`:
/// `status.decodeMessage` has no failure mode at all — it copies what it
/// cannot decode — so it "succeeds" on every input including the empty one.
/// The guard pins what each parser actually RESOLVED.
const field_seeds = [_][]const u8{
    seed("30"), // "0" — OK
    seed("3136"), // "16" — UNAUTHENTICATED
    seed("3939"), // "99" — a status number with no name
    seed("6E6F742D612D6E756D626572"), // "not-a-number"
    seed("3020"), // "0 " — a trailing space is not the grammar
    seed("3153"), // "1S" — one second
    seed("3130306D"), // "100m" — 100 milliseconds
    seed("39393939393939393953"), // "999999999S" — nine digits, one too many
    seed("3173"), // "1s" — lowercase is not a unit
    seed("312E3553"), // "1.5S"
    seed("6E6F253230656E747279253041686572"), // "no%20entry%0Ahere" — the percent-encoded message
    seed("2530302564"), // "%00%d" — a valid escape and a broken one
    seed("25"), // a lone percent at the end of the value
    seed("616263"), // "abc" — nothing to decode
    seed("61474673624738"), // "aGVsbG8" — base64 for "hello", unpadded
    seed("6147567362473839"), // "aGVsbG8=" — the same, padded
    seed("2121212121"), // "!!!!!" — not base64 at all
    seed("41423D43"), // "AB=C" — padding in the middle
    seed("3D3D3D3D"), // "===="
    seed("41414141"), // "AAAA" — three octets out
};

test "fuzz: status, timeout and metadata field parsing never panic" {
    try std.testing.fuzz({}, fuzzFieldValuesNeverPanic, .{ .corpus = &field_seeds });
}

fn fuzzFieldValuesNeverPanic(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length — see `fuzzDeframerNeverPanics` above. `len` was 0 for every
    // input, so all four parsers here were called with `""` for ever.
    // Measured over the corpus above: **0 of 20 seeds non-empty, 0 statuses,
    // 0 timeouts and 0 binary values resolved before; 20 of 20 non-empty, 3
    // statuses, 2 timeouts and 6 binary values after.**
    const len: usize = smith.slice(&buf);
    const value = buf[0..len];

    _ = status.parse(value);
    _ = call.Timeout.parse(value);

    var out: [256]u8 = undefined;
    const decoded = status.decodeMessage(value, &out);
    // Re-encoding what came out must always fit the encoder's own estimate.
    var enc: [768]u8 = undefined;
    if (status.encodedMessageLen(decoded) <= enc.len) {
        _ = status.encodeMessage(decoded, &enc);
    }

    const r = metadata.decodeValue(std.testing.allocator, "x-bin", value) catch return;
    r.deinit(std.testing.allocator);
}

test "corpus: every field seed reaches the parsers, and what they resolved is pinned" {
    // ⭐ Three second numbers rather than one, because this harness runs four
    // parsers over the same octets and a corpus that feeds one of them says
    // nothing about the other three. `decoded_bytes` in particular is the only
    // check that `decodeMessage` did any percent-decoding at all — it has no
    // error path, so it "works" on every input including `""`.
    var nonempty: usize = 0;
    var statuses: usize = 0;
    var timeouts: usize = 0;
    var bin_values: usize = 0;
    var decoded_bytes: usize = 0;
    for (field_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const value = buf[0..len];
        if (status.parse(value) != null) statuses += 1;
        if (call.Timeout.parse(value) != null) timeouts += 1;
        var out: [256]u8 = undefined;
        decoded_bytes += status.decodeMessage(value, &out).len;
        const r = metadata.decodeValue(std.testing.allocator, "x-bin", value) catch continue;
        defer r.deinit(std.testing.allocator);
        bin_values += 1;
    }
    try testing.expectEqual(field_seeds.len, nonempty);
    try testing.expectEqual(@as(usize, 3), statuses);
    try testing.expectEqual(@as(usize, 2), timeouts);
    try testing.expectEqual(@as(usize, 6), bin_values);
    try testing.expectEqual(@as(usize, 92), decoded_bytes);
}
