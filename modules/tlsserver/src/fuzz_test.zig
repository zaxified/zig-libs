// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for tlsserver (added 2026-10-20):
//! `TLSSERVER_FUZZ=<runs>[,<first seed>]` (testkit's driver). Harness name:
//! `tlsserver-record`: for a random suite and traffic secret, a sealed record
//! (random content length, inner type and padding) opens back to the same
//! content and type; the same record damaged — a flipped bit anywhere, the
//! header's length or type octets aimed at, truncation, extension, random
//! bytes in place of the ciphertext — or opened under another sequence number
//! is refused, never accepted unless identical, never a panic; a refused
//! record never advances the sequence number.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const ScriptSource = testkit.fuzz.ScriptSource;

const record = @import("record.zig");

/// Reach counters for one harness's labels (copied from `tls13`'s
/// fuzz_test). `mark` also feeds the driver's `REACH` report; `reach` runs
/// `seeds` seeds in the ordinary test binary and fails with
/// `error.HarnessDoesNotReach` if a label never fired.
fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

        fn mark(comptime l: Label) void {
            counts[@backingInt(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @fromBackingInt(@intCast(i))), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

const Mark = Marker(enum {
    aes128,
    aes256,
    chacha,
    genuine,
    padded,
    empty_content,
    flipped_refused,
    header_refused,
    resized_refused,
    garbage_refused,
    wrong_seq_refused,
});

const max_content = 1200; // keeps runs fast; the 2^14 bound is a unit test

fn fuzzRecord(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const suites = [_]record.CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 };
    const suite = suites[src.index(suites.len)];
    switch (suite) {
        .aes_128_gcm_sha256 => Mark.mark(.aes128),
        .aes_256_gcm_sha384 => Mark.mark(.aes256),
        else => Mark.mark(.chacha),
    }
    var secret: [48]u8 = undefined;
    src.bytes(&secret);
    const secret_len = suite.hashLen().?;

    var tx: record.Protection = undefined;
    try tx.init(suite, secret[0..secret_len]);
    tx.seq = src.value(u8); // a few distinct nonces per key
    const seq0 = tx.seq;

    // One run in eight at the short edge (0..3 octets: an empty record is
    // legal and has the least to authenticate).
    const content_len = if (src.valueRangeAtMost(u8, 0, 7) == 0) src.valueRangeAtMost(u16, 0, 3) else src.valueRangeAtMost(u16, 0, max_content);
    const pad = if (src.valueRangeAtMost(u8, 0, 3) == 0) src.valueRangeAtMost(u16, 1, 300) else 0;
    const types = [_]record.ContentType{ .handshake, .application_data, .alert };
    const ctype = types[src.index(types.len)];
    var content: [max_content]u8 = undefined;
    src.bytes(content[0..content_len]);

    var buf: [record.header_len + max_content + 1 + 300 + record.tag_len + 16]u8 = undefined;
    @memcpy(buf[record.header_len..][0..content_len], content[0..content_len]);
    const rec_len = (try tx.seal(&buf, content_len, ctype, pad)).len;
    var genuine: [buf.len]u8 = undefined;
    @memcpy(genuine[0..rec_len], buf[0..rec_len]);

    // Genuine: opens to the same content and type.
    {
        var rx: record.Protection = undefined;
        try rx.init(suite, secret[0..secret_len]);
        rx.seq = seq0;
        var in = genuine;
        const o = try rx.open(in[0..rec_len]);
        if (o.content_type != ctype) return error.WrongContentType;
        if (!std.mem.eql(u8, o.content, content[0..content_len])) return error.WrongContent;
        if (rx.seq != seq0 + 1) return error.SequenceNotAdvanced;
        Mark.mark(.genuine);
        if (pad != 0) Mark.mark(.padded);
        if (content_len == 0) Mark.mark(.empty_content);
    }

    // Damaged copies: refused unless the damage left the bytes identical.
    var in: [buf.len + 8]u8 = undefined;
    var n: usize = rec_len;
    @memcpy(in[0..rec_len], genuine[0..rec_len]);
    const kind = src.valueRangeAtMost(u8, 0, 4);
    switch (kind) {
        0 => in[src.index(rec_len)] ^= @as(u8, 1) << @intCast(src.valueRangeAtMost(u8, 0, 7)),
        1 => {
            // The header: type, version or length octets.
            in[src.index(record.header_len)] = src.value(u8);
        },
        2 => {
            const new_n = src.valueRangeAtMost(u16, 0, @intCast(rec_len + 8));
            if (new_n > n) src.bytes(in[n..new_n]);
            n = new_n;
        },
        3 => src.bytes(in[record.header_len..rec_len]),
        else => {}, // sequence number below
    }
    var rx: record.Protection = undefined;
    try rx.init(suite, secret[0..secret_len]);
    rx.seq = if (kind == 4) seq0 +% (1 + @as(u64, src.value(u8))) else seq0;
    const seq_before = rx.seq;
    // Decided before `open`, which decrypts `in` in place.
    const identical = kind != 4 and n == rec_len and std.mem.eql(u8, in[0..n], genuine[0..rec_len]);
    if (rx.open(in[0..n])) |_| {
        // Damage that rewrote a byte with its own value is no damage.
        if (!identical) return error.DamagedRecordAccepted;
    } else |_| {
        if (rx.seq != seq_before) return error.SequenceAdvancedOnFailure;
        switch (kind) {
            0 => Mark.mark(.flipped_refused),
            1 => Mark.mark(.header_refused),
            2 => Mark.mark(.resized_refused),
            3 => Mark.mark(.garbage_refused),
            else => Mark.mark(.wrong_seq_refused),
        }
    }
}

fn fuzzRecordSmith(_: void, smith: *std.testing.Smith) anyerror!void {
    var script: [2048]u8 = undefined;
    var src: ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzRecord(ScriptSource, &src, testing.allocator);
}

test "fuzz: tlsserver record, genuine opens / damaged refused" {
    try testing.fuzz({}, fuzzRecordSmith, .{});
}
test "fuzz driver: TLSSERVER_FUZZ (record)" {
    try fuzz_driver.run(fuzzRecord, .{ .prefix = "TLSSERVER_FUZZ", .name = "tlsserver-record" });
}
test "fuzz harness: record, 300 seeds, reaches every outcome" {
    try Mark.reach(fuzzRecord, "tlsserver-record", 300);
}
