// SPDX-License-Identifier: MIT

//! Fuzz harness for `open` (the entry point that takes attacker bytes): a
//! genuine record under a knob-chosen profile opens; a copy with damaged
//! ciphertext, tag, additional data or nonce, or truncated, is refused with
//! the plaintext buffer zeroed — never a panic. Generic over the choice
//! source: `testing.fuzz` (Smith) and testkit's deterministic driver
//! (`AESCCM_FUZZ=<runs>`).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const Cursor = testkit.fuzz.Cursor;
const aesccm = @import("root.zig");
const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;

const Label = enum { genuine, damaged_refused, zeroed, ccm8_12, ccm16_12, ccm8_13, ccm16_256 };
var counts: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    counts[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

fn expand(knobs: *Cursor, out: []u8) void {
    var s: u64 = 0;
    for (0..8) |_| s = (s << 8) | knobs.byte();
    var prng = std.Random.DefaultPrng.init(s);
    prng.random().bytes(out);
}

fn one(comptime C: type, knobs: *Cursor) !void {
    var key: [C.key_length]u8 = undefined;
    expand(knobs, &key);
    var nonce: [C.nonce_length]u8 = undefined;
    expand(knobs, &nonce);
    var pt_buf: [80]u8 = undefined;
    expand(knobs, &pt_buf);
    const pt = pt_buf[0..knobs.ranged(0, pt_buf.len)];
    var ad_buf: [40]u8 = undefined;
    expand(knobs, &ad_buf);
    const ad = ad_buf[0..knobs.ranged(0, ad_buf.len)];
    var ctx = C.init(key);
    defer ctx.deinit();
    var ct_buf: [80]u8 = undefined;
    const ct = ct_buf[0..pt.len];
    var tag: [C.tag_length]u8 = undefined;
    try ctx.seal(ct, &tag, pt, ad, nonce);
    var out_buf: [80]u8 = undefined;
    const out = out_buf[0..pt.len];
    try ctx.open(out, ct, tag, ad, nonce);
    if (!std.mem.eql(u8, out, pt)) return error.OpenedWrongPlaintext;
    mark(.genuine);

    var bad_ct = ct_buf;
    var bad_tag = tag;
    var bad_ad = ad_buf;
    var bad_nonce = nonce;
    var len: usize = pt.len;
    switch (knobs.ranged(0, 4)) {
        0 => if (len > 0) {
            bad_ct[knobs.ranged(0, @intCast(len - 1))] ^= @as(u8, 1) << @intCast(knobs.ranged(0, 7));
        } else {
            bad_tag[0] ^= 1;
        },
        1 => bad_tag[knobs.ranged(0, C.tag_length - 1)] ^= @as(u8, 1) << @intCast(knobs.ranged(0, 7)),
        2 => if (ad.len > 0) {
            bad_ad[knobs.ranged(0, @intCast(ad.len - 1))] ^= 0x80;
        } else {
            bad_tag[C.tag_length - 1] ^= 1;
        },
        3 => bad_nonce[knobs.ranged(0, C.nonce_length - 1)] ^= 1,
        else => if (len > 0) {
            len -= 1;
        } else {
            bad_tag[1] ^= 2;
        },
    }
    @memset(&out_buf, 0xaa);
    if (ctx.open(out_buf[0..len], bad_ct[0..len], bad_tag, bad_ad[0..ad.len], bad_nonce)) |_| return error.DamagedAccepted else |e| {
        if (e != error.AuthenticationFailed) return error.WrongRefusalKind;
        mark(.damaged_refused);
    }
    if (!std.mem.allEqual(u8, out_buf[0..len], 0)) return error.PlaintextNotZeroed;
    mark(.zeroed);
}

fn fuzzOpen(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [64]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    switch (knobs.ranged(0, 3)) {
        0 => {
            mark(.ccm8_12);
            try one(aesccm.Aes128Ccm8, &knobs);
        },
        1 => {
            mark(.ccm16_12);
            try one(aesccm.Aes128Ccm, &knobs);
        },
        2 => {
            mark(.ccm8_13);
            try one(aesccm.Aes128Ccm8Nonce13, &knobs);
        },
        else => {
            mark(.ccm16_256);
            try one(aesccm.Ccm(Aes256, 16, 12), &knobs);
        },
    }
}

fn smithOpen(_: void, smith: *std.testing.Smith) anyerror!void {
    try fuzzOpen(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: aesccm open, genuine accepted / damaged refused and zeroed" {
    try testing.fuzz({}, smithOpen, .{});
}

test "fuzz driver: AESCCM_FUZZ (open)" {
    try fuzz_driver.run(fuzzOpen, .{ .prefix = "AESCCM_FUZZ", .name = "aesccm-open" });
}

test "fuzz harness: open, 200 seeds, reaches every label" {
    counts = @splat(0);
    for (0..200) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        try fuzzOpen(fuzz_driver.Rng, &rng, testing.allocator);
    }
    for (counts) |n| try testing.expect(n > 0);
}
