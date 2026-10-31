// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GX, gx1-a) for nl80211's public parsers.
//! Findings NL-1 .. NL-6, see ~/CML/20261029-panic-sweep/nl80211-sweep.report.md.
//! Tests that need private engines (`dumpStep`, `nextEventIn`, error maps) sit
//! at the end of client.zig.
const std = @import("std");
const testing = std.testing;
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const wiphy = @import("wiphy.zig");
const reg = @import("reg.zig");

/// One NEW_WIPHY fragment: wiphy `idx`, band `band`, and `n` channels with
/// indices `first .. first + n`, each an (empty) channel nest.
fn fragment(gpa: std.mem.Allocator, idx: u32, band: u16, first: u16, n: u16) ![]u8 {
    var m: std.ArrayList(u8) = .empty;
    errdefer m.deinit(gpa);
    try codec.appendAttrU32(gpa, &m, uapi.ATTR.WIPHY, idx);
    const bands = try codec.nestBegin(gpa, &m, uapi.ATTR.WIPHY_BANDS);
    const b = try codec.nestBegin(gpa, &m, band);
    const freqs = try codec.nestBegin(gpa, &m, uapi.BAND_ATTR.FREQS);
    var i: u16 = 0;
    while (i < n) : (i += 1) {
        const f = try codec.nestBegin(gpa, &m, first + i);
        try codec.appendAttrU32(gpa, &m, uapi.FREQUENCY_ATTR.FREQ, 2412 + @as(u32, first + i));
        try codec.nestEnd(&m, f);
    }
    try codec.nestEnd(&m, freqs);
    try codec.nestEnd(&m, b);
    try codec.nestEnd(&m, bands);
    return m.toOwnedSlice(gpa);
}

test "wiphy.Parser: at most max_wiphys radios (sweep NL-1)" {
    const gpa = testing.allocator;
    var p: wiphy.Parser = .init(gpa);
    defer p.deinit();
    var i: u32 = 0;
    while (i < wiphy.max_wiphys) : (i += 1) {
        const f = try fragment(gpa, i, 0, 0, 1);
        defer gpa.free(f);
        try p.feed(f);
    }
    // A fragment of an EXISTING radio is still merged...
    {
        const f = try fragment(gpa, 3, 0, 1, 1);
        defer gpa.free(f);
        try p.feed(f);
    }
    // ...a new one is refused.
    const f = try fragment(gpa, wiphy.max_wiphys, 0, 0, 1);
    defer gpa.free(f);
    try testing.expectError(error.TooManyEntries, p.feed(f));
    const list = try p.finish();
    defer wiphy.freeAll(gpa, list);
    try testing.expectEqual(@as(usize, wiphy.max_wiphys), list.len);
}

test "wiphy.Parser: at most max_bands bands per radio (sweep NL-1)" {
    const gpa = testing.allocator;
    var p: wiphy.Parser = .init(gpa);
    defer p.deinit();
    var i: u16 = 0;
    while (i < wiphy.max_bands) : (i += 1) {
        const f = try fragment(gpa, 0, i, 0, 1);
        defer gpa.free(f);
        try p.feed(f);
    }
    const f = try fragment(gpa, 0, wiphy.max_bands, 0, 1);
    defer gpa.free(f);
    try testing.expectError(error.TooManyEntries, p.feed(f));
}

test "wiphy.Parser: at most max_channels_per_band channels, repeats merge (sweep NL-1)" {
    const gpa = testing.allocator;
    var p: wiphy.Parser = .init(gpa);
    defer p.deinit();
    // Exactly at the cap, in two fragments.
    {
        const f = try fragment(gpa, 0, 1, 0, 600);
        defer gpa.free(f);
        try p.feed(f);
    }
    {
        const f = try fragment(gpa, 0, 1, 600, wiphy.max_channels_per_band - 600);
        defer gpa.free(f);
        try p.feed(f);
    }
    // Updating existing channels does not count against the cap (and, with
    // the hash index, costs no scan).
    {
        const f = try fragment(gpa, 0, 1, 0, 1024);
        defer gpa.free(f);
        try p.feed(f);
    }
    const f = try fragment(gpa, 0, 1, wiphy.max_channels_per_band, 1);
    defer gpa.free(f);
    try testing.expectError(error.TooManyEntries, p.feed(f));
    const list = try p.finish();
    defer wiphy.freeAll(gpa, list);
    try testing.expectEqual(@as(usize, 1), list.len);
    try testing.expectEqual(@as(usize, wiphy.max_channels_per_band), list[0].bands[0].freqs.len);
    // Merge kept insertion order and values (index i -> 2412 + i).
    try testing.expectEqual(@as(u32, 2412 + 700), list[0].bands[0].freqs[700].freq_mhz);
}

fn rulesNest(gpa: std.mem.Allocator, n: usize) ![]u8 {
    var m: std.ArrayList(u8) = .empty;
    errdefer m.deinit(gpa);
    try codec.appendAttrString(gpa, &m, uapi.ATTR.REG_ALPHA2, "DE");
    const nest = try codec.nestBegin(gpa, &m, uapi.ATTR.REG_RULES);
    for (0..n) |i| {
        const one = try codec.nestBegin(gpa, &m, @intCast(i % 60000 + 1));
        try codec.appendAttrU32(gpa, &m, uapi.REG_RULE_ATTR.FREQ_RANGE_START, 2_402_000);
        try codec.nestEnd(&m, one);
    }
    try codec.nestEnd(&m, nest);
    return m.toOwnedSlice(gpa);
}

test "reg.parse: at most max_rules rules per domain (sweep NL-2)" {
    const gpa = testing.allocator;
    const ok = try rulesNest(gpa, reg.max_rules);
    defer gpa.free(ok);
    var d = try reg.parse(gpa, ok);
    defer d.deinit(gpa);
    try testing.expectEqual(@as(usize, reg.max_rules), d.rules.len);

    const big = try rulesNest(gpa, reg.max_rules + 1);
    defer gpa.free(big);
    try testing.expectError(error.TooManyEntries, reg.parse(gpa, big));
}

test "wiphy.Parser: at most max_total_channels channels across all radios and bands (sweep REV-NL-1)" {
    const gpa = testing.allocator;
    var p: wiphy.Parser = .init(gpa);
    defer p.deinit();
    // Radio 0: 16 bands x 1024 channels = exactly the aggregate cap.
    try testing.expectEqual(@as(usize, 16384), wiphy.max_total_channels);
    var b: u16 = 0;
    while (b < wiphy.max_bands) : (b += 1) {
        const f = try fragment(gpa, 0, b, 0, wiphy.max_channels_per_band);
        defer gpa.free(f);
        try p.feed(f);
    }
    // Updating an existing channel adds nothing...
    {
        const f = try fragment(gpa, 0, 0, 0, 1);
        defer gpa.free(f);
        try p.feed(f);
    }
    // ...one new channel on another radio is the cap + 1.
    const f = try fragment(gpa, 1, 0, 0, 1);
    defer gpa.free(f);
    try testing.expectError(error.TooManyEntries, p.feed(f));
}

// ── delta audit (wave GX, gxa-a) ────────────────────────────────────────────

test "wiphy.Parser: a feed that hit OutOfMemory can be fed again, no stale channel index (sweep audit GX-NL1)" {
    // `freqFor` puts the index entry BEFORE appending the channel; if the
    // append fails the entry must go, or the retry resolves the channel to a
    // position past the end of the list.
    var i: usize = 0;
    var failed: usize = 0;
    while (i < 40) : (i += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        var p: wiphy.Parser = .init(fa.allocator());
        defer p.deinit();
        const f = try fragment(testing.allocator, 0, 1, 0, 3);
        defer testing.allocator.free(f);
        p.feed(f) catch |e| {
            try testing.expectEqual(error.OutOfMemory, e);
            failed += 1;
            fa.fail_index = std.math.maxInt(usize);
            try p.feed(f);
        };
        fa.fail_index = std.math.maxInt(usize); // finish() is not under test here
        const list = try p.finish();
        defer wiphy.freeAll(fa.allocator(), list);
        try testing.expectEqual(@as(usize, 3), list[0].bands[0].freqs.len);
        for (list[0].bands[0].freqs, 0..) |fr, k| try testing.expectEqual(2412 + @as(u32, @intCast(k)), fr.freq_mhz);
    }
    try testing.expect(failed >= 3);
}

test "wiphy.Parser: the aggregate channel count starts again after finish (sweep audit GX-NL2)" {
    const gpa = testing.allocator;
    var p: wiphy.Parser = .init(gpa);
    defer p.deinit();
    var b: u16 = 0;
    while (b < wiphy.max_bands) : (b += 1) {
        const f = try fragment(gpa, 0, b, 0, wiphy.max_channels_per_band);
        defer gpa.free(f);
        try p.feed(f);
    }
    wiphy.freeAll(gpa, try p.finish());
    // The parser is reusable: a full second parse fits the cap again.
    const f = try fragment(gpa, 1, 0, 0, 10);
    defer gpa.free(f);
    try p.feed(f);
    const list = try p.finish();
    defer wiphy.freeAll(gpa, list);
    try testing.expectEqual(@as(usize, 10), list[0].bands[0].freqs.len);
}

test "the published ceilings keep their magnitudes (sweep audit GX-NL3)" {
    try testing.expectEqual(@as(usize, 256), wiphy.max_wiphys);
    try testing.expectEqual(@as(usize, 16), wiphy.max_bands);
    try testing.expectEqual(@as(usize, 1024), wiphy.max_channels_per_band);
    try testing.expectEqual(@as(usize, 1024), reg.max_rules);
    try testing.expectEqual(@as(usize, 256), reg.max_domains);
}

test "wiphy.Parser: re-fed channels do not count toward the aggregate cap (sweep audit GX-NL5)" {
    const gpa = testing.allocator;
    var p: wiphy.Parser = .init(gpa);
    defer p.deinit();
    // 16383 channels: one short of the cap.
    var b: u16 = 0;
    while (b < wiphy.max_bands - 1) : (b += 1) {
        const f = try fragment(gpa, 0, b, 0, wiphy.max_channels_per_band);
        defer gpa.free(f);
        try p.feed(f);
    }
    {
        const f = try fragment(gpa, 0, b, 0, wiphy.max_channels_per_band - 1);
        defer gpa.free(f);
        try p.feed(f);
    }
    // 2048 re-fed channels add nothing...
    {
        const f = try fragment(gpa, 0, 0, 0, wiphy.max_channels_per_band);
        defer gpa.free(f);
        try p.feed(f);
        try p.feed(f);
    }
    // ...so exactly one new channel still fits, and the next is refused.
    {
        const f = try fragment(gpa, 0, b, wiphy.max_channels_per_band - 1, 1);
        defer gpa.free(f);
        try p.feed(f);
    }
    const f = try fragment(gpa, 1, 0, 0, 1);
    defer gpa.free(f);
    try testing.expectError(error.TooManyEntries, p.feed(f));
}

test "wiphy.Parser: a re-fed channel updates its own entry, not another (sweep audit GX-NL6)" {
    const gpa = testing.allocator;
    var p: wiphy.Parser = .init(gpa);
    defer p.deinit();
    {
        const f = try fragment(gpa, 0, 1, 0, 5);
        defer gpa.free(f);
        try p.feed(f);
    }
    {
        const f = try fragment(gpa, 0, 1, 3, 1); // channel 3 again
        defer gpa.free(f);
        try p.feed(f);
    }
    const list = try p.finish();
    defer wiphy.freeAll(gpa, list);
    const freqs = list[0].bands[0].freqs;
    try testing.expectEqual(@as(usize, 5), freqs.len);
    for (freqs, 0..) |fr, k| {
        try testing.expectEqual(@as(u32, @intCast(k)), fr.index);
        try testing.expectEqual(2412 + @as(u32, @intCast(k)), fr.freq_mhz);
    }
}
