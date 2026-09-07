// SPDX-License-Identifier: MIT
//! Regulatory domain: decoding `NL80211_CMD_GET_REG` and building
//! `NL80211_CMD_REQ_SET_REG`.
//!
//! `GET_REG` is a **dump**, and on a modern kernel it answers with more than
//! one message: the global domain first (alpha2 `"00"`, the world regdomain),
//! then one per self-managed wiphy, each tagged with `NL80211_ATTR_WIPHY`.
//! So `parse` decodes one message and the caller collects the list.
//!
//! Frequencies in a rule are **kilohertz**, not megahertz — a detail that is
//! easy to get wrong by three orders of magnitude, so `RegRule` names the unit
//! in every field and offers MHz accessors.
//!
//! `REQ_SET_REG` is only a *hint*: the kernel intersects the request with the
//! driver's own regulatory constraints and with any world-roaming rules, so
//! the domain that comes back from a subsequent `GET_REG` may not be the
//! alpha2 that was asked for. It needs `CAP_NET_ADMIN`.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const genl = @import("genetlink");
const uapi = @import("uapi.zig");
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

pub const ParseError = codec.Error || error{OutOfMemory};
pub const BuildError = error{ OutOfMemory, InvalidRequest };

/// One regulatory rule: a frequency range plus the power and behaviour limits
/// that apply inside it.
pub const RegRule = struct {
    /// `NL80211_RRF_*` bits.
    flags: u32 = 0,
    start_khz: u32 = 0,
    end_khz: u32 = 0,
    /// Widest channel bandwidth permitted inside the range.
    max_bandwidth_khz: u32 = 0,
    /// Maximum antenna gain, mBi (100 · dBi). 0 = unspecified.
    max_antenna_gain_mbi: u32 = 0,
    /// Maximum EIRP, mBm (100 · dBm).
    max_eirp_mbm: u32 = 0,
    /// Channel availability check time for DFS, milliseconds.
    dfs_cac_time_ms: u32 = 0,
    /// Power spectral density, mBm/MHz, when `RRF.PSD` is set.
    psd_mbm: ?u32 = null,

    pub fn startMhz(r: RegRule) u32 {
        return r.start_khz / 1000;
    }
    pub fn endMhz(r: RegRule) u32 {
        return r.end_khz / 1000;
    }
    pub fn maxBandwidthMhz(r: RegRule) u32 {
        return r.max_bandwidth_khz / 1000;
    }
    /// Maximum EIRP in whole dBm.
    pub fn maxEirpDbm(r: RegRule) u32 {
        return r.max_eirp_mbm / 100;
    }
    /// The range requires radar detection.
    pub fn dfs(r: RegRule) bool {
        return r.flags & uapi.RRF.DFS != 0;
    }
    /// No initiating radiation: passive scan only, no beaconing.
    pub fn noIr(r: RegRule) bool {
        return r.flags & uapi.RRF.NO_IR != 0;
    }
    /// Does this rule cover `mhz`?
    pub fn covers(r: RegRule, mhz: u32) bool {
        // `mhz * 1000` overflows `u32` for `mhz > 4_294_967`; widen to `u64`
        // rather than wrap or panic on an out-of-range caller-supplied
        // frequency.
        const khz: u64 = @as(u64, mhz) * 1000;
        return khz >= r.start_khz and khz <= r.end_khz;
    }
};

/// One regulatory domain as the kernel reports it.
pub const RegDomain = struct {
    /// ISO/IEC 3166-1 alpha-2, or `"00"` for the world domain. Always 2 bytes.
    alpha2: [2]u8 = .{ '0', '0' },
    /// Set when this domain belongs to one self-managed radio rather than the
    /// system as a whole.
    wiphy: ?u32 = null,
    dfs_region: ?uapi.DfsRegion = null,
    reg_type: ?uapi.RegType = null,
    /// Who asked for this domain (`enum nl80211_reg_initiator`).
    initiator: ?u8 = null,
    /// Owned.
    rules: []RegRule = &.{},

    /// The rule covering `mhz`, or null.
    pub fn ruleFor(d: RegDomain, mhz: u32) ?RegRule {
        for (d.rules) |r| if (r.covers(mhz)) return r;
        return null;
    }

    /// True for the "world" regulatory domain, which is deliberately
    /// conservative (passive scan on most channels).
    pub fn isWorld(d: RegDomain) bool {
        return std.mem.eql(u8, &d.alpha2, "00");
    }

    pub fn deinit(d: *RegDomain, gpa: std.mem.Allocator) void {
        gpa.free(d.rules);
        d.* = undefined;
    }
};

pub fn freeAll(gpa: std.mem.Allocator, list: []RegDomain) void {
    for (list) |*d| d.deinit(gpa);
    gpa.free(list);
}

/// Decode one `NL80211_CMD_GET_REG` reply message's attribute bytes.
pub fn parse(gpa: std.mem.Allocator, attr_bytes: []const u8) ParseError!RegDomain {
    var d: RegDomain = .{};
    errdefer d.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.REG_ALPHA2 => {
            // The kernel sends a NUL-terminated 3-byte string.
            const s = a.asString();
            if (s.len != 2) return error.BadLength;
            d.alpha2 = s[0..2].*;
        },
        uapi.ATTR.WIPHY => d.wiphy = try a.asU32(),
        uapi.ATTR.DFS_REGION => d.dfs_region = @enumFromInt(@as(u32, try a.asU8())),
        uapi.ATTR.REG_TYPE => d.reg_type = @enumFromInt(@as(u32, try a.asU8())),
        uapi.ATTR.REG_INITIATOR => d.initiator = try a.asU8(),
        uapi.ATTR.REG_RULES => {
            if (d.rules.len != 0) return error.BadLength; // repeated attribute
            d.rules = try parseRules(gpa, a.data);
        },
        else => {},
    };
    return d;
}

fn parseRules(gpa: std.mem.Allocator, nest: []const u8) ParseError![]RegRule {
    var out: std.ArrayList(RegRule) = .empty;
    errdefer out.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = nest };
    while (try it.next()) |entry| {
        var r: RegRule = .{};
        var inner: codec.AttrIterator = .{ .buf = entry.data };
        while (try inner.next()) |a| switch (a.type) {
            uapi.REG_RULE_ATTR.REG_RULE_FLAGS => r.flags = try a.asU32(),
            uapi.REG_RULE_ATTR.FREQ_RANGE_START => r.start_khz = try a.asU32(),
            uapi.REG_RULE_ATTR.FREQ_RANGE_END => r.end_khz = try a.asU32(),
            uapi.REG_RULE_ATTR.FREQ_RANGE_MAX_BW => r.max_bandwidth_khz = try a.asU32(),
            uapi.REG_RULE_ATTR.POWER_RULE_MAX_ANT_GAIN => r.max_antenna_gain_mbi = try a.asU32(),
            uapi.REG_RULE_ATTR.POWER_RULE_MAX_EIRP => r.max_eirp_mbm = try a.asU32(),
            uapi.REG_RULE_ATTR.DFS_CAC_TIME => r.dfs_cac_time_ms = try a.asU32(),
            uapi.REG_RULE_ATTR.POWER_RULE_PSD => r.psd_mbm = try a.asU32(),
            else => {},
        };
        try out.append(gpa, r);
    }
    return out.toOwnedSlice(gpa);
}

/// Build a `NL80211_CMD_GET_REG` dump request.
pub fn buildGetReg(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        family_id,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK | codec.NLM_F_DUMP,
        seq,
        0,
    );
    try genl.appendHeader(gpa, &list, uapi.CMD.GET_REG, uapi.family_version);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build a `NL80211_CMD_REQ_SET_REG` request. `alpha2` must be exactly two
/// bytes; it goes on the wire NUL-terminated, as `iw reg set` sends it.
pub fn buildReqSetReg(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    alpha2: []const u8,
) BuildError![]u8 {
    if (alpha2.len != 2) return error.InvalidRequest;
    for (alpha2) |c| {
        if (!std.ascii.isAlphanumeric(c)) return error.InvalidRequest;
    }
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        family_id,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        seq,
        0,
    );
    try genl.appendHeader(gpa, &list, uapi.CMD.REQ_SET_REG, uapi.family_version);
    codec.appendAttrString(gpa, &list, uapi.ATTR.REG_ALPHA2, alpha2) catch |e| switch (e) {
        error.AttrTooLong => unreachable, // 2 bytes
        error.OutOfMemory => return error.OutOfMemory,
    };
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "buildReqSetReg validates the alpha2" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidRequest, buildReqSetReg(gpa, 41, 1, "U"));
    try testing.expectError(error.InvalidRequest, buildReqSetReg(gpa, 41, 1, "USA"));
    try testing.expectError(error.InvalidRequest, buildReqSetReg(gpa, 41, 1, "U-"));
    const ok = try buildReqSetReg(gpa, 41, 1, "US");
    defer gpa.free(ok);
    // "00" (the world domain) is a legitimate request too.
    const world = try buildReqSetReg(gpa, 41, 1, "00");
    gpa.free(world);
}

test "parse: rules decode with kHz→MHz conversion and DFS flags" {
    const gpa = testing.allocator;
    var rules: std.ArrayList(u8) = .empty;
    defer rules.deinit(gpa);
    // 5250–5330 MHz, 80 MHz wide, DFS, 20 dBm, 60 s CAC.
    const one = try codec.nestBegin(gpa, &rules, 1);
    try codec.appendAttrU32(gpa, &rules, uapi.REG_RULE_ATTR.REG_RULE_FLAGS, uapi.RRF.DFS);
    try codec.appendAttrU32(gpa, &rules, uapi.REG_RULE_ATTR.FREQ_RANGE_START, 5_250_000);
    try codec.appendAttrU32(gpa, &rules, uapi.REG_RULE_ATTR.FREQ_RANGE_END, 5_330_000);
    try codec.appendAttrU32(gpa, &rules, uapi.REG_RULE_ATTR.FREQ_RANGE_MAX_BW, 80_000);
    try codec.appendAttrU32(gpa, &rules, uapi.REG_RULE_ATTR.POWER_RULE_MAX_EIRP, 2000);
    try codec.appendAttrU32(gpa, &rules, uapi.REG_RULE_ATTR.DFS_CAC_TIME, 60_000);
    codec.nestEnd(&rules, one) catch return error.InvalidRequest;

    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try codec.appendAttrString(gpa, &msg, uapi.ATTR.REG_ALPHA2, "DE");
    try codec.appendAttrU8(gpa, &msg, uapi.ATTR.DFS_REGION, 2); // ETSI
    const nest = try codec.nestBegin(gpa, &msg, uapi.ATTR.REG_RULES);
    try msg.appendSlice(gpa, rules.items);
    codec.nestEnd(&msg, nest) catch return error.InvalidRequest;

    var d = try parse(gpa, msg.items);
    defer d.deinit(gpa);
    try testing.expectEqualStrings("DE", &d.alpha2);
    try testing.expect(!d.isWorld());
    try testing.expectEqual(uapi.DfsRegion.etsi, d.dfs_region.?);
    try testing.expectEqual(@as(usize, 1), d.rules.len);
    const r = d.rules[0];
    try testing.expectEqual(@as(u32, 5250), r.startMhz());
    try testing.expectEqual(@as(u32, 5330), r.endMhz());
    try testing.expectEqual(@as(u32, 80), r.maxBandwidthMhz());
    try testing.expectEqual(@as(u32, 20), r.maxEirpDbm());
    try testing.expect(r.dfs());
    try testing.expect(!r.noIr());
    try testing.expect(r.covers(5280));
    try testing.expect(!r.covers(2412));
    try testing.expectEqual(@as(?RegRule, null), d.ruleFor(2412));
    try testing.expectEqual(@as(u32, 5250), d.ruleFor(5280).?.startMhz());
}

// P-18 (same finding as station.zig's kilobitsPerSecond): `mhz * 1000`
// overflowed `u32` for `mhz > 4_294_967`, reachable through the public
// `RegDomain.ruleFor` with a caller-supplied frequency.
test "RegRule.covers does not overflow on an out-of-range frequency" {
    const r = RegRule{ .start_khz = 2_400_000, .end_khz = 2_500_000 };
    try testing.expect(!r.covers(std.math.maxInt(u32)));
    try testing.expect(!r.covers(4_294_968));
    try testing.expect(r.covers(2450));
}

test "parse: the world domain" {
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try codec.appendAttrString(gpa, &msg, uapi.ATTR.REG_ALPHA2, "00");
    var d = try parse(gpa, msg.items);
    defer d.deinit(gpa);
    try testing.expect(d.isWorld());
    try testing.expectEqual(@as(usize, 0), d.rules.len);
    try testing.expectEqual(@as(?u32, null), d.wiphy);
}

test "parse: malformed regulatory replies error out without leaking rules" {
    const gpa = testing.allocator;
    // alpha2 of the wrong length.
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try codec.appendAttrString(gpa, &msg, uapi.ATTR.REG_ALPHA2, "USA");
    try testing.expectError(error.BadLength, parse(gpa, msg.items));

    // REG_RULES present twice: the second must not orphan the first list.
    var msg2: std.ArrayList(u8) = .empty;
    defer msg2.deinit(gpa);
    const a = try codec.nestBegin(gpa, &msg2, uapi.ATTR.REG_RULES);
    const inner = try codec.nestBegin(gpa, &msg2, 1);
    try codec.appendAttrU32(gpa, &msg2, uapi.REG_RULE_ATTR.FREQ_RANGE_START, 1);
    codec.nestEnd(&msg2, inner) catch return error.InvalidRequest;
    codec.nestEnd(&msg2, a) catch return error.InvalidRequest;
    const dup_start = msg2.items.len;
    try msg2.appendSlice(gpa, msg2.items[0..dup_start]);
    try testing.expectError(error.BadLength, parse(gpa, msg2.items));

    // A truncated rule TLV.
    var msg3: std.ArrayList(u8) = .empty;
    defer msg3.deinit(gpa);
    const b = try codec.nestBegin(gpa, &msg3, uapi.ATTR.REG_RULES);
    try msg3.appendSlice(gpa, &.{ 0x40, 0x00, 0x01, 0x00, 0xff });
    codec.nestEnd(&msg3, b) catch return error.InvalidRequest;
    try testing.expectError(error.Truncated, parse(gpa, msg3.items));
}

/// GET_REG reply attribute lists for `fuzzParse`, in the format `Smith.slice` reads (see
/// `testkit.fuzz`): a little-endian u32 length, then the frame.
///
/// ⭐ Built at run time by `codec`'s own encoders, the way the value tests
/// above build theirs, rather than quoted as hex: an nl80211 attribute is a
/// netlink TLV, whose length and scalars are HOST byte order, so a hex corpus
/// would be a little-endian one and the counts pinned below would be false on
/// a big-endian target instead of failing there.
const Corpus = struct {
    scratch: [8192]u8 = undefined,
    store: [8192]u8 = undefined,
    used: usize = 0,
    entries: [8][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *Corpus, frame: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = sd;
        self.used += sd.len;
        self.n += 1;
    }

    fn build(self: *Corpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const gpa = fba.allocator();

        // DE with one DFS rule: the shape the kHz→MHz conversion works on.
        var de: std.ArrayList(u8) = .empty;
        {
            var rules: std.ArrayList(u8) = .empty;
            const one = try codec.nestBegin(gpa, &rules, 1);
            try codec.appendAttrU32(gpa, &rules, uapi.REG_RULE_ATTR.REG_RULE_FLAGS, uapi.RRF.DFS);
            try codec.appendAttrU32(gpa, &rules, uapi.REG_RULE_ATTR.FREQ_RANGE_START, 5_250_000);
            try codec.appendAttrU32(gpa, &rules, uapi.REG_RULE_ATTR.FREQ_RANGE_END, 5_330_000);
            try codec.appendAttrU32(gpa, &rules, uapi.REG_RULE_ATTR.FREQ_RANGE_MAX_BW, 80_000);
            try codec.appendAttrU32(gpa, &rules, uapi.REG_RULE_ATTR.POWER_RULE_MAX_EIRP, 2000);
            try codec.appendAttrU32(gpa, &rules, uapi.REG_RULE_ATTR.DFS_CAC_TIME, 60_000);
            try codec.nestEnd(&rules, one);

            try codec.appendAttrString(gpa, &de, uapi.ATTR.REG_ALPHA2, "DE");
            try codec.appendAttrU8(gpa, &de, uapi.ATTR.DFS_REGION, 2); // ETSI
            const nest = try codec.nestBegin(gpa, &de, uapi.ATTR.REG_RULES);
            try de.appendSlice(gpa, rules.items);
            try codec.nestEnd(&de, nest);
        }
        self.push(de.items);

        // The world domain: an alpha2 and no rules at all.
        var world: std.ArrayList(u8) = .empty;
        try codec.appendAttrString(gpa, &world, uapi.ATTR.REG_ALPHA2, "00");
        self.push(world.items);

        // An empty REG_RULES nest.
        var empty_rules: std.ArrayList(u8) = .empty;
        try codec.appendAttrString(gpa, &empty_rules, uapi.ATTR.REG_ALPHA2, "US");
        {
            const nest = try codec.nestBegin(gpa, &empty_rules, uapi.ATTR.REG_RULES);
            try codec.nestEnd(&empty_rules, nest);
        }
        self.push(empty_rules.items);

        // ── the refusals ───────────────────────────────────────────────────
        // An alpha2 of the wrong length.
        var bad_alpha: std.ArrayList(u8) = .empty;
        try codec.appendAttrString(gpa, &bad_alpha, uapi.ATTR.REG_ALPHA2, "USA");
        self.push(bad_alpha.items);
        // A TLV header declaring 0x40 octets over a 2-octet buffer.
        self.push(&[_]u8{ 0x40, 0x00 });
        // A rules nest whose inner TLV is truncated — the shape that must not
        // leak the rules allocated before it.
        var leaky: std.ArrayList(u8) = .empty;
        try codec.appendAttrString(gpa, &leaky, uapi.ATTR.REG_ALPHA2, "DE");
        {
            var rules: std.ArrayList(u8) = .empty;
            const one = try codec.nestBegin(gpa, &rules, 1);
            try codec.appendAttrU32(gpa, &rules, uapi.REG_RULE_ATTR.FREQ_RANGE_START, 5_250_000);
            try codec.nestEnd(&rules, one);
            try rules.appendSlice(gpa, &.{ 0x40, 0x00, 0x02, 0x00, 0x01 });
            const nest = try codec.nestBegin(gpa, &leaky, uapi.ATTR.REG_RULES);
            try leaky.appendSlice(gpa, rules.items);
            try codec.nestEnd(&leaky, nest);
        }
        self.push(leaky.items);

        return self.entries[0..self.n];
    }
};

test "fuzz: regulatory parse never crashes or leaks" {
    var corpus: Corpus = .{};
    try testing.fuzz({}, fuzzParse, .{ .corpus = try corpus.build() });
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and `parse` was handed an empty attribute list, with
    // the reply sitting unread in `raw`.
    //
    // ⛔ And it looked HEALTHIER that way: a reply with no
    // attributes is a legal (empty) domain, so `parse("")` succeeded every
    // round. Measured 2026-09-07 over the corpus above: **0 of 6 seeds
    // non-empty, 6 of 6 "parsed" and 0 rules decoded before; 6 of 6 non-empty,
    // 3 parsed and 1 rule after.** The rule count is the number that says the
    // REG_RULES nest walk — everything this file is about — ran at all.
    const len: usize = smith.slice(&raw);
    if (parse(testing.allocator, raw[0..len])) |d| {
        var dd = d;
        dd.deinit(testing.allocator);
    } else |_| {}
}

test "corpus: every regulatory seed reaches the parser, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets. `nonempty` is the reach claim and the only
    // check that catches a seed grown past the harness's buffer, which
    // `Smith.slice` reads back as the EMPTY one, silently. The second number
    // is what the first cannot say: an empty attribute list is a legal reply
    // here, so "parsed" alone counts a harness that walks nothing as a
    // success.
    var corpus: Corpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var parsed: usize = 0;
    var rules: usize = 0;
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [512]u8 = undefined;
        const len: usize = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        if (parse(testing.allocator, raw[0..len])) |d| {
            parsed += 1;
            var dd = d;
            rules += dd.rules.len;
            dd.deinit(testing.allocator);
        } else |_| {}
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 3), parsed);
    try testing.expectEqual(@as(usize, 1), rules);
}
