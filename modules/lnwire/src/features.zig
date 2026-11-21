// SPDX-License-Identifier: MIT
//! BOLT#9 feature bit vectors — the `features` byte arrays in `init`,
//! `node_announcement`, `channel_announcement` and the `channel_type` TLV.
//!
//! Layout (BOLT#9: "Flags are numbered from the least-significant bit, at
//! bit 0"; BOLT#1: every field is big-endian): bit `n` lives in octet
//! `len - 1 - n / 8`, mask `1 << (n % 8)`. Features come in pairs —
//! even = compulsory, odd = optional — and BOLT#1's "it's ok to be odd"
//! rule means only an unknown EVEN bit makes a peer incompatible.
//!
//! The raw functions take bit numbers; `Feature`/`table` below add every NAMED
//! row of BOLT#9's table, with `setFeature`/`hasFeature`/`checkDependencies`.
//! Unlisted bits stay usable through the numeric functions. Every function
//! is a pure read over (or write into) a caller-owned slice; out-of-range
//! bits read as unset.

const std = @import("std");

/// Whether `bit` is set. A bit beyond the vector's length is unset.
pub fn isSet(features: []const u8, bit: usize) bool {
    const octet = bit / 8;
    if (octet >= features.len) return false;
    return features[features.len - 1 - octet] & (@as(u8, 1) << @intCast(bit % 8)) != 0;
}

/// Whether either bit of `bit`'s pair (compulsory or optional) is set — the
/// usual "does the peer support this feature" question.
pub fn supports(features: []const u8, bit: usize) bool {
    const even = bit & ~@as(usize, 1);
    return isSet(features, even) or isSet(features, even + 1);
}

/// The octet count a vector needs to hold `bit`.
pub fn byteLenFor(bit: usize) usize {
    return bit / 8 + 1;
}

/// Sets `bit` in `buf` (same layout). Refuses a buffer too short to hold it
/// rather than dropping the bit.
pub fn set(buf: []u8, bit: usize) error{BufferTooSmall}!void {
    const octet = bit / 8;
    if (octet >= buf.len) return error.BufferTooSmall;
    buf[buf.len - 1 - octet] |= @as(u8, 1) << @intCast(bit % 8);
}

/// The lowest EVEN (compulsory) bit set whose pair is not in `known` — the
/// bit that makes the peer incompatible (BOLT#1 `init`: "if the feature
/// vector sets required features unknown to it: MUST close the
/// connection"). `known` lists either bit of each understood pair. An
/// unknown ODD bit is never returned.
pub fn firstUnknownEvenBit(features: []const u8, known: []const u16) ?usize {
    var bit: usize = 0;
    const total = features.len * 8;
    while (bit < total) : (bit += 2) {
        if (!isSet(features, bit)) continue;
        const understood = for (known) |k| {
            if (@as(usize, k) & ~@as(usize, 1) == bit) break true;
        } else false;
        if (!understood) return bit;
    }
    return null;
}

/// `features` with leading all-zero octets removed — the minimal `flen`
/// BOLT#7 asks an origin to send ("SHOULD set `flen` to the minimum length
/// required to hold the `features` bits it sets"). Borrows the input.
pub fn minimal(features: []const u8) []const u8 {
    var i: usize = 0;
    while (i < features.len and features[i] == 0) i += 1;
    return features[i..];
}

/// Where a feature may appear (BOLT#9 "Context" column: I, N, C, 9, B, T; the C-/C+ variants
/// (always odd / always even in `channel_announcement`) are not distinguished).
pub const Contexts = packed struct {
    init: bool = false, // I: `init` message
    node_announcement: bool = false, // N
    channel_announcement: bool = false, // C
    invoice: bool = false, // 9: BOLT#11 invoice
    blinded_path: bool = false, // B
    channel_type: bool = false, // T: used in the `channel_type` field when opening channels
};

/// Named BOLT#9 features: every row of the table in `lightning/bolts` `09-features.md` (master,
/// 2026-11), including the `ASSUMED` ones. The value is the EVEN (compulsory) bit; the odd
/// (optional) bit is `bit + 1`. Names follow BOLT#9 without the `option_` prefix.
pub const Feature = enum(u16) {
    data_loss_protect = 0,
    upfront_shutdown_script = 4,
    gossip_queries = 6,
    var_onion_optin = 8,
    gossip_queries_ex = 10,
    static_remotekey = 12,
    payment_secret = 14,
    basic_mpp = 16,
    support_large_channel = 18,
    anchors = 22,
    route_blinding = 24,
    shutdown_anysegwit = 26,
    dual_fund = 28,
    quiesce = 34,
    attribution_data = 36,
    onion_messages = 38,
    zero_fee_commitments = 40,
    provide_storage = 42,
    channel_type = 44,
    scid_alias = 46,
    payment_metadata = 48,
    zeroconf = 50,
    simple_close = 60,
    splice = 62,
    onion_messages_only_channels = 66,

    /// The compulsory (even) bit.
    pub fn evenBit(self: Feature) usize {
        return @backingInt(self);
    }
    /// The optional (odd) bit.
    pub fn oddBit(self: Feature) usize {
        return @as(usize, @backingInt(self)) + 1;
    }
};

/// One row of BOLT#9's table.
pub const Row = struct {
    feature: Feature,
    contexts: Contexts,
    /// Features that must also be supported (either bit) when this one is set.
    deps: []const Feature = &.{},
};

/// BOLT#9's table, row for row (bits, `Context` column, `Dependencies` column) as in
/// `lightning/bolts` `09-features.md` master, 2026-11. `ASSUMED` features have an empty context.
/// Not rows of that table, hence not named here: bit 3 (`initial_routing_sync`), the bits of
/// `option_anchor_outputs` (20/21, removed from the table in favour of `anchors`, 22/23), and
/// experimental/staging bits (trampoline routing, ...); all stay usable through the numeric
/// functions.
pub const table = [_]Row{
    .{ .feature = .data_loss_protect, .contexts = .{} },
    .{ .feature = .upfront_shutdown_script, .contexts = .{ .init = true, .node_announcement = true } },
    .{ .feature = .gossip_queries, .contexts = .{} },
    .{ .feature = .var_onion_optin, .contexts = .{} },
    .{ .feature = .gossip_queries_ex, .contexts = .{ .init = true, .node_announcement = true } },
    .{ .feature = .static_remotekey, .contexts = .{} },
    .{ .feature = .payment_secret, .contexts = .{} },
    .{ .feature = .basic_mpp, .contexts = .{ .init = true, .node_announcement = true, .invoice = true }, .deps = &.{.payment_secret} },
    .{ .feature = .support_large_channel, .contexts = .{ .init = true, .node_announcement = true } },
    .{ .feature = .anchors, .contexts = .{ .init = true, .node_announcement = true, .channel_type = true } },
    .{ .feature = .route_blinding, .contexts = .{ .init = true, .node_announcement = true, .invoice = true } },
    .{ .feature = .shutdown_anysegwit, .contexts = .{ .init = true, .node_announcement = true } },
    .{ .feature = .dual_fund, .contexts = .{ .init = true, .node_announcement = true } },
    .{ .feature = .quiesce, .contexts = .{ .init = true, .node_announcement = true } },
    .{ .feature = .attribution_data, .contexts = .{ .init = true, .node_announcement = true, .invoice = true } },
    .{ .feature = .onion_messages, .contexts = .{ .init = true, .node_announcement = true } },
    .{ .feature = .zero_fee_commitments, .contexts = .{ .init = true, .node_announcement = true }, .deps = &.{.channel_type} },
    .{ .feature = .provide_storage, .contexts = .{ .init = true, .node_announcement = true } },
    .{ .feature = .channel_type, .contexts = .{} },
    .{ .feature = .scid_alias, .contexts = .{ .init = true, .node_announcement = true, .channel_type = true } },
    .{ .feature = .payment_metadata, .contexts = .{ .invoice = true } },
    .{ .feature = .zeroconf, .contexts = .{ .init = true, .node_announcement = true, .channel_type = true }, .deps = &.{.scid_alias} },
    .{ .feature = .simple_close, .contexts = .{ .init = true, .node_announcement = true }, .deps = &.{.shutdown_anysegwit} },
    .{ .feature = .splice, .contexts = .{ .init = true, .node_announcement = true } },
    .{ .feature = .onion_messages_only_channels, .contexts = .{ .init = true, .node_announcement = true }, .deps = &.{.onion_messages} },
};

/// The table row for `f` (every `Feature` has one).
pub fn row(f: Feature) Row {
    for (table) |r| if (r.feature == f) return r;
    unreachable; // comptime-checked by the "every Feature has a row" test
}

/// Sets `f` in `buf`: the odd (optional) bit, or the even (compulsory) bit
/// when `compulsory`. Same short-buffer refusal as `set`.
pub fn setFeature(buf: []u8, f: Feature, compulsory: bool) error{BufferTooSmall}!void {
    try set(buf, if (compulsory) f.evenBit() else f.oddBit());
}

/// Whether `f` is supported: either bit of its pair is set.
pub fn hasFeature(features: []const u8, f: Feature) bool {
    return supports(features, f.evenBit());
}

/// The first (table order) named feature that is set (either bit) while a
/// dependency of it is not, as `{feature, missing dependency}`; null if
/// consistent. Only table rows are checked; unnamed bits are ignored.
pub fn checkDependencies(features: []const u8) ?struct { feature: Feature, missing: Feature } {
    for (table) |r| {
        if (!hasFeature(features, r.feature)) continue;
        for (r.deps) |d| if (!hasFeature(features, d)) return .{ .feature = r.feature, .missing = d };
    }
    return null;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const au_kat = @import("bolt7_announcement_update_kat_vectors.zig");

test "EXTERNAL: rust-lightning's node_announcement features (`2 | 1 << 5` and 0xFFFF) read as those bits" {
    // rust-lightning builds the baseline vector's features as
    // `NodeFeatures::from_le_bytes(vec![2 | 1 << 5])` — bits 1
    // (option_data_loss_protect, optional) and 5 (option_upfront_shutdown_script,
    // optional) — and its wire hex for them is "22".
    var buf: [2]u8 = undefined;
    const base = au_kat.node_announcement_vectors[1];
    try testing.expectEqualStrings("22", base.features_hex);
    const f = try std.fmt.hexToBytes(&buf, base.features_hex);
    for (0..16) |b| try testing.expectEqual(b == 1 or b == 5, isSet(f, b));
    try testing.expect(supports(f, 0) and supports(f, 4) and !supports(f, 2));
    try testing.expectEqual(@as(?usize, null), firstUnknownEvenBit(f, &.{}));

    // `from_le_bytes(vec![0xFF, 0xFF])`: bits 0..15 all set, so with nothing
    // known the first incompatibility is bit 0, and with 0..13 known it is 14.
    const all = au_kat.node_announcement_vectors[0];
    try testing.expectEqualStrings("ffff", all.features_hex);
    const g = try std.fmt.hexToBytes(&buf, all.features_hex);
    for (0..16) |b| try testing.expect(isSet(g, b));
    try testing.expect(!isSet(g, 16));
    try testing.expectEqual(@as(?usize, 0), firstUnknownEvenBit(g, &.{}));
    try testing.expectEqual(@as(?usize, 14), firstUnknownEvenBit(g, &.{ 0, 3, 4, 7, 8, 10, 13, 12 }));
}

test "SELF-DERIVED (BOLT#9 text): bit numbering runs from the LAST octet" {
    // Byte order is not distinguishable in any vendored vector (all are one
    // octet or all-0xFF), so this is from BOLT#9/BOLT#1's wording alone.
    var buf: [3]u8 = @splat(0);
    try set(&buf, 0);
    try set(&buf, 9);
    try set(&buf, 23);
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x02, 0x01 }, &buf);
    try testing.expect(isSet(&buf, 9) and !isSet(&buf, 8) and !isSet(&buf, 1));
    try testing.expectError(error.BufferTooSmall, set(&buf, 24));
    try testing.expectEqual(@as(usize, 4), byteLenFor(24));
    try testing.expect(!isSet(&buf, 1000));
    try testing.expect(!isSet(&.{}, 0));
    // An odd unknown bit is fine; the even one is not.
    try testing.expectEqual(@as(?usize, null), firstUnknownEvenBit(&.{ 0x00, 0x02 }, &.{}));
    try testing.expectEqual(@as(?usize, 8), firstUnknownEvenBit(&.{ 0x01, 0x02 }, &.{}));
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00 }, minimal(&.{ 0x00, 0x00, 0x01, 0x00 }));
    try testing.expectEqual(@as(usize, 0), minimal(&.{ 0, 0 }).len);
}

test "named feature table: bits, set/has by name, both bits" {
    try testing.expectEqual(@as(usize, 14), Feature.payment_secret.evenBit());
    try testing.expectEqual(@as(usize, 15), Feature.payment_secret.oddBit());
    var buf: [2]u8 = @splat(0);
    try setFeature(&buf, .var_onion_optin, false);
    try testing.expect(isSet(&buf, 9) and !isSet(&buf, 8));
    try testing.expect(hasFeature(&buf, .var_onion_optin));
    try setFeature(&buf, .data_loss_protect, true);
    try testing.expect(isSet(&buf, 0) and hasFeature(&buf, .data_loss_protect));
    try testing.expect(!hasFeature(&buf, .gossip_queries));
    // quiesce is bit 34: a 2-octet buffer refuses it.
    try testing.expectError(error.BufferTooSmall, setFeature(&buf, .quiesce, false));
    var big: [7]u8 = @splat(0); // holds bit 50/51
    try setFeature(&big, .zeroconf, true);
    try testing.expect(isSet(&big, 50) and hasFeature(&big, .zeroconf));
}

test "named feature table: every Feature has exactly one row, deps are in-table" {
    for (std.enums.values(Feature)) |f| {
        var n: usize = 0;
        for (table) |r| {
            if (r.feature == f) n += 1;
        }
        try testing.expectEqual(@as(usize, 1), n);
    }
    for (table) |r| {
        try testing.expectEqual(@as(usize, 0), r.feature.evenBit() % 2);
        for (r.deps) |d| try testing.expect(d != r.feature);
    }
    try testing.expect(row(.basic_mpp).deps[0] == .payment_secret);
    try testing.expect(row(.payment_metadata).contexts.invoice and !row(.payment_metadata).contexts.init);
    // The table is exactly the BOLT#9 rows: bits as published, ASSUMED rows without a context.
    try testing.expectEqual(@as(usize, 25), table.len);
    try testing.expectEqual(@as(usize, 28), Feature.dual_fund.evenBit());
    try testing.expectEqual(@as(usize, 36), Feature.attribution_data.evenBit());
    try testing.expectEqual(@as(usize, 38), Feature.onion_messages.evenBit());
    try testing.expectEqual(@as(usize, 40), Feature.zero_fee_commitments.evenBit());
    try testing.expectEqual(@as(usize, 42), Feature.provide_storage.evenBit());
    try testing.expectEqual(@as(usize, 60), Feature.simple_close.evenBit());
    try testing.expectEqual(@as(usize, 62), Feature.splice.evenBit());
    try testing.expectEqual(@as(usize, 66), Feature.onion_messages_only_channels.evenBit());
    try testing.expect(row(.anchors).contexts.channel_type and row(.scid_alias).contexts.channel_type and row(.zeroconf).contexts.channel_type);
    try testing.expect(!row(.payment_secret).contexts.init and !row(.data_loss_protect).contexts.init);
    try testing.expect(row(.attribution_data).contexts.invoice and row(.attribution_data).contexts.init);
    try testing.expect(row(.simple_close).deps[0] == .shutdown_anysegwit);
    try testing.expect(row(.zero_fee_commitments).deps[0] == .channel_type);
    try testing.expect(row(.onion_messages_only_channels).deps[0] == .onion_messages);
}

test "checkDependencies: set but dependency missing" {
    var buf: [9]u8 = @splat(0); // holds bit 66/67
    try testing.expectEqual(null, checkDependencies(&buf));
    try setFeature(&buf, .basic_mpp, false);
    const r = checkDependencies(&buf).?;
    try testing.expect(r.feature == .basic_mpp and r.missing == .payment_secret);
    try setFeature(&buf, .payment_secret, true);
    try testing.expectEqual(null, checkDependencies(&buf));
    // Either bit of the dependency's pair satisfies it; zeroconf needs scid_alias.
    try setFeature(&buf, .zeroconf, false);
    try testing.expect(checkDependencies(&buf).?.missing == .scid_alias);
    try setFeature(&buf, .scid_alias, true);
    try testing.expectEqual(null, checkDependencies(&buf));
    // The newer rows: simple_close needs shutdown_anysegwit, onion_messages_only_channels needs
    // onion_messages, zero_fee_commitments needs channel_type.
    try setFeature(&buf, .simple_close, false);
    try testing.expect(checkDependencies(&buf).?.missing == .shutdown_anysegwit);
    try setFeature(&buf, .shutdown_anysegwit, false);
    try testing.expectEqual(null, checkDependencies(&buf));
    try setFeature(&buf, .onion_messages_only_channels, true);
    try testing.expect(checkDependencies(&buf).?.missing == .onion_messages);
    try setFeature(&buf, .onion_messages, false);
    try testing.expectEqual(null, checkDependencies(&buf));
    try setFeature(&buf, .zero_fee_commitments, false);
    try testing.expect(checkDependencies(&buf).?.missing == .channel_type);
    try setFeature(&buf, .channel_type, true);
    try testing.expectEqual(null, checkDependencies(&buf));
    // Empty vector is consistent.
    try testing.expectEqual(null, checkDependencies(&.{}));
}
