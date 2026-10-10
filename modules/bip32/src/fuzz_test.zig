// SPDX-License-Identifier: MIT

//! Shared plumbing for bip32's deterministic fuzz driver (added 2026-10-10).
//!
//! The harness BODIES stay in `root.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness
//! begins with one `slice`, so corpus seeds replay as before). This file
//! holds what they share with the driver: the reach counters with the N-seed
//! in-suite check, and the input draw.
//!
//! Driver: `BIP32_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `bip32-parse`, `bip32-derive`, `bip32-mnemonic`, `bip32-path`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;

/// One harness input into `buf`; returns its length. Under `Smith` (`--fuzz`,
/// `_INPUT` replay) it is exactly `src.slice`. Under the driver's `Rng` half
/// the draws are instead a corpus entry (frames carry a little-endian u32
/// length header; the octets after the frame, if any, are dropped) with 0-3
/// octets damaged and maybe truncated: random bytes alone almost never get
/// past the first grammar check of these parsers.
pub fn drawInput(comptime S: type, src: *S, buf: []u8, corpus: []const []const u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (corpus.len == 0 or !src.value(bool)) return src.slice(buf);
    const entry = corpus[src.index(corpus.len)];
    const flen = std.mem.readInt(u32, entry[0..4], .little);
    const frame = entry[4..][0..@min(flen, entry.len - 4)];
    return damage(src, buf, frame);
}

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated (the
/// driver's `Rng` only; the damage is drawn from `src`).
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels. `mark` also feeds the
/// driver's `REACH` report; `reach` runs `seeds` seeds in the ordinary test
/// binary and fails with `error.HarnessDoesNotReach` if a label never fired.
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
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
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

// ── harnesses ───────────────────────────────────────────────────────────

const bip32 = @import("bip32.zig");
const bip39 = @import("bip39.zig");
const bech32 = @import("bech32");
const Cursor = testkit.fuzz.Cursor;
const Rng = fuzz_driver.Rng;

const ParseMark = Marker(enum { genuine_accepted, accepted_priv, accepted_pub, refused_checksum, refused_structure });
const DeriveMark = Marker(enum { derived, public_matches_private, hardened_refused, roundtrip, flipped_refused, wrong_network_refused });
const MnemonicMark = Marker(enum { genuine_accepted, accepted, refused, reencoded, validate_agrees });
const PathMark = Marker(enum { accepted, refused, canonical });

test "fuzz driver: BIP32_FUZZ (parse)" {
    try fuzz_driver.run(fuzzParse, .{ .prefix = "BIP32_FUZZ", .name = "bip32-parse" });
}
test "fuzz harness: parse, 400 seeds, reaches every outcome" {
    try ParseMark.reach(fuzzParse, "bip32-parse", 400);
}
test "fuzz: parseExtended never panics, and what it accepts re-serializes to the same text" {
    try testing.fuzz({}, struct {
        fn f(_: void, s: *testing.Smith) !void {
            return fuzzParse(testing.Smith, s, testing.allocator);
        }
    }.f, .{});
}

/// A 78-octet extended-key payload from the cursor; `network` picks the
/// version words. Private keys are masked below the group order's top byte.
fn buildPayload(k: *Cursor, network: bip32.Network, payload: *[78]u8) void {
    const is_priv = k.byte() & 1 == 0;
    const v = if (is_priv) network.privVersion() else network.pubVersion();
    std.mem.writeInt(u32, payload[0..4], v, .big);
    const master = k.ranged(0, 3) == 0;
    payload[4] = if (master) 0 else @max(1, k.byte()); // depth 0 demands a zero fingerprint and index
    for (payload[5..9]) |*b| b.* = if (master) 0 else k.byte();
    for (payload[9..13]) |*b| b.* = if (master) 0 else k.byte();
    for (payload[13..45]) |*b| b.* = k.byte();
    var priv: [32]u8 = undefined;
    for (&priv) |*b| b.* = k.byte();
    priv[0] &= 0x7f;
    if (priv[0] == 0 and priv[1] == 0) priv[1] = 1;
    if (is_priv) {
        payload[45] = 0;
        payload[46..78].* = priv;
    } else {
        const kp = bip32.ExtendedPrivKey{ .depth = 0, .parent_fingerprint = @splat(0), .child_number = 0, .chain_code = @splat(0), .privkey = priv };
        const pub_key = bip32.neuter(&kp) catch {
            payload[45..78].* = @splat(0);
            return;
        };
        payload[45..78].* = pub_key.pubkey;
    }
}

fn fuzzParse(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var text_buf: [bip32.max_serialized_len + 8]u8 = undefined;
    var len: usize = undefined;
    var network: bip32.Network = .mainnet;
    var untouched = false;
    if (S == Rng) {
        var raw: [160]u8 = undefined;
        const n: usize = src.slice(&raw);
        var k: Cursor = .{ .bytes = raw[0..n] };
        network = if (k.byte() & 1 == 0) .mainnet else .testnet;
        var payload: [78]u8 = undefined;
        buildPayload(&k, network, &payload);
        // Payload-level damage (valid checksum, bad structure) 1 in 2 ...
        const payload_hits = if (k.byte() & 1 == 0) k.ranged(1, 3) else 0;
        for (0..payload_hits) |_| payload[k.ranged(0, 77)] = k.byte();
        const text = try bech32.base58.checkEncode(&payload, &text_buf);
        len = text.len;
        // ... string-level damage (broken checksum) 1 in 4.
        const string_hits = if (k.ranged(0, 3) == 0) k.ranged(1, 2) else 0;
        for (0..string_hits) |_| text_buf[k.ranged(0, @intCast(len - 1))] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"[k.ranged(0, 57)];
        untouched = payload_hits == 0 and string_hits == 0;
    } else {
        len = src.slice(&text_buf);
    }
    const text = text_buf[0..len];
    var out: bip32.ParsedKey = undefined;
    bip32.parseExtended(text, network, &out) catch |e| {
        if (untouched) return error.GenuineKeyRefused;
        switch (e) {
            error.ChecksumMismatch => ParseMark.mark(.refused_checksum),
            else => ParseMark.mark(.refused_structure),
        }
        return;
    };
    if (untouched) ParseMark.mark(.genuine_accepted);
    // Canonical: an accepted key re-serializes to the very text it came from.
    var again: [bip32.max_serialized_len]u8 = undefined;
    switch (out) {
        .private => |*kp| {
            defer @constCast(kp).deinit();
            ParseMark.mark(.accepted_priv);
            const s = try bip32.serializePriv(kp, network, &again);
            if (!std.mem.eql(u8, s, text)) return error.AcceptedKeyNotCanonical;
        },
        .public => |kp| {
            ParseMark.mark(.accepted_pub);
            const s = try bip32.serializePub(kp, network, &again);
            if (!std.mem.eql(u8, s, text)) return error.AcceptedKeyNotCanonical;
        },
    }
}

test "fuzz driver: BIP32_FUZZ (derive)" {
    try fuzz_driver.run(fuzzDerive, .{ .prefix = "BIP32_FUZZ", .name = "bip32-derive", .scale = 2 });
}
test "fuzz harness: derive, 100 seeds, reaches every outcome" {
    try DeriveMark.reach(fuzzDerive, "bip32-derive", 100);
}
test "fuzz: derivation agrees between the private and public sides, and serialization round-trips" {
    try testing.fuzz({}, struct {
        fn f(_: void, s: *testing.Smith) !void {
            return fuzzDerive(testing.Smith, s, testing.allocator);
        }
    }.f, .{});
}

/// seed -> master -> a few children: `ckdPub(neuter(parent), i)` equals
/// `neuter(ckdPriv(parent, i))` for every non-hardened `i` (the public-parent
/// oracle), `ckdPrivWithParentPub` agrees with `ckdPriv`, a hardened `ckdPub`
/// is refused, serialize/parse round-trips, one changed character of the text
/// and the other network are refused.
fn fuzzDerive(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [120]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };
    var seed: [bip32.max_seed_bytes]u8 = undefined;
    for (&seed) |*b| b.* = k.byte();
    const seed_len = k.ranged(bip32.min_seed_bytes, bip32.max_seed_bytes);
    var node: bip32.ExtendedPrivKey = undefined;
    bip32.masterFromSeed(seed[0..seed_len], &node) catch return;
    defer node.deinit();
    const network: bip32.Network = if (k.byte() & 1 == 0) .mainnet else .testnet;

    for (0..k.ranged(1, 3)) |_| {
        var index: u32 = (@as(u32, k.byte()) << 8) | k.byte();
        if (k.byte() & 1 == 0) index +%= bip32.hardened_offset;
        var child: bip32.ExtendedPrivKey = undefined;
        bip32.ckdPriv(&node, index, &child) catch continue;
        defer child.deinit();
        DeriveMark.mark(.derived);
        const parent_pub = try bip32.neuter(&node);
        var child2: bip32.ExtendedPrivKey = undefined;
        try bip32.ckdPrivWithParentPub(&node, parent_pub.pubkey, index, &child2);
        defer child2.deinit();
        if (!std.mem.eql(u8, &child.privkey, &child2.privkey) or !std.mem.eql(u8, &child.chain_code, &child2.chain_code) or !std.mem.eql(u8, &child.parent_fingerprint, &child2.parent_fingerprint))
            return error.WithParentPubDiffers;
        const child_pub = try bip32.neuter(&child);
        if (index < bip32.hardened_offset) {
            const via_pub = bip32.ckdPub(parent_pub, index) catch return error.PublicDerivationFailed;
            if (!std.mem.eql(u8, &via_pub.pubkey, &child_pub.pubkey) or !std.mem.eql(u8, &via_pub.chain_code, &child_pub.chain_code) or
                via_pub.depth != child_pub.depth or via_pub.child_number != child_pub.child_number or !std.mem.eql(u8, &via_pub.parent_fingerprint, &child_pub.parent_fingerprint))
                return error.PublicParentDisagrees;
            DeriveMark.mark(.public_matches_private);
        } else {
            if (bip32.ckdPub(parent_pub, index)) |_| return error.HardenedPublicAccepted else |e| if (e != error.HardenedRequiresPrivateKey) return error.WrongHardenedError;
            DeriveMark.mark(.hardened_refused);
        }

        // Serialize / parse round trip, both halves.
        var buf: [bip32.max_serialized_len]u8 = undefined;
        const text = try bip32.serializePriv(&child, network, &buf);
        var parsed: bip32.ParsedKey = undefined;
        try bip32.parseExtended(text, network, &parsed);
        defer parsed.private.deinit();
        if (!std.mem.eql(u8, &parsed.private.privkey, &child.privkey) or parsed.private.depth != child.depth or parsed.private.child_number != child.child_number) return error.RoundTripAltered;
        var pbuf: [bip32.max_serialized_len]u8 = undefined;
        const ptext = try bip32.serializePub(child_pub, network, &pbuf);
        var pparsed: bip32.ParsedKey = undefined;
        try bip32.parseExtended(ptext, network, &pparsed);
        if (!std.mem.eql(u8, &pparsed.public.pubkey, &child_pub.pubkey)) return error.PublicRoundTripAltered;
        DeriveMark.mark(.roundtrip);

        // One changed character of the text is refused; so is the other network.
        const at = k.ranged(0, @intCast(text.len - 1));
        const old = buf[at];
        buf[at] = if (old == 'z') 'y' else old + 1;
        var bad: bip32.ParsedKey = undefined;
        if (bip32.parseExtended(buf[0..text.len], network, &bad)) |_| {
            if (std.mem.indexOfScalar(u8, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", buf[at]) != null) return error.ChangedTextAccepted;
        } else |_| {}
        buf[at] = old;
        DeriveMark.mark(.flipped_refused);
        const other: bip32.Network = if (network == .mainnet) .testnet else .mainnet;
        if (bip32.parseExtended(text, other, &bad)) |_| return error.OtherNetworkAccepted else |e| if (e != error.WrongNetwork) return error.WrongNetworkError;
        DeriveMark.mark(.wrong_network_refused);
        node.deinit();
        node = child;
    }
}

test "fuzz driver: BIP32_FUZZ (mnemonic)" {
    try fuzz_driver.run(fuzzMnemonic, .{ .prefix = "BIP32_FUZZ", .name = "bip32-mnemonic" });
}
test "fuzz harness: mnemonic, 400 seeds, reaches every outcome" {
    try MnemonicMark.reach(fuzzMnemonic, "bip32-mnemonic", 400);
}
test "fuzz: mnemonicToEntropy never panics, and what it accepts re-encodes to the same text" {
    try testing.fuzz({}, struct {
        fn f(_: void, s: *testing.Smith) !void {
            return fuzzMnemonic(testing.Smith, s, testing.allocator);
        }
    }.f, .{});
}

fn fuzzMnemonic(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var text_buf: [bip39.max_mnemonic_len + 16]u8 = undefined;
    var len: usize = undefined;
    var untouched = false;
    var entropy_in: [32]u8 = undefined;
    var entropy_in_len: usize = 0;
    if (S == Rng) {
        var raw: [64]u8 = undefined;
        const n: usize = src.slice(&raw);
        var k: Cursor = .{ .bytes = raw[0..n] };
        for (&entropy_in) |*b| b.* = k.byte();
        entropy_in_len = 16 + 4 * k.ranged(0, 4);
        const text = try bip39.entropyToMnemonic(entropy_in[0..entropy_in_len], &text_buf);
        len = text.len;
        const hits = if (k.byte() & 1 == 0) k.ranged(1, 3) else 0;
        for (0..hits) |_| text_buf[k.ranged(0, @intCast(len - 1))] = "abcdefghijklmnopqrstuvwxyz  "[k.ranged(0, 27)];
        // A truncation 1 in 8.
        if (k.ranged(0, 7) == 0) len = k.ranged(0, @intCast(len));
        untouched = hits == 0 and len == text.len;
    } else {
        len = src.slice(&text_buf);
    }
    const text = text_buf[0..len];
    var out: [bip39.max_entropy_bytes]u8 = undefined;
    const ent = bip39.mnemonicToEntropy(text, &out) catch {
        if (untouched) return error.GenuineMnemonicRefused;
        MnemonicMark.mark(.refused);
        if (bip39.validateMnemonic(text)) |_| return error.ValidateDisagrees else |_| {}
        return;
    };
    MnemonicMark.mark(.accepted);
    if (untouched) {
        MnemonicMark.mark(.genuine_accepted);
        if (!std.mem.eql(u8, ent, entropy_in[0..entropy_in_len])) return error.GenuineEntropyAltered;
    }
    bip39.validateMnemonic(text) catch return error.ValidateDisagrees;
    MnemonicMark.mark(.validate_agrees);
    var again: [bip39.max_mnemonic_len]u8 = undefined;
    const t2 = try bip39.entropyToMnemonic(ent, &again);
    if (!std.mem.eql(u8, t2, text)) return error.AcceptedMnemonicNotCanonical;
    MnemonicMark.mark(.reencoded);
}

test "fuzz driver: BIP32_FUZZ (path)" {
    try fuzz_driver.run(fuzzPath, .{ .prefix = "BIP32_FUZZ", .name = "bip32-path" });
}
test "fuzz harness: path, 400 seeds, reaches every outcome" {
    try PathMark.reach(fuzzPath, "bip32-path", 400);
}
test "fuzz: parsePath never panics, and what it accepts has one canonical spelling" {
    try testing.fuzz({}, struct {
        fn f(_: void, s: *testing.Smith) !void {
            return fuzzPath(testing.Smith, s, testing.allocator);
        }
    }.f, .{});
}

fn fuzzPath(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var text_buf: [160]u8 = undefined;
    var len: usize = undefined;
    if (S == Rng) {
        var raw: [40]u8 = undefined;
        const n: usize = src.slice(&raw);
        var k: Cursor = .{ .bytes = raw[0..n] };
        var w: std.Io.Writer = .fixed(&text_buf);
        w.writeAll("m") catch unreachable;
        for (0..k.ranged(0, 6)) |_| {
            const idx: u32 = if (k.byte() & 1 == 0) k.byte() else (@as(u32, k.byte()) << 24 | @as(u32, k.byte()) << 16 | @as(u32, k.byte()) << 8 | k.byte()) & 0x7fff_ffff;
            w.print("/{d}", .{idx}) catch unreachable;
            switch (k.ranged(0, 4)) {
                0 => w.writeAll("'") catch unreachable,
                1 => w.writeAll("h") catch unreachable,
                else => {},
            }
        }
        len = w.buffered().len;
        const hits = if (k.byte() & 1 == 0) k.ranged(1, 2) else 0;
        for (0..hits) |_| text_buf[k.ranged(0, @intCast(len - 1))] = "m/'hH+_0123456789 "[k.ranged(0, 17)];
    } else {
        len = src.slice(&text_buf);
    }
    var out: [bip32.max_path_depth]u32 = undefined;
    const path = bip32.parsePath(text_buf[0..len], &out) catch {
        PathMark.mark(.refused);
        return;
    };
    PathMark.mark(.accepted);
    // Canonical spelling: m/<n>[']; it parses to the same indices, and any
    // accepted spelling (h/H, M, no leading m) maps to it.
    var canon: [320]u8 = undefined;
    var w: std.Io.Writer = .fixed(&canon);
    w.writeAll("m") catch unreachable;
    for (path) |i| {
        if (i >= bip32.hardened_offset) w.print("/{d}'", .{i - bip32.hardened_offset}) catch unreachable else w.print("/{d}", .{i}) catch unreachable;
    }
    var out2: [bip32.max_path_depth]u32 = undefined;
    const path2 = try bip32.parsePath(w.buffered(), &out2);
    if (!std.mem.eql(u32, path, path2)) return error.CanonicalPathDiffers;
    PathMark.mark(.canonical);
}
