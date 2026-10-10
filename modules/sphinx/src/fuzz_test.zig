// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for sphinx (added 2026-10-10): `SPHINX_FUZZ=<runs>[,<first seed>]`
//! (testkit's driver; `_ONLY` selects a harness by name). Harness names:
//! `sphinx-packet` (OnionPacket.fromSlice on damaged genuine packets: accepted
//! means it re-encodes to the input), `sphinx-route` (a whole route built by
//! `construct`, peeled hop by hop; a flipped bit, other associated data or a
//! damaged packet is refused) and `sphinx-forged` (a packet whose HMAC is
//! VALID because the sender chose the ephemeral key, carrying an arbitrary
//! deobfuscated hop frame: `process` returns a result or a typed error for
//! any frame, never a panic).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;
pub const Cursor = testkit.fuzz.Cursor;

/// Reach counters for one harness's labels. `mark` also feeds the driver's
/// `REACH` report; `reach` runs `seeds` seeds in the ordinary test binary and
/// fails with `error.HarnessDoesNotReach` if a label never fired.
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

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated.
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

/// Deterministic bytes from a knob cursor (its first octets seed a PRNG).
pub fn expand(knobs: *Cursor, out: []u8) void {
    var s: u64 = 0;
    for (0..8) |_| s = (s << 8) | knobs.byte();
    var prng = std.Random.DefaultPrng.init(s);
    prng.random().bytes(out);
}

/// Smith-side wrapper so `--fuzz` keeps working: the harness bodies are
/// generic over `S`; `testing.fuzz` hands them a `std.testing.Smith`.
pub fn smithWrap(comptime harness: anytype) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            try harness(std.testing.Smith, smith, testing.allocator);
        }
    }.f;
}

const sphinx = @import("root.zig");
const keyderive = @import("keyderive.zig");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const OnionPacket = sphinx.OnionPacket;
const packet_len = sphinx.packet_len;
const hop_payloads_len = sphinx.hop_payloads_len;

fn flipBit(knobs: *Cursor, bytes: []u8) usize {
    const at = (@as(usize, knobs.byte()) << 8 | knobs.byte()) % bytes.len;
    bytes[at] ^= @as(u8, 1) << @intCast(knobs.ranged(0, 7));
    return at;
}

fn privKey(knobs: *Cursor) [32]u8 {
    var k: [32]u8 = undefined;
    expand(knobs, &k);
    k[0] &= 0x7f; // below the group order, never zero in practice
    k[0] |= 0x01;
    return k;
}

fn pubOf(k: [32]u8) ![sphinx.pubkey_len]u8 {
    return (try Secp256k1.basePoint.mul(k, .big)).toCompressedSec1();
}

const Route = struct {
    n: usize,
    privs: [4][32]u8,
    pubs: [4][sphinx.pubkey_len]u8,
    payloads: [4][40]u8,
    plens: [4]usize,
    session: [32]u8,
    ad: [8]u8,
    pkt: OnionPacket,

    fn make(knobs: *Cursor) !Route {
        var r: Route = undefined;
        r.n = knobs.ranged(1, 4);
        for (0..r.n) |i| {
            r.privs[i] = privKey(knobs);
            r.pubs[i] = try pubOf(r.privs[i]);
            expand(knobs, &r.payloads[i]);
            r.plens[i] = knobs.ranged(2, 40);
        }
        r.session = privKey(knobs);
        expand(knobs, &r.ad);
        var slices: [4][]const u8 = undefined;
        for (0..r.n) |i| slices[i] = r.payloads[i][0..r.plens[i]];
        r.pkt = try sphinx.construct(&r.session, r.pubs[0..r.n], slices[0..r.n], &r.ad);
        return r;
    }
};

const PacketMark = Marker(enum { accepted, refused_version, refused_key, refused_length });

fn fuzzPacket(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [32]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    const r = try Route.make(&knobs);
    const wire = r.pkt.toBytes();
    var buf: [packet_len + 8]u8 = undefined;
    const n = damage(src, &buf, &wire);
    // The version octet and the public key are the only bytes the decoder reads.
    if (n > 34 and knobs.byte() % 3 == 0) buf[src.index(34)] = src.value(u8);
    if (OnionPacket.fromSlice(buf[0..n])) |p| {
        if (!std.mem.eql(u8, &p.toBytes(), buf[0..n])) return error.NonCanonicalPacketAccepted;
        PacketMark.mark(.accepted);
    } else |e| switch (e) {
        error.UnsupportedVersion => PacketMark.mark(.refused_version),
        error.InvalidPublicKey => PacketMark.mark(.refused_key),
        error.WrongLength => PacketMark.mark(.refused_length),
    }
}

test "fuzz: sphinx packet decoder is canonical" {
    try testing.fuzz({}, smithWrap(fuzzPacket), .{});
}
test "fuzz driver: SPHINX_FUZZ (packet)" {
    try fuzz_driver.run(fuzzPacket, .{ .prefix = "SPHINX_FUZZ", .name = "sphinx-packet", .scale = 2 });
}
test "fuzz harness: packet, 400 seeds, reaches every outcome" {
    try PacketMark.reach(fuzzPacket, "sphinx-packet", 400);
}

const RouteMark = Marker(enum { peeled, final_hop, forwarded, flipped_refused, wrong_ad_refused, damaged_refused, wrong_node_refused, multi_hop });

fn fuzzRoute(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [32]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    const r = try Route.make(&knobs);

    // Genuine: every hop peels its own payload, the last one is final.
    var pkt = r.pkt;
    for (0..r.n) |i| {
        const res = sphinx.process(&r.privs[i], pkt, &r.ad) catch return error.GenuineHopRefused;
        if (!std.mem.eql(u8, res.payload(), r.payloads[i][0..r.plens[i]])) return error.PayloadDiffers;
        RouteMark.mark(.peeled);
        if (i + 1 == r.n) {
            if (res.next_packet != null) return error.FinalHopForwards;
            RouteMark.mark(.final_hop);
        } else {
            pkt = res.next_packet orelse return error.MiddleHopDoesNotForward;
            RouteMark.mark(.forwarded);
        }
    }
    if (r.n > 1) RouteMark.mark(.multi_hop);

    // One flipped bit anywhere in the first packet, through the wire decoder.
    const wire = r.pkt.toBytes();
    {
        var b = wire;
        _ = flipBit(&knobs, &b);
        if (OnionPacket.fromSlice(&b)) |p| {
            if (sphinx.process(&r.privs[0], p, &r.ad)) |_| return error.FlippedPacketAccepted else |_| {}
        } else |_| {}
        RouteMark.mark(.flipped_refused);
    }
    // Other associated data.
    {
        var ad2 = r.ad;
        _ = flipBit(&knobs, &ad2);
        if (sphinx.process(&r.privs[0], r.pkt, &ad2)) |_| return error.WrongAdAccepted else |_| {}
        if (sphinx.process(&r.privs[0], r.pkt, r.ad[0..7])) |_| return error.WrongAdAccepted else |_| {}
        RouteMark.mark(.wrong_ad_refused);
    }
    // A node that is not hop 0.
    {
        const other = privKey(&knobs);
        if (!std.mem.eql(u8, &other, &r.privs[0])) {
            if (sphinx.process(&other, r.pkt, &r.ad)) |_| return error.WrongNodeAccepted else |_| {}
            RouteMark.mark(.wrong_node_refused);
        }
    }
    // Multi-octet damage / truncation.
    {
        var buf: [packet_len + 8]u8 = undefined;
        const n = damage(src, &buf, &wire);
        if (OnionPacket.fromSlice(buf[0..n])) |p| {
            if (sphinx.process(&r.privs[0], p, &r.ad)) |_| {
                if (!std.mem.eql(u8, buf[0..n], &wire)) return error.DamagedPacketAccepted;
            } else |_| RouteMark.mark(.damaged_refused);
        } else |_| RouteMark.mark(.damaged_refused);
    }
}

test "fuzz: sphinx route, genuine peeled / damaged refused" {
    try testing.fuzz({}, smithWrap(fuzzRoute), .{});
}
test "fuzz driver: SPHINX_FUZZ (route)" {
    try fuzz_driver.run(fuzzRoute, .{ .prefix = "SPHINX_FUZZ", .name = "sphinx-route", .scale = 4 });
}
test "fuzz harness: route, 60 seeds, reaches every outcome" {
    try RouteMark.reach(fuzzRoute, "sphinx-route", 60);
}

const ForgedMark = Marker(enum { final_hop, forwarded, malformed, reserved, huge_length, boundary_length });

/// A packet addressed to `node_pub` whose HMAC verifies: the sender picks
/// the ephemeral key, so it knows the shared secret and may put ANY bytes
/// under the obfuscation.
fn forge(node_pub: [sphinx.pubkey_len]u8, eph: [32]u8, plain: *const [hop_payloads_len]u8, ad: []const u8) !OnionPacket {
    const node_point = try Secp256k1.fromSec1(&node_pub);
    const ss_point = try node_point.mul(eph, .big);
    var ss: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&ss_point.toCompressedSec1(), &ss, .{});
    var rho: [32]u8 = undefined;
    keyderive.generateKey(&rho, .rho, &ss);
    var mu: [32]u8 = undefined;
    keyderive.generateKey(&mu, .mu, &ss);
    var stream: [hop_payloads_len]u8 = undefined;
    keyderive.generateCipherStream(&rho, &stream);
    var pkt: OnionPacket = undefined;
    pkt.version = 0;
    pkt.public_key = try pubOf(eph);
    for (&pkt.hop_payloads, plain, stream) |*o, p, s| o.* = p ^ s;
    var mac = std.crypto.auth.hmac.sha2.HmacSha256.init(&mu);
    mac.update(&pkt.hop_payloads);
    mac.update(ad);
    mac.final(&pkt.hmac);
    return pkt;
}

fn fuzzForged(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [32]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    const node = privKey(&knobs);
    const node_pub = try pubOf(node);
    const eph = privKey(&knobs);
    var ad: [4]u8 = undefined;
    expand(&knobs, &ad);

    var plain: [hop_payloads_len]u8 = undefined;
    expand(&knobs, plain[0..32]);
    src.bytes(&plain);
    // A structured frame in front: a bigsize of every width, a length near a
    // boundary or huge, then a next-hmac that is zero or random.
    const shape = knobs.ranged(0, 5);
    var at: usize = 0;
    switch (shape) {
        0 => {}, // pure random
        1 => { // 0xff + 8-octet length
            plain[0] = 0xff;
            std.mem.writeInt(u64, plain[1..9], switch (knobs.ranged(0, 4)) {
                0 => std.math.maxInt(u64),
                1 => std.math.maxInt(u64) - 31,
                2 => std.math.maxInt(u64) - 32,
                3 => @as(u64, 1) << 32,
                else => std.mem.readInt(u64, plain[9..17], .big) | (@as(u64, 1) << 33),
            }, .big);
            ForgedMark.mark(.huge_length);
        },
        2 => { // 0xfe + 4-octet length
            plain[0] = 0xfe;
            std.mem.writeInt(u32, plain[1..5], @as(u32, 0x10000) + knobs.ranged(0, 255) * 0x1000000 / 256, .big);
        },
        3 => { // 0xfd + 2-octet length, near the 1300-octet boundary
            plain[0] = 0xfd;
            const lens = [_]u16{ 0xfd, 1266, 1267, 1268, 1299, 1300, 1301, 0xffff };
            std.mem.writeInt(u16, plain[1..3], lens[knobs.ranged(0, lens.len - 1)], .big);
            ForgedMark.mark(.boundary_length);
        },
        4 => { // one-octet length, small
            const pick = knobs.ranged(0, 0xfc);
            plain[0] = @intCast(if (pick % 7 == 0) pick % 2 else pick); // 0 and 1 are the reserved lengths
            at = 1 + plain[0];
            if (at + 32 <= plain.len and knobs.byte() & 1 == 0) @memset(plain[at..][0..32], 0); // final hop
        },
        else => { // a valid-looking frame with a zero next_hmac somewhere
            plain[0] = 0x10;
            @memset(plain[17..49], 0);
        },
    }
    const pkt = try forge(node_pub, eph, &plain, &ad);
    if (sphinx.process(&node, pkt, &ad)) |res| {
        if (res.payload().len > hop_payloads_len) return error.PayloadTooLong;
        if (res.next_packet) |_| ForgedMark.mark(.forwarded) else ForgedMark.mark(.final_hop);
    } else |e| switch (e) {
        error.MalformedPayload => ForgedMark.mark(.malformed),
        error.ReservedPayloadLength => ForgedMark.mark(.reserved),
        else => {}, // InvalidPublicKey / IdentityElement: not reachable for a valid forge
    }
}

test "fuzz: sphinx process on authenticated hostile frames" {
    try testing.fuzz({}, smithWrap(fuzzForged), .{});
}
test "fuzz driver: SPHINX_FUZZ (forged)" {
    try fuzz_driver.run(fuzzForged, .{ .prefix = "SPHINX_FUZZ", .name = "sphinx-forged" });
}
test "fuzz harness: forged, 600 seeds, reaches every outcome" {
    try ForgedMark.reach(fuzzForged, "sphinx-forged", 600);
}
