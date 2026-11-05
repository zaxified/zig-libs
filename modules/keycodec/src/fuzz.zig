// SPDX-License-Identifier: MIT

//! Fuzz harness: keys built from the script, written, read back; then the
//! written DER and PEM mutated and read again.
//!
//! One draw, the script; its bytes pick the algorithm, the encoding and every
//! part. Oracles:
//!  - round trip: a key built from random parts writes, and reads back into
//!    exactly those parts (DER and PEM paths), unless it is an EC scalar out
//!    of [1, n) -- decided here by an independent big-integer comparison
//!    against std's (and the p521 constant's) group orders, not by the
//!    module's borrow chain;
//!  - mutation: any DER or PEM the reader accepts is writable, and what is
//!    written reads back into the same parts (a fixpoint); any input is an
//!    error or a key, never a panic;
//!  - SPKI: a public key built from random parts round-trips.

const std = @import("std");
const testing = std.testing;
const kc = @import("root.zig");
const fuzzseed = @import("testkit").fuzz;
const fuzz_driver = fuzzseed.driver;

const max_script = 512;

const Reach = enum { rt_ec, rt_rsa, rt_edx, rt_pq, ec_out_of_range, mut_ok, mut_err, pem_mut_ok, pem_mut_err, spki_rt };
var reach: [@typeInfo(Reach).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Reach) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

const seeds = [_][]const u8{
    fuzzseed.seed(""),
    fuzzseed.seed("\x00\x00\x00\x20"), // round trip, P-256, PKCS#8
    fuzzseed.seed("\x01\x08\x01\x05\x03"), // mutation, RSA
    fuzzseed.seed("\x02\x0c\x00\x02"), // PEM mutation, ML-KEM
    fuzzseed.seed("\x03\x04\x00"), // SPKI, Ed25519
};

test "fuzz: keycodec round trips and mutations" {
    try testing.fuzz({}, fuzzOne, .{ .corpus = &seeds });
}

fn fuzzOne(_: void, smith: *testing.Smith) !void {
    var buf: [max_script]u8 = undefined;
    const n = smith.slice(&buf);
    var src: Replay = .{ .data = buf[0..n] };
    return harness(Replay, &src, testing.allocator);
}

const Replay = struct {
    data: []const u8,
    pub fn slice(self: *Replay, out: []u8) u32 {
        @memcpy(out[0..self.data.len], self.data);
        return @intCast(self.data.len);
    }
};

/// Generic over the choice source (`testing.Smith` under `--fuzz`, the
/// driver's `Rng`): the only draw is the one `slice`.
pub fn harness(comptime Src: type, src: *Src, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var script_buf: [max_script]u8 = undefined;
    const n = src.slice(&script_buf);
    var cur: fuzzseed.Cursor = .{ .bytes = script_buf[0..n] };
    const mode = cur.byte() % 4;
    var parts: Parts = undefined;
    const key = build(&cur, &parts);
    switch (mode) {
        0 => try roundTrip(key),
        1 => try mutateDer(key, &cur),
        2 => try mutatePem(key, &cur),
        3 => try spkiRoundTrip(&cur, &parts),
        else => unreachable,
    }
}

const algorithms = std.enums.values(kc.Algorithm);

/// Storage for the parts a built key points into.
const Parts = struct {
    secret: [8192]u8,
    expanded: [4896]u8,
    public: [2592]u8,
    params: [2]u8,
};

fn fill(cur: *fuzzseed.Cursor, out: []u8) void {
    for (out) |*b| b.* = cur.byte();
}

/// A key of a script-chosen algorithm and encoding, from script bytes.
fn build(cur: *fuzzseed.Cursor, p: *Parts) kc.PrivateKey {
    const a = algorithms[cur.byte() % algorithms.len];
    var k: kc.PrivateKey = .{ .algorithm = a, .encoding = .pkcs8, .secret = &.{} };
    const flags = cur.byte();
    if (a.isEc()) {
        if (flags & 1 != 0) k.encoding = .sec1;
        const n = a.secretLen().?;
        const len = cur.ranged(1, @intCast(n));
        fill(cur, p.secret[0..len]);
        // Mostly in range: clear the top byte's high bits half the time.
        if (flags & 2 != 0 and len == n) p.secret[0] &= if (a == .ec_p521) 0x01 else 0x7f;
        k.secret = p.secret[0..len];
        if (flags & 4 != 0) {
            const pl = a.publicLen().?;
            p.public[0] = 0x04;
            fill(cur, p.public[1..pl]);
            k.public = p.public[0..pl];
        }
    } else if (a.isRsa()) {
        if (a == .rsa and flags & 1 != 0) k.encoding = .pkcs1;
        k.secret = pkcs1(cur, p.secret[0..]);
        if (a == .rsa_pss and flags & 2 != 0) {
            p.params = .{ 0x30, 0x00 };
            k.parameters = &p.params;
        }
    } else if (a.isPq()) {
        const form: kc.PqForm = @fromBackingInt(@intCast(flags % 3));
        k.pq_form = form;
        switch (form) {
            .seed => {
                fill(cur, p.secret[0..a.secretLen().?]);
                k.secret = p.secret[0..a.secretLen().?];
            },
            .expanded => {
                fill(cur, p.secret[0..a.expandedLen().?]);
                k.secret = p.secret[0..a.expandedLen().?];
            },
            .both => {
                fill(cur, p.secret[0..a.secretLen().?]);
                fill(cur, p.expanded[0..a.expandedLen().?]);
                k.secret = p.secret[0..a.secretLen().?];
                k.expanded = p.expanded[0..a.expandedLen().?];
            },
        }
    } else {
        fill(cur, p.secret[0..a.secretLen().?]);
        k.secret = p.secret[0..a.secretLen().?];
        if (flags & 4 != 0) {
            fill(cur, p.public[0..a.publicLen().?]);
            k.public = p.public[0..a.publicLen().?];
        }
    }
    return k;
}

/// An RSAPrivateKey of eight random non-empty INTEGERs (version 0).
fn pkcs1(cur: *fuzzseed.Cursor, out: []u8) []const u8 {
    var ints: [8][8]u8 = undefined;
    var lens: [8]usize = undefined;
    var content: usize = 3;
    for (&ints, &lens) |*i, *l| {
        l.* = cur.ranged(1, 8);
        fill(cur, i[0..l.*]);
        content += 2 + l.*;
    }
    var w = kc.der.Writer.init(out);
    w.header(0x30, content);
    w.tlv(0x02, &.{0});
    for (ints, lens) |i, l| w.tlv(0x02, i[0..l]);
    return w.finish() catch unreachable; // < 100 bytes into 8 KiB
}

/// Independent model of "an EC scalar in [1, n)": big-endian integers.
fn scalarValid(a: kc.Algorithm, raw: []const u8) bool {
    var padded: [66]u8 = @splat(0);
    @memcpy(padded[66 - raw.len ..], raw);
    const v = std.mem.readInt(u528, &padded, .big);
    const n: u528 = switch (a) {
        .ec_p256 => std.crypto.ecc.P256.scalar.field_order,
        .ec_p384 => std.crypto.ecc.P384.scalar.field_order,
        .ec_secp256k1 => std.crypto.ecc.Secp256k1.scalar.field_order,
        .ec_p521 => @import("p521").scalar.field_order,
        else => unreachable,
    };
    return v != 0 and v < n;
}

fn markAlg(a: kc.Algorithm) void {
    if (a.isEc()) mark(.rt_ec) else if (a.isRsa()) mark(.rt_rsa) else if (a.isPq()) mark(.rt_pq) else mark(.rt_edx);
}

fn roundTrip(k: kc.PrivateKey) !void {
    var der_buf: [kc.max_private_der_len]u8 = undefined;
    const der = kc.writePrivateKeyDer(&der_buf, k) catch |err| {
        try testing.expectEqual(error.MalformedKey, err);
        try testing.expect(k.algorithm.isEc() and !scalarValid(k.algorithm, k.secret));
        mark(.ec_out_of_range);
        return;
    };
    if (k.algorithm.isEc()) try testing.expect(scalarValid(k.algorithm, k.secret));
    try expectSameKey(k, try kc.parsePrivateKeyDer(der));
    var pem_buf: [kc.max_private_pem_len]u8 = undefined;
    var back_buf: [kc.max_private_der_len]u8 = undefined;
    const text = try kc.writePrivateKeyPem(&pem_buf, k);
    try expectSameKey(k, try kc.parsePrivateKeyPem(text, &back_buf));
    markAlg(k.algorithm);
}

fn expectSameKey(want: kc.PrivateKey, got: kc.PrivateKey) !void {
    try testing.expectEqual(want.algorithm, got.algorithm);
    try testing.expectEqual(want.encoding, got.encoding);
    try testing.expectEqual(want.pq_form, got.pq_form);
    if (want.algorithm.isEc()) {
        var a: [66]u8 = undefined;
        var b: [66]u8 = undefined;
        const n = want.algorithm.secretLen().?;
        try want.scalarInto(a[0..n]);
        try got.scalarInto(b[0..n]);
        try testing.expectEqualSlices(u8, a[0..n], b[0..n]);
    } else try testing.expectEqualSlices(u8, want.secret, got.secret);
    try testing.expectEqualSlices(u8, want.expanded, got.expanded);
    try testing.expectEqual(want.public == null, got.public == null);
    if (want.public) |p| try testing.expectEqualSlices(u8, p, got.public.?);
    try testing.expectEqualSlices(u8, want.parameters, got.parameters);
}

/// What the reader accepts is writable and reads back the same.
fn fixpoint(k: kc.PrivateKey) !void {
    var out: [kc.max_private_der_len]u8 = undefined;
    const der = try kc.writePrivateKeyDer(&out, k);
    try expectSameKey(k, try kc.parsePrivateKeyDer(der));
}

fn mutateDer(k: kc.PrivateKey, cur: *fuzzseed.Cursor) !void {
    var der_buf: [kc.max_private_der_len]u8 = undefined;
    const der = kc.writePrivateKeyDer(&der_buf, k) catch return; // out of range: nothing to mutate
    const flips = cur.ranged(1, 4);
    for (0..flips) |_| {
        const at = (@as(usize, cur.word()) << 8 | cur.byte()) % der.len;
        der[at] ^= cur.byte() | 1;
    }
    const len = if (cur.byte() & 1 == 0) der.len else (@as(usize, cur.word()) % (der.len + 1));
    if (kc.parsePrivateKeyDer(der[0..len])) |got| {
        try fixpoint(got);
        mark(.mut_ok);
    } else |_| mark(.mut_err);
    _ = kc.parseSpki(der[0..len]) catch {};
}

fn mutatePem(k: kc.PrivateKey, cur: *fuzzseed.Cursor) !void {
    var pem_buf: [kc.max_private_pem_len]u8 = undefined;
    const text = kc.writePrivateKeyPem(&pem_buf, k) catch return;
    const alphabet = "AB+/=-\n\r :\x00Proc-Type: 4,ENCRYPTED\n";
    const flips = cur.ranged(1, 3);
    for (0..flips) |_| {
        const at = (@as(usize, cur.word()) << 8 | cur.byte()) % text.len;
        text[at] = alphabet[cur.byte() % alphabet.len];
    }
    var der_buf: [kc.max_private_der_len]u8 = undefined;
    if (kc.parsePrivateKeyPem(text, &der_buf)) |got| {
        try fixpoint(got);
        mark(.pem_mut_ok);
    } else |_| mark(.pem_mut_err);
    var pub_buf: [kc.max_public_der_len]u8 = undefined;
    _ = kc.parsePublicKeyPem(text, &pub_buf) catch {};
}

fn spkiRoundTrip(cur: *fuzzseed.Cursor, p: *Parts) !void {
    const a = algorithms[cur.byte() % algorithms.len];
    var pk: kc.PublicKey = .{ .algorithm = a, .key = &.{} };
    if (a.isEc()) {
        const n = a.secretLen().?;
        if (cur.byte() & 1 == 0) {
            p.public[0] = 0x04;
            fill(cur, p.public[1 .. 1 + 2 * n]);
            pk.key = p.public[0 .. 1 + 2 * n];
        } else {
            p.public[0] = 0x02 | (cur.byte() & 1);
            fill(cur, p.public[1 .. 1 + n]);
            pk.key = p.public[0 .. 1 + n];
        }
    } else if (a.isRsa()) {
        var w = kc.der.Writer.init(&p.public);
        const nl = cur.ranged(1, 64);
        const el = cur.ranged(1, 4);
        w.header(0x30, 2 + nl + 2 + el);
        w.header(0x02, nl);
        for (0..nl) |_| w.byte(cur.byte());
        w.header(0x02, el);
        for (0..el) |_| w.byte(cur.byte());
        pk.key = w.finish() catch unreachable;
    } else {
        fill(cur, p.public[0..a.publicLen().?]);
        pk.key = p.public[0..a.publicLen().?];
    }
    var buf: [kc.max_public_der_len]u8 = undefined;
    const der = try kc.writeSpki(&buf, pk);
    const back = try kc.parseSpki(der);
    try testing.expectEqual(pk.algorithm, back.algorithm);
    try testing.expectEqualSlices(u8, pk.key, back.key);
    mark(.spki_rt);
}

test "fuzz driver: KEYCODEC_FUZZ" {
    try fuzz_driver.run(harness, .{ .prefix = "KEYCODEC_FUZZ", .name = "keycodec" });
}

test "fuzz harness: 2000 seeds in every test run, and it gets everywhere" {
    reach = @splat(0);
    for (0..2000) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |e| {
            std.debug.print("seed {d}: {t}\n", .{ seed, e });
            return e;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 2000 seeds\n", .{@as(Reach, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

test "corpus: every seed runs the harness clean" {
    for (seeds) |sd| {
        var smith: testing.Smith = .{ .in = sd };
        var buf: [max_script]u8 = undefined;
        const n = smith.slice(&buf);
        var r: Replay = .{ .data = buf[0..n] };
        try harness(Replay, &r, testing.allocator);
    }
}
