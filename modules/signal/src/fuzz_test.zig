// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for signal (added 2026-10-10): `SIGNAL_FUZZ=<runs>[,<first seed>]`
//! (testkit's driver; `_ONLY` selects a harness by name). Harness names:
//! `signal-ratchet` (a live Double Ratchet conversation, in order and
//! reversed; every delivery first tried with a flipped bit and a damaged
//! copy, which must be refused and leave the session able to take the genuine
//! message; a replay is refused), `signal-x3dh` (PreKeyBundle / InitialMessage
//! codecs and the handshake: a damaged bundle or initial message never yields
//! an agreed session) and `signal-xeddsa` (genuine signature accepted, a
//! flipped bit / other message / other key refused).
//!
//! X25519 ignores the top bit of a public key's last octet (RFC 7748), so a
//! flip of that bit is the same key; where the AEAD associated data does not
//! cover the raw octets such a flip is legitimately accepted, and the
//! harnesses name which positions they exempt.

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

const rat = @import("ratchet.zig");
const x3 = @import("x3dh.zig");
const xed = @import("xeddsa.zig");
const X25519 = std.crypto.dh.X25519;

fn flipBit(knobs: *Cursor, bytes: []u8) usize {
    const at = (@as(usize, knobs.byte()) << 8 | knobs.byte()) % bytes.len;
    bytes[at] ^= @as(u8, 1) << @intCast(knobs.ranged(0, 7));
    return at;
}

fn keyPair(knobs: *Cursor) !X25519.KeyPair {
    var seed: [32]u8 = undefined;
    expand(knobs, &seed);
    return X25519.KeyPair.generateDeterministic(seed);
}

// ── ratchet ────────────────────────────────────────────────────────────────

const RatchetMark = Marker(enum { delivered, reversed, flipped_refused, damaged_refused, replay_refused, bob_replied, header_flip, ciphertext_flip });

fn deliver(gpa: std.mem.Allocator, io: std.Io, rx: *rat.State, wire: []const u8) ![]u8 {
    if (wire.len < rat.Header.encoded_length) return error.InvalidHeader;
    const h = try rat.Header.fromBytes(wire[0..rat.Header.encoded_length]);
    return rx.decrypt(gpa, h, wire[rat.Header.encoded_length..], io);
}

fn fuzzRatchet(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [24]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var sk: [32]u8 = undefined;
    expand(&knobs, &sk);
    var ad: [rat.associated_data_length]u8 = undefined;
    expand(&knobs, &ad);
    const bob_kp = try keyPair(&knobs);
    var alice: rat.State = undefined;
    try rat.State.initAlice(&sk, ad, bob_kp.public_key, io, &alice);
    defer alice.deinit(gpa);
    var bob: rat.State = undefined;
    rat.State.initBob(&sk, ad, &bob_kp, &bob);
    defer bob.deinit(gpa);

    const turns = knobs.ranged(2, 4);
    var turn: usize = 0;
    while (turn < turns) : (turn += 1) {
        // Alice speaks first; Bob can only send once he has received.
        const a_sends = turn % 2 == 0;
        const tx = if (a_sends) &alice else &bob;
        const rx = if (a_sends) &bob else &alice;
        const count = knobs.ranged(1, 3);
        var wires: [3][]u8 = undefined;
        var pts: [3][24]u8 = undefined;
        var plens: [3]usize = undefined;
        for (0..count) |i| {
            expand(&knobs, &pts[i]);
            plens[i] = knobs.ranged(0, 24);
            const m = try tx.encrypt(gpa, pts[i][0..plens[i]]);
            defer m.deinit(gpa);
            wires[i] = try gpa.alloc(u8, rat.Header.encoded_length + m.ciphertext.len);
            wires[i][0..rat.Header.encoded_length].* = m.header.toBytes();
            @memcpy(wires[i][rat.Header.encoded_length..], m.ciphertext);
        }
        defer for (0..count) |i| gpa.free(wires[i]);
        const reverse = knobs.byte() & 1 == 1;
        if (reverse) RatchetMark.mark(.reversed);
        for (0..count) |k| {
            const i = if (reverse) count - 1 - k else k;
            // Tampered copies first; each must be refused and leave `rx` intact.
            {
                const copy = try gpa.dupe(u8, wires[i]);
                defer gpa.free(copy);
                const at = flipBit(&knobs, copy);
                if (at < rat.Header.encoded_length) RatchetMark.mark(.header_flip) else RatchetMark.mark(.ciphertext_flip);
                // The top bit of the header's dh last octet is the same X25519 key
                // but the header octets are authenticated: still refused.
                if (deliver(gpa, io, rx, copy)) |p| {
                    gpa.free(p);
                    return error.FlippedMessageAccepted;
                } else |_| RatchetMark.mark(.flipped_refused);
                var buf: [rat.Header.encoded_length + 64]u8 = undefined;
                const n = damage(src, &buf, wires[i]);
                if (deliver(gpa, io, rx, buf[0..n])) |p| {
                    gpa.free(p);
                    if (!std.mem.eql(u8, buf[0..n], wires[i])) return error.DamagedMessageAccepted;
                    // identical bytes: it was delivered, treat the next as a replay
                    RatchetMark.mark(.delivered);
                    if (deliver(gpa, io, rx, wires[i])) |p2| {
                        gpa.free(p2);
                        return error.ReplayAccepted;
                    } else |_| RatchetMark.mark(.replay_refused);
                    continue;
                } else |_| RatchetMark.mark(.damaged_refused);
            }
            const p = deliver(gpa, io, rx, wires[i]) catch return error.GenuineMessageRefused;
            defer gpa.free(p);
            if (!std.mem.eql(u8, p, pts[i][0..plens[i]])) return error.PlaintextDiffers;
            RatchetMark.mark(.delivered);
            if (deliver(gpa, io, rx, wires[i])) |p2| {
                gpa.free(p2);
                return error.ReplayAccepted;
            } else |_| RatchetMark.mark(.replay_refused);
        }
        if (!a_sends) RatchetMark.mark(.bob_replied);
    }
}

test "fuzz: signal ratchet, genuine accepted / damaged refused" {
    try testing.fuzz({}, smithWrap(fuzzRatchet), .{});
}
test "fuzz driver: SIGNAL_FUZZ (ratchet)" {
    try fuzz_driver.run(fuzzRatchet, .{ .prefix = "SIGNAL_FUZZ", .name = "signal-ratchet", .scale = 2 });
}
test "fuzz harness: ratchet, 200 seeds, reaches every outcome" {
    try RatchetMark.reach(fuzzRatchet, "signal-ratchet", 200);
}

// ── x3dh ───────────────────────────────────────────────────────────────────

const X3Mark = Marker(enum { genuine_agreed, bundle_flip_refused, bundle_flip_exempt, initial_flip_refused, initial_flip_exempt, initial_decode_refused, bundle_damaged, initial_damaged });

fn fuzzX3dh(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [24]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const alice_ik = try keyPair(&knobs);
    const bob_ik = try keyPair(&knobs);
    const spk_kp = try keyPair(&knobs);
    const opk_kp = try keyPair(&knobs);
    var z: xed.RandomData = undefined;
    expand(&knobs, &z);
    var spk: x3.SignedPreKey = undefined;
    x3.generateSignedPreKey(&bob_ik, 7, z, io, &spk);
    spk.key_pair = spk_kp;
    spk.signature = xed.sign(&bob_ik.secret_key, &spk_kp.public_key, z);
    const opk: x3.OneTimePreKey = .{ .key_pair = opk_kp, .id = 9 };
    const use_opk = knobs.byte() & 1 == 1;
    const bundle: x3.PreKeyBundle = .{
        .identity_key = bob_ik.public_key,
        .signed_prekey = spk_kp.public_key,
        .signed_prekey_id = spk.id,
        .signed_prekey_signature = spk.signature,
        .one_time_prekey = if (use_opk) opk_kp.public_key else null,
        .one_time_prekey_id = if (use_opk) opk.id else null,
    };
    var pt: [20]u8 = undefined;
    expand(&knobs, &pt);
    const pt_s = pt[0..knobs.ranged(0, 20)];

    // Genuine: the bundle round-trips its codec, the handshake agrees.
    const wire_bundle = bundle.toBytes();
    const decoded = x3.PreKeyBundle.fromBytes(wire_bundle) catch return error.GenuineBundleRefused;
    var init: x3.InitiateOutput = undefined;
    try x3.initiate(gpa, &alice_ik, decoded, pt_s, io, &init);
    defer init.message.deinit(gpa);
    const wire_init = try init.message.toBytes(gpa);
    defer gpa.free(wire_init);
    const rx_msg = x3.InitialMessage.fromBytes(gpa, wire_init) catch return error.GenuineInitialRefused;
    defer rx_msg.deinit(gpa);
    var resp: x3.RespondOutput = undefined;
    try x3.respond(gpa, &bob_ik, &spk, if (use_opk) &opk else null, rx_msg, &resp);
    defer gpa.free(resp.plaintext);
    if (!std.mem.eql(u8, &resp.agreement.shared_secret, &init.agreement.shared_secret)) return error.SecretsDiffer;
    if (!std.mem.eql(u8, resp.plaintext, pt_s)) return error.PlaintextDiffers;
    X3Mark.mark(.genuine_agreed);

    // A flipped bundle never yields an agreed session. Exempt: the ids (not
    // authenticated at this layer), the OPK slot when absent, and the top bit
    // of a public key's last octet.
    {
        var b = wire_bundle;
        const at = flipBit(&knobs, &b);
        const exempt = (at >= 64 and at < 68) or (at >= 133 and at < 137) or (at >= 133 and !use_opk) or (at == 31 or at == 63 or at == 168);
        if (x3.PreKeyBundle.fromBytes(b)) |fb| {
            var out2: x3.InitiateOutput = undefined;
            if (x3.initiate(gpa, &alice_ik, fb, pt_s, io, &out2)) {
                defer out2.message.deinit(gpa);
                var r2: x3.RespondOutput = undefined;
                if (x3.respond(gpa, &bob_ik, &spk, if (use_opk) &opk else null, out2.message, &r2)) {
                    defer gpa.free(r2.plaintext);
                    const agreed = std.mem.eql(u8, &r2.agreement.shared_secret, &out2.agreement.shared_secret) and std.mem.eql(u8, r2.plaintext, pt_s);
                    if (agreed and !exempt) {
                        return error.FlippedBundleAgreed;
                    }
                    if (exempt) X3Mark.mark(.bundle_flip_exempt);
                } else |_| X3Mark.mark(.bundle_flip_refused);
            } else |_| X3Mark.mark(.bundle_flip_refused);
        } else |_| {}
        // Multi-octet damage: no panic.
        const d = damageBundle(src, wire_bundle);
        if (x3.PreKeyBundle.fromBytes(d)) |fb| {
            var out2: x3.InitiateOutput = undefined;
            if (x3.initiate(gpa, &alice_ik, fb, pt_s, io, &out2)) |_| out2.message.deinit(gpa) else |_| {}
            X3Mark.mark(.bundle_damaged);
        } else |_| {}
    }
    // A flipped initial message. Exempt: the ids/flag (Bob passes his keys
    // explicitly) and the ephemeral key's top bit (not in the AD).
    {
        const copy = try gpa.dupe(u8, wire_init);
        defer gpa.free(copy);
        const at = flipBit(&knobs, copy);
        const exempt = (at >= 64 and at < 73) or at == 63;
        if (x3.InitialMessage.fromBytes(gpa, copy)) |fm| {
            defer fm.deinit(gpa);
            var r2: x3.RespondOutput = undefined;
            if (x3.respond(gpa, &bob_ik, &spk, if (use_opk) &opk else null, fm, &r2)) {
                gpa.free(r2.plaintext);
                if (!exempt) return error.FlippedInitialAccepted;
                X3Mark.mark(.initial_flip_exempt);
            } else |_| X3Mark.mark(.initial_flip_refused);
        } else |_| X3Mark.mark(.initial_decode_refused);
        var buf: [256]u8 = undefined;
        const n = damage(src, &buf, wire_init);
        if (x3.InitialMessage.fromBytes(gpa, buf[0..n])) |fm| {
            defer fm.deinit(gpa);
            var r2: x3.RespondOutput = undefined;
            if (x3.respond(gpa, &bob_ik, &spk, if (use_opk) &opk else null, fm, &r2)) |_| gpa.free(r2.plaintext) else |_| {}
            X3Mark.mark(.initial_damaged);
        } else |_| {}
    }
}

fn damageBundle(src: anytype, genuine: [x3.PreKeyBundle.encoded_length]u8) [x3.PreKeyBundle.encoded_length]u8 {
    var out = genuine;
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| out[src.index(out.len)] = src.value(u8);
    return out;
}

test "fuzz: signal x3dh, damaged bundle / initial message never agree" {
    try testing.fuzz({}, smithWrap(fuzzX3dh), .{});
}
test "fuzz driver: SIGNAL_FUZZ (x3dh)" {
    try fuzz_driver.run(fuzzX3dh, .{ .prefix = "SIGNAL_FUZZ", .name = "signal-x3dh", .scale = 2 });
}
test "fuzz harness: x3dh, 200 seeds, reaches every outcome" {
    try X3Mark.reach(fuzzX3dh, "signal-x3dh", 200);
}

// ── xeddsa ─────────────────────────────────────────────────────────────────

const XMark = Marker(enum { genuine_accepted, libsignal_accepted, flipped_sig_refused, other_msg_refused, other_key_refused, random_sig });

fn fuzzXeddsa(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [24]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    const kp = try keyPair(&knobs);
    const other = try keyPair(&knobs);
    var z: xed.RandomData = undefined;
    expand(&knobs, &z);
    var msg: [40]u8 = undefined;
    expand(&knobs, &msg);
    const m = msg[0..knobs.ranged(0, 40)];

    const sig = xed.sign(&kp.secret_key, m, z);
    if (!xed.verify(kp.public_key, m, sig)) return error.GenuineSignatureRefused;
    XMark.mark(.genuine_accepted);
    const lsig = xed.libsignal.sign(&kp.secret_key, m, z);
    if (!xed.libsignal.verify(kp.public_key, m, lsig)) return error.GenuineLibsignalRefused;
    XMark.mark(.libsignal_accepted);

    var bad = sig;
    _ = flipBit(&knobs, &bad);
    if (xed.verify(kp.public_key, m, bad)) return error.FlippedSignatureAccepted;
    var lbad = lsig;
    _ = flipBit(&knobs, &lbad);
    if (xed.libsignal.verify(kp.public_key, m, lbad)) return error.FlippedLibsignalSignatureAccepted;
    XMark.mark(.flipped_sig_refused);

    var m2: [41]u8 = undefined;
    @memcpy(m2[0..m.len], m);
    m2[m.len] = 0x7e;
    if (xed.verify(kp.public_key, m2[0 .. m.len + 1], sig)) return error.OtherMessageAccepted;
    if (m.len > 0) {
        var m3 = m2;
        m3[knobs.ranged(0, @intCast(m.len - 1))] ^= 1;
        if (xed.verify(kp.public_key, m3[0..m.len], sig)) return error.OtherMessageAccepted;
    }
    XMark.mark(.other_msg_refused);
    if (!std.mem.eql(u8, &other.public_key, &kp.public_key) and xed.verify(other.public_key, m, sig)) return error.OtherKeyAccepted;
    XMark.mark(.other_key_refused);

    // Arbitrary key and signature: a verdict, never a panic.
    var pk: [32]u8 = undefined;
    src.bytes(&pk);
    var rs: xed.Signature = undefined;
    src.bytes(&rs);
    _ = xed.verify(pk, m, rs);
    _ = xed.libsignal.verify(pk, m, rs);
    XMark.mark(.random_sig);
}

test "fuzz: signal xeddsa, genuine accepted / flipped refused" {
    try testing.fuzz({}, smithWrap(fuzzXeddsa), .{});
}
test "fuzz driver: SIGNAL_FUZZ (xeddsa)" {
    try fuzz_driver.run(fuzzXeddsa, .{ .prefix = "SIGNAL_FUZZ", .name = "signal-xeddsa" });
}
test "fuzz harness: xeddsa, 100 seeds, reaches every outcome" {
    try XMark.reach(fuzzXeddsa, "signal-xeddsa", 100);
}
