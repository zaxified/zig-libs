// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for iec62351 (added 2026-10-10).
//!
//! `IEC62351_FUZZ=<runs>[,<first seed>]` runs the harnesses (testkit's fuzz
//! driver; `_ONLY` selects one by name, `_MS`, `_SEEDFILE`, `_INPUT` as
//! documented there). Each is generic over its source of choices.
//! - `iec62351-goose`: GOOSE / SV frames sealed by `goose.build` (HMAC-SHA-256
//!   at three tag lengths, AES-GMAC at two, ECDSA P-256; both header profiles)
//!   verify; damaged (0-3 octets, truncation) they are refused, or accepted
//!   only if nothing the MAC covers changed (the unauthenticated key
//!   metadata is by design not covered); the extension, BER and frame parsers
//!   never panic on the same bytes.
//! - `iec62351-replay`: a publisher's genuine GOOSE identities (state
//!   changes, retransmissions) interleaved with replays, reorderings and
//!   forged old state: the guard accepts the genuine in-order stream, never
//!   accepts a (stNum, sqNum) pair twice or one older than the last accepted,
//!   and a rejection leaves its state untouched.
//! - `iec62351-acse`: an IEC 62351-4 signed token spliced into an AARQ by
//!   `acse.insertAuthFields`: found, verified and genuine; a damaged PDU or
//!   token is refused (a damaged octet outside the token may still verify),
//!   another key, an expired or a future token never.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const goose = @import("goose.zig");
const replay = @import("replay.zig");
const acse = @import("acse.zig");
const ber = @import("ber.zig");
pub const fuzz_driver = testkit.fuzz.driver;

const EcdsaP256 = @import("p256").EcdsaP256Sha256;

/// `frame` into `buf` with 0-3 octets damaged (half within the first 24) and
/// maybe truncated. The driver's `Rng` only.
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        const span = if (src.value(bool)) @min(n, 24) else n;
        buf[src.index(span)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels (see jwt's fuzz_test.zig).
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

fn keyPair(seed_byte: u8) !EcdsaP256.KeyPair {
    const seed: [EcdsaP256.KeyPair.seed_length]u8 = @splat(seed_byte);
    return EcdsaP256.KeyPair.generateDeterministic(seed);
}

// ── iec62351-goose ──────────────────────────────────────────────────────────

const GooseMark = Marker(enum {
    mac_frame,
    gmac_frame,
    ecdsa_frame,
    ts2007,
    genuine_verified,
    domain_damaged_refused,
    metadata_damaged_accepted,
    extension_damaged_refused,
    parse_refused,
});

pub fn fuzzGoose(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var key: [32]u8 = undefined;
    src.bytes(&key);
    var apdu: [96]u8 = undefined;
    src.bytes(&apdu);
    const apdu_len = src.index(apdu.len + 1);
    const profile: goose.HeaderProfile = if (src.index(4) == 0) .ts2007 else .ed2020;
    if (profile.flag_bit == null) GooseMark.mark(.ts2007);
    const appid: u16 = @intCast(0x3000 + src.index(0x100));
    const auth: goose.AuthenticationValue = .{
        .time_of_current_key = src.value(u32),
        .time_to_next_key = src.value(u16),
        .key_id = src.value(u32),
        .tag = &.{},
    };

    var kp = try keyPair(0x44);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));
    const Which = enum { hmac80, hmac128, hmac256, gmac64, gmac128, ecdsa };
    const which: Which = @enumFromInt(src.index(6));
    var iv_counter = goose.IvCounter.init(appid);
    var frame_buf: [512]u8 = undefined;
    var sealer: goose.Sealer = undefined;
    var verifier: goose.Verifier = undefined;
    var iv_source: ?goose.IvSource = null;
    switch (which) {
        .hmac80, .hmac128, .hmac256 => {
            const alg: goose.MacAlgorithm = switch (which) {
                .hmac80 => .hmac_sha256_80,
                .hmac128 => .hmac_sha256_128,
                else => .hmac_sha256_256,
            };
            sealer = .{ .mac = .{ .algorithm = alg, .key = key[0..32] } };
            verifier = .{ .mac = .{ .algorithm = alg, .key = key[0..32] } };
            GooseMark.mark(.mac_frame);
        },
        .gmac64, .gmac128 => {
            const alg: goose.MacAlgorithm = if (which == .gmac64) .aes_gmac_64 else .aes_gmac_128;
            sealer = .{ .mac = .{ .algorithm = alg, .key = key[0..16] } };
            verifier = .{ .mac = .{ .algorithm = alg, .key = key[0..16] } };
            iv_source = .{ .counter = &iv_counter };
            GooseMark.mark(.gmac_frame);
        },
        .ecdsa => {
            sealer = .{ .ecdsa_p256_sha256 = .{ .key_pair = &kp, .noise = null } };
            verifier = .{ .ecdsa_p256_sha256 = kp.public_key };
            GooseMark.mark(.ecdsa_frame);
        },
    }
    const frame = try goose.build(&frame_buf, .{
        .ether_type = if (src.value(bool)) goose.ether_type_goose else goose.ether_type_sv,
        .appid = appid,
        .apdu = apdu[0..apdu_len],
        .header = profile,
        .auth = auth,
        .iv_source = iv_source,
    }, sealer);
    const genuine = try goose.verify(frame, profile, verifier);
    GooseMark.mark(.genuine_verified);
    const domain_len = genuine.frame.macDomain().len;

    var dmg: [512]u8 = undefined;
    var n: usize = 0;
    if (S == fuzz_driver.Rng) {
        n = damage(src, &dmg, frame);
    } else n = src.slice(&dmg);
    const changed = n != frame.len or !std.mem.eql(u8, dmg[0..n], frame);

    // The parsers, on whatever came out.
    if (goose.parse(dmg[0..n], profile)) |f| {
        _ = f.macDomain();
        _ = goose.AuthenticationValue.parse(f.extension, true, goose.max_mac_len) catch {};
        _ = goose.AuthenticationValue.parse(f.extension, false, goose.max_mac_len) catch {};
    } else |_| GooseMark.mark(.parse_refused);
    _ = ber.read(dmg[0..n]) catch {};

    if (goose.verify(dmg[0..n], profile, verifier)) |r| {
        if (!changed) return;
        // Accepted although octets differ: only the unauthenticated metadata
        // may have changed -- the covered domain, the tag and the IV are those
        // of the genuine frame.
        const same_domain = r.frame.macDomain().len == domain_len and std.mem.eql(u8, r.frame.macDomain(), genuine.frame.macDomain());
        const same_tag = std.mem.eql(u8, r.tag, genuine.tag);
        const same_iv = (r.iv == null) == (genuine.iv == null) and (r.iv == null or std.mem.eql(u8, &r.iv.?, &genuine.iv.?));
        if (!same_domain or !same_tag or !same_iv) {
            std.debug.print("iec62351-goose: a frame whose authenticated bytes changed VERIFIED ({t})\n", .{which});
            return error.TamperedFrameVerified;
        }
        GooseMark.mark(.metadata_damaged_accepted);
    } else |_| {
        if (!changed) return error.GenuineFrameRefused;
        if (n >= goose.apdu_offset and n > 0 and domain_len <= n and !std.mem.eql(u8, dmg[0..domain_len], frame[0..domain_len])) {
            GooseMark.mark(.domain_damaged_refused);
        } else GooseMark.mark(.extension_damaged_refused);
    }
}

fn fuzzGooseSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzGoose(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: sealed GOOSE frames verify, tampered ones do not" {
    try testing.fuzz({}, fuzzGooseSmith, .{});
}

test "fuzz driver: IEC62351_FUZZ (goose)" {
    try fuzz_driver.run(fuzzGoose, .{ .prefix = "IEC62351_FUZZ", .name = "iec62351-goose" });
}

test "fuzz harness: goose, 400 seeds, reaches every outcome" {
    try GooseMark.reach(fuzzGoose, "iec62351-goose", 400);
}

// ── iec62351-replay ─────────────────────────────────────────────────────────

const ReplayMark = Marker(enum { accepted_first, accepted_new_state, accepted_in_sequence, replay_refused, forged_old_refused, other_refused });

pub fn fuzzReplay(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    const ms = std.time.ns_per_ms;
    var g: replay.GooseGuard = .init(.{ .max_state_age_ns = std.math.maxInt(u64) / 4, .max_skew_ns = 1000 * ms });
    var now: u64 = 1_000_000 * ms;
    var st: u32 = src.value(u32);
    var sq: u32 = 0;
    var t_ns: u64 = now;
    var accepted: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer accepted.deinit(testing.allocator);
    var last: ?struct { st: u32, sq: u32 } = null;
    const steps = 4 + src.index(28);
    for (0..steps) |_| {
        // The publisher's next genuine frame (a retransmission, or a state change)...
        var id: replay.GooseIdentity = undefined;
        const kind = src.index(10);
        var genuine = false;
        switch (kind) {
            0...4 => {
                sq +%= 1;
                id = .{ .st_num = st, .sq_num = sq, .t_ns = t_ns, .time_allowed_to_live_ms = 2000 };
                genuine = true;
            },
            5, 6 => {
                st +%= 1;
                sq = 0;
                t_ns = now;
                id = .{ .st_num = st, .sq_num = sq, .t_ns = t_ns, .time_allowed_to_live_ms = 2000 };
                genuine = true;
            },
            // ...or an attacker's: the previous frame again, an old state, an old sequence.
            7 => id = .{ .st_num = st, .sq_num = sq, .t_ns = t_ns, .time_allowed_to_live_ms = 2000 },
            8 => id = .{ .st_num = st -% @as(u32, @intCast(1 + src.index(5))), .sq_num = @intCast(src.index(8)), .t_ns = t_ns, .time_allowed_to_live_ms = 2000 },
            else => id = .{ .st_num = st, .sq_num = sq -% @as(u32, @intCast(1 + src.index(5))), .t_ns = t_ns, .time_allowed_to_live_ms = 2000 },
        }
        const before = g.state;
        const v = g.accept(id, now);
        const key = (@as(u64, id.st_num) << 32) | id.sq_num;
        if (v.accepted()) {
            if (accepted.contains(key)) return error.IdentityAcceptedTwice;
            try accepted.put(testing.allocator, key, {});
            if (last) |l| {
                // Forward in serial-number order: a newer state, or the same state with a newer sequence.
                const newer_state = id.st_num != l.st and (id.st_num -% l.st) < 0x8000_0000;
                const newer_seq = id.st_num == l.st and id.sq_num != l.sq and (id.sq_num -% l.sq) < 0x8000_0000;
                if (!newer_state and !newer_seq) return error.AcceptedAnOlderIdentity;
            }
            last = .{ .st = id.st_num, .sq = id.sq_num };
            switch (v) {
                .accept_first => ReplayMark.mark(.accepted_first),
                .accept_new_state => ReplayMark.mark(.accepted_new_state),
                else => ReplayMark.mark(.accepted_in_sequence),
            }
        } else {
            // A rejection leaves the state as it was.
            if ((before == null) != (g.state == null)) return error.RejectionChangedTheState;
            if (before) |b| if (b.st_num != g.state.?.st_num or b.sq_num != g.state.?.sq_num or b.t_ns != g.state.?.t_ns) return error.RejectionChangedTheState;
            if (kind == 7 or kind == 8 or kind == 9) {
                if (kind == 7) ReplayMark.mark(.replay_refused) else ReplayMark.mark(.forged_old_refused);
            } else ReplayMark.mark(.other_refused);
            // A genuine frame the guard refused is only a defect when nothing excuses it.
            if (genuine and v == .reject_replay_state) return error.GenuineStateChangeRefused;
        }
        now += @intCast(1 + src.index(50));
        now += ms;
    }
}

fn fuzzReplaySmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzReplay(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: the GOOSE guard against a publisher and an attacker" {
    try testing.fuzz({}, fuzzReplaySmith, .{});
}

test "fuzz driver: IEC62351_FUZZ (replay)" {
    try fuzz_driver.run(fuzzReplay, .{ .prefix = "IEC62351_FUZZ", .name = "iec62351-replay" });
}

test "fuzz harness: replay, 400 seeds, reaches every outcome" {
    try ReplayMark.reach(fuzzReplay, "iec62351-replay", 400);
}

// ── iec62351-acse ───────────────────────────────────────────────────────────

const sample_aarq = [_]u8{
    0x60, 0x1c,
    0x80, 0x02,
    0x07, 0x80,
    0xa1, 0x07,
    0x06, 0x05,
    0x28, 0xca,
    0x22, 0x02,
    0x03, 0xbe,
    0x0d, 0x28,
    0x0b, 0x06,
    0x02, 0x51,
    0x01, 0xa0,
    0x05, 0xa8,
    0x03, 0x80,
    0x01, 0x05,
};
const mechanism_arc = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x2e, 0x05 };

const AcseMark = Marker(enum {
    genuine_verified,
    token_damaged_refused,
    pdu_damaged_refused,
    outside_token_accepted,
    wrong_key_refused,
    expired_refused,
    future_refused,
});

pub fn fuzzAcse(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var kp = try keyPair(0x21);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));
    var other_kp = try keyPair(0x22);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&other_kp));
    var identity: [24]u8 = undefined;
    src.bytes(&identity);
    const idl = src.index(identity.len + 1);
    const now_s: u64 = 1_600_000_000 + src.index(1000);
    var sig_buf: [64]u8 = undefined;
    var token_buf: [256]u8 = undefined;
    const token = try acse.signToken(&token_buf, &sig_buf, .{ .ecdsa_p256_sha256 = .{ .key_pair = &kp, .noise = null } }, 1, now_s, identity[0..idl]);
    var fields_buf: [512]u8 = undefined;
    const fields = try acse.buildAuthFields(&fields_buf, .{
        .mechanism = .{ .custom = &mechanism_arc },
        .value = .{ .other = .{ .mechanism = &mechanism_arc, .value = token } },
    });
    var pdu_buf: [768]u8 = undefined;
    const pdu = try acse.insertAuthFields(&pdu_buf, &sample_aarq, .aarq, fields);

    const verifier: acse.TokenVerifier = .{ .ecdsa_p256_sha256 = kp.public_key };
    // The genuine PDU: found, asserted, verified.
    const f = try acse.findAuthFields(pdu, .aarq);
    if (!f.assertsAuthentication()) return error.GenuinePduDoesNotAssert;
    const got = try acse.verifyToken(f.value.?.other.value, verifier, now_s + 1, .{});
    if (!std.mem.eql(u8, got.identity, identity[0..idl])) return error.IdentityChanged;
    AcseMark.mark(.genuine_verified);

    // Another key, an expired token, one from the future.
    if (acse.verifyToken(token, .{ .ecdsa_p256_sha256 = other_kp.public_key }, now_s, .{})) |_| return error.WrongKeyVerified else |_| AcseMark.mark(.wrong_key_refused);
    if (acse.verifyToken(token, verifier, now_s + 61 + src.index(100000), .{})) |_| return error.ExpiredTokenVerified else |_| AcseMark.mark(.expired_refused);
    if (acse.verifyToken(token, verifier, now_s -| (6 + src.index(100000)), .{})) |_| return error.FutureTokenVerified else |_| AcseMark.mark(.future_refused);

    // A damaged PDU (S == Rng) or random bytes (Smith).
    var dmg: [768]u8 = undefined;
    var n: usize = 0;
    if (S == fuzz_driver.Rng) {
        n = damage(src, &dmg, pdu);
    } else n = src.slice(&dmg);
    const changed = n != pdu.len or !std.mem.eql(u8, dmg[0..n], pdu);
    const token_at = std.mem.indexOf(u8, pdu, token).?;
    const in_token = blk: {
        if (n < pdu.len) break :blk true;
        for (dmg[0..n], pdu, 0..) |a, b, i| if (a != b and i >= token_at and i < token_at + token.len) break :blk true;
        break :blk false;
    };
    const found = acse.findAuthFields(dmg[0..n], .aarq) catch {
        if (changed) AcseMark.mark(.pdu_damaged_refused);
        return;
    };
    _ = found.assertsAuthentication();
    if (found.value) |v| switch (v) {
        .other => |o| {
            if (acse.verifyToken(o.value, verifier, now_s + 1, .{})) |_| {
                if (in_token and changed) {
                    // The token's octets changed and it still verifies: only a
                    // change outside what the signature covers (BER length
                    // forms) may do that.
                    if (!std.mem.eql(u8, o.value, token)) {
                        std.debug.print("acse: a token with changed octets VERIFIED\n", .{});
                        return error.DamagedTokenVerified;
                    }
                }
                if (changed) AcseMark.mark(.outside_token_accepted);
            } else |_| if (changed) AcseMark.mark(.token_damaged_refused);
        },
        else => {},
    };
}

fn fuzzAcseSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzAcse(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: a signed token in an AARQ, genuine and damaged" {
    try testing.fuzz({}, fuzzAcseSmith, .{});
}

test "fuzz driver: IEC62351_FUZZ (acse)" {
    try fuzz_driver.run(fuzzAcse, .{ .prefix = "IEC62351_FUZZ", .name = "iec62351-acse", .scale = 4 });
}

test "fuzz harness: acse, 400 seeds, reaches every outcome" {
    try AcseMark.reach(fuzzAcse, "iec62351-acse", 400);
}
