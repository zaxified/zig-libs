// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for opaque (added 2026-10-10): `OPAQUE_FUZZ=<runs>[,<first seed>]`
//! (testkit's driver; `_ONLY` selects a harness by name). Harness names:
//! `opaque-login` (a whole registration + login with knob-chosen keys,
//! password and context; the genuine KE3 is accepted by the server and both
//! session keys agree; ONE flipped bit in KE2, KE3, KE1, the stored record or
//! a wrong password is refused by the side that checks; a multi-octet
//! damaged message is accepted only when byte-identical) and
//! `opaque-hostile` (random fixed-width wire messages into the entry points
//! that validate them: never a panic, and a KE2 nobody made never opens).

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

const o = @import("root.zig");
const shim = @import("test_shim.zig");

fn flipBit(knobs: *Cursor, bytes: []u8) void {
    const at = (@as(usize, knobs.byte()) << 8 | knobs.byte()) % bytes.len;
    bytes[at] ^= @as(u8, 1) << @intCast(knobs.ranged(0, 7));
}

/// `genuine` with 0-3 octets overwritten (fixed width: the wire types take
/// arrays); equal to `genuine` when the writes changed nothing.
fn damageFixed(src: anytype, comptime N: usize, genuine: [N]u8) [N]u8 {
    var out = genuine;
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| out[src.index(N)] = src.value(u8);
    return out;
}

const LoginMark = Marker(enum {
    genuine_accepted,
    wrong_password_refused,
    flipped_ke2_refused,
    damaged_ke2_refused,
    flipped_ke3_refused,
    flipped_ke1_refused,
    flipped_record_refused,
    wrong_context_refused,
    damaged_reg_response,
});

fn fuzzLogin(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [16]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };

    var password: [20]u8 = undefined;
    expand(&knobs, &password);
    const pw = password[0..knobs.ranged(0, 20)];
    var wrong_pw = password;
    wrong_pw[0] ^= 1;
    const wpw = if (pw.len == 0) "x" else wrong_pw[0..pw.len];
    var cred_id: [8]u8 = undefined;
    expand(&knobs, &cred_id);
    var oprf_seed: [o.Nh]u8 = undefined;
    expand(&knobs, &oprf_seed);
    var seed: [o.Nseed]u8 = undefined;
    expand(&knobs, &seed);
    const server = try shim.deriveAkeKeyPair(seed);
    var wide: [64]u8 = undefined;
    expand(&knobs, &wide);
    const reg_blind = shim.scalarFromWideBytes(wide);
    expand(&knobs, &wide);
    const login_blind = shim.scalarFromWideBytes(wide);
    expand(&knobs, &wide);
    const bad_blind = shim.scalarFromWideBytes(wide);
    var nonces: [4][o.Nn]u8 = undefined;
    for (&nonces) |*n| expand(&knobs, n);
    var kseed: [2][o.Nseed]u8 = undefined;
    for (&kseed) |*k| expand(&knobs, k);
    var context: [6]u8 = undefined;
    expand(&knobs, &context);
    const ctx = context[0..knobs.ranged(0, 6)];
    const ids: o.Identities = .{};

    // Registration.
    const req = try shim.createRegistrationRequest(pw, reg_blind);
    const resp = try shim.createRegistrationResponse(req, server.public_key, &cred_id, oprf_seed);
    const fin = try shim.finalizeRegistrationRequest(pw, reg_blind, resp, ids, nonces[0], .identity);
    const record = fin.record;

    // A damaged registration response yields a record that is not the genuine
    // one (or is refused): it can never be a silent equal.
    {
        const dw = damageFixed(src, o.RegistrationResponse.encoded_length, resp.toBytes());
        if (shim.finalizeRegistrationRequest(pw, reg_blind, o.RegistrationResponse.fromBytes(dw), ids, nonces[0], .identity)) |r2| {
            const same_in = std.mem.eql(u8, &dw, &resp.toBytes());
            const same_out = std.mem.eql(u8, &r2.record.toBytes(), &record.toBytes());
            if (!same_in and same_out) return error.DamagedRegistrationResponseSilentlyEqual;
        } else |_| {}
        LoginMark.mark(.damaged_reg_response);
    }

    // Genuine login.
    const k1 = try shim.generateKE1(pw, login_blind, nonces[1], kseed[0]);
    const k2 = try shim.generateKE2(server.private_key, server.public_key, record, &cred_id, oprf_seed, k1.ke1, ids, ctx, nonces[2], nonces[3], kseed[1]);
    const k3 = shim.generateKE3(k1.state, ids, ctx, k2.ke2, .identity) catch return error.GenuineLoginRefused;
    const sk = shim.serverFinish(k2.state, k3.ke3) catch return error.GenuineKE3Refused;
    if (!std.mem.eql(u8, &sk, &k3.session_key)) return error.SessionKeysDiffer;
    if (!std.mem.eql(u8, &k3.export_key, &fin.export_key)) return error.ExportKeysDiffer;
    LoginMark.mark(.genuine_accepted);

    // Wrong password (client side).
    {
        const w1 = try shim.generateKE1(wpw, login_blind, nonces[1], kseed[0]);
        const w2 = try shim.generateKE2(server.private_key, server.public_key, record, &cred_id, oprf_seed, w1.ke1, ids, ctx, nonces[2], nonces[3], kseed[1]);
        if (shim.generateKE3(w1.state, ids, ctx, w2.ke2, .identity)) |_| {
            return error.WrongPasswordAccepted;
        } else |_| LoginMark.mark(.wrong_password_refused);
    }
    // Wrong context: the transcript differs, the MAC refuses.
    {
        var ctx2: [7]u8 = undefined;
        @memcpy(ctx2[0..ctx.len], ctx);
        ctx2[ctx.len] = 0x5a;
        if (shim.generateKE3(k1.state, ids, ctx2[0 .. ctx.len + 1], k2.ke2, .identity)) |_| {
            return error.WrongContextAccepted;
        } else |_| LoginMark.mark(.wrong_context_refused);
    }
    // KE2: one flipped bit, anywhere.
    {
        var b = k2.ke2.toBytes();
        flipBit(&knobs, &b);
        if (shim.generateKE3(k1.state, ids, ctx, o.KE2.fromBytes(b), .identity)) |_| {
            return error.FlippedKE2Accepted;
        } else |_| LoginMark.mark(.flipped_ke2_refused);
        const d = damageFixed(src, o.KE2.encoded_length, k2.ke2.toBytes());
        if (shim.generateKE3(k1.state, ids, ctx, o.KE2.fromBytes(d), .identity)) |_| {
            if (!std.mem.eql(u8, &d, &k2.ke2.toBytes())) return error.DamagedKE2Accepted;
        } else |_| LoginMark.mark(.damaged_ke2_refused);
    }
    // KE3: one flipped bit.
    {
        var b = k3.ke3.toBytes();
        flipBit(&knobs, &b);
        if (shim.serverFinish(k2.state, o.KE3.fromBytes(b))) |_| {
            return error.FlippedKE3Accepted;
        } else |_| LoginMark.mark(.flipped_ke3_refused);
    }
    // KE1 flipped in transit: the server answers (or refuses), the client's
    // own transcript no longer matches what the server MACed.
    {
        var b = k1.ke1.toBytes();
        flipBit(&knobs, &b);
        if (shim.generateKE2(server.private_key, server.public_key, record, &cred_id, oprf_seed, o.KE1.fromBytes(b), ids, ctx, nonces[2], nonces[3], kseed[1])) |bad2| {
            if (shim.generateKE3(k1.state, ids, ctx, bad2.ke2, .identity)) |_| return error.FlippedKE1Accepted else |_| {}
        } else |_| {}
        LoginMark.mark(.flipped_ke1_refused);
    }
    // The stored record, one flipped bit: the login cannot complete.
    {
        var b = record.toBytes();
        flipBit(&knobs, &b);
        const rec2 = o.RegistrationRecord.fromBytes(b);
        if (shim.generateKE2(server.private_key, server.public_key, rec2, &cred_id, oprf_seed, k1.ke1, ids, ctx, nonces[2], nonces[3], kseed[1])) |bad2| {
            if (shim.generateKE3(k1.state, ids, ctx, bad2.ke2, .identity)) |_| return error.FlippedRecordAccepted else |_| {}
        } else |_| {}
        LoginMark.mark(.flipped_record_refused);
    }
    _ = bad_blind;
}

test "fuzz: opaque login, genuine accepted / flipped refused" {
    try testing.fuzz({}, smithWrap(fuzzLogin), .{});
}
test "fuzz driver: OPAQUE_FUZZ (login)" {
    try fuzz_driver.run(fuzzLogin, .{ .prefix = "OPAQUE_FUZZ", .name = "opaque-login", .scale = 4 });
}
test "fuzz harness: login, 40 seeds, reaches every outcome" {
    try LoginMark.reach(fuzzLogin, "opaque-login", 40);
}

const HostileMark = Marker(enum { request_ok, request_refused, ke1_ok, ke1_refused, ke2_refused, record_invalid, record_valid });

fn fuzzHostile(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [16]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    var seed: [o.Nseed]u8 = undefined;
    expand(&knobs, &seed);
    const server = try shim.deriveAkeKeyPair(seed);
    var oprf_seed: [o.Nh]u8 = undefined;
    expand(&knobs, &oprf_seed);
    var wide: [64]u8 = undefined;
    expand(&knobs, &wide);
    const blind = shim.scalarFromWideBytes(wide);
    var nonce: [o.Nn]u8 = undefined;
    expand(&knobs, &nonce);

    // Hostile registration request: raw or a damaged genuine one.
    const genuine = try shim.createRegistrationRequest("pw", blind);
    var rq: [o.RegistrationRequest.encoded_length]u8 = undefined;
    src.bytes(&rq);
    if (knobs.byte() & 1 == 0) rq = damageFixed(src, rq.len, genuine.toBytes());
    if (shim.createRegistrationResponse(o.RegistrationRequest.fromBytes(rq), server.public_key, "cred", oprf_seed)) |_| HostileMark.mark(.request_ok) else |_| HostileMark.mark(.request_refused);

    // A record built from random bytes, validated, then driven through KE2.
    var rb: [o.RegistrationRecord.encoded_length]u8 = undefined;
    src.bytes(&rb);
    const record = o.RegistrationRecord.fromBytes(rb);
    if (record.validate()) |_| HostileMark.mark(.record_valid) else |_| HostileMark.mark(.record_invalid);

    var k1b: [o.KE1.encoded_length]u8 = undefined;
    src.bytes(&k1b);
    const real = try shim.generateKE1("pw", blind, nonce, seed);
    if (knobs.byte() & 1 == 0) k1b = damageFixed(src, k1b.len, real.ke1.toBytes());
    if (shim.generateKE2(server.private_key, server.public_key, record, "cred", oprf_seed, o.KE1.fromBytes(k1b), .{}, "ctx", nonce, nonce, seed)) |_| HostileMark.mark(.ke1_ok) else |_| HostileMark.mark(.ke1_refused);

    // A KE2 nobody made never opens.
    var k2b: [o.KE2.encoded_length]u8 = undefined;
    src.bytes(&k2b);
    if (shim.generateKE3(real.state, .{}, "ctx", o.KE2.fromBytes(k2b), .identity)) |_| return error.ForgedKE2Accepted else |_| HostileMark.mark(.ke2_refused);
}

test "fuzz: opaque hostile wire messages" {
    try testing.fuzz({}, smithWrap(fuzzHostile), .{});
}
test "fuzz driver: OPAQUE_FUZZ (hostile)" {
    try fuzz_driver.run(fuzzHostile, .{ .prefix = "OPAQUE_FUZZ", .name = "opaque-hostile" });
}
test "fuzz harness: hostile, 300 seeds, reaches every outcome" {
    try HostileMark.reach(fuzzHostile, "opaque-hostile", 300);
}
