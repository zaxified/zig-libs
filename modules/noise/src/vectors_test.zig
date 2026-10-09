// SPDX-License-Identifier: MIT
//! The cacophony test vectors for Noise rev 34, run byte-exact.
//!
//! `testdata/cacophony-subset.json` is copied verbatim (whole JSON objects)
//! from snow's `tests/vectors/cacophony.txt` (github.com/mcginty/snow) by
//! `tools/extract-vectors.py`: every `Noise_*_25519_ChaChaPoly_SHA256` vector
//! — the 15 fundamental and 23 deferred patterns and every PSK variant the
//! file carries — plus IK, KK1, NNpsk0 and XXpsk3 under the other seven
//! 25519 suites. Each vector fixes both parties' keys, prologue and PSKs and
//! lists every handshake and transport message byte for byte, and the final
//! handshake hash.
//!
//! The protocol name is resolved at run time through
//! `patterns.parseProtocolName` and the session is opened with the checked
//! `HandshakeState.init`, so the catalog, the PSK placement, the name parser
//! and the validation are all anchored by the same bytes. ChaChaPoly vectors
//! run under both ChaCha20-Poly1305 implementations (`chachapoly` and std).

const std = @import("std");
const chachapoly = @import("chachapoly");
const patterns = @import("patterns.zig");
const state = @import("state.zig");

const testing = std.testing;
const X25519 = std.crypto.dh.X25519;
const sha2 = std.crypto.hash.sha2;
const blake2 = std.crypto.hash.blake2;
const StdChaCha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

const vectors_json = @embedFile("testdata/cacophony-subset.json");

/// Every suite a vector in the subset can name, each ChaChaPoly one twice.
const suites = .{
    state.Suite(X25519, chachapoly.ChaCha20Poly1305, sha2.Sha256),
    state.Suite(X25519, StdChaCha, sha2.Sha256),
    state.Suite(X25519, chachapoly.ChaCha20Poly1305, sha2.Sha512),
    state.Suite(X25519, StdChaCha, sha2.Sha512),
    state.Suite(X25519, chachapoly.ChaCha20Poly1305, blake2.Blake2s256),
    state.Suite(X25519, StdChaCha, blake2.Blake2s256),
    state.Suite(X25519, chachapoly.ChaCha20Poly1305, blake2.Blake2b512),
    state.Suite(X25519, StdChaCha, blake2.Blake2b512),
    state.Suite(X25519, Aes256Gcm, sha2.Sha256),
    state.Suite(X25519, Aes256Gcm, sha2.Sha512),
    state.Suite(X25519, Aes256Gcm, blake2.Blake2s256),
    state.Suite(X25519, Aes256Gcm, blake2.Blake2b512),
};

fn noRandomFill(_: *anyopaque, _: []u8) void {
    @panic("vector handshake must not draw randomness (ephemeral injected)");
}
const no_random = std.Random{ .ptr = undefined, .fillFn = noRandomFill };

fn hexAlloc(a: std.mem.Allocator, v: ?std.json.Value) !?[]u8 {
    const s = (v orelse return null).string;
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn keyPair(comptime S: type, a: std.mem.Allocator, v: ?std.json.Value) !?S.KeyPair {
    const b = (try hexAlloc(a, v)) orelse return null;
    return try S.KeyPair.generateDeterministic(b[0..32].*);
}

fn pub32(comptime S: type, a: std.mem.Allocator, v: ?std.json.Value) !?[S.DHLEN]u8 {
    const b = (try hexAlloc(a, v)) orelse return null;
    return b[0..S.DHLEN].*;
}

fn psks(a: std.mem.Allocator, v: ?std.json.Value) ![]const [32]u8 {
    const arr = (v orelse return &.{}).array.items;
    const out = try a.alloc([32]u8, arr.len);
    for (arr, out) |x, *o| _ = try std.fmt.hexToBytes(o, x.string);
    return out;
}

/// `Keys` with the private key pairs by value, for the tests (a copy of a test
/// key in a test frame proves nothing); `mk` turns them into the pointers the
/// library takes.
fn TestKeys(comptime S: type) type {
    return struct {
        s: ?S.KeyPair = null,
        e: ?S.KeyPair = null,
        rs: ?[S.DHLEN]u8 = null,
        re: ?[S.DHLEN]u8 = null,
        psks: []const [32]u8 = &.{},
    };
}

/// The checked `init` in the by-value shape the tests want.
fn mk(comptime S: type, pattern: patterns.HandshakePattern, initiator: bool, prologue: []const u8, tk: TestKeys(S)) S.HandshakeState.InitError!S.HandshakeState {
    var hs: S.HandshakeState = .{};
    const keys: S.HandshakeState.Keys = .{
        .s = if (tk.s) |*k| k else null,
        .e = if (tk.e) |*k| k else null,
        .rs = tk.rs,
        .re = tk.re,
        .psks = tk.psks,
    };
    try hs.init(pattern, initiator, prologue, &keys);
    return hs;
}

fn runVector(comptime S: type, a: std.mem.Allocator, v: std.json.ObjectMap, pattern: patterns.HandshakePattern) !void {
    var ini = try mk(S, pattern, true, (try hexAlloc(a, v.get("init_prologue"))).?, .{
        .s = try keyPair(S, a, v.get("init_static")),
        .e = try keyPair(S, a, v.get("init_ephemeral")),
        .rs = try pub32(S, a, v.get("init_remote_static")),
        .psks = try psks(a, v.get("init_psks")),
    });
    var rsp = try mk(S, pattern, false, (try hexAlloc(a, v.get("resp_prologue"))).?, .{
        .s = try keyPair(S, a, v.get("resp_static")),
        .e = try keyPair(S, a, v.get("resp_ephemeral")),
        .rs = try pub32(S, a, v.get("resp_remote_static")),
        .psks = try psks(a, v.get("resp_psks")),
    });
    const n_hs = pattern.message_patterns.len;
    const one_way = n_hs == 1;
    var t_ini: [2]S.CipherState = undefined;
    var t_rsp: [2]S.CipherState = undefined;
    for (v.get("messages").?.array.items, 0..) |m, i| {
        const payload = (try hexAlloc(a, m.object.get("payload"))).?;
        const ct = (try hexAlloc(a, m.object.get("ciphertext"))).?;
        // Handshake messages alternate; transport messages alternate too,
        // except after a one-way pattern, where only the initiator sends.
        const from_initiator = one_way or i % 2 == 0;
        var wire: [1024]u8 = undefined;
        var plain: [1024]u8 = undefined;
        if (i < n_hs) {
            const writer = if (from_initiator) &ini else &rsp;
            const reader = if (from_initiator) &rsp else &ini;
            var wt: [2]S.CipherState = undefined;
            var rt: [2]S.CipherState = undefined;
            const wr = try writer.writeMessage(no_random, payload, &wire, &wt);
            try testing.expectEqualSlices(u8, ct, wire[0..wr.len]);
            const rr = try reader.readMessage(ct, &plain, &rt);
            try testing.expectEqualSlices(u8, payload, plain[0..rr.len]);
            if (i == n_hs - 1) {
                try testing.expect(wr.complete and rr.complete);
                t_ini = if (from_initiator) wt else rt;
                t_rsp = if (from_initiator) rt else wt;
            } else {
                try testing.expect(!wr.complete and !rr.complete);
            }
        } else {
            const send = if (from_initiator) &t_ini[0] else &t_rsp[1];
            const recv = if (from_initiator) &t_rsp[0] else &t_ini[1];
            try send.encryptWithAd("", payload, wire[0..ct.len]);
            try testing.expectEqualSlices(u8, ct, wire[0..ct.len]);
            try recv.decryptWithAd("", ct, plain[0..payload.len]);
            try testing.expectEqualSlices(u8, payload, plain[0..payload.len]);
        }
    }
    const hh = (try hexAlloc(a, v.get("handshake_hash"))).?;
    try testing.expectEqualSlices(u8, hh, &ini.symmetric_state.getHandshakeHash());
    try testing.expectEqualSlices(u8, hh, &rsp.symmetric_state.getHandshakeHash());
}

test "cacophony vectors: 87 protocols byte-exact, every pattern of the catalog" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, a, vectors_json, .{});
    const list = parsed.object.get("vectors").?.array.items;
    try testing.expectEqual(@as(usize, 87), list.len);

    var runs: usize = 0;
    var seen: [patterns.catalog.len]bool = @splat(false);
    var psk_runs: usize = 0;
    for (list) |item| {
        const v = item.object;
        const name = v.get("protocol_name").?.string;
        var st: patterns.Storage = .{};
        const proto = try patterns.parseProtocolName(&st, name);
        try testing.expectEqualStrings(name["Noise_".len..][0..proto.pattern.name.len], proto.pattern.name);
        var matched: usize = 0;
        inline for (suites) |S| {
            if (S.matches(proto)) {
                runVector(S, a, v, proto.pattern) catch |e| {
                    std.debug.print("vector {s} under {s}: {t}\n", .{ name, @typeName(S.AeadCipher), e });
                    return e;
                };
                matched += 1;
                runs += 1;
            }
        }
        try testing.expect(matched >= 1);
        for (patterns.catalog, 0..) |p, i| {
            if (std.mem.startsWith(u8, proto.pattern.name, p.name) and
                (proto.pattern.name.len == p.name.len or std.ascii.isLower(proto.pattern.name[p.name.len])))
                seen[i] = true;
        }
        if (std.mem.indexOf(u8, proto.pattern.name, "psk") != null) psk_runs += 1;
    }
    // Every catalog pattern is anchored by at least one vector.
    for (seen, patterns.catalog) |s, p| testing.expect(s) catch |e| {
        std.debug.print("no vector for {s}\n", .{p.name});
        return e;
    };
    // 59 + 28 vectors; the 59 + 12 ChaChaPoly ones run twice.
    try testing.expectEqual(@as(usize, 87 + 59 + 12), runs);
    try testing.expect(psk_runs >= 21);
}

// ── HandshakeState.init: spec §7.3 validation ───────────────────────────────

const S0 = state.Suite(X25519, chachapoly.ChaCha20Poly1305, sha2.Sha256);
const Token = @import("token.zig").Token;

fn kp(b: u8) S0.KeyPair {
    return S0.KeyPair.generateDeterministic([_]u8{b} ** 32) catch unreachable;
}

test "init: missing keys, PSK count and invalid patterns are refused before anything runs" {
    const s1 = kp(1);
    const s2 = kp(2);
    // NK: the initiator must know the responder's static (pre-message).
    try testing.expectError(error.MissingKey, mk(S0, patterns.NK, true, "", .{}));
    _ = try mk(S0, patterns.NK, true, "", .{ .rs = s2.public_key });
    try testing.expectError(error.MissingKey, mk(S0, patterns.NK, false, "", .{}));
    // XX: each side sends its static, so each needs one.
    try testing.expectError(error.MissingKey, mk(S0, patterns.XX, true, "", .{}));
    try testing.expectError(error.MissingKey, mk(S0, patterns.XX, false, "", .{}));
    _ = try mk(S0, patterns.XX, false, "", .{ .s = s1 });
    // KN: the responder must know the initiator's static in advance.
    try testing.expectError(error.MissingKey, mk(S0, patterns.KN, false, "", .{}));
    _ = try mk(S0, patterns.KN, false, "", .{ .rs = s1.public_key });
    // NN with no key at all is fine; a responder's static is needed for `es`
    // in NK only on the responder side.
    _ = try mk(S0, patterns.NN, true, "", .{});
    // PSKs: exactly one per token.
    const xx3 = patterns.withPsk(patterns.XX, &.{3});
    try testing.expectError(error.PskCountMismatch, mk(S0, xx3, true, "", .{ .s = s1 }));
    try testing.expectError(error.PskCountMismatch, mk(S0, patterns.XX, true, "", .{ .s = s1, .psks = &.{[_]u8{0} ** 32} }));
    _ = try mk(S0, xx3, true, "", .{ .s = s1, .psks = &.{[_]u8{0} ** 32} });
    // Invalid patterns (§7.3): a DH before its keys, a key sent twice, an
    // empty pattern, a DH token in a pre-message.
    const bad = [_]patterns.HandshakePattern{
        .{ .name = "B1", .message_patterns = &.{&.{ .ee, .e }} },
        .{ .name = "B2", .message_patterns = &.{ &.{.e}, &.{ .e, .e } } },
        .{ .name = "B3", .message_patterns = &.{} },
        .{ .name = "B4", .pre_message_initiator = &.{.ee}, .message_patterns = &.{&.{.e}} },
        .{ .name = "B5", .pre_message_responder = &.{.s}, .message_patterns = &.{ &.{.e}, &.{ .e, .s } } },
        .{ .name = "B6", .message_patterns = &.{ &.{.e}, &.{ .e, .es } } },
        .{ .name = "B7", .message_patterns = &.{&.{ .e, .se }} },
        .{ .name = "X" ** 120, .message_patterns = &.{&.{.e}} },
    };
    for (bad) |p| {
        try testing.expectError(error.InvalidPattern, mk(S0, p, true, "", .{ .s = s1, .rs = s2.public_key }));
    }
}

// ── pluggable primitives by `noise_name` ────────────────────────────────────

/// X25519 under a declared name — the shape an X448 or secp256k1 adapter
/// from another module takes. Declaring the spec name "25519" must give
/// exactly the std binding's transcript; declaring another name must change it.
fn NamedDh(comptime name: []const u8) type {
    return struct {
        pub const noise_name = name;
        pub const public_length = X25519.public_length;
        pub const seed_length = X25519.seed_length;
        pub const KeyPair = X25519.KeyPair;
        pub const scalarmult = X25519.scalarmult;
    };
}

test "a primitive declaring noise_name joins a suite; the name reaches the transcript" {
    const Alias = state.Suite(NamedDh("25519"), chachapoly.ChaCha20Poly1305, sha2.Sha256);
    const Other = state.Suite(NamedDh("448"), chachapoly.ChaCha20Poly1305, sha2.Sha256);
    try testing.expectEqualStrings("_25519_ChaChaPoly_SHA256", Alias.name_suffix);
    try testing.expectEqualStrings("_448_ChaChaPoly_SHA256", Other.name_suffix);
    const a = try mk(Alias, patterns.NN, true, "p", .{});
    const b = try mk(S0, patterns.NN, true, "p", .{});
    const c = try mk(Other, patterns.NN, true, "p", .{});
    try testing.expectEqualSlices(u8, &b.symmetric_state.h, &a.symmetric_state.h);
    try testing.expect(!std.mem.eql(u8, &b.symmetric_state.h, &c.symmetric_state.h));
    var st: patterns.Storage = .{};
    try testing.expect(Other.matches(try patterns.parseProtocolName(&st, "Noise_NN_448_ChaChaPoly_SHA256")));
    try testing.expect(!Other.matches(try patterns.parseProtocolName(&st, "Noise_NN_25519_ChaChaPoly_SHA256")));
}

// ── seeded sweeps: random patterns, damaged messages, hostile names ────────
//
// (1) Random token patterns with random key sets: whatever `init` accepts
// for both sides must run to completion without a panic, and both sides must
// agree on the handshake hash and the transport keys — `init` is the guard
// that makes `writeMessage`/`readMessage` safe, so this checks the guard.
// (2) Valid handshakes of catalog + PSK patterns with one message damaged
// (bit flip, truncation, extension): the reader errors, never panics, and a
// damaged message is never accepted once a key protects it.
// (3) Random protocol names from name fragments: parse never panics.

fn randomPattern(r: std.Random, toks: *[4][6]Token, slices: *[4][]const Token, pre: *[2][2]Token) patterns.HandshakePattern {
    const all = [_]Token{ .e, .s, .ee, .es, .se, .ss, .psk };
    const n = r.intRangeAtMost(usize, 1, 4);
    for (0..n) |m| {
        const len = r.intRangeAtMost(usize, 0, 5);
        for (0..len) |k| toks[m][k] = all[r.uintLessThan(usize, all.len)];
        slices[m] = toks[m][0..len];
    }
    const pi_len = r.uintAtMost(usize, 2);
    const pr_len = r.uintAtMost(usize, 2);
    for (0..pi_len) |k| pre[0][k] = if (r.boolean()) .e else .s;
    for (0..pr_len) |k| pre[1][k] = if (r.uintLessThan(u8, 8) == 0) .ee else if (r.boolean()) .e else .s;
    return .{ .name = "R", .pre_message_initiator = pre[0][0..pi_len], .pre_message_responder = pre[1][0..pr_len], .message_patterns = slices[0..n] };
}

test "sweep: whatever init accepts runs to an agreed handshake" {
    var accepted: usize = 0;
    var refused: usize = 0;
    var completed_with_psk: usize = 0;
    var prng_r = std.Random.DefaultPrng.init(99);
    // Keys once: key generation in the loop was most of the run time.
    const i_s = kp(1);
    const r_s = kp(2);
    const i_e = kp(3);
    const r_e = kp(4);
    for (0..10_000) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        const r = prng.random();
        var toks: [4][6]Token = undefined;
        var slices: [4][]const Token = undefined;
        var pre: [2][2]Token = undefined;
        const p = randomPattern(r, &toks, &slices, &pre);
        const psk_list = [_][32]u8{ [_]u8{7} ** 32, [_]u8{8} ** 32, [_]u8{9} ** 32, [_]u8{10} ** 32, [_]u8{11} ** 32, [_]u8{12} ** 32 };
        var n_psk: usize = 0;
        for (p.message_patterns) |mp| for (mp) |t| {
            n_psk += @intFromBool(t == .psk);
        };
        // Random key availability, consistent between the two sides.
        const give_is = r.boolean();
        const give_rs = r.boolean();
        const pre_e_i = std.mem.indexOfScalar(Token, p.pre_message_initiator, .e) != null;
        const pre_e_r = std.mem.indexOfScalar(Token, p.pre_message_responder, .e) != null;
        var ini = mk(S0, p, true, "x", .{
            .s = if (give_is) i_s else null,
            .e = if (pre_e_i) i_e else null,
            .rs = if (give_rs) r_s.public_key else null,
            .re = if (pre_e_r) r_e.public_key else null,
            .psks = psk_list[0..@min(n_psk, psk_list.len)],
        }) catch {
            refused += 1;
            continue;
        };
        var rsp = mk(S0, p, false, "x", .{
            .s = if (give_rs) r_s else null,
            .e = if (pre_e_r) r_e else null,
            .rs = if (give_is) i_s.public_key else null,
            .re = if (pre_e_i) i_e.public_key else null,
            .psks = psk_list[0..@min(n_psk, psk_list.len)],
        }) catch {
            refused += 1;
            continue;
        };
        accepted += 1;
        var wire: [512]u8 = undefined;
        var plain: [64]u8 = undefined;
        var last: [2]S0.CipherState = undefined;
        var last_r: [2]S0.CipherState = undefined;
        for (0..p.message_patterns.len) |m| {
            const w = if (m % 2 == 0) &ini else &rsp;
            const rd = if (m % 2 == 0) &rsp else &ini;
            const out = try w.writeMessage(prng_r.random(), "hi", &wire, &last);
            const in = try rd.readMessage(wire[0..out.len], &plain, &last_r);
            try testing.expectEqualStrings("hi", plain[0..in.len]);
        }
        try testing.expectEqualSlices(u8, &ini.symmetric_state.h, &rsp.symmetric_state.h);
        try testing.expectEqualSlices(u8, &last[0].k, &last_r[0].k);
        if (n_psk > 0) completed_with_psk += 1;
    }
    // Measured 2026-10-04 (see SPEC.md § Verification).
    // Measured: 372 accepted (91 with PSKs), 9 628 refused.
    try testing.expect(accepted > 250);
    try testing.expect(refused > 5_000);
    try testing.expect(completed_with_psk > 60);
}

test "sweep: a damaged handshake message is refused, never a panic" {
    const cases = .{
        .{ patterns.XX, false },                         .{ patterns.IK, false },
        .{ patterns.KK1, false },                        .{ patterns.NX, false },
        .{ patterns.withPsk(patterns.XX, &.{3}), true }, .{ patterns.withPsk(patterns.NN, &.{0}), true },
    };
    var detected: usize = 0;
    var undetected_unkeyed: usize = 0;
    var fork_caught: usize = 0;
    const i_s = kp(1);
    const r_s = kp(2);
    inline for (cases) |c| {
        const p = c[0];
        for (0..400) |seed| {
            var prng = std.Random.DefaultPrng.init(seed);
            const r = prng.random();
            const psk1 = [_][32]u8{[_]u8{5} ** 32};
            const pk: []const [32]u8 = if (c[1]) &psk1 else &.{};
            var ini = try mk(S0, p, true, "", .{ .s = i_s, .rs = r_s.public_key, .psks = pk });
            var rsp = try mk(S0, p, false, "", .{ .s = r_s, .rs = i_s.public_key, .psks = pk });
            var tp: [2]S0.CipherState = undefined;
            const target = r.uintLessThan(usize, p.message_patterns.len);
            var forked = false;
            for (0..p.message_patterns.len) |m| {
                const w = if (m % 2 == 0) &ini else &rsp;
                const rd = if (m % 2 == 0) &rsp else &ini;
                var wire: [512]u8 = undefined;
                var plain: [64]u8 = undefined;
                const keyed = rd.symmetric_state.cipher_state.hasKey() or m > 0 or c[1];
                const out = try w.writeMessage(r, "payload", &wire, &tp);
                var len = out.len;
                if (forked) {
                    // The transcripts differ since the undetected change:
                    // the first keyed message after it must fail.
                    if (rd.readMessage(wire[0..len], &plain, &tp)) |_| return error.ForkNotCaught else |_| fork_caught += 1;
                    break;
                }
                if (m == target) {
                    switch (r.uintLessThan(u8, 3)) {
                        0 => wire[r.uintLessThan(usize, len)] ^= @as(u8, 1) << r.int(u3),
                        1 => len = r.uintLessThan(usize, len),
                        else => {
                            wire[len] = r.int(u8);
                            len += 1;
                        },
                    }
                    if (rd.readMessage(wire[0..len], &plain, &tp)) |_| {
                        // Only an unkeyed first message (NN/XX/NX `-> e`
                        // without PSK) can carry a change undetected — and
                        // then the transcripts have forked: the next keyed
                        // message fails.
                        try testing.expect(!keyed);
                        undetected_unkeyed += 1;
                        forked = true;
                        continue;
                    } else |_| detected += 1;
                    break;
                }
                _ = try rd.readMessage(wire[0..len], &plain, &tp);
            }
        }
    }
    // Measured 2026-10-04 (see SPEC.md § Verification).
    // Measured: 2 072 refused at once, 328 unkeyed first messages changed
    // undetected — every one of them caught by the next message.
    try testing.expect(detected > 1500);
    try testing.expect(undetected_unkeyed > 100);
    try testing.expectEqual(undetected_unkeyed, fork_caught);
}

test "sweep: random protocol names parse or refuse, never panic" {
    const frags = [_][]const u8{ "Noise", "_", "XX", "IK", "K1", "X1", "N", "psk", "0", "3", "+", "fallback", "25519", "448", "ChaChaPoly", "AESGCM", "SHA256", "BLAKE2s", "psk9", "1" };
    var ok: usize = 0;
    var refused: usize = 0;
    for (0..20_000) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        const r = prng.random();
        var buf: [96]u8 = undefined;
        var n: usize = 0;
        if (r.boolean()) {
            // Half start from a well-formed name and get damaged below.
            const base = patterns.catalog[r.uintLessThan(usize, patterns.catalog.len)];
            const mods = [_][]const u8{ "", "psk0", "psk1", "psk2", "psk0+psk2", "fallback" };
            const w = std.fmt.bufPrint(&buf, "Noise_{s}{s}_25519_ChaChaPoly_SHA256", .{ base.name, mods[r.uintLessThan(usize, mods.len)] }) catch unreachable;
            n = w.len;
            if (r.boolean()) {
                const at = r.uintLessThan(usize, n);
                buf[at] = "_+p0Xs"[r.uintLessThan(usize, 6)];
            }
        } else if (r.boolean()) {
            @memcpy(buf[0..6], "Noise_");
            n = 6;
        }
        for (0..if (n > 6) 0 else r.intRangeAtMost(usize, 1, 10)) |_| {
            const f = frags[r.uintLessThan(usize, frags.len)];
            if (n + f.len > buf.len) break;
            @memcpy(buf[n..][0..f.len], f);
            n += f.len;
        }
        var st: patterns.Storage = .{};
        if (patterns.parseProtocolName(&st, buf[0..n])) |p| {
            ok += 1;
            try testing.expect(p.pattern.message_patterns.len >= 1);
        } else |_| refused += 1;
        if (st.parse(buf[0..n])) |p| {
            ok += 1;
            try testing.expect(p.name.len <= patterns.max_name_len);
        } else |_| refused += 1;
    }
    // Measured: 6 286 resolved, 33 714 refused.
    try testing.expect(ok > 4000);
    try testing.expect(refused > 25_000);
}

test "init: a pre-message ephemeral needs the key on both sides" {
    // `initialize` alone would unwrap the missing key (`self.e.?` /
    // `self.re.?`) while hashing the pre-message — a panic, or undefined
    // behaviour in ReleaseFast. Spec §7.2 allows `e` in a pre-message.
    const p: patterns.HandshakePattern = .{ .name = "Pe", .pre_message_initiator = &.{.e}, .message_patterns = &.{&.{ .e, .ee }} };
    // The responder's view: the initiator's pre-message `e` is remote.
    const q: patterns.HandshakePattern = .{ .name = "Qe", .pre_message_initiator = &.{.e}, .message_patterns = &.{ &.{.s}, &.{ .e, .ee } } };
    try testing.expectError(error.MissingKey, mk(S0, q, true, "", .{ .s = kp(1) }));
    _ = try mk(S0, q, true, "", .{ .s = kp(1), .e = kp(3) });
    try testing.expectError(error.MissingKey, mk(S0, q, false, "", .{}));
    _ = try mk(S0, q, false, "", .{ .re = kp(3).public_key });
    // An `e` sent again after a pre-message `e` breaks §7.3.
    try testing.expectError(error.InvalidPattern, mk(S0, p, true, "", .{ .e = kp(3) }));
}
