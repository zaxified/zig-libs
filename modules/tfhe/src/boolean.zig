// SPDX-License-Identifier: MIT

//! boolean — encrypted bits and the binary gates on them: the layer a caller
//! of TFHE gate bootstrapping actually uses.
//!
//! ## Encoding — tfhe-rs's boolean encoding
//!
//! `true` is the torus value `+q/8`, `false` is `−q/8`. A gate adds its
//! inputs (and a constant) so that the result's phase lands in the upper half
//! of the torus exactly when the gate's output is `true`, then bootstraps with
//! the constant test polynomial `q/8`: blind rotation reads `+q/8` for a phase
//! in `[0, q/2)` and, by negacyclicity, `−q/8` in `[q/2, q)`. That is the
//! sign function, so the output is a fresh `±q/8` again. With inputs `±q/8`:
//!
//!   | gate | linear combination before the bootstrap |
//!   |------|-----------------------------------------|
//!   | AND  | `−q/8 + a + b`                          |
//!   | NAND | `+q/8 − a − b`                          |
//!   | OR   | `+q/8 + a + b`                          |
//!   | NOR  | `−q/8 − a − b`                          |
//!   | XOR  | `+q/4 + 2·(a + b)`                      |
//!   | XNOR | `−q/4 − 2·(a + b)`                      |
//!   | NOT  | `−a` (no bootstrap)                     |
//!
//! and `mux(c, a, b) = c ? a : b` bootstraps `c AND a` and `¬c AND b` without
//! key switching, adds `+q/8`, and key-switches once. These are the
//! Chillotti–Gama–Georgieva–Izabachène gate formulas (J. Cryptology 2020,
//! §5) on that encoding, and the encoding and the bootstrap order (PBS, then
//! key switch, ciphertexts under the small key) are tfhe-rs's
//! `EncryptionKeyChoice::Small`: `interop_test.zig` evaluates the same gates
//! in both directions — tfhe-rs ciphertexts through these gates, and this
//! module's keys and ciphertexts through tfhe-rs's `ServerKey`.
//!
//! `ServerKey` holds the bootstrap key prepared in the NTT domain and the
//! key-switch key; it is the evaluation key a client ships to a server. The
//! client keeps `ClientKey` (the two secret keys).

const std = @import("std");
const torus = @import("torus.zig");

const T = torus.Torus;
const Allocator = std.mem.Allocator;

/// `+q/8` — the encoding of `true`.
pub const true_value: T = 1 << 29;
/// `−q/8` — the encoding of `false`.
pub const false_value: T = 0 -% true_value;

/// Encode a bit (`true` → `+q/8`, `false` → `−q/8`). Branch-free.
pub fn encode(b: bool) T {
    const m: T = 0 -% @as(T, @intFromBool(b));
    return (true_value & m) | (false_value & ~m);
}

/// Decode a phase: `true` iff it lies in `[0, q/2)`.
pub fn decode(phase: T) bool {
    return phase >> 31 == 0;
}

/// The client's two secret keys for the instance `F = Tfhe(P)`.
pub fn ClientKey(comptime F: type) type {
    return struct {
        const Self = @This();
        lwe: F.LweKey(F.lwe_dim),
        glwe: F.GlweKey,

        /// Both keys from `io`'s CSPRNG.
        pub fn generate(io: std.Io) Self {
            return .{ .lwe = F.lweKeyGen(F.lwe_dim, io), .glwe = F.glweKeyGen(io) };
        }

        /// Encrypt a bit under the small key.
        pub fn encrypt(self: *const Self, b: bool, io: std.Io) F.LweN {
            return F.lweEncrypt(F.lwe_dim, &self.lwe, encode(b), io);
        }

        pub fn decrypt(self: *const Self, ct: *const F.LweN) bool {
            return decode(F.lwePhase(F.lwe_dim, &self.lwe, ct));
        }

        /// Wipe both keys.
        pub fn deinit(self: *Self) void {
            self.lwe.deinit();
            self.glwe.deinit();
        }
    };
}

/// The evaluation key for `F = Tfhe(P)` and the gates that use it.
pub fn ServerKey(comptime F: type) type {
    return struct {
        const Self = @This();
        bsk: F.PreparedBootstrapKey,
        ksk: F.KeySwitchKey,

        /// The constant test polynomial `q/8`: the sign function.
        const sign_lut: F.Poly = blk: {
            @setEvalBranchQuota(F.ring_degree * 4 + 1000);
            var p: F.Poly = undefined;
            for (&p.c) |*c| c.* = true_value;
            break :blk p;
        };

        /// Generate the bootstrap and key-switch keys for `client` from `io`'s
        /// CSPRNG and prepare the bootstrap key.
        pub fn generate(allocator: Allocator, client: *const ClientKey(F), io: std.Io) Allocator.Error!Self {
            var bsk = try F.bootstrapKeyGen(allocator, &client.lwe, &client.glwe, io);
            defer bsk.deinit(allocator);
            var ksk = try F.keySwitchKeyGen(allocator, &client.glwe, &client.lwe, io);
            errdefer ksk.deinit(allocator);
            return .{ .bsk = try F.PreparedBootstrapKey.init(allocator, &bsk), .ksk = ksk };
        }

        /// Build from standard-domain keys (e.g. decoded from bytes). Borrows
        /// `bsk` (prepares a copy) and takes ownership of `ksk`.
        /// On error `ksk` is freed too: ownership passes on every path.
        pub fn fromKeys(allocator: Allocator, bsk: *const F.BootstrapKey, ksk: F.KeySwitchKey) Allocator.Error!Self {
            const pk = F.PreparedBootstrapKey.init(allocator, bsk) catch |e| {
                var k = ksk;
                k.deinit(allocator);
                return e;
            };
            return .{ .bsk = pk, .ksk = ksk };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            self.bsk.deinit(allocator);
            self.ksk.deinit(allocator);
        }

        /// A noiseless encryption of a public bit, usable as a gate input.
        pub fn trivial(b: bool) F.LweN {
            return F.lweTrivial(F.lwe_dim, encode(b));
        }

        /// Bootstrap the sign of `ct`'s phase to a fresh `±q/8`.
        fn sign(self: *const Self, ct: *const F.LweN) F.LweN {
            return self.bsk.bootstrap(&self.ksk, &sign_lut, ct);
        }

        /// `c + x + y` on the small key.
        fn sum3(c: T, x: *const F.LweN, y: *const F.LweN) F.LweN {
            const s = F.lweAdd(F.lwe_dim, x, y);
            return F.lweAddConstant(F.lwe_dim, &s, c);
        }

        pub fn @"and"(self: *const Self, a: *const F.LweN, b: *const F.LweN) F.LweN {
            return self.sign(&sum3(false_value, a, b));
        }
        pub fn nand(self: *const Self, a: *const F.LweN, b: *const F.LweN) F.LweN {
            const s = F.lweNeg(F.lwe_dim, &F.lweAdd(F.lwe_dim, a, b));
            return self.sign(&F.lweAddConstant(F.lwe_dim, &s, 1 << 29));
        }
        pub fn @"or"(self: *const Self, a: *const F.LweN, b: *const F.LweN) F.LweN {
            return self.sign(&sum3(1 << 29, a, b));
        }
        pub fn nor(self: *const Self, a: *const F.LweN, b: *const F.LweN) F.LweN {
            const s = F.lweNeg(F.lwe_dim, &F.lweAdd(F.lwe_dim, a, b));
            return self.sign(&F.lweAddConstant(F.lwe_dim, &s, false_value));
        }
        pub fn xor(self: *const Self, a: *const F.LweN, b: *const F.LweN) F.LweN {
            const s = F.lweScalarMul(F.lwe_dim, &F.lweAdd(F.lwe_dim, a, b), 2);
            return self.sign(&F.lweAddConstant(F.lwe_dim, &s, 1 << 30));
        }
        pub fn xnor(self: *const Self, a: *const F.LweN, b: *const F.LweN) F.LweN {
            const s = F.lweScalarMul(F.lwe_dim, &F.lweAdd(F.lwe_dim, a, b), 0 -% @as(T, 2));
            return self.sign(&F.lweAddConstant(F.lwe_dim, &s, @as(T, 0xC000_0000)));
        }
        /// Negation is linear: no bootstrap, no key needed.
        pub fn not(a: *const F.LweN) F.LweN {
            return F.lweNeg(F.lwe_dim, a);
        }
        /// `c ? a : b`: two bootstraps without key switch, one key switch.
        pub fn mux(self: *const Self, c: *const F.LweN, a: *const F.LweN, b: *const F.LweN) F.LweN {
            const lhs = sum3(false_value, c, a); // c AND a
            const nc = F.lweNeg(F.lwe_dim, c);
            const rhs = sum3(false_value, &nc, b); // ¬c AND b
            const u1_ = self.bsk.bootstrapBig(&sign_lut, &lhs);
            const u2_ = self.bsk.bootstrapBig(&sign_lut, &rhs);
            const big = F.lweAddConstant(F.big_lwe_dim, &F.lweAdd(F.big_lwe_dim, &u1_, &u2_), 1 << 29);
            return F.keySwitch(&self.ksk, &big);
        }
    };
}

const testing = std.testing;
const params = @import("params.zig");
const tfhe = @import("tfhe.zig");

/// Small `k = 2` set (no security): every gate, quickly.
const Small = tfhe.Tfhe(.{
    .n = 16,
    .k = 2,
    .N = 64,
    .bg_bits = 6,
    .ell = 3,
    .bks_bits = 3,
    .ell_ks = 6,
    .lwe_noise = .{ .uniform = 1 << 8 },
    .glwe_noise = .{ .uniform = 1 << 6 },
});

test "encode/decode: true = +q/8, false = −q/8, sign decides" {
    try testing.expectEqual(@as(T, 0x2000_0000), encode(true));
    try testing.expectEqual(@as(T, 0xE000_0000), encode(false));
    try testing.expect(decode(encode(true)) and !decode(encode(false)));
    try testing.expect(decode(0) and decode(0x7fff_ffff) and !decode(0x8000_0000) and !decode(0xffff_ffff));
}

test "every gate's truth table, on encrypted and on trivial inputs" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var ck = Small.ClientKey.generate(io);
    defer ck.deinit();
    var sk = try Small.ServerKey.generate(testing.allocator, &ck, io);
    defer sk.deinit(testing.allocator);

    for (0..2) |round| {
        for (0..4) |it| {
            const a = it & 1 == 1;
            const b = it & 2 == 2;
            const ca = if (round == 0) ck.encrypt(a, io) else Small.ServerKey.trivial(a);
            const cb = if (round == 0) ck.encrypt(b, io) else Small.ServerKey.trivial(b);
            try testing.expectEqual(a and b, ck.decrypt(&sk.@"and"(&ca, &cb)));
            try testing.expectEqual(!(a and b), ck.decrypt(&sk.nand(&ca, &cb)));
            try testing.expectEqual(a or b, ck.decrypt(&sk.@"or"(&ca, &cb)));
            try testing.expectEqual(!(a or b), ck.decrypt(&sk.nor(&ca, &cb)));
            try testing.expectEqual(a != b, ck.decrypt(&sk.xor(&ca, &cb)));
            try testing.expectEqual(a == b, ck.decrypt(&sk.xnor(&ca, &cb)));
            try testing.expectEqual(!a, ck.decrypt(&Small.ServerKey.not(&ca)));
            for ([_]bool{ false, true }) |c| {
                const cc = ck.encrypt(c, io);
                try testing.expectEqual(if (c) a else b, ck.decrypt(&sk.mux(&cc, &ca, &cb)));
            }
        }
    }
}

test "gates compose: a 4-bit ripple-carry adder, 40 gates deep" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var ck = Small.ClientKey.generate(io);
    defer ck.deinit();
    var sk = try Small.ServerKey.generate(testing.allocator, &ck, io);
    defer sk.deinit(testing.allocator);

    const pairs = [_][2]u4{ .{ 0, 0 }, .{ 15, 1 }, .{ 9, 7 }, .{ 5, 10 } };
    for (pairs) |pr| {
        var xa: [4]Small.LweN = undefined;
        var xb: [4]Small.LweN = undefined;
        for (0..4) |i| {
            xa[i] = ck.encrypt((pr[0] >> @intCast(i)) & 1 == 1, io);
            xb[i] = ck.encrypt((pr[1] >> @intCast(i)) & 1 == 1, io);
        }
        var carry = Small.ServerKey.trivial(false);
        var sum: u5 = 0;
        for (0..4) |i| {
            const t = sk.xor(&xa[i], &xb[i]);
            const s = sk.xor(&t, &carry);
            carry = sk.@"or"(&sk.@"and"(&xa[i], &xb[i]), &sk.@"and"(&t, &carry));
            if (ck.decrypt(&s)) sum |= @as(u5, 1) << @intCast(i);
        }
        if (ck.decrypt(&carry)) sum |= 16;
        try testing.expectEqual(@as(u5, pr[0]) + pr[1], sum);
    }
}

test "a server key built from standard-domain keys evaluates the same" {
    var prng = std.Random.DefaultPrng.init(77);
    const rnd = prng.random();
    const lwe = Small.lweKeyGenForTest(16, rnd);
    const glwe = Small.glweKeyGenForTest(rnd);
    const ck: Small.ClientKey = .{ .lwe = lwe, .glwe = glwe };
    var bsk = try Small.bootstrapKeyGenForTest(testing.allocator, &lwe, &glwe, rnd);
    defer bsk.deinit(testing.allocator);
    const ksk = try Small.keySwitchKeyGenForTest(testing.allocator, &glwe, &lwe, rnd);
    var sk = try Small.ServerKey.fromKeys(testing.allocator, &bsk, ksk);
    defer sk.deinit(testing.allocator);
    const t = Small.lweEncryptForTest(16, &lwe, encode(true), rnd);
    const f = Small.lweEncryptForTest(16, &lwe, encode(false), rnd);
    try testing.expect(!ck.decrypt(&sk.@"and"(&t, &f)));
    try testing.expect(ck.decrypt(&sk.@"or"(&t, &f)));
}

test {
    _ = params;
}
