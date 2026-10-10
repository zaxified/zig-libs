// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh noise`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-noise`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! `DefaultSuite` (X25519, the `chachapoly` sibling, SHA-256):
//!
//!  * `hs` — a full `Noise_XXpsk3` handshake, both roles. Tainted: both
//!    static private keys, every ephemeral seed (drawn from a `std.Random` whose
//!    fill marks its output undefined) and the PSK. The handshake therefore
//!    runs with secret `ck`, `k`, `h` and every DH output, through
//!    `writeMessage`/`readMessage`, `mixKey`, `mixKeyAndHash`,
//!    `encryptAndHash`/`decryptAndHash` and `split`. Message lengths and the
//!    pattern are public.
//!  * `transport` — the split pair after an UNTAINTED handshake: both
//!    transport keys tainted, then `encryptWithAd`/`decryptWithAd` both ways
//!    and `rekey`.
//!
//! The in-file pattern names this module's own files. The DH and the AEAD are
//! std's X25519 and `chachapoly`, which carry their own rows; a public key
//! derived from a tainted seed is itself tainted here, so std's X25519
//! identity-point rejection shows up in the total, not in-file.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const noise = @import("root.zig");

const S = noise.DefaultSuite;
const Target = enum { hs, transport };
const Taint = enum { yes, no };

var taint_on = false;

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    return full[0..n].*;
}

fn reloadVolatile(comptime n: usize, src: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, src) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

/// A deterministic `std.Random` whose output is tainted when `taint_on`:
/// the ephemeral seeds `writeMessage` draws are secrets.
const TaintRng = struct {
    prng: std.Random.DefaultPrng,
    fn fill(self: *TaintRng, buf: []u8) void {
        self.prng.random().bytes(buf);
        if (taint_on) std.valgrind.memcheck.makeMemUndefined(buf);
    }
    fn random(self: *TaintRng) std.Random {
        return std.Random.init(self, fill);
    }
};

const XXpsk3 = noise.withPsk(noise.patterns.XX, &.{3});

/// One full XXpsk3 handshake; returns both sides' split pairs.
fn handshake(
    rng: std.Random,
    is: *const S.KeyPair,
    rs: *const S.KeyPair,
    psk: *const [32]u8,
    ti: *[2]S.CipherState,
    tr: *[2]S.CipherState,
) ![S.HASHLEN]u8 {
    const psks = [_][32]u8{psk.*};
    var ini: S.HandshakeState = .{};
    var rsp: S.HandshakeState = .{};
    try ini.init(XXpsk3, true, "ctgrind", &.{ .s = is, .psks = &psks });
    try rsp.init(XXpsk3, false, "ctgrind", &.{ .s = rs, .psks = &psks });
    inline for (0..XXpsk3.message_patterns.len) |i| {
        const writer = if (i % 2 == 0) &ini else &rsp;
        const reader = if (i % 2 == 0) &rsp else &ini;
        var wire: [512]u8 = undefined;
        var plain: [64]u8 = undefined;
        const wt = if (i % 2 == 0) ti else tr;
        const rt = if (i % 2 == 0) tr else ti;
        const wr = try writer.writeMessage(rng, "handshake payload", &wire, wt);
        const rr = try reader.readMessage(wire[0..wr.len], &plain, rt);
        std.debug.print("ctgrind_result={x}\n", .{plain[0..rr.len]});
    }
    return ini.symmetric_state.getHandshakeHash();
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var trng: TaintRng = .{ .prng = .init(0x6e6f697365) };
    var ti: [2]S.CipherState = undefined;
    var tr: [2]S.CipherState = undefined;

    switch (target) {
        .hs => {
            taint_on = taint == .yes;
            // The static key pairs are generated untainted and only their
            // private halves are then tainted: a static PUBLIC key is public
            // (it goes on the wire), and tainting the seed would make the
            // harness's own keygen report std's identity check.
            var is = try S.KeyPair.generateDeterministic(secretBytes(32, "ctgrind-noise-static-i-v1"));
            var rs = try S.KeyPair.generateDeterministic(secretBytes(32, "ctgrind-noise-static-r-v1"));
            var psk = secretBytes(32, "ctgrind-noise-psk-v1");
            if (taint_on) {
                std.valgrind.memcheck.makeMemUndefined(&is.secret_key);
                std.valgrind.memcheck.makeMemUndefined(&rs.secret_key);
                std.valgrind.memcheck.makeMemUndefined(&psk);
            }
            is.secret_key = reloadVolatile(32, &is.secret_key);
            rs.secret_key = reloadVolatile(32, &rs.secret_key);
            const p = reloadVolatile(32, &psk);
            const h = try handshake(trng.random(), &is, &rs, &p, &ti, &tr);
            std.debug.print("ctgrind_result={x}\n", .{h});
            std.debug.print("ctgrind_result={x}\n", .{ti[0].k ++ tr[1].k});
        },
        .transport => {
            const is = try S.KeyPair.generateDeterministic(secretBytes(32, "ctgrind-noise-static-i-v1"));
            const rs = try S.KeyPair.generateDeterministic(secretBytes(32, "ctgrind-noise-static-r-v1"));
            const p = secretBytes(32, "ctgrind-noise-psk-v1");
            _ = try handshake(trng.random(), &is, &rs, &p, &ti, &tr);
            if (taint == .yes) for ([_]*[2]S.CipherState{ &ti, &tr }) |pair| for (pair) |*cs| {
                std.valgrind.memcheck.makeMemUndefined(&cs.k);
            };
            var wire: [64 + 16]u8 = undefined;
            var plain: [64]u8 = undefined;
            const msg = "initiator->responder, 32 bytes.";
            for (0..3) |round| {
                try ti[0].encryptWithAd("ad", msg, wire[0 .. msg.len + 16]);
                try tr[0].decryptWithAd("ad", wire[0 .. msg.len + 16], plain[0..msg.len]);
                try tr[1].encryptWithAd("", msg, wire[0 .. msg.len + 16]);
                try ti[1].decryptWithAd("", wire[0 .. msg.len + 16], plain[0..msg.len]);
                if (round == 1) {
                    for ([_]*[2]S.CipherState{ &ti, &tr }) |pair| for (pair) |*cs| cs.rekey();
                }
            }
            std.debug.print("ctgrind_result={x}\n", .{wire[0 .. msg.len + 16]});
            std.debug.print("ctgrind_result={x}\n", .{plain[0..msg.len]});
        },
    }
}
