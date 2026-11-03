// SPDX-License-Identifier: MIT

//! `testkit.stackprobe` probe of the pointer-keyed entry points (`xorInto`,
//! `streamInto`, `encryptInto`, `decryptInto`, and `hchacha20`), residue below the burn and the
//! key as a needle in any frame. The older `stackprobe_test.zig` stays as it
//! was. ReleaseFast only (`skipUnlessOptimized`, a runtime skip). Short
//! (short-engine) and wide messages, per-message burns (AEAD: 1 / 4 KiB, ChaCha20: 2 / 4 KiB, TIGHT).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;
const C = root.ChaCha20;
const A = root.ChaCha20Poly1305;

const P = sp.Probe(.{ .window = 64 * 1024 });

var key: [32]u8 = undefined;
var ct: [2048]u8 = undefined;
var pt: [2048]u8 = undefined;
var tag: [16]u8 = undefined;
const msg: [2048]u8 = @splat(0x5a);
const nonce: [12]u8 = @splat(9);
const ad = "dead-stack probe";

test "STACKPROBE: no ChaCha20 key residue after the pointer-keyed entry points" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("chachapoly probe key", &key, .{});
    const ks = &[_][]const u8{&key};

    inline for (.{ 32, 1000 }) |len| {
        const l = std.fmt.comptimePrint("{d}", .{len});
        _ = try P.run("xorInto " ++ l, C.xorInto, .{ ct[0..len], msg[0..len], 1, &key, nonce }, ks, .{});
        _ = try P.run("streamInto " ++ l, C.streamInto, .{ ct[0..len], 1, &key, nonce }, ks, .{});
        _ = try P.run("encryptInto " ++ l, A.encryptInto, .{ ct[0..len], &tag, msg[0..len], ad, nonce, &key }, ks, .{});
        _ = try P.run("decryptInto " ++ l, A.decryptInto, .{ pt[0..len], ct[0..len], tag, ad, nonce, &key }, ks, .{});
        try std.testing.expectEqualSlices(u8, msg[0..len], pt[0..len]);
    }
    // The subkey derivation on its own: the key must not survive below its burn.
    _ = try P.run("hchacha20", root.hchacha20, .{ &subkey, &key, &hinput }, ks, .{});
}

var subkey: [32]u8 = undefined;
const hinput: [16]u8 = @splat(0x33);

var ad_long: [64]u8 = @splat(0x77);

test "STACKPROBE: the short AEAD's 1 KiB burn covers its largest inputs, and every secret the engine holds" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("chachapoly short probe key", &key, .{});
    // Secrets the key-only needle misses: the short core's duplicated key
    // halves (rows b and c hold each half twice), block 0 (the Poly1305 key)
    // and the first data keystream block (it XORs a known plaintext to the
    // ciphertext, so it is as good as the plaintext).
    var b0: [32]u8 = undefined;
    var c0: [32]u8 = undefined;
    b0[0..16].* = key[0..16].*;
    b0[16..].* = key[0..16].*;
    c0[0..16].* = key[16..].*;
    c0[16..].* = key[16..].*;
    var blocks: [128]u8 = @splat(0);
    std.crypto.stream.chacha.ChaCha20IETF.xor(&blocks, &blocks, 0, key, nonce);
    const secrets = &[_][]const u8{ &key, &b0, &c0, blocks[0..32], blocks[64..96] };
    const verbose = std.testing.environ.getPosix("CHACHAPOLY_PROBE_VERBOSE") != null;

    // The largest short inputs (total 192 exactly, both ways), a P = 1 one,
    // a mid one and the first wide one.
    inline for (.{ .{ 171, 21 }, .{ 192, 0 }, .{ 64, 0 }, .{ 65, 0 }, .{ 193, 0 }, .{ 100, 16 } }) |c| {
        const n = c[0];
        const adv: []const u8 = ad_long[0..c[1]];
        const short = n + c[1] <= 192;
        const l = std.fmt.comptimePrint("{d}+{d}", .{ n, c[1] });
        const seal = try P.run("short AEAD seal " ++ l, A.encryptInto, .{ ct[0..n], &tag, msg[0..n], adv, nonce, &key }, secrets, .{});
        const open = try P.run("short AEAD open " ++ l, A.decryptInto, .{ pt[0..n], ct[0..n], tag, adv, nonce, &key }, secrets, .{});
        try std.testing.expectEqualSlices(u8, msg[0..n], pt[0..n]);
        // With the burn on, the dirtied depth is the burn's own end (margin 0
        // by construction), so the body is measured again WITHOUT the burn:
        // that depth is what the burn must cover.
        root.skip_aead_burn = true;
        defer root.skip_aead_burn = false;
        const raw_seal = try P.run("raw seal " ++ l, A.encryptInto, .{ ct[0..n], &tag, msg[0..n], adv, nonce, &key }, &.{}, .{ .burn = false, .residue = false });
        const raw_open = try P.run("raw open " ++ l, A.decryptInto, .{ pt[0..n], ct[0..n], tag, adv, nonce, &key }, &.{}, .{ .burn = false, .residue = false });
        root.skip_aead_burn = false;
        inline for (.{ .{ seal, raw_seal }, .{ open, raw_open } }, 0..) |pair, i| {
            const r = pair[0];
            const raw = pair[1];
            // The burn is the size we ship, ends no shallower than the deepest
            // byte the unburned body wrote, and `burn_top` is the entry
            // frame's depth (a burn that did not start there would leave the
            // frames above it unzeroed, which the residue rule cannot see).
            try std.testing.expect(r.burn_len >= (if (short) 1024 else 4096));
            try std.testing.expect(raw.dirty_depth <= r.burn_top + r.burn_len);
            try std.testing.expect(r.burn_top < 512);
            if (verbose) std.debug.print("CHACHAPOLY_PROBE {s} {d}+{d} {s}: body {d} burn_top {d} burn_len {d} margin {d}\n", .{ if (short) "short" else "wide", n, c[1], if (i == 0) "seal" else "open", raw.dirty_depth, r.burn_top, r.burn_len, r.burn_top + r.burn_len - raw.dirty_depth });
        }
    }
}
