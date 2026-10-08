// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the key-handling entry points (review
//! 2026-10-08), kept in the module per `CONVENTIONS.md` §9. Same method as
//! `bip340`'s `stackprobe_test.zig`: paint a large stack window, call one entry
//! point at that depth, then claim an equally large UNINITIALISED buffer at the
//! same depth and count 32-byte needles in it. ReleaseFast/ReleaseSmall only —
//! Debug and ReleaseSafe fill `undefined` with 0xaa, so the scan cannot see a
//! dead frame there (the push lane runs it in ReleaseFast: `test.sh`'s
//! `run_rf_only`).
//!
//! The needles are every secret the module derives, in the representations
//! its steps hold them in: big-endian bytes, the little-endian `u256` image
//! (`k256`'s scalar decode), the `Scalar` in-memory image, and the SHA-512
//! word image (the bytes of eight big-endian words loaded into native `u64`s,
//! as HMAC-SHA512's message schedule and state hold them). The hardened
//! derivation input `0x00 || privkey` is a needle of its own in word image: 31
//! of the key's 32 bytes, at the offset HMAC reads them.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const bip32 = @import("bip32.zig");
const bip39 = @import("bip39.zig");
const k256 = @import("k256");
const Scalar = k256.Secp256k1.scalar.Scalar;

const WINDOW = 256 * 1024;

const Needle = struct { name: []const u8, bytes: [32]u8 };
const max_needles = 40;

const Needles = struct {
    items: [max_needles]Needle = undefined,
    len: usize = 0,

    fn add(self: *Needles, name: []const u8, bytes: [32]u8) void {
        self.items[self.len] = .{ .name = name, .bytes = bytes };
        self.len += 1;
    }

    /// A private scalar in every representation `k256` and HMAC hold it in.
    fn addKey(self: *Needles, comptime name: []const u8, be: [32]u8) void {
        self.add(name ++ ", big-endian", be);
        self.add(name ++ ", little-endian", le(be));
        self.add(name ++ ", Scalar in-memory", std.mem.asBytes(&(Scalar.fromBytes(be, .big) catch unreachable)).*);
        self.add(name ++ ", SHA-512 word image", wordImage(be));
    }

    fn slice(self: *const Needles) []const Needle {
        return self.items[0..self.len];
    }
};

fn le(be: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, std.mem.readInt(u256, &be, .big), .little);
    return out;
}

/// Four big-endian 64-bit words as a little-endian machine stores them.
fn wordImage(be: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    for (0..4) |w| std.mem.writeInt(u64, out[w * 8 ..][0..8], std.mem.readInt(u64, be[w * 8 ..][0..8], .big), .native);
    return out;
}

noinline fn paint() void {
    var buf: [WINDOW]u8 = undefined;
    @memset(&buf, 0xC7);
    std.mem.doNotOptimizeAway(&buf);
}

noinline fn scan(needles: []const Needle, hits: []usize) void {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    var i: usize = 0;
    while (i + 32 <= WINDOW) : (i += 1) {
        for (needles, hits) |*nd, *h| {
            var j: usize = 0;
            while (j < 32 and p[i + j] == nd.bytes[j]) : (j += 1) {}
            if (j == 32) h.* += 1;
        }
    }
    std.mem.doNotOptimizeAway(&buf);
}

/// How deep the previous call dirtied the stack below the scan frame's top.
/// Printed, not asserted.
noinline fn dirtyDepth() usize {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    var i: usize = 0;
    while (i < WINDOW and p[i] == 0xC7) : (i += 1) {}
    std.mem.doNotOptimizeAway(&buf);
    return WINDOW - i;
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    var out: [64]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(&out, "public data", "public key");
    std.mem.doNotOptimizeAway(&out);
}

/// Positive control: parks a secret in a stack local and returns.
var leaky_secret: [32]u8 = undefined;
noinline fn callLeaky() void {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..132].* = leaky_secret;
    std.mem.doNotOptimizeAway(&local);
}

// ── the probed calls ─────────────────────────────────────────────────────
//
// Every wrapper wipes the secret result it was handed, the way a caller is
// told to (`ExtendedPrivKey.deinit`), so a hit is a copy the module left, not
// the probe's own.

const probe_seed: [32]u8 = blk: {
    var s: [32]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = @intCast(0x40 + i);
    break :blk s;
};
const probe_entropy: [32]u8 = blk: {
    var s: [32]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = @intCast(0x91 ^ (i * 7));
    break :blk s;
};
const probe_path = [_]u32{ bip32.hardened_offset + 44, bip32.hardened_offset + 0, 7 };

var master: bip32.ExtendedPrivKey = undefined;
var xprv_buf: [bip32.max_serialized_len]u8 = undefined;
var xprv: []const u8 = undefined;
var mnemonic_buf: [bip39.max_mnemonic_len]u8 = undefined;
var mnemonic: []const u8 = undefined;

/// Where the wrappers put a secret result: a global, not a local, so the
/// wrapper's own frame (inside the scanned window) never holds the copy a
/// caller is responsible for.
var sink_key: bip32.ExtendedPrivKey = undefined;
var sink_parsed: bip32.ParsedKey = undefined;

noinline fn callMasterFromSeed() void {
    bip32.masterFromSeed(&probe_seed, &sink_key) catch unreachable;
    sink_key.deinit();
}

noinline fn callCkdPrivHardened() void {
    bip32.ckdPriv(&master, bip32.hardened_offset + 1, &sink_key) catch unreachable;
    sink_key.deinit();
}

noinline fn callCkdPrivNormal() void {
    bip32.ckdPriv(&master, 1, &sink_key) catch unreachable;
    sink_key.deinit();
}

noinline fn callDerivePath() void {
    bip32.derivePath(&master, &probe_path, &sink_key) catch unreachable;
    sink_key.deinit();
}

noinline fn callNeuter() void {
    var k = bip32.neuter(&master) catch unreachable;
    k.deinit();
}

noinline fn callSerializePriv() void {
    var out: [bip32.max_serialized_len]u8 = undefined;
    const s = bip32.serializePriv(&master, .mainnet, &out) catch unreachable;
    std.mem.doNotOptimizeAway(s.len);
    std.crypto.secureZero(u8, &out);
}

noinline fn callParseExtended() void {
    bip32.parseExtended(xprv, .mainnet, &sink_parsed) catch unreachable;
    sink_parsed.private.deinit();
}

noinline fn callMnemonicToEntropy() void {
    var out: [bip39.max_entropy_bytes]u8 = undefined;
    _ = bip39.mnemonicToEntropy(mnemonic, &out) catch unreachable;
    std.crypto.secureZero(u8, &out);
}

noinline fn callValidateMnemonic() void {
    bip39.validateMnemonic(mnemonic) catch unreachable;
}

noinline fn callEntropyToMnemonic() void {
    var out: [bip39.max_mnemonic_len]u8 = undefined;
    const s = bip39.entropyToMnemonic(&probe_entropy, &out) catch unreachable;
    std.mem.doNotOptimizeAway(s.len);
    std.crypto.secureZero(u8, &out);
}

noinline fn callMnemonicToSeed() void {
    var out: [64]u8 = undefined;
    bip39.mnemonicToSeed(mnemonic, "probe passphrase", &out) catch unreachable;
    std.crypto.secureZero(u8, &out);
}

const probes = [_]struct { name: []const u8, call: *const fn () void }{
    .{ .name = "masterFromSeed", .call = callMasterFromSeed },
    .{ .name = "ckdPriv hardened", .call = callCkdPrivHardened },
    .{ .name = "ckdPriv normal", .call = callCkdPrivNormal },
    .{ .name = "derivePath", .call = callDerivePath },
    .{ .name = "neuter", .call = callNeuter },
    .{ .name = "serializePriv", .call = callSerializePriv },
    .{ .name = "parseExtended xprv", .call = callParseExtended },
    .{ .name = "mnemonicToEntropy", .call = callMnemonicToEntropy },
    .{ .name = "validateMnemonic", .call = callValidateMnemonic },
    .{ .name = "entropyToMnemonic", .call = callEntropyToMnemonic },
    .{ .name = "mnemonicToSeed", .call = callMnemonicToSeed },
};

fn buildNeedles(n: *Needles) !void {
    n.add("seed", probe_seed);
    n.add("seed, SHA-512 word image", wordImage(probe_seed));
    n.addKey("master key", master.privkey);
    n.add("master chain code", master.chain_code);
    n.add("master chain code, SHA-512 word image", wordImage(master.chain_code));

    var h: bip32.ExtendedPrivKey = undefined;
    try bip32.ckdPriv(&master, bip32.hardened_offset + 1, &h);
    defer h.deinit();
    n.addKey("hardened child key", h.privkey);
    const il_h = try k256.Secp256k1.scalar.sub(h.privkey, master.privkey, .big);
    n.add("hardened IL, big-endian", il_h);
    n.add("hardened IL, SHA-512 word image", wordImage(il_h));
    var data: [32]u8 = undefined;
    data[0] = 0;
    data[1..32].* = master.privkey[0..31].*;
    n.add("0x00||master key, SHA-512 word image", wordImage(data));

    var c: bip32.ExtendedPrivKey = undefined;
    try bip32.ckdPriv(&master, 1, &c);
    defer c.deinit();
    n.addKey("normal child key", c.privkey);

    var leaf: bip32.ExtendedPrivKey = undefined;
    try bip32.derivePath(&master, &probe_path, &leaf);
    defer leaf.deinit();
    n.addKey("path leaf key", leaf.privkey);

    n.add("entropy", probe_entropy);
    var seed: [64]u8 = undefined;
    try bip39.mnemonicToSeed(mnemonic, "probe passphrase", &seed);
    n.add("bip39 seed[0..32]", seed[0..32].*);
    n.add("bip39 seed[32..64]", seed[32..64].*);
    n.add("bip39 seed[0..32], SHA-512 word image", wordImage(seed[0..32].*));
    n.add("bip39 seed[32..64], SHA-512 word image", wordImage(seed[32..64].*));
    // A 24-word mnemonic is longer than SHA-512's block, so HMAC keys on its
    // hash: that digest is the PBKDF2 password in all but name.
    var mh: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(mnemonic, &mh, .{});
    n.add("SHA-512(mnemonic)[0..32]", mh[0..32].*);
    n.add("SHA-512(mnemonic)[0..32], word image", wordImage(mh[0..32].*));
}

test "STACKPROBE (review 2026-10-08): no key, seed or entropy residue on the dead stack after bip32/bip39 calls" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;

    try bip32.masterFromSeed(&probe_seed, &master);
    defer master.deinit();
    xprv = try bip32.serializePriv(&master, .mainnet, &xprv_buf);
    mnemonic = try bip39.entropyToMnemonic(&probe_entropy, &mnemonic_buf);

    var needles: Needles = .{};
    try buildNeedles(&needles);
    const nd = needles.slice();
    leaky_secret = master.privkey;

    var neg: [max_needles]usize = @splat(0);
    paint();
    callInnocent();
    scan(nd, neg[0..nd.len]);

    var pos: [max_needles]usize = @splat(0);
    paint();
    callLeaky();
    scan(nd, pos[0..nd.len]);

    var hits: [probes.len][max_needles]usize = @splat(@splat(0));
    var depth: [probes.len]usize = undefined;
    for (probes, &hits, &depth) |pr, *h, *d| {
        for (0..3) |_| {
            paint();
            pr.call();
            scan(nd, h[0..nd.len]);
        }
        paint();
        pr.call();
        d.* = dirtyDepth();
    }

    var bad = false;
    for (neg[0..nd.len]) |x| bad = bad or x != 0;
    bad = bad or pos[2] < 1; // "master key, big-endian"
    for (&hits) |*h| for (h[0..nd.len]) |x| {
        bad = bad or x != 0;
    };
    // Printed only on failure: the lane treats stderr from a passing test as
    // a FAIL (scripts/lib/test-lib.sh).
    if (bad) {
        std.debug.print("\n=== STACKPROBE bip32 ({t}, window {d} KiB) NEG={any} POS(master key)={d} ===\n", .{ builtin.mode, WINDOW / 1024, neg[0..nd.len], pos[2] });
        for (probes, &hits, depth) |pr, *h, d| {
            std.debug.print("  {s:<20} dirty below the call={d} B\n", .{ pr.name, d });
            for (nd, h[0..nd.len]) |n, x| {
                if (x != 0) std.debug.print("    RESIDUE {s:<40} {d} (3 calls)\n", .{ n.name, x });
            }
        }
        return error.TestUnexpectedResult;
    }
}
