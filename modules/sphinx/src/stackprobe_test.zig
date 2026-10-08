// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `deriveHopSecrets`, `construct` and `process`
//! (review 2026-10-08), kept in the module per `CONVENTIONS.md` §9. Same
//! method as `bip340`'s `stackprobe_test.zig`: paint a large stack window, run
//! one call at that depth, then claim an equally large UNINITIALISED buffer at
//! the same depth and count 32-byte needles in it. ReleaseFast/ReleaseSmall
//! only — Debug and ReleaseSafe fill `undefined` with 0xaa, so the scan cannot
//! see a dead frame there (the push lane runs it in ReleaseFast: `test.sh`'s
//! `run_rf_only`).
//!
//! Inputs are the BOLT#4 vector (`kat_vectors.zig`). The needles are every
//! secret of the route: the session key, the blinded ephemeral scalars
//! `e_1..e_4` (big- and little-endian), the blinding factors, every hop's
//! shared secret and its `rho`/`mu` keys, the padding key, and the two
//! processing nodes' private keys. Per-hop needles share a name; the
//! failure print adds each needle's index (hop order). Every call writes its result to a global,
//! so a hit is a copy left in a dead frame.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const sphinx = @import("root.zig");
const v = @import("kat_vectors.zig");
const Secp256k1 = @import("k256").Secp256k1;
const Sha256 = std.crypto.hash.sha2.Sha256;

const WINDOW = 256 * 1024;
const hops = v.pubkeys.len;

const Needle = struct { name: []const u8, bytes: [32]u8 };
const max_needles = 48;

const Needles = struct {
    items: [max_needles]Needle = undefined,
    len: usize = 0,

    fn add(self: *Needles, name: []const u8, bytes: [32]u8) void {
        self.items[self.len] = .{ .name = name, .bytes = bytes };
        self.len += 1;
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

fn hex32(s: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
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
    var out: [32]u8 = undefined;
    Sha256.hash("public", &out, .{});
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

// ── the probed calls, on global inputs and outputs ───────────────────────

var session_key: [32]u8 = undefined;
var node_priv: [2][32]u8 = undefined;
var pubkeys: [hops][sphinx.pubkey_len]u8 = undefined;
var payload_store: [hops][300]u8 = undefined;
var payloads: [hops][]const u8 = undefined;
var assoc: [32]u8 = undefined;
var hop_secrets: [hops]sphinx.HopSecret = undefined;
var onion: sphinx.OnionPacket = undefined;
var res0: sphinx.ProcessResult = undefined;
var res1: sphinx.ProcessResult = undefined;

noinline fn callDerive() void {
    sphinx.deriveHopSecrets(&session_key, &pubkeys, &hop_secrets) catch unreachable;
}
noinline fn callConstruct() void {
    onion = sphinx.construct(&session_key, &pubkeys, &payloads, &assoc) catch unreachable;
}
noinline fn callProcess0() void {
    res0 = sphinx.process(&node_priv[0], onion, &assoc) catch unreachable;
}
noinline fn callProcess1() void {
    res1 = sphinx.process(&node_priv[1], res0.next_packet.?, &assoc) catch unreachable;
}

const probes = [_]struct { name: []const u8, call: *const fn () void }{
    .{ .name = "deriveHopSecrets", .call = callDerive },
    .{ .name = "construct", .call = callConstruct },
    .{ .name = "process (hop 0)", .call = callProcess0 },
    .{ .name = "process (hop 1)", .call = callProcess1 },
};

fn buildNeedles(n: *Needles) !void {
    n.add("session key", session_key);
    n.add("node 1 private key", node_priv[1]);
    n.add("node 1 private key, little-endian", le(node_priv[1]));
    n.add("pad key", sphinx.generateKey(.pad, session_key));
    var hs: [hops]sphinx.HopSecret = undefined;
    try sphinx.deriveHopSecrets(&session_key, &pubkeys, &hs);
    var e = session_key;
    for (hs, 0..) |h, i| {
        n.add("shared secret ss_i", h.shared_secret);
        n.add("rho_i", sphinx.generateKey(.rho, h.shared_secret));
        n.add("mu_i", sphinx.generateKey(.mu, h.shared_secret));
        if (i + 1 == hops) break;
        var bf: [32]u8 = undefined;
        var hasher = Sha256.init(.{});
        hasher.update(&h.ephemeral_pubkey);
        hasher.update(&h.shared_secret);
        hasher.final(&bf);
        n.add("blinding factor", bf);
        e = try Secp256k1.scalar.mul(e, bf, .big);
        n.add("ephemeral scalar e_i, big-endian", e);
        n.add("ephemeral scalar e_i, little-endian", le(e));
    }
}

test "STACKPROBE (review 2026-10-08): no key or shared-secret residue on the dead stack after construct/process" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;

    session_key = hex32(v.session_key);
    node_priv = .{ hex32(v.node_privkeys[0]), hex32(v.node_privkeys[1]) };
    // Not the vector's associated data: it is byte-identical to node 1's
    // private key (both 0x42 × 32), which would make every HMAC input a hit.
    assoc = @splat(0x5a);
    for (&pubkeys, v.pubkeys) |*p, s| _ = try std.fmt.hexToBytes(p, s);
    for (&payloads, &payload_store, v.payloads) |*p, *st, s| {
        const raw = try std.fmt.hexToBytes(st, s);
        // Strip the bigsize length prefix: `construct` adds its own.
        const skip: usize = if (raw[0] == 0xfd) 3 else 1;
        p.* = raw[skip..];
    }

    var needles: Needles = .{};
    try buildNeedles(&needles);
    const nd = needles.slice();
    leaky_secret = node_priv[1];

    var neg: [max_needles]usize = @splat(0);
    paint();
    callInnocent();
    scan(nd, neg[0..nd.len]);

    var pos: [max_needles]usize = @splat(0);
    paint();
    callLeaky();
    scan(nd, pos[0..nd.len]);

    var hits: [probes.len][max_needles]usize = @splat(@splat(0));
    var depth: [probes.len]usize = @splat(0);
    for (0..3) |_| {
        for (probes, &hits, &depth) |pr, *h, *d| {
            paint();
            pr.call();
            d.* = @max(d.*, dirtyDepth());
            scan(nd, h[0..nd.len]);
        }
    }

    var bad = false;
    for (neg[0..nd.len]) |x| bad = bad or x != 0;
    bad = bad or pos[1] < 1; // "node 1 private key"
    for (&hits) |*h| for (h[0..nd.len]) |x| {
        bad = bad or x != 0;
    };
    // Printed only on failure: the lane treats stderr from a passing test as
    // a FAIL (scripts/lib/test-lib.sh).
    if (bad) {
        std.debug.print("\n=== STACKPROBE sphinx ({t}, window {d} KiB) NEG={any} POS={d} ===\n", .{ builtin.mode, WINDOW / 1024, neg[0..nd.len], pos[1] });
        for (probes, &hits, depth) |pr, *h, d| {
            std.debug.print("  {s:<20} dirty below the call={d} B\n", .{ pr.name, d });
            for (nd, h[0..nd.len], 0..) |n, x, k| {
                if (x != 0) std.debug.print("    RESIDUE #{d:<2} {s:<36} {d} (3 calls)\n", .{ k, n.name, x });
            }
        }
        return error.TestUnexpectedResult;
    }
}
