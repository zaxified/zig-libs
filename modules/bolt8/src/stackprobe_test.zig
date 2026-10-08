// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the handshake and transport (review
//! 2026-10-08; SPEC § Backlog "Dead-stack copies"), kept in the module per
//! `CONVENTIONS.md` §9. Method (2026-10-08): the direct-region engine of
//! `p256`'s `stackprobe_test.zig` (painted region below the probe, step run
//! under a `PAD`-deep shim, snapshot scanned for 32-byte needles) — the earlier
//! "scan a local buffer" form was blind to the top few hundred bytes
//! of the measured call. ReleaseFast/ReleaseSmall only — Debug and ReleaseSafe
//! fill `undefined` with 0xaa (the push lane runs it in ReleaseFast:
//! `test.sh`'s `run_rf_only`).
//!
//! Every step works on GLOBAL state, so what an `Initiator`/`Responder`/
//! `Transport` legitimately holds is never in the scanned window; a hit is a
//! copy left in a dead frame. The needles are every secret of one handshake:
//! both static and both ephemeral private keys (big- and little-endian), the
//! three DH outputs `es`/`ee`/`se` and the x-coordinates of the shared points
//! they hash, the chaining key and cipher key after each act, and the
//! transport keys `sk`/`rk`. A seeded generator makes the ephemerals the same
//! in the dry run that collects the needles and in every probed run.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const bolt8 = @import("root.zig");
const kv = @import("kat_vectors.zig");
const Secp256k1 = @import("k256").Secp256k1;

const dh = bolt8.dh;
const transport = bolt8.transport;

const WINDOW = 256 * 1024;

const Needle = struct { name: []const u8, bytes: [32]u8 };
const max_needles = 32;

const Needles = struct {
    items: [max_needles]Needle = undefined,
    len: usize = 0,

    fn add(self: *Needles, name: []const u8, bytes: [32]u8) void {
        self.items[self.len] = .{ .name = name, .bytes = bytes };
        self.len += 1;
    }

    fn addKey(self: *Needles, comptime name: []const u8, be: [32]u8) void {
        self.add(name ++ ", big-endian", be);
        self.add(name ++ ", little-endian", le(be));
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

// ── the measured region (2026-10-08) ────────────────────────────────────────
//
// Direct-region engine, as `p256`'s probe: the region lies `PAD` bytes below
// the probe's own stack position and the measured call runs as `shim(call)`
// under a `PAD`-deep frame. The earlier "scan a local buffer" form
// was blind to the top few hundred bytes (the scanner's own header and
// locals), i.e. to the callers' and wrappers' frames. Calls are no-argument
// `noinline fn`s: inputs come from module-level `var`s and results go into
// module-level `var`s, so the harness's own locals never hold the secret.
const PAD = 2048;

var region_lo: usize = 0;
var snap: [WINDOW]u8 = undefined;

/// An address inside a frame called from the probe, at the depth
/// `paint`/`shim`/`snapshot` start at.
noinline fn stackHere() usize {
    var x: u8 = 0;
    std.mem.doNotOptimizeAway(&x);
    return @intFromPtr(&x);
}

noinline fn paint() void {
    const p: [*]volatile u8 = @ptrFromInt(region_lo);
    for (0..WINDOW) |i| p[i] = 0xC7;
}

/// Run `call` `PAD` bytes deeper than the probe; `pad` is touched after the
/// call too, so it cannot be a tail call.
noinline fn shim(call: *const fn () void) void {
    var pad: [PAD]u8 = undefined;
    std.mem.doNotOptimizeAway(&pad);
    call();
    std.mem.doNotOptimizeAway(&pad);
}

noinline fn snapshot() void {
    const p: [*]const volatile u8 = @ptrFromInt(region_lo);
    for (&snap, 0..) |*d, i| d.* = p[i];
}

/// Zero the callee-saved registers before a measured call: they still hold the
/// test's own values (needles it just computed) and the call's prologue spills
/// them into its frame, where the scan would credit them to the call.
inline fn scrubCalleeSaved() void {
    if (builtin.cpu.arch == .x86_64) asm volatile (
        \\xorl %%ebx, %%ebx
        \\xorl %%r12d, %%r12d
        \\xorl %%r13d, %%r13d
        \\xorl %%r14d, %%r14d
        \\xorl %%r15d, %%r15d
        ::: .{ .rbx = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true });
}

/// Paint the region, run `call` under `shim`, snapshot the region into `snap`.
/// `inline`: the region top is computed in the caller's own frame, and as a
/// frame of its own it would run the call deeper than that top.
inline fn measure(call: *const fn () void) void {
    region_lo = stackHere() - PAD - WINDOW;
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
}

/// How deep the last call's frames reached below the region's top.
fn dirtyDepth() usize {
    var i: usize = 0;
    while (i < WINDOW and snap[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

/// Bytes below the region's top of the shallowest / deepest needle hit seen by
/// `countIn` since the last `resetDepths`.
var hit_min_depth: usize = 0;
var hit_max_depth: usize = 0;

fn resetDepths() void {
    hit_min_depth = 0;
    hit_max_depth = 0;
}

/// Occurrences of the 32-byte `needle` in the last snapshot.
fn countIn(needle: *const [32]u8) usize {
    var hits: usize = 0;
    var i: usize = 0;
    while (i + 32 <= WINDOW) : (i += 1) {
        if (snap[i] == needle[0] and std.mem.eql(u8, snap[i..][0..32], needle)) {
            hits += 1;
            const d = WINDOW - i;
            if (hit_min_depth == 0 or d < hit_min_depth) hit_min_depth = d;
            if (d > hit_max_depth) hit_max_depth = d;
        }
    }
    return hits;
}

/// Add to `hits[i]` the occurrences of `needles[i]` in the last snapshot.
fn countAll(needles: []const Needle, hits: []usize) void {
    for (needles, hits) |*nd, *h| h.* += countIn(&nd.bytes);
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("public", &out, .{});
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

// ── the handshake, one step per probed call, on global state ─────────────

var i_ls: dh.KeyPair = undefined;
var r_ls: dh.KeyPair = undefined;
var ini: bolt8.Initiator = undefined;
var rsp: bolt8.Responder = undefined;
var prng_i: std.Random.DefaultPrng = undefined;
var prng_r: std.Random.DefaultPrng = undefined;
var m1: bolt8.act.Act1 = undefined;
var m2: bolt8.act.Act2 = undefined;
var m3: bolt8.act.Act3 = undefined;
var res_i: bolt8.HandshakeResult = undefined;
var res_r: bolt8.HandshakeResult = undefined;
var t_i: bolt8.Transport = undefined;
var t_r: bolt8.Transport = undefined;
const plaintext = "bolt8 dead-stack probe message";
var wire: [transport.length_frame_len + plaintext.len + 16]u8 = undefined;
var got: [plaintext.len]u8 = undefined;

/// Fresh handshake objects for one run. Built here, outside the probed
/// window: assigning a returned struct to an existing location (a global)
/// makes the compiler build it in a temporary of the CALLER's frame first,
/// which is the caller's copy, not the module's. The probed `init` steps
/// below use the idiomatic form instead.
fn reset() void {
    prng_i = .init(0xb018_0001);
    prng_r = .init(0xb018_0002);
    ini = bolt8.Initiator.init(&i_ls, r_ls.public_key);
    rsp = bolt8.Responder.init(&r_ls);
}

/// `var x = init(...); defer x.deinit();` — what a caller is told to write.
noinline fn stepInitiatorInit() void {
    var x = bolt8.Initiator.init(&i_ls, r_ls.public_key);
    defer x.deinit();
    std.mem.doNotOptimizeAway(&x);
}
noinline fn stepResponderInit() void {
    var x = bolt8.Responder.init(&r_ls);
    defer x.deinit();
    std.mem.doNotOptimizeAway(&x);
}
noinline fn stepGenAct1() void {
    m1 = ini.genAct1(.{ .seeded_for_test = prng_i.random() }) catch unreachable;
}
noinline fn stepReadAct1() void {
    rsp.readAct1(m1) catch unreachable;
}
noinline fn stepGenAct2() void {
    m2 = rsp.genAct2(.{ .seeded_for_test = prng_r.random() }) catch unreachable;
}
noinline fn stepReadAct2() void {
    ini.readAct2(m2) catch unreachable;
}
noinline fn stepGenAct3() void {
    m3 = ini.genAct3(&res_i) catch unreachable;
}
noinline fn stepReadAct3() void {
    rsp.readAct3(m3, &res_r) catch unreachable;
}
noinline fn stepTransportInit() void {
    t_i = bolt8.Transport.init(res_i);
    t_r = bolt8.Transport.init(res_r);
}
noinline fn stepSend() void {
    t_i.sendMessage(plaintext, &wire) catch unreachable;
}
noinline fn stepRecv() void {
    const n = t_r.recvLength(wire[0..transport.length_frame_len]) catch unreachable;
    std.debug.assert(n == plaintext.len);
    t_r.recvMessage(wire[transport.length_frame_len..], &got) catch unreachable;
}

const steps = [_]struct { name: []const u8, call: *const fn () void }{
    .{ .name = "Initiator.init", .call = stepInitiatorInit },
    .{ .name = "Responder.init", .call = stepResponderInit },
    .{ .name = "genAct1", .call = stepGenAct1 },
    .{ .name = "readAct1", .call = stepReadAct1 },
    .{ .name = "genAct2", .call = stepGenAct2 },
    .{ .name = "readAct2", .call = stepReadAct2 },
    .{ .name = "genAct3", .call = stepGenAct3 },
    .{ .name = "readAct3", .call = stepReadAct3 },
    .{ .name = "Transport.init", .call = stepTransportInit },
    // Each left the transport key once or twice per message until
    // `chachapoly`'s AEAD got its own stack burn (2026-10-08).
    .{ .name = "sendMessage", .call = stepSend },
    .{ .name = "recvLength+recvMessage", .call = stepRecv },
};

fn sharedX(secret: [32]u8, remote: [33]u8) ![32]u8 {
    const p = try (try Secp256k1.fromSec1(&remote)).mul(secret, .big);
    return p.toCompressedSec1()[1..33].*;
}

/// A dry run of the same handshake, collecting every secret as it appears.
fn buildNeedles(n: *Needles) !void {
    reset();
    n.addKey("initiator static key", i_ls.secret_key);
    n.addKey("responder static key", r_ls.secret_key);

    stepGenAct1();
    const ie = ini.ephemeral.?;
    n.addKey("initiator ephemeral key", ie.secret_key);
    n.add("es", try dh.dh(ie.secret_key, r_ls.public_key));
    n.add("es shared point x", try sharedX(ie.secret_key, r_ls.public_key));
    n.add("ck after act 1", ini.ss.ck);
    n.add("temp_k1", ini.ss.cipher_state.k);

    stepReadAct1();
    stepGenAct2();
    const re = rsp.ephemeral.?;
    n.addKey("responder ephemeral key", re.secret_key);
    n.add("ee", try dh.dh(re.secret_key, ie.public_key));
    n.add("ee shared point x", try sharedX(re.secret_key, ie.public_key));
    n.add("ck after act 2", rsp.ss.ck);
    n.add("temp_k2", rsp.ss.cipher_state.k);

    stepReadAct2();
    stepGenAct3();
    n.add("se", try dh.dh(i_ls.secret_key, re.public_key));
    n.add("se shared point x", try sharedX(i_ls.secret_key, re.public_key));
    n.add("ck after act 3", res_i.ck);
    n.add("temp_k3", ini.ss.cipher_state.k);
    n.add("sk (initiator)", res_i.sk);
    n.add("rk (initiator)", res_i.rk);
}

test "STACKPROBE (review 2026-10-08): no key or DH residue on the dead stack after any handshake or transport step" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;

    i_ls = try dh.KeyPair.generateDeterministic(kv.init_ls_priv.*);
    r_ls = try dh.KeyPair.generateDeterministic(kv.resp_ls_priv.*);

    var needles: Needles = .{};
    try buildNeedles(&needles);
    const nd = needles.slice();
    leaky_secret = r_ls.secret_key;

    var neg: [max_needles]usize = @splat(0);
    measure(callInnocent);
    countAll(nd, neg[0..nd.len]);

    var pos: [max_needles]usize = @splat(0);
    measure(callLeaky);
    countAll(nd, pos[0..nd.len]);

    var hits: [steps.len][max_needles]usize = @splat(@splat(0));
    var depth: [steps.len]usize = @splat(0);
    var shallow: [steps.len]usize = @splat(0);
    var deep: [steps.len]usize = @splat(0);
    for (0..3) |_| {
        reset();
        for (steps, &hits, &depth, &shallow, &deep) |st, *h, *d, *s, *dp| {
            resetDepths();
            measure(st.call);
            d.* = @max(d.*, dirtyDepth());
            countAll(nd, h[0..nd.len]);
            if (hit_min_depth != 0 and (s.* == 0 or hit_min_depth < s.*)) s.* = hit_min_depth;
            dp.* = @max(dp.*, hit_max_depth);
        }
    }

    var bad = false;
    for (neg[0..nd.len]) |x| bad = bad or x != 0;
    bad = bad or pos[2] < 1; // "responder static key, big-endian"
    for (&hits) |*h| for (h[0..nd.len]) |x| {
        bad = bad or x != 0;
    };
    // Printed only on failure: the lane treats stderr from a passing test as
    // a FAIL (scripts/lib/test-lib.sh).
    if (bad) {
        std.debug.print("\n=== STACKPROBE bolt8 ({t}, window {d} KiB) NEG={any} POS={d} ===\n", .{ builtin.mode, WINDOW / 1024, neg[0..nd.len], pos[2] });
        for (steps, &hits, depth, shallow, deep) |st, *h, d, s, dp| {
            std.debug.print("  {s:<24} dirty below the call={d} B, hits {d}..{d} B\n", .{ st.name, d, s, dp });
            for (nd, h[0..nd.len]) |n, x| {
                if (x != 0) std.debug.print("    RESIDUE {s:<34} {d} (3 runs)\n", .{ n.name, x });
            }
        }
        return error.TestUnexpectedResult;
    }
}
