// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for every entry point that touches a Paillier
//! secret (the factors, `λ`, `μ`, the CRT block, a plaintext or the
//! encryption randomness), kept in the module per `CONVENTIONS.md` §9.
//!
//! Method as `p256`'s `stackprobe_test.zig` (direct region, 2026-10-08: the
//! earlier "scan a local buffer at the call's depth" form was blind to the top
//! few hundred bytes of the measured call): paint a stack region below the
//! probe, run one call under a `PAD`-deep shim, snapshot the region and look for
//! secrets in the snapshot — every 16-byte window of every secret's in-memory
//! image and big-endian bytes, and of every byte the call drew from its
//! `std.Random`. ReleaseFast/ReleaseSmall only — Debug and ReleaseSafe fill
//! `undefined` with 0xaa.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const paillier = @import("root.zig");
const Fe = paillier.Fe;

const WINDOW = 2 * 1024 * 1024;

/// true: print every call's copies and dirty depth (to size a burn). A
/// passing test must print nothing: the lane counts stderr as a FAIL.
const verbose = false;
/// Set around the positive control, whose one copy is expected.
var quiet = false;

// ── recording RNG ────────────────────────────────────────────────────────

const Draw = struct { at: usize, len: usize, ret: usize };

const Recorder = struct {
    csprng: std.Random.DefaultCsprng,
    log: std.ArrayList(u8) = .empty,
    draws: std.ArrayList(Draw) = .empty,

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        self.csprng.fill(buf);
        self.draws.append(std.heap.page_allocator, .{ .at = self.log.items.len, .len = buf.len, .ret = @returnAddress() }) catch @panic("probe OOM"); // global-alloc-ok: the probe's recorder and needle index must not allocate from the allocator of the call it measures (testing.allocator), and live outside any test block
        self.log.appendSlice(std.heap.page_allocator, buf) catch @panic("probe OOM"); // global-alloc-ok: the probe's recorder and needle index must not allocate from the allocator of the call it measures (testing.allocator), and live outside any test block
    }

    fn random(self: *Recorder) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

var recorder: Recorder = undefined;

// ── stack window ─────────────────────────────────────────────────────────

const PAD = 2048;

var snap: [WINDOW]u8 = undefined;
var region_lo: usize = 0;

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

/// Run `call` `PAD` bytes deeper than the probe, so its frames lie inside the
/// region. `pad` is touched after the call too, so it cannot be a tail call.
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

/// How deep the last call's frames reached below the region's top.
fn dirtyDepth() usize {
    var i: usize = 0;
    while (i < WINDOW and snap[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

/// Zero the callee-saved registers before a measured call: they still hold
/// the TEST's values (needles it just computed) and the call's prologue
/// spills them into its frame, where the scan would credit them to the call.
inline fn scrubCalleeSaved() void {
    if (builtin.cpu.arch == .x86_64) asm volatile (
        \\xorl %%ebx, %%ebx
        \\xorl %%r12d, %%r12d
        \\xorl %%r13d, %%r13d
        \\xorl %%r14d, %%r14d
        \\xorl %%r15d, %%r15d
        ::: .{ .rbx = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true });
}

/// `inline`: as its own frame it would run the call deeper than the region top.
inline fn measure(call: *const fn () void) void {
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
}

// ── needles ──────────────────────────────────────────────────────────────

const Loc = struct { src: u16, off: u32 };

const Needles = struct {
    arena: std.heap.ArenaAllocator,
    names: std.ArrayList([]const u8) = .empty,
    map: std.AutoHashMapUnmanaged(u128, Loc) = .empty,

    fn init() Needles {
        return .{ .arena = .init(std.heap.page_allocator) }; // global-alloc-ok: the probe's recorder and needle index must not allocate from the allocator of the call it measures (testing.allocator), and live outside any test block
    }

    fn deinit(self: *Needles) void {
        self.arena.deinit();
    }

    fn add(self: *Needles, name: []const u8, bytes: []const u8) void {
        const a = self.arena.allocator();
        const src: u16 = @intCast(self.names.items.len);
        self.names.append(a, name) catch @panic("probe OOM");
        if (bytes.len < 16) return;
        for (0..bytes.len - 15) |off| {
            const w = bytes[off..][0..16];
            if (!highEntropy(w)) continue;
            const gop = self.map.getOrPut(a, std.mem.readInt(u128, w, .little)) catch @panic("probe OOM");
            if (!gop.found_existing) gop.value_ptr.* = .{ .src = src, .off = @intCast(off) };
        }
    }

    fn addRaw(self: *Needles, name: []const u8, bytes: []const u8) void {
        self.add(name, self.arena.allocator().dupe(u8, bytes) catch @panic("probe OOM"));
    }

    /// Drops every needle window that also occurs in `public` — bytes the
    /// call publishes. Fiat-Shamir responses like Πfac's `z1 = e·p + α`
    /// carry the top bytes of a mask wider than `e·p` verbatim, by design.
    fn dropPublic(self: *Needles, public: []const u8) void {
        if (public.len < 16) return;
        for (0..public.len - 15) |off| _ = self.map.remove(std.mem.readInt(u128, public[off..][0..16], .little));
    }

    fn addRng(self: *Needles) void {
        self.add("RNG stream", recorder.log.items);
    }
};

fn highEntropy(w: *const [16]u8) bool {
    var seen: [256]bool = @splat(false);
    var distinct: usize = 0;
    for (w) |b| {
        if (!seen[b]) distinct += 1;
        seen[b] = true;
    }
    return distinct >= 10;
}

const Report = struct {
    /// Stack offsets where a needle window starts, counted once per run of
    /// consecutive matches (one copy of a 32-byte secret = 17 windows).
    copies: usize = 0,
    depth: usize = 0,
};

fn analyse(label: []const u8, needles: *const Needles) Report {
    var rep: Report = .{ .depth = dirtyDepth() };
    var prev: ?Loc = null;
    var i: usize = 0;
    while (i + 16 <= WINDOW) : (i += 1) {
        const key = std.mem.readInt(u128, snap[i..][0..16], .little);
        const hit = needles.map.get(key);
        defer prev = hit;
        const h = hit orelse continue;
        if (prev) |p| if (p.src == h.src and p.off + 1 == h.off) continue;
        rep.copies += 1;
        const name = needles.names.items[h.src];
        if (quiet) continue;
        std.debug.print("  RESIDUE [{s}] depth {d}: {s} @{d}", .{ label, WINDOW - i, name, h.off });
        if (std.mem.startsWith(u8, name, "RNG stream")) {
            const at = h.off + rng_base;
            for (recorder.draws.items, 0..) |d, n| {
                if (at >= d.at and at < d.at + d.len) {
                    std.debug.print(" (draw #{d}, {d} B at +{d}, ret anchor{s}0x{x})", .{ n, d.len, at - d.at, if (d.ret >= @intFromPtr(&anchor)) "+" else "-", if (d.ret >= @intFromPtr(&anchor)) d.ret - @intFromPtr(&anchor) else @intFromPtr(&anchor) - d.ret });
                    break;
                }
            }
        }
        std.debug.print("\n", .{});
    }
    if (verbose or (rep.copies != 0 and !quiet)) std.debug.print("  [{s}] copies={d} dirty={d} B\n", .{ label, rep.copies, rep.depth });
    return rep;
}

/// Where in `recorder.log` the current "RNG stream" needle source starts.
var rng_base: usize = 0;

/// Symbol the `ret` offsets above are relative to (for `addr2line`).
noinline fn anchor() void {
    std.mem.doNotOptimizeAway(@as(u8, 0));
}

// ── controls ─────────────────────────────────────────────────────────────

const innocent_in: [32]u8 = @splat(0x11);
var leak_src: [32]u8 = undefined;

noinline fn callInnocent() void {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&innocent_in, &out, .{});
    std.mem.doNotOptimizeAway(&out);
}

noinline fn callLeaky() void {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..132].* = leak_src;
    std.mem.doNotOptimizeAway(&local);
}

// ── the probed calls ─────────────────────────────────────────────────────

const Io = struct {
    kp: paillier.KeyPair = undefined,
    gen: paillier.KeyPair = undefined,
    sk_back: paillier.SecretKey = undefined,
    lambda_be: [paillier.modulus_sq_bytes]u8 = undefined,
    mu_be: [paillier.modulus_bytes]u8 = undefined,
    n_be: [paillier.modulus_bytes]u8 = undefined,
    m: Fe = undefined,
    r: Fe = undefined,
    k: Fe = undefined,
    c: paillier.Ciphertext = undefined,
    c2: paillier.Ciphertext = undefined,
    plain: Fe = undefined,
};
var io: Io = .{};

noinline fn callGenerate() void {
    paillier.generate(recorder.random(), paillier.modulus_bits, &io.gen) catch @panic("generate");
}
noinline fn callSecretFromBytes() void {
    paillier.SecretKey.fromBytes(&io.n_be, &io.lambda_be, &io.mu_be, &io.sk_back) catch @panic("SecretKey.fromBytes");
}
noinline fn callLambdaToBytes() void {
    io.kp.secret.lambdaToBytes(&io.lambda_be) catch @panic("lambdaToBytes");
}
noinline fn callMuToBytes() void {
    io.kp.secret.muToBytes(&io.mu_be) catch @panic("muToBytes");
}
noinline fn callEncrypt() void {
    io.c = paillier.encrypt(io.kp.public, &io.m, &io.r) catch @panic("encrypt");
}
noinline fn callEncryptRandom() void {
    io.c2 = paillier.encryptRandom(io.kp.public, &io.m, recorder.random()) catch @panic("encryptRandom");
}
noinline fn callDecrypt() void {
    paillier.decrypt(&io.kp.secret, io.c, &io.plain) catch @panic("decrypt");
}
noinline fn callDecryptNoCrt() void {
    paillier.decrypt(&io.sk_back, io.c, &io.plain) catch @panic("decrypt (no CRT)");
}
noinline fn callAddPlaintext() void {
    io.c2 = paillier.addPlaintext(io.kp.public, io.c, &io.m) catch @panic("addPlaintext");
}
noinline fn callMulPlaintext() void {
    io.c2 = paillier.mulPlaintext(io.kp.public, io.c, &io.k) catch @panic("mulPlaintext");
}

fn addSecretKey(n: *Needles, sk: *const paillier.SecretKey) void {
    n.addRaw("lambda", std.mem.asBytes(&sk.lambda));
    n.addRaw("mu", std.mem.asBytes(&sk.mu));
    if (sk.crt) |*crt| n.addRaw("crt (p,q-derived)", std.mem.asBytes(crt));
}

fn probeCall(label: []const u8, comptime call: fn () void, comptime fill: fn (*Needles) void) usize {
    const start = recorder.log.items.len;
    region_lo = stackHere() - PAD - WINDOW;
    measure(call);
    var n = Needles.init();
    defer n.deinit();
    fill(&n);
    n.add("RNG stream (this call)", recorder.log.items[start..]);
    rng_base = start;
    defer rng_base = 0;
    return analyse(label, &n).copies;
}

test "STACKPROBE: no Paillier secret on the dead stack after any entry point" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    recorder = .{ .csprng = .init(@splat(0x2f)) };
    defer {
        recorder.log.deinit(std.heap.page_allocator);
        recorder.draws.deinit(std.heap.page_allocator);
    }
    // A 2048-bit key, plaintext, randomness and multiplier (high-entropy).
    io = .{};
    var prng = std.Random.DefaultCsprng.init(@splat(0x45));
    try paillier.generate(prng.random(), paillier.modulus_bits, &io.gen);
    io.kp = io.gen;
    var buf: [paillier.modulus_bytes - 1]u8 = undefined;
    prng.random().bytes(&buf);
    io.m = try Fe.fromBytes(io.kp.public.n_sq, &buf, .big);
    prng.random().bytes(&buf);
    io.r = try Fe.fromBytes(io.kp.public.n_sq, &buf, .big);
    prng.random().bytes(&buf);
    io.k = try Fe.fromBytes(io.kp.public.n_sq, &buf, .big);
    try io.kp.public.nToBytes(&io.n_be);

    const F = struct {
        fn key(n: *Needles) void {
            addSecretKey(n, &io.kp.secret);
            n.addRaw("lambda BE", &io.lambda_be);
            n.addRaw("mu BE", &io.mu_be);
        }
        fn gen(n: *Needles) void {
            addSecretKey(n, &io.gen.secret);
        }
        fn plain(n: *Needles) void {
            key(n);
            n.addRaw("m", std.mem.asBytes(&io.m));
            n.addRaw("r", std.mem.asBytes(&io.r));
            n.addRaw("k", std.mem.asBytes(&io.k));
            n.addRaw("decrypted", std.mem.asBytes(&io.plain));
        }
        fn back(n: *Needles) void {
            plain(n);
            addSecretKey(n, &io.sk_back);
        }
    };

    // Controls.
    {
        var n = Needles.init();
        defer n.deinit();
        F.key(&n);
        region_lo = stackHere() - PAD - WINDOW;
        measure(callInnocent);
        try std.testing.expectEqual(@as(usize, 0), analyse("NEG control", &n).copies);
        leak_src = std.mem.asBytes(&io.kp.secret.lambda)[0..32].*;
        measure(callLeaky);
        quiet = true;
        defer quiet = false;
        try std.testing.expect(analyse("POS control", &n).copies >= 1);
    }

    var total: usize = 0;
    total += probeCall("generate", callGenerate, F.gen);
    total += probeCall("lambdaToBytes", callLambdaToBytes, F.key);
    total += probeCall("muToBytes", callMuToBytes, F.key);
    total += probeCall("SecretKey.fromBytes", callSecretFromBytes, F.back);
    total += probeCall("encrypt", callEncrypt, F.plain);
    total += probeCall("encryptRandom", callEncryptRandom, F.plain);
    total += probeCall("decrypt (CRT)", callDecrypt, F.plain);
    total += probeCall("decrypt (no CRT)", callDecryptNoCrt, F.back);
    total += probeCall("addPlaintext", callAddPlaintext, F.plain);
    total += probeCall("mulPlaintext", callMulPlaintext, F.plain);
    // `fromPrimes` is `generate`'s last step (`fromPrimesImpl`), measured
    // there: the module has no 1024-bit prime fixture to call it with.
    if (verbose or total != 0) std.debug.print("TOTAL residue copies: {d}\n", .{total});
    try std.testing.expectEqual(@as(usize, 0), total);
}
