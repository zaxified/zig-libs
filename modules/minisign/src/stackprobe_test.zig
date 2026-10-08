// SPDX-License-Identifier: MIT

//! Dead-stack (and freed-heap) residue probe for the secret-key paths:
//! `KeyPair.generate`, the signers (`signMessage` both algorithms, `signFile`,
//! `signDigest`, `signFileDigest`, `signTrustedComment`), `toRawSecretKeyPlain`,
//! `sealSecretKey` / `openSecretKey` (password -> scrypt -> key stream) and the
//! secret-key file codec (`parseSecretKeyFile`, `writeSecretKeyFile`). Kept in
//! the module per `CONVENTIONS.md` §9.
//!
//! Method as `ssh`'s probe: paint a stack window below the probe, run the call
//! `PAD` bytes deeper, snapshot the window and look for secrets.
//! ReleaseFast / ReleaseSmall only — Debug and ReleaseSafe fill `undefined`
//! with 0xaa, so the scan cannot see a dead frame there.
//!
//! Needles are every 16-byte window of every image a secret is held in: the
//! Ed25519 seed, the clamped and unclamped scalar, the nonce prefix, the
//! `seed ‖ pk` secret-key image, for a signature the nonce
//! `reduce64(SHA-512(prefix ‖ M))` (raw and reduced; `M` is what is actually
//! handed to Ed25519 — the file, its BLAKE2b-512 prehash, a digest, or
//! `signature ‖ trusted comment`), for seal/open the scrypt key stream, the
//! plaintext checksum and the password, and for the file codec the wire image
//! and its base64 text. Windows with fewer than 8 distinct bytes are skipped.
//!
//! scrypt works on the HEAP (three allocator buffers: `xy`, `V`, `dk`). After
//! the seal/open calls the probe also counts the non-zero bytes left in the
//! allocator's backing store (`heap`): a freed-but-unwiped buffer shows up
//! there.
//!
//! scrypt parameters: `ops_limit = 32768, mem_limit = 1 << 16` (what the
//! module's own tests use), so one derivation is milliseconds.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const ms = @import("root.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Ed = std.crypto.ecc.Edwards25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Blake2b256 = std.crypto.hash.blake2.Blake2b256;
const Blake2b512 = std.crypto.hash.blake2.Blake2b512;

const WINDOW = 1024 * 1024; // scrypt + pbkdf2 + Ed25519 frames stay far below
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 16384;

const Needles = struct {
    win: [max_windows]u128 = undefined,
    owner: [max_windows]u8 = undefined,
    len: usize = 0,
    names: [32][]const u8 = undefined,
    n_names: usize = 0,

    fn addImage(self: *Needles, name: []const u8, image: []const u8) void {
        const id: u8 = @intCast(self.lookupName(name));
        var i: usize = 0;
        while (i + W <= image.len) : (i += 1) {
            if (distinct(image[i..][0..W]) < 8) continue;
            self.win[self.len] = std.mem.readInt(u128, image[i..][0..W], .little);
            self.owner[self.len] = id;
            self.len += 1;
        }
    }

    /// `image` as given and byte-reversed.
    fn addBoth(self: *Needles, name: []const u8, image: []const u8) void {
        self.addImage(name, image);
        var r: [512]u8 = undefined;
        @memcpy(r[0..image.len], image);
        std.mem.reverse(u8, r[0..image.len]);
        self.addImage(name, r[0..image.len]);
    }

    fn distinct(w: *const [W]u8) usize {
        var seen: [256]bool = @splat(false);
        var c: usize = 0;
        for (w) |b| {
            if (!seen[b]) c += 1;
            seen[b] = true;
        }
        return c;
    }

    fn lookupName(self: *Needles, name: []const u8) usize {
        for (self.names[0..self.n_names], 0..) |n, i| if (std.mem.eql(u8, n, name)) return i;
        self.names[self.n_names] = name;
        self.n_names += 1;
        return self.n_names - 1;
    }

    fn sort(self: *Needles) void {
        const Ctx = struct {
            n: *Needles,
            pub fn lessThan(c: @This(), a: usize, b: usize) bool {
                return c.n.win[a] < c.n.win[b];
            }
            pub fn swap(c: @This(), a: usize, b: usize) void {
                std.mem.swap(u128, &c.n.win[a], &c.n.win[b]);
                std.mem.swap(u8, &c.n.owner[a], &c.n.owner[b]);
            }
        };
        std.sort.pdqContext(0, self.len, Ctx{ .n = self });
    }

    fn find(self: *const Needles, v: u128) ?u8 {
        var lo: usize = 0;
        var hi: usize = self.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (self.win[mid] < v) lo = mid + 1 else hi = mid;
        }
        return if (lo < self.len and self.win[lo] == v) self.owner[lo] else null;
    }
};

const Hits = [32]usize;

// ── the measured region ─────────────────────────────────────────────────────
//
// The region is addressed directly, below a fixed distance (`PAD`) under the
// probe's own stack position, and the measured call runs under a `PAD`-deep
// frame (`shim`), so its frames start inside the region. `paint` and
// `snapshot` run at the probe's own depth with frames far smaller than `PAD`:
// no instrument frame overlaps the region, so even the call's shallowest
// frames (a wrapper's by-value copies) are seen.
const PAD = 2048;

var region_lo: usize = 0;
var region_hi: usize = 0;
var snap: [WINDOW]u8 = undefined;

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

var hit_min_depth: usize = 0;
var hit_max_depth: usize = 0;

fn scan(needles: *const Needles) Hits {
    var hits: Hits = @splat(0);
    hit_min_depth = 0;
    hit_max_depth = 0;
    var skip_until: usize = 0;
    var i: usize = 0;
    while (i + W <= WINDOW) : (i += 1) {
        if (i < skip_until) continue;
        if (needles.find(std.mem.readInt(u128, snap[i..][0..W], .little))) |id| {
            hits[id] += 1;
            const d = WINDOW - i;
            if (hit_min_depth == 0 or d < hit_min_depth) hit_min_depth = d;
            if (d > hit_max_depth) hit_max_depth = d;
            skip_until = i + W;
        }
    }
    return hits;
}

fn dirtyDepth() usize {
    var i: usize = 0;
    while (i < WINDOW and snap[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    var out: [32]u8 = undefined;
    Sha256.hash("public", &out, .{});
    std.mem.doNotOptimizeAway(&out);
}

/// Positive control: parks a secret in a stack local and returns.
var leak_src: [LEAK]u8 = undefined;
noinline fn callLeaky() void {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..][0..LEAK].* = leak_src;
    std.mem.doNotOptimizeAway(&local);
}

/// Zero the callee-saved registers before a measured call: they still hold
/// the TEST's values — needles it just computed — and the call's prologue
/// spills them into its frame, where the scan credits them to the call.
inline fn scrubCalleeSaved() void {
    if (builtin.cpu.arch == .x86_64) asm volatile (
        \\xorl %%ebx, %%ebx
        \\xorl %%r12d, %%r12d
        \\xorl %%r13d, %%r13d
        \\xorl %%r14d, %%r14d
        \\xorl %%r15d, %%r15d
        ::: .{ .rbx = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true });
}

/// `inline`: as its own frame it ran the call deeper than the region top
/// `runProbe` computed (acme, 2026-10-08).
inline fn measure(call: *const fn () void, n: *const Needles) Hits {
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
    return scan(n);
}

fn runProbe(label: []const u8, call: *const fn () void, n: *const Needles, heap_checked: bool) !usize {
    region_hi = stackHere() - PAD;
    region_lo = region_hi - WINDOW;

    const neg = measure(callInnocent, n);
    const pos = measure(callLeaky, n);

    var total: Hits = @splat(0);
    var shallowest: usize = 0;
    var deepest: usize = 0;
    for (0..5) |_| {
        for (&total, measure(call, n)) |*t, x| t.* += x;
        if (hit_min_depth != 0 and (shallowest == 0 or hit_min_depth < shallowest)) shallowest = hit_min_depth;
        if (hit_max_depth > deepest) deepest = hit_max_depth;
    }
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
    const depth = dirtyDepth();
    const heap = if (heap_checked) heapDirty() else 0;

    var sum: usize = 0;
    for (total) |h| sum += h;
    var neg_sum: usize = 0;
    for (neg) |h| neg_sum += h;
    var pos_sum: usize = 0;
    for (pos) |h| pos_sum += h;
    if (verbose or sum != 0 or heap != 0 or neg_sum != 0 or pos_sum == 0) {
        std.debug.print("\n=== STACKPROBE minisign: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B heap={d} ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth, heap });
        for (n.names[0..n.n_names], 0..) |name, i| {
            if (total[i] != 0) std.debug.print("    RESIDUE {s:<14} {d} (5 calls)\n", .{ name, total[i] });
        }
        if (sum != 0) std.debug.print("    hits {d}..{d} B below the region top\n", .{ shallowest, deepest });
    }
    try std.testing.expectEqual(@as(usize, 0), neg_sum);
    try std.testing.expect(pos_sum >= 1); // the scan can see a parked secret
    return sum + heap;
}

fn skipUnlessOptimized() !void {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
}

// ── the allocator's backing store (scrypt's xy / V / dk live here) ──────────

var heap_buf: [512 * 1024]u8 = @splat(0);
var heap_fba: std.heap.FixedBufferAllocator = undefined;

/// Zero the backing store and start a fresh allocator over it; every call
/// that takes an allocator gets one of these, so what is left afterwards was
/// written by the call and not wiped before `free`.
fn heapReset() void {
    @memset(&heap_buf, 0);
    heap_fba = .init(&heap_buf);
}

/// Non-zero bytes left in the backing store after the last call.
fn heapDirty() usize {
    var c: usize = 0;
    for (heap_buf) |b| {
        if (b != 0) c += 1;
    }
    return c;
}

fn gpa() std.mem.Allocator {
    return heap_fba.allocator();
}

// ── needles ─────────────────────────────────────────────────────────────────

fn ed25519KeyNeedles(n: *Needles, kp: *const Ed25519.KeyPair) void {
    const seed = kp.secret_key.seed();
    n.addBoth("seed", &seed);
    var az: [64]u8 = undefined;
    Sha512.hash(&seed, &az, .{});
    n.addBoth("a (unclamped)", az[0..32]);
    var a = az[0..32].*;
    Ed.scalar.clamp(&a);
    n.addBoth("a", &a);
    n.addBoth("prefix", az[32..64]);
    // `seed ‖ pk`, the plaintext secret key as minisign stores it: only the
    // windows that overlap the seed count (the pk half alone is public).
    n.addBoth("sk image", kp.secret_key.toBytes()[0..47]);
}

/// std signs without noise: nonce = reduce64(SHA-512(prefix ‖ msg)); `msg` is
/// exactly what was handed to Ed25519. Callable more than once (two messages).
fn ed25519SignNeedles(n: *Needles, kp: *const Ed25519.KeyPair, msg: []const u8, comptime tag: []const u8) void {
    ed25519KeyNeedles(n, kp);
    var az: [64]u8 = undefined;
    Sha512.hash(&kp.secret_key.seed(), &az, .{});
    var h = Sha512.init(.{});
    h.update(az[32..64]);
    h.update(msg);
    var nonce64: [64]u8 = undefined;
    h.final(&nonce64);
    n.addBoth("nonce64 " ++ tag, &nonce64);
    n.addBoth("r " ++ tag, &Ed.scalar.reduce64(nonce64));
}

const test_pw = "correct horse battery staple";
const params_ops: u64 = 32768;
const params_mem: usize = 1 << 16;

/// Key stream + plaintext checksum + password for `seal`/`open`.
fn sealNeedles(n: *Needles, kp: *const ms.KeyPair, salt: *const [ms.salt_length]u8) !void {
    ed25519KeyNeedles(n, &kp.ed25519);
    n.addImage("password", test_pw);
    var stream: [104]u8 = undefined;
    const params = std.crypto.pwhash.scrypt.Params.fromLimits(params_ops, params_mem);
    try std.crypto.pwhash.scrypt.kdf(heap_fba.allocator(), &stream, test_pw, salt, params);
    n.addBoth("stream", &stream);
    var chk: [32]u8 = undefined;
    var h = Blake2b256.init(.{});
    h.update(&ms.sig_alg_legacy);
    h.update(&kp.key_number);
    h.update(&kp.ed25519.secret_key.toBytes());
    h.final(&chk);
    n.addBoth("plain chk", &chk);
}

// ── the probed calls (all `noinline`, secrets read from static memory) ──────

const case_msg = "a release tarball, as far as the signer is concerned";
const case_comment = "timestamp:1760000000\tfile:release.tar.gz";

var cur_seed: [32]u8 = undefined;
var cur_salt: [ms.salt_length]u8 = undefined;
var cur_kp: ms.KeyPair = undefined;
var cur_plain: ms.RawSecretKey = undefined;
var cur_sealed: ms.RawSecretKey = undefined;
var cur_digest: [ms.prehash_length]u8 = undefined;
var cur_sig: ms.RawSignature = undefined;
var cur_text: [512]u8 = undefined;
var cur_text_len: usize = 0;

var kp_sink: ms.KeyPair = undefined;
var raw_sink: ms.RawSecretKey = undefined;
var sig_sink: ms.RawSignature = undefined;
var signed_sink: ms.SignedFile = undefined;
var gsig_sink: [ms.signature_length]u8 = undefined;
var parsed_sink: ms.ParsedSecretKey = undefined;
var wbuf: [512]u8 = undefined;

/// An `Io` whose secure random is the case's seed, so `generate`'s output is
/// known to the probe. Everything else is `std.Io.failing`'s.
var fake_vtable: std.Io.VTable = undefined;

fn fakeRandomSecure(_: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
    @memcpy(buffer, cur_seed[0..buffer.len]);
}

fn fakeRandom(_: ?*anyopaque, buffer: []u8) void {
    for (buffer, 0..) |*b, i| b.* = @intCast(0x40 + i);
}

fn fakeSwapCancelProtection(_: ?*anyopaque, _: std.Io.CancelProtection) std.Io.CancelProtection {
    return .unblocked;
}

fn fakeIo() std.Io {
    fake_vtable = std.Io.failing.vtable.*;
    fake_vtable.randomSecure = fakeRandomSecure;
    fake_vtable.random = fakeRandom;
    fake_vtable.swapCancelProtection = fakeSwapCancelProtection;
    return .{ .userdata = null, .vtable = &fake_vtable };
}

noinline fn callGenerate() void {
    ms.KeyPair.generate(&kp_sink, fakeIo());
    std.mem.doNotOptimizeAway(&kp_sink);
}

noinline fn callSignLegacy() void {
    sig_sink = ms.signMessage(&cur_kp, case_msg, .legacy) catch unreachable;
    std.mem.doNotOptimizeAway(&sig_sink);
}

noinline fn callSignPrehashed() void {
    sig_sink = ms.signMessage(&cur_kp, case_msg, .prehashed) catch unreachable;
    std.mem.doNotOptimizeAway(&sig_sink);
}

noinline fn callSignFile() void {
    heapReset();
    signed_sink = ms.signFile(gpa(), &cur_kp, case_msg, .prehashed, case_comment) catch unreachable;
    std.mem.doNotOptimizeAway(&signed_sink);
}

noinline fn callSignFileDigest() void {
    heapReset();
    signed_sink = ms.signFileDigest(gpa(), &cur_kp, cur_digest, case_comment) catch unreachable;
    std.mem.doNotOptimizeAway(&signed_sink);
}

noinline fn callSignTrustedComment() void {
    heapReset();
    gsig_sink = ms.signTrustedComment(gpa(), &cur_kp, cur_sig, case_comment) catch unreachable;
    std.mem.doNotOptimizeAway(&gsig_sink);
}

noinline fn callToRawPlain() void {
    cur_kp.toRawSecretKeyPlain(&raw_sink);
    std.mem.doNotOptimizeAway(&raw_sink);
}

noinline fn callSeal() void {
    heapReset();
    ms.sealSecretKey(gpa(), &raw_sink, &cur_kp, test_pw, cur_salt, params_ops, params_mem) catch unreachable;
    std.mem.doNotOptimizeAway(&raw_sink);
}

noinline fn callOpenSealed() void {
    heapReset();
    ms.openSecretKey(gpa(), &kp_sink, &cur_sealed, test_pw) catch unreachable;
    std.mem.doNotOptimizeAway(&kp_sink);
}

noinline fn callOpenPlain() void {
    heapReset();
    ms.openSecretKey(gpa(), &kp_sink, &cur_plain, null) catch unreachable;
    std.mem.doNotOptimizeAway(&kp_sink);
}

noinline fn callParse() void {
    ms.parseSecretKeyFile(&parsed_sink, cur_text[0..cur_text_len]) catch unreachable;
    std.mem.doNotOptimizeAway(&parsed_sink);
}

noinline fn callWrite() void {
    var w = std.Io.Writer.fixed(&wbuf);
    ms.writeSecretKeyFile(&w, "probe key", &cur_plain) catch unreachable;
    std.mem.doNotOptimizeAway(&wbuf);
}

/// A high-entropy seed (a repeated byte would be skipped as low-entropy).
fn caseSeed(i: u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(&[_]u8{ 'm', 'i', 'n', 'i', 's', 'i', 'g', 'n', i }, &out, .{});
    return out;
}

test "STACKPROBE: no key, nonce, key-stream or password residue after minisign key and signing paths" {
    try skipUnlessOptimized();
    var bad: usize = 0;

    for (0..2) |ci| {
        cur_seed = caseSeed(@intCast(ci));
        ms.KeyPair.generate(&cur_kp, fakeIo());
        // The fake `Io` must have produced the seed we think it did.
        try std.testing.expectEqualSlices(u8, &cur_seed, &cur_kp.ed25519.secret_key.seed());
        const kp = &cur_kp.ed25519;
        leak_src = cur_seed;
        for (&cur_salt, 0..) |*b, i| b.* = @intCast(0x90 + i);

        // generate: the known seed → every image derived from it.
        {
            var n: Needles = .{};
            ed25519KeyNeedles(&n, kp);
            n.sort();
            bad += try runProbe("KeyPair.generate", callGenerate, &n, false);
        }

        // signMessage, both algorithms.
        {
            var n: Needles = .{};
            ed25519SignNeedles(&n, kp, case_msg, "legacy");
            n.sort();
            bad += try runProbe("signMessage legacy", callSignLegacy, &n, false);
        }
        cur_digest = undefined;
        Blake2b512.hash(case_msg, &cur_digest, .{});
        {
            var n: Needles = .{};
            ed25519SignNeedles(&n, kp, &cur_digest, "prehash");
            n.sort();
            bad += try runProbe("signMessage prehashed", callSignPrehashed, &n, false);
        }

        // signFile prehashed = prehashed signature + trusted-comment signature;
        // signFileDigest = signDigest + signTrustedComment.
        cur_sig = try ms.signMessage(&cur_kp, case_msg, .prehashed);
        var global_msg: [ms.signature_length + case_comment.len]u8 = undefined;
        global_msg[0..ms.signature_length].* = cur_sig.signature;
        @memcpy(global_msg[ms.signature_length..], case_comment);
        {
            var n: Needles = .{};
            ed25519SignNeedles(&n, kp, &cur_digest, "prehash");
            ed25519SignNeedles(&n, kp, &global_msg, "global");
            n.sort();
            bad += try runProbe("signFile prehashed", callSignFile, &n, false);
            bad += try runProbe("signFileDigest", callSignFileDigest, &n, false);
        }
        {
            var n: Needles = .{};
            ed25519SignNeedles(&n, kp, &global_msg, "global");
            n.sort();
            bad += try runProbe("signTrustedComment", callSignTrustedComment, &n, false);
        }

        // Secret-key codecs and sealing.
        cur_kp.toRawSecretKeyPlain(&cur_plain);
        {
            var n: Needles = .{};
            ed25519KeyNeedles(&n, kp);
            n.sort();
            bad += try runProbe("toRawSecretKeyPlain", callToRawPlain, &n, false);
        }
        {
            heapReset();
            var n: Needles = .{};
            try sealNeedles(&n, &cur_kp, &cur_salt);
            n.sort();
            bad += try runProbe("sealSecretKey", callSeal, &n, true);
            heapReset();
            try ms.sealSecretKey(gpa(), &cur_sealed, &cur_kp, test_pw, cur_salt, params_ops, params_mem);
            bad += try runProbe("openSecretKey (sealed)", callOpenSealed, &n, true);
        }
        {
            var n: Needles = .{};
            ed25519KeyNeedles(&n, kp);
            n.sort();
            bad += try runProbe("openSecretKey (plain)", callOpenPlain, &n, true);
        }

        // File codec: a plaintext secret-key file is the key.
        {
            var w = std.Io.Writer.fixed(&cur_text);
            try ms.writeSecretKeyFile(&w, "probe key", &cur_plain);
            cur_text_len = w.end;
            var n: Needles = .{};
            ed25519KeyNeedles(&n, kp);
            // The base64 body of the key file (second line).
            const body = cur_text[0..cur_text_len];
            const nl = std.mem.indexOfScalar(u8, body, '\n').?;
            n.addImage("file b64", std.mem.trimEnd(u8, body[nl + 1 ..], "\n"));
            n.sort();
            bad += try runProbe("parseSecretKeyFile", callParse, &n, false);
            bad += try runProbe("writeSecretKeyFile", callWrite, &n, false);
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
