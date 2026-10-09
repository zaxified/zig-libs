// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the secret paths of the module: the `Group`
//! state machine (`create`, `fromWelcome`, `createCommit` with an Add and with
//! a path update, `processCommit`, `updateLeaf`, `joinByExternalCommit`,
//! `epochAuthenticator`) and the building blocks under it (`crypto`,
//! `keyschedule`, `secrettree`, `framing`, `welcome`, `treekem`). Kept in the
//! module per `CONVENTIONS.md` §9.
//!
//! Engine as `megolm`'s probe (2026-10-09 form). ReleaseFast/ReleaseSmall only
//! — Debug and ReleaseSafe fill `undefined` with 0xaa. Randomness comes from a
//! RECORDING `std.Io` (a copy of `Threaded`'s vtable whose `randomSecure` hands
//! out `SHA-512(label ‖ draw index)` and logs every draw), so the path
//! secrets, leaf keys and HPKE ephemerals minted inside a call are needles.
//! Every operation sets `rec_counter` to a fixed base first, so a pristine run
//! (outside the measured region) and the measured calls draw the same bytes.
//!
//! ⚠ STATE. A `Group` owns heap memory (wiping arenas, the tree), so a
//! by-value copy is NOT a pristine copy: a commit frees the old tree arena
//! and wipes it, and that would reach the original. Instead the state each
//! mutating call needs is rebuilt `POOL` times OUTSIDE the measured region
//! (identical replicas, deterministic randomness); each measured call takes
//! the next replica. `runProbe` calls the adapter six times (five + one for
//! the dirty depth), `POOL` is 8. Groups live on `page_allocator` and are
//! never freed: the probe process is short-lived and leaking keeps freed
//! memory from being reused under the next replica.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a key in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const mls = @import("root.zig");
const Sha512 = std.crypto.hash.sha2.Sha512;
const Aes128 = std.crypto.core.aes.Aes128;
const X25519 = std.crypto.dh.X25519;

const S = mls.suite.default;
const G = mls.group.Group(S);
const Secrets = mls.keyschedule.EpochSecrets(S);
const KN = mls.secrettree.KeyNonce(S);
const crypto = mls.crypto;
const keyschedule = mls.keyschedule;
const secrettree = mls.secrettree;
const framing = mls.framing;
const welcome = mls.welcome;
const treekem = mls.treekem;

// ── engine (as hpke/p256 probes, 2026-10-08 form) ──
const WINDOW = 256 * 1024;
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 8192;

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
            self.win[self.len] = std.mem.readInt(u128, image[i..][0..W], .little);
            self.owner[self.len] = id;
            self.len += 1;
        }
    }

    fn lookupName(self: *Needles, name: []const u8) usize {
        for (self.names[0..self.n_names], 0..) |n, i| if (std.mem.eql(u8, n, name)) return i;
        self.names[self.n_names] = name;
        self.n_names += 1;
        return self.n_names - 1;
    }

    /// The image and its byte reversal (a big-endian value is often held
    /// little-endian, and the reverse).
    fn addBytes(self: *Needles, name: []const u8, b: []const u8) void {
        self.addImage(name, b);
        var r: [256]u8 = undefined;
        @memcpy(r[0..b.len], b);
        std.mem.reverse(u8, r[0..b.len]);
        self.addImage(name, r[0..b.len]);
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
// frames (a wrapper's by-value copies) are seen. The earlier form claimed an
// uninitialised buffer at the call's depth instead, and the claiming frame's
// own header and locals hid the top few hundred bytes (2026-10-08: a stale
// negative-control hit there, and a positive control that went blind when
// the scan function grew a local).
const PAD = 2048;

var region_lo: usize = 0;
var region_hi: usize = 0;
var snap: [WINDOW]u8 = undefined;

/// An address inside a frame called from the probe — below the probe's
/// own frame, at the depth `paint`/`shim`/`snapshot` start at.
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

/// Count needle windows in the last snapshot, one per run of overlapping
/// windows. `hit_min_depth`/`hit_max_depth`: bytes below the region's top.
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

/// How deep the last call's frames reached below the region's top.
fn dirtyDepth() usize {
    var i: usize = 0;
    while (i < WINDOW and snap[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("public", &out, .{});
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
/// spills them into its frame, where the scan credits them to the call
/// (2026-10-08: a negative-control "hit" of `x mod q` between two saved stack
/// pointers in `callInnocent`'s frame, gone when the setup code changed). The
/// compiler saves and restores the probe's own values around the asm.
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
/// `runProbe` computed (2026-10-08).
inline fn measure(call: *const fn () void, n: *const Needles) Hits {
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
    return scan(n);
}

fn runProbe(label: []const u8, call: *const fn () void, n: *const Needles) !usize {
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

    var sum: usize = 0;
    for (total) |h| sum += h;
    var neg_sum: usize = 0;
    for (neg) |h| neg_sum += h;
    // Summed over every needle: images that share a window (a scalar and its
    // zero-extended form) report a hit under whichever name sorts first.
    var pos_sum: usize = 0;
    for (pos) |h| pos_sum += h;
    if (verbose or sum != 0 or neg_sum != 0 or pos_sum == 0) {
        std.debug.print("\n=== STACKPROBE mls: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
        for (n.names[0..n.n_names], 0..) |name, i| {
            if (total[i] != 0) std.debug.print("    RESIDUE {s:<10} {d} (5 calls)\n", .{ name, total[i] });
        }
        if (sum != 0) std.debug.print("    hits {d}..{d} B below the region top\n", .{ shallowest, deepest });
    }
    try std.testing.expectEqual(@as(usize, 0), neg_sum);
    try std.testing.expect(pos_sum >= 1); // the scan can see a parked secret
    return sum;
}

fn skipUnlessOptimized() !void {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
}

/// Audit-local deterministic byte strings: hashes of a label, so no 16-byte
/// window of them is a run of zeros or of paint that a dead stack holds anyway.
fn seedBytes(comptime N: usize, label: []const u8, i: u8) [N]u8 {
    var out: [N]u8 = undefined;
    var h = std.crypto.hash.sha2.Sha512.init(.{});
    h.update(label);
    h.update(&[_]u8{i});
    var d: [64]u8 = undefined;
    h.final(&d);
    var o: usize = 0;
    var ctr: u8 = 0;
    while (o < N) : (ctr += 1) {
        var hh = std.crypto.hash.sha2.Sha512.init(.{});
        hh.update(&d);
        hh.update(&[_]u8{ctr});
        var blk: [64]u8 = undefined;
        hh.final(&blk);
        const k = @min(64, N - o);
        @memcpy(out[o..][0..k], blk[0..k]);
        o += k;
    }
    return out;
}

// ── recording Io ────────────────────────────────────────────────────────────

var threaded: std.Io.Threaded = undefined;
var rec_vtable: std.Io.VTable = undefined;
var rec_label: u8 = 0;
var rec_counter: usize = 0;
var rec_log: [16][64]u8 = undefined;
var rec_len: [16]usize = @splat(0);

fn recSecure(_: ?*anyopaque, buf: []u8) std.Io.RandomSecureError!void {
    var o: usize = 0;
    var blk: usize = 0;
    var h: [64]u8 = undefined;
    while (o < buf.len) : (blk += 1) {
        var s = Sha512.init(.{});
        s.update("mls-probe-draw");
        s.update(&[_]u8{rec_label});
        s.update(std.mem.asBytes(&rec_counter));
        s.update(std.mem.asBytes(&blk));
        s.final(&h);
        const k = @min(64, buf.len - o);
        @memcpy(buf[o..][0..k], h[0..k]);
        o += k;
    }
    if (rec_counter < rec_log.len) {
        @memcpy(rec_log[rec_counter][0..@min(64, buf.len)], buf[0..@min(64, buf.len)]);
        rec_len[rec_counter] = buf.len;
    }
    rec_counter += 1;
}

var rec_io: std.Io = undefined;
fn setUpIo() void {
    threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    const base = threaded.io();
    rec_vtable = base.vtable.*;
    rec_vtable.randomSecure = recSecure;
    rec_io = .{ .userdata = base.userdata, .vtable = &rec_vtable };
}

fn rewind() void {
    rec_counter = 0;
}

// ── world: clients, replicas, pristine results ──────────────────────────────

const gpa = std.heap.page_allocator;
const POOL = 8;
const n_cases = 2;

// Draw-counter bases. The log keeps draws 0..15, so each stage owns a slice.
const base_create = 0;
const base_c1 = 1; // commit 1 (Add bob): draws 1..5
const base_c2 = 6; // commit 2 (path update): draws 6..10
const base_ext = 11; // external join: draws 11..15
const base_lo = 3; // low-level calls that draw

fn die(comptime what: []const u8) noreturn {
    @panic("mls stackprobe: " ++ what ++ " failed");
}

/// One test participant, as `group.zig`'s `TestClient` (a probe cannot reach
/// file-private test helpers), but the key pairs are kept whole.
const Client = struct {
    sig: S.Sig.KeyPair,
    init_kp: S.Kem.KeyPair,
    enc_kp: S.Kem.KeyPair,
    kp_msg: []u8,
    kp: mls.keypackage.KeyPackage,

    fn init(arena: std.mem.Allocator, name: []const u8, seed: u8) !Client {
        const sig = try S.Sig.KeyPair.generateDeterministic(@splat(seed));
        const init_kp = try S.Kem.KeyPair.generateDeterministic(@splat(seed +% 64));
        const enc_kp = try S.Kem.KeyPair.generateDeterministic(@splat(seed +% 128));
        const kp = try mls.keypackage.create(S, arena, .{
            .signature_key_pair = &sig,
            .init_key = init_kp.public_key,
            .encryption_key = enc_kp.public_key,
            .credential = .{ .basic = name },
            .capabilities = .{
                .versions = &.{1},
                .cipher_suites = &.{1},
                .extensions = &.{},
                .proposals = &.{},
                .credentials = &.{1},
            },
            .lifetime = .{ .not_before = 0, .not_after = std.math.maxInt(u64) },
        });
        const msg: framing.MLSMessage = .{ .key_package = kp };
        return .{ .sig = sig, .init_kp = init_kp, .enc_kp = enc_kp, .kp_msg = try msg.encodeAlloc(arena), .kp = kp };
    }

    fn join(self: *const Client, welcome_msg: []const u8, out: *G) !void {
        try G.fromWelcome(gpa, .{
            .welcome_msg = welcome_msg,
            .key_package_msg = self.kp_msg,
            .init_priv = &self.init_kp.secret_key,
            .encryption_priv = &self.enc_kp.secret_key,
        }, out);
    }
};

var cl_arena: std.heap.ArenaAllocator = undefined;
var alice: Client = undefined;
var bob: Client = undefined;
var dave: Client = undefined;
var props1: [1]G.CommitSource = undefined;
var upd_kp: S.Kem.KeyPair = undefined;
var welcome1: []u8 = undefined;
var commit2: []u8 = undefined;
var gi2: []u8 = undefined;

/// Replica pool: `take` hands out the next unused replica of a state.
var pool: [POOL]G = undefined;
var pool_k: usize = 0;
fn take() *G {
    if (pool_k >= POOL) die("pool exhausted");
    const p = &pool[pool_k];
    pool_k += 1;
    return p;
}

// Builders (used for the pristine run and for the replicas).

fn mkA0(out: *G) void {
    rec_counter = base_create;
    G.create(gpa, .{
        .io = rec_io,
        .group_id = "mls-probe-group",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = &alice.enc_kp.secret_key,
    }, out) catch die("create");
}

fn doCommit1(a: *G) void {
    rec_counter = base_c1;
    const c = a.createCommit(gpa, .{
        .io = rec_io,
        .signature_key_pair = &alice.sig,
        .proposals = &props1,
        .include_external_pub = true,
    }) catch die("commit1");
    welcome1 = c.welcome.?;
}

fn doCommit2(a: *G) void {
    rec_counter = base_c2;
    const c = a.createCommit(gpa, .{
        .io = rec_io,
        .signature_key_pair = &alice.sig,
        .include_external_pub = true,
    }) catch die("commit2");
    commit2 = c.commit;
    gi2 = c.group_info;
}

fn mkA1(out: *G) void {
    mkA0(out);
    doCommit1(out);
}

fn fillA0() void {
    for (&pool) |*p| mkA0(p);
    pool_k = 0;
}
fn fillA1() void {
    for (&pool) |*p| mkA1(p);
    pool_k = 0;
}
fn fillB1() void {
    for (&pool) |*p| bob.join(welcome1, p) catch die("bob join");
    pool_k = 0;
}

// Pristine results, collected once per case on throw-away instances.

const Draw = struct { b: [64]u8, l: usize };
const Draws = struct {
    items: [16]Draw = undefined,
    n: usize = 0,
};
/// The draws the last operation made, from slot `lo` up to the current counter.
fn grab(lo: usize) Draws {
    var d: Draws = .{};
    var i = lo;
    while (i < @min(rec_counter, 16)) : (i += 1) {
        d.items[d.n] = .{ .b = rec_log[i], .l = @min(rec_len[i], 64) };
        d.n += 1;
    }
    return d;
}

const PathCopy = struct {
    v: [6][32]u8 = undefined,
    n: usize = 0,
    fn of(g: *const G) PathCopy {
        var p: PathCopy = .{};
        for (g.my_path_secrets.items) |e| {
            if (e.path_secret.len != 32 or p.n == p.v.len) continue;
            p.v[p.n] = e.path_secret[0..32].*;
            p.n += 1;
        }
        return p;
    }
};

var s0: Secrets = undefined; // alice, epoch 0
var s1: Secrets = undefined; // alice, epoch 1
var s2: Secrets = undefined; // alice, epoch 2
var sb1: Secrets = undefined; // bob, epoch 1
var sb2: Secrets = undefined; // bob, epoch 2
var sd: Secrets = undefined; // dave, epoch 3 (external join)
var d_create: Draws = undefined;
var d_c1: Draws = undefined;
var d_c2: Draws = undefined;
var d_ext: Draws = undefined;
var enc0: [32]u8 = undefined; // alice's leaf private key per epoch
var enc1: [32]u8 = undefined;
var enc2: [32]u8 = undefined;
var encb2: [32]u8 = undefined;
var encd: [32]u8 = undefined;
var pa1: PathCopy = undefined;
var pa2: PathCopy = undefined;
var pb1: PathCopy = undefined;
var pb2: PathCopy = undefined;
var ext_kem_out: [32]u8 = undefined;
var ext_init_secret: [S.Nh]u8 = undefined;
var ea_g: G = undefined; // an untouched epoch-1 group for the read-only calls
var gc_bytes: []u8 = undefined;
var ref: [S.Hash.digest_length]u8 = undefined;
var wl: welcome.Welcome = undefined;
var gs_plain: []u8 = undefined;

fn setUp(ci: u8) !void {
    setUpIo();
    rec_label = ci;
    cl_arena = std.heap.ArenaAllocator.init(gpa);
    const aa = cl_arena.allocator();
    alice = try Client.init(aa, "alice", 1 +% ci *% 8);
    bob = try Client.init(aa, "bob", 2 +% ci *% 8);
    dave = try Client.init(aa, "dave", 3 +% ci *% 8);
    props1[0] = .{ .by_value = .{ .add = bob.kp } };
    upd_kp = try S.Kem.KeyPair.generateDeterministic(@splat(0x33 +% ci));

    // epoch 0
    var a0: G = undefined;
    mkA0(&a0);
    s0 = a0.secrets;
    enc0 = a0.my_encryption_priv;
    d_create = grab(base_create);

    // epoch 1: add bob
    var a1: G = undefined;
    mkA0(&a1);
    doCommit1(&a1);
    s1 = a1.secrets;
    enc1 = a1.my_encryption_priv;
    pa1 = PathCopy.of(&a1);
    d_c1 = grab(base_c1);
    mkA1(&ea_g);
    gc_bytes = try ea_g.groupContextAlloc(gpa);

    // bob joins epoch 1
    var b1: G = undefined;
    try bob.join(welcome1, &b1);
    sb1 = b1.secrets;
    pb1 = PathCopy.of(&b1);

    // epoch 2: alice commits a path update, bob follows
    doCommit2(&a1);
    s2 = a1.secrets;
    enc2 = a1.my_encryption_priv;
    pa2 = PathCopy.of(&a1);
    d_c2 = grab(base_c2);
    try b1.processCommit(.{ .commit_msg = commit2 });
    sb2 = b1.secrets;
    encb2 = b1.my_encryption_priv;
    pb2 = PathCopy.of(&b1);

    // dave joins by external commit on epoch 2's GroupInfo
    rec_counter = base_ext;
    var j: G.ExternalJoin = undefined;
    try G.joinByExternalCommit(gpa, gpa, .{
        .io = rec_io,
        .group_info_msg = gi2,
        .key_package_msg = dave.kp_msg,
        .signature_key_pair = &dave.sig,
    }, &j);
    d_ext = grab(base_ext);
    sd = j.group.secrets;
    encd = j.group.my_encryption_priv;
    {
        var r = mls.codec.Reader.init(j.messages.commit);
        const msg = try framing.MLSMessage.decode(aa, &r);
        for (msg.public_message.content.body.commit.proposals) |p| switch (p) {
            .proposal => |pp| switch (pp) {
                .external_init => |k| ext_kem_out = k[0..32].*,
                else => {},
            },
            .reference => {},
        };
        var ext_kp: S.Kem.KeyPair = undefined;
        keyschedule.externalKeyPair(S, &s2.external_secret, &ext_kp);
        try keyschedule.externalInitReceiver(S, ext_kem_out, &ext_kp, &ext_init_secret);
    }

    // the Welcome's pieces for the free-standing welcome calls
    {
        var r = mls.codec.Reader.init(welcome1);
        const msg = try framing.MLSMessage.decode(aa, &r);
        wl = msg.welcome;
        ref = try crypto.make_keypackage_ref(S, try bob.kp.encodeAlloc(aa));
        const slot = wl.findSecret(&ref).?;
        gs_plain = try welcome.decryptGroupSecrets(S, gpa, &bob.init_kp, wl.encrypted_group_info, slot.encrypted_group_secrets);
    }
    rec_counter = 0;
    leak_src = seedBytes(32, "mls-leak-src", ci);
}

// ── needle helpers ──────────────────────────────────────────────────────────

fn hasName(n: *const Needles, name: []const u8) bool {
    for (n.names[0..n.n_names]) |x| if (std.mem.eql(u8, x, name)) return true;
    return false;
}

/// `addBytes` with the capacity checks the engine leaves out (an overflow of
/// `win`/`names` would be an out-of-bounds write in ReleaseFast), and without
/// all-zero values (every dead stack holds those).
fn add(n: *Needles, name: []const u8, b: []const u8) void {
    if (b.len < W) return;
    if (b.len > 256) die("needle too long");
    var nz = false;
    for (b) |x| if (x != 0) {
        nz = true;
        break;
    };
    if (!nz) return;
    if (n.len + 2 * (b.len - W + 1) > max_windows) die("needle set full");
    if (!hasName(n, name) and n.n_names >= n.names.len) die("too many needle names");
    n.addBytes(name, b);
}

fn addImg(n: *Needles, name: []const u8, b: []const u8) void {
    if (n.len + (b.len - W + 1) > max_windows) die("needle set full");
    if (!hasName(n, name) and n.n_names >= n.names.len) die("too many needle names");
    n.addImage(name, b);
}

/// The first half of the HMAC ipad/opad blocks: `key ^ 0x36` / `key ^ 0x5c`.
/// (The second half is a constant and would match any HMAC's pad.)
fn addHmacPads(n: *Needles, key: *const [32]u8) void {
    var ip: [32]u8 = undefined;
    var op: [32]u8 = undefined;
    for (key, 0..) |k, i| {
        ip[i] = k ^ 0x36;
        op[i] = k ^ 0x5c;
    }
    add(n, "hmac pad", &ip);
    add(n, "hmac pad", &op);
}

/// The AES-128 key schedule of an AEAD key.
fn addAes(n: *Needles, key: *const [16]u8) void {
    const c = Aes128.initEnc(key.*);
    addImg(n, "aead sched", std.mem.asBytes(&c));
}

fn addKn(n: *Needles, kn: *const KN) void {
    add(n, "aead key", &kn.key);
    add(n, "aead nonce", &kn.nonce);
    addAes(n, &kn.key);
}

fn addSecretsAs(n: *Needles, name: []const u8, s: *const Secrets) void {
    inline for (@typeInfo(Secrets).@"struct".fields) |f| add(n, name, &@field(s, f.name));
}

fn addSecrets(n: *Needles, s: *const Secrets) void {
    add(n, "joiner_secret", &s.joiner_secret);
    add(n, "welcome_secret", &s.welcome_secret);
    add(n, "epoch_secret", &s.epoch_secret);
    add(n, "sender_data_secret", &s.sender_data_secret);
    add(n, "encryption_secret", &s.encryption_secret);
    add(n, "exporter_secret", &s.exporter_secret);
    add(n, "external_secret", &s.external_secret);
    add(n, "confirmation_key", &s.confirmation_key);
    add(n, "membership_key", &s.membership_key);
    add(n, "resumption_psk", &s.resumption_psk);
    add(n, "epoch_authenticator", &s.epoch_authenticator);
    add(n, "init_secret", &s.init_secret);
}

/// What an epoch's secrets derive further: the external KEM private key, the
/// Welcome key/nonce, `member_secret`.
fn addDerived(n: *Needles, s: *const Secrets) void {
    var ek: S.Kem.KeyPair = undefined;
    keyschedule.externalKeyPair(S, &s.external_secret, &ek);
    add(n, "ext priv", &ek.secret_key);
    var kn: KN = undefined;
    welcome.welcomeKeyNonce(S, &s.welcome_secret, &kn) catch die("welcomeKeyNonce");
    add(n, "welcome key", &kn.key);
    add(n, "welcome nonce", &kn.nonce);
    addAes(n, &kn.key);
    const zero = keyschedule.zeroSecret(S);
    var m: [32]u8 = undefined;
    keyschedule.memberSecret(S, &s.joiner_secret, &zero, &m);
    add(n, "member_secret", &m);
}

/// The RFC 9420 §7.4 chain from a path secret: `path_secret[i+1] =
/// DeriveSecret(path_secret[i], "path")`, `node_secret = DeriveSecret(ps,
/// "node")`, the node key pair `DeriveKeyPair(node_secret)`. Index 1 is the
/// `commit_secret` when the filtered direct path has one node.
fn addPathChain(n: *Needles, ps0: [32]u8) void {
    var ps = ps0;
    const names = [_][]const u8{ "path0", "path1", "path2" };
    for (names, 0..) |nm, i| {
        add(n, nm, &ps);
        if (i < 2) {
            var node: [32]u8 = undefined;
            crypto.DeriveSecret(S, &ps, "node", &node) catch die("DeriveSecret");
            add(n, "node secret", &node);
            var kp: S.Kem.KeyPair = undefined;
            S.Kem.deriveKeyPair(&kp, &node);
            add(n, "node priv", &kp.secret_key);
        }
        var next: [32]u8 = undefined;
        crypto.DeriveSecret(S, &ps, "path", &next) catch die("DeriveSecret");
        ps = next;
    }
}

fn addDraws(n: *Needles, d: *const Draws) void {
    for (d.items[0..d.n]) |x| {
        const b = x.b[0..x.l];
        add(n, "draw", b);
        if (b.len == 32) {
            addPathChain(n, b[0..32].*);
            var kp: S.Kem.KeyPair = undefined;
            S.Kem.deriveKeyPair(&kp, b);
            add(n, "kem priv", &kp.secret_key);
        }
    }
}

fn addPaths(n: *Needles, p: *const PathCopy) void {
    for (p.v[0..p.n]) |ps| addPathChain(n, ps);
}

/// `Extract(init_secret_prev, commit_secret)` for every commit-secret
/// candidate the draws yield (`commit_secret` = the chain element after the
/// root's path secret).
fn addExtract(n: *Needles, prev_init: *const [32]u8, d: *const Draws) void {
    for (d.items[0..d.n]) |x| {
        if (x.l != 32) continue;
        var ps: [32]u8 = x.b[0..32].*;
        for (0..3) |_| {
            var next: [32]u8 = undefined;
            crypto.DeriveSecret(S, &ps, "path", &next) catch die("DeriveSecret");
            ps = next;
            var m: [32]u8 = undefined;
            keyschedule.extractInitCommit(S, prev_init, &ps, &m);
            add(n, "member_secret", &m);
        }
    }
}

fn addSigning(n: *Needles, kp: *const S.Sig.KeyPair) void {
    add(n, "sig key", &kp.secret_key.bytes);
    add(n, "sig seed", kp.secret_key.bytes[0..32]);
}

/// The group-level ending: the two controls.
fn addControl(n: *Needles) void {
    n.addBytes("control", &leak_src);
}

// ── sinks ───────────────────────────────────────────────────────────────────

var g_sink: G = undefined;
var created_sink: G.Created = undefined;
var leaf_sink: mls.tree.LeafNode = undefined;
var ea_sink: [S.Nh]u8 = undefined;
var join_sink: G.ExternalJoin = undefined;
var staged_sink: treekem.Staged(S) = undefined;

// ADAPTER: the only block that depends on the call shapes of the module API.
// Every `callX` makes exactly one public call, secrets by pointer to the
// probe's static variables and results through out-pointers into static sinks.

// Group level.
noinline fn callCreate() void {
    rec_counter = base_create;
    G.create(gpa, .{
        .io = rec_io,
        .group_id = "mls-probe-group",
        .key_package_msg = alice.kp_msg,
        .encryption_priv = &alice.enc_kp.secret_key,
    }, &g_sink) catch die("create");
}
noinline fn callFromWelcome() void {
    G.fromWelcome(gpa, .{
        .welcome_msg = welcome1,
        .key_package_msg = bob.kp_msg,
        .init_priv = &bob.init_kp.secret_key,
        .encryption_priv = &bob.enc_kp.secret_key,
    }, &g_sink) catch die("fromWelcome");
}
noinline fn callCommitAdd() void {
    const a = take();
    rec_counter = base_c1;
    created_sink = a.createCommit(gpa, .{
        .io = rec_io,
        .signature_key_pair = &alice.sig,
        .proposals = &props1,
        .include_external_pub = true,
    }) catch die("createCommit(add)");
}
noinline fn callCommitPath() void {
    const a = take();
    rec_counter = base_c2;
    created_sink = a.createCommit(gpa, .{
        .io = rec_io,
        .signature_key_pair = &alice.sig,
        .include_external_pub = true,
    }) catch die("createCommit(path)");
}
noinline fn callProcessCommit() void {
    take().processCommit(.{ .commit_msg = commit2 }) catch die("processCommit");
}
noinline fn callUpdateLeaf() void {
    leaf_sink = take().updateLeaf(.{
        .signature_key_pair = &alice.sig,
        .encryption_key_pair = &upd_kp,
    }) catch die("updateLeaf");
}
noinline fn callExternalJoin() void {
    rec_counter = base_ext;
    G.joinByExternalCommit(gpa, gpa, .{
        .io = rec_io,
        .group_info_msg = gi2,
        .key_package_msg = dave.kp_msg,
        .signature_key_pair = &dave.sig,
    }, &join_sink) catch die("joinByExternalCommit");
}
noinline fn callEpochAuthenticator() void {
    ea_g.epochAuthenticator(&ea_sink);
}

// Low level: crypto and keyschedule.
var lo_secret: [32]u8 = undefined;
var lo_out32: [32]u8 = undefined;
var lo_out16: [16]u8 = undefined;
var lo_kp: S.Kem.KeyPair = undefined;
var lo_pt: [32]u8 = undefined;
var lo_ct: [32 + S.Aead.tag_length]u8 = undefined;
var lo_enc: S.Kem.EncappedKey = undefined;
var lo_dec: [32]u8 = undefined;
var lo_init_prev: [32]u8 = undefined;
var lo_commit: [32]u8 = undefined;
var lo_zero: [32]u8 = @splat(0);
var lo_epoch: Secrets = undefined;
var lo_ek: S.Kem.KeyPair = undefined;
var ek_sink: S.Kem.KeyPair = undefined;
var lo_psk: [32]u8 = undefined;
var lo_psk_nonce: [32]u8 = undefined;
var lo_psks: [1]keyschedule.PreSharedKey(S) = undefined;
var lo_pskout: [32]u8 = undefined;
var ei_sink: keyschedule.ExternalInit(S) = undefined;
var ei_recv_sink: [32]u8 = undefined;

noinline fn callDeriveSecret() void {
    crypto.DeriveSecret(S, &lo_secret, "welcome", &lo_out32) catch die("DeriveSecret");
}
noinline fn callExpandWithLabel() void {
    crypto.ExpandWithLabel(S, &lo_secret, "key", "probe-context", &lo_out16) catch die("ExpandWithLabel");
}
noinline fn callEncryptWithLabel() void {
    rec_counter = base_lo;
    lo_enc = crypto.EncryptWithLabel(S, lo_kp.public_key, rec_io, "probe label", "probe ctx", &lo_pt, &lo_ct) catch die("EncryptWithLabel");
}
noinline fn callDecryptWithLabel() void {
    crypto.DecryptWithLabel(S, lo_enc, &lo_kp, "probe label", "probe ctx", &lo_ct, &lo_dec) catch die("DecryptWithLabel");
}
noinline fn callDeriveEpoch() void {
    keyschedule.deriveEpoch(S, gpa, &lo_init_prev, &lo_commit, &lo_zero, gc_bytes, &lo_epoch) catch die("deriveEpoch");
}
noinline fn callExternalKeyPair() void {
    keyschedule.externalKeyPair(S, &lo_secret, &ek_sink);
}
noinline fn callMlsExporter() void {
    keyschedule.mlsExporter(S, &lo_secret, "probe exporter label", "probe exporter context", &lo_out32) catch die("mlsExporter");
}
noinline fn callPskSecret() void {
    keyschedule.pskSecret(S, gpa, &lo_psks, &lo_pskout) catch die("pskSecret");
}
noinline fn callExternalInitSender() void {
    rec_counter = base_lo;
    keyschedule.externalInitSender(S, lo_ek.public_key, rec_io, &ei_sink) catch die("externalInitSender");
}
noinline fn callExternalInitReceiver() void {
    keyschedule.externalInitReceiver(S, ext_kem_out, &lo_ek, &ei_recv_sink) catch die("externalInitReceiver");
}

// Low level: secret tree and framing.
var st_enc_secret: [32]u8 = undefined;
var st_base: [32]u8 = undefined;
var st_rt: secrettree.Ratchet(S) = undefined;
var st_win: secrettree.Window(S, 4) = undefined;
var st_kn_sink: KN = undefined;
var st_sdk_sink: secrettree.SenderDataKeys(S) = undefined;
var st_rt_sink: secrettree.Ratchet(S) = undefined;
var st_win_sink: secrettree.Window(S, 4) = undefined;
var st_secret_sink: [32]u8 = undefined;
var sd_secret: [32]u8 = undefined;
var pm_bytes: []u8 = undefined;
var pm: framing.PrivateMessage = undefined;
var pm_kn: KN = undefined;
const pm_guard: [4]u8 = .{ 1, 2, 3, 4 };
var pm_sd_sink: framing.SenderData = undefined;
var pm_pt_sink: []u8 = undefined;
var pm_out_sink: []u8 = undefined;
var fc: framing.FramedContent = undefined;

noinline fn callRatchetBase() void {
    secrettree.ratchetBaseSecret(S, &st_enc_secret, 4, 2, .application, &st_secret_sink) catch die("ratchetBaseSecret");
}
noinline fn callNodeSecret() void {
    secrettree.nodeSecret(S, &st_enc_secret, 4, 4, &st_secret_sink) catch die("nodeSecret");
}
noinline fn callRatchetCurrent() void {
    st_rt.current(&st_kn_sink) catch die("Ratchet.current");
}
noinline fn callRatchetAdvance() void {
    st_rt_sink = st_rt;
    st_rt_sink.advance() catch die("Ratchet.advance");
}
noinline fn callWindowGet() void {
    st_win_sink = st_win;
    st_win_sink.get(2, &st_kn_sink) catch die("Window.get");
}
noinline fn callSenderDataKeys() void {
    secrettree.senderDataKeys(S, &sd_secret, pm.ciphertext, &st_sdk_sink) catch die("senderDataKeys");
}
noinline fn callProtectPrivate() void {
    pm_out_sink = framing.protectPrivate(S, gpa, .{
        .signature_key_pair = &alice.sig,
        .group_context = gc_bytes,
        .content = fc,
        .key_nonce = &pm_kn,
        .generation = 0,
        .reuse_guard = pm_guard,
        .sender_data_secret = &sd_secret,
    }) catch die("protectPrivate");
}
noinline fn callDecryptSenderData() void {
    pm_sd_sink = framing.decryptSenderData(S, gpa, pm, &sd_secret) catch die("decryptSenderData");
}
noinline fn callDecryptContent() void {
    pm_pt_sink = framing.decryptContent(S, gpa, pm, &pm_kn, pm_guard) catch die("decryptContent");
}

// Low level: welcome and treekem.
var gs_sink: []u8 = undefined;
var joined_sink: welcome.Joined(S) = undefined;
var join_params: welcome.JoinParams(S) = undefined;
var stage_leaf: S.Kem.KeyPair = undefined;
var stage_ps0: [32]u8 = undefined;

noinline fn callDecryptGroupSecrets() void {
    const slot = wl.findSecret(&ref).?;
    gs_sink = welcome.decryptGroupSecrets(S, gpa, &bob.init_kp, wl.encrypted_group_info, slot.encrypted_group_secrets) catch die("decryptGroupSecrets");
}
noinline fn callWelcomeJoin() void {
    welcome.join(S, gpa, &join_params, &joined_sink) catch die("welcome.join");
}
noinline fn callStageUpdatePath() void {
    const a = take();
    treekem.stageUpdatePath(S, gpa, &a.ratchet_tree, a.my_leaf_index, .{
        .group_id = "mls-probe-group",
        .signature_key_pair = &alice.sig,
        .leaf_key_pair = &stage_leaf,
        .path_secret_0 = &stage_ps0,
        .signature_key = alice.kp.leaf_node.signature_key,
        .credential = alice.kp.leaf_node.credential,
        .capabilities = alice.kp.leaf_node.capabilities,
        .extensions = alice.kp.leaf_node.extensions,
    }, &staged_sink) catch die("stageUpdatePath");
}
// SKIPPED: treekem.processUpdatePath as a free-standing call. It needs the
// committer's UpdatePath, the post-proposal tree and the provisional
// GroupContext of a real commit; it runs inside `Group.processCommit`, whose
// probe covers its dead frames.
// END ADAPTER

// ── probes ──────────────────────────────────────────────────────────────────

test "STACKPROBE: no secret residue on the dead stack (mls Group)" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setUp(@intCast(ci));
        var n: Needles = .{};

        // Group.create: init_secret_[-1] (draw 0), epoch 0's secrets, the leaf key.
        n = .{};
        addSecrets(&n, &s0);
        addDerived(&n, &s0);
        addDraws(&n, &d_create);
        add(&n, "enc_priv", &enc0);
        {
            const zero = keyschedule.zeroSecret(S);
            var pj: [32]u8 = undefined;
            keyschedule.extractInitCommit(S, d_create.items[0].b[0..32], &zero, &pj);
            add(&n, "member_secret", &pj);
        }
        addControl(&n);
        n.sort();
        bad += try runProbe("Group.create", callCreate, &n);

        // Group.fromWelcome (bob): epoch 1's secrets, bob's keys, path secrets.
        n = .{};
        addSecrets(&n, &sb1);
        addDerived(&n, &sb1);
        addPaths(&n, &pb1);
        add(&n, "init_priv", &bob.init_kp.secret_key);
        add(&n, "enc_priv", &bob.enc_kp.secret_key);
        add(&n, "group secrets", gs_plain[0..@min(gs_plain.len, 64)]);
        addControl(&n);
        n.sort();
        bad += try runProbe("Group.fromWelcome", callFromWelcome, &n);

        // Group.createCommit (Add bob).
        fillA0();
        n = .{};
        addSecretsAs(&n, "old secrets", &s0);
        addSecrets(&n, &s1);
        addDerived(&n, &s1);
        addDraws(&n, &d_c1);
        addExtract(&n, &s0.init_secret, &d_c1);
        addPaths(&n, &pa1);
        addSigning(&n, &alice.sig);
        add(&n, "enc_priv", &enc0);
        add(&n, "enc_priv", &enc1);
        addControl(&n);
        n.sort();
        bad += try runProbe("Group.createCommit(add)", callCommitAdd, &n);

        // Group.createCommit (path update, epoch 1 -> 2).
        fillA1();
        n = .{};
        addSecretsAs(&n, "old secrets", &s1);
        addSecrets(&n, &s2);
        addDerived(&n, &s2);
        addDraws(&n, &d_c2);
        addExtract(&n, &s1.init_secret, &d_c2);
        addPaths(&n, &pa1);
        addPaths(&n, &pa2);
        addSigning(&n, &alice.sig);
        add(&n, "enc_priv", &enc1);
        add(&n, "enc_priv", &enc2);
        addControl(&n);
        n.sort();
        bad += try runProbe("Group.createCommit(path)", callCommitPath, &n);

        // Group.processCommit (bob receives commit 2).
        fillB1();
        n = .{};
        addSecretsAs(&n, "old secrets", &sb1);
        addSecrets(&n, &sb2);
        addDerived(&n, &sb2);
        addDraws(&n, &d_c2); // the committer's draws: path secrets reach the receiver
        addExtract(&n, &sb1.init_secret, &d_c2);
        addPaths(&n, &pb1);
        addPaths(&n, &pb2);
        add(&n, "enc_priv", &bob.enc_kp.secret_key);
        add(&n, "enc_priv", &encb2);
        addControl(&n);
        n.sort();
        bad += try runProbe("Group.processCommit", callProcessCommit, &n);

        // Group.updateLeaf.
        fillA1();
        n = .{};
        addSecrets(&n, &s1);
        addSigning(&n, &alice.sig);
        add(&n, "enc_priv", &upd_kp.secret_key);
        add(&n, "enc_priv", &enc1);
        addControl(&n);
        n.sort();
        bad += try runProbe("Group.updateLeaf", callUpdateLeaf, &n);

        // Group.joinByExternalCommit (dave, on epoch 2's GroupInfo).
        var lo_ek_s2: S.Kem.KeyPair = undefined;
        keyschedule.externalKeyPair(S, &s2.external_secret, &lo_ek_s2);
        n = .{};
        addSecrets(&n, &sd);
        addDerived(&n, &sd);
        addDerived(&n, &s2);
        addDraws(&n, &d_ext);
        addExtract(&n, &ext_init_secret, &d_ext);
        add(&n, "init_secret", &ext_init_secret);
        add(&n, "ext priv", &lo_ek_s2.secret_key);
        addSigning(&n, &dave.sig);
        add(&n, "enc_priv", &dave.enc_kp.secret_key);
        add(&n, "enc_priv", &encd);
        addControl(&n);
        n.sort();
        bad += try runProbe("Group.joinByExternalCommit", callExternalJoin, &n);

        // Group.epochAuthenticator (a plain accessor).
        n = .{};
        addSecrets(&n, &s1);
        addControl(&n);
        n.sort();
        bad += try runProbe("Group.epochAuthenticator", callEpochAuthenticator, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "STACKPROBE: no secret residue on the dead stack (mls building blocks)" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        const c: u8 = @intCast(ci);
        try setUp(c);
        var n: Needles = .{};

        lo_secret = seedBytes(32, "mls-lo-secret", c);
        lo_init_prev = seedBytes(32, "mls-lo-init", c);
        lo_commit = seedBytes(32, "mls-lo-commit", c);
        lo_pt = seedBytes(32, "mls-lo-plaintext", c);
        lo_kp = try S.Kem.KeyPair.generateDeterministic(seedBytes(32, "mls-lo-kem", c));
        keyschedule.externalKeyPair(S, &s2.external_secret, &lo_ek);

        // crypto.DeriveSecret / ExpandWithLabel.
        {
            var out: [32]u8 = undefined;
            try crypto.DeriveSecret(S, &lo_secret, "welcome", &out);
            n = .{};
            add(&n, "secret", &lo_secret);
            addHmacPads(&n, &lo_secret);
            add(&n, "output", &out);
            addControl(&n);
            n.sort();
            bad += try runProbe("crypto.DeriveSecret", callDeriveSecret, &n);

            var o16: [16]u8 = undefined;
            try crypto.ExpandWithLabel(S, &lo_secret, "key", "probe-context", &o16);
            n = .{};
            add(&n, "secret", &lo_secret);
            addHmacPads(&n, &lo_secret);
            add(&n, "output", &o16);
            addControl(&n);
            n.sort();
            bad += try runProbe("crypto.ExpandWithLabel", callExpandWithLabel, &n);
        }

        // crypto.EncryptWithLabel / DecryptWithLabel.
        {
            rec_counter = base_lo;
            lo_enc = try crypto.EncryptWithLabel(S, lo_kp.public_key, rec_io, "probe label", "probe ctx", &lo_pt, &lo_ct);
            const d = grab(base_lo);
            n = .{};
            add(&n, "plaintext", &lo_pt);
            addDraws(&n, &d);
            for (d.items[0..d.n]) |x| {
                if (x.l != 32) continue;
                var ekp: S.Kem.KeyPair = undefined;
                S.Kem.deriveKeyPair(&ekp, x.b[0..32]);
                if (X25519.scalarmult(ekp.secret_key, lo_kp.public_key)) |dh| add(&n, "dh", &dh) else |_| {}
            }
            addControl(&n);
            n.sort();
            bad += try runProbe("crypto.EncryptWithLabel", callEncryptWithLabel, &n);

            n = .{};
            add(&n, "plaintext", &lo_pt);
            add(&n, "recipient priv", &lo_kp.secret_key);
            if (X25519.scalarmult(lo_kp.secret_key, lo_enc)) |dh| add(&n, "dh", &dh) else |_| {}
            addControl(&n);
            n.sort();
            bad += try runProbe("crypto.DecryptWithLabel", callDecryptWithLabel, &n);
        }

        // keyschedule.deriveEpoch / externalKeyPair / mlsExporter.
        {
            var out: Secrets = undefined;
            try keyschedule.deriveEpoch(S, gpa, &lo_init_prev, &lo_commit, &lo_zero, gc_bytes, &out);
            var pre: [32]u8 = undefined;
            keyschedule.extractInitCommit(S, &lo_init_prev, &lo_commit, &pre);
            n = .{};
            add(&n, "init_prev", &lo_init_prev);
            add(&n, "commit_secret", &lo_commit);
            add(&n, "pre_joiner", &pre);
            addHmacPads(&n, &pre);
            addHmacPads(&n, &out.joiner_secret);
            addHmacPads(&n, &out.epoch_secret);
            addSecrets(&n, &out);
            addDerived(&n, &out);
            addControl(&n);
            n.sort();
            bad += try runProbe("keyschedule.deriveEpoch", callDeriveEpoch, &n);

            var ek: S.Kem.KeyPair = undefined;
            keyschedule.externalKeyPair(S, &lo_secret, &ek);
            n = .{};
            add(&n, "external_secret", &lo_secret);
            add(&n, "ext priv", &ek.secret_key);
            addControl(&n);
            n.sort();
            bad += try runProbe("keyschedule.externalKeyPair", callExternalKeyPair, &n);

            var derived: [32]u8 = undefined;
            try crypto.DeriveSecret(S, &lo_secret, "probe exporter label", &derived);
            var o32: [32]u8 = undefined;
            try keyschedule.mlsExporter(S, &lo_secret, "probe exporter label", "probe exporter context", &o32);
            n = .{};
            add(&n, "exporter_secret", &lo_secret);
            addHmacPads(&n, &lo_secret);
            add(&n, "derived", &derived);
            addHmacPads(&n, &derived);
            add(&n, "output", &o32);
            addControl(&n);
            n.sort();
            bad += try runProbe("keyschedule.mlsExporter", callMlsExporter, &n);
        }

        // keyschedule.pskSecret.
        {
            lo_psk = seedBytes(32, "mls-lo-psk", c);
            lo_psk_nonce = seedBytes(32, "mls-lo-psk-nonce", c);
            lo_psks[0] = .{ .id = .{ .id = .{ .external = "probe-psk-id" }, .psk_nonce = &lo_psk_nonce }, .secret = &lo_psk };
            var out: [32]u8 = undefined;
            try keyschedule.pskSecret(S, gpa, &lo_psks, &out);
            const extracted = S.Hkdf.extract(&keyschedule.zeroSecret(S), &lo_psk);
            n = .{};
            add(&n, "psk", &lo_psk);
            add(&n, "psk extracted", &extracted);
            addHmacPads(&n, &extracted);
            add(&n, "psk_secret", &out);
            addControl(&n);
            n.sort();
            bad += try runProbe("keyschedule.pskSecret", callPskSecret, &n);
        }

        // keyschedule.externalInitSender / externalInitReceiver.
        {
            rec_counter = base_lo;
            var ei: keyschedule.ExternalInit(S) = undefined;
            try keyschedule.externalInitSender(S, lo_ek.public_key, rec_io, &ei);
            const d = grab(base_lo);
            n = .{};
            addDraws(&n, &d);
            for (d.items[0..d.n]) |x| {
                if (x.l != 32) continue;
                var ekp: S.Kem.KeyPair = undefined;
                S.Kem.deriveKeyPair(&ekp, x.b[0..32]);
                if (X25519.scalarmult(ekp.secret_key, lo_ek.public_key)) |dh| add(&n, "dh", &dh) else |_| {}
            }
            add(&n, "init_secret", &ei.init_secret);
            addControl(&n);
            n.sort();
            bad += try runProbe("keyschedule.externalInitSender", callExternalInitSender, &n);

            n = .{};
            add(&n, "ext priv", &lo_ek.secret_key);
            if (X25519.scalarmult(lo_ek.secret_key, ext_kem_out)) |dh| add(&n, "dh", &dh) else |_| {}
            add(&n, "init_secret", &ext_init_secret);
            addControl(&n);
            n.sort();
            bad += try runProbe("keyschedule.externalInitReceiver", callExternalInitReceiver, &n);
        }

        // secrettree: node/base secrets, Ratchet, Window.
        {
            st_enc_secret = seedBytes(32, "mls-st-enc", c);
            try secrettree.ratchetBaseSecret(S, &st_enc_secret, 4, 2, .application, &st_base);
            secrettree.Ratchet(S).init(&st_base, &st_rt);
            secrettree.Window(S, 4).init(&st_base, &st_win);

            // Everything the tree and the ratchet derive: node secrets 0..6,
            // ratchet secrets of generations 0..3, their keys and nonces.
            var base_set: Needles = .{};
            add(&base_set, "encryption_secret", &st_enc_secret);
            addHmacPads(&base_set, &st_enc_secret);
            for (0..7) |ni| {
                var ns: [32]u8 = undefined;
                try secrettree.nodeSecret(S, &st_enc_secret, 4, ni, &ns);
                add(&base_set, "node secret", &ns);
                addHmacPads(&base_set, &ns);
            }
            var r = st_rt;
            for (0..4) |_| {
                add(&base_set, "ratchet", &r.secret);
                addHmacPads(&base_set, &r.secret);
                var kn: KN = undefined;
                try r.current(&kn);
                addKn(&base_set, &kn);
                try r.advance();
            }
            addControl(&base_set);
            base_set.sort();
            bad += try runProbe("secrettree.ratchetBaseSecret", callRatchetBase, &base_set);
            bad += try runProbe("secrettree.nodeSecret", callNodeSecret, &base_set);
            bad += try runProbe("secrettree.Ratchet.current", callRatchetCurrent, &base_set);
            bad += try runProbe("secrettree.Ratchet.advance", callRatchetAdvance, &base_set);
            bad += try runProbe("secrettree.Window.get", callWindowGet, &base_set);
        }

        // framing.protectPrivate / decryptSenderData / decryptContent, secrettree.senderDataKeys.
        {
            sd_secret = seedBytes(32, "mls-sd-secret", c);
            var r = st_rt;
            try r.current(&pm_kn);
            fc = .{
                .group_id = "mls-probe-group",
                .epoch = 1,
                .sender = .{ .member = 0 },
                .authenticated_data = "aad",
                .body = .{ .application = "mls probe application data" },
            };
            pm_bytes = try framing.protectPrivate(S, gpa, .{
                .signature_key_pair = &alice.sig,
                .group_context = gc_bytes,
                .content = fc,
                .key_nonce = &pm_kn,
                .generation = 0,
                .reuse_guard = pm_guard,
                .sender_data_secret = &sd_secret,
            });
            var rd = mls.codec.Reader.init(pm_bytes);
            pm = try framing.PrivateMessage.decode(&rd);
            var sdk: secrettree.SenderDataKeys(S) = undefined;
            try secrettree.senderDataKeys(S, &sd_secret, pm.ciphertext, &sdk);
            var guarded = pm_kn;
            for (pm_guard, 0..) |g, i| guarded.nonce[i] ^= g;

            n = .{};
            add(&n, "sender_data_secret", &sd_secret);
            addHmacPads(&n, &sd_secret);
            add(&n, "sd key", &sdk.key);
            add(&n, "sd nonce", &sdk.nonce);
            addAes(&n, &sdk.key);
            addControl(&n);
            n.sort();
            bad += try runProbe("secrettree.senderDataKeys", callSenderDataKeys, &n);

            bad += try runProbe("framing.decryptSenderData", callDecryptSenderData, &n);

            n = .{};
            addKn(&n, &pm_kn);
            add(&n, "aead nonce", &guarded.nonce);
            addControl(&n);
            n.sort();
            bad += try runProbe("framing.decryptContent", callDecryptContent, &n);

            n = .{};
            addKn(&n, &pm_kn);
            add(&n, "aead nonce", &guarded.nonce);
            add(&n, "sender_data_secret", &sd_secret);
            addHmacPads(&n, &sd_secret);
            add(&n, "sd key", &sdk.key);
            add(&n, "sd nonce", &sdk.nonce);
            addAes(&n, &sdk.key);
            addSigning(&n, &alice.sig);
            addControl(&n);
            n.sort();
            bad += try runProbe("framing.protectPrivate", callProtectPrivate, &n);
        }

        // welcome.decryptGroupSecrets / join.
        {
            n = .{};
            add(&n, "init_priv", &bob.init_kp.secret_key);
            const slot = wl.findSecret(&ref).?;
            if (X25519.scalarmult(bob.init_kp.secret_key, slot.encrypted_group_secrets.kem_output[0..32].*)) |dh| add(&n, "dh", &dh) else |_| {}
            add(&n, "group secrets", gs_plain[0..@min(gs_plain.len, 64)]);
            add(&n, "joiner_secret", &sb1.joiner_secret);
            addControl(&n);
            n.sort();
            bad += try runProbe("welcome.decryptGroupSecrets", callDecryptGroupSecrets, &n);

            join_params = .{
                .welcome = wl,
                .key_package_ref = &ref,
                .init_key_pair = &bob.init_kp,
                .signer_key = alice.sig.public_key,
            };
            n = .{};
            addSecrets(&n, &sb1);
            addDerived(&n, &sb1);
            add(&n, "init_priv", &bob.init_kp.secret_key);
            if (X25519.scalarmult(bob.init_kp.secret_key, slot.encrypted_group_secrets.kem_output[0..32].*)) |dh| add(&n, "dh", &dh) else |_| {}
            add(&n, "group secrets", gs_plain[0..@min(gs_plain.len, 64)]);
            addControl(&n);
            n.sort();
            bad += try runProbe("welcome.join", callWelcomeJoin, &n);
        }

        // treekem.stageUpdatePath.
        {
            stage_leaf = try S.Kem.KeyPair.generateDeterministic(seedBytes(32, "mls-stage-leaf", c));
            stage_ps0 = seedBytes(32, "mls-stage-ps0", c);
            fillA1();
            var pa: G = undefined;
            mkA1(&pa);
            var st: treekem.Staged(S) = undefined;
            try treekem.stageUpdatePath(S, gpa, &pa.ratchet_tree, pa.my_leaf_index, .{
                .group_id = "mls-probe-group",
                .signature_key_pair = &alice.sig,
                .leaf_key_pair = &stage_leaf,
                .path_secret_0 = &stage_ps0,
                .signature_key = alice.kp.leaf_node.signature_key,
                .credential = alice.kp.leaf_node.credential,
                .capabilities = alice.kp.leaf_node.capabilities,
                .extensions = alice.kp.leaf_node.extensions,
            }, &st);
            n = .{};
            addPathChain(&n, stage_ps0);
            add(&n, "leaf priv", &stage_leaf.secret_key);
            add(&n, "commit_secret", &st.commit_secret);
            for (st.nodes) |node| addPathChain(&n, node.path_secret);
            addSigning(&n, &alice.sig);
            addControl(&n);
            n.sort();
            bad += try runProbe("treekem.stageUpdatePath", callStageUpdatePath, &n);
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
