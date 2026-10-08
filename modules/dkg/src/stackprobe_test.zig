// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for every `dkg` entry point that touches a
//! secret (the two dealing polynomials, the shares sent and accepted, the
//! output share), kept in the module per `CONVENTIONS.md` §9.
//!
//! Method as `p256`'s `stackprobe_test.zig` (direct region, 2026-10-08: the
//! earlier "scan a local buffer at the call's depth" form was blind to the top
//! few hundred bytes of the measured call): paint a stack region below the
//! probe, run one call under a `PAD`-deep shim, snapshot the region and look for
//! secrets in the snapshot — every 16-byte window of every secret's big-endian,
//! little-endian and in-memory image, and of every byte the call drew from its
//! `std.Random`. ReleaseFast/ReleaseSmall only — Debug and ReleaseSafe fill
//! `undefined` with 0xaa.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const dkg = @import("root.zig");
const commit = @import("commit.zig");
const core = @import("core.zig");
const wire = @import("wire.zig");
const Scalar = dkg.Scalar;
const Participant = dkg.Participant;

const WINDOW = 4 * 1024 * 1024;

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

    fn addScalar(self: *Needles, name: []const u8, s: Scalar) void {
        const be = s.toBytes(.big);
        var le: [32]u8 = undefined;
        for (be, 0..) |b, i| le[31 - i] = b;
        const a = self.arena.allocator();
        self.add(std.fmt.allocPrint(a, "{s} BE", .{name}) catch @panic("probe OOM"), &be);
        self.add(std.fmt.allocPrint(a, "{s} LE", .{name}) catch @panic("probe OOM"), a.dupe(u8, &le) catch @panic("probe OOM"));
        self.add(std.fmt.allocPrint(a, "{s} mem", .{name}) catch @panic("probe OOM"), a.dupe(u8, std.mem.asBytes(&s)) catch @panic("probe OOM"));
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

// ── GJKR, one participant call at a time ─────────────────────────────────

const n_parties = 3;
const cfg: dkg.Config = .{ .t = 2, .n = n_parties };
var parties: [n_parties]Participant = undefined;
var outgoing: [n_parties][]wire.Outgoing = undefined;
var cur_party: usize = 0;
var cur_from: u32 = 0;
var cur_bytes: []const u8 = &.{};
var out_share: dkg.DkgShareOutput = undefined;

noinline fn callInit() void {
    parties[cur_party] = Participant.init(std.testing.allocator, cfg, @intCast(cur_party + 1), recorder.random()) catch @panic("init");
}
noinline fn callStart() void {
    parties[cur_party].start() catch @panic("start");
}
noinline fn callHandle() void {
    parties[cur_party].handle(cur_from, cur_bytes) catch @panic("handle");
}
noinline fn callAdvance() void {
    parties[cur_party].advance() catch @panic("advance");
}
noinline fn callOutput() void {
    out_share = parties[cur_party].output().?;
}

fn addParticipant(n: *Needles, p: *const Participant) void {
    for (p.a) |c| n.addScalar("a (dealing)", c);
    for (p.b) |c| n.addScalar("b (blinding)", c);
    for ([_][]?Scalar{ p.wire_s, p.wire_sp, p.accepted, p.accepted_sp, p.revealed }) |list|
        for (list) |maybe| if (maybe) |s| n.addScalar("share", s);
    if (p.result) |r| n.addScalar("output x_i", r.secret_share);
}

fn probeParty(label: []const u8, comptime call: fn () void) usize {
    const start = recorder.log.items.len;
    region_lo = stackHere() - PAD - WINDOW;
    measure(call);
    var n = Needles.init();
    defer n.deinit();
    for (&parties) |*p| addParticipant(&n, p);
    n.add("RNG stream (this call)", recorder.log.items[start..]);
    rng_base = start;
    defer rng_base = 0;
    return analyse(label, &n).copies;
}

test "STACKPROBE: no secret on the dead stack after any GJKR participant call" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    recorder = .{ .csprng = .init(@splat(0x3d)) };
    defer {
        recorder.log.deinit(std.heap.page_allocator);
        recorder.draws.deinit(std.heap.page_allocator);
    }

    var total: usize = 0;
    var label_buf: [64]u8 = undefined;
    var built: usize = 0;
    defer for (parties[0..built]) |*p| p.deinit();
    for (0..n_parties) |i| {
        cur_party = i;
        total += probeParty(try std.fmt.bufPrint(&label_buf, "init party {d}", .{i + 1}), callInit);
        built += 1;
    }

    // Controls (after init: the needles are the parties' polynomials).
    {
        var n = Needles.init();
        defer n.deinit();
        for (&parties) |*p| addParticipant(&n, p);
        region_lo = stackHere() - PAD - WINDOW;
        measure(callInnocent);
        try std.testing.expectEqual(@as(usize, 0), analyse("NEG control", &n).copies);
        leak_src = parties[0].a[0].toBytes(.big);
        measure(callLeaky);
        quiet = true;
        defer quiet = false;
        try std.testing.expect(analyse("POS control", &n).copies >= 1);
    }

    for (0..n_parties) |i| {
        cur_party = i;
        total += probeParty(try std.fmt.bufPrint(&label_buf, "start party {d}", .{i + 1}), callStart);
    }
    var round: usize = 0;
    while (round < 6) : (round += 1) {
        var settled = true;
        for (&parties) |*p| switch (p.phase()) {
            .done, .aborted => {},
            else => settled = false,
        };
        if (settled) break;
        for (&parties, 0..) |*p, i| outgoing[i] = try p.takeOutgoing();
        defer for (outgoing) |msgs| wire.freeOutgoing(allocator, msgs);
        for (outgoing, 0..) |msgs, from| for (msgs) |m| {
            for (0..n_parties) |to| {
                const wanted = switch (m.to) {
                    .broadcast => to != from,
                    .party => |j| j == to + 1,
                };
                if (!wanted) continue;
                cur_party = to;
                cur_from = @intCast(from + 1);
                cur_bytes = m.bytes;
                total += probeParty(try std.fmt.bufPrint(&label_buf, "handle round {d} {d}->{d}", .{ round, from + 1, to + 1 }), callHandle);
            }
        };
        for (&parties, 0..) |*p, i| switch (p.phase()) {
            .done, .aborted => {},
            else => {
                cur_party = i;
                total += probeParty(try std.fmt.bufPrint(&label_buf, "advance round {d} party {d}", .{ round, i + 1 }), callAdvance);
            },
        };
    }
    for (&parties) |*p| try std.testing.expectEqual(dkg.Phase.done, p.phase());
    for (0..n_parties) |i| {
        cur_party = i;
        total += probeParty(try std.fmt.bufPrint(&label_buf, "output party {d}", .{i + 1}), callOutput);
        out_share.deinit();
    }

    if (verbose or total != 0) std.debug.print("TOTAL residue copies (GJKR): {d}\n", .{total});
    try std.testing.expectEqual(@as(usize, 0), total);
}

// ── reshare, and the ECDSA keygen and refresh state machines ─────────────

const reshare = @import("reshare.zig");
const tecdsa = @import("threshold_ecdsa");
const aux_info = tecdsa.aux_info;
const paillier = @import("paillier");

/// Every secret a protocol struct holds, found by its fields' types:
/// `Scalar` in any optional/slice shape, the output share, a `KeyShare`, and
/// the nested protocol structs. Public scalars a struct may hold are few
/// (none in these types) and would show as residue to triage, not hide one.
fn addSecretsOf(n: *Needles, comptime T: type, v: *const T) void {
    inline for (@typeInfo(T).@"struct".fields) |f| {
        const x = &@field(v, f.name);
        switch (f.type) {
            Scalar => n.addScalar(f.name, x.*),
            ?Scalar => if (x.*) |s| n.addScalar(f.name, s),
            []Scalar, []const Scalar => for (x.*) |s| n.addScalar(f.name, s),
            []?Scalar => for (x.*) |m| if (m) |s| n.addScalar(f.name, s),
            ?[]Scalar => if (x.*) |sl| for (sl) |s| n.addScalar(f.name, s),
            []?[]Scalar => for (x.*) |m| if (m) |sl| for (sl) |s| n.addScalar(f.name, s),
            ?dkg.DkgShareOutput => if (x.*) |o| n.addScalar("output share", o.secret_share),
            dkg.DkgShareOutput => n.addScalar("share", x.secret_share),
            ?tecdsa.KeyShare => if (x.*) |*k| addKeyShare(n, k),
            tecdsa.KeyShare => addKeyShare(n, x),
            Participant, reshare.ReshareDealer, reshare.ReshareReceiver => addSecretsOf(n, f.type, x),
            *const aux_info.LocalAux => addLocalAux(n, x.*),
            else => {},
        }
    }
}

fn addPaillierSecret(n: *Needles, sk: *const paillier.SecretKey) void {
    n.addRaw("paillier lambda", std.mem.asBytes(&sk.lambda));
    n.addRaw("paillier mu", std.mem.asBytes(&sk.mu));
    if (sk.crt) |*crt| n.addRaw("paillier crt (p,q-derived)", std.mem.asBytes(crt));
}

fn addKeyShare(n: *Needles, k: *const tecdsa.KeyShare) void {
    n.addScalar("key share x_i", k.secret_share);
    n.addRaw("message seed", &k.message_seed);
    addPaillierSecret(n, &k.paillier_secret);
}

fn addLocalAux(n: *Needles, l: *const aux_info.LocalAux) void {
    n.addRaw("paillier p", l.paillier.p());
    n.addRaw("paillier q", l.paillier.q());
    addPaillierSecret(n, &l.paillier.key.secret);
    n.addRaw("aux p~", l.trapdoor.p);
    n.addRaw("aux q~", l.trapdoor.q);
    n.addRaw("aux lambda", std.mem.asBytes(&l.trapdoor.lambda));
    n.addRaw("message seed", &l.message_seed);
}

/// One probed call on a party of any of the state-machine types: `call`
/// runs `op` on `probe_target`, which `drive` points at the party.
const Op = enum { start, advance, handle };
var probe_target: *anyopaque = undefined;
var probe_from: u32 = 0;
var probe_sender: reshare.Sender = undefined;

fn Driver(comptime P: type) type {
    return struct {
        noinline fn start() void {
            const p: *P = @ptrCast(@alignCast(probe_target));
            p.start() catch @panic("start");
        }
        noinline fn advance() void {
            const p: *P = @ptrCast(@alignCast(probe_target));
            p.advance() catch @panic("advance");
        }
        noinline fn handle() void {
            const p: *P = @ptrCast(@alignCast(probe_target));
            if (P == reshare.ReshareReceiver)
                p.handle(probe_sender, cur_bytes) catch @panic("handle")
            else
                p.handle(probe_from, cur_bytes) catch @panic("handle");
        }

        fn probe(comptime op: Op, p: *P, label: []const u8, comptime fill: fn (*Needles) void) usize {
            probe_target = p;
            const start_at = recorder.log.items.len;
            region_lo = stackHere() - PAD - WINDOW;
            measure(switch (op) {
                .start => start,
                .advance => advance,
                .handle => handle,
            });
            var n = Needles.init();
            defer n.deinit();
            fill(&n);
            n.add("RNG stream (this call)", recorder.log.items[start_at..]);
            rng_base = start_at;
            defer rng_base = 0;
            return analyse(label, &n).copies;
        }
    };
}

var dealers: [2]reshare.ReshareDealer = undefined;
var receivers: [4]reshare.ReshareReceiver = undefined;
var old_outputs: []dkg.DkgShareOutput = undefined;

fn fillReshare(n: *Needles) void {
    for (&dealers) |*d| addSecretsOf(n, reshare.ReshareDealer, d);
    for (&receivers) |*r| addSecretsOf(n, reshare.ReshareReceiver, r);
    for (old_outputs) |o| n.addScalar("old share", o.secret_share);
}

noinline fn callDealerInit() void {
    dealers[cur_party] = reshare.ReshareDealer.init(std.testing.allocator, &old_outputs[cur_party], reshare_cfg.new, recorder.random()) catch @panic("ReshareDealer.init");
}
var reshare_cfg: reshare.ReshareConfig = undefined;

fn deliverReshare(allocator: std.mem.Allocator, total: *usize, from_dealers: bool, label_buf: []u8) !void {
    if (from_dealers) {
        for (&dealers) |*d| {
            const msgs = try d.takeOutgoing();
            defer wire.freeOutgoing(allocator, msgs);
            for (msgs) |m| for (&receivers) |*r| {
                switch (m.to) {
                    .broadcast => {},
                    .party => |j| if (j != r.id()) continue,
                }
                probe_sender = .{ .dealer = d.id() };
                cur_bytes = m.bytes;
                total.* += Driver(reshare.ReshareReceiver).probe(.handle, r, try std.fmt.bufPrint(label_buf, "receiver {d} handle from dealer {d}", .{ r.id(), d.id() }), fillReshare);
            };
        }
    } else {
        for (&receivers) |*r| {
            const msgs = try r.takeOutgoing();
            defer wire.freeOutgoing(allocator, msgs);
            for (msgs) |m| {
                for (&receivers) |*q| if (q.id() != r.id()) {
                    probe_sender = .{ .receiver = r.id() };
                    cur_bytes = m.bytes;
                    total.* += Driver(reshare.ReshareReceiver).probe(.handle, q, try std.fmt.bufPrint(label_buf, "receiver {d} handle from receiver {d}", .{ q.id(), r.id() }), fillReshare);
                };
                for (&dealers) |*d| {
                    probe_from = r.id();
                    cur_bytes = m.bytes;
                    total.* += Driver(reshare.ReshareDealer).probe(.handle, d, try std.fmt.bufPrint(label_buf, "dealer {d} handle from receiver {d}", .{ d.id(), r.id() }), fillReshare);
                }
            }
        }
    }
}

test "STACKPROBE: no secret on the dead stack after any reshare dealer or receiver call" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    recorder = .{ .csprng = .init(@splat(0x4a)) };
    defer {
        recorder.log.deinit(std.heap.page_allocator);
        recorder.draws.deinit(std.heap.page_allocator);
    }
    const old_cfg: dkg.Config = .{ .t = 2, .n = 3 };
    {
        var prng = std.Random.DefaultPrng.init(0x7265_7368);
        old_outputs = try dkg.Dkg.run(allocator, old_cfg, .{}, prng.random());
    }
    defer {
        for (old_outputs) |*o| o.deinit();
        allocator.free(old_outputs);
    }
    var xs: [3]dkg.Element = undefined;
    for (old_outputs, &xs) |o, *x| x.* = o.verifying_share;
    reshare_cfg = .{ .old = old_cfg, .new = .{ .t = 3, .n = 4 }, .dealers = &.{ 1, 2 }, .group_public_key = old_outputs[0].group_public_key, .old_verifying_shares = &xs };

    var total: usize = 0;
    var label_buf: [80]u8 = undefined;
    for (0..2) |i| {
        cur_party = i;
        const start_at = recorder.log.items.len;
        region_lo = stackHere() - PAD - WINDOW;
        measure(callDealerInit);
        var n = Needles.init();
        defer n.deinit();
        addSecretsOf(&n, reshare.ReshareDealer, &dealers[i]);
        for (old_outputs) |o| n.addScalar("old share", o.secret_share);
        n.add("RNG stream (this call)", recorder.log.items[start_at..]);
        rng_base = start_at;
        defer rng_base = 0;
        total += analyse(try std.fmt.bufPrint(&label_buf, "ReshareDealer.init {d}", .{i + 1}), &n).copies;
    }
    defer for (&dealers) |*d| d.deinit();
    for (&receivers, 1..) |*r, id| r.* = try reshare.ReshareReceiver.init(allocator, reshare_cfg, @intCast(id));
    defer for (&receivers) |*r| r.deinit();

    // Rig.run's sequence, every call probed.
    for (&dealers) |*d| total += Driver(reshare.ReshareDealer).probe(.start, d, try std.fmt.bufPrint(&label_buf, "dealer {d} start", .{d.id()}), fillReshare);
    try deliverReshare(allocator, &total, true, &label_buf);
    for (&receivers) |*r| total += Driver(reshare.ReshareReceiver).probe(.advance, r, try std.fmt.bufPrint(&label_buf, "receiver {d} advance (shares)", .{r.id()}), fillReshare);
    try deliverReshare(allocator, &total, false, &label_buf);
    for (&receivers) |*r| total += Driver(reshare.ReshareReceiver).probe(.advance, r, try std.fmt.bufPrint(&label_buf, "receiver {d} advance (complaints)", .{r.id()}), fillReshare);
    for (&dealers) |*d| total += Driver(reshare.ReshareDealer).probe(.advance, d, try std.fmt.bufPrint(&label_buf, "dealer {d} advance", .{d.id()}), fillReshare);
    try deliverReshare(allocator, &total, true, &label_buf);
    for (&receivers) |*r| total += Driver(reshare.ReshareReceiver).probe(.advance, r, try std.fmt.bufPrint(&label_buf, "receiver {d} advance (defenses)", .{r.id()}), fillReshare);
    for (&receivers) |*r| try std.testing.expect(r.output() != null);

    if (verbose or total != 0) std.debug.print("TOTAL residue copies (reshare): {d}\n", .{total});
    try std.testing.expectEqual(@as(usize, 0), total);
}

/// Test-only `LocalAux` from Blum primes, as `ecdsa_keygen.zig`'s tests
/// build it (production safe primes take minutes).
fn quickLocal(allocator: std.mem.Allocator, random: std.Random) !aux_info.LocalAux {
    var key: tecdsa.PaillierBlumKey = undefined;
    try tecdsa.generatePaillierBlum(random, 2048, &key);
    errdefer key.wipe();
    var ring: tecdsa.PaillierBlumKey = undefined;
    try tecdsa.generatePaillierBlum(random, 2048, &ring);
    defer ring.wipe();
    const nt = ring.modulus();
    var buf: [tecdsa.aux_modulus_bytes]u8 = undefined;
    random.bytes(&buf);
    buf[0] &= 0x3f;
    const h2 = nt.sq(try tecdsa.AuxFe.fromBytes(nt, &buf, .big));
    random.bytes(&buf);
    buf[0] &= 0x3f;
    const lambda = try tecdsa.AuxFe.fromBytes(nt, &buf, .big);
    const h1 = try nt.pow(h2, lambda); // h1 ∈ ⟨h2⟩, the relation Πprm proves
    const p = try allocator.dupe(u8, ring.p());
    errdefer allocator.free(p);
    const q = try allocator.dupe(u8, ring.q());
    var seed: [32]u8 = undefined;
    random.bytes(&seed);
    const aux: tecdsa.AuxParams = .{ .n_tilde = nt, .h1 = h1, .h2 = h2 };
    var trapdoor: tecdsa.AuxTrapdoor = .{ .p = p, .q = q, .lambda = lambda };
    var local: aux_info.LocalAux = undefined;
    aux_info.LocalAux.fromParts(&key, aux, &trapdoor, &seed, &local);
    return local;
}

const ecdsa_keygen = @import("ecdsa_keygen.zig");
const ecdsa_refresh = @import("ecdsa_refresh.zig");
var locals: [6]aux_info.LocalAux = undefined;
var kparties: [3]ecdsa_keygen.EcdsaKeygen = undefined;
var rparties: [3]ecdsa_refresh.EcdsaRefresh = undefined;
var kshares: [3]tecdsa.KeyShare = undefined;
var rshares: [3]tecdsa.KeyShare = undefined;

/// How many of `kparties` / `rparties` are initialised (the init probes
/// read the parties after each call).
var kmade: usize = 0;
var rmade: usize = 0;

fn fillKeygen(n: *Needles) void {
    for (kparties[0..kmade]) |*p| addSecretsOf(n, ecdsa_keygen.EcdsaKeygen, p);
    for (locals[0..3]) |*l| addLocalAux(n, l);
}
fn fillTaken(n: *Needles) void {
    fillKeygen(n);
    for (kshares[0 .. cur_party + 1]) |*k| addKeyShare(n, k);
}
fn fillRefresh(n: *Needles) void {
    for (rparties[0..rmade]) |*p| addSecretsOf(n, ecdsa_refresh.EcdsaRefresh, p);
    for (locals[3..6]) |*l| addLocalAux(n, l);
    for (&kshares) |*k| addKeyShare(n, k);
}

noinline fn callKeygenInit() void {
    kmade = cur_party + 1;
    kparties[cur_party] = ecdsa_keygen.EcdsaKeygen.init(std.testing.allocator, .{ .t = 2, .n = 3 }, @intCast(cur_party + 1), "stackprobe keygen", &locals[cur_party], recorder.random()) catch @panic("EcdsaKeygen.init");
}
noinline fn callRefreshInit() void {
    rmade = cur_party + 1;
    rparties[cur_party] = ecdsa_refresh.EcdsaRefresh.init(std.testing.allocator, &kshares[cur_party], "stackprobe refresh", &locals[3 + cur_party], recorder.random()) catch @panic("EcdsaRefresh.init");
}
noinline fn callKeygenTake() void {
    if (!kparties[cur_party].takeKeyShare(&kshares[cur_party])) @panic("takeKeyShare");
}
noinline fn callRefreshTake() void {
    if (!rparties[cur_party].takeKeyShare(&rshares[cur_party])) @panic("takeKeyShare");
}

fn probePlain(label: []const u8, comptime call: fn () void, comptime fill: fn (*Needles) void) usize {
    const start_at = recorder.log.items.len;
    region_lo = stackHere() - PAD - WINDOW;
    measure(call);
    var n = Needles.init();
    defer n.deinit();
    fill(&n);
    n.add("RNG stream (this call)", recorder.log.items[start_at..]);
    rng_base = start_at;
    defer rng_base = 0;
    return analyse(label, &n).copies;
}

/// `ecdsa_refresh.zig`'s `runAll` with every call probed.
fn runProbed(comptime P: type, allocator: std.mem.Allocator, group: []P, name: []const u8, comptime fill: fn (*Needles) void) !usize {
    var total: usize = 0;
    var label_buf: [80]u8 = undefined;
    for (group, 1..) |*p, i| total += Driver(P).probe(.start, p, try std.fmt.bufPrint(&label_buf, "{s} {d} start", .{ name, i }), fill);
    var rounds: usize = 0;
    while (true) : (rounds += 1) {
        try std.testing.expect(rounds < 16);
        for (group, 1..) |*src, from| {
            const msgs = try src.takeOutgoing();
            defer wire.freeOutgoing(allocator, msgs);
            for (msgs) |m| for (group, 1..) |*dst, to| {
                if (to == from) continue;
                switch (m.to) {
                    .broadcast => {},
                    .party => |j| if (j != to) continue,
                }
                probe_from = @intCast(from);
                cur_bytes = m.bytes;
                total += Driver(P).probe(.handle, dst, try std.fmt.bufPrint(&label_buf, "{s} {d} handle round {d} from {d}", .{ name, to, rounds, from }), fill);
            };
        }
        if (std.mem.eql(u8, @tagName(group[0].phase()), "done")) break;
        for (group, 1..) |*p, i| total += Driver(P).probe(.advance, p, try std.fmt.bufPrint(&label_buf, "{s} {d} advance round {d}", .{ name, i, rounds }), fill);
    }
    return total;
}

test "STACKPROBE: no secret on the dead stack after any ECDSA keygen or refresh call" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    {
        var prng = std.Random.DefaultPrng.init(0x6563_6b67);
        for (&locals) |*l| l.* = try quickLocal(allocator, prng.random());
    }
    defer for (&locals) |*l| l.deinit(allocator);
    recorder = .{ .csprng = .init(@splat(0x5b)) };
    defer {
        recorder.log.deinit(std.heap.page_allocator);
        recorder.draws.deinit(std.heap.page_allocator);
    }

    var total: usize = 0;
    var label_buf: [80]u8 = undefined;
    for (0..3) |i| {
        cur_party = i;
        total += probePlain(try std.fmt.bufPrint(&label_buf, "EcdsaKeygen.init {d}", .{i + 1}), callKeygenInit, fillKeygen);
    }
    defer for (&kparties) |*p| p.deinit();
    total += try runProbed(ecdsa_keygen.EcdsaKeygen, allocator, &kparties, "keygen", fillKeygen);
    for (0..3) |i| {
        cur_party = i;
        total += probePlain(try std.fmt.bufPrint(&label_buf, "EcdsaKeygen.takeKeyShare {d}", .{i + 1}), callKeygenTake, fillTaken);
    }
    defer for (&kshares) |*s| {
        s.paillier_secret.deinit();
        allocator.free(s.public_keys.entries);
    };

    for (0..3) |i| {
        cur_party = i;
        total += probePlain(try std.fmt.bufPrint(&label_buf, "EcdsaRefresh.init {d}", .{i + 1}), callRefreshInit, fillRefresh);
    }
    defer for (&rparties) |*p| p.deinit();
    total += try runProbed(ecdsa_refresh.EcdsaRefresh, allocator, &rparties, "refresh", fillRefresh);
    for (0..3) |i| {
        cur_party = i;
        total += probePlain(try std.fmt.bufPrint(&label_buf, "EcdsaRefresh.takeKeyShare {d}", .{i + 1}), callRefreshTake, fillRefresh);
    }
    defer for (&rshares) |*s| {
        s.paillier_secret.deinit();
        allocator.free(s.public_keys.entries);
    };
    if (verbose or total != 0) std.debug.print("TOTAL residue copies (ecdsa keygen/refresh): {d}\n", .{total});
    try std.testing.expectEqual(@as(usize, 0), total);
}

// ── the free functions: commitments, share checks, drivers ───────────────

const Free = struct {
    var a: [3]Scalar = undefined;
    var b: [3]Scalar = undefined;
    var s: Scalar = undefined;
    var sp: Scalar = undefined;
    var drawn: Scalar = undefined;
    var combined: Scalar = undefined;
    var received: [3]?Scalar = undefined;
    var ped: []dkg.Element = undefined;
    var fel: []dkg.Element = undefined;
    var outs: []dkg.DkgShareOutput = undefined;
    var shares: []tecdsa.KeyShare = undefined;
    var keys: [3]paillier.KeyPair = undefined;
    var aux: [3]tecdsa.AuxParams = undefined;
    var seeds: [3][32]u8 = undefined;
    var sink: usize = 0;

    noinline fn randomScalar() void {
        commit.randomScalar(recorder.random(), &drawn);
    }
    noinline fn evalPoly() void {
        commit.evalPoly(&a, commit.scalarFromIndex(2), &s);
        commit.evalPoly(&b, commit.scalarFromIndex(2), &sp);
    }
    noinline fn pedersenCommitVector() void {
        ped = commit.pedersenCommitVector(std.testing.allocator, &a, &b, commit.pedersenH()) catch @panic("pedersenCommitVector");
    }
    noinline fn feldmanCommitVector() void {
        fel = commit.feldmanCommitVector(std.testing.allocator, &a) catch @panic("feldmanCommitVector");
    }
    noinline fn evalShares() void {
        const e1 = commit.pedersenEvalShare(&s, &sp, commit.pedersenH()) catch @panic("pedersenEvalShare");
        const e2 = commit.feldmanEvalShare(&s) catch @panic("feldmanEvalShare");
        sink +%= @intFromPtr(&e1) +% @intFromPtr(&e2);
    }
    noinline fn verifyShares() void {
        if (!core.verifyPedersenShare(ped, 2, &s, &sp, commit.pedersenH())) @panic("verifyPedersenShare");
        if (!core.verifyFeldmanShare(fel, 2, &s)) @panic("verifyFeldmanShare");
    }
    noinline fn combine() void {
        core.combineKeyShare(&.{ true, true, true }, &received, &combined) catch @panic("combineKeyShare");
    }
    noinline fn dkgRun() void {
        outs = dkg.Dkg.run(std.testing.allocator, .{ .t = 2, .n = 3 }, .{}, recorder.random()) catch @panic("Dkg.run");
    }
    noinline fn reconstructs() void {
        if (!(dkg.checks.reconstructsToQ(std.testing.allocator, outs) catch @panic("reconstructsToQ"))) @panic("reconstructsToQ: false");
    }
    noinline fn assemble() void {
        shares = dkg.assembleKeyShares(std.testing.allocator, outs, 2, &keys, &aux, &seeds) catch @panic("assembleKeyShares");
    }

    fn fill(n: *Needles) void {
        for (a) |x| n.addScalar("a", x);
        for (b) |x| n.addScalar("b", x);
        n.addScalar("s", s);
        n.addScalar("s'", sp);
        n.addScalar("drawn", drawn);
        n.addScalar("combined", combined);
        for (received) |m| if (m) |x| n.addScalar("received", x);
    }
    fn fillDkg(n: *Needles) void {
        for (outs) |o| n.addScalar("output share", o.secret_share);
    }
    fn fillAssembled(n: *Needles) void {
        fillDkg(n);
        for (&keys) |*k| addPaillierSecret(n, &k.secret);
        for (&seeds) |*sd| n.addRaw("message seed", sd);
    }
};

test "STACKPROBE: no secret on the dead stack after the commitment, share-check and driver functions" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    recorder = .{ .csprng = .init(@splat(0x6c)) };
    defer {
        recorder.log.deinit(std.heap.page_allocator);
        recorder.draws.deinit(std.heap.page_allocator);
    }
    var prng = std.Random.DefaultCsprng.init(@splat(0x6d));
    for (&Free.a, &Free.b) |*x, *y| {
        commit.randomScalar(prng.random(), x);
        commit.randomScalar(prng.random(), y);
    }
    for (&Free.received) |*r| {
        var x: Scalar = undefined;
        commit.randomScalar(prng.random(), &x);
        r.* = x;
    }
    Free.s = Scalar.zero;
    Free.sp = Scalar.zero;
    Free.drawn = Scalar.zero;
    Free.combined = Scalar.zero;
    for (&Free.keys, &Free.aux, &Free.seeds) |*k, *x, *sd| {
        try paillier.generate(prng.random(), 2048, k);
        x.* = try tecdsa.signing.testAuxParams(prng.random());
        prng.random().bytes(sd);
    }

    var total: usize = 0;
    total += probePlain("commit.randomScalar", Free.randomScalar, Free.fill);
    total += probePlain("commit.evalPoly", Free.evalPoly, Free.fill);
    total += probePlain("commit.pedersenCommitVector", Free.pedersenCommitVector, Free.fill);
    defer allocator.free(Free.ped);
    total += probePlain("commit.feldmanCommitVector", Free.feldmanCommitVector, Free.fill);
    defer allocator.free(Free.fel);
    total += probePlain("commit.pedersen/feldmanEvalShare", Free.evalShares, Free.fill);
    total += probePlain("core.verifyPedersen/FeldmanShare", Free.verifyShares, Free.fill);
    total += probePlain("core.combineKeyShare", Free.combine, Free.fill);
    total += probePlain("Dkg.run", Free.dkgRun, Free.fillDkg);
    defer {
        for (Free.outs) |*o| o.deinit();
        allocator.free(Free.outs);
    }
    total += probePlain("checks.reconstructsToQ", Free.reconstructs, Free.fillDkg);
    total += probePlain("assembleKeyShares", Free.assemble, Free.fillAssembled);
    defer {
        allocator.free(Free.shares[0].public_keys.entries);
        allocator.free(Free.shares);
    }
    if (verbose or total != 0) std.debug.print("TOTAL residue copies (free functions): {d}\n", .{total});
    try std.testing.expectEqual(@as(usize, 0), total);
}
