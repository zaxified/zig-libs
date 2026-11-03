// SPDX-License-Identifier: MIT

//! Per-hop path MTU (what `tracepath(8)` prints): the pure engine.
//!
//! `hopsWith` walks TTL 1, 2, 3 ... with DF probes of the current path-MTU
//! estimate. A Time Exceeded names the router at that TTL and says the estimate
//! reached it; a Fragmentation Needed / Packet Too Big says some link before it
//! is smaller (the router that sent it is the one whose outgoing link is the
//! limit) and lowers the estimate; the destination's Echo Reply ends the walk.
//! It owns no socket, no clock and no allocator: the prober is a seam, the
//! output is a caller-supplied slice, and `probeHops` in `root.zig` is the live
//! wrapper.
//!
//! Within one TTL the estimate is searched like `searchWith` does: the size
//! that failed is `hi`, the largest size proved to get an answer is `lo`
//! (the floor, checked once, to start with), and without a usable next-hop
//! MTU the next size is the middle. A hint inside `(lo, hi)` is probed first
//! and, if it passes, is the answer (it is the one place an estimate moves on
//! a router's word, and it is still only ever probed, not adopted).
//!
//! Why it terminates: the TTL runs to `min(max_hops, out.len)`, and at one TTL
//! at most `max_steps_per_hop` probes are sent, plus one floor check. Nothing a
//! prober returns, however hostile, changes that.
//!
//! What the numbers are worth. `Hop.proved` says it: when set, `mtu` is a size
//! that was probed and answered by THAT hop (or the destination), never a hint
//! taken on trust (a hint only decides what to probe next; RFC 1191 section 3 and
//! RFC 8201 section 4: an estimate only ever decreases, so a forged hint can make
//! the answer smaller, not larger). When it is not set, `mtu` is the estimate
//! carried over: the hop was silent, the step budget ran out, no probe could be
//! sent, or even the floor-sized probe failed.
//!
//! Silence is not evidence of a drop. A size that got no answer after the
//! prober's own retries is re-probed once at the end of the hop's search; if it
//! answers then, it is taken, but either way the hop is marked
//! `silence_narrowed` and the result `uncertain`: a lossy or rate-limited
//! router looks exactly like a black hole, and the (possibly too small)
//! estimate carries to every later hop.

const std = @import("std");
const netaddr = @import("netaddr");

/// Per TTL, the most probes sent before the walk gives up narrowing and keeps
/// the largest size it proved: the bisection of 65535 needs 16, the rest is
/// slack for hints. Bounds the work a hostile path can cost per hop.
pub const max_steps_per_hop: u8 = 32;

pub const Hop = struct {
    /// The TTL this hop was probed with (1-based).
    ttl: u8,
    /// Who answered at this TTL: the router (Time Exceeded) or the destination.
    /// `null`: nothing answered (a silent router, or one that rate-limits ICMP).
    addr: ?netaddr.Ip,
    /// The path MTU up to and including this hop: the largest wire size that
    /// was probed and reached it. For a silent hop the estimate carried over.
    mtu: u16,
    /// The estimate was lowered while this TTL was probed: some link before
    /// this hop is smaller than the previous hop's `mtu`.
    narrowed: bool = false,
    /// The router that reported the smaller next-hop MTU (its OUTGOING link is
    /// the limit), when it said who it was. Only with `narrowed`.
    narrowed_by: ?netaddr.Ip = null,
    /// This hop is the destination (it answered the Echo).
    is_destination: bool = false,
    /// `mtu` was probed and answered by this hop. Not set for a silent hop, an
    /// exhausted step budget, a send that failed, or a floor-sized probe that
    /// failed: there `mtu` is the estimate carried over from the hop before.
    proved: bool = false,
    /// The estimate was lowered because a size got NO answer (not because a
    /// router said so). A drop, packet loss and an ICMP rate limit cannot be told
    /// apart, so the hop's `mtu` may be smaller than its link.
    silence_narrowed: bool = false,
};

/// What one probe at (TTL, size) came back as.
pub const HopOutcome = union(enum) {
    /// ICMP Time Exceeded from `from` (null when the socket did not say).
    time_exceeded: ?netaddr.Ip,
    /// The destination's Echo Reply.
    echo_reply: ?netaddr.Ip,
    /// Fragmentation Needed / Packet Too Big, with the next-hop MTU it carried
    /// (null when absent or not delivered) and who sent it.
    frag_needed: struct { hint: ?u32, from: ?netaddr.Ip },
    /// The local kernel refused the size (EMSGSIZE).
    local_reject,
    /// Every send failed for a reason that says nothing about the path.
    send_failed,
    /// Nothing came back after the attempt budget.
    no_reply,
};

pub const HopProber = struct {
    ctx: *anyopaque,
    probeFn: *const fn (ctx: *anyopaque, ttl: u8, wire_size: u16) HopOutcome,

    pub fn probe(self: HopProber, ttl: u8, wire_size: u16) HopOutcome {
        return self.probeFn(self.ctx, ttl, wire_size);
    }
};

pub const HopsError = error{
    /// `ceiling` at or below `floor`: nothing to walk.
    CeilingTooLow,
    /// `max_hops == 0` or an empty output slice.
    NoHops,
};

pub const HopsResult = struct {
    /// The hops walked, in TTL order: a prefix of the caller's slice.
    hops: []const Hop,
    /// The estimate after the walk. With `reached` it is the path MTU to the
    /// destination (the destination answered at this size); without, only the
    /// path MTU to the last hop that answered.
    mtu: u16,
    /// The destination answered.
    reached: bool,
    /// Some TTL answered a small probe but not a larger one, with no ICMP
    /// message either way: an MTU black hole in front of that hop. The walk
    /// stepped the size down until the hop answered.
    blackhole: bool,
    /// Some hop is `silence_narrowed`: `blackhole` and the final `mtu` are
    /// evidence, not proof (loss or a rate limit looks the same), and the
    /// estimate carried to every later hop.
    uncertain: bool = false,
    /// The overall deadline ended the walk (set by `probeHops`, which owns the clock).
    timed_out: bool = false,
};

pub const HopsParams = struct {
    floor: u16,
    ceiling: u16,
    max_hops: u8 = 30,
    /// Stop after this many silent hops in a row (at least 1).
    max_silent_hops: u8 = 4,
};

/// Record who answered; the destination's Echo Reply marks the hop.
fn answered(hop: *Hop, answer: HopOutcome) void {
    switch (answer) {
        .time_exceeded => |from| hop.addr = from,
        .echo_reply => |from| {
            hop.addr = from;
            hop.is_destination = true;
        },
        else => {},
    }
}

/// Walk the path. `out` receives one `Hop` per TTL walked.
pub fn hopsWith(prober: HopProber, params: HopsParams, out: []Hop) HopsError!HopsResult {
    if (params.ceiling <= params.floor) return error.CeilingTooLow;
    const limit: usize = @min(@as(usize, params.max_hops), out.len);
    if (limit == 0) return error.NoHops;
    const max_silent: u8 = @max(params.max_silent_hops, 1);
    const floor = params.floor;

    var est: u16 = params.ceiling;
    var n: usize = 0;
    var silent_run: u8 = 0;
    var blackhole = false;
    var reached = false;
    var uncertain = false;

    while (n < limit) {
        const ttl: u8 = @intCast(n + 1);
        var hop: Hop = .{ .ttl = ttl, .addr = null, .mtu = est };
        // Largest size proved to get an answer at this TTL, and whether it was
        // really probed (the floor is only assumed until then); the smallest
        // size that failed (0: none yet).
        var lo: u16 = floor;
        var proved = false;
        var hi: u16 = 0;
        var floor_checked = false;
        var steps: u8 = 0;
        // The failure that set `hi` was silence; whether `hi` was re-probed once.
        var hi_silent = false;
        var confirmed = false;

        probing: while (true) {
            if (steps >= max_steps_per_hop) break :probing;
            steps += 1;
            var hint: ?u32 = null;
            var this_silent = false;
            const answer = prober.probe(ttl, est);
            switch (answer) {
                .time_exceeded, .echo_reply => {
                    answered(&hop, answer);
                    lo = est;
                    proved = true;
                    if (hi == 0) break :probing;
                    if (hi - lo <= 1) {
                        if (hi_silent and !confirmed) {
                            confirmed = true;
                            est = hi;
                            continue :probing;
                        }
                        break :probing;
                    }
                    est = lo + (hi - lo) / 2;
                    continue :probing;
                },
                .frag_needed => |f| {
                    hop.narrowed = true;
                    if (f.from != null) hop.narrowed_by = f.from;
                    hint = f.hint;
                },
                .local_reject => {},
                .send_failed => break :probing,
                .no_reply => {
                    if (est <= floor) break :probing; // a silent hop
                    if (!floor_checked) {
                        // Silence at this size: a silent hop, or a size-dependent
                        // drop? A floor-sized probe tells them apart, once.
                        floor_checked = true;
                        const small = prober.probe(ttl, floor);
                        switch (small) {
                            .time_exceeded, .echo_reply => {
                                answered(&hop, small);
                                blackhole = true;
                                proved = true;
                            },
                            else => break :probing,
                        }
                    }
                    this_silent = true;
                    hop.silence_narrowed = true;
                },
            }
            // The size `est` did not get through. Narrow.
            if (est <= floor) break :probing;
            hi = est;
            hi_silent = this_silent;
            if (hint) |h| {
                if (h > lo and h < hi) {
                    est = @intCast(h);
                    hi = est + 1;
                    continue :probing;
                }
            }
            if (hi - lo <= 1) {
                // Nothing between the last proved size and the failure. A failure
                // by silence is asked once more before it is believed.
                if (hi_silent and !confirmed and proved) {
                    confirmed = true;
                    est = hi;
                    continue :probing;
                }
                // If `lo` was only assumed, ask the hop once at that size.
                est = lo;
                if (proved) break :probing;
                continue :probing;
            }
            est = lo + (hi - lo) / 2;
        }

        if (proved) est = lo;
        hop.mtu = est;
        hop.proved = proved;
        if (hop.silence_narrowed) uncertain = true;
        out[n] = hop;
        n += 1;
        if (hop.is_destination) {
            reached = true;
            break;
        }
        silent_run = if (hop.addr == null) silent_run +| 1 else 0;
        if (silent_run >= max_silent) break;
    }

    return .{ .hops = out[0..n], .mtu = est, .reached = reached, .blackhole = blackhole, .uncertain = uncertain };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn ip4(a: u8, b: u8, c: u8, d: u8) netaddr.Ip {
    return .{ .v4 = .{ a, b, c, d } };
}

/// A scripted path: router `i` (TTL i+1) answers Time Exceeded from
/// `addrs[i]`; link `i` (the outgoing link of router `i`, entered by a packet
/// that survived TTL i+1) has MTU `links[i]`; the destination is router
/// `addrs.len`, reached at TTL `addrs.len + 1`. A packet bigger than a link it
/// would cross is answered by the router in front of that link, with or
/// without ICMP (`explicit`), with or without a hint (`hint`).
const FakePath = struct {
    addrs: []const netaddr.Ip,
    /// links[i]: MTU of the link out of router i (links.len == addrs.len; the
    /// last link leads to the destination).
    links: []const u16,
    explicit: bool = true,
    hint: bool = true,
    /// Routers that never answer Time Exceeded (rate-limited / filtered).
    silent: []const bool = &.{},
    probes: usize = 0,

    fn prober(self: *FakePath) HopProber {
        return .{ .ctx = self, .probeFn = probeFn };
    }

    fn probeFn(ctx: *anyopaque, ttl: u8, size: u16) HopOutcome {
        const self: *FakePath = @ptrCast(@alignCast(ctx));
        self.probes += 1;
        // The packet crosses links 0.. while its TTL lasts.
        var i: usize = 0;
        while (i < ttl) : (i += 1) {
            if (i >= self.addrs.len) break; // reached the destination
            // Before forwarding out of router i the router checks TTL first.
            if (i + 1 == ttl) {
                // TTL expires AT router i.
                return if (self.isSilent(i)) .no_reply else .{ .time_exceeded = self.addrs[i] };
            }
            if (size > self.links[i]) {
                if (!self.explicit) return .no_reply;
                if (self.isSilent(i)) return .no_reply;
                return .{ .frag_needed = .{ .hint = if (self.hint) self.links[i] else null, .from = self.addrs[i] } };
            }
        }
        return .{ .echo_reply = ip4(10, 9, 9, 9) };
    }

    fn isSilent(self: *const FakePath, i: usize) bool {
        return i < self.silent.len and self.silent[i];
    }
};

const test_addrs = [_]netaddr.Ip{ ip4(10, 0, 0, 1), ip4(10, 0, 1, 1), ip4(10, 0, 2, 1) };

test "hopsWith: the narrowing link is attributed to the router in front of it, and the MTU never grows" {
    // links: r1->r2 1500, r2->r3 1400, r3->dst 1492 (a later, larger link).
    var fp: FakePath = .{ .addrs = &test_addrs, .links = &.{ 1500, 1400, 1492 } };
    var out: [16]Hop = undefined;
    const r = try hopsWith(fp.prober(), .{ .floor = 68, .ceiling = 1500 }, &out);
    try testing.expect(r.reached);
    try testing.expectEqual(@as(usize, 4), r.hops.len);
    try testing.expectEqual(@as(u16, 1400), r.mtu);
    try testing.expectEqual(@as(u16, 1500), r.hops[0].mtu);
    try testing.expectEqual(@as(u16, 1500), r.hops[1].mtu);
    // TTL 3 expires at r3, so the size must already have crossed r2->r3 (1400):
    // the Frag-Needed came from r2, whose outgoing link is the 1400 one.
    try testing.expectEqual(@as(u16, 1400), r.hops[2].mtu);
    try testing.expect(r.hops[2].narrowed);
    try testing.expect(r.hops[2].narrowed_by.?.eql(test_addrs[1]));
    try testing.expectEqual(@as(u16, 1400), r.hops[3].mtu);
    try testing.expect(r.hops[3].is_destination);
    try testing.expect(!r.blackhole);
    for (r.hops[1..], 1..) |h, i| try testing.expect(h.mtu <= r.hops[i - 1].mtu);
}

test "hopsWith: without a hint the estimate is bisected and still lands exactly on the narrowest link" {
    var fp: FakePath = .{ .addrs = &test_addrs, .links = &.{ 1500, 1300, 1500 }, .hint = false };
    var out: [16]Hop = undefined;
    const r = try hopsWith(fp.prober(), .{ .floor = 68, .ceiling = 1500 }, &out);
    try testing.expect(r.reached);
    try testing.expectEqual(@as(u16, 1300), r.mtu);
    try testing.expect(r.hops[2].narrowed);
    try testing.expectEqual(@as(u16, 1300), r.hops[2].mtu);
}

test "hopsWith: a black hole (no ICMP) in front of a hop is stepped around and flagged" {
    var fp: FakePath = .{ .addrs = &test_addrs, .links = &.{ 1500, 1300, 1500 }, .explicit = false };
    var out: [16]Hop = undefined;
    const r = try hopsWith(fp.prober(), .{ .floor = 68, .ceiling = 1500 }, &out);
    try testing.expect(r.reached);
    try testing.expect(r.blackhole);
    try testing.expectEqual(@as(u16, 1300), r.mtu);
    try testing.expectEqual(@as(u16, 1300), r.hops[2].mtu);
}

test "hopsWith: a silent router is a silent hop, not a black hole" {
    var fp: FakePath = .{
        .addrs = &test_addrs,
        .links = &.{ 1500, 1500, 1500 },
        .silent = &.{ false, true, false },
    };
    var out: [16]Hop = undefined;
    const r = try hopsWith(fp.prober(), .{ .floor = 68, .ceiling = 1500 }, &out);
    try testing.expect(r.reached);
    try testing.expect(!r.blackhole);
    try testing.expect(r.hops[1].addr == null);
    try testing.expectEqual(@as(u16, 1500), r.hops[1].mtu);
}

test "hopsWith: stops after max_silent_hops silent hops in a row, not reached" {
    const SilentAll = struct {
        fn f(_: *anyopaque, _: u8, _: u16) HopOutcome {
            return .no_reply;
        }
    };
    var dummy: u8 = 0;
    var out: [16]Hop = undefined;
    const r = try hopsWith(.{ .ctx = &dummy, .probeFn = SilentAll.f }, .{ .floor = 68, .ceiling = 1500, .max_silent_hops = 3 }, &out);
    try testing.expect(!r.reached);
    try testing.expectEqual(@as(usize, 3), r.hops.len);
}

test "hopsWith: a hostile prober cannot make the walk longer than its bounds" {
    // Always Frag-Needed with a 1-byte-lower hint: bounded by max_steps_per_hop per TTL.
    const Lower = struct {
        calls: usize = 0,
        fn f(ctx: *anyopaque, _: u8, size: u16) HopOutcome {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            return .{ .frag_needed = .{ .hint = size - 1, .from = null } };
        }
    };
    var l: Lower = .{};
    var out: [8]Hop = undefined;
    const r = try hopsWith(.{ .ctx = &l, .probeFn = Lower.f }, .{ .floor = 68, .ceiling = 9000, .max_hops = 5 }, &out);
    try testing.expect(!r.reached);
    try testing.expect(l.calls <= 5 * (max_steps_per_hop + 2));
}

test "hopsWith: a forged hint above the failed size is ignored, a smaller one can only shrink the answer" {
    // The path's real narrowest link is 1400; every Frag-Needed claims 9000 (above) or 100 (below).
    const Forge = struct {
        hint: u32,
        fn f(ctx: *anyopaque, ttl: u8, size: u16) HopOutcome {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (ttl == 1) return .{ .time_exceeded = null };
            if (size <= 1400) return .{ .echo_reply = null };
            return .{ .frag_needed = .{ .hint = self.hint, .from = null } };
        }
    };
    for ([_]u32{ 9000, 100, 0, std.math.maxInt(u32) }) |h| {
        var fg: Forge = .{ .hint = h };
        var out: [4]Hop = undefined;
        const r = try hopsWith(.{ .ctx = &fg, .probeFn = Forge.f }, .{ .floor = 68, .ceiling = 1500 }, &out);
        try testing.expect(r.reached);
        // A hint that is not below the failed size, or is absent, changes nothing. A forged
        // SMALLER one can only make the answer smaller (RFC 8201 section 4 allows a decrease), and
        // the answer is still a size that was probed and answered, never the forgery unprobed.
        if (h == 100) try testing.expectEqual(@as(u16, 100), r.mtu) else try testing.expectEqual(@as(u16, 1400), r.mtu);
    }
}

test "hopsWith: bounds and refusals" {
    var out: [4]Hop = undefined;
    var dummy: u8 = 0;
    const P = struct {
        fn f(_: *anyopaque, _: u8, _: u16) HopOutcome {
            return .{ .echo_reply = null };
        }
    };
    const pr: HopProber = .{ .ctx = &dummy, .probeFn = P.f };
    try testing.expectError(error.CeilingTooLow, hopsWith(pr, .{ .floor = 1280, .ceiling = 1280 }, &out));
    try testing.expectError(error.NoHops, hopsWith(pr, .{ .floor = 68, .ceiling = 1500, .max_hops = 0 }, &out));
    try testing.expectError(error.NoHops, hopsWith(pr, .{ .floor = 68, .ceiling = 1500 }, out[0..0]));
    // max_hops above the slice is capped by the slice.
    const Te = struct {
        fn f(_: *anyopaque, _: u8, _: u16) HopOutcome {
            return .{ .time_exceeded = null };
        }
    };
    const r = try hopsWith(.{ .ctx = &dummy, .probeFn = Te.f }, .{ .floor = 68, .ceiling = 1500, .max_hops = 255 }, &out);
    try testing.expectEqual(@as(usize, 4), r.hops.len);
    // max_silent_hops = 0 behaves as 1, never as "no limit".
    const S = struct {
        fn f(_: *anyopaque, _: u8, _: u16) HopOutcome {
            return .send_failed;
        }
    };
    const r2 = try hopsWith(.{ .ctx = &dummy, .probeFn = S.f }, .{ .floor = 68, .ceiling = 1500, .max_silent_hops = 0 }, &out);
    try testing.expectEqual(@as(usize, 1), r2.hops.len);
}

test "hopsWith: property -- the reported MTU equals the smallest link over a range of paths, with and without hints" {
    var prng = std.Random.DefaultPrng.init(0x7061);
    const rnd = prng.random();
    for (0..300) |_| {
        var links: [3]u16 = undefined;
        for (&links) |*l| l.* = rnd.intRangeAtMost(u16, 69, 1500);
        var fp: FakePath = .{ .addrs = &test_addrs, .links = &links, .hint = rnd.boolean(), .explicit = rnd.boolean() };
        var out: [8]Hop = undefined;
        const r = try hopsWith(fp.prober(), .{ .floor = 68, .ceiling = 1500 }, &out);
        try testing.expect(r.reached);
        var smallest: u16 = 1500;
        for (links) |l| smallest = @min(smallest, l);
        try testing.expectEqual(smallest, r.mtu);
        for (r.hops[1..], 1..) |h, i| try testing.expect(h.mtu <= r.hops[i - 1].mtu);
    }
}

/// Link 1400 on TTL 2 and beyond, sizes above it silent (a black hole), plus
/// scripted loss: the call numbers in `lose` (counted over the whole walk) get no
/// answer whatever the size.
const LossyPath = struct {
    lose: []const usize,
    calls: usize = 0,
    fn prober(self: *LossyPath) HopProber {
        return .{ .ctx = self, .probeFn = f };
    }
    fn f(ctx: *anyopaque, ttl: u8, size: u16) HopOutcome {
        const self: *LossyPath = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        for (self.lose) |c| if (c == self.calls) return .no_reply;
        if (ttl == 1) return .{ .time_exceeded = null };
        if (size > 1400) return .no_reply;
        return if (ttl == 2) .{ .time_exceeded = null } else .{ .echo_reply = null };
    }
};

test "hopsWith: a lost probe at the edge gives 1398 or 1399 for a 1400 link, flagged uncertain, never claimed" {
    // The bisection from 1500 asks (ttl 2): 1500, floor, 784, 1142, 1321, 1410, 1365, 1387, 1398, 1404, 1401, 1399.
    // Call numbers: ttl 1 is call 1; ttl 2 starts at 2, so the probe of 1399 is call 2 + 11 = 13.
    var lp: LossyPath = .{ .lose = &.{13} };
    var out: [8]Hop = undefined;
    const r = try hopsWith(lp.prober(), .{ .floor = 68, .ceiling = 1500 }, &out);
    try testing.expect(r.reached);
    try testing.expect(r.uncertain);
    try testing.expect(r.hops[1].silence_narrowed);
    try testing.expect(r.hops[1].proved);
    // The re-probe of the failed edge answered: 1399, one under the link, flagged.
    try testing.expectEqual(@as(u16, 1399), r.hops[1].mtu);
    try testing.expectEqual(@as(u16, 1399), r.mtu);
}

test "hopsWith: persistent loss at the edge ends one under, flagged; the estimate carries on" {
    var lp: LossyPath = .{ .lose = &.{ 13, 14 } };
    var out: [8]Hop = undefined;
    const r = try hopsWith(lp.prober(), .{ .floor = 68, .ceiling = 1500 }, &out);
    try testing.expect(r.uncertain and r.blackhole);
    try testing.expectEqual(@as(u16, 1398), r.hops[1].mtu);
    try testing.expectEqual(@as(u16, 1398), r.hops[2].mtu); // carried to the destination
    try testing.expect(r.hops[2].is_destination);
}

test "hopsWith: a clean path claims no uncertainty; unproved hops say so" {
    var fp: FakePath = .{ .addrs = &test_addrs, .links = &.{ 1500, 1400, 1500 } };
    var out: [8]Hop = undefined;
    const r = try hopsWith(fp.prober(), .{ .floor = 68, .ceiling = 1500 }, &out);
    try testing.expect(!r.uncertain);
    for (r.hops) |h| try testing.expect(h.proved and !h.silence_narrowed);
    // A silent hop, a failed send and an exhausted budget are not proved.
    var fs: FakePath = .{ .addrs = &test_addrs, .links = &.{ 1500, 1500, 1500 }, .silent = &.{ false, true, false } };
    const r2 = try hopsWith(fs.prober(), .{ .floor = 68, .ceiling = 1500 }, &out);
    try testing.expect(!r2.hops[1].proved and r2.hops[0].proved);
    const SF = struct {
        fn f(_: *anyopaque, _: u8, _: u16) HopOutcome {
            return .send_failed;
        }
    };
    var d: u8 = 0;
    const r3 = try hopsWith(.{ .ctx = &d, .probeFn = SF.f }, .{ .floor = 68, .ceiling = 1500 }, &out);
    try testing.expect(!r3.hops[0].proved);
}
