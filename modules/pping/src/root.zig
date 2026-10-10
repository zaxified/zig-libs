// SPDX-License-Identifier: MIT
//! pping — Pollere-style passive RTT estimation from TCP timestamp echoes.
//!
//! A network observation point (e.g. a tap, a router, a middlebox — anything
//! that can see both directions of a TCP flow, without being an endpoint of
//! it) derives round-trip time with ZERO active probing, by watching the
//! flow's own RFC 7323 TCP Timestamps option: every segment that carries the
//! option asserts a TSval ("my clock reads this now") and echoes a TSecr
//! ("the last TSval I validly received from you"). Because a TSecr value is
//! only ever a TSval the OTHER side actually sent, matching a TSecr you see
//! going one way back to the TSval that produced it — seen going the OTHER
//! way, earlier — recovers exactly the elapsed round-trip time between them,
//! with no cooperation from either endpoint and no synthetic traffic
//! injected onto the wire. This is Kathleen Nichols' pping technique
//! (Pollere LLC): <https://github.com/pollere/pping>.
//!
//! **The algorithm, precisely:**
//!   - Per flow, per direction, maintain a bounded table mapping
//!     `tsval -> first_seen_time`, storing only the FIRST time each distinct
//!     TSval was observed going that way (see `table.TsTable`).
//!   - When a packet arrives going the OPPOSITE direction carrying
//!     `tsecr = T`, and that opposite direction's table has an entry for
//!     `tsval == T`, emit an RTT sample `now - stored_time`.
//!   - **First-echo-only rule:** the moment a match is found, the matched
//!     entry is CONSUMED (deleted) — not just read. A later segment that
//!     re-echoes the same TSecr value (a delayed ACK, a duplicate ACK from
//!     loss/reordering, a keepalive) finds nothing there and correctly
//!     produces no second, inflated sample. Without this rule, every
//!     duplicate echo of an already-matched TSval would masquerade as a
//!     fresh (and wrong) RTT measurement.
//!   - **Bounded memory:** each (flow, direction) table has a fixed
//!     capacity (`Config.capacity`, allocated once, never grown) and ages
//!     out entries older than `Config.max_age` — a TSval nobody echoes
//!     within a few worst-case RTTs is never coming back and must not be
//!     remembered forever.
//!   - Matching is exact-value equality on the 32-bit TSval, which is what
//!     makes the whole scheme agnostic to each host's TSval clock tick rate
//!     (RFC 7323 §5.3 deliberately leaves this host-specific) and immune to
//!     TSval wraparound concerns that a subtraction/ordering-based
//!     comparison would have to reason about.
//!
//! **ICMP / ICMPv6 Echo.** The same table answers ping traffic: an Echo
//! Request's (identifier, sequence) is stored the way a TSval is, and the
//! Echo Reply carrying the same pair going the other way is the echo that
//! consumes it (`Estimator.observeEcho`, `match.matchEchoReply`, decoder in
//! `echo.zig`). Samples come out as the same `RttSample`, tagged by `proto`.
//!
//! **Status (core scope: TCP Timestamps and ICMP/ICMPv6 Echo, one flow per
//! estimator).** The bounded `TsTable` (`table.zig`), the TCP Timestamps
//! option parser (`parse.zig`), the ICMP/IP echo decoder (`echo.zig`), the
//! matching core (`match.matchEcho`, `match.matchEchoReply`) and this file's
//! `Estimator` are implemented and tested; QUIC spin bit, a multi-flow table
//! and output formats are not (README, Backlog). `gate.fable_core_implemented`
//! is a leftover switch from when `matchEcho` was a stub; it is `true`.
//!
//! Provenance: models the Pollere pping technique (Kathleen Nichols,
//! <https://github.com/pollere/pping>) and RFC 7323 (TCP Extensions for
//! High Performance) §3's Timestamps option. Clean-room from the published
//! technique/spec — no pping source consulted or copied; see ../../../NOTICE.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Passive RTT estimation from TCP TSval/TSecr echo matching (RFC 7323 / Pollere pping) and ICMP/ICMPv6 echo request/reply pairing — bounded per-direction table, no double-counting of duplicate ACKs or duplicate replies",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "Pollere pping passive RTT — TCP TSval/TSecr echo matching (RFC 7323)",
    .deps = .{},
};

// ── public API ──────────────────────────────────────────────────────────────

const table_mod = @import("table.zig");
pub const TsTable = table_mod.TsTable;
pub const TsEntry = table_mod.Entry;

const parse = @import("parse.zig");
pub const parseTcpTimestamps = parse.parseTcpTimestamps;
pub const TcpTimestamps = parse.Timestamps;

/// FABLE tier — see `match.zig`. `matchEcho` is the irreducible algorithm;
/// everything else in this module (below) is fully real today.
const match = @import("match.zig");
pub const matchEcho = match.matchEcho;
pub const matchEchoReply = match.matchEchoReply;

const echo_mod = @import("echo.zig");
pub const IcmpEcho = echo_mod.IcmpEcho;
pub const IcmpFamily = echo_mod.Family;
pub const EchoKind = echo_mod.Kind;
pub const IpAddr = echo_mod.IpAddr;
pub const IpEcho = echo_mod.IpEcho;
pub const EchoParseError = echo_mod.ParseError;
pub const parseIcmpEcho = echo_mod.parseIcmpEcho;
pub const parseIpEcho = echo_mod.parseIpEcho;
pub const max_ipv6_extension_headers = echo_mod.max_ipv6_extension_headers;

const gate = @import("gate.zig");
/// Flip once `match.zig`'s `matchEcho` is a real implementation — see `gate.zig`.
pub const fable_core_implemented = gate.fable_core_implemented;

/// Which way an `Observation` is traveling, relative to the two ends of the
/// flow an `Estimator` instance is tracking. `pping` does not care which
/// side is "the client" — only that the two directions are consistently
/// labeled by the caller across the flow's lifetime.
pub const Direction = enum {
    a_to_b,
    b_to_a,

    /// The other direction of the same flow.
    pub fn opposite(self: Direction) Direction {
        return switch (self) {
            .a_to_b => .b_to_a,
            .b_to_a => .a_to_b,
        };
    }
};

/// A caller-supplied identifier for the flow an `Estimator` is tracking
/// (e.g. a 4-tuple hash, a connection-table index — whatever the caller
/// already uses to demultiplex packets to flows). `pping` itself is
/// **flow-key-agnostic**: one `Estimator` instance already represents ONE
/// flow's both directions (see `Estimator` below), so nothing in this
/// module ever stores, compares, or hashes a `FlowKey` — a caller tracking
/// many concurrent flows keeps its own `HashMap(FlowKey, Estimator)` (or
/// equivalent) externally. This `u64` alias is offered only as a
/// convenient default for callers with no reason to invent their own type;
/// substituting a caller-defined struct changes nothing about how
/// `Estimator` is used.
pub const FlowKey = u64;

/// Bounded-memory + aging knobs for one direction's `TsTable`. Both fields
/// are consumed entirely by `match.matchEcho` (see that function's doc for
/// the exact eviction policy) — this struct just declares and documents the
/// shape of the tuning surface.
pub const Config = struct {
    /// Maximum number of distinct, not-yet-matched TSvals retained per
    /// (flow, direction) table at once. `Estimator.init` allocates each of
    /// the flow's two `TsTable`s to exactly this size, ONE TIME — the
    /// allocation never grows, regardless of how long the observed stream
    /// runs (see `table.TsTable`'s module doc). Size this to comfortably
    /// exceed the flow's expected bandwidth-delay product in segments (how
    /// many distinct TSvals can be in flight, unacknowledged, at once).
    capacity: usize = 256,
    /// Maximum age, in the same abstract time unit as `Observation.now`
    /// (nanoseconds, milliseconds, simulated ticks — `pping` never reads a
    /// wall clock itself, so the unit is entirely the caller's choice), a
    /// stored-but-unmatched TSval entry may reach before
    /// `match.matchEcho`'s aging sweep evicts it. Bounds memory over TIME
    /// (even below `capacity`, e.g. on a flow with one direction stalled)
    /// and, as a side effect, bounds the largest RTT any `RttSample` can
    /// ever report. Set this to a small multiple of the flow's expected
    /// worst-case RTT.
    max_age: u64 = 60_000,
};

/// Which matching rule produced an `RttSample`.
pub const Proto = enum {
    /// TCP Timestamps: a TSecr matched the TSval it echoes (`Estimator.observe`).
    tcp_timestamps,
    /// ICMP Echo Reply (type 0) matched an Echo Request (type 8) (`observeEcho`).
    icmp_echo,
    /// ICMPv6 Echo Reply (129) matched an Echo Request (128) (`observeEcho`).
    icmpv6_echo,
};

/// One emitted round-trip-time measurement.
pub const RttSample = struct {
    /// Elapsed time between the matched TSval (or Echo Request) first being
    /// observed and its echo arriving — same unit as `Observation.now` /
    /// `Config.max_age`.
    rtt: u64,
    /// The value that was matched (useful for correlating a sample back to a
    /// specific packet, e.g. in a trace/log): the TSval for `.tcp_timestamps`;
    /// for the echo protocols, `identifier << 16 | sequence` — see
    /// `echoIdentifier` / `echoSequence`.
    tsval: u32,
    /// The `Observation.now` of the echo that completed the match (i.e. the
    /// time the sample became available, not the time the RTT started).
    at: u64,
    /// Which matching rule produced this sample.
    proto: Proto = .tcp_timestamps,

    /// The Echo identifier of an `.icmp_echo` / `.icmpv6_echo` sample.
    pub fn echoIdentifier(self: RttSample) u16 {
        return @truncate(self.tsval >> 16);
    }

    /// The Echo sequence number of an `.icmp_echo` / `.icmpv6_echo` sample.
    pub fn echoSequence(self: RttSample) u16 {
        return @truncate(self.tsval);
    }
};

/// One decoded ICMP / ICMPv6 Echo message fed to `Estimator.observeEcho`.
/// `echo` comes from `parseIpEcho` / `parseIcmpEcho`; `dir` is the direction
/// the packet traveled, labeled consistently for the flow (an `IpEcho` can
/// pick one with `IpEcho.direction`); `now` is as in `Observation`.
pub const EchoObservation = struct {
    dir: Direction,
    echo: IcmpEcho,
    now: u64,
};

/// One parsed packet-level fact fed to `Estimator.observe`: the direction it
/// traveled, its TCP Timestamps option value (both fields are always
/// present together on the wire — RFC 7323 §3.2's option carries TSval and
/// TSecr as one unit, see `parseTcpTimestamps`), and the caller's clock
/// reading at observation time.
pub const Observation = struct {
    dir: Direction,
    tsval: u32,
    tsecr: u32,
    /// Caller-supplied clock reading, same unit as `Config.max_age`. Should
    /// be monotonically non-decreasing across a sequence of calls to the
    /// same `Estimator` for `RttSample.rtt` to be meaningful, but a caller
    /// that violates this cannot crash `Estimator`/`TsTable` — aging uses a
    /// saturating age calculation (see `TsTable.evictOlderThan`) precisely
    /// so out-of-order `now` values degrade to "nothing evicted" rather
    /// than undefined behavior.
    now: u64,
};

/// Tracks ONE flow's both directions and emits `RttSample`s as TSecr echoes
/// arrive. Owns two fixed-capacity `TsTable`s (one per `Direction`),
/// allocated once at `init` and never grown — see `Config.capacity`. All
/// bookkeeping in THIS type beyond owning the tables (construction,
/// counters, table-occupancy accessors) is mechanical; the actual
/// match/consume/insert/evict decision on every observation is delegated to
/// `match.matchEcho` — see that function's doc for the design contract it
/// must satisfy.
///
/// A caller tracking many concurrent flows keeps one `Estimator` per flow,
/// indexed by whatever `FlowKey` it chooses (see `FlowKey`'s doc) —
/// `Estimator` itself has no notion of a flow identity beyond "the two
/// directions I was constructed with".
pub const Estimator = struct {
    cfg: Config,
    /// Indexed by `@intFromEnum(Direction)`. `tables[@intFromEnum(d)]`
    /// holds the TSvals seen going direction `d`; a TSecr seen going `d`
    /// is matched against `tables[@intFromEnum(d.opposite())]`.
    tables: [2]TsTable,
    /// Total `RttSample`s this estimator has emitted since `init`/`reset`.
    samples_emitted: u64 = 0,
    /// Total `observe` / `observeEcho` calls since `init`/`reset` (matches,
    /// non-matches and refused calls).
    observations_total: u64 = 0,
    /// What this estimator's tables hold, fixed by the first `observe` (TCP
    /// TSvals) or `observeEcho` (echo keys) after `init`/`reset`. The two key
    /// spaces are both `u32` and would collide in one table, so a call of the
    /// other kind afterwards is refused — returns `null`, changes no table and
    /// counts in `observations_refused`. A ping flow is its own flow: give it
    /// its own `Estimator`.
    traffic: Traffic = .unset,
    /// Calls refused because they did not match `traffic`.
    observations_refused: u64 = 0,

    pub const Traffic = enum { unset, tcp_timestamps, icmp_echo };

    /// Allocate both directions' tables at `cfg.capacity`. The allocation
    /// happens exactly once, here — nothing later in this type's lifetime
    /// (re)allocates (see `Config.capacity`'s doc).
    pub fn init(gpa: Allocator, cfg: Config) Allocator.Error!Estimator {
        var tables: [2]TsTable = undefined;
        tables[0] = try TsTable.init(gpa, cfg.capacity);
        errdefer tables[0].deinit(gpa);
        tables[1] = try TsTable.init(gpa, cfg.capacity);
        return .{ .cfg = cfg, .tables = tables };
    }

    /// Free both directions' table storage. `self` must not be used afterward.
    pub fn deinit(self: *Estimator, gpa: Allocator) void {
        for (&self.tables) |*t| t.deinit(gpa);
        self.* = undefined;
    }

    /// Empty both tables and zero the counters; capacity/allocation is kept
    /// (mirrors `TsTable.reset`).
    pub fn reset(self: *Estimator) void {
        for (&self.tables) |*t| t.reset();
        self.samples_emitted = 0;
        self.observations_total = 0;
        self.traffic = .unset;
        self.observations_refused = 0;
    }

    fn admit(self: *Estimator, want: Traffic) bool {
        if (self.traffic == .unset) self.traffic = want;
        if (self.traffic == want) return true;
        self.observations_refused += 1;
        return false;
    }

    /// Fold one observation in. Locates the two relevant tables (this
    /// observation's own direction for a possible insert, the opposite
    /// direction for a possible echo match) and delegates the actual
    /// decision to `match.matchEcho` — see that function's doc for exactly
    /// what it does with them. Returns the emitted `RttSample`, if this
    /// observation completed a round trip.
    pub fn observe(self: *Estimator, obs: Observation) ?RttSample {
        self.observations_total += 1;
        if (!self.admit(.tcp_timestamps)) return null;
        const same = &self.tables[@intFromEnum(obs.dir)];
        const opp = &self.tables[@intFromEnum(obs.dir.opposite())];
        const sample = match.matchEcho(same, opp, self.cfg, obs);
        if (sample != null) self.samples_emitted += 1;
        return sample;
    }

    /// Fold one ICMP / ICMPv6 Echo message in (see `match.matchEchoReply`):
    /// a request is remembered by (identifier, sequence) in its direction's
    /// table, a reply going the other way consumes it and returns the sample.
    /// Duplicate replies, unmatched replies and requests return `null`.
    /// Refused (returns `null`, touches nothing) on an estimator already
    /// fed TCP observations — see `traffic`.
    pub fn observeEcho(self: *Estimator, obs: EchoObservation) ?RttSample {
        self.observations_total += 1;
        if (!self.admit(.icmp_echo)) return null;
        const same = &self.tables[@intFromEnum(obs.dir)];
        const opp = &self.tables[@intFromEnum(obs.dir.opposite())];
        const sample = match.matchEchoReply(same, opp, self.cfg, obs);
        if (sample != null) self.samples_emitted += 1;
        return sample;
    }

    /// Current occupancy of the table for direction `dir` (`<= cfg.capacity`,
    /// always — see `TsTable.insert`'s `error.Full` guarantee).
    pub fn tableCount(self: *const Estimator, dir: Direction) usize {
        return self.tables[@intFromEnum(dir)].count();
    }
};

// ── smoke: the shell works WITHOUT ever touching the Fable stub ─────────────

const testing = std.testing;

test "smoke: Direction.opposite is its own inverse" {
    try testing.expectEqual(Direction.b_to_a, Direction.a_to_b.opposite());
    try testing.expectEqual(Direction.a_to_b, Direction.b_to_a.opposite());
}

test "smoke: Estimator constructs with defaults, both tables empty, counters zero" {
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), est.tableCount(.a_to_b));
    try testing.expectEqual(@as(usize, 0), est.tableCount(.b_to_a));
    try testing.expectEqual(@as(u64, 0), est.samples_emitted);
    try testing.expectEqual(@as(u64, 0), est.observations_total);
}

test "smoke: Estimator honors a custom capacity for both directions' tables" {
    var est = try Estimator.init(testing.allocator, .{ .capacity = 7 });
    defer est.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 7), est.tables[0].capacity());
    try testing.expectEqual(@as(usize, 7), est.tables[1].capacity());
}

test "smoke: Estimator.reset empties tables and zeroes counters without touching capacity" {
    var est = try Estimator.init(testing.allocator, .{ .capacity = 4 });
    defer est.deinit(testing.allocator);
    // Poke the tables directly (mechanical TsTable API — no Fable stub
    // involved) to prove reset genuinely clears state, without needing
    // `observe`/`matchEcho`.
    try est.tables[@intFromEnum(Direction.a_to_b)].insert(1, 100);
    est.samples_emitted = 3;
    est.observations_total = 5;
    est.reset();
    try testing.expectEqual(@as(usize, 0), est.tableCount(.a_to_b));
    try testing.expectEqual(@as(usize, 0), est.tableCount(.b_to_a));
    try testing.expectEqual(@as(u64, 0), est.samples_emitted);
    try testing.expectEqual(@as(u64, 0), est.observations_total);
    try testing.expectEqual(@as(usize, 4), est.tables[0].capacity());
}

test "smoke: observe() increments observations_total by exactly one per call" {
    // Regression: no existing test ever checked observations_total's actual
    // increment behavior via observe() -- only that it starts (and resets
    // back to) zero. A mutation double-counting (or never counting) survived
    // the whole suite.
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);
    _ = est.observe(.{ .dir = .a_to_b, .tsval = 1, .tsecr = 0, .now = 0 });
    try testing.expectEqual(@as(u64, 1), est.observations_total);
    _ = est.observe(.{ .dir = .b_to_a, .tsval = 2, .tsecr = 1, .now = 10 });
    try testing.expectEqual(@as(u64, 2), est.observations_total);
    _ = est.observe(.{ .dir = .a_to_b, .tsval = 3, .tsecr = 0, .now = 20 });
    try testing.expectEqual(@as(u64, 3), est.observations_total);
}

test "smoke: fable_core_implemented resolves and is true once the core is in" {
    try testing.expectEqual(true, fable_core_implemented);
}

test "smoke: parseTcpTimestamps and matchEcho are reachable as re-exports (no stub call)" {
    const bytes = [_]u8{ 8, 10, 0, 0, 0, 1, 0, 0, 0, 2 };
    const ts = parseTcpTimestamps(&bytes).?;
    try testing.expectEqual(@as(u32, 1), ts.tsval);
    _ = matchEcho; // resolved as a value (function pointer), never called here
}

// ── fuzz: a hostile observation stream into one estimator ───────────────────

const fz = @import("fuzz_test.zig");
const StreamMark = fz.Marker(enum {
    sample,
    no_match,
    duplicate_echo_silent,
    capacity_pressed,
    aged_out,
    backwards_clock,
    genuine_roundtrip,
    echo_sample,
    mixed_refused,
});

test "fuzz: an observation stream keeps the tables bounded, consumes the first echo only" {
    try std.testing.fuzz({}, fuzzStreamSmith, .{});
}

test "fuzz driver: PPING_FUZZ (estimator)" {
    try fz.fuzz_driver.run(fuzzStream, .{ .prefix = "PPING_FUZZ", .name = "pping-estimator" });
}

test "fuzz harness: estimator, 300 seeds, reaches every outcome" {
    try StreamMark.reach(fuzzStream, "pping-estimator", 300);
}

fn fuzzStreamSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzStream(std.testing.Smith, smith, testing.allocator);
}

/// One estimator on a small TSval space (so echoes collide with sends), a tiny
/// capacity and max_age (so capacity eviction and aging both fire), and a clock
/// that mostly advances and sometimes steps backwards (which must degrade to
/// "nothing evicted", never a panic). Checked after every step: occupancy stays
/// within capacity; a sample's `at` is the observation's clock, its `tsval` was
/// sent in the opposite direction, and its `rtt` lies between "now minus the
/// last time that value was sent" and "now minus the first"; an echo is
/// consumed once -- a second sample for the same send is an error. At the start
/// a genuine round trip (send, echo within max_age) must yield exactly its RTT.
fn fuzzStream(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const cfg: Config = .{ .capacity = src.valueRangeAtMost(u8, 1, 8), .max_age = src.valueRangeAtMost(u8, 1, 30) };
    var est = try Estimator.init(gpa, cfg);
    defer est.deinit(gpa);
    var echo_est = try Estimator.init(gpa, cfg);
    defer echo_est.deinit(gpa);

    var now: u64 = src.valueRangeAtMost(u8, 0, 50);
    // Model: per direction and TSval, the earliest and latest time it was sent
    // since it went live, and whether a send is still unconsumed.
    const Slot = struct { first: u64 = 0, last: u64 = 0, sent: bool = false, live: bool = false };
    var model: [2][16]Slot = @splat(@splat(.{}));

    if (src.value(bool)) {
        // Genuine round trip on a fresh estimator.
        const x = src.value(u32);
        const delay: u64 = src.valueRangeAtMost(u8, 0, @intCast(cfg.max_age));
        _ = est.observe(.{ .dir = .a_to_b, .tsval = x, .tsecr = 0, .now = now });
        const got = est.observe(.{ .dir = .b_to_a, .tsval = x +% 1, .tsecr = x, .now = now + delay }) orelse
            return error.GenuineRoundTripNoSample;
        if (got.rtt != delay or got.tsval != x or got.at != now + delay) return error.GenuineRoundTripWrongSample;
        // The echo is consumed: its duplicate yields nothing.
        if (est.observe(.{ .dir = .b_to_a, .tsval = x +% 2, .tsecr = x, .now = now + delay }) != null) return error.DuplicateEchoSampled;
        StreamMark.mark(.genuine_roundtrip);
        est.reset();
    }

    const steps = src.valueRangeAtMost(u8, 1, 60);
    for (0..steps) |_| {
        const adv = src.valueRangeAtMost(u8, 0, 12);
        if (src.valueRangeAtMost(u8, 0, 19) == 0) {
            now -|= adv;
            StreamMark.mark(.backwards_clock);
        } else now += adv;
        const dir: Direction = if (src.value(bool)) .a_to_b else .b_to_a;
        const di = @intFromEnum(dir);
        const oi = @intFromEnum(dir.opposite());
        const tsval = src.valueRangeAtMost(u8, 0, 15);
        const tsecr = src.valueRangeAtMost(u8, 0, 15);
        if (src.valueRangeAtMost(u8, 0, 9) == 0) {
            // Echo traffic on its own estimator, plus a mixed call that must be refused.
            const e: IcmpEcho = .{
                .family = if (src.value(bool)) .v4 else .v6,
                .kind = if (src.value(bool)) .request else .reply,
                .identifier = src.valueRangeAtMost(u8, 0, 3),
                .sequence = src.valueRangeAtMost(u8, 0, 3),
            };
            if (echo_est.observeEcho(.{ .dir = dir, .echo = e, .now = now })) |smp| {
                StreamMark.mark(.echo_sample);
                if (smp.at != now or smp.proto == .tcp_timestamps) return error.EchoSampleWrong;
            }
            const before = echo_est.observations_refused;
            if (echo_est.traffic == .icmp_echo) {
                if (echo_est.observe(.{ .dir = dir, .tsval = tsval, .tsecr = tsecr, .now = now }) != null) return error.MixedCallSampled;
                if (echo_est.observations_refused != before + 1) return error.MixedCallNotCounted;
                StreamMark.mark(.mixed_refused);
            }
            for ([2]Direction{ .a_to_b, .b_to_a }) |d| if (echo_est.tableCount(d) > cfg.capacity) return error.EchoTableOverCapacity;
            continue;
        }
        const was_full = est.tableCount(dir) == cfg.capacity;
        const got = est.observe(.{ .dir = dir, .tsval = tsval, .tsecr = tsecr, .now = now });
        if (got) |smp| {
            StreamMark.mark(.sample);
            const m = &model[oi][tsecr];
            if (!m.sent or !m.live) return error.SampleForUnsentOrConsumedEcho;
            if (smp.at != now or smp.tsval != tsecr or smp.proto != .tcp_timestamps) return error.SampleFieldsWrong;
            // rtt = now - first_seen of the entry, and first_seen is one of the sends.
            if (now >= m.first) {
                if (smp.rtt > now - m.first) return error.RttAboveFirstSend;
            }
            if (now >= m.last) {
                if (smp.rtt < now - m.last) return error.RttBelowLastSend;
            }
            m.live = false;
        } else {
            StreamMark.mark(.no_match);
            if (model[oi][tsecr].live == false and model[oi][tsecr].sent) StreamMark.mark(.duplicate_echo_silent);
        }
        // This observation's own send (a duplicate TSval keeps its first-seen).
        const mine = &model[di][tsval];
        if (!mine.sent or !mine.live) {
            mine.first = now;
            mine.last = now;
        }
        // The stored entry's first-seen is one of the sends since this one
        // went live; with a clock that steps backwards that is neither the
        // earliest nor the latest in call order, so keep the range.
        mine.first = @min(mine.first, now);
        mine.last = @max(mine.last, now);
        mine.sent = true;
        mine.live = true;
        if (was_full) StreamMark.mark(.capacity_pressed);
        for ([2]Direction{ .a_to_b, .b_to_a }) |d| if (est.tableCount(d) > cfg.capacity) return error.TableOverCapacity;
        if (est.samples_emitted > est.observations_total) return error.MoreSamplesThanObservations;
    }
    if (now > cfg.max_age) StreamMark.mark(.aged_out);
}

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────────
//
// refAllDecls walks every pub declaration reachable from this file (including
// the sub-module re-exports above), which is what pulls table.zig / parse.zig
// / match.zig / gate.zig / kat.zig / property.zig's own `test` blocks into
// `zig build test-pping` — a bare `pub const x = @import("x.zig")` re-export
// alone does NOT do this (the dark-tests rule).

test {
    std.testing.refAllDecls(@This());
    _ = @import("table.zig");
    _ = @import("parse.zig");
    _ = @import("match.zig");
    _ = @import("gate.zig");
    _ = @import("kat.zig");
    _ = @import("property.zig");
    _ = @import("echo.zig");
    _ = @import("echo_kat.zig");
}
