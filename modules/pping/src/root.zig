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
//! **Status: complete — harness and core both implemented.** The bounded
//! `TsTable` (`table.zig`, full test suite: insert/lookup/remove/aging/
//! capacity-eviction-primitives/bounded-memory-under-a-long-stream), the TCP
//! Timestamps option parser (`parse.zig`, KAT corpus + a fuzz-style hostile-
//! input test proving it never reads out of bounds), and this file's
//! `Estimator` shell (construction, reset, table-occupancy accessors) are
//! all real and pass today. The irreducible algorithm itself,
//! **`match.matchEcho`** (`src/match.zig`), is also implemented (no longer a
//! stub) per the full contract documented on that function (first-echo
//! consume, exact-value match, insert-if-first, aging-before-capacity-
//! eviction). `gate.fable_core_implemented` is `true`, so the tests that
//! call it transitively (via `Estimator.observe` — see `kat.zig` /
//! `property.zig`) run for real and report PASS, not SKIP.
//!
//! Provenance: models the Pollere pping technique (Kathleen Nichols,
//! <https://github.com/pollere/pping>) and RFC 7323 (TCP Extensions for
//! High Performance) §3's Timestamps option. Clean-room from the published
//! technique/spec — no pping source consulted or copied; see ../../NOTICE.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const meta = .{
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

/// One emitted round-trip-time measurement.
pub const RttSample = struct {
    /// Elapsed time between the matched TSval first being observed and its
    /// TSecr echo arriving — same unit as `Observation.now` / `Config.max_age`.
    rtt: u64,
    /// The TSval that was matched (useful for correlating a sample back to
    /// a specific segment, e.g. in a trace/log).
    tsval: u32,
    /// The `Observation.now` of the echo that completed the match (i.e. the
    /// time the sample became available, not the time the RTT started).
    at: u64,
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
    /// Total `observe` calls since `init`/`reset` (matches + non-matches).
    observations_total: u64 = 0,

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
    }

    /// Fold one observation in. Locates the two relevant tables (this
    /// observation's own direction for a possible insert, the opposite
    /// direction for a possible echo match) and delegates the actual
    /// decision to `match.matchEcho` — see that function's doc for exactly
    /// what it does with them. Returns the emitted `RttSample`, if this
    /// observation completed a round trip.
    pub fn observe(self: *Estimator, obs: Observation) ?RttSample {
        self.observations_total += 1;
        const same = &self.tables[@intFromEnum(obs.dir)];
        const opp = &self.tables[@intFromEnum(obs.dir.opposite())];
        const sample = match.matchEcho(same, opp, self.cfg, obs);
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

test "smoke: fable_core_implemented resolves and is true once the core is in" {
    try testing.expectEqual(true, fable_core_implemented);
}

test "smoke: parseTcpTimestamps and matchEcho are reachable as re-exports (no stub call)" {
    const bytes = [_]u8{ 8, 10, 0, 0, 0, 1, 0, 0, 0, 2 };
    const ts = parseTcpTimestamps(&bytes).?;
    try testing.expectEqual(@as(u32, 1), ts.tsval);
    _ = matchEcho; // resolved as a value (function pointer), never called here
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
}
