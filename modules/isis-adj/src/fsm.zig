// SPDX-License-Identifier: MIT

//! The point-to-point adjacency state machine (ISO/IEC 10589 §8.2 + RFC 5303
//! three-way handshake) for ONE P2P neighbour.
//!
//! Pure and time-injected: the `Adjacency` owns no clock, no timer, no socket,
//! and (in the steady path) allocates nothing. The caller drives it with a
//! monotonic `now` it supplies, feeds it received P2P IIH PDUs (decoded by the
//! sibling `isis` codec), and acts on the returned `Effect` — send an IIH, raise
//! the adjacency, tear it down. Determinism: the same `(event, now)` stream
//! yields the same transitions and effects.
//!
//! ## The three-way handshake, in one paragraph
//! Two routers must each know the *other* has heard *it* before the link is
//! trusted — a plain "I heard a hello, we're up" rule half-opens on a
//! unidirectional link. RFC 5303 carries each router's view (its own three-way
//! state + a reference to the neighbour it has heard) in TLV 240. We reach **Up**
//! only when the neighbour's 240 echoes *our* (system-id, extended-local-circuit-id)
//! back to us and the neighbour is itself past Down; otherwise a heard-but-unconfirmed
//! neighbour holds us at **Initializing**. That echo test is the loop guard.
//!
//! See `../SPEC.md` for the full state × event table and the mismatch rules.

const std = @import("std");
const isis = @import("isis");
const three_way = @import("three_way.zig");

pub const ThreeWayState = three_way.ThreeWayState;
pub const ThreeWayTlv = three_way.ThreeWayTlv;
pub const Neighbor = three_way.Neighbor;

/// A caller-supplied monotonic timestamp. Abstract ticks in the caller's own
/// unit — the FSM never reads a wall clock (the repo removed `std.time`
/// timestamps). `holding_time` / `hello_interval` are in the *same* unit, so a
/// caller running in seconds sets `holding_time = 30`; one running in
/// milliseconds sets `holding_time = 30_000`. The math is purely comparison and
/// addition of these values, so the unit is the caller's to choose.
pub const Time = u64;

pub const SystemId = [6]u8;

/// The logical adjacency state (ISO 10589 §8.2). Distinct from the *wire*
/// encoding `ThreeWayState` (whose byte values are RFC 5303's up==0/down==2) —
/// this enum is in intuitive order and is what the FSM reasons in; `wireState`
/// maps it to the byte we advertise.
pub const State = enum {
    down,
    initializing,
    up,

    /// The RFC 5303 TLV-240 state byte we advertise for this logical state.
    pub fn wireState(s: State) ThreeWayState {
        return switch (s) {
            .down => .down,
            .initializing => .initializing,
            .up => .up,
        };
    }
};

/// Why an adjacency left the Up state.
pub const DownReason = enum {
    /// The neighbour's hold timer expired (no IIH within holding-time).
    hold_expired,
    /// The local circuit was administratively stopped (`stop`).
    stopped,
    /// The neighbour restarted / withdrew its confirmation of us (a received
    /// IIH that no longer echoes us, dropping Up → Initializing).
    neighbor_restarted,
};

/// Why a received IIH was ignored without changing state (a soft reject — not a
/// decode error).
pub const RejectReason = enum {
    /// The IIH's source system-id equals ours: a looped-back / self hello.
    looped_back,
    /// The neighbour shares no IS level with us (circuit-type bitmask disjoint).
    level_mismatch,
    /// The circuit has not been `start`ed.
    not_started,
    /// A **third** system sent an IIH while this circuit already has a
    /// neighbour. A point-to-point circuit carries exactly ONE adjacency
    /// (ISO/IEC 10589 §8.2.4 — the P2P adjacency is the circuit's, and there is
    /// one neighbour per circuit), so an IIH whose source-id differs from the
    /// neighbour we are already tracking is not "the neighbour" and must not be
    /// acted on. Accepting it would let any unauthenticated station on the wire
    /// (an IIH carries no authentication unless TLV 10 is configured) refresh
    /// *our* hold timer with *its* chosen holding-time, overwrite the recorded
    /// neighbour, and — because it cannot echo our system-id in TLV 240 — drag
    /// the adjacency Up→Initializing on every frame. The incumbent is kept and
    /// nothing is mutated; the stranger can only be adopted once the incumbent's
    /// hold genuinely expires (`tick` → Down clears the neighbour).
    other_neighbor,
    /// The IIH's Maximum Area Addresses (common-header field, ISO/IEC 10589
    /// §9.6) differs from ours. ISO 10589 §8.2 requires such an IIH be
    /// discarded outright — the two systems disagree on how many area
    /// addresses an IS may carry, which is a numbering-plan mismatch, not a
    /// routing decision either side can paper over.
    max_area_mismatch,
    /// A Level-1-only circuit's neighbour advertised no Area Addresses (#1)
    /// TLV entry in common with `Config.local_areas`. ISO 10589 §8.2.2/§7.2.4:
    /// a Level 1 adjacency requires a shared area; Level 2 does not (an
    /// `.level1_2` circuit is left to still form its L2 component, so this
    /// check applies only to pure `.level1` circuits — see `SPEC.md` §5).
    area_mismatch,
};

pub const Transition = struct { from: State, to: State };

/// The standard hold = multiplier × hello relationship (ISO 10589 default
/// multiplier is 3, hello 10s → hold 30s).
pub const default_hello_interval: Time = 10;
pub const default_hold_multiplier: u16 = 3;

/// Static per-circuit configuration. Immutable for the life of the `Adjacency`.
pub const Config = struct {
    /// Our 6-octet system id — placed in our IIH source-id and echoed by the
    /// neighbour into its TLV 240 to complete the handshake.
    system_id: SystemId,
    /// Our 32-bit extended local circuit id (RFC 5303) — the second half of the
    /// (system-id, circuit-id) pair the neighbour must echo to bring us Up.
    extended_local_circuit_id: u32,
    /// The 1-octet Local Circuit ID carried in the P2P IIH fixed header
    /// (ISO 10589 §9.7). Independent of the 32-bit extended id above.
    local_circuit_id: u8 = 1,
    /// Which IS levels this circuit runs. Used both to stamp our outgoing IIH and
    /// for the cheap level-compatibility reject on receive.
    circuit_type: isis.pdu.CircuitType = .level1_2,
    /// Our Maximum Area Addresses (ISO/IEC 10589 §9.6), stamped on our outgoing
    /// common header and compared against a received IIH's own value on receive
    /// (§8.2: a mismatch is discarded, not merely logged).
    max_area_addresses: u8 = isis.header.default_max_area_addresses,
    /// Our area addresses (ISO 10589 §7.2.4), each a raw NSAP area prefix.
    /// Empty (the default) means area-address matching is NOT enforced — this
    /// module has no configuration source of its own, so an unconfigured area
    /// list cannot be distinguished from "matching not wanted" and the check is
    /// skipped rather than rejecting every neighbour. Only consulted for pure
    /// `.level1` circuits (see `RejectReason.area_mismatch`). The slice is
    /// borrowed, not copied: it must outlive the `Adjacency`.
    local_areas: []const []const u8 = &.{},
    /// The holding-time we advertise (neighbour multiplies nothing — it uses this
    /// verbatim as *its* hold deadline for us). Same unit as `Time`.
    holding_time: u16 = @intCast(default_hold_multiplier * default_hello_interval),
    /// How often we ask the caller to emit an IIH. Same unit as `Time`.
    hello_interval: Time = default_hello_interval,
    /// RFC 5303 three-way handshake required (the default and correct behaviour).
    /// When `false` the FSM falls back to the pre-5303 two-way rule — Up on any
    /// accepted IIH, ignoring the 240 echo. This is BOTH a legitimate
    /// interop-fallback knob AND the module's positive control: a test flips it
    /// off to prove the three-way guard has teeth (without the guard the
    /// half-open case would wrongly reach Up).
    three_way_required: bool = true,
};

/// Everything needed to build an outgoing P2P IIH, returned by the FSM so it
/// never has to own a buffer. Build the PDU yourself, or hand this to
/// `buildHello` for a one-call `isis`-encoded PDU.
pub const HelloFields = struct {
    source_id: SystemId,
    holding_time: u16,
    local_circuit_id: u8,
    circuit_type: isis.pdu.CircuitType,
    /// Our Maximum Area Addresses (ISO/IEC 10589 §9.6), stamped into the common
    /// header so a peer checking it against its own `Config.max_area_addresses`
    /// sees our real value rather than the wire default.
    max_area_addresses: u8 = isis.header.default_max_area_addresses,
    /// Our TLV 240 payload: our current state, our extended circuit id, and —
    /// once we have heard the neighbour — the neighbour block echoing it.
    three_way: ThreeWayTlv,
};

/// A received P2P IIH reduced to the fields the FSM reasons about. Produced from
/// raw bytes by `rxHelloBytes`, or built directly by a caller that already
/// decoded the PDU.
pub const RxHello = struct {
    source_id: SystemId,
    holding_time: u16,
    circuit_type: isis.pdu.CircuitType,
    local_circuit_id: u8,
    /// The neighbour's Maximum Area Addresses (common-header field). Defaults to
    /// the wire default (3) so existing callers that don't care about this check
    /// (i.e. that model a neighbour running the default) keep compiling and
    /// passing unchanged; a real `rxHelloBytes` caller always supplies the
    /// decoded value.
    max_area_addresses: u8 = isis.header.default_max_area_addresses,
    /// The neighbour's Area Addresses (#1) TLV, raw (undecoded) value bytes, if
    /// present. Only consulted when `Config.local_areas` is non-empty and the
    /// circuit is pure `.level1`. Kept raw (not eagerly parsed into owned
    /// storage) so `rxHello` stays allocation-free; a malformed inner record is
    /// treated as "no shared area found" rather than corrupting the FSM.
    neighbor_area_addresses: ?[]const u8 = null,
    /// The neighbour's TLV 240, if present. Absent means the neighbour is not
    /// speaking three-way (or omitted it): we can hear it but can never confirm
    /// the loop guard from it, so it can raise us at most to Initializing.
    three_way: ?ThreeWayTlv = null,
};

/// What changed as a result of an event. All fields are independent: a single
/// `tick` can, e.g., both expire the hold (`adjacency_down`) and be due to send
/// a fresh IIH (`send_hello`).
pub const Effect = struct {
    /// The state transition this event caused, if any.
    transition: ?Transition = null,
    /// The adjacency entered Up this call — the upper layer may start using it.
    adjacency_up: bool = false,
    /// The adjacency left Up this call — the upper layer must stop using it.
    adjacency_down: ?DownReason = null,
    /// The caller should emit a P2P IIH built from these fields now.
    send_hello: ?HelloFields = null,
    /// A received IIH was ignored for this reason (no state change).
    rejected: ?RejectReason = null,
};

pub const DecodeError = isis.pdu.DecodeError || isis.tlv.Error || three_way.DecodeError;

/// One point-to-point adjacency. Single-owner: one caller/loop drives it; it is
/// lock-free and holds no shared state.
pub const Adjacency = struct {
    cfg: Config,
    state: State = .down,
    started: bool = false,

    /// The neighbour we have heard, once we have heard one. Populated on the
    /// first accepted IIH and cleared when the adjacency falls to Down.
    neighbor_system_id: ?SystemId = null,
    /// The neighbour's extended local circuit id, from its TLV 240 (needed to
    /// fill the neighbour block in *our* outgoing 240). Absent if the neighbour
    /// sent no 240.
    neighbor_ext_circuit_id: ?u32 = null,

    /// Absolute deadline (in `now` units) past which the neighbour is considered
    /// gone. Refreshed to `now + neighbour.holding_time` on every accepted IIH.
    hold_deadline: Time = 0,
    /// Absolute time at which the next IIH is due. `tick` emits when `now` passes
    /// it and reschedules by `hello_interval`.
    next_hello_due: Time = 0,

    pub fn init(cfg: Config) Adjacency {
        return .{ .cfg = cfg };
    }

    /// The current logical state.
    pub fn currentState(self: *const Adjacency) State {
        return self.state;
    }

    /// The next-IIH due time (absolute, in `now` units). Only meaningful while
    /// started.
    pub fn nextHelloDue(self: *const Adjacency) Time {
        return self.next_hello_due;
    }

    /// Bring the circuit up. Resets to Down (no neighbour heard yet), primes the
    /// hello timer to fire immediately, and returns an `Effect` carrying that
    /// first IIH so the handshake starts without waiting a full interval.
    pub fn start(self: *Adjacency, now: Time) Effect {
        self.started = true;
        self.state = .down;
        self.neighbor_system_id = null;
        self.neighbor_ext_circuit_id = null;
        self.hold_deadline = 0;
        self.next_hello_due = now + self.cfg.hello_interval;
        return .{ .send_hello = self.helloFields() };
    }

    /// Administratively tear the circuit down. If it was Up, reports
    /// `adjacency_down = .stopped`.
    pub fn stop(self: *Adjacency) Effect {
        const prev = self.state;
        self.started = false;
        self.state = .down;
        self.neighbor_system_id = null;
        self.neighbor_ext_circuit_id = null;
        var eff: Effect = .{};
        if (prev != .down) {
            eff.transition = .{ .from = prev, .to = .down };
            if (prev == .up) eff.adjacency_down = .stopped;
        }
        return eff;
    }

    /// The fields for an outgoing IIH reflecting the current state. Our TLV 240
    /// carries the neighbour block iff we have heard the neighbour's 240 (so a
    /// non-240 neighbour never sees us claim to have completed the handshake).
    pub fn helloFields(self: *const Adjacency) HelloFields {
        var tw: ThreeWayTlv = .{
            .state = self.state.wireState(),
            .extended_local_circuit_id = self.cfg.extended_local_circuit_id,
        };
        if (self.neighbor_system_id) |sid| {
            if (self.neighbor_ext_circuit_id) |ext| {
                tw.neighbor = .{ .system_id = sid, .extended_local_circuit_id = ext };
            }
        }
        return .{
            .source_id = self.cfg.system_id,
            .holding_time = self.cfg.holding_time,
            .local_circuit_id = self.cfg.local_circuit_id,
            .circuit_type = self.cfg.circuit_type,
            .max_area_addresses = self.cfg.max_area_addresses,
            .three_way = tw,
        };
    }

    /// Advance timers. Expires the hold (→ Down) if the deadline has passed, and
    /// emits a due IIH. Both can happen in one call.
    pub fn tick(self: *Adjacency, now: Time) Effect {
        var eff: Effect = .{};
        if (!self.started) return eff;

        // Hold expiry: only meaningful once we have actually heard a neighbour
        // (hold_deadline is set on the first accepted IIH). While Down and
        // still hunting we keep emitting hellos but have no hold to expire.
        if (self.state != .down and now >= self.hold_deadline) {
            const prev = self.state;
            self.state = .down;
            self.neighbor_system_id = null;
            self.neighbor_ext_circuit_id = null;
            eff.transition = .{ .from = prev, .to = .down };
            if (prev == .up) eff.adjacency_down = .hold_expired;
        }

        if (now >= self.next_hello_due) {
            eff.send_hello = self.helloFields();
            self.next_hello_due = now + self.cfg.hello_interval;
        }
        return eff;
    }

    /// Decode raw P2P IIH bytes with the `isis` codec, extract the fields + TLV
    /// 240, and drive `rxHello`. A malformed PDU or a malformed 240 is a typed
    /// error and leaves the FSM state UNCHANGED (nothing is mutated before the
    /// decode succeeds).
    pub fn rxHelloBytes(self: *Adjacency, bytes: []const u8, now: Time) DecodeError!Effect {
        const p = try isis.P2pHello.decode(bytes);
        var tw: ?ThreeWayTlv = null;
        if (try isis.tlv.findFirst(p.tlv_bytes, three_way.tlv_code)) |val| {
            tw = try ThreeWayTlv.decode(val);
        }
        const area_addresses = try isis.tlv.findFirst(p.tlv_bytes, isis.tlvs.code.area_addresses);
        return self.rxHello(.{
            .source_id = p.source_id,
            .holding_time = p.holding_time,
            .circuit_type = p.circuit_type,
            .local_circuit_id = p.local_circuit_id,
            .max_area_addresses = p.header.max_area_addresses,
            .neighbor_area_addresses = area_addresses,
            .three_way = tw,
        }, now);
    }

    /// Process a received P2P IIH (already reduced to `RxHello`). Applies the
    /// acceptance checks, refreshes the hold timer, runs the three-way logic, and
    /// returns the resulting `Effect`. Never returns an error — a hello it will
    /// not act on comes back as `Effect.rejected` with the state untouched.
    pub fn rxHello(self: *Adjacency, rx: RxHello, now: Time) Effect {
        if (!self.started) return .{ .rejected = .not_started };

        // ── acceptance checks (ISO 10589 §8.2, the cheap ones) ──────────────
        // Loopback / self: an IIH whose source is our own system-id is a
        // reflected frame; forming on it would be a self-adjacency.
        if (std.mem.eql(u8, &rx.source_id, &self.cfg.system_id)) {
            return .{ .rejected = .looped_back };
        }
        // Level compatibility: the circuit-type low bits are a level bitmask
        // (bit0 = L1, bit1 = L2). Disjoint masks share no level → no adjacency.
        if ((@intFromEnum(rx.circuit_type) & @intFromEnum(self.cfg.circuit_type)) == 0) {
            return .{ .rejected = .level_mismatch };
        }
        // Maximum Area Addresses (ISO 10589 §8.2): a neighbour disagreeing with
        // us on how many area addresses an IS may carry is discarded outright,
        // not merely noted — the two sides are running an incompatible
        // numbering plan and nothing downstream can paper over that.
        if (rx.max_area_addresses != self.cfg.max_area_addresses) {
            return .{ .rejected = .max_area_mismatch };
        }
        // Area-address matching (ISO 10589 §8.2.2/§7.2.4): required only for a
        // Level 1 adjacency. `.level1_2` is left unchecked here because this
        // FSM tracks one combined state per circuit rather than split L1/L2
        // sub-states — rejecting a `.level1_2` circuit on an area mismatch
        // would also block the L2 component, which ISO 10589 says must still
        // form. Skipped entirely when `local_areas` is unconfigured.
        if (self.cfg.circuit_type == .level1 and self.cfg.local_areas.len != 0) {
            if (!self.sharesArea(rx.neighbor_area_addresses)) {
                return .{ .rejected = .area_mismatch };
            }
        }
        // One circuit, one neighbour (ISO/IEC 10589 §8.2.4). Once we have heard
        // a neighbour, only *that* system-id drives this adjacency. Checked
        // BEFORE any mutation, so a stranger's IIH refreshes no hold, overwrites
        // no neighbour and forces no transition — see `RejectReason.other_neighbor`.
        // The lock releases exactly when the incumbent's hold expires: `tick`
        // clears `neighbor_system_id` on the way to Down, and `start`/`stop` do
        // the same, so a genuine neighbour change still converges in one hold.
        if (self.neighbor_system_id) |incumbent| {
            if (!std.mem.eql(u8, &incumbent, &rx.source_id)) {
                return .{ .rejected = .other_neighbor };
            }
        }

        // ── accepted: refresh hold + record the neighbour ───────────────────
        self.hold_deadline = now + @as(Time, rx.holding_time);
        self.neighbor_system_id = rx.source_id;
        // Unconditional, not just when a 240 is present: an accepted IIH that
        // carries no TLV 240 at all means the neighbour has stopped (or never
        // started) speaking RFC 5303, so any previously recorded extended
        // circuit id is no longer current and must be cleared rather than left
        // stale — otherwise `helloFields` keeps advertising a neighbour block
        // for a handshake reference the peer withdrew.
        self.neighbor_ext_circuit_id = if (rx.three_way) |tw| tw.extended_local_circuit_id else null;

        // ── three-way decision ──────────────────────────────────────────────
        // echoed == the neighbour's 240 names US (our system-id AND our extended
        // circuit id) — proof it has heard us. The loop guard.
        //
        // The neighbour's extended-local-circuit-id is itself optional on the
        // wire (RFC 5303 §3.1's 11-octet shape — system-id present, extended id
        // absent; Wireshark-anchored, see three_way.zig). A bare system-id match
        // cannot disambiguate WHICH of possibly several parallel P2P circuits to
        // that neighbour this echo is about, so it does not count as echoed —
        // same ceiling as no neighbour block at all (Initializing, never Up).
        const echoed = blk: {
            const tw = rx.three_way orelse break :blk false;
            const nb = tw.neighbor orelse break :blk false;
            const nb_ext = nb.extended_local_circuit_id orelse break :blk false;
            break :blk std.mem.eql(u8, &nb.system_id, &self.cfg.system_id) and
                nb_ext == self.cfg.extended_local_circuit_id;
        };
        // The neighbour must also not itself be Down (a router that echoes us but
        // claims Down is mid-reset — hold at Initializing, don't race it to Up).
        const neighbor_past_down = if (rx.three_way) |tw| tw.state != .down else true;

        const new_state: State = if (self.cfg.three_way_required)
            (if (echoed and neighbor_past_down) .up else .initializing)
        else
            // Pre-5303 two-way fallback / positive control: trust a single
            // accepted hello. This is the DELIBERATELY WEAKER rule.
            .up;

        return self.applyState(new_state, now);
    }

    fn applyState(self: *Adjacency, new_state: State, now: Time) Effect {
        _ = now;
        const prev = self.state;
        self.state = new_state;
        var eff: Effect = .{};
        if (new_state == prev) return eff;
        eff.transition = .{ .from = prev, .to = new_state };
        if (new_state == .up) eff.adjacency_up = true;
        if (prev == .up and new_state != .up) eff.adjacency_down = .neighbor_restarted;
        return eff;
    }

    /// True iff `neighbor_tlv` (a neighbour's raw Area Addresses #1 TLV value,
    /// if any) names at least one area in common with `cfg.local_areas`. No
    /// TLV at all, or a malformed inner record, is "no shared area" (false) —
    /// fail closed rather than guess. `rxHello` cannot propagate an error, so
    /// a bad record from `AreaAddressIterator` is swallowed here rather than
    /// surfaced; a hostile PDU still cannot corrupt the FSM, it is just
    /// treated as a mismatch.
    fn sharesArea(self: *const Adjacency, neighbor_tlv: ?[]const u8) bool {
        const raw = neighbor_tlv orelse return false;
        var it = isis.tlvs.AreaAddressIterator.init(raw);
        while (true) {
            const area = it.next() catch return false;
            const a = area orelse return false;
            for (self.cfg.local_areas) |local| {
                if (std.mem.eql(u8, local, a)) return true;
            }
        }
    }
};

/// Convenience: build a complete P2P IIH into `buf` from `HelloFields`, using the
/// `isis` P2P IIH builder plus a raw TLV 240. Offered for callers that want one
/// call; the FSM itself never touches a buffer. Returns the encoded PDU slice.
pub fn buildHello(buf: []u8, f: HelloFields) error{ BufferTooSmall, ValueTooLong, MalformedTlv }![]const u8 {
    var b = isis.pdu.P2pHelloBuilder.init(buf, .{
        .source_id = f.source_id,
        .holding_time = f.holding_time,
        .local_circuit_id = f.local_circuit_id,
        .circuit_type = f.circuit_type,
        .max_area_addresses = f.max_area_addresses,
    }) catch return error.BufferTooSmall;
    var val_buf: [15]u8 = undefined;
    const val = f.three_way.encode(&val_buf) catch |e| switch (e) {
        error.MalformedTlv => return error.MalformedTlv,
        error.BufferTooSmall => unreachable, // 15 bytes always fits val_buf
    };
    b.tlvs.addTlv(three_way.tlv_code, val) catch |e| switch (e) {
        error.BufferTooSmall => return error.BufferTooSmall,
        error.ValueTooLong => return error.ValueTooLong,
    };
    return b.finish();
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const sys_a: SystemId = .{ 0, 0, 0, 0, 0, 0xA };
const sys_b: SystemId = .{ 0, 0, 0, 0, 0, 0xB };

fn cfgA() Config {
    return .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 };
}

test "start primes an immediate hello and stays Down until heard" {
    var adj = Adjacency.init(cfgA());
    const e = adj.start(0);
    try testing.expect(e.send_hello != null);
    try testing.expectEqual(State.down, adj.currentState());
    // Our first 240 has no neighbour block (we have heard no one).
    try testing.expectEqual(ThreeWayState.down, e.send_hello.?.three_way.state);
    try testing.expect(e.send_hello.?.three_way.neighbor == null);
}

test "loopback (self source-id) is rejected, no state change" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    const e = adj.rxHello(.{
        .source_id = sys_a, // == ours
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
    }, 1);
    try testing.expectEqual(RejectReason.looped_back, e.rejected.?);
    try testing.expectEqual(State.down, adj.currentState());
}

test "level mismatch (disjoint circuit-type masks) is rejected" {
    var adj = Adjacency.init(.{ .system_id = sys_a, .extended_local_circuit_id = 1, .circuit_type = .level1 });
    _ = adj.start(0);
    const e = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level2, // L1 & L2 masks are disjoint
        .local_circuit_id = 1,
    }, 1);
    try testing.expectEqual(RejectReason.level_mismatch, e.rejected.?);
    try testing.expectEqual(State.down, adj.currentState());
}

test "rxHello before start is rejected as not_started" {
    var adj = Adjacency.init(cfgA());
    const e = adj.rxHello(.{ .source_id = sys_b, .holding_time = 30, .circuit_type = .level1_2, .local_circuit_id = 1 }, 1);
    try testing.expectEqual(RejectReason.not_started, e.rejected.?);
}

// Regression (audit W2 `isis-adj` F2): ISO/IEC 10589 §8.2 requires an IIH
// whose Maximum Area Addresses differs from ours to be discarded. Before the
// fix, `RxHello` had no place to carry the field at all — `rxHelloBytes`
// decoded and then threw it away — so a neighbour advertising a different
// value reached Up exactly as if it agreed with us.
test "Maximum Area Addresses mismatch is rejected, no state change" {
    var adj = Adjacency.init(cfgA()); // cfgA: max_area_addresses defaults to 3
    _ = adj.start(0);
    const e = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .max_area_addresses = 5, // disagrees with our 3
        .three_way = .{
            .state = .initializing,
            .extended_local_circuit_id = 0xB1,
            .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 },
        },
    }, 1);
    try testing.expectEqual(RejectReason.max_area_mismatch, e.rejected.?);
    try testing.expectEqual(State.down, adj.currentState());
    try testing.expect(adj.neighbor_system_id == null);
}

// Same defect, driven end-to-end through the real `isis` wire codec (not just
// the RxHello struct literal), so the fix is proven against actual decoded
// bytes and not just against a test that happens to populate the new field.
test "rxHelloBytes rejects a real wire IIH advertising a different Maximum Area Addresses" {
    var pdu_buf: [128]u8 = undefined;
    var pb = try isis.pdu.P2pHelloBuilder.init(&pdu_buf, .{
        .source_id = sys_b,
        .holding_time = 30,
        .max_area_addresses = 5, // != cfgA()'s default of 3
    });
    var val_buf: [15]u8 = undefined;
    const tw: ThreeWayTlv = .{ .state = .initializing, .extended_local_circuit_id = 0xB1 };
    const val = try tw.encode(&val_buf);
    try pb.tlvs.addTlv(three_way.tlv_code, val);
    const wire = pb.finish();

    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    const e = try adj.rxHelloBytes(wire, 1);
    try testing.expectEqual(RejectReason.max_area_mismatch, e.rejected.?);
    try testing.expectEqual(State.down, adj.currentState());
}

// Regression (audit W2 `isis-adj` F3): a pure Level-1 P2P adjacency must not
// reach Up with a neighbour whose Area Addresses (#1) TLV shares no area with
// ours. Before the fix there was no such check at all — `SPEC.md` documented
// it as a deferred hook, but the audit's own probe showed a neighbour
// advertising a disjoint area (`49.9999` against our configured area) still
// reached Up.
test "L1 adjacency with a disjoint area is rejected once local_areas is configured" {
    const our_area = [_]u8{ 0x49, 0x00, 0x01 };
    var adj = Adjacency.init(.{
        .system_id = sys_a,
        .extended_local_circuit_id = 1,
        .circuit_type = .level1,
        .local_areas = &.{&our_area},
    });
    _ = adj.start(0);

    const disjoint_area = [_]u8{ 0x49, 0x99, 0x99 };
    const e = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1,
        .local_circuit_id = 1,
        .neighbor_area_addresses = &[_]u8{disjoint_area.len} ++ disjoint_area,
        .three_way = .{
            .state = .initializing,
            .extended_local_circuit_id = 0xB1,
            .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 1 },
        },
    }, 1);
    try testing.expectEqual(RejectReason.area_mismatch, e.rejected.?);
    try testing.expectEqual(State.down, adj.currentState());
}

test "L1 adjacency with a shared area reaches Up" {
    const our_area = [_]u8{ 0x49, 0x00, 0x01 };
    var adj = Adjacency.init(.{
        .system_id = sys_a,
        .extended_local_circuit_id = 1,
        .circuit_type = .level1,
        .local_areas = &.{&our_area},
    });
    _ = adj.start(0);

    const e = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1,
        .local_circuit_id = 1,
        .neighbor_area_addresses = &[_]u8{our_area.len} ++ our_area, // same area
        .three_way = .{
            .state = .initializing,
            .extended_local_circuit_id = 0xB1,
            .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 1 },
        },
    }, 1);
    try testing.expect(e.adjacency_up);
    try testing.expectEqual(State.up, adj.currentState());
}

// Driven end-to-end through the real `isis` codec's Area Addresses builder.
test "rxHelloBytes rejects a real wire L1 IIH with a disjoint area" {
    const our_area = [_]u8{ 0x49, 0x00, 0x01 };
    const their_area = [_]u8{ 0x49, 0x99, 0x99 };

    var pdu_buf: [128]u8 = undefined;
    var pb = try isis.pdu.P2pHelloBuilder.init(&pdu_buf, .{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1,
    });
    var val_buf: [15]u8 = undefined;
    const tw: ThreeWayTlv = .{ .state = .initializing, .extended_local_circuit_id = 0xB1 };
    const val = try tw.encode(&val_buf);
    try pb.tlvs.addTlv(three_way.tlv_code, val);
    try isis.tlvs.addAreaAddresses(&pb.tlvs, &.{&their_area});
    const wire = pb.finish();

    var adj = Adjacency.init(.{
        .system_id = sys_a,
        .extended_local_circuit_id = 1,
        .circuit_type = .level1,
        .local_areas = &.{&our_area},
    });
    _ = adj.start(0);
    const e = try adj.rxHelloBytes(wire, 1);
    try testing.expectEqual(RejectReason.area_mismatch, e.rejected.?);
    try testing.expectEqual(State.down, adj.currentState());
}

test "area matching is not enforced when local_areas is unconfigured (opt-in, no regression)" {
    // Even a pure .level1 circuit must reach Up on a disjoint area exactly as
    // before this fix, as long as `Config.local_areas` is left at its default
    // (empty) — the module has no local area list to compare against, so the
    // check is skipped rather than treated as "reject everything".
    var adj = Adjacency.init(.{
        .system_id = sys_a,
        .extended_local_circuit_id = 1,
        .circuit_type = .level1, // would gate the check ON if local_areas were set
    });
    _ = adj.start(0);
    const disjoint_area = [_]u8{ 0x49, 0x99, 0x99 };
    const e = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1,
        .local_circuit_id = 1,
        .neighbor_area_addresses = &[_]u8{disjoint_area.len} ++ disjoint_area,
        .three_way = .{
            .state = .initializing,
            .extended_local_circuit_id = 0xB1,
            .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 1 },
        },
    }, 1);
    try testing.expect(e.adjacency_up);
}

// Regression (audit W2 `isis-adj` F4): `neighbor_ext_circuit_id` must not
// survive an accepted IIH that carries no TLV 240 at all. Before the fix the
// assignment was guarded by `if (rx.three_way) |tw|`, so a no-240 IIH left the
// PREVIOUS neighbour's extended circuit id in place, and `helloFields` kept
// advertising a neighbour block referencing a handshake the peer withdrew.
test "an accepted IIH with no TLV 240 clears a previously recorded neighbour_ext_circuit_id" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    // First hello carries a 240 with an extended circuit id — recorded.
    _ = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1 },
    }, 1);
    try testing.expectEqual(@as(?u32, 0xB1), adj.neighbor_ext_circuit_id);

    // Second hello, still from B (so it is accepted), carries NO TLV 240 at
    // all — the stale value must be cleared, not left in place.
    _ = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = null,
    }, 2);
    try testing.expect(adj.neighbor_ext_circuit_id == null);
    // And the outgoing 240 must not claim a neighbour block for it.
    try testing.expect(adj.helloFields().three_way.neighbor == null);
}

// Regression (audit W2 `isis-adj` F1): a third system-id must not be able to
// touch an established adjacency. Before the fix `rxHello` never compared
// `rx.source_id` against the neighbour already on this circuit, so ONE hello
// from an unauthenticated stranger refreshed `hold_deadline` to the stranger's
// chosen holding-time, overwrote `neighbor_system_id`, and (the stranger cannot
// echo us) dropped the adjacency Up→Initializing with `.neighbor_restarted`.
// Repeated at any rate that is a permanent flap; worse, once the real neighbour
// goes silent the stranger's refreshes keep `hold_deadline` in the future, so
// the hold never expires and the FSM never returns to a clean Down.
test "a third system-id cannot hijack an established adjacency, nor wedge its hold timer" {
    const sys_c: SystemId = .{ 0, 0, 0, 0, 0, 0xC };
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);

    // A and B reach Up at t=1 with B's holding_time = 30 → hold expires at 31.
    const up = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{
            .state = .initializing,
            .extended_local_circuit_id = 0xB1,
            .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 },
        },
    }, 1);
    try testing.expect(up.adjacency_up);
    try testing.expectEqual(State.up, adj.currentState());
    try testing.expectEqual(@as(Time, 31), adj.hold_deadline);

    // C sprays hellos with the maximum holding-time and no TLV 240 at all.
    var t: Time = 2;
    while (t < 30) : (t += 1) {
        const e = adj.rxHello(.{
            .source_id = sys_c,
            .holding_time = 65535,
            .circuit_type = .level1_2,
            .local_circuit_id = 1,
        }, t);
        // Rejected outright: no transition, no down report, no hello scheduled.
        try testing.expectEqual(@as(?RejectReason, .other_neighbor), e.rejected);
        try testing.expect(e.transition == null);
        try testing.expect(e.adjacency_down == null);
        // Nothing was mutated: still Up, still B, hold untouched (NOT 65535+t).
        try testing.expectEqual(State.up, adj.currentState());
        try testing.expectEqual(sys_b, adj.neighbor_system_id.?);
        try testing.expectEqual(@as(Time, 31), adj.hold_deadline);
    }

    // The real neighbour has gone silent, so the hold must still expire on time
    // — C's refreshes cannot hold it open. (Before the fix `hold_deadline` was
    // 65535 + 29 here and this adjacency stayed nominally alive forever.)
    const dead = adj.tick(31);
    try testing.expectEqual(State.down, adj.currentState());
    try testing.expectEqual(DownReason.hold_expired, dead.adjacency_down.?);
    try testing.expect(adj.neighbor_system_id == null);

    // Down releases the circuit: C is now an ordinary candidate neighbour.
    const after = adj.rxHello(.{
        .source_id = sys_c,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{
            .state = .initializing,
            .extended_local_circuit_id = 0xC1,
            .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 },
        },
    }, 32);
    try testing.expect(after.rejected == null);
    try testing.expect(after.adjacency_up);
    try testing.expectEqual(sys_c, adj.neighbor_system_id.?);
}

test "a neighbour not echoing us holds us at Initializing (three-way guard)" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    // Neighbour B says Init, gives its ext id, but no neighbour block (hasn't
    // confirmed hearing us).
    const e = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1 },
    }, 1);
    try testing.expectEqual(State.initializing, adj.currentState());
    try testing.expect(e.adjacency_up == false);
    // Now our outgoing 240 DOES carry a neighbour block (we heard B's ext id).
    const hf = adj.helloFields();
    try testing.expect(hf.three_way.neighbor != null);
    try testing.expectEqual(sys_b, hf.three_way.neighbor.?.system_id);
}

test "a neighbour that echoes us (and is past Down) brings us Up" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    const e = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{
            .state = .initializing,
            .extended_local_circuit_id = 0xB1,
            .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 },
        },
    }, 1);
    try testing.expectEqual(State.up, adj.currentState());
    try testing.expect(e.adjacency_up);
    try testing.expectEqual(Transition{ .from = .down, .to = .up }, e.transition.?);
}

test "neighbour system-id present WITHOUT its extended-circuit-id (11-octet wire shape) is NOT an echo" {
    // RFC 5303 §3.1 also allows a neighbour block with the system-id but no
    // extended-local-circuit-id (Wireshark-anchored, see three_way.zig). Our
    // system-id matches, but with no circuit-id we cannot disambiguate which
    // parallel circuit this is about, so it must not reach Up — same ceiling as
    // no neighbour block at all.
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    const e = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{
            .state = .initializing,
            .extended_local_circuit_id = 0xB1,
            .neighbor = .{ .system_id = sys_a }, // no extended_local_circuit_id
        },
    }, 1);
    try testing.expectEqual(State.initializing, adj.currentState());
    try testing.expect(e.adjacency_up == false);
}

test "echo requires BOTH system-id and circuit-id to match, not just one" {
    // system-id matches ours but the extended circuit-id does not.
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    const e1 = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{
            .state = .initializing,
            .extended_local_circuit_id = 0xB1,
            .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xFF },
        },
    }, 1);
    try testing.expectEqual(State.initializing, adj.currentState());
    try testing.expect(e1.adjacency_up == false);

    // extended circuit-id matches ours but the system-id does not.
    var adj2 = Adjacency.init(cfgA());
    _ = adj2.start(0);
    const e2 = adj2.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{
            .state = .initializing,
            .extended_local_circuit_id = 0xB1,
            .neighbor = .{ .system_id = sys_b, .extended_local_circuit_id = 0xA1 },
        },
    }, 1);
    try testing.expectEqual(State.initializing, adj2.currentState());
    try testing.expect(e2.adjacency_up == false);
}

test "echo with neighbour claiming Down does NOT bring us Up" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    const e = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{
            .state = .down, // mid-reset: references us but claims Down
            .extended_local_circuit_id = 0xB1,
            .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 },
        },
    }, 1);
    try testing.expectEqual(State.initializing, adj.currentState());
    try testing.expect(e.adjacency_up == false);
}

test "rxHelloBytes decodes a real isis P2P IIH and drives the FSM" {
    // Build B's IIH (echoing A) with the isis codec + our buildHello, then feed
    // the raw bytes to A.
    var pdu_buf: [128]u8 = undefined;
    const b_fields: HelloFields = .{
        .source_id = sys_b,
        .holding_time = 30,
        .local_circuit_id = 1,
        .circuit_type = .level1_2,
        .three_way = .{
            .state = .initializing,
            .extended_local_circuit_id = 0xB1,
            .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 },
        },
    };
    const wire = try buildHello(&pdu_buf, b_fields);

    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    const e = try adj.rxHelloBytes(wire, 1);
    try testing.expect(e.adjacency_up);
    try testing.expectEqual(State.up, adj.currentState());
}

test "malformed bytes and a malformed 240 are typed errors, state unchanged" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    // Garbage: long enough to pass the length check, but a bad discriminator.
    try testing.expectError(error.BadDiscriminator, adj.rxHelloBytes(&([_]u8{0xFF} ** 24), 1));
    try testing.expectEqual(State.down, adj.currentState());

    // A well-formed P2P IIH but with a TLV 240 of illegal length (2 octets).
    var buf: [128]u8 = undefined;
    var pb = try isis.pdu.P2pHelloBuilder.init(&buf, .{ .source_id = sys_b, .holding_time = 30 });
    try pb.tlvs.addTlv(three_way.tlv_code, &[_]u8{ 0, 1 }); // len 2 → BadLength
    const wire = pb.finish();
    try testing.expectError(error.BadLength, adj.rxHelloBytes(wire, 1));
    try testing.expectEqual(State.down, adj.currentState());
}

test "hold timer expires the adjacency to Down with hold_expired" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    // Bring Up at t=1 with holding_time 30 → deadline 31.
    _ = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .up, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } },
    }, 1);
    try testing.expectEqual(State.up, adj.currentState());
    // Just before the deadline: still Up.
    const before = adj.tick(30);
    try testing.expect(before.adjacency_down == null);
    try testing.expectEqual(State.up, adj.currentState());
    // At the deadline: Down, hold_expired.
    const at = adj.tick(31);
    try testing.expectEqual(DownReason.hold_expired, at.adjacency_down.?);
    try testing.expectEqual(State.down, adj.currentState());
}

test "a refreshing hello just before the deadline keeps it Up" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    const up: RxHello = .{
        .source_id = sys_b,
        .holding_time = 10,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .up, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } },
    };
    _ = adj.rxHello(up, 1); // deadline 11
    _ = adj.tick(10); // still Up
    _ = adj.rxHello(up, 10); // refresh → deadline 20
    try testing.expectEqual(State.up, adj.currentState());
    _ = adj.tick(11); // past the OLD deadline but before the new one
    try testing.expectEqual(State.up, adj.currentState());
    const gone = adj.tick(20); // past the refreshed deadline
    try testing.expectEqual(DownReason.hold_expired, gone.adjacency_down.?);
}

test "tick emits hellos on the hello_interval cadence" {
    var adj = Adjacency.init(.{ .system_id = sys_a, .extended_local_circuit_id = 1, .hello_interval = 10 });
    _ = adj.start(0); // next due at 10
    try testing.expect(adj.tick(5).send_hello == null);
    try testing.expect(adj.tick(10).send_hello != null); // due
    try testing.expect(adj.tick(11).send_hello == null);
    try testing.expect(adj.tick(20).send_hello != null); // next cadence
}

test "stop from Up reports adjacency_down = stopped" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    _ = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .up, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } },
    }, 1);
    const e = adj.stop();
    try testing.expectEqual(DownReason.stopped, e.adjacency_down.?);
    try testing.expectEqual(State.down, adj.currentState());
}
