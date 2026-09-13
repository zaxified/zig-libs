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
    /// The local circuit was administratively stopped (`stop`), or restarted
    /// by `start` while the adjacency was Up.
    stopped,
    /// The neighbour restarted / withdrew its confirmation of us (a received
    /// IIH that no longer echoes us, dropping Up → Initializing).
    neighbor_restarted,
    /// The recorded neighbour sent an IIH with a different Local Circuit ID
    /// (ISO 10589 §9.7): the link now ends on another of its interfaces. The
    /// adjacency is deleted. See `Config.detect_circuit_id_change`.
    circuit_id_changed,
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
    /// A **third** system sent an IIH while this circuit has an **Up**
    /// adjacency. A point-to-point circuit carries exactly ONE adjacency
    /// (ISO/IEC 10589 §8.2.4), so an IIH whose source-id differs from the
    /// neighbour the handshake completed with is not "the neighbour" and must
    /// not be acted on: an IIH carries no authentication unless TLV 10 is
    /// configured, and acting on it would let any station on the wire refresh
    /// *our* hold timer with *its* chosen holding-time, overwrite the recorded
    /// neighbour, and drag the adjacency Up→Initializing. The incumbent is kept
    /// and nothing is mutated until its hold genuinely expires.
    ///
    /// The lock guards an ESTABLISHED adjacency only. While the adjacency is
    /// still `initializing` — a neighbour heard, nothing proven — a different
    /// source-id simply replaces the recorded candidate (ISO 10589 / FRR
    /// semantics). The earlier rule locked the circuit on the FIRST hello
    /// heard, so one unauthenticated frame from a stranger, carrying a
    /// `holding_time` of its choosing (up to 65 535 units), kept the real
    /// neighbour out for exactly that long (the A1 audit measured 1998/1998
    /// of its hellos rejected). A stranger now has to keep transmitting to
    /// keep displacing the candidate, and the genuine neighbour's next echoing
    /// hello takes the circuit to Up — at which point the lock applies.
    other_neighbor,
    /// The IIH's TLV 240 carries a neighbour block that names ANOTHER system
    /// (or our system with another extended local circuit id — a parallel
    /// circuit's handshake). RFC 5303 §3.2 (ISO 10589 §8.2.4.1.1 as amended):
    /// "If they are present, and the Neighbor System ID contained therein does
    /// not match the local system's ID, or the Neighbor Extended Local Circuit
    /// ID does not match the local system's extended circuit ID, the PDU SHALL
    /// be discarded and no further action is taken." Checked BEFORE any
    /// mutation: such a PDU refreshes no hold, records no neighbour and causes
    /// no transition. Before this rule existed the mismatch only made the
    /// hello "not an echo" and the PDU was otherwise processed — one frame
    /// naming a third system dropped an Up adjacency to Initializing, moved
    /// the hold to the attacker's `holding_time` and overwrote the recorded
    /// neighbour's extended circuit id.
    neighbor_mismatch,
    /// The neighbour advertises three-way state **Up** while we are **Down**.
    /// RFC 5303 §3.2 table, cell (local Down, received Up) = Down, "Neighbor
    /// restarted": we have no adjacency, so its claim to a completed handshake
    /// is stale — one side restarted, and the neighbour must be driven back
    /// through Initializing before the link is trusted. Nothing is recorded.
    /// Before this rule one such frame — a replay, or the live hellos of a
    /// neighbour that never noticed our restart — took a fresh circuit
    /// straight to Up, declaring a possibly unidirectional link functional,
    /// which is the exact failure the three-way handshake exists to prevent.
    neighbor_up_while_down,
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
    /// The IIH's `holding_time` is below `Config.min_neighbor_holding_time`.
    /// A hold of 0 took the adjacency Up and expired it at the same instant
    /// (A1 audit F13). Neither RFC 5303 nor FRR sets a floor; this is a local
    /// policy with a default that refuses only 0.
    holding_time_too_short,
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
    /// RFC 5303 §3.2 b) backward compatibility (A1 audit F5). The RFC runs its
    /// three-way table on the received state alone when the neighbour's TLV
    /// 240 carries no (complete) neighbour block: "the procedure works
    /// properly if neither field is ever included". With this `true` such a
    /// peer reaching Initializing takes us Up. Default `false`: without the
    /// echo nothing proves the peer heard THIS circuit, so the ceiling stays
    /// Initializing. A block naming someone else is discarded either way.
    accept_without_neighbor_fields: bool = false,
    /// Return `send_hello` from `rxHello` whenever it changes state, so the
    /// handshake converges on events instead of waiting for `hello_interval`
    /// (A1 audit F12; FRR sends a triggered IIH on every state change). At
    /// most one hello per received IIH, never more. The periodic schedule is
    /// not moved. `false` restores cadence-only hellos.
    triggered_hello: bool = true,
    /// The smallest neighbour `holding_time` accepted; below it the IIH is
    /// `rejected = .holding_time_too_short` (A1 audit F13). Default 1 refuses
    /// only 0, which expired the adjacency in the instant it formed. 0
    /// disables the check.
    min_neighbor_holding_time: u16 = 1,
    /// Delete the adjacency when the recorded neighbour's IIH carries a
    /// different Local Circuit ID than the one it was formed with (A1 audit
    /// F14): the link was moved to another interface. For a peer without TLV
    /// 240 this is the only sign of it. Reported as a transition to Down and,
    /// from Up, `adjacency_down = .circuit_id_changed`. FRR leaves this step of
    /// ISO 10589 §8.2.5.2 c) unimplemented ("FIXME - Missing parts"); `false`
    /// matches it.
    detect_circuit_id_change: bool = true,
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
    /// Any FURTHER Area Addresses (#1) TLV instances beyond the first (ISO
    /// 10589 permits a neighbour to split its announced areas across more than
    /// one #1 TLV; audit A1 `isis-adj` F8). Additive default (empty) so every
    /// existing caller that fills only `neighbor_area_addresses` is unaffected.
    /// `rxHelloBytes` populates it from the wire; a hand-built `RxHello` that
    /// wants the same coverage supplies it directly.
    neighbor_area_addresses_more: []const []const u8 = &.{},
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
    /// The neighbour's 1-octet Local Circuit ID from the IIH it was accepted
    /// with; compared by `Config.detect_circuit_id_change`.
    neighbor_local_circuit_id: ?u8 = null,

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
    /// Called on a live adjacency it reports the drop the way `stop` does
    /// (`transition`, and `adjacency_down = .stopped` from Up; A1 audit F7).
    pub fn start(self: *Adjacency, now: Time) Effect {
        const prev = self.state;
        self.started = true;
        self.state = .down;
        self.neighbor_system_id = null;
        self.neighbor_ext_circuit_id = null;
        self.neighbor_local_circuit_id = null;
        self.hold_deadline = 0;
        self.next_hello_due = now + self.cfg.hello_interval;
        var eff: Effect = .{ .send_hello = self.helloFields() };
        if (prev != .down) {
            eff.transition = .{ .from = prev, .to = .down };
            if (prev == .up) eff.adjacency_down = .stopped;
        }
        return eff;
    }

    /// Administratively tear the circuit down. If it was Up, reports
    /// `adjacency_down = .stopped`.
    pub fn stop(self: *Adjacency) Effect {
        const prev = self.state;
        self.started = false;
        self.state = .down;
        self.neighbor_system_id = null;
        self.neighbor_ext_circuit_id = null;
        self.neighbor_local_circuit_id = null;
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
            self.neighbor_local_circuit_id = null;
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
        // The whole TLV stream must be well formed, not just the prefix up to
        // the TLVs we read: `findFirst` stops at its first hit, so a TLV lying
        // about its length BEHIND the 240 used to pass — and the same PDU is
        // refused by a sibling that walks it all. One PDU, one verdict.
        _ = try isis.tlv.count(p.tlv_bytes);
        var tw: ?ThreeWayTlv = null;
        if (try isis.tlv.findFirst(p.tlv_bytes, three_way.tlv_code)) |val| {
            tw = try ThreeWayTlv.decode(val);
        }
        // Audit F8: a neighbour may legally split its announced areas across
        // MORE than one Area Addresses (#1) TLV. `findFirst` only ever sees the
        // first instance, so a shared area sitting in a second #1 TLV was
        // missed whenever a non-matching first TLV preceded it — and, since
        // `local_areas` matching is fail-closed, the adjacency was wrongly
        // rejected. Walk the stream once collecting every #1 instance (bounded,
        // no allocation) so `sharesArea` sees the neighbour's FULL area set.
        var area_addresses: ?[]const u8 = null;
        var more_buf: [7][]const u8 = undefined;
        var more_len: usize = 0;
        {
            var it = isis.tlv.TlvIterator.init(p.tlv_bytes);
            while (try it.next()) |raw| {
                if (raw.code != isis.tlvs.code.area_addresses) continue;
                if (area_addresses == null) {
                    area_addresses = raw.value;
                } else if (more_len < more_buf.len) {
                    more_buf[more_len] = raw.value;
                    more_len += 1;
                }
                // Beyond `more_buf.len` extra instances (implausible in
                // practice) are not consulted — fail closed, never fail open.
            }
        }
        return self.rxHello(.{
            .source_id = p.source_id,
            .holding_time = p.holding_time,
            .circuit_type = p.circuit_type,
            .local_circuit_id = p.local_circuit_id,
            .max_area_addresses = p.header.max_area_addresses,
            .neighbor_area_addresses = area_addresses,
            .neighbor_area_addresses_more = more_buf[0..more_len],
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
        if (rx.max_area_addresses != self.effectiveMaxAreaAddresses()) {
            return .{ .rejected = .max_area_mismatch };
        }
        // Audit F13: a hold of 0 formed the adjacency and expired it in the
        // same instant. Local policy, see `Config.min_neighbor_holding_time`.
        if (rx.holding_time < self.cfg.min_neighbor_holding_time) {
            return .{ .rejected = .holding_time_too_short };
        }
        // Area-address matching (ISO 10589 §8.2.2/§7.2.4): required only for a
        // Level 1 adjacency. `.level1_2` is left unchecked here because this
        // FSM tracks one combined state per circuit rather than split L1/L2
        // sub-states — rejecting a `.level1_2` circuit on an area mismatch
        // would also block the L2 component, which ISO 10589 says must still
        // form. Skipped entirely when `local_areas` is unconfigured.
        if (self.cfg.circuit_type == .level1 and self.cfg.local_areas.len != 0) {
            if (!self.sharesArea(rx.neighbor_area_addresses) and
                !self.sharesAreaInAny(rx.neighbor_area_addresses_more))
            {
                return .{ .rejected = .area_mismatch };
            }
        }
        // One circuit, one neighbour (ISO/IEC 10589 §8.2.4). Once the handshake
        // has COMPLETED, only that system-id drives this adjacency. Checked
        // BEFORE any mutation, so a stranger's IIH refreshes no hold, overwrites
        // no neighbour and forces no transition — see `RejectReason.other_neighbor`
        // for why the lock applies to an Up adjacency and not to a candidate
        // still at Initializing. The lock releases when the incumbent's hold
        // expires (`tick` clears `neighbor_system_id` on the way to Down) or on
        // `start`/`stop`.
        if (self.state == .up) {
            if (self.neighbor_system_id) |incumbent| {
                if (!std.mem.eql(u8, &incumbent, &rx.source_id)) {
                    return .{ .rejected = .other_neighbor };
                }
            }
        }
        // RFC 5303 §3.2: a neighbour block that names someone else — or our
        // system on another circuit — means this PDU is not about THIS
        // adjacency at all. Discard it whole, before anything is touched.
        if (rx.three_way) |tw| {
            if (tw.neighbor) |nb| {
                if (!std.mem.eql(u8, &nb.system_id, &self.cfg.system_id)) {
                    return .{ .rejected = .neighbor_mismatch };
                }
                if (nb.extended_local_circuit_id) |ext| {
                    if (ext != self.cfg.extended_local_circuit_id) return .{ .rejected = .neighbor_mismatch };
                }
            }
        }
        // RFC 5303 §3.2 table, (local Down, received Up) = Down / "Neighbor
        // restarted": we hold no adjacency, so a peer that claims the handshake
        // is complete is stale. It must see us at Down (our next hello says so)
        // and come back through Initializing; we record nothing from this PDU.
        if (self.state == .down) {
            if (rx.three_way) |tw| {
                if (tw.state == .up) return .{ .rejected = .neighbor_up_while_down };
            }
        }
        // Audit F14: the recorded neighbour now speaks from another Local
        // Circuit ID, so the link ends on a different interface of it. The
        // adjacency formed on the old one is deleted; the next hello from the
        // new interface starts over from Down.
        if (self.cfg.detect_circuit_id_change and self.state != .down) {
            if (self.neighbor_system_id) |sid| {
                if (self.neighbor_local_circuit_id) |old| {
                    if (std.mem.eql(u8, &sid, &rx.source_id) and old != rx.local_circuit_id) {
                        const prev = self.state;
                        self.state = .down;
                        self.neighbor_system_id = null;
                        self.neighbor_ext_circuit_id = null;
                        self.neighbor_local_circuit_id = null;
                        self.hold_deadline = 0;
                        var eff: Effect = .{ .transition = .{ .from = prev, .to = .down } };
                        if (prev == .up) eff.adjacency_down = .circuit_id_changed;
                        if (self.cfg.triggered_hello) eff.send_hello = self.helloFields();
                        return eff;
                    }
                }
            }
        }

        // ── accepted: refresh hold + record the neighbour ───────────────────
        self.hold_deadline = now + @as(Time, rx.holding_time);
        self.neighbor_system_id = rx.source_id;
        self.neighbor_local_circuit_id = rx.local_circuit_id;
        // Unconditional, not just when a 240 is present: an accepted IIH that
        // carries no TLV 240 at all means the neighbour has stopped (or never
        // started) speaking RFC 5303, so any previously recorded extended
        // circuit id is no longer current and must be cleared rather than left
        // stale — otherwise `helloFields` keeps advertising a neighbour block
        // for a handshake reference the peer withdrew.
        self.neighbor_ext_circuit_id = if (rx.three_way) |tw| tw.extended_local_circuit_id else null;

        // ── three-way decision ──────────────────────────────────────────────
        // echoed == the neighbour's 240 names US (our system-id AND our extended
        // circuit id) — proof it has heard us. The loop guard. A block naming
        // anyone else was discarded above (`neighbor_mismatch`), so here a
        // present block either echoes us or is the bare-system-id shape.
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

        // Audit F5, opt-in: RFC 5303 §3.2 b) runs the table on the received
        // state when the neighbour fields are absent. A block naming anyone
        // else never gets here (discarded above), so any 240 that did is
        // either the echo or carries no complete block.
        const confirmed = echoed or (self.cfg.accept_without_neighbor_fields and rx.three_way != null);

        const new_state: State = if (self.cfg.three_way_required)
            (if (confirmed and neighbor_past_down) .up else .initializing)
        else
            // Pre-5303 two-way fallback / positive control: trust a single
            // accepted hello. This is the DELIBERATELY WEAKER rule.
            .up;

        // Audit F4 / RFC 5303 §3.2 table: EVERY cell in the "received Down"
        // column is action "Initialize" — "no event is generated and the
        // adjacency three-way state SHALL be set to 'Initializing'" — verbatim
        // text confirmed against RFC 5303 §3.2. FRR agrees: the Initialize
        // action only reschedules a hello, `adj_state` is left UP. A peer
        // reporting itself Down is not the same as our echo/liveness check
        // failing (the OTHER way `applyState` can leave Up, still reported
        // below) — it is the peer TELLING us to reinitialize, silently.
        const initialize_action = if (rx.three_way) |tw| tw.state == .down else false;
        var eff = self.applyState(new_state, now, initialize_action);
        // Audit F12: tell the neighbour about the new state now, not at the
        // next `hello_interval`.
        if (self.cfg.triggered_hello and eff.transition != null) eff.send_hello = self.helloFields();
        return eff;
    }

    fn applyState(self: *Adjacency, new_state: State, now: Time, initialize_action: bool) Effect {
        _ = now;
        const prev = self.state;
        self.state = new_state;
        var eff: Effect = .{};
        if (new_state == prev) return eff;
        eff.transition = .{ .from = prev, .to = new_state };
        if (new_state == .up) eff.adjacency_up = true;
        if (prev == .up and new_state != .up and !initialize_action) eff.adjacency_down = .neighbor_restarted;
        return eff;
    }

    /// Audit F16: `isis.header.decode` normalizes a WIRE `max_area_addresses`
    /// of 0 (the ISO 10589 §9.6 shorthand for "3") to 3 before `rxHelloBytes`
    /// ever sees it, so `rx.max_area_addresses` is never 0. `Config` is a
    /// caller-supplied *value*, not decoded wire bytes, so the same shorthand
    /// written there (`.max_area_addresses = 0`, "use the default") stayed
    /// literally 0 and compared unequal to every real neighbour's normalized 3
    /// — rejecting every one of them. Normalizing here, at the single point of
    /// comparison, makes both sides speak the same normalized value.
    fn effectiveMaxAreaAddresses(self: *const Adjacency) u8 {
        return if (self.cfg.max_area_addresses == 0)
            isis.header.default_max_area_addresses
        else
            self.cfg.max_area_addresses;
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

    /// Audit F8: the neighbour's area set is the UNION of every Area Addresses
    /// (#1) TLV it sent, not just the first — `sharesArea` alone only ever sees
    /// one instance. A malformed instance is "no shared area found" for THAT
    /// instance only (fail closed per-instance), same as `sharesArea` itself.
    fn sharesAreaInAny(self: *const Adjacency, more: []const []const u8) bool {
        for (more) |raw| {
            if (self.sharesArea(raw)) return true;
        }
        return false;
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

fn rxFrom(src: SystemId, lcid: u8, hold: u16, tw: ?ThreeWayTlv) RxHello {
    return .{ .source_id = src, .holding_time = hold, .circuit_type = .level1_2, .local_circuit_id = lcid, .three_way = tw };
}

const echo_init: ThreeWayTlv = .{
    .state = .initializing,
    .extended_local_circuit_id = 0xB1,
    .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 },
};

fn upAdjacency(cfg: Config) !Adjacency {
    var adj = Adjacency.init(cfg);
    _ = adj.start(0);
    _ = adj.rxHello(rxFrom(sys_b, 1, 30, echo_init), 1);
    try testing.expectEqual(State.up, adj.currentState());
    return adj;
}

test "audit F5: a 240 without neighbour fields stays Initializing by default, goes Up by the RFC 5303 table when opted in" {
    const bare_init: ThreeWayTlv = .{ .state = .initializing, .extended_local_circuit_id = 0xB1 };
    const bare_down: ThreeWayTlv = .{ .state = .down, .extended_local_circuit_id = 0xB1 };

    var strict = Adjacency.init(cfgA());
    _ = strict.start(0);
    for (0..6) |i| _ = strict.rxHello(rxFrom(sys_b, 1, 30, bare_init), 1 + i);
    try testing.expectEqual(State.initializing, strict.currentState());

    var cfg = cfgA();
    cfg.accept_without_neighbor_fields = true;
    // Table (Down, Initializing) = Up.
    var legacy = Adjacency.init(cfg);
    _ = legacy.start(0);
    const e = legacy.rxHello(rxFrom(sys_b, 1, 30, bare_init), 1);
    try testing.expectEqual(State.up, legacy.currentState());
    try testing.expect(e.adjacency_up);
    // Table (Up, Down) = Initialize.
    _ = legacy.rxHello(rxFrom(sys_b, 1, 30, bare_down), 2);
    try testing.expectEqual(State.initializing, legacy.currentState());
    // The switch does not reach an IIH without any 240 (option absent).
    var no_240 = Adjacency.init(cfg);
    _ = no_240.start(0);
    _ = no_240.rxHello(rxFrom(sys_b, 1, 30, null), 1);
    try testing.expectEqual(State.initializing, no_240.currentState());
    // Nor a block naming someone else: still discarded.
    var foreign = Adjacency.init(cfg);
    _ = foreign.start(0);
    const f = foreign.rxHello(rxFrom(sys_b, 1, 30, .{
        .state = .initializing,
        .extended_local_circuit_id = 0xB1,
        .neighbor = .{ .system_id = sys_b, .extended_local_circuit_id = 0xA1 },
    }), 1);
    try testing.expectEqual(RejectReason.neighbor_mismatch, f.rejected.?);
}

test "audit F7: start() over an Up adjacency reports the drop like stop()" {
    var adj = try upAdjacency(cfgA());
    const e = adj.start(5);
    try testing.expectEqual(Transition{ .from = .up, .to = .down }, e.transition.?);
    try testing.expectEqual(DownReason.stopped, e.adjacency_down.?);
    try testing.expect(e.send_hello != null);
    try testing.expectEqual(State.down, adj.currentState());
    // From Initializing: a transition, no adjacency_down.
    var init_adj = Adjacency.init(cfgA());
    _ = init_adj.start(0);
    _ = init_adj.rxHello(rxFrom(sys_b, 1, 30, null), 1);
    const e2 = init_adj.start(5);
    try testing.expectEqual(Transition{ .from = .initializing, .to = .down }, e2.transition.?);
    try testing.expect(e2.adjacency_down == null);
}

test "audit F12: a state change in rxHello triggers a hello carrying the new state; no change, no hello" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    const e1 = adj.rxHello(rxFrom(sys_b, 1, 30, .{ .state = .down, .extended_local_circuit_id = 0xB1 }), 1);
    try testing.expectEqual(ThreeWayState.initializing, e1.send_hello.?.three_way.state);
    try testing.expectEqual(sys_b, e1.send_hello.?.three_way.neighbor.?.system_id);
    const e2 = adj.rxHello(rxFrom(sys_b, 1, 30, .{ .state = .down, .extended_local_circuit_id = 0xB1 }), 2);
    try testing.expect(e2.transition == null);
    try testing.expect(e2.send_hello == null);
    const e3 = adj.rxHello(rxFrom(sys_b, 1, 30, echo_init), 3);
    try testing.expectEqual(ThreeWayState.up, e3.send_hello.?.three_way.state);

    var cfg = cfgA();
    cfg.triggered_hello = false;
    var quiet = Adjacency.init(cfg);
    _ = quiet.start(0);
    const q = quiet.rxHello(rxFrom(sys_b, 1, 30, echo_init), 1);
    try testing.expect(q.transition != null);
    try testing.expect(q.send_hello == null);
}

test "audit F13: a holding_time of 0 is rejected by default; 1 is accepted; the floor is configurable" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    const e = adj.rxHello(rxFrom(sys_b, 1, 0, echo_init), 1);
    try testing.expectEqual(RejectReason.holding_time_too_short, e.rejected.?);
    try testing.expectEqual(State.down, adj.currentState());
    _ = adj.rxHello(rxFrom(sys_b, 1, 1, echo_init), 1);
    try testing.expectEqual(State.up, adj.currentState());

    var cfg = cfgA();
    cfg.min_neighbor_holding_time = 0;
    var off = Adjacency.init(cfg);
    _ = off.start(0);
    _ = off.rxHello(rxFrom(sys_b, 1, 0, echo_init), 1);
    try testing.expectEqual(State.up, off.currentState());
    cfg.min_neighbor_holding_time = 10;
    var floor = Adjacency.init(cfg);
    _ = floor.start(0);
    try testing.expectEqual(RejectReason.holding_time_too_short, floor.rxHello(rxFrom(sys_b, 1, 9, echo_init), 1).rejected.?);
    _ = floor.rxHello(rxFrom(sys_b, 1, 10, echo_init), 1);
    try testing.expectEqual(State.up, floor.currentState());
}

test "audit F14: the neighbour's Local Circuit ID changing deletes the adjacency; unchanged or opted out, it stays" {
    var adj = try upAdjacency(cfgA());
    const same = adj.rxHello(rxFrom(sys_b, 1, 30, echo_init), 2);
    try testing.expect(same.transition == null);
    try testing.expectEqual(State.up, adj.currentState());

    const moved = adj.rxHello(rxFrom(sys_b, 2, 30, echo_init), 3);
    try testing.expectEqual(Transition{ .from = .up, .to = .down }, moved.transition.?);
    try testing.expectEqual(DownReason.circuit_id_changed, moved.adjacency_down.?);
    try testing.expectEqual(State.down, adj.currentState());
    try testing.expect(adj.neighbor_system_id == null);
    // Our next hello says Down with no neighbour block.
    try testing.expectEqual(ThreeWayState.down, moved.send_hello.?.three_way.state);
    try testing.expect(moved.send_hello.?.three_way.neighbor == null);
    // Nothing is left to expire.
    try testing.expect(adj.tick(100).adjacency_down == null);

    // Only the RECORDED neighbour is compared: at Initializing another system
    // on another circuit id replaces the candidate (F2 semantics), it does
    // not delete anything.
    const sys_c: SystemId = .{ 0, 0, 0, 0, 0, 0xC };
    var cand = Adjacency.init(cfgA());
    _ = cand.start(0);
    _ = cand.rxHello(rxFrom(sys_b, 1, 30, null), 1);
    const other = cand.rxHello(rxFrom(sys_c, 2, 30, null), 2);
    try testing.expect(other.transition == null);
    try testing.expectEqual(State.initializing, cand.currentState());
    try testing.expectEqual(sys_c, cand.neighbor_system_id.?);

    var cfg = cfgA();
    cfg.detect_circuit_id_change = false;
    var off = try upAdjacency(cfg);
    _ = off.rxHello(rxFrom(sys_b, 2, 30, echo_init), 3);
    try testing.expectEqual(State.up, off.currentState());
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

test "a neighbour block naming someone else is a DISCARD, not a half-echo (RFC 5303 \u{a7}3.2, audit F1)" {
    // Both halves of the reference must match; a block that names our
    // system-id on another extended circuit id is a parallel circuit's
    // handshake, one that names another system is not about us at all. Either
    // way the PDU is discarded whole: no neighbour recorded, no hold set, no
    // transition. (This used to leave the adjacency at Initializing — the PDU
    // was processed and merely "not an echo".)
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
    try testing.expectEqual(@as(?RejectReason, .neighbor_mismatch), e1.rejected);
    try testing.expectEqual(State.down, adj.currentState());
    try testing.expect(adj.neighbor_system_id == null);
    try testing.expectEqual(@as(Time, 0), adj.hold_deadline);

    const e2 = adj.rxHello(.{
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
    try testing.expectEqual(@as(?RejectReason, .neighbor_mismatch), e2.rejected);
    try testing.expectEqual(State.down, adj.currentState());
}

test "audit F1: one IIH whose neighbour block names a third system cannot touch an Up adjacency" {
    // The audit's P2 probe: before the fix this frame dropped Up→Initializing
    // with `neighbor_restarted`, moved the hold to now + 65535 and overwrote
    // the recorded neighbour's extended circuit id — all from a PDU RFC 5303
    // says to discard before anything is examined further.
    const sys_c: SystemId = .{ 0, 0, 0, 0, 0, 0xC };
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    _ = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } },
    }, 1);
    try testing.expectEqual(State.up, adj.currentState());
    try testing.expectEqual(@as(Time, 31), adj.hold_deadline);

    // Same source-id as the real neighbour (spoofed), so the one-neighbour
    // lock does not catch it — only the neighbour-block rule can.
    const e = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 65535,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0x77, .neighbor = .{ .system_id = sys_c, .extended_local_circuit_id = 0xC1 } },
    }, 5);
    try testing.expectEqual(@as(?RejectReason, .neighbor_mismatch), e.rejected);
    try testing.expect(e.transition == null);
    try testing.expect(e.adjacency_down == null);
    try testing.expectEqual(State.up, adj.currentState());
    try testing.expectEqual(@as(Time, 31), adj.hold_deadline); // not 65540
    try testing.expectEqual(@as(?u32, 0xB1), adj.neighbor_ext_circuit_id); // not 0x77
    // Our outgoing 240 still echoes B.
    try testing.expectEqual(sys_b, adj.helloFields().three_way.neighbor.?.system_id);
}

test "audit F3: a fresh circuit does not go Up on a neighbour that already claims Up (RFC 5303 table, Down x Up = Down)" {
    // A restarted (our side) or replayed "Up + echoes you" hello on a Down
    // circuit used to reach Up in one frame — declaring a link functional
    // that nothing we send may be reaching. The cell says Down, "Neighbor
    // restarted": record nothing, let the peer see our Down and re-initialize.
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    const stale_up: RxHello = .{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .up, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } },
    };
    var n: usize = 0;
    while (n < 5) : (n += 1) {
        const e = adj.rxHello(stale_up, 1 + n);
        try testing.expectEqual(@as(?RejectReason, .neighbor_up_while_down), e.rejected);
        try testing.expect(!e.adjacency_up);
        try testing.expectEqual(State.down, adj.currentState());
        try testing.expect(adj.neighbor_system_id == null);
    }
    // Our hello keeps saying Down, with no neighbour block — the peer, per the
    // same table (its Up x our Down = Down), falls back and re-initializes.
    try testing.expectEqual(ThreeWayState.down, adj.helloFields().three_way.state);
    try testing.expect(adj.helloFields().three_way.neighbor == null);

    // Once it comes back at Initializing (echoing us), the handshake proceeds.
    const init_echo: RxHello = .{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } },
    };
    const up = adj.rxHello(init_echo, 10);
    try testing.expect(up.adjacency_up);
    try testing.expectEqual(State.up, adj.currentState());
    // And from Initializing/Up, a received Up is fine (cells Init x Up = Up,
    // Up x Up = Accept): the rule is specific to local Down.
    var adj2 = Adjacency.init(cfgA());
    _ = adj2.start(0);
    _ = adj2.rxHello(.{ .source_id = sys_b, .holding_time = 30, .circuit_type = .level1_2, .local_circuit_id = 1, .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1 } }, 1);
    try testing.expectEqual(State.initializing, adj2.currentState());
    try testing.expect(adj2.rxHello(stale_up, 2).adjacency_up);
    try testing.expect(adj2.rxHello(stale_up, 3).rejected == null);
    try testing.expectEqual(State.up, adj2.currentState());
}

test "audit F2: a stranger's hello while still Initializing does not lock the circuit for its holding_time" {
    // Before: the first hello heard (from anyone, unauthenticated, no 240)
    // locked the circuit for ITS holding_time — 65 535 units — and every hello
    // of the real neighbour was rejected `.other_neighbor` until then. Now a
    // candidate at Initializing is replaced by the next hello from someone
    // else; the real neighbour's echo takes the circuit to Up, and only THEN
    // does the lock hold (see the "third system-id cannot hijack" test).
    const sys_c: SystemId = .{ 0, 0, 0, 0, 0, 0xC };
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);

    const stranger = adj.rxHello(.{ .source_id = sys_c, .holding_time = 65535, .circuit_type = .level1_2, .local_circuit_id = 1 }, 1);
    try testing.expect(stranger.rejected == null);
    try testing.expectEqual(State.initializing, adj.currentState());
    try testing.expectEqual(sys_c, adj.neighbor_system_id.?);

    const real = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } },
    }, 2);
    try testing.expect(real.rejected == null); // was: .other_neighbor for 65 535 units
    try testing.expect(real.adjacency_up);
    try testing.expectEqual(sys_b, adj.neighbor_system_id.?);
    try testing.expectEqual(@as(Time, 32), adj.hold_deadline); // B's hold, not the stranger's

    // Up: the stranger is now locked out, and its frame changes nothing.
    const again = adj.rxHello(.{ .source_id = sys_c, .holding_time = 65535, .circuit_type = .level1_2, .local_circuit_id = 1 }, 3);
    try testing.expectEqual(@as(?RejectReason, .other_neighbor), again.rejected);
    try testing.expectEqual(State.up, adj.currentState());
    try testing.expectEqual(@as(Time, 32), adj.hold_deadline);
}

test "audit F10: the hold expires at Initializing too — the state a candidate parks in" {
    // M23 in the audit weakened `tick` so the hold only expired from Up and
    // 37/37 stayed green. A candidate that went silent must fall back to Down
    // (transition, no `adjacency_down` — it was never Up).
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    _ = adj.rxHello(.{ .source_id = sys_b, .holding_time = 30, .circuit_type = .level1_2, .local_circuit_id = 1, .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1 } }, 1);
    try testing.expectEqual(State.initializing, adj.currentState());
    try testing.expect(adj.tick(30).transition == null);
    const e = adj.tick(31);
    try testing.expectEqual(Transition{ .from = .initializing, .to = .down }, e.transition.?);
    try testing.expect(e.adjacency_down == null);
    try testing.expectEqual(State.down, adj.currentState());
    try testing.expect(adj.neighbor_system_id == null);
    try testing.expect(adj.neighbor_ext_circuit_id == null);
}

test "audit F11: on an enforced L1 circuit a MISSING or MALFORMED Area Addresses TLV is a mismatch (fail closed)" {
    // SPEC §5 promised both halves; mutations M15/M16 turned each fail-open
    // with the suite green, because every test supplied a well-formed TLV.
    const our_area = [_]u8{ 0x49, 0x00, 0x01 };
    var adj = Adjacency.init(.{ .system_id = sys_a, .extended_local_circuit_id = 1, .circuit_type = .level1, .local_areas = &.{&our_area} });
    _ = adj.start(0);
    const echo: ThreeWayTlv = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 1 } };

    const missing = adj.rxHello(.{ .source_id = sys_b, .holding_time = 30, .circuit_type = .level1, .local_circuit_id = 1, .neighbor_area_addresses = null, .three_way = echo }, 1);
    try testing.expectEqual(@as(?RejectReason, .area_mismatch), missing.rejected);
    try testing.expectEqual(State.down, adj.currentState());

    // Inner record claims 9 bytes, TLV holds 2: malformed → no shared area.
    const malformed = adj.rxHello(.{ .source_id = sys_b, .holding_time = 30, .circuit_type = .level1, .local_circuit_id = 1, .neighbor_area_addresses = &[_]u8{ 9, 0x49 }, .three_way = echo }, 2);
    try testing.expectEqual(@as(?RejectReason, .area_mismatch), malformed.rejected);
    try testing.expectEqual(State.down, adj.currentState());
}

test "audit F6: a TLV lying about its length BEHIND the 240 fails the whole PDU, state unchanged" {
    // `findFirst` stopped at its first hit, so the rest of the stream was never
    // walked; this PDU used to be accepted and raise the adjacency to Up.
    var buf: [128]u8 = undefined;
    var pb = try isis.pdu.P2pHelloBuilder.init(&buf, .{ .source_id = sys_b, .holding_time = 30 });
    var val_buf: [15]u8 = undefined;
    const tw: ThreeWayTlv = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } };
    try pb.tlvs.addTlv(three_way.tlv_code, try tw.encode(&val_buf));
    // An Area Addresses (#1) TLV too, so BOTH lookups this module performs
    // succeed before the liar is reached — without the whole-stream walk the
    // liar is then never seen (the audit's P9 shape).
    try isis.tlvs.addAreaAddresses(&pb.tlvs, &.{&[_]u8{ 0x49, 0x00, 0x01 }});
    try pb.tlvs.addTlv(0x81, &[_]u8{0x01}); // protocols supported, fine
    const good_len = pb.finish().len;
    // Append a TLV header that claims 200 bytes of value with none behind it,
    // and patch the PDU length so the header is inside the PDU.
    var wire: [128]u8 = undefined;
    @memcpy(wire[0..good_len], buf[0..good_len]);
    wire[good_len] = 0x63;
    wire[good_len + 1] = 200;
    const total = good_len + 2;
    std.mem.writeInt(u16, wire[17..19], @intCast(total), .big); // P2P IIH pdu_length offset
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    try testing.expectError(error.TruncatedTlv, adj.rxHelloBytes(wire[0..total], 1));
    try testing.expectEqual(State.down, adj.currentState());
    try testing.expect(adj.neighbor_system_id == null);
    // The same PDU without the liar is accepted and goes Up.
    try testing.expect((try adj.rxHelloBytes(buf[0..good_len], 1)).adjacency_up);
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
    // Bring Up at t=1 with holding_time 30 → deadline 31. (The neighbour
    // advertises Initializing: a peer claiming Up towards a Down circuit is
    // the RFC 5303 (Down, Up) cell and is refused — see the F3 test.)
    _ = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } },
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
    var up: RxHello = .{
        .source_id = sys_b,
        .holding_time = 10,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } },
    };
    _ = adj.rxHello(up, 1); // deadline 11
    up.three_way.?.state = .up; // the peer has seen us Up by now — refreshes carry Up
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

// Regression (audit A1 `isis-adj` F4): RFC 5303 §3.2 table, "Initialize"
// action (received three-way state == Down, any local state) — "no event is
// generated". Before the fix, `applyState` fired `adjacency_down =
// .neighbor_restarted` on EVERY Up-losing transition, including this silent
// one: a peer that reports itself Down (a normal, expected reinitialize, not
// a security event) looked identical to a genuine loss of echo confirmation.
test "audit F4: a peer reporting itself Down drops Up->Initializing SILENTLY (RFC 5303 Initialize action)" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    _ = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } },
    }, 1);
    try testing.expectEqual(State.up, adj.currentState());

    // B restarts and its next hello reports itself Down (still echoing us —
    // an echo is orthogonal to the peer's OWN reported state).
    const e = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .down, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } },
    }, 2);
    try testing.expectEqual(State.initializing, adj.currentState());
    try testing.expectEqual(Transition{ .from = .up, .to = .initializing }, e.transition.?);
    try testing.expect(e.adjacency_down == null); // was: .neighbor_restarted
}

// A genuine echo-loss (peer still reports Initializing/Up, just stops naming
// us) is NOT the "Initialize" action (RFC table cell = "Accept": normal
// procedures apply) and must keep reporting `adjacency_down` — F4's fix must
// not silence this path too.
test "audit F4 control: losing the echo while the peer still reports Initializing DOES report adjacency_down" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    _ = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } },
    }, 1);
    try testing.expectEqual(State.up, adj.currentState());

    const e = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1 }, // no neighbour block anymore
    }, 2);
    try testing.expectEqual(State.initializing, adj.currentState());
    try testing.expectEqual(DownReason.neighbor_restarted, e.adjacency_down.?);
}

// Regression (audit A1 `isis-adj` F8): ISO 10589 allows a neighbour to split
// its announced Area Addresses across more than one #1 TLV; FRR compares
// across all of them. Before the fix `findFirst` only ever saw ONE instance,
// so a neighbour whose shared area sat in a SECOND #1 TLV (behind a
// non-matching first one) was wrongly rejected `.area_mismatch`.
test "audit F8: a shared area in the SECOND Area Addresses TLV is found, not just the first" {
    const our_area = [_]u8{ 0x49, 0x00, 0x01 };
    const their_other_area = [_]u8{ 0x49, 0x99, 0x99 };
    var adj = Adjacency.init(.{
        .system_id = sys_a,
        .extended_local_circuit_id = 1,
        .circuit_type = .level1,
        .local_areas = &.{&our_area},
    });
    _ = adj.start(0);
    const echo: ThreeWayTlv = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 1 } };
    const e = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1,
        .local_circuit_id = 1,
        // First TLV: an area we do NOT share.
        .neighbor_area_addresses = &[_]u8{their_other_area.len} ++ their_other_area,
        // Second TLV: the one we DO share — used to be invisible entirely.
        .neighbor_area_addresses_more = &.{&([_]u8{our_area.len} ++ our_area)},
        .three_way = echo,
    }, 1);
    try testing.expect(e.rejected == null);
    try testing.expect(e.adjacency_up);
}

// Driven end-to-end through the real `isis` codec: two Area Addresses TLVs on
// the wire, the second one shared with us.
test "rxHelloBytes finds a shared area across two wire Area Addresses TLVs" {
    const our_area = [_]u8{ 0x49, 0x00, 0x01 };
    const their_other_area = [_]u8{ 0x49, 0x99, 0x99 };
    var pdu_buf: [160]u8 = undefined;
    var pb = try isis.pdu.P2pHelloBuilder.init(&pdu_buf, .{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1,
    });
    var val_buf: [15]u8 = undefined;
    const tw: ThreeWayTlv = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 1 } };
    try pb.tlvs.addTlv(three_way.tlv_code, try tw.encode(&val_buf));
    try isis.tlvs.addAreaAddresses(&pb.tlvs, &.{&their_other_area});
    try isis.tlvs.addAreaAddresses(&pb.tlvs, &.{&our_area});
    const wire = pb.finish();

    var adj = Adjacency.init(.{
        .system_id = sys_a,
        .extended_local_circuit_id = 1,
        .circuit_type = .level1,
        .local_areas = &.{&our_area},
    });
    _ = adj.start(0);
    const e = try adj.rxHelloBytes(wire, 1);
    try testing.expect(e.rejected == null);
    try testing.expect(e.adjacency_up);
}

// Regression (audit A1 `isis-adj` F16): `isis.header.decode` normalizes a
// wire Maximum Area Addresses of 0 to 3 (ISO 10589 §9.6 shorthand) before
// `rx.max_area_addresses` is ever populated, but `Config.max_area_addresses`
// — a caller-supplied value, not decoded wire bytes — was compared literally.
// A caller writing the same shorthand (`= 0`, "use the default") into
// `Config` rejected every real neighbour, which always arrives normalized.
test "audit F16: Config.max_area_addresses = 0 (the wire shorthand for 3) does not reject a default-3 neighbour" {
    var adj = Adjacency.init(.{
        .system_id = sys_a,
        .extended_local_circuit_id = 1,
        .max_area_addresses = 0, // shorthand for 3, same as the wire encoding
    });
    _ = adj.start(0);
    const e = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .max_area_addresses = 3, // a normalized neighbour, as rxHelloBytes always supplies
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 1 } },
    }, 1);
    try testing.expect(e.rejected == null);
    try testing.expect(e.adjacency_up);
}

// A genuine, non-shorthand disagreement (2 vs 3) must still be rejected — the
// F16 fix only forgives the 0-means-3 shorthand, it does not loosen the check.
test "audit F16 control: a real Maximum Area Addresses disagreement is still rejected" {
    var adj = Adjacency.init(.{
        .system_id = sys_a,
        .extended_local_circuit_id = 1,
        .max_area_addresses = 2, // a genuine (non-shorthand) value
    });
    _ = adj.start(0);
    const e = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .max_area_addresses = 3,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 1 } },
    }, 1);
    try testing.expectEqual(RejectReason.max_area_mismatch, e.rejected.?);
}

// Regression (audit A1 `isis-adj` F15, pin only — no functional change): a
// duplicate TLV 240 uses the FIRST instance, discarding the second — the same
// choice FRR makes (audit: "FRR druhé zahodí s varováním"). Pinned so a future
// change to `findFirst`/the walk order is a deliberate, tested decision.
test "audit F15: a duplicate TLV 240 uses the FIRST instance (matches FRR)" {
    var pdu_buf: [160]u8 = undefined;
    var pb = try isis.pdu.P2pHelloBuilder.init(&pdu_buf, .{ .source_id = sys_b, .holding_time = 30 });
    var val_buf: [15]u8 = undefined;
    // First 240: echoes us, state Initializing -> would bring adjacency Up.
    const first: ThreeWayTlv = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } };
    try pb.tlvs.addTlv(three_way.tlv_code, try first.encode(&val_buf));
    // Second 240: state-only, no echo — would hold at Initializing if it won.
    const second: ThreeWayTlv = .{ .state = .down };
    try pb.tlvs.addTlv(three_way.tlv_code, try second.encode(&val_buf));
    const wire = pb.finish();

    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    const e = try adj.rxHelloBytes(wire, 1);
    // The FIRST instance decided the outcome: echoed, past Down -> Up.
    try testing.expect(e.adjacency_up);
    try testing.expectEqual(State.up, adj.currentState());
}

test "stop from Up reports adjacency_down = stopped" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    _ = adj.rxHello(.{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } },
    }, 1);
    const e = adj.stop();
    try testing.expectEqual(DownReason.stopped, e.adjacency_down.?);
    try testing.expectEqual(State.down, adj.currentState());
}
