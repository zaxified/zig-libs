// SPDX-License-Identifier: MIT

//! The LAN (broadcast circuit) adjacency state machine, ISO/IEC 10589 §8.4,
//! for ONE circuit at ONE level.
//!
//! A broadcast circuit carries many neighbours, so one `LanCircuit` holds a
//! neighbour table (caller-supplied storage: the machine allocates nothing)
//! and a neighbour is identified by the SNPA (source MAC) of its hello, not by
//! a circuit id. A circuit that runs both levels runs two machines, one per
//! LAN IIH type (15 for Level 1, 16 for Level 2), as ISO 10589 does.
//!
//! Neighbour states: `initializing` once a hello is accepted, `up` once the
//! neighbour's IS Neighbours (#6) TLV lists OUR SNPA, which proves it hears
//! us (the LAN's two-way check, the role the three-way TLV plays on a
//! point-to-point circuit). A neighbour that stops listing us falls back to
//! `initializing`; one whose hold timer (its advertised holding time) runs out
//! is deleted. Priority and the LAN ID each neighbour advertises are tracked
//! and flagged when they change, since they are the inputs of the DIS election
//! (`isis-dis`'s `Candidate` is `{system_id, priority, snpa}` plus the
//! pseudonode id in the neighbour's `lan_id`).
//!
//! The acceptance checks are those of `fsm.Adjacency` (loopback, Maximum Area
//! Addresses, holding-time floor, Level 1 area match, Protocols Supported,
//! authentication), plus the LAN ones: the IIH type must be this level's, and
//! with `Config.ipv4_subnets` a neighbour must have an address in one of our
//! subnets (RFC 1195 section 2.2; FRR and holo-isis do the same). The RFC 5306
//! helper runs per neighbour, keyed by SNPA.
//!
//! Pure and time-injected like `fsm.zig`.

const std = @import("std");
const isis = @import("isis");
const fsm = @import("fsm.zig");
const restart_mod = @import("restart.zig");

pub const Time = fsm.Time;
pub const SystemId = fsm.SystemId;
pub const Snpa = [6]u8;
pub const RejectReason = fsm.RejectReason;
pub const DownReason = fsm.DownReason;
pub const Counters = fsm.Counters;
pub const Restart = restart_mod.Restart;

pub const Level = enum { l1, l2 };

pub const Subnet = struct {
    addr: [4]u8,
    prefix_len: u8,

    pub fn contains(self: Subnet, a: [4]u8) bool {
        if (self.prefix_len > 32) return false;
        const x = std.mem.readInt(u32, &self.addr, .big);
        const y = std.mem.readInt(u32, &a, .big);
        if (self.prefix_len == 0) return true;
        const shift: u5 = @intCast(32 - self.prefix_len);
        return (x >> shift) == (y >> shift) and self.prefix_len <= 32;
    }
};

pub const Config = struct {
    system_id: SystemId,
    /// Our SNPA on this circuit; listed by the neighbours that hear us.
    snpa: Snpa,
    level: Level,
    /// The levels this circuit runs, stamped into the hello's circuit type.
    circuit_type: isis.pdu.CircuitType = .level1_2,
    /// Our DIS election priority (7 bits, ISO 10589 section 9.5).
    priority: u7 = 64,
    /// The 1-octet circuit id: pseudonode id of the LAN ID when we are DIS.
    local_circuit_id: u8 = 1,
    max_area_addresses: u8 = isis.header.default_max_area_addresses,
    /// Our area addresses, sent in every hello (#1); a Level 1 neighbour must
    /// share one. Empty: none sent and none required. Borrowed.
    local_areas: []const []const u8 = &.{},
    holding_time: u16 = 30,
    hello_interval: Time = 10,
    min_neighbor_holding_time: u16 = 1,
    auth_keys: []const isis.auth.Key = &.{},
    protocols: []const u8 = &.{},
    /// Our IPv4 subnets on this circuit: sent as #132 (the addresses) and
    /// required of neighbours (one address in any of them) when non-empty.
    ipv4_subnets: []const Subnet = &.{},
    hello_padding: fsm.HelloPadding = .never,
    mtu: u16 = 1492,
    graceful_restart_helper: bool = false,
    /// Send a triggered hello on a neighbour state change.
    triggered_hello: bool = true,
};

pub const NeighborState = enum { initializing, up };

pub const Neighbor = struct {
    snpa: Snpa,
    system_id: SystemId,
    state: NeighborState,
    priority: u7,
    /// The LAN ID the neighbour advertises (its view of the DIS).
    lan_id: [7]u8,
    circuit_type: isis.pdu.CircuitType,
    hold_deadline: Time,
    /// What the adjacency is used for; on a LAN this is the machine's level.
    usage: fsm.Usage,
    helper: restart_mod.HelperState = .{},
};

pub const EventKind = enum {
    /// A hello from an unknown SNPA created an entry (Initializing).
    new_neighbor,
    /// The neighbour reached Up.
    up,
    /// The neighbour left Up (`reason`) and is now Initializing or deleted.
    down,
    /// The entry was deleted (hold expired, or replaced by another system).
    deleted,
    /// Priority or advertised LAN ID changed: re-run the DIS election.
    dis_input_changed,
};

pub const Event = struct {
    kind: EventKind,
    snpa: Snpa,
    system_id: SystemId,
    reason: ?DownReason = null,
};

/// What a received hello caused. Several fields can be set together.
pub const Effect = struct {
    event: ?Event = null,
    /// A second event of the same hello (an entry replaced by another system
    /// reports `deleted` for the old one and `new_neighbor` for the new).
    event2: ?Event = null,
    rejected: ?RejectReason = null,
    /// Send a hello now (triggered, `Config.triggered_hello`).
    send_hello: bool = false,
    /// Send a hello acknowledging the restart of this neighbour (RA, RFC 5306
    /// section 3.2.1): `buildHello` with `.ack`.
    ack: ?SystemId = null,
    /// Send a complete CSNP set and set SRM on every LSP: we are the router that
    /// does it for this restarter (highest priority, then highest MAC, among the
    /// Up neighbours not in restart mode, ourselves included).
    send_csnp: bool = false,
    /// The neighbour's SA changed: suppress / resume advertising it.
    suppress: ?struct { snpa: Snpa, on: bool } = null,
};

pub const DecodeError = isis.pdu.DecodeError || isis.tlv.Error || restart_mod.DecodeError || isis.tlvs.ParseError;

/// A received LAN IIH reduced to what the machine reads.
pub const RxHello = struct {
    snpa: Snpa,
    level: Level,
    source_id: SystemId,
    holding_time: u16,
    circuit_type: isis.pdu.CircuitType,
    priority: u7,
    lan_id: [7]u8,
    max_area_addresses: u8 = isis.header.default_max_area_addresses,
    /// Raw Area Addresses (#1) values, one per TLV instance.
    area_tlvs: []const []const u8 = &.{},
    /// Raw IS Neighbours (#6) values (lists of 6-octet SNPAs), one per instance.
    neighbor_tlvs: []const []const u8 = &.{},
    protocols: ?[]const u8 = null,
    /// Raw IP Interface Address (#132) values, one per instance.
    ip_tlvs: []const []const u8 = &.{},
    restart: ?Restart = null,
};

pub const TickResult = struct {
    /// Events written to the caller's buffer.
    events: []const Event,
    /// A hello is due.
    send_hello: bool,
};

pub const BuildError = error{ BufferTooSmall, ValueTooLong, MalformedTlv };

pub const BuildOptions = struct {
    /// Acknowledge the restart of this neighbour (RA) with this remaining time.
    ack: ?struct { neighbor: SystemId, remaining_time: u16 } = null,
};

pub const LanCircuit = struct {
    cfg: Config,
    storage: []Neighbor,
    len: usize = 0,
    started: bool = false,
    next_hello_due: Time = 0,
    is_dis: bool = false,
    /// The LAN ID we advertise: the DIS we currently see (ours when none).
    lan_id: [7]u8,
    counters: Counters = .{},

    /// `storage` bounds the neighbour table; a neighbour beyond it is refused
    /// (`RejectReason.neighbor_table_full`).
    pub fn init(cfg: Config, storage: []Neighbor) LanCircuit {
        var id: [7]u8 = undefined;
        @memcpy(id[0..6], &cfg.system_id);
        id[6] = cfg.local_circuit_id;
        return .{ .cfg = cfg, .storage = storage, .lan_id = id };
    }

    /// The neighbour table, in the order entries were created.
    pub fn neighbors(self: *const LanCircuit) []const Neighbor {
        return self.storage[0..self.len];
    }

    pub fn find(self: *const LanCircuit, snpa: Snpa) ?*const Neighbor {
        for (self.neighbors()) |*n| if (std.mem.eql(u8, &n.snpa, &snpa)) return n;
        return null;
    }

    pub fn upCount(self: *const LanCircuit) usize {
        var c: usize = 0;
        for (self.neighbors()) |n| {
            if (n.state == .up) c += 1;
        }
        return c;
    }

    /// Tell the machine whether this router is the DIS: the DIS sends hellos
    /// three times as often (ISO 10589 section 8.4.1).
    pub fn setDis(self: *LanCircuit, dis: bool) void {
        self.is_dis = dis;
    }

    /// Set the LAN ID we advertise (the elected DIS's, from `isis-dis`).
    pub fn setLanId(self: *LanCircuit, id: [7]u8) void {
        self.lan_id = id;
    }

    fn interval(self: *const LanCircuit) Time {
        return if (self.is_dis) @max(1, self.cfg.hello_interval / 3) else self.cfg.hello_interval;
    }

    pub fn start(self: *LanCircuit, now: Time) void {
        self.started = true;
        self.len = 0;
        self.next_hello_due = now + self.interval();
    }

    /// Stop the circuit; every neighbour is dropped. Returns how many were Up.
    pub fn stop(self: *LanCircuit) usize {
        const up = self.upCount();
        self.started = false;
        self.len = 0;
        self.counters.adjacency_changes += @intCast(up);
        return up;
    }

    fn note(self: *LanCircuit, eff: Effect) Effect {
        if (eff.rejected) |r| {
            self.counters.rejected_total += 1;
            self.counters.rejected.getPtr(r).* += 1;
        }
        inline for (.{ eff.event, eff.event2 }) |maybe| if (maybe) |ev| switch (ev.kind) {
            .up, .down => self.counters.adjacency_changes += 1,
            else => {},
        };
        return eff;
    }

    /// Delete expired neighbours (writing one `deleted` event each, plus `down`
    /// before it when the neighbour was Up) and report whether a hello is due.
    /// `out` should hold two events per table entry; extra events are dropped.
    pub fn tick(self: *LanCircuit, now: Time, out: []Event) TickResult {
        var n: usize = 0;
        if (self.started) {
            var i: usize = 0;
            while (i < self.len) {
                const nb = self.storage[i];
                if (now >= nb.hold_deadline) {
                    self.counters.hold_expirations += 1;
                    if (nb.state == .up) {
                        self.counters.adjacency_changes += 1;
                        if (n < out.len) {
                            out[n] = .{ .kind = .down, .snpa = nb.snpa, .system_id = nb.system_id, .reason = .hold_expired };
                            n += 1;
                        }
                    } else self.counters.init_fails += 1;
                    if (n < out.len) {
                        out[n] = .{ .kind = .deleted, .snpa = nb.snpa, .system_id = nb.system_id, .reason = .hold_expired };
                        n += 1;
                    }
                    self.removeAt(i);
                } else i += 1;
            }
        }
        var send = false;
        if (self.started and now >= self.next_hello_due) {
            send = true;
            self.next_hello_due = now + self.interval();
        }
        return .{ .events = out[0..n], .send_hello = send };
    }

    fn removeAt(self: *LanCircuit, i: usize) void {
        var j = i;
        while (j + 1 < self.len) : (j += 1) self.storage[j] = self.storage[j + 1];
        self.len -= 1;
    }

    /// Decode a LAN IIH with the `isis` codec and process it. `snpa` is the
    /// source MAC of the frame. A malformed PDU is a typed error and mutates
    /// nothing; one that fails authentication is a `rejected` effect.
    pub fn rxHelloBytes(self: *LanCircuit, bytes: []const u8, snpa: Snpa, now: Time) DecodeError!Effect {
        const p = try isis.LanHello.decode(bytes);
        _ = try isis.tlv.count(p.tlv_bytes);
        if (self.cfg.auth_keys.len != 0) {
            _ = isis.auth.verify(bytes, self.cfg.auth_keys) catch |e| switch (e) {
                error.AuthMissing => return self.note(.{ .rejected = .auth_missing }),
                error.KeyNotFound, error.UnsupportedAuthType, error.AuthFailed, error.MalformedAuth, error.UnsupportedPduType => return self.note(.{ .rejected = .auth_failed }),
                else => |de| return de,
            };
        }
        var areas: [8][]const u8 = undefined;
        var na: usize = 0;
        var nbrs: [8][]const u8 = undefined;
        var nn: usize = 0;
        var ips: [8][]const u8 = undefined;
        var ni: usize = 0;
        var protocols: ?[]const u8 = null;
        var rs: ?Restart = null;
        var it = isis.tlv.TlvIterator.init(p.tlv_bytes);
        while (try it.next()) |raw| {
            switch (raw.code) {
                isis.tlvs.code.area_addresses => {
                    if (na < areas.len) {
                        areas[na] = raw.value;
                        na += 1;
                    }
                },
                isis.tlvs.code.is_neighbours_iih => {
                    if (nn < nbrs.len) {
                        nbrs[nn] = raw.value;
                        nn += 1;
                    }
                },
                isis.tlvs.code.ip_interface_address => {
                    if (ni < ips.len) {
                        ips[ni] = raw.value;
                        ni += 1;
                    }
                },
                isis.tlvs.code.protocols_supported => if (protocols == null) {
                    protocols = raw.value;
                },
                restart_mod.tlv_code => if (self.cfg.graceful_restart_helper and rs == null) {
                    rs = try Restart.decode(raw.value);
                },
                else => {},
            }
        }
        return self.rxHello(.{
            .snpa = snpa,
            .level = if (p.header.pdu_type == .l2_lan_iih) .l2 else .l1,
            .source_id = p.source_id,
            .holding_time = p.holding_time,
            .circuit_type = p.circuit_type,
            .priority = p.priority,
            .lan_id = p.lan_id,
            .max_area_addresses = p.header.max_area_addresses,
            .area_tlvs = areas[0..na],
            .neighbor_tlvs = nbrs[0..nn],
            .protocols = protocols,
            .ip_tlvs = ips[0..ni],
            .restart = rs,
        }, now);
    }

    fn sharesArea(self: *const LanCircuit, tlvs: []const []const u8) bool {
        for (tlvs) |raw| {
            var it = isis.tlvs.AreaAddressIterator.init(raw);
            while (true) {
                const maybe = it.next() catch break;
                const a = maybe orelse break;
                for (self.cfg.local_areas) |local| if (std.mem.eql(u8, local, a)) return true;
            }
        }
        return false;
    }

    fn listsUs(self: *const LanCircuit, tlvs: []const []const u8) bool {
        for (tlvs) |raw| {
            var it = isis.tlvs.SnpaIterator.init(raw);
            while (true) {
                const maybe = it.next() catch break;
                const m = maybe orelse break;
                if (std.mem.eql(u8, &m, &self.cfg.snpa)) return true;
            }
        }
        return false;
    }

    fn sharesSubnet(self: *const LanCircuit, tlvs: []const []const u8) bool {
        for (tlvs) |raw| {
            var pos: usize = 0;
            while (pos + 4 <= raw.len) : (pos += 4) {
                const a: [4]u8 = raw[pos..][0..4].*;
                for (self.cfg.ipv4_subnets) |s| if (s.contains(a)) return true;
            }
        }
        return false;
    }

    /// Process a received LAN IIH. Never fails; a hello it will not act on comes
    /// back as `Effect.rejected` with the table untouched.
    pub fn rxHello(self: *LanCircuit, rx: RxHello, now: Time) Effect {
        return self.note(self.rxInner(rx, now));
    }

    fn rxInner(self: *LanCircuit, rx: RxHello, now: Time) Effect {
        if (!self.started) return .{ .rejected = .not_started };
        if (rx.level != self.cfg.level) return .{ .rejected = .level_mismatch };
        if (std.mem.eql(u8, &rx.source_id, &self.cfg.system_id) or std.mem.eql(u8, &rx.snpa, &self.cfg.snpa)) {
            return .{ .rejected = .looped_back };
        }
        const max_area = if (self.cfg.max_area_addresses == 0) isis.header.default_max_area_addresses else self.cfg.max_area_addresses;
        if (rx.max_area_addresses != max_area) return .{ .rejected = .max_area_mismatch };
        if (rx.holding_time < self.cfg.min_neighbor_holding_time) return .{ .rejected = .holding_time_too_short };
        // Level 1 needs a shared area (ISO 10589 section 8.4.2.1); Level 2 never.
        if (self.cfg.level == .l1 and self.cfg.local_areas.len != 0 and !self.sharesArea(rx.area_tlvs)) {
            return .{ .rejected = .area_mismatch };
        }
        // The neighbour must run the level of this machine.
        const bit: u2 = if (self.cfg.level == .l1) 1 else 2;
        if (@backingInt(rx.circuit_type) & bit == 0) return .{ .rejected = .level_mismatch };
        if (self.cfg.protocols.len != 0) {
            const theirs = rx.protocols orelse &[_]u8{0x81};
            var common = false;
            for (self.cfg.protocols) |n| {
                if (std.mem.indexOfScalar(u8, theirs, n) != null) common = true;
            }
            if (!common) return .{ .rejected = .no_common_protocol };
        }
        if (self.cfg.ipv4_subnets.len != 0 and !self.sharesSubnet(rx.ip_tlvs)) {
            return .{ .rejected = .ip_subnet_mismatch };
        }

        var eff: Effect = .{};
        const heard_us = self.listsUs(rx.neighbor_tlvs);
        var idx: ?usize = null;
        for (self.neighbors(), 0..) |n, i| {
            if (std.mem.eql(u8, &n.snpa, &rx.snpa)) idx = i;
        }

        // RFC 5306 section 3.2.1: a restart request from the Up neighbour of
        // that SNPA and system id changes no state, even though its hello no
        // longer lists us (it lost its adjacency database).
        if (self.cfg.graceful_restart_helper) if (rx.restart) |rs| {
            if (idx) |i| {
                const nb = &self.storage[i];
                if (rs.rr and nb.state == .up and std.mem.eql(u8, &nb.system_id, &rx.source_id)) {
                    if (!nb.helper.restart_mode) {
                        nb.helper.restart_mode = true;
                        nb.hold_deadline = now + @as(Time, rx.holding_time);
                    }
                    if (rs.sa != nb.helper.suppress) {
                        nb.helper.suppress = rs.sa;
                        eff.suppress = .{ .snpa = nb.snpa, .on = rs.sa };
                    }
                    nb.priority = rx.priority;
                    nb.lan_id = rx.lan_id;
                    self.counters.hellos_accepted += 1;
                    eff.ack = nb.system_id;
                    eff.send_csnp = self.iAmCsnpRouter();
                    return eff;
                }
            }
        };

        const new_state: NeighborState = if (heard_us) .up else .initializing;
        const usage: fsm.Usage = if (self.cfg.level == .l1) .level1 else .level2;
        if (idx == null) {
            if (self.len == self.storage.len) return .{ .rejected = .neighbor_table_full };
            self.storage[self.len] = .{
                .snpa = rx.snpa,
                .system_id = rx.source_id,
                .state = new_state,
                .priority = rx.priority,
                .lan_id = rx.lan_id,
                .circuit_type = rx.circuit_type,
                .hold_deadline = now + @as(Time, rx.holding_time),
                .usage = usage,
            };
            self.len += 1;
            self.counters.hellos_accepted += 1;
            eff.event = .{ .kind = .new_neighbor, .snpa = rx.snpa, .system_id = rx.source_id };
            if (new_state == .up) eff.event2 = .{ .kind = .up, .snpa = rx.snpa, .system_id = rx.source_id };
            eff.send_hello = self.cfg.triggered_hello;
            self.helperAfter(&eff, &self.storage[self.len - 1], rx);
            return eff;
        }
        const nb = &self.storage[idx.?];
        // Another system now answers from this SNPA: the old adjacency is gone
        // (reported), the new one starts over.
        if (!std.mem.eql(u8, &nb.system_id, &rx.source_id)) {
            const old = nb.*;
            eff.event = .{ .kind = .deleted, .snpa = old.snpa, .system_id = old.system_id };
            if (old.state == .up) {
                eff.event = .{ .kind = .down, .snpa = old.snpa, .system_id = old.system_id, .reason = .neighbor_restarted };
                eff.event2 = .{ .kind = .deleted, .snpa = old.snpa, .system_id = old.system_id };
            }
            nb.* = .{
                .snpa = rx.snpa,
                .system_id = rx.source_id,
                .state = new_state,
                .priority = rx.priority,
                .lan_id = rx.lan_id,
                .circuit_type = rx.circuit_type,
                .hold_deadline = now + @as(Time, rx.holding_time),
                .usage = usage,
            };
            self.counters.hellos_accepted += 1;
            eff.send_hello = self.cfg.triggered_hello;
            return eff;
        }
        self.counters.hellos_accepted += 1;
        nb.hold_deadline = now + @as(Time, rx.holding_time);
        nb.circuit_type = rx.circuit_type;
        const was = nb.state;
        nb.state = new_state;
        if (was != new_state) {
            if (new_state == .up) {
                eff.event = .{ .kind = .up, .snpa = nb.snpa, .system_id = nb.system_id };
            } else {
                // The neighbour stopped listing us.
                eff.event = .{ .kind = .down, .snpa = nb.snpa, .system_id = nb.system_id, .reason = .neighbor_restarted };
            }
            eff.send_hello = self.cfg.triggered_hello;
        }
        if (nb.priority != rx.priority or !std.mem.eql(u8, &nb.lan_id, &rx.lan_id)) {
            nb.priority = rx.priority;
            nb.lan_id = rx.lan_id;
            if (eff.event == null) {
                eff.event = .{ .kind = .dis_input_changed, .snpa = nb.snpa, .system_id = nb.system_id };
            } else eff.event2 = .{ .kind = .dis_input_changed, .snpa = nb.snpa, .system_id = nb.system_id };
        }
        self.helperAfter(&eff, nb, rx);
        return eff;
    }

    /// Restart handling of a hello processed the normal way.
    fn helperAfter(self: *LanCircuit, eff: *Effect, nb: *Neighbor, rx: RxHello) void {
        if (!self.cfg.graceful_restart_helper) return;
        const rs: Restart = rx.restart orelse .{};
        nb.helper.restart_mode = nb.helper.restart_mode and rs.rr;
        if (rs.sa != nb.helper.suppress) {
            nb.helper.suppress = rs.sa;
            eff.suppress = .{ .snpa = nb.snpa, .on = rs.sa };
        }
        // An RR without an Up adjacency is processed normally and still answered.
        if (rs.rr) eff.ack = nb.system_id;
    }

    /// RFC 5306 section 3.2.1 c): do we have the highest priority (then highest
    /// source MAC) among the Up neighbours not in restart mode, ourselves
    /// included? Then we send the CSNPs.
    fn iAmCsnpRouter(self: *const LanCircuit) bool {
        for (self.neighbors()) |n| {
            if (n.state != .up or n.helper.restart_mode) continue;
            if (n.priority > self.cfg.priority) return false;
            if (n.priority == self.cfg.priority and std.mem.order(u8, &n.snpa, &self.cfg.snpa) == .gt) return false;
        }
        return true;
    }

    fn padTarget(self: *const LanCircuit) u16 {
        return switch (self.cfg.hello_padding) {
            .never => 0,
            .always => self.cfg.mtu,
            .during_formation => if (self.upCount() == self.len and self.len != 0) 0 else self.cfg.mtu,
        };
    }

    /// Build our LAN IIH into `buf`: our areas, the SNPAs of every neighbour
    /// that is not deleted (Initializing or Up: ISO 10589 section 8.4.1), the
    /// protocols and IPv4 addresses, the Restart TLV when helping, padding, and
    /// the authentication TLV signed last.
    pub fn buildHello(self: *const LanCircuit, buf: []u8, opts: BuildOptions) BuildError![]const u8 {
        var b = isis.pdu.LanHelloBuilder.init(buf, .{
            .is_l2 = self.cfg.level == .l2,
            .circuit_type = self.cfg.circuit_type,
            .source_id = self.cfg.system_id,
            .holding_time = self.cfg.holding_time,
            .priority = self.cfg.priority,
            .lan_id = self.lan_id,
            .max_area_addresses = self.cfg.max_area_addresses,
        }) catch return error.BufferTooSmall;
        if (self.cfg.auth_keys.len != 0) try isis.auth.addPlaceholder(&b.tlvs, self.cfg.auth_keys[0]);
        if (self.cfg.local_areas.len != 0) {
            isis.tlvs.addAreaAddresses(&b.tlvs, self.cfg.local_areas) catch |e| switch (e) {
                error.BadTlvLength => return error.MalformedTlv,
                else => |x| return x,
            };
        }
        if (self.cfg.protocols.len != 0) try b.tlvs.addTlv(isis.tlvs.code.protocols_supported, self.cfg.protocols);
        if (self.cfg.ipv4_subnets.len != 0) {
            var v: [isis.tlv.max_value_len]u8 = undefined;
            var n: usize = 0;
            for (self.cfg.ipv4_subnets) |s| {
                if (n + 4 > v.len) return error.ValueTooLong;
                @memcpy(v[n..][0..4], &s.addr);
                n += 4;
            }
            try b.tlvs.addTlv(isis.tlvs.code.ip_interface_address, v[0..n]);
        }
        // IS Neighbours: at most 42 SNPAs per TLV.
        var chunk: [42][6]u8 = undefined;
        var c: usize = 0;
        for (self.neighbors()) |n| {
            chunk[c] = n.snpa;
            c += 1;
            if (c == chunk.len) {
                try isis.tlvs.addIsNeighboursIih(&b.tlvs, chunk[0..c]);
                c = 0;
            }
        }
        if (c != 0) try isis.tlvs.addIsNeighboursIih(&b.tlvs, chunk[0..c]);
        if (self.cfg.graceful_restart_helper) {
            var r: Restart = .{};
            if (opts.ack) |a| r = .{ .ra = true, .remaining_time = a.remaining_time, .neighbor_id = a.neighbor };
            var rbuf: [Restart.max_len]u8 = undefined;
            try b.tlvs.addTlv(restart_mod.tlv_code, r.encode(&rbuf));
        }
        const pad = self.padTarget();
        if (pad != 0) try fsm.addPadding(&b.tlvs, isis.pdu.lan_iih_fixed_len, pad);
        const n = b.finish().len;
        if (self.cfg.auth_keys.len != 0) isis.auth.sign(buf[0..n], self.cfg.auth_keys[0]) catch return error.MalformedTlv;
        return buf[0..n];
    }

    /// The acknowledgement a restarting neighbour waits for: our hello with RA
    /// set, the neighbour's system id and the time left on its hold timer.
    pub fn buildAck(self: *const LanCircuit, buf: []u8, neighbor: SystemId, now: Time) BuildError![]const u8 {
        var left: u16 = self.cfg.holding_time;
        for (self.neighbors()) |n| {
            if (std.mem.eql(u8, &n.system_id, &neighbor)) left = @intCast(@min(n.hold_deadline -| now, std.math.maxInt(u16)));
        }
        return self.buildHello(buf, .{ .ack = .{ .neighbor = neighbor, .remaining_time = left } });
    }
};
