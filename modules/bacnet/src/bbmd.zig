// SPDX-License-Identifier: MIT

//! **Annex J — BBMD behaviour and the foreign-device registration timer.**
//! `bvll` carries the codecs; this file is the policy: a BACnet Broadcast
//! Management Device (J.4, J.5) and the registration side of a foreign device
//! (J.5.2).
//!
//! Like `client` and `device` it is pure and time-injected: the caller passes
//! `now_ms` and a `Transport`, and there is no clock, thread or socket in
//! here.
//!
//! ## What a BBMD does
//!
//! * **Original-Broadcast-NPDU from the local subnet** is re-sent as
//!   `Forwarded-NPDU` (origin = the sender) to every peer in the BDT other than
//!   itself, and to every registered foreign device. A peer whose mask is
//!   `255.255.255.255` gets it by unicast ("one-hop"); any other mask means a
//!   directed broadcast to `ip | ~mask` ("two-hop", the peer's subnet is
//!   reached by the network, not by the peer).
//! * **Forwarded-NPDU from a peer** (accepted only from an address in the BDT)
//!   is broadcast again on the local subnet, as a `Forwarded-NPDU` that keeps
//!   its origin, **unless** this BBMD's own BDT entry has a mask other than
//!   all ones, which means the peer reached the subnet by directed broadcast
//!   and local devices have it already (J.4.5). It also goes to the foreign
//!   devices.
//! * **Distribute-Broadcast-To-Network from a registered foreign device** is
//!   broadcast locally, forwarded to the peers and to the other foreign
//!   devices, all as `Forwarded-NPDU` with the device as origin. From an
//!   unregistered sender it is a NAK.
//! * **Register-Foreign-Device** adds or refreshes a table entry that lives
//!   for `ttl + 30 s` (the grace period of J.5.2.3) and answers with a
//!   `BVLC-Result`; a full table is a NAK.
//! * **Read/Write-Broadcast-Distribution-Table, Read-Foreign-Device-Table,
//!   Delete-Foreign-Device-Table-Entry** are served; Write-BDT is a NAK unless
//!   `Config.accept_bdt_writes` (J.4.4 lets a BBMD refuse it).
//!
//! The NPDU of every message that is also meant for a device on the BBMD's
//! host is handed back as `Outcome.deliver`.

const std = @import("std");
const bvll = @import("bvll.zig");
const transport = @import("transport.zig");

const BipAddress = bvll.BipAddress;
const Transport = transport.Transport;

pub const Error = bvll.Error || transport.TransportError;

/// The grace period a BBMD adds to a foreign device's time-to-live (J.5.2.3).
pub const fd_grace_seconds: u32 = 30;

pub const Config = struct {
    /// This BBMD's own B/IP address: its entry in every BDT, and what it
    /// is never forwarded to.
    address: BipAddress,
    /// Serve `Write-Broadcast-Distribution-Table`. Off by default: a BDT that
    /// anyone on the network can rewrite redirects every broadcast.
    accept_bdt_writes: bool = false,
};

/// What `handle` leaves for the host application.
pub const Outcome = union(enum) {
    /// Nothing for the application: link-layer management, or a message that
    /// was refused.
    none,
    /// An NPDU the application on this host should see. `origin` is the
    /// device that sent it (the BVLC origin of a Forwarded-NPDU, else the
    /// sender); `broadcast` says it was a broadcast.
    deliver: struct { origin: BipAddress, npdu: []const u8, broadcast: bool },
};

pub fn Bbmd(comptime max_bdt: usize, comptime max_fdt: usize) type {
    return struct {
        const Self = @This();

        config: Config,
        tp: Transport,
        bdt: [max_bdt]bvll.BdtEntry = undefined,
        bdt_len: usize = 0,
        fdt: [max_fdt]Foreign = @splat(.{}),
        tx: [transport.max_datagram]u8 = undefined,

        const Foreign = struct {
            active: bool = false,
            address: BipAddress = .{ .ip = @splat(0) },
            ttl_seconds: u16 = 0,
            expires_ms: u64 = 0,
        };

        pub fn init(tp: Transport, config: Config) Self {
            return .{ .config = config, .tp = tp };
        }

        /// Replaces the BDT. The entry for this BBMD itself belongs in it (its
        /// mask says how peers reach this subnet); more than `max_bdt` entries
        /// is `error.NoSpace`.
        pub fn setBdt(self: *Self, entries: []const bvll.BdtEntry) error{NoSpace}!void {
            if (entries.len > max_bdt) return error.NoSpace;
            @memcpy(self.bdt[0..entries.len], entries);
            self.bdt_len = entries.len;
        }

        pub fn bdtEntries(self: *const Self) []const bvll.BdtEntry {
            return self.bdt[0..self.bdt_len];
        }

        /// How many foreign devices are registered (and not yet lapsed).
        pub fn foreignCount(self: *const Self) usize {
            var n: usize = 0;
            for (self.fdt) |f| {
                if (f.active) n += 1;
            }
            return n;
        }

        /// Receives at most one datagram and handles it.
        pub fn poll(self: *Self, now_ms: u64, rx: []u8) Error!Outcome {
            self.expire(now_ms);
            const got = (try self.tp.recv(rx)) orelse return .none;
            return self.handle(now_ms, got.from, got.bytes) catch |e| switch (e) {
                // A malformed datagram is dropped, as `device` drops it.
                error.NotBvlc,
                error.LengthMismatch,
                error.UnknownFunction,
                error.InvalidBody,
                error.Truncated,
                => .none,
                else => e,
            };
        }

        /// Drops the foreign devices whose registration (plus grace) lapsed.
        pub fn expire(self: *Self, now_ms: u64) void {
            for (&self.fdt) |*f| {
                if (f.active and now_ms >= f.expires_ms) f.active = false;
            }
        }

        pub fn handle(self: *Self, now_ms: u64, from: BipAddress, dgram: []const u8) Error!Outcome {
            self.expire(now_ms);
            const msg = try bvll.decode(dgram);
            switch (msg) {
                .original_unicast_npdu => |n| return .{ .deliver = .{ .origin = from, .npdu = n, .broadcast = false } },
                .original_broadcast_npdu => |n| {
                    try self.forwardTo(from, n, .{ .peers = true, .foreign = true, .local = false, .skip = null });
                    return .{ .deliver = .{ .origin = from, .npdu = n, .broadcast = true } };
                },
                .forwarded_npdu => |f| {
                    // Only a BDT peer may hand us a Forwarded-NPDU.
                    const peer = self.findBdt(from) orelse return .none;
                    _ = peer;
                    const local = !self.reachedBySubnetBroadcast();
                    try self.forwardTo(f.origin, f.npdu, .{ .peers = false, .foreign = true, .local = local, .skip = null });
                    return .{ .deliver = .{ .origin = f.origin, .npdu = f.npdu, .broadcast = true } };
                },
                .distribute_broadcast_to_network => |n| {
                    if (self.findForeign(from) == null) {
                        try self.result(from, .distribute_broadcast_to_network_nak);
                        return .none;
                    }
                    try self.forwardTo(from, n, .{ .peers = true, .foreign = true, .local = true, .skip = from });
                    return .{ .deliver = .{ .origin = from, .npdu = n, .broadcast = true } };
                },
                .register_foreign_device => |r| {
                    const slot = self.findForeign(from) orelse self.freeForeign() orelse {
                        try self.result(from, .register_foreign_device_nak);
                        return .none;
                    };
                    slot.* = .{
                        .active = true,
                        .address = from,
                        .ttl_seconds = r.ttl_seconds,
                        .expires_ms = now_ms + (@as(u64, r.ttl_seconds) + fd_grace_seconds) * 1000,
                    };
                    try self.result(from, .success);
                    return .none;
                },
                .read_broadcast_distribution_table => {
                    var body: [bvll.BdtEntry.wire_len * max_bdt]u8 = undefined;
                    const t = try bvll.encodeBdt(self.bdt[0..self.bdt_len], &body);
                    try self.send(from, .{ .read_broadcast_distribution_table_ack = t });
                },
                .write_broadcast_distribution_table => |t| {
                    if (!self.config.accept_bdt_writes) {
                        try self.result(from, .write_broadcast_distribution_table_nak);
                        return .none;
                    }
                    var entries: [max_bdt]bvll.BdtEntry = undefined;
                    var n: usize = 0;
                    var it = bvll.bdtIterator(t);
                    while (it.next()) |e| {
                        if (n == max_bdt) {
                            try self.result(from, .write_broadcast_distribution_table_nak);
                            return .none;
                        }
                        entries[n] = e;
                        n += 1;
                    }
                    self.setBdt(entries[0..n]) catch unreachable;
                    try self.result(from, .success);
                },
                .read_foreign_device_table => {
                    var entries: [max_fdt]bvll.FdtEntry = undefined;
                    var n: usize = 0;
                    for (self.fdt) |f| {
                        if (!f.active) continue;
                        const left_ms = f.expires_ms -| now_ms;
                        entries[n] = .{
                            .address = f.address,
                            .ttl_seconds = f.ttl_seconds,
                            .remaining_seconds = @intCast(@min((left_ms + 999) / 1000, std.math.maxInt(u16))),
                        };
                        n += 1;
                    }
                    var body: [bvll.FdtEntry.wire_len * max_fdt]u8 = undefined;
                    const t = try bvll.encodeFdt(entries[0..n], &body);
                    try self.send(from, .{ .read_foreign_device_table_ack = t });
                },
                .delete_foreign_device_table_entry => |a| {
                    if (self.findForeign(a)) |f| {
                        f.active = false;
                        try self.result(from, .success);
                    } else try self.result(from, .delete_foreign_device_table_entry_nak);
                },
                // Results and acks are answers to requests this BBMD does not
                // make; a secure wrapper is not interpreted.
                else => {},
            }
            return .none;
        }

        // ── internals ──────────────────────────────────────────────────────

        fn findBdt(self: *Self, a: BipAddress) ?*bvll.BdtEntry {
            for (self.bdt[0..self.bdt_len]) |*e| {
                if (e.address.eql(a)) return e;
            }
            return null;
        }

        fn findForeign(self: *Self, a: BipAddress) ?*Foreign {
            for (&self.fdt) |*f| {
                if (f.active and f.address.eql(a)) return f;
            }
            return null;
        }

        fn freeForeign(self: *Self) ?*Foreign {
            for (&self.fdt) |*f| {
                if (!f.active) return f;
            }
            return null;
        }

        /// True when this BBMD's own BDT entry says peers reach its subnet by
        /// directed broadcast (a mask other than all ones): the local devices
        /// then have a forwarded message already.
        fn reachedBySubnetBroadcast(self: *Self) bool {
            const me = self.findBdt(self.config.address) orelse return false;
            return !std.mem.eql(u8, &me.mask, &[4]u8{ 255, 255, 255, 255 });
        }

        const Targets = struct { peers: bool, foreign: bool, local: bool, skip: ?BipAddress };

        fn forwardTo(self: *Self, origin: BipAddress, npdu: []const u8, t: Targets) Error!void {
            var buf: [transport.max_datagram]u8 = undefined;
            const dg = try bvll.encode(.{ .forwarded_npdu = .{ .origin = origin, .npdu = npdu } }, &buf);
            if (t.local) try self.tp.broadcast(dg);
            if (t.peers) {
                for (self.bdt[0..self.bdt_len]) |e| {
                    if (e.address.eql(self.config.address)) continue;
                    const all_ones = std.mem.eql(u8, &e.mask, &[4]u8{ 255, 255, 255, 255 });
                    if (all_ones) {
                        try self.tp.send(e.address, dg);
                    } else {
                        var dest = e.address;
                        for (&dest.ip, e.mask) |*b, m| b.* |= ~m;
                        try self.tp.send(dest, dg);
                    }
                }
            }
            if (t.foreign) {
                for (self.fdt) |f| {
                    if (!f.active) continue;
                    // The device that originated it already has it.
                    if (f.address.eql(origin)) continue;
                    if (t.skip) |s| if (f.address.eql(s)) continue;
                    try self.tp.send(f.address, dg);
                }
            }
        }

        fn result(self: *Self, to: BipAddress, code: bvll.ResultCode) Error!void {
            try self.send(to, .{ .result = code });
        }

        fn send(self: *Self, to: BipAddress, msg: bvll.Message) Error!void {
            const dg = try bvll.encode(msg, &self.tx);
            try self.tp.send(to, dg);
        }
    };
}

/// The foreign-device side (J.5.2): keeps a registration with one BBMD alive.
/// Call `tick` from the poll loop and feed it the `BVLC-Result` the BBMD
/// answers with.
pub const ForeignRegistration = struct {
    bbmd: BipAddress,
    /// The time-to-live asked for, in seconds. The BBMD keeps the entry for
    /// 30 seconds longer.
    ttl_seconds: u16,
    state: State = .unregistered,
    /// When the next Register-Foreign-Device is due.
    next_ms: u64 = 0,

    pub const State = enum {
        /// Nothing sent yet, or a registration was refused or lapsed.
        unregistered,
        /// A request is out, no answer yet.
        pending,
        registered,
        /// The BBMD answered with a NAK (its table is full, or it is no BBMD).
        refused,
    };

    /// How long to wait for the answer before asking again.
    pub const retry_ms: u64 = 5_000;

    pub fn init(bbmd: BipAddress, ttl_seconds: u16) ForeignRegistration {
        return .{ .bbmd = bbmd, .ttl_seconds = ttl_seconds };
    }

    /// Sends the registration when it is due: the first time, again at half
    /// the time-to-live while registered (long before the BBMD's grace period
    /// is needed), and every `retry_ms` while no answer has come or after a
    /// refusal.
    pub fn tick(self: *ForeignRegistration, now_ms: u64, tp: Transport) Error!void {
        if (now_ms < self.next_ms) return;
        var buf: [8]u8 = undefined;
        const dg = try bvll.encode(.{ .register_foreign_device = .{ .ttl_seconds = self.ttl_seconds } }, &buf);
        try tp.send(self.bbmd, dg);
        const half: u64 = @max(1000, @as(u64, self.ttl_seconds) * 500);
        self.next_ms = now_ms + if (self.state == .registered) half else retry_ms;
        if (self.state != .registered) self.state = .pending;
    }

    /// The BBMD's answer to a Register-Foreign-Device; a success schedules the
    /// next registration at half the time-to-live from `now_ms`.
    pub fn onResult(self: *ForeignRegistration, now_ms: u64, from: BipAddress, code: bvll.ResultCode) void {
        if (!from.eql(self.bbmd)) return;
        switch (code) {
            .success => {
                self.state = .registered;
                self.next_ms = now_ms + @max(1000, @as(u64, self.ttl_seconds) * 500);
            },
            .register_foreign_device_nak => self.state = .refused,
            else => {},
        }
    }

    pub fn isRegistered(self: *const ForeignRegistration) bool {
        return self.state == .registered;
    }

    /// Sends `npdu` to the BBMD as a Distribute-Broadcast-To-Network. Refused
    /// (`error.NotRegistered`) until the BBMD has accepted the registration:
    /// an unregistered sender gets a NAK for it.
    pub fn distribute(self: *const ForeignRegistration, tp: Transport, npdu: []const u8) (Error || error{NotRegistered})!void {
        if (self.state != .registered) return error.NotRegistered;
        var buf: [transport.max_datagram]u8 = undefined;
        const dg = try bvll.wrap(.distribute_broadcast_to_network, npdu, &buf);
        try tp.send(self.bbmd, dg);
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const A: BipAddress = .{ .ip = .{ 192, 0, 2, 10 } }; // this BBMD
const B: BipAddress = .{ .ip = .{ 198, 51, 100, 10 } }; // a peer BBMD (one-hop)
const C: BipAddress = .{ .ip = .{ 203, 0, 113, 10 } }; // a peer BBMD (two-hop)
const F: BipAddress = .{ .ip = .{ 192, 0, 2, 50 } }; // a foreign device
const G: BipAddress = .{ .ip = .{ 192, 0, 2, 51 } }; // another foreign device
const D: BipAddress = .{ .ip = .{ 192, 0, 2, 60 } }; // a local device

const Rig = struct {
    net: transport.LoopNetwork = .{},
    a: transport.LoopTransport = transport.LoopTransport.init(A),
    b: transport.LoopTransport = transport.LoopTransport.init(B),
    c: transport.LoopTransport = transport.LoopTransport.init(C),
    f: transport.LoopTransport = transport.LoopTransport.init(F),
    g: transport.LoopTransport = transport.LoopTransport.init(G),
    d: transport.LoopTransport = transport.LoopTransport.init(D),

    fn wire(self: *Rig) void {
        self.net.attach(&self.a);
        self.net.attach(&self.b);
        self.net.attach(&self.c);
        self.net.attach(&self.f);
        self.net.attach(&self.g);
        self.net.attach(&self.d);
    }

    /// Everything waiting at `ep`, as the BVLC functions in arrival order.
    fn drain(ep: *transport.LoopTransport, out: *[8]bvll.Function) usize {
        var n: usize = 0;
        var buf: [transport.max_datagram]u8 = undefined;
        while ((ep.transport().recv(&buf) catch null)) |got| {
            out[n] = (bvll.decode(got.bytes) catch unreachable).function();
            n += 1;
        }
        return n;
    }
};

const npdu_bytes = [_]u8{ 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08 }; // a Who-Is NPDU

fn dgOf(msg: bvll.Message, buf: []u8) []u8 {
    return bvll.encode(msg, buf) catch unreachable;
}

fn newBbmd(rig: *Rig) Bbmd(4, 2) {
    var bb = Bbmd(4, 2).init(rig.a.transport(), .{ .address = A });
    bb.setBdt(&.{
        .{ .address = A, .mask = .{ 255, 255, 255, 255 } },
        .{ .address = B, .mask = .{ 255, 255, 255, 255 } },
        .{ .address = C, .mask = .{ 255, 255, 255, 0 } },
    }) catch unreachable;
    return bb;
}

test "Register-Foreign-Device: accepted for ttl + 30 s, refreshed, lapses, full table NAKs" {
    var rig: Rig = .{};
    rig.wire();
    var bb = newBbmd(&rig);
    var buf: [64]u8 = undefined;
    var fs: [8]bvll.Function = undefined;

    _ = try bb.handle(0, F, dgOf(.{ .register_foreign_device = .{ .ttl_seconds = 60 } }, &buf));
    try testing.expectEqual(@as(usize, 1), bb.foreignCount());
    var rx: [64]u8 = undefined;
    const ack = (try rig.f.transport().recv(&rx)).?;
    try testing.expectEqual(bvll.ResultCode.success, (try bvll.decode(ack.bytes)).result);

    // Alive at 89.9 s (60 + 30 grace), gone at 90 s.
    bb.expire(89_999);
    try testing.expectEqual(@as(usize, 1), bb.foreignCount());
    // Re-registering refreshes the same slot.
    _ = try bb.handle(80_000, F, dgOf(.{ .register_foreign_device = .{ .ttl_seconds = 60 } }, &buf));
    try testing.expectEqual(@as(usize, 1), bb.foreignCount());
    bb.expire(169_999);
    try testing.expectEqual(@as(usize, 1), bb.foreignCount());
    bb.expire(170_000);
    try testing.expectEqual(@as(usize, 0), bb.foreignCount());
    _ = Rig.drain(&rig.f, &fs);

    // Two slots: the third foreign device is refused.
    _ = try bb.handle(0, F, dgOf(.{ .register_foreign_device = .{ .ttl_seconds = 60 } }, &buf));
    _ = try bb.handle(0, G, dgOf(.{ .register_foreign_device = .{ .ttl_seconds = 60 } }, &buf));
    _ = try bb.handle(0, D, dgOf(.{ .register_foreign_device = .{ .ttl_seconds = 60 } }, &buf));
    const nak = (try rig.d.transport().recv(&rx)).?;
    try testing.expectEqual(bvll.ResultCode.register_foreign_device_nak, (try bvll.decode(nak.bytes)).result);
}

test "an Original-Broadcast is forwarded to the peers (one-hop unicast, two-hop directed) and the foreign devices" {
    var rig: Rig = .{};
    rig.wire();
    var bb = newBbmd(&rig);
    var buf: [64]u8 = undefined;
    var fs: [8]bvll.Function = undefined;
    _ = try bb.handle(0, F, dgOf(.{ .register_foreign_device = .{ .ttl_seconds = 60 } }, &buf));
    _ = Rig.drain(&rig.f, &fs);

    const out = try bb.handle(1, D, dgOf(.{ .original_broadcast_npdu = &npdu_bytes }, &buf));
    try testing.expectEqual(D, out.deliver.origin);
    try testing.expect(out.deliver.broadcast);

    // Peer B by unicast to its address, peer C by a directed broadcast to
    // 203.0.113.255 (no such endpoint in the loop network: nothing arrives).
    var rx: [transport.max_datagram]u8 = undefined;
    const to_b = (try rig.b.transport().recv(&rx)).?;
    const fwd = (try bvll.decode(to_b.bytes)).forwarded_npdu;
    try testing.expectEqual(D, fwd.origin);
    try testing.expectEqualSlices(u8, &npdu_bytes, fwd.npdu);
    // The foreign device gets it too, with the same origin.
    const to_f = (try rig.f.transport().recv(&rx)).?;
    try testing.expectEqual(D, (try bvll.decode(to_f.bytes)).forwarded_npdu.origin);
    // Nothing went to the BBMD itself, and no local re-broadcast of a local broadcast.
    try testing.expectEqual(@as(usize, 0), Rig.drain(&rig.g, &fs));
    try testing.expectEqual(@as(usize, 0), Rig.drain(&rig.d, &fs));
}

test "a Forwarded-NPDU from a peer is re-broadcast locally and sent to the foreign devices; a stranger's is dropped" {
    var rig: Rig = .{};
    rig.wire();
    var bb = newBbmd(&rig);
    var buf: [64]u8 = undefined;
    var fs: [8]bvll.Function = undefined;
    _ = try bb.handle(0, F, dgOf(.{ .register_foreign_device = .{ .ttl_seconds = 60 } }, &buf));
    _ = Rig.drain(&rig.f, &fs);
    const origin: BipAddress = .{ .ip = .{ 198, 51, 100, 77 } };

    // From a stranger: nothing happens.
    const dropped = try bb.handle(1, G, dgOf(.{ .forwarded_npdu = .{ .origin = origin, .npdu = &npdu_bytes } }, &buf));
    try testing.expect(dropped == .none);
    try testing.expectEqual(@as(usize, 0), Rig.drain(&rig.d, &fs));

    // From peer B (this BBMD's own entry is all-ones: B came by unicast).
    const out = try bb.handle(2, B, dgOf(.{ .forwarded_npdu = .{ .origin = origin, .npdu = &npdu_bytes } }, &buf));
    try testing.expectEqual(origin, out.deliver.origin);
    try testing.expectEqual(@as(usize, 1), Rig.drain(&rig.d, &fs)); // the local broadcast
    try testing.expectEqual(bvll.Function.forwarded_npdu, fs[0]);
    // The foreign device gets its unicast copy (and, an artefact of the
    // loop network, which has no subnets, the local broadcast too).
    try testing.expectEqual(@as(usize, 2), Rig.drain(&rig.f, &fs));

    // With a subnet mask on its own entry the peers reach the subnet
    // themselves: no local re-broadcast, the foreign devices still get it.
    bb.setBdt(&.{
        .{ .address = A, .mask = .{ 255, 255, 255, 0 } },
        .{ .address = B, .mask = .{ 255, 255, 255, 255 } },
    }) catch unreachable;
    _ = try bb.handle(3, B, dgOf(.{ .forwarded_npdu = .{ .origin = origin, .npdu = &npdu_bytes } }, &buf));
    try testing.expectEqual(@as(usize, 0), Rig.drain(&rig.d, &fs));
    try testing.expectEqual(@as(usize, 1), Rig.drain(&rig.f, &fs));
}

test "Distribute-Broadcast-To-Network: from a registered device it fans out, from a stranger it is a NAK" {
    var rig: Rig = .{};
    rig.wire();
    var bb = newBbmd(&rig);
    var buf: [64]u8 = undefined;
    var fs: [8]bvll.Function = undefined;
    _ = try bb.handle(0, F, dgOf(.{ .register_foreign_device = .{ .ttl_seconds = 60 } }, &buf));
    _ = try bb.handle(0, G, dgOf(.{ .register_foreign_device = .{ .ttl_seconds = 60 } }, &buf));
    _ = Rig.drain(&rig.f, &fs);
    _ = Rig.drain(&rig.g, &fs);

    // A stranger.
    _ = try bb.handle(1, D, dgOf(.{ .distribute_broadcast_to_network = &npdu_bytes }, &buf));
    var rx: [64]u8 = undefined;
    const nak = (try rig.d.transport().recv(&rx)).?;
    try testing.expectEqual(bvll.ResultCode.distribute_broadcast_to_network_nak, (try bvll.decode(nak.bytes)).result);

    // The registered F: a local broadcast (D sees it), peer B by unicast, the
    // other foreign device G by unicast; F itself gets no unicast copy. The
    // loop network has no subnets, so its broadcast reaches every endpoint
    // once: B, G and F each see that one as well.
    const out = try bb.handle(2, F, dgOf(.{ .distribute_broadcast_to_network = &npdu_bytes }, &buf));
    try testing.expectEqual(F, out.deliver.origin);
    try testing.expectEqual(@as(usize, 1), Rig.drain(&rig.d, &fs));
    try testing.expectEqual(@as(usize, 2), Rig.drain(&rig.b, &fs));
    try testing.expectEqual(@as(usize, 2), Rig.drain(&rig.g, &fs));
    try testing.expectEqual(@as(usize, 1), Rig.drain(&rig.f, &fs));
}

test "the tables: Read-BDT, Write-BDT (refused unless enabled), Read-FDT, Delete-FDT-Entry" {
    var rig: Rig = .{};
    rig.wire();
    var bb = newBbmd(&rig);
    var buf: [128]u8 = undefined;
    var rx: [128]u8 = undefined;

    _ = try bb.handle(0, D, dgOf(.read_broadcast_distribution_table, &buf));
    const bdt_ack = (try rig.d.transport().recv(&rx)).?;
    var it = bvll.bdtIterator((try bvll.decode(bdt_ack.bytes)).read_broadcast_distribution_table_ack);
    try testing.expectEqual(A, it.next().?.address);
    try testing.expectEqual(B, it.next().?.address);
    try testing.expectEqual([4]u8{ 255, 255, 255, 0 }, it.next().?.mask);
    try testing.expect(it.next() == null);

    var tbl: [64]u8 = undefined;
    const t = try bvll.encodeBdt(&.{.{ .address = A }}, &tbl);
    _ = try bb.handle(0, D, dgOf(.{ .write_broadcast_distribution_table = t }, &buf));
    try testing.expectEqual(bvll.ResultCode.write_broadcast_distribution_table_nak, (try bvll.decode((try rig.d.transport().recv(&rx)).?.bytes)).result);
    try testing.expectEqual(@as(usize, 3), bb.bdtEntries().len);
    bb.config.accept_bdt_writes = true;
    _ = try bb.handle(0, D, dgOf(.{ .write_broadcast_distribution_table = t }, &buf));
    try testing.expectEqual(bvll.ResultCode.success, (try bvll.decode((try rig.d.transport().recv(&rx)).?.bytes)).result);
    try testing.expectEqual(@as(usize, 1), bb.bdtEntries().len);
    // Five entries do not fit a table of four.
    const five = try bvll.encodeBdt(&.{ .{ .address = A }, .{ .address = B }, .{ .address = C }, .{ .address = D }, .{ .address = F } }, &tbl);
    _ = try bb.handle(0, D, dgOf(.{ .write_broadcast_distribution_table = five }, &buf));
    try testing.expectEqual(bvll.ResultCode.write_broadcast_distribution_table_nak, (try bvll.decode((try rig.d.transport().recv(&rx)).?.bytes)).result);
    try testing.expectEqual(@as(usize, 1), bb.bdtEntries().len);

    _ = try bb.handle(1_000, F, dgOf(.{ .register_foreign_device = .{ .ttl_seconds = 60 } }, &buf));
    _ = try rig.f.transport().recv(&rx);
    _ = try bb.handle(11_000, D, dgOf(.read_foreign_device_table, &buf));
    const fdt_ack = (try rig.d.transport().recv(&rx)).?;
    var fit = bvll.fdtIterator((try bvll.decode(fdt_ack.bytes)).read_foreign_device_table_ack);
    const e = fit.next().?;
    try testing.expectEqual(F, e.address);
    try testing.expectEqual(@as(u16, 60), e.ttl_seconds);
    try testing.expectEqual(@as(u16, 80), e.remaining_seconds); // 60 + 30 - 10
    try testing.expect(fit.next() == null);

    _ = try bb.handle(12_000, D, dgOf(.{ .delete_foreign_device_table_entry = F }, &buf));
    try testing.expectEqual(bvll.ResultCode.success, (try bvll.decode((try rig.d.transport().recv(&rx)).?.bytes)).result);
    try testing.expectEqual(@as(usize, 0), bb.foreignCount());
    _ = try bb.handle(12_000, D, dgOf(.{ .delete_foreign_device_table_entry = F }, &buf));
    try testing.expectEqual(bvll.ResultCode.delete_foreign_device_table_entry_nak, (try bvll.decode((try rig.d.transport().recv(&rx)).?.bytes)).result);
}

test "ForeignRegistration: registers, re-registers at half the ttl, retries a silent or refusing BBMD" {
    var rig: Rig = .{};
    rig.wire();
    var bb = newBbmd(&rig);
    var reg = ForeignRegistration.init(A, 60);
    var rx: [transport.max_datagram]u8 = undefined;
    try testing.expectError(error.NotRegistered, reg.distribute(rig.f.transport(), &npdu_bytes));

    // The first tick sends; the BBMD answers; the result registers.
    try reg.tick(0, rig.f.transport());
    try testing.expectEqual(ForeignRegistration.State.pending, reg.state);
    const req = (try rig.a.transport().recv(&rx)).?;
    _ = try bb.handle(0, req.from, req.bytes);
    const ans = (try rig.f.transport().recv(&rx)).?;
    reg.onResult(0, ans.from, (try bvll.decode(ans.bytes)).result);
    try testing.expect(reg.isRegistered());
    // An answer from anyone else is ignored.
    reg.onResult(0, D, .register_foreign_device_nak);
    try testing.expect(reg.isRegistered());

    // Nothing is sent before half the ttl (30 s), then it re-registers.
    try reg.tick(29_999, rig.f.transport());
    try testing.expectEqual(@as(usize, 0), rig.a.pending());
    try reg.tick(30_000, rig.f.transport());
    try testing.expectEqual(@as(usize, 1), rig.a.pending());
    _ = try rig.a.transport().recv(&rx);

    // Distribute goes to the BBMD as Distribute-Broadcast-To-Network.
    try reg.distribute(rig.f.transport(), &npdu_bytes);
    const dist = (try rig.a.transport().recv(&rx)).?;
    try testing.expectEqualSlices(u8, &npdu_bytes, (try bvll.decode(dist.bytes)).distribute_broadcast_to_network);

    // A NAK marks it refused and the next tick retries after 5 s.
    reg.onResult(30_001, A, .register_foreign_device_nak);
    try testing.expectEqual(ForeignRegistration.State.refused, reg.state);
    try reg.tick(60_000, rig.f.transport());
    try testing.expectEqual(ForeignRegistration.State.pending, reg.state);
    _ = try rig.a.transport().recv(&rx);
    try reg.tick(64_999, rig.f.transport());
    try testing.expectEqual(@as(usize, 0), rig.a.pending());
    try reg.tick(65_000, rig.f.transport());
    try testing.expectEqual(@as(usize, 1), rig.a.pending());
}
