// SPDX-License-Identifier: MIT

//! **Implicit (Class 0/1) I/O messaging** (CIP Vol 1 ch. 3, Vol 2 §3-2): the
//! cyclic UDP datagrams, port 2222, that carry an assembly's octets once a
//! `Forward_Open` has set a connection up.
//!
//! This file is the connection's *engine* and nothing else: it holds the
//! timers, the sequence numbers and the checks, and it neither owns a socket
//! nor reads a clock. The caller hands it the time (`now_us`, microseconds,
//! monotonic) and the octets that arrived, and takes back the octets to send.
//! That is what makes the RPI timer, the watchdog and the duplicate rules
//! testable with a fake clock, and what lets the `adapter` use it without
//! this file knowing about assemblies.
//!
//! One datagram is a bare CPF item list (no encapsulation header, no
//! interface handle): a **Sequenced Address** item (`0x8002`: connection id,
//! 32-bit sequence number) and a **Connected Data** item (`0x00B1`). The data
//! item holds, in order, a 16-bit **data sequence count** (Class 1 only), an
//! optional 32-bit **Run/Idle header** (bit 0 = Run), and the application's
//! octets.
//!
//! The rules the engine implements:
//!
//! * **Producing.** A *cyclic* connection sends one datagram every RPI; a
//!   *change-of-state* or *application-triggered* one sends when the caller
//!   says the data changed (not sooner than the production inhibit time after
//!   the last one) and, as a heartbeat, every RPI. The 32-bit sequence number
//!   grows by one with every datagram; the 16-bit count grows with every
//!   *new* production and is repeated by a heartbeat.
//! * **Consuming.** A datagram for another connection id is not ours. A
//!   sequence number that is not ahead of the last one is stale and is
//!   dropped without touching the watchdog; a jump is a **gap** (reported as
//!   the number of datagrams missed) and the datagram is taken. A repeated
//!   data count is a heartbeat: no new data, but the watchdog is restarted.
//! * **Watchdog.** The connection is dead when nothing valid arrived for
//!   `RPI × 4 × 2^multiplier` (the consuming direction's RPI). `check` reports
//!   it once; the connection is then `timed_out` and neither sends nor
//!   receives.

const std = @import("std");
const cpf = @import("cpf.zig");

pub const Error = error{
    /// The output buffer is too small for the datagram.
    BufferTooSmall,
    /// The payload does not fit the 16-bit item length.
    TooLong,
};

/// The transport trigger of a connection (`TransportClass.trigger`).
pub const Trigger = enum(u3) {
    cyclic = 0,
    change_of_state = 1,
    application = 2,
};

/// Class 0 sends data alone; Class 1 prefixes a 16-bit sequence count.
pub const TransportClass = enum(u1) { class0 = 0, class1 = 1 };

/// The 32-bit real-time header's Run bit.
pub const run_bit: u32 = 1;

pub const Config = struct {
    class: TransportClass = .class1,
    trigger: Trigger = .cyclic,
    /// The connection id on the datagrams this end sends.
    produce_id: u32,
    /// The connection id this end accepts.
    consume_id: u32,
    /// Microseconds between productions (the producing direction's RPI).
    produce_rpi_us: u32,
    /// The other end's RPI, which times the watchdog.
    consume_rpi_us: u32,
    /// `Forward_Open`'s connection timeout multiplier: the watchdog is
    /// `consume_rpi × 4 × 2^multiplier` (values above 7 are reserved and are
    /// taken as 7).
    timeout_multiplier: u8 = 0,
    /// A 32-bit Run/Idle header leads the data this end sends / receives.
    produce_header: bool = false,
    consume_header: bool = false,
    /// Least time between two data-change productions, microseconds.
    inhibit_us: u32 = 0,
};

pub const State = enum { established, timed_out };

/// What `receive` made of one datagram.
pub const Received = union(enum) {
    /// A new production. `payload` borrows from the datagram. `run` is the
    /// Run/Idle header's bit (always true when the connection has no header).
    /// `missed` datagrams were lost since the last one.
    data: struct { payload: []const u8, run: bool, missed: u32 },
    /// The same data count again: nothing new, the watchdog is restarted.
    heartbeat: struct { run: bool, missed: u32 },
    /// Not accepted: see `Dropped`. The watchdog is **not** restarted.
    dropped: Dropped,
};

pub const Dropped = enum {
    /// The connection is `timed_out`.
    closed,
    /// Not an I/O datagram (not two items, wrong item types, short data).
    malformed,
    /// For another connection id.
    wrong_connection,
    /// A sequence number or data count behind the last one.
    stale,
};

/// Why `check` says the connection is dead.
pub const Expired = struct { silent_for_us: u64 };

pub const Connection = struct {
    cfg: Config,
    state: State = .established,
    /// The 32-bit sequence number of the next datagram sent, and the 16-bit
    /// data count of the last new production.
    tx_seq: u32 = 0,
    tx_count: u16 = 0,
    next_tx_us: u64,
    last_new_us: ?u64 = null,
    /// The last sequence number / count accepted.
    rx_seq: ?u32 = null,
    rx_count: ?u16 = null,
    deadline_us: u64,
    /// Counters for a test or a status page.
    produced: u64 = 0,
    consumed: u64 = 0,
    missed: u64 = 0,
    stale: u64 = 0,

    pub fn init(cfg: Config, now_us: u64) Connection {
        return .{
            .cfg = cfg,
            .next_tx_us = now_us,
            .deadline_us = now_us +| timeoutUs(cfg),
        };
    }

    /// `consume_rpi × 4 × 2^multiplier`.
    pub fn timeoutUs(cfg: Config) u64 {
        return @as(u64, cfg.consume_rpi_us) * (@as(u64, 4) << @intCast(@min(cfg.timeout_multiplier, 7)));
    }

    /// The next moment `produce` or `check` has something to do.
    pub fn nextDueUs(self: *const Connection) ?u64 {
        if (self.state != .established) return null;
        return @min(self.next_tx_us, self.deadline_us);
    }

    /// Builds the next datagram into `out` when one is due, else `null`.
    /// `payload` is the application's octets; `changed` says they differ from
    /// the last production (it matters to the change-of-state and
    /// application triggers only); `run` is the header's Run bit.
    pub fn produce(
        self: *Connection,
        now_us: u64,
        payload: []const u8,
        changed: bool,
        run: bool,
        out: []u8,
    ) Error!?[]const u8 {
        if (self.state != .established) return null;
        const heartbeat_due = now_us >= self.next_tx_us;
        var new = false;
        switch (self.cfg.trigger) {
            .cyclic => {
                if (!heartbeat_due) return null;
                new = true;
            },
            .change_of_state, .application => {
                const inhibited = if (self.last_new_us) |t| now_us < t +| self.cfg.inhibit_us else false;
                if (changed and !inhibited) {
                    new = true;
                } else if (!heartbeat_due) {
                    return null;
                }
            },
        }
        const dgram = try encode(self.cfg, self.tx_seq, self.tx_count +% @intFromBool(new), run, payload, out);
        self.tx_seq +%= 1;
        if (new) {
            self.tx_count +%= 1;
            self.last_new_us = now_us;
        }
        self.produced += 1;
        // Cyclic: keep the cadence; if the caller was late by more than a
        // period, restart it from now instead of bursting to catch up.
        // Change of state / application: any production restarts the
        // heartbeat timer.
        const rpi: u64 = self.cfg.produce_rpi_us;
        self.next_tx_us = if (self.cfg.trigger != .cyclic or now_us >= self.next_tx_us +| rpi)
            now_us +| rpi
        else
            self.next_tx_us +| rpi;
        return dgram;
    }

    /// Takes one datagram that arrived at `now_us`.
    pub fn receive(self: *Connection, now_us: u64, datagram: []const u8) Received {
        if (self.state != .established) return .{ .dropped = .closed };
        var storage: [4]cpf.Item = undefined;
        const list = cpf.decode(datagram, &storage) catch return .{ .dropped = .malformed };
        if (list.items.len < 2) return .{ .dropped = .malformed };
        const addr = cpf.SequencedAddress.decode(list.items[0]) catch return .{ .dropped = .malformed };
        const item = list.items[1];
        if (item.type_id != .connected_data) return .{ .dropped = .malformed };
        if (addr.connection_id != self.cfg.consume_id) return .{ .dropped = .wrong_connection };

        var d = item.data;
        var count: ?u16 = null;
        if (self.cfg.class == .class1) {
            if (d.len < 2) return .{ .dropped = .malformed };
            count = std.mem.readInt(u16, d[0..2], .little);
            d = d[2..];
        }
        var run = true;
        if (self.cfg.consume_header) {
            if (d.len < 4) return .{ .dropped = .malformed };
            run = std.mem.readInt(u32, d[0..4], .little) & run_bit != 0;
            d = d[4..];
        }

        var missed: u32 = 0;
        if (self.rx_seq) |last| {
            const ahead: i32 = @bitCast(addr.sequence_number -% last);
            if (ahead <= 0) {
                self.stale += 1;
                return .{ .dropped = .stale };
            }
            missed = @intCast(ahead - 1);
        }
        var is_new = true;
        if (count) |c| {
            if (self.rx_count) |last_c| {
                const ahead_c: i16 = @bitCast(c -% last_c);
                if (ahead_c < 0) {
                    self.stale += 1;
                    return .{ .dropped = .stale };
                }
                is_new = ahead_c > 0;
            }
            self.rx_count = c;
        }
        self.rx_seq = addr.sequence_number;
        self.deadline_us = now_us +| timeoutUs(self.cfg);
        self.missed += missed;
        if (!is_new) return .{ .heartbeat = .{ .run = run, .missed = missed } };
        self.consumed += 1;
        return .{ .data = .{ .payload = d, .run = run, .missed = missed } };
    }

    /// Reports the watchdog's expiry, once: the connection is `timed_out`
    /// from then on.
    pub fn check(self: *Connection, now_us: u64) ?Expired {
        if (self.state != .established or now_us < self.deadline_us) return null;
        self.state = .timed_out;
        return .{ .silent_for_us = now_us - (self.deadline_us - timeoutUs(self.cfg)) };
    }
};

/// One I/O datagram: the Sequenced Address item and the Connected Data item.
/// With `cfg.class == .class1` the data item starts with `count`; with
/// `cfg.produce_header` the 32-bit Run/Idle header follows it.
pub fn encode(cfg: Config, seq: u32, count: u16, run: bool, payload: []const u8, out: []u8) Error![]const u8 {
    const head: usize = (if (cfg.class == .class1) @as(usize, 2) else 0) + (if (cfg.produce_header) @as(usize, 4) else 0);
    if (head + payload.len > 0xFFFF) return error.TooLong;
    const need = 2 + (4 + 8) + (4 + head + payload.len);
    if (out.len < need) return error.BufferTooSmall;
    std.mem.writeInt(u16, out[0..2], 2, .little);
    std.mem.writeInt(u16, out[2..4], @backingInt(cpf.ItemType.sequenced_address), .little);
    std.mem.writeInt(u16, out[4..6], 8, .little);
    std.mem.writeInt(u32, out[6..10], cfg.produce_id, .little);
    std.mem.writeInt(u32, out[10..14], seq, .little);
    std.mem.writeInt(u16, out[14..16], @backingInt(cpf.ItemType.connected_data), .little);
    std.mem.writeInt(u16, out[16..18], @intCast(head + payload.len), .little);
    var off: usize = 18;
    if (cfg.class == .class1) {
        std.mem.writeInt(u16, out[off..][0..2], count, .little);
        off += 2;
    }
    if (cfg.produce_header) {
        std.mem.writeInt(u32, out[off..][0..4], if (run) run_bit else 0, .little);
        off += 4;
    }
    @memcpy(out[off..][0..payload.len], payload);
    return out[0 .. off + payload.len];
}

/// The group addresses a target hands out to multicast connections: `count`
/// consecutive IPv4 addresses from `start` (the TCP/IP Interface object's
/// `Num_Mcast` and `Mcast_Start_Addr`), given out round-robin.
pub const MulticastPool = struct {
    start: [4]u8 = .{ 239, 192, 1, 0 },
    count: u16 = 32,
    next: u16 = 0,

    pub fn take(self: *MulticastPool) ?[4]u8 {
        if (self.count == 0) return null;
        const base = std.mem.readInt(u32, &self.start, .big);
        var out: [4]u8 = undefined;
        std.mem.writeInt(u32, &out, base +% self.next, .big);
        self.next = (self.next + 1) % self.count;
        return out;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn cfgFor(trigger: Trigger) Config {
    return .{
        .trigger = trigger,
        .produce_id = 0x1111_0001,
        .consume_id = 0x2222_0002,
        .produce_rpi_us = 10_000,
        .consume_rpi_us = 10_000,
        .timeout_multiplier = 0,
    };
}

/// The same configuration seen from the other end.
fn mirror(c: Config) Config {
    var m = c;
    m.produce_id = c.consume_id;
    m.consume_id = c.produce_id;
    m.produce_rpi_us = c.consume_rpi_us;
    m.consume_rpi_us = c.produce_rpi_us;
    m.produce_header = c.consume_header;
    m.consume_header = c.produce_header;
    return m;
}

test "the datagram layout: sequenced address, then count, header, data" {
    var cfg = cfgFor(.cyclic);
    cfg.produce_header = true;
    var buf: [64]u8 = undefined;
    const d = try encode(cfg, 0x0A0B0C0D, 0x0102, true, &.{ 0xAA, 0xBB }, &buf);
    try testing.expectEqualSlices(u8, &.{
        0x02, 0x00, // two items
        0x02, 0x80, 0x08, 0x00, 0x01, 0x00, 0x11, 0x11, 0x0D, 0x0C, 0x0B, 0x0A, // sequenced address
        0xB1, 0x00, 0x08, 0x00, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0xAA, 0xBB, // count, header (Run), data
    }, d);
    cfg.class = .class0;
    cfg.produce_header = false;
    const d0 = try encode(cfg, 1, 0, true, &.{0xCC}, &buf);
    try testing.expectEqualSlices(u8, &.{ 0xB1, 0x00, 0x01, 0x00, 0xCC }, d0[14..]);
    try testing.expectError(error.BufferTooSmall, encode(cfg, 1, 0, true, &.{0xCC}, buf[0..18]));
}

test "cyclic: one datagram per RPI, cadence kept, sequence and count grow" {
    var c = Connection.init(cfgFor(.cyclic), 1_000);
    var buf: [64]u8 = undefined;
    // The first production is due at once, the next one RPI later.
    const first = (try c.produce(1_000, &.{1}, false, true, &buf)).?;
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, first[10..14], .little));
    try testing.expectEqual(@as(?[]const u8, null), try c.produce(10_999, &.{1}, false, true, &buf));
    // A late poll sends one datagram, not a burst, and the cadence restarts.
    const second = (try c.produce(40_000, &.{2}, false, true, &buf)).?;
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, second[10..14], .little));
    try testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, second[18..20], .little));
    try testing.expectEqual(@as(?[]const u8, null), try c.produce(40_001, &.{2}, false, true, &buf));
    try testing.expectEqual(@as(u64, 50_000), c.next_tx_us);
    try testing.expectEqual(@as(u64, 41_000), c.nextDueUs().?); // the watchdog is sooner
}

test "change of state: a change goes out at once (after the inhibit time), a heartbeat repeats the count" {
    var cfg = cfgFor(.change_of_state);
    cfg.inhibit_us = 3_000;
    var c = Connection.init(cfg, 0);
    var buf: [64]u8 = undefined;
    // The initial heartbeat is the first datagram; unchanged data, count 0.
    const hb = (try c.produce(0, &.{1}, false, true, &buf)).?;
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, hb[18..20], .little));
    try testing.expectEqual(@as(?[]const u8, null), try c.produce(5_000, &.{1}, false, true, &buf));
    // A change: new count.
    const ch = (try c.produce(5_000, &.{2}, true, true, &buf)).?;
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, ch[18..20], .little));
    // Another change inside the inhibit time waits.
    try testing.expectEqual(@as(?[]const u8, null), try c.produce(7_000, &.{3}, true, true, &buf));
    const ch2 = (try c.produce(8_000, &.{3}, true, true, &buf)).?;
    try testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, ch2[18..20], .little));
    // No change for an RPI: the heartbeat resends the count, with a new sequence number.
    const hb2 = (try c.produce(20_000, &.{3}, false, true, &buf)).?;
    try testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, hb2[18..20], .little));
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, hb2[10..14], .little));
}

test "consume: data, heartbeat, gap, stale, wrong connection, Run/Idle" {
    var cfg = cfgFor(.cyclic);
    cfg.consume_header = true;
    var rx = Connection.init(cfg, 0);
    var tx = Connection.init(mirror(cfg), 0);
    var buf: [64]u8 = undefined;
    var pkt: [3][64]u8 = undefined;
    var lens: [3]usize = undefined;
    for (0..3) |i| {
        lens[i] = (try tx.produce(@as(u64, i) * 10_000, &.{@intCast(i + 1)}, false, i != 1, &buf)).?.len;
        @memcpy(pkt[i][0..lens[i]], buf[0..lens[i]]);
    }
    // 0: data. 2: a gap of one datagram. 1 afterwards: stale (and Idle).
    const r0 = rx.receive(100, pkt[0][0..lens[0]]).data;
    try testing.expect(r0.run and r0.payload[0] == 1 and r0.missed == 0);
    const r2 = rx.receive(200, pkt[2][0..lens[2]]).data;
    try testing.expectEqual(@as(u32, 1), r2.missed);
    try testing.expectEqual(Dropped.stale, rx.receive(300, pkt[1][0..lens[1]]).dropped);
    try testing.expectEqual(@as(u64, 1), rx.missed);
    try testing.expectEqual(@as(u64, 1), rx.stale);
    // The same datagram again: stale too (sequence not ahead).
    try testing.expectEqual(Dropped.stale, rx.receive(400, pkt[2][0..lens[2]]).dropped);
    // A datagram whose sequence moved but whose count did not is a heartbeat.
    var hbcfg = mirror(cfg);
    hbcfg.trigger = .change_of_state;
    var hb = Connection.init(hbcfg, 0);
    var rx2 = Connection.init(cfg, 0);
    _ = rx2.receive(0, (try hb.produce(0, &.{9}, false, true, &buf)).?).data;
    try testing.expect(rx2.receive(10_000, (try hb.produce(10_000, &.{9}, false, true, &buf)).?) == .heartbeat);
    try testing.expectEqual(@as(u64, 1), rx2.consumed);
    // Idle: the header's Run bit is clear, the data is still delivered.
    var idle = Connection.init(mirror(cfg), 0);
    const id = (try idle.produce(0, &.{7}, false, false, &buf)).?;
    var rx3 = Connection.init(cfg, 0);
    const got = rx3.receive(0, id).data;
    try testing.expect(!got.run and got.payload[0] == 7);
    // Another connection's datagram, and garbage, do not count.
    var other = mirror(cfg);
    other.produce_id = 0x9999;
    var o = Connection.init(other, 0);
    try testing.expectEqual(Dropped.wrong_connection, rx3.receive(1, (try o.produce(0, &.{1}, false, true, &buf)).?).dropped);
    try testing.expectEqual(Dropped.malformed, rx3.receive(1, &.{ 1, 2, 3 }).dropped);
    // One item only: not an I/O datagram.
    const one_item = [_]u8{ 0x01, 0x00, 0x02, 0x80, 0x08, 0x00, 0, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expectEqual(Dropped.malformed, rx3.receive(1, &one_item).dropped);
}

test "watchdog: RPI x 4 x 2^multiplier, restarted by valid data only, reported once" {
    var cfg = cfgFor(.cyclic);
    cfg.timeout_multiplier = 1; // 10 ms x 4 x 2 = 80 ms
    try testing.expectEqual(@as(u64, 80_000), Connection.timeoutUs(cfg));
    cfg.timeout_multiplier = 200; // reserved: taken as 7
    try testing.expectEqual(@as(u64, 10_000 * 4 * 128), Connection.timeoutUs(cfg));
    cfg.timeout_multiplier = 1;
    var rx = Connection.init(cfg, 0);
    var tx = Connection.init(mirror(cfg), 0);
    var buf: [64]u8 = undefined;
    try testing.expectEqual(@as(?Expired, null), rx.check(79_999));
    // A valid datagram at 50 ms moves the deadline to 130 ms.
    _ = rx.receive(50_000, (try tx.produce(0, &.{1}, false, true, &buf)).?).data;
    try testing.expectEqual(@as(?Expired, null), rx.check(129_999));
    // A stale one at 100 ms does not.
    var again = Connection.init(mirror(cfg), 0);
    try testing.expectEqual(Dropped.stale, rx.receive(100_000, (try again.produce(0, &.{1}, false, true, &buf)).?).dropped);
    try testing.expectEqual(@as(u64, 130_000), rx.deadline_us);
    const dead = rx.check(130_000).?;
    try testing.expectEqual(@as(u64, 80_000), dead.silent_for_us);
    try testing.expectEqual(@as(?Expired, null), rx.check(200_000));
    try testing.expectEqual(State.timed_out, rx.state);
    // A dead connection neither sends nor receives.
    try testing.expectEqual(@as(?[]const u8, null), try rx.produce(300_000, &.{1}, true, true, &buf));
    try testing.expectEqual(Dropped.closed, rx.receive(300_000, (try tx.produce(20_000, &.{1}, false, true, &buf)).?).dropped);
    try testing.expectEqual(@as(?u64, null), rx.nextDueUs());
}

test "class 0 has no data count: every datagram is new" {
    var cfg = cfgFor(.cyclic);
    cfg.class = .class0;
    var tx = Connection.init(mirror(cfg), 0);
    var rx = Connection.init(cfg, 0);
    var buf: [64]u8 = undefined;
    for (0..3) |i| {
        const d = (try tx.produce(@as(u64, i) * 10_000, &.{@intCast(i)}, false, true, &buf)).?;
        try testing.expectEqual(@as(u8, @intCast(i)), rx.receive(@as(u64, i) * 10_000, d).data.payload[0]);
    }
    try testing.expectEqual(@as(u64, 3), rx.consumed);
}

test "sequence numbers wrap" {
    var cfg = cfgFor(.cyclic);
    cfg.class = .class0;
    var tx = Connection.init(mirror(cfg), 0);
    tx.tx_seq = 0xFFFF_FFFF;
    var rx = Connection.init(cfg, 0);
    var buf: [64]u8 = undefined;
    _ = rx.receive(0, (try tx.produce(0, &.{1}, false, true, &buf)).?).data;
    const after = rx.receive(1, (try tx.produce(10_000, &.{2}, false, true, &buf)).?).data;
    try testing.expectEqual(@as(u32, 0), after.missed);
    try testing.expectEqual(@as(u8, 2), after.payload[0]);
}

test "the multicast pool hands out its range round-robin" {
    var pool: MulticastPool = .{ .start = .{ 239, 192, 1, 254 }, .count = 3 };
    try testing.expectEqual([4]u8{ 239, 192, 1, 254 }, pool.take().?);
    try testing.expectEqual([4]u8{ 239, 192, 1, 255 }, pool.take().?);
    try testing.expectEqual([4]u8{ 239, 192, 2, 0 }, pool.take().?);
    try testing.expectEqual([4]u8{ 239, 192, 1, 254 }, pool.take().?);
    var none: MulticastPool = .{ .count = 0 };
    try testing.expectEqual(@as(?[4]u8, null), none.take());
}
