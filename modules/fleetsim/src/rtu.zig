// SPDX-License-Identifier: MIT
//! Modbus serial-line framing by silence (MODBUS over Serial Line v1.02 §2.5.1.1,
//! RTU mode): a frame ends after a silent interval of 3.5 character times and
//! begins with whatever arrives next; a frame whose own bytes are separated by
//! more than 1.5 character times is invalid and discarded. RTU has no length
//! field, so a node on a serial gateway cannot be fed a concatenated stream
//! (`node.Framing.opaque_whole`): something has to cut the byte stream into
//! frames first, and on the wire that something is time. `Framer` is that, over
//! the fleet's injected time, with no clock of its own, so a run stays replayable
//! (ModbusPal and the serial-gateway setups it models hit exactly this).
//!
//! Times are in microseconds (`t3.5` is 1750 us above 19200 baud, under the
//! fleet's millisecond `Time`): `Framer` takes them as plain numbers, and
//! `fleet.submit` takes the milliseconds of the frame it returns.
//!
//! ```zig
//! var framer = serial_rtu.Framer.initBaud(9600); // fleetsim.serial_rtu
//! if (framer.push(chunk, arrival_us)) |frame| try f.submit(node, frame, arrival_us / 1000);
//! if (framer.poll(now_us)) |frame| try f.submit(node, frame, now_us / 1000);
//! ```

const std = @import("std");

/// The two silent intervals for a line speed.
pub const Timing = struct {
    /// More than this between two bytes of a frame invalidates it.
    t15_us: u32,
    /// At least this of silence ends a frame.
    t35_us: u32,

    /// The spec's values: 11 bits per character (start, 8 data, parity or a
    /// second stop, stop) below and at 19200 baud, the fixed 750 us / 1750 us above it.
    pub fn forBaud(baud: u32) Timing {
        if (baud > 19200) return .{ .t15_us = 750, .t35_us = 1750 };
        const char_us: u64 = 11 * 1_000_000 / @max(baud, 1);
        return .{ .t15_us = @intCast(char_us * 3 / 2), .t35_us = @intCast(char_us * 7 / 2) };
    }

    /// One character on the wire at `baud` (11 bits), in microseconds, at least 1.
    pub fn charUs(baud: u32) u32 {
        return @intCast(@max(1, 11 * 1_000_000 / @max(baud, 1)));
    }
};

/// The longest RTU ADU (`modbus.rtu.max_adu_len`).
pub const max_frame_len = 256;

pub const Stats = struct {
    /// Frames returned.
    frames: u64 = 0,
    /// Frames dropped for a gap over 1.5 character times inside them.
    broken: u64 = 0,
    /// Frames dropped for more than `max_frame_len` bytes.
    overlong: u64 = 0,
};

pub const Framer = struct {
    timing: Timing,
    /// Time one byte takes on the line (`Timing.charUs`): a chunk of n bytes
    /// arriving at `t` occupies the line until `t + n * char_us`.
    char_us: u32,
    buf: [max_frame_len]u8 = undefined,
    len: usize = 0,
    /// The frame being built is already invalid (a gap, or too long).
    spoiled: bool = false,
    /// ... because it grew past `max_frame_len` (counted as `overlong`, not `broken`).
    overlong: bool = false,
    /// When the last byte received so far finished arriving.
    last_end_us: u64 = 0,
    /// The frame `push` hands back while it starts the next one.
    out: [max_frame_len]u8 = undefined,
    stats: Stats = .{},

    pub fn init(timing: Timing) Framer {
        return .{ .timing = timing, .char_us = @max(1, timing.t15_us * 2 / 3) };
    }

    /// `init` for a line speed (`char_us` is then the true character time).
    pub fn initBaud(baud: u32) Framer {
        var f = init(.forBaud(baud));
        f.char_us = Timing.charUs(baud);
        return f;
    }

    /// Bytes whose first one arrives at `at_us` (back to back, at line speed).
    /// If the line was silent for `t35` before them, the frame collected so far
    /// is complete and is returned (valid until the next call) while these bytes
    /// begin the next one; a gap above `t15` but under `t35` spoils the frame in
    /// progress. A longer frame than `max_frame_len` is dropped (counted).
    /// `at_us` must not be earlier than the end of the previous chunk.
    pub fn push(self: *Framer, bytes: []const u8, at_us: u64) ?[]const u8 {
        if (bytes.len == 0) return null;
        var done: ?[]const u8 = null;
        if (self.len != 0 or self.spoiled) {
            const gap = at_us -| self.last_end_us;
            if (gap >= self.timing.t35_us) {
                done = self.finish();
            } else if (gap > self.timing.t15_us) {
                self.spoiled = true;
            }
        }
        if (self.len + bytes.len > max_frame_len) {
            if (!self.spoiled) {
                self.stats.overlong += 1;
                self.overlong = true;
            }
            self.spoiled = true;
            self.len = 0;
        } else if (!self.spoiled) {
            @memcpy(self.buf[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
        }
        self.last_end_us = at_us + @as(u64, bytes.len) * self.char_us;
        return done;
    }

    /// The frame collected so far, once the line has been silent for `t35` at
    /// `now_us` (valid until the next call); null before that or when there is
    /// nothing.
    pub fn poll(self: *Framer, now_us: u64) ?[]const u8 {
        if (self.len == 0 and !self.spoiled) return null;
        if (now_us -| self.last_end_us < self.timing.t35_us) return null;
        return self.finish();
    }

    /// When `poll` will have a frame, if the line stays silent (null: nothing pending).
    pub fn nextDeadlineUs(self: *const Framer) ?u64 {
        if (self.len == 0 and !self.spoiled) return null;
        return self.last_end_us + self.timing.t35_us;
    }

    fn finish(self: *Framer) ?[]const u8 {
        defer {
            self.len = 0;
            self.spoiled = false;
            self.overlong = false;
        }
        if (self.spoiled) {
            if (!self.overlong) self.stats.broken += 1;
            return null;
        }
        if (self.len == 0) return null;
        @memcpy(self.out[0..self.len], self.buf[0..self.len]);
        self.stats.frames += 1;
        return self.out[0..self.len];
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Timing.forBaud: 11-bit characters up to 19200, the fixed 750 / 1750 us above" {
    const t96 = Timing.forBaud(9600); // 1145 us a character
    try testing.expectEqual(@as(u32, 1717), t96.t15_us);
    try testing.expectEqual(@as(u32, 4007), t96.t35_us);
    const t192 = Timing.forBaud(19200);
    try testing.expectEqual(@as(u32, 858), t192.t15_us);
    try testing.expectEqual(@as(u32, 2002), t192.t35_us);
    for ([_]u32{ 38400, 115200 }) |b| {
        const t = Timing.forBaud(b);
        try testing.expectEqual(@as(u32, 750), t.t15_us);
        try testing.expectEqual(@as(u32, 1750), t.t35_us);
    }
    try testing.expectEqual(@as(u32, 1145), Timing.charUs(9600));
    // A nonsense speed does not divide by zero.
    _ = Timing.forBaud(0);
    try testing.expectEqual(@as(u32, 11_000_000), Timing.charUs(0));
}

const req_a = [_]u8{ 0x01, 0x03, 0x00, 0x00, 0x00, 0x02, 0xC4, 0x0B };
const req_b = [_]u8{ 0x02, 0x03, 0x00, 0x10, 0x00, 0x01, 0x85, 0xF6 };

test "Framer: a frame ends after 3.5 characters of silence, found by the next chunk or by poll" {
    var f = Framer.initBaud(9600);
    const char = f.char_us;
    try testing.expectEqual(@as(?[]const u8, null), f.push(&req_a, 0));
    // The next request starts exactly t3.5 after the last byte of the first: the first is complete.
    const end_a = 8 * @as(u64, char);
    const got = f.push(&req_b, end_a + f.timing.t35_us).?;
    try testing.expectEqualSlices(u8, &req_a, got);
    // The second ends when polled after the silence, not before.
    const end_b = end_a + f.timing.t35_us + 8 * @as(u64, char);
    try testing.expectEqual(@as(?[]const u8, null), f.poll(end_b + f.timing.t35_us - 1));
    try testing.expectEqual(end_b + f.timing.t35_us, f.nextDeadlineUs().?);
    try testing.expectEqualSlices(u8, &req_b, f.poll(end_b + f.timing.t35_us).?);
    try testing.expectEqual(@as(?[]const u8, null), f.poll(end_b + 10 * f.timing.t35_us));
    try testing.expectEqual(@as(?u64, null), f.nextDeadlineUs());
    try testing.expectEqual(@as(u64, 2), f.stats.frames);
}

test "Framer: bytes within t1.5 of each other are one frame, however they are chunked" {
    var f = Framer.initBaud(9600);
    const char: u64 = f.char_us;
    var t: u64 = 0;
    for (req_a) |b| { // one byte at a time, back to back
        try testing.expectEqual(@as(?[]const u8, null), f.push(&.{b}, t));
        t += char;
    }
    // A gap just under t1.5 does not spoil it.
    try testing.expectEqual(@as(?[]const u8, null), f.push(&.{0x00}, t + f.timing.t15_us));
    const frame = f.poll(t + f.timing.t15_us + char + f.timing.t35_us).?;
    try testing.expectEqual(@as(usize, 9), frame.len);
}

test "Framer: a gap over t1.5 inside a frame drops it; the frame after it is fine" {
    var f = Framer.initBaud(9600);
    const char: u64 = f.char_us;
    try testing.expectEqual(@as(?[]const u8, null), f.push(req_a[0..4], 0));
    // t1.5 < gap < t3.5: the line was not idle long enough to end the frame, yet too long to continue it.
    const resume_at = 4 * char + f.timing.t15_us + 1;
    try testing.expect(resume_at - 4 * char < f.timing.t35_us);
    try testing.expectEqual(@as(?[]const u8, null), f.push(req_a[4..], resume_at));
    try testing.expectEqual(@as(?[]const u8, null), f.poll(resume_at + 4 * char + f.timing.t35_us)); // dropped, nothing to return
    try testing.expectEqual(@as(u64, 1), f.stats.broken);
    try testing.expectEqual(@as(u64, 0), f.stats.frames);
    // A clean frame after it.
    const t0 = resume_at + 4 * char + 3 * f.timing.t35_us;
    try testing.expectEqual(@as(?[]const u8, null), f.push(&req_b, t0));
    try testing.expectEqualSlices(u8, &req_b, f.poll(t0 + 8 * char + f.timing.t35_us).?);
}

test "Framer: two requests with no silence between them are one (invalid) frame, as on a real line" {
    var f = Framer.initBaud(9600);
    const char: u64 = f.char_us;
    try testing.expectEqual(@as(?[]const u8, null), f.push(&req_a, 0));
    try testing.expectEqual(@as(?[]const u8, null), f.push(&req_b, 8 * char));
    const frame = f.poll(16 * char + f.timing.t35_us).?;
    try testing.expectEqual(@as(usize, 16), frame.len); // not split: RTU has no length field
}

test "Framer: more than a frame's worth of bytes is dropped and counted once" {
    var f = Framer.initBaud(115200);
    const big: [200]u8 = @splat(0x55);
    try testing.expectEqual(@as(?[]const u8, null), f.push(&big, 0));
    try testing.expectEqual(@as(?[]const u8, null), f.push(&big, 200 * @as(u64, f.char_us)));
    try testing.expectEqual(@as(?[]const u8, null), f.poll(10_000_000));
    try testing.expectEqual(@as(u64, 1), f.stats.overlong);
    try testing.expectEqual(@as(u64, 0), f.stats.frames);
    // The framer recovers.
    try testing.expectEqual(@as(?[]const u8, null), f.push(&req_a, 20_000_000));
    try testing.expectEqualSlices(u8, &req_a, f.poll(30_000_000).?);
}

test "Framer into the fleet: a Modbus RTU node answers each request the silence delimited" {
    const fleet_mod = @import("fleet.zig");
    const adapters = @import("adapters.zig");
    const modbus = @import("modbus");
    const gpa = testing.allocator;
    var holdings = [_]u16{ 0x1111, 0x2222, 0x3333, 0x4444 };
    var slave = adapters.Modbus.init(
        .{ .unit_id = 1, .framing = .rtu },
        .{ .holding_registers = .{ .base = 0, .values = &holdings } },
    );
    var f = try fleet_mod.Fleet.init(gpa, .{ .max_frame_len = 300 });
    defer f.deinit();
    const id = try f.addNode(.{ .node = slave.node(), .tag = 1 });
    var req_buf: [modbus.rtu.max_adu_len]u8 = undefined;
    const req = try modbus.rtu.encodeAdu(&req_buf, 1, &.{ 0x03, 0x00, 0x00, 0x00, 0x02 });

    var framer = Framer.initBaud(19200);
    const char: u64 = framer.char_us;
    // Two requests 10 ms apart (one takes 4.6 ms on the wire at 19200 baud), each delivered as two chunks (a UART FIFO's worth).
    var t: u64 = 0;
    var submitted: usize = 0;
    for ([_]u64{ 0, 10_000 }) |start| {
        t = start;
        if (framer.push(req[0..3], t)) |fr| {
            try f.submit(id, fr, t / 1000);
            submitted += 1;
        }
        t += 3 * char;
        if (framer.push(req[3..], t)) |fr| {
            try f.submit(id, fr, t / 1000);
            submitted += 1;
        }
        t += (req.len - 3) * char;
    }
    if (framer.poll(t + framer.timing.t35_us)) |fr| {
        try f.submit(id, fr, t / 1000);
        submitted += 1;
    }
    try testing.expectEqual(@as(usize, 2), submitted);
    _ = try f.advance(100);
    try testing.expectEqual(@as(usize, 2), f.outbound().len);
    for (f.outbound()) |o| {
        const reply = f.frameBytes(o);
        try testing.expectEqualSlices(u8, &.{ 0x03, 0x04, 0x11, 0x11, 0x22, 0x22 }, reply[1..7]);
    }
}
