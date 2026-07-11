// SPDX-License-Identifier: MIT

//! dtls.flight — RFC 9147 §7 ACK message framing, plus a retransmission
//! timer and flight-bookkeeping state machine. No wall-clock calls
//! anywhere in this file: every time-dependent function takes `now_ms` from
//! the caller, so the whole thing is deterministically unit-testable
//! (CONVENTIONS.md §7 "pure logic" verification style) with a fake clock.

const std = @import("std");

pub const AckError = error{
    BufferTooShort,
    TooManyRecords,
};

/// RFC 9147 §7: identifies one previously-sent record by (epoch,
/// sequence_number) — what an ACK message says it has received.
pub const RecordNumber = struct {
    epoch: u64,
    sequence_number: u64,
};

pub const record_number_len = 16; // 8-byte epoch + 8-byte sequence_number

pub fn encodeRecordNumber(rn: RecordNumber, out: *[record_number_len]u8) void {
    std.mem.writeInt(u64, out[0..8], rn.epoch, .big);
    std.mem.writeInt(u64, out[8..16], rn.sequence_number, .big);
}

pub fn decodeRecordNumber(buf: *const [record_number_len]u8) RecordNumber {
    return .{
        .epoch = std.mem.readInt(u64, buf[0..8], .big),
        .sequence_number = std.mem.readInt(u64, buf[8..16], .big),
    };
}

/// RFC 9147 §7: `struct { RecordNumber record_numbers<0..2^16-1>; } Ack;` —
/// a 2-byte length prefix (in bytes, TLS presentation-language vector
/// convention) followed by that many `RecordNumber` entries. This encodes/
/// decodes the ACK message BODY only; which content type / record it
/// travels under is the caller's concern (RFC 9147 §7 defines the "ack"
/// content type at the record layer, orthogonal to this framing).
pub fn encodeAck(record_numbers: []const RecordNumber, out: []u8) AckError![]u8 {
    const body_len = record_numbers.len * record_number_len;
    if (body_len > std.math.maxInt(u16)) return error.TooManyRecords;
    if (out.len < 2 + body_len) return error.BufferTooShort;

    std.mem.writeInt(u16, out[0..2], @intCast(body_len), .big);
    var i: usize = 2;
    for (record_numbers) |rn| {
        encodeRecordNumber(rn, out[i..][0..record_number_len]);
        i += record_number_len;
    }
    return out[0..i];
}

pub fn decodeAck(buf: []const u8, out: []RecordNumber) AckError![]RecordNumber {
    if (buf.len < 2) return error.BufferTooShort;
    const body_len: usize = std.mem.readInt(u16, buf[0..2], .big);
    if (buf.len < 2 + body_len) return error.BufferTooShort;
    if (body_len % record_number_len != 0) return error.BufferTooShort;

    const count = body_len / record_number_len;
    if (count > out.len) return error.TooManyRecords;

    var i: usize = 2;
    for (0..count) |k| {
        out[k] = decodeRecordNumber(buf[i..][0..record_number_len]);
        i += record_number_len;
    }
    return out[0..count];
}

// ── retransmission timer ─────────────────────────────────────────────────
//
// RFC 9147 §5.7 carries forward DTLS 1.2's retransmission approach (RFC
// 6347 §4.2.4): an exponentially-doubling timeout, capped, restarting from
// the initial value on every new flight. Exact backoff parameters are
// implementation-defined in both RFCs — this models the shape (double on
// timeout, cap, reset per flight), not a mandated constant schedule.

pub const RetransmitTimer = struct {
    initial_timeout_ms: u64,
    max_timeout_ms: u64,
    current_timeout_ms: u64,
    deadline_ms: ?u64 = null,

    pub fn init(initial_timeout_ms: u64, max_timeout_ms: u64) RetransmitTimer {
        return .{
            .initial_timeout_ms = initial_timeout_ms,
            .max_timeout_ms = max_timeout_ms,
            .current_timeout_ms = initial_timeout_ms,
        };
    }

    /// Arms (or re-arms) the timer for the current flight, starting at `now_ms`.
    pub fn arm(self: *RetransmitTimer, now_ms: u64) void {
        self.deadline_ms = now_ms + self.current_timeout_ms;
    }

    pub fn isArmed(self: RetransmitTimer) bool {
        return self.deadline_ms != null;
    }

    pub fn isExpired(self: RetransmitTimer, now_ms: u64) bool {
        const dl = self.deadline_ms orelse return false;
        return now_ms >= dl;
    }

    /// Doubles the backoff (capped at `max_timeout_ms`) and re-arms from `now_ms`.
    /// Call this when `isExpired` was true and the flight is being resent.
    pub fn onTimeout(self: *RetransmitTimer, now_ms: u64) void {
        self.current_timeout_ms = @min(self.current_timeout_ms * 2, self.max_timeout_ms);
        self.arm(now_ms);
    }

    /// Resets to `initial_timeout_ms` — call when moving on to a new flight.
    pub fn reset(self: *RetransmitTimer) void {
        self.current_timeout_ms = self.initial_timeout_ms;
        self.deadline_ms = null;
    }
};

// ── flight bookkeeping ────────────────────────────────────────────────────

pub const FlightError = error{BufferFull};

/// Tracks which of the current flight's outgoing records the peer has
/// ACKed yet (RFC 9147 §7's ACK-based reliability). Caller-supplied
/// fixed-capacity buffer, no allocator — matching the zero-alloc style of
/// this module's other pure-logic files.
pub const FlightTracker = struct {
    sent: []RecordNumber,
    count: usize = 0,

    pub fn init(sent_buf: []RecordNumber) FlightTracker {
        return .{ .sent = sent_buf };
    }

    pub fn markSent(self: *FlightTracker, rn: RecordNumber) FlightError!void {
        if (self.count >= self.sent.len) return error.BufferFull;
        self.sent[self.count] = rn;
        self.count += 1;
    }

    /// Removes `rn` from the pending set if present (swap-remove — order
    /// doesn't matter for "what still needs retransmitting").
    pub fn markAcked(self: *FlightTracker, rn: RecordNumber) void {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (self.sent[i].epoch == rn.epoch and self.sent[i].sequence_number == rn.sequence_number) {
                self.sent[i] = self.sent[self.count - 1];
                self.count -= 1;
                return;
            }
        }
    }

    pub fn pending(self: FlightTracker) []const RecordNumber {
        return self.sent[0..self.count];
    }

    pub fn allAcked(self: FlightTracker) bool {
        return self.count == 0;
    }

    pub fn clear(self: *FlightTracker) void {
        self.count = 0;
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "record number round-trip" {
    const rn = RecordNumber{ .epoch = 3, .sequence_number = 0x1234567890AB };
    var buf: [record_number_len]u8 = undefined;
    encodeRecordNumber(rn, &buf);
    const dec = decodeRecordNumber(&buf);
    try testing.expectEqual(rn.epoch, dec.epoch);
    try testing.expectEqual(rn.sequence_number, dec.sequence_number);
}

test "ack: hand-built golden bytes, two record numbers" {
    const rns = [_]RecordNumber{
        .{ .epoch = 1, .sequence_number = 1 },
        .{ .epoch = 1, .sequence_number = 2 },
    };
    var buf: [2 + 2 * record_number_len]u8 = undefined;
    const enc = try encodeAck(&rns, &buf);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x20, // body_len = 32
        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, // epoch=1, seq=1
        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, // epoch=1, seq=2
    }, enc);

    var out: [2]RecordNumber = undefined;
    const dec = try decodeAck(enc, &out);
    try testing.expectEqual(@as(usize, 2), dec.len);
    try testing.expectEqual(rns[0].sequence_number, dec[0].sequence_number);
    try testing.expectEqual(rns[1].sequence_number, dec[1].sequence_number);
}

test "ack: empty ack round-trip" {
    var buf: [2]u8 = undefined;
    const enc = try encodeAck(&.{}, &buf);
    try testing.expectEqualSlices(u8, &.{ 0, 0 }, enc);
    var out: [1]RecordNumber = undefined;
    const dec = try decodeAck(enc, &out);
    try testing.expectEqual(@as(usize, 0), dec.len);
}

test "ack: decode buffer too short" {
    const buf = [_]u8{ 0x00, 0x20, 1, 2, 3 }; // claims 32 bytes, has 3
    var out: [2]RecordNumber = undefined;
    try testing.expectError(error.BufferTooShort, decodeAck(&buf, &out));
}

test "ack: decode too many records for caller's buffer" {
    const rns = [_]RecordNumber{
        .{ .epoch = 0, .sequence_number = 1 },
        .{ .epoch = 0, .sequence_number = 2 },
    };
    var buf: [2 + 2 * record_number_len]u8 = undefined;
    const enc = try encodeAck(&rns, &buf);
    var out: [1]RecordNumber = undefined;
    try testing.expectError(error.TooManyRecords, decodeAck(enc, &out));
}

test "RetransmitTimer: doubles on timeout, caps at max, resets" {
    var t = RetransmitTimer.init(1000, 4000);
    try testing.expect(!t.isArmed());
    t.arm(0);
    try testing.expect(!t.isExpired(999));
    try testing.expect(t.isExpired(1000));

    t.onTimeout(1000); // current -> 2000, deadline -> 3000
    try testing.expectEqual(@as(u64, 2000), t.current_timeout_ms);
    try testing.expect(!t.isExpired(2999));
    try testing.expect(t.isExpired(3000));

    t.onTimeout(3000); // current -> 4000 (would be 4000, exactly cap)
    try testing.expectEqual(@as(u64, 4000), t.current_timeout_ms);
    t.onTimeout(7000); // current -> 8000 capped to 4000
    try testing.expectEqual(@as(u64, 4000), t.current_timeout_ms);

    t.reset();
    try testing.expectEqual(@as(u64, 1000), t.current_timeout_ms);
    try testing.expect(!t.isArmed());
}

test "FlightTracker: mark sent/acked, pending shrinks" {
    var sent_buf: [4]RecordNumber = undefined;
    var tracker = FlightTracker.init(&sent_buf);
    try tracker.markSent(.{ .epoch = 2, .sequence_number = 1 });
    try tracker.markSent(.{ .epoch = 2, .sequence_number = 2 });
    try tracker.markSent(.{ .epoch = 2, .sequence_number = 3 });
    try testing.expectEqual(@as(usize, 3), tracker.pending().len);
    try testing.expect(!tracker.allAcked());

    tracker.markAcked(.{ .epoch = 2, .sequence_number = 2 });
    try testing.expectEqual(@as(usize, 2), tracker.pending().len);
    for (tracker.pending()) |rn| try testing.expect(rn.sequence_number != 2);

    tracker.markAcked(.{ .epoch = 2, .sequence_number = 1 });
    tracker.markAcked(.{ .epoch = 2, .sequence_number = 3 });
    try testing.expect(tracker.allAcked());
}

test "FlightTracker: buffer full is a typed error" {
    var sent_buf: [1]RecordNumber = undefined;
    var tracker = FlightTracker.init(&sent_buf);
    try tracker.markSent(.{ .epoch = 0, .sequence_number = 1 });
    try testing.expectError(error.BufferFull, tracker.markSent(.{ .epoch = 0, .sequence_number = 2 }));
}
