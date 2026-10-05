// SPDX-License-Identifier: MIT

//! OFFLINE replay of the rsyslogd oracle (`tools/interop.zig` +
//! `tools/rsyslog_oracle.py`, frozen in `rsyslog_oracle_vectors.zig`). A real
//! rsyslogd parsed every message below -- RFC 5424 as the datagram
//! `buildDatagram` makes over UDP and as the `writeOctetCounted` frame over
//! TCP, RFC 3164 lines over UDP -- back to what the message meant: PRI, the
//! timestamp's instant, millisecond and offset, each header field after the
//! documented sanitizing and limits, every SD-PARAM value unescaped to the
//! caller's bytes (mmpstrucdata), MSG byte for byte. No rsyslogd at test time:
//! the replay requires the very bytes it parsed.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const vectors = @import("rsyslog_oracle_vectors.zig");

fn knownDivergence(name: []const u8) bool {
    for (vectors.divergences) |d| if (std.mem.eql(u8, d.name, name)) return true;
    return false;
}

test "rsyslogd oracle: every RFC 5424 message encodes to the bytes rsyslogd read back as meant" {
    var bad: usize = 0;
    for (vectors.rfc5424, 0..) |c, i| {
        try testing.expect(c.ok);
        if (c.divergence.len > 0) try testing.expect(knownDivergence(c.divergence));
        var scratch: [2 * root.default_udp_limit]u8 = undefined;
        const udp = root.buildDatagram(&c.msg, &scratch, .{});
        var line_buf: [8192]u8 = undefined;
        const line = try root.bufPrint(&c.msg, &line_buf);
        var frame: std.Io.Writer.Allocating = .init(testing.allocator);
        defer frame.deinit();
        try root.writeOctetCounted(&frame.writer, line);
        if (!std.mem.eql(u8, udp, c.udp) or !std.mem.eql(u8, frame.written(), c.frame)) {
            bad += 1;
            if (bad <= 5) std.debug.print("case {d}: encoded\n{s}\njudged\n{s}\n", .{ i, udp, c.udp });
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

test "rsyslogd oracle: every RFC 3164 line encodes to the bytes rsyslogd read back as meant" {
    var bad: usize = 0;
    for (vectors.rfc3164, 0..) |c, i| {
        try testing.expect(c.ok);
        var buf: [8192]u8 = undefined;
        const line = try root.bsd.bufPrint(&c.msg, &buf);
        if (!std.mem.eql(u8, line, c.line)) {
            bad += 1;
            if (bad <= 5) std.debug.print("case {d}: encoded\n{s}\njudged\n{s}\n", .{ i, line, c.line });
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

test "journald oracle: validFieldName accepts exactly the names journald keeps from a client" {
    for (vectors.field_names) |f| {
        const ours = if (root.journal.validFieldName(f.name)) |_| true else |_| false;
        if (ours != f.journald_kept) std.debug.print("field name {s}: validFieldName {}, journald kept {}\n", .{ f.name, ours, f.journald_kept });
        try testing.expectEqual(f.journald_kept, ours);
    }
}
