// SPDX-License-Identifier: MIT

//! The parser against what is not ours, offline:
//!
//!   - what a real rsyslogd read from each message of `rsyslog_oracle_vectors.zig`
//!     is what the message meant, so `parse` and `parseBsd` must read the same
//!     meaning out of the same bytes;
//!   - `parse_oracle_vectors.zig`: go-syslog v4 (`tools/go_oracle`) on the RFC's
//!     examples, grammar edges and damaged lines, verdict and fields.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const rsyslog = @import("rsyslog_oracle_vectors.zig");
const vectors = @import("parse_oracle_vectors.zig");

fn sanitizedEql(got: ?[]const u8, sent: ?[]const u8, max: usize) bool {
    const s = sent orelse return got == null;
    const n = @min(s.len, max);
    if (n == 0 or (n == 1 and (s[0] < 33 or s[0] > 126 or s[0] == '-'))) return got == null;
    const g = got orelse return false;
    if (g.len != n) return false;
    for (s[0..n], g) |a, b| {
        if (b != (if (a >= 33 and a <= 126) a else '-')) return false;
    }
    return true;
}

test "rsyslogd's RFC 5424 vectors: the parser reads each datagram as rsyslogd did" {
    var read: usize = 0;
    for (rsyslog.rfc5424) |c| {
        var line_buf: [8192]u8 = undefined;
        const line = try root.bufPrint(&c.msg, &line_buf);
        const m = root.parse(line) catch |e| {
            std.debug.print("refused ({t}): {s}\n", .{ e, line });
            return e;
        };
        read += 1;
        try testing.expectEqual(c.msg.facility, m.facility);
        try testing.expectEqual(c.msg.severity, m.severity);
        try testing.expect(sanitizedEql(m.hostname, c.msg.hostname, root.max_hostname));
        try testing.expect(sanitizedEql(m.app_name, c.msg.app_name, root.max_app_name));
        try testing.expect(sanitizedEql(m.procid, c.msg.procid, root.max_procid));
        try testing.expect(sanitizedEql(m.msgid, c.msg.msgid, root.max_msgid));
        // A MSG that starts with a BOM reads as the flag plus the text.
        const bom = "\xEF\xBB\xBF";
        const has_bom = std.mem.startsWith(u8, c.msg.msg, bom);
        try testing.expectEqual(has_bom, m.msg_utf8);
        try testing.expectEqualStrings(if (has_bom) c.msg.msg[bom.len..] else c.msg.msg, m.msg);
        if (c.msg.timestamp) |ts| {
            if (root.decompose(ts)) |_| {
                try testing.expectEqual(ts.unix_ms, m.timestamp.?.toTimestamp().unix_ms);
            } else |_| try testing.expect(m.timestamp == null);
        } else try testing.expect(m.timestamp == null);

        var els = m.elements();
        for (c.msg.structured_data) |el| {
            var ps = (els.next() orelse return error.SdLost).params();
            for (el.params) |p| {
                var buf: [2048]u8 = undefined;
                const got = ps.next() orelse return error.ParamLost;
                try testing.expectEqualStrings(p.value, try got.value(&buf));
            }
            try testing.expect(ps.next() == null);
        }
        try testing.expect(els.next() == null);

        // The UDP form, when not cut, and the TCP frame carry the same line.
        var framed: [8192 + 8]u8 = undefined;
        var w: std.Io.Writer = .fixed(&framed);
        try root.writeOctetCounted(&w, line);
        const f = (try root.nextFrame(w.buffered(), root.default_max_frame)).?;
        try testing.expectEqualStrings(line, f.payload);
        try testing.expectEqualStrings(c.frame, w.buffered());
    }
    try testing.expect(read == rsyslog.rfc5424.len);
}

test "rsyslogd's RFC 3164 vectors: the parser reads each line as rsyslogd did" {
    for (rsyslog.rfc3164) |c| {
        const m = root.parseBsd(c.line);
        try testing.expect(m.has_priority);
        try testing.expectEqual(c.msg.facility, m.facility);
        try testing.expectEqual(c.msg.severity, m.severity);
        // The TAG the encoder made (alnum, `-` for the rest). An empty one has no
        // TAG to find; the line then starts its CONTENT with the `: `.
        if (c.msg.tag.len > 0) {
            try testing.expectEqualStrings(c.msg.msg, m.msg);
            const tag = m.tag orelse return error.TagLost;
            try testing.expectEqual(@min(c.msg.tag.len, root.bsd.max_tag), tag.len);
            if (c.msg.hostname) |h| {
                if (root.bsd.validHostname(h)) try testing.expectEqualStrings(h, m.hostname.?);
            }
        }
        // `UnixEmitter.sendBsd`'s form has no HOSTNAME, and reads the same.
        const u = root.parseBsd(c.unix);
        try testing.expect(u.hostname == null);
        if (c.msg.tag.len > 0) try testing.expectEqualStrings(c.msg.msg, u.msg);
    }
}

fn optEql(got: ?[]const u8, want: []const u8, present: bool) bool {
    if (!present) return got == null;
    const g = got orelse return false;
    return std.mem.eql(u8, g, want);
}

/// `ours` read the same SD as go-syslog's maps: everything in both directions
/// (a repeated name has one value there, so any occurrence counts).
fn sameSd(m: *const root.Parsed, sd: []const [3][]const u8) !bool {
    var buf: [2048]u8 = undefined;
    for (sd) |want| {
        var found = false;
        var els = m.elements();
        while (els.next()) |el| {
            if (!std.mem.eql(u8, el.id, want[0])) continue;
            var ps = el.params();
            while (ps.next()) |p| {
                if (!std.mem.eql(u8, p.name, want[1])) continue;
                if (std.mem.eql(u8, try p.value(&buf), want[2])) found = true;
            }
        }
        if (!found) return false;
    }
    var els = m.elements();
    while (els.next()) |el| {
        var ps = el.params();
        while (ps.next()) |p| {
            const in = for (sd) |want| {
                if (std.mem.eql(u8, el.id, want[0]) and std.mem.eql(u8, p.name, want[1])) break true;
            } else false;
            if (!in) return false;
        }
    }
    return true;
}

fn fieldsAgree(c: *const vectors.Case, m: *const root.Parsed) !bool {
    if (c.pri != root.priority(m.facility, m.severity)) return false;
    if (c.version != m.version) return false;
    if (!optEql(m.hostname, c.hostname, c.has_hostname)) return false;
    if (!optEql(m.app_name, c.app_name, c.has_app_name)) return false;
    if (!optEql(m.procid, c.procid, c.has_procid)) return false;
    if (!optEql(m.msgid, c.msgid, c.has_msgid)) return false;
    // go-syslog leaves a BOM in the message; ours moves it to `msg_utf8`.
    const bom = "\xEF\xBB\xBF";
    const has_bom = std.mem.startsWith(u8, c.msg, bom);
    if (has_bom != m.msg_utf8) return false;
    if (!std.mem.eql(u8, if (has_bom) c.msg[bom.len..] else c.msg, m.msg)) return false;
    if (c.has_time) {
        if (m.timestamp == null or m.timestamp.?.unix_us != c.unix_us) return false;
    } else if (m.timestamp != null) return false;
    return sameSd(m, c.sd);
}

test "go-syslog v4 on grammar edges and damaged lines: same verdict, same fields" {
    var both: usize = 0;
    var bad: usize = 0;
    var diverged: usize = 0;
    for (&vectors.cases) |*c| {
        const r = root.parse(c.line);
        const ours = if (r) |_| true else |_| false;
        if (c.divergence.len > 0) {
            // go-syslog refused this under a rule ours deliberately does not have
            // (`vectors.divergences`). A line may still break something else, so
            // only the known name is required; ours must not panic, that is all.
            const known = for (vectors.divergences) |d| {
                if (std.mem.eql(u8, d.name, c.divergence)) break true;
            } else false;
            try testing.expect(known);
            if (ours) diverged += 1;
            continue;
        }
        var why: []const u8 = "";
        if (r) |m| {
            if (!c.accepted) {
                why = "we accept, go-syslog refuses";
            } else if (try fieldsAgree(c, &m)) {
                both += 1;
            } else why = "fields differ";
        } else |_| {
            if (c.accepted) why = "we refuse, go-syslog accepts";
        }
        if (why.len > 0) {
            bad += 1;
            if (bad <= 60) std.debug.print("{s}: {f}\n", .{ why, std.ascii.hexEscape(c.line, .lower) });
        }
    }
    if (bad > 0) std.debug.print("{d} disagreements of {d}\n", .{ bad, vectors.cases.len });
    try testing.expectEqual(@as(usize, 0), bad);
    try testing.expect(both > 50);
    // The rules are real on this table: lines we read and go-syslog refused.
    try testing.expect(diverged > 3);
}
