// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor: golang.org/x/net/dns/dnsmessage (v0.59.0,
//! BSD-3-Clause; the parser Go's own resolver uses) as an independent
//! implementation of `message.zig`. The cases are ours
//! (`tools/go_oracle/main.go`); Go's answers to them were captured into
//! `go_oracle_vectors.zig`, and the tests here replay the same bytes through
//! THIS module and compare. No Go at test time. Exempt from a NOTICE entry
//! under §0's black-box-oracle carve-out: only Go's observable verdicts were
//! recorded, no Go source was read or ported.
//!
//!  - `built`: messages dnsmessage's own Builder produced, plain and with
//!    name compression;
//!  - `crafted`: messages built byte by byte (pointers, label types, name
//!    lengths, RDLENGTH lies, every decoded type short and long, OPT shapes);
//!  - `queries`: query parameters; `encodeQuery` must produce Go's Builder
//!    bytes exactly, and refuse what Go refuses.
//!
//! Both sides render a decoded message as the text described in the vectors
//! file (`Case`); a difference in any line is a divergence. Go is an oracle,
//! not an authority: every deliberate difference is listed in `divergences`
//! with the judgement; an unlisted difference fails, and so does a listed one
//! that has started to agree.

const std = @import("std");
const testing = std.testing;
const msg = @import("message.zig");
const vectors = @import("go_oracle_vectors.zig");

const Divergence = struct { id: []const u8, why: []const u8 };

/// dnspython 2.8.0 (`dns.message.from_wire`) was asked as the tiebreaker on
/// each; every entry below sides with it.
const divergences = [_]Divergence{
    .{ .id = "a_rdlen_5", .why = "an A record with RDLENGTH 5: dnsmessage reads 4 octets and skips the fifth; RFC 1035 3.4.1 says 4 octets, dnspython and we refuse it (BadRecord)" },
    .{ .id = "rdlen_past_end", .why = "RDLENGTH 40 with 4 bytes left: dnsmessage decodes the A record from the 4; dnspython and we report the message truncated" },
    .{ .id = "ns_name_past_rdlen", .why = "an NS name that runs past RDLENGTH: dnsmessage reads it anyway; dnspython and we refuse it" },
    .{ .id = "caa_empty_tag", .why = "dnsmessage has no CAA type (raw RDATA); RFC 8659 4.1 requires a non-empty tag, dnspython and we refuse an empty one" },
    .{ .id = "caa_tag_overrun", .why = "a CAA tag length past RDLENGTH: raw for dnsmessage; dnspython and we refuse it" },
    .{ .id = "label_with_dot", .why = "a label containing '.': dnsmessage refuses the name; dnspython and we decode it (documented: dotted text plus Record.labels for the true boundaries, audit F7)" },
};

const Lines = std.ArrayList([]const u8);

fn hex(w: *std.Io.Writer, bytes: []const u8) !void {
    for (bytes) |b| try w.print("{x:0>2}", .{b});
}

fn renderRecord(a: std.mem.Allocator, r: msg.Record) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    const w = &out.writer;
    try w.print("{s} {d} {d} {d} ", .{ r.name, @intFromEnum(r.ty), @intFromEnum(r.class), r.ttl });
    switch (r.data) {
        .a => |v| try w.print("A {d}.{d}.{d}.{d}", .{ v[0], v[1], v[2], v[3] }),
        .aaaa => |v| {
            try w.writeAll("AAAA ");
            try hex(w, &v);
        },
        .ns => |n| try w.print("NS {s}", .{n}),
        .cname => |n| try w.print("CNAME {s}", .{n}),
        .ptr => |n| try w.print("PTR {s}", .{n}),
        .mx => |m| try w.print("MX {d} {s}", .{ m.preference, m.exchange }),
        .txt => |strings| {
            try w.writeAll("TXT ");
            for (strings, 0..) |s, i| {
                if (i > 0) try w.writeByte(',');
                try hex(w, s);
            }
        },
        .soa => |s| try w.print("SOA {s} {s} {d} {d} {d} {d} {d}", .{ s.mname, s.rname, s.serial, s.refresh, s.retry, s.expire, s.minimum }),
        .srv => |s| try w.print("SRV {d} {d} {d} {s}", .{ s.priority, s.weight, s.port, s.target }),
        .opt => |o| {
            try w.print("OPT {d} {d} {d} {d} ", .{ o.udp_payload_size, o.extended_rcode, o.version, @intFromBool(o.dnssec_ok) });
            try hex(w, o.options);
        },
        // dnsmessage has no CAA type: compare its raw RDATA.
        .caa => |c| {
            try w.print("RAW {x:0>2}{x:0>2}", .{ c.flags, c.tag.len });
            try hex(w, c.tag);
            try hex(w, c.value);
        },
        .unknown => |raw| {
            try w.writeAll("RAW ");
            try hex(w, raw);
        },
    }
    return out.toOwnedSlice();
}

/// Describe the first difference between our decode of `c.bytes` and Go's.
fn compare(a: std.mem.Allocator, c: vectors.Case, why: *std.Io.Writer) !void {
    var m = msg.decode(testing.allocator, c.bytes) catch |err| {
        if (c.err == null) return why.print("ours: error.{t}; go decoded it", .{err});
        return;
    };
    defer m.deinit();
    if (c.err) |e| return why.print("ours: decoded; go: \"{s}\"", .{e});

    const h = m.header;
    const hdr = try std.fmt.allocPrint(a, "id={d} qr={d} op={d} aa={d} tc={d} rd={d} ra={d} rcode={d}", .{
        h.id,                                @intFromBool(h.response),  @intFromEnum(h.opcode),
        @intFromBool(h.authoritative),       @intFromBool(h.truncated), @intFromBool(h.recursion_desired),
        @intFromBool(h.recursion_available), h.rcode,
    });
    if (!std.mem.eql(u8, hdr, c.header)) return why.print("header: ours \"{s}\", go \"{s}\"", .{ hdr, c.header });

    if (m.questions.len != c.questions.len) return why.print("questions: ours {d}, go {d}", .{ m.questions.len, c.questions.len });
    for (m.questions, c.questions, 0..) |q, want, i| {
        const got = try std.fmt.allocPrint(a, "{s} {d} {d}", .{ q.name, @intFromEnum(q.ty), @intFromEnum(q.class) });
        if (!std.mem.eql(u8, got, want)) return why.print("question {d}: ours \"{s}\", go \"{s}\"", .{ i, got, want });
    }
    const sections = [_]struct { name: []const u8, ours: []const msg.Record, go: []const []const u8 }{
        .{ .name = "answer", .ours = m.answers, .go = c.answers },
        .{ .name = "authority", .ours = m.authorities, .go = c.authorities },
        .{ .name = "additional", .ours = m.additionals, .go = c.additionals },
    };
    for (sections) |s| {
        if (s.ours.len != s.go.len) return why.print("{s}s: ours {d}, go {d}", .{ s.name, s.ours.len, s.go.len });
        for (s.ours, s.go, 0..) |r, want, i| {
            const got = try renderRecord(a, r);
            if (!std.mem.eql(u8, got, want)) return why.print("{s} {d}: ours \"{s}\", go \"{s}\"", .{ s.name, i, got, want });
        }
    }
}

fn find(id: []const u8) ?Divergence {
    for (divergences) |d| if (std.mem.eql(u8, d.id, id)) return d;
    return null;
}

fn replayTable(comptime table: []const vectors.Case) !void {
    var failed: usize = 0;
    for (table) |c| {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        var why_buf: [768]u8 = undefined;
        var why: std.Io.Writer = .fixed(&why_buf);
        compare(arena.allocator(), c, &why) catch |err| switch (err) {
            error.WriteFailed => {},
            else => return err,
        };
        const differs = why.end > 0;
        const listed = find(c.id) != null;
        if (differs and !listed) {
            std.debug.print("go oracle: {s}: {s}\n", .{ c.id, why.buffered() });
            failed += 1;
        } else if (!differs and listed) {
            std.debug.print("go oracle: {s} is listed as a divergence but agrees with Go now\n", .{c.id});
            failed += 1;
        }
    }
    if (failed != 0) return error.GoOracleDisagrees;
}

test "go oracle: messages dnsmessage's Builder produced decode the same here" {
    try replayTable(&vectors.built);
}

test "go oracle: crafted messages decode the same here" {
    try replayTable(&vectors.crafted);
}

test "go oracle: encodeQuery writes dnsmessage's Builder bytes, and refuses what it refuses" {
    var failed: usize = 0;
    for (vectors.queries) |q| {
        var buf: [msg.max_query_len]u8 = undefined;
        const got = msg.encodeQuery(&buf, q.name, @enumFromInt(q.ty), .{ .id = q.id, .recursion_desired = q.rd, .edns_udp_size = q.edns });
        const id = find(q.name) != null;
        if (q.bytes) |want| {
            const ours = got catch |err| {
                if (!id) std.debug.print("go oracle: query \"{s}\": ours error.{t}, go built it\n", .{ q.name, err });
                failed += @intFromBool(!id);
                continue;
            };
            if (!std.mem.eql(u8, ours, want)) {
                if (!id) std.debug.print("go oracle: query \"{s}\": bytes differ\n", .{q.name});
                failed += @intFromBool(!id);
            }
        } else if (got) |_| {
            if (!id) std.debug.print("go oracle: query \"{s}\": ours built it, go refused\n", .{q.name});
            failed += @intFromBool(!id);
        } else |_| {}
    }
    if (failed != 0) return error.GoOracleDisagrees;
}

test "go oracle: every divergence names a case that exists" {
    for (divergences) |d| {
        var seen = false;
        inline for (.{ vectors.built, vectors.crafted }) |t| {
            for (t) |c| seen = seen or std.mem.eql(u8, c.id, d.id);
        }
        for (vectors.queries) |q| seen = seen or std.mem.eql(u8, q.name, d.id);
        if (!seen) {
            std.debug.print("go oracle: divergence {s} names no case\n", .{d.id});
            return error.StaleDivergence;
        }
    }
}
