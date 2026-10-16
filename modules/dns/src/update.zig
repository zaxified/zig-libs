// SPDX-License-Identifier: MIT

//! RFC 2136 dynamic update: build an UPDATE message and send it to a zone's
//! primary server, optionally signed with TSIG (`tsig.zig`) — what `nsupdate`,
//! certbot's rfc2136 plugin and lego's `rfc2136` provider do to publish an
//! ACME DNS-01 record on BIND, Knot, PowerDNS or Windows DNS.
//!
//! Message shape (§2): the four sections are reused as ZONE (one SOA question
//! naming the zone), PREREQUISITE (answer section), UPDATE (authority) and
//! ADDITIONAL; the class and TTL fields carry the operation (§2.4, §2.5).
//! `Builder` writes prerequisites first, then updates — the wire order — and
//! refuses a prerequisite after an update (`error.OutOfOrder`). Names are
//! never compressed (as `encodeQuery`). Class is IN throughout.
//!
//! `send` assigns a fresh random message id, signs when a key is given,
//! sends over UDP (TCP for a message over 512 bytes, after a truncated reply,
//! or with `transport = .tcp`) and returns the response code — `no_error`
//! means the update was applied; `refused`, `not_auth`, `yx_rrset`, ... are the
//! server's verdict for the caller to read. A signed update accepts only a
//! response signed with the same key (`tsig.verify`), so an off-path forger
//! cannot fake success; an unsigned one has only the id and the question echo.

const std = @import("std");
const netaddr = @import("netaddr");
const message = @import("message.zig");
const tsig = @import("tsig.zig");
const Resolver = @import("Resolver.zig");

pub const Error = message.EncodeError || error{
    /// A prerequisite after an update (the sections are written in order).
    OutOfOrder,
    /// 65 535 records in one section.
    TooManyRecords,
};

pub const Builder = struct {
    buf: []u8,
    len: usize,
    stage: enum { prerequisite, update } = .prerequisite,

    /// Start an UPDATE for `zone` (the zone apex, e.g. "example.org") in
    /// `buf`. Size `buf` for the records plus `tsig.recordLen(key)` when the
    /// message will be signed.
    pub fn init(buf: []u8, zone: []const u8) Error!Builder {
        var w: std.Io.Writer = .fixed(buf);
        writeInit(&w, zone) catch |err| switch (err) {
            error.WriteFailed => return error.BufferTooSmall,
            else => |e| return e,
        };
        return .{ .buf = buf, .len = w.end };
    }

    fn writeInit(w: *std.Io.Writer, zone: []const u8) (message.EncodeError || error{WriteFailed})!void {
        try w.writeInt(u16, 0, .big); // id: `send` assigns one
        try w.writeInt(u16, @as(u16, @intFromEnum(message.Opcode.update)) << 11, .big);
        try w.writeInt(u16, 1, .big); // ZOCOUNT
        try w.writeInt(u16, 0, .big); // PRCOUNT
        try w.writeInt(u16, 0, .big); // UPCOUNT
        try w.writeInt(u16, 0, .big); // ADCOUNT
        try message.writeName(w, zone);
        try w.writeInt(u16, @intFromEnum(message.Type.soa), .big);
        try w.writeInt(u16, @intFromEnum(message.Class.in), .big);
    }

    /// The message so far (unsigned; id 0 until `send` or `setId`).
    pub fn bytes(b: *const Builder) []u8 {
        return b.buf[0..b.len];
    }

    pub fn setId(b: *Builder, id: u16) void {
        std.mem.writeInt(u16, b.buf[0..2], id, .big);
    }

    // ── prerequisites (§2.4) ────────────────────────────────────────────────

    /// The RRset `name`/`ty` exists, whatever its records (§2.4.1).
    pub fn requireRrsetExists(b: *Builder, name: []const u8, ty: message.Type) Error!void {
        try b.record(.prerequisite, name, ty, .any, 0, "");
    }

    /// The RRset `name`/`ty` exists with exactly the records given in
    /// consecutive calls (§2.4.2): one call per record.
    pub fn requireRecord(b: *Builder, name: []const u8, ty: message.Type, rdata: []const u8) Error!void {
        try b.record(.prerequisite, name, ty, .in, 0, rdata);
    }

    /// No RRset `name`/`ty` exists (§2.4.3).
    pub fn requireRrsetAbsent(b: *Builder, name: []const u8, ty: message.Type) Error!void {
        try b.record(.prerequisite, name, ty, .none, 0, "");
    }

    /// `name` owns at least one record (§2.4.4).
    pub fn requireNameInUse(b: *Builder, name: []const u8) Error!void {
        try b.record(.prerequisite, name, .any, .any, 0, "");
    }

    /// `name` owns no record (§2.4.5).
    pub fn requireNameNotInUse(b: *Builder, name: []const u8) Error!void {
        try b.record(.prerequisite, name, .any, .none, 0, "");
    }

    // ── updates (§2.5) ──────────────────────────────────────────────────────

    /// Add one record to an RRset (§2.5.1). Adding a record that already
    /// exists is a no-op on the server.
    pub fn add(b: *Builder, name: []const u8, ty: message.Type, ttl: u32, rdata: []const u8) Error!void {
        try b.record(.update, name, ty, .in, ttl, rdata);
    }

    /// Delete the whole RRset `name`/`ty` (§2.5.2).
    pub fn deleteRrset(b: *Builder, name: []const u8, ty: message.Type) Error!void {
        try b.record(.update, name, ty, .any, 0, "");
    }

    /// Delete every RRset `name` owns (§2.5.3).
    pub fn deleteName(b: *Builder, name: []const u8) Error!void {
        try b.record(.update, name, .any, .any, 0, "");
    }

    /// Delete one record from an RRset (§2.5.4), matched by its RDATA.
    pub fn delete(b: *Builder, name: []const u8, ty: message.Type, rdata: []const u8) Error!void {
        try b.record(.update, name, ty, .none, 0, rdata);
    }

    fn record(
        b: *Builder,
        section: @TypeOf(b.stage),
        name: []const u8,
        ty: message.Type,
        class: message.Class,
        ttl: u32,
        rdata: []const u8,
    ) Error!void {
        if (section == .prerequisite and b.stage == .update) return error.OutOfOrder;
        const count_at: usize = if (section == .prerequisite) 6 else 8;
        const count = std.mem.readInt(u16, b.buf[count_at..][0..2], .big);
        if (count == std.math.maxInt(u16)) return error.TooManyRecords;
        if (rdata.len > std.math.maxInt(u16)) return error.BufferTooSmall;
        var w: std.Io.Writer = .fixed(b.buf[b.len..]);
        writeRecord(&w, name, ty, class, ttl, rdata) catch |err| switch (err) {
            error.WriteFailed => return error.BufferTooSmall,
            else => |e| return e,
        };
        b.len += w.end;
        b.stage = section;
        std.mem.writeInt(u16, b.buf[count_at..][0..2], count + 1, .big);
    }
};

fn writeRecord(
    w: *std.Io.Writer,
    name: []const u8,
    ty: message.Type,
    class: message.Class,
    ttl: u32,
    rdata: []const u8,
) (message.EncodeError || error{WriteFailed})!void {
    try message.writeName(w, name);
    try w.writeInt(u16, @intFromEnum(ty), .big);
    try w.writeInt(u16, @intFromEnum(class), .big);
    try w.writeInt(u32, ttl, .big);
    try w.writeInt(u16, @intCast(rdata.len), .big);
    try w.writeAll(rdata);
}

/// TXT RDATA for `value`: one character-string, or several of at most 255
/// bytes each when it is longer (RFC 1035 §3.3.14; what `nsupdate` and
/// dnspython do with a long value). Returns the written slice of `buf`.
pub fn txtRdata(buf: []u8, value: []const u8) error{BufferTooSmall}![]u8 {
    const chunks = @max(1, std.math.divCeil(usize, value.len, 255) catch unreachable);
    if (buf.len < value.len + chunks) return error.BufferTooSmall;
    var at: usize = 0;
    var rest = value;
    for (0..chunks) |_| {
        const n: usize = @min(rest.len, 255);
        buf[at] = @intCast(n);
        @memcpy(buf[at + 1 ..][0..n], rest[0..n]);
        at += 1 + n;
        rest = rest[n..];
    }
    return buf[0..at];
}

pub const SendOptions = struct {
    /// Sign the update and require a signed response (RFC 8945).
    key: ?*const tsig.Key = null,
    fudge: u16 = tsig.default_fudge,
};

pub const SendError = Resolver.Error || tsig.VerifyError || error{
    /// The builder's buffer has no room for the TSIG record.
    BufferTooSmall,
};

/// Send the update built in `b` to `server` (the zone's primary; port, timeout
/// and attempts from the resolver's `Options`) and return the response code.
/// Overwrites the message id with a fresh random one; the TSIG record (when
/// `options.key` is set) is written after `b.len` and not kept, so `b` can be
/// sent again.
pub fn send(r: *Resolver, server: netaddr.Ip, b: *Builder, options: SendOptions) SendError!message.Rcode {
    var id_bytes: [2]u8 = undefined;
    r.io.random(&id_bytes);
    b.setId(std.mem.readInt(u16, &id_bytes, .big));

    var packet: []const u8 = b.bytes();
    var request_mac: tsig.Mac = .{};
    // Signing bumps ARCOUNT in the builder's header; put it back, so a second
    // `send` of the same builder signs the same message, not one that
    // announces a record it no longer carries.
    const arcount = b.buf[10..12].*;
    defer b.buf[10..12].* = arcount;
    if (options.key) |key| {
        packet = tsig.sign(b.buf, b.len, key, .{ .time = @intCast(nowSeconds(r.io)), .fudge = options.fudge }, &request_mac) catch |err| switch (err) {
            error.BufferTooSmall => return error.BufferTooSmall,
            error.NameTooLong => return error.NameTooLong,
            error.BadName => return error.BadName,
            // The builder writes a header and caps every count below 65 535.
            error.Malformed => unreachable,
        };
    }

    const raw = try r.exchange(server, packet);
    defer r.gpa.free(raw);

    if (options.key) |key| {
        var seen: tsig.Mac = undefined;
        try tsig.verify(raw, key, .{ .now = nowSeconds(r.io), .request_mac = request_mac.slice() }, &seen);
    }

    var msg = message.decode(r.gpa, raw) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    defer msg.deinit();
    if (msg.header.opcode != .update) return error.MalformedResponse;
    // §3.8: the response echoes the zone section; a server may also return
    // it empty (with FORMERR, for one), but never a different zone.
    if (msg.questions.len > 1) return error.MalformedResponse;
    if (msg.questions.len == 1) {
        const q = msg.questions[0];
        var zone_buf: [message.max_name_text_len]u8 = undefined;
        const zone = zoneOf(b, &zone_buf);
        if (q.ty != .soa or q.class != .in or !std.ascii.eqlIgnoreCase(q.name, zone)) return error.MalformedResponse;
    }
    return msg.rcode();
}

fn nowSeconds(io: std.Io) u64 {
    const ns = std.Io.Clock.real.now(io).nanoseconds;
    return if (ns <= 0) 0 else @intCast(@divTrunc(ns, std.time.ns_per_s));
}

/// The zone name `b` was started with, as dotted text (no trailing dot).
fn zoneOf(b: *const Builder, out: *[message.max_name_text_len]u8) []const u8 {
    var pos: usize = message.header_len;
    var len: usize = 0;
    while (b.buf[pos] != 0) {
        const n = b.buf[pos];
        if (len != 0) {
            out[len] = '.';
            len += 1;
        }
        @memcpy(out[len..][0..n], b.buf[pos + 1 ..][0..n]);
        len += n;
        pos += 1 + n;
    }
    return out[0..len];
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const vectors = @import("tsig_vectors.zig");

test "Builder: byte-identical to dnspython's uncompressed UpdateMessage" {
    var buf: [1024]u8 = undefined;
    var b = try Builder.init(&buf, "example.org");
    b.setId(0x4242);
    var rd: [512]u8 = undefined;
    try b.requireNameInUse("example.org");
    try b.requireNameNotInUse("new.example.org");
    try b.requireRrsetExists("www.example.org", .a);
    try b.requireRrsetAbsent("_acme-challenge.example.org", .cname);
    try b.requireRecord("www.example.org", .a, &.{ 192, 0, 2, 1 });
    try b.add("_acme-challenge.example.org", .txt, 60, try txtRdata(&rd, "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"));
    try b.add("long.example.org", .txt, 300, try txtRdata(&rd, &(@as([300]u8, @splat('x')))));
    try b.delete("_acme-challenge.example.org", .txt, try txtRdata(&rd, "old"));
    try b.deleteRrset("stale.example.org", .txt);
    try b.deleteName("gone.example.org");
    try testing.expectEqualSlices(u8, vectors.update_all_ops, b.bytes());
}

test "Builder: section order, buffer and name errors leave the message intact" {
    var buf: [64]u8 = undefined;
    var b = try Builder.init(&buf, "example.org");
    try b.add("a.example.org", .a, 60, &.{ 192, 0, 2, 1 });
    try testing.expectError(error.OutOfOrder, b.requireNameInUse("example.org"));
    const before = b.len;
    try testing.expectError(error.BufferTooSmall, b.add("a-very-long-label-to-overflow.example.org", .a, 60, &.{ 192, 0, 2, 1 }));
    try testing.expectError(error.BadName, b.add("a..example.org", .a, 60, &.{ 192, 0, 2, 1 }));
    try testing.expectEqual(before, b.len);
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, buf[8..10], .big));
    var small: [20]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, Builder.init(&small, "example.org"));

    var msg = try message.decode(testing.allocator, b.bytes());
    defer msg.deinit();
    try testing.expectEqual(message.Opcode.update, msg.header.opcode);
    try testing.expectEqualStrings("example.org", msg.questions[0].name);
    try testing.expectEqual(@as(usize, 1), msg.authorities.len);
}

test "txtRdata: splits at 255, empty value is one empty string" {
    var buf: [600]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0}, try txtRdata(&buf, ""));
    try testing.expectEqualSlices(u8, "\x03abc", try txtRdata(&buf, "abc"));
    const v: [510]u8 = @splat('v');
    const out = try txtRdata(&buf, &v);
    try testing.expectEqual(@as(usize, 512), out.len);
    try testing.expectEqual(@as(u8, 255), out[0]);
    try testing.expectEqual(@as(u8, 255), out[256]);
    try testing.expectError(error.BufferTooSmall, txtRdata(buf[0..511], &v));
}
