// SPDX-License-Identifier: MIT

//! Typed views of the rdata of TLSA (RFC 6698), SSHFP (RFC 4255), URI
//! (RFC 7553), NAPTR (RFC 3403) and SVCB/HTTPS (RFC 9460) records.
//!
//! `message.decode` hands these types out as `Record.data.unknown` (raw rdata,
//! `Record.ty` says which). `parse` turns such a record into a struct; it adds
//! no `Record.Data` variant on purpose, so the exhaustive switches over
//! `Record.Data` in consumers (`dnssec` treats `.unknown` as raw canonical
//! rdata) keep their meaning.
//!
//! Names inside rdata (NAPTR replacement, SVCB TargetName) are never
//! compressed (RFC 3403 §4.1, RFC 9460 §2.2), so the raw bytes are enough.
//! They come back as dotted text without the trailing root dot, the root
//! being "", exactly as `message.zig` spells decoded names.
//!
//! Everything returned lives in the `arena` passed to `parse` (the rdata is
//! copied once, so the result does not borrow from the record). Every length
//! is bounds-checked: any malformed input is `error.BadRecord`, never a panic.
//!
//! ```zig
//! const svcb = try dns.rdata.parse(dns.rdata.Svcb, arena, rec); // HTTPS or SVCB
//! if (svcb.alpn()) |*it| { var i = it.*; while (i.next()) |id| use(id); }
//! ```

const std = @import("std");
const message = @import("message.zig");

pub const ParseError = error{
    /// `rec.ty` is not the type `T` describes (or `rec.data` is not raw).
    WrongType,
    /// The rdata violates the type's wire format or a MUST of its RFC.
    BadRecord,
    OutOfMemory,
};

/// RFC 6698 §2.1.
pub const Tlsa = struct {
    usage: u8,
    selector: u8,
    matching: u8,
    /// Certificate association data (may be empty).
    data: []const u8,
};

/// RFC 4255 §3.1.
pub const Sshfp = struct {
    algorithm: u8,
    fp_type: u8,
    fingerprint: []const u8,
};

/// RFC 7553 §4.5. `target` is never empty (§4.4).
pub const Uri = struct {
    priority: u16,
    weight: u16,
    target: []const u8,
};

/// RFC 3403 §4.1. `flags`, `services` and `regexp` are the raw
/// <character-string> contents (each 0..255 bytes).
pub const Naptr = struct {
    order: u16,
    preference: u16,
    flags: []const u8,
    services: []const u8,
    regexp: []const u8,
    /// Dotted text, "" for the root.
    replacement: []const u8,
};

pub const SvcParam = struct { key: u16, value: []const u8 };

/// SvcParamKeys of RFC 9460 §14.3.2 that this file understands.
pub const svc_key = struct {
    pub const mandatory: u16 = 0;
    pub const alpn: u16 = 1;
    pub const no_default_alpn: u16 = 2;
    pub const port: u16 = 3;
    pub const ipv4hint: u16 = 4;
    pub const ech: u16 = 5;
    pub const ipv6hint: u16 = 6;
};

/// Iterates the alpn-ids of an `alpn` SvcParam (already validated).
pub const AlpnIter = struct {
    rest: []const u8,
    pub fn next(self: *AlpnIter) ?[]const u8 {
        if (self.rest.len == 0) return null;
        const n: usize = self.rest[0];
        if (self.rest.len < 1 + n) {
            self.rest = &.{};
            return null;
        }
        const id = self.rest[1..][0..n];
        self.rest = self.rest[1 + n ..];
        return id;
    }
};

fn AddrIter(comptime n: usize) type {
    return struct {
        rest: []const u8,
        pub fn next(self: *@This()) ?[n]u8 {
            if (self.rest.len < n) return null;
            const a = self.rest[0..n].*;
            self.rest = self.rest[n..];
            return a;
        }
    };
}
pub const Ipv4Iter = AddrIter(4);
pub const Ipv6Iter = AddrIter(16);

/// Iterates the keys of a `mandatory` SvcParam (already validated).
pub const KeyIter = struct {
    rest: []const u8,
    pub fn next(self: *KeyIter) ?u16 {
        if (self.rest.len < 2) return null;
        const k = std.mem.readInt(u16, self.rest[0..2], .big);
        self.rest = self.rest[2..];
        return k;
    }
};

/// RFC 9460 §2.2. SVCB (64) and HTTPS (65) share this wire format (§9).
/// Priority 0 is AliasMode (§2.4.2): its params, if any, are exposed, not
/// rejected.
pub const Svcb = struct {
    priority: u16,
    /// Dotted text, "" for the root ("." in presentation form).
    target: []const u8,
    /// Strictly ascending by key; values already checked against §7.
    params: []const SvcParam,

    pub fn isAlias(s: Svcb) bool {
        return s.priority == 0;
    }

    /// The raw value of `key`, or null when the param is absent.
    pub fn param(s: Svcb, key: u16) ?[]const u8 {
        for (s.params) |p| if (p.key == key) return p.value;
        return null;
    }

    pub fn alpn(s: Svcb) ?AlpnIter {
        return if (s.param(svc_key.alpn)) |v| .{ .rest = v } else null;
    }
    pub fn noDefaultAlpn(s: Svcb) bool {
        return s.param(svc_key.no_default_alpn) != null;
    }
    pub fn port(s: Svcb) ?u16 {
        const v = s.param(svc_key.port) orelse return null;
        return std.mem.readInt(u16, v[0..2], .big);
    }
    pub fn ipv4hint(s: Svcb) ?Ipv4Iter {
        return if (s.param(svc_key.ipv4hint)) |v| .{ .rest = v } else null;
    }
    pub fn ipv6hint(s: Svcb) ?Ipv6Iter {
        return if (s.param(svc_key.ipv6hint)) |v| .{ .rest = v } else null;
    }
    /// The ECHConfigList bytes.
    pub fn ech(s: Svcb) ?[]const u8 {
        return s.param(svc_key.ech);
    }
    pub fn mandatory(s: Svcb) ?KeyIter {
        return if (s.param(svc_key.mandatory)) |v| .{ .rest = v } else null;
    }
};

// ── parsing ─────────────────────────────────────────────────────────────

const Reader = struct {
    b: []const u8,
    at: usize = 0,

    fn left(r: Reader) usize {
        return r.b.len - r.at;
    }
    fn byte(r: *Reader) ParseError!u8 {
        if (r.left() < 1) return error.BadRecord;
        defer r.at += 1;
        return r.b[r.at];
    }
    fn word(r: *Reader) ParseError!u16 {
        if (r.left() < 2) return error.BadRecord;
        defer r.at += 2;
        return std.mem.readInt(u16, r.b[r.at..][0..2], .big);
    }
    fn take(r: *Reader, n: usize) ParseError![]const u8 {
        if (r.left() < n) return error.BadRecord;
        defer r.at += n;
        return r.b[r.at..][0..n];
    }
    fn rest(r: *Reader) []const u8 {
        defer r.at = r.b.len;
        return r.b[r.at..];
    }
    /// <character-string>: length octet + that many octets.
    fn charString(r: *Reader) ParseError![]const u8 {
        return r.take(try r.byte());
    }
    /// An uncompressed wire name, as dotted text in `arena`.
    fn name(r: *Reader, arena: std.mem.Allocator) ParseError![]const u8 {
        const start = r.at;
        var text_len: usize = 0;
        var labels: usize = 0;
        while (true) {
            const n = try r.byte();
            if (n == 0) break;
            if (n > message.max_label_len) return error.BadRecord; // 0x40.. incl. pointers
            _ = try r.take(n);
            text_len += n;
            labels += 1;
            if (r.at - start > 255) return error.BadRecord;
        }
        if (labels > 0) text_len += labels - 1;
        if (text_len > message.max_name_text_len) return error.BadRecord;
        const out = try arena.alloc(u8, text_len);
        var at = start;
        var o: usize = 0;
        while (b_len(r.b, at)) |n| : (at += n + 1) {
            if (o != 0) {
                out[o] = '.';
                o += 1;
            }
            @memcpy(out[o..][0..n], r.b[at + 1 ..][0..n]);
            o += n;
        }
        return out;
    }
};

/// Label length at `at`, or null at the terminating zero (second pass of
/// `Reader.name`, after validation).
fn b_len(b: []const u8, at: usize) ?usize {
    const n = b[at];
    return if (n == 0) null else n;
}

fn rawOf(rec: message.Record) ParseError![]const u8 {
    return switch (rec.data) {
        .unknown => |b| b,
        else => error.WrongType,
    };
}

fn tlsa(arena: std.mem.Allocator, raw: []const u8) ParseError!Tlsa {
    var r: Reader = .{ .b = try arena.dupe(u8, raw) };
    return .{
        .usage = try r.byte(),
        .selector = try r.byte(),
        .matching = try r.byte(),
        .data = r.rest(),
    };
}

fn sshfp(arena: std.mem.Allocator, raw: []const u8) ParseError!Sshfp {
    var r: Reader = .{ .b = try arena.dupe(u8, raw) };
    return .{
        .algorithm = try r.byte(),
        .fp_type = try r.byte(),
        .fingerprint = r.rest(),
    };
}

fn uri(arena: std.mem.Allocator, raw: []const u8) ParseError!Uri {
    var r: Reader = .{ .b = try arena.dupe(u8, raw) };
    const priority = try r.word();
    const weight = try r.word();
    if (r.left() == 0) return error.BadRecord; // RFC 7553 §4.4: target is not empty
    return .{ .priority = priority, .weight = weight, .target = r.rest() };
}

fn naptr(arena: std.mem.Allocator, raw: []const u8) ParseError!Naptr {
    var r: Reader = .{ .b = try arena.dupe(u8, raw) };
    const order = try r.word();
    const preference = try r.word();
    const flags = try r.charString();
    const services = try r.charString();
    const regexp = try r.charString();
    const replacement = try r.name(arena);
    if (r.left() != 0) return error.BadRecord;
    return .{
        .order = order,
        .preference = preference,
        .flags = flags,
        .services = services,
        .regexp = regexp,
        .replacement = replacement,
    };
}

/// RFC 9460 §7 value shapes. `params` is complete (ascending), for the
/// `mandatory` cross-check.
fn checkValue(key: u16, v: []const u8, params: []const SvcParam) ParseError!void {
    switch (key) {
        svc_key.mandatory => {
            if (v.len == 0 or v.len % 2 != 0) return error.BadRecord;
            var prev: ?u16 = null;
            var it: KeyIter = .{ .rest = v };
            // Both lists ascend, so one merge walk checks presence: O(n + m).
            // A nested scan was quadratic in a hostile record (~16k params x
            // ~16k mandatory keys in 64 KiB of rdata).
            var pi: usize = 0;
            while (it.next()) |k| {
                if (k == svc_key.mandatory) return error.BadRecord; // §8: not itself
                if (prev) |p| if (k <= p) return error.BadRecord; // strictly ascending
                prev = k;
                while (pi < params.len and params[pi].key < k) pi += 1;
                if (pi == params.len or params[pi].key != k) return error.BadRecord; // §8: every listed key present
            }
        },
        svc_key.alpn => {
            if (v.len == 0) return error.BadRecord;
            var rest = v;
            while (rest.len != 0) {
                const n: usize = rest[0];
                if (n == 0 or rest.len < 1 + n) return error.BadRecord;
                rest = rest[1 + n ..];
            }
        },
        svc_key.no_default_alpn => if (v.len != 0) return error.BadRecord,
        svc_key.port => if (v.len != 2) return error.BadRecord,
        svc_key.ipv4hint => if (v.len == 0 or v.len % 4 != 0) return error.BadRecord,
        svc_key.ipv6hint => if (v.len == 0 or v.len % 16 != 0) return error.BadRecord,
        svc_key.ech => if (v.len == 0) return error.BadRecord,
        else => {},
    }
}

fn svcb(arena: std.mem.Allocator, raw: []const u8) ParseError!Svcb {
    var r: Reader = .{ .b = try arena.dupe(u8, raw) };
    const priority = try r.word();
    const target = try r.name(arena);
    var list: std.ArrayList(SvcParam) = .empty;
    var prev: ?u16 = null;
    while (r.left() != 0) {
        const key = try r.word();
        const len = try r.word();
        const value = try r.take(len);
        if (prev) |p| if (key <= p) return error.BadRecord; // §2.2: ascending, no duplicates
        prev = key;
        try list.append(arena, .{ .key = key, .value = value });
    }
    const params = list.items;
    for (params) |p| try checkValue(p.key, p.value, params);
    return .{ .priority = priority, .target = target, .params = params };
}

/// Parse `rec`'s rdata as `T` (one of `Tlsa`, `Sshfp`, `Uri`, `Naptr`,
/// `Svcb`). `rec.ty` must be the matching type (`.https` and `.svcb` both for
/// `Svcb`) and `rec.data` raw (`.unknown`), else `error.WrongType`. The
/// result lives in `arena`.
pub fn parse(comptime T: type, arena: std.mem.Allocator, rec: message.Record) ParseError!T {
    const ok = switch (T) {
        Tlsa => rec.ty == .tlsa,
        Sshfp => rec.ty == .sshfp,
        Uri => rec.ty == .uri,
        Naptr => rec.ty == .naptr,
        Svcb => rec.ty == .svcb or rec.ty == .https,
        else => @compileError("rdata.parse: unsupported type " ++ @typeName(T)),
    };
    if (!ok) return error.WrongType;
    const raw = try rawOf(rec);
    return switch (T) {
        Tlsa => tlsa(arena, raw),
        Sshfp => sshfp(arena, raw),
        Uri => uri(arena, raw),
        Naptr => naptr(arena, raw),
        Svcb => svcb(arena, raw),
        else => unreachable,
    };
}

// ── tests ───────────────────────────────────────────────────────────────

const testing = std.testing;
const vectors = @import("rdata_vectors.zig");

fn mk(ty: message.Type, wire: []const u8) message.Record {
    return .{ .name = "x.example", .ty = ty, .class = .in, .ttl = 60, .data = .{ .unknown = wire } };
}

test "dnspython vectors: TLSA" {
    for (vectors.tlsa) |v| {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const t = try parse(Tlsa, arena.allocator(), mk(.tlsa, v.wire));
        try testing.expectEqual(v.usage, t.usage);
        try testing.expectEqual(v.selector, t.selector);
        try testing.expectEqual(v.matching, t.matching);
        try testing.expectEqualSlices(u8, v.data, t.data);
    }
}

test "dnspython vectors: SSHFP" {
    for (vectors.sshfp) |v| {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const t = try parse(Sshfp, arena.allocator(), mk(.sshfp, v.wire));
        try testing.expectEqual(v.algorithm, t.algorithm);
        try testing.expectEqual(v.fp_type, t.fp_type);
        try testing.expectEqualSlices(u8, v.fingerprint, t.fingerprint);
    }
}

test "dnspython vectors: URI" {
    for (vectors.uri) |v| {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const t = try parse(Uri, arena.allocator(), mk(.uri, v.wire));
        try testing.expectEqual(v.priority, t.priority);
        try testing.expectEqual(v.weight, t.weight);
        try testing.expectEqualStrings(v.target, t.target);
    }
}

test "dnspython vectors: NAPTR" {
    for (vectors.naptr) |v| {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const t = try parse(Naptr, arena.allocator(), mk(.naptr, v.wire));
        try testing.expectEqual(v.order, t.order);
        try testing.expectEqual(v.preference, t.preference);
        try testing.expectEqualSlices(u8, v.flags, t.flags);
        try testing.expectEqualSlices(u8, v.services, t.services);
        try testing.expectEqualSlices(u8, v.regexp, t.regexp);
        try testing.expectEqualStrings(v.replacement, t.replacement);
    }
}

test "dnspython vectors: SVCB / HTTPS, params and every accessor" {
    for (vectors.svcb) |v| {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const s = try parse(Svcb, a, mk(@fromBackingInt(@intCast(v.ty)), v.wire));
        try testing.expectEqual(v.priority, s.priority);
        try testing.expectEqualStrings(v.target, s.target);
        try testing.expectEqual(v.priority == 0, s.isAlias());
        try testing.expectEqual(v.params.len, s.params.len);
        for (v.params, s.params) |want, got| {
            try testing.expectEqual(want.key, got.key);
            try testing.expectEqualSlices(u8, want.value, got.value);
        }
        // alpn
        if (v.alpn) |want| {
            var it = s.alpn().?;
            for (want) |id| try testing.expectEqualSlices(u8, id, it.next().?);
            try testing.expectEqual(@as(?[]const u8, null), it.next());
        } else try testing.expect(s.alpn() == null);
        try testing.expectEqual(v.no_default_alpn, s.noDefaultAlpn());
        try testing.expectEqual(v.port, s.port());
        if (v.ipv4hint) |want| {
            var it = s.ipv4hint().?;
            for (want) |ad| try testing.expectEqual(ad, it.next().?);
            try testing.expectEqual(@as(?[4]u8, null), it.next());
        } else try testing.expect(s.ipv4hint() == null);
        if (v.ipv6hint) |want| {
            var it = s.ipv6hint().?;
            for (want) |ad| try testing.expectEqual(ad, it.next().?);
            try testing.expectEqual(@as(?[16]u8, null), it.next());
        } else try testing.expect(s.ipv6hint() == null);
        if (v.ech) |want| {
            try testing.expectEqualSlices(u8, want, s.ech().?);
        } else try testing.expect(s.ech() == null);
        if (v.mandatory) |want| {
            var it = s.mandatory().?;
            for (want) |k| try testing.expectEqual(k, it.next().?);
            try testing.expectEqual(@as(?u16, null), it.next());
        } else try testing.expect(s.mandatory() == null);
    }
}

test "SVCB: AliasMode with params is accepted and exposed (RFC 9460 §2.4.2)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const wire = "\x00\x00" ++ "\x05alias\x07example\x00" ++ "\x00\x01\x00\x03\x02h2";
    const s = try parse(Svcb, arena.allocator(), mk(.https, wire));
    try testing.expect(s.isAlias());
    try testing.expectEqualStrings("alias.example", s.target);
    try testing.expectEqualStrings("h2", s.alpn().?.rest[1..]);
}

test "parse: the type must match, the data must be raw" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const tl = vectors.tlsa[0].wire;
    try testing.expectError(error.WrongType, parse(Tlsa, a, mk(.sshfp, tl)));
    try testing.expectError(error.WrongType, parse(Sshfp, a, mk(.tlsa, tl)));
    try testing.expectError(error.WrongType, parse(Uri, a, mk(.naptr, tl)));
    try testing.expectError(error.WrongType, parse(Naptr, a, mk(.uri, tl)));
    try testing.expectError(error.WrongType, parse(Svcb, a, mk(.tlsa, tl)));
    try testing.expectError(error.WrongType, parse(Svcb, a, mk(.txt, tl)));
    var r = mk(.tlsa, tl);
    r.data = .{ .cname = "x" };
    try testing.expectError(error.WrongType, parse(Tlsa, a, r));
    _ = try parse(Svcb, a, mk(.svcb, "\x00\x01\x00"));
    _ = try parse(Svcb, a, mk(.https, "\x00\x01\x00"));
}

const long_label: [64]u8 = @splat('a');

test "negative table: every malformed rdata is BadRecord" {
    const T = struct { ty: message.Type, wire: []const u8, what: []const u8 };
    const bad = [_]T{
        .{ .ty = .tlsa, .wire = "", .what = "TLSA empty" },
        .{ .ty = .tlsa, .wire = "\x03\x01", .what = "TLSA shorter than 3" },
        .{ .ty = .sshfp, .wire = "\x01", .what = "SSHFP shorter than 2" },
        .{ .ty = .uri, .wire = "\x00\x0a\x00", .what = "URI shorter than 4" },
        .{ .ty = .uri, .wire = "\x00\x0a\x00\x01", .what = "URI empty target" },
        .{ .ty = .naptr, .wire = "\x00\x01\x00\x02\x01u\x07E2U", .what = "NAPTR services string truncated" },
        .{ .ty = .naptr, .wire = "\x00\x01\x00\x02\x01u\x00\x00", .what = "NAPTR replacement missing" },
        .{ .ty = .naptr, .wire = "\x00\x01\x00\x02\x00\x00\x00\x00\x00", .what = "NAPTR trailing bytes" },
        .{ .ty = .naptr, .wire = "\x00\x01\x00\x02\x00\x00\x00\xc0\x0c", .what = "NAPTR compression pointer" },
        .{ .ty = .naptr, .wire = "\x00\x01\x00\x02\x00\x00\x00\x03abc", .what = "NAPTR name unterminated" },
        .{ .ty = .svcb, .wire = "\x00", .what = "SVCB priority truncated" },
        .{ .ty = .svcb, .wire = "\x00\x01", .what = "SVCB target missing" },
        .{ .ty = .svcb, .wire = "\x00\x01\x40" ++ long_label ++ "\x00", .what = "SVCB label over 63" },
        .{ .ty = .svcb, .wire = "\x00\x01\x00\x00\x03\x00\x02\x00\x50\x00\x01\x00\x03\x02h2", .what = "SVCB keys out of order" },
        .{ .ty = .svcb, .wire = "\x00\x01\x00\x00\x03\x00\x02\x00\x50\x00\x03\x00\x02\x1f\x90", .what = "SVCB duplicate key" },
        .{ .ty = .svcb, .wire = "\x00\x01\x00\x00\x03\x00\x02\x00", .what = "SVCB value truncated" },
        .{ .ty = .svcb, .wire = "\x00\x01\x00\x00\x03\x00", .what = "SVCB param header truncated" },
        .{ .ty = .svcb, .wire = "\x00\x01\x00\x00\x00\x00\x02\x00\x01", .what = "SVCB mandatory names absent key" },
        .{ .ty = .svcb, .wire = "\x00\x01\x00\x00\x00\x00\x02\x00\x00", .what = "SVCB mandatory names itself" },
        .{ .ty = .svcb, .wire = "\x00\x01\x00\x00\x00\x00\x03\x00\x01\x00", .what = "SVCB mandatory odd length" },
        .{ .ty = .svcb, .wire = "\x00\x01\x00\x00\x00\x00\x04\x00\x03\x00\x01\x00\x01\x00\x03\x00\x02\x00\x50", .what = "SVCB mandatory not ascending" },
        .{ .ty = .svcb, .wire = "\x00\x01\x00\x00\x00\x00\x00", .what = "SVCB mandatory empty" },
        .{ .ty = .https, .wire = "\x00\x01\x00\x00\x03\x00\x01\x00", .what = "HTTPS port one byte" },
        .{ .ty = .https, .wire = "\x00\x01\x00\x00\x04\x00\x03\x01\x02\x03", .what = "HTTPS ipv4hint length 3" },
        .{ .ty = .https, .wire = "\x00\x01\x00\x00\x06\x00\x04\x01\x02\x03\x04", .what = "HTTPS ipv6hint length 4" },
        .{ .ty = .https, .wire = "\x00\x01\x00\x00\x01\x00\x00", .what = "HTTPS alpn empty" },
        .{ .ty = .https, .wire = "\x00\x01\x00\x00\x01\x00\x01\x00", .what = "HTTPS alpn zero-length id" },
        .{ .ty = .https, .wire = "\x00\x01\x00\x00\x01\x00\x03\x05h2", .what = "HTTPS alpn id past value" },
        .{ .ty = .https, .wire = "\x00\x01\x00\x00\x02\x00\x01\x00", .what = "HTTPS no-default-alpn with value" },
        .{ .ty = .https, .wire = "\x00\x01\x00\x00\x05\x00\x00", .what = "HTTPS ech empty" },
    };
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    for (bad) |c| {
        const a = arena.allocator();
        const got: ParseError!void = switch (c.ty) {
            .tlsa => if (parse(Tlsa, a, mk(c.ty, c.wire))) |_| {} else |e| e,
            .sshfp => if (parse(Sshfp, a, mk(c.ty, c.wire))) |_| {} else |e| e,
            .uri => if (parse(Uri, a, mk(c.ty, c.wire))) |_| {} else |e| e,
            .naptr => if (parse(Naptr, a, mk(c.ty, c.wire))) |_| {} else |e| e,
            else => if (parse(Svcb, a, mk(c.ty, c.wire))) |_| {} else |e| e,
        };
        testing.expectError(error.BadRecord, got) catch |e| {
            std.debug.print("negative case not rejected: {s}\n", .{c.what});
            return e;
        };
    }
}

test "OOM: every allocation failure is OutOfMemory, never a panic or leak" {
    for (vectors.svcb) |v| {
        var fail: usize = 0;
        while (true) : (fail += 1) {
            var fa: testing.FailingAllocator = .init(testing.allocator, .{ .fail_index = fail });
            var arena: std.heap.ArenaAllocator = .init(fa.allocator());
            defer arena.deinit();
            if (parse(Svcb, arena.allocator(), mk(@fromBackingInt(@intCast(v.ty)), v.wire))) |_| {
                break;
            } else |e| try testing.expectEqual(error.OutOfMemory, e);
        }
    }
}

test "Svcb mandatory: a 10,000-key list over 10,000 params is checked in one merge walk; a missing key is still BadRecord" {
    const n = 10_000;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // priority 1, root target, mandatory (key 0) listing keys 8..8+n-1, then
    // those n params with empty values (unknown keys: any value is fine).
    var wire: std.ArrayList(u8) = .empty;
    try wire.appendSlice(a, &.{ 0, 1, 0, 0, 0 });
    try wire.appendSlice(a, &.{ @intCast((2 * n) >> 8), @intCast((2 * n) & 0xff) });
    for (0..n) |i| try wire.appendSlice(a, &.{ @intCast((8 + i) >> 8), @intCast((8 + i) & 0xff) });
    for (0..n) |i| try wire.appendSlice(a, &.{ @intCast((8 + i) >> 8), @intCast((8 + i) & 0xff), 0, 0 });
    const s = try parse(Svcb, a, mk(.svcb, wire.items));
    try testing.expectEqual(@as(usize, n + 1), s.params.len);
    // Drop the last param: the mandatory list now names an absent key.
    try testing.expectError(error.BadRecord, parse(Svcb, a, mk(.svcb, wire.items[0 .. wire.items.len - 4])));
}
