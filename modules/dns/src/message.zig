// SPDX-License-Identifier: MIT

//! DNS wire-format message codec (RFC 1035 §4) — pure and transport-agnostic.
//!
//! Encodes queries and decodes responses: header, question and resource-record
//! sections, name-compression pointers (decode side; encode never compresses),
//! rdata for A/AAAA/PTR/CNAME/NS/MX/TXT/SOA (RFC 1035), SRV (RFC 2782),
//! CAA (RFC 8659), and the EDNS(0) OPT pseudo-record (RFC 6891). Modeled
//! after Go `x/net/dns/dnsmessage` and miekg/dns.
//!
//! Robustness rules for adversarial input (this file must be bulletproof):
//! - a compression pointer must point strictly backwards, before its own
//!   position (Go enforces the same; RFC 1035 says "a *prior* occurrence"),
//! - decoded name text is capped at 253 chars (= the RFC's 255-byte wire cap),
//! - pointer chains are additionally capped at `max_pointer_jumps`,
//! - section counts are sanity-checked against the remaining packet length
//!   before allocating,
//! so malformed, truncated or looping packets always return a `DecodeError` —
//! no panics, no hangs, no unbounded allocation.
//!
//! Decoded names are dotted ASCII text without the trailing root dot (root is
//! the empty string); no `\DDD` escape handling (labels are raw bytes).
//! Allocation model: `decode` builds the whole `Message`
//! behind a single arena owned by the message (free with `Message.deinit`);
//! `encodeQuery` writes into a caller-provided buffer, no allocation.

const std = @import("std");

// ── wire vocabulary ─────────────────────────────────────────────────────────

/// Resource-record / query type (RFC 1035 §3.2.2, RFC 3596, RFC 2782,
/// RFC 8659, RFC 6891). Non-exhaustive: unlisted values decode as `.unknown`
/// rdata.
pub const Type = enum(u16) {
    a = 1,
    ns = 2,
    cname = 5,
    soa = 6,
    ptr = 12,
    mx = 15,
    txt = 16,
    aaaa = 28,
    srv = 33,
    opt = 41,
    caa = 257,
    _,
};

/// Record class (RFC 1035 §3.2.4). Effectively always `.in`; non-exhaustive
/// because the OPT pseudo-record overloads the field with a UDP payload size.
pub const Class = enum(u16) {
    in = 1,
    ch = 3,
    hs = 4,
    any = 255,
    _,
};

pub const Opcode = enum(u4) {
    query = 0,
    iquery = 1,
    status = 2,
    _,
};

/// Response code, EDNS(0)-extended to 12 bits (header 4 bits + OPT high 8;
/// see `Message.rcode`).
pub const Rcode = enum(u12) {
    no_error = 0,
    form_err = 1,
    serv_fail = 2,
    nx_domain = 3,
    not_imp = 4,
    refused = 5,
    yx_domain = 6,
    yx_rrset = 7,
    nx_rrset = 8,
    not_auth = 9,
    not_zone = 10,
    bad_vers = 16,
    _,
};

/// Longest name in text form (no trailing dot). Equivalent to the RFC 1035
/// 255-byte wire-format cap.
pub const max_name_text_len = 253;
pub const max_label_len = 63;
pub const header_len = 12;

/// Upper bound on compression-pointer follows per name. Strictly-backwards
/// pointers already guarantee termination; this is defense in depth
/// (miekg/dns caps at 10; real answers use 1–3).
pub const max_pointer_jumps = 16;

/// Wire size that always fits any `encodeQuery` output:
/// header + name + type/class + OPT record.
pub const max_query_len = header_len + (max_name_text_len + 2) + 4 + 11;

// ── message model ───────────────────────────────────────────────────────────

pub const Header = struct {
    id: u16 = 0,
    /// QR bit — true for responses.
    response: bool = false,
    opcode: Opcode = .query,
    authoritative: bool = false,
    truncated: bool = false,
    recursion_desired: bool = false,
    recursion_available: bool = false,
    /// The raw 4-bit header RCODE. Use `Message.rcode` for the
    /// EDNS(0)-extended value.
    rcode: u4 = 0,
};

pub const Question = struct {
    name: []const u8,
    ty: Type,
    class: Class,
};

pub const Record = struct {
    name: []const u8,
    ty: Type,
    class: Class,
    ttl: u32,
    data: Data,

    pub const Data = union(enum) {
        a: [4]u8,
        aaaa: [16]u8,
        cname: []const u8,
        ns: []const u8,
        ptr: []const u8,
        mx: Mx,
        /// TXT character-strings, one slice per string. See `Record.txtConcat`
        /// for the joined form most consumers (SPF, verification tokens) want.
        txt: []const []const u8,
        soa: Soa,
        srv: Srv,
        caa: Caa,
        opt: Opt,
        /// Raw RDATA of any type not decoded above (`Record.ty` still tells
        /// which one it is).
        unknown: []const u8,
    };

    pub const Mx = struct {
        preference: u16,
        exchange: []const u8,
    };

    pub const Soa = struct {
        mname: []const u8,
        rname: []const u8,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    };

    /// SRV service locator (RFC 2782). The RFC forbids compressing the
    /// target on the wire, but real servers emit it anyway, so the decoder
    /// accepts pointers there (miekg/dns and Go dnsmessage do the same).
    pub const Srv = struct {
        priority: u16,
        weight: u16,
        port: u16,
        target: []const u8,
    };

    /// CAA property (RFC 8659 §4.1), e.g. `0 issue "letsencrypt.org"`.
    pub const Caa = struct {
        /// Bit 7 (0x80) is the "issuer critical" flag; the rest is reserved.
        flags: u8,
        /// Property tag, 1–15 alphanumeric chars per the RFC (e.g. "issue",
        /// "issuewild", "iodef"); the decoder only enforces non-empty.
        tag: []const u8,
        /// Property value — the rest of the RDATA, may be empty.
        value: []const u8,
    };

    /// For a TXT record: the character-strings concatenated in wire order —
    /// the form SPF/DKIM/verification-token consumers expect. Null for any
    /// other record type. Caller owns the returned bytes.
    pub fn txtConcat(r: *const Record, gpa: std.mem.Allocator) error{OutOfMemory}!?[]u8 {
        return switch (r.data) {
            .txt => |strings| try std.mem.concat(gpa, u8, strings),
            else => null,
        };
    }

    /// EDNS(0) OPT pseudo-record fields (RFC 6891 §6.1). The wire class/ttl
    /// fields are overloaded; they are decoded here and left raw in
    /// `Record.class` / `Record.ttl`.
    pub const Opt = struct {
        /// Requestor's advertised UDP payload size (the wire CLASS field).
        udp_payload_size: u16,
        /// Upper 8 bits of the extended RCODE (the wire TTL's top byte).
        extended_rcode: u8,
        version: u8,
        dnssec_ok: bool,
        /// Raw EDNS options ({code, len, data} stream), undecoded.
        options: []const u8,
    };
};

/// A decoded DNS message. All slices (names, rdata) live in an arena owned by
/// the message — one `deinit` frees everything.
pub const Message = struct {
    arena: *std.heap.ArenaAllocator,
    header: Header,
    questions: []const Question,
    answers: []const Record,
    authorities: []const Record,
    additionals: []const Record,

    pub fn deinit(m: *Message) void {
        const arena = m.arena;
        const child = arena.child_allocator;
        arena.deinit();
        child.destroy(arena);
        m.* = undefined;
    }

    /// The EDNS(0)-extended response code: header RCODE (low 4 bits) merged
    /// with the OPT record's extended-RCODE byte when present (RFC 6891 §6.1.3).
    pub fn rcode(m: *const Message) Rcode {
        var v: u12 = m.header.rcode;
        for (m.additionals) |r| {
            if (r.data == .opt) v |= @as(u12, r.data.opt.extended_rcode) << 4;
        }
        return @enumFromInt(v);
    }
};

// ── encoding ────────────────────────────────────────────────────────────────

pub const EncodeError = error{
    /// Name exceeds 253 text chars / 255 wire bytes.
    NameTooLong,
    /// Empty label (`a..b`) or label longer than 63 bytes.
    BadName,
    BufferTooSmall,
};

pub const QueryOptions = struct {
    id: u16 = 0,
    recursion_desired: bool = true,
    /// EDNS(0) advertised UDP payload size (adds an OPT record to the
    /// additional section); null = plain RFC 1035 query, 512-byte limit.
    /// Default 1232 follows the DNS-flag-day-2020 recommendation.
    edns_udp_size: ?u16 = 1232,
};

/// Encode a single-question query for `name`/`ty` (class IN) into `buf` and
/// return the written slice. A `buf` of `max_query_len` bytes always fits.
/// `name` is dotted text; one trailing dot is allowed and ignored.
pub fn encodeQuery(buf: []u8, name: []const u8, ty: Type, options: QueryOptions) EncodeError![]u8 {
    var w: std.Io.Writer = .fixed(buf);
    writeQuery(&w, name, ty, options) catch |err| switch (err) {
        error.WriteFailed => return error.BufferTooSmall,
        else => |e| return e,
    };
    return w.buffered();
}

fn writeQuery(
    w: *std.Io.Writer,
    name: []const u8,
    ty: Type,
    options: QueryOptions,
) (EncodeError || error{WriteFailed})!void {
    var flags: u16 = 0;
    if (options.recursion_desired) flags |= 0x0100;
    try w.writeInt(u16, options.id, .big);
    try w.writeInt(u16, flags, .big);
    try w.writeInt(u16, 1, .big); // QDCOUNT
    try w.writeInt(u16, 0, .big); // ANCOUNT
    try w.writeInt(u16, 0, .big); // NSCOUNT
    try w.writeInt(u16, @intFromBool(options.edns_udp_size != null), .big); // ARCOUNT
    try writeName(w, name);
    try w.writeInt(u16, @intFromEnum(ty), .big);
    try w.writeInt(u16, @intFromEnum(Class.in), .big);
    if (options.edns_udp_size) |size| {
        try w.writeByte(0); // root name
        try w.writeInt(u16, @intFromEnum(Type.opt), .big);
        try w.writeInt(u16, size, .big); // class = payload size
        try w.writeInt(u32, 0, .big); // ttl = extended RCODE + flags
        try w.writeInt(u16, 0, .big); // RDLENGTH
    }
}

/// Write `name` (dotted text, optional single trailing dot, "" or "." = root)
/// in wire format: length-prefixed labels, zero-terminated. Never compresses.
pub fn writeName(w: *std.Io.Writer, name: []const u8) (EncodeError || error{WriteFailed})!void {
    var n = name;
    if (std.mem.endsWith(u8, n, ".")) n = n[0 .. n.len - 1];
    if (n.len > max_name_text_len) return error.NameTooLong;
    if (n.len != 0) {
        var it = std.mem.splitScalar(u8, n, '.');
        while (it.next()) |label| {
            if (label.len == 0 or label.len > max_label_len) return error.BadName;
            try w.writeByte(@intCast(label.len));
            try w.writeAll(label);
        }
    }
    try w.writeByte(0);
}

// ── decoding ────────────────────────────────────────────────────────────────

pub const DecodeError = error{
    /// Packet ends before the structure it announces.
    Truncated,
    /// Compression pointer out of range or not pointing strictly backwards.
    BadPointer,
    /// More than `max_pointer_jumps` pointer follows in one name.
    PointerLoop,
    /// Reserved label type (0b01/0b10 top bits).
    BadLabel,
    NameTooLong,
    /// RDATA inconsistent with its type/length (e.g. an A record whose
    /// RDLENGTH is not 4, or an rdata name running past RDLENGTH).
    BadRecord,
    OutOfMemory,
};

/// Decode a whole DNS message (typically a response). The returned `Message`
/// owns all of its slices; free with `Message.deinit`. Never panics on
/// malformed input.
pub fn decode(gpa: std.mem.Allocator, bytes: []const u8) DecodeError!Message {
    const arena_ptr = try gpa.create(std.heap.ArenaAllocator);
    errdefer gpa.destroy(arena_ptr);
    arena_ptr.* = std.heap.ArenaAllocator.init(gpa);
    errdefer arena_ptr.deinit();
    const arena = arena_ptr.allocator();

    var d: Decoder = .{ .bytes = bytes };
    const id = try d.takeInt(u16);
    const flags = try d.takeInt(u16);
    const qdcount = try d.takeInt(u16);
    const ancount = try d.takeInt(u16);
    const nscount = try d.takeInt(u16);
    const arcount = try d.takeInt(u16);

    const header: Header = .{
        .id = id,
        .response = flags & 0x8000 != 0,
        .opcode = @enumFromInt(@as(u4, @truncate(flags >> 11))),
        .authoritative = flags & 0x0400 != 0,
        .truncated = flags & 0x0200 != 0,
        .recursion_desired = flags & 0x0100 != 0,
        .recursion_available = flags & 0x0080 != 0,
        .rcode = @truncate(flags),
    };

    const questions = try takeQuestions(&d, arena, qdcount);
    const answers = try takeRecords(&d, arena, ancount);
    const authorities = try takeRecords(&d, arena, nscount);
    const additionals = try takeRecords(&d, arena, arcount);

    return .{
        .arena = arena_ptr,
        .header = header,
        .questions = questions,
        .answers = answers,
        .authorities = authorities,
        .additionals = additionals,
    };
}

const Decoder = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn takeInt(d: *Decoder, comptime T: type) DecodeError!T {
        const n = @sizeOf(T);
        if (d.bytes.len - d.pos < n) return error.Truncated;
        const v = std.mem.readInt(T, d.bytes[d.pos..][0..n], .big);
        d.pos += n;
        return v;
    }

    fn takeName(d: *Decoder, arena: std.mem.Allocator) DecodeError![]const u8 {
        var buf: [max_name_text_len]u8 = undefined;
        const res = try readNameText(d.bytes, d.pos, &buf);
        d.pos = res.next_pos;
        return arena.dupe(u8, buf[0..res.text_len]);
    }
};

const NameResult = struct {
    /// Length of the decoded text placed in the output buffer.
    text_len: usize,
    /// Position right after the name's in-place bytes (after the first
    /// pointer when compressed).
    next_pos: usize,
};

/// Decode one (possibly compressed) name starting at `bytes[start]` into
/// `out` as dotted text. Bounded: pointers must aim strictly backwards, the
/// text is capped at 253 chars and pointer follows at `max_pointer_jumps`.
fn readNameText(bytes: []const u8, start: usize, out: *[max_name_text_len]u8) DecodeError!NameResult {
    var pos = start;
    var resume_pos: ?usize = null;
    var out_len: usize = 0;
    var jumps: usize = 0;
    while (true) {
        if (pos >= bytes.len) return error.Truncated;
        const b = bytes[pos];
        switch (b & 0xc0) {
            0x00 => {
                if (b == 0) {
                    pos += 1;
                    break;
                }
                const len: usize = b;
                if (bytes.len - pos - 1 < len) return error.Truncated;
                const label = bytes[pos + 1 ..][0..len];
                const sep: usize = @intFromBool(out_len != 0);
                if (out_len + sep + label.len > max_name_text_len) return error.NameTooLong;
                if (sep != 0) {
                    out[out_len] = '.';
                    out_len += 1;
                }
                @memcpy(out[out_len..][0..label.len], label);
                out_len += label.len;
                pos += 1 + len;
            },
            0xc0 => {
                if (bytes.len - pos < 2) return error.Truncated;
                const target = (@as(usize, b & 0x3f) << 8) | bytes[pos + 1];
                if (resume_pos == null) resume_pos = pos + 2;
                // RFC 1035 §4.1.4: a pointer references a PRIOR occurrence.
                // Enforcing it (like Go dnsmessage) rules out forward jumps
                // and, with the caps above, makes loops impossible.
                if (target >= pos) return error.BadPointer;
                jumps += 1;
                if (jumps > max_pointer_jumps) return error.PointerLoop;
                pos = target;
            },
            else => return error.BadLabel, // 0b01/0b10: reserved label types
        }
    }
    return .{ .text_len = out_len, .next_pos = resume_pos orelse pos };
}

/// Smallest possible wire encodings, used to sanity-check section counts
/// before allocating (an adversarial header cannot force a large allocation).
const min_question_wire = 5; // root name + type + class
const min_record_wire = 11; // root name + type + class + ttl + rdlength

fn takeQuestions(d: *Decoder, arena: std.mem.Allocator, count: u16) DecodeError![]Question {
    if (@as(usize, count) * min_question_wire > d.bytes.len - d.pos) return error.Truncated;
    const questions = try arena.alloc(Question, count);
    for (questions) |*q| {
        const name = try d.takeName(arena);
        const ty: Type = @enumFromInt(try d.takeInt(u16));
        const class: Class = @enumFromInt(try d.takeInt(u16));
        q.* = .{ .name = name, .ty = ty, .class = class };
    }
    return questions;
}

fn takeRecords(d: *Decoder, arena: std.mem.Allocator, count: u16) DecodeError![]Record {
    if (@as(usize, count) * min_record_wire > d.bytes.len - d.pos) return error.Truncated;
    const records = try arena.alloc(Record, count);
    for (records) |*r| r.* = try takeRecord(d, arena);
    return records;
}

fn takeRecord(d: *Decoder, arena: std.mem.Allocator) DecodeError!Record {
    const name = try d.takeName(arena);
    const ty: Type = @enumFromInt(try d.takeInt(u16));
    const class_raw = try d.takeInt(u16);
    const ttl = try d.takeInt(u32);
    const rdlength = try d.takeInt(u16);
    if (d.bytes.len - d.pos < rdlength) return error.Truncated;
    const rdata_start = d.pos;
    const rdata_end = rdata_start + rdlength;

    const data: Record.Data = switch (ty) {
        .a => blk: {
            if (rdlength != 4) return error.BadRecord;
            break :blk .{ .a = d.bytes[rdata_start..][0..4].* };
        },
        .aaaa => blk: {
            if (rdlength != 16) return error.BadRecord;
            break :blk .{ .aaaa = d.bytes[rdata_start..][0..16].* };
        },
        .cname, .ns, .ptr => blk: {
            const rname = try takeRdataName(d, arena, rdata_end);
            break :blk switch (ty) {
                .cname => .{ .cname = rname },
                .ns => .{ .ns = rname },
                .ptr => .{ .ptr = rname },
                else => unreachable,
            };
        },
        .mx => blk: {
            const preference = try d.takeInt(u16);
            const exchange = try takeRdataName(d, arena, rdata_end);
            break :blk .{ .mx = .{ .preference = preference, .exchange = exchange } };
        },
        .txt => blk: {
            var strings: std.ArrayList([]const u8) = .empty;
            var p = rdata_start;
            while (p < rdata_end) {
                const len: usize = d.bytes[p];
                p += 1;
                if (rdata_end - p < len) return error.BadRecord;
                try strings.append(arena, try arena.dupe(u8, d.bytes[p..][0..len]));
                p += len;
            }
            break :blk .{ .txt = try strings.toOwnedSlice(arena) };
        },
        .soa => blk: {
            const mname = try takeRdataName(d, arena, rdata_end);
            const rname = try takeRdataName(d, arena, rdata_end);
            break :blk .{ .soa = .{
                .mname = mname,
                .rname = rname,
                .serial = try d.takeInt(u32),
                .refresh = try d.takeInt(u32),
                .retry = try d.takeInt(u32),
                .expire = try d.takeInt(u32),
                .minimum = try d.takeInt(u32),
            } };
        },
        .srv => .{ .srv = .{
            .priority = try d.takeInt(u16),
            .weight = try d.takeInt(u16),
            .port = try d.takeInt(u16),
            .target = try takeRdataName(d, arena, rdata_end),
        } },
        .caa => blk: {
            // flags (1) + tag length (1); tag must be non-empty and fit,
            // value is whatever RDATA remains (may be empty).
            if (rdlength < 2) return error.BadRecord;
            const tag_len: usize = d.bytes[rdata_start + 1];
            if (tag_len == 0 or tag_len > rdlength - 2) return error.BadRecord;
            const tag_start = rdata_start + 2;
            break :blk .{ .caa = .{
                .flags = d.bytes[rdata_start],
                .tag = try arena.dupe(u8, d.bytes[tag_start..][0..tag_len]),
                .value = try arena.dupe(u8, d.bytes[tag_start + tag_len .. rdata_end]),
            } };
        },
        .opt => .{ .opt = .{
            .udp_payload_size = class_raw,
            .extended_rcode = @truncate(ttl >> 24),
            .version = @truncate(ttl >> 16),
            .dnssec_ok = ttl & 0x8000 != 0,
            .options = try arena.dupe(u8, d.bytes[rdata_start..rdata_end]),
        } },
        else => .{ .unknown = try arena.dupe(u8, d.bytes[rdata_start..rdata_end]) },
    };
    if (d.pos > rdata_end) return error.BadRecord; // rdata fields overran RDLENGTH
    d.pos = rdata_end;

    return .{
        .name = name,
        .ty = ty,
        .class = @enumFromInt(class_raw),
        .ttl = ttl,
        .data = data,
    };
}

/// Decode a name inside RDATA. Compression may point anywhere earlier in the
/// message, but the name's own bytes must not run past the RDATA window.
fn takeRdataName(d: *Decoder, arena: std.mem.Allocator, rdata_end: usize) DecodeError![]const u8 {
    var buf: [max_name_text_len]u8 = undefined;
    const res = try readNameText(d.bytes, d.pos, &buf);
    if (res.next_pos > rdata_end) return error.BadRecord;
    d.pos = res.next_pos;
    return arena.dupe(u8, buf[0..res.text_len]);
}

// ── tests: encoding ─────────────────────────────────────────────────────────

const testing = std.testing;

test "encodeQuery: golden bytes, no EDNS" {
    var buf: [max_query_len]u8 = undefined;
    const q = try encodeQuery(&buf, "example.com", .a, .{ .id = 0xabcd, .edns_udp_size = null });
    try testing.expectEqualSlices(u8, "\xab\xcd" ++ // id
        "\x01\x00" ++ // flags: RD
        "\x00\x01\x00\x00\x00\x00\x00\x00" ++ // counts: 1 question
        "\x07example\x03com\x00" ++ // QNAME
        "\x00\x01" ++ // QTYPE A
        "\x00\x01", // QCLASS IN
        q);
}

test "encodeQuery: golden bytes with EDNS(0) OPT" {
    var buf: [max_query_len]u8 = undefined;
    const q = try encodeQuery(&buf, "example.com.", .aaaa, .{ .id = 0x0102, .edns_udp_size = 1232 });
    try testing.expectEqualSlices(u8, "\x01\x02" ++
        "\x01\x00" ++
        "\x00\x01\x00\x00\x00\x00\x00\x01" ++ // ARCOUNT = 1 (OPT)
        "\x07example\x03com\x00" ++
        "\x00\x1c" ++ // QTYPE AAAA
        "\x00\x01" ++
        "\x00" ++ // OPT: root name
        "\x00\x29" ++ // type 41
        "\x04\xd0" ++ // class = udp payload 1232
        "\x00\x00\x00\x00" ++ // ttl = ext-rcode/version/flags
        "\x00\x00", // rdlength 0
        q);
}

test "encodeQuery: recursion_desired off clears the RD bit" {
    var buf: [max_query_len]u8 = undefined;
    const q = try encodeQuery(&buf, "x.y", .ptr, .{ .recursion_desired = false, .edns_udp_size = null });
    try testing.expectEqual(@as(u8, 0), q[2]);
    try testing.expectEqual(@as(u8, 0), q[3]);
}

test "encodeQuery: root name" {
    var buf: [max_query_len]u8 = undefined;
    const q = try encodeQuery(&buf, ".", .ns, .{ .id = 1, .edns_udp_size = null });
    try testing.expectEqualSlices(u8, "\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x00" ++ "\x00\x02" ++ "\x00\x01", q);
}

test "encodeQuery: name validation errors" {
    var buf: [max_query_len]u8 = undefined;
    const long_label = "a" ** 64 ++ ".com";
    try testing.expectError(error.BadName, encodeQuery(&buf, long_label, .a, .{}));
    try testing.expectError(error.BadName, encodeQuery(&buf, "a..b", .a, .{}));
    try testing.expectError(error.BadName, encodeQuery(&buf, "..", .a, .{}));
    const too_long = ("abcdefg." ** 32) ++ "x"; // 257 chars
    try testing.expectError(error.NameTooLong, encodeQuery(&buf, too_long, .a, .{}));

    var tiny: [10]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encodeQuery(&tiny, "example.com", .a, .{}));
}

test "encodeQuery: 63-byte label and 253-char name are accepted" {
    var buf: [max_query_len]u8 = undefined;
    const label63 = "a" ** 63;
    _ = try encodeQuery(&buf, label63 ++ ".com", .a, .{});
    // 4×63 + 3 dots = 255 → too long; 3×63+61+3 = 253 → ok.
    const name253 = label63 ++ "." ++ label63 ++ "." ++ label63 ++ "." ++ "b" ** 61;
    comptime std.debug.assert(name253.len == 253);
    _ = try encodeQuery(&buf, name253, .a, .{});
    const name254 = label63 ++ "." ++ label63 ++ "." ++ label63 ++ "." ++ "b" ** 62;
    try testing.expectError(error.NameTooLong, encodeQuery(&buf, name254, .a, .{}));
}

// ── tests: decoding (golden packets) ────────────────────────────────────────

test "decode: response with compression pointers and a CNAME chain" {
    const resp = "\xab\xcd" ++ // id
        "\x81\x80" ++ // QR RD RA, rcode 0
        "\x00\x01\x00\x03\x00\x00\x00\x00" ++ // 1 question, 3 answers
        // question @12: example.com A IN (name is 13 bytes → ends @25)
        "\x07example\x03com\x00" ++ "\x00\x01" ++ "\x00\x01" ++
        // answer 1 @29: example.com CNAME www.example.com, ttl 300
        //   rdata @41: "\x03www" + pointer to @12
        "\xc0\x0c" ++ "\x00\x05" ++ "\x00\x01" ++ "\x00\x00\x01\x2c" ++
        "\x00\x06" ++ "\x03www\xc0\x0c" ++
        // answer 2 @47: www.example.com (pointer to @41=0x29) A 93.184.216.34
        "\xc0\x29" ++ "\x00\x01" ++ "\x00\x01" ++ "\x00\x00\x00\x3c" ++
        "\x00\x04" ++ "\x5d\xb8\xd8\x22" ++
        // answer 3 @63: www.example.com AAAA 2606:2800:220:1:248:1893:25c8:1946
        "\xc0\x29" ++ "\x00\x1c" ++ "\x00\x01" ++ "\x00\x00\x00\x3c" ++
        "\x00\x10" ++ "\x26\x06\x28\x00\x02\x20\x00\x01\x02\x48\x18\x93\x25\xc8\x19\x46";

    var msg = try decode(testing.allocator, resp);
    defer msg.deinit();

    try testing.expectEqual(@as(u16, 0xabcd), msg.header.id);
    try testing.expect(msg.header.response);
    try testing.expect(msg.header.recursion_desired);
    try testing.expect(msg.header.recursion_available);
    try testing.expect(!msg.header.authoritative);
    try testing.expect(!msg.header.truncated);
    try testing.expectEqual(Rcode.no_error, msg.rcode());

    try testing.expectEqual(@as(usize, 1), msg.questions.len);
    try testing.expectEqualStrings("example.com", msg.questions[0].name);
    try testing.expectEqual(Type.a, msg.questions[0].ty);
    try testing.expectEqual(Class.in, msg.questions[0].class);

    try testing.expectEqual(@as(usize, 3), msg.answers.len);
    const a1 = msg.answers[0];
    try testing.expectEqualStrings("example.com", a1.name);
    try testing.expectEqual(Type.cname, a1.ty);
    try testing.expectEqual(@as(u32, 300), a1.ttl);
    try testing.expectEqualStrings("www.example.com", a1.data.cname);

    const a2 = msg.answers[1];
    try testing.expectEqualStrings("www.example.com", a2.name);
    try testing.expectEqual(Type.a, a2.ty);
    try testing.expectEqual([4]u8{ 93, 184, 216, 34 }, a2.data.a);

    const a3 = msg.answers[2];
    try testing.expectEqual(Type.aaaa, a3.ty);
    try testing.expectEqual(@as(u8, 0x26), a3.data.aaaa[0]);
    try testing.expectEqual(@as(u8, 0x46), a3.data.aaaa[15]);
}

test "decode: MX/TXT/NS/unknown answers, SOA authority, OPT additional" {
    const resp = "\x00\x01" ++
        "\x84\x00" ++ // QR AA, rcode 0
        "\x00\x01\x00\x04\x00\x01\x00\x01" ++
        // question @12: test.zone MX IN (name 11 bytes → ends @23)
        "\x04test\x04zone\x00" ++ "\x00\x0f" ++ "\x00\x01" ++
        // answer 1 @27: MX 10 mail.test.zone ("\x04mail" @41, ptr → @12)
        "\xc0\x0c" ++ "\x00\x0f" ++ "\x00\x01" ++ "\x00\x00\x0e\x10" ++
        "\x00\x09" ++ "\x00\x0a\x04mail\xc0\x0c" ++
        // answer 2 @48: TXT "hello" "world"
        "\xc0\x0c" ++ "\x00\x10" ++ "\x00\x01" ++ "\x00\x00\x0e\x10" ++
        "\x00\x0c" ++ "\x05hello\x05world" ++
        // answer 3 @72: NS ns.test.zone ("\x02ns" @84, ptr → @12)
        "\xc0\x0c" ++ "\x00\x02" ++ "\x00\x01" ++ "\x00\x00\x0e\x10" ++
        "\x00\x05" ++ "\x02ns\xc0\x0c" ++
        // answer 4 @89: unknown type 99, raw rdata
        "\xc0\x0c" ++ "\x00\x63" ++ "\x00\x01" ++ "\x00\x00\x00\x05" ++
        "\x00\x02" ++ "\xde\xad" ++
        // authority @103: SOA (mname = ptr → @84 "ns.test.zone")
        "\xc0\x0c" ++ "\x00\x06" ++ "\x00\x01" ++ "\x00\x00\x0e\x10" ++
        "\x00\x1e" ++ "\xc0\x54" ++ "\x05admin\xc0\x0c" ++
        "\x00\x00\x00\x01" ++ // serial 1
        "\x00\x00\x1c\x20" ++ // refresh 7200
        "\x00\x00\x0e\x10" ++ // retry 3600
        "\x00\x12\x75\x00" ++ // expire 1209600
        "\x00\x00\x01\x2c" ++ // minimum 300
        // additional @145: OPT, payload 1232, extended rcode 1, DO set
        "\x00" ++ "\x00\x29" ++ "\x04\xd0" ++ "\x01\x00\x80\x00" ++ "\x00\x00";

    var msg = try decode(testing.allocator, resp);
    defer msg.deinit();

    try testing.expect(msg.header.authoritative);
    try testing.expectEqual(@as(usize, 4), msg.answers.len);

    const mx = msg.answers[0].data.mx;
    try testing.expectEqual(@as(u16, 10), mx.preference);
    try testing.expectEqualStrings("mail.test.zone", mx.exchange);

    const txt = msg.answers[1].data.txt;
    try testing.expectEqual(@as(usize, 2), txt.len);
    try testing.expectEqualStrings("hello", txt[0]);
    try testing.expectEqualStrings("world", txt[1]);

    try testing.expectEqualStrings("ns.test.zone", msg.answers[2].data.ns);

    try testing.expectEqual(@as(u16, 99), @intFromEnum(msg.answers[3].ty));
    try testing.expectEqualSlices(u8, "\xde\xad", msg.answers[3].data.unknown);

    try testing.expectEqual(@as(usize, 1), msg.authorities.len);
    const soa = msg.authorities[0].data.soa;
    try testing.expectEqualStrings("ns.test.zone", soa.mname);
    try testing.expectEqualStrings("admin.test.zone", soa.rname);
    try testing.expectEqual(@as(u32, 1), soa.serial);
    try testing.expectEqual(@as(u32, 7200), soa.refresh);
    try testing.expectEqual(@as(u32, 3600), soa.retry);
    try testing.expectEqual(@as(u32, 1209600), soa.expire);
    try testing.expectEqual(@as(u32, 300), soa.minimum);

    try testing.expectEqual(@as(usize, 1), msg.additionals.len);
    const opt = msg.additionals[0].data.opt;
    try testing.expectEqual(@as(u16, 1232), opt.udp_payload_size);
    try testing.expectEqual(@as(u8, 1), opt.extended_rcode);
    try testing.expectEqual(@as(u8, 0), opt.version);
    try testing.expect(opt.dnssec_ok);
    // Extended rcode = (1 << 4) | 0 = 16 = BADVERS.
    try testing.expectEqual(Rcode.bad_vers, msg.rcode());
}

test "decode: PTR response (seed shape)" {
    const resp = "\xbe\xef" ++ "\x81\x80" ++ "\x00\x01\x00\x01\x00\x00\x00\x00" ++
        "\x018\x018\x018\x018\x07in-addr\x04arpa\x00" ++ "\x00\x0c" ++ "\x00\x01" ++
        "\xc0\x0c" ++ "\x00\x0c" ++ "\x00\x01" ++ "\x00\x00\x00\x3c" ++
        "\x00\x0c" ++ "\x03dns\x06google\x00";
    var msg = try decode(testing.allocator, resp);
    defer msg.deinit();
    try testing.expectEqualStrings("8.8.8.8.in-addr.arpa", msg.questions[0].name);
    try testing.expectEqualStrings("dns.google", msg.answers[0].data.ptr);
}

test "decode: SRV answer with a compressed target (RFC 2782 _sip._tcp shape)" {
    const resp = "\x00\x03" ++ "\x81\x80" ++ "\x00\x01\x00\x01\x00\x00\x00\x00" ++
        // question @12: _sip._tcp.example.com SRV IN ("example.com" @22 = 0x16)
        "\x04_sip\x04_tcp\x07example\x03com\x00" ++ "\x00\x21" ++ "\x00\x01" ++
        // answer @39: SRV 10 60 5060 sipserver.example.com, ttl 300
        "\xc0\x0c" ++ "\x00\x21" ++ "\x00\x01" ++ "\x00\x00\x01\x2c" ++
        "\x00\x12" ++ "\x00\x0a\x00\x3c\x13\xc4" ++ "\x09sipserver\xc0\x16";

    var msg = try decode(testing.allocator, resp);
    defer msg.deinit();

    try testing.expectEqualStrings("_sip._tcp.example.com", msg.questions[0].name);
    try testing.expectEqual(Type.srv, msg.questions[0].ty);
    try testing.expectEqual(@as(usize, 1), msg.answers.len);
    try testing.expectEqual(Type.srv, msg.answers[0].ty);
    const srv = msg.answers[0].data.srv;
    try testing.expectEqual(@as(u16, 10), srv.priority);
    try testing.expectEqual(@as(u16, 60), srv.weight);
    try testing.expectEqual(@as(u16, 5060), srv.port);
    try testing.expectEqualStrings("sipserver.example.com", srv.target);
}

test "decode: CAA answers (RFC 8659), including an empty value" {
    const resp = "\x00\x04" ++ "\x81\x80" ++ "\x00\x01\x00\x02\x00\x00\x00\x00" ++
        // question @12: example.com CAA IN
        "\x07example\x03com\x00" ++ "\x01\x01" ++ "\x00\x01" ++
        // answer 1 @29: CAA 0 issue "letsencrypt.org", ttl 3600
        "\xc0\x0c" ++ "\x01\x01" ++ "\x00\x01" ++ "\x00\x00\x0e\x10" ++
        "\x00\x16" ++ "\x00" ++ "\x05issue" ++ "letsencrypt.org" ++
        // answer 2: CAA with critical flag, tag iodef, empty value
        "\xc0\x0c" ++ "\x01\x01" ++ "\x00\x01" ++ "\x00\x00\x0e\x10" ++
        "\x00\x07" ++ "\x80" ++ "\x05iodef";

    var msg = try decode(testing.allocator, resp);
    defer msg.deinit();

    try testing.expectEqual(Type.caa, msg.questions[0].ty);
    try testing.expectEqual(@as(usize, 2), msg.answers.len);
    const c1 = msg.answers[0].data.caa;
    try testing.expectEqual(@as(u8, 0), c1.flags);
    try testing.expectEqualStrings("issue", c1.tag);
    try testing.expectEqualStrings("letsencrypt.org", c1.value);
    const c2 = msg.answers[1].data.caa;
    try testing.expectEqual(@as(u8, 0x80), c2.flags);
    try testing.expectEqualStrings("iodef", c2.tag);
    try testing.expectEqualStrings("", c2.value);
}

test "decode: TXT with zero character-strings decodes as an empty set" {
    const resp = "\x00\x05" ++ "\x81\x80" ++ "\x00\x01\x00\x01\x00\x00\x00\x00" ++
        "\x01a\x00" ++ "\x00\x10" ++ "\x00\x01" ++
        "\xc0\x0c" ++ "\x00\x10" ++ "\x00\x01" ++ "\x00\x00\x00\x3c" ++ "\x00\x00";
    var msg = try decode(testing.allocator, resp);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 0), msg.answers[0].data.txt.len);
}

test "Record.txtConcat joins TXT strings; null for other types" {
    const txt: Record = .{
        .name = "x",
        .ty = .txt,
        .class = .in,
        .ttl = 0,
        .data = .{ .txt = &.{ "hello", "world" } },
    };
    const joined = (try txt.txtConcat(testing.allocator)).?;
    defer testing.allocator.free(joined);
    try testing.expectEqualStrings("helloworld", joined);

    const empty: Record = .{
        .name = "x",
        .ty = .txt,
        .class = .in,
        .ttl = 0,
        .data = .{ .txt = &.{} },
    };
    const none = (try empty.txtConcat(testing.allocator)).?;
    defer testing.allocator.free(none);
    try testing.expectEqualStrings("", none);

    const a: Record = .{
        .name = "x",
        .ty = .a,
        .class = .in,
        .ttl = 0,
        .data = .{ .a = .{ 192, 0, 2, 1 } },
    };
    try testing.expectEqual(@as(?[]u8, null), try a.txtConcat(testing.allocator));
}

test "decode: NXDOMAIN rcode surfaces" {
    const resp = "\x00\x02" ++ "\x81\x83" ++ // rcode 3
        "\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x04nope\x07invalid\x00" ++ "\x00\x01" ++ "\x00\x01";
    var msg = try decode(testing.allocator, resp);
    defer msg.deinit();
    try testing.expectEqual(Rcode.nx_domain, msg.rcode());
    try testing.expectEqual(@as(usize, 0), msg.answers.len);
}

test "decode: round-trips an encoded query" {
    var buf: [max_query_len]u8 = undefined;
    const q = try encodeQuery(&buf, "example.com", .aaaa, .{ .id = 0x1234 });
    var msg = try decode(testing.allocator, q);
    defer msg.deinit();
    try testing.expectEqual(@as(u16, 0x1234), msg.header.id);
    try testing.expect(!msg.header.response);
    try testing.expect(msg.header.recursion_desired);
    try testing.expectEqualStrings("example.com", msg.questions[0].name);
    try testing.expectEqual(Type.aaaa, msg.questions[0].ty);
    try testing.expectEqual(@as(usize, 1), msg.additionals.len);
    try testing.expectEqual(@as(u16, 1232), msg.additionals[0].data.opt.udp_payload_size);
}

// ── tests: adversarial input ────────────────────────────────────────────────

fn expectDecodeError(expected: DecodeError, bytes: []const u8) !void {
    if (decode(testing.allocator, bytes)) |msg| {
        var m = msg;
        m.deinit();
        return error.TestUnexpectedResult;
    } else |err| {
        try testing.expectEqual(expected, err);
    }
}

test "decode: every truncation of a valid response errors, never panics" {
    const resp = "\xab\xcd" ++ "\x81\x80" ++ "\x00\x01\x00\x01\x00\x00\x00\x00" ++
        "\x07example\x03com\x00" ++ "\x00\x01" ++ "\x00\x01" ++
        "\xc0\x0c" ++ "\x00\x01" ++ "\x00\x01" ++ "\x00\x00\x00\x3c" ++
        "\x00\x04" ++ "\x01\x02\x03\x04";
    var n: usize = 0;
    while (n < resp.len) : (n += 1) {
        if (decode(testing.allocator, resp[0..n])) |msg| {
            var m = msg;
            m.deinit();
            return error.TestUnexpectedResult;
        } else |_| {} // any DecodeError is acceptable; panics/hangs are not
    }
}

test "decode: pointer to itself is rejected" {
    // Question name at offset 12 is a pointer to offset 12.
    const p = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\xc0\x0c" ++ "\x00\x01\x00\x01";
    try expectDecodeError(error.BadPointer, p);
}

test "decode: forward pointer is rejected" {
    const p = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\xc0\x20" ++ "\x00\x01\x00\x01";
    try expectDecodeError(error.BadPointer, p);
}

test "decode: label/pointer cycle terminates with an error" {
    // Offset 12: label "a", then a pointer back to offset 12. Each jump is
    // "strictly backwards" in isolation yet the walk cycles — an infinite
    // loop for a naive decoder; the jump budget stops it (the 253-char name
    // cap would too, a little later).
    const p = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x01a\xc0\x0c" ++ "\x00\x01\x00\x01";
    try expectDecodeError(error.PointerLoop, p);
}

test "decode: reserved label types are rejected" {
    const p40 = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\x41a\x00" ++ "\x00\x01\x00\x01";
    try expectDecodeError(error.BadLabel, p40);
    const p80 = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\x81a\x00" ++ "\x00\x01\x00\x01";
    try expectDecodeError(error.BadLabel, p80);
}

test "decode: adversarial counts cannot force large allocations" {
    // Claims 65535 answers in a 17-byte packet → Truncated before any alloc.
    const p = "\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00" ++ "\x01a\x00\x00\x01";
    try expectDecodeError(error.Truncated, p);
}

test "decode: bad rdata lengths are rejected" {
    const head = "\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00";
    // A record with RDLENGTH 3.
    try expectDecodeError(error.BadRecord, head ++ "\x01a\x00" ++ "\x00\x01\x00\x01" ++
        "\x00\x00\x00\x00" ++ "\x00\x03" ++ "\x01\x02\x03");
    // AAAA with RDLENGTH 4.
    try expectDecodeError(error.BadRecord, head ++ "\x01a\x00" ++ "\x00\x1c\x00\x01" ++
        "\x00\x00\x00\x00" ++ "\x00\x04" ++ "\x01\x02\x03\x04");
    // RDLENGTH runs past the packet end.
    try expectDecodeError(error.Truncated, head ++ "\x01a\x00" ++ "\x00\x10\x00\x01" ++
        "\x00\x00\x00\x00" ++ "\x00\xff" ++ "\x05hello");
    // TXT character-string longer than RDATA.
    try expectDecodeError(error.BadRecord, head ++ "\x01a\x00" ++ "\x00\x10\x00\x01" ++
        "\x00\x00\x00\x00" ++ "\x00\x03" ++ "\x09ab");
    // CNAME whose name bytes run past RDLENGTH.
    try expectDecodeError(error.BadRecord, head ++ "\x01a\x00" ++ "\x00\x05\x00\x01" ++
        "\x00\x00\x00\x00" ++ "\x00\x02" ++ "\x03www\x00");
    // SRV RDLENGTH shorter than the fixed fields, packet continuing after.
    try expectDecodeError(error.BadRecord, head ++ "\x01a\x00" ++ "\x00\x21\x00\x01" ++
        "\x00\x00\x00\x00" ++ "\x00\x04" ++ "\x00\x0a\x00\x3c" ++ "\x13\xc4\x00");
    // SRV RDLENGTH shorter than the fixed fields at the packet end.
    try expectDecodeError(error.Truncated, head ++ "\x01a\x00" ++ "\x00\x21\x00\x01" ++
        "\x00\x00\x00\x00" ++ "\x00\x04" ++ "\x00\x0a\x00\x3c");
    // SRV target with a pointer past the packet end.
    try expectDecodeError(error.BadPointer, head ++ "\x01a\x00" ++ "\x00\x21\x00\x01" ++
        "\x00\x00\x00\x00" ++ "\x00\x08" ++ "\x00\x0a\x00\x3c\x13\xc4" ++ "\xc0\xff");
    // CAA RDATA shorter than flags + tag length.
    try expectDecodeError(error.BadRecord, head ++ "\x01a\x00" ++ "\x01\x01\x00\x01" ++
        "\x00\x00\x00\x00" ++ "\x00\x01" ++ "\x00");
    // CAA tag length overruns RDLENGTH.
    try expectDecodeError(error.BadRecord, head ++ "\x01a\x00" ++ "\x01\x01\x00\x01" ++
        "\x00\x00\x00\x00" ++ "\x00\x04" ++ "\x00\x09ab");
    // CAA with an empty tag (RFC 8659 requires 1+ chars).
    try expectDecodeError(error.BadRecord, head ++ "\x01a\x00" ++ "\x01\x01\x00\x01" ++
        "\x00\x00\x00\x00" ++ "\x00\x03" ++ "\x00\x00x");
}

test "decode: empty and header-only packets" {
    try expectDecodeError(error.Truncated, "");
    try expectDecodeError(error.Truncated, "\x00\x01\x80");
    // A bare header with zero counts is a valid (empty) message.
    var msg = try decode(testing.allocator, "\x00\x01\x80\x00" ++ "\x00\x00" ** 4);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 0), msg.questions.len);
}

test "fuzz: decoder never crashes or leaks on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var packet: [512]u8 = undefined;
    smith.bytes(&packet);
    const len: usize = smith.valueRangeAtMost(u16, 0, packet.len);
    if (decode(testing.allocator, packet[0..len])) |msg| {
        var m = msg;
        m.deinit();
    } else |_| {}
}
