// SPDX-License-Identifier: MIT

//! DHCPv6 (RFC 8415) message + options codec: the IPv6 counterpart of `dhcp`.
//!
//! - `Message.parse` — the client/server header (type + 24-bit transaction id)
//!   or the relay header (type, hop count, link and peer address), and the
//!   framing of every option behind it, checked once. Everything is a slice
//!   into the caller's buffer — no allocation.
//! - Typed accessors for the options a client, a relay or a rogue-server
//!   check reads: DUIDs (client/server id), elapsed time, preference, rapid
//!   commit, status code, IA_NA / IA_TA / IA_PD with their IA Address and IA
//!   Prefix sub-options, option request, DNS servers (23), SNTP servers
//!   (31), domain list (24), Relay Message (9, with an iterative `unwrap`).
//!   An absent option is `null`; an option of an impossible length is an
//!   error, never a guess.
//! - `Builder` — a message or relay header and options into a caller buffer,
//!   with `begin`/`end` for the options that nest (IA_NA/IA_PD, Relay Message).
//!
//! Every other option passes through `OptionIterator` / `Message.option`
//! raw. No sockets, no state machine, no retransmission timers.
//!
//! Provenance: clean-room from RFC 8415 (message and option formats; it
//! obsoletes RFC 3315 and RFC 3633), RFC 3646 (DNS servers, domain list) and
//! RFC 4075 (SNTP servers). No third-party DHCPv6 source was consulted.

const std = @import("std");
const testing = std.testing;
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");
const Mac = @import("mac.zig").Mac;
const fz = @import("fuzz_test.zig");

pub const ParseError = error{
    /// Shorter than the 4-byte client/server header or the 34-byte relay header.
    Truncated,
    /// An option header or its declared length overruns the buffer.
    TruncatedOption,
    /// A known option carries an impossible length or content (an odd option
    /// request list, a DUID over 128 octets, a compressed domain name, …).
    BadOptionLength,
    /// `Message.unwrap`: the Relay Message option is missing from a relay
    /// message, or a relay message is not followed by a message at all.
    BadRelay,
    /// `Message.unwrap`: more relay layers than the caller allowed.
    TooDeep,
};

pub const BuildError = error{
    BufferTooSmall,
    /// Option data longer than 65535 octets.
    OptionTooLong,
    /// `Builder.init` given a relay type, or `initRelay` a non-relay one.
    WrongKind,
    /// A name that cannot be encoded: an empty label, a label over 63 octets,
    /// a name over 254 characters.
    BadName,
    /// `Builder.end` given a mark that does not name an option this builder
    /// opened and has not closed.
    BadMark,
    /// `addClientId` / `addServerId` given something `Duid.parse` refuses.
    BadDuid,
};

pub const client_header_len = 4;
pub const relay_header_len = 34;

pub const MessageType = enum(u8) {
    solicit = 1,
    advertise = 2,
    request = 3,
    confirm = 4,
    renew = 5,
    rebind = 6,
    reply = 7,
    release = 8,
    decline = 9,
    reconfigure = 10,
    information_request = 11,
    relay_forw = 12,
    relay_repl = 13,
    _,
};

/// The option codes this module reads or writes (IANA "DHCPv6 Option Codes").
pub const OptionCode = struct {
    pub const client_id: u16 = 1;
    pub const server_id: u16 = 2;
    pub const ia_na: u16 = 3;
    pub const ia_ta: u16 = 4;
    pub const ia_addr: u16 = 5;
    pub const oro: u16 = 6;
    pub const preference: u16 = 7;
    pub const elapsed_time: u16 = 8;
    pub const relay_message: u16 = 9;
    pub const unicast: u16 = 12;
    pub const status_code: u16 = 13;
    pub const rapid_commit: u16 = 14;
    pub const user_class: u16 = 15;
    pub const vendor_class: u16 = 16;
    pub const vendor_opts: u16 = 17;
    pub const interface_id: u16 = 18;
    pub const dns_servers: u16 = 23;
    pub const domain_list: u16 = 24;
    pub const ia_pd: u16 = 25;
    pub const ia_prefix: u16 = 26;
    pub const sntp_servers: u16 = 31;
    pub const information_refresh_time: u16 = 32;
    pub const client_fqdn: u16 = 39;
    pub const reconfigure_message: u16 = 19;
    pub const reconfigure_accept: u16 = 20;
    pub const pd_exclude: u16 = 67;
};

pub const StatusCode = enum(u16) {
    success = 0,
    unspec_fail = 1,
    no_addrs_avail = 2,
    no_binding = 3,
    not_on_link = 4,
    use_multicast = 5,
    no_prefix_avail = 6,
    _,
};

/// Which identity association an `IaIterator` walks.
pub const IaKind = enum(u16) {
    na = OptionCode.ia_na,
    ta = OptionCode.ia_ta,
    pd = OptionCode.ia_pd,
};

pub const DuidType = enum(u16) {
    llt = 1,
    en = 2,
    ll = 3,
    uuid = 4,
    _,
};

/// A DUID (RFC 8415 §11): the type and the rest, validated for the types it
/// knows; an unknown type passes through.
pub const Duid = struct {
    kind: DuidType,
    /// The octets after the 2-byte type.
    data: []const u8,

    pub const max_len = 128;

    /// `value` is the whole option value (type included).
    pub fn parse(value: []const u8) ParseError!Duid {
        if (value.len < 2 or value.len - 2 > max_len) return error.BadOptionLength;
        const d: Duid = .{ .kind = @fromBackingInt(std.mem.readInt(u16, value[0..2], .big)), .data = value[2..] };
        const min: usize = switch (d.kind) {
            .llt => 7, // hardware type, time, at least one octet of address
            .en => 5, // enterprise number, at least one octet of identifier
            .ll => 3, // hardware type, at least one octet of address
            .uuid => 16,
            _ => 0,
        };
        if (d.data.len < min or (d.kind == .uuid and d.data.len != 16)) return error.BadOptionLength;
        return d;
    }

    /// The IANA hardware type of an LLT or LL DUID.
    pub fn hardwareType(d: Duid) ?u16 {
        if (d.kind != .llt and d.kind != .ll) return null;
        if (d.data.len < 2) return null;
        return std.mem.readInt(u16, d.data[0..2], .big);
    }

    /// Seconds since 2000-01-01 of an LLT DUID.
    pub fn time(d: Duid) ?u32 {
        if (d.kind != .llt or d.data.len < 6) return null;
        return std.mem.readInt(u32, d.data[2..6], .big);
    }

    pub fn linkLayerAddress(d: Duid) ?[]const u8 {
        return switch (d.kind) {
            .llt => if (d.data.len >= 6) d.data[6..] else null,
            .ll => if (d.data.len >= 2) d.data[2..] else null,
            else => null,
        };
    }

    pub fn enterpriseNumber(d: Duid) ?u32 {
        if (d.kind != .en or d.data.len < 4) return null;
        return std.mem.readInt(u32, d.data[0..4], .big);
    }
};

pub const Option = struct {
    code: u16,
    data: []const u8,
};

/// A walk over any options region (the message's, an IA's, a Relay
/// Message's). After the first error the iterator is terminal: `next`
/// returns null.
pub const OptionIterator = struct {
    buf: []const u8,
    pos: usize = 0,
    failed: bool = false,

    pub fn init(region: []const u8) OptionIterator {
        return .{ .buf = region };
    }

    pub fn next(it: *OptionIterator) ParseError!?Option {
        if (it.failed) return null;
        return it.nextRaw() catch |err| {
            it.failed = true;
            return err;
        };
    }

    fn nextRaw(it: *OptionIterator) ParseError!?Option {
        if (it.pos == it.buf.len) return null;
        if (it.buf.len - it.pos < 4) return error.TruncatedOption;
        const code = std.mem.readInt(u16, it.buf[it.pos..][0..2], .big);
        const len: usize = std.mem.readInt(u16, it.buf[it.pos + 2 ..][0..2], .big);
        if (it.buf.len - it.pos - 4 < len) return error.TruncatedOption;
        const o: Option = .{ .code = code, .data = it.buf[it.pos + 4 ..][0..len] };
        it.pos += 4 + len;
        return o;
    }
};

/// The first option with `code` in `region`.
pub fn findOption(region: []const u8, code: u16) ParseError!?[]const u8 {
    var it = OptionIterator.init(region);
    while (try it.next()) |o| if (o.code == code) return o.data;
    return null;
}

/// A list of 16-octet IPv6 addresses (options 23, 31).
pub const Ip6List = struct {
    bytes: []const u8,

    pub fn count(l: Ip6List) usize {
        return l.bytes.len / 16;
    }

    pub fn at(l: Ip6List, i: usize) ?[16]u8 {
        if (i >= l.count()) return null;
        return l.bytes[i * 16 ..][0..16].*;
    }
};

/// A list of 16-bit option codes (the option request, 6).
pub const CodeList = struct {
    bytes: []const u8,

    pub fn count(l: CodeList) usize {
        return l.bytes.len / 2;
    }

    pub fn at(l: CodeList, i: usize) ?u16 {
        if (i >= l.count()) return null;
        return std.mem.readInt(u16, l.bytes[i * 2 ..][0..2], .big);
    }
};

/// A list of `{u16 length, data}` entries (the User Class and Vendor Class options).
pub const OpaqueDataIterator = struct {
    buf: []const u8,
    pos: usize = 0,
    failed: bool = false,

    pub fn next(it: *OpaqueDataIterator) ParseError!?[]const u8 {
        if (it.failed or it.pos == it.buf.len) return null;
        if (it.buf.len - it.pos < 2) {
            it.failed = true;
            return error.BadOptionLength;
        }
        const n: usize = std.mem.readInt(u16, it.buf[it.pos..][0..2], .big);
        if (it.buf.len - it.pos - 2 < n) {
            it.failed = true;
            return error.BadOptionLength;
        }
        const d = it.buf[it.pos + 2 ..][0..n];
        it.pos += 2 + n;
        return d;
    }
};

pub const Status = struct {
    code: StatusCode,
    message: []const u8,
};

fn parseStatus(value: []const u8) ParseError!Status {
    if (value.len < 2) return error.BadOptionLength;
    return .{ .code = @fromBackingInt(std.mem.readInt(u16, value[0..2], .big)), .message = value[2..] };
}

pub const Ia = struct {
    iaid: u32,
    /// Renew / rebind times in seconds; 0 for an IA_TA, which has none.
    t1: u32,
    t2: u32,
    /// The IA's own options: addresses, prefixes, a status code.
    options: []const u8,

    /// RFC 8415 §21.4 / §21.22: a client that gets T1 > T2, both non-zero,
    /// discards the IA. The fields are returned raw either way.
    pub fn timersValid(ia: Ia) bool {
        return ia.t1 == 0 or ia.t2 == 0 or ia.t1 <= ia.t2;
    }

    pub fn addresses(ia: Ia) IaAddrIterator {
        return .{ .it = OptionIterator.init(ia.options) };
    }

    pub fn prefixes(ia: Ia) IaPrefixIterator {
        return .{ .it = OptionIterator.init(ia.options) };
    }

    /// The IA-level Status Code, if present.
    pub fn statusCode(ia: Ia) ParseError!?Status {
        const v = (try findOption(ia.options, OptionCode.status_code)) orelse return null;
        return try parseStatus(v);
    }
};

pub const IaAddr = struct {
    addr: [16]u8,
    /// Seconds; 0xffffffff is infinity.
    preferred: u32,
    valid: u32,
    options: []const u8,

    /// RFC 8415 §21.6: the client MUST discard an address whose preferred
    /// lifetime exceeds its valid lifetime. The fields are returned raw either way.
    pub fn isValid(a: IaAddr) bool {
        return a.preferred <= a.valid;
    }
};

pub const IaPrefix = struct {
    preferred: u32,
    valid: u32,
    prefix_len: u8,
    prefix: [16]u8,
    options: []const u8,

    /// Prefix Exclude (RFC 6603, option 67) inside this prefix: the excluded
    /// prefix length and the subnet-id octets, or null when absent. Needs the
    /// excluded length to be longer than this prefix's.
    pub fn prefixExclude(p: IaPrefix) ParseError!?struct { len: u8, subnet_id: []const u8 } {
        const v = (try findOption(p.options, OptionCode.pd_exclude)) orelse return null;
        if (v.len < 1 or v[0] > 128 or v[0] <= p.prefix_len) return error.BadOptionLength;
        const bits: usize = v[0] - p.prefix_len;
        if (v.len != 1 + (bits + 7) / 8) return error.BadOptionLength;
        return .{ .len = v[0], .subnet_id = v[1..] };
    }

    /// RFC 8415 §21.22: the same rule for a prefix.
    pub fn isValid(p: IaPrefix) bool {
        return p.preferred <= p.valid;
    }
};

pub const IaAddrIterator = struct {
    it: OptionIterator,

    pub fn next(self: *IaAddrIterator) ParseError!?IaAddr {
        while (try self.it.next()) |o| {
            if (o.code != OptionCode.ia_addr) continue;
            if (o.data.len < 24) {
                self.it.failed = true;
                return error.BadOptionLength;
            }
            return .{
                .addr = o.data[0..16].*,
                .preferred = std.mem.readInt(u32, o.data[16..20], .big),
                .valid = std.mem.readInt(u32, o.data[20..24], .big),
                .options = o.data[24..],
            };
        }
        return null;
    }
};

pub const IaPrefixIterator = struct {
    it: OptionIterator,

    pub fn next(self: *IaPrefixIterator) ParseError!?IaPrefix {
        while (try self.it.next()) |o| {
            if (o.code != OptionCode.ia_prefix) continue;
            if (o.data.len < 25 or o.data[8] > 128) {
                self.it.failed = true;
                return error.BadOptionLength;
            }
            return .{
                .preferred = std.mem.readInt(u32, o.data[0..4], .big),
                .valid = std.mem.readInt(u32, o.data[4..8], .big),
                .prefix_len = o.data[8],
                .prefix = o.data[9..25].*,
                .options = o.data[25..],
            };
        }
        return null;
    }
};

pub const IaIterator = struct {
    it: OptionIterator,
    kind: IaKind,

    pub fn next(self: *IaIterator) ParseError!?Ia {
        const code: u16 = @backingInt(self.kind);
        const fixed: usize = if (self.kind == .ta) 4 else 12;
        while (try self.it.next()) |o| {
            if (o.code != code) continue;
            if (o.data.len < fixed) {
                self.it.failed = true;
                return error.BadOptionLength;
            }
            return .{
                .iaid = std.mem.readInt(u32, o.data[0..4], .big),
                .t1 = if (fixed == 12) std.mem.readInt(u32, o.data[4..8], .big) else 0,
                .t2 = if (fixed == 12) std.mem.readInt(u32, o.data[8..12], .big) else 0,
                .options = o.data[fixed..],
            };
        }
        return null;
    }
};

/// The Domain Search List (24, RFC 3646): uncompressed RFC 1035 names. Each
/// name is rendered dotted into the caller's buffer, without a trailing dot.
pub const DomainListIterator = struct {
    buf: []const u8,
    pos: usize = 0,
    failed: bool = false,

    /// 253 characters dotted = 255 octets on the wire with the length bytes and
    /// the root label (RFC 1035 §2.3.4).
    pub const max_name_len = 253;

    pub fn next(it: *DomainListIterator, out: *[max_name_len]u8) ParseError!?[]const u8 {
        if (it.failed) return null;
        return it.nextName(out) catch |err| {
            it.failed = true;
            return err;
        };
    }

    fn nextName(it: *DomainListIterator, out: *[max_name_len]u8) ParseError!?[]const u8 {
        if (it.pos == it.buf.len) return null;
        var n: usize = 0;
        while (true) {
            if (it.pos >= it.buf.len) return error.BadOptionLength; // no root label
            const l: usize = it.buf[it.pos];
            it.pos += 1;
            if (l == 0) break;
            if (l > 63) return error.BadOptionLength; // pointer or reserved: v6 never compresses
            if (it.buf.len - it.pos < l) return error.BadOptionLength;
            const dot: usize = @intFromBool(n != 0);
            if (n + dot + l > max_name_len) return error.BadOptionLength;
            if (dot == 1) out[n] = '.';
            @memcpy(out[n + dot ..][0..l], it.buf[it.pos..][0..l]);
            n += dot + l;
            it.pos += l;
        }
        return out[0..n];
    }
};

pub const Message = struct {
    msg_type: MessageType,
    /// Transaction id of a client/server message; 0 for a relay message.
    xid: u24 = 0,
    /// Relay messages only.
    hop_count: u8 = 0,
    link_address: [16]u8 = @splat(0),
    peer_address: [16]u8 = @splat(0),
    /// Everything behind the header; its framing was checked by `parse`.
    options_raw: []const u8,

    pub fn isRelay(m: *const Message) bool {
        return m.msg_type == .relay_forw or m.msg_type == .relay_repl;
    }

    pub fn parse(bytes: []const u8) ParseError!Message {
        if (bytes.len < 1) return error.Truncated;
        const t: MessageType = @fromBackingInt(bytes[0]);
        var m: Message = .{ .msg_type = t, .options_raw = undefined };
        if (m.isRelay()) {
            if (bytes.len < relay_header_len) return error.Truncated;
            m.hop_count = bytes[1];
            m.link_address = bytes[2..18].*;
            m.peer_address = bytes[18..34].*;
            m.options_raw = bytes[relay_header_len..];
        } else {
            if (bytes.len < client_header_len) return error.Truncated;
            m.xid = std.mem.readInt(u24, bytes[1..4], .big);
            m.options_raw = bytes[client_header_len..];
        }
        var it = OptionIterator.init(m.options_raw);
        while (try it.next()) |_| {}
        return m;
    }

    pub fn options(m: *const Message) OptionIterator {
        return OptionIterator.init(m.options_raw);
    }

    /// The first option with `code`, raw.
    pub fn option(m: *const Message, code: u16) ?[]const u8 {
        return (findOption(m.options_raw, code) catch null);
    }

    pub fn clientId(m: *const Message) ParseError!?Duid {
        const v = m.option(OptionCode.client_id) orelse return null;
        return try Duid.parse(v);
    }

    pub fn serverId(m: *const Message) ParseError!?Duid {
        const v = m.option(OptionCode.server_id) orelse return null;
        return try Duid.parse(v);
    }

    /// Hundredths of a second since the client began the exchange.
    pub fn elapsedTime(m: *const Message) ParseError!?u16 {
        const v = m.option(OptionCode.elapsed_time) orelse return null;
        if (v.len != 2) return error.BadOptionLength;
        return std.mem.readInt(u16, v[0..2], .big);
    }

    pub fn preference(m: *const Message) ParseError!?u8 {
        const v = m.option(OptionCode.preference) orelse return null;
        if (v.len != 1) return error.BadOptionLength;
        return v[0];
    }

    pub fn rapidCommit(m: *const Message) ParseError!bool {
        const v = m.option(OptionCode.rapid_commit) orelse return false;
        if (v.len != 0) return error.BadOptionLength;
        return true;
    }

    pub fn statusCode(m: *const Message) ParseError!?Status {
        const v = m.option(OptionCode.status_code) orelse return null;
        return try parseStatus(v);
    }

    /// The Option Request option's codes.
    pub fn optionRequest(m: *const Message) ParseError!?CodeList {
        const v = m.option(OptionCode.oro) orelse return null;
        if (v.len % 2 != 0) return error.BadOptionLength;
        return .{ .bytes = v };
    }

    pub fn identityAssociations(m: *const Message, kind: IaKind) IaIterator {
        return .{ .it = m.options(), .kind = kind };
    }

    pub fn dnsServers(m: *const Message) ParseError!?Ip6List {
        return m.addressList(OptionCode.dns_servers);
    }

    pub fn sntpServers(m: *const Message) ParseError!?Ip6List {
        return m.addressList(OptionCode.sntp_servers);
    }

    fn addressList(m: *const Message, code: u16) ParseError!?Ip6List {
        const v = m.option(code) orelse return null;
        if (v.len % 16 != 0) return error.BadOptionLength;
        return .{ .bytes = v };
    }

    pub fn domainList(m: *const Message) ?DomainListIterator {
        const v = m.option(OptionCode.domain_list) orelse return null;
        return .{ .buf = v };
    }

    /// Client FQDN (39, RFC 4704): the flags octet and the name, decoded from
    /// its uncompressed wire form into `out` (dotted, no trailing dot; an
    /// empty name stays empty). A partial name (flag N/S bits aside) is the caller's business.
    pub fn clientFqdn(m: *const Message, out: *[DomainListIterator.max_name_len]u8) ParseError!?struct { flags: u8, name: []const u8 } {
        const v = m.option(OptionCode.client_fqdn) orelse return null;
        if (v.len < 1) return error.BadOptionLength;
        var it: DomainListIterator = .{ .buf = v[1..] };
        const name = (try it.next(out)) orelse out[0..0];
        return .{ .flags = v[0], .name = name };
    }

    /// Vendor Class (16, RFC 8415 §21.16): enterprise number and the opaque
    /// class entries. User Class (15, §21.15) is the same list without the number.
    pub fn vendorClass(m: *const Message) ParseError!?struct { enterprise: u32, classes: OpaqueDataIterator } {
        const v = m.option(OptionCode.vendor_class) orelse return null;
        if (v.len < 4) return error.BadOptionLength;
        return .{ .enterprise = std.mem.readInt(u32, v[0..4], .big), .classes = .{ .buf = v[4..] } };
    }

    pub fn userClass(m: *const Message) ?OpaqueDataIterator {
        const v = m.option(OptionCode.user_class) orelse return null;
        return .{ .buf = v };
    }

    /// Reconfigure Message (19, RFC 8415 §21.19): the message type the client must send (5 renew, 6 rebind, 11 information-request).
    pub fn reconfigureMessage(m: *const Message) ParseError!?MessageType {
        const v = m.option(OptionCode.reconfigure_message) orelse return null;
        if (v.len != 1) return error.BadOptionLength;
        return @fromBackingInt(v[0]);
    }

    /// Reconfigure Accept (20): present or not.
    pub fn reconfigureAccept(m: *const Message) ParseError!bool {
        const v = m.option(OptionCode.reconfigure_accept) orelse return false;
        if (v.len != 0) return error.BadOptionLength;
        return true;
    }

    /// The Relay Message option's value (the message a relay carries).
    pub fn relayMessage(m: *const Message) ?[]const u8 {
        return m.option(OptionCode.relay_message);
    }

    /// Peels relay layers iteratively, outermost first, until a client/server
    /// message: at most `max_depth` layers (RFC 8415 §19.1.1: a hop count of
    /// 8 is the usual relay limit). A message that is not a relay one is
    /// returned as is. `depth` is how many layers were peeled.
    pub fn unwrap(m: Message, max_depth: u8) ParseError!struct { inner: Message, depth: u8 } {
        var cur = m;
        var depth: u8 = 0;
        while (cur.isRelay()) {
            if (depth == max_depth) return error.TooDeep;
            const v = cur.relayMessage() orelse return error.BadRelay;
            cur = try Message.parse(v);
            depth += 1;
        }
        return .{ .inner = cur, .depth = depth };
    }
};

// ── building ─────────────────────────────────────────────────────────────────

/// A DUID-LL (type 3) for an Ethernet MAC, into `out`.
pub fn duidLl(out: *[10]u8, mac: Mac) []const u8 {
    std.mem.writeInt(u16, out[0..2], 3, .big);
    std.mem.writeInt(u16, out[2..4], 1, .big);
    out[4..10].* = mac.octets;
    return out;
}

/// A DUID-LLT (type 1) for an Ethernet MAC, `seconds` since 2000-01-01.
pub fn duidLlt(out: *[14]u8, mac: Mac, seconds: u32) []const u8 {
    std.mem.writeInt(u16, out[0..2], 1, .big);
    std.mem.writeInt(u16, out[2..4], 1, .big);
    std.mem.writeInt(u32, out[4..8], seconds, .big);
    out[8..14].* = mac.octets;
    return out;
}

pub const Builder = struct {
    buf: []u8,
    len: usize,

    /// An open nested option, from `begin`.
    pub const Mark = struct { at: usize, code: u16 };

    pub fn init(buf: []u8, msg_type: MessageType, xid: u24) BuildError!Builder {
        if (msg_type == .relay_forw or msg_type == .relay_repl) return error.WrongKind;
        if (buf.len < client_header_len) return error.BufferTooSmall;
        buf[0] = @backingInt(msg_type);
        std.mem.writeInt(u24, buf[1..4], xid, .big);
        return .{ .buf = buf, .len = client_header_len };
    }

    pub fn initRelay(buf: []u8, msg_type: MessageType, hop_count: u8, link: [16]u8, peer: [16]u8) BuildError!Builder {
        if (msg_type != .relay_forw and msg_type != .relay_repl) return error.WrongKind;
        if (buf.len < relay_header_len) return error.BufferTooSmall;
        buf[0] = @backingInt(msg_type);
        buf[1] = hop_count;
        buf[2..18].* = link;
        buf[18..34].* = peer;
        return .{ .buf = buf, .len = relay_header_len };
    }

    fn room(b: *Builder, n: usize) BuildError!void {
        if (b.buf.len - b.len < n) return error.BufferTooSmall;
    }

    pub fn addOption(b: *Builder, code: u16, data: []const u8) BuildError!void {
        if (data.len > 0xffff) return error.OptionTooLong;
        try b.room(4 + data.len);
        std.mem.writeInt(u16, b.buf[b.len..][0..2], code, .big);
        std.mem.writeInt(u16, b.buf[b.len + 2 ..][0..2], @intCast(data.len), .big);
        @memcpy(b.buf[b.len + 4 ..][0..data.len], data);
        b.len += 4 + data.len;
    }

    /// Opens an option whose value the caller appends to; close it with `end`.
    /// `prefix` is the fixed part of the value (an IA's id and timers).
    pub fn begin(b: *Builder, code: u16, prefix: []const u8) BuildError!Mark {
        try b.room(4 + prefix.len);
        const at = b.len;
        std.mem.writeInt(u16, b.buf[at..][0..2], code, .big);
        std.mem.writeInt(u16, b.buf[at + 2 ..][0..2], 0, .big);
        @memcpy(b.buf[at + 4 ..][0..prefix.len], prefix);
        b.len += 4 + prefix.len;
        return .{ .at = at, .code = code };
    }

    /// Fixes the length of the option `begin` opened (and of everything added
    /// since). Marks close innermost first.
    ///
    /// A forged or stale mark is `error.BadMark`, never an overflow or a
    /// write elsewhere: the mark must lie inside the written bytes, carry the
    /// option code found there, and that option's length field must still be
    /// the 0 `begin` wrote. What this cannot prove without per-option state:
    /// a mark of an option that was opened and is still open but is not the
    /// innermost one (closing out of order gives a message with wrong
    /// lengths, memory-safely), or a forged mark that happens to land on an
    /// open option's header with the right code.
    pub fn end(b: *Builder, m: Mark) BuildError!void {
        if (m.at > b.len or b.len - m.at < 4) return error.BadMark;
        if (std.mem.readInt(u16, b.buf[m.at..][0..2], .big) != m.code) return error.BadMark;
        if (std.mem.readInt(u16, b.buf[m.at + 2 ..][0..2], .big) != 0) return error.BadMark;
        const n = b.len - m.at - 4;
        if (n > 0xffff) return error.OptionTooLong;
        std.mem.writeInt(u16, b.buf[m.at + 2 ..][0..2], @intCast(n), .big);
    }

    pub fn addClientId(b: *Builder, duid: []const u8) BuildError!void {
        _ = Duid.parse(duid) catch return error.BadDuid;
        try b.addOption(OptionCode.client_id, duid);
    }

    pub fn addServerId(b: *Builder, duid: []const u8) BuildError!void {
        _ = Duid.parse(duid) catch return error.BadDuid;
        try b.addOption(OptionCode.server_id, duid);
    }

    pub fn addElapsedTime(b: *Builder, centiseconds: u16) BuildError!void {
        var v: [2]u8 = undefined;
        std.mem.writeInt(u16, &v, centiseconds, .big);
        try b.addOption(OptionCode.elapsed_time, &v);
    }

    pub fn addPreference(b: *Builder, p: u8) BuildError!void {
        try b.addOption(OptionCode.preference, &.{p});
    }

    pub fn addRapidCommit(b: *Builder) BuildError!void {
        try b.addOption(OptionCode.rapid_commit, &.{});
    }

    pub fn addOptionRequest(b: *Builder, codes: []const u16) BuildError!void {
        if (codes.len > 0x7fff) return error.OptionTooLong;
        try b.room(4 + codes.len * 2);
        const m = try b.begin(OptionCode.oro, &.{});
        for (codes) |c| {
            std.mem.writeInt(u16, b.buf[b.len..][0..2], c, .big);
            b.len += 2;
        }
        try b.end(m);
    }

    pub fn addStatusCode(b: *Builder, code: StatusCode, message: []const u8) BuildError!void {
        if (message.len > 0xffff - 2) return error.OptionTooLong;
        try b.room(6 + message.len);
        var c: [2]u8 = undefined;
        std.mem.writeInt(u16, &c, @backingInt(code), .big);
        const m = try b.begin(OptionCode.status_code, &c);
        @memcpy(b.buf[b.len..][0..message.len], message);
        b.len += message.len;
        try b.end(m);
    }

    /// DNS recursive name servers (23) or SNTP servers (31).
    pub fn addAddressList(b: *Builder, code: u16, addrs: []const [16]u8) BuildError!void {
        if (addrs.len > 0xffff / 16) return error.OptionTooLong;
        try b.room(4 + addrs.len * 16);
        const m = try b.begin(code, &.{});
        for (addrs) |a| {
            @memcpy(b.buf[b.len..][0..16], &a);
            b.len += 16;
        }
        try b.end(m);
    }

    /// The Domain Search List (24), never compressed. A trailing dot is
    /// accepted and dropped; an empty name is refused.
    pub fn addDomainList(b: *Builder, names: []const []const u8) BuildError!void {
        const save = b.len;
        errdefer b.len = save;
        const m = try b.begin(OptionCode.domain_list, &.{});
        for (names) |full| {
            const name = if (full.len > 1 and full[full.len - 1] == '.') full[0 .. full.len - 1] else full;
            if (name.len == 0 or name.len > DomainListIterator.max_name_len) return error.BadName;
            var rest = name;
            while (true) {
                const dot = std.mem.findScalar(u8, rest, '.');
                const label = if (dot) |d| rest[0..d] else rest;
                if (label.len == 0 or label.len > 63) return error.BadName;
                try b.room(1 + label.len);
                b.buf[b.len] = @intCast(label.len);
                @memcpy(b.buf[b.len + 1 ..][0..label.len], label);
                b.len += 1 + label.len;
                rest = if (dot) |d| rest[d + 1 ..] else break;
            }
            try b.room(1);
            b.buf[b.len] = 0;
            b.len += 1;
        }
        try b.end(m);
    }

    /// Opens an IA_NA / IA_TA / IA_PD; add `addIaAddr` / `addIaPrefix` /
    /// `addStatusCode`, then `end`. `t1` and `t2` are ignored for an IA_TA.
    pub fn beginIa(b: *Builder, kind: IaKind, iaid: u32, t1: u32, t2: u32) BuildError!Mark {
        var p: [12]u8 = undefined;
        std.mem.writeInt(u32, p[0..4], iaid, .big);
        std.mem.writeInt(u32, p[4..8], t1, .big);
        std.mem.writeInt(u32, p[8..12], t2, .big);
        return b.begin(@backingInt(kind), p[0..if (kind == .ta) 4 else 12]);
    }

    pub fn addIaAddr(b: *Builder, addr: [16]u8, preferred: u32, valid: u32) BuildError!void {
        var v: [24]u8 = undefined;
        v[0..16].* = addr;
        std.mem.writeInt(u32, v[16..20], preferred, .big);
        std.mem.writeInt(u32, v[20..24], valid, .big);
        try b.addOption(OptionCode.ia_addr, &v);
    }

    pub fn addIaPrefix(b: *Builder, prefix: [16]u8, prefix_len: u8, preferred: u32, valid: u32) BuildError!void {
        var v: [25]u8 = undefined;
        std.mem.writeInt(u32, v[0..4], preferred, .big);
        std.mem.writeInt(u32, v[4..8], valid, .big);
        v[8] = prefix_len;
        v[9..25].* = prefix;
        try b.addOption(OptionCode.ia_prefix, &v);
    }

    /// The Relay Message option (9) carrying `inner`, a whole message.
    pub fn addRelayMessage(b: *Builder, inner: []const u8) BuildError!void {
        try b.addOption(OptionCode.relay_message, inner);
    }

    pub fn finish(b: *const Builder) []const u8 {
        return b.buf[0..b.len];
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn hp(comptime s: []const u8) *const [s.len / 2]u8 {
    const v = comptime hex(s);
    return &v;
}

const addr1: [16]u8 = hex("20010db8000000000000000000000001");
const addr2: [16]u8 = hex("20010db8000000000000000000000002");

/// A Reply as a server answers a Solicit: ids, an IA_NA with an address, an
/// IA_PD with a prefix, DNS, a domain list, a status, a preference.
fn buildReply(out: []u8) ![]const u8 {
    var b = try Builder.init(out, .reply, 0xabcdef);
    var cid: [10]u8 = undefined;
    try b.addClientId(duidLl(&cid, .{ .octets = hex("020000000001") }));
    var sid: [14]u8 = undefined;
    try b.addServerId(duidLlt(&sid, .{ .octets = hex("020000000002") }, 0x30d5a1b2));
    const na = try b.beginIa(.na, 1, 3600, 5400);
    try b.addIaAddr(addr1, 7200, 14400);
    try b.addStatusCode(.success, "ok");
    try b.end(na);
    const pd = try b.beginIa(.pd, 2, 1000, 2000);
    try b.addIaPrefix(hex("20010db8aaaa00000000000000000000"), 56, 3000, 6000);
    try b.end(pd);
    try b.addAddressList(OptionCode.dns_servers, &.{ addr1, addr2 });
    try b.addDomainList(&.{ "example.com", "lab.example.org." });
    try b.addPreference(255);
    try b.addElapsedTime(1234);
    try b.addRapidCommit();
    try b.addOptionRequest(&.{ 23, 24, 25 });
    return b.finish();
}

test "dhcp6: a built Reply parses back to every field" {
    var out: [512]u8 = undefined;
    const bytes = try buildReply(&out);
    const m = try Message.parse(bytes);
    try testing.expectEqual(MessageType.reply, m.msg_type);
    try testing.expectEqual(@as(u24, 0xabcdef), m.xid);
    try testing.expect(!m.isRelay());

    const c = (try m.clientId()).?;
    try testing.expectEqual(DuidType.ll, c.kind);
    try testing.expectEqual(@as(?u16, 1), c.hardwareType());
    try testing.expectEqualSlices(u8, hp("020000000001"), c.linkLayerAddress().?);
    const s = (try m.serverId()).?;
    try testing.expectEqual(DuidType.llt, s.kind);
    try testing.expectEqual(@as(?u32, 0x30d5a1b2), s.time());
    try testing.expectEqualSlices(u8, hp("020000000002"), s.linkLayerAddress().?);

    var na = m.identityAssociations(.na);
    const ia = (try na.next()).?;
    try testing.expectEqual(@as(u32, 1), ia.iaid);
    try testing.expectEqual(@as(u32, 3600), ia.t1);
    try testing.expectEqual(@as(u32, 5400), ia.t2);
    var ad = ia.addresses();
    const a = (try ad.next()).?;
    try testing.expectEqualSlices(u8, &addr1, &a.addr);
    try testing.expectEqual(@as(u32, 7200), a.preferred);
    try testing.expectEqual(@as(u32, 14400), a.valid);
    try testing.expect((try ad.next()) == null);
    try testing.expect((try na.next()) == null);
    const st = (try ia.statusCode()).?;
    try testing.expectEqual(StatusCode.success, st.code);
    try testing.expectEqualStrings("ok", st.message);

    var pd = m.identityAssociations(.pd);
    const ipd = (try pd.next()).?;
    var pf = ipd.prefixes();
    const p = (try pf.next()).?;
    try testing.expectEqual(@as(u8, 56), p.prefix_len);
    try testing.expectEqual(@as(u32, 6000), p.valid);
    var ta = m.identityAssociations(.ta);
    try testing.expect((try ta.next()) == null);

    const dns = (try m.dnsServers()).?;
    try testing.expectEqual(@as(usize, 2), dns.count());
    try testing.expectEqualSlices(u8, &addr2, &dns.at(1).?);
    try testing.expect(dns.at(2) == null);
    var dl = m.domainList().?;
    var nb: [DomainListIterator.max_name_len]u8 = undefined;
    try testing.expectEqualStrings("example.com", (try dl.next(&nb)).?);
    try testing.expectEqualStrings("lab.example.org", (try dl.next(&nb)).?);
    try testing.expect((try dl.next(&nb)) == null);

    try testing.expectEqual(@as(?u8, 255), try m.preference());
    try testing.expectEqual(@as(?u16, 1234), try m.elapsedTime());
    try testing.expect(try m.rapidCommit());
    const oro = (try m.optionRequest()).?;
    try testing.expectEqual(@as(?u16, 25), oro.at(2));
    try testing.expect((try m.statusCode()) == null);
    try testing.expect((try m.sntpServers()) == null);
}

test "dhcp6: a Solicit's exact bytes (RFC 8415 §8 header, §21.4 IA_NA)" {
    // Solicit, xid 0x123456; Client ID DUID-LL; Elapsed Time 0; IA_NA iaid 1
    // t1 = t2 = 0 (the client leaves the timers to the server); Option Request 23, 24.
    var out: [128]u8 = undefined;
    var b = try Builder.init(&out, .solicit, 0x123456);
    var cid: [10]u8 = undefined;
    try b.addClientId(duidLl(&cid, .{ .octets = hex("020000000001") }));
    try b.addElapsedTime(0);
    const ia = try b.beginIa(.na, 1, 0, 0);
    try b.end(ia);
    try b.addOptionRequest(&.{ 23, 24 });
    const exp = hex("01123456" ++ "0001000a00030001020000000001" ++ "000800020000" ++ "0003000c000000010000000000000000" ++ "0006000400170018");
    try testing.expectEqualSlices(u8, &exp, b.finish());
}

test "dhcp6: relay-forward wrapping, unwrap and its depth limit" {
    var inner_buf: [512]u8 = undefined;
    const inner = try buildReply(&inner_buf);
    var l1: [700]u8 = undefined;
    var r1 = try Builder.initRelay(&l1, .relay_forw, 0, addr1, addr2);
    try r1.addRelayMessage(inner);
    try r1.addOption(OptionCode.interface_id, "eth7");
    var l2: [800]u8 = undefined;
    var r2 = try Builder.initRelay(&l2, .relay_forw, 1, addr2, addr1);
    try r2.addRelayMessage(r1.finish());

    const m = try Message.parse(r2.finish());
    try testing.expect(m.isRelay());
    try testing.expectEqual(@as(u8, 1), m.hop_count);
    try testing.expectEqualSlices(u8, &addr2, &m.link_address);
    try testing.expectEqualSlices(u8, &addr1, &m.peer_address);
    const u = try m.unwrap(8);
    try testing.expectEqual(@as(u8, 2), u.depth);
    try testing.expectEqual(MessageType.reply, u.inner.msg_type);
    try testing.expectEqual(@as(u24, 0xabcdef), u.inner.xid);
    try testing.expectError(error.TooDeep, m.unwrap(1));
    // A non-relay message unwraps to itself.
    const plain = try Message.parse(inner);
    try testing.expectEqual(@as(u8, 0), (try plain.unwrap(0)).depth);
    // A relay message with no Relay Message option.
    var l3: [64]u8 = undefined;
    const bare = try Builder.initRelay(&l3, .relay_repl, 0, addr1, addr2);
    try testing.expectError(error.BadRelay, (try Message.parse(bare.finish())).unwrap(8));
    // The 34-byte header is the minimum.
    try testing.expectError(error.Truncated, Message.parse(bare.finish()[0..33]));
}

test "dhcp6: hostile input is a typed error" {
    try testing.expectError(error.Truncated, Message.parse(""));
    try testing.expectError(error.Truncated, Message.parse(hp("010000")));
    // Option header cut, option length past the end.
    try testing.expectError(error.TruncatedOption, Message.parse(hp("01000000" ++ "000100")));
    try testing.expectError(error.TruncatedOption, Message.parse(hp("01000000" ++ "00010005aabb")));
    // Known options of an impossible length.
    const bad_elapsed = try Message.parse(hp("01000000" ++ "00080003000000"));
    try testing.expectError(error.BadOptionLength, bad_elapsed.elapsedTime());
    const bad_dns = try Message.parse(hp("01000000" ++ "00170005aabbccddee"));
    try testing.expectError(error.BadOptionLength, bad_dns.dnsServers());
    const bad_oro = try Message.parse(hp("01000000" ++ "00060003aabbcc"));
    try testing.expectError(error.BadOptionLength, bad_oro.optionRequest());
    const bad_pref = try Message.parse(hp("01000000" ++ "0007000200ff"));
    try testing.expectError(error.BadOptionLength, bad_pref.preference());
    const bad_rc = try Message.parse(hp("01000000" ++ "000e0001ff"));
    try testing.expectError(error.BadOptionLength, bad_rc.rapidCommit());
    const short_status = try Message.parse(hp("01000000" ++ "000d000100"));
    try testing.expectError(error.BadOptionLength, short_status.statusCode());
    // DUIDs: an LL with no address, a UUID of 15 octets, an unknown type passes.
    const bad_ll = try Message.parse(hp("01000000" ++ "000100040003" ++ "0001"));
    try testing.expectError(error.BadOptionLength, bad_ll.clientId());
    try testing.expectError(error.BadOptionLength, Duid.parse(hp("0004" ++ "00112233445566778899aabbccddee")));
    try testing.expectEqual(@as(u16, 99), @backingInt((try Duid.parse(hp("0063aabb"))).kind));
    var big: [132]u8 = @splat(0);
    big[1] = 99;
    try testing.expectError(error.BadOptionLength, Duid.parse(&big)); // 130 octets after the type
    // An IA too short, an IA address too short, a prefix length of 129.
    const short_ia = try Message.parse(hp("01000000" ++ "00030004" ++ "00000001"));
    var it = short_ia.identityAssociations(.na);
    try testing.expectError(error.BadOptionLength, it.next());
    try testing.expect((try it.next()) == null); // terminal after an error
    const ia_na = Ia{ .iaid = 0, .t1 = 0, .t2 = 0, .options = hp("0005000300aabb") };
    var ai = ia_na.addresses();
    try testing.expectError(error.BadOptionLength, ai.next());
    const pfx129 = Ia{ .iaid = 0, .t1 = 0, .t2 = 0, .options = hp("001a0019" ++ "0000000000000000" ++ "81" ++ "00000000000000000000000000000000") };
    var pi = pfx129.prefixes();
    try testing.expectError(error.BadOptionLength, pi.next());
    // Domain lists: a compression pointer, a missing root label, a label over the end.
    var nb: [DomainListIterator.max_name_len]u8 = undefined;
    for ([_][]const u8{ hp("c00c"), hp("03616263"), hp("0561626300") }) |bad| {
        var d: DomainListIterator = .{ .buf = bad };
        try testing.expectError(error.BadOptionLength, d.next(&nb));
        try testing.expect((try d.next(&nb)) == null);
    }
    // A name over 254 characters: 5 labels of 63 octets.
    var long: [5 * 64 + 1]u8 = undefined;
    for (0..5) |i| {
        long[i * 64] = 63;
        @memset(long[i * 64 + 1 ..][0..63], 'a');
    }
    long[320] = 0;
    var dl: DomainListIterator = .{ .buf = &long };
    try testing.expectError(error.BadOptionLength, dl.next(&nb));
}

test "dhcp6: builder limits and marks" {
    var small: [5]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, Builder.init(small[0..3], .solicit, 0));
    var b = try Builder.init(&small, .solicit, 0);
    try testing.expectError(error.BufferTooSmall, b.addOption(1, "x"));
    try testing.expectEqual(@as(usize, 4), b.finish().len); // unchanged
    var buf: [64]u8 = undefined;
    try testing.expectError(error.WrongKind, Builder.init(&buf, .relay_forw, 0));
    try testing.expectError(error.WrongKind, Builder.initRelay(&buf, .reply, 0, addr1, addr1));
    var c = try Builder.init(&buf, .solicit, 0);
    // Forged marks: far past the end, the largest offset (the old `at + 4`
    // overflowed), one inside the header, and one that is real but stale.
    for ([_]usize{ 100, std.math.maxInt(usize), std.math.maxInt(usize) - 3, 1, 3 }) |at| {
        try testing.expectError(error.BadMark, c.end(.{ .at = at, .code = 0 }));
    }
    const live = try c.begin(OptionCode.ia_na, &.{ 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0 });
    try testing.expectError(error.BadMark, c.end(.{ .at = live.at, .code = live.code +% 1 })); // wrong code
    try c.end(live);
    try testing.expectError(error.BadMark, c.end(live)); // closed once already: its length is no longer 0
    try testing.expectError(error.BadMark, c.end(.{ .at = 0, .code = 0 })); // inside the message header
    try testing.expectError(error.BadName, c.addDomainList(&.{"a..b"}));
    try testing.expectError(error.BadName, c.addDomainList(&.{""}));
    try testing.expectEqual(@as(usize, 4 + 4 + 12), c.finish().len); // a refused name leaves nothing behind
    var huge: [70000]u8 = undefined;
    var d = try Builder.init(&huge, .solicit, 0);
    try testing.expectError(error.OptionTooLong, d.addOption(1, huge[0..65536]));
    const m = try d.begin(1, &.{});
    d.len += 65536;
    try testing.expectError(error.OptionTooLong, d.end(m));
}

test "dhcp6: domain names are limited to 253 characters, parser and Builder (RFC 1035 §2.3.4: 255 octets on the wire)" {
    // 63 + 63 + 63 + 61 characters and three dots = 253; one more character = 254.
    var n253: [253]u8 = undefined;
    @memset(&n253, 'a');
    for ([_]usize{ 63, 127, 191 }) |at| n253[at] = '.';
    var n254: [254]u8 = undefined;
    @memset(&n254, 'a');
    for ([_]usize{ 63, 127, 191 }) |at| n254[at] = '.';
    var buf: [600]u8 = undefined;
    var nb: [DomainListIterator.max_name_len]u8 = undefined;
    {
        var b = try Builder.init(&buf, .reply, 1);
        try b.addDomainList(&.{&n253});
        const m = try Message.parse(b.finish());
        var it = m.domainList().?;
        try testing.expectEqualStrings(&n253, (try it.next(&nb)).?);
        // 253 characters is 255 octets on the wire.
        try testing.expectEqual(@as(usize, 4 + 4 + 255), b.finish().len);
    }
    {
        var b = try Builder.init(&buf, .reply, 1);
        try testing.expectError(error.BadName, b.addDomainList(&.{&n254}));
        try testing.expectEqual(@as(usize, 4), b.finish().len);
        // The parser refuses the same name when it arrives on the wire.
        var wire: [260]u8 = undefined;
        var at: usize = 0;
        var rest: []const u8 = &n254;
        while (true) {
            const dot = std.mem.findScalar(u8, rest, '.');
            const label = if (dot) |d| rest[0..d] else rest;
            wire[at] = @intCast(label.len);
            @memcpy(wire[at + 1 ..][0..label.len], label);
            at += 1 + label.len;
            rest = if (dot) |d| rest[d + 1 ..] else break;
        }
        wire[at] = 0;
        var it: DomainListIterator = .{ .buf = wire[0 .. at + 1] };
        try testing.expectError(error.BadOptionLength, it.next(&nb));
    }
}

test "dhcp6: the Builder refuses a DUID the parser refuses; short hand-built DUIDs give null (sweep D6-4)" {
    var buf: [300]u8 = undefined;
    var b = try Builder.init(&buf, .solicit, 0);
    var big: [131]u8 = @splat(1);
    big[0] = 0;
    big[1] = 99; // unknown type, 129 octets after it
    try testing.expectError(error.BadDuid, b.addClientId(big[0..131]));
    try b.addClientId(big[0..130]); // 128 octets after the type is the limit
    try testing.expectError(error.BadDuid, b.addServerId(&.{ 0, 3, 0, 1 })); // LL without an address
    try testing.expectError(error.BadDuid, b.addServerId(&.{}));
    try testing.expectError(error.BadDuid, b.addServerId(&.{1}));
    for ([_]DuidType{ .llt, .en, .ll, .uuid, @fromBackingInt(77) }) |k| {
        for (0..9) |n| {
            const d: Duid = .{ .kind = k, .data = big[0..n] };
            std.mem.doNotOptimizeAway(.{ d.hardwareType(), d.time(), d.linkLayerAddress(), d.enterpriseNumber() });
        }
    }
    const empty: Duid = .{ .kind = .llt, .data = &.{} };
    try testing.expect(empty.hardwareType() == null and empty.time() == null and empty.linkLayerAddress() == null);
}

test "dhcp6: Client FQDN, Vendor/User Class, Reconfigure, Prefix Exclude (hand-built from RFC 4704, 8415 §21.15-21.20, RFC 6603)" {
    var buf: [300]u8 = undefined;
    var b = try Builder.init(&buf, .reconfigure, 9);
    // Client FQDN: flags S=1, then www.example.com in wire form.
    try b.addOption(OptionCode.client_fqdn, &.{ 1, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 });
    try b.addOption(OptionCode.vendor_class, &.{ 0, 0, 0x01, 0x37, 0, 3, 'a', 'b', 'c', 0, 1, 'z' });
    try b.addOption(OptionCode.user_class, &.{ 0, 2, 'h', 'i' });
    try b.addOption(OptionCode.reconfigure_message, &.{5});
    try b.addOption(OptionCode.reconfigure_accept, &.{});
    const pd = try b.beginIa(.pd, 1, 0, 0);
    const pfx = try b.begin(OptionCode.ia_prefix, hp("0000000a" ++ "00000014" ++ "30" ++ "20010db8000000000000000000000000"));
    // Prefix Exclude: excluded /56, so 8 subnet-id bits = 1 octet.
    try b.addOption(OptionCode.pd_exclude, &.{ 56, 0xab });
    try b.end(pfx);
    try b.end(pd);
    const m = try Message.parse(b.finish());
    var nb: [DomainListIterator.max_name_len]u8 = undefined;
    const f = (try m.clientFqdn(&nb)).?;
    try testing.expectEqual(@as(u8, 1), f.flags);
    try testing.expectEqualStrings("www.example.com", f.name);
    const vc = (try m.vendorClass()).?;
    try testing.expectEqual(@as(u32, 311), vc.enterprise);
    var cls = vc.classes;
    try testing.expectEqualStrings("abc", (try cls.next()).?);
    try testing.expectEqualStrings("z", (try cls.next()).?);
    try testing.expect((try cls.next()) == null);
    var uc = m.userClass().?;
    try testing.expectEqualStrings("hi", (try uc.next()).?);
    try testing.expectEqual(MessageType.renew, (try m.reconfigureMessage()).?);
    try testing.expect(try m.reconfigureAccept());
    var it = m.identityAssociations(.pd);
    const ia = (try it.next()).?;
    var pit = ia.prefixes();
    const p = (try pit.next()).?;
    const ex = (try p.prefixExclude()).?;
    try testing.expectEqual(@as(u8, 56), ex.len);
    try testing.expectEqualSlices(u8, &.{0xab}, ex.subnet_id);
    // Hostile: a class entry that overruns, an exclude no longer than the prefix.
    const bad = try Message.parse(hp("07000000" ++ "000f0004" ++ "00ffaabb"));
    var bu = bad.userClass().?;
    try testing.expectError(error.BadOptionLength, bu.next());
    try testing.expect((try bu.next()) == null);
    const shorter: IaPrefix = .{ .preferred = 0, .valid = 0, .prefix_len = 64, .prefix = @splat(0), .options = hp("00430002" ++ "40ab") };
    try testing.expectError(error.BadOptionLength, shorter.prefixExclude());
}

test "dhcp6: lifetimes and timers the RFC tells a client to discard are returned raw and flagged (RFC 8415 §21.4, §21.6, §21.22)" {
    var buf: [200]u8 = undefined;
    var b = try Builder.init(&buf, .reply, 1);
    const na = try b.beginIa(.na, 1, 500, 100); // T1 > T2, both non-zero
    try b.addIaAddr(addr1, 200, 100); // preferred > valid
    try b.end(na);
    const pd = try b.beginIa(.pd, 2, 0, 100); // T1 = 0: valid
    try b.addIaPrefix(addr2, 64, 100, 200);
    try b.end(pd);
    const m = try Message.parse(b.finish());
    var it = m.identityAssociations(.na);
    const ia = (try it.next()).?;
    try testing.expectEqual(@as(u32, 500), ia.t1);
    try testing.expect(!ia.timersValid());
    var ad = ia.addresses();
    const a = (try ad.next()).?;
    try testing.expectEqual(@as(u32, 200), a.preferred);
    try testing.expect(!a.isValid());
    var pit = m.identityAssociations(.pd);
    const ip = (try pit.next()).?;
    try testing.expect(ip.timersValid());
    var pf = ip.prefixes();
    try testing.expect((try pf.next()).?.isValid());
}

// ── fuzz: DHCPv6 parse off the wire, never panics ───────────────────────────

fn seed(comptime h: []const u8) []const u8 {
    return testkit.fuzz.seedHex(h);
}

const seeds = [_][]const u8{
    // Solicit with Client ID (DUID-LL), Elapsed Time, IA_NA, Option Request.
    seed("01123456" ++ "0001000a00030001020000000001" ++ "000800020000" ++ "0003000c000000010000000000000000" ++ "0006000400170018"),
    // Reply: Server ID (LLT), IA_NA with an IA Address and a Status Code.
    seed("07abcdef" ++ "0002000e000100" ++ "0130d5a1b2020000000002" ++
        "0003002e" ++ "00000001" ++ "00000e10" ++ "00001518" ++ "00050018" ++ "20010db8000000000000000000000001" ++ "00001c20" ++ "00003840" ++ "000d0002" ++ "0000"),
    // Reply: IA_PD with an IA Prefix.
    seed("07abcdef" ++ "00190029" ++ "00000002" ++ "000003e8" ++ "000007d0" ++ "001a0019" ++ "00000bb8" ++ "00001770" ++ "38" ++ "20010db8aaaa00000000000000000000"),
    // Reply: two DNS servers and a two-name domain list.
    seed("07abcdef" ++ "00170020" ++ "20010db8000000000000000000000001" ++ "20010db8000000000000000000000002" ++
        "00180016" ++ "076578616d706c6503636f6d00" ++ "046c616203636f6d00"),
    // Relay-forward wrapping a Solicit.
    seed("0c01" ++ "20010db8000000000000000000000001" ++ "20010db8000000000000000000000002" ++ "00090018" ++ "01123456" ++ "0001000a00030001020000000001" ++ "00080002" ++ "0000"),
    // Relay-forward with no Relay Message; relay header cut; empty; bare header.
    seed("0c00" ++ "20010db8000000000000000000000001" ++ "20010db8000000000000000000000002"),
    seed("0c00" ++ "20010db8000000000000000000000001"),
    seed(""),
    seed("01000000"),
    // Hostile: option length past the end; compressed domain list; prefix length 255.
    seed("01000000" ++ "00010064aabb"),
    seed("07000000" ++ "00180002c00c"),
    seed("07000000" ++ "001a0019" ++ "00000000" ++ "00000000" ++ "ff" ++ "00000000000000000000000000000000"),
};

fn walkDuid(d: Duid) void {
    std.mem.doNotOptimizeAway(.{ d.hardwareType(), d.time(), d.linkLayerAddress(), d.enterpriseNumber() });
    fz.mark(.duid);
}

fn walkIa(ia: Ia) void {
    fz.mark(.ia);
    std.mem.doNotOptimizeAway(.{ ia.timersValid(), ia.statusCode() catch null });
    var a = ia.addresses();
    while (a.next() catch null) |x| {
        fz.mark(.address);
        std.mem.doNotOptimizeAway(x.isValid());
        var sub = OptionIterator.init(x.options);
        while (sub.next() catch null) |o| std.mem.doNotOptimizeAway(o.data.len);
    }
    var p = ia.prefixes();
    while (p.next() catch null) |x| {
        fz.mark(.prefix);
        std.mem.doNotOptimizeAway(x.isValid());
        std.mem.doNotOptimizeAway(x.prefixExclude() catch null);
        var sub = OptionIterator.init(x.options);
        while (sub.next() catch null) |o| std.mem.doNotOptimizeAway(o.data.len);
    }
}

fn parseDhcp6(bytes: []const u8) void {
    const m = Message.parse(bytes) catch return fz.mark(.rejected);
    fz.mark(.parsed);
    var nb: [DomainListIterator.max_name_len]u8 = undefined;
    if (m.clientId() catch null) |d| walkDuid(d);
    if (m.serverId() catch null) |d| walkDuid(d);
    _ = m.elapsedTime() catch {};
    _ = m.preference() catch {};
    _ = m.rapidCommit() catch {};
    _ = m.statusCode() catch {};
    if (m.optionRequest() catch null) |l| for (0..l.count() + 1) |i| std.mem.doNotOptimizeAway(l.at(i));
    if (m.sntpServers() catch null) |l| for (0..l.count() + 1) |i| std.mem.doNotOptimizeAway(l.at(i));
    if (m.dnsServers() catch null) |l| for (0..l.count() + 1) |i| std.mem.doNotOptimizeAway(l.at(i));
    if (m.domainList()) |d0| {
        var d = d0;
        while (d.next(&nb) catch null) |name| std.mem.doNotOptimizeAway(name.len);
    }
    if (m.clientFqdn(&nb) catch null) |f| std.mem.doNotOptimizeAway(f.name.len);
    if (m.vendorClass() catch null) |vc| {
        var c = vc.classes;
        while (c.next() catch null) |x| std.mem.doNotOptimizeAway(x.len);
    }
    if (m.userClass()) |u| {
        var c = u;
        while (c.next() catch null) |x| std.mem.doNotOptimizeAway(x.len);
    }
    _ = m.reconfigureMessage() catch {};
    _ = m.reconfigureAccept() catch {};
    inline for (.{ IaKind.na, IaKind.ta, IaKind.pd }) |k| {
        var it = m.identityAssociations(k);
        while (it.next() catch null) |ia| walkIa(ia);
    }
    var it = m.options();
    while (it.next() catch null) |_| {}
    if (m.unwrap(4)) |u| {
        if (u.depth > 0) fz.mark(.relay);
        std.mem.doNotOptimizeAway(u.inner.xid);
    } else |_| {}
}

fn fuzzDhcp6Parse(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [256]u8 = undefined;
    const len: usize = src.slice(&buf);
    parseDhcp6(buf[0..len]);
}

fn fuzzDhcp6Mutated(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [256]u8 = undefined;
    parseDhcp6(fz.damaged(S, src, &seeds, &buf));
}

/// Builds a message from drawn choices, with hostile arguments (bad DUIDs,
/// bad names, forged marks, tiny buffers), and parses the result back: the
/// Builder may refuse, never panic, and never emit what the parser refuses.
fn fuzzDhcp6Build(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var out: [400]u8 = undefined;
    const cap = src.valueRangeAtMost(u16, 0, out.len);
    var a1: [16]u8 = undefined;
    var a2: [16]u8 = undefined;
    src.bytes(&a1);
    src.bytes(&a2);
    var b = (if (src.value(bool))
        Builder.initRelay(out[0..cap], @fromBackingInt(src.valueRangeAtMost(u8, 12, 13)), src.value(u8), a1, a2)
    else
        Builder.init(out[0..cap], @fromBackingInt(src.valueRangeAtMost(u8, 1, 11)), src.value(u16))) catch return fz.mark(.rejected);
    const long_label: [64]u8 = @splat('x');
    const names = [_][]const u8{ "example.com", "a..b", "", "lab.example.org.", &long_label };
    const addrs = [_][16]u8{ a1, a2 };
    for (0..src.valueRangeAtMost(u8, 0, 8)) |_| switch (src.valueRangeAtMost(u8, 0, 9)) {
        0, 1 => {
            var duid: [24]u8 = undefined;
            src.bytes(&duid);
            std.mem.writeInt(u16, duid[0..2], src.valueRangeAtMost(u16, 0, 5), .big);
            const n = src.valueRangeAtMost(u8, 0, duid.len);
            if (src.value(bool)) b.addClientId(duid[0..n]) catch {} else b.addServerId(duid[0..n]) catch {};
        },
        2 => b.addElapsedTime(src.value(u16)) catch {},
        3 => if (b.beginIa(@fromBackingInt(@as(u16, switch (src.valueRangeAtMost(u8, 0, 2)) {
            0 => 3,
            1 => 4,
            else => 25,
        })), src.value(u16), src.value(u16), src.value(u16))) |m| {
            if (src.value(bool)) b.addIaAddr(a1, src.value(u16), src.value(u16)) catch {};
            if (src.value(bool)) b.addIaPrefix(a2, src.valueRangeAtMost(u8, 0, 140), src.value(u16), src.value(u16)) catch {};
            if (src.value(bool)) b.addStatusCode(.success, "ok") catch {};
            b.end(m) catch {};
        } else |_| {},
        4 => b.addAddressList(OptionCode.dns_servers, addrs[0..src.valueRangeAtMost(u8, 0, 2)]) catch {},
        5 => b.addDomainList(names[0..src.valueRangeAtMost(u8, 1, names.len)]) catch {},
        6 => b.addOptionRequest(&.{ 23, 24, src.value(u16) }) catch {},
        7 => b.addStatusCode(@fromBackingInt(src.value(u16)), "no") catch {},
        8 => b.addOption(src.value(u16), a1[0..src.valueRangeAtMost(u8, 0, 16)]) catch {},
        else => b.end(.{ .at = src.value(u16), .code = src.value(u16) }) catch {},
    };
    const msg = b.finish();
    const m = Message.parse(msg) catch return error.BuilderEmittedWhatParseRefuses;
    fz.mark(.builder_roundtrip);
    parseDhcp6(msg);
    std.mem.doNotOptimizeAway(m.xid);
}

test "fuzz: DHCPv6 parse never panics on arbitrary bytes" {
    try testing.fuzz({}, fz.fuzzScript(fuzzDhcp6Parse, 256), .{ .corpus = &seeds });
}

test "fuzz: dhcp6 parse, damaged corpus entries" {
    try testing.fuzz({}, fz.fuzzScript(fuzzDhcp6Mutated, 64), .{});
}

test "fuzz: dhcp6 builder, hostile arguments" {
    try testing.fuzz({}, fz.fuzzScript(fuzzDhcp6Build, 256), .{});
}

test "fuzz driver: L2DISCO_FUZZ (dhcp6)" {
    try fz.fuzz_driver.runAll(.{
        .{ fuzzDhcp6Parse, .{ .prefix = "L2DISCO_FUZZ", .name = "l2disco-dhcp6" } },
        .{ fuzzDhcp6Mutated, .{ .prefix = "L2DISCO_FUZZ", .name = "l2disco-dhcp6-mutated" } },
        .{ fuzzDhcp6Build, .{ .prefix = "L2DISCO_FUZZ", .name = "l2disco-dhcp6-build" } },
    });
}

test "fuzz harness: 400 seeds in every test run, and they get everywhere (dhcp6)" {
    // Depth is asserted per harness: the damaged-corpus run must reach IAs,
    // addresses, prefixes, DUID accessors and relay peeling; the builder run
    // must round-trip; random bytes need only parse and reject.
    try fz.checkReachEach("l2disco dhcp6", .{ fuzzDhcp6Parse, fuzzDhcp6Mutated, fuzzDhcp6Build }, .{
        &[_]fz.Label{.rejected},
        &[_]fz.Label{ .rejected, .parsed, .duid, .ia, .address, .prefix, .relay },
        &[_]fz.Label{ .builder_roundtrip, .duid, .ia, .address, .prefix },
    }, 4000);
}

test "corpus: the DHCPv6 seeds are non-empty and the parse split is pinned" {
    // The reach claim, executable: a seed longer than the harness buffer is
    // read back as the EMPTY one by `Smith.slice`. `deep` counts seeds that
    // got past the framing walk into an IA, an address or a prefix.
    var nonempty: usize = 0;
    var parsed: usize = 0;
    var deep: usize = 0;
    for (seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const m = Message.parse(buf[0..len]) catch continue;
        parsed += 1;
        inline for (.{ IaKind.na, IaKind.pd }) |k| {
            var it = m.identityAssociations(k);
            while (it.next() catch null) |ia| {
                var a = ia.addresses();
                var p = ia.prefixes();
                if ((a.next() catch null) != null or (p.next() catch null) != null) deep += 1;
            }
        }
    }
    try testing.expectEqual(seeds.len - 1, nonempty); // one seed IS the empty message
    try testing.expect(parsed >= 8);
    try testing.expect(deep >= 2);
}
