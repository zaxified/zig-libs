//! DNS resolver — UDP (with TC-bit → TCP retry), TCP (RFC 1035 §4.2.2
//! two-byte length prefix) and DoH (RFC 8484, `application/dns-message` over
//! the sibling `http` module; plus the common `application/dns-json` variant
//! via `std.json`).
//!
//! Modeled after Go's built-in resolver (`net/dnsclient_unix.go`): servers
//! and search list come from /etc/resolv.conf (explicit `Options.servers`
//! override), `lookupIp`/`reverse` consult /etc/hosts first, search-list
//! expansion follows Go's `conf.nameList`. One `Resolver` is owned by one
//! thread (`.single_owner`); every call blocks until an answer or timeout.
//!
//! Timeout model: `timeout_ms` bounds each UDP attempt natively
//! (`Socket.receiveTimeout`). TCP/DoH connects currently rely on the OS
//! default because std 0.16.0's `Io.Threaded` has not implemented
//! `netConnectIp*` with a timeout yet (same TODO as http.Client).

const std = @import("std");
const builtin = @import("builtin");
const netaddr = @import("netaddr");
const http = @import("http");
const dns = @import("root.zig");
const message = @import("message.zig");
const config = @import("config.zig");
const net = std.Io.net;

const Resolver = @This();

io: std.Io,
gpa: std.mem.Allocator,
options: Options,
/// Present iff `options.doh_url` is set.
http_client: ?http.Client,
/// resolv.conf, loaded lazily on first use (do not copy the Resolver after).
conf: ?config.ResolvConf,
conf_text: ?[]u8,

pub const Transport = enum {
    /// UDP first; retry over TCP when the response has the TC bit set.
    auto,
    /// TCP only.
    tcp,
};

pub const DohMethod = enum {
    /// RFC 8484 POST — the request body is the binary DNS message.
    post,
    /// RFC 8484 GET — the message travels base64url-encoded in `?dns=`.
    get,
};

pub const Options = struct {
    /// Explicit DNS servers; empty = read /etc/resolv.conf (falling back to
    /// localhost like Go when that is missing/empty).
    servers: []const netaddr.Ip = &.{},
    port: u16 = 53,
    /// DoH endpoint (e.g. "https://dns.google/dns-query"). When set, ALL
    /// queries go over HTTPS and `servers`/`transport` are ignored.
    doh_url: ?[]const u8 = null,
    doh_method: DohMethod = .post,
    /// TLS verification for DoH.
    doh_tls: http.Client.TlsOptions = .{},
    transport: Transport = .auto,
    /// Per-attempt budget; 0 = no timeout. Enforced natively on UDP receive;
    /// see the module comment for the TCP/DoH connect caveat.
    timeout_ms: u32 = 5000,
    /// UDP retry rounds over the server list (min 1).
    attempts: u8 = 2,
    /// Consult /etc/hosts in `lookupIp`/`reverse` before querying.
    use_hosts: bool = true,
    /// Apply the resolv.conf search list / ndots in `resolve`/`lookupIp`.
    use_search: bool = true,
    /// EDNS(0) advertised UDP payload size; null disables the OPT record.
    edns_udp_size: ?u16 = 1232,
    hosts_path: []const u8 = "/etc/hosts",
    resolv_conf_path: []const u8 = "/etc/resolv.conf",
};

pub const Error = error{
    /// From the codec: name over 253 chars / bad label (see message.zig).
    NameTooLong,
    BadName,
    /// No response within `timeout_ms × attempts`.
    Timeout,
    /// Socket-level failure (bind/send/connect/read).
    NetworkFailed,
    /// The response did not decode, or its id/QR did not match the query.
    MalformedResponse,
    /// DoH transport failed (HTTP error, non-200 status, oversized body).
    DohFailed,
    /// A DoH operation was requested without `Options.doh_url`.
    NoDohEndpoint,
    OutOfMemory,
    Canceled,
};

/// `io` must support net + async operations (e.g. `std.Io.Threaded`).
pub fn init(io: std.Io, gpa: std.mem.Allocator, options: Options) Resolver {
    return .{
        .io = io,
        .gpa = gpa,
        .options = options,
        .http_client = if (options.doh_url != null)
            http.Client.init(io, gpa, .{
                .tls = options.doh_tls,
                .total_timeout_ms = options.timeout_ms,
            })
        else
            null,
        .conf = null,
        .conf_text = null,
    };
}

pub fn deinit(r: *Resolver) void {
    if (r.http_client) |*c| c.deinit();
    if (r.conf_text) |t| r.gpa.free(t);
    r.* = undefined;
}

// ── high-level API ──────────────────────────────────────────────────────────

/// Resolve `name`/`ty` applying the search list (Go `conf.nameList` order,
/// unless `use_search` is off or the name is rooted). Returns the first
/// response with rcode NOERROR and at least one answer; otherwise the last
/// response (so the caller can inspect the rcode — NXDOMAIN is a valid
/// answer, not an error). Does NOT consult /etc/hosts — use `lookupIp` for
/// getaddrinfo-like behavior. Caller owns the message (`Message.deinit`).
pub fn resolve(r: *Resolver, name: []const u8, ty: message.Type) Error!message.Message {
    var search: []const []const u8 = &.{};
    var ndots: u8 = 1;
    if (r.options.use_search) {
        try r.ensureConfig();
        search = r.conf.?.search();
        ndots = r.conf.?.ndots;
    }

    var candidate_buf: [message.max_name_text_len]u8 = undefined;
    var it = config.NameIterator.init(name, search, ndots);
    var last: ?message.Message = null;
    errdefer if (last) |*m| m.deinit();
    while (it.next(&candidate_buf)) |candidate| {
        const msg = try r.query(candidate, ty);
        if (msg.rcode() == .no_error and msg.answers.len > 0) {
            if (last) |*m| m.deinit();
            return msg;
        }
        if (last) |*m| m.deinit();
        last = msg;
    }
    return last orelse error.BadName; // only an empty/over-long name yields no candidate
}

/// All IPv4 + IPv6 addresses for `name`: IP literals pass through, /etc/hosts
/// is consulted first (when enabled), then A and AAAA queries per search-list
/// candidate. On Linux the result is ordered by RFC 6724 destination rules
/// (netaddr) like getaddrinfo. Returns an empty slice when nothing resolves;
/// caller frees with `gpa.free`.
pub fn lookupIp(r: *Resolver, name: []const u8) Error![]netaddr.Ip {
    var list: std.ArrayList(netaddr.Ip) = .empty;
    errdefer list.deinit(r.gpa);

    if (netaddr.parseIp(name)) |ip| {
        try list.append(r.gpa, ip);
        return list.toOwnedSlice(r.gpa);
    }

    if (r.options.use_hosts) hosts: {
        const content = r.readHosts() orelse break :hosts;
        defer r.gpa.free(content);
        var ips: [16]netaddr.Ip = undefined;
        const n = config.hostsIpsForName(content, name, &ips);
        if (n > 0) {
            try list.appendSlice(r.gpa, ips[0..n]);
            sortIps(list.items);
            return list.toOwnedSlice(r.gpa);
        }
    }

    var search: []const []const u8 = &.{};
    var ndots: u8 = 1;
    if (r.options.use_search) {
        try r.ensureConfig();
        search = r.conf.?.search();
        ndots = r.conf.?.ndots;
    }

    var candidate_buf: [message.max_name_text_len]u8 = undefined;
    var it = config.NameIterator.init(name, search, ndots);
    while (it.next(&candidate_buf)) |candidate| {
        for ([_]message.Type{ .a, .aaaa }) |ty| {
            var msg = r.query(candidate, ty) catch |err| switch (err) {
                error.Canceled, error.OutOfMemory => |e| return e,
                else => continue, // tolerate one family failing (Go aggregates too)
            };
            defer msg.deinit();
            for (msg.answers) |rec| {
                if (dns.recordIp(rec)) |ip| try list.append(r.gpa, ip);
            }
        }
        if (list.items.len > 0) break; // first useful candidate wins
    }

    sortIps(list.items);
    return list.toOwnedSlice(r.gpa);
}

/// PTR lookup: /etc/hosts first (when enabled), then a reverse query for the
/// `in-addr.arpa`/`ip6.arpa` name built via netaddr. Returns the host names
/// (possibly empty); free with `freeNames`.
pub fn reverse(r: *Resolver, ip: netaddr.Ip) Error![]const []const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (names.items) |n| r.gpa.free(n);
        names.deinit(r.gpa);
    }

    if (r.options.use_hosts) hosts: {
        const content = r.readHosts() orelse break :hosts;
        defer r.gpa.free(content);
        var name_buf: [message.max_name_text_len]u8 = undefined;
        if (config.hostsNameForIp(content, ip, &name_buf)) |name| {
            try names.append(r.gpa, try r.gpa.dupe(u8, name));
            return names.toOwnedSlice(r.gpa);
        }
    }

    var rev_buf: [dns.max_reverse_name_len]u8 = undefined;
    var msg = try r.query(dns.reverseName(ip, &rev_buf), .ptr);
    defer msg.deinit();
    for (msg.answers) |rec| switch (rec.data) {
        .ptr => |name| try names.append(r.gpa, try r.gpa.dupe(u8, name)),
        else => {},
    };
    return names.toOwnedSlice(r.gpa);
}

/// Free a slice returned by `reverse`.
pub fn freeNames(r: *Resolver, names: []const []const u8) void {
    for (names) |n| r.gpa.free(n);
    r.gpa.free(names);
}

/// One-shot query for exactly `name` (no search list, no hosts file) over
/// the configured transport. Caller owns the returned message.
pub fn query(r: *Resolver, name: []const u8, ty: message.Type) Error!message.Message {
    var qbuf: [message.max_query_len]u8 = undefined;

    if (r.options.doh_url != null) {
        // RFC 8484 §4.1: use id 0 so DoH caches can be effective.
        const packet = try encodeChecked(&qbuf, name, ty, 0, r.options.edns_udp_size);
        const raw = try r.dohExchange(packet);
        defer r.gpa.free(raw);
        return r.decodeResponse(raw, 0);
    }

    var id_bytes: [2]u8 = undefined;
    r.io.random(&id_bytes);
    const id = std.mem.readInt(u16, &id_bytes, .big);
    const packet = try encodeChecked(&qbuf, name, ty, id, r.options.edns_udp_size);

    const servers = try r.serverList();
    const rbuf = try r.gpa.alloc(u8, @max(512, r.options.edns_udp_size orelse 0));
    defer r.gpa.free(rbuf);

    var last_err: ?Error = null;
    var attempt: u8 = 0;
    while (attempt < @max(1, r.options.attempts)) : (attempt += 1) {
        for (servers) |server| {
            if (r.options.transport == .tcp) {
                const raw = r.tcpExchange(server, packet) catch |err| switch (err) {
                    error.Canceled, error.OutOfMemory => |e| return e,
                    else => {
                        last_err = err;
                        continue;
                    },
                };
                defer r.gpa.free(raw);
                return r.decodeResponse(raw, id);
            }

            const raw = r.udpExchange(server, packet, id, rbuf) catch |err| switch (err) {
                error.Canceled, error.OutOfMemory => |e| return e,
                else => {
                    last_err = err;
                    continue;
                },
            };
            if (raw.len >= 3 and raw[2] & 0x02 != 0) { // TC bit → retry over TCP
                const traw = r.tcpExchange(server, packet) catch |err| switch (err) {
                    error.Canceled, error.OutOfMemory => |e| return e,
                    else => {
                        last_err = err;
                        continue;
                    },
                };
                defer r.gpa.free(traw);
                return r.decodeResponse(traw, id);
            }
            return r.decodeResponse(raw, id);
        }
    }
    return last_err orelse error.Timeout;
}

fn encodeChecked(buf: []u8, name: []const u8, ty: message.Type, id: u16, edns: ?u16) Error![]u8 {
    return message.encodeQuery(buf, name, ty, .{ .id = id, .edns_udp_size = edns }) catch |err| switch (err) {
        error.BufferTooSmall => unreachable, // max_query_len always fits
        error.NameTooLong => error.NameTooLong,
        error.BadName => error.BadName,
    };
}

fn decodeResponse(r: *Resolver, raw: []const u8, id: u16) Error!message.Message {
    var msg = message.decode(r.gpa, raw) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    errdefer msg.deinit();
    if (!msg.header.response or msg.header.id != id) return error.MalformedResponse;
    return msg;
}

// ── configuration plumbing ──────────────────────────────────────────────────

/// Go's fallback when resolv.conf is missing or names no servers.
const default_servers = [_]netaddr.Ip{
    .{ .v4 = .{ 127, 0, 0, 1 } },
    .{ .v6 = [_]u8{0} ** 15 ++ [_]u8{1} },
};

fn serverList(r: *Resolver) Error![]const netaddr.Ip {
    if (r.options.servers.len > 0) return r.options.servers;
    try r.ensureConfig();
    const from_conf = r.conf.?.servers();
    return if (from_conf.len > 0) from_conf else &default_servers;
}

fn ensureConfig(r: *Resolver) Error!void {
    if (r.conf != null) return;
    const text = std.Io.Dir.cwd().readFileAlloc(
        r.io,
        r.options.resolv_conf_path,
        r.gpa,
        .limited(64 * 1024),
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => try r.gpa.alloc(u8, 0), // unreadable → glibc-style defaults
    };
    r.conf_text = text;
    r.conf = config.parseResolvConf(text);
}

fn readHosts(r: *Resolver) ?[]u8 {
    return std.Io.Dir.cwd().readFileAlloc(
        r.io,
        r.options.hosts_path,
        r.gpa,
        .limited(1 << 20),
    ) catch null;
}

fn sortIps(ips: []netaddr.Ip) void {
    if (comptime builtin.os.tag != .linux) return; // systemSource is Linux-only
    if (ips.len > 1 and ips.len <= netaddr.max_sort_candidates)
        netaddr.sortDestinations(ips, netaddr.systemSource);
}

// ── transports ──────────────────────────────────────────────────────────────

fn toNetAddress(ip: netaddr.Ip, port: u16) net.IpAddress {
    return switch (ip) {
        .v4 => |b| .{ .ip4 = .{ .bytes = b, .port = port } },
        .v6 => |b| .{ .ip6 = .{ .bytes = b, .port = port } },
    };
}

fn attemptDeadline(r: *Resolver) std.Io.Timeout {
    const ms = r.options.timeout_ms;
    if (ms == 0) return .none;
    const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
    return t.toDeadline(r.io);
}

/// One UDP round-trip. Datagrams from the wrong peer or with the wrong id
/// are ignored (anti-spoofing, same as Go/c-ares) until the deadline.
/// The returned slice points into `rbuf`.
fn udpExchange(r: *Resolver, server: netaddr.Ip, packet: []const u8, id: u16, rbuf: []u8) Error![]u8 {
    const io = r.io;
    const dest = toNetAddress(server, r.options.port);
    const bind_addr: net.IpAddress = switch (server) {
        .v4 => .{ .ip4 = .unspecified(0) },
        .v6 => .{ .ip6 = .unspecified(0) },
    };
    const sock = bind_addr.bind(io, .{ .mode = .dgram }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.NetworkFailed,
    };
    defer sock.close(io);
    sock.send(io, &dest, packet) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.NetworkFailed,
    };

    const deadline = r.attemptDeadline();
    while (true) {
        const incoming = sock.receiveTimeout(io, rbuf, deadline) catch |err| switch (err) {
            error.Timeout => return error.Timeout,
            error.Canceled => return error.Canceled,
            else => return error.NetworkFailed,
        };
        if (!incoming.from.eql(&dest)) continue;
        if (incoming.data.len < message.header_len) continue;
        if (std.mem.readInt(u16, incoming.data[0..2], .big) != id) continue;
        return incoming.data;
    }
}

/// One TCP round-trip: 2-byte big-endian length prefix both ways
/// (RFC 1035 §4.2.2). Returns a gpa-owned response.
fn tcpExchange(r: *Resolver, server: netaddr.Ip, packet: []const u8) Error![]u8 {
    const io = r.io;
    const dest = toNetAddress(server, r.options.port);
    // No native connect timeout: std 0.16.0 Io.Threaded panics on it (same
    // TODO as http.Client.connectTimeout); the OS default applies.
    const stream = dest.connect(io, .{ .mode = .stream }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Timeout => return error.Timeout,
        else => return error.NetworkFailed,
    };
    defer stream.close(io);

    var wbuf: [message.max_query_len + 2]u8 = undefined;
    var sw = stream.writer(io, &wbuf);
    const w = &sw.interface;
    w.writeInt(u16, @intCast(packet.len), .big) catch return error.NetworkFailed;
    w.writeAll(packet) catch return error.NetworkFailed;
    w.flush() catch return error.NetworkFailed;

    var tbuf: [4096]u8 = undefined;
    var sr = stream.reader(io, &tbuf);
    const len = sr.interface.takeInt(u16, .big) catch return error.NetworkFailed;
    const out = try r.gpa.alloc(u8, len);
    errdefer r.gpa.free(out);
    sr.interface.readSliceAll(out) catch return error.NetworkFailed;
    return out;
}

/// Practical cap for a DoH response body (a DNS message is ≤ 64 KiB).
const max_doh_response = 128 * 1024;

/// RFC 8484 exchange over the http module. Returns the gpa-owned raw DNS
/// message from the response body.
fn dohExchange(r: *Resolver, packet: []const u8) Error![]u8 {
    const url = r.options.doh_url orelse return error.NoDohEndpoint;
    const client = &(r.http_client.?);

    var res = switch (r.options.doh_method) {
        .post => client.request(.post, url, .{
            .headers = &.{
                .{ .name = "Content-Type", .value = "application/dns-message" },
                .{ .name = "Accept", .value = "application/dns-message" },
            },
            .body = packet,
        }),
        .get => blk: {
            const Encoder = std.base64.url_safe_no_pad.Encoder;
            var b64_buf: [Encoder.calcSize(message.max_query_len)]u8 = undefined;
            const dns_param = Encoder.encode(&b64_buf, packet);
            const sep: u8 = if (std.mem.indexOfScalar(u8, url, '?') != null) '&' else '?';
            const full = std.fmt.allocPrint(r.gpa, "{s}{c}dns={s}", .{ url, sep, dns_param }) catch
                return error.OutOfMemory;
            defer r.gpa.free(full);
            break :blk client.request(.get, full, .{
                .headers = &.{.{ .name = "Accept", .value = "application/dns-message" }},
            });
        },
    } catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Canceled => return error.Canceled,
        error.Timeout => return error.Timeout,
        else => return error.DohFailed,
    };
    defer res.deinit();
    if (res.status != 200) return error.DohFailed;
    return res.readAllAlloc(r.gpa, max_doh_response) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.DohFailed,
    };
}

// ── DoH-JSON (application/dns-json) ─────────────────────────────────────────

/// The Google/Cloudflare `application/dns-json` schema (the fields we care
/// about; unknown ones are ignored). Record data stays textual — parse
/// A/AAAA `data` with `netaddr.parseIp` if needed.
pub const JsonMessage = struct {
    Status: u32 = 0,
    TC: bool = false,
    Question: []const JsonQuestion = &.{},
    Answer: []const JsonRecord = &.{},
    Authority: []const JsonRecord = &.{},

    pub const JsonQuestion = struct {
        name: []const u8 = "",
        type: u16 = 0,
    };

    pub const JsonRecord = struct {
        name: []const u8 = "",
        type: u16 = 0,
        TTL: u32 = 0,
        data: []const u8 = "",
    };
};

pub const JsonAnswer = std.json.Parsed(JsonMessage);

/// Query via the non-standard-but-common DoH-JSON API. `Options.doh_url`
/// must point at a JSON-capable endpoint (https://dns.google/resolve or
/// https://cloudflare-dns.com/dns-query). Free with `JsonAnswer.deinit`.
pub fn queryJson(r: *Resolver, name: []const u8, ty: message.Type) Error!JsonAnswer {
    const url = r.options.doh_url orelse return error.NoDohEndpoint;
    const client = &(r.http_client.?);

    const sep: u8 = if (std.mem.indexOfScalar(u8, url, '?') != null) '&' else '?';
    const full = std.fmt.allocPrint(r.gpa, "{s}{c}name={s}&type={d}", .{
        url, sep, name, @intFromEnum(ty),
    }) catch return error.OutOfMemory;
    defer r.gpa.free(full);

    var res = client.request(.get, full, .{
        .headers = &.{.{ .name = "Accept", .value = "application/dns-json" }},
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Canceled => return error.Canceled,
        error.Timeout => return error.Timeout,
        else => return error.DohFailed,
    };
    defer res.deinit();
    if (res.status != 200) return error.DohFailed;
    const body = res.readAllAlloc(r.gpa, max_doh_response) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.DohFailed,
    };
    defer r.gpa.free(body);

    return std.json.parseFromSlice(JsonMessage, r.gpa, body, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always, // body is freed on return
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
}

// ── tests (offline) ─────────────────────────────────────────────────────────

const testing = std.testing;

test "DoH-JSON schema parses a canned Cloudflare response" {
    const body =
        \\{"Status":3,"TC":false,"RD":true,"RA":true,"AD":true,"CD":false,
        \\ "Question":[{"name":"example.com","type":1}],
        \\ "Answer":[{"name":"example.com","type":1,"TTL":86400,"data":"93.184.216.34"},
        \\           {"name":"example.com","type":46,"TTL":86400,"data":"a 8 2 86400 sig"}],
        \\ "extra_field_from_the_future":{"x":1}}
    ;
    const parsed = try std.json.parseFromSlice(JsonMessage, testing.allocator, body, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    try testing.expectEqual(@as(u32, 3), parsed.value.Status);
    try testing.expectEqual(@as(usize, 1), parsed.value.Question.len);
    try testing.expectEqual(@as(usize, 2), parsed.value.Answer.len);
    try testing.expectEqual(@as(u16, 1), parsed.value.Answer[0].type);
    try testing.expectEqual(@as(u32, 86400), parsed.value.Answer[0].TTL);
    try testing.expectEqualStrings("93.184.216.34", parsed.value.Answer[0].data);
    // A-record data is netaddr-parseable.
    try testing.expect(netaddr.parseIp(parsed.value.Answer[0].data) != null);
}

test "toNetAddress maps netaddr.Ip to std.Io.net.IpAddress" {
    const v4 = toNetAddress(netaddr.parseIp("192.0.2.1").?, 53);
    try testing.expectEqual([4]u8{ 192, 0, 2, 1 }, v4.ip4.bytes);
    try testing.expectEqual(@as(u16, 53), v4.ip4.port);
    const v6 = toNetAddress(netaddr.parseIp("2001:db8::1").?, 853);
    try testing.expectEqual(@as(u8, 0x20), v6.ip6.bytes[0]);
    try testing.expectEqual(@as(u16, 853), v6.ip6.port);
}

// ── tests (live network — gracefully skipped when unavailable) ──────────────

fn skipLive(err: anyerror) error{SkipZigTest} {
    std.debug.print("live dns test skipped: {s}\n", .{@errorName(err)});
    return error.SkipZigTest;
}

test "live: resolve example.com A over UDP" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var r = Resolver.init(io, testing.allocator, .{ .timeout_ms = 3000 });
    defer r.deinit();

    var msg = r.resolve("example.com", .a) catch |err| return skipLive(err);
    defer msg.deinit();
    if (msg.rcode() != .no_error) return skipLive(error.UnexpectedRcode);
    var found = false;
    for (msg.answers) |rec| {
        if (rec.data == .a) found = true;
    }
    try testing.expect(found);
}

test "live: resolve example.com A over TCP" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var r = Resolver.init(io, testing.allocator, .{ .transport = .tcp, .timeout_ms = 4000 });
    defer r.deinit();

    var msg = r.resolve("example.com", .a) catch |err| return skipLive(err);
    defer msg.deinit();
    if (msg.rcode() != .no_error) return skipLive(error.UnexpectedRcode);
    try testing.expect(msg.answers.len > 0);
}

test "live: lookupIp collects A + AAAA" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var r = Resolver.init(io, testing.allocator, .{ .timeout_ms = 3000 });
    defer r.deinit();

    const ips = r.lookupIp("example.com") catch |err| return skipLive(err);
    defer testing.allocator.free(ips);
    if (ips.len == 0) return skipLive(error.NoAddresses);
}

test "live: reverse PTR of 8.8.8.8" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var r = Resolver.init(io, testing.allocator, .{ .timeout_ms = 3000 });
    defer r.deinit();

    const names = r.reverse(netaddr.parseIp("8.8.8.8").?) catch |err| return skipLive(err);
    defer r.freeNames(names);
    if (names.len == 0) return skipLive(error.NoPtrRecords);
    try testing.expect(std.mem.indexOf(u8, names[0], "dns.google") != null);
}

test "live: DoH POST via dns.google (proves the http dep)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var r = Resolver.init(io, testing.allocator, .{
        .doh_url = "https://dns.google/dns-query",
        .timeout_ms = 8000,
    });
    defer r.deinit();

    var msg = r.query("example.com", .a) catch |err| return skipLive(err);
    defer msg.deinit();
    if (msg.rcode() != .no_error) return skipLive(error.UnexpectedRcode);
    try testing.expect(msg.answers.len > 0);
}

test "live: DoH GET via cloudflare-dns.com" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var r = Resolver.init(io, testing.allocator, .{
        .doh_url = "https://cloudflare-dns.com/dns-query",
        .doh_method = .get,
        .timeout_ms = 8000,
    });
    defer r.deinit();

    var msg = r.query("example.com", .a) catch |err| return skipLive(err);
    defer msg.deinit();
    if (msg.rcode() != .no_error) return skipLive(error.UnexpectedRcode);
    try testing.expect(msg.answers.len > 0);
}

test "live: DoH-JSON via dns.google/resolve" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var r = Resolver.init(io, testing.allocator, .{
        .doh_url = "https://dns.google/resolve",
        .timeout_ms = 8000,
    });
    defer r.deinit();

    const parsed = r.queryJson("example.com", .a) catch |err| return skipLive(err);
    defer parsed.deinit();
    try testing.expectEqual(@as(u32, 0), parsed.value.Status);
    try testing.expect(parsed.value.Answer.len > 0);
}
