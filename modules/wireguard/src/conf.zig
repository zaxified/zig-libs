// SPDX-License-Identifier: MIT
//! The `wg` configuration file: what `wg setconf`, `addconf`, `syncconf` read and
//! `wg showconf` prints. `[Interface]` with `PrivateKey`, `ListenPort`, `FwMark`;
//! any number of `[Peer]` with `PublicKey`, `PresharedKey`, `AllowedIPs`,
//! `Endpoint`, `PersistentKeepalive`. Pure text, no socket and no file: read the
//! file yourself, parse it into a `Config` and give that to `setDevice`.
//!
//! Written from wg(8) (the man page, § CONFIGURATION FILE FORMAT) and checked
//! black-box against the `wg` binary and the kernel by `tools/interop.zig` (D);
//! no wireguard-tools source was read (GPL-2.0). What the tool does beyond the man
//! page and is copied here comes from those runs, and each case is a test below.
//! Stricter than `wg` on purpose, by those runs: a port above 65535 (`wg` takes it
//! and sends something else) and brackets around an IPv4 endpoint.
//!
//! The text holds private keys. The parser keeps no slice of it, wipes what it
//! copies and tells the caller where the error is by line number, never by value.

const std = @import("std");
const netaddr = @import("netaddr");
const root = @import("root.zig");
const wipe = @import("wipe.zig");
const burn = @import("burn.zig");
const uapi = @import("uapi.zig");

const Allocator = std.mem.Allocator;
const Config = root.Config;
const PeerConfig = root.PeerConfig;
const AllowedIp = root.AllowedIp;
const Endpoint = root.Endpoint;
const Device = root.Device;
const Key = root.Key;

pub const Mode = enum {
    /// `wg setconf`: the file is the whole configuration. What it leaves out is
    /// cleared: peers, the private key, the port, the mark, a peer's PSK and
    /// keepalive.
    set,
    /// `wg addconf`: the file adds to the device. What it leaves out stays.
    add,
};

/// Turns a hostname in `Endpoint` into an address (the `dns` module, a table).
/// `wg` calls getaddrinfo; this module opens no socket, so the caller decides.
pub const Resolver = struct {
    ctx: ?*anyopaque = null,
    /// Writes `out`, which starts null. False, or true with `out` left null:
    /// `error.InvalidEndpoint`. `host` is a syntactically possible hostname (at most
    /// 253 bytes of letters, digits, `-`, `.`, `_`) and valid for this call only.
    resolve: *const fn (ctx: ?*anyopaque, host: []const u8, port: u16, out: *?Endpoint) bool,
};

pub const Options = struct {
    mode: Mode = .set,
    /// `wg-quick`'s keys in `[Interface]`: `Address`, `DNS`, `MTU`, `Table`,
    /// `PreUp`, `PreDown`, `PostUp`, `PostDown`, `SaveConfig`. `wg` refuses them;
    /// `.ignore` is `wg syncconf <(wg-quick strip …)` without the shell. They
    /// configure the host and are for the caller to read, not for this module.
    wg_quick_keys: enum { reject, ignore } = .reject,
    /// Without one, a hostname in `Endpoint` is `error.EndpointNeedsResolver`.
    resolver: ?Resolver = null,
    /// Bounds on the file, so a large input is an error with a name and not
    /// memory. The default is wireguard-go's `MaxPeers`.
    max_peers: u32 = 1 << 16,
    /// Across all peers. The default is 16 per peer at `max_peers`.
    max_allowed_ips: u32 = 1 << 20,
};

pub const ParseError = error{
    OutOfMemory,
    /// A line that is no `[Section]` and no `Key = Value`, or a NUL.
    InvalidSyntax,
    /// A section other than `[Interface]` and `[Peer]`.
    UnknownSection,
    /// A key this section does not have, or one before any section.
    UnknownKey,
    /// A `[Peer]` without `PublicKey`.
    MissingPublicKey,
    /// Not a 44-character canonical base64 key.
    InvalidKey,
    InvalidListenPort,
    InvalidFwMark,
    InvalidAllowedIp,
    InvalidEndpoint,
    /// `Endpoint` names a host and `Options.resolver` is null.
    EndpointNeedsResolver,
    InvalidPersistentKeepalive,
    /// More peers than `Options.max_peers`.
    TooManyPeers,
    /// More allowed-ips than `Options.max_allowed_ips`.
    TooManyAllowedIps,
};

/// Where the parser stopped. No text of the line: it may be a private key.
pub const Diagnostic = struct { line: u32 = 0 };

/// A parsed file. `config` borrows from this value's blocks; `deinit` wipes them.
pub const ParsedConfig = struct {
    gpa: Allocator,
    config: Config = .{},
    peers: []PeerConfig = &.{},

    pub fn deinit(p: *ParsedConfig) void {
        for (p.peers) |peer| p.gpa.free(peer.allowed_ips);
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(p.peers));
        p.gpa.free(p.peers);
        std.crypto.secureZero(u8, std.mem.asBytes(&p.config));
        p.* = undefined;
    }
};

const Section = enum { none, interface, peer };

/// A key in this section, case-insensitively, as `wg` reads them.
fn keyIs(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// Parse `text`; `out` is written only on success (`deinit` it then). `out.config`
/// has no interface name: set `config.ifname` before `setDevice`.
///
/// A `PublicKey` that comes twice is two entries, in file order, as `wg` sends them:
/// the later one's values win where it has any (`tools/interop.zig` D6).
pub fn parse(gpa: Allocator, text: []const u8, opts: Options, diag: ?*Diagnostic, out: *ParsedConfig) ParseError!void {
    return burn.run(burn.cp_burn, ParseError!void, parseBody, .{ gpa, text, &opts, diag, out });
}

fn parseBody(gpa: Allocator, text: []const u8, opts_ptr: *const Options, diag: ?*Diagnostic, out: *ParsedConfig) ParseError!void {
    const opts = opts_ptr.*;
    // Peers carry pre-shared keys: the list wipes what it leaves behind when it
    // grows, and so does the line scratch, which sees every key.
    var wa = wipe.WipingAllocator.init(gpa);
    const a = wa.allocator();
    var peers: std.ArrayList(PeerConfig) = .empty;
    var ips: std.ArrayList(AllowedIp) = .empty;
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(a);
    defer ips.deinit(gpa);
    var done = false;
    defer if (!done) {
        for (peers.items) |peer| gpa.free(peer.allowed_ips);
        peers.deinit(a);
    };

    var cfg: Config = .{};
    defer std.crypto.secureZero(u8, std.mem.asBytes(&cfg));
    var section: Section = .none;
    var peer: PeerConfig = .{ .public_key = @splat(0) };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&peer));
    var peer_has_key = false;
    var total_ips: u64 = 0;
    var line_no: u32 = 0;
    errdefer if (diag) |d| {
        d.line = line_no;
    };

    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        line_no +|= 1;
        // A comment runs to the end of the line, and whitespace means nothing
        // anywhere in it (`Allowed IPs = 10.0.0.1 / 8` is what `wg` reads too).
        const body = raw[0 .. std.mem.findScalar(u8, raw, '#') orelse raw.len];
        scratch.clearRetainingCapacity();
        for (body) |c| {
            if (c == 0) return error.InvalidSyntax;
            if (!std.ascii.isWhitespace(c)) try scratch.append(a, c);
        }
        const line = scratch.items;
        if (line.len == 0) continue;

        if (line[0] == '[') {
            if (section == .peer) try finishPeer(gpa, a, &peers, &peer, &ips, peer_has_key);
            peer_has_key = false;
            if (line[line.len - 1] != ']') return error.InvalidSyntax;
            const name = line[1 .. line.len - 1];
            if (keyIs(name, "Interface")) {
                // A second one goes on adding to the first, as in `wg` (the man
                // page says one; the tool takes more).
                section = .interface;
            } else if (keyIs(name, "Peer")) {
                if (peers.items.len >= opts.max_peers) return error.TooManyPeers;
                section = .peer;
                peer = .{ .public_key = @splat(0) };
                peer.replace_allowed_ips = opts.mode == .set;
                if (opts.mode == .set) {
                    peer.preshared_key = @splat(0);
                    peer.persistent_keepalive_interval = 0;
                }
            } else return error.UnknownSection;
            continue;
        }

        const eq = std.mem.findScalar(u8, line, '=') orelse return error.InvalidSyntax;
        const key = line[0..eq];
        const value = line[eq + 1 ..];
        switch (section) {
            .none => return error.UnknownKey,
            .interface => {
                if (keyIs(key, "PrivateKey")) {
                    cfg.private_key = @as(Key, undefined);
                    root.keyFromBase64Into(value, &cfg.private_key.?) catch return error.InvalidKey;
                } else if (keyIs(key, "ListenPort")) {
                    cfg.listen_port = uapi.number(u16, value) orelse return error.InvalidListenPort;
                } else if (keyIs(key, "FwMark")) {
                    cfg.fwmark = parseFwMark(value) orelse return error.InvalidFwMark;
                } else if (opts.wg_quick_keys == .ignore and isWgQuickKey(key)) {
                    // the caller's; wg-quick reads these, wg does not
                } else return error.UnknownKey;
            },
            .peer => {
                if (keyIs(key, "PublicKey")) {
                    root.keyFromBase64Into(value, &peer.public_key) catch return error.InvalidKey;
                    peer_has_key = true;
                } else if (keyIs(key, "PresharedKey")) {
                    peer.preshared_key = @as(Key, undefined);
                    root.keyFromBase64Into(value, &peer.preshared_key.?) catch return error.InvalidKey;
                } else if (keyIs(key, "AllowedIPs")) {
                    // Even in `add`: the line replaces the peer's list, as `wg addconf`.
                    peer.replace_allowed_ips = true;
                    var ip_it = std.mem.splitScalar(u8, value, ',');
                    while (ip_it.next()) |ip_text| {
                        if (ip_text.len == 0) return error.InvalidAllowedIp;
                        total_ips += 1;
                        if (total_ips > opts.max_allowed_ips) return error.TooManyAllowedIps;
                        try ips.append(gpa, AllowedIp.parse(ip_text) catch return error.InvalidAllowedIp);
                    }
                } else if (keyIs(key, "Endpoint")) {
                    peer.endpoint = try parseEndpointWith(value, opts.resolver);
                } else if (keyIs(key, "PersistentKeepalive")) {
                    peer.persistent_keepalive_interval = parseKeepalive(value) orelse return error.InvalidPersistentKeepalive;
                } else return error.UnknownKey;
            },
        }
    }
    if (section == .peer) try finishPeer(gpa, a, &peers, &peer, &ips, peer_has_key);

    if (opts.mode == .set) {
        cfg.replace_peers = true;
        if (cfg.private_key == null) cfg.private_key = @splat(0);
        if (cfg.listen_port == null) cfg.listen_port = 0;
        if (cfg.fwmark == null) cfg.fwmark = 0;
    }
    const owned = try peers.toOwnedSlice(a);
    done = true;
    out.* = .{ .gpa = gpa, .peers = owned, .config = cfg };
    out.config.peers = owned;
}

fn finishPeer(gpa: Allocator, a: Allocator, peers: *std.ArrayList(PeerConfig), peer: *PeerConfig, ips: *std.ArrayList(AllowedIp), has_key: bool) ParseError!void {
    if (!has_key) return error.MissingPublicKey;
    try peers.ensureUnusedCapacity(a, 1);
    peer.allowed_ips = try ips.toOwnedSlice(gpa);
    peers.appendAssumeCapacity(peer.*);
}

fn isWgQuickKey(key: []const u8) bool {
    for ([_][]const u8{ "Address", "DNS", "MTU", "Table", "PreUp", "PreDown", "PostUp", "PostDown", "SaveConfig" }) |k| {
        if (keyIs(key, k)) return true;
    }
    return false;
}

/// `off`, decimal, or `0x…`. A fwmark is 32 bits.
fn parseFwMark(v: []const u8) ?u32 {
    if (keyIs(v, "off")) return 0;
    if (v.len > 2 and v[0] == '0' and v[1] == 'x') {
        if (!std.ascii.isHex(v[2])) return null; // no sign after the prefix
        return std.fmt.parseInt(u32, v[2..], 16) catch null;
    }
    return uapi.number(u32, v);
}

/// `off`, or 0..65535 seconds.
fn parseKeepalive(v: []const u8) ?u16 {
    if (keyIs(v, "off")) return 0;
    return uapi.number(u16, v);
}

/// `ip:port` or `[ip6]:port` / `[ip6%scope]:port`, the scope a number. Null:
/// not an address and port (it may be a hostname).
pub fn parseEndpoint(text: []const u8) ?Endpoint {
    const hp = netaddr.parseHostPort(text) orelse return null;
    if (netaddr.parseIp4(hp.host)) |a| {
        // Brackets are for IPv6.
        if (text[0] == '[') return null;
        return .{ .v4 = .{ .addr = a, .port = hp.port } };
    }
    if (text[0] != '[') return null;
    const pct = std.mem.findScalar(u8, hp.host, '%');
    const a = netaddr.parseIp6(hp.host[0 .. pct orelse hp.host.len]) orelse return null;
    const scope: u32 = if (pct) |i| std.fmt.parseInt(u32, hp.host[i + 1 ..], 10) catch return null else 0;
    return .{ .v6 = .{ .addr = a, .port = hp.port, .scope_id = scope } };
}

fn parseEndpointWith(text: []const u8, resolver: ?Resolver) ParseError!Endpoint {
    if (parseEndpoint(text)) |e| return e;
    const hp = netaddr.parseHostPort(text) orelse return error.InvalidEndpoint;
    // A broken address is not a hostname to go and look up.
    if (netaddr.parseIpZoned(hp.host) != null or text[0] == '[') return error.InvalidEndpoint;
    if (!possibleHostname(hp.host)) return error.InvalidEndpoint;
    const r = resolver orelse return error.EndpointNeedsResolver;
    var e: ?Endpoint = null;
    if (!r.resolve(r.ctx, hp.host, hp.port, &e)) return error.InvalidEndpoint;
    return e orelse error.InvalidEndpoint;
}

/// Nothing a resolver should be handed: too long for DNS, or holding bytes no
/// hostname has (a config file is text someone may have typed anything into).
fn possibleHostname(host: []const u8) bool {
    if (host.len == 0 or host.len > 253) return false;
    for (host) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '.' and c != '_') return false;
    }
    return true;
}

/// Longest `formatEndpoint`: `[` IPv6 `%` u32 `]:` port.
pub const max_endpoint_text_len = 1 + netaddr.max_ip_text_len + 1 + 10 + 2 + 5;

/// The text `parseEndpoint` reads.
pub fn formatEndpoint(e: Endpoint, buf: *[max_endpoint_text_len]u8) []const u8 {
    var ip_buf: [netaddr.max_ip_text_len]u8 = undefined;
    return switch (e) {
        .v4 => |v| std.mem.print(buf, "{s}:{d}", .{ netaddr.formatIp(.{ .v4 = v.addr }, &ip_buf), v.port }) catch unreachable,
        .v6 => |v| if (v.scope_id != 0)
            std.mem.print(buf, "[{s}%{d}]:{d}", .{ netaddr.formatIp(.{ .v6 = v.addr }, &ip_buf), v.scope_id, v.port }) catch unreachable
        else
            std.mem.print(buf, "[{s}]:{d}", .{ netaddr.formatIp(.{ .v6 = v.addr }, &ip_buf), v.port }) catch unreachable,
    };
}

/// `10.0.0.0/24`, `2001:db8::/32`, the address as it is.
pub fn formatAllowedIp(w: *std.Io.Writer, ip: *const AllowedIp) std.Io.Writer.Error!void {
    var ip_buf: [netaddr.max_ip_text_len]u8 = undefined;
    const text = if (ip.addr_len == 4)
        netaddr.formatIp(.{ .v4 = ip.addr[0..4].* }, &ip_buf)
    else
        netaddr.formatIp(.{ .v6 = ip.addr }, &ip_buf);
    try w.print("{s}/{d}", .{ text, ip.cidr });
}

fn writeKeyLine(w: *std.Io.Writer, name: []const u8, key: *const Key) std.Io.Writer.Error!void {
    return burn.run(burn.cp_burn, std.Io.Writer.Error!void, writeKeyLineBody, .{ w, name, key });
}

fn writeKeyLineBody(w: *std.Io.Writer, name: []const u8, key: *const Key) std.Io.Writer.Error!void {
    var b: [root.key_b64_len]u8 = undefined;
    root.keyToBase64Into(key, &b);
    defer std.crypto.secureZero(u8, &b);
    try w.print("{s} = {s}\n", .{ name, &b });
}

fn writeAllowedIps(w: *std.Io.Writer, ips: []const AllowedIp) std.Io.Writer.Error!void {
    if (ips.len == 0) return;
    try w.writeAll("AllowedIPs = ");
    for (ips, 0..) |*ip, i| {
        if (i != 0) try w.writeAll(", ");
        try formatAllowedIp(w, ip);
    }
    try w.writeByte('\n');
}

/// `wg showconf`: a device as a file. It holds the private key if the device
/// reported one. The stats are not in the format.
pub fn formatDevice(w: *std.Io.Writer, dev: *const Device) std.Io.Writer.Error!void {
    try w.writeAll("[Interface]\n");
    if (dev.listen_port != 0) try w.print("ListenPort = {d}\n", .{dev.listen_port});
    if (dev.fwmark != 0) try w.print("FwMark = 0x{x}\n", .{dev.fwmark});
    if (dev.private_key) |*k| try writeKeyLine(w, "PrivateKey", k);
    for (dev.peers) |*p| {
        try w.writeAll("\n[Peer]\n");
        try writeKeyLine(w, "PublicKey", &p.public_key);
        if (p.preshared_key) |*k| try writeKeyLine(w, "PresharedKey", k);
        try writeAllowedIps(w, p.allowed_ips);
        if (p.endpoint) |e| {
            var buf: [max_endpoint_text_len]u8 = undefined;
            try w.print("Endpoint = {s}\n", .{formatEndpoint(e, &buf)});
        }
        if (p.persistent_keepalive_interval != 0) try w.print("PersistentKeepalive = {d}\n", .{p.persistent_keepalive_interval});
    }
}

/// A `Config` as a file: what it sets. A cleared value (a zero key, port 0)
/// is what `parse` in `.set` mode reads for a line that is not there.
pub fn formatConfig(w: *std.Io.Writer, cfg: *const Config) std.Io.Writer.Error!void {
    return burn.run(burn.cp_burn, std.Io.Writer.Error!void, formatConfigBody, .{ w, cfg });
}

fn formatConfigBody(w: *std.Io.Writer, cfg: *const Config) std.Io.Writer.Error!void {
    const zero: Key = @splat(0);
    try w.writeAll("[Interface]\n");
    if (cfg.listen_port) |v| if (v != 0) try w.print("ListenPort = {d}\n", .{v});
    if (cfg.fwmark) |v| if (v != 0) try w.print("FwMark = 0x{x}\n", .{v});
    if (cfg.private_key) |*k| if (!std.crypto.timing_safe.eql(Key, k.*, zero)) try writeKeyLine(w, "PrivateKey", k);
    for (cfg.peers) |*p| {
        try w.writeAll("\n[Peer]\n");
        try writeKeyLine(w, "PublicKey", &p.public_key);
        if (p.preshared_key) |*k| if (!std.crypto.timing_safe.eql(Key, k.*, zero)) try writeKeyLine(w, "PresharedKey", k);
        try writeAllowedIps(w, p.allowed_ips);
        if (p.endpoint) |e| {
            var buf: [max_endpoint_text_len]u8 = undefined;
            try w.print("Endpoint = {s}\n", .{formatEndpoint(e, &buf)});
        }
        if (p.persistent_keepalive_interval) |v| if (v != 0) try w.print("PersistentKeepalive = {d}\n", .{v});
    }
}

/// `wg syncconf`: the changes that take `current` to `desired`, leaving alone
/// whatever is already right, so that a live peer's session survives. Parse the
/// file with `.mode = .add`: as with `wg syncconf`, a peer value the file leaves
/// out keeps the device's (a PSK, a keepalive, an endpoint, the allowed-ips
/// without an `AllowedIPs` line), while a peer the file leaves out is removed and
/// the interface's key, port and mark are cleared if it leaves them out. A peer
/// that differs is sent whole. Allowed-ips compare as a set.
///
/// `n log n` over sorted keys, no hash table: the cost must not hang on how the
/// keys fall into one. The result's `config.ifname` is `desired.ifname`, borrowed.
///
/// A `PublicKey` twice in `desired`: the entries stay in file order, the first compared
/// with the device and the rest always sent, so the device ends as `wg syncconf` leaves
/// it, on the last one's values (`tools/interop.zig` D6).
pub fn sync(gpa: Allocator, current: *const Device, desired: *const Config, out: *ParsedConfig) error{OutOfMemory}!void {
    return burn.run(burn.cp_burn, error{OutOfMemory}!void, syncBody, .{ gpa, current, desired, out });
}

fn syncBody(gpa: Allocator, current: *const Device, desired: *const Config, out: *ParsedConfig) error{OutOfMemory}!void {
    var wa = wipe.WipingAllocator.init(gpa);
    const a = wa.allocator();
    var delta: std.ArrayList(PeerConfig) = .empty;
    var done = false;
    defer if (!done) {
        for (delta.items) |p| gpa.free(p.allowed_ips);
        delta.deinit(a);
    };

    const order_cur = try gpa.alloc(usize, current.peers.len);
    defer gpa.free(order_cur);
    const order_des = try gpa.alloc(usize, desired.peers.len);
    defer gpa.free(order_des);
    for (order_cur, 0..) |*o, i| o.* = i;
    for (order_des, 0..) |*o, i| o.* = i;
    std.mem.sort(usize, order_cur, current, struct {
        fn lt(c: *const Device, x: usize, y: usize) bool {
            return std.mem.order(u8, &c.peers[x].public_key, &c.peers[y].public_key) == .lt;
        }
    }.lt);
    std.mem.sort(usize, order_des, desired, struct {
        fn lt(c: *const Config, x: usize, y: usize) bool {
            return std.mem.order(u8, &c.peers[x].public_key, &c.peers[y].public_key) == .lt;
        }
    }.lt);

    var i: usize = 0;
    var j: usize = 0;
    try delta.ensureTotalCapacity(a, current.peers.len + desired.peers.len);
    while (i < order_cur.len or j < order_des.len) {
        const c: ?*const root.Peer = if (i < order_cur.len) &current.peers[order_cur[i]] else null;
        const d: ?*const PeerConfig = if (j < order_des.len) &desired.peers[order_des[j]] else null;
        const ord: std.math.Order = if (c == null)
            .gt
        else if (d == null)
            .lt
        else
            std.mem.order(u8, &c.?.public_key, &d.?.public_key);
        switch (ord) {
            .lt => {
                delta.appendAssumeCapacity(.{ .public_key = c.?.public_key, .remove = true });
                i += 1;
            },
            .gt => {
                try appendWhole(gpa, &delta, d.?);
                j += 1;
            },
            .eq => {
                if (!(try samePeer(gpa, c.?, d.?))) try appendWhole(gpa, &delta, d.?);
                i += 1;
                j += 1;
            },
        }
    }

    var cfg: Config = .{ .ifname = desired.ifname, .ifindex = desired.ifindex };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&cfg));
    // The device's own values follow the file as in `setconf`: left out means
    // cleared (wg syncconf, measured on FwMark). Sent only when they change.
    const zero: Key = @splat(0);
    const want_key: *const Key = if (desired.private_key) |*k| k else &zero;
    const have_key: *const Key = if (current.private_key) |*h| h else &zero;
    if (!std.crypto.timing_safe.eql(Key, want_key.*, have_key.*)) cfg.private_key = want_key.*;
    const want_port = desired.listen_port orelse 0;
    if (want_port != current.listen_port) cfg.listen_port = want_port;
    const want_mark = desired.fwmark orelse 0;
    if (want_mark != current.fwmark) cfg.fwmark = want_mark;
    const owned = try delta.toOwnedSlice(a);
    done = true;
    out.* = .{ .gpa = gpa, .peers = owned, .config = cfg };
    out.config.peers = owned;
}

fn appendWhole(gpa: Allocator, delta: *std.ArrayList(PeerConfig), d: *const PeerConfig) error{OutOfMemory}!void {
    var p = d.*;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&p));
    p.remove = false;
    p.update_only = false;
    p.allowed_ips = try gpa.dupe(AllowedIp, d.allowed_ips);
    delta.appendAssumeCapacity(p);
}

fn ipLess(_: void, x: AllowedIp, y: AllowedIp) bool {
    if (x.family != y.family) return x.family < y.family;
    if (x.cidr != y.cidr) return x.cidr < y.cidr;
    return std.mem.order(u8, x.bytes(), y.bytes()) == .lt;
}

fn samePeer(gpa: Allocator, c: *const root.Peer, d: *const PeerConfig) error{OutOfMemory}!bool {
    if (d.preshared_key) |*k| {
        const zero: Key = @splat(0);
        const have: *const Key = if (c.preshared_key) |*h| h else &zero;
        if (!std.crypto.timing_safe.eql(Key, k.*, have.*)) return false;
    }
    if (d.persistent_keepalive_interval) |v| if (v != c.persistent_keepalive_interval) return false;
    if (d.endpoint) |e| {
        const have = c.endpoint orelse return false;
        if (!std.meta.eql(e, have)) return false;
    }
    if (!d.replace_allowed_ips) return true;
    if (d.allowed_ips.len != c.allowed_ips.len) return false;
    const x = try gpa.dupe(AllowedIp, c.allowed_ips);
    defer gpa.free(x);
    const y = try gpa.dupe(AllowedIp, d.allowed_ips);
    defer gpa.free(y);
    std.mem.sortUnstable(AllowedIp, x, {}, ipLess);
    std.mem.sortUnstable(AllowedIp, y, {}, ipLess);
    for (x, y) |p, q| {
        if (p.family != q.family or p.cidr != q.cidr or !std.mem.eql(u8, p.bytes(), q.bytes())) return false;
    }
    return true;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const fixture_priv = "wFvUHvCFh9Vyq7hzvWhH3l2pW9Wg4ZzGZ1m4ZQ1rV3M=";
const fixture_pub = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
const fixture_psk = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=";

test "conf: a whole file, keys any case, whitespace anywhere, comments" {
    const text =
        \\# a comment
        \\[Interface]
        \\  PrivateKey = wFvUHvCFh9Vyq7hzvWhH3l2pW9Wg4ZzGZ1m4ZQ1rV3M=  # trailing
        \\listenport=51820
        \\FwMark = 0x10
        \\
        \\[peer]
        \\PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
        \\PresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=
        \\AllowedIPs = 10.0.0.0/24, 2001:db8::/32
        \\AllowedIPs = 10.9.0.1
        \\Endpoint = 203.0.113.5:51820
        \\PersistentKeepalive = 25
        \\[Peer]
        \\PublicKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=
        \\Endpoint = [2001:db8::1]:1
        \\PersistentKeepalive = off
        \\
    ;
    var p: ParsedConfig = undefined;
    try parse(testing.allocator, text, .{}, null, &p);
    defer p.deinit();
    try testing.expectEqual(@as(?u16, 51820), p.config.listen_port);
    try testing.expectEqual(@as(?u32, 16), p.config.fwmark);
    try testing.expect(p.config.replace_peers);
    try testing.expectEqual(try root.keyFromBase64(fixture_priv), p.config.private_key.?);
    try testing.expectEqual(@as(usize, 2), p.config.peers.len);
    const a = p.config.peers[0];
    try testing.expectEqual(try root.keyFromBase64(fixture_pub), a.public_key);
    try testing.expectEqual(try root.keyFromBase64(fixture_psk), a.preshared_key.?);
    try testing.expect(a.replace_allowed_ips);
    try testing.expectEqual(@as(usize, 3), a.allowed_ips.len);
    try testing.expectEqual(@as(u8, 24), a.allowed_ips[0].cidr);
    try testing.expectEqual(@as(u8, 32), a.allowed_ips[1].cidr);
    try testing.expectEqual(@as(u16, root.AF.INET6), a.allowed_ips[1].family);
    try testing.expectEqual(@as(u8, 32), a.allowed_ips[2].cidr);
    try testing.expectEqual(@as(u16, 51820), a.endpoint.?.port());
    try testing.expectEqual(@as(?u16, 25), a.persistent_keepalive_interval);
    const b = p.config.peers[1];
    try testing.expectEqual(@as(?u16, 0), b.persistent_keepalive_interval);
    try testing.expectEqual(@as(u16, 1), b.endpoint.?.v6.port);
    // `set`: what the peer did not say is cleared.
    try testing.expectEqual(@as(Key, @splat(0)), b.preshared_key.?);
}

test "conf: set clears what the file leaves out, add leaves it" {
    const text = "[Peer]\nPublicKey = " ++ fixture_pub ++ "\n";
    var s: ParsedConfig = undefined;
    try parse(testing.allocator, text, .{}, null, &s);
    defer s.deinit();
    try testing.expectEqual(@as(Key, @splat(0)), s.config.private_key.?);
    try testing.expectEqual(@as(?u16, 0), s.config.listen_port);
    try testing.expectEqual(@as(?u32, 0), s.config.fwmark);
    try testing.expect(s.config.replace_peers);
    var a: ParsedConfig = undefined;
    try parse(testing.allocator, text, .{ .mode = .add }, null, &a);
    defer a.deinit();
    try testing.expect(a.config.private_key == null and a.config.listen_port == null and a.config.fwmark == null);
    try testing.expect(!a.config.replace_peers);
    try testing.expect(!a.config.peers[0].replace_allowed_ips);
    try testing.expect(a.config.peers[0].preshared_key == null);
    try testing.expect(a.config.peers[0].persistent_keepalive_interval == null);
    var b: ParsedConfig = undefined;
    try parse(testing.allocator, text ++ "AllowedIPs = 10.0.0.1/32\n", .{ .mode = .add }, null, &b);
    defer b.deinit();
    try testing.expect(b.config.peers[0].replace_allowed_ips);
}

fn expectParseError(want: ParseError, text: []const u8, opts: Options, line: u32) !void {
    var d: Diagnostic = .{};
    var p: ParsedConfig = undefined;
    try testing.expectError(want, parse(testing.allocator, text, opts, &d, &p));
    try testing.expectEqual(line, d.line);
}

test "conf: every refusal, with its line" {
    const ok_peer = "[Peer]\nPublicKey = " ++ fixture_pub ++ "\n";
    try expectParseError(error.UnknownKey, "PrivateKey = x\n", .{}, 1);
    try expectParseError(error.InvalidSyntax, "[Interface\n", .{}, 1);
    try expectParseError(error.InvalidSyntax, "[Interface]\nno-equals\n", .{}, 2);
    try expectParseError(error.InvalidSyntax, "[Interface]\nFoo\x00 = 1\n", .{}, 2);
    try expectParseError(error.UnknownSection, "[Other]\n", .{}, 1);
    try expectParseError(error.UnknownKey, "[Interface]\nAddress = 10.0.0.1/24\n", .{}, 2);
    try expectParseError(error.UnknownKey, "[Peer]\nListenPort = 1\n", .{}, 2);
    try expectParseError(error.MissingPublicKey, "[Peer]\nEndpoint = 1.2.3.4:5\n", .{}, 3);
    try expectParseError(error.MissingPublicKey, "[Peer]\n[Peer]\nPublicKey = " ++ fixture_pub ++ "\n", .{}, 2);
    try expectParseError(error.InvalidKey, "[Interface]\nPrivateKey = short\n", .{}, 2);
    try expectParseError(error.InvalidKey, "[Peer]\nPublicKey = short\n", .{}, 2);
    try expectParseError(error.InvalidKey, ok_peer ++ "PresharedKey = short\n", .{}, 3);
    try expectParseError(error.InvalidListenPort, "[Interface]\nListenPort = 65536\n", .{}, 2);
    try expectParseError(error.InvalidListenPort, "[Interface]\nListenPort = -1\n", .{}, 2);
    try expectParseError(error.InvalidFwMark, "[Interface]\nFwMark = 0x100000000\n", .{}, 2);
    try expectParseError(error.InvalidFwMark, "[Interface]\nFwMark = nope\n", .{}, 2);
    try expectParseError(error.InvalidFwMark, "[Interface]\nFwMark = 0X10\n", .{}, 2);
    try expectParseError(error.InvalidAllowedIp, ok_peer ++ "AllowedIPs = 10.0.0.0/33\n", .{}, 3);
    try expectParseError(error.InvalidAllowedIp, ok_peer ++ "AllowedIPs = 10.0.0.0/8,,10.0.0.1\n", .{}, 3);
    try expectParseError(error.InvalidAllowedIp, ok_peer ++ "AllowedIPs =\n", .{}, 3);
    try expectParseError(error.InvalidEndpoint, ok_peer ++ "Endpoint = 1.2.3.4\n", .{}, 3);
    try expectParseError(error.InvalidEndpoint, ok_peer ++ "Endpoint = 1.2.3.4:65536\n", .{}, 3);
    try expectParseError(error.InvalidEndpoint, ok_peer ++ "Endpoint = [1.2.3.4]:5\n", .{}, 3);
    try expectParseError(error.InvalidEndpoint, ok_peer ++ "Endpoint = [::1%eth0]:5\n", .{}, 3);
    try expectParseError(error.EndpointNeedsResolver, ok_peer ++ "Endpoint = vpn.example.com:51820\n", .{}, 3);
    try expectParseError(error.InvalidPersistentKeepalive, ok_peer ++ "PersistentKeepalive = 65536\n", .{}, 3);
    try expectParseError(error.TooManyPeers, ok_peer ++ ok_peer, .{ .max_peers = 1 }, 3);
    try expectParseError(error.TooManyAllowedIps, ok_peer ++ "AllowedIPs = 10.0.0.1, 10.0.0.2\n", .{ .max_allowed_ips = 1 }, 3);
}

test "conf: wg-quick keys, hostnames by resolver, a second Interface" {
    const text = "[Interface]\nAddress = 10.0.0.1/24\nDNS = 1.1.1.1\nMTU=1400\nTable=off\nPreUp=x\nPostUp=x\nPreDown=x\nPostDown=x\nSaveConfig=true\n";
    var q: ParsedConfig = undefined;
    try parse(testing.allocator, text, .{ .wg_quick_keys = .ignore }, null, &q);
    q.deinit();

    const R = struct {
        var called: usize = 0;
        fn res(_: ?*anyopaque, host: []const u8, port: u16, out: *?Endpoint) bool {
            called += 1;
            if (std.mem.eql(u8, host, "says.yes.writes.nothing")) return true;
            if (!std.mem.eql(u8, host, "vpn.example.com")) return false;
            out.* = .{ .v4 = .{ .addr = .{ 192, 0, 2, 1 }, .port = port } };
            return true;
        }
    };
    const peer = "[Peer]\nPublicKey = " ++ fixture_pub ++ "\n";
    var p: ParsedConfig = undefined;
    try parse(testing.allocator, peer ++ "Endpoint = vpn.example.com:7\n", .{ .resolver = .{ .resolve = R.res } }, null, &p);
    defer p.deinit();
    try testing.expectEqual(@as(u16, 7), p.config.peers[0].endpoint.?.v4.port);
    try testing.expectEqual(@as(usize, 0), p.config.peers[0].allowed_ips.len);
    try expectParseError(error.InvalidEndpoint, peer ++ "Endpoint = other.example.com:7\n", .{ .resolver = .{ .resolve = R.res } }, 3);
    // A resolver that says true and writes nothing is no address.
    try expectParseError(error.InvalidEndpoint, peer ++ "Endpoint = says.yes.writes.nothing:7\n", .{ .resolver = .{ .resolve = R.res } }, 3);
    // Not hostnames: the resolver never sees them.
    const called = R.called;
    const long: [254]u8 = @splat('a');
    try expectParseError(error.InvalidEndpoint, peer ++ "Endpoint = " ++ &long ++ ":7\n", .{ .resolver = .{ .resolve = R.res } }, 3);
    try expectParseError(error.InvalidEndpoint, peer ++ "Endpoint = bad!host:7\n", .{ .resolver = .{ .resolve = R.res } }, 3);
    try expectParseError(error.InvalidEndpoint, peer ++ "Endpoint = \xc3\xa9.example:7\n", .{ .resolver = .{ .resolve = R.res } }, 3);
    try testing.expectEqual(called, R.called);
    var twice: ParsedConfig = undefined;
    try parse(testing.allocator, "[Interface]\nListenPort = 1\n[Interface]\nFwMark = 2\n", .{}, null, &twice);
    defer twice.deinit();
    try testing.expectEqual(@as(?u16, 1), twice.config.listen_port);
    try testing.expectEqual(@as(?u32, 2), twice.config.fwmark);
}

test "conf: endpoints round-trip through their text" {
    var buf: [max_endpoint_text_len]u8 = undefined;
    for ([_][]const u8{ "1.2.3.4:5", "[2001:db8::1]:65535", "[fe80::1%7]:51820" }) |t| {
        const e = parseEndpoint(t).?;
        try testing.expectEqualStrings(t, formatEndpoint(e, &buf));
    }
    try testing.expect(parseEndpoint("") == null);
    try testing.expect(parseEndpoint("[::1]") == null);
    try testing.expect(parseEndpoint("host:1") == null);
    try testing.expect(parseEndpoint("::1:5") == null);
    try testing.expect(parseEndpoint("[::1%]:5") == null);
    // The longest there is fits.
    const long: Endpoint = .{ .v6 = .{ .addr = @splat(0xff), .port = 65535, .scope_id = std.math.maxInt(u32) } };
    try testing.expectEqual(long, parseEndpoint(formatEndpoint(long, &buf)).?);
}

test "conf: a Device prints as a file that parses back to it" {
    var ips = [_]AllowedIp{ AllowedIp.v4(.{ 10, 0, 0, 0 }, 24), AllowedIp.v6(@splat(0x20), 64) };
    var peers = [_]root.Peer{.{
        .public_key = try root.keyFromBase64(fixture_pub),
        .preshared_key = try root.keyFromBase64(fixture_psk),
        .endpoint = .{ .v4 = .{ .addr = .{ 203, 0, 113, 5 }, .port = 51820 } },
        .persistent_keepalive_interval = 25,
        .allowed_ips = &ips,
    }};
    const dev: Device = .{ .private_key = try root.keyFromBase64(fixture_priv), .listen_port = 51820, .fwmark = 0x10, .peers = &peers };
    var out: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try formatDevice(&w, &dev);
    try testing.expectEqualStrings(
        "[Interface]\nListenPort = 51820\nFwMark = 0x10\nPrivateKey = " ++ fixture_priv ++
            "\n\n[Peer]\nPublicKey = " ++ fixture_pub ++
            "\nPresharedKey = " ++ fixture_psk ++
            "\nAllowedIPs = 10.0.0.0/24, 2020:2020:2020:2020:2020:2020:2020:2020/64\nEndpoint = 203.0.113.5:51820\nPersistentKeepalive = 25\n",
        w.buffered(),
    );
    var p: ParsedConfig = undefined;
    try parse(testing.allocator, w.buffered(), .{}, null, &p);
    defer p.deinit();
    try testing.expectEqual(@as(?u16, 25), p.config.peers[0].persistent_keepalive_interval);
    try testing.expectEqual(ips.len, p.config.peers[0].allowed_ips.len);

    // A Config prints the same way.
    var out2: [1024]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&out2);
    try formatConfig(&w2, &p.config);
    try testing.expectEqualStrings(w.buffered(), w2.buffered());
    // An all-empty device.
    var w3: std.Io.Writer = .fixed(&out2);
    try formatDevice(&w3, &Device{});
    try testing.expectEqualStrings("[Interface]\n", w3.buffered());
    var w4: std.Io.Writer = .fixed(&out2);
    try formatConfig(&w4, &Config{ .private_key = @splat(0), .listen_port = 0, .fwmark = 0 });
    try testing.expectEqualStrings("[Interface]\n", w4.buffered());
}

test "conf: sync sends only what changed" {
    const k1 = try root.keyFromBase64(fixture_pub);
    const k2 = try root.keyFromBase64(fixture_psk);
    const k3 = try root.keyFromBase64(fixture_priv);
    var cur_ips = [_]AllowedIp{ AllowedIp.v4(.{ 10, 0, 0, 1 }, 32), AllowedIp.v4(.{ 10, 0, 0, 2 }, 32) };
    var same_ips_other_order = [_]AllowedIp{ AllowedIp.v4(.{ 10, 0, 0, 2 }, 32), AllowedIp.v4(.{ 10, 0, 0, 1 }, 32) };
    var cur_peers = [_]root.Peer{
        .{ .public_key = k1, .allowed_ips = &cur_ips },
        .{ .public_key = k2 },
    };
    const cur: Device = .{ .private_key = k3, .listen_port = 1, .fwmark = 0, .peers = &cur_peers };

    // k1 unchanged, k2 gone, k3 new; only the port differs on the device.
    const des_peers = [_]PeerConfig{
        .{ .public_key = k1, .replace_allowed_ips = true, .preshared_key = @splat(0), .persistent_keepalive_interval = 0, .allowed_ips = &same_ips_other_order },
        .{ .public_key = k3, .replace_allowed_ips = true, .allowed_ips = &same_ips_other_order },
    };
    const des: Config = .{ .ifname = "wg0", .private_key = k3, .listen_port = 2, .fwmark = 0, .replace_peers = true, .peers = &des_peers };
    var d: ParsedConfig = undefined;
    try sync(testing.allocator, &cur, &des, &d);
    defer d.deinit();
    try testing.expect(!d.config.replace_peers); // that is the point
    try testing.expectEqualStrings("wg0", d.config.ifname);
    try testing.expect(d.config.private_key == null);
    try testing.expectEqual(@as(?u16, 2), d.config.listen_port);
    try testing.expect(d.config.fwmark == null);
    try testing.expectEqual(@as(usize, 2), d.config.peers.len);
    var removed: usize = 0;
    var added: usize = 0;
    for (d.config.peers) |p| {
        if (p.remove) {
            removed += 1;
            try testing.expectEqual(k2, p.public_key);
        } else {
            added += 1;
            try testing.expectEqual(k3, p.public_key);
            try testing.expect(p.replace_allowed_ips);
        }
    }
    try testing.expectEqual(@as(usize, 1), removed);
    try testing.expectEqual(@as(usize, 1), added);

    // Differences that count, one by one.
    const base: PeerConfig = .{ .public_key = k1, .replace_allowed_ips = true, .allowed_ips = &cur_ips };
    const a = testing.allocator;
    try testing.expect(try samePeer(a, &cur_peers[0], &base));
    var v = base;
    v.preshared_key = k2;
    try testing.expect(!try samePeer(a, &cur_peers[0], &v));
    v = base;
    v.persistent_keepalive_interval = 9;
    try testing.expect(!try samePeer(a, &cur_peers[0], &v));
    v = base;
    v.endpoint = .{ .v4 = .{ .addr = .{ 1, 2, 3, 4 }, .port = 5 } };
    try testing.expect(!try samePeer(a, &cur_peers[0], &v));
    v = base;
    v.allowed_ips = cur_ips[0..1];
    try testing.expect(!try samePeer(a, &cur_peers[0], &v));
    // No `AllowedIPs` line: the device's list stands.
    v = base;
    v.allowed_ips = &.{};
    v.replace_allowed_ips = false;
    try testing.expect(try samePeer(a, &cur_peers[0], &v));
    var other = cur_ips;
    other[1].cidr = 31;
    v = base;
    v.allowed_ips = &other;
    try testing.expect(!try samePeer(a, &cur_peers[0], &v));
}

test "conf: max_allowed_ips counts every entry: the limit itself passes, one more does not" {
    const ok_peer = "[Peer]\nPublicKey = " ++ fixture_pub ++ "\n";
    var p: ParsedConfig = undefined;
    try parse(testing.allocator, ok_peer ++ "AllowedIPs = 10.0.0.1, 10.0.0.2\nAllowedIPs = 10.0.0.3\n", .{ .max_allowed_ips = 3 }, null, &p);
    defer p.deinit();
    try testing.expectEqual(@as(usize, 3), p.config.peers[0].allowed_ips.len); // the lines of one peer add up
    try expectParseError(error.TooManyAllowedIps, ok_peer ++ "AllowedIPs = 10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4\n", .{ .max_allowed_ips = 3 }, 3);
    try expectParseError(error.TooManyAllowedIps, ok_peer ++ "AllowedIPs = 10.0.0.1, 10.0.0.2\nAllowedIPs = 10.0.0.3, 10.0.0.4\n", .{ .max_allowed_ips = 3 }, 4);
}

test "conf: set clears a missing keepalive, add leaves it; a peer without its own key is refused" {
    const ok_peer = "[Peer]\nPublicKey = " ++ fixture_pub ++ "\n";
    var s: ParsedConfig = undefined;
    try parse(testing.allocator, ok_peer, .{}, null, &s);
    defer s.deinit();
    try testing.expectEqual(@as(?u16, 0), s.config.peers[0].persistent_keepalive_interval);
    var a: ParsedConfig = undefined;
    try parse(testing.allocator, ok_peer, .{ .mode = .add }, null, &a);
    defer a.deinit();
    try testing.expectEqual(@as(?u16, null), a.config.peers[0].persistent_keepalive_interval);
    // The key of one section does not carry over to the next.
    try expectParseError(error.MissingPublicKey, ok_peer ++ "[Peer]\nAllowedIPs = 10.0.0.1\n", .{}, 5);
    try expectParseError(error.MissingPublicKey, ok_peer ++ "[Interface]\nListenPort = 1\n[Peer]\n", .{}, 6);
}

test "conf: a fwmark is digits or 0x and hex digits, nothing in between" {
    try expectParseError(error.InvalidFwMark, "[Interface]\nFwMark = 0x+1\n", .{}, 2);
    try expectParseError(error.InvalidFwMark, "[Interface]\nFwMark = 0x-1\n", .{}, 2);
    try expectParseError(error.InvalidFwMark, "[Interface]\nFwMark = 0x_1\n", .{}, 2);
    try expectParseError(error.InvalidFwMark, "[Interface]\nFwMark = 0x\n", .{}, 2);
    var p: ParsedConfig = undefined;
    try parse(testing.allocator, "[Interface]\nFwMark = 0xFf\n", .{}, null, &p);
    defer p.deinit();
    try testing.expectEqual(@as(?u32, 255), p.config.fwmark);
}

test "conf: sync leaves an unchanged device, a reordered set and equal ports alone, and sends a changed endpoint" {
    const k1 = try root.keyFromBase64(fixture_pub);
    const k3 = try root.keyFromBase64(fixture_priv);
    const a = testing.allocator;
    // The same address under two prefix lengths, in the other order.
    var cur_ips = [_]AllowedIp{ AllowedIp.v4(.{ 10, 0, 0, 0 }, 8), AllowedIp.v4(.{ 10, 0, 0, 0 }, 24) };
    var des_ips = [_]AllowedIp{ AllowedIp.v4(.{ 10, 0, 0, 0 }, 24), AllowedIp.v4(.{ 10, 0, 0, 0 }, 8) };
    const ep: Endpoint = .{ .v4 = .{ .addr = .{ 203, 0, 113, 5 }, .port = 51820 } };
    var cur_peers = [_]root.Peer{.{ .public_key = k1, .endpoint = ep, .allowed_ips = &cur_ips }};
    const cur: Device = .{ .private_key = k3, .listen_port = 7, .fwmark = 9, .peers = &cur_peers };
    var des_peers = [_]PeerConfig{.{ .public_key = k1, .replace_allowed_ips = true, .endpoint = ep, .allowed_ips = &des_ips }};
    const des: Config = .{ .ifname = "wg0", .private_key = k3, .listen_port = 7, .fwmark = 9, .replace_peers = true, .peers = &des_peers };
    var d: ParsedConfig = undefined;
    try sync(a, &cur, &des, &d);
    defer d.deinit();
    try testing.expectEqual(@as(usize, 0), d.config.peers.len);
    try testing.expect(d.config.private_key == null);
    try testing.expect(d.config.listen_port == null);
    try testing.expect(d.config.fwmark == null);

    // Only the endpoint differs: same address, other port; other address, same port; v6.
    for ([_]Endpoint{
        .{ .v4 = .{ .addr = .{ 203, 0, 113, 5 }, .port = 51821 } },
        .{ .v4 = .{ .addr = .{ 203, 0, 113, 6 }, .port = 51820 } },
        .{ .v6 = .{ .addr = @splat(1), .port = 51820, .scope_id = 0 } },
    }) |other| {
        des_peers[0].endpoint = other;
        try testing.expect(!try samePeer(a, &cur_peers[0], &des_peers[0]));
        var e: ParsedConfig = undefined;
        try sync(a, &cur, &des, &e);
        defer e.deinit();
        try testing.expectEqual(@as(usize, 1), e.config.peers.len);
        try testing.expect(std.meta.eql(other, e.config.peers[0].endpoint.?));
    }
}

test "conf: a PublicKey twice is two entries in file order, and sync keeps that order" {
    const a = testing.allocator;
    const k = try root.keyFromBase64(fixture_pub);
    const text = "[Peer]\nPublicKey = " ++ fixture_pub ++ "\nAllowedIPs = 10.0.0.1/32\nPersistentKeepalive = 1\n" ++
        "[Peer]\nPublicKey = " ++ fixture_pub ++ "\nAllowedIPs = 10.0.0.2/32\nPersistentKeepalive = 2\n";
    var p: ParsedConfig = undefined;
    try parse(a, text, .{ .mode = .add }, null, &p);
    defer p.deinit();
    try testing.expectEqual(@as(usize, 2), p.config.peers.len);
    try testing.expectEqual(@as(u8, 1), p.config.peers[0].allowed_ips[0].addr[3]);
    try testing.expectEqual(@as(u8, 2), p.config.peers[1].allowed_ips[0].addr[3]);

    // Already at the first entry's values: the second still goes, so the last wins.
    var ips = [_]AllowedIp{AllowedIp.v4(.{ 10, 0, 0, 1 }, 32)};
    var peers = [_]root.Peer{.{ .public_key = k, .persistent_keepalive_interval = 1, .allowed_ips = &ips }};
    const cur: Device = .{ .peers = &peers };
    var d1: ParsedConfig = undefined;
    try sync(a, &cur, &p.config, &d1);
    defer d1.deinit();
    try testing.expectEqual(@as(usize, 1), d1.config.peers.len);
    try testing.expectEqual(@as(?u16, 2), d1.config.peers[0].persistent_keepalive_interval);
    // At neither: both go, in order, and the first with its replace flag.
    peers[0].persistent_keepalive_interval = 9;
    var d2: ParsedConfig = undefined;
    try sync(a, &cur, &p.config, &d2);
    defer d2.deinit();
    try testing.expectEqual(@as(usize, 2), d2.config.peers.len);
    try testing.expectEqual(@as(?u16, 1), d2.config.peers[0].persistent_keepalive_interval);
    try testing.expectEqual(@as(?u16, 2), d2.config.peers[1].persistent_keepalive_interval);
}

test "conf: out of memory at every allocation frees everything" {
    const text = "[Interface]\nPrivateKey = " ++ fixture_priv ++ "\n[Peer]\nPublicKey = " ++ fixture_pub ++
        "\nAllowedIPs = 10.0.0.1, 10.0.0.2, 10.0.0.3\n[Peer]\nPublicKey = " ++ fixture_psk ++ "\nAllowedIPs = 10.0.0.4\n";
    var fail_at: usize = 0;
    while (true) : (fail_at += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_at });
        var p: ParsedConfig = undefined;
        if (parse(fa.allocator(), text, .{}, null, &p)) |_| {
            p.deinit();
            break;
        } else |err| try testing.expectEqual(error.OutOfMemory, err);
    }
    try testing.expect(fail_at > 3);
}

const conf_fuzz = struct {
    const fuzz_driver = @import("testkit").fuzz.driver;
    const Label = enum { raw_refused, raw_parsed, built_parsed, built_damaged, roundtrip };
    var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

    fn mark(comptime l: Label) void {
        reach[@backingInt(l)] += 1;
        fuzz_driver.hit(@tagName(l));
    }

    const fragments = [_][]const u8{
        "[Interface]\n",                          "[Peer]\n",               "PrivateKey = " ++ fixture_priv ++ "\n", "PublicKey = " ++ fixture_pub ++ "\n",
        "PresharedKey = " ++ fixture_psk ++ "\n", "ListenPort = 51820\n",   "FwMark = 0x10\n",                       "FwMark = off\n",
        "AllowedIPs = 10.0.0.0/8, ::/0\n",        "Endpoint = 1.2.3.4:5\n", "Endpoint = [::1%3]:5\n",                "Endpoint = host.example:5\n",
        "PersistentKeepalive = 25\n",             "# comment\n",            "\n",                                    "=\n",
        "[\n",                                    "]\n",                    "ListenPort=\n",                         "AllowedIPs=,\n",
        "Address=1\n",
    };

    fn harness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
        // Raw bytes first: nothing here may do worse than refuse.
        var raw: [256]u8 = undefined;
        const n = smith.slice(&raw);
        var p: ParsedConfig = undefined;
        if (parse(gpa, raw[0..n], .{}, null, &p)) |_| {
            mark(.raw_parsed);
            p.deinit();
        } else |_| mark(.raw_refused);

        // Then a file put together from valid-looking lines.
        var text: std.ArrayList(u8) = .empty;
        defer text.deinit(gpa);
        const lines = smith.value(u8) % 16;
        for (0..lines) |_| try text.appendSlice(gpa, fragments[smith.value(u8) % fragments.len]);
        if (smith.value(u8) & 1 == 0 and text.items.len > 0) {
            text.items[smith.value(u16) % text.items.len] ^= @as(u8, 1) << @intCast(smith.value(u8) % 8);
            mark(.built_damaged);
        }
        const mode: Mode = if (smith.value(u8) & 1 == 0) .set else .add;
        var q: ParsedConfig = undefined;
        parse(gpa, text.items, .{ .mode = mode, .wg_quick_keys = .ignore }, null, &q) catch return;
        defer q.deinit();
        mark(.built_parsed);

        // What parses prints, and what prints parses to the same peers.
        var printed: std.Io.Writer.Allocating = .init(gpa);
        defer printed.deinit();
        try formatConfig(&printed.writer, &q.config);
        var r: ParsedConfig = undefined;
        try parse(gpa, printed.written(), .{ .mode = mode }, null, &r);
        defer r.deinit();
        if (r.config.peers.len != q.config.peers.len) return error.RoundTripMismatch;
        // Interface values: an explicit zero and an absent one print alike.
        const zero: Key = @splat(0);
        if ((r.config.listen_port orelse 0) != (q.config.listen_port orelse 0) or
            (r.config.fwmark orelse 0) != (q.config.fwmark orelse 0) or
            !std.mem.eql(u8, &(r.config.private_key orelse zero), &(q.config.private_key orelse zero)))
            return error.RoundTripMismatch;
        for (q.config.peers, r.config.peers) |a, b| {
            if (!std.mem.eql(u8, &a.public_key, &b.public_key) or a.allowed_ips.len != b.allowed_ips.len)
                return error.RoundTripMismatch;
            if (!std.mem.eql(u8, &(a.preshared_key orelse zero), &(b.preshared_key orelse zero)) or
                (a.persistent_keepalive_interval orelse 0) != (b.persistent_keepalive_interval orelse 0) or
                !std.meta.eql(a.endpoint, b.endpoint) or a.replace_allowed_ips != b.replace_allowed_ips)
                return error.RoundTripMismatch;
            for (a.allowed_ips, b.allowed_ips) |x, y| {
                if (x.family != y.family or x.cidr != y.cidr or !std.mem.eql(u8, x.bytes(), y.bytes()))
                    return error.RoundTripMismatch;
            }
        }
        mark(.roundtrip);
    }
};

test "fuzz driver: WIREGUARD_FUZZ (wireguard-conf)" {
    try conf_fuzz.fuzz_driver.run(conf_fuzz.harness, .{ .prefix = "WIREGUARD_FUZZ", .name = "wireguard-conf" });
}

test "fuzz harness: 300 seeds of wireguard-conf in every test run, and they get everywhere" {
    conf_fuzz.reach = @splat(0);
    for (0..300) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: conf_fuzz.fuzz_driver.Rng = .{ .r = prng.random() };
        try conf_fuzz.harness(conf_fuzz.fuzz_driver.Rng, &rng, testing.allocator);
    }
    for (conf_fuzz.reach, 0..) |n, i| {
        // Random bytes are hardly ever a config file.
        if (n == 0 and i != @backingInt(conf_fuzz.Label.raw_parsed)) {
            std.debug.print("reach: wireguard-conf label {d} never hit\n", .{i});
            return error.HarnessDoesNotReach;
        }
    }
}
