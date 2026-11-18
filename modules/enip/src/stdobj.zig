// SPDX-License-Identifier: MIT

//! The standard CIP objects a scanner or commissioning tool reads off every
//! EtherNet/IP device, as the adapter serves them: the **TCP/IP Interface**
//! object (class `0xF5`, CIP Vol 2 ch. 5-4) and the **Ethernet Link** object
//! (class `0xF6`, ch. 5-5).
//!
//! Everything here is pure: the values come from the caller's configuration
//! (no operating-system call, no clock, no socket) and the functions turn an
//! attribute number into reply octets, or a `Set_Attribute_Single` payload
//! into a general status. The adapter owns the routing and the CIP framing.
//!
//! Encodings follow CIP Vol 2 and the way OpENer (BSD-style licence, source
//! read for the wire format only), EIPScanner (MIT) and pycomm3 (MIT) read
//! them:
//!
//! * an IPv4 address is a `UDINT` whose value is the address read as a
//!   big-endian number (`192.168.1.1` is `0xC0A80101`), so on the wire, which
//!   is little-endian, it is `01 01 A8 C0`;
//! * a `STRING` is a 16-bit length then the octets, and an odd-length one is
//!   followed by one zero pad octet (OpENer's `EncodeCipString`, Vol 2's
//!   word alignment of attribute 5);
//! * the Physical Link Object attribute is a 16-bit path size in words then a
//!   padded EPATH (`20 F6 24 <instance>`), or size 0 for no link.

const std = @import("std");
const cip = @import("cip.zig");

pub const Error = error{TooLong};

/// Vol 2 Table 5-4.3: the domain name is at most 48 octets, the host name at
/// most 64 (RFC 1123, OpENer's limits).
pub const max_domain_name: usize = 48;
pub const max_host_name: usize = 64;

/// Instance attribute numbers (Vol 2 Table 5-4.3).
pub const TcpIpAttr = struct {
    pub const status: u16 = 1;
    pub const configuration_capability: u16 = 2;
    pub const configuration_control: u16 = 3;
    pub const physical_link_object: u16 = 4;
    pub const interface_configuration: u16 = 5;
    pub const host_name: u16 = 6;
};

/// Bit of the Status attribute: an interface configuration change waits for a
/// reset (Vol 2: "Interface Configuration Pending").
pub const status_config_pending: u32 = 0x10;
/// Configuration Capability bit 4: "Configuration Settable".
pub const capability_settable: u32 = 0x10;
const control_method_mask: u32 = 0x0F;
const control_dns_enable: u32 = 0x10;

/// What the TCP/IP Interface object (instance 1) reports. All of it is
/// caller-supplied; nothing is read from the operating system.
pub const TcpIpConfig = struct {
    /// Attribute 1. Default `1`: the configuration was obtained from stored
    /// (non-volatile) data, which is what a statically configured device says.
    status: u32 = 0x0000_0001,
    /// Attribute 2. Default `0`: no DHCP, BOOTP or DNS client. The
    /// "Configuration Settable" bit is added automatically when the adapter
    /// is configured to accept `Set_Attribute_Single`.
    configuration_capability: u32 = 0,
    /// Attribute 3, the start-up value: bits 0-3 the method (`0` stored,
    /// `1` BOOTP, `2` DHCP), bit 4 DNS enable.
    configuration_control: u32 = 0,
    /// Attribute 4: the Ethernet Link instance the interface sits on
    /// (`20 F6 24 <n>`); `0` reports an empty path.
    physical_link_instance: u8 = 1,
    /// Attribute 5 (interface configuration).
    ip_address: [4]u8 = @splat(0),
    network_mask: [4]u8 = @splat(0),
    gateway: [4]u8 = @splat(0),
    name_server: [4]u8 = @splat(0),
    name_server_2: [4]u8 = @splat(0),
    domain_name: []const u8 = "",
    /// Attribute 6.
    host_name: []const u8 = "",
};

/// What a successful `Set_Attribute_Single` changed. Starts as "nothing
/// changed", so the configured values are what is reported.
pub const TcpIpState = struct {
    control: ?u32 = null,
    iface_set: bool = false,
    addrs: [5][4]u8 = undefined,
    domain_buf: [max_domain_name]u8 = undefined,
    domain_len: usize = 0,
    host_set: bool = false,
    host_buf: [max_host_name]u8 = undefined,
    host_len: usize = 0,
    pending: bool = false,

    fn domain(self: *const TcpIpState, cfg: TcpIpConfig) []const u8 {
        return if (self.iface_set) self.domain_buf[0..self.domain_len] else cfg.domain_name;
    }

    fn host(self: *const TcpIpState, cfg: TcpIpConfig) []const u8 {
        return if (self.host_set) self.host_buf[0..self.host_len] else cfg.host_name;
    }

    fn addr(self: *const TcpIpState, cfg: TcpIpConfig, i: usize) [4]u8 {
        if (self.iface_set) return self.addrs[i];
        return switch (i) {
            0 => cfg.ip_address,
            1 => cfg.network_mask,
            2 => cfg.gateway,
            3 => cfg.name_server,
            else => cfg.name_server_2,
        };
    }

    fn controlValue(self: *const TcpIpState, cfg: TcpIpConfig) u32 {
        return self.control orelse cfg.configuration_control;
    }
};

fn putU16(buf: []u8, v: u16) void {
    std.mem.writeInt(u16, buf[0..2], v, .little);
}

fn putU32(buf: []u8, v: u32) void {
    std.mem.writeInt(u32, buf[0..4], v, .little);
}

/// A `STRING`: length, octets, pad to an even length. Returns the octets used.
fn putString(buf: []u8, s: []const u8, limit: usize) Error!usize {
    if (s.len > limit) return error.TooLong;
    putU16(buf, @intCast(s.len));
    @memcpy(buf[2..][0..s.len], s);
    if (s.len & 1 != 0) {
        buf[2 + s.len] = 0;
        return 3 + s.len;
    }
    return 2 + s.len;
}

/// Writes attribute `attr` of the TCP/IP Interface object into `buf` (at
/// least 256 octets) and returns its length, or `null` when the attribute is
/// not served.
pub fn tcpipAttribute(
    cfg: TcpIpConfig,
    st: *const TcpIpState,
    settable: bool,
    attr: u16,
    buf: []u8,
) Error!?usize {
    switch (attr) {
        TcpIpAttr.status => {
            putU32(buf, cfg.status | if (st.pending) status_config_pending else 0);
            return 4;
        },
        TcpIpAttr.configuration_capability => {
            putU32(buf, cfg.configuration_capability | if (settable) capability_settable else 0);
            return 4;
        },
        TcpIpAttr.configuration_control => {
            putU32(buf, st.controlValue(cfg));
            return 4;
        },
        TcpIpAttr.physical_link_object => {
            if (cfg.physical_link_instance == 0) {
                putU16(buf, 0);
                return 2;
            }
            putU16(buf, 2);
            buf[2] = 0x20;
            buf[3] = @intCast(@backingInt(cip.ClassCode.ethernet_link));
            buf[4] = 0x24;
            buf[5] = cfg.physical_link_instance;
            return 6;
        },
        TcpIpAttr.interface_configuration => {
            var off: usize = 0;
            for (0..5) |i| {
                putU32(buf[off..], std.mem.readInt(u32, &st.addr(cfg, i), .big));
                off += 4;
            }
            return off + try putString(buf[off..], st.domain(cfg), max_domain_name);
        },
        TcpIpAttr.host_name => return try putString(buf, st.host(cfg), max_host_name),
        else => return null,
    }
}

/// The attributes a `Get_Attributes_All` returns, in numeric order: the six
/// Vol 2 marks required (1 to 6). Returns the total length.
pub fn tcpipAll(cfg: TcpIpConfig, st: *const TcpIpState, settable: bool, buf: []u8) Error!usize {
    var off: usize = 0;
    var attr: u16 = TcpIpAttr.status;
    while (attr <= TcpIpAttr.host_name) : (attr += 1) {
        off += (try tcpipAttribute(cfg, st, settable, attr, buf[off..])).?;
    }
    return off;
}

fn isAlnum(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9');
}

/// RFC 1123 label as OpENer checks it: alphanumeric first and last octet,
/// letters, digits and `-` between, at least one octet.
fn validLabel(s: []const u8) bool {
    if (s.len == 0 or !isAlnum(s[0]) or !isAlnum(s[s.len - 1])) return false;
    for (s) |c| if (!isAlnum(c) and c != '-') return false;
    return true;
}

/// A dot-separated list of labels; no leading, trailing or doubled dot.
fn validDomain(s: []const u8) bool {
    if (s.len == 0) return true;
    var it = std.mem.splitScalar(u8, s, '.');
    while (it.next()) |label| if (!validLabel(label)) return false;
    return true;
}

fn validMask(mask: u32) bool {
    const host_span = ~mask +% 1;
    return host_span != 0 and host_span & (host_span - 1) == 0 and mask != 0xFFFF_FFFF;
}

fn networkOrBroadcast(ip: u32, mask: u32) bool {
    return ip & mask == ip or ip | ~mask == ip;
}

/// OpENer's `IsValidNetworkConfig` (Vol 2 Table 5-4.3 hints): the address is
/// set, not loopback, in class A/B/C and neither the network nor the
/// broadcast address; the mask is zero or a contiguous prefix; a gateway is
/// in class A/B/C, not loopback, not network/broadcast and on the same
/// network; the name servers are in class A/B/C.
fn validInterface(a: [5]u32) bool {
    const ip = a[0];
    const mask = a[1];
    const gw = a[2];
    if (ip == 0) return false;
    if (mask != 0 and !validMask(mask)) return false;
    for ([_]u32{ ip, gw, a[3], a[4] }) |x| if (x >= 0xE000_0000) return false;
    if (ip >> 24 == 127 or gw >> 24 == 127) return false;
    if (networkOrBroadcast(ip, mask)) return false;
    if (gw != 0) {
        if (networkOrBroadcast(gw, mask)) return false;
        if (mask != 0 and mask & ip != mask & gw) return false;
    }
    return true;
}

/// The octets a counted `STRING` field occupies, or the status that refuses
/// them: `data.len` must be the length prefix plus the string, with or
/// without the pad octet.
fn stringField(data: []const u8, at: usize, limit: usize) union(enum) { ok: []const u8, status: cip.GeneralStatus } {
    if (data.len < at + 2) return .{ .status = .not_enough_data };
    const n: usize = std.mem.readInt(u16, data[at..][0..2], .little);
    if (n > limit) return .{ .status = .too_much_data };
    if (data.len < at + 2 + n) return .{ .status = .not_enough_data };
    if (data.len > at + 2 + n + (n & 1)) return .{ .status = .too_much_data };
    return .{ .ok = data[at + 2 ..][0..n] };
}

/// `Set_Attribute_Single` on the TCP/IP Interface object: `success`, or the
/// general status that refuses it. Only attributes 3, 5 and 6 can be set, and
/// only when `settable`; everything else the object serves is read-only
/// (`attribute_not_settable`), anything it does not serve is
/// `attribute_not_supported`.
pub fn tcpipSet(
    cfg: TcpIpConfig,
    st: *TcpIpState,
    settable: bool,
    attr: u16,
    data: []const u8,
) cip.GeneralStatus {
    switch (attr) {
        TcpIpAttr.status,
        TcpIpAttr.configuration_capability,
        TcpIpAttr.physical_link_object,
        => return .attribute_not_settable,
        TcpIpAttr.configuration_control => {
            if (!settable) return .attribute_not_settable;
            if (data.len < 4) return .not_enough_data;
            if (data.len > 4) return .too_much_data;
            const v = std.mem.readInt(u32, data[0..4], .little);
            if (v & control_method_mask >= 3 or v & ~(control_method_mask | control_dns_enable) != 0)
                return .invalid_attribute_value;
            st.control = v;
            return .success;
        },
        TcpIpAttr.interface_configuration => {
            if (!settable) return .attribute_not_settable;
            // Only a statically configured interface takes an address.
            if (st.controlValue(cfg) & control_method_mask != 0) return .object_state_conflict;
            const domain = switch (stringField(data, 20, max_domain_name)) {
                .ok => |s| s,
                .status => |s| return s,
            };
            var a: [5]u32 = undefined;
            for (0..5) |i| a[i] = std.mem.readInt(u32, data[i * 4 ..][0..4], .little);
            if (!validInterface(a) or !validDomain(domain)) return .invalid_attribute_value;
            for (0..5) |i| std.mem.writeInt(u32, &st.addrs[i], a[i], .big);
            @memcpy(st.domain_buf[0..domain.len], domain);
            st.domain_len = domain.len;
            st.iface_set = true;
            st.pending = true;
            return .success;
        },
        TcpIpAttr.host_name => {
            if (!settable) return .attribute_not_settable;
            const name = switch (stringField(data, 0, max_host_name)) {
                .ok => |s| s,
                .status => |s| return s,
            };
            if (!validLabel(name)) return .invalid_attribute_value;
            @memcpy(st.host_buf[0..name.len], name);
            st.host_len = name.len;
            st.host_set = true;
            st.pending = true;
            return .success;
        },
        else => return .attribute_not_supported,
    }
}

/// Instance attribute numbers of the Ethernet Link object (Vol 2 ch. 5-5).
pub const EthLinkAttr = struct {
    pub const interface_speed: u16 = 1;
    pub const interface_flags: u16 = 2;
    pub const physical_address: u16 = 3;
};

/// What the Ethernet Link object (instance 1) reports: the three attributes
/// Vol 2 marks required. The counters (4, 5), interface control (6) and the
/// rest are optional and not served (`attribute_not_supported`). All values
/// are the caller's; nothing is read from the operating system.
pub const EthLinkConfig = struct {
    /// Attribute 1, in Mbit/s (`0` when unknown or autonegotiating).
    interface_speed: u32 = 100,
    /// Attribute 2: bit 0 link active, bit 1 full duplex, bits 2-4 the
    /// autonegotiation status (`3`: speed and duplex determined), bit 5
    /// manual setting requires reset, bit 6 local hardware fault. Default
    /// `0x0F`: link up, full duplex, autonegotiation succeeded.
    interface_flags: u32 = 0x0000_000F,
    /// Attribute 3, six octets in transmission order. The default is a
    /// locally administered address, a placeholder to be set.
    physical_address: [6]u8 = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
};

/// Writes attribute `attr` of the Ethernet Link object into `buf` and returns
/// its length, or `null` when the attribute is not served.
pub fn ethLinkAttribute(cfg: EthLinkConfig, attr: u16, buf: []u8) ?usize {
    switch (attr) {
        EthLinkAttr.interface_speed => {
            putU32(buf, cfg.interface_speed);
            return 4;
        },
        EthLinkAttr.interface_flags => {
            putU32(buf, cfg.interface_flags);
            return 4;
        },
        EthLinkAttr.physical_address => {
            @memcpy(buf[0..6], &cfg.physical_address);
            return 6;
        },
        else => return null,
    }
}

/// `Get_Attributes_All`: attributes 1 to 3 in order.
pub fn ethLinkAll(cfg: EthLinkConfig, buf: []u8) usize {
    var off: usize = 0;
    var attr: u16 = EthLinkAttr.interface_speed;
    while (attr <= EthLinkAttr.physical_address) : (attr += 1) {
        off += ethLinkAttribute(cfg, attr, buf[off..]).?;
    }
    return off;
}

// ── Assembly object (class 0x04, CIP Vol 1 ch. 5-5) ─────────────────────────

/// Class revision the Assembly object reports. Vol 1 fixes it at `2`
/// (OpENer: "according to the CIP spec currently this has to be 2").
pub const assembly_revision: u16 = 2;
/// Highest class attribute number reported (class attribute 6) and highest
/// instance attribute number (class attribute 7), as OpENer's class object
/// builds them for the Assembly class.
pub const assembly_max_class_attribute: u16 = 7;
pub const assembly_max_instance_attribute: u16 = 4;

/// Instance attribute numbers (Vol 1 Table 5-5.2): 3 is the data (a byte
/// array, `Get` and `Set`), 4 its size in octets (`UINT`, `Get` only).
pub const AssemblyAttr = struct {
    pub const data: u16 = 3;
    pub const size: u16 = 4;
};

/// One Assembly instance, defined by the caller. The octets live in the
/// caller's memory: a read answers with the buffer as it is, a successful
/// `Set_Attribute_Single` overwrites it, so the application publishes its
/// outputs and reads its inputs by touching the same bytes.
pub const Assembly = struct {
    /// Instance id, `1` to `65535` (`0` is the class itself and is never
    /// served; a repeated id is answered from its first entry).
    instance: u16,
    /// Attribute 3. Its length is attribute 4 and the only size a
    /// `Set_Attribute_Single` accepts. At most 65535 octets (the size is a
    /// `UINT`); a longer buffer is not served.
    data: []u8,
    /// Whether `Set_Attribute_Single` may write attribute 3. A read-only
    /// instance answers `attribute_not_settable`, like an input assembly.
    writable: bool = false,
    /// Handed back to both hooks.
    ctx: ?*anyopaque = null,
    /// Called before attribute 3 is read, so the application can refresh the
    /// buffer (OpENer's `BeforeAssemblyDataSend`).
    before_get: ?*const fn (ctx: ?*anyopaque, data: []u8) void = null,
    /// Called after a `Set_Attribute_Single` has overwritten the buffer
    /// (OpENer's `AfterAssemblyDataReceived`). Returning `false` answers
    /// `invalid_attribute_value`; as in OpENer the octets are already stored.
    after_set: ?*const fn (ctx: ?*anyopaque, data: []const u8) bool = null,
};

/// The served instance `id`, or `null` (instance 0, an unknown id, a buffer
/// that does not fit the `UINT` size attribute).
pub fn assemblyFind(list: []const Assembly, id: u32) ?*const Assembly {
    if (id == 0 or id > std.math.maxInt(u16)) return null;
    for (list) |*a| {
        if (a.instance == id and a.data.len <= std.math.maxInt(u16)) return a;
    }
    return null;
}

/// Writes class attribute `attr` of the Assembly class (instance 0) into
/// `buf`, or returns `null` when it is not served. As OpENer: 1 revision,
/// 2 largest instance id, 3 number of instances, 6 highest class attribute,
/// 7 highest instance attribute, all `UINT`; the optional-attribute lists (4,
/// 5) are not readable singly.
pub fn assemblyClassAttribute(list: []const Assembly, attr: u16, buf: []u8) ?usize {
    var max: u16 = 0;
    var count: u16 = 0;
    for (list, 0..) |a, i| {
        if (assemblyFind(list, a.instance) != &list[i]) continue;
        count += 1;
        max = @max(max, a.instance);
    }
    const v: u16 = switch (attr) {
        1 => assembly_revision,
        2 => max,
        3 => count,
        6 => assembly_max_class_attribute,
        7 => assembly_max_instance_attribute,
        else => return null,
    };
    putU16(buf, v);
    return 2;
}

/// The general status of `Set_Attribute_Single` on attribute `attr` of `a`
/// with `data`, storing the octets when it succeeds. The order is OpENer's:
/// the attribute must exist (`0x14`), be settable (`0x0E`), then the length
/// must match exactly (`0x13` too short, `0x15` too long), then the hook.
pub fn assemblySet(a: *const Assembly, attr: u16, data: []const u8) cip.GeneralStatus {
    if (attr != AssemblyAttr.data and attr != AssemblyAttr.size) return .attribute_not_supported;
    if (attr == AssemblyAttr.size or !a.writable) return .attribute_not_settable;
    if (data.len < a.data.len) return .not_enough_data;
    if (data.len > a.data.len) return .too_much_data;
    @memcpy(a.data, data);
    if (a.after_set) |hook| {
        if (!hook(a.ctx, a.data)) return .invalid_attribute_value;
    }
    return .success;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn be(a: u8, b: u8, c: u8, d: u8) u32 {
    return std.mem.readInt(u32, &[4]u8{ a, b, c, d }, .big);
}

test "validInterface: each rule refuses on its own and a plain configuration passes" {
    const ok = [5]u32{ be(192, 168, 1, 10), be(255, 255, 255, 0), be(192, 168, 1, 1), be(8, 8, 8, 8), 0 };
    try testing.expect(validInterface(ok));
    var a = ok;
    a[0] = 0; // no address
    try testing.expect(!validInterface(a));
    a = ok;
    a[1] = be(255, 0, 255, 0); // not a prefix
    try testing.expect(!validInterface(a));
    a = ok;
    a[1] = 0xFFFF_FFFF; // /32 is not a network mask
    try testing.expect(!validInterface(a));
    a = ok;
    a[1] = 0; // no mask is allowed (and then the gateway is not checked against it)
    a[2] = be(10, 0, 0, 1);
    try testing.expect(validInterface(a));
    a = ok;
    a[0] = be(224, 0, 0, 1); // multicast is not class A/B/C
    try testing.expect(!validInterface(a));
    a = ok;
    a[0] = be(223, 255, 255, 10); // the last class C address is fine...
    a[2] = be(223, 255, 255, 1);
    try testing.expect(validInterface(a));
    a[0] = be(224, 0, 0, 0); // ...and the first of class D is not
    try testing.expect(!validInterface(a));
    a = ok;
    a[2] = be(224, 0, 0, 0);
    try testing.expect(!validInterface(a));
    a = ok;
    a[3] = be(224, 0, 0, 0);
    try testing.expect(!validInterface(a));
    a = ok;
    a[3] = be(240, 0, 0, 1); // nor is a name server there
    try testing.expect(!validInterface(a));
    a = ok;
    a[4] = be(224, 0, 0, 1);
    try testing.expect(!validInterface(a));
    a = ok;
    a[0] = be(127, 0, 0, 1);
    a[2] = 0;
    try testing.expect(!validInterface(a)); // loopback address
    a = ok;
    a[2] = be(127, 0, 0, 1);
    try testing.expect(!validInterface(a)); // loopback gateway
    a = ok;
    a[0] = be(192, 168, 1, 0); // network address
    try testing.expect(!validInterface(a));
    a = ok;
    a[0] = be(192, 168, 1, 255); // broadcast address
    try testing.expect(!validInterface(a));
    a = ok;
    a[1] = 0; // without a mask only the class and loopback rules can refuse the gateway
    a[2] = be(224, 0, 0, 1);
    try testing.expect(!validInterface(a));
    a[2] = be(127, 0, 0, 1);
    try testing.expect(!validInterface(a));
    a[2] = be(10, 0, 0, 1);
    try testing.expect(validInterface(a));
    a = ok;
    a[2] = be(192, 168, 1, 255); // gateway is the broadcast address
    try testing.expect(!validInterface(a));
    a = ok;
    a[2] = be(192, 168, 1, 0); // gateway is the network address
    try testing.expect(!validInterface(a));
    a = ok;
    a[2] = be(192, 168, 2, 1); // gateway off the network
    try testing.expect(!validInterface(a));
    a = ok;
    a[2] = 0; // no gateway
    try testing.expect(validInterface(a));
}

test "host names and domains follow RFC 1123 labels" {
    try testing.expect(validLabel("plc-1"));
    try testing.expect(validLabel("a"));
    // every edge of the three alphanumeric ranges
    try testing.expect(validLabel("azAZ09"));
    try testing.expect(validLabel("0-9"));
    for ([_]u8{ '`', '{', '@', '[', '/', ':' }) |c| {
        try testing.expect(!validLabel(&.{ 'a', c, 'a' }));
        try testing.expect(!validLabel(&.{c}));
    }
    try testing.expect(!validLabel(""));
    try testing.expect(!validLabel("-a"));
    try testing.expect(!validLabel("a-"));
    try testing.expect(!validLabel("a_b"));
    try testing.expect(!validLabel("a.b"));
    try testing.expect(validDomain(""));
    try testing.expect(validDomain("example.com"));
    try testing.expect(!validDomain(".example"));
    try testing.expect(!validDomain("example."));
    try testing.expect(!validDomain("a..b"));
    try testing.expect(!validDomain("."));
}

test "tcpip attributes: encodings of the six required ones" {
    const cfg: TcpIpConfig = .{
        .status = 1,
        .configuration_capability = 0x04,
        .configuration_control = 0x02,
        .ip_address = .{ 192, 168, 1, 10 },
        .network_mask = .{ 255, 255, 255, 0 },
        .gateway = .{ 192, 168, 1, 1 },
        .name_server = .{ 8, 8, 8, 8 },
        .name_server_2 = .{ 8, 8, 4, 4 },
        .domain_name = "lan",
        .host_name = "plc01",
    };
    const st: TcpIpState = .{};
    var b: [256]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 1, 0, 0, 0 }, b[0..(try tcpipAttribute(cfg, &st, false, 1, &b)).?]);
    try testing.expectEqualSlices(u8, &.{ 4, 0, 0, 0 }, b[0..(try tcpipAttribute(cfg, &st, false, 2, &b)).?]);
    try testing.expectEqualSlices(u8, &.{ 0x14, 0, 0, 0 }, b[0..(try tcpipAttribute(cfg, &st, true, 2, &b)).?]);
    try testing.expectEqualSlices(u8, &.{ 2, 0, 0, 0 }, b[0..(try tcpipAttribute(cfg, &st, false, 3, &b)).?]);
    try testing.expectEqualSlices(u8, &.{ 2, 0, 0x20, 0xF6, 0x24, 1 }, b[0..(try tcpipAttribute(cfg, &st, false, 4, &b)).?]);
    try testing.expectEqualSlices(u8, &.{
        10, 1, 0xA8, 0xC0, // ip
        0, 255, 255, 255, // mask... little-endian of 0xFFFFFF00
        1, 1, 0xA8, 0xC0, // gateway
        8, 8, 8, 8, // ns 1
        4, 4, 8,   8, // ns 2
        3, 0, 'l', 'a',
        'n', 0, // odd length: padded
    }, b[0..(try tcpipAttribute(cfg, &st, false, 5, &b)).?]);
    try testing.expectEqualSlices(u8, &.{ 5, 0, 'p', 'l', 'c', '0', '1', 0 }, b[0..(try tcpipAttribute(cfg, &st, false, 6, &b)).?]);
    try testing.expectEqual(@as(?usize, null), try tcpipAttribute(cfg, &st, false, 7, &b));
    try testing.expectEqual(@as(?usize, null), try tcpipAttribute(cfg, &st, false, 0, &b));
    // no physical link: empty path
    var nolink = cfg;
    nolink.physical_link_instance = 0;
    try testing.expectEqualSlices(u8, &.{ 0, 0 }, b[0..(try tcpipAttribute(nolink, &st, false, 4, &b)).?]);
    // even-length strings carry no pad
    var even = cfg;
    even.host_name = "ab";
    try testing.expectEqualSlices(u8, &.{ 2, 0, 'a', 'b' }, b[0..(try tcpipAttribute(even, &st, false, 6, &b)).?]);
    // over-long strings are refused rather than truncated
    var long = cfg;
    const a65: [65]u8 = @splat('a');
    long.host_name = &a65;
    try testing.expectError(error.TooLong, tcpipAttribute(long, &st, false, 6, &b));
    long.host_name = a65[0..64];
    try testing.expectEqual(@as(?usize, 66), try tcpipAttribute(long, &st, false, 6, &b));
    long.domain_name = a65[0..49];
    try testing.expectError(error.TooLong, tcpipAttribute(long, &st, false, 5, &b));
    long.domain_name = a65[0..48];
    try testing.expectEqual(@as(?usize, 20 + 2 + 48), try tcpipAttribute(long, &st, false, 5, &b));
}

test "tcpipAll concatenates attributes 1 to 6" {
    const cfg: TcpIpConfig = .{ .host_name = "h" };
    const st: TcpIpState = .{};
    var b: [256]u8 = undefined;
    const n = try tcpipAll(cfg, &st, false, &b);
    // 4+4+4 + (2+4) + (20+2) + (2+1+1)
    try testing.expectEqual(@as(usize, 12 + 6 + 22 + 4), n);
    try testing.expectEqualSlices(u8, &.{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, b[0..12]);
    try testing.expectEqualSlices(u8, &.{ 1, 0, 'h', 0 }, b[n - 4 .. n]);
}

test "tcpipSet: refused unless enabled, and the refusal order" {
    const cfg: TcpIpConfig = .{};
    var st: TcpIpState = .{};
    const four = [_]u8{ 0, 0, 0, 0 };
    for ([_]u16{ 3, 5, 6 }) |a| {
        try testing.expectEqual(cip.GeneralStatus.attribute_not_settable, tcpipSet(cfg, &st, false, a, &four));
    }
    for ([_]u16{ 1, 2, 4 }) |a| {
        try testing.expectEqual(cip.GeneralStatus.attribute_not_settable, tcpipSet(cfg, &st, true, a, &four));
        try testing.expectEqual(cip.GeneralStatus.attribute_not_settable, tcpipSet(cfg, &st, false, a, &four));
    }
    for ([_]u16{ 0, 7, 13, 0x14 }) |a| {
        try testing.expectEqual(cip.GeneralStatus.attribute_not_supported, tcpipSet(cfg, &st, true, a, &four));
    }
    try testing.expectEqual(@as(?u32, null), st.control);
}

test "tcpipSet attribute 3: length, reserved values and the stored result" {
    const cfg: TcpIpConfig = .{};
    var st: TcpIpState = .{};
    try testing.expectEqual(cip.GeneralStatus.not_enough_data, tcpipSet(cfg, &st, true, 3, &.{ 2, 0, 0 }));
    try testing.expectEqual(cip.GeneralStatus.too_much_data, tcpipSet(cfg, &st, true, 3, &.{ 2, 0, 0, 0, 0 }));
    try testing.expectEqual(cip.GeneralStatus.invalid_attribute_value, tcpipSet(cfg, &st, true, 3, &.{ 3, 0, 0, 0 }));
    try testing.expectEqual(cip.GeneralStatus.invalid_attribute_value, tcpipSet(cfg, &st, true, 3, &.{ 0x0F, 0, 0, 0 }));
    try testing.expectEqual(cip.GeneralStatus.invalid_attribute_value, tcpipSet(cfg, &st, true, 3, &.{ 2, 0x20, 0, 0 }));
    try testing.expectEqual(cip.GeneralStatus.invalid_attribute_value, tcpipSet(cfg, &st, true, 3, &.{ 2, 0, 0, 0x80 }));
    try testing.expectEqual(@as(?u32, null), st.control);
    try testing.expectEqual(cip.GeneralStatus.success, tcpipSet(cfg, &st, true, 3, &.{ 0x12, 0, 0, 0 }));
    try testing.expectEqual(@as(?u32, 0x12), st.control);
    try testing.expectEqual(cip.GeneralStatus.success, tcpipSet(cfg, &st, true, 3, &.{ 0, 0, 0, 0 }));
    try testing.expectEqual(@as(?u32, 0), st.control);
    try testing.expect(!st.pending);
}

fn ifaceData(buf: []u8, dom: []const u8, pad: bool) []u8 {
    const words = [5]u32{ be(10, 0, 0, 7), be(255, 255, 0, 0), be(10, 0, 0, 1), be(1, 1, 1, 1), 0 };
    for (words, 0..) |w, i| putU32(buf[i * 4 ..], w);
    putU16(buf[20..], @intCast(dom.len));
    @memcpy(buf[22..][0..dom.len], dom);
    var n = 22 + dom.len;
    if (pad) {
        buf[n] = 0;
        n += 1;
    }
    return buf[0..n];
}

test "tcpipSet attribute 5: needs a static method, validates, records and marks pending" {
    const cfg: TcpIpConfig = .{ .configuration_control = 2 };
    var st: TcpIpState = .{};
    var buf: [128]u8 = undefined;
    // DHCP-configured: the interface does not take a stored address.
    try testing.expectEqual(cip.GeneralStatus.object_state_conflict, tcpipSet(cfg, &st, true, 5, ifaceData(&buf, "lan", true)));
    try testing.expect(!st.iface_set);
    // Switch to the static method first.
    try testing.expectEqual(cip.GeneralStatus.success, tcpipSet(cfg, &st, true, 3, &.{ 0, 0, 0, 0 }));
    try testing.expectEqual(cip.GeneralStatus.not_enough_data, tcpipSet(cfg, &st, true, 5, buf[0..21]));
    try testing.expectEqual(cip.GeneralStatus.not_enough_data, tcpipSet(cfg, &st, true, 5, ifaceData(&buf, "lan", true)[0..23]));
    try testing.expectEqual(cip.GeneralStatus.too_much_data, tcpipSet(cfg, &st, true, 5, buf[0..28]));
    // Odd-length domain accepted with or without its pad octet.
    var d2: [128]u8 = undefined;
    try testing.expectEqual(cip.GeneralStatus.success, tcpipSet(cfg, &st, true, 5, ifaceData(&d2, "lan", false)));
    try testing.expectEqual(cip.GeneralStatus.success, tcpipSet(cfg, &st, true, 5, ifaceData(&d2, "lan", true)));
    // Even length with a stray pad is one octet too many.
    try testing.expectEqual(cip.GeneralStatus.too_much_data, tcpipSet(cfg, &st, true, 5, ifaceData(&d2, "ab", true)));
    // Domain over 48 octets.
    var big: [128]u8 = undefined;
    @memset(big[0..49], 'a');
    try testing.expectEqual(cip.GeneralStatus.too_much_data, tcpipSet(cfg, &st, true, 5, ifaceData(&d2, big[0..49], true)));
    try testing.expectEqual(cip.GeneralStatus.success, tcpipSet(cfg, &st, true, 5, ifaceData(&d2, big[0..48], false)));
    // Invalid values are refused and leave the last good one in place.
    try testing.expectEqual(cip.GeneralStatus.invalid_attribute_value, tcpipSet(cfg, &st, true, 5, ifaceData(&d2, "-x", false)));
    const zero_ip = ifaceData(&d2, "x", true);
    putU32(zero_ip[0..], 0);
    try testing.expectEqual(cip.GeneralStatus.invalid_attribute_value, tcpipSet(cfg, &st, true, 5, zero_ip));
    try testing.expect(st.iface_set and st.pending);
    try testing.expectEqual(@as(usize, 48), st.domain_len);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 7 }, &st.addrs[0]);
    try testing.expectEqualSlices(u8, &.{ 255, 255, 0, 0 }, &st.addrs[1]);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &st.addrs[2]);
    try testing.expectEqualSlices(u8, &.{ 1, 1, 1, 1 }, &st.addrs[3]);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &st.addrs[4]);
}

test "tcpipSet attribute 6: host name length, label rule, and the status bit" {
    const cfg: TcpIpConfig = .{};
    var st: TcpIpState = .{};
    try testing.expectEqual(cip.GeneralStatus.not_enough_data, tcpipSet(cfg, &st, true, 6, &.{1}));
    try testing.expectEqual(cip.GeneralStatus.not_enough_data, tcpipSet(cfg, &st, true, 6, &.{ 3, 0, 'a', 'b' }));
    try testing.expectEqual(cip.GeneralStatus.too_much_data, tcpipSet(cfg, &st, true, 6, &.{ 2, 0, 'a', 'b', 0 }));
    try testing.expectEqual(cip.GeneralStatus.too_much_data, tcpipSet(cfg, &st, true, 6, &.{ 1, 0, 'a', 0, 0 }));
    try testing.expectEqual(cip.GeneralStatus.too_much_data, tcpipSet(cfg, &st, true, 6, &.{ 65, 0 }));
    try testing.expectEqual(cip.GeneralStatus.invalid_attribute_value, tcpipSet(cfg, &st, true, 6, &.{ 0, 0 }));
    try testing.expectEqual(cip.GeneralStatus.invalid_attribute_value, tcpipSet(cfg, &st, true, 6, &.{ 2, 0, 'a', '-' }));
    try testing.expect(!st.host_set);
    try testing.expect(!st.pending);
    try testing.expectEqual(cip.GeneralStatus.success, tcpipSet(cfg, &st, true, 6, &.{ 1, 0, 'a', 0 }));
    try testing.expectEqual(cip.GeneralStatus.success, tcpipSet(cfg, &st, true, 6, &.{ 1, 0, 'b' }));
    try testing.expect(st.host_set and st.pending);
    try testing.expectEqualStrings("b", st.host(cfg));
    var b: [256]u8 = undefined;
    // the status attribute now reports the pending bit
    try testing.expectEqualSlices(u8, &.{ 0x11, 0, 0, 0 }, b[0..(try tcpipAttribute(cfg, &st, true, 1, &b)).?]);
    // the 64-octet name fits
    var full: [66]u8 = undefined;
    putU16(&full, 64);
    @memset(full[2..], 'z');
    try testing.expectEqual(cip.GeneralStatus.success, tcpipSet(cfg, &st, true, 6, &full));
    try testing.expectEqual(@as(usize, 64), st.host_len);
}

test "ethernet link attributes: encodings and the all-reply" {
    const cfg: EthLinkConfig = .{
        .interface_speed = 1000,
        .interface_flags = 0x0000_0003,
        .physical_address = .{ 0x00, 0x1D, 0x9C, 0xAA, 0xBB, 0xCC },
    };
    var b: [64]u8 = @splat(0xEE);
    try testing.expectEqualSlices(u8, &.{ 0xE8, 3, 0, 0 }, b[0..ethLinkAttribute(cfg, 1, &b).?]);
    try testing.expectEqualSlices(u8, &.{ 3, 0, 0, 0 }, b[0..ethLinkAttribute(cfg, 2, &b).?]);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x1D, 0x9C, 0xAA, 0xBB, 0xCC }, b[0..ethLinkAttribute(cfg, 3, &b).?]);
    for ([_]u16{ 0, 4, 5, 6, 7, 10, 0x14 }) |a| try testing.expectEqual(@as(?usize, null), ethLinkAttribute(cfg, a, &b));
    const n = ethLinkAll(cfg, &b);
    try testing.expectEqualSlices(u8, &.{ 0xE8, 3, 0, 0, 3, 0, 0, 0, 0x00, 0x1D, 0x9C, 0xAA, 0xBB, 0xCC }, b[0..n]);
    // the defaults: 100 Mbit/s, link up, full duplex, autonegotiated
    const d: EthLinkConfig = .{};
    try testing.expectEqual(@as(u32, 100), d.interface_speed);
    try testing.expectEqual(@as(u32, 0x0F), d.interface_flags);
    try testing.expectEqual(@as(u8, 0x02), d.physical_address[0] & 0x03);
}

test "assemblySet: the refusal order and what is stored" {
    var buf = [3]u8{ 1, 2, 3 };
    var ro_buf = [3]u8{ 1, 2, 3 };
    const w: Assembly = .{ .instance = 1, .data = &buf, .writable = true };
    const r: Assembly = .{ .instance = 2, .data = &ro_buf };
    // unknown attribute before anything else, even on a read-only instance
    try testing.expectEqual(cip.GeneralStatus.attribute_not_supported, assemblySet(&r, 5, &.{}));
    try testing.expectEqual(cip.GeneralStatus.attribute_not_supported, assemblySet(&w, 0, &.{ 1, 2, 3 }));
    try testing.expectEqual(cip.GeneralStatus.attribute_not_supported, assemblySet(&w, 2, &.{ 1, 2, 3 }));
    // not settable before the length is looked at
    try testing.expectEqual(cip.GeneralStatus.attribute_not_settable, assemblySet(&w, 4, &.{ 3, 0 }));
    try testing.expectEqual(cip.GeneralStatus.attribute_not_settable, assemblySet(&r, 3, &.{}));
    try testing.expectEqual(cip.GeneralStatus.attribute_not_settable, assemblySet(&r, 3, &.{ 9, 9, 9 }));
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, &ro_buf);
    // exact length only
    try testing.expectEqual(cip.GeneralStatus.not_enough_data, assemblySet(&w, 3, &.{ 7, 7 }));
    try testing.expectEqual(cip.GeneralStatus.too_much_data, assemblySet(&w, 3, &.{ 7, 7, 7, 7 }));
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, &buf);
    try testing.expectEqual(cip.GeneralStatus.success, assemblySet(&w, 3, &.{ 7, 8, 9 }));
    try testing.expectEqualSlices(u8, &.{ 7, 8, 9 }, &buf);
}

test "assemblyFind and class attributes: instance 0, repeats and oversize buffers" {
    var a = [1]u8{0};
    var b = [2]u8{ 0, 0 };
    const list = [_]Assembly{
        .{ .instance = 0, .data = &a },
        .{ .instance = 5, .data = &a },
        .{ .instance = 5, .data = &b },
        .{ .instance = 9, .data = &b },
    };
    try testing.expectEqual(@as(?*const Assembly, null), assemblyFind(&list, 0));
    try testing.expectEqual(@as(?*const Assembly, null), assemblyFind(&list, 6));
    try testing.expectEqual(@as(?*const Assembly, null), assemblyFind(&list, 0x10005));
    // the largest id a UINT holds is served
    const top = [_]Assembly{.{ .instance = 65535, .data = &a }};
    try testing.expectEqual(@as(*const Assembly, &top[0]), assemblyFind(&top, 65535).?);
    try testing.expectEqual(@as(*const Assembly, &list[1]), assemblyFind(&list, 5).?);
    var o: [2]u8 = undefined;
    try testing.expectEqual(@as(?usize, 2), assemblyClassAttribute(&list, 3, &o));
    try testing.expectEqualSlices(u8, &.{ 2, 0 }, &o); // 5 and 9; instance 0 and the repeat are not counted
    _ = assemblyClassAttribute(&list, 2, &o);
    try testing.expectEqualSlices(u8, &.{ 9, 0 }, &o);
    try testing.expectEqual(@as(?usize, null), assemblyClassAttribute(&list, 4, &o));
    try testing.expectEqual(@as(?usize, 2), assemblyClassAttribute(&.{}, 2, &o));
    try testing.expectEqualSlices(u8, &.{ 0, 0 }, &o);
}
