// SPDX-License-Identifier: MIT
//! `NL80211_CMD_CONNECT` / `NL80211_CMD_DISCONNECT` request building.
//!
//! ## Which association path this implements — read this before using it
//!
//! nl80211 offers three ways to get onto a network, and they are **not**
//! interchangeable:
//!
//! 1. **`CONNECT` with the SME in the driver/firmware.** One command carries
//!    the SSID, security parameters and (for WPA2-PSK) the PMK; the driver
//!    then runs authentication, association *and the 4-way handshake* itself.
//!    This is the path this module implements, and it works only on hardware
//!    whose firmware has an internal SME — most `mac80211`-based Wi-Fi chips do
//!    **not**.
//! 2. **`CONNECT` with `NL80211_ATTR_WANT_1X_4WAY_HS`**, where the driver does
//!    auth+assoc but hands the 4-way handshake to userspace over the control
//!    port. Building the request is in scope here; running the handshake is
//!    not.
//! 3. **`AUTHENTICATE` + `ASSOCIATE` + a userspace supplicant.** What
//!    `wpa_supplicant` does on ordinary mac80211 hardware: EAPOL frames,
//!    key derivation, PTK/GTK installation via `NL80211_CMD_NEW_KEY`, PMKSA
//!    caching, SAE, 802.1X/EAP.
//!
//! **Path 3 is out of scope and this module will not grow it.** A supplicant is
//! a large security-critical state machine (EAPOL-Key replay counters, PMKID
//! derivation, GTK rekeying, SAE's finite-field crypto) and shipping half of
//! one would be worse than shipping none. So: this module can *ask* the kernel
//! to connect, and on a driver with an internal SME that is sufficient; on
//! everything else the connect will be refused or will stall at the handshake,
//! and the honest answer is "run `wpa_supplicant` and use this module for
//! enumeration, scanning and statistics".
//!
//! Nothing here derives a PMK from a passphrase either — PBKDF2 over the SSID
//! is the caller's job (`std.crypto.pwhash.pbkdf2`), so no passphrase ever has
//! to enter this module.
//!
//! ## Provenance of the encodings
//!
//! The `CONNECT` (SSID / frequency / privacy / WEP `KEYS` nest) and
//! `DISCONNECT` attribute layouts here were verified byte-for-byte against
//! requests captured from `iw` (see `goldens.zig`). `iw` has no WPA2 mode, so
//! the WPA-specific attributes — `WPA_VERSIONS`, `CIPHER_SUITES_PAIRWISE`,
//! `CIPHER_SUITE_GROUP`, `AKM_SUITES`, `PMK`, `USE_MFP`, `WANT_1X_4WAY_HS` —
//! are **derived from the UAPI header**, not from a capture, and are covered
//! only by round-trip tests. That gap is stated again in SPEC.md.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const genl = @import("genetlink");
const uapi = @import("uapi.zig");

pub const BuildError = error{ OutOfMemory, InvalidRequest };

/// A WEP key for the legacy `NL80211_ATTR_KEYS` nest. WEP is broken; this
/// exists because `iw connect … key 0:…` is the capture the encoder was
/// validated against, not because anyone should use it.
pub const WepKey = struct {
    /// Key index 0–3.
    index: u8 = 0,
    /// 5 bytes (WEP-40) or 13 bytes (WEP-104).
    data: []const u8,
    /// Install as the default transmit key.
    default: bool = true,

    fn cipher(k: WepKey) BuildError!u32 {
        return switch (k.data.len) {
            5 => uapi.CIPHER.WEP40,
            13 => uapi.CIPHER.WEP104,
            else => error.InvalidRequest,
        };
    }
};

/// Parameters of a `NL80211_CMD_CONNECT`.
pub const ConnectOptions = struct {
    ifindex: u32,
    /// Raw SSID bytes, ≤ 32.
    ssid: []const u8,
    /// Pin the association to one AP.
    bssid: ?uapi.Mac = null,
    /// Previous BSSID, for a roam.
    prev_bssid: ?uapi.Mac = null,
    /// Restrict the association to one channel, MHz.
    freq_mhz: ?u32 = null,
    auth_type: ?uapi.AuthType = null,
    /// Set the 802.11 Privacy bit — required for WEP and for RSN.
    privacy: bool = false,
    /// `WPA_VERSION.@"2"` for WPA2, `| WPA_VERSION.@"3"` for WPA3.
    wpa_versions: ?u32 = null,
    /// Acceptable pairwise cipher suites (`CIPHER.CCMP`, …).
    ciphers_pairwise: []const u32 = &.{},
    cipher_group: ?u32 = null,
    /// Acceptable AKM suites (`AKM.PSK`, …).
    akm_suites: []const u32 = &.{},
    /// The 32-byte pairwise master key, for the driver-SME path (see the file
    /// header). Derive it with PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32).
    pmk: ?[]const u8 = null,
    /// Management frame protection policy.
    use_mfp: ?uapi.Mfp = null,
    /// Ask the driver to leave the 4-way handshake to userspace.
    want_1x_4way_hs: bool = false,
    /// Extra information elements for the association request.
    ie_bytes: []const u8 = &.{},
    /// Legacy WEP keys.
    wep_keys: []const WepKey = &.{},
    /// Tear the connection down when this netlink socket closes.
    socket_owner: bool = false,

    /// The ordinary WPA2-Personal shape: CCMP pairwise + group, AKM PSK, open
    /// authentication, privacy on, PMK supplied. Only useful on a driver with
    /// an internal SME — see the file header.
    pub fn wpa2Psk(ifindex: u32, ssid: []const u8, pmk: *const [uapi.pmk_len]u8) ConnectOptions {
        return .{
            .ifindex = ifindex,
            .ssid = ssid,
            .auth_type = .open_system,
            .privacy = true,
            .wpa_versions = uapi.WPA_VERSION.@"2",
            .ciphers_pairwise = &.{uapi.CIPHER.CCMP},
            .cipher_group = uapi.CIPHER.CCMP,
            .akm_suites = &.{uapi.AKM.PSK},
            .pmk = pmk,
            .use_mfp = .optional,
        };
    }

    /// An open (unencrypted) network.
    pub fn open(ifindex: u32, ssid: []const u8) ConnectOptions {
        return .{ .ifindex = ifindex, .ssid = ssid, .auth_type = .open_system };
    }
};

/// Build a complete `NL80211_CMD_CONNECT` request. Caller frees.
///
/// Attribute order matches `iw`'s so the golden comparison is meaningful;
/// netlink itself does not care about order.
pub fn buildConnect(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    opts: ConnectOptions,
) BuildError![]u8 {
    if (opts.ssid.len == 0 or opts.ssid.len > uapi.max_ssid_len) return error.InvalidRequest;
    if (opts.pmk) |p| {
        if (p.len != uapi.pmk_len) return error.InvalidRequest;
    }
    for (opts.wep_keys) |k| {
        _ = try k.cipher();
        if (k.index > 3) return error.InvalidRequest;
    }

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        family_id,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        seq,
        0,
    );
    try genl.appendHeader(gpa, &list, uapi.CMD.CONNECT, uapi.family_version);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.IFINDEX, opts.ifindex);
    try appendRaw(gpa, &list, uapi.ATTR.SSID, opts.ssid);
    if (opts.bssid) |m| try appendRaw(gpa, &list, uapi.ATTR.MAC, &m);
    if (opts.prev_bssid) |m| try appendRaw(gpa, &list, uapi.ATTR.PREV_BSSID, &m);
    if (opts.freq_mhz) |f| try codec.appendAttrU32(gpa, &list, uapi.ATTR.WIPHY_FREQ, f);
    if (opts.auth_type) |a|
        try codec.appendAttrU32(gpa, &list, uapi.ATTR.AUTH_TYPE, @intFromEnum(a));
    if (opts.ie_bytes.len != 0) try appendRaw(gpa, &list, uapi.ATTR.IE, opts.ie_bytes);
    if (opts.privacy) try appendRaw(gpa, &list, uapi.ATTR.PRIVACY, &.{});

    if (opts.wep_keys.len != 0) {
        // `iw` sets NLA_F_NESTED on both the KEYS container and each key —
        // matched here so the golden comparison is byte-exact (the kernel's
        // policy ignores the bit either way).
        const keys = try codec.nestBegin(gpa, &list, uapi.ATTR.KEYS | codec.NLA_F_NESTED);
        for (opts.wep_keys, 1..) |k, i| {
            if (i > std.math.maxInt(u16)) return error.InvalidRequest;
            const key_index: u16 = @intCast(i);
            const one = try codec.nestBegin(gpa, &list, key_index | codec.NLA_F_NESTED);
            try codec.appendAttrU8(gpa, &list, uapi.KEY.IDX, k.index);
            try codec.appendAttrU32(gpa, &list, uapi.KEY.CIPHER, try k.cipher());
            try appendRaw(gpa, &list, uapi.KEY.DATA, k.data);
            if (k.default) try appendRaw(gpa, &list, uapi.KEY.DEFAULT, &.{});
            codec.nestEnd(&list, one);
        }
        codec.nestEnd(&list, keys);
    }

    if (opts.wpa_versions) |v|
        try codec.appendAttrU32(gpa, &list, uapi.ATTR.WPA_VERSIONS, v);
    if (opts.ciphers_pairwise.len != 0)
        try appendU32Array(gpa, &list, uapi.ATTR.CIPHER_SUITES_PAIRWISE, opts.ciphers_pairwise);
    if (opts.cipher_group) |c|
        try codec.appendAttrU32(gpa, &list, uapi.ATTR.CIPHER_SUITE_GROUP, c);
    if (opts.akm_suites.len != 0)
        try appendU32Array(gpa, &list, uapi.ATTR.AKM_SUITES, opts.akm_suites);
    if (opts.use_mfp) |m|
        try codec.appendAttrU32(gpa, &list, uapi.ATTR.USE_MFP, @intFromEnum(m));
    if (opts.pmk) |p| try appendRaw(gpa, &list, uapi.ATTR.PMK, p);
    if (opts.want_1x_4way_hs) try appendRaw(gpa, &list, uapi.ATTR.WANT_1X_4WAY_HS, &.{});
    if (opts.socket_owner) try appendRaw(gpa, &list, uapi.ATTR.SOCKET_OWNER, &.{});

    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// 802.11 reason code 3, "deauthenticated because sending STA is leaving" —
/// what `iw` and `wpa_supplicant` send on a user-requested disconnect.
pub const reason_deauth_leaving: u16 = 3;

/// Build a `NL80211_CMD_DISCONNECT` request. `reason_code` of null omits the
/// attribute entirely, which is what `iw dev … disconnect` does.
pub fn buildDisconnect(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    ifindex: u32,
    reason_code: ?u16,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        family_id,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        seq,
        0,
    );
    try genl.appendHeader(gpa, &list, uapi.CMD.DISCONNECT, uapi.family_version);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.IFINDEX, ifindex);
    if (reason_code) |r| try codec.appendAttrU16(gpa, &list, uapi.ATTR.REASON_CODE, r);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

fn appendRaw(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    t: u16,
    data: []const u8,
) BuildError!void {
    codec.appendAttr(gpa, list, t, data) catch |e| switch (e) {
        error.AttrTooLong => return error.InvalidRequest,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// A flat array of u32s in one attribute — the shape
/// `NL80211_ATTR_CIPHER_SUITES_PAIRWISE` and `AKM_SUITES` use (not a nest).
fn appendU32Array(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    t: u16,
    values: []const u32,
) BuildError!void {
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(gpa);
    for (values) |v| {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .little);
        try raw.appendSlice(gpa, &b);
    }
    try appendRaw(gpa, list, t, raw.items);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Walk a built request and return the payload of the first attribute of
/// `want`, or null.
fn attrOf(msg: []const u8, want: u16) !?[]const u8 {
    var it: codec.MessageIterator = .{ .buf = msg };
    const m = (try it.next()).?;
    var attrs: codec.AttrIterator = .{ .buf = m.payload[genl.header_len..] };
    while (try attrs.next()) |a| {
        if (a.type == want) return a.data;
    }
    return null;
}

test "buildConnect rejects malformed parameters" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidRequest, buildConnect(gpa, 41, 1, .{
        .ifindex = 3,
        .ssid = "",
    }));
    const long: [33]u8 = @splat('x');
    try testing.expectError(error.InvalidRequest, buildConnect(gpa, 41, 1, .{
        .ifindex = 3,
        .ssid = &long,
    }));
    // A PMK of the wrong length.
    try testing.expectError(error.InvalidRequest, buildConnect(gpa, 41, 1, .{
        .ifindex = 3,
        .ssid = "net",
        .pmk = &[_]u8{0} ** 16,
    }));
    // A WEP key that is neither 5 nor 13 bytes.
    try testing.expectError(error.InvalidRequest, buildConnect(gpa, 41, 1, .{
        .ifindex = 3,
        .ssid = "net",
        .wep_keys = &.{.{ .data = "abcdef" }},
    }));
    // A WEP key index out of range.
    try testing.expectError(error.InvalidRequest, buildConnect(gpa, 41, 1, .{
        .ifindex = 3,
        .ssid = "net",
        .wep_keys = &.{.{ .index = 4, .data = "abcde" }},
    }));
}

test "buildConnect: SSID is raw bytes, not a NUL-terminated string" {
    const gpa = testing.allocator;
    const req = try buildConnect(gpa, 41, 1, .open(3, "TestNet"));
    defer gpa.free(req);
    const ssid = (try attrOf(req, uapi.ATTR.SSID)).?;
    try testing.expectEqualStrings("TestNet", ssid); // 7 bytes, no NUL
    try testing.expectEqual(@as(usize, 7), ssid.len);
}

test "buildConnect: WPA2-PSK carries the full security parameter set" {
    const gpa = testing.allocator;
    const pmk: [32]u8 = @splat(0xa5);
    const req = try buildConnect(gpa, 41, 9, .wpa2Psk(3, "SecureNet", &pmk));
    defer gpa.free(req);

    try testing.expectEqual(@as(usize, 0), (try attrOf(req, uapi.ATTR.PRIVACY)).?.len);
    const versions = (try attrOf(req, uapi.ATTR.WPA_VERSIONS)).?;
    try testing.expectEqual(uapi.WPA_VERSION.@"2", std.mem.readInt(u32, versions[0..4], .little));
    const pairwise = (try attrOf(req, uapi.ATTR.CIPHER_SUITES_PAIRWISE)).?;
    try testing.expectEqual(@as(usize, 4), pairwise.len);
    try testing.expectEqual(uapi.CIPHER.CCMP, std.mem.readInt(u32, pairwise[0..4], .little));
    const group = (try attrOf(req, uapi.ATTR.CIPHER_SUITE_GROUP)).?;
    try testing.expectEqual(uapi.CIPHER.CCMP, std.mem.readInt(u32, group[0..4], .little));
    const akm = (try attrOf(req, uapi.ATTR.AKM_SUITES)).?;
    try testing.expectEqual(uapi.AKM.PSK, std.mem.readInt(u32, akm[0..4], .little));
    try testing.expectEqualSlices(u8, &pmk, (try attrOf(req, uapi.ATTR.PMK)).?);
    const mfp = (try attrOf(req, uapi.ATTR.USE_MFP)).?;
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, mfp[0..4], .little));
}

test "buildConnect: multiple cipher suites pack into one flat u32 array" {
    const gpa = testing.allocator;
    const req = try buildConnect(gpa, 41, 1, .{
        .ifindex = 3,
        .ssid = "n",
        .ciphers_pairwise = &.{ uapi.CIPHER.CCMP, uapi.CIPHER.GCMP_256 },
    });
    defer gpa.free(req);
    const p = (try attrOf(req, uapi.ATTR.CIPHER_SUITES_PAIRWISE)).?;
    try testing.expectEqual(@as(usize, 8), p.len);
    try testing.expectEqual(uapi.CIPHER.CCMP, std.mem.readInt(u32, p[0..4], .little));
    try testing.expectEqual(uapi.CIPHER.GCMP_256, std.mem.readInt(u32, p[4..8], .little));
}

test "buildDisconnect: reason code is optional" {
    const gpa = testing.allocator;
    const without = try buildDisconnect(gpa, 41, 1, 3, null);
    defer gpa.free(without);
    try testing.expectEqual(@as(?[]const u8, null), try attrOf(without, uapi.ATTR.REASON_CODE));

    const with = try buildDisconnect(gpa, 41, 1, 3, reason_deauth_leaving);
    defer gpa.free(with);
    const r = (try attrOf(with, uapi.ATTR.REASON_CODE)).?;
    try testing.expectEqual(@as(u16, 3), std.mem.readInt(u16, r[0..2], .little));
}

test "buildConnect: 1X-4-way-handshake and socket-owner are bare flags" {
    const gpa = testing.allocator;
    const req = try buildConnect(gpa, 41, 1, .{
        .ifindex = 3,
        .ssid = "n",
        .want_1x_4way_hs = true,
        .socket_owner = true,
    });
    defer gpa.free(req);
    try testing.expectEqual(@as(usize, 0), (try attrOf(req, uapi.ATTR.WANT_1X_4WAY_HS)).?.len);
    try testing.expectEqual(@as(usize, 0), (try attrOf(req, uapi.ATTR.SOCKET_OWNER)).?.len);
}
