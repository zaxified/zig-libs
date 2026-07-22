// SPDX-License-Identifier: MIT
//! IEEE 802.11 information elements — the length-prefixed TLV stream carried
//! by `NL80211_BSS_INFORMATION_ELEMENTS` and `NL80211_BSS_BEACON_IES`.
//!
//! **This is the module's whole hostile-input surface.** Everything else on
//! the nl80211 wire is produced by the local kernel; IEs are verbatim bytes
//! off the air, written by whatever transmitter happened to be in range. A
//! beacon can therefore claim any length it likes, nest counts that do not fit
//! the element, or simply stop mid-field.
//!
//! The rules this file enforces, and the reason each one exists:
//!
//! * **Every step is bounds-checked before it is taken.** `Iterator.next`
//!   validates that a 2-byte header and then `len` body bytes are actually
//!   present; a claim that overruns the buffer is `error.Truncated`, never a
//!   read past the end.
//! * **Iteration always advances by at least 2 bytes**, so a walk over N bytes
//!   terminates in at most N/2 steps by construction — no attacker-chosen loop
//!   count.
//! * **Sub-parsers (RSN/WPA) treat every field after the first as optional.**
//!   The RSN element is defined so that a transmitter may stop after any
//!   field; a parser that demands the whole thing rejects legitimate APs. So
//!   short input ends the parse, while a *count* that does not fit the
//!   remaining bytes is `error.Malformed` — that one is a lie, not brevity.
//! * **Fixed-capacity suite lists, no allocation.** A hostile element cannot
//!   make this file allocate; `SuiteList.declared` still reports the count the
//!   transmitter claimed so a caller can see that it was clipped.
//! * **`summarize` never fails.** The convenience path stops at the first
//!   malformed element and returns what it decoded, because a single bad IE in
//!   a beacon must not make the surrounding BSS undecodable.

const std = @import("std");
const uapi = @import("uapi.zig");

pub const Error = error{
    /// An element header or body runs past the end of the stream.
    Truncated,
    /// A structurally invalid element body (e.g. an RSN suite count that does
    /// not fit the element).
    Malformed,
};

/// Element ids this module knows by name (IEEE 802.11-2020 Table 9-128).
pub const EID = struct {
    pub const SSID: u8 = 0;
    pub const SUPPORTED_RATES: u8 = 1;
    pub const DS_PARAMS: u8 = 3;
    pub const TIM: u8 = 5;
    pub const COUNTRY: u8 = 7;
    pub const BSS_LOAD: u8 = 11;
    pub const CHALLENGE: u8 = 16;
    pub const POWER_CONSTRAINT: u8 = 32;
    pub const ERP: u8 = 42;
    pub const HT_CAPABILITY: u8 = 45;
    pub const RSN: u8 = 48;
    pub const EXTENDED_SUPPORTED_RATES: u8 = 50;
    pub const HT_OPERATION: u8 = 61;
    pub const RM_ENABLED_CAPS: u8 = 70;
    pub const EXT_CAPABILITY: u8 = 127;
    pub const VHT_CAPABILITY: u8 = 191;
    pub const VHT_OPERATION: u8 = 192;
    pub const TX_POWER_ENVELOPE: u8 = 195;
    pub const VENDOR_SPECIFIC: u8 = 221;
    pub const RSN_EXTENSION: u8 = 244;
    /// Element ID Extension — the real id is the first body byte.
    pub const EXTENSION: u8 = 255;
};

/// Extension ids seen behind `EID.EXTENSION`.
pub const EXT_EID = struct {
    pub const HE_CAPABILITY: u8 = 35;
    pub const HE_OPERATION: u8 = 36;
    pub const EHT_OPERATION: u8 = 106;
    pub const EHT_CAPABILITY: u8 = 108;
};

/// One parsed information element. `body` borrows from the input buffer.
pub const Element = struct {
    id: u8,
    /// For `id == EID.EXTENSION`, the element-id-extension byte; null
    /// otherwise. An `EID.EXTENSION` element with an empty body has no
    /// extension id and is reported with `ext_id == null`.
    ext_id: ?u8 = null,
    /// The element body. For an extension element the extension-id byte is
    /// **not** included — `body` starts after it.
    body: []const u8,
};

/// Bounds-checked walk over an IE stream. Construct with
/// `.{ .buf = ies }`, then loop on `next()`.
pub const Iterator = struct {
    buf: []const u8,
    offset: usize = 0,

    pub fn next(it: *Iterator) Error!?Element {
        if (it.offset >= it.buf.len) return null;
        const rest = it.buf[it.offset..];
        if (rest.len < 2) return error.Truncated;
        const id = rest[0];
        const len: usize = rest[1];
        if (2 + len > rest.len) return error.Truncated;
        const body = rest[2..][0..len];
        it.offset += 2 + len; // >= 2, so iteration always terminates
        if (id == EID.EXTENSION and len >= 1)
            return .{ .id = id, .ext_id = body[0], .body = body[1..] };
        return .{ .id = id, .body = body };
    }
};

/// The body of the first element with `id`, or null. Stops at the first
/// malformed element rather than erroring — see the file header.
pub fn find(ies: []const u8, id: u8) ?[]const u8 {
    var it: Iterator = .{ .buf = ies };
    while (it.next() catch return null) |e| {
        if (e.id == id and e.ext_id == null) return e.body;
    }
    return null;
}

/// The body of the first extension element with extension id `ext_id`.
pub fn findExtension(ies: []const u8, ext_id: u8) ?[]const u8 {
    var it: Iterator = .{ .buf = ies };
    while (it.next() catch return null) |e| {
        if (e.id == EID.EXTENSION and e.ext_id == ext_id) return e.body;
    }
    return null;
}

/// The body of the first vendor-specific element whose 3-byte OUI and 1-byte
/// vendor type match, with those 4 bytes stripped.
pub fn findVendor(ies: []const u8, oui: [3]u8, vendor_type: u8) ?[]const u8 {
    var it: Iterator = .{ .buf = ies };
    while (it.next() catch return null) |e| {
        if (e.id != EID.VENDOR_SPECIFIC or e.body.len < 4) continue;
        if (!std.mem.eql(u8, e.body[0..3], &oui)) continue;
        if (e.body[3] != vendor_type) continue;
        return e.body[4..];
    }
    return null;
}

/// The Microsoft OUI that carries the pre-RSN WPA1 element and WMM/WPS.
pub const oui_microsoft: [3]u8 = .{ 0x00, 0x50, 0xf2 };
/// Vendor type 1 behind `oui_microsoft` = the WPA (v1) element.
pub const vendor_type_wpa: u8 = 1;

// ── rates ──────────────────────────────────────────────────────────────────

/// One entry of a Supported Rates / Extended Supported Rates element. The
/// wire byte is the rate in 500 kbit/s units with the top bit meaning "this
/// rate is in the BSS basic rate set".
pub const Rate = struct {
    /// Rate in 500 kbit/s units (0–127).
    half_mbps: u7,
    basic: bool,

    pub fn fromByte(b: u8) Rate {
        return .{ .half_mbps = @truncate(b & 0x7f), .basic = (b & 0x80) != 0 };
    }

    pub fn kilobitsPerSecond(r: Rate) u32 {
        return @as(u32, r.half_mbps) * 500;
    }
};

/// Iterate the rates of a Supported Rates or Extended Supported Rates body.
pub const RateIterator = struct {
    body: []const u8,
    offset: usize = 0,

    pub fn next(it: *RateIterator) ?Rate {
        if (it.offset >= it.body.len) return null;
        defer it.offset += 1;
        return .fromByte(it.body[it.offset]);
    }
};

// ── RSN / WPA ──────────────────────────────────────────────────────────────

/// The most suite selectors of one kind this module keeps. Real elements
/// carry one or two; the cap exists so a hostile beacon cannot make the
/// parser allocate or the caller's stack frame grow.
pub const max_suites = 8;

/// A clipped list of suite selectors plus the count the transmitter declared.
pub const SuiteList = struct {
    items: [max_suites]u32 = @splat(0),
    len: u8 = 0,
    /// The count field as it appeared on the wire, before clipping to
    /// `max_suites`. `declared > len` means the list was clipped.
    declared: u16 = 0,

    pub fn slice(s: *const SuiteList) []const u32 {
        return s.items[0..s.len];
    }

    pub fn contains(s: *const SuiteList, suite: u32) bool {
        return std.mem.indexOfScalar(u32, s.slice(), suite) != null;
    }
};

/// A decoded RSN (802.11i) element, or the pre-standard WPA1 vendor element,
/// which has the same field order with the 00-50-F2 OUI.
///
/// Every field after `version` is optional on the wire; a field left at its
/// default means the transmitter stopped before it. `group_cipher` defaults to
/// the standard's own default (CCMP for RSN) so callers do not have to
/// special-case the short form.
pub const Rsn = struct {
    version: u16,
    group_cipher: u32,
    pairwise: SuiteList = .{},
    akm: SuiteList = .{},
    /// RSN Capabilities field, if present.
    capabilities: ?u16 = null,
    /// Number of PMKIDs the element advertised (the PMKIDs themselves are not
    /// kept — they are only meaningful to a supplicant).
    pmkid_count: u16 = 0,
    group_mgmt_cipher: ?u32 = null,

    /// Bit 6 of RSN Capabilities: management frame protection required.
    pub fn mfpRequired(r: Rsn) bool {
        return (r.capabilities orelse 0) & (1 << 6) != 0;
    }

    /// Bit 7 of RSN Capabilities: management frame protection capable.
    pub fn mfpCapable(r: Rsn) bool {
        return (r.capabilities orelse 0) & (1 << 7) != 0;
    }

    /// True when the AKM list offers plain WPA2 pre-shared key (or its
    /// SHA-256 variant) — the case `connect.wpa2Psk` covers.
    pub fn offersPsk(r: Rsn) bool {
        return r.akm.contains(uapi.AKM.PSK) or r.akm.contains(uapi.AKM.PSK_SHA256);
    }

    /// True when the AKM list offers WPA3-Personal (SAE).
    pub fn offersSae(r: Rsn) bool {
        return r.akm.contains(uapi.AKM.SAE) or r.akm.contains(uapi.AKM.FT_OVER_SAE);
    }
};

/// Parse an RSN element body (`EID.RSN`).
pub fn parseRsn(body: []const u8) Error!Rsn {
    return parseRsnLike(body, uapi.CIPHER.CCMP);
}

/// Parse the body of a WPA1 vendor element — i.e. what `findVendor(ies,
/// oui_microsoft, vendor_type_wpa)` returns. Same layout as RSN; the default
/// group cipher for WPA1 is TKIP.
pub fn parseWpa1(body: []const u8) Error!Rsn {
    return parseRsnLike(body, uapi.CIPHER.TKIP);
}

fn parseRsnLike(body: []const u8, default_group: u32) Error!Rsn {
    if (body.len < 2) return error.Truncated;
    var r: Rsn = .{
        .version = std.mem.readInt(u16, body[0..2], .little),
        .group_cipher = default_group,
    };
    var off: usize = 2;

    // Group cipher — optional.
    if (body.len - off < 4) return r;
    r.group_cipher = readSuite(body[off..][0..4]);
    off += 4;

    // Pairwise cipher list — optional.
    off = readSuiteList(body, off, &r.pairwise) catch |e| return e;
    if (off >= body.len) return r;

    // AKM list — optional.
    off = readSuiteList(body, off, &r.akm) catch |e| return e;
    if (off >= body.len) return r;

    // RSN capabilities — optional.
    if (body.len - off < 2) return r;
    r.capabilities = std.mem.readInt(u16, body[off..][0..2], .little);
    off += 2;

    // PMKID list — optional. Only the count is kept, but the bytes must be
    // there or the element is lying about its own shape.
    if (body.len - off < 2) return r;
    r.pmkid_count = std.mem.readInt(u16, body[off..][0..2], .little);
    off += 2;
    const pmkid_bytes = @as(usize, r.pmkid_count) * 16;
    if (body.len - off < pmkid_bytes) return error.Malformed;
    off += pmkid_bytes;

    // Group management cipher — optional.
    if (body.len - off < 4) return r;
    r.group_mgmt_cipher = readSuite(body[off..][0..4]);
    off += 4;
    return r;
}

/// Read a `u16 count` followed by `count` 4-byte suite selectors, keeping at
/// most `max_suites` of them. Returns the offset just past the list, or
/// `body.len` when the list is absent (the element stopped early).
fn readSuiteList(body: []const u8, start: usize, out: *SuiteList) Error!usize {
    if (body.len - start < 2) return body.len;
    const count = std.mem.readInt(u16, body[start..][0..2], .little);
    var off = start + 2;
    const need = @as(usize, count) * 4;
    // A count that does not fit is a lie about the element's own structure,
    // not a legitimately short element — reject it.
    if (body.len - off < need) return error.Malformed;
    out.declared = count;
    var i: u16 = 0;
    while (i < count) : (i += 1) {
        if (out.len < max_suites) {
            out.items[out.len] = readSuite(body[off..][0..4]);
            out.len += 1;
        }
        off += 4;
    }
    return off;
}

/// A suite selector is `OUI[3] ‖ type`, big-endian on the wire, which is the
/// same number nl80211 reports in `NL80211_ATTR_CIPHER_SUITES` (0x000FAC04 =
/// 00-0F-AC:4 = CCMP).
fn readSuite(raw: *const [4]u8) u32 {
    return std.mem.readInt(u32, raw, .big);
}

// ── summary ────────────────────────────────────────────────────────────────

/// The handful of fields a caller almost always wants out of a beacon, in one
/// pass. Slices borrow from the input buffer.
///
/// Never fails: parsing stops at the first malformed element and whatever was
/// decoded before it is returned. `truncated` records that this happened.
pub const Summary = struct {
    /// SSID bytes, verbatim — **not** a string. A hidden network sends an
    /// empty or all-zero SSID, and a legitimate SSID may hold any bytes at
    /// all, including invalid UTF-8. Never print it unescaped.
    ssid: []const u8 = &.{},
    /// True when the SSID element was present but empty or all zeroes.
    hidden_ssid: bool = false,
    supported_rates: []const u8 = &.{},
    extended_rates: []const u8 = &.{},
    /// Channel number from the DS Parameter Set element.
    ds_channel: ?u8 = null,
    /// ERP element's information byte.
    erp: ?u8 = null,
    /// Country string ("DE ", "US "…) from the Country element.
    country: ?[]const u8 = null,
    rsn: ?Rsn = null,
    wpa1: ?Rsn = null,
    /// True when a HT Capabilities element was present.
    ht: bool = false,
    /// True when a VHT Capabilities element was present.
    vht: bool = false,
    /// True when a HE Capabilities extension element was present.
    he: bool = false,
    /// The walk stopped early on a malformed element.
    truncated: bool = false,

    /// Best-effort privacy verdict from the elements alone. `capability`
    /// comes from `NL80211_BSS_CAPABILITY` bit 4 (Privacy) and is what tells
    /// WEP apart from open when no RSN/WPA element is present.
    pub fn security(s: Summary, capability: ?u16) Security {
        if (s.rsn) |r| {
            if (r.offersSae()) return .wpa3_sae;
            if (r.offersPsk()) return .wpa2_psk;
            return .wpa2_enterprise;
        }
        if (s.wpa1 != null) return .wpa1;
        const privacy = (capability orelse 0) & (1 << 4) != 0;
        return if (privacy) .wep else .open;
    }
};

pub const Security = enum { open, wep, wpa1, wpa2_psk, wpa2_enterprise, wpa3_sae };

/// Decode the elements listed in `Summary` in one pass. See `Summary`.
pub fn summarize(ies: []const u8) Summary {
    var s: Summary = .{};
    var it: Iterator = .{ .buf = ies };
    while (true) {
        const maybe = it.next() catch {
            s.truncated = true;
            return s;
        };
        const e = maybe orelse return s;
        switch (e.id) {
            EID.SSID => if (s.ssid.len == 0 and !s.hidden_ssid) {
                s.ssid = e.body;
                s.hidden_ssid = e.body.len == 0 or std.mem.allEqual(u8, e.body, 0);
            },
            EID.SUPPORTED_RATES => if (s.supported_rates.len == 0) {
                s.supported_rates = e.body;
            },
            EID.EXTENDED_SUPPORTED_RATES => if (s.extended_rates.len == 0) {
                s.extended_rates = e.body;
            },
            EID.DS_PARAMS => if (e.body.len >= 1 and s.ds_channel == null) {
                s.ds_channel = e.body[0];
            },
            EID.ERP => if (e.body.len >= 1 and s.erp == null) {
                s.erp = e.body[0];
            },
            EID.COUNTRY => if (e.body.len >= 3 and s.country == null) {
                s.country = e.body[0..3];
            },
            EID.RSN => if (s.rsn == null) {
                s.rsn = parseRsn(e.body) catch blk: {
                    s.truncated = true;
                    break :blk null;
                };
            },
            EID.HT_CAPABILITY => s.ht = true,
            EID.VHT_CAPABILITY => s.vht = true,
            EID.EXTENSION => if (e.ext_id == EXT_EID.HE_CAPABILITY) {
                s.he = true;
            },
            EID.VENDOR_SPECIFIC => if (s.wpa1 == null and e.body.len >= 4 and
                std.mem.eql(u8, e.body[0..3], &oui_microsoft) and
                e.body[3] == vendor_type_wpa)
            {
                s.wpa1 = parseWpa1(e.body[4..]) catch blk: {
                    s.truncated = true;
                    break :blk null;
                };
            },
            else => {},
        }
    }
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "iterator walks a well-formed stream and reports the extension id" {
    const ies = [_]u8{
        0, 3, 'a', 'b', 'c', // SSID
        1, 2, 0x82, 0x84, // supported rates
        255, 3, 35, 0xaa, 0xbb, // extension element, ext id 35 (HE caps)
        3, 1, 6, // DS params, channel 6
    };
    var it: Iterator = .{ .buf = &ies };
    const a = (try it.next()).?;
    try testing.expectEqual(@as(u8, EID.SSID), a.id);
    try testing.expectEqualStrings("abc", a.body);
    try testing.expectEqual(@as(?u8, null), a.ext_id);

    const b = (try it.next()).?;
    try testing.expectEqual(@as(u8, EID.SUPPORTED_RATES), b.id);
    try testing.expectEqualSlices(u8, &.{ 0x82, 0x84 }, b.body);

    const c = (try it.next()).?;
    try testing.expectEqual(@as(u8, EID.EXTENSION), c.id);
    try testing.expectEqual(@as(?u8, 35), c.ext_id);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, c.body);

    const d = (try it.next()).?;
    try testing.expectEqual(@as(u8, EID.DS_PARAMS), d.id);
    try testing.expectEqualSlices(u8, &.{6}, d.body);

    try testing.expectEqual(@as(?Element, null), try it.next());
}

test "hostile: a length that overruns the buffer is Truncated, not an OOB read" {
    // Element claims 200 body bytes but only 2 follow.
    var it: Iterator = .{ .buf = &.{ 0, 200, 'a', 'b' } };
    try testing.expectError(error.Truncated, it.next());

    // A dangling single header byte.
    var it2: Iterator = .{ .buf = &.{0} };
    try testing.expectError(error.Truncated, it2.next());

    // Valid element followed by a dangling header byte.
    var it3: Iterator = .{ .buf = &.{ 0, 1, 'x', 3 } };
    _ = try it3.next();
    try testing.expectError(error.Truncated, it3.next());

    // 0xff at the very end: an extension element with no extension id.
    var it4: Iterator = .{ .buf = &.{ 255, 0 } };
    const e = (try it4.next()).?;
    try testing.expectEqual(@as(?u8, null), e.ext_id);
    try testing.expectEqual(@as(usize, 0), e.body.len);
}

test "iterator over an empty stream yields nothing" {
    var it: Iterator = .{ .buf = &.{} };
    try testing.expectEqual(@as(?Element, null), try it.next());
    try testing.expectEqual(@as(?[]const u8, null), find(&.{}, EID.SSID));
}

test "zero-length elements still advance (no infinite loop)" {
    const ies = [_]u8{ 0, 0, 1, 0, 3, 0 } ** 8;
    var it: Iterator = .{ .buf = &ies };
    var n: usize = 0;
    while (try it.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 24), n);
}

test "rates decode with the basic-rate bit split off" {
    var it: RateIterator = .{ .body = &.{ 0x82, 0x84, 0x8b, 0x0c } };
    const r1 = it.next().?;
    try testing.expect(r1.basic);
    try testing.expectEqual(@as(u32, 1000), r1.kilobitsPerSecond()); // 1 Mbit/s
    const r2 = it.next().?;
    try testing.expectEqual(@as(u32, 2000), r2.kilobitsPerSecond());
    const r3 = it.next().?;
    try testing.expectEqual(@as(u32, 5500), r3.kilobitsPerSecond());
    const r4 = it.next().?;
    try testing.expect(!r4.basic);
    try testing.expectEqual(@as(u32, 6000), r4.kilobitsPerSecond());
    try testing.expectEqual(@as(?Rate, null), it.next());
}

test "RSN: the real element captured from a WPA2-PSK beacon" {
    // Captured verbatim from this machine's air (see goldens.zig); the AP's
    // identity is not in these bytes.
    const body = [_]u8{
        0x01, 0x00, // version 1
        0x00, 0x0f, 0xac, 0x04, // group: CCMP
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // 1 pairwise: CCMP
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, // 1 AKM: PSK
        0x0c, 0x00, // RSN capabilities
    };
    const r = try parseRsn(&body);
    try testing.expectEqual(@as(u16, 1), r.version);
    try testing.expectEqual(uapi.CIPHER.CCMP, r.group_cipher);
    try testing.expectEqualSlices(u32, &.{uapi.CIPHER.CCMP}, r.pairwise.slice());
    try testing.expectEqualSlices(u32, &.{uapi.AKM.PSK}, r.akm.slice());
    try testing.expectEqual(@as(?u16, 0x000c), r.capabilities);
    try testing.expect(r.offersPsk());
    try testing.expect(!r.offersSae());
    try testing.expect(!r.mfpRequired());
    try testing.expect(!r.mfpCapable());
    try testing.expectEqual(@as(?u32, null), r.group_mgmt_cipher);
}

test "RSN: WPA3 transition mode (PSK + SAE, MFP capable, group mgmt cipher)" {
    const body = [_]u8{
        0x01, 0x00,
        0x00, 0x0f,
        0xac, 0x04,
        0x01, 0x00,
        0x00, 0x0f,
        0xac, 0x04,
        0x02, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x0f, 0xac, 0x08, // PSK + SAE
        0x80, 0x00, // MFP capable
        0x00, 0x00, // 0 PMKIDs
        0x00, 0x0f, 0xac, 0x06, // group mgmt: BIP-CMAC-128
    };
    const r = try parseRsn(&body);
    try testing.expectEqual(@as(u8, 2), r.akm.len);
    try testing.expect(r.offersPsk());
    try testing.expect(r.offersSae());
    try testing.expect(r.mfpCapable());
    try testing.expect(!r.mfpRequired());
    try testing.expectEqual(@as(?u32, uapi.CIPHER.AES_CMAC), r.group_mgmt_cipher);
}

test "RSN: every field after version may legitimately be absent" {
    // Version only.
    var r = try parseRsn(&.{ 0x01, 0x00 });
    try testing.expectEqual(uapi.CIPHER.CCMP, r.group_cipher); // the default
    try testing.expectEqual(@as(u8, 0), r.pairwise.len);
    try testing.expectEqual(@as(?u16, null), r.capabilities);

    // Version + group cipher.
    r = try parseRsn(&.{ 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02 });
    try testing.expectEqual(uapi.CIPHER.TKIP, r.group_cipher);
    try testing.expectEqual(@as(u8, 0), r.pairwise.len);

    // Version + group + pairwise, stopping before the AKM list.
    r = try parseRsn(&.{ 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04 });
    try testing.expectEqual(@as(u8, 1), r.pairwise.len);
    try testing.expectEqual(@as(u8, 0), r.akm.len);

    // Too short even for a version.
    try testing.expectError(error.Truncated, parseRsn(&.{0x01}));
    try testing.expectError(error.Truncated, parseRsn(&.{}));
}

test "hostile RSN: a suite count that does not fit is Malformed" {
    // Claims 0xffff pairwise suites with none present.
    try testing.expectError(error.Malformed, parseRsn(&.{
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0xff, 0xff,
    }));
    // Claims 2 pairwise suites but supplies one.
    try testing.expectError(error.Malformed, parseRsn(&.{
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x02, 0x00, 0x00, 0x0f, 0xac, 0x04,
    }));
    // Claims 0xffff PMKIDs.
    try testing.expectError(error.Malformed, parseRsn(&.{
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff,
    }));
}

test "hostile RSN: an over-long suite list is clipped, and says so" {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    try body.appendSlice(testing.allocator, &.{ 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04 });
    const n = max_suites + 5;
    try body.appendSlice(testing.allocator, &.{ n, 0x00 });
    for (0..n) |i| try body.appendSlice(testing.allocator, &.{ 0x00, 0x0f, 0xac, @intCast(i) });

    const r = try parseRsn(body.items);
    try testing.expectEqual(@as(u8, max_suites), r.pairwise.len);
    try testing.expectEqual(@as(u16, n), r.pairwise.declared);
    try testing.expect(r.pairwise.declared > r.pairwise.len);
}

test "vendor element lookup: WPA1 and a non-match" {
    const ies = [_]u8{
        221, 8, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00, 0x00, 0x50, // WPA1, clipped body
        221, 5, 0x00, 0x90, 0x4c, 0x04, 0x17, // some other vendor
    };
    const wpa = findVendor(&ies, oui_microsoft, vendor_type_wpa).?;
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x00, 0x50 }, wpa);
    try testing.expectEqual(@as(?[]const u8, null), findVendor(&ies, oui_microsoft, 4));
    try testing.expectEqual(@as(?[]const u8, null), findVendor(&ies, .{ 0xaa, 0xbb, 0xcc }, 1));
}

test "summarize on a hidden-SSID beacon" {
    const ies = [_]u8{
        0, 4, 0,    0,    0,    0, // zero-filled SSID = hidden
        1, 4, 0x82, 0x84, 0x8b, 0x96,
        3, 1, 11,
    };
    const s = summarize(&ies);
    try testing.expect(s.hidden_ssid);
    try testing.expectEqual(@as(?u8, 11), s.ds_channel);
    try testing.expectEqual(Security.open, s.security(0));
    try testing.expectEqual(Security.wep, s.security(1 << 4));
    try testing.expect(!s.truncated);
}

test "summarize stops at a malformed element and reports what it had" {
    const ies = [_]u8{
        0,   3,    'a',  'b',  'c',
        1,   2,    0x82, 0x84,
        // then a lie:
        221,
        250, 0x00,
    };
    const s = summarize(&ies);
    try testing.expectEqualStrings("abc", s.ssid);
    try testing.expectEqualSlices(u8, &.{ 0x82, 0x84 }, s.supported_rates);
    try testing.expect(s.truncated);
}

test "summarize: a malformed RSN does not sink the rest of the beacon" {
    const ies = [_]u8{
        0, 3, 'x', 'y', 'z',
        48, 8, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0xff, 0xff, // lying count
        3,  1, 1,
    };
    const s = summarize(&ies);
    try testing.expectEqualStrings("xyz", s.ssid);
    try testing.expectEqual(@as(?Rsn, null), s.rsn);
    try testing.expect(s.truncated);
    try testing.expectEqual(@as(?u8, 1), s.ds_channel); // parsing continued
}

test "fuzz: the IE walk never crashes on arbitrary bytes" {
    try testing.fuzz({}, fuzzIes, .{});
}

fn fuzzIes(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const buf = raw[0..len];

    var it: Iterator = .{ .buf = buf };
    while (it.next() catch null) |e| {
        _ = e;
    }
    const s = summarize(buf);
    std.mem.doNotOptimizeAway(&s);
    if (parseRsn(buf)) |r| std.mem.doNotOptimizeAway(&r) else |_| {}
    if (parseWpa1(buf)) |r| std.mem.doNotOptimizeAway(&r) else |_| {}
    _ = find(buf, EID.SSID);
    _ = findExtension(buf, EXT_EID.HE_CAPABILITY);
    _ = findVendor(buf, oui_microsoft, vendor_type_wpa);
}
