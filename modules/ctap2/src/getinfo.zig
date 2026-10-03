// SPDX-License-Identifier: MIT
//! `authenticatorGetInfo` (0x04, CTAP 2.1 §6.4): the response subset needed to
//! drive PIN handling. Unknown keys and unknown option ids are ignored (the
//! spec lets authenticators add both); a known key with the wrong CBOR type is
//! an error. The result owns nothing: strings are folded into flags, byte
//! strings copied into arrays.

const std = @import("std");
const cbor = @import("cbor");
const ctap2pin = @import("ctap2pin");
const framing = @import("framing.zig");

const Allocator = std.mem.Allocator;
const ParseError = framing.ParseError;

pub const Versions = struct {
    fido_2_1: bool = false,
    fido_2_0: bool = false,
    fido_2_1_pre: bool = false,
    u2f_v2: bool = false,
};

/// The `options` map (CTAP 2.1 §6.4). `null` = the option id is absent, which
/// the spec defines per option (usually "not supported"); use the accessors on
/// `Info` for the PIN-relevant readings.
pub const Options = struct {
    plat: ?bool = null,
    rk: ?bool = null,
    client_pin: ?bool = null,
    up: ?bool = null,
    uv: ?bool = null,
    pin_uv_auth_token: ?bool = null,
    no_mc_ga_permissions_with_client_pin: ?bool = null,
    large_blobs: ?bool = null,
    bio_enroll: ?bool = null,
    uv_bio_enroll: ?bool = null,
    authnr_cfg: ?bool = null,
    uv_acfg: ?bool = null,
    cred_mgmt: ?bool = null,
    set_min_pin_length: ?bool = null,
};

/// PIN/UV auth protocols the authenticator lists, in its order of preference.
/// Values other than 1 and 2 are dropped (a newer protocol this module cannot
/// speak); duplicates are kept out.
pub const ProtocolList = struct {
    items: [2]ctap2pin.Protocol = undefined,
    len: u8 = 0,

    pub fn slice(self: *const ProtocolList) []const ctap2pin.Protocol {
        return self.items[0..self.len];
    }

    pub fn contains(self: *const ProtocolList, p: ctap2pin.Protocol) bool {
        return std.mem.indexOfScalar(ctap2pin.Protocol, self.slice(), p) != null;
    }

    fn add(self: *ProtocolList, p: ctap2pin.Protocol) void {
        if (self.contains(p)) return;
        self.items[self.len] = p;
        self.len += 1;
    }
};

pub const Info = struct {
    versions: Versions = .{},
    aaguid: [16]u8 = @splat(0),
    options: Options = .{},
    max_msg_size: ?u64 = null,
    /// `null` when the key is absent: a CTAP 2.0 authenticator, which speaks
    /// protocol One only (see `preferredProtocol`).
    pin_uv_auth_protocols: ?ProtocolList = null,
    force_pin_change: ?bool = null,
    min_pin_length: ?u32 = null,

    /// The protocol to use: the authenticator's first listed protocol that
    /// this module implements; protocol One when the list is absent (CTAP 2.0);
    /// `null` when the list names only protocols we cannot speak.
    pub fn preferredProtocol(self: Info) ?ctap2pin.Protocol {
        const list = self.pin_uv_auth_protocols orelse return .one;
        if (list.len == 0) return null;
        return list.items[0];
    }

    /// `clientPin` option: `null` = no PIN support, `false` = supported but
    /// no PIN set yet, `true` = a PIN is set.
    pub fn pinState(self: Info) ?bool {
        return self.options.client_pin;
    }

    /// Whether `getPinUvAuthTokenUsingPinWithPermissions` is available.
    pub fn supportsPinWithPermissions(self: Info) bool {
        return (self.options.client_pin orelse false) and (self.options.pin_uv_auth_token orelse false);
    }

    /// Whether `getPinUvAuthTokenUsingUvWithPermissions` is available.
    pub fn supportsUvWithPermissions(self: Info) bool {
        return (self.options.uv orelse false) and (self.options.pin_uv_auth_token orelse false);
    }

    /// The minimum PIN length in code points a platform must enforce: the
    /// authenticator's `minPINLength`, else the default 4.
    pub fn effectiveMinPinLength(self: Info) u32 {
        return self.min_pin_length orelse 4;
    }
};

const option_fields = .{
    .{ "plat", "plat" },
    .{ "rk", "rk" },
    .{ "clientPin", "client_pin" },
    .{ "up", "up" },
    .{ "uv", "uv" },
    .{ "pinUvAuthToken", "pin_uv_auth_token" },
    .{ "noMcGaPermissionsWithClientPin", "no_mc_ga_permissions_with_client_pin" },
    .{ "largeBlobs", "large_blobs" },
    .{ "bioEnroll", "bio_enroll" },
    .{ "uvBioEnroll", "uv_bio_enroll" },
    .{ "authnrCfg", "authnr_cfg" },
    .{ "uvAcfg", "uv_acfg" },
    .{ "credMgmt", "cred_mgmt" },
    .{ "setMinPINLength", "set_min_pin_length" },
};

fn parseOptions(v: cbor.Value) ParseError!Options {
    const entries = switch (v) {
        .map => |m| m,
        else => return error.UnexpectedType,
    };
    var out: Options = .{};
    var seen: [option_fields.len]bool = @splat(false);
    for (entries) |e| {
        const key = switch (e.key) {
            .text => |t| t,
            else => return error.UnexpectedType, // option ids are text strings
        };
        inline for (option_fields, 0..) |f, i| {
            if (std.mem.eql(u8, key, f[0])) {
                if (seen[i]) return error.DuplicateKey;
                seen[i] = true;
                @field(out, f[1]) = try framing.asBool(e.value);
            }
        }
    }
    return out;
}

fn parseVersions(v: cbor.Value) ParseError!Versions {
    const items = switch (v) {
        .array => |a| a,
        else => return error.UnexpectedType,
    };
    var out: Versions = .{};
    for (items) |it| {
        const s = switch (it) {
            .text => |t| t,
            else => return error.UnexpectedType,
        };
        if (std.mem.eql(u8, s, "FIDO_2_1")) out.fido_2_1 = true;
        if (std.mem.eql(u8, s, "FIDO_2_0")) out.fido_2_0 = true;
        if (std.mem.eql(u8, s, "FIDO_2_1_PRE")) out.fido_2_1_pre = true;
        if (std.mem.eql(u8, s, "U2F_V2")) out.u2f_v2 = true;
    }
    return out;
}

fn parseProtocols(v: cbor.Value) ParseError!ProtocolList {
    const items = switch (v) {
        .array => |a| a,
        else => return error.UnexpectedType,
    };
    var out: ProtocolList = .{};
    for (items) |it| {
        const n = try framing.asUint(it);
        if (n > 255) continue;
        const p = ctap2pin.Protocol.fromWire(@intCast(n)) catch continue;
        out.add(p);
    }
    return out;
}

/// Parse the CBOR body of an `authenticatorGetInfo` response (status byte
/// already stripped). `versions` (0x01) and `aaguid` (0x03) are required.
pub fn parse(allocator: Allocator, body: []const u8) (ParseError || Allocator.Error)!Info {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const entries = try framing.decodeMap(arena.allocator(), body);

    var info: Info = .{};
    info.versions = try parseVersions((try framing.find(entries, 0x01)) orelse return error.MissingField);
    const aaguid = try framing.asBytes((try framing.find(entries, 0x03)) orelse return error.MissingField);
    if (aaguid.len != 16) return error.BadLength;
    info.aaguid = aaguid[0..16].*;
    if (try framing.find(entries, 0x04)) |v| info.options = try parseOptions(v);
    if (try framing.find(entries, 0x05)) |v| info.max_msg_size = try framing.asUint(v);
    if (try framing.find(entries, 0x06)) |v| info.pin_uv_auth_protocols = try parseProtocols(v);
    if (try framing.find(entries, 0x0C)) |v| info.force_pin_change = try framing.asBool(v);
    if (try framing.find(entries, 0x0D)) |v| info.min_pin_length = try framing.asU32(v);
    return info;
}

/// Send `authenticatorGetInfo` over `transport` and parse the answer.
pub fn get(allocator: Allocator, transport: framing.Transport, max_response: usize) framing.CallError!Info {
    const resp = try framing.call(allocator, transport, @intFromEnum(framing.Command.get_info), null, max_response);
    defer resp.deinit(allocator);
    return parse(allocator, resp.body);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn enc(a: Allocator, v: cbor.Value) ![]u8 {
    return cbor.encode(a, v, .{ .canonical = true });
}

fn baseEntries(aaguid: []const u8) [2]cbor.MapEntry {
    return .{
        .{ .key = .{ .uint = 1 }, .value = .{ .array = &.{ .{ .text = "FIDO_2_1" }, .{ .text = "FIDO_2_0" }, .{ .text = "X_UNKNOWN" } } } },
        .{ .key = .{ .uint = 3 }, .value = .{ .bytes = aaguid } },
    };
}

test "parse: a full PIN-relevant GetInfo" {
    const a = testing.allocator;
    const aaguid = [_]u8{0xAB} ** 16;
    const opts = [_]cbor.MapEntry{
        .{ .key = .{ .text = "clientPin" }, .value = .{ .bool = true } },
        .{ .key = .{ .text = "pinUvAuthToken" }, .value = .{ .bool = true } },
        .{ .key = .{ .text = "uv" }, .value = .{ .bool = false } },
        .{ .key = .{ .text = "someFutureOption" }, .value = .{ .uint = 5 } }, // unknown id: ignored, any type
    };
    const b = baseEntries(&aaguid);
    const entries = [_]cbor.MapEntry{
        b[0],                                                                                    b[1],
        .{ .key = .{ .uint = 4 }, .value = .{ .map = &opts } },                                  .{ .key = .{ .uint = 5 }, .value = .{ .uint = 1200 } },
        .{ .key = .{ .uint = 6 }, .value = .{ .array = &.{ .{ .uint = 2 }, .{ .uint = 1 } } } }, .{ .key = .{ .uint = 0x0C }, .value = .{ .bool = true } },
        .{ .key = .{ .uint = 0x0D }, .value = .{ .uint = 6 } },                                  .{ .key = .{ .uint = 0x63 }, .value = .{ .text = "unknown key ignored" } },
    };
    const bytes = try enc(a, .{ .map = &entries });
    defer a.free(bytes);
    const info = try parse(a, bytes);
    try testing.expect(info.versions.fido_2_1 and info.versions.fido_2_0 and !info.versions.u2f_v2);
    try testing.expectEqualSlices(u8, &aaguid, &info.aaguid);
    try testing.expectEqual(@as(?bool, true), info.options.client_pin);
    try testing.expectEqual(@as(?bool, true), info.options.pin_uv_auth_token);
    try testing.expectEqual(@as(?bool, false), info.options.uv);
    try testing.expectEqual(@as(?bool, null), info.options.rk);
    try testing.expectEqual(@as(?u64, 1200), info.max_msg_size);
    try testing.expectEqual(@as(?bool, true), info.force_pin_change);
    try testing.expectEqual(@as(u32, 6), info.effectiveMinPinLength());
    try testing.expectEqual(ctap2pin.Protocol.two, info.preferredProtocol().?);
    try testing.expect(info.pin_uv_auth_protocols.?.contains(.one));
    try testing.expect(info.supportsPinWithPermissions());
    try testing.expect(!info.supportsUvWithPermissions());
}

test "parse: minimal response, CTAP 2.0 defaults" {
    const a = testing.allocator;
    const aaguid = [_]u8{0} ** 16;
    const b = baseEntries(&aaguid);
    const bytes = try enc(a, .{ .map = &b });
    defer a.free(bytes);
    const info = try parse(a, bytes);
    try testing.expectEqual(ctap2pin.Protocol.one, info.preferredProtocol().?); // list absent = protocol One
    try testing.expectEqual(@as(u32, 4), info.effectiveMinPinLength());
    try testing.expectEqual(@as(?bool, null), info.pinState());
    try testing.expect(!info.supportsPinWithPermissions());
}

test "parse: unknown protocols are dropped, an unspeakable-only list has no preferred protocol" {
    const a = testing.allocator;
    const aaguid = [_]u8{0} ** 16;
    const b = baseEntries(&aaguid);
    const entries = [_]cbor.MapEntry{
        b[0],                                                                                                                       b[1],
        .{ .key = .{ .uint = 6 }, .value = .{ .array = &.{ .{ .uint = 3 }, .{ .uint = 2 }, .{ .uint = 2 }, .{ .uint = 1000 } } } },
    };
    const bytes = try enc(a, .{ .map = &entries });
    defer a.free(bytes);
    const info = try parse(a, bytes);
    try testing.expectEqual(@as(u8, 1), info.pin_uv_auth_protocols.?.len);
    try testing.expectEqual(ctap2pin.Protocol.two, info.preferredProtocol().?);

    const only_new = [_]cbor.MapEntry{
        b[0],                                                                  b[1],
        .{ .key = .{ .uint = 6 }, .value = .{ .array = &.{.{ .uint = 3 }} } },
    };
    const bytes2 = try enc(a, .{ .map = &only_new });
    defer a.free(bytes2);
    try testing.expectEqual(@as(?ctap2pin.Protocol, null), (try parse(a, bytes2)).preferredProtocol());
}

fn expectParseError(expected: anyerror, entries: []const cbor.MapEntry) !void {
    const a = testing.allocator;
    const bytes = try enc(a, .{ .map = entries });
    defer a.free(bytes);
    try testing.expectError(expected, parse(a, bytes));
}

test "parse: wrong types, missing and malformed fields are typed errors" {
    const aaguid = [_]u8{0} ** 16;
    const b = baseEntries(&aaguid);
    // missing versions / aaguid
    try expectParseError(error.MissingField, &.{b[1]});
    try expectParseError(error.MissingField, &.{b[0]});
    // wrong type of versions and of an element
    try expectParseError(error.UnexpectedType, &.{ .{ .key = .{ .uint = 1 }, .value = .{ .text = "FIDO_2_1" } }, b[1] });
    try expectParseError(error.UnexpectedType, &.{ .{ .key = .{ .uint = 1 }, .value = .{ .array = &.{.{ .uint = 1 }} } }, b[1] });
    // aaguid: wrong type, wrong length
    try expectParseError(error.UnexpectedType, &.{ b[0], .{ .key = .{ .uint = 3 }, .value = .{ .text = "0123456789abcdef" } } });
    try expectParseError(error.BadLength, &.{ b[0], .{ .key = .{ .uint = 3 }, .value = .{ .bytes = "short" } } });
    // options: not a map / non-bool value for a known id / non-text id
    try expectParseError(error.UnexpectedType, &.{ b[0], b[1], .{ .key = .{ .uint = 4 }, .value = .{ .uint = 1 } } });
    try expectParseError(error.UnexpectedType, &.{ b[0], b[1], .{ .key = .{ .uint = 4 }, .value = .{ .map = &.{.{ .key = .{ .text = "clientPin" }, .value = .{ .uint = 1 } }} } } });
    try expectParseError(error.UnexpectedType, &.{ b[0], b[1], .{ .key = .{ .uint = 4 }, .value = .{ .map = &.{.{ .key = .{ .uint = 1 }, .value = .{ .bool = true } }} } } });
    // maxMsgSize / forcePINChange / minPINLength / protocols: wrong types and range
    try expectParseError(error.UnexpectedType, &.{ b[0], b[1], .{ .key = .{ .uint = 5 }, .value = .{ .bytes = "x" } } });
    try expectParseError(error.UnexpectedType, &.{ b[0], b[1], .{ .key = .{ .uint = 0x0C }, .value = .{ .uint = 1 } } });
    try expectParseError(error.UnexpectedType, &.{ b[0], b[1], .{ .key = .{ .uint = 0x0D }, .value = .{ .negint = 0 } } });
    try expectParseError(error.ValueOutOfRange, &.{ b[0], b[1], .{ .key = .{ .uint = 0x0D }, .value = .{ .uint = 1 << 40 } } });
    try expectParseError(error.UnexpectedType, &.{ b[0], b[1], .{ .key = .{ .uint = 6 }, .value = .{ .uint = 2 } } });
    try expectParseError(error.UnexpectedType, &.{ b[0], b[1], .{ .key = .{ .uint = 6 }, .value = .{ .array = &.{.{ .text = "2" }} } } });
    // duplicate key
    try expectParseError(error.DuplicateKey, &.{ b[0], b[1], b[1] });
}

test "parse: not a map, empty, truncated and trailing bytes" {
    const a = testing.allocator;
    try testing.expectError(error.EmptyResponse, parse(a, ""));
    try testing.expectError(error.MalformedCbor, parse(a, &.{0xa1}));
    try testing.expectError(error.UnexpectedType, parse(a, &.{0x80}));
    try testing.expectError(error.MalformedCbor, parse(a, &.{ 0xa0, 0x00 })); // trailing garbage
}

test "parse: an aaguid longer than 16 bytes is refused" {
    const aaguid = [_]u8{0} ** 17;
    const b = baseEntries(&aaguid);
    try expectParseError(error.BadLength, &b);
}

test "parse: a duplicated option id is refused" {
    const aaguid = [_]u8{0} ** 16;
    const b = baseEntries(&aaguid);
    const opts = [_]cbor.MapEntry{
        .{ .key = .{ .text = "uv" }, .value = .{ .bool = true } },
        .{ .key = .{ .text = "uv" }, .value = .{ .bool = false } },
    };
    try expectParseError(error.DuplicateKey, &.{ b[0], b[1], .{ .key = .{ .uint = 4 }, .value = .{ .map = &opts } } });
}

test "parse: every version string sets its own flag" {
    const a = testing.allocator;
    const aaguid = [_]u8{0} ** 16;
    const b = baseEntries(&aaguid);
    const names = [_][]const u8{ "FIDO_2_1", "FIDO_2_0", "FIDO_2_1_PRE", "U2F_V2" };
    for (names, 0..) |name, which| {
        const versions = [_]cbor.Value{.{ .text = name }};
        const entries = [_]cbor.MapEntry{ .{ .key = .{ .uint = 1 }, .value = .{ .array = &versions } }, b[1] };
        const bytes = try enc(a, .{ .map = &entries });
        defer a.free(bytes);
        const v = (try parse(a, bytes)).versions;
        try testing.expectEqual(which == 0, v.fido_2_1);
        try testing.expectEqual(which == 1, v.fido_2_0);
        try testing.expectEqual(which == 2, v.fido_2_1_pre);
        try testing.expectEqual(which == 3, v.u2f_v2);
    }
}

test "supportsPinWithPermissions / supportsUvWithPermissions need both options" {
    var info: Info = .{};
    try testing.expect(!info.supportsPinWithPermissions());
    info.options.client_pin = true;
    try testing.expect(!info.supportsPinWithPermissions()); // pinUvAuthToken absent
    info.options.pin_uv_auth_token = false;
    try testing.expect(!info.supportsPinWithPermissions());
    info.options.client_pin = false;
    info.options.pin_uv_auth_token = true;
    try testing.expect(!info.supportsPinWithPermissions()); // no PIN set / supported
    info.options.client_pin = true;
    try testing.expect(info.supportsPinWithPermissions());

    var uv: Info = .{};
    uv.options.pin_uv_auth_token = true;
    try testing.expect(!uv.supportsUvWithPermissions()); // uv absent
    uv.options.uv = false;
    try testing.expect(!uv.supportsUvWithPermissions());
    uv.options.uv = true;
    uv.options.pin_uv_auth_token = false;
    try testing.expect(!uv.supportsUvWithPermissions());
    uv.options.pin_uv_auth_token = true;
    try testing.expect(uv.supportsUvWithPermissions());
}
