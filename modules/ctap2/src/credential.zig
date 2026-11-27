// SPDX-License-Identifier: MIT
//! `authenticatorMakeCredential` (0x01, CTAP 2.1 §6.1), `authenticatorGetAssertion` (0x02, §6.2) and
//! `authenticatorGetNextAssertion` (0x08, §6.3): request encoding and response parsing over a caller-supplied
//! `Transport` (the `ctaphid.Channel`'s, or any other).
//!
//! The command layer only. What it does not do: the WebAuthn client steps (building `clientDataJSON` and hashing it,
//! the origin checks, extension input processing: the caller passes `clientDataHash` and the already-built extension
//! map), the `pinUvAuthParam` (that is `Token.authenticate` of `clientpin.zig` over `clientDataHash`), and the
//! verification of what comes back: `auth_data` and the attestation statement go to the `webauthn` module
//! (`parseAuthenticatorData`, `verifyAttestation`, `verifyAssertion`; `attestationObject` below builds the
//! WebAuthn attestation object from a response).
//!
//! Every returned slice lives in the caller's arena. Requests encode with CTAP2 canonical CBOR (§8.1); every map key
//! here is a small integer or a short text string, for which RFC 8949 bytewise order and CTAP2's "shortest first"
//! coincide. Checked against python-fido2 2.2.1 as a black-box oracle (`tools/gen_credential_vectors.py`).

const std = @import("std");
const cbor = @import("cbor");
const ctap2pin = @import("ctap2pin");
const framing = @import("framing.zig");

const Allocator = std.mem.Allocator;
const Value = cbor.Value;
const MapEntry = cbor.MapEntry;

/// Receive buffer of one transaction unless the caller sets another: the CTAPHID message ceiling (57 + 128 * 59).
pub const default_max_response: usize = 7609;
/// Most assertions `getAssertions` collects (`numberOfCredentials` above it is `ValueOutOfRange`).
pub const max_assertions: u32 = 64;

pub const CredentialError = framing.CallError || error{
    /// A request that cannot be valid: an empty RP id, an empty `pubKeyCredParams`, a `pinUvAuthParam` without its
    /// protocol (or the other way round), a user id longer than 64 bytes.
    InvalidRequest,
};

/// A `PublicKeyCredentialDescriptor` (type is always `"public-key"`).
pub const CredentialDescriptor = struct {
    id: []const u8,
    /// `usb`, `nfc`, `ble`, `hybrid`, `internal`, ...; written only when not empty.
    transports: []const []const u8 = &.{},
};

pub const RpEntity = struct {
    id: []const u8,
    name: ?[]const u8 = null,
};

pub const UserEntity = struct {
    id: []const u8,
    name: ?[]const u8 = null,
    display_name: ?[]const u8 = null,
};

/// The `options` map: `null` leaves the key out.
pub const Options = struct {
    rk: ?bool = null,
    up: ?bool = null,
    uv: ?bool = null,
};

pub const MakeCredentialRequest = struct {
    client_data_hash: [32]u8,
    rp: RpEntity,
    user: UserEntity,
    /// COSE algorithm numbers in order of preference (-7 ES256, -257 RS256, -8 EdDSA, ...); type `"public-key"`.
    pub_key_cred_params: []const i64,
    exclude_list: []const CredentialDescriptor = &.{},
    /// The extension inputs, already built: text key to CBOR value (`credProtect`: 2, `hmac-secret`: true, ...).
    extensions: []const MapEntry = &.{},
    options: Options = .{},
    pin_uv_auth_param: ?[]const u8 = null,
    pin_uv_auth_protocol: ?ctap2pin.Protocol = null,
    /// `enterpriseAttestation` (1 vendor-facilitated, 2 platform-managed).
    enterprise_attestation: ?u8 = null,
};

pub const GetAssertionRequest = struct {
    rp_id: []const u8,
    client_data_hash: [32]u8,
    allow_list: []const CredentialDescriptor = &.{},
    extensions: []const MapEntry = &.{},
    options: Options = .{},
    pin_uv_auth_param: ?[]const u8 = null,
    pin_uv_auth_protocol: ?ctap2pin.Protocol = null,
};

// ── request encoding ────────────────────────────────────────────────────────

fn text(s: []const u8) Value {
    return .{ .text = s };
}

fn textKey(k: []const u8, v: Value) MapEntry {
    return .{ .key = text(k), .value = v };
}

fn uintKey(k: u64, v: Value) MapEntry {
    return .{ .key = .{ .uint = k }, .value = v };
}

fn descriptor(arena: Allocator, d: CredentialDescriptor) Allocator.Error!Value {
    var entries: std.ArrayList(MapEntry) = .empty;
    try entries.append(arena, textKey("type", text("public-key")));
    try entries.append(arena, textKey("id", .{ .bytes = d.id }));
    if (d.transports.len != 0) {
        const items = try arena.alloc(Value, d.transports.len);
        for (d.transports, items) |t, *it| it.* = text(t);
        try entries.append(arena, textKey("transports", .{ .array = items }));
    }
    return .{ .map = entries.items };
}

fn descriptorArray(arena: Allocator, list: []const CredentialDescriptor) Allocator.Error!Value {
    const items = try arena.alloc(Value, list.len);
    for (list, items) |d, *it| it.* = try descriptor(arena, d);
    return .{ .array = items };
}

fn optionsMap(arena: Allocator, o: Options) Allocator.Error!?Value {
    var entries: std.ArrayList(MapEntry) = .empty;
    if (o.rk) |b| try entries.append(arena, textKey("rk", .{ .bool = b }));
    if (o.up) |b| try entries.append(arena, textKey("up", .{ .bool = b }));
    if (o.uv) |b| try entries.append(arena, textKey("uv", .{ .bool = b }));
    if (entries.items.len == 0) return null;
    return .{ .map = entries.items };
}

fn checkAuth(param: ?[]const u8, protocol: ?ctap2pin.Protocol) error{InvalidRequest}!void {
    if ((param == null) != (protocol == null)) return error.InvalidRequest;
    if (param) |p| if (p.len != 16 and p.len != 32) return error.InvalidRequest;
}

/// The CBOR map of an `authenticatorMakeCredential` request (`encodeRequest(0x01, this)` is the message).
pub fn makeCredentialParams(arena: Allocator, req: MakeCredentialRequest) (Allocator.Error || error{InvalidRequest})!Value {
    if (req.rp.id.len == 0 or req.pub_key_cred_params.len == 0 or req.user.id.len == 0 or req.user.id.len > 64) return error.InvalidRequest;
    try checkAuth(req.pin_uv_auth_param, req.pin_uv_auth_protocol);

    var entries: std.ArrayList(MapEntry) = .empty;
    try entries.append(arena, uintKey(0x01, .{ .bytes = try arena.dupe(u8, &req.client_data_hash) }));

    var rp: std.ArrayList(MapEntry) = .empty;
    try rp.append(arena, textKey("id", text(req.rp.id)));
    if (req.rp.name) |n| try rp.append(arena, textKey("name", text(n)));
    try entries.append(arena, uintKey(0x02, .{ .map = rp.items }));

    var user: std.ArrayList(MapEntry) = .empty;
    try user.append(arena, textKey("id", .{ .bytes = req.user.id }));
    if (req.user.name) |n| try user.append(arena, textKey("name", text(n)));
    if (req.user.display_name) |n| try user.append(arena, textKey("displayName", text(n)));
    try entries.append(arena, uintKey(0x03, .{ .map = user.items }));

    const params = try arena.alloc(Value, req.pub_key_cred_params.len);
    for (req.pub_key_cred_params, params) |alg, *p| {
        const e = try arena.alloc(MapEntry, 2);
        e[0] = textKey("alg", Value.fromI64(alg));
        e[1] = textKey("type", text("public-key"));
        p.* = .{ .map = e };
    }
    try entries.append(arena, uintKey(0x04, .{ .array = params }));

    if (req.exclude_list.len != 0) try entries.append(arena, uintKey(0x05, try descriptorArray(arena, req.exclude_list)));
    if (req.extensions.len != 0) try entries.append(arena, uintKey(0x06, .{ .map = req.extensions }));
    if (try optionsMap(arena, req.options)) |o| try entries.append(arena, uintKey(0x07, o));
    if (req.pin_uv_auth_param) |p| {
        try entries.append(arena, uintKey(0x08, .{ .bytes = p }));
        try entries.append(arena, uintKey(0x09, .{ .uint = @backingInt(req.pin_uv_auth_protocol.?) }));
    }
    if (req.enterprise_attestation) |e| try entries.append(arena, uintKey(0x0A, .{ .uint = e }));
    return .{ .map = entries.items };
}

/// The CBOR map of an `authenticatorGetAssertion` request.
pub fn getAssertionParams(arena: Allocator, req: GetAssertionRequest) (Allocator.Error || error{InvalidRequest})!Value {
    if (req.rp_id.len == 0) return error.InvalidRequest;
    try checkAuth(req.pin_uv_auth_param, req.pin_uv_auth_protocol);

    var entries: std.ArrayList(MapEntry) = .empty;
    try entries.append(arena, uintKey(0x01, text(req.rp_id)));
    try entries.append(arena, uintKey(0x02, .{ .bytes = try arena.dupe(u8, &req.client_data_hash) }));
    if (req.allow_list.len != 0) try entries.append(arena, uintKey(0x03, try descriptorArray(arena, req.allow_list)));
    if (req.extensions.len != 0) try entries.append(arena, uintKey(0x04, .{ .map = req.extensions }));
    if (try optionsMap(arena, req.options)) |o| try entries.append(arena, uintKey(0x05, o));
    if (req.pin_uv_auth_param) |p| {
        try entries.append(arena, uintKey(0x06, .{ .bytes = p }));
        try entries.append(arena, uintKey(0x07, .{ .uint = @backingInt(req.pin_uv_auth_protocol.?) }));
    }
    return .{ .map = entries.items };
}

// ── response parsing (pure; fuzzed) ─────────────────────────────────────────

/// Fixed part of authenticator data: rpIdHash (32), flags (1), signCount (4).
const min_auth_data_len = 37;

fn asText(v: Value) framing.ParseError![]const u8 {
    return switch (v) {
        .text => |t| t,
        else => error.UnexpectedType,
    };
}

fn asMap(v: Value) framing.ParseError![]const MapEntry {
    return switch (v) {
        .map => |m| m,
        else => error.UnexpectedType,
    };
}

fn findText(entries: []const MapEntry, key: []const u8) framing.ParseError!?Value {
    var found: ?Value = null;
    for (entries) |e| switch (e.key) {
        .text => |k| if (std.mem.eql(u8, k, key)) {
            if (found != null) return error.DuplicateKey;
            found = e.value;
        },
        else => {},
    };
    return found;
}

pub const ParsedDescriptor = struct {
    id: []const u8,
    transports: []const []const u8 = &.{},
};

fn parseDescriptor(arena: Allocator, v: Value) (framing.ParseError || Allocator.Error)!ParsedDescriptor {
    const m = try asMap(v);
    const ty = try asText((try findText(m, "type")) orelse return error.MissingField);
    if (!std.mem.eql(u8, ty, "public-key")) return error.UnexpectedType;
    const id = try framing.asBytes((try findText(m, "id")) orelse return error.MissingField);
    if (id.len == 0) return error.BadLength;
    var out: ParsedDescriptor = .{ .id = id };
    if (try findText(m, "transports")) |t| {
        const arr = switch (t) {
            .array => |a| a,
            else => return error.UnexpectedType,
        };
        const items = try arena.alloc([]const u8, arr.len);
        for (arr, items) |e, *it| it.* = try asText(e);
        out.transports = items;
    }
    return out;
}

pub const ParsedUser = struct {
    id: []const u8,
    name: ?[]const u8 = null,
    display_name: ?[]const u8 = null,
};

fn parseUser(v: Value) framing.ParseError!ParsedUser {
    const m = try asMap(v);
    var out: ParsedUser = .{ .id = try framing.asBytes((try findText(m, "id")) orelse return error.MissingField) };
    if (try findText(m, "name")) |n| out.name = try asText(n);
    if (try findText(m, "displayName")) |n| out.display_name = try asText(n);
    return out;
}

fn checkAuthData(b: []const u8) framing.ParseError!void {
    if (b.len < min_auth_data_len) return error.BadLength;
}

fn optLargeBlobKey(v: ?Value) framing.ParseError!?[]const u8 {
    const x = v orelse return null;
    const b = try framing.asBytes(x);
    if (b.len != 32) return error.BadLength;
    return b;
}

pub const MakeCredentialResponse = struct {
    /// Attestation statement format identifier (`packed`, `tpm`, `none`, `fido-u2f`, ...).
    fmt: []const u8,
    /// Authenticator data (rpIdHash, flags, signCount, attested credential data, extensions): `webauthn`'s
    /// `parseAuthenticatorData` reads it.
    auth_data: []const u8,
    /// The attestation statement map, as returned.
    att_stmt: Value,
    /// `epAtt`: an enterprise attestation was returned.
    ep_att: ?bool = null,
    large_blob_key: ?[]const u8 = null,
};

/// Parse an `authenticatorMakeCredential` response body (`allocator`: an arena).
pub fn parseMakeCredentialResponse(allocator: Allocator, body: []const u8) (framing.ParseError || Allocator.Error)!MakeCredentialResponse {
    const entries = try framing.decodeMap(allocator, body);
    const fmt = try asText((try framing.find(entries, 0x01)) orelse return error.MissingField);
    const auth_data = try framing.asBytes((try framing.find(entries, 0x02)) orelse return error.MissingField);
    try checkAuthData(auth_data);
    const att = (try framing.find(entries, 0x03)) orelse return error.MissingField;
    _ = try asMap(att);
    var out: MakeCredentialResponse = .{ .fmt = fmt, .auth_data = auth_data, .att_stmt = att };
    if (try framing.find(entries, 0x04)) |v| out.ep_att = try framing.asBool(v);
    out.large_blob_key = try optLargeBlobKey(try framing.find(entries, 0x05));
    return out;
}

/// The WebAuthn attestation object (`{"fmt", "attStmt", "authData"}`, canonical CBOR) of a response: what a relying
/// party's `webauthn.verifyAttestation` / `verifyRegistration` takes.
pub fn attestationObject(allocator: Allocator, resp: MakeCredentialResponse) cbor.EncodeError![]u8 {
    const entries = [_]MapEntry{
        textKey("fmt", text(resp.fmt)),
        textKey("attStmt", resp.att_stmt),
        textKey("authData", .{ .bytes = resp.auth_data }),
    };
    return cbor.encode(allocator, .{ .map = &entries }, .{ .canonical = true });
}

pub const Assertion = struct {
    /// The credential used; absent when the authenticator left it out (a one-entry allow list).
    credential: ?ParsedDescriptor = null,
    auth_data: []const u8,
    signature: []const u8,
    user: ?ParsedUser = null,
    /// `numberOfCredentials`: only in the first response of several.
    number_of_credentials: ?u32 = null,
    user_selected: ?bool = null,
    large_blob_key: ?[]const u8 = null,
};

/// Parse an `authenticatorGetAssertion` / `authenticatorGetNextAssertion` response body (`allocator`: an arena).
pub fn parseAssertionResponse(allocator: Allocator, body: []const u8) (framing.ParseError || Allocator.Error)!Assertion {
    const entries = try framing.decodeMap(allocator, body);
    const auth_data = try framing.asBytes((try framing.find(entries, 0x02)) orelse return error.MissingField);
    try checkAuthData(auth_data);
    const signature = try framing.asBytes((try framing.find(entries, 0x03)) orelse return error.MissingField);
    var out: Assertion = .{ .auth_data = auth_data, .signature = signature };
    if (try framing.find(entries, 0x01)) |v| out.credential = try parseDescriptor(allocator, v);
    if (try framing.find(entries, 0x04)) |v| out.user = try parseUser(v);
    if (try framing.find(entries, 0x05)) |v| out.number_of_credentials = try framing.asU32(v);
    if (try framing.find(entries, 0x06)) |v| out.user_selected = try framing.asBool(v);
    out.large_blob_key = try optLargeBlobKey(try framing.find(entries, 0x07));
    return out;
}

// ── commands ────────────────────────────────────────────────────────────────

/// `authenticatorMakeCredential`. Blocks for as long as the transport does (the user's touch); a status such as
/// `error.CredentialExcluded`, `error.OperationDenied`, `error.UserActionTimeout`, `error.PinInvalid` is the typed
/// answer. `arena` owns the result.
pub fn makeCredential(arena: Allocator, transport: framing.Transport, req: MakeCredentialRequest, max_response: usize) CredentialError!MakeCredentialResponse {
    const params = try makeCredentialParams(arena, req);
    const resp = try framing.call(arena, transport, @backingInt(framing.Command.make_credential), params, max_response);
    return parseMakeCredentialResponse(arena, resp.body);
}

/// `authenticatorGetAssertion`: the first assertion (`number_of_credentials` says how many there are in all; the
/// rest come from `getNextAssertion`, or all at once from `getAssertions`).
pub fn getAssertion(arena: Allocator, transport: framing.Transport, req: GetAssertionRequest, max_response: usize) CredentialError!Assertion {
    const params = try getAssertionParams(arena, req);
    const resp = try framing.call(arena, transport, @backingInt(framing.Command.get_assertion), params, max_response);
    return parseAssertionResponse(arena, resp.body);
}

/// `authenticatorGetNextAssertion` (no parameters).
pub fn getNextAssertion(arena: Allocator, transport: framing.Transport, max_response: usize) CredentialError!Assertion {
    const resp = try framing.call(arena, transport, @backingInt(framing.Command.get_next_assertion), null, max_response);
    return parseAssertionResponse(arena, resp.body);
}

/// `getAssertion` followed by `getNextAssertion` until `numberOfCredentials` assertions are in (at most
/// `max_assertions`). The first element carries `number_of_credentials`.
pub fn getAssertions(arena: Allocator, transport: framing.Transport, req: GetAssertionRequest, max_response: usize) CredentialError![]const Assertion {
    const first = try getAssertion(arena, transport, req, max_response);
    const total = first.number_of_credentials orelse 1;
    if (total == 0 or total > max_assertions) return error.ValueOutOfRange;
    const out = try arena.alloc(Assertion, total);
    out[0] = first;
    for (out[1..]) |*a| a.* = try getNextAssertion(arena, transport, max_response);
    return out;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const vectors = @import("credential_vectors.zig");
const testutil = @import("testutil.zig");

fn caseByName(name: []const u8) vectors.Case {
    for (vectors.cases) |c| if (std.mem.eql(u8, c.name, name)) return c;
    unreachable;
}

const cdh: [32]u8 = @import("fido2_vectors.zig").hex("a1d4f7a3e2d4d6a1a5b2f0c5e9d6f0a3a7c5b3b8d1c2e3f40516273849a0b1c2");

fn sha256(s: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(s, &out, .{});
    return out;
}

const user_alice: UserEntity = .{ .id = &.{ 1, 2, 3, 4 }, .name = "alice", .display_name = "Alice A." };

test "makeCredential: request bytes equal python-fido2's, minimal and fully loaded, both PIN protocols" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const rp: RpEntity = .{ .id = "example.com", .name = "Example" };

    const minimal = try framing.encodeRequest(a, 0x01, try makeCredentialParams(a, .{
        .client_data_hash = sha256("client data"),
        .rp = rp,
        .user = user_alice,
        .pub_key_cred_params = &.{-7},
    }));
    try testing.expectEqualSlices(u8, caseByName("mc_minimal").requests[0], minimal);

    const ext = [_]MapEntry{ textKey("credProtect", .{ .uint = 2 }), textKey("hmac-secret", .{ .bool = true }) };
    const aa = @as([16]u8, @splat(0xaa));
    const bb = @as([20]u8, @splat(0xbb));
    const excl = [_]CredentialDescriptor{ .{ .id = &aa }, .{ .id = &bb, .transports = &.{ "usb", "nfc" } } };
    const auth16: [16]u8 = blk: {
        var b: [16]u8 = undefined;
        for (&b, 0..) |*x, i| x.* = @intCast(i);
        break :blk b;
    };
    const full = try framing.encodeRequest(a, 0x01, try makeCredentialParams(a, .{
        .client_data_hash = sha256("client data"),
        .rp = rp,
        .user = user_alice,
        .pub_key_cred_params = &.{ -7, -257, -8 },
        .exclude_list = &excl,
        .extensions = &ext,
        .options = .{ .rk = true, .uv = false },
        .pin_uv_auth_param = &auth16,
        .pin_uv_auth_protocol = .one,
        .enterprise_attestation = 2,
    }));
    try testing.expectEqualSlices(u8, caseByName("mc_full_protocol1").requests[0], full);

    var auth32: [32]u8 = undefined;
    for (&auth32, 0..) |*x, i| x.* = @intCast(i);
    const p2 = try framing.encodeRequest(a, 0x01, try makeCredentialParams(a, .{
        .client_data_hash = sha256("client data 2"),
        .rp = .{ .id = "example.com" },
        .user = .{ .id = &.{7} },
        .pub_key_cred_params = &.{-7},
        .options = .{ .rk = true },
        .pin_uv_auth_param = &auth32,
        .pin_uv_auth_protocol = .two,
    }));
    try testing.expectEqualSlices(u8, caseByName("mc_protocol2").requests[0], p2);
}

test "getAssertion / getNextAssertion: request bytes equal python-fido2's" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const minimal = try framing.encodeRequest(a, 0x02, try getAssertionParams(a, .{ .rp_id = "example.com", .client_data_hash = sha256("client data") }));
    try testing.expectEqualSlices(u8, caseByName("ga_minimal").requests[0], minimal);

    var cred_id: [32]u8 = undefined;
    for (&cred_id, 0..) |*x, i| x.* = @intCast(i);
    const cc = @as([8]u8, @splat(0xcc));
    const allow = [_]CredentialDescriptor{ .{ .id = &cred_id }, .{ .id = &cc, .transports = &.{"internal"} } };
    const ext = [_]MapEntry{textKey("credBlob", .{ .bool = true })};
    var auth32: [32]u8 = undefined;
    for (&auth32, 0..) |*x, i| x.* = @intCast(i);
    const full = try framing.encodeRequest(a, 0x02, try getAssertionParams(a, .{
        .rp_id = "example.com",
        .client_data_hash = sha256("client data 2"),
        .allow_list = &allow,
        .extensions = &ext,
        .options = .{ .up = false, .uv = true },
        .pin_uv_auth_param = &auth32,
        .pin_uv_auth_protocol = .two,
    }));
    const vc = caseByName("ga_full_protocol2");
    try testing.expectEqualSlices(u8, vc.requests[0], full);
    try testing.expectEqualSlices(u8, vc.requests[1], &.{0x08}); // getNextAssertion: the command byte alone
    const next = try framing.encodeRequest(a, 0x08, null);
    try testing.expectEqualSlices(u8, vc.requests[1], next);
}

test "makeCredential end to end over a scripted transport: python-fido2's request, the scripted response parsed" {
    var script = testutil.ScriptTransport.init(testing.allocator, caseByName("mc_full_protocol1").responses);
    defer script.deinit();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const ext = [_]MapEntry{ textKey("credProtect", .{ .uint = 2 }), textKey("hmac-secret", .{ .bool = true }) };
    const aa = @as([16]u8, @splat(0xaa));
    const bb = @as([20]u8, @splat(0xbb));
    const excl = [_]CredentialDescriptor{ .{ .id = &aa }, .{ .id = &bb, .transports = &.{ "usb", "nfc" } } };
    var auth16: [16]u8 = undefined;
    for (&auth16, 0..) |*x, i| x.* = @intCast(i);
    const resp = try makeCredential(a, script.transport(), .{
        .client_data_hash = sha256("client data"),
        .rp = .{ .id = "example.com", .name = "Example" },
        .user = user_alice,
        .pub_key_cred_params = &.{ -7, -257, -8 },
        .exclude_list = &excl,
        .extensions = &ext,
        .options = .{ .rk = true, .uv = false },
        .pin_uv_auth_param = &auth16,
        .pin_uv_auth_protocol = .one,
        .enterprise_attestation = 2,
    }, default_max_response);
    try testing.expectEqualSlices(u8, caseByName("mc_full_protocol1").requests[0], script.requests.items[0]);
    try testing.expectEqualStrings("packed", resp.fmt);
    try testing.expectEqual(@as(?bool, true), resp.ep_att);
    try testing.expectEqual(@as(usize, 32), resp.large_blob_key.?.len);
    try testing.expectEqualSlices(u8, &@import("fido2_vectors.zig").hex(vectors.rp_id_hash), resp.auth_data[0..32]);
    try testing.expectEqual(@as(u8, 0xC5), resp.auth_data[32]);
    const sig = (try findText(try asMap(resp.att_stmt), "sig")).?;
    try testing.expectEqualSlices(u8, &@import("fido2_vectors.zig").hex(vectors.signature), sig.bytes);
    // The attestation object has the three WebAuthn members and round-trips through cbor.
    const obj = try attestationObject(a, resp);
    const v = try cbor.decode(a, obj, .{});
    const m = try asMap(v);
    try testing.expectEqualStrings("packed", (try asText((try findText(m, "fmt")).?)));
    try testing.expectEqualSlices(u8, resp.auth_data, (try findText(m, "authData")).?.bytes);
    try testing.expect((try findText(m, "attStmt")) != null);
}

test "getAssertions: the first assertion and the next one, user and credential parsed" {
    var script = testutil.ScriptTransport.init(testing.allocator, caseByName("ga_full_protocol2").responses);
    defer script.deinit();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const list = try getAssertions(a, script.transport(), .{ .rp_id = "example.com", .client_data_hash = sha256("client data 2") }, default_max_response);
    try testing.expectEqual(@as(usize, 2), list.len);
    try testing.expectEqual(@as(?u32, 2), list[0].number_of_credentials);
    try testing.expectEqual(@as(usize, 32), list[0].credential.?.id.len);
    try testing.expectEqualStrings("alice", list[0].user.?.name.?);
    try testing.expectEqualStrings("Alice A.", list[0].user.?.display_name.?);
    try testing.expectEqual(@as(usize, 32), list[0].large_blob_key.?.len);
    try testing.expectEqual(@as(u8, 31), list[1].credential.?.id[0]); // the reversed id
    try testing.expectEqual(@as(?u32, null), list[1].number_of_credentials);
    try testing.expectEqual(@as(usize, 2), list[1].user.?.id.len);
    try testing.expectEqual(@as(usize, 2), script.requests.items.len);
    try testing.expectEqualSlices(u8, &.{0x08}, script.requests.items[1]);
    // The minimal answer has no user and no credential count.
    var s2 = testutil.ScriptTransport.init(testing.allocator, caseByName("ga_minimal").responses);
    defer s2.deinit();
    const one = try getAssertion(a, s2.transport(), .{ .rp_id = "example.com", .client_data_hash = sha256("client data") }, default_max_response);
    try testing.expect(one.user == null and one.number_of_credentials == null);
    try testing.expectEqual(@as(usize, 37), one.auth_data.len);
}

test "credential commands: refusals, typed statuses and malformed responses" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const base: MakeCredentialRequest = .{ .client_data_hash = cdh, .rp = .{ .id = "x" }, .user = .{ .id = &.{1} }, .pub_key_cred_params = &.{-7} };
    var bad = base;
    bad.rp.id = "";
    try testing.expectError(error.InvalidRequest, makeCredentialParams(a, bad));
    bad = base;
    bad.pub_key_cred_params = &.{};
    try testing.expectError(error.InvalidRequest, makeCredentialParams(a, bad));
    bad = base;
    bad.pin_uv_auth_param = &(@as([16]u8, @splat(0))); // no protocol
    try testing.expectError(error.InvalidRequest, makeCredentialParams(a, bad));
    bad = base;
    bad.pin_uv_auth_param = &(@as([20]u8, @splat(0))); // neither 16 nor 32
    bad.pin_uv_auth_protocol = .one;
    try testing.expectError(error.InvalidRequest, makeCredentialParams(a, bad));
    const long_id = @as([65]u8, @splat(1));
    bad = base;
    bad.user.id = &long_id;
    try testing.expectError(error.InvalidRequest, makeCredentialParams(a, bad));
    try testing.expectError(error.InvalidRequest, getAssertionParams(a, .{ .rp_id = "", .client_data_hash = cdh }));

    // Authenticator statuses.
    for ([_]struct { code: u8, err: anyerror }{
        .{ .code = 0x19, .err = error.CredentialExcluded },
        .{ .code = 0x2E, .err = error.NoCredentials },
        .{ .code = 0x27, .err = error.OperationDenied },
        .{ .code = 0x2F, .err = error.UserActionTimeout },
        .{ .code = 0x31, .err = error.PinInvalid },
    }) |c| {
        var s = testutil.ScriptTransport.init(testing.allocator, &.{&.{c.code}});
        defer s.deinit();
        try testing.expectError(c.err, makeCredential(a, s.transport(), base, default_max_response));
        var s2 = testutil.ScriptTransport.init(testing.allocator, &.{&.{c.code}});
        defer s2.deinit();
        try testing.expectError(c.err, getAssertion(a, s2.transport(), .{ .rp_id = "x", .client_data_hash = cdh }, default_max_response));
    }

    // Malformed response bodies: each missing / mistyped field is its own error, never a panic.
    const ad = @as([37]u8, @splat(0));
    const sig = @as([8]u8, @splat(1));
    const good_mc = [_]MapEntry{
        uintKey(1, text("none")), uintKey(2, .{ .bytes = &ad }), uintKey(3, .{ .map = &.{} }),
    };
    const enc = struct {
        fn f(al: Allocator, entries: []const MapEntry) ![]u8 {
            return cbor.encode(al, .{ .map = entries }, .{ .canonical = true });
        }
    }.f;
    _ = try parseMakeCredentialResponse(a, try enc(a, &good_mc));
    try testing.expectError(error.MissingField, parseMakeCredentialResponse(a, try enc(a, good_mc[1..])));
    try testing.expectError(error.MissingField, parseMakeCredentialResponse(a, try enc(a, good_mc[0..2])));
    const short_ad = [_]MapEntry{ good_mc[0], uintKey(2, .{ .bytes = ad[0..36] }), good_mc[2] };
    try testing.expectError(error.BadLength, parseMakeCredentialResponse(a, try enc(a, &short_ad)));
    const att_not_map = [_]MapEntry{ good_mc[0], good_mc[1], uintKey(3, .{ .uint = 1 }) };
    try testing.expectError(error.UnexpectedType, parseMakeCredentialResponse(a, try enc(a, &att_not_map)));
    const lbk_short = [_]MapEntry{ good_mc[0], good_mc[1], good_mc[2], uintKey(5, .{ .bytes = ad[0..31] }) };
    try testing.expectError(error.BadLength, parseMakeCredentialResponse(a, try enc(a, &lbk_short)));
    try testing.expectError(error.MalformedCbor, parseMakeCredentialResponse(a, &.{ 0xa1, 0x01 }));
    try testing.expectError(error.EmptyResponse, parseMakeCredentialResponse(a, ""));

    const good_ga = [_]MapEntry{ uintKey(2, .{ .bytes = &ad }), uintKey(3, .{ .bytes = &sig }) };
    _ = try parseAssertionResponse(a, try enc(a, &good_ga));
    try testing.expectError(error.MissingField, parseAssertionResponse(a, try enc(a, good_ga[0..1])));
    const bad_cred = [_]MapEntry{ good_ga[0], good_ga[1], uintKey(1, .{ .map = &.{} }) };
    try testing.expectError(error.MissingField, parseAssertionResponse(a, try enc(a, &bad_cred)));
    const cred_type = [_]MapEntry{ textKey("type", text("other")), textKey("id", .{ .bytes = &sig }) };
    const bad_type = [_]MapEntry{ good_ga[0], good_ga[1], uintKey(1, .{ .map = &cred_type }) };
    try testing.expectError(error.UnexpectedType, parseAssertionResponse(a, try enc(a, &bad_type)));
    const huge_n = [_]MapEntry{ good_ga[0], good_ga[1], uintKey(5, .{ .uint = 1 << 40 }) };
    try testing.expectError(error.ValueOutOfRange, parseAssertionResponse(a, try enc(a, &huge_n)));

    // `numberOfCredentials` above the cap is refused before any further transaction.
    const many = [_]MapEntry{ good_ga[0], good_ga[1], uintKey(5, .{ .uint = max_assertions + 1 }) };
    var resp: [64]u8 = undefined;
    resp[0] = 0;
    const body = try enc(a, &many);
    @memcpy(resp[1..][0..body.len], body);
    var s3 = testutil.ScriptTransport.init(testing.allocator, &.{resp[0 .. 1 + body.len]});
    defer s3.deinit();
    try testing.expectError(error.ValueOutOfRange, getAssertions(a, s3.transport(), .{ .rp_id = "x", .client_data_hash = cdh }, default_max_response));
}

test "the make-credential response's authenticator data is what webauthn parses" {
    const webauthn = @import("webauthn");
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const hex = @import("fido2_vectors.zig").hex;
    const body = caseByName("mc_minimal").responses[0][1..];
    const resp = try parseMakeCredentialResponse(a, body);
    const ad = try webauthn.parseAuthenticatorData(a, resp.auth_data);
    try testing.expectEqualSlices(u8, &hex(vectors.rp_id_hash), &ad.rp_id_hash);
    try testing.expect(ad.flags.user_present and ad.flags.attested_credential_data);
    try testing.expectEqual(@as(u32, 7), ad.sign_count);
    try testing.expectEqualSlices(u8, &hex(vectors.aaguid), &ad.attested_credential_data.?.aaguid);
    try testing.expectEqualSlices(u8, &hex(vectors.cred_id), ad.attested_credential_data.?.credential_id);
}
