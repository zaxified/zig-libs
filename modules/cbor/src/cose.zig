// SPDX-License-Identifier: MIT
//! cose — minimal RFC 9052 (CBOR Object Signing and Encryption) layer over
//! the sibling `cbor` codec: parse a `COSE_Key` (EC2 + OKP) into a typed
//! struct, parse/build `COSE_Sign1`, and build the `Sig_structure` bytes a
//! signer/verifier feeds to its signature algorithm. This is exactly the
//! slice WebAuthn/FIDO2 needs to pull an authenticator's public key out of
//! an attestation object and verify a signature over it — the actual
//! ECDSA/EdDSA math stays in the sibling `p256`/`ed448`/etc. modules; this
//! module never re-hand-rolls CBOR (everything routes through `cbor.Value`/
//! `cbor.decode`/`cbor.encode`) and never implements a signature algorithm
//! itself.
//!
//! **Deliberately out of scope** (see README "Deferred"): private-key
//! material (`d`, COSE label -4) is never parsed or emitted — this is a
//! verifier/public-key-consumer layer, not a key-storage format; COSE_Mac0/
//! COSE_Encrypt0/full COSE_Sign (multi-signer) are not implemented; RSA and
//! symmetric COSE key types are not modeled (`parseKey` returns
//! `error.UnsupportedKty` for anything but EC2/OKP).
//!
//! Provenance: RFC 9052 (COSE, STD); clean-room from the spec, no
//! third-party COSE implementation consulted (CONVENTIONS.md §5 merger
//! doctrine — no NOTICE entry needed).

const std = @import("std");
const Allocator = std.mem.Allocator;
const cbor = @import("root.zig");
const Value = cbor.Value;
const MapEntry = cbor.MapEntry;

// ── registered parameter labels (RFC 9052 §7 / RFC 9053) ───────────────────

/// COSE_Key common parameter labels (RFC 9052 §7, Table 3).
pub const label_kty: i64 = 1;
pub const label_alg: i64 = 3;

/// EC2/OKP key-type-specific parameter labels (RFC 9053 §7.1, Table 20/21 —
/// the same label numbers serve both key types).
pub const label_crv: i64 = -1;
pub const label_x: i64 = -2;
pub const label_y: i64 = -3;
// label -4 ("d", the private key) is intentionally never referenced here.

/// COSE key type values (RFC 9052 §7, Table 4 / IANA COSE Key Types).
pub const kty_okp: i64 = 1;
pub const kty_ec2: i64 = 2;

/// A selection of COSE algorithm identifiers (RFC 9053 §2/§7, IANA COSE
/// Algorithms) — the ones a WebAuthn/COSE consumer of this module is likely
/// to see in the wild. Not exhaustive; `Ec2Key.alg`/`OkpKey.alg` carry the
/// raw `i64` regardless, so an unlisted algorithm still round-trips.
pub const alg_es256: i64 = -7;
pub const alg_eddsa: i64 = -8;
pub const alg_es384: i64 = -35;
pub const alg_es512: i64 = -36;

/// COSE elliptic-curve identifiers (RFC 9053 §7.1, Table 22).
pub const crv_p256: i64 = 1;
pub const crv_p384: i64 = 2;
pub const crv_p521: i64 = 3;
pub const crv_x25519: i64 = 4;
pub const crv_x448: i64 = 5;
pub const crv_ed25519: i64 = 6;
pub const crv_ed448: i64 = 7;

// ── COSE_Key ─────────────────────────────────────────────────────────────────

pub const KeyError = error{
    /// The `cbor.Value` isn't a map at all.
    NotAMap,
    /// A required field (`kty`, `crv`, `x`, or for EC2 `y`) is absent.
    MissingField,
    /// A field is present but the wrong CBOR type (e.g. `x` isn't a byte string).
    WrongType,
    /// `kty` is present and well-typed but not EC2 (2) or OKP (1) — the only
    /// two key types this module models.
    UnsupportedKty,
};

/// An EC2 (double-coordinate elliptic curve) public key (RFC 9053 §7.1) —
/// the shape `ctap2pin`'s `PublicKey{x,y}` uses inline for P-256, made
/// generic over the COSE `crv` label and carrying `alg`. `x`/`y` are the
/// big-endian field-element encodings, exactly as they appear on the wire
/// (not curve-validated here — the consuming curve module, e.g. `p256`'s
/// `Fe.fromBytes` + `fromAffineCoordinates`, does that).
pub const Ec2Key = struct {
    /// COSE algorithm (label 3), if present.
    alg: ?i64,
    /// COSE curve (label -1), e.g. `crv_p256`.
    crv: i64,
    x: []const u8,
    y: []const u8,
};

/// An OKP (octet key pair — Ed25519/X25519-family) public key (RFC 9053
/// §7.2): a single coordinate `x`, no `y`.
pub const OkpKey = struct {
    alg: ?i64,
    crv: i64,
    x: []const u8,
};

pub const Key = union(enum) {
    ec2: Ec2Key,
    okp: OkpKey,
};

fn labelValue(label: i64) Value {
    return Value.fromI64(label);
}

fn labelMatches(key: Value, label: i64) bool {
    return switch (key) {
        .uint, .negint => (key.toI64() orelse return false) == label,
        else => false,
    };
}

fn mapGet(entries: []const MapEntry, label: i64) ?Value {
    for (entries) |e| {
        if (labelMatches(e.key, label)) return e.value;
    }
    return null;
}

fn intField(entries: []const MapEntry, label: i64) KeyError!?i64 {
    const v = mapGet(entries, label) orelse return null;
    return v.toI64() orelse return error.WrongType;
}

fn requiredIntField(entries: []const MapEntry, label: i64) KeyError!i64 {
    return (try intField(entries, label)) orelse error.MissingField;
}

fn bstrField(entries: []const MapEntry, label: i64) KeyError![]const u8 {
    const v = mapGet(entries, label) orelse return error.MissingField;
    return switch (v) {
        .bytes => |b| b,
        else => error.WrongType,
    };
}

/// Parse a `COSE_Key` map (RFC 9052 §7) into a typed `Key`. `value` must be
/// a `cbor.Value.map` (decode it first, e.g. via `cbor.decode`); returned
/// slices borrow `value`'s own byte-string slices (no fresh allocation —
/// keep the decoded `Value` tree, and the allocator it was decoded into,
/// alive as long as the `Key`).
pub fn parseKey(value: Value) KeyError!Key {
    const entries = switch (value) {
        .map => |m| m,
        else => return error.NotAMap,
    };
    const kty = try requiredIntField(entries, label_kty);
    const alg = try intField(entries, label_alg);
    const crv = try requiredIntField(entries, label_crv);
    const x = try bstrField(entries, label_x);

    return switch (kty) {
        kty_ec2 => .{ .ec2 = .{ .alg = alg, .crv = crv, .x = x, .y = try bstrField(entries, label_y) } },
        kty_okp => .{ .okp = .{ .alg = alg, .crv = crv, .x = x } },
        else => error.UnsupportedKty,
    };
}

/// Build the `cbor.Value` map for an EC2 `COSE_Key` (RFC 9053 §7.1) — the
/// EC2/P-256 shape `ctap2pin`'s `PublicKey{x,y}` generalizes to any curve.
/// Field order: kty, [alg], crv, x, y (kty=2/EC2 fixed). Feed the result to
/// `cbor.encode` to get wire bytes.
pub fn encodeEc2Key(a: Allocator, k: Ec2Key) Allocator.Error!Value {
    var list: std.ArrayList(MapEntry) = .empty;
    try list.append(a, .{ .key = labelValue(label_kty), .value = .{ .uint = @intCast(kty_ec2) } });
    if (k.alg) |alg| try list.append(a, .{ .key = labelValue(label_alg), .value = labelValue(alg) });
    try list.append(a, .{ .key = labelValue(label_crv), .value = labelValue(k.crv) });
    try list.append(a, .{ .key = labelValue(label_x), .value = .{ .bytes = k.x } });
    try list.append(a, .{ .key = labelValue(label_y), .value = .{ .bytes = k.y } });
    return .{ .map = try list.toOwnedSlice(a) };
}

/// Build the `cbor.Value` map for an OKP `COSE_Key` (RFC 9053 §7.2). Field
/// order: kty, [alg], crv, x (kty=1/OKP fixed).
pub fn encodeOkpKey(a: Allocator, k: OkpKey) Allocator.Error!Value {
    var list: std.ArrayList(MapEntry) = .empty;
    try list.append(a, .{ .key = labelValue(label_kty), .value = .{ .uint = @intCast(kty_okp) } });
    if (k.alg) |alg| try list.append(a, .{ .key = labelValue(label_alg), .value = labelValue(alg) });
    try list.append(a, .{ .key = labelValue(label_crv), .value = labelValue(k.crv) });
    try list.append(a, .{ .key = labelValue(label_x), .value = .{ .bytes = k.x } });
    return .{ .map = try list.toOwnedSlice(a) };
}

// ── COSE_Sign1 (RFC 9052 §4.2) ──────────────────────────────────────────────

pub const Sign1Error = error{
    /// Not a 4-element array (after optionally unwrapping a tag-18 wrapper).
    NotSign1,
    WrongType,
};

/// A parsed/to-be-built `COSE_Sign1` structure (RFC 9052 §4.2): the 4-tuple
/// `[protected, unprotected, payload, signature]`.
pub const Sign1 = struct {
    /// The protected header, still as its serialized `bstr .cbor
    /// header_map` bytes (RFC 9052 §3) — pass these bytes verbatim into
    /// `sigStructure`, don't re-encode a decoded map (re-encoding is not
    /// guaranteed byte-identical to what was signed unless it happened to
    /// be produced by this same encoder in canonical form).
    protected: []const u8,
    /// The unprotected header map's entries (not integrity-protected).
    unprotected: []const MapEntry,
    /// The payload `bstr`, or `null` for a detached payload (CBOR `null`
    /// where the wire has `nil`, RFC 9052 §4.1).
    payload: ?[]const u8,
    signature: []const u8,
};

/// Parse a `COSE_Sign1` (RFC 9052 §4.2). `value` may be the bare 4-element
/// array or that array wrapped in CBOR tag 18 (`COSE_Sign1` tag) — if
/// tagged, the tag number is not itself verified to be 18 (callers that
/// care can check `value.tag.number` before calling).
pub fn parseSign1(value: Value) Sign1Error!Sign1 {
    const inner = switch (value) {
        .tag => |t| t.value.*,
        else => value,
    };
    const arr = switch (inner) {
        .array => |a| a,
        else => return error.NotSign1,
    };
    if (arr.len != 4) return error.NotSign1;

    const protected = switch (arr[0]) {
        .bytes => |b| b,
        else => return error.WrongType,
    };
    const unprotected = switch (arr[1]) {
        .map => |m| m,
        else => return error.WrongType,
    };
    const payload: ?[]const u8 = switch (arr[2]) {
        .bytes => |b| b,
        .null_value => null,
        else => return error.WrongType,
    };
    const signature = switch (arr[3]) {
        .bytes => |b| b,
        else => return error.WrongType,
    };
    return .{ .protected = protected, .unprotected = unprotected, .payload = payload, .signature = signature };
}

/// Build the wire bytes for `s` (the bare 4-element array — RFC 9052 does
/// not require the tag-18 wrapper; callers wanting it can wrap the result
/// in `Value.Tag{.number = 18, ...}` and re-encode themselves).
pub fn encodeSign1(a: Allocator, s: Sign1) Allocator.Error![]u8 {
    const payload_v: Value = if (s.payload) |p| .{ .bytes = p } else .null_value;
    const arr = [_]Value{
        .{ .bytes = s.protected },
        .{ .map = s.unprotected },
        payload_v,
        .{ .bytes = s.signature },
    };
    return try cbor.encode(a, .{ .array = &arr }, .{});
}

/// Build the `Sig_structure` bytes (RFC 9052 §4.4) that get hashed/signed
/// or hashed/verified — `context` is `"Signature1"` for `COSE_Sign1`.
/// `external_aad` is normally empty (`&.{}`) unless the application defines
/// additional authenticated data. This is as far as this module goes: the
/// caller feeds the returned bytes to their signature algorithm's
/// sign/verify (e.g. the sibling `p256`/`k256`/`ed448` modules).
pub fn sigStructure(a: Allocator, protected: []const u8, external_aad: []const u8, payload: []const u8) Allocator.Error![]u8 {
    const arr = [_]Value{
        .{ .text = "Signature1" },
        .{ .bytes = protected },
        .{ .bytes = external_aad },
        .{ .bytes = payload },
    };
    return try cbor.encode(a, .{ .array = &arr }, .{});
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

test "COSE_Key: EC2 P-256 round-trip, byte-identical to ctap2pin's field layout" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // The exact EC2/P-256 field shape ctap2pin's inline COSE_Key handling
    // uses (kty=2, alg=ES256, crv=1/P-256, x/y 32-byte big-endian coords).
    var x: [32]u8 = undefined;
    var y: [32]u8 = undefined;
    for (&x, 0..) |*b, i| b.* = @intCast(i);
    for (&y, 0..) |*b, i| b.* = @intCast(i + 100);

    const key_v = try encodeEc2Key(a, .{ .alg = alg_es256, .crv = crv_p256, .x = &x, .y = &y });
    const bytes = try cbor.encode(a, key_v, .{});

    const decoded = try cbor.decode(a, bytes, .{});
    const parsed = try parseKey(decoded);
    try testing.expect(parsed == .ec2);
    try testing.expectEqual(@as(?i64, alg_es256), parsed.ec2.alg);
    try testing.expectEqual(@as(i64, crv_p256), parsed.ec2.crv);
    try testing.expectEqualSlices(u8, &x, parsed.ec2.x);
    try testing.expectEqualSlices(u8, &y, parsed.ec2.y);

    // Byte-identical re-encode of the parsed key.
    const key_v2 = try encodeEc2Key(a, parsed.ec2);
    const bytes2 = try cbor.encode(a, key_v2, .{});
    try testing.expectEqualSlices(u8, bytes, bytes2);
}

test "COSE_Key: OKP Ed25519 round-trip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var x: [32]u8 = undefined;
    for (&x, 0..) |*b, i| b.* = @intCast(255 - i);

    const key_v = try encodeOkpKey(a, .{ .alg = alg_eddsa, .crv = crv_ed25519, .x = &x });
    const bytes = try cbor.encode(a, key_v, .{});
    const decoded = try cbor.decode(a, bytes, .{});
    const parsed = try parseKey(decoded);
    try testing.expect(parsed == .okp);
    try testing.expectEqual(@as(i64, crv_ed25519), parsed.okp.crv);
    try testing.expectEqualSlices(u8, &x, parsed.okp.x);
}

test "COSE_Key: missing required field -> MissingField" {
    // kty + crv + x, but no y — EC2 requires y.
    const entries = [_]MapEntry{
        .{ .key = .{ .uint = 1 }, .value = .{ .uint = 2 } },
        .{ .key = Value.fromI64(-1), .value = .{ .uint = 1 } },
        .{ .key = Value.fromI64(-2), .value = .{ .bytes = "x" } },
    };
    try testing.expectError(error.MissingField, parseKey(.{ .map = &entries }));
}

test "COSE_Key: wrong-typed x/y -> WrongType (not silently coerced to empty)" {
    // KeyError.WrongType is declared but was never exercised — bstrField's
    // "not a byte string" branch (x/y arrive as e.g. a text string or an
    // int) had no reject test at all.
    const entries_bad_x = [_]MapEntry{
        .{ .key = .{ .uint = 1 }, .value = .{ .uint = 2 } }, // kty=EC2
        .{ .key = Value.fromI64(-1), .value = .{ .uint = 1 } }, // crv
        .{ .key = Value.fromI64(-2), .value = .{ .text = "not-bytes" } }, // x: wrong type
        .{ .key = Value.fromI64(-3), .value = .{ .bytes = "y" } },
    };
    try testing.expectError(error.WrongType, parseKey(.{ .map = &entries_bad_x }));

    const entries_bad_y = [_]MapEntry{
        .{ .key = .{ .uint = 1 }, .value = .{ .uint = 2 } },
        .{ .key = Value.fromI64(-1), .value = .{ .uint = 1 } },
        .{ .key = Value.fromI64(-2), .value = .{ .bytes = "x" } },
        .{ .key = Value.fromI64(-3), .value = .{ .uint = 7 } }, // y: wrong type
    };
    try testing.expectError(error.WrongType, parseKey(.{ .map = &entries_bad_y }));
}

test "COSE_Key: unsupported kty -> UnsupportedKty" {
    const entries = [_]MapEntry{
        .{ .key = .{ .uint = 1 }, .value = .{ .uint = 4 } }, // kty=4 (symmetric) — not modeled
        .{ .key = Value.fromI64(-1), .value = .{ .uint = 1 } },
        .{ .key = Value.fromI64(-2), .value = .{ .bytes = "x" } },
    };
    try testing.expectError(error.UnsupportedKty, parseKey(.{ .map = &entries }));
}

test "COSE_Sign1: round-trip build/parse + Sig_structure shape" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const protected = [_]u8{ 0xa1, 0x01, 0x26 }; // {1: -7} — {alg: ES256}, definite map
    const unprotected = [_]MapEntry{};
    const payload = "hello cose";
    const signature = [_]u8{ 0xde, 0xad, 0xbe, 0xef } ** 4; // 16 bytes, arbitrary

    const s = Sign1{ .protected = &protected, .unprotected = &unprotected, .payload = payload, .signature = &signature };
    const bytes = try encodeSign1(a, s);

    const decoded = try cbor.decode(a, bytes, .{});
    const parsed = try parseSign1(decoded);
    try testing.expectEqualSlices(u8, &protected, parsed.protected);
    try testing.expectEqual(@as(usize, 0), parsed.unprotected.len);
    try testing.expectEqualStrings(payload, parsed.payload.?);
    try testing.expectEqualSlices(u8, &signature, parsed.signature);

    const sig_struct = try sigStructure(a, &protected, &.{}, payload);
    // Sig_structure = ["Signature1", protected, external_aad, payload] —
    // a definite 4-element array whose first item is the text "Signature1".
    const sd = try cbor.decode(a, sig_struct, .{});
    try testing.expect(sd == .array);
    try testing.expectEqual(@as(usize, 4), sd.array.len);
    try testing.expectEqualStrings("Signature1", sd.array[0].text);
    try testing.expectEqualSlices(u8, &protected, sd.array[1].bytes);
    try testing.expectEqual(@as(usize, 0), sd.array[2].bytes.len);
    try testing.expectEqualSlices(u8, payload, sd.array[3].bytes);
}

test "COSE_Sign1: detached payload (nil) round-trips to null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const protected = [_]u8{0xa0}; // {} empty definite map
    const unprotected = [_]MapEntry{};
    const signature = [_]u8{1} ** 8;
    const s = Sign1{ .protected = &protected, .unprotected = &unprotected, .payload = null, .signature = &signature };
    const bytes = try encodeSign1(a, s);
    const decoded = try cbor.decode(a, bytes, .{});
    const parsed = try parseSign1(decoded);
    try testing.expect(parsed.payload == null);
}

test "COSE_Sign1: tag-18-wrapped input parses the same as bare array" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const protected = [_]u8{0xa0};
    const unprotected = [_]MapEntry{};
    const signature = [_]u8{9} ** 4;
    const s = Sign1{ .protected = &protected, .unprotected = &unprotected, .payload = "p", .signature = &signature };
    const bare_bytes = try encodeSign1(a, s);
    const bare_value = try cbor.decode(a, bare_bytes, .{});

    const tagged: Value = .{ .tag = .{ .number = 18, .value = &bare_value } };
    const tagged_bytes = try cbor.encode(a, tagged, .{});
    const tagged_decoded = try cbor.decode(a, tagged_bytes, .{});

    const parsed_bare = try parseSign1(bare_value);
    const parsed_tagged = try parseSign1(tagged_decoded);
    try testing.expectEqualSlices(u8, parsed_bare.signature, parsed_tagged.signature);
}

test "COSE_Sign1: not an array -> NotSign1" {
    try testing.expectError(error.NotSign1, parseSign1(.{ .uint = 1 }));
}

test "COSE_Sign1: wrong element count -> NotSign1" {
    const arr = [_]Value{ .{ .uint = 1 }, .{ .uint = 2 } };
    try testing.expectError(error.NotSign1, parseSign1(.{ .array = &arr }));
}

test "COSE_Sign1: each of the 4 fields rejects the wrong CBOR type -> WrongType" {
    // Sign1Error.WrongType is declared but every field-type-mismatch branch
    // in parseSign1 (protected/unprotected/payload/signature) was
    // completely unexercised — only the array-shape errors (NotSign1) had
    // reject tests.
    const good_unprotected = [_]MapEntry{};
    const good_bytes = [_]u8{1};

    // protected: not a bstr.
    try testing.expectError(error.WrongType, parseSign1(.{
        .array = &[_]Value{
            .{ .uint = 0 }, // should be bytes
            .{ .map = &good_unprotected },
            .{ .bytes = &good_bytes },
            .{ .bytes = &good_bytes },
        },
    }));
    // unprotected: not a map.
    try testing.expectError(error.WrongType, parseSign1(.{
        .array = &[_]Value{
            .{ .bytes = &good_bytes },
            .{ .uint = 0 }, // should be a map
            .{ .bytes = &good_bytes },
            .{ .bytes = &good_bytes },
        },
    }));
    // payload: neither bytes nor CBOR null.
    try testing.expectError(error.WrongType, parseSign1(.{
        .array = &[_]Value{
            .{ .bytes = &good_bytes },
            .{ .map = &good_unprotected },
            .{ .uint = 0 }, // should be bytes or null_value
            .{ .bytes = &good_bytes },
        },
    }));
    // signature: not a bstr.
    try testing.expectError(error.WrongType, parseSign1(.{
        .array = &[_]Value{
            .{ .bytes = &good_bytes },
            .{ .map = &good_unprotected },
            .{ .bytes = &good_bytes },
            .{ .uint = 0 }, // should be bytes
        },
    }));
}
