// SPDX-License-Identifier: MIT
//! cose — minimal RFC 9052 (CBOR Object Signing and Encryption) layer over
//! the sibling `cbor` codec: parse a `COSE_Key` (EC2, OKP or AKP) into a typed
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
//! material is never parsed or emitted — `d` at COSE label -4 for EC2/OKP
//! and `priv` at label -2 for AKP, which is the SAME NUMBER that means `x`
//! under a different `kty`. This is a verifier/public-key-consumer layer,
//! not a key-storage format; COSE_Mac0/COSE_Encrypt0/full COSE_Sign
//! (multi-signer) are not implemented; RSA and symmetric COSE key types are
//! not modeled (`parseKey` returns `error.UnsupportedKty` for anything but
//! EC2, OKP and AKP). There is no `encodeAkpKey` — this module parses AKP
//! keys, it does not emit them.
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

/// AKP key-type-specific parameter labels (RFC 9964 §3). Note that these
/// REUSE label numbers -1 and -2, which mean `crv` and `x` for EC2/OKP: COSE
/// key parameter labels are scoped to the key type, so the same integer is a
/// different parameter depending on `kty`. That is why `parseKey` must read
/// `kty` before it reads anything else.
pub const label_pub: i64 = -1;
// label -2 ("priv", the private key seed) is intentionally never referenced
// here, for the same reason as EC2/OKP's -4: this module parses public keys.

/// COSE key type values (RFC 9052 §7, Table 4 / IANA COSE Key Types).
pub const kty_okp: i64 = 1;
pub const kty_ec2: i64 = 2;
/// Algorithm Key Pair (RFC 9964 §3) — a generic public/private key pair whose
/// bytes are formatted by whatever `alg` says. Used here for ML-DSA.
pub const kty_akp: i64 = 7;

/// A selection of COSE algorithm identifiers (RFC 9053 §2/§7, IANA COSE
/// Algorithms) — the ones a WebAuthn/COSE consumer of this module is likely
/// to see in the wild. Not exhaustive; `Ec2Key.alg`/`OkpKey.alg` carry the
/// raw `i64` regardless, so an unlisted algorithm still round-trips.
pub const alg_es256: i64 = -7;
pub const alg_eddsa: i64 = -8;
pub const alg_es384: i64 = -35;
pub const alg_es512: i64 = -36;
/// ML-DSA (FIPS 204) via RFC 9964 §8.1. Pure ML-DSA with an empty context
/// string; the RFC specifies no HashML-DSA algorithm.
pub const alg_ml_dsa_44: i64 = -48;
pub const alg_ml_dsa_65: i64 = -49;
pub const alg_ml_dsa_87: i64 = -50;

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
    /// `kty` is present and well-typed but not EC2 (2), OKP (1) or AKP (7) —
    /// the key types this module models.
    UnsupportedKty,
    /// Two entries in the map share the same integer label. RFC 9052 §3:
    /// "Labels in each of the maps MUST be unique. When processing messages,
    /// if a label appears multiple times, the message MUST be rejected as
    /// malformed." (fetched and read 2026-08-07, https://www.rfc-editor.org/rfc/rfc9052.html
    /// §3). A first-wins or last-wins reader disagrees with any
    /// spec-conformant peer about which copy is authoritative — a
    /// parser-differential in front of the key material itself.
    ///
    /// The check is generic over the label's CBOR type, not just integers:
    /// `tstr` labels are legal COSE and an integer above `maxInt(i64)` has no
    /// signed form, and both used to slip past.
    DuplicateLabel,
    /// The map carries more than `max_map_entries` entries. The uniqueness
    /// check above is quadratic and its input comes off the wire, so the
    /// count is bounded rather than paid — see `max_map_entries` for the
    /// measurement that made this a refusal instead of a comment.
    TooManyEntries,
    /// An AKP key's `pub` is not the length its own REQUIRED `alg` fixes
    /// (RFC 9964 §3 / FIPS 204 Table 2: 1312 / 1952 / 2592 bytes for
    /// ML-DSA-44 / -65 / -87).
    WrongKeyLength,
    /// `kty` and `alg` name different families: an ML-DSA `alg` on a key that
    /// is not AKP, or a signature `alg` this module knows to be EC2/OKP-only
    /// on an AKP key. Only pairs where BOTH sides are registered here are
    /// judged — an `alg` outside `alg_*` still round-trips under any `kty`,
    /// the way the algorithm-identifier constants' doc comment promises.
    AlgKtyMismatch,
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

/// An AKP (algorithm key pair) public key (RFC 9964 §3): opaque `pub` bytes
/// whose format is decided entirely by `alg`, which is why `alg` is required
/// here and optional for EC2/OKP.
pub const AkpKey = struct {
    /// REQUIRED for AKP keys (RFC 9964 §3: "The alg ... is REQUIRED for all
    /// AKP keys"). For ML-DSA it also fixes the parameter set, and therefore
    /// the length `pub_bytes` must have — deliberately NOT inferred from that
    /// length, which would accept a key whose `alg` and bytes disagree.
    alg: i64,
    /// The `pub` parameter (label -1): the raw algorithm-defined public key.
    /// For ML-DSA this is the FIPS 204 encoding, unwrapped.
    pub_bytes: []const u8,
};

pub const Key = union(enum) {
    ec2: Ec2Key,
    okp: OkpKey,
    akp: AkpKey,
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

/// True if two entries' keys are the same COSE label.
///
/// Integer labels compare numerically across the `uint`/`negint`
/// representations. RFC 9052 §3's uniqueness requirement is about *labels*,
/// not integer labels: a `tstr` label is legal COSE, and an integer larger
/// than `maxInt(i64)` has no `toI64`. An earlier version returned `false` for
/// every one of those, so a duplicated text label — or a duplicated `2^63`
/// — passed the uniqueness check and reached the caller in
/// `Sign1.unprotected`, where a first-wins consumer resolves it. Those cases
/// now compare structurally.
fn labelKeyEql(a: Value, b: Value) bool {
    if (a.toI64()) |ai| {
        const bi = b.toI64() orelse return false;
        return ai == bi;
    }
    // Not i64-representable on the left; only an identical shape can collide.
    return switch (a) {
        .uint => |x| switch (b) {
            .uint => |y| x == y,
            else => false,
        },
        .negint => |x| switch (b) {
            .negint => |y| x == y,
            else => false,
        },
        .text => |x| switch (b) {
            .text => |y| std.mem.eql(u8, x, y),
            else => false,
        },
        .bytes => |x| switch (b) {
            .bytes => |y| std.mem.eql(u8, x, y),
            else => false,
        },
        else => false,
    };
}

/// The largest map this layer will scan for duplicate labels, and therefore
/// the largest `COSE_Key` or header bucket it accepts at all.
///
/// ⚠ This bound is load-bearing, not tidiness. `checkLabels` compares
/// every pair, which is quadratic, and the map it scans comes off the wire:
/// `webauthn` hands `parseCredentialKey` the unbounded tail of a
/// client-supplied `authData`. Measured in ReleaseFast on the audited host,
/// one call, with no duplicate present so the scan runs to completion:
///
/// ```text
///   labels     input        decode       parseKey
///     4000     24005B         263us        22052us
///    16000     96005B        1040us       369726us
///   128000    768005B        8090us     26375567us
/// ```
///
/// Decode is linear; the scan quadrupled its cost for every doubling — 768 KB
/// of input bought **26 seconds** of one core. A cap is the fix that keeps
/// this function allocation-free (`parseKey`/`parseSign1` allocate nothing,
/// which callers rely on), and it costs nothing real: RFC 9052 header buckets
/// and `COSE_Key` maps carry single-digit label counts, so 256 is roughly
/// thirty times the largest legitimate map and still bounds the scan at
/// 32,640 comparisons.
pub const max_map_entries: usize = 256;

/// The two ways a header-bucket map can be rejected before any field is read.
/// Deliberately its own narrow set: it is a subset of both `KeyError` and
/// `Sign1Error`, so `checkLabels` can guard either entry point without
/// widening the error either one advertises.
pub const LabelError = error{ DuplicateLabel, TooManyEntries };

/// RFC 9052 §3 forbids a repeated label in a header-bucket map. Detect it
/// generically over every entry — not just the labels this module happens
/// to read — because a producer and a lenient first/last-wins consumer can
/// disagree about which of two copies is authoritative.
///
/// Returns `error.TooManyEntries` above `max_map_entries` rather than paying
/// the quadratic scan; see that constant for the measurement.
fn checkLabels(entries: []const MapEntry) LabelError!void {
    if (entries.len > max_map_entries) return error.TooManyEntries;
    for (entries, 0..) |e, i| {
        for (entries[i + 1 ..]) |o| {
            if (labelKeyEql(e.key, o.key)) return error.DuplicateLabel;
        }
    }
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
    try checkLabels(entries);
    const kty = try requiredIntField(entries, label_kty);
    const alg = try intField(entries, label_alg);

    // A key may not claim another family's algorithm. `jwt`, on the JOSE half
    // of the same RFC 9964, ends its AKP branch with exactly this rule; the
    // two halves of one RFC in one repository should not disagree about it.
    // Only pairs where both sides are registered above are judged, so an
    // unlisted `alg` is unaffected.
    if (alg) |a| {
        const ml_dsa = akpPublicKeyLen(a) != null;
        const ec_or_okp = a == alg_es256 or a == alg_es384 or a == alg_es512 or a == alg_eddsa;
        if (kty == kty_akp and ec_or_okp) return error.AlgKtyMismatch;
        if (kty != kty_akp and ml_dsa) return error.AlgKtyMismatch;
    }

    // `kty` decides what the negative labels MEAN, so nothing below -1 may be
    // read before this switch: -1 is `crv` for EC2/OKP and `pub` for AKP.
    return switch (kty) {
        kty_ec2 => .{ .ec2 = .{
            .alg = alg,
            .crv = try requiredIntField(entries, label_crv),
            .x = try bstrField(entries, label_x),
            .y = try bstrField(entries, label_y),
        } },
        kty_okp => .{ .okp = .{
            .alg = alg,
            .crv = try requiredIntField(entries, label_crv),
            .x = try bstrField(entries, label_x),
        } },
        kty_akp => blk: {
            const key_alg = alg orelse return error.MissingField;
            const pub_bytes = try bstrField(entries, label_pub);
            // `alg` fixes the parameter set AND therefore the length. Not
            // inferring the set from the length is correct and deliberate --
            // but it is not the same as not CHECKING the length, and only the
            // check closes the seam. Without it this function hands the caller
            // an `alg` and an unconstrained slice, and the natural consumer
            // expression is the one this module's own KAT writes:
            // `pub_bytes[0..Scheme.PublicKey.encoded_length].*`. Measured on a
            // key declaring ML-DSA-87 with ML-DSA-44's 1312 bytes, that is
            // `index out of bounds: index 2592, len 1312` in Debug and a
            // 1280-byte out-of-bounds READ in ReleaseFast, straight into a
            // signature verifier. The sibling `jwt`, on the JOSE half of this
            // same RFC, has checked it since it landed.
            if (akpPublicKeyLen(key_alg)) |want| {
                if (pub_bytes.len != want) return error.WrongKeyLength;
            }
            break :blk .{ .akp = .{ .alg = key_alg, .pub_bytes = pub_bytes } };
        },
        else => error.UnsupportedKty,
    };
}

/// The `pub` length RFC 9964 §3 fixes for an AKP `alg`, or `null` when the
/// algorithm is not one this module knows a length for (an unlisted `alg`
/// still round-trips, as it does for EC2/OKP — see the algorithm-identifier
/// constants above, which are "a selection", not a closed set).
///
/// Exported so a consumer that accepts an unlisted `alg` can apply the same
/// rule itself instead of re-deriving FIPS 204 Table 2 from memory.
/// The lengths are taken from `std.crypto.sign.mldsa`'s own FIPS 204 types
/// rather than transcribed as literals: a number copied out of Table 2 by
/// hand is a number that can be copied wrong, and `encoded_length` is a
/// comptime constant, so naming it costs nothing at runtime.
pub fn akpPublicKeyLen(alg: i64) ?usize {
    const mldsa = std.crypto.sign.mldsa;
    return switch (alg) {
        alg_ml_dsa_44 => mldsa.MLDSA44.PublicKey.encoded_length,
        alg_ml_dsa_65 => mldsa.MLDSA65.PublicKey.encoded_length,
        alg_ml_dsa_87 => mldsa.MLDSA87.PublicKey.encoded_length,
        else => null,
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
    /// The unprotected header map has a repeated label — see `KeyError.DuplicateLabel`.
    DuplicateLabel,
    /// The unprotected header map is larger than `max_map_entries` — see that
    /// constant, and `KeyError.TooManyEntries`.
    TooManyEntries,
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
    try checkLabels(unprotected);
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

test "COSE_Key: a duplicated label is rejected, not resolved first-wins (RFC 9052 §3)" {
    // Two `alg` (label 3) entries: -7 (ES256) then -65535 (RS1). A
    // first-wins reader picks -7; a last-wins reader picks -65535 — the
    // parser-differential RFC 9052 §3 exists specifically to forbid.
    const entries = [_]MapEntry{
        .{ .key = Value.fromI64(label_kty), .value = .{ .uint = kty_ec2 } },
        .{ .key = Value.fromI64(label_alg), .value = Value.fromI64(-7) },
        .{ .key = Value.fromI64(label_alg), .value = Value.fromI64(-65535) },
        .{ .key = Value.fromI64(label_crv), .value = .{ .uint = 1 } },
        .{ .key = Value.fromI64(label_x), .value = .{ .bytes = "x" } },
        .{ .key = Value.fromI64(label_y), .value = .{ .bytes = "y" } },
    };
    try testing.expectError(error.DuplicateLabel, parseKey(.{ .map = &entries }));
}

test "COSE_Sign1: a duplicated label in the unprotected header is rejected" {
    const unprotected = [_]MapEntry{
        .{ .key = Value.fromI64(1), .value = .{ .uint = 1 } },
        .{ .key = Value.fromI64(1), .value = .{ .uint = 2 } },
    };
    const arr = [_]Value{
        .{ .bytes = &.{} },
        .{ .map = &unprotected },
        .{ .bytes = "payload" },
        .{ .bytes = "sig" },
    };
    try testing.expectError(error.DuplicateLabel, parseSign1(.{ .array = &arr }));
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

// ── audit 2026-09-01: guards that were correct but held by nothing ─────────

test "AKP: pub length must match the length its own alg fixes" {
    var a = std.testing.allocator;

    const sets = [_]struct { alg: i64, len: usize }{
        .{ .alg = alg_ml_dsa_44, .len = akpPublicKeyLen(alg_ml_dsa_44).? },
        .{ .alg = alg_ml_dsa_65, .len = akpPublicKeyLen(alg_ml_dsa_65).? },
        .{ .alg = alg_ml_dsa_87, .len = akpPublicKeyLen(alg_ml_dsa_87).? },
    };

    for (sets) |s| {
        const right = try a.alloc(u8, s.len);
        defer a.free(right);
        @memset(right, 0xAB);

        // The correct length parses.
        const ok_entries = [_]MapEntry{
            .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_akp) } },
            .{ .key = .{ .uint = @intCast(label_alg) }, .value = Value.fromI64(s.alg) },
            .{ .key = Value.fromI64(label_pub), .value = .{ .bytes = right } },
        };
        const k = try parseKey(.{ .map = &ok_entries });
        try testing.expectEqual(s.alg, k.akp.alg);
        try testing.expectEqual(s.len, k.akp.pub_bytes.len);

        // Every other parameter set's length, plus the boundaries and empty,
        // must be refused under THIS alg -- the cross-set mix-up is the shape
        // a real confusion produces.
        for (sets) |other| {
            if (other.len == s.len) continue;
            const wrong = try a.alloc(u8, other.len);
            defer a.free(wrong);
            @memset(wrong, 0xAB);
            const bad = [_]MapEntry{
                .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_akp) } },
                .{ .key = .{ .uint = @intCast(label_alg) }, .value = Value.fromI64(s.alg) },
                .{ .key = Value.fromI64(label_pub), .value = .{ .bytes = wrong } },
            };
            try testing.expectError(error.WrongKeyLength, parseKey(.{ .map = &bad }));
        }

        for ([_]usize{ 0, 1, s.len - 1, s.len + 1 }) |n| {
            const wrong = try a.alloc(u8, n);
            defer a.free(wrong);
            @memset(wrong, 0xAB);
            const bad = [_]MapEntry{
                .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_akp) } },
                .{ .key = .{ .uint = @intCast(label_alg) }, .value = Value.fromI64(s.alg) },
                .{ .key = Value.fromI64(label_pub), .value = .{ .bytes = wrong } },
            };
            try testing.expectError(error.WrongKeyLength, parseKey(.{ .map = &bad }));
        }
    }

    // An alg this module knows no length for still round-trips, the way an
    // unlisted EC2 `alg` does -- the constants are a selection, not a set.
    try testing.expectEqual(@as(?usize, null), akpPublicKeyLen(-999));
    const unlisted = [_]MapEntry{
        .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_akp) } },
        .{ .key = .{ .uint = @intCast(label_alg) }, .value = Value.fromI64(-999) },
        .{ .key = Value.fromI64(label_pub), .value = .{ .bytes = "short" } },
    };
    const k = try parseKey(.{ .map = &unlisted });
    try testing.expectEqual(@as(i64, -999), k.akp.alg);
}

test "AKP: pub missing or wrong-typed is refused" {
    const no_pub = [_]MapEntry{
        .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_akp) } },
        .{ .key = .{ .uint = @intCast(label_alg) }, .value = Value.fromI64(alg_ml_dsa_44) },
    };
    try testing.expectError(error.MissingField, parseKey(.{ .map = &no_pub }));

    const text_pub = [_]MapEntry{
        .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_akp) } },
        .{ .key = .{ .uint = @intCast(label_alg) }, .value = Value.fromI64(alg_ml_dsa_44) },
        .{ .key = Value.fromI64(label_pub), .value = .{ .text = "not bytes" } },
    };
    try testing.expectError(error.WrongType, parseKey(.{ .map = &text_pub }));
}

test "duplicate labels are caught at any distance, not just adjacent ones" {
    // The duplicated pair sits at index 0 and index 4: an adjacent-pair scan
    // would miss it entirely.
    const entries = [_]MapEntry{
        .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_ec2) } },
        .{ .key = .{ .uint = 100 }, .value = .{ .uint = 1 } },
        .{ .key = .{ .uint = 101 }, .value = .{ .uint = 1 } },
        .{ .key = .{ .uint = 102 }, .value = .{ .uint = 1 } },
        .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_okp) } },
    };
    try testing.expectError(error.DuplicateLabel, parseKey(.{ .map = &entries }));
}

test "duplicate labels that are not i64 integers are caught too" {
    // RFC 9052 §3 says "labels", not "integer labels". A tstr label is legal
    // COSE, and an integer above maxInt(i64) has no signed form -- both used
    // to return false from the comparison and slip through.
    const dup_text = [_]MapEntry{
        .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_ec2) } },
        .{ .key = .{ .text = "vendor" }, .value = .{ .uint = 1 } },
        .{ .key = .{ .text = "vendor" }, .value = .{ .uint = 2 } },
    };
    try testing.expectError(error.DuplicateLabel, parseKey(.{ .map = &dup_text }));

    const huge: u64 = @as(u64, 1) << 63; // > maxInt(i64), so toI64 is null
    const dup_huge = [_]MapEntry{
        .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_ec2) } },
        .{ .key = .{ .uint = huge }, .value = .{ .uint = 1 } },
        .{ .key = .{ .uint = huge }, .value = .{ .uint = 2 } },
    };
    try testing.expectError(error.DuplicateLabel, parseKey(.{ .map = &dup_huge }));

    const dup_bytes = [_]MapEntry{
        .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_ec2) } },
        .{ .key = .{ .bytes = "L" }, .value = .{ .uint = 1 } },
        .{ .key = .{ .bytes = "L" }, .value = .{ .uint = 2 } },
    };
    try testing.expectError(error.DuplicateLabel, parseKey(.{ .map = &dup_bytes }));

    // Different labels of the same shape must still be accepted -- a check
    // that rejects everything is not a check.
    const distinct = [_]MapEntry{
        .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_okp) } },
        .{ .key = Value.fromI64(label_crv), .value = Value.fromI64(crv_ed25519) },
        .{ .key = Value.fromI64(label_x), .value = .{ .bytes = "k" } },
        .{ .key = .{ .text = "a" }, .value = .{ .uint = 1 } },
        .{ .key = .{ .text = "b" }, .value = .{ .uint = 2 } },
    };
    _ = try parseKey(.{ .map = &distinct });
}

test "an oversized map is refused before the quadratic scan is paid" {
    var a = std.testing.allocator;

    const entries = try a.alloc(MapEntry, max_map_entries + 1);
    defer a.free(entries);
    for (entries, 0..) |*e, i| {
        e.* = .{ .key = .{ .uint = @intCast(1000 + i) }, .value = .{ .uint = 1 } };
    }
    try testing.expectError(error.TooManyEntries, parseKey(.{ .map = entries }));
    try testing.expectError(error.TooManyEntries, parseSign1(.{ .array = &[_]Value{
        .{ .bytes = "" },
        .{ .map = entries },
        .{ .bytes = "p" },
        .{ .bytes = "s" },
    } }));

    // Exactly at the cap is still accepted: the bound must not be off by one
    // against a legitimate (if implausible) map.
    const at_cap = entries[0..max_map_entries];
    at_cap[0] = .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_akp) } };
    try testing.expectError(error.MissingField, parseKey(.{ .map = at_cap }));
}

test "COSE_Sign1: an array longer than 4 elements is not a COSE_Sign1" {
    try testing.expectError(error.NotSign1, parseSign1(.{ .array = &[_]Value{
        .{ .bytes = "" },
        .{ .map = &[_]MapEntry{} },
        .{ .bytes = "payload" },
        .{ .bytes = "sig" },
        .{ .uint = 5 },
    } }));
}

test "a key may not claim another family's algorithm" {
    // An EC2 key declaring ML-DSA, and an AKP key declaring ES256, are the
    // two directions of the same confusion. A consumer that dispatches on
    // `alg` rather than on the union tag is the one this protects.
    const ec2_claiming_mldsa = [_]MapEntry{
        .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_ec2) } },
        .{ .key = .{ .uint = @intCast(label_alg) }, .value = Value.fromI64(alg_ml_dsa_44) },
        .{ .key = Value.fromI64(label_crv), .value = Value.fromI64(crv_p256) },
        .{ .key = Value.fromI64(label_x), .value = .{ .bytes = &[_]u8{0} ** 32 } },
        .{ .key = Value.fromI64(label_y), .value = .{ .bytes = &[_]u8{0} ** 32 } },
    };
    try testing.expectError(error.AlgKtyMismatch, parseKey(.{ .map = &ec2_claiming_mldsa }));

    const okp_claiming_mldsa = [_]MapEntry{
        .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_okp) } },
        .{ .key = .{ .uint = @intCast(label_alg) }, .value = Value.fromI64(alg_ml_dsa_87) },
        .{ .key = Value.fromI64(label_crv), .value = Value.fromI64(crv_ed25519) },
        .{ .key = Value.fromI64(label_x), .value = .{ .bytes = &[_]u8{0} ** 32 } },
    };
    try testing.expectError(error.AlgKtyMismatch, parseKey(.{ .map = &okp_claiming_mldsa }));

    const akp_claiming_es256 = [_]MapEntry{
        .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_akp) } },
        .{ .key = .{ .uint = @intCast(label_alg) }, .value = Value.fromI64(alg_es256) },
        .{ .key = Value.fromI64(label_pub), .value = .{ .bytes = &[_]u8{0} ** 32 } },
    };
    try testing.expectError(error.AlgKtyMismatch, parseKey(.{ .map = &akp_claiming_es256 }));

    // An `alg` this module does not register is judged by neither side and
    // still round-trips under any `kty` -- the constants are a selection.
    const ec2_unlisted_alg = [_]MapEntry{
        .{ .key = .{ .uint = @intCast(label_kty) }, .value = .{ .uint = @intCast(kty_ec2) } },
        .{ .key = .{ .uint = @intCast(label_alg) }, .value = Value.fromI64(-777) },
        .{ .key = Value.fromI64(label_crv), .value = Value.fromI64(crv_p256) },
        .{ .key = Value.fromI64(label_x), .value = .{ .bytes = &[_]u8{0} ** 32 } },
        .{ .key = Value.fromI64(label_y), .value = .{ .bytes = &[_]u8{0} ** 32 } },
    };
    const k = try parseKey(.{ .map = &ec2_unlisted_alg });
    try testing.expectEqual(@as(?i64, -777), k.ec2.alg);
}
