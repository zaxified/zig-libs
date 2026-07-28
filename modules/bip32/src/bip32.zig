// SPDX-License-Identifier: MIT

//! bip32 — BIP-32 hierarchical-deterministic keys over secp256k1.
//!
//! `masterFromSeed` (HMAC-SHA512(key="Bitcoin seed", data=seed) → master
//! privkey + chain code), `ckdPriv`/`ckdPub` (hardened + normal child
//! derivation), `serializePriv`/`serializePub`/`parseExtended` (the
//! xprv/xpub Base58Check wire format, mainnet version bytes), and
//! `parsePath`/`derivePath` (`m/44'/0'/0'/0/0`-style path strings).
//!
//! Handles SECRET key material: every buffer this module allocates on the
//! stack that can hold a private-key-derived value (`HMAC-SHA512` output,
//! the intermediate hardened-derivation input) is zeroized before the
//! owning function returns. A `deinit` on `ExtendedPrivKey` is provided for
//! callers to zero the struct itself once done with it — the module cannot
//! do that automatically since the struct outlives the call that built it.

const std = @import("std");
const k256 = @import("k256");
const ripemd160 = @import("ripemd160");
const bech32 = @import("bech32");

const Secp256k1 = k256.Secp256k1;

/// Mainnet extended-private-key version bytes (`xprv...`).
pub const version_mainnet_priv: u32 = 0x0488ADE4;
/// Mainnet extended-public-key version bytes (`xpub...`).
pub const version_mainnet_pub: u32 = 0x0488B21E;

/// Child indices `>= hardened_offset` (2^31) are hardened derivation.
pub const hardened_offset: u32 = 0x8000_0000;

/// The Base58Check-encoded serialized-key payload length (BIP-32 §
/// "Serialization format"): 4 version + 1 depth + 4 parent-fingerprint +
/// 4 child-number + 32 chain-code + 33 key = 78 bytes.
pub const serialized_payload_len = 78;
/// Generous bound on the Base58Check-encoded xprv/xpub string.
pub const max_serialized_len = 128;

/// An extended PRIVATE key — SECRET (`privkey`). Zero with `deinit` once done.
pub const ExtendedPrivKey = struct {
    depth: u8,
    parent_fingerprint: [4]u8,
    child_number: u32,
    chain_code: [32]u8,
    privkey: [32]u8,

    /// Zero the secret fields. Callers that finish with a derived key
    /// (after serializing it, deriving children, etc.) should call this.
    pub fn deinit(self: *ExtendedPrivKey) void {
        std.crypto.secureZero(u8, &self.privkey);
        std.crypto.secureZero(u8, &self.chain_code);
    }

    /// True iff this is a master key (depth 0, zero parent fingerprint /
    /// child number — the BIP-32 "zero depth" invariant this module's
    /// parser also enforces on decode).
    pub fn isMaster(self: ExtendedPrivKey) bool {
        return self.depth == 0 and std.mem.allEqual(u8, &self.parent_fingerprint, 0) and self.child_number == 0;
    }
};

/// An extended PUBLIC key — not secret (though chain codes carry privacy,
/// not secrecy, implications the caller should still be mindful of).
pub const ExtendedPubKey = struct {
    depth: u8,
    parent_fingerprint: [4]u8,
    child_number: u32,
    chain_code: [32]u8,
    /// Compressed SEC1 (33 bytes: `0x02`/`0x03` prefix + 32-byte x).
    pubkey: [33]u8,
};

pub const MasterError = error{InvalidMasterKey};

/// `masterFromSeed`: HMAC-SHA512(key="Bitcoin seed", data=seed) → (IL =
/// master privkey, IR = master chain code). BIP-32 requires rejecting
/// `IL >= n` or `IL == 0` (probability ~2^-127; the reference implementation
/// re-seeds and retries — this module reports it as a typed error instead,
/// leaving the retry policy to the caller).
pub fn masterFromSeed(seed: []const u8) MasterError!ExtendedPrivKey {
    var i: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &i);
    std.crypto.auth.hmac.sha2.HmacSha512.create(&i, seed, "Bitcoin seed");

    const il = i[0..32].*;
    const ir = i[32..64].*;

    Secp256k1.scalar.rejectNonCanonical(il, .big) catch return error.InvalidMasterKey;
    if (std.mem.allEqual(u8, &il, 0)) return error.InvalidMasterKey;

    return .{
        .depth = 0,
        .parent_fingerprint = .{ 0, 0, 0, 0 },
        .child_number = 0,
        .chain_code = ir,
        .privkey = il,
    };
}

pub const CkdError = error{
    /// The HMAC-derived child key is invalid (`IL >= n`, or the resulting
    /// child scalar/point is the identity) — BIP-32's documented ~2^-127
    /// "try the next index" case.
    InvalidChildKey,
    /// `ckdPub` was asked to derive a hardened child — impossible without
    /// the private key (BIP-32's defining restriction on public derivation).
    HardenedRequiresPrivateKey,
};

/// Derive the compressed SEC1 pubkey `k·G` for a private scalar `k`.
fn pubkeyFromPriv(priv: [32]u8) std.crypto.errors.IdentityElementError![33]u8 {
    const point = try Secp256k1.combMulBase(priv, .big);
    return point.toCompressedSec1();
}

/// The BIP-32 fingerprint: the first 4 bytes of `hash160(compressed_pubkey)`.
pub fn fingerprint(compressed_pubkey: [33]u8) [4]u8 {
    var h: [20]u8 = undefined;
    ripemd160.hash160(&compressed_pubkey, &h);
    return h[0..4].*;
}

/// Private (hardened or normal) child-key derivation `CKDpriv`.
pub fn ckdPriv(parent: ExtendedPrivKey, index: u32) CkdError!ExtendedPrivKey {
    const hardened = index >= hardened_offset;

    var data: [37]u8 = undefined;
    defer std.crypto.secureZero(u8, &data); // holds the parent privkey when hardened
    if (hardened) {
        data[0] = 0x00;
        @memcpy(data[1..33], &parent.privkey);
    } else {
        const parent_pub = pubkeyFromPriv(parent.privkey) catch return error.InvalidChildKey;
        @memcpy(data[0..33], &parent_pub);
    }
    std.mem.writeInt(u32, data[33..37], index, .big);

    var i: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &i);
    std.crypto.auth.hmac.sha2.HmacSha512.create(&i, &data, &parent.chain_code);

    const il = i[0..32].*;
    const ir = i[32..64].*;

    const child_priv = Secp256k1.scalar.add(parent.privkey, il, .big) catch return error.InvalidChildKey;
    if (std.mem.allEqual(u8, &child_priv, 0)) return error.InvalidChildKey;

    const parent_pub = pubkeyFromPriv(parent.privkey) catch return error.InvalidChildKey;

    return .{
        .depth = parent.depth +% 1,
        .parent_fingerprint = fingerprint(parent_pub),
        .child_number = index,
        .chain_code = ir,
        .privkey = child_priv,
    };
}

/// Public (normal only — hardened is impossible) child-key derivation
/// `CKDpub`.
pub fn ckdPub(parent: ExtendedPubKey, index: u32) CkdError!ExtendedPubKey {
    if (index >= hardened_offset) return error.HardenedRequiresPrivateKey;

    var data: [37]u8 = undefined;
    @memcpy(data[0..33], &parent.pubkey);
    std.mem.writeInt(u32, data[33..37], index, .big);

    var i: [64]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(&i, &data, &parent.chain_code);
    const il = i[0..32].*;
    const ir = i[32..64].*;

    Secp256k1.scalar.rejectNonCanonical(il, .big) catch return error.InvalidChildKey;
    const il_point = Secp256k1.combMulBase(il, .big) catch return error.InvalidChildKey;
    const parent_point = Secp256k1.fromSec1(&parent.pubkey) catch return error.InvalidChildKey;
    const child_point = il_point.add(parent_point);
    child_point.rejectIdentity() catch return error.InvalidChildKey;

    return .{
        .depth = parent.depth +% 1,
        .parent_fingerprint = fingerprint(parent.pubkey),
        .child_number = index,
        .chain_code = ir,
        .pubkey = child_point.toCompressedSec1(),
    };
}

/// "Neuter" an extended private key into its public counterpart (drops the
/// private scalar, keeping depth/fingerprint/child-number/chain-code).
pub fn neuter(priv: ExtendedPrivKey) std.crypto.errors.IdentityElementError!ExtendedPubKey {
    return .{
        .depth = priv.depth,
        .parent_fingerprint = priv.parent_fingerprint,
        .child_number = priv.child_number,
        .chain_code = priv.chain_code,
        .pubkey = try pubkeyFromPriv(priv.privkey),
    };
}

// ── serialization (Base58Check xprv/xpub) ───────────────────────────────

fn writeHeader(payload: *[serialized_payload_len]u8, version: u32, depth: u8, parent_fp: [4]u8, child_number: u32, chain_code: [32]u8) void {
    std.mem.writeInt(u32, payload[0..4], version, .big);
    payload[4] = depth;
    @memcpy(payload[5..9], &parent_fp);
    std.mem.writeInt(u32, payload[9..13], child_number, .big);
    @memcpy(payload[13..45], &chain_code);
}

/// Serialize an extended private key as `xprv...` (Base58Check).
pub fn serializePriv(k: ExtendedPrivKey, out: []u8) bech32.base58.Error![]const u8 {
    var payload: [serialized_payload_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &payload); // carries the secret privkey
    writeHeader(&payload, version_mainnet_priv, k.depth, k.parent_fingerprint, k.child_number, k.chain_code);
    payload[45] = 0x00;
    @memcpy(payload[46..78], &k.privkey);
    return bech32.base58.checkEncode(&payload, out);
}

/// Serialize an extended public key as `xpub...` (Base58Check).
pub fn serializePub(k: ExtendedPubKey, out: []u8) bech32.base58.Error![]const u8 {
    var payload: [serialized_payload_len]u8 = undefined;
    writeHeader(&payload, version_mainnet_pub, k.depth, k.parent_fingerprint, k.child_number, k.chain_code);
    @memcpy(payload[45..78], &k.pubkey);
    return bech32.base58.checkEncode(&payload, out);
}

pub const ParseError = bech32.base58.CheckError || error{
    /// Decoded payload isn't exactly 78 bytes.
    InvalidLength,
    /// Version bytes aren't the mainnet xprv/xpub constants.
    UnknownVersion,
    /// xprv version but the key byte isn't the `0x00` private-key marker.
    InvalidPrivateKeyMarker,
    /// The private scalar is 0 or `>= n` (BIP-32's `1..n-1` range).
    PrivateKeyOutOfRange,
    /// xpub version but the 33-byte key isn't a valid compressed SEC1 point.
    InvalidPublicKey,
    /// Depth 0 must carry an all-zero parent fingerprint (BIP-32 vector 5).
    ZeroDepthNonZeroFingerprint,
    /// Depth 0 must carry a zero child number (BIP-32 vector 5).
    ZeroDepthNonZeroIndex,
};

pub const ParsedKey = union(enum) {
    private: ExtendedPrivKey,
    public: ExtendedPubKey,
};

/// Decode + fully validate a Base58Check `xprv`/`xpub` string. Fail-closed:
/// every BIP-32 test-vector-5 invalid case (version/key-type mismatch, bad
/// key prefix, off-curve pubkey, out-of-range privkey, zero-depth invariant
/// violation, bad checksum, unknown version) is a distinct typed error, not
/// a best-effort partial parse.
pub fn parseExtended(s: []const u8) ParseError!ParsedKey {
    var buf: [bech32.base58.max_payload_len]u8 = undefined;
    const payload = try bech32.base58.checkDecode(s, &buf);
    if (payload.len != serialized_payload_len) return error.InvalidLength;

    const version = std.mem.readInt(u32, payload[0..4], .big);
    const depth = payload[4];
    var parent_fp: [4]u8 = undefined;
    @memcpy(&parent_fp, payload[5..9]);
    const child_number = std.mem.readInt(u32, payload[9..13], .big);
    var chain_code: [32]u8 = undefined;
    @memcpy(&chain_code, payload[13..45]);

    if (depth == 0) {
        if (!std.mem.allEqual(u8, &parent_fp, 0)) return error.ZeroDepthNonZeroFingerprint;
        if (child_number != 0) return error.ZeroDepthNonZeroIndex;
    }

    switch (version) {
        version_mainnet_priv => {
            if (payload[45] != 0x00) return error.InvalidPrivateKeyMarker;
            var priv: [32]u8 = undefined;
            @memcpy(&priv, payload[46..78]);
            const canonical = blk: {
                Secp256k1.scalar.rejectNonCanonical(priv, .big) catch break :blk false;
                break :blk true;
            };
            if (!canonical or std.mem.allEqual(u8, &priv, 0)) {
                std.crypto.secureZero(u8, &priv);
                std.crypto.secureZero(u8, &buf);
                return error.PrivateKeyOutOfRange;
            }
            std.crypto.secureZero(u8, &buf); // raw decode buffer no longer needed
            return .{ .private = .{
                .depth = depth,
                .parent_fingerprint = parent_fp,
                .child_number = child_number,
                .chain_code = chain_code,
                .privkey = priv,
            } };
        },
        version_mainnet_pub => {
            var pk: [33]u8 = undefined;
            @memcpy(&pk, payload[45..78]);
            _ = Secp256k1.fromSec1(&pk) catch return error.InvalidPublicKey;
            return .{ .public = .{
                .depth = depth,
                .parent_fingerprint = parent_fp,
                .child_number = child_number,
                .chain_code = chain_code,
                .pubkey = pk,
            } };
        },
        else => return error.UnknownVersion,
    }
}

// ── derivation-path parsing (`m/44'/0'/0'/0/0`) ─────────────────────────

/// Generous ceiling on a path's depth (real paths are ≤ 6-8 levels).
pub const max_path_depth = 32;

pub const PathError = error{
    /// A path segment isn't a valid `[0-9]+['hH]?` component.
    InvalidPathSegment,
    /// The pre-hardened-offset index doesn't fit in 31 bits.
    IndexOutOfRange,
    /// More segments than `out`/`max_path_depth` can hold.
    PathTooDeep,
};

/// Parse a `m/44'/0'/0'/0/0`-style path (leading `m`/`M` optional, `'`/`h`/`H`
/// mark hardened) into raw BIP-32 child indices (hardened offset already
/// folded in) written into `out`.
pub fn parsePath(path: []const u8, out: []u32) PathError![]const u32 {
    var it = std.mem.tokenizeScalar(u8, path, '/');
    var count: usize = 0;
    var first = true;
    while (it.next()) |seg| {
        if (first) {
            first = false;
            if (seg.len == 1 and (seg[0] == 'm' or seg[0] == 'M')) continue;
        }
        if (count >= out.len or count >= max_path_depth) return error.PathTooDeep;

        var s = seg;
        var hardened = false;
        if (s.len > 0) {
            const last = s[s.len - 1];
            if (last == '\'' or last == 'h' or last == 'H') {
                hardened = true;
                s = s[0 .. s.len - 1];
            }
        }
        if (s.len == 0) return error.InvalidPathSegment;
        const idx = std.fmt.parseUnsigned(u32, s, 10) catch return error.InvalidPathSegment;
        if (idx >= hardened_offset) return error.IndexOutOfRange;

        out[count] = if (hardened) idx + hardened_offset else idx;
        count += 1;
    }
    return out[0..count];
}

/// Derive `master` along `path` (raw indices, e.g. from `parsePath`) via
/// repeated `ckdPriv`.
pub fn derivePath(master: ExtendedPrivKey, path: []const u32) CkdError!ExtendedPrivKey {
    var cur = master;
    for (path) |idx| cur = try ckdPriv(cur, idx);
    return cur;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "masterFromSeed + serializePriv/serializePub round-trip via parseExtended" {
    const seed = [_]u8{0x01} ** 32;
    var master = try masterFromSeed(&seed);
    defer master.deinit();

    var priv_buf: [max_serialized_len]u8 = undefined;
    const xprv = try serializePriv(master, &priv_buf);

    const pub_key = try neuter(master);
    var pub_buf: [max_serialized_len]u8 = undefined;
    const xpub = try serializePub(pub_key, &pub_buf);

    const parsed_priv = try parseExtended(xprv);
    try testing.expect(parsed_priv == .private);
    try testing.expectEqualSlices(u8, &master.privkey, &parsed_priv.private.privkey);
    try testing.expectEqualSlices(u8, &master.chain_code, &parsed_priv.private.chain_code);

    const parsed_pub = try parseExtended(xpub);
    try testing.expect(parsed_pub == .public);
    try testing.expectEqualSlices(u8, &pub_key.pubkey, &parsed_pub.public.pubkey);
}

test "ckdPriv hardened vs normal both derive, and neuter(ckdPriv) == ckdPub(neuter) for normal" {
    const seed = [_]u8{0xab} ** 32;
    var master = try masterFromSeed(&seed);
    defer master.deinit();
    const master_pub = try neuter(master);

    var hardened_child = try ckdPriv(master, hardened_offset + 0);
    defer hardened_child.deinit();
    try testing.expectEqual(@as(u8, 1), hardened_child.depth);

    var normal_child = try ckdPriv(master, 5);
    defer normal_child.deinit();
    try testing.expectEqual(@as(u8, 1), normal_child.depth);

    // Public derivation only works for the normal child (CKDpub can't
    // reproduce a hardened child — it never sees the private key).
    const via_priv = try neuter(normal_child);
    const via_pub = try ckdPub(master_pub, 5);
    try testing.expectEqualSlices(u8, &via_priv.pubkey, &via_pub.pubkey);
    try testing.expectEqualSlices(u8, &via_priv.chain_code, &via_pub.chain_code);

    try testing.expectError(error.HardenedRequiresPrivateKey, ckdPub(master_pub, hardened_offset + 0));
}

test "parsePath: m/44'/0'/0'/0/0 and bare relative paths" {
    var out: [max_path_depth]u32 = undefined;
    const p1 = try parsePath("m/44'/0'/0'/0/0", &out);
    try testing.expectEqualSlices(u32, &.{
        hardened_offset + 44,
        hardened_offset + 0,
        hardened_offset + 0,
        0,
        0,
    }, p1);

    const p2 = try parsePath("0h/1H/2", &out);
    try testing.expectEqualSlices(u32, &.{ hardened_offset + 0, hardened_offset + 1, 2 }, p2);

    try testing.expectError(error.InvalidPathSegment, parsePath("m/abc", &out));
    // 2^31 fits in u32 but is >= hardened_offset, so it's out of range for a
    // pre-offset index (2^32 itself would overflow parseUnsigned(u32, ...)
    // first and hit InvalidPathSegment instead — this exercises the range
    // check specifically, not the parse-overflow path).
    try testing.expectError(error.IndexOutOfRange, parsePath("m/2147483648", &out)); // 2^31
}

test "derivePath matches manual chained ckdPriv" {
    const seed = [_]u8{0x42} ** 32;
    var master = try masterFromSeed(&seed);
    defer master.deinit();

    var out: [max_path_depth]u32 = undefined;
    const path = try parsePath("m/0'/1/2'", &out);

    var manual = try ckdPriv(master, hardened_offset + 0);
    manual = try ckdPriv(manual, 1);
    manual = try ckdPriv(manual, hardened_offset + 2);

    var via_path = try derivePath(master, path);
    defer via_path.deinit();
    try testing.expectEqualSlices(u8, &manual.privkey, &via_path.privkey);
    try testing.expectEqualSlices(u8, &manual.chain_code, &via_path.chain_code);
}

test "parseExtended rejects a bad-length / bad-checksum string" {
    try testing.expectError(error.ChecksumMismatch, parseExtended(
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
    ));
}

// ── fuzz: extended-key + derivation-path text parse, never panics ──────────
//
// `parseExtended` is what loads an `xprv`/`xpub` a user pastes in (or an
// exchange/wallet imports) — Base58Check text with no structural guarantee
// until the checksum's been verified. `parsePath` similarly takes a
// derivation-path string a caller (config, CLI, wallet UI) may pass through
// verbatim from a user.

test "fuzz: parseExtended never panics on arbitrary text" {
    try testing.fuzz({}, fuzzParseExtended, .{});
}

fn fuzzParseExtended(_: void, smith: *std.testing.Smith) !void {
    var buf: [128]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    _ = parseExtended(buf[0..len]) catch return;
}

test "fuzz: parsePath never panics on arbitrary text" {
    try testing.fuzz({}, fuzzParsePath, .{});
}

fn fuzzParsePath(_: void, smith: *std.testing.Smith) !void {
    const alphabet = "0123456789/'hHmM";
    var buf: [96]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    for (buf[0..len]) |*c| {
        if (smith.boolWeighted(1, 4)) c.* = alphabet[c.* % alphabet.len];
    }
    var out: [max_path_depth]u32 = undefined;
    _ = parsePath(buf[0..len], &out) catch return;
}
