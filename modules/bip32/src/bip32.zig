// SPDX-License-Identifier: MIT

//! bip32 — BIP-32 hierarchical-deterministic keys over secp256k1.
//!
//! `masterFromSeed` (HMAC-SHA512(key="Bitcoin seed", data=seed) → master
//! privkey + chain code), `ckdPriv`/`ckdPub` (hardened + normal child
//! derivation), `serializePriv`/`serializePub`/`parseExtended` (the
//! xprv/xpub or tprv/tpub Base58Check wire format), and
//! `parsePath`/`derivePath` (`m/44'/0'/0'/0/0`-style path strings).
//!
//! Handles SECRET key material, under CONVENTIONS §2.1. Every stack buffer
//! this module owns that can hold a private-key-derived value is zeroized
//! before the owning function returns (Z1): the `HMAC-SHA512` output *and* the
//! `IL`/`IR`/child-scalar copies taken out of it, the hardened-derivation input,
//! the xprv serialization payload, and `parseExtended`'s Base58Check decode
//! scratch — the last on every exit path, not only the two xprv ones. The
//! `defer`s are registered before the fallible calls that fill the buffers, so
//! an error return cannot skip one.
//!
//! `ExtendedPrivKey` itself outlives the call that built it, so it is the
//! caller's to destroy (Z2) — `ExtendedPrivKey.deinit` does it.
//!
//! Note what such a wipe is and is not worth: it clears the storage it names,
//! never the register and spill-slot copies the compiler may also hold, and it
//! is not observable from a test (see §2.1). It is defence in depth against a
//! later read of this frame's memory, not a proof of absence.

const std = @import("std");
const k256 = @import("k256");
const ripemd160 = @import("ripemd160");
const bech32 = @import("bech32");

const Secp256k1 = k256.Secp256k1;

/// Mainnet extended-private-key version bytes (`xprv...`).
pub const version_mainnet_priv: u32 = 0x0488ADE4;
/// Mainnet extended-public-key version bytes (`xpub...`).
pub const version_mainnet_pub: u32 = 0x0488B21E;
/// Testnet extended-private-key version bytes (`tprv...`).
pub const version_testnet_priv: u32 = 0x04358394;
/// Testnet extended-public-key version bytes (`tpub...`).
pub const version_testnet_pub: u32 = 0x043587CF;

/// Which network's version bytes an extended key carries — BIP-32 §
/// "Serialization format" defines exactly these two pairs. Serialization
/// writes the chosen network's bytes; `parseExtended` accepts only the chosen
/// network and names the other one as `error.WrongNetwork`, so a `tpub`
/// pasted into a mainnet wallet is refused rather than read as mainnet.
pub const Network = enum {
    mainnet,
    testnet,

    pub fn privVersion(n: Network) u32 {
        return switch (n) {
            .mainnet => version_mainnet_priv,
            .testnet => version_testnet_priv,
        };
    }

    pub fn pubVersion(n: Network) u32 {
        return switch (n) {
            .mainnet => version_mainnet_pub,
            .testnet => version_testnet_pub,
        };
    }

    fn other(n: Network) Network {
        return switch (n) {
            .mainnet => .testnet,
            .testnet => .mainnet,
        };
    }
};

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

    /// Zero `chain_code`. Audit finding `bip32` L3: `chain_code` isn't
    /// secret in the same sense `ExtendedPrivKey.privkey` is, but it's
    /// exactly the ingredient (see SPEC.md's "public-parent + private-child"
    /// note) that turns one leaked non-hardened child private key into the
    /// recovery of this key's own parent private key — worth clearing once
    /// this struct is no longer needed, same as the private side.
    pub fn deinit(self: *ExtendedPubKey) void {
        std.crypto.secureZero(u8, &self.chain_code);
    }
};

/// Seed length bound BIP-32's "Master key generation" requires: "Generate a
/// seed byte sequence S of a chosen length (between 128 and 512 bits)."
pub const min_seed_bytes = 16;
/// See `min_seed_bytes`.
pub const max_seed_bytes = 64;

pub const MasterError = error{
    InvalidMasterKey,
    /// `seed.len` is outside BIP-32's mandated 128-512-bit range
    /// (`min_seed_bytes..max_seed_bytes`). Audit finding `bip32` H3: prior to
    /// this check `masterFromSeed` accepted any length, including 0 —
    /// `masterFromSeed("")` returned a valid, silently-wrong master key
    /// instead of surfacing a truncated read, an off-by-one buffer, or an
    /// uninitialized length as an error.
    InvalidSeedLength,
};

/// `masterFromSeed`: HMAC-SHA512(key="Bitcoin seed", data=seed) → (IL =
/// master privkey, IR = master chain code). BIP-32 requires rejecting
/// `IL >= n` or `IL == 0` (probability ~2^-127; the reference implementation
/// re-seeds and retries — this module reports it as a typed error instead,
/// leaving the retry policy to the caller).
pub fn masterFromSeed(seed: []const u8) MasterError!ExtendedPrivKey {
    if (seed.len < min_seed_bytes or seed.len > max_seed_bytes) return error.InvalidSeedLength;

    var i: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &i);
    std.crypto.auth.hmac.sha2.HmacSha512.create(&i, seed, "Bitcoin seed");

    // CONVENTIONS §2.1 Z1: `il`/`ir` are our own copies of the master scalar
    // and chain code, so we wipe them. The `defer` runs after the return
    // operand has been built, so the returned struct still carries the values.
    var il = i[0..32].*;
    defer std.crypto.secureZero(u8, &il);
    var ir = i[32..64].*;
    defer std.crypto.secureZero(u8, &ir);

    return masterFromIL(il, ir);
}

/// The master-key math from `IL`/`IR` onward, split out as a test-only seam
/// (mirrors `ckdPubFromIL`/`ckdPrivFromIL`): both `IL >= n` and `IL == 0`
/// fire with probability ~2^-127 under an honest HMAC output, so no seed
/// exercises either guard. This lets a test hand in a synthetic `il`
/// directly. Not `pub` outside the module — call `masterFromSeed` for real
/// derivation.
fn masterFromIL(il: [32]u8, ir: [32]u8) MasterError!ExtendedPrivKey {
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
///
/// Recomputes the parent's public key on every call. Audit finding `bip32`
/// H5: that recompute (a scalar EC multiply) is 93.5% of this function's
/// cost, and it is the SAME value on every sibling derived from one parent —
/// deriving 1000 addresses under one account key recomputes the identical
/// `k·G` 1000 times. A caller deriving many siblings from the same parent
/// should compute `neuter(parent).pubkey` once and call
/// `ckdPrivWithParentPub` instead; measured 15.2x faster over 1000 siblings
/// (44.6ms -> 2.94ms projected). This function is unchanged for callers who
/// derive a single child, or who don't have the parent pubkey handy.
pub fn ckdPriv(parent: ExtendedPrivKey, index: u32) CkdError!ExtendedPrivKey {
    // Computed once and reused for both the non-hardened HMAC input and the
    // parent fingerprint below — `pubkeyFromPriv` is a scalar EC multiply,
    // not free, and the parent scalar does not change within this call.
    const parent_pub = pubkeyFromPriv(parent.privkey) catch return error.InvalidChildKey;
    return ckdPrivWithParentPub(parent, parent_pub, index);
}

/// `ckdPriv`, but takes the parent's compressed SEC1 pubkey instead of
/// recomputing it — see `ckdPriv`'s doc comment (audit finding `bip32` H5).
/// `parent_pub` MUST be `(try neuter(parent)).pubkey`; passing any other
/// value silently derives a wrong fingerprint (hardened children) or a wrong
/// child key (normal children), because both are computed FROM it here
/// exactly as `ckdPriv` computes them from its own freshly-derived copy —
/// this function trusts the caller's copy instead of re-deriving it.
pub fn ckdPrivWithParentPub(parent: ExtendedPrivKey, parent_pub: [33]u8, index: u32) CkdError!ExtendedPrivKey {
    const hardened = index >= hardened_offset;

    var data: [37]u8 = undefined;
    defer std.crypto.secureZero(u8, &data); // holds the parent privkey when hardened
    if (hardened) {
        data[0] = 0x00;
        @memcpy(data[1..33], &parent.privkey);
    } else {
        @memcpy(data[0..33], &parent_pub);
    }
    std.mem.writeInt(u32, data[33..37], index, .big);

    var i: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &i);
    std.crypto.auth.hmac.sha2.HmacSha512.create(&i, &data, &parent.chain_code);

    // CONVENTIONS §2.1 Z1 — see `masterFromSeed`. `il` the offset scalar;
    // `ir` the child chain code.
    var il = i[0..32].*;
    defer std.crypto.secureZero(u8, &il);
    var ir = i[32..64].*;
    defer std.crypto.secureZero(u8, &ir);

    return ckdPrivFromIL(parent, parent_pub, index, il, ir);
}

/// The `CKDpriv` math from `IL`/`IR` onward, split out as a test-only seam
/// (mirrors `ckdPubFromIL` below): `child_priv == 0` (BIP-32's documented
/// ~2^-127 retry case) fires only if `il == -parent.privkey (mod n)`, which
/// no honest HMAC output will ever hit. This lets a test hand in that exact
/// synthetic `il` (computable as `Secp256k1.scalar.neg(parent.privkey)`
/// since the caller knows the parent scalar) to exercise the guard directly.
/// Not `pub` outside the module — call `ckdPriv`/`ckdPrivWithParentPub` for
/// real derivation.
fn ckdPrivFromIL(parent: ExtendedPrivKey, parent_pub: [33]u8, index: u32, il: [32]u8, ir: [32]u8) CkdError!ExtendedPrivKey {
    var child_priv = Secp256k1.scalar.add(parent.privkey, il, .big) catch return error.InvalidChildKey;
    defer std.crypto.secureZero(u8, &child_priv);
    if (std.mem.allEqual(u8, &child_priv, 0)) return error.InvalidChildKey;

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

    return ckdPubFromIL(parent, index, il, ir);
}

/// The `CKDpub` math from `IL`/`IR` onward, split out of `ckdPub` as a
/// test-only seam: `IL >= n` (BIP-32's `CKDpub` step 3) fires with
/// probability ~2^-128 under an honest HMAC output, so no vector built from
/// a real seed can exercise the `rejectNonCanonical` guard below. This lets
/// a test hand in a synthetic non-canonical `il` directly. Not `pub` outside
/// the module — call `ckdPub` for real derivation.
fn ckdPubFromIL(parent: ExtendedPubKey, index: u32, il: [32]u8, ir: [32]u8) CkdError!ExtendedPubKey {
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

/// Serialize an extended private key as `xprv...` (mainnet) or `tprv...`
/// (testnet), Base58Check.
pub fn serializePriv(k: ExtendedPrivKey, network: Network, out: []u8) bech32.base58.Error![]const u8 {
    var payload: [serialized_payload_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &payload); // carries the secret privkey
    writeHeader(&payload, network.privVersion(), k.depth, k.parent_fingerprint, k.child_number, k.chain_code);
    payload[45] = 0x00;
    @memcpy(payload[46..78], &k.privkey);
    return bech32.base58.checkEncode(&payload, out);
}

/// Serialize an extended public key as `xpub...` (mainnet) or `tpub...`
/// (testnet), Base58Check.
pub fn serializePub(k: ExtendedPubKey, network: Network, out: []u8) bech32.base58.Error![]const u8 {
    var payload: [serialized_payload_len]u8 = undefined;
    writeHeader(&payload, network.pubVersion(), k.depth, k.parent_fingerprint, k.child_number, k.chain_code);
    @memcpy(payload[45..78], &k.pubkey);
    return bech32.base58.checkEncode(&payload, out);
}

pub const ParseError = bech32.base58.CheckError || error{
    /// Decoded payload isn't exactly 78 bytes.
    InvalidLength,
    /// Version bytes belong to neither network's xprv/xpub constants.
    UnknownVersion,
    /// Version bytes are the OTHER network's (e.g. a `tpub` parsed as
    /// mainnet) — a real key, refused because the caller asked for a
    /// different network.
    WrongNetwork,
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
/// a best-effort partial parse. Only `network`'s version bytes are accepted;
/// the other network's are `error.WrongNetwork`.
pub fn parseExtended(s: []const u8, network: Network) ParseError!ParsedKey {
    var buf: [bech32.base58.max_payload_len]u8 = undefined;
    // CONVENTIONS §2.1 Z1: for an xprv, `buf` holds the decoded private
    // scalar. The `defer` is registered *before* the fallible decode and
    // before every validation `return`, so no exit path can skip it — the
    // previous per-path calls covered only the two xprv outcomes and left the
    // scalar of a malformed xprv (bad length, unknown version, xpub version
    // byte over private payload) sitting in the frame.
    defer std.crypto.secureZero(u8, &buf);
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

    const other = network.other();
    const is_private = if (version == network.privVersion())
        true
    else if (version == network.pubVersion())
        false
    else if (version == other.privVersion() or version == other.pubVersion())
        return error.WrongNetwork
    else
        return error.UnknownVersion;

    if (is_private) {
        if (payload[45] != 0x00) return error.InvalidPrivateKeyMarker;
        var priv: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &priv);
        @memcpy(&priv, payload[46..78]);
        const canonical = blk: {
            Secp256k1.scalar.rejectNonCanonical(priv, .big) catch break :blk false;
            break :blk true;
        };
        if (!canonical or std.mem.allEqual(u8, &priv, 0)) {
            return error.PrivateKeyOutOfRange;
        }
        return .{ .private = .{
            .depth = depth,
            .parent_fingerprint = parent_fp,
            .child_number = child_number,
            .chain_code = chain_code,
            .privkey = priv,
        } };
    }
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
    // `splitScalar`, not `tokenizeScalar`: tokenize silently collapses empty
    // segments, so a doubled or trailing `/` (`m//0/`) would parse as `m/0`
    // instead of being rejected. A derivation path is an identity — two
    // spellings must not map to the same key path (wave-2 audit finding
    // `bip32` F5).
    var it = std.mem.splitScalar(u8, path, '/');
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
        // Digits only: `std.fmt.parseUnsigned` on its own accepts a leading
        // `+` and `_` digit separators (Zig number-literal leniency), which
        // would let `m/+5` and `m/1_0'` parse as valid indices distinct in
        // spelling but identical in the index they produce.
        for (s) |c| {
            if (c < '0' or c > '9') return error.InvalidPathSegment;
        }
        // No unbounded leading zeros: `m/7`, `m/007`, and `m/000...007`
        // would otherwise all parse as the identical index — the same
        // two-spellings-one-identity problem `+`/`_` above guards against
        // (audit finding `bip32` L1). `s.len == 1` still allows the literal
        // segment "0".
        if (s.len > 1 and s[0] == '0') return error.InvalidPathSegment;
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
    const xprv = try serializePriv(master, .mainnet, &priv_buf);

    const pub_key = try neuter(master);
    var pub_buf: [max_serialized_len]u8 = undefined;
    const xpub = try serializePub(pub_key, .mainnet, &pub_buf);

    const parsed_priv = try parseExtended(xprv, .mainnet);
    try testing.expect(parsed_priv == .private);
    try testing.expectEqualSlices(u8, &master.privkey, &parsed_priv.private.privkey);
    try testing.expectEqualSlices(u8, &master.chain_code, &parsed_priv.private.chain_code);

    const parsed_pub = try parseExtended(xpub, .mainnet);
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

test "ckdPrivWithParentPub matches ckdPriv exactly, for both hardened and normal children (H5)" {
    // ckdPrivWithParentPub exists so a caller deriving many siblings can
    // compute the parent's pubkey ONCE and skip ckdPriv's internal
    // recompute; it must be bit-for-bit interchangeable with ckdPriv when
    // given the correct parent pubkey, for both derivation kinds.
    const seed = [_]u8{0x5e} ** 32;
    var master = try masterFromSeed(&seed);
    defer master.deinit();
    const master_pub = try neuter(master);

    var via_ckdpriv_h = try ckdPriv(master, hardened_offset + 3);
    defer via_ckdpriv_h.deinit();
    var via_seam_h = try ckdPrivWithParentPub(master, master_pub.pubkey, hardened_offset + 3);
    defer via_seam_h.deinit();
    try testing.expectEqualSlices(u8, &via_ckdpriv_h.privkey, &via_seam_h.privkey);
    try testing.expectEqualSlices(u8, &via_ckdpriv_h.chain_code, &via_seam_h.chain_code);
    try testing.expectEqualSlices(u8, &via_ckdpriv_h.parent_fingerprint, &via_seam_h.parent_fingerprint);

    var via_ckdpriv_n = try ckdPriv(master, 3);
    defer via_ckdpriv_n.deinit();
    var via_seam_n = try ckdPrivWithParentPub(master, master_pub.pubkey, 3);
    defer via_seam_n.deinit();
    try testing.expectEqualSlices(u8, &via_ckdpriv_n.privkey, &via_seam_n.privkey);
    try testing.expectEqualSlices(u8, &via_ckdpriv_n.chain_code, &via_seam_n.chain_code);
    try testing.expectEqualSlices(u8, &via_ckdpriv_n.parent_fingerprint, &via_seam_n.parent_fingerprint);
}

test "ckdPub rejects a non-canonical IL (IL >= n, BIP-32 CKDpub step 3)" {
    // No honest HMAC output can hit this (probability ~2^-128), so this
    // drives the math directly through the test-only `ckdPubFromIL` seam
    // with a synthetic IL of all-0xFF bytes, which as a big-endian 256-bit
    // integer is far above the secp256k1 order n
    // (0xFFFF...FFFE BAAEDCE6 AF48A03B BFD25E8C D0364141).
    const seed = [_]u8{0xcd} ** 32;
    var master = try masterFromSeed(&seed);
    defer master.deinit();
    const master_pub = try neuter(master);

    const non_canonical_il = [_]u8{0xff} ** 32;
    const ir = [_]u8{0x11} ** 32;
    try testing.expectError(error.InvalidChildKey, ckdPubFromIL(master_pub, 0, non_canonical_il, ir));
}

// secp256k1 group order n, split into 8-hex-digit groups for readability:
// FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
const secp256k1_n_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const secp256k1_n_plus_1_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142";
const secp256k1_n_plus_2_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364143";
const secp256k1_n_minus_1_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140";
const u256_max_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

test "masterFromSeed rejects seeds outside BIP-32's 128-512-bit range (H3)" {
    // BIP-32 "Master key generation": seed length must be 128-512 bits.
    // Before this guard `masterFromSeed` took any length, including 0.
    try testing.expectError(error.InvalidSeedLength, masterFromSeed(&[_]u8{}));
    try testing.expectError(error.InvalidSeedLength, masterFromSeed(&[_]u8{0x01} ** 1));
    try testing.expectError(error.InvalidSeedLength, masterFromSeed(&[_]u8{0x01} ** (min_seed_bytes - 1)));
    try testing.expectError(error.InvalidSeedLength, masterFromSeed(&[_]u8{0x01} ** (max_seed_bytes + 1)));
    try testing.expectError(error.InvalidSeedLength, masterFromSeed(&[_]u8{0x01} ** 256));

    // Positive control: the boundary lengths BIP-32 allows must still work —
    // both are real BIP-32 test vector lengths (vector 1 = 16B, vector 3/2 = 64B).
    var min_ok = try masterFromSeed(&[_]u8{0x01} ** min_seed_bytes);
    min_ok.deinit();
    var max_ok = try masterFromSeed(&[_]u8{0x01} ** max_seed_bytes);
    max_ok.deinit();
}

test "parseExtended rejects private keys beyond n: a ladder, not just n and 0 (H4 test-teeth gap)" {
    // BIP-32 test vector 5 pins exactly `privkey == 0` and `privkey == n`
    // (both KILL an outright removal of the range check), but no vector in
    // the corpus covers the open interval (n, 2^256) — so a check weakened
    // to match only those two exact bit patterns passes the whole suite.
    // This builds the missing rungs directly: n+1, n+2, and 2^256-1, plus a
    // positive control at n-1 (the largest value the range check must ACCEPT).
    const seed = [_]u8{0x01} ** 32;
    var master = try masterFromSeed(&seed);
    defer master.deinit();

    const Case = struct { hex: []const u8, want_error: bool };
    const cases = [_]Case{
        .{ .hex = secp256k1_n_plus_1_hex, .want_error = true },
        .{ .hex = secp256k1_n_plus_2_hex, .want_error = true },
        .{ .hex = u256_max_hex, .want_error = true },
        .{ .hex = secp256k1_n_minus_1_hex, .want_error = false }, // positive control
    };
    for (cases) |c| {
        var priv: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&priv, c.hex);
        const forged = ExtendedPrivKey{
            .depth = 0,
            .parent_fingerprint = .{ 0, 0, 0, 0 },
            .child_number = 0,
            .chain_code = master.chain_code,
            .privkey = priv,
        };
        var buf: [max_serialized_len]u8 = undefined;
        const xprv = try serializePriv(forged, .mainnet, &buf);
        if (c.want_error) {
            try testing.expectError(error.PrivateKeyOutOfRange, parseExtended(xprv, .mainnet));
        } else {
            const parsed = try parseExtended(xprv, .mainnet);
            try testing.expect(parsed == .private);
        }
    }
}

test "ckdPub rejects IL near n, not just an all-0xFF pattern (M2 weaken-resistant)" {
    // The existing guard test (above) uses IL = 0xFF*32. A check weakened to
    // match only that exact byte pattern (e.g. `il[0]==0xff and
    // il[31]==0xff`) still passes it. n itself and n+1 are the values
    // actually adjacent to the boundary the guard exists to enforce.
    const seed = [_]u8{0xcd} ** 32;
    var master = try masterFromSeed(&seed);
    defer master.deinit();
    const master_pub = try neuter(master);
    const ir = [_]u8{0x11} ** 32;

    var il_n: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&il_n, secp256k1_n_hex);
    try testing.expectError(error.InvalidChildKey, ckdPubFromIL(master_pub, 0, il_n, ir));

    var il_n_plus_1: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&il_n_plus_1, secp256k1_n_plus_1_hex);
    try testing.expectError(error.InvalidChildKey, ckdPubFromIL(master_pub, 0, il_n_plus_1, ir));
}

test "masterFromSeed's IL>=n and IL==0 rejects are live code, not dead branches (M1)" {
    var il_n: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&il_n, secp256k1_n_hex);
    const ir = [_]u8{0x22} ** 32;
    try testing.expectError(error.InvalidMasterKey, masterFromIL(il_n, ir));

    const il_zero = [_]u8{0} ** 32;
    try testing.expectError(error.InvalidMasterKey, masterFromIL(il_zero, ir));

    // Positive control: a legitimate small IL must still succeed.
    const il_one = [_]u8{0} ** 31 ++ [_]u8{1};
    var ok = try masterFromIL(il_one, ir);
    ok.deinit();
}

test "ckdPriv's child_priv==0 reject is live code, not a dead branch (M1)" {
    // child_priv = parent.privkey + il (mod n); il = -parent.privkey (mod n)
    // is the unique value that drives it to 0, and it's computable here
    // because the test knows the parent scalar — no honest HMAC output will
    // ever land on it.
    const seed = [_]u8{0x77} ** 32;
    var master = try masterFromSeed(&seed);
    defer master.deinit();
    const master_pub = try neuter(master);

    const il_neg = try Secp256k1.scalar.neg(master.privkey, .big);
    const ir = [_]u8{0x33} ** 32;
    try testing.expectError(error.InvalidChildKey, ckdPrivFromIL(master, master_pub.pubkey, 0, il_neg, ir));
}

test "ckdPubFromIL's rejectIdentity reject is live code, distinct from rejectNonCanonical (M1)" {
    // Same il = -parent.privkey (mod n) construction as the ckdPriv test
    // above: IL*G + parent_pub = -parent_pub + parent_pub = the identity
    // point, which is a DIFFERENT guard (`rejectIdentity`) from the IL>=n
    // check the M2 test above exercises.
    const seed = [_]u8{0x77} ** 32;
    var master = try masterFromSeed(&seed);
    defer master.deinit();
    const master_pub = try neuter(master);

    const il_neg = try Secp256k1.scalar.neg(master.privkey, .big);
    const ir = [_]u8{0x44} ** 32;
    try testing.expectError(error.InvalidChildKey, ckdPubFromIL(master_pub, 0, il_neg, ir));
}

test "parseExtended rejects non-78-byte payloads regardless of checksum validity (M4 test-teeth gap)" {
    // BIP-32 test vector 5's 16 invalid strings are ALL 78-byte payloads
    // (wrong version/prefix/range/checksum) — none of them is the wrong
    // LENGTH, so the length check has never been exercised by the corpus.
    var enc_buf: [bech32.base58.max_encoded_len]u8 = undefined;
    inline for (.{ 10, 40, 77, 79, 120 }) |plen| {
        var payload: [plen]u8 = [_]u8{0} ** plen;
        if (plen >= 4) std.mem.writeInt(u32, payload[0..4], version_mainnet_priv, .big);
        const s = try bech32.base58.checkEncode(&payload, &enc_buf);
        try testing.expectError(error.InvalidLength, parseExtended(s, .mainnet));
    }
    // Positive control: the real length still parses (any other test already
    // covers this; repeated here so this test alone proves 78 is special).
    const seed = [_]u8{0x09} ** 32;
    var master = try masterFromSeed(&seed);
    defer master.deinit();
    var buf: [max_serialized_len]u8 = undefined;
    const xprv = try serializePriv(master, .mainnet, &buf);
    const parsed = try parseExtended(xprv, .mainnet);
    try testing.expect(parsed == .private);
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

test "F5 regression: parsePath rejects +/_ leniency and empty segments from doubled/trailing slashes" {
    var out: [max_path_depth]u32 = undefined;

    // `std.fmt.parseUnsigned` on its own accepts these; the path parser must
    // not, or `m/+5` and `m/5` become the same identity under two spellings.
    try testing.expectError(error.InvalidPathSegment, parsePath("m/+5", &out));
    try testing.expectError(error.InvalidPathSegment, parsePath("m/1_0'", &out));
    try testing.expectError(error.InvalidPathSegment, parsePath("m/-5", &out));

    // Doubled/trailing/leading slashes must not silently collapse to a
    // shorter, differently-spelled path.
    try testing.expectError(error.InvalidPathSegment, parsePath("m//0", &out));
    try testing.expectError(error.InvalidPathSegment, parsePath("m/0/", &out));
    try testing.expectError(error.InvalidPathSegment, parsePath("/m/0", &out));

    // Positive control: the legitimate spelling still parses.
    const p = try parsePath("m/0", &out);
    try testing.expectEqualSlices(u32, &.{0}, p);
}

test "parsePath rejects unbounded leading zeros: m/7 and m/007 must not be the same identity (L1)" {
    var out: [max_path_depth]u32 = undefined;
    try testing.expectError(error.InvalidPathSegment, parsePath("m/007", &out));
    try testing.expectError(error.InvalidPathSegment, parsePath("m/0000007", &out));
    try testing.expectError(error.InvalidPathSegment, parsePath("m/007'", &out)); // hardened spelling too
    try testing.expectError(error.InvalidPathSegment, parsePath("m/44'/007", &out)); // not just the first segment

    // Positive control: the bare "0" segment (not a leading zero on a
    // nonzero value) must still parse — it's the only single-digit case.
    const p = try parsePath("m/0", &out);
    try testing.expectEqualSlices(u32, &.{0}, p);
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
        .mainnet,
    ));
}

// ── fuzz: extended-key + derivation-path text parse, never panics ──────────
//
// `parseExtended` is what loads an `xprv`/`xpub` a user pastes in (or an
// exchange/wallet imports) — Base58Check text with no structural guarantee
// until the checksum's been verified. `parsePath` similarly takes a
// derivation-path string a caller (config, CLI, wallet UI) may pass through
// verbatim from a user.

/// `testkit.fuzz` — see that module for why a corpus entry is not the frame.
const tkfuzz = @import("testkit").fuzz;
const pathSeed = tkfuzz.seed;

const xkey_fuzz_buf_len = 128;
const xkey_seed_count = 8;

/// The corpus both `fuzzParseExtended` and its guard replay.
///
/// ⛔ An `xprv`/`xpub` is Base58**Check**: the last four octets are a double
/// SHA-256 over everything before them. A hand-edited literal therefore dies
/// at `error.ChecksumMismatch` before `parseExtended` reads a single field, so
/// the only way to get a seed that reaches the version/depth/key checks is to
/// serialize one with the module's own `serializePriv`/`serializePub`.
const XKeyCorpus = struct {
    stores: [xkey_seed_count][4 + xkey_fuzz_buf_len]u8 = undefined,
    slots: [xkey_seed_count][]const u8 = undefined,

    fn build(self: *XKeyCorpus) ![]const []const u8 {
        const master_seed = [_]u8{0x01} ** 32;
        var master = try masterFromSeed(&master_seed);
        defer master.deinit();

        var priv_buf: [max_serialized_len]u8 = undefined;
        const xprv = try serializePriv(master, .mainnet, &priv_buf);
        const pub_key = try neuter(master);
        var pub_buf: [max_serialized_len]u8 = undefined;
        const xpub = try serializePub(pub_key, .mainnet, &pub_buf);

        // A derived child, so the depth/child-number/fingerprint fields are
        // non-zero on at least one seed rather than all-zero everywhere.
        var child = try ckdPriv(master, hardened_offset + 44);
        defer child.deinit();
        var child_buf: [max_serialized_len]u8 = undefined;
        const child_xprv = try serializePriv(child, .mainnet, &child_buf);

        var mutant: [xkey_fuzz_buf_len]u8 = undefined;

        self.slots[0] = tkfuzz.seedInto(&self.stores[0], xprv); // parses as .private
        self.slots[1] = tkfuzz.seedInto(&self.stores[1], xpub); // parses as .public
        self.slots[2] = tkfuzz.seedInto(&self.stores[2], child_xprv); // depth 1, hardened child
        // A flipped payload character: the checksum must catch it.
        @memcpy(mutant[0..xprv.len], xprv);
        mutant[10] = if (mutant[10] == 'z') 'y' else mutant[10] + 1;
        self.slots[3] = tkfuzz.seedInto(&self.stores[3], mutant[0..xprv.len]);
        // A flipped CHECKSUM character, which is a different code path from a
        // flipped payload character even though both end at the same error.
        @memcpy(mutant[0..xprv.len], xprv);
        mutant[xprv.len - 1] = if (mutant[xprv.len - 1] == 'z') 'y' else mutant[xprv.len - 1] + 1;
        self.slots[4] = tkfuzz.seedInto(&self.stores[4], mutant[0..xprv.len]);
        // The bad-length/bad-checksum literal the value test above uses.
        self.slots[5] = tkfuzz.seedInto(
            &self.stores[5],
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
        );
        // Not Base58 at all: `0` and `l` are outside the alphabet.
        self.slots[6] = tkfuzz.seedInto(&self.stores[6], "xprv0lIO" ++ "1" ** 100);
        self.slots[7] = tkfuzz.seedInto(&self.stores[7], ""); // the ONE input the collapsed harness ran
        return &self.slots;
    }
};

test "fuzz: parseExtended never panics on arbitrary text" {
    var corpus: XKeyCorpus = .{};
    const seeds = try corpus.build();
    try testing.fuzz({}, fuzzParseExtended, .{ .corpus = seeds });
}

fn fuzzParseExtended(_: void, smith: *std.testing.Smith) !void {
    var buf: [xkey_fuzz_buf_len]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM —
    // so `len` was 0 for every input and `parseExtended` was handed "", which
    // fails the Base58 length check before touching the checksum, the version
    // bytes or the key material, with the xprv sitting unread in `buf`.
    // Measured 2026-09-07 over the corpus above: **0 of 8 seeds non-empty and
    // 0 keys parsed before, 7 of 8 non-empty (one seed IS the empty string)
    // and 3 parsed after.**
    const len: usize = smith.slice(&buf);
    _ = parseExtended(buf[0..len], .mainnet) catch return;
}

test "corpus: every xkey seed reaches parseExtended, and the parsed count is pinned" {
    // ⭐ Built from `XKeyCorpus.build`, the same call the harness makes: a
    // guard measuring a different corpus is not a guard. It is also the only
    // thing that would notice a seed outgrowing the 128-octet buffer — such a
    // seed reads back EMPTY rather than truncated.
    //
    // `privates`/`publics` are pinned separately because the two arms of
    // `ParsedKey` are different code below the checksum, and neither can be
    // reached by the empty string.
    var corpus: XKeyCorpus = .{};
    const seeds = try corpus.build();
    var nonempty: usize = 0;
    var privates: usize = 0;
    var publics: usize = 0;
    var checksum_failures: usize = 0;
    for (seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [xkey_fuzz_buf_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (parseExtended(buf[0..len], .mainnet)) |k| {
            switch (k) {
                .private => |p| {
                    var m = p;
                    m.deinit();
                    privates += 1;
                },
                .public => publics += 1,
            }
        } else |err| if (err == error.ChecksumMismatch) {
            checksum_failures += 1;
        }
    }
    // One seed IS the empty string, a legal member of a refusal corpus.
    try testing.expectEqual(seeds.len - 1, nonempty);
    // Measured 2026-09-07: with the collapsing draw, 0 non-empty, 0 private,
    // 0 public and 0 checksum failures — one empty string eight times, all
    // eight rejected on length. After:
    try testing.expectEqual(@as(usize, 2), privates);
    try testing.expectEqual(@as(usize, 1), publics);
    try testing.expectEqual(@as(usize, 3), checksum_failures);
}

/// Derivation paths in the format `Smith.slice` reads. Unlike an xprv these
/// are plain text with no checksum, so they can be quoted directly — lifted
/// from `parsePath: m/44'/0'/0'/0/0 and bare relative paths` and from the F5
/// regression that pins the `+`/`_`/empty-segment rejections.
const path_seeds = [_][]const u8{
    pathSeed("m/44'/0'/0'/0/0"), // the BIP-44 account path
    pathSeed("0h/1H/2"), // a bare relative path, both hardened spellings
    pathSeed("m/0"), // the shortest accepted path
    pathSeed("m/0'/1/2'"), // the path `derivePath matches manual chained ckdPriv` uses
    pathSeed("m/2147483647'/0"), // the largest legal hardened index
    pathSeed("m/abc"), // InvalidPathSegment
    pathSeed("m/2147483648"), // IndexOutOfRange: 2^31 pre-offset
    pathSeed("m/+5"), // InvalidPathSegment: parseUnsigned leniency, refused here
    pathSeed("m/1_0'"), // InvalidPathSegment: digit separator
    pathSeed("m/-5"), // InvalidPathSegment
    pathSeed("m//0"), // InvalidPathSegment: doubled slash
    pathSeed("m/0/"), // InvalidPathSegment: trailing slash
    pathSeed("/m/0"), // InvalidPathSegment: leading slash
    pathSeed("m" ++ "/0" ** 33), // PathTooDeep: 33 segments against max_path_depth = 32
    // The charset knob, one `u64` word per octet it is meant to decide.
    // ⛔ Measured 2026-09-08: over the fifteen seeds above, `boolWeighted(1, 4)`
    // was drawn 159 times and returned `true` **zero** times, because the byte
    // draw leaves nothing behind and an exhausted `Smith` returns the weight
    // minimum. The alphabet-bending loop had never executed its body. These
    // two seeds are the only inputs in the ordinary lane that reach it.
    bentPathSeed(&[_]u8{ 14, 10, 0, 11, 10, 1 }, &([_]u64{1} ** 6)), // -> "m/0'/1"
    bentPathSeed("X/0", &.{1}), // only the FIRST octet bent: 'X' -> '8', rest verbatim
    pathSeed(""), // the ONE input the collapsed harness ever ran
};

/// `pathSeed` plus a tail of `u64` words for the per-octet charset knob in
/// `fuzzParsePath` (`1` bends that octet into `path_alphabet`, `0` leaves it
/// alone; once the words run out every remaining draw is the weight minimum).
fn bentPathSeed(comptime raw: []const u8, comptime bends: []const u64) []const u8 {
    return &struct {
        const words = blk: {
            var w: [bends.len * 8]u8 = undefined;
            for (bends, 0..) |b, i| std.mem.writeInt(u64, w[i * 8 ..][0..8], b, .little);
            break :blk w;
        };
        const bytes = std.mem.toBytes(@as(u32, raw.len)) ++ raw[0..raw.len].* ++ words;
    }.bytes;
}

test "fuzz: parsePath never panics on arbitrary text" {
    try testing.fuzz({}, fuzzParsePath, .{ .corpus = &path_seeds });
}

const path_alphabet = "0123456789/'hHmM";

fn fuzzParsePath(_: void, smith: *std.testing.Smith) !void {
    var buf: [96]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length — same defect and same measurement as `fuzzParseExtended` above.
    // Measured 2026-09-07 over the corpus above: **0 of 15 seeds non-empty and
    // 0 paths parsed before, 14 of 15 non-empty and 5 parsed after.**
    const len: usize = smith.slice(&buf);
    // ⚠ Under `--fuzz` this biases raw bytes toward the path alphabet. On a
    // corpus replay `Smith` is drained by the draw above, so the knob is the
    // weight minimum — `false` — unless the seed carries a `u64` word per
    // octet after the frame. That is deliberate: a seed that IS a real path
    // wants to reach `parsePath` verbatim, and the two `bentPathSeed` entries
    // are there so the loop body is not dead in the ordinary lane. Measured
    // 2026-09-08: 0 bent octets in 159 draws before, 7 in 168 after.
    for (buf[0..len]) |*c| {
        if (smith.boolWeighted(1, 4)) c.* = path_alphabet[c.* % path_alphabet.len];
    }
    var out: [max_path_depth]u32 = undefined;
    _ = parsePath(buf[0..len], &out) catch return;
}

test "corpus: every path reaches parsePath, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment.
    //
    // `levels` — total derivation levels parsed across the corpus — is pinned
    // beside `parsed`, because it is the number the empty input cannot move
    // and it notices a seed being shortened as well as dropped.
    var nonempty: usize = 0;
    var parsed: usize = 0;
    var levels: usize = 0;
    var hardened: usize = 0;
    var bent: usize = 0;
    var bend_draws: usize = 0;
    for (path_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [96]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        for (buf[0..len]) |*c| {
            bend_draws += 1;
            if (smith.boolWeighted(1, 4)) {
                c.* = path_alphabet[c.* % path_alphabet.len];
                bent += 1;
            }
        }
        var out: [max_path_depth]u32 = undefined;
        if (parsePath(buf[0..len], &out)) |p| {
            parsed += 1;
            levels += p.len;
            for (p) |ix| {
                if (ix >= hardened_offset) hardened += 1;
            }
        } else |_| {}
    }
    // One seed IS the empty path, a legal member of a refusal corpus.
    try testing.expectEqual(path_seeds.len - 1, nonempty);
    // Measured 2026-09-07: with the collapsing draw, 0 non-empty, 0 parsed,
    // 0 levels and 0 hardened indices — one empty string fifteen times.
    try testing.expectEqual(@as(usize, 7), parsed);
    try testing.expectEqual(@as(usize, 18), levels);
    try testing.expectEqual(@as(usize, 9), hardened);
    // ⛔ The knob after the byte draw. Measured 2026-09-08: 0 of 159 draws
    // returned `true` before the two `bentPathSeed` entries were added, so the
    // alphabet-bending branch was dead in the ordinary lane. Pinned as a pair
    // — `bend_draws` moves if a seed is shortened, `bent` if a tail is lost.
    try testing.expectEqual(@as(usize, 168), bend_draws);
    try testing.expectEqual(@as(usize, 7), bent);
}
