// SPDX-License-Identifier: MIT
//! BOLT#4 "Route Blinding": the cryptography of blinded paths.
//!
//! The path creator (the recipient, for a payment) picks a session key `e_0`
//! and, for each node `N_i` of the path, derives (BOLT#4 "Requirements"):
//!
//! ```text
//! E_i  = e_i * G                              path_key (first one published)
//! ss_i = SHA256(e_i * N_i)                    = SHA256(k_i * E_i) at N_i
//! rho_i = HMAC256("rho", ss_i)
//! B_i  = HMAC256("blinded_node_id", ss_i) * N_i
//! encrypted_data_i = ChaCha20-Poly1305(rho_i, nonce 0, ad "", data_i)
//! e_{i+1} = SHA256(E_i || ss_i) * e_i,  E_{i+1} = SHA256(E_i || ss_i) * E_i
//! ```
//!
//! A node of the path receiving `E_i` (`unblind`) computes `ss_i`, decrypts its
//! `encrypted_recipient_data`, derives `E_{i+1}` for the next node and its own
//! blinded private key `b_i = HMAC256("blinded_node_id", ss_i) * k_i`, the key
//! it peels the onion addressed to `B_i` with (`core.process`). The TLV
//! contents of the payloads (`short_channel_id`, `payment_relay`,
//! `next_path_key_override`, ...) are the caller's; this file moves bytes.
//! Anchors: BOLT#4 `route-blinding-test.json` (generate and unblind
//! sections), `kat_test` in this file.

const std = @import("std");
const Secp256k1 = @import("k256").Secp256k1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const ChaChaPoly = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const keyderive = @import("keyderive.zig");
const burn = @import("burn.zig");

pub const pubkey_len = 33;
pub const tag_len = ChaChaPoly.tag_length;

pub const Error = error{
    /// A node id or path key is not a valid compressed secp256k1 point.
    InvalidPublicKey,
    /// A degenerate scalar or point (probability ~2^-128 for honest input).
    IdentityElement,
    /// `encrypted_data` does not authenticate under this node's `rho`.
    DecryptionFailed,
    /// An output buffer is not `payload.len + tag_len` (create) or
    /// `encrypted.len - tag_len` (unblind), or the slice counts differ.
    LengthMismatch,
};

/// Bytes `burn.stack` zeroes after the EC work (secp256k1 multiplies).
const blind_burn = 40 * 1024;

fn blindedNodeFactor(out: *[32]u8, ss: *const [32]u8) void {
    HmacSha256.create(out, ss, "blinded_node_id");
}

fn nextFactor(out: *[32]u8, path_key: *const [pubkey_len]u8, ss: *const [32]u8) void {
    var h = Sha256.init(.{});
    h.update(path_key);
    h.update(ss);
    h.final(out);
}

/// One hop of a blinded path, sender side.
pub const BlindedHop = struct {
    blinded_node_id: [pubkey_len]u8,
    /// `encrypted_recipient_data`: the caller's buffer, `payload.len + 16`.
    encrypted_data: []u8,
};

/// Create a blinded path over `node_ids` from `session_key`, encrypting
/// `payloads[i]` for node `i` into `out[i].encrypted_data` (the caller sizes
/// each `payloads[i].len + tag_len`). Returns the first path key `E_0`
/// (`first_path_key`, published with the path). Two paths concatenate by the
/// creator of the first putting the second's `E_0` into its last payload as
/// `next_path_key_override`.
pub fn createPath(
    session_key: *const [32]u8,
    node_ids: []const [pubkey_len]u8,
    payloads: []const []const u8,
    out: []BlindedHop,
) Error![pubkey_len]u8 {
    defer burn.stack(blind_burn);
    return createPathBody(session_key, node_ids, payloads, out);
}

noinline fn createPathBody(
    session_key: *const [32]u8,
    node_ids: []const [pubkey_len]u8,
    payloads: []const []const u8,
    out: []BlindedHop,
) Error![pubkey_len]u8 {
    if (node_ids.len != payloads.len or node_ids.len != out.len) return error.LengthMismatch;
    for (payloads, out) |p, o| if (o.encrypted_data.len != p.len + tag_len) return error.LengthMismatch;
    var e = session_key.*;
    defer std.crypto.secureZero(u8, &e);
    var point = Secp256k1.combMulBase(e, .big) catch return error.IdentityElement;
    const first = point.toCompressedSec1();
    for (node_ids, payloads, out) |nid, payload, *o| {
        const n_point = Secp256k1.fromSec1(&nid) catch return error.InvalidPublicKey;
        var ss: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &ss);
        const shared = n_point.mul(e, .big) catch return error.IdentityElement;
        Sha256.hash(&shared.toCompressedSec1(), &ss, .{});
        var f: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &f);
        blindedNodeFactor(&f, &ss);
        o.blinded_node_id = (n_point.mul(f, .big) catch return error.IdentityElement).toCompressedSec1();
        var rho: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &rho);
        keyderive.generateKey(&rho, .rho, &ss);
        const nonce: [ChaChaPoly.nonce_length]u8 = @splat(0);
        ChaChaPoly.encrypt(o.encrypted_data[0..payload.len], o.encrypted_data[payload.len..][0..tag_len], payload, "", nonce, rho);
        // Next path key and path private key.
        const path_key = point.toCompressedSec1();
        nextFactor(&f, &path_key, &ss);
        point = point.mul(f, .big) catch return error.IdentityElement;
        e = Secp256k1.scalar.mul(e, f, .big) catch return error.IdentityElement;
    }
    return first;
}

/// What a node of a blinded path learns from its `path_key`.
pub const Unblinded = struct {
    /// `b_i`: the private key of the blinded node id `B_i`; the onion for
    /// this hop is processed with it (`core.process`).
    blinded_privkey: [32]u8,
    /// `E_{i+1}`, to forward to the next node (unless the decrypted data
    /// carries `next_path_key_override`).
    next_path_key: [pubkey_len]u8,
};

/// The receiving side: `node_privkey` = `k_i`, `path_key` = `E_i`,
/// `encrypted` = this hop's `encrypted_recipient_data`; the plaintext goes to
/// `plain_out` (`encrypted.len - tag_len` bytes; zeroed on failure).
pub fn unblind(
    node_privkey: *const [32]u8,
    path_key: *const [pubkey_len]u8,
    encrypted: []const u8,
    plain_out: []u8,
    out: *Unblinded,
) Error!void {
    defer burn.stack(blind_burn);
    return unblindBody(node_privkey, path_key, encrypted, plain_out, out);
}

noinline fn unblindBody(
    node_privkey: *const [32]u8,
    path_key: *const [pubkey_len]u8,
    encrypted: []const u8,
    plain_out: []u8,
    out: *Unblinded,
) Error!void {
    if (encrypted.len < tag_len or plain_out.len != encrypted.len - tag_len) return error.LengthMismatch;
    const e_point = Secp256k1.fromSec1(path_key) catch return error.InvalidPublicKey;
    var ss: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &ss);
    const shared = e_point.mul(node_privkey.*, .big) catch return error.IdentityElement;
    Sha256.hash(&shared.toCompressedSec1(), &ss, .{});
    var rho: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &rho);
    keyderive.generateKey(&rho, .rho, &ss);
    const nonce: [ChaChaPoly.nonce_length]u8 = @splat(0);
    const n = plain_out.len;
    ChaChaPoly.decrypt(plain_out, encrypted[0..n], encrypted[n..][0..tag_len].*, "", nonce, rho) catch {
        std.crypto.secureZero(u8, plain_out);
        return error.DecryptionFailed;
    };
    var f: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &f);
    blindedNodeFactor(&f, &ss);
    out.blinded_privkey = Secp256k1.scalar.mul(node_privkey.*, f, .big) catch return error.IdentityElement;
    nextFactor(&f, path_key, &ss);
    out.next_path_key = (e_point.mul(f, .big) catch return error.IdentityElement).toCompressedSec1();
}

// ── tests: BOLT#4 route-blinding-test.json ─────────────────────────────────

const testing = std.testing;

fn hx(comptime n: usize, comptime s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const Hop = struct {
    node_id: []const u8,
    node_privkey: []const u8,
    encoded_tlvs: []const u8,
    path_key: []const u8,
    encrypted_data: []const u8,
    blinded_node_id: []const u8,
    blinded_privkey: []const u8,
    next_path_key: []const u8,
};

// Bob -> Carol (session 02..02), then Dave -> Eve (session 01..01); BOLT#4
// `route-blinding-test.json`, fields copied programmatically.
const hops = [_]Hop{
    .{ .node_id = "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c", .node_privkey = "4242424242424242424242424242424242424242424242424242424242424242", .encoded_tlvs = "011a0000000000000000000000000000000000000000000000000000020800000000000006c10a0800240000009627100c06000b69e505dc0e00fd023103123456", .path_key = "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766", .encrypted_data = "cd4100ff9c09ed28102b210ac73aa12d63e90852cebc496c49f57c49982088b49f2e70b99287fdee0aa58aa39913ab405813b999f66783aa2fe637b3cda91ffc0913c30324e2c6ce327e045183e4bffecb", .blinded_node_id = "03da173ad2aee2f701f17e59fbd16cb708906d69838a5f088e8123fb36e89a2c25", .blinded_privkey = "d12fec0332c3e9d224789a17ebd93595f37d37bd8ef8bd3d2e6ce50acb9e554f", .next_path_key = "034e09f450a80c3d252b258aba0a61215bf60dda3b0dc78ffb0736ea1259dfd8a0" },
    .{ .node_id = "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007", .node_privkey = "4343434343434343434343434343434343434343434343434343434343434343", .encoded_tlvs = "020800000000000004510821031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f0a0800300000006401f40c06000b69c105dc0e00", .path_key = "034e09f450a80c3d252b258aba0a61215bf60dda3b0dc78ffb0736ea1259dfd8a0", .encrypted_data = "cc0f16524fd7f8bb0b1d8d40ad71709ef140174c76faa574cac401bb8992fef76c4d004aa485dd599ed1cf2715f57ff62da5aaec5d7b10d59b04d8a9d77e472b9b3ecc2179334e411be22fa4c02b467c7e", .blinded_node_id = "02e466727716f044290abf91a14a6d90e87487da160c2a3cbd0d465d7a78eb83a7", .blinded_privkey = "bfa697fbbc8bbc43ca076e6dd60d306038a32af216b9dc6fc4e59e5ae28823c1", .next_path_key = "03af5ccc91851cb294e3a364ce63347709a08cdffa58c672e9a5c587ddd1bbca60" },
    .{ .node_id = "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991", .node_privkey = "4444444444444444444444444444444444444444444444444444444444444444", .encoded_tlvs = "01230000000000000000000000000000000000000000000000000000000000000000000000020800000000000002310a060090000000fa0c06000b699105dc0e00", .path_key = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f", .encrypted_data = "0fa0a72cff3b64a3d6e1e4903cf8c8b0a17144aeb249dcb86561adee1f679ee8db3e561d9c43815fd4bcebf6f58c546da0cd8a9bf5cebd0d554802f6c0255e28e4a27343f761fe518cd897463187991105", .blinded_node_id = "036861b366f284f0a11738ffbf7eda46241a8977592878fe3175ae1d1e4754eccf", .blinded_privkey = "cebc115c7fce4c295dc396dea6c79115b289b8ceeceea2ed61cf31428d88fc4e", .next_path_key = "03e09038ee76e50f444b19abf0a555e8697e035f62937168b80adf0931b31ce52a" },
    .{ .node_id = "02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145", .node_privkey = "4545454545454545454545454545454545454545454545454545454545454545", .encoded_tlvs = "011a00000000000000000000000000000000000000000000000000000604deadbeef0c06000b690105dc0e0f020000000000000000000000000000fdffff0206c1", .path_key = "03e09038ee76e50f444b19abf0a555e8697e035f62937168b80adf0931b31ce52a", .encrypted_data = "da1a7e5f7881219884beae6ae68971de73bab4c3055d9865b1afb60724a2e4d3f0489ad884f7f3f77149209f0df51efd6b276294a02e3949c7254fbc8b5cab58212d9a78983e1cf86fe218b30c4ca8f6d8", .blinded_node_id = "021982a48086cb8984427d3727fe35a03d396b234f0701f5249daa12e8105c8dae", .blinded_privkey = "ff4e07da8d92838bedd019ce532eb990ed73b574e54a67862a1df81b40c0d2af", .next_path_key = "038fc6859a402b96ce4998c537c823d6ab94d1598fca02c788ba5dd79fbae83589" },
};

fn unhexAlloc(a: std.mem.Allocator, s: []const u8) ![]u8 {
    const b = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(b, s);
    return b;
}

test "route blinding: createPath reproduces BOLT#4 route-blinding-test.json (both concatenated segments)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const segs = [_]struct { session: [32]u8, lo: usize }{
        .{ .session = @splat(0x02), .lo = 0 },
        .{ .session = @splat(0x01), .lo = 2 },
    };
    for (segs) |seg| {
        var ids: [2][pubkey_len]u8 = undefined;
        var payloads: [2][]const u8 = undefined;
        var out: [2]BlindedHop = undefined;
        for (0..2) |i| {
            const h = hops[seg.lo + i];
            _ = try std.fmt.hexToBytes(&ids[i], h.node_id);
            payloads[i] = try unhexAlloc(a, h.encoded_tlvs);
            out[i].encrypted_data = try a.alloc(u8, payloads[i].len + tag_len);
        }
        const first = try createPath(&seg.session, &ids, &payloads, &out);
        var want_pk: [pubkey_len]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want_pk, hops[seg.lo].path_key);
        try testing.expectEqualSlices(u8, &want_pk, &first);
        for (0..2) |i| {
            const h = hops[seg.lo + i];
            try testing.expectEqualSlices(u8, try unhexAlloc(a, h.blinded_node_id), &out[i].blinded_node_id);
            try testing.expectEqualSlices(u8, try unhexAlloc(a, h.encrypted_data), out[i].encrypted_data);
        }
    }
}

test "route blinding: unblind at every hop gives the published blinded key, plaintext and next path key" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (hops) |h| {
        var k: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&k, h.node_privkey);
        var pk: [pubkey_len]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pk, h.path_key);
        const enc = try unhexAlloc(a, h.encrypted_data);
        const plain = try a.alloc(u8, enc.len - tag_len);
        var u: Unblinded = undefined;
        try unblind(&k, &pk, enc, plain, &u);
        try testing.expectEqualSlices(u8, try unhexAlloc(a, h.encoded_tlvs), plain);
        try testing.expectEqualSlices(u8, try unhexAlloc(a, h.blinded_privkey), &u.blinded_privkey);
        try testing.expectEqualSlices(u8, try unhexAlloc(a, h.next_path_key), &u.next_path_key);
        // b_i * G is the blinded node id.
        const bid = (try Secp256k1.basePoint.mul(u.blinded_privkey, .big)).toCompressedSec1();
        try testing.expectEqualSlices(u8, try unhexAlloc(a, h.blinded_node_id), &bid);
        // Tampered data, another node's key, bad lengths and a bad path key.
        enc[0] ^= 1;
        try testing.expectError(error.DecryptionFailed, unblind(&k, &pk, enc, plain, &u));
        enc[0] ^= 1;
        var k2 = k;
        k2[31] ^= 1;
        try testing.expectError(error.DecryptionFailed, unblind(&k2, &pk, enc, plain, &u));
        try testing.expectError(error.LengthMismatch, unblind(&k, &pk, enc, plain[1..], &u));
        var bad_pk = pk;
        bad_pk[0] = 0x05;
        try testing.expectError(error.InvalidPublicKey, unblind(&k, &bad_pk, enc, plain, &u));
    }
}

test "route blinding: createPath refuses mismatched lengths and a bad node id" {
    const s: [32]u8 = @splat(2);
    var buf: [20]u8 = undefined;
    var out = [_]BlindedHop{.{ .blinded_node_id = undefined, .encrypted_data = &buf }};
    const ids = [_][pubkey_len]u8{@splat(0x02)};
    try testing.expectError(error.LengthMismatch, createPath(&s, &ids, &.{"abc"}, &out));
    try testing.expectError(error.LengthMismatch, createPath(&s, &ids, &.{}, out[0..0]));
    var bad = ids;
    bad[0][0] = 0x07;
    try testing.expectError(error.InvalidPublicKey, createPath(&s, &bad, &.{"abcd"}, &out));
}
