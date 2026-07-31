// SPDX-License-Identifier: MIT
//! Tests against the official BOLT#4 test vector (`kat_vectors.zig`).
//!
//! Coverage:
//!   - `OnionPacket.fromBytes`/`.toBytes()` round-trip on the official
//!     1366-byte packet, incl. the packet-level version/pubkey-validity
//!     checks.
//!   - Every hop's published PRIVATE key really derives its published
//!     PUBLIC key (`Secp256k1.basePoint.mul` — plain std, no Sphinx logic).
//!   - The first hop's ECDH shared secret `ss_0`, computed directly against
//!     raw `std.crypto.ecc.Secp256k1`/`std.crypto.hash.sha2.Sha256` calls
//!     (an std-only cross-check of `core.deriveHopSecrets`'s hop-0 step,
//!     computable without the blinding chain since hop 0's ephemeral
//!     scalar is the raw `session_key`).
//!   - `bigsize`/`hopframe.shiftSize` against the 5 real per-hop payload
//!     lengths the vector encodes.
//!   - The three crypto cores, end-to-end against the official vector:
//!     `deriveHopSecrets` reproduces all 5 published `shared_secrets`;
//!     `construct` reproduces the published 1366-byte `onion` BYTE-EXACT
//!     (the make-or-break oracle for the whole module); `process` peels
//!     hop 0 of the published packet; and a full construct → 5x process
//!     round-trip recovers every hop's TLV payload with the final hop
//!     flagged. Plus the constant-time HMAC gate: a 1-bit hmac tamper is
//!     `error.IntegrityCheckFailed`.

const std = @import("std");
const sphinx = @import("root.zig");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const v = @import("kat_vectors.zig");

const testing = std.testing;

fn hexN(comptime n: usize, hex_str: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

/// Decode a variable-length hex string into `buf` (which must be at least
/// `hex_str.len / 2` bytes) and return the written subslice.
fn hexInto(buf: []u8, hex_str: []const u8) []u8 {
    const n = hex_str.len / 2;
    _ = std.fmt.hexToBytes(buf[0..n], hex_str) catch unreachable;
    return buf[0..n];
}

test "KAT: the official 1366-byte onion packet round-trips through OnionPacket" {
    const onion_bytes = hexN(sphinx.packet_len, v.onion);
    const pkt = try sphinx.OnionPacket.fromBytes(onion_bytes);
    try testing.expectEqual(sphinx.version_byte, pkt.version);

    // Coincidence of this particular fixture (documented in
    // kat_vectors.zig): session_key numerically equals node_privkeys[0],
    // so the embedded ephemeral pubkey epk_0 = session_key * G equals
    // pubkeys[0] exactly.
    const expected_pubkey = hexN(sphinx.pubkey_len, v.pubkeys[0]);
    try testing.expectEqualSlices(u8, &expected_pubkey, &pkt.public_key);

    try testing.expectEqualSlices(u8, &onion_bytes, &pkt.toBytes());
}

test "KAT: every published node_privkey really derives its published pubkey (std-only, no sphinx core)" {
    inline for (v.pubkeys, v.node_privkeys) |pubkey_hex, privkey_hex| {
        const privkey = hexN(32, privkey_hex);
        const expected_pubkey = hexN(sphinx.pubkey_len, pubkey_hex);
        const derived_point = try Secp256k1.basePoint.mul(privkey, .big);
        const derived_pubkey = derived_point.toCompressedSec1();
        try testing.expectEqualSlices(u8, &expected_pubkey, &derived_pubkey);
    }
}

test "KAT: hop-0 shared secret ss_0, via raw std secp256k1 ECDH (std-only cross-check of core.zig)" {
    // BOLT#4 "Shared Secret": ss_0 = SHA256(compressed(hop0_pubkey *
    // ephemeral_scalar_0)), and ephemeral_scalar_0 IS session_key (the
    // chain's starting point, before any blinding) -- the one shared
    // secret in this 5-hop route computable without the blinding chain,
    // recomputed here against raw std calls (Secp256k1.fromSec1 ->
    // .mul(_, .big) -> .toCompressedSec1() -> Sha256.hash) independently
    // of core.deriveHopSecrets' own implementation.
    const session_key = hexN(32, v.session_key);
    const hop0_pubkey_bytes = hexN(sphinx.pubkey_len, v.pubkeys[0]);

    const hop0_point = try Secp256k1.fromSec1(&hop0_pubkey_bytes);
    const shared_point = try hop0_point.mul(session_key, .big);
    const compressed = shared_point.toCompressedSec1();

    var ss: [32]u8 = undefined;
    Sha256.hash(&compressed, &ss, .{});

    const expected_ss = hexN(32, v.shared_secrets[0]);
    try testing.expectEqualSlices(u8, &expected_ss, &ss);
}

test "KAT: bigsize length prefixes on the 5 official hop payloads (18, 82, 18, 18, 272)" {
    const expected_lens = [_]u64{ 18, 82, 18, 18, 272 };
    var scratch: [600]u8 = undefined;
    inline for (v.payloads, expected_lens) |payload_hex, expected_len| {
        const bytes = hexInto(&scratch, payload_hex);
        const decoded = try sphinx.bigsize.read(bytes);
        try testing.expectEqual(expected_len, decoded.value);
        try testing.expectEqual(bytes.len, decoded.len + @as(usize, @intCast(decoded.value)));
    }
}

test "KAT: hopframe.shiftSize on the 5 official hop payload lengths (51, 115, 51, 51, 307)" {
    try testing.expectEqual(@as(usize, 51), sphinx.hopframe.shiftSize(18));
    try testing.expectEqual(@as(usize, 115), sphinx.hopframe.shiftSize(82));
    try testing.expectEqual(@as(usize, 51), sphinx.hopframe.shiftSize(18));
    try testing.expectEqual(@as(usize, 51), sphinx.hopframe.shiftSize(18));
    try testing.expectEqual(@as(usize, 307), sphinx.hopframe.shiftSize(272));
    // Sum of all 5 shift sizes must fit within the 1300-byte hop_payloads
    // budget (with room for filler) -- a real invariant the official
    // 5-hop route satisfies.
    const total = 51 + 115 + 51 + 51 + 307;
    try testing.expect(total <= sphinx.hop_payloads_len);
}

test "KAT: generateKey('rho'/'mu', ss_0) are well-formed and distinct" {
    const ss0 = hexN(32, v.shared_secrets[0]);
    const rho = sphinx.generateKey(.rho, ss0);
    const mu = sphinx.generateKey(.mu, ss0);
    try testing.expect(!std.mem.eql(u8, &rho, &mu));

    // std-only recomputation, proving generateKey's HMAC-key/message
    // argument order matches BOLT#4 "Key Generation" exactly (key-type
    // label as the HMAC KEY, shared secret as the MESSAGE).
    var expected_rho: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&expected_rho, &ss0, "rho");
    try testing.expectEqualSlices(u8, &expected_rho, &rho);
}

// ── crypto-core KAT tests (the official-vector oracles) ──────────────────

/// The 5 hop pubkeys, decoded to their fixed 33-byte wire form.
fn katPubkeys() [5][sphinx.pubkey_len]u8 {
    var out: [5][sphinx.pubkey_len]u8 = undefined;
    inline for (v.pubkeys, 0..) |hex, i| out[i] = hexN(sphinx.pubkey_len, hex);
    return out;
}

/// Decode the 5 hop payloads into `storage` and strip each one's own
/// bigsize length prefix: `construct` takes the raw TLV content (its
/// `hopframe.writeHopFrame` re-adds the prefix), while the fixture's
/// `payloads[i]` is `bigsize(len) ++ tlv` (see kat_vectors.zig).
fn katPayloadTlvs(storage: *[5][300]u8) ![5][]const u8 {
    var out: [5][]const u8 = undefined;
    inline for (v.payloads, 0..) |hex, i| {
        const bytes = hexInto(&storage[i], hex);
        const len_field = try sphinx.bigsize.read(bytes);
        try testing.expectEqual(bytes.len - len_field.len, @as(usize, @intCast(len_field.value)));
        out[i] = bytes[len_field.len..];
    }
    return out;
}

test "KAT: deriveHopSecrets(session_key, pubkeys) equals kat_vectors.shared_secrets[0..5]" {
    const hop_pubkeys = katPubkeys();
    var out: [5]sphinx.HopSecret = undefined;
    try sphinx.deriveHopSecrets(hexN(32, v.session_key), &hop_pubkeys, &out);
    inline for (v.shared_secrets, 0..) |expected_hex, i| {
        try testing.expectEqualSlices(u8, &hexN(32, expected_hex), &out[i].shared_secret);
    }
    // Fixture coincidence (documented in kat_vectors.zig): session_key ==
    // node_privkeys[0], so epk_0 = session_key * G == pubkeys[0]. The later
    // hops' epk_i are blinded and equal none of the node pubkeys.
    try testing.expectEqualSlices(u8, &hop_pubkeys[0], &out[0].ephemeral_pubkey);
    try testing.expect(!std.mem.eql(u8, &hop_pubkeys[1], &out[1].ephemeral_pubkey));
}

test "KAT: construct(...) equals kat_vectors.onion byte-exact" {
    const hop_pubkeys = katPubkeys();
    var storage: [5][300]u8 = undefined;
    const tlvs = try katPayloadTlvs(&storage);
    const associated_data = hexN(32, v.associated_data);

    const pkt = try sphinx.construct(hexN(32, v.session_key), &hop_pubkeys, &tlvs, &associated_data);
    try testing.expectEqualSlices(u8, &hexN(sphinx.packet_len, v.onion), &pkt.toBytes());
}

test "KAT: process(node_privkeys[0], onion, associated_data) extracts payloads[0]'s TLV content" {
    const pkt = try sphinx.OnionPacket.fromBytes(hexN(sphinx.packet_len, v.onion));
    const associated_data = hexN(32, v.associated_data);
    const result = try sphinx.process(hexN(32, v.node_privkeys[0]), pkt, &associated_data);

    // payloads[0] is bigsize(18) ++ 18-byte TLV; process returns the TLV.
    var storage: [5][300]u8 = undefined;
    const tlvs = try katPayloadTlvs(&storage);
    try testing.expectEqualSlices(u8, tlvs[0], result.payload());
    try testing.expect(result.next_packet != null); // hop 0 of 5 is not the final hop
}

test "KAT: full construct -> process round-trip peels all 5 hops" {
    const hop_pubkeys = katPubkeys();
    var storage: [5][300]u8 = undefined;
    const tlvs = try katPayloadTlvs(&storage);
    const associated_data = hexN(32, v.associated_data);

    var pkt = try sphinx.construct(hexN(32, v.session_key), &hop_pubkeys, &tlvs, &associated_data);
    inline for (v.node_privkeys, 0..) |privkey_hex, i| {
        const result = try sphinx.process(hexN(32, privkey_hex), pkt, &associated_data);
        try testing.expectEqualSlices(u8, tlvs[i], result.payload());
        if (i + 1 < v.node_privkeys.len) {
            try testing.expect(result.next_packet != null);
            pkt = result.next_packet.?;
            // Each forwarded packet is a well-formed wire packet in its own
            // right (version 0, on-curve blinded pubkey).
            _ = try sphinx.OnionPacket.fromBytes(pkt.toBytes());
        } else {
            try testing.expect(result.next_packet == null); // final hop
        }
    }
}

test "KAT: a 1-bit hmac tamper on the official onion is IntegrityCheckFailed" {
    var pkt = try sphinx.OnionPacket.fromBytes(hexN(sphinx.packet_len, v.onion));
    pkt.hmac[0] ^= 0x01;
    const associated_data = hexN(32, v.associated_data);
    try testing.expectError(
        error.IntegrityCheckFailed,
        sphinx.process(hexN(32, v.node_privkeys[0]), pkt, &associated_data),
    );

    // Same for the wrong node key: not the intended recipient -> fail closed.
    const good = try sphinx.OnionPacket.fromBytes(hexN(sphinx.packet_len, v.onion));
    try testing.expectError(
        error.IntegrityCheckFailed,
        sphinx.process(hexN(32, v.node_privkeys[1]), good, &associated_data),
    );
}

test "KAT: a hop_payloads tamper that would decode to a RESERVED bigsize length is STILL IntegrityCheckFailed, not a parse error (MAC-before-decrypt ordering)" {
    // process()'s doc comment/step 2-4 comment is explicit: the HMAC MUST
    // be checked "BEFORE touching hop_payloads' content in any
    // data-dependent way." The existing hmac-tamper test only flips a bit
    // in the `hmac` FIELD itself, leaving `hop_payloads` untouched — the
    // deobfuscated plaintext still parses structurally fine regardless of
    // check order, so that test can't distinguish "checked first" from
    // "checked last, parsed fine anyway, rejected at the end instead".
    //
    // This test computes the REAL rho keystream for hop 0 (from the
    // published `shared_secrets[0]`, exactly `generateKey(.rho, ss)` —
    // `core.zig`'s own step 5) and picks a `hop_payloads[0]` byte whose
    // DEOBFUSCATED value is `1` — a "reserved" bigsize length
    // (`hopframe.readHopFrame` rejects any length `< 2`). If the HMAC
    // check ever moved to run AFTER deobfuscation/parsing (the exact bug
    // class this guards against), this input would surface
    // `error.ReservedPayloadLength` instead of `error.IntegrityCheckFailed`
    // — a live parse-error oracle over the tampered ciphertext, reached
    // before the integrity check ever ran.
    const ss0 = hexN(32, v.shared_secrets[0]);
    const rho = sphinx.generateKey(.rho, ss0);
    var stream_byte: [1]u8 = undefined;
    sphinx.generateCipherStream(rho, &stream_byte);

    var pkt = try sphinx.OnionPacket.fromBytes(hexN(sphinx.packet_len, v.onion));
    pkt.hop_payloads[0] = stream_byte[0] ^ 1; // deobfuscates to exactly 1
    const associated_data = hexN(32, v.associated_data);
    try testing.expectError(
        error.IntegrityCheckFailed,
        sphinx.process(hexN(32, v.node_privkeys[0]), pkt, &associated_data),
    );
}
