// SPDX-License-Identifier: MIT

//! quic-crypto.initial — RFC 9001 §5.2 Initial Secrets: the QUIC v1 Initial
//! encryption-level secret derivation, seeded from the client's chosen
//! Destination Connection ID rather than from a TLS handshake secret. This
//! is the ONE encryption level whose secret does not come from the TLS key
//! schedule (§5.1) — every other level's traffic secret is a TLS-derived
//! `Derive-Secret` output the QUIC engine hands to `keyschedule.zig`.
//!
//! **Implemented and KAT-validated** against RFC 9001 Appendix A.1: the
//! `sanity` test drives the published vectors through `std.crypto` directly
//! (independent oracle), and the API test drives the same vectors through
//! `deriveInitialSecrets` byte-exact.

const std = @import("std");
const burn = @import("burn.zig");
const version = @import("version.zig");

pub const Version = version.Version;

/// RFC 9001 §5.2: the fixed QUIC v1 HKDF-Extract salt used to derive the
/// Initial secret from the client's Destination Connection ID. "Future
/// versions of QUIC SHOULD generate a new salt value" — this constant is
/// version-specific (v1), not a QUIC-wide invariant.
pub const initial_salt_v1: [20]u8 = version.initial_salt_v1;

/// RFC 9369 §3.3.1: the fixed QUIC v2 Initial salt.
pub const initial_salt_v2: [20]u8 = version.initial_salt_v2;

/// The two directional secrets §5.2 derives from one Destination Connection
/// ID. Always 32 bytes (SHA-256) — RFC 9001 §5.2: "The hash function for
/// HKDF when deriving initial secrets and keys is SHA-256", fixed
/// regardless of whatever cipher suite TLS eventually negotiates (Initial
/// packets are exchanged before any suite negotiation completes).
pub const InitialSecrets = struct {
    client_initial_secret: [32]u8,
    server_initial_secret: [32]u8,
};

/// RFC 9001 §5.2 pseudocode:
/// ```
/// initial_secret = HKDF-Extract(initial_salt_v1, client_dst_connection_id)
/// client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
/// server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
/// ```
/// `client_dst_connection_id` is the Destination Connection ID field from
/// the client's FIRST Initial packet (0..20 bytes per RFC 9000 §7.2 — zero
/// length is valid, e.g. after a Retry with a zero-length server SCID).
///
/// **Implement via `std.crypto.tls.hkdfExpandLabel` DIRECTLY** —
/// `std.crypto.kdf.hkdf.HkdfSha256.extract(&initial_salt_v1,
/// client_dst_connection_id)` for `initial_secret`, then
/// `std.crypto.tls.hkdfExpandLabel(HkdfSha256, initial_secret, "client in"/
/// "server in", "", 32)`. This is the `tlsresume.psk` thin-wrapper pattern,
/// NOT `dtls.keyschedule`'s forked-label-prefix pattern — RFC 9001 draws no
/// prefix fork the way RFC 9147/DTLS 1.3 does (see root.zig's module doc,
/// "the key finding", and SPEC.md).
pub fn deriveInitialSecrets(out: *InitialSecrets, client_dcid: []const u8) void {
    deriveInitialSecretsFor(.v1, out, client_dcid);
}

/// `deriveInitialSecrets` for an explicit QUIC version: the same §5.2 chain
/// with that version's Initial salt (RFC 9369 §3.3.1 for `.v2`). The
/// `"client in"` / `"server in"` labels are NOT versioned — RFC 9369 §3.3.2
/// changes only the key/iv/hp/ku labels.
pub fn deriveInitialSecretsFor(ver: Version, out: *InitialSecrets, client_dcid: []const u8) void {
    burn.run(burn.kdf_burn, void, deriveInitialSecretsBody, .{ ver, out, client_dcid });
}

fn deriveInitialSecretsBody(ver: Version, out: *InitialSecrets, client_dcid: []const u8) void {
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const initial_secret = Hkdf.extract(ver.initialSalt(), client_dcid);
    out.client_initial_secret = std.crypto.tls.hkdfExpandLabel(Hkdf, initial_secret, "client in", "", 32);
    out.server_initial_secret = std.crypto.tls.hkdfExpandLabel(Hkdf, initial_secret, "server in", "", 32);
}

// ── tests ────────────────────────────────────────────────────────────────
//
// RFC 9001 Appendix A.1 ("Keys") known-answer vectors. The destination
// connection ID (0x8394c8f03e515708) and every hex constant below were
// extracted verbatim from https://www.rfc-editor.org/rfc/rfc9001.txt
// Appendix A.1 and cross-checked against TWO independent oracles before
// being committed here: a from-scratch Python hmac/hashlib HKDF
// reimplementation, and the `cryptography` package (OpenSSL-backed). Both
// reproduced every byte below exactly.

const testing = std.testing;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

fn hexTo(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const client_dst_connection_id = hexTo(8, "8394c8f03e515708");
const rfc_initial_secret = hexTo(32, "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
const rfc_client_initial_secret = hexTo(32, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
const rfc_server_initial_secret = hexTo(32, "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");

test "sanity: RFC 9001 App. A.1 initial-secret chain matches std.crypto directly" {
    const initial_secret = HkdfSha256.extract(&initial_salt_v1, &client_dst_connection_id);
    try testing.expectEqualSlices(u8, &rfc_initial_secret, &initial_secret);

    const client_initial_secret = std.crypto.tls.hkdfExpandLabel(HkdfSha256, initial_secret, "client in", "", 32);
    try testing.expectEqualSlices(u8, &rfc_client_initial_secret, &client_initial_secret);

    const server_initial_secret = std.crypto.tls.hkdfExpandLabel(HkdfSha256, initial_secret, "server in", "", 32);
    try testing.expectEqualSlices(u8, &rfc_server_initial_secret, &server_initial_secret);
}

test "initial_salt_v1 constant is the exact 20-byte RFC 9001 §5.2 value" {
    try testing.expectEqualSlices(u8, &hexTo(20, "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), &initial_salt_v1);
}

test "deriveInitialSecrets: App. A.1 client + server initial secrets" {
    var s: InitialSecrets = undefined;
    deriveInitialSecrets(&s, &client_dst_connection_id);
    try testing.expectEqualSlices(u8, &rfc_client_initial_secret, &s.client_initial_secret);
    try testing.expectEqualSlices(u8, &rfc_server_initial_secret, &s.server_initial_secret);
}

// RFC 9369 Appendix A.1 (p. 8-9 of the RFC text): the same DCID under the v2
// salt. Values copied from https://www.rfc-editor.org/rfc/rfc9369.txt.
test "deriveInitialSecretsFor(.v2): RFC 9369 App. A.1 initial secrets" {
    const initial_secret = HkdfSha256.extract(&initial_salt_v2, &client_dst_connection_id);
    try testing.expectEqualSlices(u8, &hexTo(32, "2062e8b3cd8d52092614b8071d0aa1fb7c2e3ac193f78b280e72d8f5751f6aba"), &initial_secret);
    var s: InitialSecrets = undefined;
    deriveInitialSecretsFor(.v2, &s, &client_dst_connection_id);
    try testing.expectEqualSlices(u8, &hexTo(32, "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b"), &s.client_initial_secret);
    try testing.expectEqualSlices(u8, &hexTo(32, "0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1"), &s.server_initial_secret);
}

test "deriveInitialSecretsFor(.v1) is deriveInitialSecrets; v1 and v2 differ" {
    var a: InitialSecrets = undefined;
    var b: InitialSecrets = undefined;
    deriveInitialSecrets(&a, &client_dst_connection_id);
    deriveInitialSecretsFor(.v1, &b, &client_dst_connection_id);
    try testing.expectEqualSlices(u8, &a.client_initial_secret, &b.client_initial_secret);
    try testing.expectEqualSlices(u8, &a.server_initial_secret, &b.server_initial_secret);
    var c: InitialSecrets = undefined;
    deriveInitialSecretsFor(.v2, &c, &client_dst_connection_id);
    try testing.expect(!std.mem.eql(u8, &a.client_initial_secret, &c.client_initial_secret));
}
