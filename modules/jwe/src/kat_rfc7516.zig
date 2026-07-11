// SPDX-License-Identifier: MIT

//! jwe.kat_rfc7516 — the two RFC 7516 Appendix A worked, full-compact-token
//! examples, transcribed verbatim from the RFC text.
//!
//! - **A.1** (RSA-OAEP + A256GCM): both `alg` (RSA-OAEP, SHA-1) and `enc`
//!   (A256GCM) are REAL in this module, so this test runs for real — but
//!   only the DECRYPT direction, since RSA-OAEP encryption is randomized
//!   (a fresh OAEP seed each time means re-encrypting never reproduces the
//!   RFC's exact ciphertext bytes; the RFC says as much in its own §A.1.8).
//! - **A.3** (A128KW + A128CBC-HS256): everything here is deterministic
//!   (RFC §A.3.8 notes both AES Key Wrap and the CBC-HMAC construction are
//!   deterministic given these inputs), so this asserts byte-exact in BOTH
//!   directions — decrypt recovers the exact plaintext, and encrypt (with
//!   the RFC's CEK + IV pinned through a fixed-stream `random`) reproduces
//!   the RFC's exact compact token.

const std = @import("std");
const rsa = @import("rsa");
const root = @import("root.zig");

// RFC 7516 §A.1 — RSAES-OAEP (SHA-1) key wrap + A256GCM content encryption.
// Plaintext: "The true sign of intelligence is not knowledge but
// imagination."
test "RFC 7516 A.1: RSA-OAEP + A256GCM — decrypt direction, byte-exact plaintext" {
    // JWK n/e/p/q from §A.1.3 (2048-bit RSA key), base64url, line breaks
    // removed. `rsa.SecretKey.fromPrimes` re-derives d/dP/dQ/qInv itself —
    // only p, q, e are needed.
    const p_b64 = "1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-" ++
        "SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf" ++
        "fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0";
    const q_b64 = "wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm" ++
        "UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX" ++
        "IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc";
    const e_b64 = "AQAB";

    const dec = std.base64.url_safe_no_pad.Decoder;
    var p_buf: [150]u8 = undefined;
    var q_buf: [150]u8 = undefined;
    var e_buf: [8]u8 = undefined;
    const p = p_buf[0..try dec.calcSizeForSlice(p_b64)];
    try dec.decode(p, p_b64);
    const q = q_buf[0..try dec.calcSizeForSlice(q_b64)];
    try dec.decode(q, q_b64);
    const e = e_buf[0..try dec.calcSizeForSlice(e_b64)];
    try dec.decode(e, e_b64);

    const sk = try rsa.SecretKey.fromPrimes(p, q, e);

    // The full compact token from §A.1.7, line breaks removed.
    const token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ." ++
        "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe" ++
        "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb" ++
        "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV" ++
        "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8" ++
        "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi" ++
        "6UklfCpIMfIjf7iGdXKHzg." ++
        "48V1_ALb6US04U3b." ++
        "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji" ++
        "SdiwkIr3ajwQzaBtQD_A." ++
        "XFBoMYUZodetZdvTiFvSkQ";

    const plaintext = try root.decryptCompact(std.testing.allocator, .{ .rsa_private = sk }, token, .{
        .expect_alg = .@"RSA-OAEP",
        .expect_enc = .A256GCM,
    });
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings(
        "The true sign of intelligence is not knowledge but imagination.",
        plaintext,
    );
}

// RFC 7516 §A.3 — A128KW key wrap + A128CBC-HS256 content encryption.
// Plaintext: "Live long and prosper." Both halves (`aeskw`, `enc.cbc_hmac`)
// are deterministic given the published CEK + IV (the RFC says as much in
// its own §A.3.8), so unlike A.1 this asserts BOTH directions byte-exact —
// the integration proof that the two careful cores compose correctly through
// `root.zig`'s dispatch.
test "RFC 7516 A.3: A128KW + A128CBC-HS256 — byte-exact, both directions" {
    // Shared KEK (JWK oct, §A.3.3): base64url "GawgguFyGrWKav7AX4VKUg".
    const kek_b64 = "GawgguFyGrWKav7AX4VKUg";
    var kek: [16]u8 = undefined;
    try std.base64.url_safe_no_pad.Decoder.decode(&kek, kek_b64);
    // CEK (256-bit, §A.3.2): MAC_KEY = first 16 bytes, ENC_KEY = last 16.
    const cek = [_]u8{
        4,   211, 31,  197, 84,  157, 252, 254, 11,  100, 157, 250, 63,  170, 106, 206,
        107, 124, 212, 45,  111, 107, 9,   219, 200, 177, 0,   240, 143, 156, 44,  207,
    };
    // JWE Encrypted Key (§A.3.3): AES128-KW-wrapped CEK under the KEK above.
    const encrypted_key = [_]u8{
        232, 160, 123, 211, 183, 76,  245, 132, 200, 128, 123, 75,
        190, 216, 22,  67,  201, 138, 193, 186, 9,   91,  122, 31,
        246, 90,  28,  139, 57,  3,   76,  124, 193, 11,  98,  37,
        173, 61,  104, 57,
    };
    // JWE Initialization Vector (§A.3.4).
    const iv = [_]u8{ 3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101 };
    // The full compact token from §A.3.7, line breaks removed.
    const token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." ++
        "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." ++
        "AxY8DCtDaGlsbGljb3RoZQ." ++
        "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." ++
        "U0m_YmjN04DJvceFICbCVQ";

    // Decrypt direction: the full token must authenticate and recover the
    // exact plaintext.
    const plaintext = try root.decryptCompact(std.testing.allocator, .{ .symmetric = &kek }, token, .{
        .expect_alg = .A128KW,
        .expect_enc = .@"A128CBC-HS256",
    });
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("Live long and prosper.", plaintext);

    // The key wrap itself, byte-exact against §A.3.3's Encrypted Key.
    var ek_buf: [40]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &encrypted_key, try root.aeskw.wrap(&kek, &cek, &ek_buf));

    // Encrypt direction: `encryptCompact` draws the CEK first, then the
    // content IV, from its `random` — feed it the RFC's exact CEK ‖ IV via a
    // fixed byte stream and the whole token must reproduce byte-exact
    // (deterministic per §A.3.8; the header JSON this module writes is
    // byte-identical to §A.3.1's).
    var fixed = FixedStream{ .data = &(cek ++ iv) };
    const re_encrypted = try root.encryptCompact(
        std.testing.allocator,
        .A128KW,
        .@"A128CBC-HS256",
        .{ .symmetric = &kek },
        "Live long and prosper.",
        "",
        std.Random.init(&fixed, FixedStream.fill),
        .{},
    );
    defer std.testing.allocator.free(re_encrypted);
    try std.testing.expectEqualStrings(token, re_encrypted);
}

/// Test-only "random" that replays a fixed byte stream — how the A.3 encrypt
/// direction pins the RFC's published CEK and IV. Never a pattern for
/// production callers (encryptCompact's `random` MUST be a real CSPRNG).
const FixedStream = struct {
    data: []const u8,
    pos: usize = 0,

    fn fill(self: *FixedStream, buf: []u8) void {
        std.debug.assert(self.pos + buf.len <= self.data.len);
        @memcpy(buf, self.data[self.pos..][0..buf.len]);
        self.pos += buf.len;
    }
};
