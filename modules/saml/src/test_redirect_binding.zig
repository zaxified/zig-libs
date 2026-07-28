// SPDX-License-Identifier: MIT
//! HTTP-Redirect binding: `encodeRedirectField` (the outbound half of the
//! existing `decodeRedirectField`) and the query-string signing scheme
//! (`buildSignedRedirectQuery` / `verifyRedirectSignature`, SAML Bindings
//! §3.4.4.1). This mechanism did not exist in this module before — unlike the
//! enveloped-XML-signature primitive `test_sign.zig`/`test_slo.zig` build on
//! (already anchored via `test_fixture.zig`'s openssl/lxml fixture), NOTHING
//! here was previously anchored against anything.
//!
//! So this file carries the genuine EXTERNAL anchor: `signingInputIsOpensslVerifiable`
//! below is a fixed SigningInput string, signed OFFLINE with `openssl dgst
//! -sha256 -sign` under a freshly generated 2048-bit test key (never used
//! anywhere else, private key discarded — only the public key and the
//! resulting signature are embedded here), independently confirmed with
//! `openssl dgst -sha256 -verify` before being pasted in. A green
//! `verifyRedirectSignature` against that fixed signature is real
//! cross-implementation interop for the percent-encoding + SigningInput
//! construction + RSA-SHA256/PKCS1v15 verification path — not a self
//! round-trip. Every OTHER test in this file is explicitly labeled
//! CONSTRUCTED/self-round-trip: this module's own signer feeds this module's
//! own verifier.

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const rsa = @import("rsa");

// ── encodeRedirectField / decodeRedirectField: self round-trip ─────────────

test "encodeRedirectField <-> decodeRedirectField: self round-trip" {
    const alloc = testing.allocator;
    const xml_bytes = "<samlp:LogoutRequest ID=\"_r1\">hello & <world/></samlp:LogoutRequest>";
    const field = try saml.encodeRedirectField(alloc, xml_bytes);
    defer alloc.free(field);
    // Not just base64-of-plaintext: DEFLATE actually ran.
    try testing.expect(!std.mem.eql(u8, field, xml_bytes));

    const back = try saml.decodeRedirectField(alloc, field);
    defer alloc.free(back);
    try testing.expectEqualStrings(xml_bytes, back);
}

// ── buildSignedRedirectQuery / verifyRedirectSignature: CONSTRUCTED (self) ──

fn makeKey(seed: u64) !rsa.KeyPair {
    var prng = std.Random.DefaultPrng.init(seed);
    return rsa.generate(prng.random(), 1024, 65537);
}

test "buildSignedRedirectQuery -> verifyRedirectSignature round-trips (CONSTRUCTED, self-signed)" {
    const alloc = testing.allocator;
    const kp = try makeKey(0x2ED1_0001);

    const field = try saml.encodeRedirectField(alloc, "<samlp:LogoutRequest ID=\"_r2\"/>");
    defer alloc.free(field);

    const query = try saml.buildSignedRedirectQuery(alloc, .{
        .kind = .request,
        .message_field = field,
        .relay_state = "opaque-state-123",
        .key = .{ .rsa = kp.secret_key },
    });
    defer alloc.free(query);

    try testing.expect(std.mem.startsWith(u8, query, "SAMLRequest="));
    try testing.expect(std.mem.indexOf(u8, query, "&RelayState=") != null);
    try testing.expect(std.mem.indexOf(u8, query, "&SigAlg=") != null);
    try testing.expect(std.mem.indexOf(u8, query, "&Signature=") != null);

    // Parse the (already-URL-encoded) query string apart ourselves to feed
    // verifyRedirectSignature the URL-DECODED values it expects — none of our
    // test values contain characters that get percent-encoded EXCEPT inside
    // `field`/`sig_alg`/the signature, so a literal split + our own decode is
    // enough here without pulling in a URL-decoder dependency.
    const parts = try splitQuery(alloc, query);
    defer parts.deinit(alloc);

    const ok = try saml.verifyRedirectSignature(alloc, .{
        .kind = .request,
        .message_field = parts.saml_request.?,
        .relay_state = parts.relay_state,
        .sig_alg = parts.sig_alg.?,
        .signature_b64 = parts.signature.?,
        .key = kp.public_key,
    });
    try testing.expect(ok);
}

test "verifyRedirectSignature: flipped signature byte -> false (not an error)" {
    const alloc = testing.allocator;
    const kp = try makeKey(0x2ED1_0002);
    const field = try saml.encodeRedirectField(alloc, "<samlp:LogoutRequest ID=\"_r3\"/>");
    defer alloc.free(field);
    const query = try saml.buildSignedRedirectQuery(alloc, .{
        .kind = .request,
        .message_field = field,
        .key = .{ .rsa = kp.secret_key },
    });
    defer alloc.free(query);
    var parts = try splitQuery(alloc, query);
    defer parts.deinit(alloc);

    // Flip one byte of the (still base64-valid-shaped) signature.
    const sig = parts.signature.?;
    sig[0] = if (sig[0] == 'A') 'B' else 'A';

    const ok = try saml.verifyRedirectSignature(alloc, .{
        .kind = .request,
        .message_field = parts.saml_request.?,
        .relay_state = parts.relay_state,
        .sig_alg = parts.sig_alg.?,
        .signature_b64 = sig,
        .key = kp.public_key,
    });
    try testing.expect(!ok);
}

test "verifyRedirectSignature: wrong key -> false" {
    const alloc = testing.allocator;
    const kp = try makeKey(0x2ED1_0003);
    const other = try makeKey(0x2ED1_0004);
    const field = try saml.encodeRedirectField(alloc, "<samlp:LogoutRequest ID=\"_r4\"/>");
    defer alloc.free(field);
    const query = try saml.buildSignedRedirectQuery(alloc, .{
        .kind = .request,
        .message_field = field,
        .key = .{ .rsa = kp.secret_key },
    });
    defer alloc.free(query);
    const parts = try splitQuery(alloc, query);
    defer parts.deinit(alloc);

    const ok = try saml.verifyRedirectSignature(alloc, .{
        .kind = .request,
        .message_field = parts.saml_request.?,
        .relay_state = parts.relay_state,
        .sig_alg = parts.sig_alg.?,
        .signature_b64 = parts.signature.?,
        .key = other.public_key, // WRONG key
    });
    try testing.expect(!ok);
}

test "verifyRedirectSignature: message tampered after signing -> false" {
    const alloc = testing.allocator;
    const kp = try makeKey(0x2ED1_0005);
    const field = try saml.encodeRedirectField(alloc, "<samlp:LogoutRequest ID=\"_r5\"/>");
    defer alloc.free(field);
    const query = try saml.buildSignedRedirectQuery(alloc, .{
        .kind = .request,
        .message_field = field,
        .key = .{ .rsa = kp.secret_key },
    });
    defer alloc.free(query);
    const parts = try splitQuery(alloc, query);
    defer parts.deinit(alloc);

    const tampered_field = try alloc.dupe(u8, parts.saml_request.?);
    defer alloc.free(tampered_field);
    tampered_field[0] = if (tampered_field[0] == 'A') 'B' else 'A';

    const ok = try saml.verifyRedirectSignature(alloc, .{
        .kind = .request,
        .message_field = tampered_field, // TAMPERED after signing
        .relay_state = parts.relay_state,
        .sig_alg = parts.sig_alg.?,
        .signature_b64 = parts.signature.?,
        .key = kp.public_key,
    });
    try testing.expect(!ok);
}

test "verifyRedirectSignature: unsupported SigAlg rejected with a typed error" {
    const alloc = testing.allocator;
    const kp = try makeKey(0x2ED1_0006);
    try testing.expectError(error.UnsupportedAlgorithm, saml.verifyRedirectSignature(alloc, .{
        .kind = .request,
        .message_field = "AAAA",
        .sig_alg = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        .signature_b64 = "AAAA",
        .key = kp.public_key,
    }));
}

// ── EXTERNAL anchor: openssl-signed SigningInput, independently confirmed ──
//
// Generated once, offline (not reproduced at test time):
//   openssl genrsa -out priv.pem 2048
//   openssl rsa -in priv.pem -pubout -out pub.pem
//   printf '%s' "$SIGNING_INPUT" > signing_input.txt   # see below, byte-exact
//   openssl dgst -sha256 -sign priv.pem -out sig.bin signing_input.txt
//   openssl dgst -sha256 -verify pub.pem -signature sig.bin signing_input.txt
//     => "Verified OK"
//   base64 -w0 sig.bin
//
// $SIGNING_INPUT (120 bytes, exactly what `verifyRedirectSignature` must
// reconstruct from the three URL-DECODED field values below):
//   SAMLRequest=AB%2BC%2FD%3D%3D&RelayState=a%20b%26c&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256
//
// i.e. message_field = "AB+C/D==" (exercises +, /, = percent-encoding),
// relay_state = "a b&c" (exercises space and &), sig_alg = the real
// RSA-SHA256 URI (exercises :, /, #). The private key was discarded after
// signing; only the public key and the resulting signature are used here.
const openssl_pub_pem =
    \\-----BEGIN PUBLIC KEY-----
    \\MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuZaOnke6JRwtsaY9I3a6
    \\1H+roWujzmHiNpdoZrvtqJLwseqS1dmUg8rjwQN+i+7GKXYBVVGVVDid5ntzRTKL
    \\4Z4+ebvGITwqoKBhUx9sLht83ujqJnP/jrQ73mX2LnKP36wleKmwEatQF6LPMFcu
    \\G+zj0kj51Q5uN3bgQ9h7SLjF0Is7OeggJHlPo6I4UfFjZpBgLiB/DLMfgzcuwFso
    \\uUszIMjUn8mk2OpX1fNKfFzSoSXvSKDS0hxw6/fRijpWkWyoRWJQPtuz3g6YI34g
    \\I8cyMP1F9uTQARxirBntUAWvgYCfm7Fdmy7GiMUyDAhM96uxXVzIXUa3nPBPdtVF
    \\LQIDAQAB
    \\-----END PUBLIC KEY-----
;
const openssl_sig_b64 = "msaNOsnUbytt7o09ebxRFmT72hmTXN5vqEnKrxfPqU3L5gO5UDY7M4FrkNJ16NIxXO+/6ojvA/d7pCusnmOYkVVWqPwnQnCMdxijGcOk479YEMHD8GRkwgCL/Eebion2Eyk/1bSQNHn/oH3qWPmOPHZCLJ62/iemmtKNQd02uEMBy7WxzMOo0HkFh1pjvMnmt78VKOGnBjl8XsVFkEMFXki8pNXaCsqxDB+y50e76DgTAqvXSvXOrtYM2vK72vZra66d9MTK9K/39FTD4RcmEVsD6bdvcAu1cIis7U425/1yxDJihbKlNwTYRUoP5yx3IGDfZQ0bI4zs9ttf52bo/w==";

test "verifyRedirectSignature: EXTERNAL anchor — openssl-signed SigningInput verifies" {
    const alloc = testing.allocator;
    const pk = try rsa.PublicKey.fromPem(openssl_pub_pem);

    const ok = try saml.verifyRedirectSignature(alloc, .{
        .kind = .request,
        .message_field = "AB+C/D==",
        .relay_state = "a b&c",
        .sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        .signature_b64 = openssl_sig_b64,
        .key = pk,
    });
    try testing.expect(ok);
}

test "verifyRedirectSignature: EXTERNAL anchor tamper — one flipped RelayState byte fails the SAME signature" {
    // Proves the anchor is actually exercising the message content (not just
    // checking that SOME signature-shaped blob parses): the openssl signature
    // was computed over relay_state="a b&c" specifically.
    const alloc = testing.allocator;
    const pk = try rsa.PublicKey.fromPem(openssl_pub_pem);
    const ok = try saml.verifyRedirectSignature(alloc, .{
        .kind = .request,
        .message_field = "AB+C/D==",
        .relay_state = "a b&d", // last char changed: c -> d
        .sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        .signature_b64 = openssl_sig_b64,
        .key = pk,
    });
    try testing.expect(!ok);
}

// ── End-to-end: LogoutRequest fully round-tripped over the Redirect binding
//    (encode + sign the query string, decode + verify + consume) ───────────

test "LogoutRequest end-to-end over the Redirect binding (self round-trip)" {
    const alloc = testing.allocator;
    const kp = try makeKey(0x2ED1_0007);

    const unsigned_req = try saml.buildLogoutRequest(alloc, .{
        .id = "_lr_redirect_01",
        .issue_instant = "2024-06-01T12:00:00Z",
        .issuer = "https://idp.example.org/saml",
        .name_id = "alice@example.org",
        // sign_with left null: Redirect binding signs the QUERY, not the XML.
    });
    defer alloc.free(unsigned_req);

    const field = try saml.encodeRedirectField(alloc, unsigned_req);
    defer alloc.free(field);
    const query = try saml.buildSignedRedirectQuery(alloc, .{
        .kind = .request,
        .message_field = field,
        .relay_state = "post-logout-redirect",
        .key = .{ .rsa = kp.secret_key },
    });
    defer alloc.free(query);

    // "Send over the wire": split the query, URL-decode (none of our chars
    // need real decoding beyond what splitQuery already does), verify.
    const parts = try splitQuery(alloc, query);
    defer parts.deinit(alloc);

    const ok = try saml.verifyRedirectSignature(alloc, .{
        .kind = .request,
        .message_field = parts.saml_request.?,
        .relay_state = parts.relay_state,
        .sig_alg = parts.sig_alg.?,
        .signature_b64 = parts.signature.?,
        .key = kp.public_key,
    });
    try testing.expect(ok);

    const recovered_xml = try saml.decodeRedirectField(alloc, parts.saml_request.?);
    defer alloc.free(recovered_xml);

    var res = try saml.consumeLogoutRequestXml(alloc, recovered_xml, .redirect_verified, .{
        .idp_entity_id = "https://idp.example.org/saml",
        .idp_key = .{ .rsa = kp.public_key }, // unused on the .redirect_verified path; here for completeness
        .now_unix = 1717243200 + 5,
    });
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

// ── tiny test-only query splitter/decoder ───────────────────────────────────
// None of the % sequences our own values need are decoded HERE — we split on
// literal '&'/'=' and unescape only the minimal RFC3986 percent-encoding our
// own `appendPercentEncoded` produces, so this exercises the real values
// `buildSignedRedirectQuery` emits without pulling in an HTTP/URL module this
// library doesn't otherwise depend on.
const QueryParts = struct {
    saml_request: ?[]u8 = null,
    relay_state: ?[]u8 = null,
    sig_alg: ?[]u8 = null,
    signature: ?[]u8 = null,

    fn deinit(self: QueryParts, alloc: std.mem.Allocator) void {
        if (self.saml_request) |s| alloc.free(s);
        if (self.relay_state) |s| alloc.free(s);
        if (self.sig_alg) |s| alloc.free(s);
        if (self.signature) |s| alloc.free(s);
    }
};

fn percentDecode(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '%' and i + 2 < s.len) {
            const hi = std.fmt.charToDigit(s[i + 1], 16) catch return error.InvalidEncoding;
            const lo = std.fmt.charToDigit(s[i + 2], 16) catch return error.InvalidEncoding;
            try out.append(alloc, hi << 4 | lo);
            i += 3;
        } else {
            try out.append(alloc, s[i]);
            i += 1;
        }
    }
    return out.toOwnedSlice(alloc);
}

fn splitQuery(alloc: std.mem.Allocator, query: []const u8) !QueryParts {
    var parts: QueryParts = .{};
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=').?;
        const key = kv[0..eq];
        const val = try percentDecode(alloc, kv[eq + 1 ..]);
        if (std.mem.eql(u8, key, "SAMLRequest")) {
            parts.saml_request = val;
        } else if (std.mem.eql(u8, key, "RelayState")) {
            parts.relay_state = val;
        } else if (std.mem.eql(u8, key, "SigAlg")) {
            parts.sig_alg = val;
        } else if (std.mem.eql(u8, key, "Signature")) {
            parts.signature = val;
        } else {
            alloc.free(val);
        }
    }
    return parts;
}
