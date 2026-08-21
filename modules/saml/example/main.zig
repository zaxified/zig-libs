// SPDX-License-Identifier: MIT

//! What a Service Provider does with `saml` on the two ends of a Web
//! Browser SSO round trip: build the outgoing `<samlp:AuthnRequest>` for
//! SP-initiated login, then — at the Assertion Consumer Service endpoint —
//! refuse anything that isn't a genuine, correctly-shaped `<samlp:Response>`
//! from the configured IdP, by name, before any signature is even reached.
//!
//! A full positive `consumeResponse` round trip needs a `<samlp:Response>`
//! actually signed by the configured `idp_key` — this module's own tests
//! get that from an independent toolchain (openssl + libxml2; see
//! SPEC.md's fixture provenance), which is out of reach for a self-
//! contained example file. What a consumer CAN and MUST get right without
//! that toolchain is everything shown here: building the request, and
//! rejecting a malformed or wrong-shaped callback cleanly. See `xmldsig`'s
//! own example/tests for signature verification exercised directly.
//!
//! Built against the PUBLISHED module (`@import("saml")`) only — no
//! `test_deps`, no filesystem, no network.

const std = @import("std");
const saml = @import("saml");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── SP-initiated SSO: build the AuthnRequest ────────────────────────
    // The caller generates the ID (and remembers it as
    // `expected_in_response_to` for when the Response comes back) and the
    // timestamp — the module has no RNG and never reads the clock.
    const request_id = "_a9f3c2e1b4d5f6071829384756abcdef0";
    const xml = try saml.buildAuthnRequest(gpa, .{
        .id = request_id,
        .issue_instant = "2024-06-01T12:00:00Z",
        .issuer = "https://sp.example.org/metadata",
        .acs_url = "https://sp.example.org/acs",
        .destination = "https://idp.example.org/sso",
        .name_id_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    });
    defer gpa.free(xml);
    std.debug.print("built AuthnRequest ({d} bytes), id={s}\n", .{ xml.len, request_id });

    // The SP is configured with the IdP's signing key out-of-band, from
    // metadata pinned ahead of time — never learned from an incoming
    // <KeyInfo>. A placeholder here since no signature is ever reached in
    // the rejection paths below.
    const idp_key: saml.VerifyKey = .{ .ecdsa_p256_sec1 = &([_]u8{0} ** 33) };

    const config: saml.Config = .{
        .idp_entity_id = "https://idp.example.org/saml",
        .idp_key = idp_key,
        .sp_entity_id = "https://sp.example.org/metadata",
        .acs_url = "https://sp.example.org/acs",
        .now_unix = 1_717_243_200, // 2024-06-01T12:00:00Z
        .expected_in_response_to = request_id,
    };

    // ── reject: well-formed XML, wrong document shape ───────────────────
    // A response whose root element isn't <samlp:Response> at all — the
    // shape a broken IdP integration or a probe against the ACS endpoint
    // produces. Refused before signature or status is even looked at.
    const wrong_root = "<foo xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>";
    consumeAcs(gpa, wrong_root, config) catch |err| switch (err) {
        error.NotSamlResponse => std.debug.print("rejected: NotSamlResponse (wrong root element)\n", .{}),
        else => return err,
    };

    // ── reject: not XML at all ───────────────────────────────────────────
    // The XSW/XXE-hardened parse fails closed on garbage input rather than
    // panicking or guessing at intent.
    consumeAcs(gpa, "this is not xml <<<", config) catch |err| switch (err) {
        error.MalformedResponse => std.debug.print("rejected: MalformedResponse (not well-formed XML)\n", .{}),
        else => return err,
    };

    // ── reject: well-formed Response, no signature ───────────────────────
    // A <samlp:Response> that is shaped right but carries no <ds:Signature>
    // anywhere — the "just trust me" attack. No signature ⇒ rejected, no
    // downgrade, regardless of what the (unsigned) assertion claims.
    const unsigned_response =
        \\<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        \\    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1"
        \\    Version="2.0" IssueInstant="2024-06-01T12:00:00Z">
        \\  <saml:Issuer>https://idp.example.org/saml</saml:Issuer>
        \\  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
        \\  <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2024-06-01T12:00:00Z">
        \\    <saml:Issuer>https://idp.example.org/saml</saml:Issuer>
        \\    <saml:Subject><saml:NameID>alice@example.org</saml:NameID></saml:Subject>
        \\  </saml:Assertion>
        \\</samlp:Response>
    ;
    consumeAcs(gpa, unsigned_response, config) catch |err| switch (err) {
        error.SignatureMissing => std.debug.print("rejected: SignatureMissing (no <ds:Signature> anywhere)\n", .{}),
        else => return err,
    };
}

fn consumeAcs(gpa: std.mem.Allocator, xml_bytes: []const u8, config: saml.Config) !void {
    var result = try saml.consumeResponseXml(gpa, xml_bytes, config);
    defer result.deinit();
    std.log.info("authenticated {s}", .{result.name_id});
}
