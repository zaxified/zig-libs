// SPDX-License-Identifier: MIT
//! Regression tests from the 2026-11-13 no-panic sweep (finding prefix SAML).

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const fx = @import("fixtures.zig");

fn baseConfig(now: i64, skew: i64) saml.Config {
    return .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = fx.idpKey(),
        .sp_entity_id = fx.sp_entity_id,
        .acs_url = fx.acs_url,
        .now_unix = now,
        .clock_skew_secs = skew,
        .expected_in_response_to = fx.request_id,
    };
}

test "consumeResponseXml: a clock at the edge of i64 is a verdict, not an integer overflow (sweep SAML-1)" {
    // `now + skew` / `now - skew` ran on the caller's clock and skew with plain
    // operators: UB in ReleaseFast, a panic in the checked modes. A clock of
    // i64 max (a bad RTC, a fuzzed value, a deliberately hostile test double)
    // is the caller's data, so it must come back as an answer. The signed
    // fixture reaches the `Conditions` bounds.
    try testing.expectError(error.AssertionExpired, saml.consumeResponseXml(testing.allocator, fx.signed_response, baseConfig(std.math.maxInt(i64), 60)));
    // Both extremes at once: whatever the verdict, it is not an overflow.
    if (saml.consumeResponseXml(testing.allocator, fx.signed_response, baseConfig(std.math.maxInt(i64), std.math.maxInt(i64)))) |ok| {
        var r = ok;
        r.deinit();
    } else |_| {}
    // The far-past clock: not yet valid, again without overflow.
    try testing.expectError(error.AssertionNotYetValid, saml.consumeResponseXml(testing.allocator, fx.signed_response, baseConfig(std.math.minInt(i64), 60)));
    // Positive control: the same document at the same moment as the fixture tests.
    var res = try saml.consumeResponseXml(testing.allocator, fx.signed_response, baseConfig(fx.t_valid, 60));
    res.deinit();
}

test "consumeLogoutRequestXml: NotOnOrAfter against an extreme clock does not overflow (sweep SAML-1)" {
    const xml_bytes =
        "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " ++
        "ID=\"_r1\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\" NotOnOrAfter=\"2024-06-01T12:05:00Z\">" ++
        "<saml:Issuer>https://idp.example.org/saml</saml:Issuer><saml:NameID>alice</saml:NameID></samlp:LogoutRequest>";
    const cfg = saml.LogoutRequestConfig{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = fx.idpKey(),
        .now_unix = std.math.minInt(i64) + 1,
        .clock_skew_secs = std.math.maxInt(i64),
    };
    // now - skew would be minInt - ... : saturates, request not yet expired.
    var res = try saml.consumeLogoutRequestXml(testing.allocator, xml_bytes, .redirect_verified, cfg);
    res.deinit();
    var late = cfg;
    late.now_unix = std.math.maxInt(i64);
    late.clock_skew_secs = 0;
    try testing.expectError(error.RequestExpired, saml.consumeLogoutRequestXml(testing.allocator, xml_bytes, .redirect_verified, late));
}

test "consumeResponseXml: a signature whose canonical form explodes is refused, not an OOM (sweep XDS-1 through saml)" {
    // 100 KB `xmlns:p` URI on the Response (which does not use `p`), 8000
    // `<p:c/>` inside the Assertion the signature references with exclusive
    // C14N: ~800 MB of canonical form, pre-authentication, from ~160 KB.
    const a = testing.allocator;
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(a);
    try src.appendSlice(a, "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " ++
        "Version=\"2.0\" xmlns:p=\"urn:");
    try src.appendNTimes(a, 'u', 100_000);
    try src.appendSlice(a, "\"><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" ++
        "<saml:Assertion ID=\"_a\" Version=\"2.0\"><saml:Issuer>https://idp.example.org/saml</saml:Issuer>" ++
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo>" ++
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>" ++
        "<ds:Reference URI=\"#_a\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms>" ++
        "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>" ++
        "</ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>");
    for (0..8000) |_| try src.appendSlice(a, "<p:c/>");
    try src.appendSlice(a, "</saml:Assertion></samlp:Response>");
    try testing.expectError(error.SignatureInvalid, saml.consumeResponseXml(a, src.items, baseConfig(fx.t_valid, 60)));
}
