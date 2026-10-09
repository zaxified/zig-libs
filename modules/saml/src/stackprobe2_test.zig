// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the four consume entry points
//! burned in the 2026-10-09 `check-secret-api` pass: `consumeResponse{,Xml}`
//! with an encrypted assertion (the SP's RSA decryption key is the needle; the
//! decrypted assertion is checked by the residue rule) and
//! `consumeLogoutRequest{,Xml}` with an `EncryptedID`. The older
//! `stackprobe_test.zig` (signing paths) is left as it was. ReleaseFast only.

const std = @import("std");
const rsa = @import("rsa");
const saml = @import("root.zig");
const ext = @import("test_encrypted_external.zig");
const encutil = @import("test_encutil.zig");
const fx = @import("fixtures.zig");
const sp = @import("testkit").stackprobe;

// The burn is 128 KiB; the window must exceed it.
const P = sp.Probe(.{ .window = 256 * 1024 });

const alloc = std.heap.page_allocator; // global-alloc-ok: the probe's file-scope fixtures (keys, encoded responses) outlive the test block and must not come from testing.allocator

var sp_key: rsa.SecretKey = undefined;
var logout_key: rsa.KeyPair = undefined;
var b64_buf: [8192]u8 = undefined;

fn respConfig() saml.Config {
    return .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = fx.idpKey(),
        .sp_entity_id = fx.sp_entity_id,
        .acs_url = fx.acs_url,
        .now_unix = fx.t_valid,
        .expected_in_response_to = fx.request_id,
        .sp_decrypt_key = &sp_key,
    };
}

test "STACKPROBE: saml consume entry points leave no SP key or decrypted-identity residue" {
    // Functional sanity first (every mode): the probed calls must reach the
    // decryption, not stop at a config error.
    sp_key = try ext.spKey();
    {
        var r = try saml.consumeResponseXml(std.testing.allocator, ext.response_with_encrypted_assertion, respConfig());
        r.deinit();
    }
    try sp.skipUnlessOptimized();

    // consumeResponse{,Xml}: the xmlsec1-encrypted assertion fixture.
    sp_key = try ext.spKey();
    const key_bytes = &[_][]const u8{std.mem.asBytes(&sp_key)};
    const xml_resp = ext.response_with_encrypted_assertion;
    _ = try P.run("consumeResponseXml", saml.consumeResponseXml, .{ alloc, xml_resp, respConfig() }, key_bytes, .{});
    const field = std.base64.standard.Encoder.encode(&b64_buf, xml_resp);
    _ = try P.run("consumeResponse", saml.consumeResponse, .{ alloc, field, respConfig() }, key_bytes, .{});

    // consumeLogoutRequest{,Xml}: an EncryptedID NameID (locally generated SP key).
    logout_key = try encutil.makeSpKey(0x5EED_0001);
    const lkey = &[_][]const u8{std.mem.asBytes(&logout_key.secret_key)};
    const name_id = "<saml:NameID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">alice@example.org</saml:NameID>";
    const enc_id = try encutil.encryptedWrapper(alloc, logout_key.public_key, "EncryptedID", name_id);
    const req = try std.fmt.allocPrint(alloc, "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " ++
        "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_lr_probe\" Version=\"2.0\" " ++
        "IssueInstant=\"2024-06-01T12:00:00Z\"><saml:Issuer>{s}</saml:Issuer>{s}</samlp:LogoutRequest>", .{ fx.idp_entity_id, enc_id });
    const lcfg: saml.LogoutRequestConfig = .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = fx.idpKey(),
        .now_unix = 1717243200 + 30,
        .sp_decrypt_key = &logout_key.secret_key,
    };
    {
        var r = try saml.consumeLogoutRequestXml(alloc, req, .redirect_verified, lcfg);
        r.deinit();
    }
    _ = try P.run("consumeLogoutRequestXml", saml.consumeLogoutRequestXml, .{ alloc, req, .redirect_verified, lcfg }, lkey, .{});
    const lfield = std.base64.standard.Encoder.encode(b64_buf[0..], req);
    // POST binding wants an embedded signature, so this one stops at the
    // signature check: the probe sees the burn on the early-error path.
    _ = try P.run("consumeLogoutRequest", saml.consumeLogoutRequest, .{ alloc, lfield, lcfg }, lkey, .{});
}
