// SPDX-License-Identifier: MIT
//! `parseIdpMetadataFor` (`<md:EntitiesDescriptor>` aggregates) and the
//! `mdui:UIInfo` reading of `parseIdpMetadata`.
//!
//! The XML is hand-built in the shapes of SAML Metadata (OASIS saml-metadata-2.0,
//! §2.3.1 EntitiesDescriptor, nested groups, a `ds:Signature` and
//! `md:Extensions` ahead of the children) and of a federation aggregate such as
//! InCommon's (`<md:EntitiesDescriptor Name=... validUntil=...>` holding
//! `md:EntityDescriptor`s, with `mdui:UIInfo` in the IdP's `md:Extensions`) and
//! of the mdui specification's example (`mdui:DisplayName`, `mdui:Description`,
//! `mdui:Logo height width xml:lang`). No external validator was run on them.

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");

const ns_decl =
    " xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"" ++
    " xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"" ++
    " xmlns:mdui=\"urn:oasis:names:tc:SAML:metadata:ui\"";

fn idp(comptime id: []const u8, comptime cert_b64: []const u8, comptime ext: []const u8) []const u8 {
    comptime return "<md:EntityDescriptor entityID=\"" ++ id ++ "\">" ++
        "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">" ++ ext ++
        "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>" ++ cert_b64 ++
        "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>" ++
        "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"" ++ id ++ "/sso\"/>" ++
        "</md:IDPSSODescriptor></md:EntityDescriptor>";
}

fn idpRoot(comptime id: []const u8, comptime cert_b64: []const u8, comptime ext: []const u8) []const u8 {
    comptime return "<md:EntityDescriptor" ++ ns_decl ++ idp(id, cert_b64, ext)["<md:EntityDescriptor".len..];
}

const sp_only = "<md:EntityDescriptor entityID=\"https://sp.example.org/\"><md:SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">" ++
    "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://sp.example.org/acs\" index=\"0\"/>" ++
    "</md:SPSSODescriptor></md:EntityDescriptor>";

const ui_ext =
    "<md:Extensions><mdui:UIInfo>" ++
    "<mdui:DisplayName xml:lang=\"en\">Example University</mdui:DisplayName>" ++
    "<mdui:DisplayName xml:lang=\"cs\">Ukázková univerzita</mdui:DisplayName>" ++
    "<mdui:Description xml:lang=\"en\">\n  Login with your campus account.\n</mdui:Description>" ++
    "<mdui:Logo height=\"60\" width=\"80\" xml:lang=\"en\"> https://idp.example.org/logo.png </mdui:Logo>" ++
    "<mdui:Logo height=\"x\" width=\"80\">https://idp.example.org/bad-height.png</mdui:Logo>" ++
    "<mdui:Logo width=\"80\">https://idp.example.org/no-height.png</mdui:Logo>" ++
    "<mdui:InformationURL xml:lang=\"en\">https://idp.example.org/about</mdui:InformationURL>" ++
    "</mdui:UIInfo></md:Extensions>";

// An InCommon-shaped aggregate: root group with Extensions + Signature, a nested
// group (a sub-federation), a plain SP and three IdPs.
const aggregate =
    "<md:EntitiesDescriptor" ++ ns_decl ++ " Name=\"urn:mace:example:federation\" validUntil=\"2030-01-01T00:00:00Z\">" ++
    "<ds:Signature><ds:SignedInfo/><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>" ++
    "<md:Extensions/>" ++
    sp_only ++
    idp("https://idp1.example.org", "SGVsbG8=", ui_ext) ++
    "<md:EntitiesDescriptor Name=\"sub\">" ++
    idp("https://idp2.example.org", "d29ybGQ=", "") ++
    "<md:EntitiesDescriptor Name=\"subsub\">" ++
    idp("https://idp3.example.org", "Zm9v", "") ++
    "</md:EntitiesDescriptor></md:EntitiesDescriptor></md:EntitiesDescriptor>";

test "aggregate: each entity is selected by entityID, at any nesting level" {
    const a = testing.allocator;
    var m1 = try saml.parseIdpMetadataFor(a, aggregate, "https://idp1.example.org", .{});
    defer m1.deinit();
    try testing.expectEqualStrings("https://idp1.example.org", m1.entity_id);
    try testing.expectEqualStrings("https://idp1.example.org/sso", m1.sso_endpoints[0].location);
    try testing.expectEqualStrings("Hello", m1.signing_certs_der[0]);

    var m2 = try saml.parseIdpMetadataFor(a, aggregate, "https://idp2.example.org", .{});
    defer m2.deinit();
    try testing.expectEqualStrings("world", m2.signing_certs_der[0]);

    var m3 = try saml.parseIdpMetadataFor(a, aggregate, "https://idp3.example.org", .{});
    defer m3.deinit();
    try testing.expectEqualStrings("foo", m3.signing_certs_der[0]);
    try testing.expectEqual(@as(usize, 0), m3.ui_info.display_names.len);
}

test "aggregate: result equals parsing the entity alone" {
    const a = testing.allocator;
    const alone = comptime idpRoot("https://idp2.example.org", "d29ybGQ=", "");
    var x = try saml.parseIdpMetadata(a, alone);
    defer x.deinit();
    var y = try saml.parseIdpMetadataFor(a, aggregate, "https://idp2.example.org", .{});
    defer y.deinit();
    try testing.expectEqualStrings(x.entity_id, y.entity_id);
    try testing.expectEqualStrings(x.signing_certs_der[0], y.signing_certs_der[0]);
    try testing.expectEqualStrings(x.sso_endpoints[0].location, y.sso_endpoints[0].location);
}

test "aggregate: not found, SP-only entity, ambiguous, malformed" {
    const a = testing.allocator;
    try testing.expectError(error.EntityNotFound, saml.parseIdpMetadataFor(a, aggregate, "https://nope.example.org", .{}));
    try testing.expectError(error.NoIdpDescriptor, saml.parseIdpMetadataFor(a, aggregate, "https://sp.example.org/", .{}));

    const dup = comptime "<md:EntitiesDescriptor" ++ ns_decl ++ ">" ++
        idp("https://idp1.example.org", "SGVsbG8=", "") ++
        "<md:EntitiesDescriptor>" ++ idp("https://idp1.example.org", "d29ybGQ=", "") ++ "</md:EntitiesDescriptor>" ++
        "</md:EntitiesDescriptor>";
    try testing.expectError(error.AmbiguousEntity, saml.parseIdpMetadataFor(a, dup, "https://idp1.example.org", .{}));
    // a different id in the same document is still answerable
    var ok = try saml.parseIdpMetadataFor(a, aggregate, "https://idp1.example.org", .{});
    ok.deinit();

    try testing.expectError(error.MalformedMetadata, saml.parseIdpMetadataFor(a, "<not-xml", "x", .{}));
    try testing.expectError(error.MalformedMetadata, saml.parseIdpMetadataFor(a, "<foo xmlns=\"urn:x\"/>", "x", .{}));
    // an EntityDescriptor without entityID is skipped, not a match for ""
    const noid = "<md:EntitiesDescriptor" ++ ns_decl ++ "><md:EntityDescriptor/></md:EntitiesDescriptor>";
    try testing.expectError(error.EntityNotFound, saml.parseIdpMetadataFor(a, noid, "", .{}));
}

test "aggregate: a plain EntityDescriptor root is accepted when its entityID matches" {
    const a = testing.allocator;
    const alone = comptime idpRoot("https://idp2.example.org", "d29ybGQ=", "");
    var m = try saml.parseIdpMetadataFor(a, alone, "https://idp2.example.org", .{});
    m.deinit();
    try testing.expectError(error.EntityNotFound, saml.parseIdpMetadataFor(a, alone, "https://other", .{}));
}

test "aggregate: bounds on nesting, entity count and parse elements" {
    const a = testing.allocator;
    // depth: aggregate nests 3 groups; max_nesting 2 refuses it, 3 accepts.
    try testing.expectError(error.MalformedMetadata, saml.parseIdpMetadataFor(a, aggregate, "https://idp3.example.org", .{ .max_nesting = 2 }));
    var ok = try saml.parseIdpMetadataFor(a, aggregate, "https://idp3.example.org", .{ .max_nesting = 3 });
    ok.deinit();
    // count: aggregate holds 4 EntityDescriptors.
    try testing.expectError(error.MalformedMetadata, saml.parseIdpMetadataFor(a, aggregate, "https://idp3.example.org", .{ .max_entities = 3 }));
    var ok2 = try saml.parseIdpMetadataFor(a, aggregate, "https://idp3.example.org", .{ .max_entities = 4 });
    ok2.deinit();
    // parse element cap
    try testing.expectError(error.MalformedMetadata, saml.parseIdpMetadataFor(a, aggregate, "https://idp3.example.org", .{ .max_elements = 20 }));

    // A very deeply nested chain of groups is refused by the nesting bound, not
    // by the stack.
    const n = 200;
    const open = "<md:EntitiesDescriptor" ++ ns_decl ++ ">";
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(a);
    try buf.appendSlice(a, open);
    for (0..n) |_| try buf.appendSlice(a, "<md:EntitiesDescriptor>");
    for (0..n) |_| try buf.appendSlice(a, "</md:EntitiesDescriptor>");
    try buf.appendSlice(a, "</md:EntitiesDescriptor>");
    try testing.expectError(error.MalformedMetadata, saml.parseIdpMetadataFor(a, buf.items, "x", .{}));
}

test "aggregate: allocation failure at every point is OutOfMemory, never a leak" {
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        if (saml.parseIdpMetadataFor(fa.allocator(), aggregate, "https://idp1.example.org", .{})) |m| {
            var mm = m;
            mm.deinit();
            break;
        } else |err| try testing.expectEqual(error.OutOfMemory, err);
    }
}

test "mdui:UIInfo: display names, description and logos with xml:lang" {
    const a = testing.allocator;
    var m = try saml.parseIdpMetadataFor(a, aggregate, "https://idp1.example.org", .{});
    defer m.deinit();
    const ui = m.ui_info;
    try testing.expectEqual(@as(usize, 2), ui.display_names.len);
    try testing.expectEqualStrings("en", ui.display_names[0].lang);
    try testing.expectEqualStrings("Example University", ui.display_names[0].value);
    try testing.expectEqualStrings("cs", ui.display_names[1].lang);
    try testing.expectEqualStrings("Ukázková univerzita", ui.display_names[1].value);
    try testing.expectEqual(@as(usize, 1), ui.descriptions.len);
    try testing.expectEqualStrings("Login with your campus account.", ui.descriptions[0].value);
    // The two Logos with a bad / missing height are skipped; the URL is trimmed.
    try testing.expectEqual(@as(usize, 1), ui.logos.len);
    try testing.expectEqualStrings("https://idp.example.org/logo.png", ui.logos[0].url);
    try testing.expectEqual(@as(u32, 80), ui.logos[0].width);
    try testing.expectEqual(@as(u32, 60), ui.logos[0].height);
    try testing.expectEqualStrings("en", ui.logos[0].lang);
}

test "mdui:UIInfo: also read by parseIdpMetadata; missing xml:lang is empty; other namespaces ignored" {
    const a = testing.allocator;
    const doc = comptime idpRoot("https://i", "SGVsbG8=", "<md:Extensions><mdui:UIInfo><mdui:DisplayName>No Lang</mdui:DisplayName>" ++
        "<x:DisplayName xmlns:x=\"urn:other\" xml:lang=\"en\">impostor</x:DisplayName></mdui:UIInfo>" ++
        "<x:UIInfo xmlns:x=\"urn:other\"><x:DisplayName xml:lang=\"en\">impostor</x:DisplayName></x:UIInfo></md:Extensions>");
    var m = try saml.parseIdpMetadata(a, doc);
    defer m.deinit();
    try testing.expectEqual(@as(usize, 1), m.ui_info.display_names.len);
    try testing.expectEqualStrings("", m.ui_info.display_names[0].lang);
    try testing.expectEqualStrings("No Lang", m.ui_info.display_names[0].value);
    try testing.expectEqual(@as(usize, 0), m.ui_info.logos.len);
}

test "mdui:UIInfo: a list is capped at max_ui_entries" {
    const a = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(a);
    try buf.appendSlice(a, "<md:Extensions><mdui:UIInfo>");
    for (0..saml.max_ui_entries + 10) |_| try buf.appendSlice(a, "<mdui:DisplayName xml:lang=\"en\">n</mdui:DisplayName>");
    try buf.appendSlice(a, "</mdui:UIInfo></md:Extensions>");
    const doc = comptime idpRoot("https://i", "SGVsbG8=", "@@");
    const at = std.mem.find(u8, doc, "@@").?;
    const full = try std.mem.concat(a, u8, &.{ doc[0..at], buf.items, doc[at + 2 ..] });
    defer a.free(full);
    var m = try saml.parseIdpMetadata(a, full);
    defer m.deinit();
    try testing.expectEqual(@as(usize, saml.max_ui_entries), m.ui_info.display_names.len);
}
