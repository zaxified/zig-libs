// SPDX-License-Identifier: MIT

//! What a document-processing consumer does with `xml`: parse a namespaced
//! document, resolve elements by (namespace URI, local name) rather than by
//! raw prefix, read entity-decoded text content, and see a malformed
//! document rejected by name.
//!
//! External judge: `xmllint` (libxml2), checked once while writing this
//! fixture, never at run time:
//!
//!   $ xmllint --xpath "namespace-uri(//*[local-name()='item'])" fixture.xml
//!   urn:example:catalog
//!   $ xmllint --xpath "namespace-uri(//*[local-name()='title'])" fixture.xml
//!   http://purl.org/dc/elements/1.1/
//!   $ printf '<root><a></b></root>' | xmllint --noout -   # exit 4, mismatch
//!
//! i.e. libxml2 resolves `<item>` (unprefixed, under the default namespace)
//! and `<dc:title>` (explicit prefix) to the same URIs this module computes,
//! and rejects the same mismatched-tag document this module rejects.

const std = @import("std");
const xml = @import("xml");

// A default namespace + a prefixed one + an entity reference + a `dc:id`
// attribute in the prefixed namespace — the ordinary shape of a real
// namespaced document, not a synthetic minimal case.
const catalog_doc =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<catalog xmlns="urn:example:catalog" xmlns:dc="http://purl.org/dc/elements/1.1/">
    \\  <item dc:id="42">
    \\    <dc:title>Report &amp; Summary</dc:title>
    \\    <price>19.99</price>
    \\  </item>
    \\</catalog>
    \\
;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer if (gpa_state.deinit() == .leak) @panic("leak");
    const gpa = gpa_state.allocator();

    var doc = try xml.parse(gpa, catalog_doc, .{});
    defer doc.deinit();

    // <item> carries no prefix but sits under the default namespace
    // declaration -- resolves to the SAME URI xmllint reports.
    const item = doc.root.firstElementChild().?;
    std.debug.print("item local={s} uri={s}\n", .{ item.local, item.uri });
    if (!std.mem.eql(u8, item.uri, "urn:example:catalog")) return error.UnexpectedNamespace;

    // <dc:title> carries an explicit prefix; the ORIGINAL prefix is kept
    // (needed for C14N) alongside the resolved URI.
    const title = item.firstElementChild().?;
    std.debug.print("title prefix={s} local={s} uri={s}\n", .{ title.prefix, title.local, title.uri });
    if (!std.mem.eql(u8, title.uri, "http://purl.org/dc/elements/1.1/")) return error.UnexpectedNamespace;

    // The `dc:id` attribute resolves through the SAME prefix binding.
    const id = item.attr("http://purl.org/dc/elements/1.1/", "id").?;
    std.debug.print("item dc:id={s}\n", .{id});

    // Entity-decoded text content: `&amp;` -> `&`, verbatim otherwise.
    const text = try title.textContent(gpa);
    defer gpa.free(text);
    std.debug.print("title text={s}\n", .{text});
    if (!std.mem.eql(u8, text, "Report & Summary")) return error.UnexpectedEntityDecode;

    // Walk item's children in document order: dc:title then price, both
    // under the default namespace catalog set (title carries a prefix,
    // price does not — both resolve through the same inherited scope).
    var it = item.elementIterator();
    const first = it.next().?;
    const second = it.next().?;
    std.debug.print("item children in order: {s} then {s}\n", .{ first.local, second.local });
    if (!std.mem.eql(u8, second.uri, "urn:example:catalog")) return error.UnexpectedNamespace;

    // Negative case: a mismatched end tag. xmllint rejects the identical
    // shape with exit code 4 ("Opening and ending tag mismatch"); this
    // module reports it as a named, catchable error rather than a panic.
    if (xml.parse(gpa, "<root><a></b></root>", .{})) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.MismatchedTag => std.debug.print("rejected \"<root><a></b></root>\": MismatchedTag (expected)\n", .{}),
        else => return err,
    }
}
