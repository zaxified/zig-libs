// SPDX-License-Identifier: MIT

//! The stdio server the official MCP TypeScript SDK's `SkillsClient`
//! (@modelcontextprotocol/client 2.4.0, black box) is pointed at by
//! `drive.mjs`: a skills catalog with the spec's example skill, a nested
//! prefix, CRLF frontmatter with optional fields, a binary file, a file name
//! that needs percent-encoding, a nested skill, a broken skill (left out) and
//! a dynamic skill; `page_size` 2 so the client walks pages. `drive.mjs`
//! builds it:
//!
//!   zig build-exe -OReleaseSafe -fllvm --dep mcp -Mroot=modules/mcp/tools/skills_oracle/server.zig \
//!     --dep jsontext --dep yaml -Mmcp=modules/mcp/src/root.zig -Mjsontext=modules/jsontext/src/root.zig \
//!     -Myaml=modules/yaml/src/root.zig

const std = @import("std");
const mcp = @import("mcp");
const skills = mcp.skills;

pub const info: mcp.Info = .{ .name = "skills-oracle", .version = "1.0.0" };

pub const files = [_]skills.File{
    // The spec's "Example Message Flow" skill, byte for byte.
    .{ .path = "pdf-processing/SKILL.md", .bytes = "---\nname: pdf-processing\ndescription: Extract, fill, and assemble PDF documents\n---\n\n# PDF processing\n\nChoose the matching template from `templates/`.\n" },
    .{ .path = "pdf-processing/templates/invoice.md", .bytes = "# Invoice\n\nCustomer:\nAmount:\n" },
    .{ .path = "pdf-processing/templates/purchase-order.md", .bytes = "# Purchase order\n\nSupplier:\nItems:\n" },
    // A prefixed skill: CRLF, optional fields, nested metadata.
    .{ .path = "acme/billing/refunds/SKILL.md", .bytes = "---\r\nname: refunds\r\ndescription: Process customer refund requests per company policy\r\nlicense: Apache-2.0\r\nmetadata:\r\n  author: acme\r\n  version: \"1.0\"\r\nallowed-tools: Read\r\n---\r\n\r\n# Refunds\r\n\r\nSee examples/email.md.\r\n" },
    .{ .path = "acme/billing/refunds/examples/email.md", .bytes = "Dear customer,\n" },
    .{ .path = "acme/billing/refunds/assets/logo.bin", .bytes = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xfe" },
    .{ .path = "acme/billing/refunds/notes with space.md", .bytes = "čeština ✓\n" },
    // A skill with a skill inside it.
    .{ .path = "outer/SKILL.md", .bytes = "---\nname: outer\ndescription: The enclosing skill\n---\nouter\n" },
    .{ .path = "outer/inner/SKILL.md", .bytes = "---\nname: inner\ndescription: The nested skill\n---\ninner\n" },
    .{ .path = "outer/inner/ref.md", .bytes = "ref\n" },
    // Broken: left out of the catalog.
    .{ .path = "broken/SKILL.md", .bytes = "no frontmatter here\n" },
};

fn readGenerated(_: ?*anyopaque, req: *mcp.ResourceRequest) bool {
    if (!std.mem.eql(u8, req.uri, "skill://reports/daily/today.md")) return false;
    req.text(req.uri, "text/markdown", "# Today\n\nAll systems nominal.\n");
    return true;
}

pub const dynamic = [_]skills.Dynamic{.{
    .path = "reports/daily",
    .skill_md = "---\nname: daily\ndescription: Assemble today's operational report from live data\n---\n\nRead today.md.\n",
    .read = readGenerated,
}};

fn tampered(_: ?*anyopaque, req: *mcp.ResourceRequest) bool {
    req.text(req.uri, "text/markdown", "# Invoice\n\nCustomer:\nAmount: 0\n");
    return true;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var gpa_state: std.heap.SafeAllocator = .init(std.heap.page_allocator, .{});
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var server = mcp.Server.init(gpa, info);
    defer server.deinit();
    server.page_size = 2;
    server.list_cache = .{ .ttl_ms = 300000, .scope = .public };
    server.read_cache = .{ .ttl_ms = 60000, .scope = .public };
    var catalog = try skills.Catalog.load(gpa, &files, &dynamic, .{});
    defer catalog.deinit();
    try catalog.attach(&server);
    // Teeth: a static resource is tried before the template, so this serves
    // other bytes than the manifest describes; the client must refuse them.
    if (init.environ.getPosix("SKILLS_ORACLE_TEETH") != null)
        try server.addResource(.{ .uri = "skill://pdf-processing/templates/invoice.md", .name = "invoice.md", .handler = tampered });
    try server.serveStdio(threaded.io());
}
