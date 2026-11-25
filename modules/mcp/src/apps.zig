// SPDX-License-Identifier: MIT
//! MCP Apps (the `io.modelcontextprotocol/ui` extension): helpers for a server
//! that ships interactive HTML for a tool. The Python SDK's `mcp.server.apps`
//! (`Apps`, `apps.tool(resource_uri=...)`, `add_html_resource`, `ResourceCsp`,
//! `ResourcePermissions`, `client_supports_apps`) and the TypeScript
//! `registerAppTool` / `registerAppResource` do the same; here they are
//! plain functions over the building blocks the server already has (`Tool.meta_json`,
//! `Resource.meta_json`, `Server.setCapabilityExtras`).
//!
//! Wire shapes (spec `ext-apps` 2026-01-26):
//!   - a tool names its UI in `_meta.ui.resourceUri` (a `ui://` uri) and may limit
//!     who can call it with `_meta.ui.visibility` (`"model"`, `"app"`);
//!   - the UI is a resource at that uri, served with the mime type
//!     `text/html;profile=mcp-app`; its `_meta.ui` may carry `csp`
//!     (`connectDomains`, `resourceDomains`, `frameDomains`, `baseUriDomains`),
//!     `permissions` (`camera`, `microphone`, `geolocation`, `clipboardWrite`),
//!     `domain` and `prefersBorder`;
//!   - a server advertises `capabilities.extensions["io.modelcontextprotocol/ui"]`;
//!     a client that renders apps declares the same key with
//!     `mimeTypes: ["text/html;profile=mcp-app"]` (`ClientCapabilities.apps`).
//!
//! Not here: the iframe bridge (`ui/initialize`, `tools/call` from the view) is the
//! host's and the view's side of the extension, not a server's.

const std = @import("std");
const root = @import("root.zig");

/// The extension's identifier, reserved by the spec.
pub const extension_id = "io.modelcontextprotocol/ui";
/// The mime type of an app's HTML resource.
pub const mime_type = "text/html;profile=mcp-app";
/// The uri scheme reserved for app resources.
pub const uri_scheme = "ui://";
/// `Server.setCapabilityExtras`' first argument for a server that serves apps.
/// That call replaces the whole extensions object: on a server that also
/// serves Skills, make it before `skills.Catalog.attach`, which merges its own
/// entry into what is there.
pub const extensions_json = "{\"" ++ extension_id ++ "\":{}}";

pub const Visibility = enum {
    /// The model may see and call the tool.
    model,
    /// Only the app's view may call it.
    app,
};

pub const Error = error{
    /// A uri that does not start with `ui://` or has nothing after it.
    InvalidUri,
    /// A tool names a UI resource nobody registered.
    UnboundUiResource,
    /// A `ui://` resource whose mime type is not `mime_type`.
    WrongMimeType,
    /// A tool's or a resource's `_meta` is not one JSON object.
    InvalidMeta,
} || std.mem.Allocator.Error;

fn checkUri(uri: []const u8) Error!void {
    if (!std.mem.startsWith(u8, uri, uri_scheme) or uri.len == uri_scheme.len) return error.InvalidUri;
}

/// `Tool.meta_json` for a tool whose UI is the resource `resource_uri`
/// (`_meta.ui.resourceUri`), optionally restricted to `visibility` (empty =
/// the spec default, both). In `arena`.
pub fn toolMeta(arena: std.mem.Allocator, resource_uri: []const u8, visibility: []const Visibility) Error![]u8 {
    try checkUri(resource_uri);
    var aw: std.Io.Writer.Allocating = .init(arena);
    var jw: std.json.Stringify = .{ .writer = &aw.writer };
    writeToolMeta(&jw, resource_uri, visibility) catch return error.OutOfMemory; // an allocating writer fails only on OOM
    return aw.written();
}

fn writeToolMeta(jw: *std.json.Stringify, resource_uri: []const u8, visibility: []const Visibility) std.Io.Writer.Error!void {
    try jw.beginObject();
    try jw.objectField("ui");
    try jw.beginObject();
    try jw.objectField("resourceUri");
    try jw.write(resource_uri);
    if (visibility.len != 0) {
        try jw.objectField("visibility");
        try jw.beginArray();
        for (visibility) |v| try jw.write(@tagName(v));
        try jw.endArray();
    }
    try jw.endObject();
    try jw.endObject();
}

/// Content-Security-Policy domains the host adds to the view's sandbox.
pub const Csp = struct {
    connect_domains: []const []const u8 = &.{},
    resource_domains: []const []const u8 = &.{},
    frame_domains: []const []const u8 = &.{},
    base_uri_domains: []const []const u8 = &.{},
};

/// Powers the view asks of the host's iframe sandbox.
pub const Permissions = struct {
    camera: bool = false,
    microphone: bool = false,
    geolocation: bool = false,
    clipboard_write: bool = false,
};

/// `_meta.ui` of an app resource.
pub const ResourceUi = struct {
    csp: ?Csp = null,
    permissions: ?Permissions = null,
    /// A dedicated sandbox origin the host may give the view.
    domain: ?[]const u8 = null,
    prefers_border: ?bool = null,
};

/// `Resource.meta_json` for an app resource: `{"ui":{...}}` with only what is set. In `arena`.
pub fn resourceMeta(arena: std.mem.Allocator, ui: ResourceUi) Error![]u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    var jw: std.json.Stringify = .{ .writer = &aw.writer };
    writeResourceMeta(&jw, ui) catch return error.OutOfMemory;
    return aw.written();
}

fn writeResourceMeta(jw: *std.json.Stringify, ui: ResourceUi) std.Io.Writer.Error!void {
    try jw.beginObject();
    try jw.objectField("ui");
    try jw.beginObject();
    if (ui.csp) |c| {
        try jw.objectField("csp");
        try jw.beginObject();
        inline for (.{ .{ "connectDomains", "connect_domains" }, .{ "resourceDomains", "resource_domains" }, .{ "frameDomains", "frame_domains" }, .{ "baseUriDomains", "base_uri_domains" } }) |f| {
            const list = @field(c, f[1]);
            if (list.len != 0) {
                try jw.objectField(f[0]);
                try jw.write(list);
            }
        }
        try jw.endObject();
    }
    if (ui.permissions) |p| {
        try jw.objectField("permissions");
        try jw.beginObject();
        inline for (.{ .{ "camera", "camera" }, .{ "microphone", "microphone" }, .{ "geolocation", "geolocation" }, .{ "clipboardWrite", "clipboard_write" } }) |f| {
            if (@field(p, f[1])) {
                try jw.objectField(f[0]);
                try jw.beginObject();
                try jw.endObject();
            }
        }
        try jw.endObject();
    }
    if (ui.domain) |d| {
        try jw.objectField("domain");
        try jw.write(d);
    }
    if (ui.prefers_border) |b| {
        try jw.objectField("prefersBorder");
        try jw.write(b);
    }
    try jw.endObject();
    try jw.endObject();
}

/// A fixed HTML document served as an app resource. Keep it alive, at one
/// address, as long as the server: `resource` stores a pointer to it (never
/// call it on a temporary). `html` must be UTF-8 — it is served as `text`, and
/// JSON text cannot carry other bytes.
pub const HtmlResource = struct {
    /// A `ui://` uri.
    uri: []const u8,
    name: []const u8,
    html: []const u8,
    title: ?[]const u8 = null,
    description: []const u8 = "",
    /// `Resource.meta_json` (`resourceMeta` builds one); "" = none.
    meta_json: []const u8 = "",

    /// The `Resource` to give `Server.addResource` (`mime_type` set, the
    /// handler answers with `html`).
    pub fn resource(self: *const HtmlResource) Error!root.Resource {
        try checkUri(self.uri);
        return .{
            .uri = self.uri,
            .name = self.name,
            .description = self.description,
            .mime_type = mime_type,
            .title = self.title,
            .size = self.html.len,
            .meta_json = self.meta_json,
            .handler = serveHtml,
            .ctx = @ptrCast(@constCast(self)),
        };
    }

    fn serveHtml(ctx: ?*anyopaque, req: *root.ResourceRequest) bool {
        const self: *const HtmlResource = @ptrCast(@alignCast(ctx.?));
        req.text(self.uri, mime_type, self.html);
        return true;
    }
};

/// Did the client declare it renders apps? `extensions["io.modelcontextprotocol/ui"]`
/// with `mimeTypes` listing `mime_type`; any other shape is "no". Same as
/// `server.clientCapabilities(peer).apps`.
pub fn clientSupportsApps(caps: root.ClientCapabilities) bool {
    return caps.apps;
}

/// The checks the Python SDK makes when a server takes its `Apps`: every tool
/// that names a UI resource finds it registered, and every `ui://` resource has
/// the app mime type. Call after the last `addTool` / `addResource`. Only
/// static resources count: a UI page served by a resource template is
/// reported as `UnboundUiResource`.
pub fn verify(server: *const root.Server) Error!void {
    for (server.resources.items) |r| {
        if (std.mem.startsWith(u8, r.uri, uri_scheme) and !std.mem.eql(u8, r.mime_type, mime_type)) return error.WrongMimeType;
    }
    var arena_state: std.heap.ArenaAllocator = .init(server.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for (server.tools.items) |t| {
        if (t.meta_json.len == 0) continue;
        const v = std.json.parseFromSliceLeaky(std.json.Value, arena, t.meta_json, .{}) catch return error.InvalidMeta;
        if (v != .object) return error.InvalidMeta;
        const ui = v.object.get("ui") orelse continue;
        if (ui != .object) continue;
        const uri = ui.object.get("resourceUri") orelse continue;
        if (uri != .string) return error.InvalidMeta;
        var found = false;
        for (server.resources.items) |r| {
            if (std.mem.eql(u8, r.uri, uri.string)) found = true;
        }
        if (!found) return error.UnboundUiResource;
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn noopTool(_: ?*anyopaque, _: *root.ToolCall) bool {
    return true;
}

test "toolMeta: resourceUri, optional visibility, only ui:// uris" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    try testing.expectEqualStrings("{\"ui\":{\"resourceUri\":\"ui://clock/app.html\"}}", try toolMeta(a, "ui://clock/app.html", &.{}));
    try testing.expectEqualStrings("{\"ui\":{\"resourceUri\":\"ui://c/a\",\"visibility\":[\"app\"]}}", try toolMeta(a, "ui://c/a", &.{.app}));
    try testing.expectEqualStrings("{\"ui\":{\"resourceUri\":\"ui://c/a\",\"visibility\":[\"model\",\"app\"]}}", try toolMeta(a, "ui://c/a", &.{ .model, .app }));
    try testing.expectError(error.InvalidUri, toolMeta(a, "https://x/y", &.{}));
    try testing.expectError(error.InvalidUri, toolMeta(a, "ui://", &.{}));
}

test "resourceMeta: only what is set, spec key spelling" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    try testing.expectEqualStrings("{\"ui\":{}}", try resourceMeta(a, .{}));
    const connect = [_][]const u8{ "https://api.example.com", "wss://live.example.com" };
    try testing.expectEqualStrings(
        "{\"ui\":{\"csp\":{\"connectDomains\":[\"https://api.example.com\",\"wss://live.example.com\"]},\"permissions\":{\"camera\":{},\"clipboardWrite\":{}},\"domain\":\"a.example\",\"prefersBorder\":false}}",
        try resourceMeta(a, .{
            .csp = .{ .connect_domains = &connect },
            .permissions = .{ .camera = true, .clipboard_write = true },
            .domain = "a.example",
            .prefers_border = false,
        }),
    );
    try testing.expectEqualStrings("{\"ui\":{\"csp\":{},\"permissions\":{}}}", try resourceMeta(a, .{ .csp = .{}, .permissions = .{} }));
}

test "an app end to end: the tool lists its ui resource, resources/read serves the html with the app mime type" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    var s = root.Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.setCapabilityExtras(extensions_json, "");
    const page: HtmlResource = .{ .uri = "ui://clock/app.html", .name = "clock", .title = "Clock", .html = "<p>12:00</p>", .meta_json = try resourceMeta(a, .{ .prefers_border = true }) };
    try s.addResource(try page.resource());
    try s.addTool(.{ .name = "now", .description = "The time.", .input_schema = "{\"type\":\"object\"}", .meta_json = try toolMeta(a, page.uri, &.{}), .handler = noopTool });
    try verify(&s);

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try s.handleMessage("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"c\",\"version\":\"1\"}}}", &out.writer);
    try testing.expect(std.mem.indexOf(u8, out.written(), "\"io.modelcontextprotocol/ui\":{}") != null);
    out.clearRetainingCapacity();
    try s.handleMessage("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}", &out.writer);
    try testing.expect(std.mem.indexOf(u8, out.written(), "\"_meta\":{\"ui\":{\"resourceUri\":\"ui://clock/app.html\"}}") != null);
    out.clearRetainingCapacity();
    try s.handleMessage("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"resources/read\",\"params\":{\"uri\":\"ui://clock/app.html\"}}", &out.writer);
    try testing.expect(std.mem.indexOf(u8, out.written(), "\"mimeType\":\"text/html;profile=mcp-app\"") != null);
    try testing.expect(std.mem.indexOf(u8, out.written(), "<p>12:00</p>") != null);
    out.clearRetainingCapacity();
    try s.handleMessage("{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"resources/list\"}", &out.writer);
    try testing.expect(std.mem.indexOf(u8, out.written(), "\"_meta\":{\"ui\":{\"prefersBorder\":true}}") != null);
}

test "verify: a tool bound to an unregistered ui resource, and a ui:// resource with another mime type, are refused" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    var s = root.Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{ .name = "now", .description = "The time.", .input_schema = "{\"type\":\"object\"}", .meta_json = try toolMeta(a, "ui://missing/app.html", &.{}), .handler = noopTool });
    try testing.expectError(error.UnboundUiResource, verify(&s));
    // A tool with other _meta, or none, is not an app tool.
    var s2 = root.Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s2.deinit();
    try s2.addTool(.{ .name = "x", .description = "d", .input_schema = "{\"type\":\"object\"}", .meta_json = "{\"other\":1}", .handler = noopTool });
    try verify(&s2);
    const wrong: HtmlResource = .{ .uri = "ui://w/a.html", .name = "w", .html = "x" };
    var r = try wrong.resource();
    r.mime_type = "text/html";
    try s2.addResource(r);
    try testing.expectError(error.WrongMimeType, verify(&s2));
    try testing.expectError(error.InvalidUri, (HtmlResource{ .uri = "file:///x", .name = "n", .html = "" }).resource());
}

test "clientSupportsApps: only an extensions entry listing the app mime type counts, and wrong shapes fail closed" {
    const cases = [_]struct { json: []const u8, want: bool }{
        .{ .json = "{\"extensions\":{\"io.modelcontextprotocol/ui\":{\"mimeTypes\":[\"text/html;profile=mcp-app\"]}}}", .want = true },
        .{ .json = "{\"extensions\":{\"io.modelcontextprotocol/ui\":{\"mimeTypes\":[\"text/plain\",\"text/html;profile=mcp-app\"]}}}", .want = true },
        .{ .json = "{}", .want = false },
        .{ .json = "{\"extensions\":{}}", .want = false },
        .{ .json = "{\"extensions\":{\"io.modelcontextprotocol/ui\":{}}}", .want = false },
        .{ .json = "{\"extensions\":{\"io.modelcontextprotocol/ui\":{\"mimeTypes\":[\"text/html\"]}}}", .want = false },
        .{ .json = "{\"extensions\":{\"io.modelcontextprotocol/ui\":{\"mimeTypes\":\"text/html;profile=mcp-app\"}}}", .want = false },
        .{ .json = "{\"extensions\":{\"io.modelcontextprotocol/ui\":true}}", .want = false },
        .{ .json = "{\"extensions\":[\"io.modelcontextprotocol/ui\"]}", .want = false },
        .{ .json = "{\"extensions\":{\"io.modelcontextprotocol/ui\":{\"mimeTypes\":[5]}}}", .want = false },
    };
    for (cases) |c| {
        var st: std.heap.ArenaAllocator = .init(testing.allocator);
        defer st.deinit();
        const v = try std.json.parseFromSliceLeaky(std.json.Value, st.allocator(), c.json, .{});
        try testing.expectEqual(c.want, clientSupportsApps(root.ClientCapabilities.parse(v)));
    }
}

fn noopResource(_: ?*anyopaque, _: *root.ResourceRequest) bool {
    return true;
}

test "mutation 2026-11-25: verify: only ui:// resources need the app mime type, only a malformed ui _meta is InvalidMeta; HtmlResource carries its size" {
    // A tool without _meta and a resource outside ui:// with another mime type are fine.
    var s = root.Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{ .name = "plain", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = noopTool });
    try s.addResource(.{ .uri = "x://doc", .name = "doc", .mime_type = "text/plain", .handler = noopResource });
    try verify(&s);
    // `ui` that is not an object is "not an app tool"; a non-string resourceUri, a non-object _meta and bad JSON are InvalidMeta.
    const ok = [_][]const u8{"{\"ui\":5}"};
    for (ok) |m| {
        var s2 = root.Server.init(testing.allocator, .{ .name = "t", .version = "0" });
        defer s2.deinit();
        try s2.addTool(.{ .name = "x", .description = "d", .input_schema = "{\"type\":\"object\"}", .meta_json = m, .handler = noopTool });
        try verify(&s2);
    }
    const bad = [_][]const u8{ "[1]", "{", "{\"ui\":{\"resourceUri\":5}}" };
    for (bad) |m| {
        var s3 = root.Server.init(testing.allocator, .{ .name = "t", .version = "0" });
        defer s3.deinit();
        try s3.addTool(.{ .name = "x", .description = "d", .input_schema = "{\"type\":\"object\"}", .meta_json = m, .handler = noopTool });
        try testing.expectError(error.InvalidMeta, verify(&s3));
    }
    const page: HtmlResource = .{ .uri = "ui://a/b.html", .name = "n", .html = "12345" };
    try testing.expectEqual(@as(u64, 5), (try page.resource()).size.?);
}
