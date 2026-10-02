// SPDX-License-Identifier: MIT

//! The 2026-07-28 half of the transport (basic/transports/streamable-http.mdx
//! of that revision): which POSTs are *modern*, the request-metadata headers
//! they must carry, and the HTTP status their JSON-RPC answer maps to.
//!
//! **Era, per request, from the body.** A body whose `params._meta` carries
//! `io.modelcontextprotocol/protocolVersion` is modern — the same switch
//! `mcp.Server` itself uses, so the transport and the server can never file
//! one request under different eras. A modern request needs no session: it
//! is served as peer 0, any `Mcp-Session-Id` is ignored and none is minted
//! (the spec's "ignore it, and do not mint or echo session IDs").
//!
//! **Headers mirror the body, and must agree with it** ("Server Validation"):
//! `MCP-Protocol-Version` = the `_meta` version, `Mcp-Method` = `method`,
//! `Mcp-Name` = `params.name` / `params.uri` on `tools/call`, `prompts/get`
//! and `resources/read`, and `Mcp-Param-{Name}` = each tool argument its
//! `inputSchema` marks with `x-mcp-header`. A missing, duplicated, malformed
//! or disagreeing header is 400 with a `HeaderMismatch` (-32020) error. The
//! point is the one the spec gives: a load balancer that routes on a header
//! and a server that executes the body must be looking at the same request.
//! A **duplicated** header is refused too, although the spec does not name
//! it: `http` answers the first value, and an intermediary may act on the
//! last.
//!
//! The converse holds as well: a body *without* the `_meta` version but a
//! `MCP-Protocol-Version` naming a modern revision is a mismatch — the header
//! claims an era the body does not speak. A session-revision value
//! (`2025-06-18`, `2025-11-25`) is what session clients send after
//! `initialize`, and those requests keep the session path untouched.

const std = @import("std");
const mcp = @import("mcp");

/// Header lookup, abstracted so the checks below are testable without a
/// socket. `count` exists to refuse duplicates.
pub const Headers = struct {
    ctx: *const anyopaque,
    getFn: *const fn (ctx: *const anyopaque, name: []const u8) ?[]const u8,
    countFn: *const fn (ctx: *const anyopaque, name: []const u8) usize,

    pub fn get(h: Headers, name: []const u8) ?[]const u8 {
        return h.getFn(h.ctx, name);
    }
    pub fn count(h: Headers, name: []const u8) usize {
        return h.countFn(h.ctx, name);
    }
};

/// What the transport does with one POST.
pub const Verdict = union(enum) {
    /// Not modern: the session-era path, exactly as before.
    legacy,
    /// Modern and its headers agree with its body: serve statelessly.
    modern,
    /// 400 + this `HeaderMismatch` error line (already serialized, with the
    /// body's id when it had a usable one, else null).
    mismatch: []const u8,
};

/// Classify `body`. `server` supplies the tool schemas for `Mcp-Param-*`;
/// the caller holds its lock. Everything allocated lives on `arena`.
pub fn classify(arena: std.mem.Allocator, headers: Headers, body: []const u8, server: *const mcp.Server) error{OutOfMemory}!Verdict {
    // Fast path for the session era: no key spelled the modern way, no
    // escape that could spell it another way (`\/`, `\u0070`, … — `mcp`
    // decodes those, so a substring test alone could be walked around), and
    // no header claiming a modern revision. Such a body cannot be modern, and
    // needs no second full parse on top of the one `mcp` does.
    if (std.mem.indexOfScalar(u8, body, '\\') == null and
        std.mem.indexOf(u8, body, mcp.meta_key.protocol_version) == null and
        !headerClaimsModern(headers)) return .legacy;

    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // Not JSON: nothing to mirror. A modern-claiming header is still a
        // claim the body does not back.
        else => return headerOnlyVerdict(arena, headers, null),
    };
    if (root != .object) return headerOnlyVerdict(arena, headers, null);
    const obj = root.object;
    const id = usableId(obj.get("id"));

    const params: ?std.json.ObjectMap = if (obj.get("params")) |p| (if (p == .object) p.object else null) else null;
    const version_v: ?std.json.Value = blk: {
        const p = params orelse break :blk null;
        const m = p.get("_meta") orelse break :blk null;
        if (m != .object) break :blk null;
        break :blk m.object.get(mcp.meta_key.protocol_version);
    };
    if (version_v == null) return headerOnlyVerdict(arena, headers, id);

    // From here the body is modern: every rule of the revision applies.
    const version = if (version_v.? == .string) version_v.?.string else null;
    const want_version = try expectOne(arena, headers, "MCP-Protocol-Version", id);
    const hv = switch (want_version) {
        .value => |v| v,
        .refused => |line| return .{ .mismatch = line },
    };
    if (version == null or !std.mem.eql(u8, hv, version.?))
        return mismatch(arena, id, "MCP-Protocol-Version header does not match the body's " ++ mcp.meta_key.protocol_version);

    const method: ?[]const u8 = if (obj.get("method")) |m| (if (m == .string) m.string else null) else null;
    const hm = switch (try expectOne(arena, headers, "Mcp-Method", id)) {
        .value => |v| v,
        .refused => |line| return .{ .mismatch = line },
    };
    if (method == null or !std.mem.eql(u8, hm, method.?))
        return mismatch(arena, id, "Mcp-Method header does not match the body's method");

    const name_field: ?[]const u8 = if (std.mem.eql(u8, method.?, "tools/call") or std.mem.eql(u8, method.?, "prompts/get"))
        "name"
    else if (std.mem.eql(u8, method.?, "resources/read"))
        "uri"
    else
        null;
    if (name_field) |field| {
        const raw = switch (try expectOne(arena, headers, "Mcp-Name", id)) {
            .value => |v| v,
            .refused => |line| return .{ .mismatch = line },
        };
        const decoded = (try decodeValue(arena, raw)) orelse
            return mismatch(arena, id, "Mcp-Name header is not a valid Base64 sentinel value");
        const body_name: ?[]const u8 = if (params) |p| (if (p.get(field)) |v| (if (v == .string) v.string else null) else null) else null;
        if (body_name == null or !std.mem.eql(u8, decoded, body_name.?))
            return mismatch(arena, id, "Mcp-Name header does not match the body");

        if (std.mem.eql(u8, method.?, "tools/call")) {
            if (findTool(server, body_name.?)) |tool| {
                const args: ?std.json.Value = if (params.?.get("arguments")) |a| (if (a == .object) a else null) else null;
                if (try checkParamHeaders(arena, headers, tool.input_schema, args, id)) |line| return .{ .mismatch = line };
            }
            // An unknown tool: `mcp` answers -32602, and there is no schema
            // whose headers could disagree.
        }
    }
    return .modern;
}

/// The verdict for a body that is not modern: legacy, unless a header claims
/// a modern revision.
fn headerOnlyVerdict(arena: std.mem.Allocator, headers: Headers, id: ?std.json.Value) error{OutOfMemory}!Verdict {
    if (headerClaimsModern(headers))
        return mismatch(arena, id, "MCP-Protocol-Version names a revision the body does not carry in " ++ mcp.meta_key.protocol_version);
    return .legacy;
}

/// Whether any `MCP-Protocol-Version` header names a modern revision (every
/// copy is looked at: a duplicate must not hide the claim).
fn headerClaimsModern(headers: Headers) bool {
    if (headers.count("MCP-Protocol-Version") > 1) return true;
    const hv = headers.get("MCP-Protocol-Version") orelse return false;
    for (mcp.modern_versions) |v| {
        if (std.mem.eql(u8, hv, v)) return true;
    }
    return false;
}

const One = union(enum) { value: []const u8, refused: []const u8 };

/// A required header present exactly once, with a header-safe value
/// (RFC 9110 field-value: VCHAR, SP, HTAB).
fn expectOne(arena: std.mem.Allocator, headers: Headers, comptime name: []const u8, id: ?std.json.Value) error{OutOfMemory}!One {
    const n = headers.count(name);
    if (n == 0) return .{ .refused = try mismatchLine(arena, id, "missing required header " ++ name) };
    if (n > 1) return .{ .refused = try mismatchLine(arena, id, "duplicated header " ++ name) };
    const v = headers.get(name).?;
    if (!headerSafe(v)) return .{ .refused = try mismatchLine(arena, id, "invalid characters in header " ++ name) };
    return .{ .value = v };
}

fn headerSafe(v: []const u8) bool {
    for (v) |c| {
        if (!(c == '\t' or (c >= 0x20 and c <= 0x7e))) return false;
    }
    return true;
}

/// Undo the spec's Base64 sentinel (`=?base64?…?=`, standard alphabet,
/// padded — the spec's own examples) or return a plain value as is. Null
/// when the sentinel is there but its content is not Base64.
pub fn decodeValue(arena: std.mem.Allocator, raw: []const u8) error{OutOfMemory}!?[]const u8 {
    const prefix = "=?base64?";
    const suffix = "?=";
    if (!(raw.len >= prefix.len + suffix.len and std.mem.startsWith(u8, raw, prefix) and std.mem.endsWith(u8, raw, suffix)))
        return raw;
    const inner = raw[prefix.len .. raw.len - suffix.len];
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(inner) catch return null;
    const out = try arena.alloc(u8, n);
    dec.decode(out, inner) catch return null;
    return out;
}

fn findTool(server: *const mcp.Server, name: []const u8) ?*const mcp.Tool {
    for (server.tools.items) |*t| {
        if (std.mem.eql(u8, t.name, name)) return t;
    }
    return null;
}

/// One `x-mcp-header` annotation: the header's name part and the chain of
/// `properties` keys leading to the annotated parameter.
pub const ParamHeader = struct {
    name: []const u8,
    path: []const []const u8,
};

/// Every `x-mcp-header` annotation statically reachable from the schema root
/// through `properties` keys only (tools.mdx "x-mcp-header"; streamable-http
/// "Schema Extension"). Annotations anywhere else are not headers — the spec
/// makes the tool invalid for a client, which then drops it from its list, so
/// nothing that client sends can carry them. A schema that is not JSON has no
/// annotations (`mcp` itself reports the broken schema on `tools/list`).
pub fn paramHeaders(arena: std.mem.Allocator, input_schema: []const u8) error{OutOfMemory}![]const ParamHeader {
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, input_schema, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return &.{},
    };
    var out: std.ArrayList(ParamHeader) = .empty;
    var path: std.ArrayList([]const u8) = .empty;
    try walkProperties(arena, root, &path, &out, 0);
    return out.items;
}

fn walkProperties(arena: std.mem.Allocator, schema: std.json.Value, path: *std.ArrayList([]const u8), out: *std.ArrayList(ParamHeader), depth: u8) error{OutOfMemory}!void {
    // The chain is as deep as the schema author made it; a registered schema
    // is the server's own, so this bound only stops a runaway, not an attack.
    // It is `mcp`'s bound: `addTool` refuses an annotation deeper than this,
    // so nothing registered can hold one this walk would miss.
    if (depth >= mcp.header_annotations.max_chain or schema != .object) return;
    const props = schema.object.get("properties") orelse return;
    if (props != .object) return;
    var it = props.object.iterator();
    while (it.next()) |e| {
        const sub = e.value_ptr.*;
        if (sub != .object) continue;
        try path.append(arena, e.key_ptr.*);
        defer _ = path.pop();
        if (sub.object.get("x-mcp-header")) |h| {
            if (h == .string) try out.append(arena, .{ .name = h.string, .path = try arena.dupe([]const u8, path.items) });
        }
        try walkProperties(arena, sub, path, out, depth + 1);
    }
}

/// Check every `Mcp-Param-{Name}` the tool's schema declares against the
/// call's arguments ("Server Behavior for Custom Headers"): a value in the
/// body needs its header, a header needs its value, and the two must agree —
/// strings exactly, integers numerically (the spec's SHOULD: `42.0` = `42`),
/// booleans as `true`/`false`. Returns the mismatch line, or null.
fn checkParamHeaders(arena: std.mem.Allocator, headers: Headers, input_schema: []const u8, args: ?std.json.Value, id: ?std.json.Value) error{OutOfMemory}!?[]const u8 {
    for (try paramHeaders(arena, input_schema)) |ph| {
        const hname = try std.fmt.allocPrint(arena, "Mcp-Param-{s}", .{ph.name});
        const body_v = valueAt(args, ph.path);
        const n = headers.count(hname);
        if (n > 1) return try mismatchLineFmt(arena, id, "duplicated header {s}", .{hname});
        if (body_v == null) {
            if (n != 0) return try mismatchLineFmt(arena, id, "{s} header has no value in the body", .{hname});
            continue;
        }
        if (n == 0) return try mismatchLineFmt(arena, id, "missing header {s}", .{hname});
        const raw = headers.get(hname).?;
        if (!headerSafe(raw)) return try mismatchLineFmt(arena, id, "invalid characters in header {s}", .{hname});
        const got = (try decodeValue(arena, raw)) orelse
            return try mismatchLineFmt(arena, id, "{s} header is not a valid Base64 sentinel value", .{hname});
        if (!headerMatches(got, body_v.?)) return try mismatchLineFmt(arena, id, "{s} header does not match the body", .{hname});
    }
    return null;
}

/// The argument at `path`, or null when absent or JSON null (the spec: a
/// null value means the client omits the header).
fn valueAt(args: ?std.json.Value, path: []const []const u8) ?std.json.Value {
    var cur = args orelse return null;
    for (path) |key| {
        if (cur != .object) return null;
        cur = cur.object.get(key) orelse return null;
    }
    if (cur == .null) return null;
    return cur;
}

fn headerMatches(header: []const u8, body: std.json.Value) bool {
    return switch (body) {
        .string => |s| std.mem.eql(u8, header, s),
        .bool => |b| std.mem.eql(u8, header, if (b) "true" else "false"),
        .integer => |i| numericEq(header, @floatFromInt(i)),
        .float => |f| numericEq(header, f),
        .number_string => |s| blk: {
            const f = std.fmt.parseFloat(f64, s) catch break :blk false;
            break :blk numericEq(header, f);
        },
        // Not a primitive the annotation can apply to; no header can match.
        .null, .array, .object => false,
    };
}

fn numericEq(header: []const u8, body: f64) bool {
    const h = std.fmt.parseFloat(f64, header) catch return false;
    return h == body;
}

/// The body's `id`, when it is one an error may echo (JSON-RPC: string,
/// number or null); anything else is answered with null.
fn usableId(v: ?std.json.Value) ?std.json.Value {
    const id = v orelse return null;
    return switch (id) {
        .string, .integer, .float, .number_string => id,
        else => null,
    };
}

fn mismatch(arena: std.mem.Allocator, id: ?std.json.Value, comptime why: []const u8) error{OutOfMemory}!Verdict {
    return .{ .mismatch = try mismatchLine(arena, id, why) };
}

fn mismatchLine(arena: std.mem.Allocator, id: ?std.json.Value, why: []const u8) error{OutOfMemory}![]const u8 {
    const msg = try std.fmt.allocPrint(arena, "Header mismatch: {s}", .{why});
    var aw: std.Io.Writer.Allocating = .init(arena);
    writeErrorLine(&aw.writer, id, msg) catch return error.OutOfMemory;
    return aw.written();
}

fn writeErrorLine(w: *std.Io.Writer, id: ?std.json.Value, msg: []const u8) std.Io.Writer.Error!void {
    try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try std.json.Stringify.value(id orelse std.json.Value.null, .{}, w);
    try w.print(",\"error\":{{\"code\":{d},\"message\":", .{mcp.error_code.header_mismatch});
    try std.json.Stringify.encodeJsonString(msg, .{}, w);
    try w.writeAll("}}");
}

fn mismatchLineFmt(arena: std.mem.Allocator, id: ?std.json.Value, comptime fmt: []const u8, args: anytype) error{OutOfMemory}![]const u8 {
    return mismatchLine(arena, id, try std.fmt.allocPrint(arena, fmt, args));
}

/// The HTTP status of a modern request's final JSON-RPC line
/// (streamable-http.mdx "Protocol Version Header", "Backward Compatibility"):
/// 400 for `UnsupportedProtocolVersionError`, `HeaderMismatch` and
/// `MissingRequiredClientCapabilityError`, 404 for an unknown method, 200 for
/// everything else — a JSON-RPC error that is a normal answer (-32602 on a
/// bad argument) is not a transport failure.
pub fn statusFor(arena: std.mem.Allocator, line: []const u8) u16 {
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, line, .{}) catch return 200;
    if (v != .object) return 200;
    const err = v.object.get("error") orelse return 200;
    if (err != .object) return 200;
    const code = err.object.get("code") orelse return 200;
    if (code != .integer) return 200;
    return switch (code.integer) {
        mcp.error_code.unsupported_protocol_version,
        mcp.error_code.header_mismatch,
        mcp.error_code.missing_required_client_capability,
        => 400,
        mcp.error_code.method_not_found => 404,
        else => 200,
    };
}

/// Whether a line the server wrote is the final response (has an `id`, no
/// `method`) rather than a notification ahead of it.
pub fn isResponseLine(arena: std.mem.Allocator, line: []const u8) bool {
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, line, .{}) catch return false;
    if (v != .object) return false;
    return v.object.get("method") == null and v.object.get("id") != null;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Header list for tests: `name: value` pairs, case-insensitive names.
const FakeHeaders = struct {
    pairs: []const [2][]const u8,

    fn headers(self: *const FakeHeaders) Headers {
        return .{ .ctx = self, .getFn = getImpl, .countFn = countImpl };
    }
    fn getImpl(ctx: *const anyopaque, name: []const u8) ?[]const u8 {
        const self: *const FakeHeaders = @ptrCast(@alignCast(ctx));
        for (self.pairs) |p| if (std.ascii.eqlIgnoreCase(p[0], name)) return p[1];
        return null;
    }
    fn countImpl(ctx: *const anyopaque, name: []const u8) usize {
        const self: *const FakeHeaders = @ptrCast(@alignCast(ctx));
        var n: usize = 0;
        for (self.pairs) |p| {
            if (std.ascii.eqlIgnoreCase(p[0], name)) n += 1;
        }
        return n;
    }
};

fn noopTool(_: ?*anyopaque, _: *mcp.ToolCall) bool {
    return false;
}

/// The spec's own `execute_sql` tool definition (streamable-http.mdx
/// "Example tool definition"), plus an `extra` nested-object parameter and
/// integer/boolean ones to cover the other value types.
const sql_schema =
    \\{
    \\  "type": "object",
    \\  "properties": {
    \\    "region": {
    \\      "type": "string",
    \\      "description": "The region to execute the query in",
    \\      "x-mcp-header": "Region"
    \\    },
    \\    "query": {
    \\      "type": "string",
    \\      "description": "The SQL query to execute"
    \\    },
    \\    "opts": {
    \\      "type": "object",
    \\      "properties": {
    \\        "shard": { "type": "integer", "x-mcp-header": "Shard" },
    \\        "dry": { "type": "boolean", "x-mcp-header": "Dry" }
    \\      }
    \\    }
    \\  },
    \\  "required": ["region", "query"]
    \\}
;

fn testServer() !mcp.Server {
    var s = mcp.Server.init(testing.allocator, .{ .name = "srv", .version = "1" });
    errdefer s.deinit();
    try s.addTool(.{ .name = "execute_sql", .description = "d", .input_schema = sql_schema, .handler = &noopTool });
    return s;
}

/// The spec's "Resulting HTTP request" body for `execute_sql`, verbatim.
const sql_body =
    \\{
    \\  "jsonrpc": "2.0",
    \\  "id": 1,
    \\  "method": "tools/call",
    \\  "params": {
    \\    "_meta": {
    \\      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    \\      "io.modelcontextprotocol/clientInfo": {
    \\        "name": "ExampleClient",
    \\        "version": "1.0.0"
    \\      },
    \\      "io.modelcontextprotocol/clientCapabilities": {}
    \\    },
    \\    "name": "execute_sql",
    \\    "arguments": {
    \\      "region": "us-west1",
    \\      "query": "SELECT * FROM users"
    \\    }
    \\  }
    \\}
;

/// Classify on `a` (the verdict's line lives there) against `testServer`.
fn classifyWith(a: std.mem.Allocator, pairs: []const [2][]const u8, body: []const u8) !Verdict {
    var s = try testServer();
    defer s.deinit();
    const fh: FakeHeaders = .{ .pairs = pairs };
    return classify(a, fh.headers(), body, &s);
}

fn expectMismatch(v: Verdict, fragment: []const u8) !void {
    switch (v) {
        .mismatch => |line| {
            if (std.mem.indexOf(u8, line, fragment) == null) {
                std.debug.print("\nmismatch line: {s}\nwanted: {s}\n", .{ line, fragment });
                return error.TestExpectedEqual;
            }
            try testing.expect(std.mem.indexOf(u8, line, "\"code\":-32020") != null);
        },
        else => return error.TestExpectedEqual,
    }
}

test "the spec's execute_sql request with its headers is modern and valid" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // streamable-http.mdx "Resulting HTTP request", headers verbatim.
    try testing.expectEqual(Verdict.modern, try classifyWith(a, &.{
        .{ "Content-Type", "application/json" },
        .{ "MCP-Protocol-Version", "2026-07-28" },
        .{ "Mcp-Method", "tools/call" },
        .{ "Mcp-Name", "execute_sql" },
        .{ "Mcp-Param-Region", "us-west1" },
    }, sql_body));
    // Header names are case-insensitive, values are not.
    try testing.expectEqual(Verdict.modern, try classifyWith(a, &.{
        .{ "mcp-protocol-version", "2026-07-28" },
        .{ "MCP-METHOD", "tools/call" },
        .{ "mcp-name", "execute_sql" },
        .{ "mcp-param-region", "us-west1" },
    }, sql_body));
    try expectMismatch(try classifyWith(a, &.{
        .{ "MCP-Protocol-Version", "2026-07-28" },
        .{ "Mcp-Method", "TOOLS/CALL" },
        .{ "Mcp-Name", "execute_sql" },
        .{ "Mcp-Param-Region", "us-west1" },
    }, sql_body), "Mcp-Method");
}

test "every required header: missing, duplicated, disagreeing or unsafe is HeaderMismatch with the body's id" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const good = [_][2][]const u8{
        .{ "MCP-Protocol-Version", "2026-07-28" },
        .{ "Mcp-Method", "tools/call" },
        .{ "Mcp-Name", "execute_sql" },
        .{ "Mcp-Param-Region", "us-west1" },
    };
    // Drop each one in turn.
    for (0..good.len) |skip| {
        var pairs: [good.len - 1][2][]const u8 = undefined;
        var n: usize = 0;
        for (good, 0..) |p, i| {
            if (i == skip) continue;
            pairs[n] = p;
            n += 1;
        }
        const v = try classifyWith(a, &pairs, sql_body);
        try expectMismatch(v, "missing");
        try testing.expect(std.mem.startsWith(u8, v.mismatch, "{\"jsonrpc\":\"2.0\",\"id\":1,"));
    }
    // Duplicate each one in turn (the same value twice still refuses).
    for (0..good.len) |dup| {
        var pairs: [good.len + 1][2][]const u8 = undefined;
        @memcpy(pairs[0..good.len], &good);
        pairs[good.len] = good[dup];
        try expectMismatch(try classifyWith(a, &pairs, sql_body), "duplicated");
    }
    // Change each value in turn.
    for (0..good.len) |change| {
        var pairs = good;
        pairs[change][1] = "other";
        try expectMismatch(try classifyWith(a, &pairs, sql_body), "does not match");
    }
    // A control character or a non-ASCII byte.
    var unsafe = good;
    unsafe[2][1] = "execute\x01sql";
    try expectMismatch(try classifyWith(a, &unsafe, sql_body), "invalid characters");
    unsafe = good;
    unsafe[3][1] = "us-w\xc3\xa9st1";
    try expectMismatch(try classifyWith(a, &unsafe, sql_body), "invalid characters");
}

test "Base64 sentinel values decode before comparing (the spec's encoding table)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // streamable-http.mdx "Encoding examples", every row.
    const rows = [_][2][]const u8{
        .{ "us-west1", "us-west1" },
        .{ "=?base64?SGVsbG8sIOS4lueVjA==?=", "Hello, 世界" },
        .{ "=?base64?IHBhZGRlZCA=?=", " padded " },
        .{ "=?base64?bGluZTEKbGluZTI=?=", "line1\nline2" },
        .{ "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=", "=?base64?literal?=" },
    };
    for (rows) |r| try testing.expectEqualStrings(r[1], (try decodeValue(a, r[0])).?);
    try testing.expect((try decodeValue(a, "=?base64?not base64!?=")) == null);
    // Too short to be the sentinel: a plain value.
    try testing.expectEqualStrings("=??=", (try decodeValue(a, "=??=")).?);

    const body =
        \\{"jsonrpc":"2.0","id":"r","method":"resources/read","params":{"uri":"file:///ü.txt","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
    ;
    var enc_buf: [64]u8 = undefined;
    const enc = std.base64.standard.Encoder.encode(&enc_buf, "file:///ü.txt");
    const sentinel = try std.fmt.allocPrint(a, "=?base64?{s}?=", .{enc});
    try testing.expectEqual(Verdict.modern, try classifyWith(a, &.{
        .{ "MCP-Protocol-Version", "2026-07-28" },
        .{ "Mcp-Method", "resources/read" },
        .{ "Mcp-Name", sentinel },
    }, body));
}

test "x-mcp-header: only properties chains count; nested, integer and boolean values; absent and null" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const found = try paramHeaders(a, sql_schema);
    try testing.expectEqual(@as(usize, 3), found.len);
    // An annotation under `items` is not a header. `mcp`'s `addTool` refuses
    // such a tool outright (`mcp.header_annotations`), so this walk only
    // meets one when called directly — as here.
    try testing.expectEqual(@as(usize, 0), (try paramHeaders(a,
        \\{"type":"object","properties":{"list":{"type":"array","items":{"type":"string","x-mcp-header":"NotAHeader"}}}}
    )).len);
    try testing.expectEqualStrings("Region", found[0].name);
    try testing.expectEqualStrings("Shard", found[1].name);
    try testing.expectEqualStrings("opts", found[1].path[0]);
    try testing.expectEqualStrings("shard", found[1].path[1]);
    try testing.expectEqual(@as(usize, 0), (try paramHeaders(a, "not json")).len);

    const head = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},\"name\":\"execute_sql\",\"arguments\":";
    const base = [_][2][]const u8{
        .{ "MCP-Protocol-Version", "2026-07-28" },
        .{ "Mcp-Method", "tools/call" },
        .{ "Mcp-Name", "execute_sql" },
        .{ "Mcp-Param-Region", "eu" },
    };
    const Case = struct { args: []const u8, extra: []const [2][]const u8, ok: bool };
    const cases = [_]Case{
        // Integer compared numerically (the spec's SHOULD: 42.0 = 42).
        .{ .args = "{\"region\":\"eu\",\"opts\":{\"shard\":42}}", .extra = &.{.{ "Mcp-Param-Shard", "42" }}, .ok = true },
        .{ .args = "{\"region\":\"eu\",\"opts\":{\"shard\":42}}", .extra = &.{.{ "Mcp-Param-Shard", "42.0" }}, .ok = true },
        .{ .args = "{\"region\":\"eu\",\"opts\":{\"shard\":42}}", .extra = &.{.{ "Mcp-Param-Shard", "43" }}, .ok = false },
        .{ .args = "{\"region\":\"eu\",\"opts\":{\"shard\":42}}", .extra = &.{}, .ok = false },
        .{ .args = "{\"region\":\"eu\",\"opts\":{\"dry\":false}}", .extra = &.{.{ "Mcp-Param-Dry", "false" }}, .ok = true },
        .{ .args = "{\"region\":\"eu\",\"opts\":{\"dry\":false}}", .extra = &.{.{ "Mcp-Param-Dry", "False" }}, .ok = false },
        // Absent or null in the body: no header expected, and one sent is refused.
        .{ .args = "{\"region\":\"eu\",\"opts\":{\"shard\":null}}", .extra = &.{}, .ok = true },
        .{ .args = "{\"region\":\"eu\"}", .extra = &.{.{ "Mcp-Param-Shard", "1" }}, .ok = false },
    };
    for (cases, 0..) |c, i| {
        var pairs: std.ArrayList([2][]const u8) = .empty;
        try pairs.appendSlice(a, &base);
        try pairs.appendSlice(a, c.extra);
        const body = try std.fmt.allocPrint(a, "{s}{s}}}}}", .{ head, c.args });
        const v = try classifyWith(a, pairs.items, body);
        testing.expectEqual(c.ok, v == .modern) catch |e| {
            std.debug.print("case {d}: {any}\n", .{ i, v });
            return e;
        };
    }
}

test "era: a legacy body stays legacy under a session-revision header; a modern header on a legacy body is refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const legacy_body = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}";
    try testing.expectEqual(Verdict.legacy, try classifyWith(a, &.{}, legacy_body));
    try testing.expectEqual(Verdict.legacy, try classifyWith(a, &.{.{ "MCP-Protocol-Version", "2025-11-25" }}, legacy_body));
    try testing.expectEqual(Verdict.legacy, try classifyWith(a, &.{.{ "MCP-Protocol-Version", "2025-06-18" }}, "not json"));
    try expectMismatch(try classifyWith(a, &.{.{ "MCP-Protocol-Version", "2026-07-28" }}, legacy_body), "does not carry");
    try expectMismatch(try classifyWith(a, &.{.{ "MCP-Protocol-Version", "2026-07-28" }}, "not json"), "does not carry");
    // A modern body naming an unknown revision, with a matching header, is
    // modern here: `mcp` answers -32022 and the transport maps that to 400.
    const future = "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/list\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2099-01-01\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}";
    try testing.expectEqual(Verdict.modern, try classifyWith(a, &.{ .{ "MCP-Protocol-Version", "2099-01-01" }, .{ "Mcp-Method", "tools/list" } }, future));
    // A non-string version in the body can match no header.
    const bad = "{\"jsonrpc\":\"2.0\",\"id\":[1],\"method\":\"tools/list\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":5}}}";
    const v = try classifyWith(a, &.{ .{ "MCP-Protocol-Version", "5" }, .{ "Mcp-Method", "tools/list" } }, bad);
    try expectMismatch(v, "MCP-Protocol-Version");
    // ...and an id that is not a JSON-RPC id is answered with null.
    try testing.expect(std.mem.startsWith(u8, v.mismatch, "{\"jsonrpc\":\"2.0\",\"id\":null,"));
}

test "an escaped modern key is still modern: the fast path cannot be walked around" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // `\/` and `\u0070` spell the same key; `mcp` would serve this statelessly,
    // so the transport must hold it to the modern header rules.
    const escaped =
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol\/\u0070rotocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
    ;
    try expectMismatch(try classifyWith(a, &.{}, escaped), "missing required header MCP-Protocol-Version");
    // Duplicated version headers on a legacy body: the second must not hide
    // behind the first.
    try expectMismatch(try classifyWith(a, &.{ .{ "MCP-Protocol-Version", "2025-11-25" }, .{ "MCP-Protocol-Version", "2026-07-28" } }, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"), "does not carry");
}

test "statusFor: 400 for the three modern refusals, 404 for an unknown method, else 200" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqual(@as(u16, 400), statusFor(a, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32022,\"message\":\"x\"}}"));
    try testing.expectEqual(@as(u16, 400), statusFor(a, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32020,\"message\":\"x\"}}"));
    try testing.expectEqual(@as(u16, 400), statusFor(a, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32021,\"message\":\"x\"}}"));
    try testing.expectEqual(@as(u16, 404), statusFor(a, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"x\"}}"));
    try testing.expectEqual(@as(u16, 200), statusFor(a, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"x\"}}"));
    try testing.expectEqual(@as(u16, 200), statusFor(a, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"));
    try testing.expectEqual(@as(u16, 200), statusFor(a, "garbage"));
    try testing.expect(isResponseLine(a, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"));
    try testing.expect(!isResponseLine(a, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}"));
}
