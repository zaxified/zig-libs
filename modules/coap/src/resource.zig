// SPDX-License-Identifier: MIT

//! coap resource registry + request dispatcher (RFC 7252 §5.8 / RFC 6690 §4).
//!
//! `Registry` holds the server's resources in caller storage; `dispatch` turns a
//! parsed request into the response `Message`: it routes by `Uri-Path`, checks
//! the method, calls the resource's handler, answers `/.well-known/core`
//! discovery from the registered resources' link attributes (RFC 6690 §4, with
//! the §4.1 query filter) and honours RFC 7967 No-Response. Transport-agnostic
//! and allocation-free, like the rest of the module.
//!
//! ```zig
//! var store: [8]coap.resource.Resource = undefined;
//! var reg = coap.resource.Registry.init(&store);
//! try reg.add(.{ .path = "/sensors/temp", .handler = tempHandler,
//!                .attrs = .{ .rt = "temperature-c", .if_ = "sensor", .ct = &.{0} } });
//!
//! const req = try coap.parse(dgram, &opts);
//! if (!coap.server.isRequest(req)) return;
//! var rb: coap.resource.ReplyBuf = .{};
//! var doc: [512]u8 = undefined; // room for the /.well-known/core document
//! if (reg.dispatch(req, &rb, &doc, .{})) |resp| send(try coap.serialize(resp, &out));
//! ```
//!
//! `dispatch` returns a piggybacked ACK-style message (`server.piggyback`). For
//! a Non-confirmable request send the same code/options/payload through
//! `server.Server.separate(req, ..., false)` instead. Duplicate suppression
//! (`reliability.Dedup`) stays the caller's, before `dispatch`.

const std = @import("std");
const coap = @import("root.zig");
const options = @import("options.zig");
const linkformat = @import("linkformat.zig");
const server = @import("server.zig");

/// A resource handler's answer. `payload` must outlive the returned message
/// (a static string, or storage the handler's `ctx` owns).
pub const Reply = struct {
    code: coap.Code,
    content_format: ?u16 = null,
    max_age: ?u32 = null,
    payload: []const u8 = &.{},
};

/// `ctx` is the resource's `ctx`; `req` is the parsed request (its options and
/// payload borrow the datagram).
pub const Handler = *const fn (ctx: ?*anyopaque, req: coap.Message) Reply;

/// The request methods a resource accepts. Anything else is answered 4.05.
pub const Methods = packed struct(u8) {
    get: bool = false,
    post: bool = false,
    put: bool = false,
    delete: bool = false,
    fetch: bool = false,
    patch: bool = false,
    ipatch: bool = false,
    _pad: u1 = 0,

    pub const read_only: Methods = .{ .get = true };
    pub const all: Methods = .{ .get = true, .post = true, .put = true, .delete = true, .fetch = true, .patch = true, .ipatch = true };

    pub fn allows(m: Methods, code: coap.Code) bool {
        return switch (code) {
            .get => m.get,
            .post => m.post,
            .put => m.put,
            .delete => m.delete,
            .fetch => m.fetch,
            .patch => m.patch,
            .ipatch => m.ipatch,
            else => false,
        };
    }
};

pub const Resource = struct {
    /// Absolute path, `/a/b`: non-empty segments, no trailing `/`, not `/`
    /// itself, not the reserved `/.well-known/core`. Borrowed.
    path: []const u8,
    handler: Handler,
    ctx: ?*anyopaque = null,
    methods: Methods = Methods.read_only,
    /// The attributes listed for this resource in `/.well-known/core`.
    attrs: linkformat.Params = .{},
    /// Keep out of `/.well-known/core` (RFC 6690 §1: discovery is optional per
    /// resource).
    hidden: bool = false,
};

pub const AddError = error{
    /// All storage slots are used.
    RegistryFull,
    /// A resource with this path is already registered.
    DuplicatePath,
    /// The path breaks the `Resource.path` rules.
    BadPath,
};

/// The reserved discovery path (RFC 6690 §4, RFC 8615).
pub const well_known_core = "/.well-known/core";

fn validPath(path: []const u8) bool {
    if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/') return false;
    if (std.mem.eql(u8, path, well_known_core)) return false;
    var prev_slash = false;
    for (path) |c| {
        if (c <= 0x20 or c == 0x7f or c == '>' or c == '?' or c == '#') return false;
        if (c == '/' and prev_slash) return false;
        prev_slash = c == '/';
    }
    return true;
}

/// Whether the request's Uri-Path segments are exactly `path`'s.
fn pathMatches(req: coap.Message, path: []const u8) bool {
    var it = options.uriPath(req);
    var segs = std.mem.splitScalar(u8, path[1..], '/');
    while (segs.next()) |seg| {
        const got = it.next() orelse return false;
        if (!std.mem.eql(u8, got, seg)) return false;
    }
    return it.next() == null;
}

/// Storage for the options of a reply (Content-Format, Max-Age) that the
/// returned `Message` points into; keep it alive as long as the message.
pub const ReplyBuf = struct {
    opts: [2]coap.Option = undefined,
    cf: [8]u8 = undefined,
    age: [8]u8 = undefined,
};

pub const DispatchOptions = struct {
    /// The request arrived at a multicast address: a discovery request that
    /// matches nothing gets no answer at all (RFC 6690 §4.1, to avoid a
    /// response storm).
    multicast: bool = false,
};

pub const Registry = struct {
    storage: []Resource,
    len: usize = 0,

    pub fn init(storage: []Resource) Registry {
        return .{ .storage = storage };
    }

    pub fn items(r: *const Registry) []const Resource {
        return r.storage[0..r.len];
    }

    pub fn add(r: *Registry, res: Resource) AddError!void {
        if (!validPath(res.path)) return error.BadPath;
        for (r.items()) |e| if (std.mem.eql(u8, e.path, res.path)) return error.DuplicatePath;
        if (r.len == r.storage.len) return error.RegistryFull;
        r.storage[r.len] = res;
        r.len += 1;
    }

    /// Remove the resource at `path`; false when there is none. Keeps the
    /// registration order of the others.
    pub fn remove(r: *Registry, path: []const u8) bool {
        for (r.items(), 0..) |e, i| if (std.mem.eql(u8, e.path, path)) {
            std.mem.copyForwards(Resource, r.storage[i .. r.len - 1], r.storage[i + 1 .. r.len]);
            r.len -= 1;
            return true;
        };
        return false;
    }

    /// The resource whose path equals the request's Uri-Path.
    pub fn find(r: *const Registry, req: coap.Message) ?*const Resource {
        for (r.items()) |*e| if (pathMatches(req, e.path)) return e;
        return null;
    }

    /// Route `req` (a request, see `server.isRequest`; anything else yields
    /// null) and build the response, or null when none is to be sent:
    /// a Non-confirmable request whose No-Response value (RFC 7967) suppresses
    /// the answer's class, or an unmatched multicast discovery (see
    /// `DispatchOptions`). A Confirmable request that suppresses its answer gets
    /// the empty ACK instead.
    ///
    /// Answers: 4.04 for an unknown path, 4.05 when the resource does not take
    /// the method, 4.06 when `Accept` asks discovery for anything but
    /// link-format, 5.00 when the discovery document does not fit `doc_buf`.
    /// `/.well-known/core` (GET only) lists the non-hidden resources as
    /// link-format, narrowed by every `name=value` Uri-Query parameter (all of
    /// them must match: RFC 6690 leaves several parameters open).
    pub fn dispatch(
        r: *const Registry,
        req: coap.Message,
        rb: *ReplyBuf,
        doc_buf: []u8,
        opt: DispatchOptions,
    ) ?coap.Message {
        if (!server.isRequest(req)) return null;
        var reply: Reply = undefined;
        if (pathMatches(req, well_known_core)) {
            reply = r.discovery(req, doc_buf, opt) orelse return null;
        } else if (r.find(req)) |res| {
            reply = if (res.methods.allows(req.code)) res.handler(res.ctx, req) else .{ .code = .method_not_allowed };
        } else {
            reply = .{ .code = .not_found };
        }

        if (options.noResponse(req) catch null) |nr| {
            if (options.no_response.suppresses(nr, reply.code)) {
                return if (req.type == .confirmable) server.ackOnly(req) else null;
            }
        }

        var n: usize = 0;
        if (reply.content_format) |cf| {
            rb.opts[n] = .{ .number = options.number.content_format, .value = options.encodeUint(cf, &rb.cf) };
            n += 1;
        }
        if (reply.max_age) |age| {
            rb.opts[n] = .{ .number = options.number.max_age, .value = options.encodeUint(age, &rb.age) };
            n += 1;
        }
        return server.piggyback(req, reply.code, rb.opts[0..n], reply.payload);
    }

    fn discovery(r: *const Registry, req: coap.Message, doc_buf: []u8, opt: DispatchOptions) ?Reply {
        if (req.code != .get) return .{ .code = .method_not_allowed };
        if (options.accept(req) catch return .{ .code = .not_acceptable }) |a| {
            if (a != options.content_format.link_format) return .{ .code = .not_acceptable };
        }
        var w = linkformat.Writer.init(doc_buf);
        for (r.items()) |res| {
            if (res.hidden) continue;
            const before = w.len;
            w.resource(res.path, res.attrs) catch return .{ .code = .internal_server_error };
            // Filter on the link exactly as written: parse it back and test
            // every `name=value` parameter (a parameter without `=` is no filter).
            var keep = true;
            var q = options.uriQuery(req);
            while (q.next()) |param| {
                const f = linkformat.Filter.parse(param) orelse continue;
                var p = linkformat.Parser.init(w.buf[before..w.len]);
                const l = (p.next() catch null) orelse {
                    keep = false;
                    break;
                };
                if (!f.matches(l)) {
                    keep = false;
                    break;
                }
            }
            if (!keep) w.len = before;
        }
        if (w.len == 0 and opt.multicast) return null;
        return .{ .code = .content, .content_format = options.content_format.link_format, .payload = w.written() };
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn tempHandler(ctx: ?*anyopaque, req: coap.Message) Reply {
    _ = ctx;
    _ = req;
    return .{ .code = .content, .content_format = 0, .max_age = 30, .payload = "21.0" };
}

fn echoHandler(ctx: ?*anyopaque, req: coap.Message) Reply {
    const counter: *usize = @ptrCast(@alignCast(ctx.?));
    counter.* += 1;
    return .{ .code = if (req.code == .patch) .changed else .content, .payload = req.payload };
}

fn getReq(path: []const []const u8, query: []const []const u8, store: []coap.Option) coap.Message {
    var n: usize = 0;
    for (path) |s| {
        store[n] = .{ .number = options.number.uri_path, .value = s };
        n += 1;
    }
    for (query) |s| {
        store[n] = .{ .number = options.number.uri_query, .value = s };
        n += 1;
    }
    return .{ .type = .confirmable, .code = .get, .message_id = 0x77, .token = &.{ 1, 2 }, .options = store[0..n] };
}

fn fixture(store: []Resource, hits: *usize) !Registry {
    var reg = Registry.init(store);
    try reg.add(.{ .path = "/sensors", .handler = tempHandler, .attrs = .{ .ct = &.{40}, .title = "Sensor Index" } });
    try reg.add(.{ .path = "/sensors/temp", .handler = tempHandler, .attrs = .{ .rt = "temperature-c", .if_ = "sensor", .ct = &.{0}, .obs = true } });
    try reg.add(.{ .path = "/sensors/light", .handler = tempHandler, .attrs = .{ .rt = "light-lux core.sen-light", .if_ = "sensor" } });
    try reg.add(.{ .path = "/secret", .handler = tempHandler, .hidden = true });
    try reg.add(.{ .path = "/echo", .handler = echoHandler, .ctx = hits, .methods = Methods.all, .attrs = .{ .sz = 1024 } });
    return reg;
}

fn discover(reg: *const Registry, query: []const []const u8, opt: DispatchOptions, doc: []u8, rb: *ReplyBuf) ?coap.Message {
    var st: [8]coap.Option = undefined;
    return reg.dispatch(getReq(&.{ ".well-known", "core" }, query, &st), rb, doc, opt);
}

test "RFC 6690 §4: /.well-known/core lists the registered resources as link-format" {
    var store: [8]Resource = undefined;
    var hits: usize = 0;
    const reg = try fixture(&store, &hits);
    var doc: [512]u8 = undefined;
    var rb: ReplyBuf = .{};
    const resp = discover(&reg, &.{}, .{}, &doc, &rb).?;
    try testing.expectEqual(coap.Type.ack, resp.type);
    try testing.expectEqual(coap.Code.content, resp.code);
    try testing.expectEqual(@as(u16, 0x77), resp.message_id);
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, resp.token);
    try testing.expectEqual(@as(?u16, options.content_format.link_format), try options.contentFormat(resp));
    // "/secret" is hidden; the rest in registration order, parseable back.
    try testing.expectEqualStrings(
        "</sensors>;ct=40;title=\"Sensor Index\"," ++
            "</sensors/temp>;rt=\"temperature-c\";if=\"sensor\";ct=0;obs," ++
            "</sensors/light>;rt=\"light-lux core.sen-light\";if=\"sensor\"," ++
            "</echo>;sz=1024",
        resp.payload,
    );
    var p = linkformat.Parser.init(resp.payload);
    var count: usize = 0;
    while (try p.next()) |_| count += 1;
    try testing.expectEqual(@as(usize, 4), count);
}

test "RFC 6690 §4.1: discovery query filtering through the dispatcher" {
    var store: [8]Resource = undefined;
    var hits: usize = 0;
    const reg = try fixture(&store, &hits);
    var doc: [512]u8 = undefined;
    var rb: ReplyBuf = .{};
    const Case = struct { q: []const []const u8, want: []const u8 };
    const cases = [_]Case{
        .{ .q = &.{"rt=temperature-c"}, .want = "</sensors/temp>;rt=\"temperature-c\";if=\"sensor\";ct=0;obs" },
        .{ .q = &.{"if=sensor"}, .want = "</sensors/temp>;rt=\"temperature-c\";if=\"sensor\";ct=0;obs,</sensors/light>;rt=\"light-lux core.sen-light\";if=\"sensor\"" },
        .{ .q = &.{"rt=core.sen*"}, .want = "</sensors/light>;rt=\"light-lux core.sen-light\";if=\"sensor\"" },
        .{ .q = &.{"href=/echo"}, .want = "</echo>;sz=1024" },
        .{ .q = &.{"href=/sensors/*"}, .want = "</sensors/temp>;rt=\"temperature-c\";if=\"sensor\";ct=0;obs,</sensors/light>;rt=\"light-lux core.sen-light\";if=\"sensor\"" },
        .{ .q = &.{ "if=sensor", "rt=light-lux" }, .want = "</sensors/light>;rt=\"light-lux core.sen-light\";if=\"sensor\"" },
        .{ .q = &.{"obs=*"}, .want = "</sensors/temp>;rt=\"temperature-c\";if=\"sensor\";ct=0;obs" },
        .{ .q = &.{"ct=40"}, .want = "</sensors>;ct=40;title=\"Sensor Index\"" },
        .{ .q = &.{"nope=x"}, .want = "" },
        .{ .q = &.{"junk"}, .want = "</sensors>;ct=40;title=\"Sensor Index\"," ++
            "</sensors/temp>;rt=\"temperature-c\";if=\"sensor\";ct=0;obs," ++
            "</sensors/light>;rt=\"light-lux core.sen-light\";if=\"sensor\"," ++
            "</echo>;sz=1024" }, // not name=value: no filter
    };
    for (cases) |c| {
        const resp = discover(&reg, c.q, .{}, &doc, &rb).?;
        try testing.expectEqual(coap.Code.content, resp.code);
        try testing.expectEqualStrings(c.want, resp.payload);
    }
}

test "RFC 6690 §4.1: an unmatched multicast discovery is not answered, a unicast one is empty" {
    var store: [8]Resource = undefined;
    var hits: usize = 0;
    const reg = try fixture(&store, &hits);
    var doc: [512]u8 = undefined;
    var rb: ReplyBuf = .{};
    try testing.expect(discover(&reg, &.{"rt=none"}, .{ .multicast = true }, &doc, &rb) == null);
    const uni = discover(&reg, &.{"rt=none"}, .{}, &doc, &rb).?;
    try testing.expectEqual(coap.Code.content, uni.code);
    try testing.expectEqual(@as(usize, 0), uni.payload.len);
    // A multicast request that does match is answered.
    try testing.expect(discover(&reg, &.{"rt=temperature-c"}, .{ .multicast = true }, &doc, &rb) != null);
}

test "dispatch: routing, 4.04, 4.05, handler, content-format and max-age options" {
    var store: [8]Resource = undefined;
    var hits: usize = 0;
    const reg = try fixture(&store, &hits);
    var doc: [64]u8 = undefined;
    var rb: ReplyBuf = .{};
    var st: [4]coap.Option = undefined;

    const ok = reg.dispatch(getReq(&.{ "sensors", "temp" }, &.{}, &st), &rb, &doc, .{}).?;
    try testing.expectEqual(coap.Code.content, ok.code);
    try testing.expectEqualStrings("21.0", ok.payload);
    try testing.expectEqual(@as(?u16, 0), try options.contentFormat(ok));
    try testing.expectEqual(@as(u64, 30), options.maxAge(ok));
    try testing.expectEqual(@as(usize, 2), ok.options.len);

    try testing.expectEqual(coap.Code.not_found, reg.dispatch(getReq(&.{"nothing"}, &.{}, &st), &rb, &doc, .{}).?.code);
    // A prefix of a registered path, or one segment too many, is not a match.
    try testing.expectEqual(coap.Code.not_found, reg.dispatch(getReq(&.{"sens"}, &.{}, &st), &rb, &doc, .{}).?.code);
    try testing.expectEqual(coap.Code.not_found, reg.dispatch(getReq(&.{ "echo", "x" }, &.{}, &st), &rb, &doc, .{}).?.code);
    try testing.expectEqual(coap.Code.not_found, reg.dispatch(getReq(&.{}, &.{}, &st), &rb, &doc, .{}).?.code);
    try testing.expectEqual(coap.Code.not_found, reg.dispatch(getReq(&.{ "sensors", "" }, &.{}, &st), &rb, &doc, .{}).?.code);

    // POST to a GET-only resource: 4.05, and the handler is not called.
    var post = getReq(&.{ "sensors", "temp" }, &.{}, &st);
    post.code = .post;
    try testing.expectEqual(coap.Code.method_not_allowed, reg.dispatch(post, &rb, &doc, .{}).?.code);
    // Not a request: no answer.
    var ack = getReq(&.{"echo"}, &.{}, &st);
    ack.type = .ack;
    try testing.expect(reg.dispatch(ack, &rb, &doc, .{}) == null);
}

test "RFC 8132: FETCH / PATCH / iPATCH reach a resource that allows them" {
    var store: [8]Resource = undefined;
    var hits: usize = 0;
    const reg = try fixture(&store, &hits);
    var doc: [64]u8 = undefined;
    var rb: ReplyBuf = .{};
    var st: [4]coap.Option = undefined;
    var req = getReq(&.{"echo"}, &.{}, &st);
    req.payload = "body";
    for ([_]coap.Code{ .fetch, .patch, .ipatch, .post, .put, .delete }) |m| {
        req.code = m;
        const resp = reg.dispatch(req, &rb, &doc, .{}).?;
        try testing.expectEqual(if (m == .patch) coap.Code.changed else coap.Code.content, resp.code);
        try testing.expectEqualStrings("body", resp.payload);
    }
    try testing.expectEqual(@as(usize, 6), hits);
    // A resource with only GET+FETCH refuses PATCH.
    var one: [1]Resource = undefined;
    var r2 = Registry.init(&one);
    try r2.add(.{ .path = "/f", .handler = tempHandler, .methods = .{ .get = true, .fetch = true } });
    var st2: [2]coap.Option = undefined;
    var q = getReq(&.{"f"}, &.{}, &st2);
    q.code = .fetch;
    try testing.expectEqual(coap.Code.content, r2.dispatch(q, &rb, &doc, .{}).?.code);
    q.code = .patch;
    try testing.expectEqual(coap.Code.method_not_allowed, r2.dispatch(q, &rb, &doc, .{}).?.code);
}

test "discovery: only GET, only link-format, too small a buffer is 5.00" {
    var store: [8]Resource = undefined;
    var hits: usize = 0;
    const reg = try fixture(&store, &hits);
    var doc: [512]u8 = undefined;
    var rb: ReplyBuf = .{};
    var st: [4]coap.Option = undefined;
    var req = getReq(&.{ ".well-known", "core" }, &.{}, &st);
    req.code = .post;
    try testing.expectEqual(coap.Code.method_not_allowed, reg.dispatch(req, &rb, &doc, .{}).?.code);
    req.code = .get;
    // Accept: 40 is fine, Accept: 50 is 4.06, an over-long Accept is 4.06.
    var acc: [3]coap.Option = .{
        .{ .number = options.number.uri_path, .value = ".well-known" },
        .{ .number = options.number.uri_path, .value = "core" },
        .{ .number = options.number.accept, .value = &.{40} },
    };
    req.options = &acc;
    try testing.expectEqual(coap.Code.content, reg.dispatch(req, &rb, &doc, .{}).?.code);
    acc[2].value = &.{50};
    try testing.expectEqual(coap.Code.not_acceptable, reg.dispatch(req, &rb, &doc, .{}).?.code);
    acc[2].value = &.{ 0, 0, 40 };
    try testing.expectEqual(coap.Code.not_acceptable, reg.dispatch(req, &rb, &doc, .{}).?.code);
    var small: [20]u8 = undefined;
    const r5 = discover(&reg, &.{}, .{}, &small, &rb).?;
    try testing.expectEqual(coap.Code.internal_server_error, r5.code);
    try testing.expectEqual(@as(usize, 0), r5.payload.len);
}

test "RFC 7967: No-Response suppresses a NON answer, a CON gets the empty ACK" {
    var store: [8]Resource = undefined;
    var hits: usize = 0;
    const reg = try fixture(&store, &hits);
    var doc: [64]u8 = undefined;
    var rb: ReplyBuf = .{};
    var opts: [3]coap.Option = .{
        .{ .number = options.number.uri_path, .value = "sensors" },
        .{ .number = options.number.uri_path, .value = "temp" },
        .{ .number = options.number.no_response, .value = &.{options.no_response.suppress_2xx} },
    };
    var req: coap.Message = .{ .type = .non_confirmable, .code = .get, .message_id = 5, .options = &opts };
    try testing.expect(reg.dispatch(req, &rb, &doc, .{}) == null);
    req.type = .confirmable;
    const ack = reg.dispatch(req, &rb, &doc, .{}).?;
    try testing.expectEqual(coap.Type.ack, ack.type);
    try testing.expectEqual(coap.Code.empty, ack.code);
    try testing.expectEqual(@as(u16, 5), ack.message_id);
    // Suppressing only 4.xx does not hide the 2.05 ...
    opts[2].value = &.{options.no_response.suppress_4xx};
    try testing.expectEqual(coap.Code.content, reg.dispatch(req, &rb, &doc, .{}).?.code);
    // ... but hides a 4.04 for the same request to an unknown path.
    opts[1].value = "none";
    req.type = .non_confirmable;
    try testing.expect(reg.dispatch(req, &rb, &doc, .{}) == null);
    // An over-long No-Response value is ignored (the option is elective).
    opts[2].value = &.{ 0, 8 };
    try testing.expectEqual(coap.Code.not_found, reg.dispatch(req, &rb, &doc, .{}).?.code);
}

test "registry: add rules, duplicates, capacity, remove" {
    var store: [2]Resource = undefined;
    var reg = Registry.init(&store);
    const h = tempHandler;
    try testing.expectError(error.BadPath, reg.add(.{ .path = "", .handler = h }));
    try testing.expectError(error.BadPath, reg.add(.{ .path = "/", .handler = h }));
    try testing.expectError(error.BadPath, reg.add(.{ .path = "a", .handler = h }));
    try testing.expectError(error.BadPath, reg.add(.{ .path = "/a/", .handler = h }));
    try testing.expectError(error.BadPath, reg.add(.{ .path = "/a//b", .handler = h }));
    try testing.expectError(error.BadPath, reg.add(.{ .path = "/a b", .handler = h }));
    try testing.expectError(error.BadPath, reg.add(.{ .path = "/a?x", .handler = h }));
    try testing.expectError(error.BadPath, reg.add(.{ .path = "/a>", .handler = h }));
    try testing.expectError(error.BadPath, reg.add(.{ .path = well_known_core, .handler = h }));
    try reg.add(.{ .path = "/a", .handler = h });
    try testing.expectError(error.DuplicatePath, reg.add(.{ .path = "/a", .handler = h }));
    try reg.add(.{ .path = "/b", .handler = h });
    try testing.expectError(error.RegistryFull, reg.add(.{ .path = "/c", .handler = h }));
    try testing.expect(!reg.remove("/zz"));
    try testing.expect(reg.remove("/a"));
    try testing.expectEqual(@as(usize, 1), reg.items().len);
    try testing.expectEqualStrings("/b", reg.items()[0].path);
    try reg.add(.{ .path = "/c", .handler = h });
    try testing.expectEqualStrings("/c", reg.items()[1].path);
    // A zero-length storage never panics.
    var none: [0]Resource = undefined;
    var empty = Registry.init(&none);
    try testing.expectError(error.RegistryFull, empty.add(.{ .path = "/a", .handler = h }));
}

test "end to end: client GET /.well-known/core?rt=… over the wire codec" {
    const client = @import("client.zig");
    var store: [8]Resource = undefined;
    var hits: usize = 0;
    const reg = try fixture(&store, &hits);

    var c = client.Client.init(100, 0x10);
    var copts: [8]coap.Option = undefined;
    var scratch: [64]u8 = undefined;
    var cout: [128]u8 = undefined;
    const req = try c.buildRequest(.get, "coap://h/.well-known/core?rt=temperature-c", .{}, &copts, &scratch, &cout);

    var sopts: [8]coap.Option = undefined;
    const rmsg = try coap.parse(req.datagram, &sopts);
    var doc: [512]u8 = undefined;
    var rb: ReplyBuf = .{};
    const resp = reg.dispatch(rmsg, &rb, &doc, .{}).?;
    var sout: [512]u8 = undefined;
    const n = try coap.serialize(resp, &sout);

    var ropts: [8]coap.Option = undefined;
    const back = try coap.parse(sout[0..n], &ropts);
    try testing.expectEqual(client.Match.piggybacked, req.exchange.match(back));
    try testing.expectEqual(@as(?u16, 40), try options.contentFormat(back));
    var p = linkformat.Parser.init(back.payload);
    const l = (try p.next()).?;
    try testing.expectEqualStrings("/sensors/temp", l.uri);
    try testing.expect(l.attr("rt").?.eql("temperature-c"));
    try testing.expect(l.attr("obs") != null);
    try testing.expect((try p.next()) == null);
}

// ── fuzz: an arbitrary datagram through parse → dispatch → serialize ────────

const testkit = @import("testkit");
const fz = @import("fuzz_test.zig");
const seed = testkit.fuzz.seedHex;

const dispatch_seeds = [_][]const u8{
    // GET /.well-known/core?rt=*
    seed("40010001" ++ "bb" ++ "2e77656c6c2d6b6e6f776e" ++ "04" ++ "636f7265" ++ "44" ++ "72743d2a"),
    // GET /.well-known/core
    seed("40010001" ++ "bb" ++ "2e77656c6c2d6b6e6f776e" ++ "04" ++ "636f7265"),
    seed("40010002" ++ "b474656d70"), // GET /temp
    seed("40060003" ++ "b474656d70" ++ "ff" ++ "6869"), // PATCH /temp with a body
    seed("40010004" ++ "b474656d70" ++ "d1ea1a"), // GET /temp, No-Response 26
    seed("50010005" ++ "b474656d70" ++ "d1ea02"), // NON GET /temp, No-Response 2
    seed("40010006" ++ "b4" ++ "2e776b6e" ++ "04" ++ "636f7265" ++ "44" ++ "72743d2a" ++ "11" ++ "28"), // path .wkn/core, Accept-ish
};

const fuzzMark = fz.Marker(enum { ran, parsed, answered, discovery, handler, suppressed });

fn fuzzDispatch(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [512]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &buf, &dispatch_seeds);
    fuzzMark.mark(.ran);

    var hits: usize = 0;
    var store: [4]Resource = undefined;
    var reg = Registry.init(&store);
    try reg.add(.{ .path = "/temp", .handler = echoHandler, .ctx = &hits, .methods = Methods.all, .attrs = .{ .rt = "t", .ct = &.{ 0, 40 }, .obs = true } });
    try reg.add(.{ .path = "/a/b", .handler = tempHandler, .attrs = .{ .title = "q\"x" } });

    var opts: [32]coap.Option = undefined;
    const msg = coap.parse(buf[0..len], &opts) catch return;
    fuzzMark.mark(.parsed);
    var rb: ReplyBuf = .{};
    var doc: [256]u8 = undefined;
    const resp = reg.dispatch(msg, &rb, &doc, .{ .multicast = src.value(bool) }) orelse {
        fuzzMark.mark(.suppressed);
        return;
    };
    fuzzMark.mark(.answered);
    if (resp.options.len != 0 and resp.options[0].number == options.number.content_format and resp.payload.len != 0) {
        // A discovery document: always parses as link-format.
        if (resp.code == .content and (try options.contentFormat(resp)) == 40) {
            fuzzMark.mark(.discovery);
            var p = linkformat.Parser.init(resp.payload);
            while (try p.next()) |_| {}
        }
    }
    if (resp.payload.len != 0 and resp.code == .changed) fuzzMark.mark(.handler);
    // The answer always serializes (sorted options) and echoes id + token.
    try testing.expectEqual(msg.message_id, resp.message_id);
    var out: [1024]u8 = undefined;
    const n = try coap.serialize(resp, &out);
    try testing.expectEqual(coap.encodedLen(resp), n);
}

test "fuzz: dispatch never panics on arbitrary datagrams" {
    try testing.fuzz({}, fuzzDispatchSmith, .{ .corpus = &dispatch_seeds });
}

fn fuzzDispatchSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzDispatch(std.testing.Smith, smith, std.testing.allocator);
}

test "fuzz driver: COAP_FUZZ (fuzzDispatch)" {
    try fz.fuzz_driver.run(fuzzDispatch, .{ .prefix = "COAP_FUZZ", .name = "coap-resource-dispatch" });
}

test "fuzz harness: fuzzDispatch, 600 seeds, reaches every outcome" {
    try fuzzMark.reach(fuzzDispatch, "coap-resource-dispatch", 600);
}
