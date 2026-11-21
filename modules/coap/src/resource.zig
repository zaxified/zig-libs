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
const block = @import("block.zig");
const observe_mod = @import("observe.zig");

/// A resource handler's answer. `payload` must outlive the returned message
/// (a static string, or storage the handler's `ctx` owns).
pub const Reply = struct {
    code: coap.Code,
    content_format: ?u16 = null,
    max_age: ?u32 = null,
    payload: []const u8 = &.{},
    /// Options the dispatcher writes for the handler (in option-number order):
    /// the Observe sequence number of a notification-style answer (RFC 7641
    /// §3.2), the Block2 descriptor of a payload the handler already cut into a
    /// block (and its `size2`, RFC 7959 §4), and the Block1 descriptor to echo
    /// when acknowledging a request block (2.31 Continue, RFC 7959 §2.3).
    observe: ?u24 = null,
    block2: ?block.Block = null,
    size2: ?u32 = null,
    block1: ?block.Block = null,
};

/// What a request's Observe option (RFC 7641 §2) asks of a resource.
pub const ObserveAction = enum { register, deregister };

/// Called for a GET that carries an Observe option 0 or 1, before the handler
/// runs. The hook does the registration bookkeeping (e.g. `observe.Registry`
/// with the request's token) and returns the sequence number to put into the
/// response's Observe option, or null to answer without one (the resource is
/// then not observed, RFC 7641 §3.1). An Observe value other than 0 or 1 is
/// treated as no Observe option.
pub const ObserveHook = *const fn (ctx: ?*anyopaque, req: coap.Message, action: ObserveAction) ?u24;

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
    /// Serve the handler's payload block-wise (RFC 7959 §2.4): the handler returns
    /// the whole representation on every call and the dispatcher cuts out the
    /// block the request's Block2 option names, or the first block when the
    /// payload exceeds `DispatchOptions.max_payload`. A request with a Block2
    /// option is always answered with a block. Off: the payload goes out as
    /// the handler returned it (it may set `Reply.block2` itself).
    blockwise: bool = false,
    /// Observe bookkeeping for this resource, see `ObserveHook`.
    observe_hook: ?ObserveHook = null,
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
    opts: [6]coap.Option = undefined,
    cf: [8]u8 = undefined,
    age: [8]u8 = undefined,
    obs: [8]u8 = undefined,
    b1: [3]u8 = undefined,
    b2: [3]u8 = undefined,
    sz2: [8]u8 = undefined,
};

pub const DispatchOptions = struct {
    /// The request arrived at a multicast address: a discovery request that
    /// matches nothing gets no answer at all (RFC 6690 §4.1, to avoid a
    /// response storm).
    multicast: bool = false,
    /// Largest payload sent in one answer where block-wise transfer is
    /// transparent (the discovery document and `Resource.blockwise` resources):
    /// a longer one goes out as Block2 blocks of the largest size that fits
    /// (SZX 6 = 1024 bytes at most; values below 16 act as 16). A request that
    /// carries a Block2 option is always answered with a block. `maxInt(usize)`
    /// switches the automatic first block off.
    max_payload: usize = 1024,
    /// Scratch for one link at a time. When given, the discovery document is
    /// generated on demand per block and `doc_buf` only has to hold a block,
    /// so the document may be larger than `doc_buf`; it must hold the longest
    /// single link. Empty: the whole document is built in `doc_buf`.
    scratch: []u8 = &.{},
};

/// The Observe action of a GET: its Observe option's value 0 or 1; anything
/// else (absent, another value, a non-GET) is null.
fn observeAction(req: coap.Message) ?ObserveAction {
    if (req.code != .get) return null;
    for (req.options) |o| {
        if (o.number != options.number.observe) continue;
        const v = options.decodeUint(o.value);
        if (o.value.len > 3) return null;
        return switch (v) {
            0 => .register,
            1 => .deregister,
            else => null,
        };
    }
    return null;
}

/// The Block2 option of a request: null when absent, `error.BadBlock` when it
/// does not decode.
fn requestBlock2(req: coap.Message) error{BadBlock}!?block.Block {
    for (req.options) |o| {
        if (o.number != options.number.block2) continue;
        return block.Block.decode(o.value) catch return error.BadBlock;
    }
    return null;
}

/// The largest SZX whose block size does not exceed `max_payload` (SZX 0, 16
/// octets, as a floor).
fn szxFor(max_payload: usize) u3 {
    var z: u3 = 6;
    while (z > 0 and block.sizeForSzx(z) > max_payload) z -= 1;
    return z;
}

/// Where the block of a `total`-octet body a request names lies: the byte range
/// and the Block2 descriptor. `want` is the request's Block2 (null: none); a
/// body that fits `max_payload` needs no block unless one was requested. The
/// server may answer a smaller block size than the request's (RFC 7959 §2.3):
/// the size is capped at what `max_payload` allows and NUM follows it. Null
/// `Window` return means: send the body whole. `error.BadBlock`: the block
/// starts past the end.
const Window = struct { from: usize, to: usize, descriptor: block.Block };

fn blockWindow(total: usize, want: ?block.Block, max_payload: usize) error{BadBlock}!?Window {
    const cap = szxFor(max_payload);
    var szx: u3 = cap;
    var start: usize = 0;
    if (want) |b| {
        szx = @min(b.szx, cap);
        start = b.offset();
    } else if (total <= max_payload) {
        return null;
    }
    // An empty body has exactly one (empty) block, NUM 0.
    if (start > total or (start == total and total != 0)) return error.BadBlock;
    const bs = block.sizeForSzx(szx);
    const to = @min(start + bs, total);
    return .{
        .from = start,
        .to = to,
        .descriptor = .{ .num = @intCast(start / bs), .more = to < total, .szx = szx },
    };
}

/// Cuts `reply.payload` to the block the request asks for (see `blockWindow`),
/// setting `block2` and, on block 0, `size2`. False: the request's Block2
/// option is malformed or addresses past the end (answer 4.02 Bad Option).
fn blockReply(reply: *Reply, req: coap.Message, max_payload: usize) bool {
    const want = requestBlock2(req) catch return false;
    const w = (blockWindow(reply.payload.len, want, max_payload) catch return false) orelse return true;
    const total = reply.payload.len;
    reply.payload = reply.payload[w.from..w.to];
    reply.block2 = w.descriptor;
    if (w.descriptor.num == 0) reply.size2 = @intCast(total);
    return true;
}

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
            if (!res.methods.allows(req.code)) {
                reply = .{ .code = .method_not_allowed };
            } else {
                const action = observeAction(req);
                const seq: ?u24 = if (action != null and res.observe_hook != null)
                    res.observe_hook.?(res.ctx, req, action.?)
                else
                    null;
                reply = res.handler(res.ctx, req);
                if (seq != null and reply.observe == null and reply.code.class() == 2) reply.observe = seq;
                if (res.blockwise and reply.block2 == null and reply.code.class() == 2 and !blockReply(&reply, req, opt.max_payload)) {
                    reply = .{ .code = .bad_option };
                }
            }
        } else {
            reply = .{ .code = .not_found };
        }

        if (options.noResponse(req) catch null) |nr| {
            if (options.no_response.suppresses(nr, reply.code)) {
                return if (req.type == .confirmable) server.ackOnly(req) else null;
            }
        }

        var n: usize = 0;
        if (reply.observe) |seq| {
            var ob: [3]u8 = undefined;
            const v = observe_mod.encodeValue(seq, &ob);
            @memcpy(rb.obs[0..v.len], v);
            rb.opts[n] = .{ .number = options.number.observe, .value = rb.obs[0..v.len] };
            n += 1;
        }
        if (reply.content_format) |cf| {
            rb.opts[n] = .{ .number = options.number.content_format, .value = options.encodeUint(cf, &rb.cf) };
            n += 1;
        }
        if (reply.max_age) |age| {
            rb.opts[n] = .{ .number = options.number.max_age, .value = options.encodeUint(age, &rb.age) };
            n += 1;
        }
        if (reply.block2) |b2| {
            // A descriptor the caller built is encodable (NUM within 20 bits);
            // a NUM too large is dropped to nothing rather than panicking.
            if (b2.encode(&rb.b2)) |v| {
                rb.opts[n] = .{ .number = options.number.block2, .value = v };
                n += 1;
            } else |_| {}
        }
        if (reply.block1) |b1| {
            if (b1.encode(&rb.b1)) |v| {
                rb.opts[n] = .{ .number = options.number.block1, .value = v };
                n += 1;
            } else |_| {}
        }
        if (reply.size2) |sz| {
            rb.opts[n] = .{ .number = options.number.size2, .value = options.encodeUint(sz, &rb.sz2) };
            n += 1;
        }
        return server.piggyback(req, reply.code, rb.opts[0..n], reply.payload);
    }

    fn discovery(r: *const Registry, req: coap.Message, doc_buf: []u8, opt: DispatchOptions) ?Reply {
        if (req.code != .get) return .{ .code = .method_not_allowed };
        if (options.accept(req) catch return .{ .code = .not_acceptable }) |a| {
            if (a != options.content_format.link_format) return .{ .code = .not_acceptable };
        }
        const want = requestBlock2(req) catch return .{ .code = .bad_option };
        if (opt.scratch.len != 0) return r.discoveryStreamed(req, doc_buf, opt, want);

        var w = linkformat.Writer.init(doc_buf);
        for (r.items()) |res| {
            if (res.hidden) continue;
            const before = w.len;
            w.resource(res.path, res.attrs) catch return .{ .code = .internal_server_error };
            if (!keeps(req, w.buf[before..w.len])) w.len = before;
        }
        if (w.len == 0 and opt.multicast) return null;
        var reply: Reply = .{ .code = .content, .content_format = options.content_format.link_format, .payload = w.written() };
        if (!blockReply(&reply, req, opt.max_payload)) return .{ .code = .bad_option };
        return reply;
    }

    /// Whether the link as written passes every `name=value` Uri-Query filter:
    /// parsed back and tested (a parameter without `=` is no filter).
    fn keeps(req: coap.Message, link: []const u8) bool {
        var q = options.uriQuery(req);
        while (q.next()) |param| {
            const f = linkformat.Filter.parse(param) orelse continue;
            var p = linkformat.Parser.init(link);
            const l = (p.next() catch null) orelse return false;
            if (!f.matches(l)) return false;
        }
        return true;
    }

    /// The discovery document one link at a time, so it may be larger than
    /// `doc_buf`: every kept link is written into `opt.scratch`, the bytes that
    /// fall into the requested block are copied into `doc_buf`, and the total
    /// length is counted for Size2 and the "more" flag.
    fn discoveryStreamed(r: *const Registry, req: coap.Message, doc_buf: []u8, opt: DispatchOptions, want: ?block.Block) ?Reply {
        const limit = @min(opt.max_payload, doc_buf.len);
        // Pass 1 sizes the document, pass 2 copies the window.
        var total: usize = 0;
        var window: ?Window = null;
        var blocked = false;
        var pass: u2 = 0;
        while (pass < 2) : (pass += 1) {
            var pos: usize = 0;
            var emitted = false;
            for (r.items()) |res| {
                if (res.hidden) continue;
                var w = linkformat.Writer.init(opt.scratch);
                w.resource(res.path, res.attrs) catch return .{ .code = .internal_server_error };
                if (!keeps(req, w.written())) continue;
                if (pass == 1) {
                    const win = window.?;
                    if (emitted) copyWindow(doc_buf, win, pos, ",");
                    copyWindow(doc_buf, win, pos + @intFromBool(emitted), w.written());
                }
                pos += w.len + @intFromBool(emitted);
                emitted = true;
            }
            if (pass == 0) {
                total = pos;
                if (total == 0 and opt.multicast) return null;
                // Whole document when it fits one answer and no block was asked for.
                const w = blockWindow(total, want, limit) catch return .{ .code = .bad_option };
                blocked = w != null;
                window = w orelse .{ .from = 0, .to = total, .descriptor = .{ .num = 0, .szx = 0 } };
            }
        }
        const win = window.?;
        var reply: Reply = .{
            .code = .content,
            .content_format = options.content_format.link_format,
            .payload = doc_buf[0 .. win.to - win.from],
        };
        if (blocked) {
            reply.block2 = win.descriptor;
            if (win.descriptor.num == 0) reply.size2 = @intCast(total);
        }
        return reply;
    }

    /// Copies the part of `bytes` (which starts at document offset `at`) that
    /// lies inside `win` into `out`.
    fn copyWindow(out: []u8, win: Window, at: usize, bytes: []const u8) void {
        const lo = @max(at, win.from);
        const hi = @min(at + bytes.len, win.to);
        if (lo >= hi) return;
        @memcpy(out[lo - win.from .. hi - win.from], bytes[lo - at .. hi - at]);
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

// ── whole-module mutation (2026-11-17): method matrix, path rules, option buffers ──

fn bothHandler(ctx: ?*anyopaque, req: coap.Message) Reply {
    _ = ctx;
    _ = req;
    return .{ .code = .content, .content_format = 50, .max_age = 300, .payload = "x" };
}

test "Methods.allows: each flag opens exactly its own method, nothing else" {
    const names = [_][]const u8{ "get", "post", "put", "delete", "fetch", "patch", "ipatch" };
    const codes = [_]coap.Code{ .get, .post, .put, .delete, .fetch, .patch, .ipatch };
    inline for (names, 0..) |nm, i| {
        var m: Methods = .{};
        @field(m, nm) = true;
        for (codes, 0..) |c, j| try testing.expectEqual(i == j, m.allows(c));
        try testing.expect(!m.allows(.content));
        try testing.expect(!m.allows(.empty));
    }
    for (codes) |c| try testing.expect(Methods.all.allows(c));
    try testing.expect(!Methods.all.allows(.content));
}

test "Registry.add: the path rules" {
    var st: [8]Resource = undefined;
    var reg = Registry.init(&st);
    const bad = [_][]const u8{ "", "/", "ab", "a/b", "/a/", "//a", "/a//b", "/a b", "/a\x7fb", "/a>b", "/a?b", "/a#b", "/.well-known/core" };
    for (bad) |p| try testing.expectError(error.BadPath, reg.add(.{ .path = p, .handler = tempHandler }));
    try reg.add(.{ .path = "/a", .handler = tempHandler });
    try reg.add(.{ .path = "/a/b", .handler = tempHandler });
    try testing.expectEqual(@as(usize, 2), reg.items().len);
}

test "dispatch: Content-Format and Max-Age options keep their own value buffers" {
    var st: [2]Resource = undefined;
    var reg = Registry.init(&st);
    try reg.add(.{ .path = "/b", .handler = bothHandler });
    var rb: ReplyBuf = .{};
    var opts: [4]coap.Option = undefined;
    var doc: [64]u8 = undefined;
    const resp = reg.dispatch(getReq(&.{"b"}, &.{}, &opts), &rb, &doc, .{}).?;
    try testing.expectEqual(@as(?u16, 50), try options.contentFormat(resp));
    try testing.expectEqual(@as(u64, 300), options.maxAge(resp));
}

test "discovery: a query parameter without '=' is skipped, the filters after it still apply" {
    var store: [8]Resource = undefined;
    var hits: usize = 0;
    const reg = try fixture(&store, &hits);
    var doc: [512]u8 = undefined;
    var rb: ReplyBuf = .{};
    const resp = discover(&reg, &.{ "flag", "rt=nomatch" }, .{}, &doc, &rb).?;
    try testing.expectEqual(coap.Code.content, resp.code);
    try testing.expectEqualStrings("", resp.payload);
}

// ── block-wise answers, Observe hook (RFC 7959 §2.4, RFC 7641 §3.1) ─────────

/// A GET with optional Observe and Block2 options, in option-number order.
fn blockReq(path: []const []const u8, query: []const []const u8, observe_val: ?[]const u8, b2: ?block.Block, store: []coap.Option, b2buf: *[3]u8) !coap.Message {
    var n: usize = 0;
    if (observe_val) |v| {
        store[n] = .{ .number = options.number.observe, .value = v };
        n += 1;
    }
    for (path) |seg| {
        store[n] = .{ .number = options.number.uri_path, .value = seg };
        n += 1;
    }
    for (query) |q| {
        store[n] = .{ .number = options.number.uri_query, .value = q };
        n += 1;
    }
    if (b2) |b| {
        store[n] = .{ .number = options.number.block2, .value = try b.encode(b2buf) };
        n += 1;
    }
    return .{ .type = .confirmable, .code = .get, .message_id = 0x41, .token = &.{ 7, 7 }, .options = store[0..n] };
}

fn optionOf(msg: coap.Message, number: u16) ?[]const u8 {
    for (msg.options) |o| if (o.number == number) return o.value;
    return null;
}

/// 3000 bytes with a position-dependent pattern.
const big_body: [3000]u8 = blk: {
    @setEvalBranchQuota(10_000);
    var b: [3000]u8 = undefined;
    for (&b, 0..) |*x, i| x.* = @truncate(i *% 7 +% 3);
    break :blk b;
};

fn bigHandler(ctx: ?*anyopaque, req: coap.Message) Reply {
    _ = ctx;
    _ = req;
    return .{ .code = .content, .content_format = 42, .payload = &big_body };
}

test "Resource.blockwise: the dispatcher cuts the handler's payload into Block2 blocks" {
    var st: [2]Resource = undefined;
    var reg = Registry.init(&st);
    try reg.add(.{ .path = "/big", .handler = bigHandler, .blockwise = true });
    try reg.add(.{ .path = "/plain", .handler = bigHandler });
    var rb: ReplyBuf = .{};
    var opts: [6]coap.Option = undefined;
    var bb: [3]u8 = undefined;
    var doc: [16]u8 = undefined;

    // No Block2 asked, payload over max_payload: the first block, with Size2.
    const r0 = reg.dispatch(try blockReq(&.{"big"}, &.{}, null, null, &opts, &bb), &rb, &doc, .{}).?;
    try testing.expectEqual(coap.Code.content, r0.code);
    try testing.expectEqual(@as(usize, 1024), r0.payload.len);
    try testing.expectEqualSlices(u8, big_body[0..1024], r0.payload);
    const b0 = try block.Block.decode(optionOf(r0, options.number.block2).?);
    try testing.expectEqual(block.Block{ .num = 0, .more = true, .szx = 6 }, b0);
    try testing.expectEqual(@as(u64, 3000), options.decodeUint(optionOf(r0, options.number.size2).?));
    // Options leave in number order (Content-Format 12, Block2 23, Size2 28).
    var last: u16 = 0;
    for (r0.options) |o| {
        try testing.expect(o.number > last);
        last = o.number;
    }

    // The last block, asked for at the same size: no more, no Size2.
    const r2 = reg.dispatch(try blockReq(&.{"big"}, &.{}, null, .{ .num = 2, .szx = 6 }, &opts, &bb), &rb, &doc, .{}).?;
    try testing.expectEqualSlices(u8, big_body[2048..], r2.payload);
    try testing.expectEqual(block.Block{ .num = 2, .more = false, .szx = 6 }, try block.Block.decode(optionOf(r2, options.number.block2).?));
    try testing.expect(optionOf(r2, options.number.size2) == null);

    // A smaller size than the server's cap is honoured, NUM counted in it.
    const r5 = reg.dispatch(try blockReq(&.{"big"}, &.{}, null, .{ .num = 5, .szx = 2 }, &opts, &bb), &rb, &doc, .{}).?;
    try testing.expectEqualSlices(u8, big_body[320..384], r5.payload);
    try testing.expectEqual(block.Block{ .num = 5, .more = true, .szx = 2 }, try block.Block.decode(optionOf(r5, options.number.block2).?));

    // A larger size than max_payload allows is answered smaller, at the same offset.
    const rc = reg.dispatch(try blockReq(&.{"big"}, &.{}, null, .{ .num = 1, .szx = 6 }, &opts, &bb), &rb, &doc, .{ .max_payload = 256 }).?;
    try testing.expectEqualSlices(u8, big_body[1024..1280], rc.payload);
    try testing.expectEqual(block.Block{ .num = 4, .more = true, .szx = 4 }, try block.Block.decode(optionOf(rc, options.number.block2).?));

    // Past the end, or a malformed option: 4.02.
    const past = reg.dispatch(try blockReq(&.{"big"}, &.{}, null, .{ .num = 3, .szx = 6 }, &opts, &bb), &rb, &doc, .{}).?;
    try testing.expectEqual(coap.Code.bad_option, past.code);
    var bad_opts: [3]coap.Option = .{
        .{ .number = options.number.uri_path, .value = "big" },
        .{ .number = options.number.block2, .value = &.{ 0, 0, 0, 7 } },
        undefined,
    };
    const malformed: coap.Message = .{ .type = .confirmable, .code = .get, .message_id = 1, .token = &.{1}, .options = bad_opts[0..2] };
    try testing.expectEqual(coap.Code.bad_option, reg.dispatch(malformed, &rb, &doc, .{}).?.code);
    bad_opts[1].value = &.{0x07}; // SZX 7 is reserved
    try testing.expectEqual(coap.Code.bad_option, reg.dispatch(malformed, &rb, &doc, .{}).?.code);

    // A resource that did not ask for it keeps its payload whole.
    const plain = reg.dispatch(try blockReq(&.{"plain"}, &.{}, null, null, &opts, &bb), &rb, &doc, .{}).?;
    try testing.expectEqual(@as(usize, 3000), plain.payload.len);
    try testing.expect(optionOf(plain, options.number.block2) == null);

    // A body that fits is not blocked unless a block was requested.
    const small = reg.dispatch(try blockReq(&.{"big"}, &.{}, null, null, &opts, &bb), &rb, &doc, .{ .max_payload = 4096 }).?;
    try testing.expectEqual(@as(usize, 3000), small.payload.len);
    try testing.expect(optionOf(small, options.number.block2) == null);
    const asked = reg.dispatch(try blockReq(&.{"big"}, &.{}, null, .{ .num = 0, .szx = 6 }, &opts, &bb), &rb, &doc, .{ .max_payload = 4096 }).?;
    try testing.expectEqual(@as(usize, 1024), asked.payload.len);
}

fn tinyHandler(ctx: ?*anyopaque, req: coap.Message) Reply {
    _ = ctx;
    _ = req;
    return .{ .code = .content, .payload = "0123456789" };
}

test "blockwise: a body that fits one block answers Block2 0, M=0 when a block was asked for" {
    var st: [1]Resource = undefined;
    var reg = Registry.init(&st);
    try reg.add(.{ .path = "/t", .handler = tinyHandler, .blockwise = true });
    var rb: ReplyBuf = .{};
    var opts: [6]coap.Option = undefined;
    var bb: [3]u8 = undefined;
    var doc: [16]u8 = undefined;
    const r = reg.dispatch(try blockReq(&.{"t"}, &.{}, null, .{ .num = 0, .szx = 0 }, &opts, &bb), &rb, &doc, .{}).?;
    try testing.expectEqualStrings("0123456789", r.payload);
    try testing.expectEqual(block.Block{ .num = 0, .more = false, .szx = 0 }, try block.Block.decode(optionOf(r, options.number.block2).?));
    // NUM 1 of a 10-byte body starts past the end.
    const past = reg.dispatch(try blockReq(&.{"t"}, &.{}, null, .{ .num = 1, .szx = 0 }, &opts, &bb), &rb, &doc, .{}).?;
    try testing.expectEqual(coap.Code.bad_option, past.code);
}

/// Fetches every block of `/.well-known/core` through the dispatcher and
/// returns the assembled document length in `out`.
fn fetchDiscovery(reg: *const Registry, query: []const []const u8, opt: DispatchOptions, doc: []u8, out: []u8) !usize {
    var asm_ = block.Assembler.init(out);
    var szx: u3 = 6;
    var guard: usize = 0;
    var num: u32 = 0;
    var first = true;
    while (guard < 200) : (guard += 1) {
        var rb: ReplyBuf = .{};
        var opts: [8]coap.Option = undefined;
        var bb: [3]u8 = undefined;
        const resp = reg.dispatch(try blockReq(&.{ ".well-known", "core" }, query, null, if (first) null else block.Block{ .num = num, .szx = szx }, &opts, &bb), &rb, doc, opt).?;
        try testing.expectEqual(coap.Code.content, resp.code);
        const b2 = optionOf(resp, options.number.block2) orelse {
            // Not blocked: the whole document.
            try asm_.accept(.{ .num = 0, .more = false, .szx = 0 }, resp.payload);
            return asm_.payload().len;
        };
        const got = try block.Block.decode(b2);
        try asm_.accept(got, resp.payload);
        if (first) try testing.expectEqual(@as(u64, resp.payload.len), @min(options.decodeUint(optionOf(resp, options.number.size2).?), block.sizeForSzx(got.szx)));
        first = false;
        if (!got.more) return asm_.payload().len;
        szx = got.szx;
        num = asm_.nextNum();
    }
    return error.TooManyBlocks;
}

test "discovery over Block2: a document larger than doc_buf is served block by block" {
    var st: [32]Resource = undefined;
    var reg = Registry.init(&st);
    var names: [24][16]u8 = undefined;
    for (0..24) |i| {
        const path = try std.fmt.bufPrint(&names[i], "/sensors/s{d:0>2}", .{i});
        try reg.add(.{ .path = path, .handler = tempHandler, .attrs = .{ .rt = "temperature-c", .if_ = "sensor", .ct = &.{0}, .obs = true } });
    }
    // The reference: the whole document in a big buffer, no blocks.
    var big: [4096]u8 = undefined;
    var rb: ReplyBuf = .{};
    var st2: [4]coap.Option = undefined;
    const full = reg.dispatch(getReq(&.{ ".well-known", "core" }, &.{}, &st2), &rb, &big, .{}).?;
    try testing.expectEqual(@as(usize, 1024), full.payload.len); // over max_payload: the first block
    try testing.expect(optionOf(full, options.number.block2) != null);
    try testing.expect(options.decodeUint(optionOf(full, options.number.size2).?) > 1024);
    var whole: [4096]u8 = undefined;
    const ref_len = try fetchDiscovery(&reg, &.{}, .{ .max_payload = 4096 }, &big, &whole);
    try testing.expect(ref_len > 1024);

    // 64-byte block buffer, 128-byte link scratch: the same document, 32-byte blocks.
    var small: [64]u8 = undefined;
    var scratch: [128]u8 = undefined;
    var got: [4096]u8 = undefined;
    const n = try fetchDiscovery(&reg, &.{}, .{ .scratch = &scratch, .max_payload = 32 }, &small, &got);
    try testing.expectEqualSlices(u8, whole[0..ref_len], got[0..n]);
    // The same with the filter applied (rt matches all, the second filter none).
    var got2: [4096]u8 = undefined;
    const n2 = try fetchDiscovery(&reg, &.{"if=sensor"}, .{ .scratch = &scratch, .max_payload = 48 }, &small, &got2);
    try testing.expectEqualSlices(u8, whole[0..ref_len], got2[0..n2]);
    const n3 = try fetchDiscovery(&reg, &.{"rt=nomatch"}, .{ .scratch = &scratch, .max_payload = 48 }, &small, &got2);
    try testing.expectEqual(@as(usize, 0), n3);

    // Without scratch a document that does not fit doc_buf is still 5.00.
    const too_small = reg.dispatch(getReq(&.{ ".well-known", "core" }, &.{}, &st2), &rb, &small, .{}).?;
    try testing.expectEqual(coap.Code.internal_server_error, too_small.code);
    // A scratch smaller than the longest link is 5.00 too.
    var tiny_scratch: [8]u8 = undefined;
    const bad = reg.dispatch(getReq(&.{ ".well-known", "core" }, &.{}, &st2), &rb, &small, .{ .scratch = &tiny_scratch }).?;
    try testing.expectEqual(coap.Code.internal_server_error, bad.code);
}

test "discovery over Block2: a request block past the end, and a multicast miss with scratch" {
    var st: [4]Resource = undefined;
    var reg = Registry.init(&st);
    try reg.add(.{ .path = "/a", .handler = tempHandler });
    var small: [64]u8 = undefined;
    var scratch: [64]u8 = undefined;
    var rb: ReplyBuf = .{};
    var opts: [6]coap.Option = undefined;
    var bb: [3]u8 = undefined;
    const past = reg.dispatch(try blockReq(&.{ ".well-known", "core" }, &.{}, null, .{ .num = 9, .szx = 0 }, &opts, &bb), &rb, &small, .{ .scratch = &scratch }).?;
    try testing.expectEqual(coap.Code.bad_option, past.code);
    // Multicast discovery that matches nothing stays silent in streamed mode too.
    try testing.expect(reg.dispatch(try blockReq(&.{ ".well-known", "core" }, &.{"rt=none"}, null, null, &opts, &bb), &rb, &small, .{ .scratch = &scratch, .multicast = true }) == null);
}

const HookLog = struct {
    action: ?ObserveAction = null,
    calls: usize = 0,
    seq: ?u24 = 0x010203,
};

fn hookFn(ctx: ?*anyopaque, req: coap.Message, action: ObserveAction) ?u24 {
    _ = req;
    const log: *HookLog = @ptrCast(@alignCast(ctx.?));
    log.action = action;
    log.calls += 1;
    return log.seq;
}

fn hookedHandler(ctx: ?*anyopaque, req: coap.Message) Reply {
    _ = ctx;
    return .{ .code = if (req.code == .get) .content else .changed, .payload = "v" };
}

test "Resource.observe_hook: register and deregister reach the hook, the sequence becomes the Observe option" {
    var log: HookLog = .{};
    var st: [2]Resource = undefined;
    var reg = Registry.init(&st);
    try reg.add(.{ .path = "/o", .handler = hookedHandler, .ctx = &log, .observe_hook = hookFn, .methods = Methods.all });
    var rb: ReplyBuf = .{};
    var opts: [6]coap.Option = undefined;
    var bb: [3]u8 = undefined;
    var doc: [16]u8 = undefined;

    const reg_resp = reg.dispatch(try blockReq(&.{"o"}, &.{}, &.{}, null, &opts, &bb), &rb, &doc, .{}).?; // Observe: empty = 0
    try testing.expectEqual(ObserveAction.register, log.action.?);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, optionOf(reg_resp, options.number.observe).?);
    const dereg = reg.dispatch(try blockReq(&.{"o"}, &.{}, &.{1}, null, &opts, &bb), &rb, &doc, .{}).?;
    try testing.expectEqual(ObserveAction.deregister, log.action.?);
    try testing.expectEqual(@as(usize, 2), log.calls);
    try testing.expect(optionOf(dereg, options.number.observe) != null);

    // Another Observe value, an over-long one, no Observe option: no hook call.
    _ = reg.dispatch(try blockReq(&.{"o"}, &.{}, &.{2}, null, &opts, &bb), &rb, &doc, .{}).?;
    _ = reg.dispatch(try blockReq(&.{"o"}, &.{}, &.{ 0, 0, 0, 1 }, null, &opts, &bb), &rb, &doc, .{}).?;
    const plain = reg.dispatch(try blockReq(&.{"o"}, &.{}, null, null, &opts, &bb), &rb, &doc, .{}).?;
    try testing.expectEqual(@as(usize, 2), log.calls);
    try testing.expect(optionOf(plain, options.number.observe) == null);

    // A hook that declines (null) leaves the answer without an Observe option.
    log.seq = null;
    const declined = reg.dispatch(try blockReq(&.{"o"}, &.{}, &.{}, null, &opts, &bb), &rb, &doc, .{}).?;
    try testing.expectEqual(@as(usize, 3), log.calls);
    try testing.expect(optionOf(declined, options.number.observe) == null);

    // A non-GET with an Observe option never reaches the hook.
    var put = try blockReq(&.{"o"}, &.{}, &.{}, null, &opts, &bb);
    put.code = .put;
    _ = reg.dispatch(put, &rb, &doc, .{}).?;
    try testing.expectEqual(@as(usize, 3), log.calls);

    // An error answer carries no Observe option, even when the hook returned one.
    log.seq = 5;
    var st2: [1]Resource = undefined;
    var reg2 = Registry.init(&st2);
    try reg2.add(.{ .path = "/o", .handler = hookedHandler, .ctx = &log, .observe_hook = hookFn });
    var post = try blockReq(&.{"o"}, &.{}, &.{}, null, &opts, &bb);
    post.code = .post; // not allowed: 4.05, no hook
    const na = reg2.dispatch(post, &rb, &doc, .{}).?;
    try testing.expectEqual(coap.Code.method_not_allowed, na.code);
    try testing.expect(optionOf(na, options.number.observe) == null);
}

fn echoBlock1Handler(ctx: ?*anyopaque, req: coap.Message) Reply {
    _ = ctx;
    var b1: ?block.Block = null;
    for (req.options) |o| if (o.number == options.number.block1) {
        b1 = block.Block.decode(o.value) catch null;
    };
    const b = b1.?;
    return .{ .code = if (b.more) .@"continue" else .changed, .block1 = b };
}

test "Reply.block1 and Reply.block2/size2: options are written in number order" {
    var st: [1]Resource = undefined;
    var reg = Registry.init(&st);
    try reg.add(.{ .path = "/up", .handler = echoBlock1Handler, .methods = Methods.all });
    var rb: ReplyBuf = .{};
    var doc: [16]u8 = undefined;
    var b1buf: [3]u8 = undefined;
    const b1: block.Block = .{ .num = 3, .more = true, .szx = 2 };
    var opts = [_]coap.Option{
        .{ .number = options.number.uri_path, .value = "up" },
        .{ .number = options.number.block1, .value = try b1.encode(&b1buf) },
    };
    const put: coap.Message = .{ .type = .confirmable, .code = .put, .message_id = 3, .token = &.{9}, .options = &opts, .payload = "x" };
    const resp = reg.dispatch(put, &rb, &doc, .{}).?;
    try testing.expectEqual(coap.Code.@"continue", resp.code);
    try testing.expectEqual(b1, try block.Block.decode(optionOf(resp, options.number.block1).?));

    // The all-options reply: Observe, Content-Format, Max-Age, Block2, Block1, Size2.
    var out: [8]coap.Option = undefined;
    _ = &out;
    const all = struct {
        fn h(_: ?*anyopaque, _: coap.Message) Reply {
            return .{
                .code = .content,
                .content_format = 5,
                .max_age = 7,
                .observe = 9,
                .block2 = .{ .num = 1, .more = true, .szx = 3 },
                .block1 = .{ .num = 0, .szx = 1 },
                .size2 = 1234,
                .payload = "p",
            };
        }
    }.h;
    var st3: [1]Resource = undefined;
    var reg3 = Registry.init(&st3);
    try reg3.add(.{ .path = "/all", .handler = all });
    var opts3: [4]coap.Option = undefined;
    const r = reg3.dispatch(getReq(&.{"all"}, &.{}, &opts3), &rb, &doc, .{}).?;
    const wanted = [_]u16{ options.number.observe, options.number.content_format, options.number.max_age, options.number.block2, options.number.block1, options.number.size2 };
    // block1 (27) sorts after block2 (23); the writer emits them in that order.
    try testing.expectEqual(@as(usize, wanted.len), r.options.len);
    var prev: u16 = 0;
    for (r.options) |o| {
        try testing.expect(o.number > prev);
        prev = o.number;
    }
    var wire: [64]u8 = undefined;
    const n = try coap.serialize(r, &wire);
    var popts: [8]coap.Option = undefined;
    const back = try coap.parse(wire[0..n], &popts);
    try testing.expectEqual(@as(usize, wanted.len), back.options.len);
}
