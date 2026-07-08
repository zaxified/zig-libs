// SPDX-License-Identifier: MIT

//! router — REST routing on top of `http.Server`.
//!
//! Maps `(method, path pattern)` to handlers: static segments, named params
//! (`/users/:id`) and a trailing wildcard (`/static/*path`), with the
//! deterministic precedence static > param > wildcard (chi-style
//! backtracking). The matcher is a per-segment trie precomputed at `add`
//! time; `dispatch` is read-only, lock-free and allocation-free (params
//! live on the stack), so one Router safely serves all of `http.Server`'s
//! connection threads at once.
//!
//! Middleware composes outer→inner in registration order: router-level
//! `use` first, then each group's middleware root→leaf, then the handler.
//! Chains are precomputed per route at add time, so middleware must be
//! registered before routes (chi's rule, surfaced as an error instead of a
//! panic). The 404/405 defaults are overridable and run the router-level
//! middleware, so metrics/cors-style middleware see misses too.
//!
//! Documented policies (matching Go chi / julienschmidt/httprouter):
//! - **HEAD → GET:** HEAD auto-routes to the GET handler when no explicit
//!   HEAD route exists (`ResponseWriter` already suppresses the body and
//!   frames the response correctly for HEAD).
//! - **405 Allow:** when the path matches but the method has no handler,
//!   the router sets `Allow` (registered methods in `http.Method` order;
//!   HEAD implied by GET) *before* invoking the 405 handler, so overrides
//!   inherit it.
//! - **Auto OPTIONS:** opt-in via `auto_options` (default off). When on and
//!   an `OPTIONS` request hits a path that has routes but *no* explicit
//!   OPTIONS handler, the router answers `204 No Content` with the same
//!   `Allow` set the 405 path computes (runs behind the router-level
//!   middleware, like the 404/405 fallbacks). An explicit OPTIONS route
//!   always wins.
//! - **Trailing slash:** `.redirect` (default, httprouter semantics)
//!   answers 301 for GET/HEAD and 308 for other methods toward the slash
//!   variant that has the route, preserving the query string; `.strict`
//!   (chi semantics) treats `/x` and `/x/` as distinct → 404. `/x` and
//!   `/x/` can always be registered as two distinct routes.
//! - **Raw matching:** paths match byte-for-byte — no percent-decoding, no
//!   case folding. `:param` never matches an empty segment; `*wildcard`
//!   matches the whole remainder (without the leading slash), possibly "".
//!
//! Introspection (what `openapi`/`metrics` build on): `Router.routes()`
//! enumerates the registered route table in registration order, `addDoc`
//! attaches optional plain-data `RouteDoc` metadata to a route, and
//! `Ctx.matchedPattern()` reports the matched route's pattern during
//! dispatch (null in the 404/405 fallbacks).

const std = @import("std");
const http = @import("http");

pub const meta = .{
    .status = .extract, // dispatch shape seeded in axp-central/src/rest.zig; the trie matcher is built here
    .platform = .any,
    .role = .server,
    // Building (add/use/group) is single-owner; a built Router is immutable
    // and dispatch is read-only + allocation-free — reentrant across all
    // connection threads.
    .concurrency = .reentrant,
    .model_after = "Go chi / julienschmidt/httprouter (segment trie, middleware chain, 404/405 semantics)",
    .deps = .{"http"},
};

const Allocator = std.mem.Allocator;

/// Upper bound of `:param` + `*wildcard` captures in a single pattern
/// (enforced at `add` time, so matching never overflows).
pub const max_params = 16;

const method_count = @typeInfo(http.Method).@"enum".fields.len;

// ── the per-request vocabulary ──────────────────────────────────────────────

/// Path params captured by the matched route, in pattern order. Values are
/// slices into the request path — valid for the handler call only.
pub const Params = struct {
    len: usize = 0,
    entries: [max_params]Entry = undefined,

    pub const Entry = struct { name: []const u8, value: []const u8 };

    /// Value of the named `:param` / `*wildcard`, or null when the matched
    /// pattern has no such name.
    pub fn get(p: *const Params, name: []const u8) ?[]const u8 {
        for (p.entries[0..p.len]) |e| {
            if (std.mem.eql(u8, e.name, name)) return e.value;
        }
        return null;
    }

    fn push(p: *Params, name: []const u8, value: []const u8) void {
        std.debug.assert(p.len < max_params); // bounded at add time
        p.entries[p.len] = .{ .name = name, .value = value };
        p.len += 1;
    }
};

/// Everything a handler/middleware gets for one request. Lives on the
/// dispatching thread's stack — never retain it past the call.
pub const Ctx = struct {
    req: *http.Server.Request,
    res: *http.Server.ResponseWriter,
    /// Params of the matched route (empty for the 404 handler).
    params: Params,
    /// `Router.state` passthrough — the application's shared state. (When
    /// served through `handler()`, `req.context` is the Router itself, so
    /// app state travels here instead.)
    state: ?*anyopaque,
    /// Per-request scratch slot, null at dispatch. Middleware may point it
    /// at request-scoped data for inner middleware/handlers (e.g. aaa-gate
    /// attaching the authenticated identity).
    data: ?*anyopaque = null,
    /// Pattern of the matched route — see `matchedPattern`.
    matched_pattern: ?[]const u8 = null,

    /// The pattern of the route serving this request (e.g. "/users/:id"),
    /// router-owned. Null in the 404 and 405 fallback handlers (no route
    /// endpoint matched). A HEAD request auto-routed to the GET handler
    /// reports the GET route's pattern. Middleware see it too — the value
    /// is stashed before the chain runs (this is the bounded-cardinality
    /// label `metrics`/`openapi` need, unlike the raw request path).
    pub fn matchedPattern(ctx: *const Ctx) ?[]const u8 {
        return ctx.matched_pattern;
    }
};

/// A route endpoint. Errors propagate to `http.Server`, which turns them
/// into a 500 when nothing was sent yet.
pub const Handler = *const fn (*Ctx) anyerror!void;

/// One middleware link: `run` is called with the middleware's own `state`
/// (its private, per-instance context — how ratelimit/metrics carry their
/// buckets/counters without globals) and must call `next.run(ctx)` to
/// continue the chain — or not, to short-circuit.
pub const Middleware = struct {
    state: ?*anyopaque = null,
    run: *const fn (state: ?*anyopaque, ctx: *Ctx, next: Next) anyerror!void,
};

/// The rest of the chain from a middleware's point of view.
pub const Next = struct {
    chain: []const Middleware,
    endpoint: Handler,

    /// Invoke the next middleware, or the endpoint once the chain is done.
    pub fn run(next: Next, ctx: *Ctx) anyerror!void {
        if (next.chain.len == 0) return next.endpoint(ctx);
        const mw = next.chain[0];
        return mw.run(mw.state, ctx, .{ .chain = next.chain[1..], .endpoint = next.endpoint });
    }
};

pub const TrailingSlash = enum {
    /// httprouter semantics: `/x/` ↔ `/x` redirect (301 GET/HEAD, 308
    /// otherwise) toward the variant that has the route.
    redirect,
    /// chi semantics: no slash tolerance — the other variant is a 404.
    strict,
};

pub const AddError = error{
    OutOfMemory,
    /// Pattern must start with '/'; `:`/`*` only introduce whole segments;
    /// `*wildcard` must be the last segment.
    InvalidPattern,
    /// This (method, pattern) already has a handler.
    DuplicateRoute,
    /// A different param/wildcard name is already registered at this
    /// position (e.g. `/u/:id` vs `/u/:name`).
    ParamNameConflict,
    /// More than `max_params` captures in one pattern.
    TooManyParams,
};

pub const UseError = error{
    OutOfMemory,
    /// Middleware chains are frozen into routes at add time — register all
    /// middleware first (chi's rule).
    RoutesAlreadyRegistered,
};

pub const GroupError = error{
    OutOfMemory,
    /// Prefix must start with '/' and not end with '/' (e.g. "/api").
    InvalidPrefix,
};

// ── route metadata ──────────────────────────────────────────────────────────

/// Optional per-route documentation, attached via `addDoc`. Plain data the
/// router copies (deep, into its arena) and returns through `routes()` —
/// the router itself never interprets it; `openapi` renders it. All fields
/// are optional (empty defaults).
pub const RouteDoc = struct {
    /// Short one-line summary (OpenAPI `summary`).
    summary: ?[]const u8 = null,
    /// Longer free-form description (OpenAPI `description`).
    description: ?[]const u8 = null,
    /// Grouping tags (OpenAPI `tags`).
    tags: []const []const u8 = &.{},
    /// JSON Schema for the request body, as JSON text — `openapi` validates
    /// and embeds it (normalized) under
    /// `requestBody.content."application/json".schema`.
    request_schema: ?[]const u8 = null,
    /// Documented responses; empty ⇒ consumers fall back to a default 200.
    responses: []const Response = &.{},
    deprecated: bool = false,

    pub const Response = struct {
        /// HTTP status code (the OpenAPI responses key).
        status: u16,
        description: []const u8,
    };
};

/// One registered route, as enumerated by `Router.routes()`.
pub const Route = struct {
    method: http.Method,
    /// Full pattern (group prefixes included), arena-owned by the Router.
    pattern: []const u8,
    /// Metadata attached via `addDoc`, null for plain registrations.
    doc: ?*const RouteDoc = null,
};

// ── the router ──────────────────────────────────────────────────────────────

pub const Router = struct {
    arena: std.heap.ArenaAllocator,
    root: Node,
    /// Router-level middleware, outermost first.
    mws: std.ArrayList(Middleware),
    /// Handed to every handler as `Ctx.state` (application state).
    state: ?*anyopaque = null,
    /// Overridable no-route handler (runs behind the router-level chain).
    not_found: Handler = defaultNotFound,
    /// Overridable wrong-method handler; `Allow` is already set on the
    /// response when it runs.
    method_not_allowed: Handler = defaultMethodNotAllowed,
    /// Opt-in automatic OPTIONS: when true, an `OPTIONS` request on a path
    /// that has registered routes but no explicit OPTIONS handler is
    /// answered `204 No Content` with the same `Allow` the 405 path builds.
    /// Off by default (existing behavior: such a request is a 405). A path
    /// with an explicit OPTIONS route keeps using that handler.
    auto_options: bool = false,
    trailing_slash: TrailingSlash = .redirect,
    routes_added: bool = false,
    /// Registered routes in registration order (see `routes`).
    route_list: std.ArrayList(Route),

    /// All registration state (nodes, patterns, chains, groups) lives in an
    /// internal arena owned by the Router — `deinit` frees everything.
    pub fn init(gpa: Allocator) Router {
        return .{
            .arena = std.heap.ArenaAllocator.init(gpa),
            .root = .{},
            .mws = .empty,
            .route_list = .empty,
        };
    }

    pub fn deinit(r: *Router) void {
        r.arena.deinit();
        r.* = undefined;
    }

    /// Append router-level middleware (outermost = first registered). Must
    /// precede all route registration.
    pub fn use(r: *Router, mw: Middleware) UseError!void {
        if (r.routes_added) return error.RoutesAlreadyRegistered;
        try r.mws.append(r.arena.allocator(), mw);
    }

    /// Register `(method, pattern) → handler`. Pattern grammar: `/`-joined
    /// segments; `:name` captures one non-empty segment; a final `*name`
    /// captures the whole remainder. See the module doc for precedence.
    pub fn add(r: *Router, method: http.Method, pattern: []const u8, h: Handler) AddError!void {
        return addRoute(r, null, method, pattern, h, null);
    }

    /// `add` with attached documentation metadata. `doc` is deep-copied
    /// into the router's arena — stack temporaries are safe.
    pub fn addDoc(r: *Router, method: http.Method, pattern: []const u8, h: Handler, doc: RouteDoc) AddError!void {
        return addRoute(r, null, method, pattern, h, doc);
    }

    /// All registered routes, in registration order (deterministic). The
    /// slice and everything it references are router-owned (arena) — valid
    /// until `deinit`, do not free; a later `add` may grow (reallocate) the
    /// slice, so re-fetch after registering. Group routes appear with their
    /// full (prefixed) pattern.
    pub fn routes(r: *const Router) []const Route {
        return r.route_list.items;
    }

    pub fn get(r: *Router, pattern: []const u8, h: Handler) AddError!void {
        return r.add(.get, pattern, h);
    }
    pub fn post(r: *Router, pattern: []const u8, h: Handler) AddError!void {
        return r.add(.post, pattern, h);
    }
    pub fn put(r: *Router, pattern: []const u8, h: Handler) AddError!void {
        return r.add(.put, pattern, h);
    }
    pub fn delete(r: *Router, pattern: []const u8, h: Handler) AddError!void {
        return r.add(.delete, pattern, h);
    }
    pub fn patch(r: *Router, pattern: []const u8, h: Handler) AddError!void {
        return r.add(.patch, pattern, h);
    }
    pub fn head(r: *Router, pattern: []const u8, h: Handler) AddError!void {
        return r.add(.head, pattern, h);
    }
    pub fn options(r: *Router, pattern: []const u8, h: Handler) AddError!void {
        return r.add(.options, pattern, h);
    }

    /// A prefixed sub-router with its own middleware. Routes added through
    /// the group get `prefix ++ pattern` and the chain router-mws + group
    /// mws (root→leaf for nested groups). The Group is arena-owned — no
    /// separate deinit.
    pub fn group(r: *Router, prefix: []const u8) GroupError!*Group {
        return makeGroup(r, null, prefix);
    }

    /// The `http.Server.Handler` adapter. Wire it as
    /// `Server.init(io, gpa, .{ .handler = router.handler(), .context = &router })`
    /// — the server's `context` MUST be the Router. Works identically
    /// against the socket-free `http.Server.serveStream`.
    pub fn handler(_: *const Router) http.Server.Handler {
        return serverAdapter;
    }

    /// Route one already-parsed request. This is the whole runtime: find
    /// the endpoint (or 404/405/redirect) and run its middleware chain.
    /// Read-only — safe concurrently once building is done.
    pub fn dispatch(r: *Router, req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
        // Non-origin-form targets ("*" from OPTIONS) route nowhere.
        if (req.path.len == 0 or req.path[0] != '/')
            return r.runFallback(req, rw, r.not_found);

        var params: Params = .{};
        if (matchRec(&r.root, req.path[1..], false, &params)) |node| {
            if (endpointFor(node, req.method)) |ep| {
                var ctx: Ctx = .{
                    .req = req,
                    .res = rw,
                    .params = params,
                    .state = r.state,
                    .matched_pattern = ep.pattern,
                };
                const next: Next = .{ .chain = ep.chain, .endpoint = ep.handler };
                return next.run(&ctx);
            }
            // Path exists, method doesn't: 405 (or auto-204 for OPTIONS).
            // Allow goes on first so an overridden handler inherits it.
            try rw.setHeader("Allow", node.allow);
            // No explicit OPTIONS endpoint reached endpointFor above, so when
            // auto_options is on we synthesize a 204 here instead of a 405.
            const endpoint = if (r.auto_options and req.method == .options)
                defaultAutoOptions
            else
                r.method_not_allowed;
            var ctx: Ctx = .{ .req = req, .res = rw, .params = params, .state = r.state };
            const next: Next = .{ .chain = r.mws.items, .endpoint = endpoint };
            return next.run(&ctx);
        }

        if (r.trailing_slash == .redirect)
            if (try r.tryRedirect(req, rw)) return;

        return r.runFallback(req, rw, r.not_found);
    }

    fn runFallback(r: *Router, req: *http.Server.Request, rw: *http.Server.ResponseWriter, h: Handler) anyerror!void {
        var ctx: Ctx = .{ .req = req, .res = rw, .params = .{}, .state = r.state };
        const next: Next = .{ .chain = r.mws.items, .endpoint = h };
        return next.run(&ctx);
    }

    /// Probe the other trailing-slash variant; when it has this route,
    /// answer 301 (GET/HEAD) / 308 with a Location preserving the query.
    /// Paths beyond the fixed buffer just fall through to 404.
    fn tryRedirect(r: *Router, req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!bool {
        const path = req.path;
        var probe: Params = .{};
        var loc_buf: [4096]u8 = undefined;
        var w: std.Io.Writer = .fixed(&loc_buf);
        if (path.len > 1 and path[path.len - 1] == '/') {
            const alt = path[0 .. path.len - 1];
            const node = matchRec(&r.root, alt[1..], false, &probe) orelse return false;
            if (endpointFor(node, req.method) == null) return false;
            w.writeAll(alt) catch return false;
        } else {
            // Match with one virtual "" segment appended = the path + "/".
            const node = matchRec(&r.root, path[1..], true, &probe) orelse return false;
            if (endpointFor(node, req.method) == null) return false;
            w.print("{s}/", .{path}) catch return false;
        }
        if (req.query.len != 0) w.print("?{s}", .{req.query}) catch return false;

        rw.setStatus(if (req.method == .get or req.method == .head) 301 else 308);
        try rw.setHeader("Location", w.buffered());
        // The Location value points into this stack frame — put the head on
        // the wire now (end() is idempotent; the serving loop's end() and
        // flush still run).
        try rw.end();
        return true;
    }

    // ── registration internals ──────────────────────────────────────────

    fn addRoute(r: *Router, g: ?*Group, method: http.Method, pattern: []const u8, h: Handler, doc: ?RouteDoc) AddError!void {
        if (pattern.len == 0 or pattern[0] != '/') return error.InvalidPattern;
        const a = r.arena.allocator();
        // Arena-duplicated: the full pattern is stored in the route table
        // and stashed as Ctx.matched_pattern — the caller's slice may be a
        // stack temporary.
        const full = if (g) |gr|
            try std.mem.concat(a, u8, &.{ gr.prefix, pattern })
        else
            try a.dupe(u8, pattern);
        const chain = try r.buildChain(g);
        const doc_copy: ?*const RouteDoc = if (doc) |d| try dupeDoc(a, d) else null;
        try r.insert(method, full, h, chain);
        try r.route_list.append(a, .{ .method = method, .pattern = full, .doc = doc_copy });
        r.routes_added = true;
        var it: ?*Group = g;
        while (it) |gr| : (it = gr.parent) gr.routes_added = true;
    }

    /// Deep-copy a RouteDoc into the arena (strings, tags, responses), so
    /// callers may pass stack temporaries.
    fn dupeDoc(a: Allocator, d: RouteDoc) Allocator.Error!*const RouteDoc {
        const tags = try a.alloc([]const u8, d.tags.len);
        for (tags, d.tags) |*slot, t| slot.* = try a.dupe(u8, t);
        const responses = try a.alloc(RouteDoc.Response, d.responses.len);
        for (responses, d.responses) |*slot, resp| slot.* = .{
            .status = resp.status,
            .description = try a.dupe(u8, resp.description),
        };
        const copy = try a.create(RouteDoc);
        copy.* = .{
            .summary = if (d.summary) |s| try a.dupe(u8, s) else null,
            .description = if (d.description) |s| try a.dupe(u8, s) else null,
            .tags = tags,
            .request_schema = if (d.request_schema) |s| try a.dupe(u8, s) else null,
            .responses = responses,
            .deprecated = d.deprecated,
        };
        return copy;
    }

    /// Concatenate router-mws ++ group-mws (root→leaf) into an arena-owned
    /// chain, frozen into the route.
    fn buildChain(r: *Router, g: ?*Group) Allocator.Error![]const Middleware {
        const a = r.arena.allocator();
        var total: usize = r.mws.items.len;
        var it: ?*const Group = g;
        while (it) |gr| : (it = gr.parent) total += gr.mws.items.len;

        const chain = try a.alloc(Middleware, total);
        @memcpy(chain[0..r.mws.items.len], r.mws.items);
        // Fill groups back-to-front: leaf-to-root iteration writes the leaf
        // (innermost) last.
        var off = total;
        it = g;
        while (it) |gr| : (it = gr.parent) {
            off -= gr.mws.items.len;
            @memcpy(chain[off..][0..gr.mws.items.len], gr.mws.items);
        }
        return chain;
    }

    /// Walk/extend the trie along `pattern`'s segments and place the
    /// endpoint. All stored strings are arena-duplicated.
    fn insert(r: *Router, method: http.Method, pattern: []const u8, h: Handler, chain: []const Middleware) AddError!void {
        const a = r.arena.allocator();
        var node: *Node = &r.root;
        var nparams: usize = 0;
        var rest: ?[]const u8 = pattern[1..];
        while (rest) |cur| {
            var seg = cur;
            var next: ?[]const u8 = null;
            if (std.mem.indexOfScalar(u8, cur, '/')) |i| {
                seg = cur[0..i];
                next = cur[i + 1 ..];
            }
            if (seg.len != 0 and seg[0] == '*') {
                const name = seg[1..];
                if (name.len == 0 or next != null) return error.InvalidPattern;
                if (std.mem.indexOfAny(u8, name, ":*") != null) return error.InvalidPattern;
                nparams += 1;
                if (nparams > max_params) return error.TooManyParams;
                if (node.wildcard) |wc| {
                    if (!std.mem.eql(u8, wc.name, name)) return error.ParamNameConflict;
                    node = wc.node;
                } else {
                    const child = try a.create(Node);
                    child.* = .{};
                    node.wildcard = .{ .name = try a.dupe(u8, name), .node = child };
                    node = child;
                }
                rest = null;
            } else if (seg.len != 0 and seg[0] == ':') {
                const name = seg[1..];
                if (name.len == 0) return error.InvalidPattern;
                if (std.mem.indexOfAny(u8, name, ":*") != null) return error.InvalidPattern;
                nparams += 1;
                if (nparams > max_params) return error.TooManyParams;
                if (node.param) |p| {
                    if (!std.mem.eql(u8, p.name, name)) return error.ParamNameConflict;
                    node = p.node;
                } else {
                    const child = try a.create(Node);
                    child.* = .{};
                    node.param = .{ .name = try a.dupe(u8, name), .node = child };
                    node = child;
                }
                rest = next;
            } else {
                if (std.mem.indexOfAny(u8, seg, ":*") != null) return error.InvalidPattern;
                if (node.static.get(seg)) |child| {
                    node = child;
                } else {
                    const child = try a.create(Node);
                    child.* = .{};
                    try node.static.put(a, try a.dupe(u8, seg), child);
                    node = child;
                }
                rest = next;
            }
        }
        const idx = @intFromEnum(method);
        if (node.endpoints[idx] != null) return error.DuplicateRoute;
        node.endpoints[idx] = .{ .handler = h, .chain = chain, .pattern = pattern };
        try r.rebuildAllow(node);
    }

    /// Recompute the node's `Allow` value: registered methods in
    /// `http.Method` order, HEAD implied by GET.
    fn rebuildAllow(r: *Router, node: *Node) error{OutOfMemory}!void {
        var buf: [64]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        const has_get = node.endpoints[@intFromEnum(http.Method.get)] != null;
        inline for (@typeInfo(http.Method).@"enum".fields, 0..) |f, i| {
            const m: http.Method = @enumFromInt(f.value);
            if (node.endpoints[i] != null or (m == .head and has_get)) {
                if (w.end != 0) w.writeAll(", ") catch unreachable;
                w.writeAll(comptime m.token()) catch unreachable;
            }
        }
        node.allow = try r.arena.allocator().dupe(u8, w.buffered());
    }
};

/// A prefixed sub-router (see `Router.group`). Arena-owned; all methods
/// mirror the Router's.
pub const Group = struct {
    router: *Router,
    parent: ?*Group,
    /// Full accumulated prefix (parents included), arena-owned.
    prefix: []const u8,
    /// This group's own middleware (parents' are collected at add time).
    mws: std.ArrayList(Middleware),
    routes_added: bool,

    /// Append group middleware; must precede routes added through this
    /// group (or its children).
    pub fn use(g: *Group, mw: Middleware) UseError!void {
        if (g.routes_added) return error.RoutesAlreadyRegistered;
        try g.mws.append(g.router.arena.allocator(), mw);
    }

    pub fn add(g: *Group, method: http.Method, pattern: []const u8, h: Handler) AddError!void {
        return Router.addRoute(g.router, g, method, pattern, h, null);
    }

    /// `add` with attached documentation metadata (see `Router.addDoc`).
    pub fn addDoc(g: *Group, method: http.Method, pattern: []const u8, h: Handler, doc: RouteDoc) AddError!void {
        return Router.addRoute(g.router, g, method, pattern, h, doc);
    }

    pub fn get(g: *Group, pattern: []const u8, h: Handler) AddError!void {
        return g.add(.get, pattern, h);
    }
    pub fn post(g: *Group, pattern: []const u8, h: Handler) AddError!void {
        return g.add(.post, pattern, h);
    }
    pub fn put(g: *Group, pattern: []const u8, h: Handler) AddError!void {
        return g.add(.put, pattern, h);
    }
    pub fn delete(g: *Group, pattern: []const u8, h: Handler) AddError!void {
        return g.add(.delete, pattern, h);
    }
    pub fn patch(g: *Group, pattern: []const u8, h: Handler) AddError!void {
        return g.add(.patch, pattern, h);
    }
    pub fn head(g: *Group, pattern: []const u8, h: Handler) AddError!void {
        return g.add(.head, pattern, h);
    }
    pub fn options(g: *Group, pattern: []const u8, h: Handler) AddError!void {
        return g.add(.options, pattern, h);
    }

    /// A nested group: prefixes and middleware accumulate.
    pub fn group(g: *Group, prefix: []const u8) GroupError!*Group {
        return makeGroup(g.router, g, prefix);
    }
};

fn makeGroup(r: *Router, parent: ?*Group, prefix: []const u8) GroupError!*Group {
    if (prefix.len < 2 or prefix[0] != '/' or prefix[prefix.len - 1] == '/')
        return error.InvalidPrefix;
    const a = r.arena.allocator();
    const g = try a.create(Group);
    g.* = .{
        .router = r,
        .parent = parent,
        .prefix = try std.mem.concat(a, u8, &.{ if (parent) |p| p.prefix else "", prefix }),
        .mws = .empty,
        .routes_added = false,
    };
    return g;
}

fn serverAdapter(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    const r: *Router = @ptrCast(@alignCast(req.context.?));
    return r.dispatch(req, rw);
}

fn defaultNotFound(ctx: *Ctx) anyerror!void {
    ctx.res.setStatus(404);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Not Found\n");
}

fn defaultMethodNotAllowed(ctx: *Ctx) anyerror!void {
    // dispatch already set the Allow header.
    ctx.res.setStatus(405);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Method Not Allowed\n");
}

fn defaultAutoOptions(ctx: *Ctx) anyerror!void {
    // dispatch already set the Allow header; 204 carries no body.
    ctx.res.setStatus(204);
}

// ── the matcher ─────────────────────────────────────────────────────────────

/// One trie level = one path segment. A trailing slash is a normal (empty)
/// static segment, so `/x` and `/x/` are naturally distinct routes.
const Node = struct {
    static: std.StringArrayHashMapUnmanaged(*Node) = .empty,
    param: ?Edge = null,
    wildcard: ?Edge = null,
    endpoints: [method_count]?Endpoint = @splat(null),
    /// Precomputed Allow header value (non-empty iff any endpoint).
    allow: []const u8 = "",

    const Edge = struct { name: []const u8, node: *Node };

    fn hasEndpoint(n: *const Node) bool {
        for (n.endpoints) |ep| {
            if (ep != null) return true;
        }
        return false;
    }
};

const Endpoint = struct {
    handler: Handler,
    chain: []const Middleware,
    /// Full arena-owned route pattern (what `Ctx.matchedPattern` reports).
    pattern: []const u8,
};

fn endpointFor(node: *const Node, method: http.Method) ?Endpoint {
    if (node.endpoints[@intFromEnum(method)]) |ep| return ep;
    if (method == .head) return node.endpoints[@intFromEnum(http.Method.get)];
    return null;
}

/// Segment-wise recursive match with backtracking: try the static child,
/// then the param child (non-empty segments only), then the wildcard —
/// each only counts when the remainder also matches a node that has at
/// least one endpoint (so an endpoint-less static prefix falls back to a
/// param sibling). `rest` is the remaining path after the leading '/';
/// null = all segments consumed. `extra` appends one virtual "" segment
/// (used to probe `path ++ "/"` without building the string). Recursion
/// depth = segment count, bounded by the server's max_header_bytes.
fn matchRec(node: *const Node, rest: ?[]const u8, extra: bool, params: *Params) ?*const Node {
    const r = rest orelse {
        if (extra) return matchRec(node, "", false, params);
        return if (node.hasEndpoint()) node else null;
    };
    var seg = r;
    var next: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, r, '/')) |i| {
        seg = r[0..i];
        next = r[i + 1 ..];
    }
    if (node.static.get(seg)) |child| {
        if (matchRec(child, next, extra, params)) |n| return n;
    }
    if (seg.len != 0) if (node.param) |p| {
        const saved = params.len;
        params.push(p.name, seg);
        if (matchRec(p.node, next, extra, params)) |n| return n;
        params.len = saved;
    };
    if (node.wildcard) |wc| {
        if (wc.node.hasEndpoint()) {
            params.push(wc.name, r);
            return wc.node;
        }
    }
    return null;
}

// ── tests (offline — through http.Server.serveStream, no socket) ────────────

const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Drive the router through the socket-free server codec with canned wire
/// bytes; returns the full response byte stream.
fn runWire(r: *Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null, // keep goldens free of Server/Date noise
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn wire(comptime method: []const u8, comptime target: []const u8) []const u8 {
    return method ++ " " ++ target ++ " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
}

fn expectStatus(got: []const u8, comptime status: []const u8) !void {
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 " ++ status));
}

fn expectHeaderLine(got: []const u8, comptime line: []const u8) !void {
    try testing.expect(std.mem.indexOf(u8, got, "\r\n" ++ line ++ "\r\n") != null);
}

fn bodyOf(got: []const u8) []const u8 {
    return got[std.mem.indexOf(u8, got, "\r\n\r\n").? + 4 ..];
}

// Test handlers.
fn hRoot(ctx: *Ctx) anyerror!void {
    try ctx.res.writeAll("root");
}
fn hHello(ctx: *Ctx) anyerror!void {
    try ctx.res.writeAll("hello");
}
fn hCreated(ctx: *Ctx) anyerror!void {
    ctx.res.setStatus(201);
    try ctx.res.writeAll("created");
}
fn hUser(ctx: *Ctx) anyerror!void {
    try ctx.res.writeAll("user=");
    try ctx.res.writeAll(ctx.params.get("id").?);
}
fn hBook(ctx: *Ctx) anyerror!void {
    try ctx.res.writeAll(ctx.params.get("id").?);
    try ctx.res.writeAll(",");
    try ctx.res.writeAll(ctx.params.get("bid").?);
    // Absent name → null (not a crash, not "").
    try testing.expectEqual(@as(?[]const u8, null), ctx.params.get("nope"));
}
fn hWildPath(ctx: *Ctx) anyerror!void {
    try ctx.res.writeAll("w=");
    try ctx.res.writeAll(ctx.params.get("path").?);
}
fn hS(ctx: *Ctx) anyerror!void {
    try ctx.res.writeAll("S");
}
fn hP(ctx: *Ctx) anyerror!void {
    try ctx.res.writeAll("P:");
    try ctx.res.writeAll(ctx.params.get("name").?);
}
fn hW(ctx: *Ctx) anyerror!void {
    try ctx.res.writeAll("W:");
    try ctx.res.writeAll(ctx.params.get("rest").?);
}
fn hQuery(ctx: *Ctx) anyerror!void {
    try ctx.res.writeAll("q=");
    try ctx.res.writeAll(ctx.req.query);
}
fn hExplicitHead(ctx: *Ctx) anyerror!void {
    try ctx.res.setHeader("X-Explicit-Head", "1");
}
fn hNfCustom(ctx: *Ctx) anyerror!void {
    ctx.res.setStatus(404);
    try ctx.res.writeAll("custom-nf");
}
fn hMnaCustom(ctx: *Ctx) anyerror!void {
    ctx.res.setStatus(405);
    try ctx.res.writeAll("custom-mna");
}

// Middleware order recording — via Ctx.state, zero process globals.
const Trace = struct {
    buf: [64]u8 = undefined,
    len: usize = 0,

    fn mark(t: *Trace, c: u8) void {
        t.buf[t.len] = c;
        t.len += 1;
    }
    fn get(t: *const Trace) []const u8 {
        return t.buf[0..t.len];
    }
    fn of(ctx: *Ctx) *Trace {
        return @ptrCast(@alignCast(ctx.state.?));
    }
};

fn hTrace(ctx: *Ctx) anyerror!void {
    Trace.of(ctx).mark('H');
    try ctx.res.writeAll("ok");
}
fn mwA(_: ?*anyopaque, ctx: *Ctx, next: Next) anyerror!void {
    Trace.of(ctx).mark('A');
    try next.run(ctx);
    Trace.of(ctx).mark('a');
}
fn mwB(_: ?*anyopaque, ctx: *Ctx, next: Next) anyerror!void {
    Trace.of(ctx).mark('B');
    try next.run(ctx);
    Trace.of(ctx).mark('b');
}
fn mwG(_: ?*anyopaque, ctx: *Ctx, next: Next) anyerror!void {
    Trace.of(ctx).mark('G');
    try next.run(ctx);
    Trace.of(ctx).mark('g');
}
fn mwV(_: ?*anyopaque, ctx: *Ctx, next: Next) anyerror!void {
    Trace.of(ctx).mark('V');
    try next.run(ctx);
    Trace.of(ctx).mark('v');
}
fn mwDeny(_: ?*anyopaque, ctx: *Ctx, next: Next) anyerror!void {
    _ = next; // short-circuit: never reaches the handler
    Trace.of(ctx).mark('D');
    ctx.res.setStatus(403);
    try ctx.res.writeAll("denied");
}
fn mwCount(state: ?*anyopaque, ctx: *Ctx, next: Next) anyerror!void {
    const n: *u32 = @ptrCast(@alignCast(state.?));
    n.* += 1;
    try next.run(ctx);
}
fn mwStamp(_: ?*anyopaque, ctx: *Ctx, next: Next) anyerror!void {
    try ctx.res.setHeader("X-Router", "v1");
    try next.run(ctx);
}

test "static routes: golden dispatch by method and path" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/", hRoot);
    try r.get("/hello", hHello);
    try r.post("/hello", hCreated);

    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 5\r\n" ++
        "\r\n" ++
        "hello", runWire(&r, wire("GET", "/hello"), &buf));
    try testing.expectEqualStrings("root", bodyOf(runWire(&r, wire("GET", "/"), &buf)));
    const posted = runWire(&r, wire("POST", "/hello"), &buf);
    try expectStatus(posted, "201");
    try testing.expectEqualStrings("created", bodyOf(posted));
}

test "params: single and multiple, values into the path" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/users/:id", hUser);
    // Same position must reuse the same param name (":uid" here would be
    // error.ParamNameConflict — httprouter semantics).
    try r.get("/users/:id/books/:bid", hBook);

    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("user=42", bodyOf(runWire(&r, wire("GET", "/users/42"), &buf)));
    try testing.expectEqualStrings("7,neuromancer", bodyOf(runWire(&r, wire("GET", "/users/7/books/neuromancer"), &buf)));
}

test "wildcard captures the remainder (possibly empty)" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/static/*path", hWildPath);

    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("w=css/app.css", bodyOf(runWire(&r, wire("GET", "/static/css/app.css"), &buf)));
    try testing.expectEqualStrings("w=", bodyOf(runWire(&r, wire("GET", "/static/"), &buf)));
}

test "precedence: static > param > wildcard" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/files/readme", hS);
    try r.get("/files/:name", hP);
    try r.get("/files/*rest", hW);

    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("S", bodyOf(runWire(&r, wire("GET", "/files/readme"), &buf)));
    try testing.expectEqualStrings("P:notes", bodyOf(runWire(&r, wire("GET", "/files/notes"), &buf)));
    // Two segments: param (one segment) can't take it → wildcard.
    try testing.expectEqualStrings("W:a/b", bodyOf(runWire(&r, wire("GET", "/files/a/b"), &buf)));
}

test "backtracking: endpoint-less static prefix falls back to param" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/users/:id", hUser);
    try r.get("/users/new/edit", hS); // creates endpoint-less "new" node

    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("S", bodyOf(runWire(&r, wire("GET", "/users/new/edit"), &buf)));
    // "new" node exists but has no endpoint → :id serves it.
    try testing.expectEqualStrings("user=new", bodyOf(runWire(&r, wire("GET", "/users/new"), &buf)));
}

test "404: golden default and override" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/hello", hHello);

    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 404 Not Found\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 10\r\n" ++
        "\r\n" ++
        "Not Found\n", runWire(&r, wire("GET", "/nope"), &buf));

    r.not_found = hNfCustom;
    const got = runWire(&r, wire("GET", "/nope"), &buf);
    try expectStatus(got, "404");
    try testing.expectEqualStrings("custom-nf", bodyOf(got));
}

test "405: Allow lists registered methods (HEAD implied by GET); override keeps Allow" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/thing", hHello);
    try r.post("/thing", hCreated);
    try r.delete("/thing", hHello);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, wire("PATCH", "/thing"), &buf);
    try testing.expectEqualStrings("HTTP/1.1 405 Method Not Allowed\r\n" ++
        "Allow: GET, HEAD, POST, DELETE\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 19\r\n" ++
        "\r\n" ++
        "Method Not Allowed\n", got);

    r.method_not_allowed = hMnaCustom;
    const got2 = runWire(&r, wire("PUT", "/thing"), &buf);
    try expectStatus(got2, "405");
    try expectHeaderLine(got2, "Allow: GET, HEAD, POST, DELETE");
    try testing.expectEqualStrings("custom-mna", bodyOf(got2));
}

test "405 without GET: Allow has no implied HEAD" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.post("/submit", hCreated);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, wire("GET", "/submit"), &buf);
    try expectStatus(got, "405");
    try expectHeaderLine(got, "Allow: POST");
}

test "auto_options off (default): OPTIONS on a routed path is a 405" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/thing", hHello);
    try r.post("/thing", hCreated);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, wire("OPTIONS", "/thing"), &buf);
    try expectStatus(got, "405");
    try expectHeaderLine(got, "Allow: GET, HEAD, POST");
}

test "auto_options on: OPTIONS → 204 with Allow; runs router middleware" {
    var count: u32 = 0;
    var r = Router.init(testing.allocator);
    defer r.deinit();
    r.auto_options = true;
    try r.use(.{ .state = &count, .run = mwCount });
    try r.get("/thing", hHello);
    try r.post("/thing", hCreated);
    try r.delete("/thing", hHello);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, wire("OPTIONS", "/thing"), &buf);
    try expectStatus(got, "204");
    try expectHeaderLine(got, "Allow: GET, HEAD, POST, DELETE");
    // Router-level middleware wraps the auto-OPTIONS response (like 404/405).
    try testing.expectEqual(@as(u32, 1), count);

    // A non-OPTIONS wrong method on the same path is still a 405.
    try expectStatus(runWire(&r, wire("PATCH", "/thing"), &buf), "405");
}

test "auto_options on: an explicit OPTIONS handler still wins" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    r.auto_options = true;
    try r.get("/thing", hHello);
    try r.options("/thing", hCreated); // explicit → 201 "created", not 204

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, wire("OPTIONS", "/thing"), &buf);
    try expectStatus(got, "201");
    try testing.expectEqualStrings("created", bodyOf(got));
}

test "HEAD auto-routes to GET; explicit HEAD route wins" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/hello", hHello);
    try r.get("/both", hHello);
    try r.head("/both", hExplicitHead);

    var buf: [1024]u8 = undefined;
    // GET framing (Content-Length: 5) with no body bytes.
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 5\r\n" ++
        "\r\n", runWire(&r, wire("HEAD", "/hello"), &buf));

    const got = runWire(&r, wire("HEAD", "/both"), &buf);
    try expectStatus(got, "200");
    try expectHeaderLine(got, "X-Explicit-Head: 1");
}

test "trailing slash: redirect policy (301 GET / 308 other, query preserved)" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/users/:id", hUser);
    try r.post("/users/:id", hCreated);
    try r.get("/static/*path", hWildPath);
    try r.get("/docs/", hHello); // registered WITH the slash

    var buf: [1024]u8 = undefined;
    // Extra slash → 301 to the slashless route.
    const got = runWire(&r, wire("GET", "/users/42/"), &buf);
    try expectStatus(got, "301");
    try expectHeaderLine(got, "Location: /users/42");
    // Query survives the redirect.
    const gotq = runWire(&r, wire("GET", "/users/42/?x=1&y=2"), &buf);
    try expectStatus(gotq, "301");
    try expectHeaderLine(gotq, "Location: /users/42?x=1&y=2");
    // Non-GET → 308.
    const gotp = runWire(&r, wire("POST", "/users/42/"), &buf);
    try expectStatus(gotp, "308");
    try expectHeaderLine(gotp, "Location: /users/42");
    // Missing slash → 301 toward the registered slash variant.
    const gotd = runWire(&r, wire("GET", "/docs"), &buf);
    try expectStatus(gotd, "301");
    try expectHeaderLine(gotd, "Location: /docs/");
    // Wildcard root: /static → /static/ (httprouter behavior).
    const gots = runWire(&r, wire("GET", "/static"), &buf);
    try expectStatus(gots, "301");
    try expectHeaderLine(gots, "Location: /static/");
    // No redirect when the method wouldn't be served there either.
    try expectStatus(runWire(&r, wire("DELETE", "/docs"), &buf), "404");
}

test "trailing slash: strict policy and distinct slash routes" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    r.trailing_slash = .strict;
    try r.get("/a", hS);
    try r.get("/b/", hHello);

    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("S", bodyOf(runWire(&r, wire("GET", "/a"), &buf)));
    // No slash tolerance in either direction.
    try expectStatus(runWire(&r, wire("GET", "/a/"), &buf), "404");
    try expectStatus(runWire(&r, wire("GET", "/b"), &buf), "404");
}

test "trailing slash: /x and /x/ can be two real routes (no redirect between)" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/a", hS);
    try r.get("/a/", hRoot);

    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("S", bodyOf(runWire(&r, wire("GET", "/a"), &buf)));
    try testing.expectEqualStrings("root", bodyOf(runWire(&r, wire("GET", "/a/"), &buf)));
}

test "params never match empty segments" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/users/:id", hUser);

    var buf: [1024]u8 = undefined;
    // "/users/" has an empty final segment; :id refuses it, no probe target
    // exists ("/users" is endpoint-less) → 404.
    try expectStatus(runWire(&r, wire("GET", "/users/"), &buf), "404");
    try expectStatus(runWire(&r, wire("GET", "/users//"), &buf), "404");
}

test "middleware: outer→inner deterministic order, recorded via ctx.state" {
    var trace: Trace = .{};
    var r = Router.init(testing.allocator);
    defer r.deinit();
    r.state = &trace;
    try r.use(.{ .run = mwA });
    try r.use(.{ .run = mwB });
    try r.get("/t", hTrace);

    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("ok", bodyOf(runWire(&r, wire("GET", "/t"), &buf)));
    try testing.expectEqualStrings("ABHba", trace.get());
}

test "middleware: short-circuit skips inner middleware and the handler" {
    var trace: Trace = .{};
    var r = Router.init(testing.allocator);
    defer r.deinit();
    r.state = &trace;
    try r.use(.{ .run = mwA });
    try r.use(.{ .run = mwDeny });
    try r.use(.{ .run = mwB }); // never reached
    try r.get("/t", hTrace);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, wire("GET", "/t"), &buf);
    try expectStatus(got, "403");
    try testing.expectEqualStrings("denied", bodyOf(got));
    try testing.expectEqualStrings("ADa", trace.get());
}

test "middleware: per-instance state (the ratelimit/metrics hook)" {
    var count: u32 = 0;
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.use(.{ .state = &count, .run = mwCount });
    try r.get("/t", hHello);

    var buf: [1024]u8 = undefined;
    _ = runWire(&r, wire("GET", "/t"), &buf);
    _ = runWire(&r, wire("GET", "/t"), &buf);
    try testing.expectEqual(@as(u32, 2), count);
}

test "middleware: response headers set by middleware reach the wire" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.use(.{ .run = mwStamp });
    try r.get("/t", hHello);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, wire("GET", "/t"), &buf);
    try expectHeaderLine(got, "X-Router: v1");
    try testing.expectEqualStrings("hello", bodyOf(got));
}

test "middleware: router-level chain also wraps 404 and 405" {
    var count: u32 = 0;
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.use(.{ .state = &count, .run = mwCount });
    try r.get("/only-get", hHello);

    var buf: [1024]u8 = undefined;
    try expectStatus(runWire(&r, wire("GET", "/nope"), &buf), "404");
    try expectStatus(runWire(&r, wire("POST", "/only-get"), &buf), "405");
    try testing.expectEqual(@as(u32, 2), count);
}

test "use after a route → error.RoutesAlreadyRegistered" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/t", hHello);
    try testing.expectError(error.RoutesAlreadyRegistered, r.use(.{ .run = mwA }));

    // Group routes freeze the router-level chain too.
    var r2 = Router.init(testing.allocator);
    defer r2.deinit();
    const g = try r2.group("/api");
    try g.get("/t", hHello);
    try testing.expectError(error.RoutesAlreadyRegistered, r2.use(.{ .run = mwA }));
    try testing.expectError(error.RoutesAlreadyRegistered, g.use(.{ .run = mwA }));
}

test "groups: prefixes nest; middleware order router→group→subgroup→handler" {
    var trace: Trace = .{};
    var r = Router.init(testing.allocator);
    defer r.deinit();
    r.state = &trace;
    try r.use(.{ .run = mwA });
    const api = try r.group("/api");
    try api.use(.{ .run = mwG });
    const v1 = try api.group("/v1");
    try v1.use(.{ .run = mwV });
    try v1.get("/things/:id", hTrace);
    try r.get("/plain", hTrace); // non-group route: no G/V

    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("ok", bodyOf(runWire(&r, wire("GET", "/api/v1/things/7"), &buf)));
    try testing.expectEqualStrings("AGVHvga", trace.get());

    trace = .{};
    try testing.expectEqualStrings("ok", bodyOf(runWire(&r, wire("GET", "/plain"), &buf)));
    try testing.expectEqualStrings("AHa", trace.get());

    // The group prefix alone is not a route.
    try expectStatus(runWire(&r, wire("GET", "/api/v1"), &buf), "404");
}

test "groups: params work inside prefixes and patterns" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    const g = try r.group("/users/:id");
    try g.get("/profile", hUser);

    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("user=42", bodyOf(runWire(&r, wire("GET", "/users/42/profile"), &buf)));
}

test "groups: prefix validation" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try testing.expectError(error.InvalidPrefix, r.group("api"));
    try testing.expectError(error.InvalidPrefix, r.group("/api/"));
    try testing.expectError(error.InvalidPrefix, r.group("/"));
    try testing.expectError(error.InvalidPrefix, r.group(""));
}

test "add: pattern validation, duplicates, param conflicts, caps" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try testing.expectError(error.InvalidPattern, r.get("nope", hHello));
    try testing.expectError(error.InvalidPattern, r.get("", hHello));
    try testing.expectError(error.InvalidPattern, r.get("/x/:", hHello)); // empty param name
    try testing.expectError(error.InvalidPattern, r.get("/x/*", hHello)); // empty wildcard name
    try testing.expectError(error.InvalidPattern, r.get("/x/*w/y", hHello)); // wildcard not last
    try testing.expectError(error.InvalidPattern, r.get("/x/a:b", hHello)); // ':' inside a segment
    try testing.expectError(error.InvalidPattern, r.get("/x/a*b", hHello)); // '*' inside a segment

    try r.get("/dup", hHello);
    try testing.expectError(error.DuplicateRoute, r.get("/dup", hRoot));
    try r.post("/dup", hCreated); // same pattern, other method: fine

    try r.get("/u/:id", hUser);
    try testing.expectError(error.ParamNameConflict, r.get("/u/:name", hHello));
    try r.get("/w/*rest", hW);
    try testing.expectError(error.ParamNameConflict, r.get("/w/*tail", hHello));

    try testing.expectError(error.TooManyParams, r.get("/:p" ** (max_params + 1), hHello));
}

// ── tests: route enumeration + matched pattern ──────────────────────────────

fn hMatchedUser(ctx: *Ctx) anyerror!void {
    // A failed expectation errors → 500, so the 200 assertion below proves it.
    try testing.expectEqualStrings("/users/:id", ctx.matchedPattern().?);
    try ctx.res.writeAll("ok");
}
fn hMatchedWild(ctx: *Ctx) anyerror!void {
    try testing.expectEqualStrings("/static/*path", ctx.matchedPattern().?);
    try ctx.res.writeAll("ok");
}
fn hNfNullPattern(ctx: *Ctx) anyerror!void {
    try testing.expectEqual(@as(?[]const u8, null), ctx.matchedPattern());
    ctx.res.setStatus(404);
    try ctx.res.writeAll("nf");
}
fn hMnaNullPattern(ctx: *Ctx) anyerror!void {
    try testing.expectEqual(@as(?[]const u8, null), ctx.matchedPattern());
    ctx.res.setStatus(405);
    try ctx.res.writeAll("mna");
}
fn mwSeesPattern(_: ?*anyopaque, ctx: *Ctx, next: Next) anyerror!void {
    // Middleware run before the handler already see the stashed pattern.
    if (ctx.matchedPattern()) |p| try testing.expect(p[0] == '/');
    try next.run(ctx);
}

test "routes(): registration-order enumeration with docs and group prefixes" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/hello", hHello);
    try r.addDoc(.post, "/users", hCreated, .{
        .summary = "Create a user",
        .description = "Creates one user.",
        .tags = &.{ "users", "write" },
        .request_schema = "{\"type\":\"object\"}",
        .responses = &.{.{ .status = 201, .description = "Created" }},
    });
    const api = try r.group("/api");
    try api.get("/things/:id", hUser);
    try api.addDoc(.delete, "/things/:id", hUser, .{ .deprecated = true });

    const rs = r.routes();
    try testing.expectEqual(@as(usize, 4), rs.len);

    try testing.expectEqual(http.Method.get, rs[0].method);
    try testing.expectEqualStrings("/hello", rs[0].pattern);
    try testing.expect(rs[0].doc == null);

    try testing.expectEqual(http.Method.post, rs[1].method);
    try testing.expectEqualStrings("/users", rs[1].pattern);
    const doc = rs[1].doc.?;
    try testing.expectEqualStrings("Create a user", doc.summary.?);
    try testing.expectEqualStrings("Creates one user.", doc.description.?);
    try testing.expectEqual(@as(usize, 2), doc.tags.len);
    try testing.expectEqualStrings("users", doc.tags[0]);
    try testing.expectEqualStrings("write", doc.tags[1]);
    try testing.expectEqualStrings("{\"type\":\"object\"}", doc.request_schema.?);
    try testing.expectEqual(@as(usize, 1), doc.responses.len);
    try testing.expectEqual(@as(u16, 201), doc.responses[0].status);
    try testing.expectEqualStrings("Created", doc.responses[0].description);
    try testing.expect(!doc.deprecated);

    // Group routes carry the full prefixed pattern.
    try testing.expectEqual(http.Method.get, rs[2].method);
    try testing.expectEqualStrings("/api/things/:id", rs[2].pattern);
    try testing.expect(rs[2].doc == null);
    try testing.expectEqual(http.Method.delete, rs[3].method);
    try testing.expect(rs[3].doc.?.deprecated);

    // Failed registrations never enter the table.
    try testing.expectError(error.DuplicateRoute, r.get("/hello", hRoot));
    try testing.expectEqual(@as(usize, 4), r.routes().len);
}

test "routes(): empty router enumerates nothing" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 0), r.routes().len);
}

test "addDoc/add copy their inputs (stack temporaries are safe)" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    {
        var pat_buf: [16]u8 = undefined;
        var sum_buf: [16]u8 = undefined;
        var tag_buf: [8]u8 = undefined;
        const pat = try std.fmt.bufPrint(&pat_buf, "/v{d}/users", .{1});
        const sum = try std.fmt.bufPrint(&sum_buf, "Sum {d}", .{7});
        const tag = try std.fmt.bufPrint(&tag_buf, "t{d}", .{9});
        try r.addDoc(.get, pat, hHello, .{ .summary = sum, .tags = &.{tag} });
        pat_buf = @splat(0xAA); // scribble the caller's memory
        sum_buf = @splat(0xAA);
        tag_buf = @splat(0xAA);
    }
    const rt = r.routes()[0];
    try testing.expectEqualStrings("/v1/users", rt.pattern);
    try testing.expectEqualStrings("Sum 7", rt.doc.?.summary.?);
    try testing.expectEqualStrings("t9", rt.doc.?.tags[0]);
    // ...and the route still dispatches.
    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("hello", bodyOf(runWire(&r, wire("GET", "/v1/users"), &buf)));
}

test "matchedPattern: the matched route's pattern on hit, null on 404/405" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.use(.{ .run = mwSeesPattern });
    try r.get("/users/:id", hMatchedUser);
    try r.get("/static/*path", hMatchedWild);
    r.not_found = hNfNullPattern;
    r.method_not_allowed = hMnaNullPattern;

    var buf: [1024]u8 = undefined;
    // Hit: handler asserts the pattern, then answers 200 "ok".
    var got = runWire(&r, wire("GET", "/users/42"), &buf);
    try expectStatus(got, "200");
    try testing.expectEqualStrings("ok", bodyOf(got));
    got = runWire(&r, wire("GET", "/static/a/b.css"), &buf);
    try expectStatus(got, "200");
    try testing.expectEqualStrings("ok", bodyOf(got));
    // HEAD auto-routed to GET reports the GET route's pattern.
    try expectStatus(runWire(&r, wire("HEAD", "/users/42"), &buf), "200");
    // Miss: overridden fallbacks assert null.
    got = runWire(&r, wire("GET", "/nope"), &buf);
    try expectStatus(got, "404");
    try testing.expectEqualStrings("nf", bodyOf(got));
    got = runWire(&r, wire("POST", "/users/42"), &buf);
    try expectStatus(got, "405");
    try testing.expectEqualStrings("mna", bodyOf(got));
}

test "query string stays available to handlers" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/q", hQuery);

    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("q=a=1&b=2", bodyOf(runWire(&r, wire("GET", "/q?a=1&b=2"), &buf)));
    try testing.expectEqualStrings("q=", bodyOf(runWire(&r, wire("GET", "/q"), &buf)));
}

test "keep-alive: one connection dispatches to two different routes" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/hello", hHello);
    try r.get("/users/:id", hUser);

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, "GET /hello HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /users/9 HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, got, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, got, "\r\n\r\nhello") != null);
    try testing.expect(std.mem.endsWith(u8, got, "\r\n\r\nuser=9"));
}

// ── tests (in-process integration — http.Server + Phase-1 http.Client) ──────

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

test "integration: router behind http.Server, driven by http.Client" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.use(.{ .run = mwStamp }); // header-setting middleware over the wire
    try r.get("/hello", hHello);
    try r.get("/users/:id", hUser);

    var server = http.Server.init(io, testing.allocator, .{
        .handler = r.handler(),
        .context = &r,
    });
    defer server.deinit();
    server.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    const port = server.boundAddress().getPort();
    var client = http.Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;

    { // static route + middleware header
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/hello", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("v1", res.header("x-router").?);
        const body = try res.readAllAlloc(testing.allocator, 1024);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("hello", body);
    }

    { // path param extraction
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/users/42", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = try res.readAllAlloc(testing.allocator, 1024);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("user=42", body);
    }

    { // 404 — middleware header still applied (chain wraps not_found)
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/nope", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 404), res.status);
        try testing.expectEqualStrings("v1", res.header("x-router").?);
    }

    { // 405 with Allow
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/hello", .{port});
        var res = try client.request(.post, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 405), res.status);
        try testing.expectEqualStrings("GET, HEAD", res.header("allow").?);
    }
}
