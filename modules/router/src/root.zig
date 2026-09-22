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
//! panic). The 404/405/auto-OPTIONS defaults and the trailing-slash
//! redirect are overridable and run the middleware chain of whichever
//! group's prefix the request path falls under (router-level `use` alone
//! when it falls under none) — a miss inside `group("/api")` runs `/api`'s
//! own middleware, not just the router-level chain, so an auth gate
//! registered via `group().use()` sees every response for its subtree,
//! including the ones no route actually served.
//!
//! Documented policies (matching Go chi / julienschmidt/httprouter):
//! - **HEAD → GET:** HEAD auto-routes to the GET handler when no explicit
//!   HEAD route exists (`ResponseWriter` already suppresses the body and
//!   frames the response correctly for HEAD).
//! - **405 Allow:** when the path matches but the method has no handler,
//!   the router sets `Allow` (registered methods in `http.Method` order;
//!   HEAD implied by GET) *before* invoking the 405 handler, so overrides
//!   inherit it. RFC 9110 §15.5.6 requires this `Allow` to list every
//!   method the target resource — the path, not one particular trie node —
//!   supports. See `method_precedence` (default `.backtrack`) for how that
//!   set is computed when more than one registered pattern has the same
//!   shape (audit finding router-F5).
//! - **Auto OPTIONS:** opt-in via `auto_options` (default off). When on and
//!   an `OPTIONS` request hits a path that has routes but *no* explicit
//!   OPTIONS handler, the router answers `204 No Content` with the same
//!   `Allow` set the 405 path computes (runs behind the router-level
//!   middleware, like the 404/405 fallbacks). An explicit OPTIONS route
//!   always wins. A root `OPTIONS /*path` route does NOT substitute for
//!   this: precedence never backtracks across methods, only across
//!   segments, so a path with any other route registered never falls
//!   through to the wildcard — see README's worked example.
//! - **Trailing slash:** `.redirect` (default, httprouter semantics)
//!   answers 301 for GET/HEAD and 308 for other methods toward the slash
//!   variant that has the route, preserving the query string; `.strict`
//!   (chi semantics) treats `/x` and `/x/` as distinct → 404. `/x` and
//!   `/x/` can always be registered as two distinct routes.
//! - **Raw matching:** paths match byte-for-byte — no percent-decoding, no
//!   case folding. `:param` never matches an empty segment; `*wildcard`
//!   matches the whole remainder (without the leading slash), possibly "".
//! - **Path normalization:** `normalize_path` (default `.remove_dot_segments`)
//!   decides how `dispatch` treats dot segments: normalize `req.target`
//!   itself, RFC 3986 §5.2.4, before matching (`.remove_dot_segments`,
//!   default — redundant but harmless when `http.Server` already did this,
//!   and correct on its own for a caller driving `Router` directly, which
//!   is a supported use), reject a non-canonical target with 400 before
//!   matching (`.reject_non_canonical`), or bypass normalization entirely
//!   and dispatch on the raw, un-rewritten path (`.off`). See
//!   `NormalizePath` and README's "Path normalization" section.
//!
//! Introspection (what `openapi`/`metrics` build on): `Router.routes()`
//! enumerates the registered route table in registration order, `addDoc`
//! attaches optional plain-data `RouteDoc` metadata to a route, and
//! `Ctx.matchedPattern()` reports the matched route's pattern during
//! dispatch (null in the 404/405 fallbacks).

const std = @import("std");
const http = @import("http");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "REST routing — trie matcher (params/wildcards), middleware chain, groups, 404/405",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
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
/// (enforced at `add` time, so matching never overflows). 8, not 16 (audit
/// finding router-F6): no in-repo pattern (or consumer) has ever used more
/// than 2, and `Params.entries`' `Entry` is two slices (32 B), so this alone
/// halves `@sizeOf(Params)` from 520 B to 264 B -- paid on every `dispatch`
/// stack frame, twice (once for the local, once copied into `Ctx` before
/// this fix -- see `Ctx.params`).
pub const max_params = 8;

/// Upper bound on the number of path segments `matchRec` will descend through.
/// A path with more segments than this cannot match anything and is refused as
/// a 404 without recursing further.
///
/// This exists so the recursion depth is bounded by THIS module rather than by
/// whatever the transport in front of it happens to cap a path at. `matchRec`
/// recurses once per segment, so with only the server's own path-length cap
/// (2 KiB) to stop it, a path of `"/a/a/…"` drives ~1024 frames — safe on a
/// default 8-16 MiB thread stack, but safe by an argument that lives in a
/// different module and could be re-tuned there
/// (or bypassed entirely by a caller invoking `dispatch` directly, which is a
/// supported use: `Router` does not require `http.Server`).
///
/// 256 is far past anything routable: the deepest registered pattern is what
/// actually decides a match, and a real one is a handful of segments. A path
/// deeper than this has no pattern to hit.
pub const max_path_segments = 256;

/// Scratch buffer size for `.remove_dot_segments`' own normalization pass
/// (see `dispatch`). `http.Server.checkOriginPath` rejects anything longer
/// before `normalizePathInto` ever runs, and `removeDotSegments` never
/// grows a path — so every `raw` this buffer receives already fits.
const normalize_buf_len = 2048;

const method_count = @typeInfo(http.Method).@"enum".fields.len;

/// One bit per `http.Method`, used to accumulate the union of methods a
/// path shape supports across every candidate `matchIn` visits (audit
/// finding router-F5) -- HEAD-implied-by-GET is applied once, at format
/// time (`writeAllow`), not baked into the stored bits, so union stays a
/// plain bitwise OR.
const AllowSet = std.bit_set.IntegerBitSet(method_count);

fn methodBits(node: *const Node) AllowSet {
    var bits: AllowSet = .initEmpty();
    for (node.endpoints, 0..) |ep, i| {
        if (ep != null) bits.set(i);
    }
    return bits;
}

/// Format `bits` (HEAD implied by GET) into `buf`, `http.Method`-ordered,
/// comma-separated -- the same layout `rebuildAllow` always produced, now
/// shared with the request-time merged Allow (`dispatch`, `.backtrack`).
fn writeAllow(buf: []u8, bits: AllowSet) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    const has_get = bits.isSet(@intFromEnum(http.Method.get));
    inline for (@typeInfo(http.Method).@"enum".fields, 0..) |f, i| {
        const m: http.Method = @enumFromInt(f.value);
        if (bits.isSet(i) or (m == .head and has_get)) {
            if (w.end != 0) w.writeAll(", ") catch unreachable;
            w.writeAll(comptime m.token()) catch unreachable;
        }
    }
    return w.buffered();
}

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
    /// Params of the matched route (empty for the 404 handler). A pointer
    /// into `dispatch`'s own stack frame, not a copy (audit finding
    /// router-F6 -- `Params` used to live TWICE on every dispatch's stack,
    /// once here and once in the local that built it, ~520 B each before
    /// `max_params` also dropped 16 -> 8): valid strictly for the handler
    /// call, exactly like the `[]const u8` values it hands out, so the
    /// existing "never retain past the call" rule already covers it.
    params: *const Params,
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
    /// Router-internal: set only when `answerRedirect` is the chain's
    /// endpoint (see `tryRedirect`). Deliberately not `data` above —
    /// middleware conventionally writes `ctx.data` before calling
    /// `next.run`, which would clobber a value stashed there.
    _redirect: ?*const RedirectInfo = null,

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

/// How `dispatch` resolves a path shape that more than one registered
/// pattern can produce, when the candidates disagree on which HTTP methods
/// they serve (audit finding router-F5). RFC 9110 §15.5.6 requires a 405's
/// `Allow` to list every method the *target resource* supports, but is
/// silent on whether the matcher should keep searching past a candidate
/// that has an endpoint for some OTHER method -- both readings below are
/// spec-compliant; `Allow` is always the union of every candidate visited
/// either way.
pub const MethodPrecedence = enum {
    /// Keep trying sibling candidates (static, then `:param`, then
    /// `*wildcard`, at every level) until one has the requested method or
    /// none are left -- chi semantics, and this module's `model_after`.
    /// Safe default: the alternative lets a route added anywhere else in
    /// the tree silently take over dispatch for a method an existing,
    /// unrelated route already served (e.g. registering `POST /users/new`
    /// turns a working `GET /users/new` -- served today by `GET
    /// /users/:id` -- into a 405, with nothing in the diff that touched
    /// `/users/:id` saying so). Costs more when a miss is deep: `min_reach`
    /// still prunes subtrees that cannot reach ANY endpoint, but it cannot
    /// prune by method, so an adversarial table (see `A1/router.md` F4) can
    /// make a 405 visit every same-shaped candidate before giving up.
    backtrack,
    /// Commit to the first candidate with ANY registered method, exactly
    /// like this module before the F5 fix (httprouter semantics): once a
    /// node has an endpoint for some method, its siblings are never tried,
    /// even for a method that node doesn't serve. Cheaper — matching never
    /// explores past the first hit — at the cost of the shadowing above.
    first_match,
};

/// How `dispatch` treats `req.path` relative to `req.target`. `http.Server`
/// runs RFC 3986 §5.2.4 dot-segment removal on `req.path` unconditionally
/// and silently before this module (or any handler) ever sees the request —
/// see the module doc and README's "Path normalization" section for the
/// full story, including why that is invisible and why it matters for a
/// route whose path segments are caller data (an object key, a device
/// name) rather than route structure.
pub const NormalizePath = enum {
    /// Normalize `req.target`'s path portion (RFC 3986 §5.2.4) before
    /// matching, and hand the handler the normalized result:
    /// `/a/../b` dispatches exactly like `/b`. Right when path segments are
    /// route structure and a `..` walking a prefix is meaningless anyway.
    ///
    /// This runs the normalization itself rather than trusting the caller
    /// to have already done it — `http.Server` does (so this reproduces its
    /// rewrite exactly and is redundant work, not a behavior change, for
    /// that caller), but a caller driving `Router` directly (a supported
    /// use: `Router` does not require `http.Server`) does not, and
    /// previously got no normalization at all under this option despite its
    /// name and doc promising one (audit finding router-F3).
    remove_dot_segments,
    /// Refuse a request whose target path is not already canonical (i.e.
    /// `removeDotSegments` would rewrite it) with 400, before any route is
    /// matched or handler runs. The right posture for a key-in-path API: a
    /// `..` segment must be an error, never a silent reroute to a different
    /// resource. Checked directly against `req.target`, so — like
    /// `.remove_dot_segments` above — this holds for a direct caller too,
    /// not only one sitting behind `http.Server`.
    reject_non_canonical,
    /// Bypass the rewrite for routing purposes: dispatch on — and hand the
    /// handler — the raw, un-rewritten path straight off the wire (`req.path`
    /// is overwritten to match, so a handler reading `ctx.req.path` sees the
    /// same value dispatch matched on). No canonicalization and no
    /// rejection; a `..` segment is just bytes, and the handler owns
    /// deciding what they mean.
    off,
};

pub const AddError = error{
    OutOfMemory,
    /// Pattern must start with '/'; `:`/`*` only introduce whole segments;
    /// `*wildcard` must be the last segment; a `/`-separated segment must
    /// not be empty other than a single trailing one (audit finding
    /// router-F11 — `//evil.example/x` used to be accepted, and a
    /// trailing-slash redirect for a path under it emitted a
    /// protocol-relative `Location` a browser reads as `http://evil.example/x`;
    /// `/x/` itself, one trailing empty segment, is still a valid, distinct
    /// route, per the module doc).
    InvalidPattern,
    /// This (method, pattern) already has a handler.
    DuplicateRoute,
    /// A different param/wildcard name is already registered at this
    /// position (e.g. `/u/:id` vs `/u/:name`).
    ParamNameConflict,
    /// The same `:name`/`*name` capture name is used more than once in one
    /// pattern (e.g. `/:a/:a`) — audit finding router-F8. Before this,
    /// such a pattern was accepted and `params.get("a")` silently returned
    /// only the FIRST value; a handler reading the second capture under
    /// its own name got the first one's value instead.
    DuplicateParamName,
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
        /// JSON Schema of the response body, as JSON text; `openapi`
        /// validates and embeds it under `content."<media_type>".schema`.
        /// Null: a response described by its status alone.
        schema: ?[]const u8 = null,
        /// The body's media type, when `schema` is set.
        media_type: []const u8 = "application/json",
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
    /// Overridable handler for a `normalize_path = .reject_non_canonical`
    /// rejection (runs behind the router-level chain, like 404/405). Unused
    /// under the other two `normalize_path` postures.
    bad_request: Handler = defaultBadRequest,
    /// Opt-in automatic OPTIONS: when true, an `OPTIONS` request on a path
    /// that has registered routes but no explicit OPTIONS handler is
    /// answered `204 No Content` with the same `Allow` the 405 path builds.
    /// Off by default (existing behavior: such a request is a 405). A path
    /// with an explicit OPTIONS route keeps using that handler.
    auto_options: bool = false,
    trailing_slash: TrailingSlash = .redirect,
    /// See `NormalizePath`. Default `.remove_dot_segments` reproduces
    /// today's behavior exactly: `http.Server` already ran the rewrite
    /// before `dispatch` is ever called, and this posture just trusts it.
    normalize_path: NormalizePath = .remove_dot_segments,
    /// See `MethodPrecedence`. Default `.backtrack` changes observable
    /// behavior from this module's previous releases (audit finding
    /// router-F5) — set `.first_match` to keep the old shadowing behavior
    /// verbatim, including its performance characteristics.
    method_precedence: MethodPrecedence = .backtrack,
    routes_added: bool = false,
    /// Registered routes in registration order (see `routes`).
    route_list: std.ArrayList(Route),
    /// Every group ever created (flat, creation order) — used by
    /// `groupFor` to find which group's middleware should wrap a fallback
    /// (404/405/auto-OPTIONS/400/redirect) for a path that didn't reach an
    /// endpoint. Not a tree: `Group` only points at its parent, so the
    /// router keeps the flat index.
    groups: std.ArrayList(*Group),

    /// All registration state (nodes, patterns, chains, groups) lives in an
    /// internal arena owned by the Router — `deinit` frees everything.
    pub fn init(gpa: Allocator) Router {
        return .{
            .arena = std.heap.ArenaAllocator.init(gpa),
            .root = .{},
            .mws = .empty,
            .route_list = .empty,
            .groups = .empty,
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

        // `normalize_path` decides what happens to dot segments — see
        // `NormalizePath`. `.remove_dot_segments` and `.reject_non_canonical`
        // both work from `req.target` directly (not from `req.path`, which a
        // caller driving `Router` without `http.Server` in front never had
        // normalized in the first place — audit finding router-F3).
        var normalize_buf: [normalize_buf_len]u8 = undefined;
        switch (r.normalize_path) {
            .remove_dot_segments => {
                const raw = rawPath(req.target);
                http.Server.checkOriginPath(raw) catch return r.runFallback(req, rw, r.bad_request);
                req.path = if (http.Server.pathHasDotSegments(raw))
                    http.Server.normalizePathInto(&normalize_buf, raw)
                else
                    raw;
            },
            .reject_non_canonical => {
                const raw = rawPath(req.target);
                http.Server.checkOriginPath(raw) catch return r.runFallback(req, rw, r.bad_request);
                if (http.Server.pathHasDotSegments(raw))
                    return r.runFallback(req, rw, r.bad_request);
            },
            .off => req.path = rawPath(req.target),
        }

        var params: Params = .{};
        // `matched`/`miss_allow` unify the two `MethodPrecedence` postures
        // below into one shared tail (audit finding router-F5): whichever
        // posture ran, `matched` means "run this endpoint", a non-empty
        // `miss_allow` means "path shape exists, method doesn't" (405 /
        // auto-OPTIONS), and neither means a genuine 404 (try the
        // trailing-slash redirect, then `not_found`).
        var matched: ?Endpoint = null;
        var miss_allow_buf: [64]u8 = undefined;
        var miss_allow: ?[]const u8 = null;
        switch (r.method_precedence) {
            .first_match => if (matchRec(&r.root, req.path[1..], false, &params)) |node| {
                if (endpointFor(node, req.method)) |ep|
                    matched = ep
                else
                    miss_allow = node.allow;
            },
            .backtrack => {
                var allow_bits: AllowSet = .initEmpty();
                if (matchRecMethod(&r.root, req.path[1..], &params, req.method, &allow_bits)) |node|
                    matched = endpointFor(node, req.method).? // guaranteed: see matchIn
                else if (allow_bits.count() != 0)
                    miss_allow = writeAllow(&miss_allow_buf, allow_bits);
            },
        }

        if (matched) |ep| {
            var ctx: Ctx = .{
                .req = req,
                .res = rw,
                .params = &params,
                .state = r.state,
                .matched_pattern = ep.pattern,
            };
            const next: Next = .{ .chain = ep.chain, .endpoint = ep.handler };
            return next.run(&ctx);
        }
        if (miss_allow) |allow| {
            // Path exists, method doesn't: 405 (or auto-204 for OPTIONS).
            // Allow goes on first so an overridden handler inherits it.
            try rw.setHeader("Allow", allow);
            // No explicit OPTIONS endpoint reached endpointFor above, so when
            // auto_options is on we synthesize a 204 here instead of a 405.
            const endpoint = if (r.auto_options and req.method == .options)
                defaultAutoOptions
            else
                r.method_not_allowed;
            var ctx: Ctx = .{ .req = req, .res = rw, .params = &params, .state = r.state };
            const next: Next = .{ .chain = r.fallbackChain(req.path), .endpoint = endpoint };
            return next.run(&ctx);
        }

        if (r.trailing_slash == .redirect)
            if (try r.tryRedirect(req, rw)) return;

        return r.runFallback(req, rw, r.not_found);
    }

    fn runFallback(r: *Router, req: *http.Server.Request, rw: *http.Server.ResponseWriter, h: Handler) anyerror!void {
        var empty_params: Params = .{};
        var ctx: Ctx = .{ .req = req, .res = rw, .params = &empty_params, .state = r.state };
        const next: Next = .{ .chain = r.fallbackChain(req.path), .endpoint = h };
        return next.run(&ctx);
    }

    /// The deepest group (by prefix length) whose prefix is a
    /// segment-boundary prefix of `path` and which has at least one route
    /// registered somewhere under it (`own_chain` gets cached — see
    /// `addRoute` — exactly when that first happens): the group whose
    /// middleware would wrap a route at this path if one existed. `"/api"`
    /// matches `"/api/x"` and `"/api"` itself, but not `"/apix"`.
    fn groupFor(r: *const Router, path: []const u8) ?*Group {
        var best: ?*Group = null;
        for (r.groups.items) |g| {
            if (g.own_chain == null) continue; // no route ever reached it
            if (!std.mem.startsWith(u8, path, g.prefix)) continue;
            if (path.len > g.prefix.len and path[g.prefix.len] != '/') continue;
            if (best == null or g.prefix.len > best.?.prefix.len) best = g;
        }
        return best;
    }

    /// Middleware chain for a request that will NOT reach a route endpoint
    /// — 404, `.reject_non_canonical`'s 400, a matched-path 405/auto-OPTIONS,
    /// and a trailing-slash redirect all go through this (F1/F2): the
    /// deepest enclosing group's own chain, or router-level `use` alone
    /// when `path` falls under no group. Precomputed per group at
    /// registration time (see `addRoute`), so — like the rest of
    /// `dispatch` — this does no allocation.
    fn fallbackChain(r: *const Router, path: []const u8) []const Middleware {
        if (r.groupFor(path)) |g| return g.own_chain.?;
        return r.mws.items;
    }

    /// Probe the other trailing-slash variant; when it has this route,
    /// run the enclosing group's middleware chain (F2 — this used to answer
    /// straight from `dispatch`, outside any chain, which let an
    /// unauthenticated request enumerate the route table via the 301/404
    /// difference) and answer 301 (GET/HEAD) / 308 with a Location
    /// preserving the query. Paths beyond the fixed buffer just fall
    /// through to 404.
    /// `noinline` (audit finding router-F6): `loc_buf` below is 4 KiB and
    /// used to cost dispatch's OWN stack frame that much even when
    /// `trailing_slash == .strict` (this function never called) or a
    /// request matches on the first try (`dispatch` returns before ever
    /// reaching the call site) — LLVM sizes a frame for every path an
    /// inlined callee could take, not the one a given request takes. A
    /// real function call only pays for `loc_buf` on the stack while this
    /// function is actually running.
    noinline fn tryRedirect(r: *Router, req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!bool {
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

        var redirect: RedirectInfo = .{
            .location = w.buffered(),
            .status = if (req.method == .get or req.method == .head) 301 else 308,
        };
        // `setHeader` (inside `answerRedirect`) copies `loc_buf` into the
        // writer, so the head no longer has to be forced out before this
        // frame dies — safe to let `loc_buf`/`redirect` live only here:
        // `next.run` below completes synchronously, entirely inside this
        // call, before either goes out of scope.
        var ctx: Ctx = .{ .req = req, .res = rw, .params = &probe, .state = r.state, ._redirect = &redirect };
        const next: Next = .{ .chain = r.fallbackChain(path), .endpoint = answerRedirect };
        try next.run(&ctx);
        return true;
    }

    // ── registration internals ──────────────────────────────────────────

    fn addRoute(r: *Router, g: ?*Group, method: http.Method, pattern: []const u8, h: Handler, doc: ?RouteDoc) AddError!void {
        if (pattern.len == 0 or pattern[0] != '/') return error.InvalidPattern;
        // The per-pattern grammar, shared with `Static`. `insert` checks the
        // full, prefixed pattern again as it walks the trie.
        try validatePattern(pattern);
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
        while (it) |gr| : (it = gr.parent) {
            gr.routes_added = true;
            // First route to reach this group (directly, or via a nested
            // subgroup) — `gr.mws` and every ancestor's are frozen from
            // here on (routes_added blocks further `use()`), so this is the
            // one safe, allocation-at-registration-time moment to cache it.
            if (gr.own_chain == null) gr.own_chain = try r.buildChain(gr);
        }
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
        // F4 (A1/router.md): every node visited on the way down, in order —
        // NOT including the final endpoint node itself — so `min_reach` can
        // be updated bottom-up once the route's total length is known
        // (`ancestors_len`, i.e. how many segments this pattern has).
        // `max_path_segments` already bounds pattern depth (`error` below is
        // unreachable in practice since a pattern longer than that could
        // never `dispatch` a match anyway, but the array is sized to it for
        // an honest bound rather than an assumed one).
        var ancestors: [max_path_segments]*Node = undefined;
        var ancestors_len: usize = 0;
        var total_segments: u32 = 0;
        // F8 (A1/router.md): capture names seen so far in THIS pattern.
        // Independent of trie structure -- unlike `ParamNameConflict`
        // below, which only fires when the SAME position was already
        // registered under a DIFFERENT name by some earlier route,
        // `/:a/:a` reuses one name at two DIFFERENT positions, and nothing
        // about the trie catches that; `params.get` would just return the
        // first value silently forever.
        var seen_names: [max_params][]const u8 = undefined;
        var seen_names_len: usize = 0;
        while (rest) |cur| {
            if (ancestors_len < ancestors.len) {
                ancestors[ancestors_len] = node;
                ancestors_len += 1;
            }
            total_segments += 1;
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
                for (seen_names[0..seen_names_len]) |s| {
                    if (std.mem.eql(u8, s, name)) return error.DuplicateParamName;
                }
                nparams += 1;
                if (nparams > max_params) return error.TooManyParams;
                seen_names[seen_names_len] = name;
                seen_names_len += 1;
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
                for (seen_names[0..seen_names_len]) |s| {
                    if (std.mem.eql(u8, s, name)) return error.DuplicateParamName;
                }
                nparams += 1;
                if (nparams > max_params) return error.TooManyParams;
                seen_names[seen_names_len] = name;
                seen_names_len += 1;
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
                // F11 (A1/router.md): an empty segment is legal ONLY as the
                // final one -- a trailing slash, e.g. `/x/`, is a real,
                // distinct route per the module doc ("a trailing slash is
                // a normal (empty) static segment"). A LEADING or INTERIOR
                // empty segment (`//x`, `/a//b`) used to be silently
                // accepted into the trie; dispatching it later made
                // `tryRedirect` emit a protocol-relative `Location`
                // (`//evil.example/x`), which a browser reads as
                // `http://evil.example/x` -- an open redirect.
                if (seg.len == 0 and next != null) return error.InvalidPattern;
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

        // F4 (A1/router.md): this endpoint is `total_segments` segments deep;
        // `node` itself needs 0 more to reach it, and each recorded ancestor
        // needs one more per step back toward the root. `@min` because a
        // shared ancestor may already have a SHORTER route through some
        // other branch — only ever shrinks, so insertion order never matters.
        node.min_reach = @min(node.min_reach, 0);
        var i: usize = ancestors_len;
        while (i > 0) {
            i -= 1;
            const distance = total_segments - @as(u32, @intCast(i));
            ancestors[i].min_reach = @min(ancestors[i].min_reach, distance);
        }
    }

    comptime {
        // `rebuildAllow`'s buffer below must fit every registered method's
        // token, comma-separated -- its `catch unreachable` would otherwise
        // be an actual runtime panic in `add()` the day `http.Method` grows
        // past what fits today (audit finding router-F9: today's 7 methods
        // use 44 of 64 bytes, so there was room to grow silently until the
        // panic, with nothing here to say by how much).
        var worst: usize = 0;
        for (@typeInfo(http.Method).@"enum".fields) |f| {
            const m: http.Method = @enumFromInt(f.value);
            worst += m.token().len + 2; // ", " separator; one spare is fine
        }
        if (worst > 64) @compileError(std.fmt.comptimePrint(
            "router: http.Method has grown to {d} members ({d} bytes worst-case " ++
                "Allow, ', '-joined) -- past rebuildAllow's 64-byte buffer, widen it",
            .{ @typeInfo(http.Method).@"enum".fields.len, worst },
        ));
    }

    /// Recompute the node's `Allow` value and its bitset twin (`allow`:
    /// registered methods in `http.Method` order, HEAD implied by GET;
    /// `allow_bits`: the same set of methods, raw -- `dispatch`'s
    /// `.backtrack` posture unions these across candidates at request
    /// time, audit finding router-F5, where a single precomputed string
    /// can't be merged).
    fn rebuildAllow(r: *Router, node: *Node) error{OutOfMemory}!void {
        node.allow_bits = methodBits(node);
        var buf: [64]u8 = undefined;
        node.allow = try r.arena.allocator().dupe(u8, writeAllow(&buf, node.allow_bits));
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
    /// This group's own chain (router-level `use` ++ every ancestor's
    /// `use`, root→leaf, ++ this group's own `use`) — cached the first time
    /// a route anywhere under this group makes `routes_added` true (see
    /// `addRoute`), at which point `mws` here and on every ancestor is
    /// frozen for good. Used by `Router.fallbackChain` (F1/F2) so a
    /// fallback for a path under this group's prefix still runs its
    /// middleware, even when no route actually matched.
    own_chain: ?[]const Middleware = null,

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
        .own_chain = null,
    };
    try r.groups.append(a, g);
    return g;
}

// ── the comptime table ─────────────────────────────────────────────────────

/// The methods a path serves, as a 405's `Allow` lists them (HEAD implied by
/// GET, `http.Method` order). What `Static.match` reports for a path whose
/// shape exists but whose method does not.
pub const Allow = struct {
    bits: AllowSet = .initEmpty(),

    /// Longest `write` output: every method token, comma-separated.
    pub const max_len = 64;

    pub fn has(a: Allow, m: http.Method) bool {
        if (a.bits.isSet(@intFromEnum(m))) return true;
        return m == .head and a.bits.isSet(@intFromEnum(http.Method.get));
    }

    /// The header value into `buf` -- the same bytes `Router`'s 405 sends.
    pub fn write(a: Allow, buf: *[max_len]u8) []const u8 {
        return writeAllow(buf, a.bits);
    }
};

/// One route of a comptime table. Its index in the slice handed to `Static`
/// is what a match returns: the caller keeps its own handler, doc and policy
/// per route in a parallel table of the same order.
pub const StaticRoute = struct {
    method: http.Method,
    /// Same grammar as `Router.add`.
    pattern: []const u8,
};

pub const StaticOptions = struct {
    /// See `MethodPrecedence`; same default as `Router`.
    method_precedence: MethodPrecedence = .backtrack,
};

/// What `Static.match` found.
pub const Match = union(enum) {
    /// The index of the matched route in the table. HEAD reaches a GET
    /// route when no HEAD route exists, as with `Router`.
    found: usize,
    /// The path shape exists, the method does not: answer 405 (or 204 to an
    /// OPTIONS) with this `Allow`.
    method_not_allowed: Allow,
    not_found,
};

/// A route table built at compile time: the same matcher (`matchIn`), the same
/// precedence, backtracking and pruning as `Router`, with no allocator, no
/// hash map, no `Ctx` and no middleware -- a function from `(method, path)` to
/// a route index and its params. Every pattern error `Router.add` would
/// return at startup is a compile error here instead.
///
/// `path` is matched byte-for-byte, as `Router` matches: it must be
/// origin-form (start with '/'), and the caller decides normalization first
/// (`http.Server` has already removed dot segments from `req.path`; see
/// `NormalizePath` and `rawPath`). No trailing-slash redirect is issued --
/// `trailingSlashVariant` says whether one would exist.
pub fn Static(comptime routes: []const StaticRoute, comptime options: StaticOptions) type {
    const table = comptime buildStatic(routes);
    return struct {
        pub const route_count = routes.len;
        const tree: StaticTree = .{ .nodes = table };

        /// Match `path` (origin-form) for `method`. `params` receives the
        /// captures of the matched route; they are slices of `path`.
        pub fn match(method: http.Method, path: []const u8, params: *Params) Match {
            params.len = 0;
            if (path.len == 0 or path[0] != '/') return .not_found;
            const rest = path[1..];
            var allow: AllowSet = .initEmpty();
            switch (options.method_precedence) {
                .backtrack => {
                    if (matchIn(tree, 0, rest, false, params, 0, segmentsRemaining(rest, false), method, &allow)) |n|
                        return .{ .found = tree.routeFor(n, method).? };
                    if (allow.count() != 0) return .{ .method_not_allowed = .{ .bits = allow } };
                    return .not_found;
                },
                .first_match => {
                    const n = matchIn(tree, 0, rest, false, params, 0, segmentsRemaining(rest, false), null, &allow) orelse
                        return .not_found;
                    if (tree.routeFor(n, method)) |i| return .{ .found = i };
                    return .{ .method_not_allowed = .{ .bits = table[n].allow_bits } };
                },
            }
        }

        pub const SlashVariant = enum { add_slash, drop_slash };

        /// For a path that matched nothing: would the other trailing-slash
        /// form serve `method`? The probe `Router`'s `.redirect` posture runs
        /// before its 404, as a pure function -- the caller builds the
        /// `Location` and decides whether to redirect at all.
        pub fn trailingSlashVariant(method: http.Method, path: []const u8) ?SlashVariant {
            if (path.len == 0 or path[0] != '/') return null;
            var probe: Params = .{};
            var unused: AllowSet = .initEmpty();
            if (path.len > 1 and path[path.len - 1] == '/') {
                const alt = path[1 .. path.len - 1];
                const n = matchIn(tree, 0, alt, false, &probe, 0, segmentsRemaining(alt, false), null, &unused) orelse return null;
                return if (tree.serves(n, method)) .drop_slash else null;
            }
            const rest = path[1..];
            const n = matchIn(tree, 0, rest, true, &probe, 0, segmentsRemaining(rest, true), null, &unused) orelse return null;
            return if (tree.serves(n, method)) .add_slash else null;
        }
    };
}

/// A comptime table node. Children are indices into the same table.
const StaticNode = struct {
    statics: []const StaticEdge = &.{},
    param: ?StaticEdge = null,
    wildcard: ?StaticEdge = null,
    /// Route index per method.
    routes: [method_count]?u32 = @splat(null),
    allow_bits: AllowSet = .initEmpty(),
    min_reach: u32 = std.math.maxInt(u32),
};

/// A static child (`seg` = its segment) or a named capture (`seg` = the name).
const StaticEdge = struct { seg: []const u8, child: u32 };

/// The comptime table as `matchIn` sees it: a `Ref` is an index.
const StaticTree = struct {
    nodes: []const StaticNode,

    pub const Ref = u32;
    pub const Edge = struct { name: []const u8, ref: Ref };

    inline fn static(t: StaticTree, n: Ref, seg: []const u8) ?Ref {
        for (t.nodes[n].statics) |e| {
            if (std.mem.eql(u8, e.seg, seg)) return e.child;
        }
        return null;
    }
    inline fn param(t: StaticTree, n: Ref) ?Edge {
        const e = t.nodes[n].param orelse return null;
        return .{ .name = e.seg, .ref = e.child };
    }
    inline fn wildcard(t: StaticTree, n: Ref) ?Edge {
        const e = t.nodes[n].wildcard orelse return null;
        return .{ .name = e.seg, .ref = e.child };
    }
    inline fn routeFor(t: StaticTree, n: Ref, m: http.Method) ?usize {
        const rs = t.nodes[n].routes;
        if (rs[@intFromEnum(m)]) |i| return i;
        if (m == .head) if (rs[@intFromEnum(http.Method.get)]) |i| return i;
        return null;
    }
    inline fn serves(t: StaticTree, n: Ref, m: http.Method) bool {
        return t.routeFor(n, m) != null;
    }
    inline fn allowBits(t: StaticTree, n: Ref) AllowSet {
        return t.nodes[n].allow_bits;
    }
    inline fn minReach(t: StaticTree, n: Ref) u32 {
        return t.nodes[n].min_reach;
    }
};

/// Build the table, refusing at compile time what `Router.add` refuses at
/// startup. Mirrors `Router.insert` step for step; the differential test
/// holds the two to the same answers.
fn buildStatic(comptime routes: []const StaticRoute) []const StaticNode {
    comptime {
        var segments: usize = 1;
        for (routes) |rt| segments += std.mem.count(u8, rt.pattern, "/") + 1;
        @setEvalBranchQuota(10_000 + 2_000 * segments);
        var nodes: [segments]StaticNode = @splat(.{});
        var len: usize = 1;
        for (routes, 0..) |rt, ri| {
            validatePattern(rt.pattern) catch |err| @compileError(std.fmt.comptimePrint(
                "router.Static: route {d} ({s} {s}): {s} -- see router.AddError.{s}",
                .{ ri, @tagName(rt.method), rt.pattern, @errorName(err), @errorName(err) },
            ));
            var node: u32 = 0;
            var ancestors: [max_path_segments]u32 = undefined;
            var ancestors_len: usize = 0;
            var total_segments: u32 = 0;
            var rest: ?[]const u8 = rt.pattern[1..];
            while (rest) |cur| {
                ancestors[ancestors_len] = node;
                ancestors_len += 1;
                total_segments += 1;
                var seg = cur;
                var next: ?[]const u8 = null;
                if (std.mem.indexOfScalar(u8, cur, '/')) |i| {
                    seg = cur[0..i];
                    next = cur[i + 1 ..];
                }
                const kind: enum { static, param, wildcard } = if (seg.len != 0 and seg[0] == '*')
                    .wildcard
                else if (seg.len != 0 and seg[0] == ':')
                    .param
                else
                    .static;
                switch (kind) {
                    .static => {
                        var found: ?u32 = null;
                        for (nodes[node].statics) |e| {
                            if (std.mem.eql(u8, e.seg, seg)) found = e.child;
                        }
                        node = found orelse blk: {
                            const child: u32 = len;
                            len += 1;
                            nodes[node].statics = nodes[node].statics ++ &[_]StaticEdge{.{ .seg = seg, .child = child }};
                            break :blk child;
                        };
                    },
                    .param, .wildcard => {
                        const name = seg[1..];
                        const slot = if (kind == .param) &nodes[node].param else &nodes[node].wildcard;
                        if (slot.*) |e| {
                            if (!std.mem.eql(u8, e.seg, name)) @compileError(std.fmt.comptimePrint(
                                "router.Static: route {d} ({s}): capture '{s}' conflicts with '{s}' at the same position -- see router.AddError.ParamNameConflict",
                                .{ ri, rt.pattern, name, e.seg },
                            ));
                            node = e.child;
                        } else {
                            const child: u32 = len;
                            len += 1;
                            slot.* = .{ .seg = name, .child = child };
                            node = child;
                        }
                    },
                }
                rest = if (kind == .wildcard) null else next;
            }
            const m = @intFromEnum(rt.method);
            if (nodes[node].routes[m]) |prev| @compileError(std.fmt.comptimePrint(
                "router.Static: route {d} ({s} {s}) duplicates route {d} -- see router.AddError.DuplicateRoute",
                .{ ri, @tagName(rt.method), rt.pattern, prev },
            ));
            nodes[node].routes[m] = ri;
            nodes[node].allow_bits.set(m);
            nodes[node].min_reach = 0;
            var i: usize = ancestors_len;
            while (i > 0) {
                i -= 1;
                const distance = total_segments - @as(u32, @intCast(i));
                nodes[ancestors[i]].min_reach = @min(nodes[ancestors[i]].min_reach, distance);
            }
        }
        const final: [len]StaticNode = nodes[0..len].*;
        return &final;
    }
}

/// The per-pattern rules of `AddError` -- everything that can be decided from
/// one pattern alone, without the rest of the table. Shared by `Router.add`
/// and `Static`, so the grammar is stated once.
pub fn validatePattern(pattern: []const u8) AddError!void {
    if (pattern.len == 0 or pattern[0] != '/') return error.InvalidPattern;
    var names: [max_params][]const u8 = undefined;
    var n: usize = 0;
    var rest: ?[]const u8 = pattern[1..];
    while (rest) |cur| {
        var seg = cur;
        var next: ?[]const u8 = null;
        if (std.mem.indexOfScalar(u8, cur, '/')) |i| {
            seg = cur[0..i];
            next = cur[i + 1 ..];
        }
        if (seg.len != 0 and (seg[0] == '*' or seg[0] == ':')) {
            const name = seg[1..];
            if (name.len == 0) return error.InvalidPattern;
            if (seg[0] == '*' and next != null) return error.InvalidPattern;
            if (std.mem.indexOfAny(u8, name, ":*") != null) return error.InvalidPattern;
            for (names[0..n]) |x| if (std.mem.eql(u8, x, name)) return error.DuplicateParamName;
            if (n == max_params) return error.TooManyParams;
            names[n] = name;
            n += 1;
        } else {
            // F11: an empty segment only as the final one (a trailing slash).
            if (seg.len == 0 and next != null) return error.InvalidPattern;
            if (std.mem.indexOfAny(u8, seg, ":*") != null) return error.InvalidPattern;
        }
        rest = next;
    }
}

/// The target's path portion -- up to '?', or the whole target when there is
/// none -- i.e. `req.path` as it stood *before* `http.Server`'s dot-segment
/// rewrite ran. `req.target` is preserved raw by `http.Server` specifically
/// so a private copy could be normalized without losing this.
pub fn rawPath(target: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, target, '?')) |i| return target[0..i];
    return target;
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

fn defaultBadRequest(ctx: *Ctx) anyerror!void {
    ctx.res.setStatus(400);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Bad Request\n");
}

fn defaultAutoOptions(ctx: *Ctx) anyerror!void {
    // dispatch already set the Allow header; 204 carries no body.
    ctx.res.setStatus(204);
}

/// A trailing-slash redirect's answer, computed by `tryRedirect` and handed
/// down through `Ctx._redirect` so `answerRedirect` can run as an ordinary
/// chain endpoint (see `tryRedirect` for why: F2).
const RedirectInfo = struct {
    location: []const u8,
    status: u16,
};

fn answerRedirect(ctx: *Ctx) anyerror!void {
    const info = ctx._redirect.?;
    ctx.res.setStatus(info.status);
    try ctx.res.setHeader("Location", info.location);
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
    /// `allow`'s bitset twin -- see `rebuildAllow`.
    allow_bits: AllowSet = .initEmpty(),
    /// Fewest ADDITIONAL segments a query needs, from this node, to reach any
    /// endpoint in this node's subtree (0 once `hasEndpoint()`). Maintained
    /// incrementally by `insert` (a route can only ever shrink an ancestor's
    /// value, never grow it, so `@min` on every insert along the new route's
    /// path keeps it correct without a separate rebuild pass). `maxInt` for a
    /// node no successful `insert` has reached yet — never observed by
    /// `matchIn` in practice, since a node only exists because some
    /// `insert` walked through it, and that same call finalizes this field
    /// before returning (see `insert`'s bottom-up update).
    ///
    /// F4 (A1/router.md): `matchIn`'s backtracking search is
    /// O(#nodes reachable at the query's own length), which a route table
    /// with the same static segment name repeated at many depths plus a
    /// `:param` sibling at each one can blow up to O(k²) — measured 64,000
    /// node visits / 3.98 ms for k=250 routes, an adversarial table a
    /// prior session's memoization attempt could NOT fix (measured 20-25x
    /// SLOWER: the adversarial construction's param subtrees are disjoint,
    /// so no node is ever revisited — there is no redundant work to cache).
    /// This field lets `matchIn` reject a subtree in O(1) BEFORE
    /// descending into it whenever the query's remaining segment count
    /// cannot possibly reach ANY endpoint under it — sound (never rejects a
    /// subtree that could still match) because it is a strictly NECESSARY
    /// condition, not a guess.
    min_reach: u32 = std.math.maxInt(u32),

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
/// param sibling), REGARDLESS of which HTTP method that endpoint is for
/// (`MethodPrecedence.first_match` semantics — `dispatch` checks the
/// method itself afterward). `rest` is the remaining path after the
/// leading '/'; null = all segments consumed. `extra` appends one virtual
/// "" segment (used to probe `path ++ "/"` without building the string).
/// Recursion depth = segment count, bounded by this module's own
/// `max_path_segments` (see `matchIn`) — not by whatever caps the
/// path upstream.
fn matchRec(node: *const Node, rest: ?[]const u8, extra: bool, params: *Params) ?*const Node {
    var unused_allow: AllowSet = .initEmpty();
    return matchIn(runtime_tree, node, rest, extra, params, 0, segmentsRemaining(rest, extra), null, &unused_allow);
}

/// `matchRec`'s `MethodPrecedence.backtrack` twin (audit finding
/// router-F5): a candidate only counts as a match when it serves `method`
/// specifically; every candidate that matches the path SHAPE but not
/// `method` instead unions its node's `allow_bits` into `allow` and lets
/// the search keep going — static, then `:param`, then `*wildcard`, at
/// every level — so a route registered elsewhere in the tree can no
/// longer silently shadow an existing route for a method it doesn't even
/// serve. A null return with `allow.count() != 0` means "the path shape
/// exists, just not for this method" (405/auto-OPTIONS); empty means a
/// genuine 404.
fn matchRecMethod(node: *const Node, rest: ?[]const u8, params: *Params, method: http.Method, allow: *AllowSet) ?*const Node {
    return matchIn(runtime_tree, node, rest, false, params, 0, segmentsRemaining(rest, false), method, allow);
}

/// Total segment count `rest`/`extra` still represent — computed ONCE per
/// top-level `matchRec` call (not per recursion level, which would turn an
/// O(1)-per-level count into an O(depth) rescan and reintroduce an O(depth²)
/// cost of its own). `matchIn` threads the result down, decrementing
/// by exactly one per segment consumed (see its own doc comment, F4).
fn segmentsRemaining(rest: ?[]const u8, extra: bool) u32 {
    var n: u32 = if (extra) 1 else 0;
    if (rest) |r| {
        n += 1;
        for (r) |c| {
            if (c == '/') n += 1;
        }
    }
    return n;
}

/// The runtime trie as `matchIn` sees it: a `Ref` is a node pointer.
///
/// ⭐ `matchIn` is the ONE matching algorithm in this module. The runtime
/// `Router` and the comptime `Static` table differ only in how a node is
/// stored -- a heap `Node` with a hash map of static children here, a flat
/// comptime array addressed by index there -- and each supplies these few
/// accessors. Precedence, backtracking, the F4 `min_reach` pruning and the
/// F5 Allow union exist once, so the two cannot drift.
const RuntimeTree = struct {
    pub const Ref = *const Node;
    pub const Edge = struct { name: []const u8, ref: Ref };

    inline fn static(_: RuntimeTree, n: Ref, seg: []const u8) ?Ref {
        return n.static.get(seg);
    }
    inline fn param(_: RuntimeTree, n: Ref) ?Edge {
        const e = n.param orelse return null;
        return .{ .name = e.name, .ref = e.node };
    }
    inline fn wildcard(_: RuntimeTree, n: Ref) ?Edge {
        const e = n.wildcard orelse return null;
        return .{ .name = e.name, .ref = e.node };
    }
    inline fn serves(_: RuntimeTree, n: Ref, m: http.Method) bool {
        return endpointFor(n, m) != null;
    }
    inline fn allowBits(_: RuntimeTree, n: Ref) AllowSet {
        return n.allow_bits;
    }
    inline fn minReach(_: RuntimeTree, n: Ref) u32 {
        return n.min_reach;
    }
};
const runtime_tree: RuntimeTree = .{};

/// The matcher. `tree` supplies the node accessors (see `RuntimeTree`);
/// `node` is where this level starts.
fn matchIn(
    tree: anytype,
    node: @TypeOf(tree).Ref,
    rest: ?[]const u8,
    extra: bool,
    params: *Params,
    depth: u32,
    remaining: u32,
    // null = `MethodPrecedence.first_match`: a candidate matches as soon as
    // it has ANY endpoint (`matchRec`'s historical contract, still used by
    // `tryRedirect`'s own path-shape probe, which checks the method itself
    // afterward either way). Non-null = `.backtrack` (audit finding
    // router-F5): a candidate matches only when it serves THIS method;
    // every candidate that matches the shape but not the method instead
    // unions its `allow_bits` into `allow` and the search keeps going.
    method: ?http.Method,
    allow: *AllowSet,
) ?@TypeOf(tree).Ref {
    // Router-owned recursion bound (see `max_path_segments`). A path this deep
    // cannot match a registered pattern, so refusing it costs nothing and the
    // frame count stops depending on the transport's path cap.
    if (depth > max_path_segments) return null;
    const r = rest orelse {
        // The virtual "" segment `extra` appends has not been consumed yet
        // here -- `segmentsRemaining` already counted it, so `remaining` is
        // passed through UNCHANGED; it is decremented below, the same as any
        // other segment, once this call re-enters with `rest = ""`.
        if (extra) return matchIn(tree, node, "", false, params, depth + 1, remaining, method, allow);
        const bits = tree.allowBits(node);
        if (method) |m| {
            if (tree.serves(node, m)) return node;
            if (bits.count() != 0) allow.setUnion(bits);
            return null;
        }
        return if (bits.count() != 0) node else null;
    };
    var seg = r;
    var next: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, r, '/')) |i| {
        seg = r[0..i];
        next = r[i + 1 ..];
    }
    // F4 (A1/router.md): `seg` is about to be consumed, so every subtree
    // reached from here has exactly `remaining - 1` segments left to work
    // with -- computed once, shared by the static AND param checks below.
    const remaining_after_seg = remaining - 1;
    if (tree.static(node, seg)) |child| {
        if (tree.minReach(child) <= remaining_after_seg) {
            if (matchIn(tree, child, next, extra, params, depth + 1, remaining_after_seg, method, allow)) |n| return n;
        }
    }
    if (seg.len != 0) if (tree.param(node)) |p| {
        if (tree.minReach(p.ref) <= remaining_after_seg) {
            const saved = params.len;
            params.push(p.name, seg);
            if (matchIn(tree, p.ref, next, extra, params, depth + 1, remaining_after_seg, method, allow)) |n| return n;
            params.len = saved;
        }
    };
    if (tree.wildcard(node)) |wc| {
        const bits = tree.allowBits(wc.ref);
        if (method) |m| {
            if (tree.serves(wc.ref, m)) {
                params.push(wc.name, r);
                return wc.ref;
            }
            if (bits.count() != 0) allow.setUnion(bits);
        } else if (bits.count() != 0) {
            params.push(wc.name, r);
            return wc.ref;
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
fn hRewritten(ctx: *Ctx) anyerror!void {
    try ctx.res.writeAll("rewritten");
}
fn hRawCatch(ctx: *Ctx) anyerror!void {
    try ctx.res.writeAll("raw:");
    try ctx.res.writeAll(ctx.params.get("rest").?);
}
fn hCaptureLen(ctx: *Ctx) anyerror!void {
    // F7: only the winning branch's capture should be live.
    try testing.expectEqual(@as(usize, 1), ctx.params.len);
    try ctx.res.writeAll(ctx.params.get("p").?);
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

/// Dispatch through a frame that is then abandoned — see the test below.
/// `noinline` so `tryRedirect`'s `loc_buf` really lives in the frame the
/// clobber reuses.
noinline fn dispatchInDoomedFrame(
    r: *Router,
    req: *http.Server.Request,
    rw: *http.Server.ResponseWriter,
) anyerror!void {
    return r.dispatch(req, rw);
}

/// Reuse it, bigger than the 4 KiB `loc_buf` the `Location` used to point at.
noinline fn clobberDoomedFrame() void {
    var scratch: [8192]u8 = undefined;
    @memset(&scratch, '#');
    std.mem.doNotOptimizeAway(&scratch);
}

test "trailing slash: the redirect's Location outlives the frame it was built in" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/users/:id", hUser);

    // `tryRedirect` used to force an early `end()` because its `Location`
    // pointed into its own stack frame; `http`'s `setHeader` copies the bytes
    // now, so the head is left to the serving loop. That makes this router
    // depend on the copy — and `runWire` cannot see it, because the loop
    // offers no seam between the handler returning and `end()` in which to
    // reuse the dead frame. So the request and the writer are built by hand
    // here and the two are driven in the loop's own order, with the scribble
    // in between.
    var in: Reader = .fixed("GET /users/42/?x=1 HTTP/1.1\r\nHost: t\r\n\r\n");
    var head_buf: [512]u8 = undefined;
    const head = try http.h1.RequestHead.parse(try http.h1.readHead(&in, &head_buf));
    var body_scratch: [64]u8 = undefined;
    var body: http.Server.RequestBody = .init(&head, &in, &body_scratch);
    const q = std.mem.indexOfScalar(u8, head.target, '?');
    var req: http.Server.Request = .{
        .method = .get,
        .target = head.target,
        .path = if (q) |i| head.target[0..i] else head.target,
        .query = if (q) |i| head.target[i + 1 ..] else "",
        .head = head,
        .body = &body,
        .context = &r,
    };

    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var response_body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &response_body_buf, &chunk_buf, .{});

    try dispatchInDoomedFrame(&r, &req, &rw);
    clobberDoomedFrame();
    try rw.end();

    const got = out.buffered();
    try expectStatus(got, "301");
    try expectHeaderLine(got, "Location: /users/42?x=1");
    try testing.expect(std.mem.indexOf(u8, got, "#") == null);
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

test "normalize_path: default dispatches the rewritten route; reject_non_canonical answers 400; off reaches the raw path" {
    // The blob-store scenario from the module doc: a raw target containing
    // `..` is silently rewritten by http.Server before this module ever
    // sees it. `/v1/blob/../other` RFC-3986-normalizes to `/v1/other` — a
    // DIFFERENT registered route, not an error.
    var buf: [1024]u8 = undefined;

    { // .remove_dot_segments (default): trust the rewrite, same as before
        // this option existed.
        var r = Router.init(testing.allocator);
        defer r.deinit();
        try r.get("/v1/other", hRewritten);
        try r.get("/v1/blob/*rest", hRawCatch);
        const got = runWire(&r, wire("GET", "/v1/blob/../other"), &buf);
        try expectStatus(got, "200");
        try testing.expectEqualStrings("rewritten", bodyOf(got));
    }
    { // .reject_non_canonical: not already canonical → 400, no route hit.
        var r = Router.init(testing.allocator);
        defer r.deinit();
        r.normalize_path = .reject_non_canonical;
        try r.get("/v1/other", hRewritten);
        try r.get("/v1/blob/*rest", hRawCatch);
        const got = runWire(&r, wire("GET", "/v1/blob/../other"), &buf);
        try expectStatus(got, "400");
        // A target that was already canonical still dispatches normally.
        const ok = runWire(&r, wire("GET", "/v1/other"), &buf);
        try expectStatus(ok, "200");
        try testing.expectEqualStrings("rewritten", bodyOf(ok));
    }
    { // .off: dispatch on — and hand the handler — the raw, un-rewritten
        // path; the wildcard capture is the literal, un-collapsed bytes.
        var r = Router.init(testing.allocator);
        defer r.deinit();
        r.normalize_path = .off;
        try r.get("/v1/other", hRewritten);
        try r.get("/v1/blob/*rest", hRawCatch);
        const got = runWire(&r, wire("GET", "/v1/blob/../other"), &buf);
        try expectStatus(got, "200");
        try testing.expectEqualStrings("raw:../other", bodyOf(got));
    }
}

test "documented: reject_non_canonical does not decode percent-encoding, so %2e%2e dispatches instead of 400" {
    // README's caveat, pinned: `.reject_non_canonical` byte-compares the raw
    // target against `removeDotSegments`'s literal-byte rewrite. Neither side
    // of that comparison percent-decodes, so a percent-encoded traversal is
    // already "canonical" and is dispatched — the literal bytes `%2e%2e` land
    // in the wildcard capture, unlike the literal `..` case above which 400s.
    var buf: [1024]u8 = undefined;
    var r = Router.init(testing.allocator);
    defer r.deinit();
    r.normalize_path = .reject_non_canonical;
    try r.get("/v1/blob/*rest", hRawCatch);
    const got = runWire(&r, wire("GET", "/v1/blob/%2e%2e/other"), &buf);
    try expectStatus(got, "200");
    try testing.expectEqualStrings("raw:%2e%2e/other", bodyOf(got));
}

test "documented: MethodPrecedence.first_match — a root OPTIONS wildcard does NOT catch OPTIONS on a path with other methods registered" {
    // .first_match reproduces this module's pre-F5 behavior exactly:
    // matchRec commits to the "/thing" node — it already has a GET
    // endpoint — before dispatch even looks at the request's method, so
    // the OPTIONS-only wildcard sibling below is never tried for this
    // path. See the `.backtrack` (default) twin below for the F5 fix.
    var r = Router.init(testing.allocator);
    defer r.deinit();
    r.method_precedence = .first_match;
    try r.get("/thing", hHello);
    try r.options("/*catchall", hCreated); // a "catch every OPTIONS" attempt

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, wire("OPTIONS", "/thing"), &buf);
    try expectStatus(got, "405");
    try expectHeaderLine(got, "Allow: GET, HEAD");

    // A path with no other routes at all DOES fall through to the wildcard
    // — the catch-all itself works, it just never backtracks INTO a node
    // that already has an endpoint for some other method.
    const got2 = runWire(&r, wire("OPTIONS", "/nope/at/all"), &buf);
    try expectStatus(got2, "201");
    try testing.expectEqualStrings("created", bodyOf(got2));
}

test "MethodPrecedence.backtrack (default): the same table now DOES fall through to the wildcard (F5)" {
    // Same fixture as the .first_match test above. Under the new default,
    // a "/thing" node with a GET endpoint but no OPTIONS is no longer a
    // dead end for OPTIONS: the search backtracks past it to the
    // OPTIONS-only wildcard, which DOES serve this method.
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try testing.expectEqual(MethodPrecedence.backtrack, r.method_precedence); // the default
    try r.get("/thing", hHello);
    try r.options("/*catchall", hCreated);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, wire("OPTIONS", "/thing"), &buf);
    try expectStatus(got, "201");
    try testing.expectEqualStrings("created", bodyOf(got));
}

test "F5: a static sibling for one method no longer shadows a working :param route for another" {
    // The audit's own repro: `GET /users/:id` works; registering an
    // unrelated `POST /users/new` elsewhere used to turn `GET /users/new`
    // into a 405, purely because `new` (static) matches before `:id`
    // (param) and the OLD matcher stopped at the first node with ANY
    // endpoint, regardless of method.
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/users/:id", hUser);
    try r.post("/users/new", hCreated);

    var buf: [1024]u8 = undefined;
    // Still works before AND after the unrelated POST route exists.
    try testing.expectEqualStrings("user=new", bodyOf(runWire(&r, wire("GET", "/users/new"), &buf)));
    try testing.expectEqualStrings("user=other", bodyOf(runWire(&r, wire("GET", "/users/other"), &buf)));
    // The static route's own method still works and still wins over :id.
    const posted = runWire(&r, wire("POST", "/users/new"), &buf);
    try expectStatus(posted, "201");
    try testing.expectEqualStrings("created", bodyOf(posted));
    // A method neither candidate serves is a genuine 405, Allow the union
    // of BOTH candidates the request's path shape could have reached
    // (RFC 9110 §15.5.6 — router-F5's other half): GET/HEAD from `:id`,
    // POST from the static sibling.
    const del = runWire(&r, wire("DELETE", "/users/new"), &buf);
    try expectStatus(del, "405");
    try expectHeaderLine(del, "Allow: GET, HEAD, POST");
    // .first_match keeps the OLD shadowing behavior verbatim.
    var legacy = Router.init(testing.allocator);
    defer legacy.deinit();
    legacy.method_precedence = .first_match;
    try legacy.get("/users/:id", hUser);
    try legacy.post("/users/new", hCreated);
    const shadowed = runWire(&legacy, wire("GET", "/users/new"), &buf);
    try expectStatus(shadowed, "405");
    try expectHeaderLine(shadowed, "Allow: POST");
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

test "group middleware runs on 405, auto-OPTIONS, an in-group 404, and a redirect (F1/F2)" {
    var trace: Trace = .{};
    var r = Router.init(testing.allocator);
    defer r.deinit();
    r.state = &trace;
    r.auto_options = true;
    const api = try r.group("/api");
    try api.use(.{ .run = mwG });
    try api.get("/things/:id", hUser);

    var buf: [1024]u8 = undefined;

    // 405: path matches, method doesn't -- group middleware must still run
    // (README teaches `group().use(.{ .run = requireAuth })` as an
    // authorization boundary; before the fix it never saw this response).
    trace = .{};
    try expectStatus(runWire(&r, wire("DELETE", "/api/things/7"), &buf), "405");
    try testing.expectEqualStrings("Gg", trace.get());

    // auto-OPTIONS: path matches, no explicit OPTIONS route -- same requirement.
    trace = .{};
    try expectStatus(runWire(&r, wire("OPTIONS", "/api/things/7"), &buf), "204");
    try testing.expectEqualStrings("Gg", trace.get());

    // 404 entirely inside the group's subtree -- group middleware must run too.
    trace = .{};
    try expectStatus(runWire(&r, wire("GET", "/api/nope"), &buf), "404");
    try testing.expectEqualStrings("Gg", trace.get());

    // A path that only shares a textual prefix, not a '/'-bounded one, is
    // NOT inside the group: "/apix" is not under "/api".
    trace = .{};
    try expectStatus(runWire(&r, wire("GET", "/apix"), &buf), "404");
    try testing.expectEqualStrings("", trace.get());

    // Redirect: "/api/things/7/" only matches with the slash stripped --
    // group middleware must run before the 301 leaks that the route exists.
    trace = .{};
    const got = runWire(&r, wire("GET", "/api/things/7/"), &buf);
    try expectStatus(got, "301");
    try expectHeaderLine(got, "Location: /api/things/7");
    try testing.expectEqualStrings("Gg", trace.get());
}

test "group middleware can deny a redirect before it reveals a route exists (F2)" {
    var trace: Trace = .{};
    var r = Router.init(testing.allocator);
    defer r.deinit();
    r.state = &trace;
    const api = try r.group("/api");
    try api.use(.{ .run = mwDeny }); // short-circuits 403, never calls next
    try api.get("/secret", hHello);

    var buf: [1024]u8 = undefined;
    // Before the fix this answered 301 `Location: /api/secret` straight
    // from `dispatch`, outside any chain -- proof, to a caller `mwDeny` was
    // registered specifically to keep out, that the route exists at all.
    const got = runWire(&r, wire("GET", "/api/secret/"), &buf);
    try expectStatus(got, "403");
    try testing.expectEqualStrings("denied", bodyOf(got));
}

test "normalize_path holds for a caller driving dispatch() directly, not only behind http.Server (F3)" {
    // `Router.dispatch` is a documented, supported entry point without
    // `http.Server` in front. Unlike `runWire` (which drives the full h1
    // codec, so `req.path` already arrives pre-normalized), this builds
    // `Request` by hand with `req.path` exactly as raw as `req.target` --
    // what a direct caller actually has.
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/v1/other", hRewritten);
    try r.get("/v1/blob/*rest", hRawCatch);

    var in: Reader = .fixed("GET /v1/blob/../other HTTP/1.1\r\nHost: t\r\n\r\n");
    var head_buf: [512]u8 = undefined;
    const head = try http.h1.RequestHead.parse(try http.h1.readHead(&in, &head_buf));
    var body_scratch: [64]u8 = undefined;
    var body: http.Server.RequestBody = .init(&head, &in, &body_scratch);
    var req: http.Server.Request = .{
        .method = .get,
        .target = head.target,
        .path = head.target, // raw -- nobody normalized it first
        .query = "",
        .head = head,
        .body = &body,
        .context = &r,
    };

    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var response_body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &response_body_buf, &chunk_buf, .{});

    try r.dispatch(&req, &rw);
    try rw.end();

    // Before the fix, `.remove_dot_segments` was a no-op for this caller:
    // the raw path (literal ".." bytes) went straight to the matcher, hit
    // the wildcard, and never reached `/v1/other` at all.
    const got = out.buffered();
    try expectStatus(got, "200");
    try testing.expectEqualStrings("rewritten", bodyOf(got));
}

test "reject_non_canonical rejects a raw dot-segment target from a direct caller too (F3)" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    r.normalize_path = .reject_non_canonical;
    try r.get("/v1/other", hRewritten);

    var in: Reader = .fixed("GET /v1/../other HTTP/1.1\r\nHost: t\r\n\r\n");
    var head_buf: [512]u8 = undefined;
    const head = try http.h1.RequestHead.parse(try http.h1.readHead(&in, &head_buf));
    var body_scratch: [64]u8 = undefined;
    var body: http.Server.RequestBody = .init(&head, &in, &body_scratch);
    var req: http.Server.Request = .{
        .method = .get,
        .target = head.target,
        .path = head.target, // never normalized, unlike runWire
        .query = "",
        .head = head,
        .body = &body,
        .context = &r,
    };

    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var response_body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &response_body_buf, &chunk_buf, .{});

    try r.dispatch(&req, &rw);
    try rw.end();

    // Before the fix this compared `req.target`'s path against `req.path`
    // -- for a direct caller they start out equal (neither has been
    // normalized by anyone), so the check silently never fired.
    try expectStatus(out.buffered(), "400");
}

test "backtracking never leaves a failed param branch's capture in params (F7)" {
    // Mutation audit: `params.len = saved;` on the failed `:p` branch has no
    // test of its own, and the suite stays green without it -- because
    // `Params.get` returns the FIRST match by name, a stale leftover entry
    // from the branch that didn't pan out is invisible to `get`, even though
    // `params.len` is wrong. Assert the length, not just the value.
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/x/:p/a/end", hHello); // "/x/A/B" never reaches "end" -- no match
    try r.get("/x/*p", hCaptureLen);

    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("A/B", bodyOf(runWire(&r, wire("GET", "/x/A/B"), &buf)));
}

test "reject_non_canonical only inspects the path, not the query string (F12a)" {
    // Mutation audit (pre-F3): deleting `rawPath`'s '?' truncation was
    // GREEN against the old suite, because `.reject_non_canonical` was the
    // only posture that ran with query strings, and it byte-compared raw
    // against `req.path` directly -- a query string alone made them differ,
    // 400ing a request with nothing non-canonical in its path. F3's fix
    // moved every posture onto `rawPath`, including `.remove_dot_segments`
    // (the default), which several PRE-EXISTING tests already exercise with
    // a query string ("trailing slash: redirect policy", "...outlives the
    // frame", "query string stays available") -- verified: mutating
    // `rawPath` the same way now fails 3 tests, not 0. This test adds the
    // one query+`.reject_non_canonical` combination none of those cover.
    var r = Router.init(testing.allocator);
    defer r.deinit();
    r.normalize_path = .reject_non_canonical;
    try r.get("/v1/other", hQuery);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, wire("GET", "/v1/other?x=1&y=2"), &buf);
    try expectStatus(got, "200");
    try testing.expectEqualStrings("q=x=1&y=2", bodyOf(got));
}

test "OPTIONS * (asterisk-form) never matches a root route (F12b)" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/", hRoot);

    var buf: [1024]u8 = undefined;
    // Mutation audit: dropping dispatch's `req.path[0] != '/'` guard lets
    // `OPTIONS *`'s literal target ("*") fall through to `matchRec` and hit
    // "/" as if an empty remainder had matched it -- it must not.
    try expectStatus(runWire(&r, wire("OPTIONS", "*"), &buf), "404");
}

test "a ':'/'*' inside a capture's own name is rejected, not silently merged (F12c)" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    // Mutation audit: dropping the `indexOfAny(name, ":*")` guard on the
    // `:name` branch lets a typo like this register as ONE capture named
    // "name*ext" instead of erroring -- which then 404s on every real
    // request, silently, because nothing ever routes to that name.
    try testing.expectError(error.InvalidPattern, r.get("/files/:name*ext", hHello));
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

    // Unique names, comptime-generated: max_params + 1 = the cap PLUS one,
    // never colliding with the DuplicateParamName check below (F8), whose
    // own test wants a REPEATED name specifically.
    {
        comptime var pattern: []const u8 = "";
        inline for (0..max_params + 1) |i| pattern = pattern ++ std.fmt.comptimePrint("/:p{d}", .{i});
        try testing.expectError(error.TooManyParams, r.get(pattern, hHello));
    }
}

test "add: duplicate capture name in one pattern is rejected (F8)" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    // The exact audit repro: `/:a/:a` -- two DIFFERENT positions, same
    // name. `params.get("a")` would silently return only the first value.
    try testing.expectError(error.DuplicateParamName, r.get("/:a/:a", hHello));
    try testing.expectError(error.DuplicateParamName, r.get("/x/:id/y/:id", hHello));
    try testing.expectError(error.DuplicateParamName, r.get("/x/:id/*id", hHello)); // mixed :/*
    // Distinct names at distinct positions: fine (not the same defect).
    try r.get("/x/:id/y/:sub_id", hHello);
}

test "add: an empty pattern segment is rejected unless it is the trailing one (F11)" {
    var r = Router.init(testing.allocator);
    defer r.deinit();
    // Leading and interior empty segments used to be silently accepted,
    // and a trailing-slash redirect under one emitted a protocol-relative
    // `Location` (`//evil.example/x`) -- an open redirect.
    try testing.expectError(error.InvalidPattern, r.get("//evil.example/x", hHello));
    try testing.expectError(error.InvalidPattern, r.get("/a//b", hHello));
    try testing.expectError(error.InvalidPattern, r.get("//", hHello));
    // A SINGLE trailing empty segment is the documented, distinct
    // trailing-slash route and must keep working.
    try r.get("/x/", hHello);
    try r.get("/", hRoot);
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

test "match depth is bounded by the router, not by whatever caps the path upstream" {
    // Audit finding router-F1: `matchRec` recurses once per segment and the
    // only thing that stopped it was the server's own path-length cap (2 KiB)
    // — a bound in a different module, which a caller driving the router
    // directly (a supported use; `Router` does not require `http.Server`) never
    // passes through at all. The bound is now the router's own, so this test
    // goes at `matchRec` rather than through the wire: the point is precisely
    // that it holds without a server in front.
    const gpa = testing.allocator;
    var r = Router.init(gpa);
    defer r.deinit();

    // Two registered routes: one exactly AT the depth limit, one just past it.
    // Both are perfectly well-formed patterns — the second is refused at match
    // time by the cap, not by `add`.
    var at_limit: std.ArrayList(u8) = .empty;
    defer at_limit.deinit(gpa);
    for (0..max_path_segments) |_| try at_limit.appendSlice(gpa, "/a");
    var past_limit: std.ArrayList(u8) = .empty;
    defer past_limit.deinit(gpa);
    try past_limit.appendSlice(gpa, at_limit.items);
    try past_limit.appendSlice(gpa, "/a");

    try r.get(at_limit.items, hRoot);
    try r.get(past_limit.items, hHello);

    // At the limit: matched.
    {
        var params: Params = .{};
        try testing.expect(matchRec(&r.root, at_limit.items[1..], false, &params) != null);
    }
    // One segment deeper: refused, even though the pattern is registered and
    // the path is its exact spelling. Without the cap this returns the node.
    {
        var params: Params = .{};
        try testing.expectEqual(
            @as(?*const Node, null),
            matchRec(&r.root, past_limit.items[1..], false, &params),
        );
    }
    // Depth is the only thing being refused: ordinary routes still match, so
    // the cap cannot have been set somewhere that breaks real routing.
    try r.get("/hello", hHello);
    try r.get("/users/:id", hUser);
    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("hello", bodyOf(runWire(&r, wire("GET", "/hello"), &buf)));
    try testing.expectEqualStrings("user=42", bodyOf(runWire(&r, wire("GET", "/users/42"), &buf)));

    // The value itself, pinned — every assertion above is written in terms of
    // `max_path_segments`, so this is what stops the constant drifting.
    try testing.expectEqual(@as(usize, 256), max_path_segments);
}

fn processCpuNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.PROCESS_CPUTIME_ID, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

test "F4: a route table with the same static segment repeated at every depth plus a :param sibling matches in bounded time" {
    // A1/router.md F4: `matchIn`'s backtracking search cost used to be
    // O(#nodes reachable within the query's own length) rather than O(query
    // length) -- a route table with the same static segment name repeated at
    // many depths, each with a `:param` sibling, is the adversarial shape:
    // measured (audit + this campaign's own re-measurement) at ~64,000 node
    // visits / ~2 ms CPU time for k=250 such routes probed with a
    // (k+1)-segment path. A prior fix attempt this same day (memoizing
    // visited nodes within one `matchRec` call) measured 20-25x SLOWER, not
    // faster -- this construction's `:param` subtrees are disjoint, so
    // backtracking never revisits a node and there is nothing to cache.
    //
    // Fixed instead by `Node.min_reach` (see its doc comment): every route
    // in THIS construction has the exact same total length (`k+2` segments:
    // `i` "a"s + one param + `(k-i)` "a"s + "end"), while the probe path has
    // `k+1` -- one short of every single route -- so the fix rejects the
    // ENTIRE table at the first descent from the root, before visiting
    // anything.
    const gpa = testing.allocator;
    var r = Router.init(gpa);
    defer r.deinit();

    const k = 250;
    var pat_buf: [4096]u8 = undefined;
    for (0..k) |i| {
        var w: Writer = .fixed(&pat_buf);
        for (0..i) |_| w.writeAll("/a") catch unreachable;
        w.writeAll("/:p") catch unreachable;
        for (0..(k - i)) |_| w.writeAll("/a") catch unreachable;
        w.writeAll("/end") catch unreachable;
        try r.get(w.buffered(), hRoot);
    }

    var probe: std.ArrayList(u8) = .empty;
    defer probe.deinit(gpa);
    for (0..(k + 1)) |_| try probe.appendSlice(gpa, "/a");

    // No match exists (every route ends in "/end", the probe never does) --
    // this measures the cost of correctly REJECTING an adversarial path, not
    // finding one.
    var params: Params = .{};
    try testing.expectEqual(@as(?*const Node, null), matchRec(&r.root, probe.items[1..], false, &params));

    // Process CPU time, not wall time -- immune to a concurrent peer
    // session's load on this machine (the audit's own measurement
    // technique for this exact construction), averaged over reps so a
    // single scheduling hiccup cannot flip the result.
    const reps = 20;
    const start = processCpuNs();
    for (0..reps) |_| {
        params.len = 0;
        _ = matchRec(&r.root, probe.items[1..], false, &params);
    }
    const avg_ns = (processCpuNs() - start) / reps;

    // Pre-fix this measured ~2,000,000 ns/call at k=250 (audit: ~4,000,000
    // for the ~2x-costlier default `.redirect` trailing-slash path this
    // test does not exercise). A 200 us ceiling is ~10x a fast machine's
    // actual post-fix cost (single-digit microseconds) and ~10x below the
    // pre-fix cost, wide enough to absorb ordinary noise while still
    // catching a regression back to the O(k^2) shape.
    errdefer std.debug.print("F4 probe: avg {d} ns/call over {d} reps (k={d})\n", .{ avg_ns, reps, k });
    try testing.expect(avg_ns < 200_000);
}

// ── Static: the comptime table ──────────────────────────────────────────────

const static_demo = [_]StaticRoute{
    .{ .method = .get, .pattern = "/users/new" },
    .{ .method = .get, .pattern = "/users/:id" },
    .{ .method = .post, .pattern = "/users" },
    .{ .method = .delete, .pattern = "/users/:id" },
    .{ .method = .get, .pattern = "/static/*path" },
    .{ .method = .get, .pattern = "/dir/" },
};

test "Static: precedence, captures, HEAD -> GET, 405 with Router's Allow, 404" {
    const S = Static(&static_demo, .{});
    var p: Params = .{};

    try testing.expectEqual(Match{ .found = 0 }, S.match(.get, "/users/new", &p));
    try testing.expectEqual(@as(usize, 0), p.len);

    try testing.expectEqual(Match{ .found = 1 }, S.match(.get, "/users/42", &p));
    try testing.expectEqualStrings("42", p.get("id").?);
    try testing.expectEqual(Match{ .found = 1 }, S.match(.head, "/users/42", &p));
    try testing.expectEqual(Match{ .found = 3 }, S.match(.delete, "/users/42", &p));

    try testing.expectEqual(Match{ .found = 4 }, S.match(.get, "/static/css/a.css", &p));
    try testing.expectEqualStrings("css/a.css", p.get("path").?);

    const m = S.match(.put, "/users/42", &p);
    var buf: [Allow.max_len]u8 = undefined;
    try testing.expectEqualStrings("GET, HEAD, DELETE", m.method_not_allowed.write(&buf));
    try testing.expect(m.method_not_allowed.has(.head));
    try testing.expect(!m.method_not_allowed.has(.put));

    try testing.expectEqual(Match.not_found, S.match(.get, "/nope", &p));
    try testing.expectEqual(Match.not_found, S.match(.get, "users", &p));
    // `:id` never matches an empty segment.
    try testing.expectEqual(Match.not_found, S.match(.get, "/users/", &p));
}

test "Static: trailing-slash variant mirrors Router's redirect probe" {
    const S = Static(&static_demo, .{});
    try testing.expectEqual(S.SlashVariant.add_slash, S.trailingSlashVariant(.get, "/dir").?);
    try testing.expectEqual(S.SlashVariant.drop_slash, S.trailingSlashVariant(.post, "/users/").?);
    try testing.expectEqual(@as(?S.SlashVariant, null), S.trailingSlashVariant(.post, "/dir"));
    try testing.expectEqual(@as(?S.SlashVariant, null), S.trailingSlashVariant(.get, "/nope"));
}

test "validatePattern and Router.add refuse the same patterns" {
    const bad = [_][]const u8{
        "",                            "x", "//x", "/a//b", "/:", "/*", "/*w/x", "/a:b", "/:a/:a", "/:a/*a", "/:x:y",
        "/:a/:b/:c/:d/:e/:f/:g/:h/:i",
    };
    for (bad) |pat| {
        var r = Router.init(testing.allocator);
        defer r.deinit();
        const want = if (r.add(.get, pat, hRoot)) |_| return error.RouterAcceptedABadPattern else |e| e;
        try testing.expectError(want, validatePattern(pat));
    }
    try validatePattern("/x/");
    try validatePattern("/a/:b/*c");
}

// M2.2 -- the differential test: the comptime table against the runtime trie,
// on generated tables, every method, both precedence postures.

const diff_vocab = [_][]const u8{ "a", "b", "users", "x" };

/// A comptime-generated table: `count` patterns of 1..4 segments drawn from
/// static words, one capture name per depth (`:p<depth>`, so no two routes
/// can conflict on a name) and a final `*w`, deduplicated per (method,
/// pattern).
fn diffTable(comptime seed: u64, comptime count: usize) []const StaticRoute {
    comptime {
        @setEvalBranchQuota(200_000);
        var state = seed;
        var out: [count]StaticRoute = undefined;
        var n: usize = 0;
        const methods = [_]http.Method{ .get, .post, .put, .delete, .head };
        while (n < count) {
            var pat: []const u8 = "";
            state = state *% 6364136223846793005 +% 1442695040888963407;
            const depth = 1 + (state >> 33) % 4;
            var d: usize = 0;
            while (d < depth) : (d += 1) {
                state = state *% 6364136223846793005 +% 1442695040888963407;
                const pick = (state >> 33) % 10;
                const seg: []const u8 = if (pick < 6)
                    diff_vocab[pick % diff_vocab.len]
                else if (pick < 9)
                    ":p" ++ std.fmt.comptimePrint("{d}", .{d})
                else if (d + 1 == depth) "*w" else diff_vocab[0];
                pat = pat ++ "/" ++ seg;
            }
            state = state *% 6364136223846793005 +% 1442695040888963407;
            if ((state >> 40) % 8 == 0 and !std.mem.endsWith(u8, pat, "*w")) pat = pat ++ "/";
            state = state *% 6364136223846793005 +% 1442695040888963407;
            const m = methods[(state >> 33) % methods.len];
            var dup = false;
            for (out[0..n]) |o| {
                if (o.method == m and std.mem.eql(u8, o.pattern, pat)) dup = true;
            }
            if (!dup) {
                out[n] = .{ .method = m, .pattern = pat };
                n += 1;
            }
        }
        const final = out;
        return &final;
    }
}

fn diffPath(rng: std.Random, buf: []u8) []const u8 {
    const words = diff_vocab ++ [_][]const u8{ "42", "" };
    var w: std.Io.Writer = .fixed(buf);
    const depth = 1 + rng.uintLessThan(usize, 5);
    for (0..depth) |_| {
        w.writeByte('/') catch unreachable;
        w.writeAll(words[rng.uintLessThan(usize, words.len)]) catch unreachable;
    }
    return w.buffered();
}

fn diffOne(comptime routes: []const StaticRoute, comptime prec: MethodPrecedence) !void {
    const S = Static(routes, .{ .method_precedence = prec });
    var r = Router.init(testing.allocator);
    defer r.deinit();
    for (routes) |rt| try r.add(rt.method, rt.pattern, hRoot);

    var prng: std.Random.DefaultPrng = .init(0x5eed ^ routes.len);
    const rng = prng.random();
    var buf: [128]u8 = undefined;
    var checked: usize = 0;
    for (0..3000) |_| {
        const path = diffPath(rng, &buf);
        inline for (@typeInfo(http.Method).@"enum".fields) |f| {
            const m: http.Method = @enumFromInt(f.value);
            var ps: Params = .{};
            const got = S.match(m, path, &ps);

            var pr: Params = .{};
            var allow_bits: AllowSet = .initEmpty();
            var want_pattern: ?[]const u8 = null;
            switch (prec) {
                .backtrack => {
                    if (matchRecMethod(&r.root, path[1..], &pr, m, &allow_bits)) |node|
                        want_pattern = endpointFor(node, m).?.pattern;
                },
                .first_match => if (matchRec(&r.root, path[1..], false, &pr)) |node| {
                    if (endpointFor(node, m)) |ep| want_pattern = ep.pattern else allow_bits = node.allow_bits;
                },
            }

            errdefer std.debug.print("differential: {s} {s} (table of {d}, {s})\n", .{ @tagName(m), path, routes.len, @tagName(prec) });
            if (want_pattern) |wp| {
                if (got != .found) return error.StaticMissedARouterMatch;
                try testing.expectEqualStrings(wp, routes[got.found].pattern);
                try testing.expectEqual(pr.len, ps.len);
                for (pr.entries[0..pr.len], ps.entries[0..ps.len]) |a, b| {
                    try testing.expectEqualStrings(a.name, b.name);
                    try testing.expectEqualStrings(a.value, b.value);
                }
                checked += 1;
            } else if (allow_bits.count() != 0) {
                if (got != .method_not_allowed) return error.StaticDisagreesOn405;
                try testing.expectEqual(allow_bits, got.method_not_allowed.bits);
            } else {
                try testing.expectEqual(Match.not_found, got);
            }
        }
    }
    // A table that never matches anything would pass vacuously.
    try testing.expect(checked > 0);
}

test "M2.2 differential: Static answers exactly as the runtime Router, generated tables" {
    inline for (.{ 1, 2, 3, 4, 5, 6, 7, 8 }) |seed| {
        const routes = comptime diffTable(@as(u64, seed) *% 0x9e3779b97f4a7c15, 12 + seed * 3);
        try diffOne(routes, .backtrack);
        try diffOne(routes, .first_match);
    }
}
