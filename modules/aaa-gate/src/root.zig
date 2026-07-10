// SPDX-License-Identifier: MIT

//! aaa-gate — bearer-token authentication, an audit hook and a
//! denied-request throttle as a `router` middleware: the AAA layer of the
//! Web/API cluster.
//!
//! Provenance: original work of the zig-libs authors (MIT). Behavior
//! modeled (design only) after envoy's ext_authz + oauth2-proxy's bearer
//! handling; bearer semantics per RFC 6750.
//!
//! ## What the gate does
//!
//! - **Authentication.** Requests in the protected scope must present
//!   `Authorization: Bearer <token>` matching one of the configured
//!   tokens. Verification hashes both sides (SHA-256) and compares the
//!   fixed-size digests with `std.crypto.timing_safe.eql`, scanning the
//!   whole token set without early exit — constant-time in the token
//!   content, the candidate length and which slot matched. Missing,
//!   malformed or wrong credentials answer **401** with
//!   `WWW-Authenticate: Bearer` and the chain is short-circuited (`next`
//!   never runs). A valid request gets an `Identity` attached to
//!   `ctx.data` (the slot `router` reserves for this module) and flows on.
//! - **API-key scheme.** `Options.auth_mode` selects the accepted
//!   scheme(s): `.bearer` (default — the behavior above, unchanged),
//!   `.api_key`, or `.either`. The API key arrives in the `X-Api-Key`
//!   header (configurable via `api_key_header`) or, when
//!   `api_key_query_param` is set, as that query parameter (verbatim, not
//!   percent-decoded — the header wins when both are present). It is
//!   verified against the configured key set (`api_key` ∪
//!   `extra_api_keys`) with the *same* constant-time digest compare as
//!   bearer, or by a caller-supplied `api_key_verify` callback (an escape
//!   hatch for a dynamic store — use `secretEqual` inside it, never
//!   `std.mem.eql`, to avoid a timing leak). A failed API-key attempt is
//!   audited and throttled exactly like a failed bearer attempt (401,
//!   same challenge, same denied-request coalescing). In `.either` mode a
//!   valid bearer **or** a valid API key passes; **bearer takes
//!   precedence** — it is checked first and its `Identity.scheme` wins
//!   when both are valid. The open plane (below) applies per mode: the
//!   plane is open only when *no* credential for the active mode(s) is
//!   configured.
//! - **Scope.** `Options.protect` picks what needs auth: `.all` (the
//!   default — secure by default) or `.mutations` (the read/write
//!   boundary: only POST/PUT/PATCH/DELETE are gated; GET/HEAD/OPTIONS
//!   stay open).
//!   Under `.all`, register `cors` *before* the gate so browser
//!   preflights (which cannot carry Authorization) are intercepted
//!   before they would 401.
//! - **Open plane.** An empty token set means **no authentication** —
//!   every request passes with `Identity.scheme == .open` (a deliberate
//!   dev/demo default: turning auth on is providing a token). If you want
//!   deny-by-default, always configure a token.
//! - **Audit.** `Options.on_audit` is a hook, not a logger: it fires
//!   synchronously with an `AuditEntry` for every **authenticated
//!   mutation** (after the handler, with the final status and the
//!   `target`/`detail` the handler put on the Identity) and for every
//!   **denial** (401, any method). Reads are not audited. Entry slices
//!   borrow request-scoped memory — copy what you keep.
//! - **Denied-request throttle** (per-key).
//!   Repeated 401s from one client are coalesced to ~1 audit entry per
//!   `throttle_window_ms` (default 5 s), folding the suppressed count
//!   into the next admitted entry (`AuditEntry.suppressed`) — an
//!   unauthenticated flood cannot flood the audit sink. Keys follow the
//!   same client-IP trust rule as `ratelimit`: rightmost element of the
//!   last `X-Forwarded-For` header (the one hop a client cannot forge
//!   when a trusted proxy fronts the server), else `X-Real-IP`, else the
//!   socket peer IP (port excluded, IPv4-mapped IPv6 unified with plain
//!   IPv4), else one shared fallback key. The store is bounded
//!   (`throttle_max_keys`, LRU eviction). The clock is injected
//!   (`Options.clock`) so tests are deterministic; only the default
//!   `.monotonic` clock ever touches the OS.
//! - **Rotation.** The token set = `Options.token` ∪
//!   `Options.extra_tokens`, mutable at runtime via `addToken` /
//!   `removeToken` — token-file rotation as an API (add the new token,
//!   migrate clients, remove the old; no file, no restart).
//!
//! ## Thread-safety
//!
//! Internally synchronized: token set and throttle store sit behind one
//! spinlock (`std.atomic.Mutex` + `spinLoopHint`, the std SmpAllocator
//! pattern — Zig 0.16 std has no io-less blocking mutex); critical
//! sections are a digest scan / hash-map touch, never an allocation
//! larger than one throttle entry. All public calls may race from
//! `http.Server`'s connection threads. Token hashing happens outside the
//! lock. The `Gate` must outlive the `Router` serving requests, at a
//! stable address (the middleware's `state` points at it).

const std = @import("std");
const builtin = @import("builtin");
const router = @import("router");
const http = @import("http");

pub const meta = .{
    .platform = .any,
    .role = .server,
    // Internally synchronized (documented spinlock over token set +
    // throttle store); safe from all connection threads at once.
    .concurrency = .threadsafe,
    .model_after = "envoy ext_authz / oauth2-proxy (bearer behavior only); RFC 6750",
    .deps = .{ "router", "http" },
};

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

// ── clock injection ─────────────────────────────────────────────────────────

/// Monotonic time source, injected so the throttle is deterministic under
/// test. Implementations must be non-decreasing; the absolute origin is
/// irrelevant (only differences are used).
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) u64,

    /// The OS monotonic clock (CLOCK_MONOTONIC; QueryPerformanceCounter
    /// on Windows). The production default — and the only place in the
    /// module that touches a real clock.
    pub const monotonic: Clock = .{ .nowFn = monotonicNowNs };

    pub fn now(c: Clock) u64 {
        return c.nowFn(c.ctx);
    }
};

fn monotonicNowNs(_: ?*anyopaque) u64 {
    switch (builtin.os.tag) {
        .windows => {
            const windows = std.os.windows;
            var qpf: windows.LARGE_INTEGER = undefined;
            var qpc: windows.LARGE_INTEGER = undefined;
            if (!windows.ntdll.RtlQueryPerformanceFrequency(&qpf).toBool()) return 0;
            if (!windows.ntdll.RtlQueryPerformanceCounter(&qpc).toBool()) return 0;
            const freq: u64 = @bitCast(qpf);
            const count: u64 = @bitCast(qpc);
            return @intCast(@as(u128, count) * std.time.ns_per_s / freq);
        },
        else => {
            var ts: std.posix.timespec = undefined;
            if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS)
                return 0;
            return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
        },
    }
}

// ── the per-request vocabulary ──────────────────────────────────────────────

/// Which methods require authentication.
pub const Protect = enum {
    /// Every method is gated (the default — secure by default). Put
    /// `cors` before the gate so preflights don't 401.
    all,
    /// Only mutations (POST/PUT/PATCH/DELETE) are gated; GET/HEAD/OPTIONS
    /// stay open (the read/write boundary).
    mutations,
};

/// Which authentication scheme(s) the gate accepts.
pub const AuthMode = enum {
    /// Only `Authorization: Bearer <token>` (the default — unchanged
    /// behavior). API-key options are ignored.
    bearer,
    /// Only the API key (`X-Api-Key` header / query-param fallback).
    /// Bearer options are ignored.
    api_key,
    /// A valid bearer **or** a valid API key passes. Bearer is checked
    /// first and takes precedence — its `Identity.scheme` wins when both
    /// are valid.
    either,
};

/// Default header carrying the API key (`Options.api_key_header`).
pub const default_api_key_header = "X-Api-Key";

/// Caller-supplied API-key verifier — the escape hatch mirroring the
/// bearer set for a dynamic key store. Receives the presented key
/// verbatim; returns whether it is valid. **Must** compare in constant
/// time (see `secretEqual`); never `std.mem.eql` on the secret. Called on
/// the serving thread, after the static key set misses. `ctx` is
/// `Options.api_key_verify_ctx` verbatim.
pub const ApiKeyVerifyFn = *const fn (ctx: ?*anyopaque, presented_key: []const u8) bool;

/// Constant-time equality for secret material (compares fixed-size
/// SHA-256 digests via `std.crypto.timing_safe.eql`, so neither content
/// nor length leaks). Exposed for `api_key_verify` callbacks so a custom
/// key store reuses the module's timing-safe compare instead of the
/// leaky `std.mem.eql`.
pub fn secretEqual(a: []const u8, b: []const u8) bool {
    return std.crypto.timing_safe.eql([Sha256.digest_length]u8, fingerprint(a), fingerprint(b));
}

/// What the gate attaches to `ctx.data` for requests it lets through.
/// Lives on the middleware's stack frame — valid for the duration of the
/// inner chain + handler call only; `ctx.data` is restored afterwards.
pub const Identity = struct {
    /// How the request passed the gate.
    scheme: Scheme,
    /// Handlers may fill these so the audit entry records *what* the
    /// mutation touched, not just the route.
    /// Slices must stay valid until the handler returns (request-scoped
    /// or static memory).
    audit_target: []const u8 = "",
    audit_detail: []const u8 = "",

    pub const Scheme = enum {
        /// A configured bearer token, verified in constant time.
        bearer,
        /// A configured API key (from the `X-Api-Key` header or the
        /// optional query-param fallback), verified in constant time.
        api_key,
        /// No credentials configured — open plane (dev default, documented).
        open,
    };
};

/// The identity the gate attached to this request, or null when no gate
/// ran / the method was out of the protected scope. Only meaningful below
/// a `Gate.middleware()` in the chain — the cast trusts that `ctx.data`
/// was set by this module (the slot `router` reserves for it).
pub fn identityOf(ctx: *const router.Ctx) ?*Identity {
    const p = ctx.data orelse return null;
    return @ptrCast(@alignCast(p));
}

/// One audited request (the audit-record fields, minus storage
/// concerns — persisting is the hook's job). All slices borrow
/// request-scoped memory: valid for the duration of the hook call only.
pub const AuditEntry = struct {
    method: http.Method,
    /// Request path (no query).
    path: []const u8,
    /// Resource the mutation touched — `Identity.audit_target` as filled
    /// by the handler; "" for denials (no handler ran).
    target: []const u8,
    /// Op-specific extra — `Identity.audit_detail`; "" for denials.
    detail: []const u8,
    /// False exactly for denials (401 short-circuits).
    authed: bool,
    /// Final response status. For an authenticated mutation whose handler
    /// errored before sending, this is the 500 the server will emit.
    status: u16,
    /// Denials only: how many earlier denials from the same client key
    /// were coalesced (not individually reported) since the last admitted
    /// entry — the "+N suppressed" fold, as data. 0 otherwise.
    suppressed: u64,
};

/// The audit hook. Called synchronously on the serving thread (keep it
/// cheap or hand off); it must not touch `ctx`/the response. `ctx` is
/// `Options.on_audit_ctx` verbatim.
pub const AuditFn = *const fn (ctx: ?*anyopaque, entry: AuditEntry) void;

/// Custom throttle-key extraction (overrides the forwarded-IP chain).
/// Must return a key valid for the duration of the call (the store copies
/// what it keeps).
pub const KeyFn = struct {
    ctx: ?*anyopaque = null,
    keyFor: *const fn (?*anyopaque, *router.Ctx) []const u8,
};

/// Throttle key when neither a forwarded/real-IP header nor a socket peer
/// address exists — only possible when the codec is driven socket-free
/// (`http.Server.serveStream` without `StreamOptions.peer`).
pub const fallback_key = "(no-client-ip)";

/// Buffer size for peer-IP key formatting (fits a full uncompressed IPv6).
pub const client_key_len_max = 48;

pub const Options = struct {
    /// The primary bearer token. Not retained — only its SHA-256 digest
    /// is stored. Null + empty `extra_tokens` ⇒ **open plane** (documented
    /// above). Must be non-empty when set.
    token: ?[]const u8 = null,
    /// Additional valid tokens (rotation set). Not retained.
    extra_tokens: []const []const u8 = &.{},
    /// Which methods require auth. Default `.all` (see `Protect`).
    protect: Protect = .all,
    /// Accepted authentication scheme(s). Default `.bearer` (existing
    /// behavior). See `AuthMode`; the `api_key*` options below apply when
    /// this is `.api_key` or `.either`.
    auth_mode: AuthMode = .bearer,
    /// The primary API key. Not retained — only its SHA-256 digest is
    /// stored. Must be non-empty when set. With an empty key set and no
    /// `api_key_verify`, the API-key scheme is an open plane (like an
    /// empty token set).
    api_key: ?[]const u8 = null,
    /// Additional valid API keys (rotation set). Not retained.
    extra_api_keys: []const []const u8 = &.{},
    /// Caller-supplied API-key verifier (dynamic store); tried after the
    /// static key set. See `ApiKeyVerifyFn` — must compare in constant
    /// time. Its presence alone closes the API-key open plane.
    api_key_verify: ?ApiKeyVerifyFn = null,
    /// Opaque pointer handed to every `api_key_verify` call.
    api_key_verify_ctx: ?*anyopaque = null,
    /// Header the API key is read from (case-insensitive). Copied into the
    /// gate. Default `X-Api-Key`.
    api_key_header: []const u8 = default_api_key_header,
    /// When set, the API key may also arrive as this query parameter
    /// (value taken verbatim — not percent-decoded); the header wins when
    /// both are present. Copied into the gate. Null ⇒ header only.
    api_key_query_param: ?[]const u8 = null,
    /// Optional realm for the challenge: `WWW-Authenticate: Bearer
    /// realm="<realm>"`. Must be quoted-string-safe (no `"` or `\`).
    /// Null ⇒ plain `WWW-Authenticate: Bearer`.
    realm: ?[]const u8 = null,
    /// Audit hook; null disables auditing (and the throttle with it).
    on_audit: ?AuditFn = null,
    /// Opaque pointer handed to every `on_audit` call.
    on_audit_ctx: ?*anyopaque = null,
    /// Denied-audit coalescing window per client key: within it, repeated
    /// 401s add to the suppressed count instead of reaching the hook.
    /// 0 disables coalescing (every denial is reported).
    throttle_window_ms: u64 = 5 * std.time.ms_per_s,
    /// At most this many distinct client keys tracked by the throttle
    /// (memory bound); beyond it the least-recently-seen key is evicted
    /// (its pending suppressed count is dropped — bounded memory wins).
    /// Must be ≥ 1.
    throttle_max_keys: usize = 1024,
    /// Time source for the throttle — inject a fake for deterministic
    /// tests.
    clock: Clock = .monotonic,
    /// Throttle-key extraction override; null = the forwarded-IP chain
    /// (`ratelimit`'s trust rule, see the module doc).
    throttle_key: ?KeyFn = null,
};

// ── the gate ────────────────────────────────────────────────────────────────

pub const Gate = struct {
    gpa: Allocator,
    protect: Protect,
    auth_mode: AuthMode = .bearer,
    on_audit: ?AuditFn,
    on_audit_ctx: ?*anyopaque,
    window_ns: u64,
    max_keys: usize,
    clock: Clock,
    throttle_key: ?KeyFn,
    /// Precomputed `WWW-Authenticate` value, gpa-owned (stable across the
    /// response lifetime — no per-request formatting on the deny path).
    challenge: []const u8,
    /// API-key verifier callback (dynamic store) + its ctx.
    api_key_verify: ?ApiKeyVerifyFn = null,
    api_key_verify_ctx: ?*anyopaque = null,
    /// Header the API key is read from — gpa-owned copy.
    api_key_header: []const u8 = default_api_key_header,
    /// Optional query-param fallback name — gpa-owned copy, or null.
    api_key_query_param: ?[]const u8 = null,
    lock: std.atomic.Mutex = .unlocked,
    /// SHA-256 digests of the valid tokens (never the tokens themselves).
    tokens: std.ArrayList([Sha256.digest_length]u8) = .empty,
    /// SHA-256 digests of the valid API keys (never the keys themselves).
    api_keys: std.ArrayList([Sha256.digest_length]u8) = .empty,
    throttle: Throttle = .{},

    /// Build a gate. Token/realm slices are consumed (hashed / formatted),
    /// never retained.
    pub fn init(gpa: Allocator, options: Options) error{OutOfMemory}!Gate {
        std.debug.assert(options.throttle_max_keys >= 1);
        var tokens: std.ArrayList([Sha256.digest_length]u8) = .empty;
        errdefer tokens.deinit(gpa);
        if (options.token) |t| {
            std.debug.assert(t.len != 0);
            try tokens.append(gpa, fingerprint(t));
        }
        for (options.extra_tokens) |t| {
            std.debug.assert(t.len != 0);
            const fp = fingerprint(t);
            if (!containsFp(tokens.items, fp)) try tokens.append(gpa, fp);
        }
        var api_keys: std.ArrayList([Sha256.digest_length]u8) = .empty;
        errdefer api_keys.deinit(gpa);
        if (options.api_key) |k| {
            std.debug.assert(k.len != 0);
            try api_keys.append(gpa, fingerprint(k));
        }
        for (options.extra_api_keys) |k| {
            std.debug.assert(k.len != 0);
            const fp = fingerprint(k);
            if (!containsFp(api_keys.items, fp)) try api_keys.append(gpa, fp);
        }
        const challenge = if (options.realm) |r|
            try std.fmt.allocPrint(gpa, "Bearer realm=\"{s}\"", .{r})
        else
            try gpa.dupe(u8, "Bearer");
        errdefer gpa.free(challenge);
        std.debug.assert(options.api_key_header.len != 0);
        const api_key_header = try gpa.dupe(u8, options.api_key_header);
        errdefer gpa.free(api_key_header);
        const api_key_query_param = if (options.api_key_query_param) |q| blk: {
            std.debug.assert(q.len != 0);
            break :blk try gpa.dupe(u8, q);
        } else null;
        return .{
            .gpa = gpa,
            .protect = options.protect,
            .auth_mode = options.auth_mode,
            .on_audit = options.on_audit,
            .on_audit_ctx = options.on_audit_ctx,
            .window_ns = options.throttle_window_ms *| std.time.ns_per_ms,
            .max_keys = options.throttle_max_keys,
            .clock = options.clock,
            .throttle_key = options.throttle_key,
            .challenge = challenge,
            .api_key_verify = options.api_key_verify,
            .api_key_verify_ctx = options.api_key_verify_ctx,
            .api_key_header = api_key_header,
            .api_key_query_param = api_key_query_param,
            .tokens = tokens,
            .api_keys = api_keys,
        };
    }

    pub fn deinit(g: *Gate) void {
        g.gpa.free(g.challenge);
        g.gpa.free(g.api_key_header);
        if (g.api_key_query_param) |q| g.gpa.free(q);
        g.tokens.deinit(g.gpa);
        g.api_keys.deinit(g.gpa);
        g.throttle.deinit(g.gpa);
        g.* = undefined;
    }

    /// A `router.Middleware` enforcing this gate (`state` = the Gate —
    /// per-instance state, no globals). Register it once, before routes;
    /// the Gate must outlive the Router, at a stable address.
    pub fn middleware(g: *Gate) router.Middleware {
        return .{ .state = g, .run = middlewareRun };
    }

    pub const Verdict = enum {
        /// A configured bearer token matched (constant-time).
        ok_bearer,
        /// A configured API key matched (constant-time).
        ok_api_key,
        /// No credentials configured for the checked scheme — open plane.
        ok_open,
        denied,
    };

    /// The pure auth decision for a presented bearer token (null = none
    /// presented). Thread-safe; hashing happens outside the lock, the
    /// digest scan visits every configured token without early exit.
    pub fn verify(g: *Gate, presented: ?[]const u8) Verdict {
        const fp: ?[Sha256.digest_length]u8 = if (presented) |p| fingerprint(p) else null;
        lockSpin(&g.lock);
        defer g.lock.unlock();
        if (g.tokens.items.len == 0) return .ok_open;
        const got = fp orelse return .denied;
        var ok = false;
        for (g.tokens.items) |want|
            ok = std.crypto.timing_safe.eql([Sha256.digest_length]u8, want, got) or ok;
        return if (ok) .ok_bearer else .denied;
    }

    /// The pure auth decision for a presented API key (null = none
    /// presented). Reuses the *same* constant-time digest compare as
    /// `verify` — never `std.mem.eql` on the secret. The static key set is
    /// scanned in full (no early exit); on a miss the `api_key_verify`
    /// callback (if any) is consulted outside the lock. Returns `.ok_open`
    /// when no key set and no callback are configured.
    pub fn verifyApiKey(g: *Gate, presented: ?[]const u8) Verdict {
        const has_verify = g.api_key_verify != null;
        const fp: ?[Sha256.digest_length]u8 = if (presented) |p| fingerprint(p) else null;
        {
            lockSpin(&g.lock);
            defer g.lock.unlock();
            if (g.api_keys.items.len == 0 and !has_verify) return .ok_open;
            if (fp) |got| {
                if (containsFp(g.api_keys.items, got)) return .ok_api_key;
            }
        }
        // Static set missed; consult the dynamic verifier (caller code —
        // kept outside the lock). Its own compare must be constant-time.
        if (has_verify) {
            if (presented) |p| {
                if (g.api_key_verify.?(g.api_key_verify_ctx, p)) return .ok_api_key;
            }
        }
        return .denied;
    }

    /// Add an API key to the valid set (rotation, mirrors `addToken`).
    /// Idempotent; `key` is hashed, not retained; must be non-empty.
    pub fn addApiKey(g: *Gate, key: []const u8) error{OutOfMemory}!void {
        std.debug.assert(key.len != 0);
        const fp = fingerprint(key);
        lockSpin(&g.lock);
        defer g.lock.unlock();
        if (containsFp(g.api_keys.items, fp)) return;
        try g.api_keys.append(g.gpa, fp);
    }

    /// Remove an API key from the valid set (mirrors `removeToken`; no-op
    /// when absent).
    pub fn removeApiKey(g: *Gate, key: []const u8) void {
        const fp = fingerprint(key);
        lockSpin(&g.lock);
        defer g.lock.unlock();
        var i: usize = 0;
        while (i < g.api_keys.items.len) {
            if (std.crypto.timing_safe.eql([Sha256.digest_length]u8, g.api_keys.items[i], fp)) {
                _ = g.api_keys.swapRemove(i);
            } else i += 1;
        }
    }

    /// Number of currently valid API keys (diagnostics / tests).
    pub fn apiKeyCount(g: *Gate) usize {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        return g.api_keys.items.len;
    }

    /// Add a token to the valid set (rotation step 1: add the new token,
    /// migrate clients, then `removeToken` the old). Idempotent — adding
    /// a token that is already valid is a no-op. `token` is hashed, not
    /// retained; must be non-empty.
    pub fn addToken(g: *Gate, token: []const u8) error{OutOfMemory}!void {
        std.debug.assert(token.len != 0);
        const fp = fingerprint(token);
        lockSpin(&g.lock);
        defer g.lock.unlock();
        if (containsFp(g.tokens.items, fp)) return;
        try g.tokens.append(g.gpa, fp);
    }

    /// Remove a token from the valid set (no-op when absent). Removing
    /// the last token reopens the plane — see the open-plane note.
    pub fn removeToken(g: *Gate, token: []const u8) void {
        const fp = fingerprint(token);
        lockSpin(&g.lock);
        defer g.lock.unlock();
        var i: usize = 0;
        while (i < g.tokens.items.len) {
            if (std.crypto.timing_safe.eql([Sha256.digest_length]u8, g.tokens.items[i], fp)) {
                _ = g.tokens.swapRemove(i);
            } else i += 1;
        }
    }

    /// Number of currently valid tokens (diagnostics / tests).
    pub fn tokenCount(g: *Gate) usize {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        return g.tokens.items.len;
    }

    /// Distinct client keys currently tracked by the denied-request
    /// throttle (diagnostics / tests).
    pub fn throttleKeyCount(g: *Gate) usize {
        lockSpin(&g.lock);
        defer g.lock.unlock();
        return g.throttle.map.count();
    }

    // ── internals ───────────────────────────────────────────────────────

    /// Denied-audit admission for `key` at the injected clock's now:
    /// null = coalesced (within the window — the hook stays quiet), else
    /// the number of previously suppressed denials to fold into the entry
    /// written now (the per-key denied-request decision).
    /// OOM tracking a new key fails open (the entry is admitted,
    /// untracked — an allocator hiccup must not silence the audit trail).
    fn deniedDecision(g: *Gate, key: []const u8) ?u64 {
        const now = g.clock.now();
        lockSpin(&g.lock);
        defer g.lock.unlock();
        return g.throttle.decide(g.gpa, key, now, g.window_ns, g.max_keys);
    }

    fn emit(g: *Gate, entry: AuditEntry) void {
        g.on_audit.?(g.on_audit_ctx, entry);
    }
};

/// SHA-256 fingerprint of a token. Verifying via fixed-size digests and
/// `std.crypto.timing_safe.eql` keeps the compare constant-time in both
/// branches and never leaks the candidate's length or content.
fn fingerprint(token: []const u8) [Sha256.digest_length]u8 {
    var out: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(token, &out, .{});
    return out;
}

fn containsFp(list: []const [Sha256.digest_length]u8, fp: [Sha256.digest_length]u8) bool {
    var found = false;
    for (list) |t| found = std.crypto.timing_safe.eql([Sha256.digest_length]u8, t, fp) or found;
    return found;
}

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// ── the denied-request throttle store ───────────────────────────────────────

/// Per-key coalescing state (keyed + bounded).
/// Guarded by the Gate's lock — no locking of its own.
const Throttle = struct {
    /// Keyed by `Entry.key` (gpa-owned copies).
    map: std.StringHashMapUnmanaged(*Entry) = .empty,
    /// Front = most recently seen; evictions pop the back.
    lru: std.DoublyLinkedList = .{},

    const Entry = struct {
        node: std.DoublyLinkedList.Node = .{},
        key: []u8,
        /// Instant of the last admitted (hook-reaching) denial.
        last_ns: u64,
        /// Denials coalesced since then.
        suppressed: u64,
    };

    fn deinit(t: *Throttle, gpa: Allocator) void {
        var it = t.map.valueIterator();
        while (it.next()) |e| {
            gpa.free(e.*.key);
            gpa.destroy(e.*);
        }
        t.map.deinit(gpa);
        t.* = undefined;
    }

    /// See `Gate.deniedDecision`. `now_ns` non-decreasing (a backwards
    /// step counts as no time passing — suppresses, never underflows).
    fn decide(t: *Throttle, gpa: Allocator, key: []const u8, now_ns: u64, window_ns: u64, max_keys: usize) ?u64 {
        if (t.map.get(key)) |e| {
            t.lru.remove(&e.node);
            t.lru.prepend(&e.node);
            if (window_ns != 0 and now_ns -| e.last_ns < window_ns) {
                e.suppressed += 1;
                return null;
            }
            const folded = e.suppressed;
            e.suppressed = 0;
            e.last_ns = now_ns;
            return folded;
        }

        // New key. First sweep entries that are past the window with
        // nothing pending (lossless memory release), then enforce the cap
        // (evicting the LRU tail may drop its pending count — documented).
        while (t.lru.last) |tail| {
            const e: *Entry = @fieldParentPtr("node", tail);
            if (e.suppressed != 0 or now_ns -| e.last_ns < window_ns) break;
            t.removeEntry(gpa, e);
        }
        if (t.map.count() >= max_keys)
            t.removeEntry(gpa, @fieldParentPtr("node", t.lru.last.?));

        t.insert(gpa, key, now_ns) catch {}; // OOM → fail open (documented)
        return 0;
    }

    fn insert(t: *Throttle, gpa: Allocator, key: []const u8, now_ns: u64) Allocator.Error!void {
        const e = try gpa.create(Entry);
        errdefer gpa.destroy(e);
        e.* = .{ .key = try gpa.dupe(u8, key), .last_ns = now_ns, .suppressed = 0 };
        errdefer gpa.free(e.key);
        try t.map.put(gpa, e.key, e);
        t.lru.prepend(&e.node);
    }

    fn removeEntry(t: *Throttle, gpa: Allocator, e: *Entry) void {
        const removed = t.map.remove(e.key);
        std.debug.assert(removed);
        t.lru.remove(&e.node);
        gpa.free(e.key);
        gpa.destroy(e);
    }
};

// ── request parsing helpers ─────────────────────────────────────────────────

/// A mutating method (the write half of the read/write boundary).
fn isMutating(m: http.Method) bool {
    return switch (m) {
        .post, .put, .delete, .patch => true,
        .get, .head, .options => false,
    };
}

/// The bearer token of the request, or null when the Authorization header
/// is absent, uses another scheme, or is malformed (never panics — any
/// header byte sequence maps to a token or to null). Scheme match is
/// case-insensitive per RFC 9110; surrounding whitespace is tolerated.
fn bearerToken(req: *const http.Server.Request) ?[]const u8 {
    const auth = req.header("authorization") orelse return null;
    const value = std.mem.trim(u8, auth, " \t");
    if (value.len < "Bearer ".len) return null;
    if (!std.ascii.eqlIgnoreCase(value[0..6], "Bearer")) return null;
    if (value[6] != ' ') return null;
    const tok = std.mem.trim(u8, value[7..], " \t");
    if (tok.len == 0) return null;
    return tok;
}

/// The API key presented on the request: the (case-insensitive)
/// `api_key_header` value, else the `api_key_query_param` query value when
/// configured, else null. Both are trimmed of surrounding SP/TAB; an
/// empty value counts as absent. The query value is taken verbatim (no
/// percent-decoding), so the header is preferred for keys with reserved
/// characters.
fn apiKeyPresented(g: *const Gate, req: *const http.Server.Request) ?[]const u8 {
    if (req.header(g.api_key_header)) |v| {
        const k = std.mem.trim(u8, v, " \t");
        if (k.len != 0) return k;
    }
    if (g.api_key_query_param) |name| {
        if (queryValue(req.query, name)) |v| {
            const k = std.mem.trim(u8, v, " \t");
            if (k.len != 0) return k;
        }
    }
    return null;
}

/// First value of query parameter `name` in a raw query string
/// (`key=val&key2=val2`), or null. The name compare is a plain byte
/// compare (the parameter name is not a secret); the value is returned
/// verbatim.
fn queryValue(query: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], name)) return pair[eq + 1 ..];
    }
    return null;
}

/// The throttle's client key per the trust rule shared with `ratelimit`
/// (see the module doc): rightmost element of the **last**
/// `X-Forwarded-For` header, else `X-Real-IP`, else the socket peer IP
/// (formatted into `buf`, port excluded; IPv4-mapped IPv6 unified with
/// plain IPv4), else `fallback_key`.
fn clientKey(req: *const http.Server.Request, buf: *[client_key_len_max]u8) []const u8 {
    var xff: ?[]const u8 = null;
    var it = req.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "x-forwarded-for")) xff = h.value;
    }
    if (xff) |v| {
        const start = if (std.mem.lastIndexOfScalar(u8, v, ',')) |i| i + 1 else 0;
        const ip = std.mem.trim(u8, v[start..], " \t");
        if (ip.len != 0) return clampKey(ip, buf);
    }
    if (req.header("x-real-ip")) |v| {
        const ip = std.mem.trim(u8, v, " \t");
        if (ip.len != 0) return clampKey(ip, buf);
    }
    if (req.peerAddress()) |peer| return formatPeerIp(peer, buf);
    return fallback_key;
}

/// Clamp an attacker-controlled, header-derived key candidate to
/// `client_key_len_max` bytes (copied into `buf`) so a forged
/// `X-Forwarded-For`/`X-Real-IP` value of unbounded length can't blow up the
/// bounded throttle store's per-entry key cost or evade coalescing by varying
/// only past the cap — same bound the peer-IP path already gets from
/// `formatPeerIp`/`formatV4`.
fn clampKey(v: []const u8, buf: *[client_key_len_max]u8) []const u8 {
    const n = @min(v.len, client_key_len_max);
    @memcpy(buf[0..n], v[0..n]);
    return buf[0..n];
}

/// Format a peer IP as a stable key: dotted quad for IPv4 (including
/// IPv4-mapped IPv6, unmapped), full uncompressed hex groups for IPv6
/// (RFC 5952 compression is irrelevant for a map key — determinism is).
fn formatPeerIp(peer: std.Io.net.IpAddress, buf: *[client_key_len_max]u8) []const u8 {
    switch (peer) {
        .ip4 => |a| return formatV4(a.bytes, buf),
        .ip6 => |a| {
            const b = a.bytes;
            const v4_mapped = std.mem.allEqual(u8, b[0..10], 0) and b[10] == 0xff and b[11] == 0xff;
            if (v4_mapped) return formatV4(b[12..16].*, buf);
            var w: std.Io.Writer = .fixed(buf);
            for (0..8) |i| {
                const group = (@as(u16, b[2 * i]) << 8) | b[2 * i + 1];
                w.print("{s}{x:0>4}", .{ if (i == 0) "" else ":", group }) catch unreachable;
            }
            return w.buffered();
        },
    }
}

fn formatV4(bytes: [4]u8, buf: *[client_key_len_max]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] }) catch unreachable;
}

// ── the middleware ──────────────────────────────────────────────────────────

/// The combined auth decision for a request under `g.auth_mode`. Returns
/// the winning `Identity.Scheme`, or null when the request must be denied.
/// Every configured scheme is checked with the module's constant-time
/// digest compare. In `.either`, bearer is checked first and wins when
/// both credentials are valid (documented precedence); the plane is open
/// only when no credential is configured for the active mode(s).
fn authorize(g: *Gate, req: *const http.Server.Request) ?Identity.Scheme {
    switch (g.auth_mode) {
        .bearer => return schemeOf(g.verify(bearerToken(req))),
        .api_key => return schemeOf(g.verifyApiKey(apiKeyPresented(g, req))),
        .either => {
            const bearer_v = g.verify(bearerToken(req)); // ok_open ⇒ no tokens
            const key_v = g.verifyApiKey(apiKeyPresented(g, req)); // ok_open ⇒ no keys
            if (bearer_v == .ok_open and key_v == .ok_open) return .open;
            if (bearer_v == .ok_bearer) return .bearer; // precedence
            if (key_v == .ok_api_key) return .api_key;
            return null;
        },
    }
}

/// Map a single-scheme `Verdict` to the identity scheme it admits, or null
/// for `.denied`.
fn schemeOf(v: Gate.Verdict) ?Identity.Scheme {
    return switch (v) {
        .ok_bearer => .bearer,
        .ok_api_key => .api_key,
        .ok_open => .open,
        .denied => null,
    };
}

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const g: *Gate = @ptrCast(@alignCast(state.?));

    const in_scope = switch (g.protect) {
        .all => true,
        .mutations => isMutating(ctx.req.method),
    };
    if (!in_scope) return next.run(ctx); // open read: no auth, no audit

    const scheme = authorize(g, ctx.req) orelse {
        // Denied: 401, chain short-circuited. Header values are gate-owned
        // stable memory, so no early end() is needed.
        ctx.res.setStatus(401);
        try ctx.res.setHeader("WWW-Authenticate", g.challenge);
        try ctx.res.setHeader("Content-Type", "text/plain");
        try ctx.res.writeAll("Unauthorized\n");
        auditDenied(g, ctx);
        return;
    };

    var ident: Identity = .{ .scheme = scheme };
    const saved = ctx.data;
    ctx.data = &ident;
    defer ctx.data = saved;

    const audited = g.on_audit != null and isMutating(ctx.req.method);
    next.run(ctx) catch |err| {
        // The server answers 500 when nothing was sent yet; otherwise the
        // head already on the wire carries the status that counts.
        if (audited) g.emit(authedEntry(ctx, &ident, if (ctx.res.headSent()) ctx.res.status else 500));
        return err;
    };
    if (audited) g.emit(authedEntry(ctx, &ident, ctx.res.status));
}

fn authedEntry(ctx: *router.Ctx, ident: *const Identity, status: u16) AuditEntry {
    return .{
        .method = ctx.req.method,
        .path = ctx.req.path,
        .target = ident.audit_target,
        .detail = ident.audit_detail,
        .authed = true,
        .status = status,
        .suppressed = 0,
    };
}

fn auditDenied(g: *Gate, ctx: *router.Ctx) void {
    if (g.on_audit == null) return; // no sink — nothing to protect either
    var key_buf: [client_key_len_max]u8 = undefined;
    const key = if (g.throttle_key) |k| k.keyFor(k.ctx, ctx) else clientKey(ctx.req, &key_buf);
    const folded = g.deniedDecision(key) orelse return; // coalesced
    g.emit(.{
        .method = ctx.req.method,
        .path = ctx.req.path,
        .target = "",
        .detail = "",
        .authed = false,
        .status = 401,
        .suppressed = folded,
    });
}

// ── tests: pure pieces (no HTTP) ────────────────────────────────────────────

const testing = std.testing;

/// Deterministic test clock.
const TestClock = struct {
    ns: u64 = 0,

    fn clock(t: *TestClock) Clock {
        return .{ .ctx = t, .nowFn = nowFn };
    }
    fn nowFn(ctx: ?*anyopaque) u64 {
        const t: *TestClock = @ptrCast(@alignCast(ctx.?));
        return t.ns;
    }
    fn advanceMs(t: *TestClock, ms: u64) void {
        t.ns += ms * std.time.ns_per_ms;
    }
};

test "verify: constant-time compare — both branches, plus length mismatch and no-token" {
    var g = try Gate.init(testing.allocator, .{ .token = "s3cr3t" });
    defer g.deinit();

    // Match branch and mismatch branch go through the same digest
    // compare (timing_safe.eql over SHA-256 fingerprints).
    try testing.expectEqual(Gate.Verdict.ok_bearer, g.verify("s3cr3t"));
    try testing.expectEqual(Gate.Verdict.denied, g.verify("s3cr3T")); // same length
    try testing.expectEqual(Gate.Verdict.denied, g.verify("s3cr3")); // shorter
    try testing.expectEqual(Gate.Verdict.denied, g.verify("s3cr3t-and-more")); // longer
    try testing.expectEqual(Gate.Verdict.denied, g.verify(null)); // nothing presented
    try testing.expectEqual(Gate.Verdict.denied, g.verify("")); // empty candidate
}

test "verify: open plane when no tokens are configured" {
    var g = try Gate.init(testing.allocator, .{});
    defer g.deinit();
    try testing.expectEqual(@as(usize, 0), g.tokenCount());
    try testing.expectEqual(Gate.Verdict.ok_open, g.verify(null));
    try testing.expectEqual(Gate.Verdict.ok_open, g.verify("anything"));
}

test "rotation: extra tokens, addToken/removeToken, old works until removed" {
    var g = try Gate.init(testing.allocator, .{
        .token = "primary",
        .extra_tokens = &.{ "spare-1", "spare-1", "spare-2" }, // dup collapses
    });
    defer g.deinit();
    try testing.expectEqual(@as(usize, 3), g.tokenCount());
    try testing.expectEqual(Gate.Verdict.ok_bearer, g.verify("primary"));
    try testing.expectEqual(Gate.Verdict.ok_bearer, g.verify("spare-1"));
    try testing.expectEqual(Gate.Verdict.ok_bearer, g.verify("spare-2"));

    // Rotation: add the new token — the old one still works…
    try g.addToken("fresh");
    try g.addToken("fresh"); // idempotent
    try testing.expectEqual(@as(usize, 4), g.tokenCount());
    try testing.expectEqual(Gate.Verdict.ok_bearer, g.verify("fresh"));
    try testing.expectEqual(Gate.Verdict.ok_bearer, g.verify("primary"));

    // …until it is removed.
    g.removeToken("primary");
    g.removeToken("never-was"); // absent → no-op
    try testing.expectEqual(@as(usize, 3), g.tokenCount());
    try testing.expectEqual(Gate.Verdict.denied, g.verify("primary"));
    try testing.expectEqual(Gate.Verdict.ok_bearer, g.verify("fresh"));
}

test "throttle: coalesces one key within the window, folds the suppressed count (seed semantics)" {
    var tc: TestClock = .{};
    var g = try Gate.init(testing.allocator, .{
        .token = "t",
        .throttle_window_ms = 5_000,
        .clock = tc.clock(),
    });
    defer g.deinit();

    tc.ns = 1000;
    // First denial always reaches the hook (folds 0 prior).
    try testing.expectEqual(@as(?u64, 0), g.deniedDecision("1.2.3.4"));
    // Within the window: suppressed.
    try testing.expectEqual(@as(?u64, null), g.deniedDecision("1.2.3.4"));
    tc.advanceMs(4_999);
    try testing.expectEqual(@as(?u64, null), g.deniedDecision("1.2.3.4"));
    // A different key has its own window.
    try testing.expectEqual(@as(?u64, 0), g.deniedDecision("5.6.7.8"));
    // Past the window: admitted, folding the 2 suppressed denials.
    tc.advanceMs(1);
    try testing.expectEqual(@as(?u64, 2), g.deniedDecision("1.2.3.4"));
    // Counter reset after an admitted entry.
    try testing.expectEqual(@as(?u64, null), g.deniedDecision("1.2.3.4"));
}

test "throttle: window 0 disables coalescing and keeps no state" {
    var tc: TestClock = .{};
    var g = try Gate.init(testing.allocator, .{
        .token = "t",
        .throttle_window_ms = 0,
        .clock = tc.clock(),
    });
    defer g.deinit();

    try testing.expectEqual(@as(?u64, 0), g.deniedDecision("a"));
    try testing.expectEqual(@as(?u64, 0), g.deniedDecision("a")); // window 0: never coalesced
    try testing.expectEqual(@as(?u64, 0), g.deniedDecision("b"));
    try testing.expectEqual(@as(?u64, 0), g.deniedDecision("c"));
    // With no window every entry is instantly stale-with-nothing-pending,
    // so each new key sweeps the rest — no state accumulates.
    try testing.expectEqual(@as(usize, 1), g.throttleKeyCount());
}

test "throttle: store bounded by max_keys (LRU eviction); evicted keys restart fresh" {
    var tc: TestClock = .{};
    var g = try Gate.init(testing.allocator, .{
        .token = "t",
        .throttle_window_ms = 60_000,
        .throttle_max_keys = 2,
        .clock = tc.clock(),
    });
    defer g.deinit();

    try testing.expectEqual(@as(?u64, 0), g.deniedDecision("a"));
    try testing.expectEqual(@as(?u64, 0), g.deniedDecision("b"));
    try testing.expectEqual(@as(?u64, 0), g.deniedDecision("c")); // at cap → evicts a (LRU)
    try testing.expectEqual(@as(usize, 2), g.throttleKeyCount());
    // a was evicted → its next denial is admitted again (fresh window)…
    try testing.expectEqual(@as(?u64, 0), g.deniedDecision("a"));
    // …while a surviving key is still coalescing.
    try testing.expectEqual(@as(?u64, null), g.deniedDecision("c"));
    try testing.expectEqual(@as(usize, 2), g.throttleKeyCount());
}

test "throttle: idle keys with nothing pending are swept; pending counts survive the sweep" {
    var tc: TestClock = .{};
    var g = try Gate.init(testing.allocator, .{
        .token = "t",
        .throttle_window_ms = 1_000,
        .clock = tc.clock(),
    });
    defer g.deinit();

    _ = g.deniedDecision("a"); // admitted; nothing pending
    _ = g.deniedDecision("b"); // admitted
    _ = g.deniedDecision("b"); // suppressed → b has a pending count
    try testing.expectEqual(@as(usize, 2), g.throttleKeyCount());

    tc.advanceMs(1_500); // both past the window
    _ = g.deniedDecision("c"); // insert sweeps the stale a, keeps b (pending)
    try testing.expectEqual(@as(usize, 2), g.throttleKeyCount());
    // b's pending count was preserved and folds on its next denial.
    try testing.expectEqual(@as(?u64, 1), g.deniedDecision("b"));
}

test "throttle: fail-open when the allocator is exhausted (audit not silenced)" {
    var tc: TestClock = .{};
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var g = Gate{
        .gpa = failing.allocator(),
        .protect = .all,
        .on_audit = null,
        .on_audit_ctx = null,
        .window_ns = std.time.ns_per_s,
        .max_keys = 8,
        .clock = tc.clock(),
        .throttle_key = null,
        .challenge = "",
        .tokens = .empty,
    };
    // Tracking fails → the denial is still admitted, nothing stored.
    try testing.expectEqual(@as(?u64, 0), g.deniedDecision("k"));
    try testing.expectEqual(@as(?u64, 0), g.deniedDecision("k"));
    try testing.expectEqual(@as(usize, 0), g.throttleKeyCount());
    g.throttle.deinit(testing.allocator);
    g.tokens.deinit(testing.allocator);
    g.api_keys.deinit(testing.allocator);
}

// ── tests: API-key scheme (pure pieces) ─────────────────────────────────────

test "verifyApiKey: same constant-time compare — same-length wrong key rejected" {
    var g = try Gate.init(testing.allocator, .{ .auth_mode = .api_key, .api_key = "k3y-abcdef" });
    defer g.deinit();

    try testing.expectEqual(Gate.Verdict.ok_api_key, g.verifyApiKey("k3y-abcdef"));
    // Same length, single byte differs → must be denied (proves the
    // decision is not a length/prefix check but the full digest compare).
    try testing.expectEqual(Gate.Verdict.denied, g.verifyApiKey("k3y-abcdeF"));
    try testing.expectEqual(Gate.Verdict.denied, g.verifyApiKey("k3y-abcde")); // shorter
    try testing.expectEqual(Gate.Verdict.denied, g.verifyApiKey("k3y-abcdef-plus")); // longer
    try testing.expectEqual(Gate.Verdict.denied, g.verifyApiKey(null)); // none presented
    try testing.expectEqual(Gate.Verdict.denied, g.verifyApiKey("")); // empty candidate
}

test "verifyApiKey: open plane when no keys and no verifier configured" {
    var g = try Gate.init(testing.allocator, .{ .auth_mode = .api_key });
    defer g.deinit();
    try testing.expectEqual(@as(usize, 0), g.apiKeyCount());
    try testing.expectEqual(Gate.Verdict.ok_open, g.verifyApiKey(null));
    try testing.expectEqual(Gate.Verdict.ok_open, g.verifyApiKey("anything"));
}

test "secretEqual: constant-time helper matches only equal secrets (incl. same length)" {
    try testing.expect(secretEqual("hunter2", "hunter2"));
    try testing.expect(!secretEqual("hunter2", "hunter3")); // same length, differs
    try testing.expect(!secretEqual("hunter2", "hunter")); // shorter
    try testing.expect(secretEqual("", "")); // equal (matching digests) — documented edge
}

test "api-key rotation: extra_api_keys, addApiKey/removeApiKey (mirrors bearer)" {
    var g = try Gate.init(testing.allocator, .{
        .auth_mode = .api_key,
        .api_key = "primary-key",
        .extra_api_keys = &.{ "spare-a", "spare-a", "spare-b" }, // dup collapses
    });
    defer g.deinit();
    try testing.expectEqual(@as(usize, 3), g.apiKeyCount());
    try testing.expectEqual(Gate.Verdict.ok_api_key, g.verifyApiKey("primary-key"));
    try testing.expectEqual(Gate.Verdict.ok_api_key, g.verifyApiKey("spare-b"));

    try g.addApiKey("fresh-key");
    try g.addApiKey("fresh-key"); // idempotent
    try testing.expectEqual(@as(usize, 4), g.apiKeyCount());
    try testing.expectEqual(Gate.Verdict.ok_api_key, g.verifyApiKey("fresh-key"));

    g.removeApiKey("primary-key");
    g.removeApiKey("never-was"); // no-op
    try testing.expectEqual(@as(usize, 3), g.apiKeyCount());
    try testing.expectEqual(Gate.Verdict.denied, g.verifyApiKey("primary-key"));
    try testing.expectEqual(Gate.Verdict.ok_api_key, g.verifyApiKey("fresh-key"));
}

/// A dynamic API-key verifier using the module's constant-time helper (the
/// escape hatch: it must not leak timing via `std.mem.eql`).
fn dynVerify(ctx: ?*anyopaque, presented: []const u8) bool {
    const want: *const []const u8 = @ptrCast(@alignCast(ctx.?));
    return secretEqual(presented, want.*);
}

test "verifyApiKey: caller-supplied verifier (escape hatch), consulted after the static set" {
    var expected: []const u8 = "dyn-secret";
    var g = try Gate.init(testing.allocator, .{
        .auth_mode = .api_key,
        .api_key = "static-key",
        .api_key_verify = dynVerify,
        .api_key_verify_ctx = @ptrCast(&expected),
    });
    defer g.deinit();

    try testing.expectEqual(Gate.Verdict.ok_api_key, g.verifyApiKey("static-key")); // static set
    try testing.expectEqual(Gate.Verdict.ok_api_key, g.verifyApiKey("dyn-secret")); // dynamic
    try testing.expectEqual(Gate.Verdict.denied, g.verifyApiKey("dyn-secreT")); // same-length wrong
    try testing.expectEqual(Gate.Verdict.denied, g.verifyApiKey(null));
}

// ── tests: middleware over the socket-free server codec ─────────────────────

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Drive a router through `http.Server.serveStream` with canned wire
/// bytes (same harness as router/ratelimit), optionally with a socket
/// peer; returns the full response byte stream.
fn runWirePeer(r: *router.Router, bytes: []const u8, out_buf: []u8, peer: ?std.Io.net.IpAddress) []const u8 {
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
        .peer = peer,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    return runWirePeer(r, bytes, out_buf, null);
}

fn wire(comptime method: []const u8, comptime target: []const u8, comptime headers: []const u8) []const u8 {
    return method ++ " " ++ target ++ " HTTP/1.1\r\nHost: t\r\n" ++ headers ++ "Connection: close\r\n\r\n";
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

/// Audit sink recording entries (copies — entry slices are
/// request-scoped) plus a handler hit counter, wired through
/// `on_audit_ctx` / `Ctx.state`.
const Sink = struct {
    recs: [16]Rec = undefined,
    len: usize = 0,
    hits: u32 = 0,

    const Rec = struct {
        method: http.Method,
        authed: bool,
        status: u16,
        suppressed: u64,
        path_buf: [64]u8 = undefined,
        path_len: usize = 0,
        target_buf: [64]u8 = undefined,
        target_len: usize = 0,
        detail_buf: [64]u8 = undefined,
        detail_len: usize = 0,

        fn path(r: *const Rec) []const u8 {
            return r.path_buf[0..r.path_len];
        }
        fn target(r: *const Rec) []const u8 {
            return r.target_buf[0..r.target_len];
        }
        fn detail(r: *const Rec) []const u8 {
            return r.detail_buf[0..r.detail_len];
        }
    };

    fn hook(ctx: ?*anyopaque, entry: AuditEntry) void {
        const s: *Sink = @ptrCast(@alignCast(ctx.?));
        var rec: Rec = .{
            .method = entry.method,
            .authed = entry.authed,
            .status = entry.status,
            .suppressed = entry.suppressed,
        };
        rec.path_len = copyInto(&rec.path_buf, entry.path);
        rec.target_len = copyInto(&rec.target_buf, entry.target);
        rec.detail_len = copyInto(&rec.detail_buf, entry.detail);
        s.recs[s.len] = rec;
        s.len += 1;
    }

    fn copyInto(buf: []u8, s: []const u8) usize {
        const n = @min(buf.len, s.len);
        @memcpy(buf[0..n], s[0..n]);
        return n;
    }
};

fn hHello(ctx: *router.Ctx) anyerror!void {
    if (ctx.state) |st| {
        const s: *Sink = @ptrCast(@alignCast(st));
        s.hits += 1;
    }
    try ctx.res.writeAll("hello");
}

/// Handler that requires the bearer identity and fills the audit fields
/// (a failed expectation errors → 500, so 200 proves the identity).
fn hSecretMutation(ctx: *router.Ctx) anyerror!void {
    const id = identityOf(ctx) orelse return error.NoIdentity;
    try testing.expectEqual(Identity.Scheme.bearer, id.scheme);
    id.audit_target = "device-7";
    id.audit_detail = "reboot";
    if (ctx.state) |st| {
        const s: *Sink = @ptrCast(@alignCast(st));
        s.hits += 1;
    }
    ctx.res.setStatus(201);
    try ctx.res.writeAll("done");
}

/// Handler asserting the gate attached NO identity (out-of-scope method).
fn hNoIdentity(ctx: *router.Ctx) anyerror!void {
    try testing.expectEqual(@as(?*Identity, null), identityOf(ctx));
    try ctx.res.writeAll("open");
}

/// Handler asserting the open-plane identity.
fn hOpenIdentity(ctx: *router.Ctx) anyerror!void {
    const id = identityOf(ctx) orelse return error.NoIdentity;
    try testing.expectEqual(Identity.Scheme.open, id.scheme);
    try ctx.res.writeAll("open-plane");
}

fn hBoom(_: *router.Ctx) anyerror!void {
    return error.Boom;
}

const GatedRouter = struct {
    r: router.Router,

    fn init(g: *Gate, sink: ?*Sink) !GatedRouter {
        var r = router.Router.init(testing.allocator);
        errdefer r.deinit();
        if (sink) |s| r.state = s;
        try r.use(g.middleware());
        try r.get("/t", hHello);
        try r.post("/t", hSecretMutation);
        return .{ .r = r };
    }

    fn deinit(gr: *GatedRouter) void {
        gr.r.deinit();
    }
};

test "middleware: golden 401 with WWW-Authenticate; valid Bearer → 200 + identity; handler never runs on deny" {
    var sink: Sink = .{};
    var g = try Gate.init(testing.allocator, .{ .token = "s3cr3t" });
    defer g.deinit();
    var gr = try GatedRouter.init(&g, &sink);
    defer gr.deinit();
    var buf: [1024]u8 = undefined;

    // No credentials: the full golden 401.
    try testing.expectEqualStrings("HTTP/1.1 401 Unauthorized\r\n" ++
        "WWW-Authenticate: Bearer\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 13\r\n" ++
        "\r\n" ++
        "Unauthorized\n", runWire(&gr.r, wire("GET", "/t", ""), &buf));
    try testing.expectEqual(@as(u32, 0), sink.hits); // handler never ran

    // Valid token: 200 and the handler saw the bearer identity (POST
    // handler asserts it; 201 proves the assertions passed).
    const got = runWire(&gr.r, wire("POST", "/t", "Authorization: Bearer s3cr3t\r\n"), &buf);
    try expectStatus(got, "201");
    try testing.expectEqualStrings("done", bodyOf(got));
    try testing.expectEqual(@as(u32, 1), sink.hits);

    // Scheme is case-insensitive (RFC 9110); GET works too under .all.
    try expectStatus(runWire(&gr.r, wire("GET", "/t", "Authorization: bearer s3cr3t\r\n"), &buf), "200");
    try testing.expectEqual(@as(u32, 2), sink.hits);

    // Wrong token: 401 + WWW-Authenticate, handler hit count unchanged.
    const denied = runWire(&gr.r, wire("POST", "/t", "Authorization: Bearer wrong\r\n"), &buf);
    try expectStatus(denied, "401");
    try expectHeaderLine(denied, "WWW-Authenticate: Bearer");
    try testing.expectEqual(@as(u32, 2), sink.hits);
}

test "middleware: malformed Authorization never panics, always 401" {
    var g = try Gate.init(testing.allocator, .{ .token = "s3cr3t" });
    defer g.deinit();
    var gr = try GatedRouter.init(&g, null);
    defer gr.deinit();
    var buf: [1024]u8 = undefined;

    inline for (.{
        "Authorization: Bearer\r\n", // scheme only
        "Authorization: Bearer \r\n", // scheme + space, empty token
        "Authorization: Bearer   \t \r\n", // whitespace token
        "Authorization: Bearers3cr3t\r\n", // missing separator
        "Authorization: Basic czNjcjN0\r\n", // wrong scheme
        "Authorization: B\r\n", // shorter than the scheme
        "Authorization: \r\n", // empty value
        "Authorization: Bearer\ts3cr3t\r\n", // tab separator (not SP)
        "Authorization: =?!@ \x01 garbage\r\n", // junk bytes
    }) |h| {
        const got = runWire(&gr.r, wire("GET", "/t", h), &buf);
        try expectStatus(got, "401");
        try expectHeaderLine(got, "WWW-Authenticate: Bearer");
    }

    // Surrounding whitespace around a well-formed credential is fine.
    try expectStatus(runWire(&gr.r, wire("GET", "/t", "Authorization:   Bearer s3cr3t  \r\n"), &buf), "200");
}

test "middleware: protect=.mutations lets reads through unauthenticated (no identity), gates writes" {
    var sink: Sink = .{};
    var g = try Gate.init(testing.allocator, .{ .token = "s3cr3t", .protect = .mutations });
    defer g.deinit();

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &sink;
    try r.use(g.middleware());
    try r.get("/t", hNoIdentity);
    try r.post("/t", hSecretMutation);
    var buf: [1024]u8 = undefined;

    // GET passes with no token; the handler proves ctx.data stayed null.
    const got = runWire(&r, wire("GET", "/t", ""), &buf);
    try expectStatus(got, "200");
    try testing.expectEqualStrings("open", bodyOf(got));
    // HEAD (auto-routed to GET) and OPTIONS are reads too → open.
    try expectStatus(runWire(&r, wire("HEAD", "/t", ""), &buf), "200");

    // POST without a token → 401; with the token → 201.
    try expectStatus(runWire(&r, wire("POST", "/t", ""), &buf), "401");
    try testing.expectEqual(@as(u32, 0), sink.hits);
    try expectStatus(runWire(&r, wire("POST", "/t", "Authorization: Bearer s3cr3t\r\n"), &buf), "201");
    try testing.expectEqual(@as(u32, 1), sink.hits);
}

test "middleware: open plane (no tokens) passes everything with the .open identity" {
    var g = try Gate.init(testing.allocator, .{});
    defer g.deinit();

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(g.middleware());
    try r.get("/t", hOpenIdentity);
    var buf: [1024]u8 = undefined;

    const got = runWire(&r, wire("GET", "/t", ""), &buf);
    try expectStatus(got, "200");
    try testing.expectEqualStrings("open-plane", bodyOf(got));
}

test "middleware: realm appears in the challenge" {
    var g = try Gate.init(testing.allocator, .{ .token = "s3cr3t", .realm = "api" });
    defer g.deinit();
    var gr = try GatedRouter.init(&g, null);
    defer gr.deinit();
    var buf: [1024]u8 = undefined;

    const got = runWire(&gr.r, wire("GET", "/t", ""), &buf);
    try expectStatus(got, "401");
    try expectHeaderLine(got, "WWW-Authenticate: Bearer realm=\"api\"");
}

test "audit: authed mutation carries handler-filled target/detail + final status; reads unaudited" {
    var sink: Sink = .{};
    var g = try Gate.init(testing.allocator, .{
        .token = "s3cr3t",
        .on_audit = Sink.hook,
        .on_audit_ctx = &sink,
    });
    defer g.deinit();
    var gr = try GatedRouter.init(&g, &sink);
    defer gr.deinit();
    var buf: [1024]u8 = undefined;

    // Authed GET: passes, not audited (reads are not mutations).
    try expectStatus(runWire(&gr.r, wire("GET", "/t", "Authorization: Bearer s3cr3t\r\n"), &buf), "200");
    try testing.expectEqual(@as(usize, 0), sink.len);

    // Authed POST: audited with the handler's audit ctx + the 201.
    try expectStatus(runWire(&gr.r, wire("POST", "/t", "Authorization: Bearer s3cr3t\r\n"), &buf), "201");
    try testing.expectEqual(@as(usize, 1), sink.len);
    const rec = &sink.recs[0];
    try testing.expectEqual(http.Method.post, rec.method);
    try testing.expect(rec.authed);
    try testing.expectEqual(@as(u16, 201), rec.status);
    try testing.expectEqual(@as(u64, 0), rec.suppressed);
    try testing.expectEqualStrings("/t", rec.path());
    try testing.expectEqualStrings("device-7", rec.target());
    try testing.expectEqualStrings("reboot", rec.detail());
}

test "audit: denied mutation audited as unauthenticated 401 with empty target/detail" {
    var sink: Sink = .{};
    var g = try Gate.init(testing.allocator, .{
        .token = "s3cr3t",
        .on_audit = Sink.hook,
        .on_audit_ctx = &sink,
    });
    defer g.deinit();
    var gr = try GatedRouter.init(&g, &sink);
    defer gr.deinit();
    var buf: [1024]u8 = undefined;

    try expectStatus(runWire(&gr.r, wire("POST", "/t", "Authorization: Bearer wrong\r\n"), &buf), "401");
    try testing.expectEqual(@as(usize, 1), sink.len);
    const rec = &sink.recs[0];
    try testing.expectEqual(http.Method.post, rec.method);
    try testing.expect(!rec.authed);
    try testing.expectEqual(@as(u16, 401), rec.status);
    try testing.expectEqual(@as(u64, 0), rec.suppressed);
    try testing.expectEqualStrings("/t", rec.path());
    try testing.expectEqualStrings("", rec.target());
    try testing.expectEqualStrings("", rec.detail());
    try testing.expectEqual(@as(u32, 0), sink.hits); // handler never ran
}

test "audit: a handler error is audited with the 500 the server will send" {
    var sink: Sink = .{};
    var g = try Gate.init(testing.allocator, .{
        .token = "s3cr3t",
        .on_audit = Sink.hook,
        .on_audit_ctx = &sink,
    });
    defer g.deinit();

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(g.middleware());
    try r.post("/boom", hBoom);
    var buf: [1024]u8 = undefined;

    try expectStatus(runWire(&r, wire("POST", "/boom", "Authorization: Bearer s3cr3t\r\n"), &buf), "500");
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expect(sink.recs[0].authed);
    try testing.expectEqual(@as(u16, 500), sink.recs[0].status);
}

test "audit throttle over the wire: one key coalesces, keys are isolated by the XFF trust rule" {
    var tc: TestClock = .{};
    var sink: Sink = .{};
    var g = try Gate.init(testing.allocator, .{
        .token = "s3cr3t",
        .on_audit = Sink.hook,
        .on_audit_ctx = &sink,
        .throttle_window_ms = 5_000,
        .clock = tc.clock(),
    });
    defer g.deinit();
    var gr = try GatedRouter.init(&g, &sink);
    defer gr.deinit();
    var buf: [1024]u8 = undefined;

    tc.ns = std.time.ns_per_s;
    const client_a = "X-Forwarded-For: 9.9.9.9, 1.2.3.4\r\n"; // spoofed prefix, real 1.2.3.4
    const client_a2 = "X-Forwarded-For: 8.8.8.8, 1.2.3.4\r\n"; // same real client
    const client_b = "X-Forwarded-For: 9.9.9.9, 5.6.7.8\r\n";

    // Every request still answers 401 — the throttle bounds the AUDIT
    // trail, never the HTTP responses.
    try expectStatus(runWire(&gr.r, wire("POST", "/t", client_a), &buf), "401");
    try testing.expectEqual(@as(usize, 1), sink.len); // first denial audited
    try expectStatus(runWire(&gr.r, wire("POST", "/t", client_a), &buf), "401");
    try expectStatus(runWire(&gr.r, wire("POST", "/t", client_a2), &buf), "401"); // forged prefix, same key
    try testing.expectEqual(@as(usize, 1), sink.len); // coalesced

    // A different real client (different rightmost element) is its own key.
    try expectStatus(runWire(&gr.r, wire("POST", "/t", client_b), &buf), "401");
    try testing.expectEqual(@as(usize, 2), sink.len);

    // Past the window the next denial is admitted, folding the 2
    // suppressed attempts into its entry.
    tc.advanceMs(5_001);
    try expectStatus(runWire(&gr.r, wire("POST", "/t", client_a), &buf), "401");
    try testing.expectEqual(@as(usize, 3), sink.len);
    try testing.expectEqual(@as(u64, 2), sink.recs[2].suppressed);
    try testing.expect(!sink.recs[2].authed);
}

test "throttle keying: X-Real-IP fallback, socket peer (port-insensitive, v4-mapped unified), fallback key" {
    var tc: TestClock = .{};
    var sink: Sink = .{};
    var g = try Gate.init(testing.allocator, .{
        .token = "s3cr3t",
        .on_audit = Sink.hook,
        .on_audit_ctx = &sink,
        .throttle_window_ms = 60_000,
        .clock = tc.clock(),
    });
    defer g.deinit();
    var gr = try GatedRouter.init(&g, &sink);
    defer gr.deinit();
    var buf: [1024]u8 = undefined;

    tc.ns = std.time.ns_per_s;
    const ip = std.Io.net.IpAddress;
    const peer_a1: ip = ip.parseIp4("10.0.0.1", 1111) catch unreachable;
    const peer_a2: ip = ip.parseIp4("10.0.0.1", 2222) catch unreachable;
    const peer_a6: ip = ip.parseIp6("::ffff:10.0.0.1", 3333) catch unreachable;
    const peer_b6: ip = ip.parseIp6("2001:db8::1", 443) catch unreachable;

    // X-Real-IP keys when no XFF is present: second denial coalesced.
    try expectStatus(runWire(&gr.r, wire("POST", "/t", "X-Real-IP: 7.7.7.7\r\n"), &buf), "401");
    try expectStatus(runWire(&gr.r, wire("POST", "/t", "X-Real-IP: 7.7.7.7\r\n"), &buf), "401");
    try testing.expectEqual(@as(usize, 1), sink.len);

    // Socket peer: port excluded, IPv4-mapped IPv6 unified with IPv4.
    try expectStatus(runWirePeer(&gr.r, wire("POST", "/t", ""), &buf, peer_a1), "401");
    try expectStatus(runWirePeer(&gr.r, wire("POST", "/t", ""), &buf, peer_a2), "401");
    try expectStatus(runWirePeer(&gr.r, wire("POST", "/t", ""), &buf, peer_a6), "401");
    try testing.expectEqual(@as(usize, 2), sink.len); // all three = one key

    // A real IPv6 peer is its own key.
    try expectStatus(runWirePeer(&gr.r, wire("POST", "/t", ""), &buf, peer_b6), "401");
    try testing.expectEqual(@as(usize, 3), sink.len);

    // No headers, no peer (socket-free): the shared fallback key.
    try expectStatus(runWire(&gr.r, wire("POST", "/t", ""), &buf), "401");
    try expectStatus(runWire(&gr.r, wire("POST", "/t", ""), &buf), "401");
    try testing.expectEqual(@as(usize, 4), sink.len);
}

test "throttle keying: an oversized X-Forwarded-For is clamped to client_key_len_max, not stored unbounded" {
    // Two distinct XFF values that agree on the first client_key_len_max
    // bytes and differ only afterward must collapse to the SAME throttle
    // key (proving the key is truncated, not the full attacker-controlled
    // header) — otherwise an attacker could send unique multi-KB XFF values
    // to blow up the bounded store and evade per-key audit coalescing.
    var tc: TestClock = .{};
    var sink: Sink = .{};
    var g = try Gate.init(testing.allocator, .{
        .token = "s3cr3t",
        .on_audit = Sink.hook,
        .on_audit_ctx = &sink,
        .throttle_window_ms = 60_000,
        .clock = tc.clock(),
    });
    defer g.deinit();
    var gr = try GatedRouter.init(&g, &sink);
    defer gr.deinit();
    var buf: [4096]u8 = undefined;

    tc.ns = std.time.ns_per_s;
    const prefix = "9" ** client_key_len_max;
    const xff_a = "X-Forwarded-For: " ++ prefix ++ "-tail-one\r\n";
    const xff_b = "X-Forwarded-For: " ++ prefix ++ "-tail-two-is-much-longer\r\n";

    try expectStatus(runWire(&gr.r, wire("POST", "/t", xff_a), &buf), "401");
    try expectStatus(runWire(&gr.r, wire("POST", "/t", xff_b), &buf), "401");
    // Both truncate to the same client_key_len_max-byte prefix -> one
    // throttle key -> the second denial is coalesced, not a fresh entry.
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqual(@as(usize, 1), g.throttleKeyCount());
}

test "rotation over the wire: new token works, old works until removed" {
    var g = try Gate.init(testing.allocator, .{ .token = "old-tok" });
    defer g.deinit();
    var gr = try GatedRouter.init(&g, null);
    defer gr.deinit();
    var buf: [1024]u8 = undefined;

    try expectStatus(runWire(&gr.r, wire("GET", "/t", "Authorization: Bearer old-tok\r\n"), &buf), "200");
    try g.addToken("new-tok");
    try expectStatus(runWire(&gr.r, wire("GET", "/t", "Authorization: Bearer new-tok\r\n"), &buf), "200");
    try expectStatus(runWire(&gr.r, wire("GET", "/t", "Authorization: Bearer old-tok\r\n"), &buf), "200");
    g.removeToken("old-tok");
    try expectStatus(runWire(&gr.r, wire("GET", "/t", "Authorization: Bearer old-tok\r\n"), &buf), "401");
    try expectStatus(runWire(&gr.r, wire("GET", "/t", "Authorization: Bearer new-tok\r\n"), &buf), "200");
}

/// Handler requiring the API-key identity (like `hSecretMutation` but for
/// the api_key scheme); 201 proves the assertions passed.
fn hApiKeyMutation(ctx: *router.Ctx) anyerror!void {
    const id = identityOf(ctx) orelse return error.NoIdentity;
    try testing.expectEqual(Identity.Scheme.api_key, id.scheme);
    id.audit_target = "device-9";
    id.audit_detail = "rekey";
    if (ctx.state) |st| {
        const s: *Sink = @ptrCast(@alignCast(st));
        s.hits += 1;
    }
    ctx.res.setStatus(201);
    try ctx.res.writeAll("done");
}

test "middleware api_key: valid X-Api-Key → 200/201 + api_key identity; missing/wrong → 401 audited + throttled" {
    var tc: TestClock = .{};
    var sink: Sink = .{};
    var g = try Gate.init(testing.allocator, .{
        .auth_mode = .api_key,
        .api_key = "k3y-abcdef",
        .on_audit = Sink.hook,
        .on_audit_ctx = &sink,
        .throttle_window_ms = 5_000,
        .clock = tc.clock(),
    });
    defer g.deinit();

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &sink;
    try r.use(g.middleware());
    try r.get("/t", hHello);
    try r.post("/t", hApiKeyMutation);
    var buf: [1024]u8 = undefined;

    tc.ns = std.time.ns_per_s;

    // Valid key: GET → 200, POST → 201 (handler saw .api_key identity).
    try expectStatus(runWire(&r, wire("GET", "/t", "X-Api-Key: k3y-abcdef\r\n"), &buf), "200");
    const ok = runWire(&r, wire("POST", "/t", "X-Api-Key: k3y-abcdef\r\n"), &buf);
    try expectStatus(ok, "201");
    try testing.expectEqualStrings("done", bodyOf(ok));
    try testing.expectEqual(@as(u32, 2), sink.hits);
    // Authed mutation was audited with the handler's target.
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expect(sink.recs[0].authed);
    try testing.expectEqualStrings("device-9", sink.recs[0].target());

    // Missing key (client 1.1.1.1) → 401 + challenge, handler untouched,
    // denial audited (new client key → admitted).
    const miss = runWire(&r, wire("POST", "/t", "X-Forwarded-For: 1.1.1.1\r\n"), &buf);
    try expectStatus(miss, "401");
    try expectHeaderLine(miss, "WWW-Authenticate: Bearer");
    try testing.expectEqual(@as(u32, 2), sink.hits);
    try testing.expectEqual(@as(usize, 2), sink.len);
    try testing.expect(!sink.recs[1].authed);
    try testing.expectEqual(@as(u16, 401), sink.recs[1].status);

    // Wrong same-length key from a different client (2.2.2.2) → 401,
    // audited; a second wrong attempt from the SAME key is throttled
    // (coalesced within the window — no new audit entry).
    const cw = "X-Forwarded-For: 2.2.2.2\r\nX-Api-Key: k3y-abcdeF\r\n";
    try expectStatus(runWire(&r, wire("POST", "/t", cw), &buf), "401");
    try testing.expectEqual(@as(usize, 3), sink.len); // first wrong: admitted
    try expectStatus(runWire(&r, wire("POST", "/t", cw), &buf), "401");
    try testing.expectEqual(@as(usize, 3), sink.len); // coalesced within window
}

test "middleware api_key: custom header name and query-param fallback (header wins)" {
    var g = try Gate.init(testing.allocator, .{
        .auth_mode = .api_key,
        .api_key = "sekret",
        .api_key_header = "X-Company-Key",
        .api_key_query_param = "api_key",
    });
    defer g.deinit();

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(g.middleware());
    try r.get("/t", hHello);
    var buf: [1024]u8 = undefined;

    // Default X-Api-Key is NOT accepted when a custom header is configured.
    try expectStatus(runWire(&r, wire("GET", "/t", "X-Api-Key: sekret\r\n"), &buf), "401");
    // The configured custom header works.
    try expectStatus(runWire(&r, wire("GET", "/t", "X-Company-Key: sekret\r\n"), &buf), "200");
    // Query-param fallback works when no header present.
    try expectStatus(runWire(&r, wire("GET", "/t?api_key=sekret", ""), &buf), "200");
    try expectStatus(runWire(&r, wire("GET", "/t?api_key=wrong", ""), &buf), "401");
    // Header wins over the query param (bad header, good query → header used → 401).
    try expectStatus(runWire(&r, wire("GET", "/t?api_key=sekret", "X-Company-Key: wrong\r\n"), &buf), "401");
}

test "middleware either: a valid bearer OR a valid api key admits; bearer takes precedence" {
    var g = try Gate.init(testing.allocator, .{
        .auth_mode = .either,
        .token = "b3arer",
        .api_key = "ap1key",
    });
    defer g.deinit();

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(g.middleware());
    try r.get("/t", hHello);
    var buf: [1024]u8 = undefined;

    // Bearer alone passes.
    try expectStatus(runWire(&r, wire("GET", "/t", "Authorization: Bearer b3arer\r\n"), &buf), "200");
    // API key alone passes.
    try expectStatus(runWire(&r, wire("GET", "/t", "X-Api-Key: ap1key\r\n"), &buf), "200");
    // Neither → 401.
    try expectStatus(runWire(&r, wire("GET", "/t", ""), &buf), "401");
    // Wrong both → 401.
    try expectStatus(runWire(&r, wire("GET", "/t", "Authorization: Bearer no\r\nX-Api-Key: no\r\n"), &buf), "401");
    // Both valid → passes; a bearer-asserting handler proves precedence.
    var r2 = router.Router.init(testing.allocator);
    defer r2.deinit();
    try r2.use(g.middleware());
    try r2.post("/t", hSecretMutation); // asserts .bearer scheme
    try expectStatus(runWire(&r2, wire("POST", "/t", "Authorization: Bearer b3arer\r\nX-Api-Key: ap1key\r\n"), &buf), "201");
}

// ── tests: in-process integration (router + http.Server + http.Client) ──────

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

test "integration: protected route over loopback — 401 / valid Bearer 200 with identity / wrong token 401" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var sink: Sink = .{};
    var g = try Gate.init(testing.allocator, .{
        .token = "s3cr3t-token",
        .on_audit = Sink.hook,
        .on_audit_ctx = &sink,
    });
    defer g.deinit();

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &sink;
    try r.use(g.middleware());
    try r.get("/secret", hHello);
    try r.post("/secret", hSecretMutation);

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
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/secret", .{port});

    { // no token → 401 with the challenge, handler untouched
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 401), res.status);
        try testing.expectEqualStrings("Bearer", res.header("www-authenticate").?);
        const body = try res.readAllAlloc(testing.allocator, 1024);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("Unauthorized\n", body);
        try testing.expectEqual(@as(u32, 0), sink.hits);
    }

    { // valid Bearer → 200; POST handler asserts the identity (201 proves it)
        const auth: []const http.Header = &.{.{ .name = "Authorization", .value = "Bearer s3cr3t-token" }};
        var res = try client.request(.get, url, .{ .headers = auth });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = try res.readAllAlloc(testing.allocator, 1024);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("hello", body);

        var res2 = try client.request(.post, url, .{ .headers = auth });
        defer res2.deinit();
        try testing.expectEqual(@as(u16, 201), res2.status);
        try testing.expectEqual(@as(u32, 2), sink.hits);
    }

    { // wrong token → 401 again
        const bad: []const http.Header = &.{.{ .name = "Authorization", .value = "Bearer wrong-token" }};
        var res = try client.request(.get, url, .{ .headers = bad });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 401), res.status);
        try testing.expectEqualStrings("Bearer", res.header("www-authenticate").?);
    }

    // The authed POST was audited with the handler's audit context.
    var authed_muts: usize = 0;
    for (sink.recs[0..sink.len]) |rec| {
        if (rec.authed) {
            authed_muts += 1;
            try testing.expectEqual(http.Method.post, rec.method);
            try testing.expectEqual(@as(u16, 201), rec.status);
            try testing.expectEqualStrings("device-7", rec.target());
        }
    }
    try testing.expectEqual(@as(usize, 1), authed_muts);
}
