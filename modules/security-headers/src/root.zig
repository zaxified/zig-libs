// SPDX-License-Identifier: MIT

//! security-headers — secure-by-default HTTP security response headers as a
//! stateless `router` middleware.
//!
//! A directly-internet-facing API should ship the standard hardening headers
//! on every response. `SecurityHeaders.init(.{})` gives the secure default
//! set; every header is individually overridable or disable-able through
//! `Options`. The middleware sets the configured headers on the
//! `ResponseWriter` **before** calling `next`, so the handler's head is
//! written with them and a handler may still override any single header by
//! setting it again (`setHeader` replaces by case-insensitive name) —
//! middleware provides the default, the handler wins.
//!
//! Default header set (see `Options` for the knobs):
//!
//! - `Strict-Transport-Security: max-age=31536000; includeSubDomains` —
//!   helmet.js 8.3.0 default (365 days, no `preload`). **Only meaningful over
//!   HTTPS**: browsers ignore HSTS received over plain HTTP, so the header
//!   is harmless there, but only ever deploy it on a host actually served
//!   via TLS — once cached, browsers refuse plain-HTTP for `max-age`
//!   (and, with `include_subdomains`, for every subdomain). Opt into
//!   `preload` only after registering at <https://hstspreload.org>.
//! - `X-Content-Type-Options: nosniff`.
//! - `X-Frame-Options: DENY` (spec-mandated default; helmet defaults to
//!   SAMEORIGIN — deviation noted). This is the legacy anti-clickjacking
//!   header; the modern form is the CSP `frame-ancestors` directive, which
//!   overrides `X-Frame-Options` in supporting browsers — keep the two
//!   consistent when you configure a CSP.
//! - `Referrer-Policy: no-referrer` (helmet default).
//! - `Cross-Origin-Opener-Policy: same-origin`,
//!   `Cross-Origin-Resource-Policy: same-origin` (helmet defaults).
//! - helmet 8.3.0's legacy/cluster defaults, each with its own knob and
//!   on by default: `Origin-Agent-Cluster: ?1`, `X-DNS-Prefetch-Control: off`,
//!   `X-Download-Options: noopen`, `X-Permitted-Cross-Domain-Policies: none`,
//!   `X-XSS-Protection: 0`.
//!
//! Off by default (opt-in):
//!
//! - `Content-Security-Policy` — **no default policy is emitted**. There is
//!   no universally-safe value: a browser-app policy breaks JSON APIs'
//!   consumers no more than an API policy breaks HTML pages, but silently
//!   shipping either is worse than making the choice explicit. Deviation
//!   from helmet (which defaults CSP on) — deliberate, and required by this
//!   module's spec ("CSP present only when configured"). Ready-made
//!   postures: `csp_api` (deny-everything, for pure JSON/binary APIs) and
//!   `csp_helmet_default` (helmet's browser-app default); `api_options` is
//!   the whole-set posture for an API (the defaults without the five
//!   browser-document headers above); the `csp` builder
//!   (`csp.build` at comptime, `csp.render` at run time) assembles and
//!   validates a policy from typed directives and `csp.Nonce` / `applyCspNonce`
//!   put a fresh per-response nonce into it. An optional
//!   `Content-Security-Policy-Report-Only` mirror is independent, for
//!   trialing a policy without enforcing it.
//! - `Permissions-Policy` — caller-supplied feature-policy string
//!   (e.g. `"camera=(), microphone=(), geolocation=()"`).
//! - `Cross-Origin-Embedder-Policy` — **off by default** (matches helmet):
//!   COEP (`require-corp`) breaks every embedded cross-origin resource that
//!   does not opt in via CORP/CORS; enable it only when you need
//!   cross-origin isolation (SharedArrayBuffer et al.).
//! - `Server` — optional fingerprint reduction: a configured value replaces
//!   `http.Server`'s automatic `Server:` header for these responses. To
//!   drop the header entirely, configure the server itself with
//!   `.server_name = null` (a header, once set, can only be replaced).
//! - `extra` — additional static headers emitted verbatim after the set
//!   above: the escape hatch for the curation's long tail (`X-Robots-Tag`,
//!   ...) without a knob each.
//!
//! Stateless and reentrant: the middleware `state` is a pointer to the
//! immutable `SecurityHeaders` (precomputed config) — no clock, no
//! allocation, no locks; the hot path is a fixed series of `setHeader`
//! calls with precomputed strings (the HSTS value is formatted once at
//! `init` into an embedded buffer). Safe to share across all of
//! `http.Server`'s connection threads.
//!
//! Placement: register it **first** (outermost, before other middleware and
//! all routes — chi's rule) so short-circuit responses from inner middleware
//! (ratelimit 429, throttle 503, auth 401) and the router's 404/405
//! fallbacks carry the headers too. Known limitation: when a handler
//! *errors*, `http.Server` resets the response to build its automatic 500,
//! which drops all previously set headers — the plain 500 carries no
//! security headers (same for the server's own 431/414/413 replies, which
//! bypass the router entirely).
//!
//! Header values are emitted verbatim onto the wire: caller-supplied
//! strings must outlive the middleware and must not contain CR/LF (checked
//! with a Debug assert at `init`).
//!
//! Header byte budget: `http.Server.ResponseWriter` copies every header's
//! name and value into a fixed-size per-response buffer, so `apply` (and
//! therefore `middleware`) can fail with `error.HeaderBytesExhausted` — see
//! `SetHeaderError`. Registered first as documented above, this middleware
//! is the *first* thing to touch that buffer, so whether it fails depends
//! only on this configuration's own header set, never on what other
//! middleware adds afterward. `init` checks exactly that condition up
//! front and fails with `InitError.HeaderBudgetExceeded` — see `InitError`
//! — so an oversized `content_security_policy` is rejected once, at
//! startup, in every build mode, rather than 500ing every request from
//! then on with none of this module's headers on that 500 either.

const std = @import("std");
const testkit = @import("testkit");
const router = @import("router");
const http = @import("http");

/// Content-Security-Policy builder and nonce (see `csp.zig`).
pub const csp = @import("csp.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Secure-by-default response headers (HSTS/CSP/nosniff/frame/referrer/COOP/CORP)",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    // An initialized SecurityHeaders is immutable; the middleware only reads
    // it and writes per-request state owned by the connection task.
    .concurrency = .reentrant,
    .model_after = "helmet.js defaults + OWASP Secure Headers Project",
    .deps = .{ "router", "http" },
};

// ── configuration ───────────────────────────────────────────────────────────

/// `Strict-Transport-Security` knobs. The value string is precomputed at
/// `SecurityHeaders.init`. HTTPS-only in effect (browsers ignore HSTS over
/// plain HTTP) — see the module doc before enabling `preload`.
pub const Hsts = struct {
    /// `max-age` in seconds. Default 31536000 (365 days — helmet default).
    max_age_s: u64 = 31_536_000,
    /// Apply to all subdomains too (helmet default: on).
    include_subdomains: bool = true,
    /// Chrome preload-list marker — requires `max_age_s` ≥ 1 year
    /// (`hsts_preload_min_age_s`), `include_subdomains`, and registration at
    /// hstspreload.org. Off by default (helmet default). Like helmet, a
    /// `preload` without the other two is refused: `init` returns
    /// `error.InvalidHstsPreload`, `applyStatic` is a compile error.
    preload: bool = false,

    /// Whether this value satisfies the preload requirements (always true
    /// when `preload` is off).
    pub fn preloadValid(h: Hsts) bool {
        return !h.preload or (h.max_age_s >= hsts_preload_min_age_s and h.include_subdomains);
    }
};

/// Minimum `max-age` for HSTS preload (one year), per hstspreload.org and
/// helmet's check.
pub const hsts_preload_min_age_s: u64 = 31_536_000;

/// One optional per header: `null` (or `false`) disables the header, a
/// string replaces the default value. Defaults = the secure baseline
/// (helmet.js defaults, except `x_frame_options` = DENY per spec). All
/// strings are borrowed — they must outlive the `SecurityHeaders`.
pub const Options = struct {
    /// `Strict-Transport-Security`; null = omit. HTTPS-only in effect.
    hsts: ?Hsts = .{},
    /// `Content-Security-Policy`; **off by default** — no universally-safe
    /// policy exists. See `csp_api` / `csp_helmet_default` for postures.
    content_security_policy: ?[]const u8 = null,
    /// `Content-Security-Policy-Report-Only`; independent of the enforcing
    /// header (typically used to trial a stricter policy).
    content_security_policy_report_only: ?[]const u8 = null,
    /// `X-Content-Type-Options: nosniff` ("nosniff" is the only defined
    /// value, hence a bool). Default on.
    x_content_type_options: bool = true,
    /// `X-Frame-Options`; default DENY (helmet uses SAMEORIGIN). Legacy —
    /// prefer expressing this as CSP `frame-ancestors` when you set a CSP,
    /// and keep both consistent.
    x_frame_options: ?[]const u8 = "DENY",
    /// `Referrer-Policy`; default `no-referrer` (helmet default — the most
    /// private; use "strict-origin-when-cross-origin" for the common
    /// browser-app compromise).
    referrer_policy: ?[]const u8 = "no-referrer",
    /// `Permissions-Policy`; caller-supplied, off by default (helmet does
    /// not set it either).
    permissions_policy: ?[]const u8 = null,
    /// `Cross-Origin-Opener-Policy`; default `same-origin` (helmet default).
    cross_origin_opener_policy: ?[]const u8 = "same-origin",
    /// `Cross-Origin-Resource-Policy`; default `same-origin` (helmet
    /// default; use "cross-origin" for public CDN-style assets).
    cross_origin_resource_policy: ?[]const u8 = "same-origin",
    /// `Cross-Origin-Embedder-Policy`; **off by default** (matches helmet —
    /// it breaks cross-origin embeds). Opt in with "require-corp" (or
    /// "credentialless") only when you need cross-origin isolation.
    cross_origin_embedder_policy: ?[]const u8 = null,
    /// `Origin-Agent-Cluster: ?1` (the only meaningful value, hence a bool).
    /// Default on (helmet default).
    origin_agent_cluster: bool = true,
    /// `X-DNS-Prefetch-Control`; default `off` (helmet default; `"on"` is
    /// the other defined value). Legacy.
    x_dns_prefetch_control: ?[]const u8 = "off",
    /// `X-Download-Options: noopen` (IE-only, legacy; the only value, hence a
    /// bool). Default on (helmet default).
    x_download_options: bool = true,
    /// `X-Permitted-Cross-Domain-Policies`; default `none` (helmet default;
    /// also `master-only`, `by-content-type`, `all`). Legacy (Flash/PDF).
    x_permitted_cross_domain_policies: ?[]const u8 = "none",
    /// `X-XSS-Protection: 0` — disables the buggy legacy XSS auditor, which
    /// is what OWASP and helmet recommend. Default on (helmet default).
    x_xss_protection: bool = true,
    /// Replacement `Server` header value (fingerprint reduction); null =
    /// leave the server's own behavior. Removal is not possible from
    /// middleware — configure `http.Server` with `.server_name = null`.
    server: ?[]const u8 = null,
    /// Additional static headers, emitted verbatim after everything above —
    /// the escape hatch for the curation's long tail (`X-Robots-Tag`, ...)
    /// without a dedicated knob each. Same default-in-effect semantics: a
    /// handler's later `setHeader` wins. Names must be ordinary headers —
    /// the managed ones (`Content-Length`, `Connection`, ...) do not belong
    /// in a static default set; `applyStatic` rejects them at compile time.
    extra: []const http.Header = &.{},
};

/// Deny-everything CSP for a pure JSON/binary API (no HTML is ever
/// rendered from these responses): nothing loads, nothing embeds it.
pub const csp_api: []const u8 =
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

/// The header posture for a pure JSON/binary API: the defaults without
/// helmet 8.3.0's five legacy/cluster headers (`Origin-Agent-Cluster`,
/// `X-DNS-Prefetch-Control`, `X-Download-Options`,
/// `X-Permitted-Cross-Domain-Policies`, `X-XSS-Protection`), which act only
/// on a document a browser renders (or on IE/Flash/Acrobat). Six headers:
/// HSTS, nosniff, X-Frame-Options, Referrer-Policy, COOP, CORP -- the
/// defaults as they were before helmet parity. Each dropped header costs
/// every response bytes on the wire and, over h2, an HPACK lookup; an API pays for
/// them and gets nothing back. CSP stays off, as in `Options{}`: add
/// `csp_api` for a deny-everything policy. Override a field by copying:
/// `comptime blk: { var o = api_options; o.content_security_policy = csp_api; break :blk o; }`.
pub const api_options: Options = .{
    .origin_agent_cluster = false,
    .x_dns_prefetch_control = null,
    .x_download_options = false,
    .x_permitted_cross_domain_policies = null,
    .x_xss_protection = false,
};

/// helmet.js 8.3.0's default browser-app policy, reproduced as configuration
/// data (helmet is MIT; see NOTICE); byte-identical to `csp.build(.{})`. A
/// reasonable starting point when the server also serves HTML.
pub const csp_helmet_default: []const u8 =
    "default-src 'self';base-uri 'self';font-src 'self' https: data:;" ++
    "form-action 'self';frame-ancestors 'self';img-src 'self' data:;" ++
    "object-src 'none';script-src 'self';script-src-attr 'none';" ++
    "style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests";

// "max-age=" + digits of maxInt(u64) + the two flags — the longest possible
// HSTS value, so the init-time formatting below can never fail.
const hsts_buf_len = "max-age=".len +
    std.fmt.count("{d}", .{std.math.maxInt(u64)}) +
    "; includeSubDomains".len + "; preload".len;

// `http.Server.ResponseWriter`'s entire per-response header-byte budget
// (see `header_copy_bytes` in `http/src/Server.zig`), read off the actual
// field's array length rather than duplicated as a literal so this can
// never silently drift out of sync with `http`'s real budget. Every
// `setHeader` call copies BOTH the name and the value into this budget.
const http_header_budget_bytes = @typeInfo(@FieldType(http.Server.ResponseWriter, "header_buf")).array.len;

// ── the middleware ──────────────────────────────────────────────────────────

/// Immutable, precomputed header set + the `router.Middleware` over it.
/// Reentrant: init once (any thread), then share freely.
pub const SecurityHeaders = struct {
    options: Options,
    /// Precomputed `Strict-Transport-Security` value (formatted at init so
    /// the per-request path allocates and formats nothing).
    hsts_buf: [hsts_buf_len]u8 = undefined,
    hsts_len: usize = 0,

    /// `SecurityHeaders.init` failure modes — config-time only, never
    /// returned by `apply`/`middleware` (see `SetHeaderError` for those).
    pub const InitError = error{
        /// This configuration's own header set (names + values, exactly as
        /// `apply` would write them) already exceeds `http.Server`'s
        /// *entire* per-response header-byte budget (`http_header_budget_bytes`,
        /// currently mirroring `http`'s `header_copy_bytes`) by itself —
        /// before any other middleware, handler, or trailer gets a single
        /// byte of it. Registered first (this module's own documented
        /// contract — see the module doc), `apply` runs before anything
        /// else has written to the response, so this is the exact
        /// condition under which `apply`/`middleware` would fail *every*
        /// request with `error.HeaderBytesExhausted`, deterministically,
        /// regardless of what else is in the chain. Caught here instead,
        /// at configuration time, in *every* build mode (this is a real
        /// error return, not a Debug-only assert) — the alternative is
        /// discovering it at request time, where `http.Server` answers
        /// with its automatic 500 and, per this module's "Known
        /// limitation", that 500 carries none of this module's headers
        /// either. Almost always caused by an oversized
        /// `content_security_policy` (and/or its `_report_only` mirror,
        /// when trialing a second, comparably large policy) — shrink it,
        /// split it, or grow `http`'s `header_copy_bytes` if the policy is
        /// genuinely required to be that large.
        HeaderBudgetExceeded,
        /// An `Options.extra` entry's NAME is not an RFC 9110 field-name
        /// token, so `http.Server`'s `setHeader` would reject it with
        /// `error.InvalidHeader` on every request — the same "fails every
        /// request, deterministically" shape `HeaderBudgetExceeded` exists
        /// to catch at configuration time, and for the same reason: that
        /// request-time failure becomes an automatic 500 carrying none of
        /// this module's headers.
        ///
        /// `init` used to validate `extra` VALUES (and only under
        /// `runtime_safety`) while never looking at the names, even though
        /// names go onto the wire just as verbatim. There is no injection
        /// risk either way — `http` re-validates names and values at
        /// `setHeader` time in every build mode — so this is about failing
        /// loudly at config time instead of silently at request time. The
        /// comptime sibling `applyStatic` already rejects the same input
        /// with a `@compileError`.
        InvalidExtraHeaderName,
        /// `hsts.preload` is set but `max_age_s` < `hsts_preload_min_age_s` or
        /// `include_subdomains` is off — hstspreload.org would reject the
        /// site and helmet throws. (`applyStatic` reports it at compile time.)
        InvalidHstsPreload,
    };

    /// RFC 9110 §5.1 field-name token. `http`'s own validator is private to
    /// that module, so the rule is restated here rather than widening its
    /// public surface for one call.
    fn validFieldName(name: []const u8) bool {
        if (name.len == 0) return false;
        for (name) |c| switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9' => {},
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => {},
            else => return false,
        };
        return true;
    }

    /// Precompute the header set. `SecurityHeaders.init(.{})` = the secure
    /// defaults. Caller-supplied strings are borrowed (must outlive the
    /// returned value) and must not contain CR/LF/NUL (Debug-asserted).
    /// Fails with `InitError.HeaderBudgetExceeded` when this configuration's
    /// own headers cannot possibly fit `http`'s per-response header budget
    /// — see `InitError` for why that is checked here rather than left to
    /// surface as a request-time failure.
    pub fn init(options: Options) InitError!SecurityHeaders {
        if (std.debug.runtime_safety) {
            if (options.content_security_policy) |v| assertValueClean(v);
            if (options.content_security_policy_report_only) |v| assertValueClean(v);
            if (options.x_frame_options) |v| assertValueClean(v);
            if (options.referrer_policy) |v| assertValueClean(v);
            if (options.permissions_policy) |v| assertValueClean(v);
            if (options.cross_origin_opener_policy) |v| assertValueClean(v);
            if (options.cross_origin_resource_policy) |v| assertValueClean(v);
            if (options.cross_origin_embedder_policy) |v| assertValueClean(v);
            if (options.x_dns_prefetch_control) |v| assertValueClean(v);
            if (options.x_permitted_cross_domain_policies) |v| assertValueClean(v);
            if (options.server) |v| assertValueClean(v);
            for (options.extra) |h| assertValueClean(h.value);
        }
        for (options.extra) |h| {
            if (!validFieldName(h.name)) return error.InvalidExtraHeaderName;
        }
        if (options.hsts) |h| {
            if (!h.preloadValid()) return error.InvalidHstsPreload;
        }
        var sh: SecurityHeaders = .{ .options = options };
        if (options.hsts) |h| {
            // The buffer is sized for the longest possible value.
            var w: std.Io.Writer = .fixed(&sh.hsts_buf);
            w.print("max-age={d}", .{h.max_age_s}) catch unreachable;
            if (h.include_subdomains) w.writeAll("; includeSubDomains") catch unreachable;
            if (h.preload) w.writeAll("; preload") catch unreachable;
            sh.hsts_len = w.buffered().len;
        }
        if (appliedHeaderBytes(&sh) > http_header_budget_bytes) return error.HeaderBudgetExceeded;
        return sh;
    }

    /// Sum of every header's name+value byte length `apply` would copy into
    /// `http.Server.ResponseWriter.header_buf` for `sh.options` — mirrors
    /// `apply`'s own field list and conditions exactly (same order doesn't
    /// matter here, only the same *set*), so it cannot drift out of sync
    /// with what `apply` actually does short of editing both in lockstep.
    fn appliedHeaderBytes(sh: *const SecurityHeaders) usize {
        const o = &sh.options;
        var total: usize = 0;
        if (o.hsts != null) total += "Strict-Transport-Security".len + sh.hstsValue().len;
        if (o.content_security_policy) |v| total += "Content-Security-Policy".len + v.len;
        if (o.content_security_policy_report_only) |v| total += "Content-Security-Policy-Report-Only".len + v.len;
        if (o.x_content_type_options) total += "X-Content-Type-Options".len + "nosniff".len;
        if (o.x_frame_options) |v| total += "X-Frame-Options".len + v.len;
        if (o.referrer_policy) |v| total += "Referrer-Policy".len + v.len;
        if (o.permissions_policy) |v| total += "Permissions-Policy".len + v.len;
        if (o.cross_origin_opener_policy) |v| total += "Cross-Origin-Opener-Policy".len + v.len;
        if (o.cross_origin_resource_policy) |v| total += "Cross-Origin-Resource-Policy".len + v.len;
        if (o.cross_origin_embedder_policy) |v| total += "Cross-Origin-Embedder-Policy".len + v.len;
        if (o.origin_agent_cluster) total += "Origin-Agent-Cluster".len + "?1".len;
        if (o.x_dns_prefetch_control) |v| total += "X-DNS-Prefetch-Control".len + v.len;
        if (o.x_download_options) total += "X-Download-Options".len + "noopen".len;
        if (o.x_permitted_cross_domain_policies) |v| total += "X-Permitted-Cross-Domain-Policies".len + v.len;
        if (o.x_xss_protection) total += "X-XSS-Protection".len + "0".len;
        if (o.server) |v| total += "Server".len + v.len;
        for (o.extra) |h| total += h.name.len + h.value.len;
        return total;
    }

    /// The precomputed `Strict-Transport-Security` value ("" when disabled).
    pub fn hstsValue(sh: *const SecurityHeaders) []const u8 {
        return sh.hsts_buf[0..sh.hsts_len];
    }

    /// Set every configured header on `res` (emitted in the fixed order
    /// below). Usable directly on any `ResponseWriter` when not routing
    /// through the middleware. Values set here are defaults in effect: a
    /// later `setHeader` with the same name replaces them (handler wins).
    ///
    /// Can fail with `error.HeaderBytesExhausted` (part of `SetHeaderError`)
    /// if `res` doesn't have enough of its header-byte budget left — `sh`
    /// was already checked at `init` time to fit the budget on its own (see
    /// `InitError.HeaderBudgetExceeded`), so reaching this error here means
    /// `res` arrived with some of that budget already spent, i.e. `sh` was
    /// applied somewhere other than first in the chain against this
    /// module's own "register it first" contract (see the module doc), or
    /// `res` is being reused across more than one logical response.
    pub fn apply(sh: *const SecurityHeaders, res: *http.Server.ResponseWriter) http.Server.ResponseWriter.SetHeaderError!void {
        const o = &sh.options;
        if (o.hsts != null) try res.setHeader("Strict-Transport-Security", sh.hstsValue());
        if (o.content_security_policy) |v| try res.setHeader("Content-Security-Policy", v);
        if (o.content_security_policy_report_only) |v| try res.setHeader("Content-Security-Policy-Report-Only", v);
        if (o.x_content_type_options) try res.setHeader("X-Content-Type-Options", "nosniff");
        if (o.x_frame_options) |v| try res.setHeader("X-Frame-Options", v);
        if (o.referrer_policy) |v| try res.setHeader("Referrer-Policy", v);
        if (o.permissions_policy) |v| try res.setHeader("Permissions-Policy", v);
        if (o.cross_origin_opener_policy) |v| try res.setHeader("Cross-Origin-Opener-Policy", v);
        if (o.cross_origin_resource_policy) |v| try res.setHeader("Cross-Origin-Resource-Policy", v);
        if (o.cross_origin_embedder_policy) |v| try res.setHeader("Cross-Origin-Embedder-Policy", v);
        if (o.origin_agent_cluster) try res.setHeader("Origin-Agent-Cluster", "?1");
        if (o.x_dns_prefetch_control) |v| try res.setHeader("X-DNS-Prefetch-Control", v);
        if (o.x_download_options) try res.setHeader("X-Download-Options", "noopen");
        if (o.x_permitted_cross_domain_policies) |v| try res.setHeader("X-Permitted-Cross-Domain-Policies", v);
        if (o.x_xss_protection) try res.setHeader("X-XSS-Protection", "0");
        if (o.server) |v| try res.setHeader("Server", v);
        for (o.extra) |h| try res.setHeader(h.name, h.value);
    }

    /// `apply` for a configuration known at compile time: the same header
    /// set in the same order, but emitted through
    /// `ResponseWriter.setHeaderStatic`, so the whole ceremony is paid when
    /// the binary is built — validation and the managed-name checks become
    /// compile errors, the HSTS value is rendered into rodata, and every
    /// name/value pair is stored as the static slices themselves. Nothing
    /// is formatted or copied per request and none of the response's
    /// header-byte budget is spent, which is why the error set shrinks:
    /// `error.HeaderBytesExhausted` cannot happen here (only the header
    /// *slot* budget remains). No `init`, no `SecurityHeaders` value, no
    /// `InitError` — pass the `Options` directly.
    ///
    /// Semantics are otherwise `apply`'s: values set here are defaults in
    /// effect, a later `setHeader` with the same name wins. Like `apply`,
    /// call it before anything else touches the response so short-circuit
    /// replies carry the headers too.
    pub fn applyStatic(comptime options: Options, res: *http.Server.ResponseWriter) error{ HeadersSent, TooManyHeaders }!void {
        inline for (comptime staticHeaders(options)) |h| try res.setHeaderStatic(h.name, h.value);
    }

    /// The header set `applyStatic` sets for `options`, in its order, as
    /// compile-time data. Hand it to `http.Server.Options.error_headers` so
    /// the answers the server writes itself (its 4xx/5xx, the 500 replacing
    /// a failed handler) carry the same headers as every routed response —
    /// middleware never sees those (`Server` is skipped there: the server
    /// manages it).
    pub fn staticHeaders(comptime options: Options) []const http.Header {
        comptime {
            var list: []const http.Header = &.{};
            if (options.hsts) |h| list = list ++ [_]http.Header{.{ .name = "Strict-Transport-Security", .value = hstsStaticValue(h) }};
            if (options.content_security_policy) |v| list = list ++ [_]http.Header{.{ .name = "Content-Security-Policy", .value = v }};
            if (options.content_security_policy_report_only) |v| list = list ++ [_]http.Header{.{ .name = "Content-Security-Policy-Report-Only", .value = v }};
            if (options.x_content_type_options) list = list ++ [_]http.Header{.{ .name = "X-Content-Type-Options", .value = "nosniff" }};
            if (options.x_frame_options) |v| list = list ++ [_]http.Header{.{ .name = "X-Frame-Options", .value = v }};
            if (options.referrer_policy) |v| list = list ++ [_]http.Header{.{ .name = "Referrer-Policy", .value = v }};
            if (options.permissions_policy) |v| list = list ++ [_]http.Header{.{ .name = "Permissions-Policy", .value = v }};
            if (options.cross_origin_opener_policy) |v| list = list ++ [_]http.Header{.{ .name = "Cross-Origin-Opener-Policy", .value = v }};
            if (options.cross_origin_resource_policy) |v| list = list ++ [_]http.Header{.{ .name = "Cross-Origin-Resource-Policy", .value = v }};
            if (options.cross_origin_embedder_policy) |v| list = list ++ [_]http.Header{.{ .name = "Cross-Origin-Embedder-Policy", .value = v }};
            if (options.origin_agent_cluster) list = list ++ [_]http.Header{.{ .name = "Origin-Agent-Cluster", .value = "?1" }};
            if (options.x_dns_prefetch_control) |v| list = list ++ [_]http.Header{.{ .name = "X-DNS-Prefetch-Control", .value = v }};
            if (options.x_download_options) list = list ++ [_]http.Header{.{ .name = "X-Download-Options", .value = "noopen" }};
            if (options.x_permitted_cross_domain_policies) |v| list = list ++ [_]http.Header{.{ .name = "X-Permitted-Cross-Domain-Policies", .value = v }};
            if (options.x_xss_protection) list = list ++ [_]http.Header{.{ .name = "X-XSS-Protection", .value = "0" }};
            if (options.server) |v| list = list ++ [_]http.Header{.{ .name = "Server", .value = v }};
            for (options.extra) |h| list = list ++ [_]http.Header{.{ .name = h.name, .value = h.value }};
            const final = list[0..list.len].*;
            return &final;
        }
    }

    /// The exact bytes `init` would format into `hsts_buf` for `h`, built
    /// at compile time instead — the two renderings are kept in lockstep by
    /// the "applyStatic: default set is byte-for-byte apply's" test.
    fn hstsStaticValue(comptime h: Hsts) []const u8 {
        comptime {
            if (!h.preloadValid()) @compileError("security-headers: hsts.preload requires max_age_s >= 31536000 and include_subdomains");
            var v: []const u8 = std.fmt.comptimePrint("max-age={d}", .{h.max_age_s});
            if (h.include_subdomains) v = v ++ "; includeSubDomains";
            if (h.preload) v = v ++ "; preload";
            return v;
        }
    }

    /// The `router.Middleware` (`state` = this immutable SecurityHeaders —
    /// per-instance, no globals; never mutated by `run`). Sets the headers,
    /// then runs the rest of the chain. Register it first (outermost,
    /// before routes — chi's rule) so inner short-circuits and 404/405
    /// fallbacks carry the headers too.
    pub fn middleware(sh: *const SecurityHeaders) router.Middleware {
        // Middleware.state is a mutable pointer by type only — run() never
        // writes through it.
        return .{ .state = @constCast(sh), .run = middlewareRun };
    }
};

/// Everything `applyCspNonce` / `applyCspWithNonce` can fail with: building
/// the policy, or writing it onto the response.
pub const CspNonceError = csp.Error || http.Server.ResponseWriter.SetHeaderError;

/// Set `Content-Security-Policy` (or `-Report-Only`) on `res` for this one
/// response, with `'nonce-<nonce>'` appended to each directive in `nonce_in`
/// (typically `&.{ .script_src, .style_src }`; each must exist in `spec`).
/// `scratch` holds the rendered policy only for the duration of the call
/// (`setHeader` copies it) -- a stack buffer is fine; nothing allocates.
/// Replaces a policy of the same name set earlier (e.g. by `apply`).
/// The caller keeps `nonce` for the HTML (`nonce.slice()`).
pub fn applyCspWithNonce(
    res: *http.Server.ResponseWriter,
    spec: csp.Spec,
    nonce: *const csp.Nonce,
    nonce_in: []const csp.Name,
    report_only: bool,
    scratch: []u8,
) CspNonceError!void {
    const value = try csp.renderNonce(spec, nonce, nonce_in, scratch);
    try res.setHeader(if (report_only) "Content-Security-Policy-Report-Only" else "Content-Security-Policy", value);
}

/// `applyCspWithNonce` with a FRESH nonce drawn from `io.randomSecure`
/// (no hidden RNG); returns the nonce for the HTML. Call once per response.
pub fn applyCspNonce(
    res: *http.Server.ResponseWriter,
    io: std.Io,
    spec: csp.Spec,
    nonce_in: []const csp.Name,
    report_only: bool,
    scratch: []u8,
) (CspNonceError || std.Io.RandomSecureError)!csp.Nonce {
    const nonce = try csp.Nonce.secure(io);
    try applyCspWithNonce(res, spec, &nonce, nonce_in, report_only, scratch);
    return nonce;
}

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const sh: *const SecurityHeaders = @ptrCast(@alignCast(state.?));
    try sh.apply(ctx.res);
    return next.run(ctx);
}

/// Header values go onto the wire verbatim — refuse response-splitting
/// characters in configuration (Debug builds only).
fn assertValueClean(v: []const u8) void {
    for (v) |c| std.debug.assert(c != '\r' and c != '\n' and c != 0);
}

// ── tests (offline — through http.Server.serveStream, no socket) ────────────

const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Drive a router through `http.Server.serveStream` with canned wire bytes
/// (same harness as the router/ratelimit/throttle tests).
fn runWireNamed(r: *router.Router, bytes: []const u8, out_buf: []u8, server_name: ?[]const u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = server_name,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    return runWireNamed(r, bytes, out_buf, null); // keep goldens free of Server noise
}

fn wire(comptime target: []const u8) []const u8 {
    return "GET " ++ target ++ " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
}

fn expectStatus(got: []const u8, comptime status: []const u8) !void {
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 " ++ status));
}

fn expectHeaderLine(got: []const u8, comptime line: []const u8) !void {
    try testing.expect(std.mem.find(u8, got, "\r\n" ++ line ++ "\r\n") != null);
}

fn expectNoHeader(got: []const u8, comptime name: []const u8) !void {
    try testing.expect(std.ascii.findIgnoreCase(got, "\r\n" ++ name ++ ":") == null);
}

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

fn hFramed(ctx: *router.Ctx) anyerror!void {
    // Handler overrides one middleware default; the rest stay.
    try ctx.res.setHeader("X-Frame-Options", "SAMEORIGIN");
    try ctx.res.writeAll("framed");
}

test "defaults: exactly the expected header set with expected values (golden wire)" {
    const sh: SecurityHeaders = try .init(.{});
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);

    var buf: [2048]u8 = undefined;
    // Byte-exact: asserts each default header AND the absence of everything
    // else (no CSP, no Permissions-Policy, no COEP, no Server).
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
        "X-Content-Type-Options: nosniff\r\n" ++
        "X-Frame-Options: DENY\r\n" ++
        "Referrer-Policy: no-referrer\r\n" ++
        "Cross-Origin-Opener-Policy: same-origin\r\n" ++
        "Cross-Origin-Resource-Policy: same-origin\r\n" ++
        "Origin-Agent-Cluster: ?1\r\n" ++
        "X-DNS-Prefetch-Control: off\r\n" ++
        "X-Download-Options: noopen\r\n" ++
        "X-Permitted-Cross-Domain-Policies: none\r\n" ++
        "X-XSS-Protection: 0\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 2\r\n" ++
        "\r\n" ++
        "ok", runWire(&r, wire("/t"), &buf));
}

test "disabling: each header omittable; everything off = a bare response" {
    { // one header off, the rest of the set intact
        const sh: SecurityHeaders = try .init(.{ .hsts = null });
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(sh.middleware());
        try r.get("/t", hOk);

        var buf: [2048]u8 = undefined;
        const got = runWire(&r, wire("/t"), &buf);
        try expectNoHeader(got, "Strict-Transport-Security");
        try expectHeaderLine(got, "X-Content-Type-Options: nosniff");
        try expectHeaderLine(got, "X-Frame-Options: DENY");
        try expectHeaderLine(got, "Referrer-Policy: no-referrer");
        try expectHeaderLine(got, "Cross-Origin-Opener-Policy: same-origin");
        try expectHeaderLine(got, "Cross-Origin-Resource-Policy: same-origin");
    }
    { // all off: golden proof that nothing is emitted
        const sh: SecurityHeaders = try .init(.{
            .hsts = null,
            .x_content_type_options = false,
            .x_frame_options = null,
            .referrer_policy = null,
            .cross_origin_opener_policy = null,
            .cross_origin_resource_policy = null,
            .origin_agent_cluster = false,
            .x_dns_prefetch_control = null,
            .x_download_options = false,
            .x_permitted_cross_domain_policies = null,
            .x_xss_protection = false,
        });
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(sh.middleware());
        try r.get("/t", hOk);

        var buf: [2048]u8 = undefined;
        try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
            "Connection: close\r\n" ++
            "Content-Length: 2\r\n" ++
            "\r\n" ++
            "ok", runWire(&r, wire("/t"), &buf));
    }
}

test "api_options: the six-header API posture, byte-exact on both paths" {
    // The static set, in wire order.
    const hs = comptime SecurityHeaders.staticHeaders(api_options);
    const want = [_]http.Header{
        .{ .name = "Strict-Transport-Security", .value = "max-age=31536000; includeSubDomains" },
        .{ .name = "X-Content-Type-Options", .value = "nosniff" },
        .{ .name = "X-Frame-Options", .value = "DENY" },
        .{ .name = "Referrer-Policy", .value = "no-referrer" },
        .{ .name = "Cross-Origin-Opener-Policy", .value = "same-origin" },
        .{ .name = "Cross-Origin-Resource-Policy", .value = "same-origin" },
    };
    try testing.expectEqual(want.len, hs.len);
    for (want, hs) |w, h| {
        try testing.expectEqualStrings(w.name, h.name);
        try testing.expectEqualStrings(w.value, h.value);
    }
    // The runtime middleware emits the same set and nothing else.
    const sh: SecurityHeaders = try .init(api_options);
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);
    var buf: [2048]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
        "X-Content-Type-Options: nosniff\r\n" ++
        "X-Frame-Options: DENY\r\n" ++
        "Referrer-Policy: no-referrer\r\n" ++
        "Cross-Origin-Opener-Policy: same-origin\r\n" ++
        "Cross-Origin-Resource-Policy: same-origin\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 2\r\n" ++
        "\r\n" ++
        "ok", runWire(&r, wire("/t"), &buf));
}

test "overriding: custom values replace the defaults" {
    const sh: SecurityHeaders = try .init(.{
        .hsts = .{ .max_age_s = 63_072_000, .include_subdomains = false },
        .x_frame_options = "SAMEORIGIN",
        .referrer_policy = "strict-origin-when-cross-origin",
        .cross_origin_opener_policy = "same-origin-allow-popups",
        .cross_origin_resource_policy = "cross-origin",
        .permissions_policy = "camera=(), microphone=(), geolocation=()",
    });
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, wire("/t"), &buf);
    try expectHeaderLine(got, "Strict-Transport-Security: max-age=63072000");
    try expectHeaderLine(got, "X-Frame-Options: SAMEORIGIN");
    try expectHeaderLine(got, "Referrer-Policy: strict-origin-when-cross-origin");
    try expectHeaderLine(got, "Cross-Origin-Opener-Policy: same-origin-allow-popups");
    try expectHeaderLine(got, "Cross-Origin-Resource-Policy: cross-origin");
    try expectHeaderLine(got, "Permissions-Policy: camera=(), microphone=(), geolocation=()");
}

test "CSP: absent by default, present exactly as configured; Report-Only independent" {
    // Absence with defaults is proven byte-exactly by the golden test above.
    const sh: SecurityHeaders = try .init(.{
        .content_security_policy = csp_api,
        .content_security_policy_report_only = "default-src 'self'",
    });
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, wire("/t"), &buf);
    try expectHeaderLine(got, "Content-Security-Policy: default-src 'none'; " ++
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    try expectHeaderLine(got, "Content-Security-Policy-Report-Only: default-src 'self'");
}

test "init: a CSP that alone would exceed http's real response header-byte budget is rejected at config time, not response time" {
    // The exact set `appliedHeaderBytes` sums for `.init(.{})`'s defaults —
    // spelled out with `.len` on the same literals `apply` writes, not a
    // number this test invents, so a change to any default's wording keeps
    // this test honest instead of silently drifting stale.
    const defaults_bytes = "Strict-Transport-Security".len + "max-age=31536000; includeSubDomains".len +
        "X-Content-Type-Options".len + "nosniff".len +
        "X-Frame-Options".len + "DENY".len +
        "Referrer-Policy".len + "no-referrer".len +
        "Cross-Origin-Opener-Policy".len + "same-origin".len +
        "Cross-Origin-Resource-Policy".len + "same-origin".len +
        "Origin-Agent-Cluster".len + "?1".len +
        "X-DNS-Prefetch-Control".len + "off".len +
        "X-Download-Options".len + "noopen".len +
        "X-Permitted-Cross-Domain-Policies".len + "none".len +
        "X-XSS-Protection".len + "0".len;
    const csp_name_bytes = "Content-Security-Policy".len;
    // Exactly how much CSP value this configuration has left before it, on
    // its own — before any other middleware, handler, or trailer touches
    // the response — exceeds `http`'s entire per-response header budget
    // (`http_header_budget_bytes`, reflected off the real
    // `http.Server.ResponseWriter`, not hardcoded).
    const room = http_header_budget_bytes - defaults_bytes - csp_name_bytes;

    var csp_buf: [room + 1]u8 = undefined;
    @memset(&csp_buf, 'a');

    // Exactly at the edge: this configuration's headers exactly fill the
    // budget and `init` accepts it (matches `dupe`'s own `>` — not `>=` —
    // exhaustion check in http/src/Server.zig).
    _ = try SecurityHeaders.init(.{ .content_security_policy = csp_buf[0..room] });

    // One byte over: this configuration's own header set no longer fits
    // `http`'s budget by itself. Registered first per this module's own
    // contract, `apply`/`middleware` would fail *every* request with
    // `error.HeaderBytesExhausted` and no way for the caller to have seen
    // it coming short of doing this arithmetic themselves — `init` does it
    // instead, once, at startup.
    try testing.expectError(error.HeaderBudgetExceeded, SecurityHeaders.init(.{ .content_security_policy = &csp_buf }));
}

test "end-to-end anchor: a config sized to exactly fill http's real header budget survives a real ResponseWriter; `init`'s notion of the budget cannot silently drift from it" {
    // Same arithmetic as the test above, but this one does not stop at
    // arithmetic: `http_header_budget_bytes` only ever *claims* to track
    // `http.Server.ResponseWriter.header_buf`'s real size. A test that only
    // ever compares against that same constant (like the one above) cannot
    // tell a correct claim from a wrong one — it would stay green even if
    // `http_header_budget_bytes` were, say, hardcoded to something other
    // than `header_buf`'s actual length. This test drives the boundary
    // configuration through an ACTUAL `http.Server.ResponseWriter` — whose
    // `header_buf` array size comes from `http`'s own type definition, not
    // from anything in this file — so a wrong `http_header_budget_bytes`
    // shows up here as `apply` returning `error.HeaderBytesExhausted`
    // against the real writer, even though `init` (misled by the wrong
    // constant) let the same configuration through.
    const defaults_bytes = "Strict-Transport-Security".len + "max-age=31536000; includeSubDomains".len +
        "X-Content-Type-Options".len + "nosniff".len +
        "X-Frame-Options".len + "DENY".len +
        "Referrer-Policy".len + "no-referrer".len +
        "Cross-Origin-Opener-Policy".len + "same-origin".len +
        "Cross-Origin-Resource-Policy".len + "same-origin".len +
        "Origin-Agent-Cluster".len + "?1".len +
        "X-DNS-Prefetch-Control".len + "off".len +
        "X-Download-Options".len + "noopen".len +
        "X-Permitted-Cross-Domain-Policies".len + "none".len +
        "X-XSS-Protection".len + "0".len;
    const csp_name_bytes = "Content-Security-Policy".len;
    const room = http_header_budget_bytes - defaults_bytes - csp_name_bytes;

    var csp_buf: [room]u8 = undefined;
    @memset(&csp_buf, 'a');

    // `init` accepts a configuration sized to exactly fill the (claimed)
    // budget...
    const sh: SecurityHeaders = try .init(.{ .content_security_policy = &csp_buf });

    // ...and driven through a REAL `http.Server.ResponseWriter` (buffers
    // sized off the same reflected constant, so this test tracks a future
    // change to the real budget instead of hardcoding today's 4096), every
    // configured header actually lands on the wire: `apply` does not
    // return `error.HeaderBytesExhausted`, which is the disagreement a
    // wrong `http_header_budget_bytes` (e.g. a literal larger than the
    // real buffer) would produce right here.
    var out_buf: [http_header_budget_bytes + 1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    try sh.apply(&rw);
    try rw.end();
    const got = out.buffered();
    try expectHeaderLine(got, "X-Content-Type-Options: nosniff");
    try testing.expect(std.mem.find(u8, got, "Content-Security-Policy: ") != null);
    try testing.expect(std.mem.find(u8, got, &csp_buf) != null);

    // One byte over: `init` refuses it before a real writer is ever
    // involved.
    var too_big: [room + 1]u8 = undefined;
    @memset(&too_big, 'a');
    try testing.expectError(error.HeaderBudgetExceeded, SecurityHeaders.init(.{ .content_security_policy = &too_big }));
}

test "csp_helmet_default: reproduced helmet.js v7 posture, byte-exact through the middleware" {
    const sh: SecurityHeaders = try .init(.{ .content_security_policy = csp_helmet_default });
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, wire("/t"), &buf);
    try expectHeaderLine(got, "Content-Security-Policy: default-src 'self';base-uri 'self';" ++
        "font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';" ++
        "img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';" ++
        "style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests");
}

test "COEP: off by default, opt-in emits it" {
    const sh: SecurityHeaders = try .init(.{ .cross_origin_embedder_policy = "require-corp" });
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);

    var buf: [2048]u8 = undefined;
    try expectHeaderLine(runWire(&r, wire("/t"), &buf), "Cross-Origin-Embedder-Policy: require-corp");
}

test "HSTS: value format for every flag combination" {
    const a: SecurityHeaders = try .init(.{});
    try testing.expectEqualStrings("max-age=31536000; includeSubDomains", a.hstsValue());

    const b: SecurityHeaders = try .init(.{ .hsts = .{ .preload = true } });
    try testing.expectEqualStrings("max-age=31536000; includeSubDomains; preload", b.hstsValue());

    const c: SecurityHeaders = try .init(.{ .hsts = .{ .max_age_s = 0, .include_subdomains = false } });
    try testing.expectEqualStrings("max-age=0", c.hstsValue());

    // preload without includeSubDomains / with a short max-age is refused
    try testing.expectError(error.InvalidHstsPreload, SecurityHeaders.init(.{ .hsts = .{ .include_subdomains = false, .preload = true } }));

    // The longest possible value exactly fills the precomputed buffer.
    const e: SecurityHeaders = try .init(.{ .hsts = .{ .max_age_s = std.math.maxInt(u64), .preload = true } });
    try testing.expectEqualStrings("max-age=18446744073709551615; includeSubDomains; preload", e.hstsValue());
    try testing.expectEqual(hsts_buf_len, e.hstsValue().len);

    const off: SecurityHeaders = try .init(.{ .hsts = null });
    try testing.expectEqualStrings("", off.hstsValue());
}

test "precedence: a handler's own header replaces the middleware default" {
    const sh: SecurityHeaders = try .init(.{});
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/framed", hFramed);

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, wire("/framed"), &buf);
    try expectStatus(got, "200");
    try expectHeaderLine(got, "X-Frame-Options: SAMEORIGIN");
    // Replaced, not duplicated — and the untouched defaults are intact.
    try testing.expectEqual(1, std.mem.count(u8, got, "X-Frame-Options"));
    try expectHeaderLine(got, "X-Content-Type-Options: nosniff");
    try expectHeaderLine(got, "Strict-Transport-Security: max-age=31536000; includeSubDomains");
}

test "Server: configured value replaces the server's automatic header" {
    { // control: without the option the server's own name goes out
        const sh: SecurityHeaders = try .init(.{});
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(sh.middleware());
        try r.get("/t", hOk);

        var buf: [2048]u8 = undefined;
        try expectHeaderLine(runWireNamed(&r, wire("/t"), &buf, "real-server/1.0"), "Server: real-server/1.0");
    }
    { // replacement: the middleware value wins, the auto value never appears
        const sh: SecurityHeaders = try .init(.{ .server = "webserver" });
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(sh.middleware());
        try r.get("/t", hOk);

        var buf: [2048]u8 = undefined;
        const got = runWireNamed(&r, wire("/t"), &buf, "real-server/1.0");
        try expectHeaderLine(got, "Server: webserver");
        try testing.expect(std.mem.find(u8, got, "real-server") == null);
    }
}

test "404/405 fallbacks carry the headers too (router-level chain)" {
    const sh: SecurityHeaders = try .init(.{});
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);

    var buf: [2048]u8 = undefined;
    const nf = runWire(&r, wire("/nope"), &buf);
    try expectStatus(nf, "404");
    try expectHeaderLine(nf, "X-Frame-Options: DENY");
    try expectHeaderLine(nf, "X-Content-Type-Options: nosniff");

    var buf2: [2048]u8 = undefined;
    const mna = runWireNamed(&r, "POST /t HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf2, null);
    try expectStatus(mna, "405");
    try expectHeaderLine(mna, "X-Frame-Options: DENY");
}

test "apply: usable directly on a bare ResponseWriter (no router)" {
    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    const sh: SecurityHeaders = try .init(.{});
    try sh.apply(&rw);
    try rw.end();
    const got = out.buffered();
    try expectHeaderLine(got, "Strict-Transport-Security: max-age=31536000; includeSubDomains");
    try expectHeaderLine(got, "Cross-Origin-Opener-Policy: same-origin");
}

test "applyStatic: default set is byte-for-byte apply's" {
    // The drift guard for the comptime twin: the same Options through both
    // paths must produce the identical head, HSTS rendering included.
    var runtime_buf: [1024]u8 = undefined;
    var static_buf: [1024]u8 = undefined;
    var body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;

    var out_r: Writer = .fixed(&runtime_buf);
    var rw_r: http.Server.ResponseWriter = .init(&out_r, &body_buf, &chunk_buf, .{});
    const sh: SecurityHeaders = try .init(.{});
    try sh.apply(&rw_r);
    try rw_r.end();

    var out_s: Writer = .fixed(&static_buf);
    var rw_s: http.Server.ResponseWriter = .init(&out_s, &body_buf, &chunk_buf, .{});
    try SecurityHeaders.applyStatic(.{}, &rw_s);
    try rw_s.end();

    try testing.expectEqualStrings(out_r.buffered(), out_s.buffered());
}

test "applyStatic: full options render comptime, spend no header bytes" {
    var out_buf: [2048]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    try SecurityHeaders.applyStatic(.{
        .hsts = .{ .max_age_s = 63_072_000, .preload = true },
        .content_security_policy = csp_api,
        .server = "webserver",
        .extra = &.{.{ .name = "X-Robots-Tag", .value = "noindex" }},
    }, &rw);
    // Static pairs are rodata slices: the copy store must be untouched.
    try testing.expectEqual(@as(usize, 0), rw.header_buf_len);
    try rw.end();
    const got = out.buffered();
    try expectHeaderLine(got, "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload");
    try expectHeaderLine(got, "Content-Security-Policy: " ++ csp_api);
    try expectHeaderLine(got, "X-Content-Type-Options: nosniff");
    try expectHeaderLine(got, "Server: webserver");
    try expectHeaderLine(got, "X-Robots-Tag: noindex");
}

test "applyStatic: handler's later setHeader still wins" {
    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    try SecurityHeaders.applyStatic(.{}, &rw);
    try rw.setHeader("X-Frame-Options", "SAMEORIGIN");
    try rw.end();
    const got = out.buffered();
    try expectHeaderLine(got, "X-Frame-Options: SAMEORIGIN");
    try testing.expect(std.mem.find(u8, got, "DENY") == null);
}

test "staticHeaders: the applyStatic set reaches http.Server's own error answers" {
    const hs = comptime SecurityHeaders.staticHeaders(.{});
    try testing.expectEqualStrings("Strict-Transport-Security", hs[0].name);
    try testing.expectEqualStrings("max-age=31536000; includeSubDomains", hs[0].value);
    // A request http refuses itself (400: no Host) never meets middleware.
    var in: std.Io.Reader = .fixed("GET / HTTP/1.1\r\n\r\n");
    var out_buf: [2048]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var head_buf: [512]u8 = undefined;
    var req_body: [64]u8 = undefined;
    var res_body: [64]u8 = undefined;
    var chunk: [64]u8 = undefined;
    var trailers: [64]u8 = undefined;
    const H = struct {
        fn handle(_: *http.Server.Request, _: *http.Server.ResponseWriter) anyerror!void {}
    };
    http.Server.serveStream(.{ .handler = H.handle, .error_headers = hs }, &in, &out, .{
        .head = &head_buf,
        .request_body = &req_body,
        .response_body = &res_body,
        .chunk = &chunk,
        .trailers = &trailers,
    });
    const got = out.buffered();
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 400 "));
    for (hs) |h| {
        var line_buf: [512]u8 = undefined;
        const line = try std.mem.print(&line_buf, "\r\n{s}: {s}\r\n", .{ h.name, h.value });
        try testing.expect(std.mem.find(u8, got, line) != null);
    }
}

test "legacy defaults: helmet 8.3.0 values, each knob alone disables its header, values overridable" {
    // KAT: helmet 8.3.0 README default set (value part of each line).
    const sh: SecurityHeaders = try .init(.{});
    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    try sh.apply(&rw);
    try rw.end();
    const got = out.buffered();
    try expectHeaderLine(got, "Origin-Agent-Cluster: ?1");
    try expectHeaderLine(got, "X-DNS-Prefetch-Control: off");
    try expectHeaderLine(got, "X-Download-Options: noopen");
    try expectHeaderLine(got, "X-Permitted-Cross-Domain-Policies: none");
    try expectHeaderLine(got, "X-XSS-Protection: 0");

    inline for (.{
        .{ "origin_agent_cluster", false, "Origin-Agent-Cluster" },
        .{ "x_dns_prefetch_control", null, "X-DNS-Prefetch-Control" },
        .{ "x_download_options", false, "X-Download-Options" },
        .{ "x_permitted_cross_domain_policies", null, "X-Permitted-Cross-Domain-Policies" },
        .{ "x_xss_protection", false, "X-XSS-Protection" },
    }) |c| {
        var o: Options = .{};
        @field(o, c[0]) = c[1];
        const s1: SecurityHeaders = try .init(o);
        var ob: [1024]u8 = undefined;
        var w: Writer = .fixed(&ob);
        var rw1: http.Server.ResponseWriter = .init(&w, &body_buf, &chunk_buf, .{});
        try s1.apply(&rw1);
        try rw1.end();
        try expectNoHeader(w.buffered(), c[2]);
        // the other four are untouched: 16 default lines minus this one
        try testing.expectEqual(@as(usize, 4), blk: {
            var n: usize = 0;
            for ([_][]const u8{ "Origin-Agent-Cluster:", "X-DNS-Prefetch-Control:", "X-Download-Options:", "X-Permitted-Cross-Domain-Policies:", "X-XSS-Protection:" }) |nm| {
                if (std.mem.find(u8, w.buffered(), nm) != null) n += 1;
            }
            break :blk n;
        });
    }

    const custom: SecurityHeaders = try .init(.{ .x_dns_prefetch_control = "on", .x_permitted_cross_domain_policies = "by-content-type" });
    var ob2: [1024]u8 = undefined;
    var w2: Writer = .fixed(&ob2);
    var rw2: http.Server.ResponseWriter = .init(&w2, &body_buf, &chunk_buf, .{});
    try custom.apply(&rw2);
    try rw2.end();
    try expectHeaderLine(w2.buffered(), "X-DNS-Prefetch-Control: on");
    try expectHeaderLine(w2.buffered(), "X-Permitted-Cross-Domain-Policies: by-content-type");
}

test "HSTS preload: refused unless max-age >= 1 year and includeSubDomains (init error)" {
    try testing.expectError(error.InvalidHstsPreload, SecurityHeaders.init(.{ .hsts = .{ .max_age_s = 31_535_999, .preload = true } }));
    try testing.expectError(error.InvalidHstsPreload, SecurityHeaders.init(.{ .hsts = .{ .include_subdomains = false, .preload = true } }));
    try testing.expectError(error.InvalidHstsPreload, SecurityHeaders.init(.{ .hsts = .{ .max_age_s = 0, .include_subdomains = false, .preload = true } }));
    // boundary accepted; non-preload values are never judged
    const ok: SecurityHeaders = try .init(.{ .hsts = .{ .max_age_s = 31_536_000, .preload = true } });
    try testing.expectEqualStrings("max-age=31536000; includeSubDomains; preload", ok.hstsValue());
    _ = try SecurityHeaders.init(.{ .hsts = .{ .max_age_s = 1, .include_subdomains = false } });
    try testing.expect((Hsts{ .max_age_s = 5 }).preloadValid());
    try testing.expect(!(Hsts{ .max_age_s = 5, .preload = true }).preloadValid());
    // comptime twin: the compile error is reachable only for invalid values;
    // a valid preload value renders at comptime.
    try testing.expectEqualStrings("max-age=63072000; includeSubDomains; preload", comptime SecurityHeaders.hstsStaticValue(.{ .max_age_s = 63_072_000, .preload = true }));
}

test "csp builder: csp_helmet_default is byte-identical to the comptime defaults; applyStatic accepts a built policy" {
    try testing.expectEqualStrings(csp_helmet_default, comptime csp.build(.{}));

    var out_buf: [2048]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    try SecurityHeaders.applyStatic(.{
        .content_security_policy = comptime csp.build(.{
            .directives = &.{.{ .name = .script_src, .values = &.{ "'self'", "https://cdn.example" } }},
            .remove = &.{.upgrade_insecure_requests},
        }),
    }, &rw);
    try testing.expectEqual(@as(usize, 0), rw.header_buf_len);
    try rw.end();
    try expectHeaderLine(out.buffered(), "Content-Security-Policy: default-src 'self';base-uri 'self';" ++
        "font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;" ++
        "object-src 'none';script-src 'self' https://cdn.example;script-src-attr 'none';" ++
        "style-src 'self' https: 'unsafe-inline'");
}

test "csp builder: runtime policy through init/apply" {
    var buf: [512]u8 = undefined;
    const policy = try csp.render(.{ .use_defaults = false, .directives = &.{
        .{ .name = .default_src, .values = &.{"'none'"} },
        .{ .name = .frame_ancestors, .values = &.{"'none'"} },
    } }, &buf);
    const sh: SecurityHeaders = try .init(.{ .content_security_policy = policy });
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);
    var wbuf: [2048]u8 = undefined;
    try expectHeaderLine(runWire(&r, wire("/t"), &wbuf), "Content-Security-Policy: default-src 'none';frame-ancestors 'none'");
}

fn hNonce(ctx: *router.Ctx) anyerror!void {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var scratch: [1024]u8 = undefined;
    const nonce = try applyCspNonce(ctx.res, threaded.io(), .{}, &.{ .script_src, .style_src }, false, &scratch);
    try ctx.res.writeAll(nonce.slice());
}

test "applyCspNonce: fresh nonce per response, rendered into script-src/style-src, handed back (body echoes it)" {
    const sh: SecurityHeaders = try .init(.{});
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/n", hNonce);

    var nonces: [2][csp.Nonce.text_len]u8 = undefined;
    for (&nonces) |*slot| {
        var buf: [4096]u8 = undefined;
        const got = runWire(&r, wire("/n"), &buf);
        const body = got[std.mem.find(u8, got, "\r\n\r\n").? + 4 ..];
        try testing.expectEqual(@as(usize, csp.Nonce.text_len), body.len);
        @memcpy(slot, body);
        const want = try testing.allocator.print("Content-Security-Policy: default-src 'self';base-uri 'self';" ++
            "font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;" ++
            "object-src 'none';script-src 'self' 'nonce-{s}';script-src-attr 'none';" ++
            "style-src 'self' https: 'unsafe-inline' 'nonce-{s}';upgrade-insecure-requests", .{ body, body });
        defer testing.allocator.free(want);
        try testing.expect(std.mem.find(u8, got, want) != null);
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, got, "Content-Security-Policy:"));
    }
    try testing.expect(!std.mem.eql(u8, &nonces[0], &nonces[1]));
}

test "applyCspWithNonce: report-only name, deterministic bytes, errors surface" {
    var out_buf: [2048]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    const nonce = csp.Nonce.fromBytes(&(@as([16]u8, @splat(0))));
    var scratch: [1024]u8 = undefined;
    try applyCspWithNonce(&rw, .{ .use_defaults = false, .directives = &.{.{ .name = .script_src, .values = &.{"'strict-dynamic'"} }} }, &nonce, &.{.script_src}, true, &scratch);
    try testing.expectError(error.NonceDirectiveMissing, applyCspWithNonce(&rw, .{ .use_defaults = false, .directives = &.{.{ .name = .img_src, .values = &.{"'self'"} }} }, &nonce, &.{.script_src}, false, &scratch));
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, applyCspWithNonce(&rw, .{}, &nonce, &.{.script_src}, false, &tiny));
    try rw.end();
    try expectHeaderLine(out.buffered(), "Content-Security-Policy-Report-Only: script-src 'strict-dynamic' 'nonce-AAAAAAAAAAAAAAAAAAAAAA'");
    try expectNoHeader(out.buffered(), "Content-Security-Policy");
}

// ── tests (in-process integration — http.Server + http.Client) ──────────────

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

test "integration: a 200 over loopback carries the headers; handler override wins" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const sh: SecurityHeaders = try .init(.{});
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/hello", hOk);
    try r.get("/framed", hFramed);

    var server = http.Server.init(io, testing.allocator, .{
        .handler = r.handler(),
        .context = &r,
    });
    defer server.deinit();
    server.bind() catch |err| {
        return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    const port = server.boundAddress().getPort();
    var client = http.Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;

    { // the full default set on a normal 200
        const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/hello", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("max-age=31536000; includeSubDomains", res.header("strict-transport-security").?);
        try testing.expectEqualStrings("nosniff", res.header("x-content-type-options").?);
        try testing.expectEqualStrings("DENY", res.header("x-frame-options").?);
        try testing.expectEqualStrings("no-referrer", res.header("referrer-policy").?);
        try testing.expectEqualStrings("same-origin", res.header("cross-origin-opener-policy").?);
        try testing.expectEqualStrings("same-origin", res.header("cross-origin-resource-policy").?);
        try testing.expect(res.header("content-security-policy") == null);
        try testing.expect(res.header("cross-origin-embedder-policy") == null);
        const body = try res.readAllAlloc(testing.allocator, 1024);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("ok", body);
    }

    { // a handler that sets its own X-Frame-Options wins over the default
        const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/framed", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("SAMEORIGIN", res.header("x-frame-options").?);
        try testing.expectEqualStrings("nosniff", res.header("x-content-type-options").?);
    }
}

// ── external anchor: published third-party literal examples ────────────────
//
// Every test above compares this module's own output against string
// literals this module's own author wrote — an in-house re-derivation, not
// an external anchor (the "helmet.js v7 default" / "OWASP" comments were
// design claims, never checked against an independent published source).
//
// The tests below instead embed short literal example header lines COPIED
// VERBATIM from published third-party documents (fetched 2026-08-01, not
// derived from this module or its tests) and assert our own emitted output
// equals them byte-for-byte:
//   - RFC 7034 SS2.2.1 ("Examples of X-Frame-Options") and RFC 6797 SS6.2
//     ("Examples") are IETF standards-track specifications — cited per
//     root NOTICE SS0's spec/RFC carve-out, no NOTICE entry needed.
//   - The OWASP Secure Headers Project excerpt is a curated third-party
//     recommendations document (Apache License 2.0, not an RFC) — see
//     `modules/security-headers/NOTICE`, which is where the obligation lives.
//
// This is a genuine external anchor for the headers it covers. It does NOT
// cover Content-Security-Policy: neither RFC 7034/6797 nor the OWASP page
// publish a single recommended CSP value string (OWASP's own CSP example is
// the generic "script-src 'self'", not a full policy comparable to
// `csp_helmet_default`), so `csp_helmet_default` remains self-anchored —
// an honest gap, not silently papered over.

test "external anchor: RFC 7034 2.2.1's own 'X-Frame-Options: DENY' example line matches our default byte-exact" {
    const rfc7034_2_2_1_example_line = "X-Frame-Options: DENY"; // copied verbatim, rfc-editor.org/rfc/rfc7034.txt

    const sh: SecurityHeaders = try .init(.{});
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);

    var buf: [2048]u8 = undefined;
    try expectHeaderLine(runWire(&r, wire("/t"), &buf), rfc7034_2_2_1_example_line);
}

test "external anchor: RFC 6797 6.2's own max-age=31536000 example matches our default's max-age number byte-exact" {
    // RFC 6797 SS6.2's first example, copied verbatim:
    //   "Strict-Transport-Security: max-age=31536000"
    // Our default's HSTS value has an additional includeSubDomains directive
    // this specific RFC example doesn't, so the full line isn't a byte-exact
    // match to a single RFC example (documented honestly, not glossed over)
    // — but the numeric max-age token this module chose (31536000) is lifted
    // directly from this RFC example, not picked independently, and the
    // RFC's OWN separate example
    // "Strict-Transport-Security: max-age=0; includeSubDomains" (same
    // section) proves "max-age=<n>; includeSubDomains" (no space before the
    // semicolon) is itself a valid RFC-illustrated form, not this module's
    // own invention.
    const sh: SecurityHeaders = try .init(.{});
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, wire("/t"), &buf);
    try testing.expect(std.mem.find(u8, got, "Strict-Transport-Security: max-age=31536000") != null);
}

test "external anchor: OWASP Secure Headers Project's own example lines match our defaults byte-exact" {
    // Copied verbatim from mainsite/01_headers.md, OWASP/www-project-secure-headers
    // (Apache License 2.0), fetched 2026-08-01 — see modules/security-headers/NOTICE.
    const sh: SecurityHeaders = try .init(.{});
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, wire("/t"), &buf);
    try expectHeaderLine(got, "X-Content-Type-Options: nosniff"); // SS "X-Content-Type-Options" > Example
    try expectHeaderLine(got, "Referrer-Policy: no-referrer"); // SS "Referrer-Policy" > Example
    try expectHeaderLine(got, "Cross-Origin-Resource-Policy: same-origin"); // SS "Cross-Origin-Resource-Policy" > Example
    try expectHeaderLine(got, "Cross-Origin-Opener-Policy: same-origin"); // SS "Cross-Origin-Opener-Policy" > Example
}

test "external anchor: OWASP's own Cross-Origin-Embedder-Policy example matches our opt-in value byte-exact" {
    // Copied verbatim from mainsite/01_headers.md: "Cross-Origin-Embedder-Policy: require-corp"
    const owasp_example_line = "Cross-Origin-Embedder-Policy: require-corp";

    const sh: SecurityHeaders = try .init(.{ .cross_origin_embedder_policy = "require-corp" });
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);

    var buf: [2048]u8 = undefined;
    try expectHeaderLine(runWire(&r, wire("/t"), &buf), owasp_example_line);
}

test "extra: emitted by the runtime path and counted against the budget" {
    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    const sh: SecurityHeaders = try .init(.{
        .extra = &.{.{ .name = "X-Robots-Tag", .value = "noindex" }},
    });
    try sh.apply(&rw);
    try rw.end();
    try expectHeaderLine(out.buffered(), "X-Robots-Tag: noindex");

    // An extra pair big enough to blow the whole header-byte budget on its
    // own must be caught at init, exactly like an oversized CSP.
    const huge = strRepeat("v", http_header_budget_bytes + 1);
    try testing.expectError(error.HeaderBudgetExceeded, SecurityHeaders.init(.{
        .extra = &.{.{ .name = "X-Big", .value = huge }},
    }));
}

test "init rejects an extra header whose NAME is not a field token" {
    // The value list was validated (Debug-only) while the name -- equally
    // verbatim on the wire -- was never looked at, so a bad name slipped
    // through config time and made `setHeader` fail on every request: an
    // automatic 500 carrying none of this module's headers. That is exactly
    // the failure shape `InitError` exists to move to config time.
    try testing.expectError(error.InvalidExtraHeaderName, SecurityHeaders.init(.{
        .extra = &.{.{ .name = "X Robots Tag", .value = "noindex" }}, // space
    }));
    try testing.expectError(error.InvalidExtraHeaderName, SecurityHeaders.init(.{
        .extra = &.{.{ .name = "", .value = "v" }},
    }));
    try testing.expectError(error.InvalidExtraHeaderName, SecurityHeaders.init(.{
        .extra = &.{.{ .name = "X-Bad:Name", .value = "v" }},
    }));

    // A legitimate token still configures cleanly.
    _ = try SecurityHeaders.init(.{
        .extra = &.{.{ .name = "X-Robots-Tag", .value = "noindex" }},
    });
}

// ── audit 2026-10-04: test asked for by mutation survivors ──────────────────

test "the init-time budget sum counts exactly the bytes apply puts on the wire" {
    // `appliedHeaderBytes` "mirrors apply's own field list and conditions
    // exactly" — it is what `init`'s `HeaderBudgetExceeded` check measures,
    // so a header it forgets is budget the check cannot see. Oracle: the
    // serialized head of a response `apply` wrote, every header enabled,
    // summing name + value of each line except the two the writer adds itself.
    var out_buf: [4096]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    const sh: SecurityHeaders = try .init(.{
        .hsts = .{ .max_age_s = 63072000, .include_subdomains = true, .preload = true },
        .content_security_policy = "default-src 'self'",
        .content_security_policy_report_only = "script-src 'none'",
        .permissions_policy = "camera=()",
        .cross_origin_embedder_policy = "require-corp",
        .server = "srv",
        .extra = &.{.{ .name = "X-Robots-Tag", .value = "noindex" }},
    });
    try sh.apply(&rw);
    try rw.end();
    const head = out.buffered();
    var it = std.mem.splitSequence(u8, head[0..std.mem.find(u8, head, "\r\n\r\n").?], "\r\n");
    _ = it.next(); // status line
    var wire_bytes: usize = 0;
    var lines: usize = 0;
    while (it.next()) |line| {
        const colon = std.mem.find(u8, line, ": ").?;
        const name = line[0..colon];
        if (std.mem.eql(u8, name, "Connection") or std.mem.eql(u8, name, "Content-Length")) continue;
        wire_bytes += name.len + line.len - colon - 2;
        lines += 1;
    }
    try testing.expectEqual(@as(usize, 17), lines); // all sixteen named headers + one extra
    try testing.expectEqual(wire_bytes, sh.appliedHeaderBytes());
}

// ── audit 2026-10-18: tests asked for by mutation survivors ────────────────

test "init accepts every RFC 9110 token character in an extra header NAME" {
    // digits, letters and each punctuation tchar (a dropped class would 500 a
    // legitimate header at request time, or let it through at config time).
    const name = "A!#$%&'*+-.^_`|~0123456789z";
    _ = try SecurityHeaders.init(.{ .extra = &.{.{ .name = name, .value = "v" }} });
    for ("9.0aZ") |c| {
        const one_c = [_]u8{ 'X', c };
        _ = try SecurityHeaders.init(.{ .extra = &.{.{ .name = &one_c, .value = "v" }} });
    }
    // and none of the delimiters
    for ("\"(),/:;<=>?@[\\]{} ") |c| {
        const bad = [_]u8{ 'X', c };
        try testing.expectError(error.InvalidExtraHeaderName, SecurityHeaders.init(.{ .extra = &.{.{ .name = &bad, .value = "v" }} }));
    }
}

fn expectStaticEqualsRuntime(comptime options: Options) !void {
    var runtime_buf: [4096]u8 = undefined;
    var static_buf: [4096]u8 = undefined;
    var body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var out_r: Writer = .fixed(&runtime_buf);
    var rw_r: http.Server.ResponseWriter = .init(&out_r, &body_buf, &chunk_buf, .{});
    const sh: SecurityHeaders = try .init(options);
    try sh.apply(&rw_r);
    try rw_r.end();
    var out_s: Writer = .fixed(&static_buf);
    var rw_s: http.Server.ResponseWriter = .init(&out_s, &body_buf, &chunk_buf, .{});
    try SecurityHeaders.applyStatic(options, &rw_s);
    try rw_s.end();
    try testing.expectEqualStrings(out_r.buffered(), out_s.buffered());
    // static pairs are rodata: none of the response's header-byte budget is spent
    try testing.expectEqual(@as(usize, 0), rw_s.header_buf_len);
}

test "applyStatic == apply: every optional header on, and the other HSTS flag combinations" {
    try expectStaticEqualsRuntime(.{
        .hsts = .{ .max_age_s = 63_072_000, .preload = true },
        .content_security_policy = csp_api,
        .content_security_policy_report_only = "default-src 'self'",
        .permissions_policy = "camera=()",
        .cross_origin_embedder_policy = "require-corp",
        .server = "srv",
        .extra = &.{ .{ .name = "X-Robots-Tag", .value = "noindex" }, .{ .name = "X-Two", .value = "2" } },
    });
    try expectStaticEqualsRuntime(.{ .hsts = .{ .max_age_s = 0, .include_subdomains = false } });
    try expectStaticEqualsRuntime(.{ .hsts = .{ .max_age_s = 1, .include_subdomains = true } });
    try expectStaticEqualsRuntime(api_options);
    try expectStaticEqualsRuntime(.{
        .hsts = null,
        .x_content_type_options = false,
        .origin_agent_cluster = false,
        .x_download_options = false,
        .x_xss_protection = false,
        .x_dns_prefetch_control = "on",
        .x_permitted_cross_domain_policies = "all",
    });
    // staticHeaders carries exactly the set applyStatic walks
    try testing.expectEqual(@as(usize, 17), comptime staticHeaders17().len);
}

fn staticHeaders17() []const http.Header {
    return SecurityHeaders.staticHeaders(.{
        .content_security_policy = csp_api,
        .content_security_policy_report_only = "default-src 'self'",
        .permissions_policy = "camera=()",
        .cross_origin_embedder_policy = "require-corp",
        .server = "srv",
        .extra = &.{.{ .name = "X-Robots-Tag", .value = "noindex" }},
    });
}

// ── external anchor: headless Chrome against this header set ───────────────
// See browser_oracle_test.zig / tools/interop.zig / tools/browser_oracle.js.
test {
    _ = @import("browser_oracle_test.zig");
    _ = @import("csp.zig");
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * (s.len + 4) + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}
