// SPDX-License-Identifier: MIT

//! HTTP/1.1 client over TCP + TLS.
//!
//! One `Client` is a lightweight config + lazily-loaded CA bundle + a
//! keyed idle-connection `Pool` (`Options.pool`, on by default). A request
//! first asks the pool for a warm connection to the target origin
//! (`scheme`/`host`/`port`); on a miss it dials fresh. A connection returns
//! to the pool on `Response.deinit`/`Upload.finish` *only* when the
//! response left it in a clean, fully-drained, keep-alive-eligible state
//! (see `Conn.keep_alive_eligible` / `isBodyDrained`) — anything else
//! (`Connection: close`, an HTTP/1.0 response without an explicit
//! `keep-alive`, a `101` upgrade, a body that was not read to completion, or
//! any read/write error) is closed instead, never pooled. Set
//! `Options.pool.enabled = false` for the old one-shot-per-request
//! behavior (`Connection: close` on every request, exactly as before).
//! Streaming both directions: response bodies are exposed as a
//! `std.Io.Reader` (chunked and Content-Length framing decoded on the fly),
//! request bodies can be streamed via `requestStreaming` (fixed length or
//! chunked), so bodies larger than memory never get buffered.
//!
//! ⚠ Sandboxes. The blocking phases of a request — name resolution +
//! `connect`, the TLS handshake, the response-head read — run on a task of
//! the `Io` (`runBounded`: the only way std 0.16 can put a deadline on
//! them), i.e. on one of `std.Io.Threaded`'s pool threads, not on the
//! thread that called `request`. A per-thread confinement (Landlock,
//! `setuid`, seccomp) applied after that pool started does not cover it.
//! Make the `Io` after the sandbox, or set `Options.inline_blocking` (which
//! also bypasses `std.Io.net.HostName.connect`: that one starts the lookup
//! and every connect as tasks of its own). The
//! CA bundle is read from the filesystem on the first HTTPS request; load it
//! before confining with `loadCaBundle` or a shared `CaBundle`.
//!
//! Implementation notes: TLS via `std.crypto.tls` (never `std.http.Client`),
//! hostname resolution via `std.Io.net.HostName` (to be swapped for the
//! `dns` module when it lands), URL/host splitting via `netaddr`.
//!
//! Timeout model. Neither timeout is enforced by the socket layer — std
//! 0.16.0 has no per-read deadline and panics on `ConnectOptions.timeout`
//! (see `runBounded`). Both are enforced the only way std allows: the
//! blocking phase runs on a concurrent task, and blowing the deadline
//! *cancels* it, which interrupts the syscall it is parked in.
//!
//!   * `connect_timeout_ms` bounds name resolution + `connect`
//!     (`connectStream`).
//!   * `total_timeout_ms` bounds a whole `request` — every redirect hop, the
//!     TLS handshake and the response-head read included — and, separately,
//!     an `Upload.finish`.
//!
//! What is NOT bounded, deliberately and not for want of a mechanism:
//!   * reading a response body through `Response.reader`. The caller drives
//!     those reads and decides how long a slow trickle is acceptable; wrap
//!     the read in your own `runBounded`-shaped race if you need one.
//!   * `H2Session` (`connectH2c`/`connectH2Over`) past the dial. Its dial
//!     gets `connect_timeout_ms` like any other, but the multiplexed session
//!     that follows has no single "the request" to bound — `h2_client` pumps
//!     one socket on behalf of every in-flight stream.
//!   * anything at all when the `Io` cannot supply a unit of concurrency
//!     (a single-threaded build; a `Threaded` at its `concurrent_limit`).
//!     There is then nothing to cancel, so the phase runs on the caller's
//!     thread exactly as it did before and only the between-phase deadline
//!     checks apply. Both option doc comments say so.
//!
//! HTTP/2 (Phase 3.2, opt-in): `connectH2c` opens a **cleartext h2c**
//! connection via prior knowledge (RFC 9113 §3.3) and returns an
//! `H2Session` that multiplexes any number of requests over that one
//! connection (the `h2_client` engine over this client's socket plumbing).
//! The h1 `request` path is byte-for-byte unchanged — h2 is strictly
//! opt-in. For h2 over TLS, `connectH2Over` (Phase 3.3) is the
//! bring-your-own-TLS seam: establish the TLS connection with your own
//! library offering `http.alpn_offer`, and when ALPN negotiated "h2"
//! (`http.protocolFromAlpn`, RFC 7301; RFC 9113 §3.3) hand the plaintext
//! reader/writer over — the same `H2Session` drives it, transport owned by
//! the caller.
//!
//! h2 pooling seam: an `H2Session` already multiplexes every request over
//! its ONE connection — that IS h2's pooling, so the h1 idle `Pool` below
//! does not apply to it and never touches `H2Session`/`connectH2c`/
//! `connectH2Over` (checking an h2 connection in/out exclusively per
//! request the way h1 does would defeat multiplexing). What is missing is
//! *reuse across calls to `connectH2c`* (each call dials a fresh h2c
//! connection); a caller that wants that today just keeps its own
//! `*H2Session` around and issues many `request`s on it — which is the
//! natural h2 usage pattern anyway. Pooling *many* h2 sessions per origin
//! (for parallelism beyond one connection's flow-control window) is a
//! documented non-goal of this pass, not a half-implementation: it would
//! need its own checkout policy (least-loaded session, not idle/warm), which
//! is different enough from the h1 `Pool` to deserve its own design rather
//! than a bolt-on.

const std = @import("std");
const testkit = @import("testkit");
const netaddr = @import("netaddr");
const http = @import("root.zig");
const h1 = @import("h1.zig");
const h2_client = @import("h2_client.zig");
const hpack = @import("hpack.zig");
const bufpool = @import("bufpool.zig");
const gzip = @import("gzip.zig");
const crc32 = @import("crc32");
const net = std.Io.net;
// std's TLS client, with the server chain verified by RFC 5280: std checks
// no basicConstraints (ziglang/zig #35877), so any certificate holder could
// impersonate any host to it. Same API as `std.crypto.tls`.
const tls = @import("tlsclient");

/// Shared, bounded slab pool for client connection buffers (see
/// `bufpool.BufferPool` and `Options.buffer_pool`).
pub const BufferPool = bufpool.BufferPool;

const client_proxy = @import("client_proxy.zig");
/// Outbound proxy settings (`Options.proxy`); see `client_proxy.zig`.
pub const Proxy = client_proxy.Proxy;

/// A client-side cookie store (Go's `http.CookieJar`), `Options.cookie_jar`:
/// asked for the cookies of every request this client writes, redirect hops
/// included, and handed the head of every response it reads, so it can take
/// the `Set-Cookie` fields. `cookies.Jar.cookieJar()` is one. Both calls may
/// come from several threads at once.
pub const CookieJar = struct {
    ctx: *anyopaque,
    /// Write `prefix` and then the `Cookie` value for a request to `url`
    /// (`a=1; b=2`); write nothing at all and return false when no cookie
    /// applies.
    write_cookies: *const fn (ctx: *anyopaque, url: http.Url, w: *std.Io.Writer, prefix: []const u8) std.Io.Writer.Error!bool,
    /// Take what a response to `url` says (its `Set-Cookie` fields).
    store: *const fn (ctx: *anyopaque, url: http.Url, head: *const h1.ResponseHead) void,
};

const Client = @This();

io: std.Io,
gpa: std.mem.Allocator,
options: Options,
ca_bundle: std.crypto.Certificate.Bundle,
ca_lock: std.Io.RwLock,
ca_scanned: bool,
pool: Pool,
/// Lifetime count of fresh dials (pool misses + pooling disabled +
/// stale-connection retries). Diagnostics/metrics and the main reuse proof
/// in tests — a steady count across repeated same-origin requests means
/// the pool is doing its job.
dial_count: std.atomic.Value(usize) = .init(0),

/// A CA bundle with its own lock, loadable once and shareable between
/// clients (`Options.shared_ca`). All methods are thread-safe.
pub const CaBundle = struct {
    bundle: std.crypto.Certificate.Bundle = .empty,
    lock: std.Io.RwLock = .init,
    scanned: bool = false,

    /// Scan the system CA store, once; later calls return at once. Call it
    /// before confining the process if the store will be unreadable after.
    pub fn load(ca: *CaBundle, gpa: std.mem.Allocator, io: std.Io) Error!void {
        return loadCa(gpa, io, &ca.lock, &ca.bundle, &ca.scanned);
    }

    pub fn deinit(ca: *CaBundle, gpa: std.mem.Allocator) void {
        ca.bundle.deinit(gpa);
        ca.* = undefined;
    }
};

pub const Options = struct {
    /// Budget for one dial — name resolution plus `connect` — after which
    /// the dial fails with `error.Timeout`; 0 = unbounded. Applies to every
    /// fresh dial (a pool hit does not dial, so it does not spend this).
    ///
    /// Enforced by canceling the task the connect is blocked in, NOT by
    /// `ConnectOptions.timeout`, which std 0.16.0 panics on — see
    /// `connectStream`. The one hole: when the `Io` has no unit of
    /// concurrency to give (single-threaded build, or a `Threaded` already at
    /// its `concurrent_limit`), the dial runs on the calling thread with
    /// nothing able to interrupt it, and this budget does not apply.
    connect_timeout_ms: u32 = 5000,
    /// Whole-exchange budget for a `request` (all redirect hops) or an
    /// `Upload.finish`, after which it fails with `error.Timeout`; 0 =
    /// unbounded. Covers the dial, the TLS handshake and the response-head
    /// read — everything up to the point the `Response` is handed back.
    ///
    /// It does NOT cover reading the response body: `Response.reader` is
    /// pulled by the caller, so a budget there would be a budget on the
    /// caller. Enforced by cancelation, with the same
    /// no-concurrency-available hole as `connect_timeout_ms`.
    total_timeout_ms: u32 = 30000,
    /// Redirect-following cap (`error.TooManyRedirects` beyond it).
    max_redirects: u8 = 10,
    tls: TlsOptions = .{},
    /// Plaintext read buffer; also bounds a single response head line.
    read_buffer_size: usize = 16 * 1024,
    /// Plaintext write buffer.
    write_buffer_size: usize = 4 * 1024,
    /// Upper bound for a whole response head (status line + headers).
    max_head_bytes: usize = 16 * 1024,
    /// Client-wide `User-Agent`, sent on every request **on both protocols**:
    /// the h1 head writer emits it, and `connectH2c` hands it to the h2
    /// session as its connection-wide default (`h2_client.Options.user_agent`)
    /// so the same option means the same thing over h2c. A per-request
    /// `user-agent` in `RequestOptions.headers` overrides it — on h1 the name
    /// is matched case-insensitively, and on h2 likewise, even though the name
    /// goes on that wire lowercased (RFC 9113 §8.2.1). Borrowed, not copied:
    /// it must outlive the `Client`. On the BYO-TLS h2 path
    /// (`connectH2Over`) there is no `Client` to read this from, so set
    /// `h2_client.Options.user_agent` on that call yourself.
    user_agent: []const u8 = "zig-libs-http/0.1",
    /// A CA bundle shared by several clients, loaded once (`CaBundle.load`)
    /// — e.g. before a process confines itself (Landlock), for clients made
    /// later on other threads. Borrowed: it must outlive the client, which
    /// never frees it. Null (default): the client loads its own on the first
    /// HTTPS request.
    shared_ca: ?*CaBundle = null,
    /// Run every blocking phase (resolve + connect, TLS handshake, head read)
    /// on the calling thread instead of on a task of the `Io`'s pool.
    ///
    /// ⚠ Why it matters: with `std.Io.Threaded`, those phases run on the
    /// pool's threads (`runBounded`, the only way std 0.16 can bound them),
    /// whichever thread called `request`. A per-thread sandbox — Landlock,
    /// `setuid`, seccomp applied to the calling thread — does NOT confine a
    /// pool thread spawned before it, so that work runs unconfined. Either
    /// make the `Io` after the sandbox, or set this. The price:
    /// `connect_timeout_ms` and `total_timeout_ms` no longer interrupt a
    /// blocked phase (nothing can cancel a syscall on the caller's own
    /// thread); only the checks between phases remain. Name resolution goes
    /// around `std.Io.net.HostName.connect` too, which would otherwise start
    /// the lookup and the connects as tasks of the `Io` by itself; the
    /// resolved addresses are then tried one at a time, not in parallel.
    inline_blocking: bool = false,
    /// h1 keep-alive connection pooling (see the module doc). Defaults on;
    /// set `.enabled = false` for the old one-connection-per-request
    /// behavior (every request explicitly sends `Connection: close`).
    pool: PoolOptions = .{},
    /// Optional shared slab pool backing the **h2 client** read/write
    /// buffers (`connectH2c`). Null (the default) = each h2c dial
    /// `gpa.alloc`s its own `read_buffer_size + write_buffer_size` slab and
    /// frees it on `H2Session.close`, exactly as before. When set, that slab
    /// is checked out of / returned to the pool instead, so a gateway that
    /// churns h2 upstream connections reuses slabs across dials instead of
    /// allocating a fresh one every time. ⚠ "Bounded" describes the IDLE
    /// reserve (`bufpool.Options.max_idle_slabs`), not slabs currently
    /// checked out: those are never counted against that cap (see
    /// `bufpool.zig`'s own doc), so peak memory is still
    /// `slab_size × concurrent dials`, same as the unpooled default — the
    /// pool buys reuse, not a memory ceiling (A1 audit G11, 2026-09-04).
    /// **The pool's `slab_size` MUST equal
    /// `read_buffer_size + write_buffer_size`** (`connectH2c` returns
    /// `error.BufferPoolSizeMismatch` otherwise) — it serves exactly that
    /// one size class. The h1 path deliberately does
    /// NOT use it: h1's idle `Pool` already recycles whole warm connections
    /// (buffers included), so h1 never churns per-request buffers the way a
    /// fresh h2c dial does. Shared across threads (the pool is internally
    /// synchronized); the allocator behind it must be thread-safe.
    buffer_pool: ?*BufferPool = null,
    /// Outbound proxy, Go's `ProxyFromEnvironment` rules (`client_proxy.zig`):
    /// `http://` requests go to the `http` proxy in absolute form
    /// (`GET http://host/path`), `https://` requests open a `CONNECT` tunnel
    /// through the `https` proxy and run TLS to the origin inside it.
    /// Credentials in the proxy URL become `Proxy-Authorization: Basic`.
    /// Default: no proxy. `Proxy.fromEnviron` reads `HTTP_PROXY`,
    /// `HTTPS_PROXY` and `NO_PROXY` -- this client never reads the
    /// environment by itself. h2c (`connectH2c`) does not use it.
    proxy: Proxy = .{},
    /// Cookie store, consulted on every request and response, redirect
    /// hops included (`CookieJar`). A caller's own `Cookie` header is kept
    /// and the jar's cookies are appended to it. Null (default): no cookies
    /// beyond the caller's. Borrowed: must outlive the client.
    cookie_jar: ?CookieJar = null,
    /// Transparent gzip decoding of response bodies — Go's default
    /// `Transport` behavior (`DisableCompression: false`), switched on with
    /// `.decompress = .gzip(max_bytes)`. Null (default) = off: every request
    /// sends `Accept-Encoding: identity`, as before, and the decoder is not
    /// even linked in (`Decompress`). On: a request that carries no caller
    /// `Accept-Encoding` and no
    /// `Range`, and is not a HEAD, asks for `Accept-Encoding: gzip`; when the
    /// response then says `Content-Encoding: gzip`, `Response.reader` hands
    /// out the decoded bytes, `Response.header` no longer reports
    /// `Content-Encoding`/`Content-Length`, and `Response.uncompressed` is
    /// set. A caller that sets its own `Accept-Encoding` gets the body as
    /// sent, exactly as in Go (only the layer that asked decodes).
    ///
    /// `max_bytes` caps the decoded bytes of one response: beyond it the
    /// read fails with `error.BodyTooLarge` (a zip bomb; Go has no such cap
    /// — `maxInt(u64)` is Go's behavior). Every member's CRC-32/ISIZE trailer
    /// is checked, as Go does: a corrupt, truncated or trailing-garbage body
    /// fails with `error.CorruptGzip`. (The header's optional CRC-16, FHCRC,
    /// is skipped unchecked where Go checks it — a judged divergence, see
    /// `gzip.skipGzipHeader`.) Concatenated members are decoded one
    /// after another (RFC 1952 §2.2, Go's multistream default). The decoder's
    /// ~70 KiB of working memory is allocated per decoded response, only when
    /// the server actually answered gzip.
    decompress: ?Decompress = null,
    /// HTTP/2 over TLS, negotiated by ALPN — Go's `Transport` with
    /// `ForceAttemptHTTP2`, switched on with `.http2 = .alpn()`. Null
    /// (default) = off: the TLS handshake offers no ALPN and every request is
    /// HTTP/1.1, as before, and no h2 code is linked in (`Http2`). On: every
    /// `https://` dial offers `h2` and `http/1.1`; when the server picks `h2`
    /// the exchange runs as one stream on that connection and
    /// `Response.proto` says `.http2`. Headers, cookies, redirects,
    /// `decompress`, `max_conns_per_host` and the timeouts mean the same on
    /// both protocols; `Response.trailer` reads an h2 trailer section.
    ///
    /// One request at a time per connection: an h2 connection is checked out
    /// of the pool for a whole exchange like an h1 one, so concurrent
    /// requests to one origin open several connections where Go would
    /// multiplex them on one (SPEC Backlog). A request that asks for a
    /// protocol upgrade (`Connection: Upgrade` + `Upgrade`, e.g. WebSocket)
    /// never goes over h2, which has no upgrade: its dial offers only
    /// `http/1.1`, as Go's does for a WebSocket request. `http://` origins
    /// stay HTTP/1.1 (h2c is `connectH2c`).
    http2: ?Http2 = null,
};

/// How `Options.http2` speaks h2; made only by `alpn`. Function pointers
/// rather than a flag for the same reason as `Decompress`: the h2 engine
/// (framing, HPACK, flow control) is linked into a binary only when
/// something calls `alpn`.
pub const Http2 = struct {
    vt: *const VTable,

    /// Offer `h2` by ALPN on every `https://` dial and use it when chosen.
    pub fn alpn() Http2 {
        return .{ .vt = &h2glue.vtable };
    }

    const VTable = struct {
        start: *const fn (conn: *Conn) Error!void,
        exchange: *const fn (conn: *Conn, method: http.Method, method_token: []const u8, url: http.Url, headers: []const http.Header, plan: BodyPlan, body: ?[]const u8, strip_sensitive: bool, ask_gzip: bool) Error!h1.ResponseHead,
        open_upload: *const fn (conn: *Conn, method: http.Method, method_token: []const u8, url: http.Url, headers: []const http.Header, plan: BodyPlan, ask_gzip: bool) Error!void,
        upload_writer: *const fn (conn: *Conn) *std.Io.Writer,
        finish_upload: *const fn (conn: *Conn) Error!h1.ResponseHead,
        setup_body: *const fn (conn: *Conn, method: http.Method) void,
        drained: *const fn (conn: *const Conn) bool,
        read_failure: *const fn (conn: *const Conn) ?Error,
        trailer: *const fn (conn: *const Conn, name: []const u8) ?[]const u8,
        release: *const fn (conn: *Conn) bool,
        destroy: *const fn (conn: *Conn) void,
    };
};

/// Which HTTP version a response came over (`Response.proto`).
pub const Proto = enum {
    http1_0,
    http1_1,
    http2,

    /// Go's `Response.Proto` spelling: `HTTP/1.0`, `HTTP/1.1`, `HTTP/2.0`.
    pub fn text(p: Proto) []const u8 {
        return switch (p) {
            .http1_0 => "HTTP/1.0",
            .http1_1 => "HTTP/1.1",
            .http2 => "HTTP/2.0",
        };
    }
};

/// How `Options.decompress` decodes; made only by `gzip`. A function
/// pointer rather than a flag on purpose: the decoder (std's flate plus the
/// gzip framing, ~23 KB on x86_64 ReleaseSmall) is linked into a binary only
/// when something calls `gzip` — a client that never decodes does not pay
/// for it (the plaintext size probe, `sizeprobe/`, measures exactly that).
pub const Decompress = struct {
    max_bytes: u64,
    start: *const fn (g: *Gunzip, raw: *std.Io.Reader, max_bytes: u64) void,

    /// gzip, as Go's `Transport` decodes it; `max_bytes` (decoded, per
    /// response) is the zip-bomb cap, `maxInt(u64)` = Go's none.
    pub fn gzip(max_bytes: u64) Decompress {
        return .{ .max_bytes = max_bytes, .start = Gunzip.init };
    }
};

/// Tunables for the idle-connection pool (`Options.pool`).
pub const PoolOptions = struct {
    /// Master switch. When false, `Client` behaves exactly as a
    /// non-pooling client always has: every request dials fresh and sends
    /// `Connection: close`.
    enabled: bool = true,
    /// Idle connections kept per `(scheme, host, port)` origin. Default 4:
    /// a reverse proxy typically fans a modest number of concurrent
    /// requests out to any one backend, so 4 warm sockets absorbs normal
    /// burst concurrency without pinning FDs a backend never asked for;
    /// callers fronting a hotter single backend can raise it.
    max_idle_per_host: u16 = 4,
    /// Idle connections kept across ALL origins combined. Default 64:
    /// bounds the client's total idle-FD/memory footprint when it talks to
    /// many distinct backends (a gateway in front of a large fleet), while
    /// still comfortably covering the common "few backends" case.
    max_idle_total: u16 = 64,
    /// An idle connection older than this is reaped — checked
    /// opportunistically whenever `acquire` scans the pool, and fully via
    /// an explicit `Client.poolSweep` call (no background thread anywhere
    /// in this module). Default 30s: comfortably under most reverse-proxy
    /// and origin-server default keep-alive timeouts (nginx/Apache
    /// commonly default to 60-75s), so a pooled connection is usually
    /// reaped by *us* before the peer would have closed it — the
    /// transparent one-shot retry (see the module doc / `request`) is the
    /// backstop for the remainder.
    idle_timeout_ms: u32 = 30_000,
    /// Cap on connections to one `(scheme, host, port)` origin — dialing,
    /// in use and idle together — Go's `Transport.MaxConnsPerHost`. 0
    /// (default, Go's too) = unlimited. A request that finds its origin at
    /// the cap first takes an idle connection if one is pooled; otherwise
    /// it waits until a connection is released to the pool (it then takes
    /// that one) or closed (it then dials), bounded by `total_timeout_ms`
    /// (`error.Timeout`; 0 = waits without bound, as Go without a context
    /// deadline). Applies with pooling off too: there every connection is
    /// closed after its response, so the cap is on concurrent exchanges.
    /// Counts the h1 connections of `request`/`requestStreaming`/`putFile`
    /// and their `*Plain` twins, an upgraded (`101`) connection until its
    /// `Response.deinit`; an h2 session (`connectH2c`) is not counted.
    max_conns_per_host: u16 = 0,
};

pub const TlsOptions = struct {
    verify: Verify = .strict,

    pub const Verify = enum {
        /// Verify the certificate chain against the system CA bundle and the
        /// request host (loaded lazily, once per Client).
        strict,
        /// No certificate or host verification. Testing/diagnostics only.
        insecure_no_verify,
    };
};

pub const RequestOptions = struct {
    /// Extra request headers. `Host`, `User-Agent` and `Accept-Encoding`
    /// override the defaults; `Connection`, `Content-Length` and
    /// `Transfer-Encoding` are managed by the client and ignored here.
    headers: []const http.Header = &.{},
    /// In-memory request body (sent with Content-Length; replayed on 307/308
    /// redirects). For streaming uploads use `requestStreaming`.
    body: ?[]const u8 = null,
    follow_redirects: bool = true,
    /// The destination gate, consulted before any dial (A1 G5; extended
    /// 2026-09-11 to cover the FIRST dial too — see `RedirectFilter.allow`).
    /// `false` ends the request with `error.RedirectRefused` (nothing was
    /// sent to the refused host). This is where a consumer that lets a user
    /// supply a URL keeps it — or a 3xx it answers with — from walking onto
    /// a loopback, link-local or RFC 1918 address, or off an allow-list of
    /// hosts — without turning `follow_redirects` off and re-implementing
    /// the chain. `null` = every destination, first hop and every redirect
    /// within `Options.max_redirects`, is dialed unexamined, as before:
    /// **a consumer that does not set this has no destination gate at all**
    /// (a recorded default, see SPEC.md — credentials are stripped on a
    /// cross-origin redirect hop, destinations are not judged).
    redirect_filter: ?RedirectFilter = null,
    /// The token sent for `Method.other` — an extension method such as
    /// "PURGE" or "PROPFIND" (Go: any `Request.Method`). Required with
    /// `.other`, refused (`InvalidHeader`) with any other method; it must
    /// be an RFC 9110 token. A 301/302/303 rewrites it to GET, as Go does.
    method_token: []const u8 = "",
};

pub const RedirectFilter = struct {
    ctx: ?*anyopaque = null,
    /// Consulted before every dial this request makes. `from` is the URL
    /// that produced `to`: the URL that answered 3xx for a redirect hop, or
    /// — for the very first dial, no redirect involved — `to` itself
    /// (`from == to` is how a filter distinguishes "this is the caller's
    /// own destination" from "this is where a redirect wants to send you").
    /// A filter that only cares about judging redirects, matching this
    /// seam's original shape, can open by checking whether `from` and `to`
    /// are the same value (a plain field-by-field comparison, or comparing
    /// whatever request-scoped identity the caller already tracks) and
    /// returning `true` early when they are — on the first-dial call they
    /// are always identical, never merely equal-looking.
    allow: *const fn (ctx: ?*anyopaque, from: http.Url, to: http.Url) bool,
};

pub const Error = error{
    UnsupportedScheme,
    BadUrl,
    UnknownHostName,
    ConnectFailed,
    TlsFailed,
    CertificateBundleLoadFailure,
    WriteFailed,
    ReadFailed,
    ConnectionClosed,
    MalformedResponse,
    UnsupportedHttpVersion,
    HeadTooLarge,
    TooManyRedirects,
    BadRedirect,
    RedirectTooLong,
    BodyTooLarge,
    UnexpectedStatus,
    Timeout,
    Canceled,
    OutOfMemory,
    /// `io.randomSecure` could not obtain entropy for TLS key material
    /// (`dialConn`'s `tls.Client.Options.entropy`); unlike `io.random` it
    /// does not fall back to a weaker source, so this is fail-closed rather
    /// than silently-degraded randomness.
    EntropyUnavailable,
    /// `connectH2c`: `Options.buffer_pool` is set, but its `slab_size` does
    /// not equal `read_buffer_size + write_buffer_size` — the pool serves
    /// one size class and this dial needs a different one. Checked before
    /// any allocation or I/O.
    BufferPoolSizeMismatch,
    /// A `RequestOptions.headers` entry cannot be put on the wire as the
    /// one field it claims to be: the name is not an RFC 9110 token, or the
    /// value carries a CR, LF, NUL or other control byte. Written into a
    /// `name: value\r\n` line such a value would become a second header (or
    /// a second request) the caller never made — the header-injection
    /// primitive — so it is refused here, before any dial. Same rule for
    /// the URL's path/query: whitespace or a control byte there fails
    /// `Url.parse` as `BadUrl`. Also a method this client cannot send:
    /// `.other` without a valid `RequestOptions.method_token` (or one given
    /// with another method), and `.connect` — tunnels are what
    /// `Options.proxy` builds, a caller cannot ask for one.
    InvalidHeader,
    /// `RequestOptions.redirect_filter` said no to a redirect target; the
    /// refused host was never dialed.
    RedirectRefused,
    /// `Options.proxy` names a proxy this client cannot use: it does not
    /// parse, it is not `http://`, or it is an `http` proxy for an `http://`
    /// request under CGI (see `Proxy`). Never a silent direct connection.
    BadProxy,
    /// The proxy answered `CONNECT` with something other than 2xx (a 407
    /// wanting credentials, a 403 policy refusal, a 502 it could not reach
    /// the origin with). Nothing was sent to the origin.
    ProxyRefused,
    /// A body this client decodes (`Options.decompress`)
    /// is not valid gzip: bad header, corrupt deflate data, a CRC-32/ISIZE
    /// mismatch, a stream cut short, or bytes after the last member that
    /// are not another member (Go: `gzip.ErrHeader` / `ErrChecksum`).
    CorruptGzip,
    /// HTTP/2 (`Options.http2`): the server reset this request's stream
    /// (RST_STREAM) — Go's `http2.StreamError`. The connection stays usable.
    StreamReset,
};

/// The outbound half of the header-injection defence: every caller-supplied
/// field is held to the rule the inbound h1 parser enforces on the wire
/// (`h1.isToken` / `h1.isValidFieldValue`), so no request this client
/// writes can contain a line it did not mean to. Called before a connection
/// is acquired — a refused request costs no dial.
fn validateHeaders(headers: []const http.Header) error{InvalidHeader}!void {
    for (headers) |hd| {
        if (!h1.isToken(hd.name) or !h1.isValidFieldValue(hd.value)) return error.InvalidHeader;
    }
}

/// The method half of the same rule (see `Error.InvalidHeader`).
fn validateMethod(method: http.Method, method_token: []const u8) error{InvalidHeader}!void {
    if (method == .connect) return error.InvalidHeader;
    if (method == .other) {
        if (!h1.isToken(method_token)) return error.InvalidHeader;
    } else if (method_token.len != 0) return error.InvalidHeader;
}

/// The token `method` goes on the wire as.
fn methodWire(method: http.Method, method_token: []const u8) []const u8 {
    return if (method == .other) method_token else method.token();
}

/// `io` must support the net + async vtable operations (e.g.
/// `std.Io.Threaded`). The allocator is used for per-request connection
/// buffers and the CA bundle.
pub fn init(io: std.Io, gpa: std.mem.Allocator, options: Options) Client {
    return .{
        .io = io,
        .gpa = gpa,
        .options = options,
        .ca_bundle = .empty,
        .ca_lock = .init,
        .ca_scanned = false,
        .pool = Pool.init(gpa, io, options.pool),
    };
}

pub fn deinit(c: *Client) void {
    c.pool.deinit();
    c.ca_bundle.deinit(c.gpa);
    c.* = undefined;
}

/// Lifetime count of fresh dials (see `dial_count`'s doc). Mainly for tests
/// and metrics.
pub fn dialCount(c: *Client) usize {
    return c.dial_count.load(.monotonic);
}

/// Total idle pooled connections currently held (all origins). Mainly for
/// tests and metrics.
pub fn poolIdleCount(c: *Client) usize {
    return c.pool.idleCount();
}

/// Reap idle connections older than `Options.pool.idle_timeout_ms` right
/// now (this also happens opportunistically whenever `acquire` scans the
/// pool). There is no background thread anywhere in this module — call
/// this from your own timer/loop if you want proactive housekeeping instead
/// of relying on next-acquire reaping.
pub fn poolSweep(c: *Client) void {
    c.pool.sweep(c.nowMs());
}

// ── the request/response exchange ───────────────────────────────────────────

/// Perform a request, following redirects per `RequestOptions`. The returned
/// `Response` owns a connection — read the body via `Response.reader` and
/// always call `Response.deinit`.
pub fn request(c: *Client, method: http.Method, url_text: []const u8, options: RequestOptions) Error!Response {
    const deadline = c.totalDeadline() orelse return c.requestInner(method, url_text, options);
    return runBounded(c.io, c.options.inline_blocking, deadline, requestInner, .{ c, method, url_text, options }) catch |err| switch (err) {
        // See `connectStream` for the same fallback: without a spare unit of
        // concurrency there is nothing to cancel, so the exchange runs on
        // this thread with only the between-phase deadline checks below.
        error.ConcurrencyUnavailable => c.requestInner(method, url_text, options),
        else => |e| e,
    };
}

/// `request`'s body, run either on the caller's thread or on the concurrent
/// task `request` bounds. The `checkDeadline` calls here are NOT the timeout
/// mechanism (they cannot interrupt a blocking read — that is what
/// `runBounded` is for); they are what still holds when no unit of
/// concurrency was available, and they stop a redirect chain or a stale-conn
/// retry from starting fresh work on a budget that is already spent.
fn requestInner(c: *Client, method: http.Method, url_text: []const u8, options: RequestOptions) Error!Response {
    const deadline = c.totalDeadline();

    var url = try http.Url.parse(url_text);
    try validateHeaders(options.headers);
    try validateMethod(method, options.method_token);
    // A1 G5 (extended 2026-09-11): the caller's OWN destination is gated
    // too, not just a redirect target — before this, `redirect_filter`
    // covered only hop-to-hop, so a consumer that lets a user supply the
    // request URL directly (no redirect involved at all) had no gate on it.
    // `from == to` here is how a filter tells the first dial apart from an
    // actual redirect hop (see `RedirectFilter.allow`'s doc).
    if (options.redirect_filter) |f| {
        if (!f.allow(f.ctx, url, url)) return error.RedirectRefused;
    }
    // Slices in `original_url` point into `url_text` (caller-owned, valid for
    // the whole call), so keeping this copy around stays valid even after
    // `url` itself gets reassigned to a redirect target below.
    const original_url = url;
    var current_method = method;
    var current_body = options.body;
    var url_owned: ?[]u8 = null;
    defer if (url_owned) |s| c.gpa.free(s);
    const h1_only = needsHttp1(options.headers);

    var redirects: u8 = 0;
    while (true) {
        try c.checkDeadline(deadline);

        // Strip credential-bearing headers unless this hop's target is the
        // *exact same origin* (scheme + host + port) as the original request
        // — a host-only check would keep sending Authorization/Cookie across
        // a same-host https→http downgrade or a same-host port change
        // (CVE-2018-18074 class: cleartext credential / cross-service leak).
        const strip_sensitive = crossOrigin(original_url, url);
        const plan: BodyPlan = if (current_body) |b| .{ .content_length = b.len } else .none;
        const ask_gzip = c.requestsGzip(current_method, options.headers);

        var reused = false;
        var conn = try c.acquireConn(url, &reused, deadline, h1_only);
        // `owned` guards the errdefer below across the two places later in
        // this same iteration that explicitly `conn.destroy()` and then may
        // still return an error (the stale-connection retry's redial, and
        // the redirect path a few lines down): a bare `errdefer
        // conn.destroy()` would fire AGAIN on the already-freed `conn` in
        // either case — a real double-free, reproduced by the
        // "stale-conn retry whose redial ALSO fails" test below (it used to
        // segfault inside `destroy`, called from this very `errdefer`). Same
        // idiom as `requestInnerPlain`'s `owned` flag; see its doc comment.
        var owned = true;
        errdefer if (owned) conn.destroy();

        const head = c.sendAndReadHead(conn, current_method, options.method_token, url, options.headers, plan, current_body, strip_sensitive, ask_gzip) catch |err| retry: {
            // Retry exactly once, and only when BOTH hold: (1) `conn` came
            // from the pool (`reused`), so it might have gone stale while
            // parked — a freshly dialed connection failing this way is a
            // real, non-retryable backend problem; (2) `isStaleConnError`
            // says the failure means nothing of this exchange reached the
            // peer as a live request (see its doc for the exact boundary).
            // We still hold the full request (method/url/headers and, on
            // this in-memory-body path, `current_body` itself) and can
            // resend it byte-for-byte on a fresh connection.
            //
            // `requestStreaming`/`Upload` deliberately get a narrower version
            // of this (only before any caller body byte is touched) — see
            // its doc comment for why a blanket retry is not safe there.
            if (!reused or !isStaleConnError(err)) return err;
            // A retry is fresh work: it must not start on a budget that is
            // already spent. Without this, a `runBounded` deadline that fires
            // during the first attempt would be *absorbed* by the retry —
            // cancelation is delivered to one cancelation point only, so the
            // second attempt would block with nothing left to interrupt it
            // and `Future.cancel` would wait on it forever. (`Canceled` is
            // deliberately absent from `isStaleConnError`, which is the other
            // half of that guard.)
            try c.checkDeadline(deadline);
            conn.destroy();
            owned = false;
            conn = try c.checkoutConn(url, &reused, deadline, false, h1_only, dialConn);
            owned = true;
            break :retry try c.sendAndReadHead(conn, current_method, options.method_token, url, options.headers, plan, current_body, strip_sensitive, ask_gzip);
        };

        redirect: {
            if (!options.follow_redirects) break :redirect;
            const next_method = http.redirectMethodFor(head.status, current_method) orelse break :redirect;
            const location = head.header("location") orelse {
                // Like Go: 307/308 without Location is returned to the
                // caller; on 301–303 it is a protocol error.
                if (head.status == 307 or head.status == 308) break :redirect;
                return error.BadRedirect;
            };
            if (redirects >= c.options.max_redirects) return error.TooManyRedirects;
            redirects += 1;

            const cap = "https://".len + url.host.len + ":65535[]".len +
                url.path.len + location.len + http.max_merged_path;
            const buf = try c.gpa.alloc(u8, cap);
            errdefer c.gpa.free(buf);
            const resolved = try http.resolveLocation(url, location, buf);
            // Parsed BEFORE `conn.destroy()` below (same "check-before-destroy"
            // ordering as `requestInnerPlain`'s redirect branch — see its
            // `owned` doc comment): `resolveLocation` copies an absolute
            // `http(s)://` Location header through verbatim, so a peer can
            // send one that fails `Url.parse` — that used to be checked
            // AFTER `conn.destroy()`, another `errdefer if (owned) …`-class
            // double-free, just gated on a malformed redirect target instead
            // of a failed redial.
            const next_url = http.Url.parse(resolved) catch return error.BadRedirect;
            // The destination gate, before `conn.destroy()` for the same
            // reason as the parse above, and before any dial: a refused
            // host receives nothing.
            if (options.redirect_filter) |f| {
                if (!f.allow(f.ctx, url, next_url)) return error.RedirectRefused;
            }

            // h1: closed, the redirect's body is not read. h2: the stream is
            // reset and the connection pooled for the next hop.
            if (conn.h2 != null) c.retire(conn) else conn.destroy();
            owned = false;
            if (url_owned) |s| c.gpa.free(s);
            url_owned = buf;
            url = next_url;
            if (head.status != 307 and head.status != 308) current_body = null;
            current_method = next_method;
            continue;
        }

        return c.makeResponse(conn, current_method, head, ask_gzip);
    }
}

/// `request`'s plaintext-only twin: identical redirect/retry/pooling
/// behavior, but every dial goes through `acquireConnPlain`/`dialPlain`
/// instead of `acquireConn`/`dialConn` — so this function's own text, and
/// everything it calls, must never name `dialConn`/`dialTls`/`ensureCaBundle`
/// either (see `dialPlain`'s doc comment). `http://` only: an `https://`
/// URL, whether passed in directly or reached via a redirect hop, fails with
/// `error.UnsupportedScheme` rather than silently downgrading or upgrading —
/// this client speaks TLS to nothing, ever.
///
/// This and `requestInnerPlain`/`acquireConnPlain` are intentionally a
/// separate copy of `request`/`requestInner`/`acquireConn` rather than a
/// shared implementation parameterized on which dialer to use: a shared
/// implementation would have to name both dialers from one place, which is
/// exactly the reachability trap `dialConn`'s dispatcher already
/// demonstrates (see its doc comment) — the duplication here is what keeps
/// this call graph provably TLS-free rather than merely usually-TLS-free.
pub fn requestPlain(c: *Client, method: http.Method, url_text: []const u8, options: RequestOptions) Error!Response {
    const deadline = c.totalDeadline() orelse return c.requestInnerPlain(method, url_text, options);
    return runBounded(c.io, c.options.inline_blocking, deadline, requestInnerPlain, .{ c, method, url_text, options }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => c.requestInnerPlain(method, url_text, options),
        else => |e| e,
    };
}

fn requestInnerPlain(c: *Client, method: http.Method, url_text: []const u8, options: RequestOptions) Error!Response {
    const deadline = c.totalDeadline();

    var url = try http.Url.parse(url_text);
    if (url.scheme != .http) return error.UnsupportedScheme;
    try validateHeaders(options.headers);
    try validateMethod(method, options.method_token);
    // A1 G5 (extended 2026-09-11) — see `requestInner`'s identical gate.
    if (options.redirect_filter) |f| {
        if (!f.allow(f.ctx, url, url)) return error.RedirectRefused;
    }
    const original_url = url;
    var current_method = method;
    var current_body = options.body;
    var url_owned: ?[]u8 = null;
    defer if (url_owned) |s| c.gpa.free(s);

    var redirects: u8 = 0;
    while (true) {
        try c.checkDeadline(deadline);

        const strip_sensitive = crossOrigin(original_url, url);
        const plan: BodyPlan = if (current_body) |b| .{ .content_length = b.len } else .none;
        const ask_gzip = c.requestsGzip(current_method, options.headers);

        var reused = false;
        var conn = try c.acquireConnPlain(url, &reused, deadline);
        // `owned` guards the errdefer below across the two places later in
        // this same iteration that explicitly `conn.destroy()` and then may
        // still return an error (the stale-connection retry's redial, and
        // the redirect-scheme check): a bare `errdefer conn.destroy()` would
        // fire AGAIN on the already-freed `conn` in either case — this is a
        // real double-free this function hit during development (see the
        // "a redirect to https:// fails closed" test, which forces the
        // redirect-branch case) — so ownership is tracked explicitly instead
        // of assumed from scope alone.
        var owned = true;
        errdefer if (owned) conn.destroy();

        const head = c.sendAndReadHead(conn, current_method, options.method_token, url, options.headers, plan, current_body, strip_sensitive, ask_gzip) catch |err| retry: {
            if (!reused or !isStaleConnError(err)) return err;
            try c.checkDeadline(deadline);
            conn.destroy();
            owned = false;
            conn = try c.checkoutConn(url, &reused, deadline, false, false, dialPlain);
            owned = true;
            break :retry try c.sendAndReadHead(conn, current_method, options.method_token, url, options.headers, plan, current_body, strip_sensitive, ask_gzip);
        };

        redirect: {
            if (!options.follow_redirects) break :redirect;
            const next_method = http.redirectMethodFor(head.status, current_method) orelse break :redirect;
            const location = head.header("location") orelse {
                if (head.status == 307 or head.status == 308) break :redirect;
                return error.BadRedirect;
            };
            if (redirects >= c.options.max_redirects) return error.TooManyRedirects;
            redirects += 1;

            const cap = "https://".len + url.host.len + ":65535[]".len +
                url.path.len + location.len + http.max_merged_path;
            const buf = try c.gpa.alloc(u8, cap);
            errdefer c.gpa.free(buf);
            const resolved = try http.resolveLocation(url, location, buf);
            const next_url = http.Url.parse(resolved) catch return error.BadRedirect;
            // A redirect can point anywhere, including `https://`; this
            // client never dials TLS, so that is a clean typed error here
            // rather than a silent scheme change. Checked BEFORE
            // `conn.destroy()` below (see `owned`'s doc comment) so this
            // return can never double-free it.
            if (next_url.scheme != .http) return error.UnsupportedScheme;
            if (options.redirect_filter) |f| {
                if (!f.allow(f.ctx, url, next_url)) return error.RedirectRefused;
            }

            conn.destroy();
            owned = false;
            if (url_owned) |s| c.gpa.free(s);
            url_owned = buf;
            url = next_url;
            if (head.status != 307 and head.status != 308) current_body = null;
            current_method = next_method;
            continue;
        }

        return c.makeResponse(conn, current_method, head, ask_gzip);
    }
}

/// A response with its (single-use) connection. Slices in `head`/`reason`
/// stay valid until `deinit`.
pub const Response = struct {
    status: u16,
    reason: []const u8,
    /// The head as received — `Content-Encoding`/`Content-Length` included
    /// even when `uncompressed` (use `header` for Go's view).
    head: h1.ResponseHead,
    conn: *Conn,
    /// Set when this client asked for gzip and is decoding the body
    /// (`Options.decompress`): `reader` yields the
    /// decoded bytes. Go's `Response.Uncompressed`.
    uncompressed: bool = false,
    gunzip: ?*Gunzip = null,

    /// First value of a response header (case-insensitive), or null. When
    /// `uncompressed`, `Content-Encoding` and `Content-Length` read as
    /// absent: they describe the bytes on the wire, not the ones `reader`
    /// hands out (Go deletes both).
    pub fn header(res: *const Response, name: []const u8) ?[]const u8 {
        if (res.uncompressed and (std.ascii.eqlIgnoreCase(name, "content-encoding") or
            std.ascii.eqlIgnoreCase(name, "content-length"))) return null;
        return res.head.header(name);
    }

    /// Streaming body reader (chunked / Content-Length framing already
    /// decoded, and gzip when `uncompressed`; reads to end-of-body). Valid
    /// until `deinit`.
    pub fn reader(res: *Response) *std.Io.Reader {
        if (res.gunzip) |g| return &g.reader;
        return res.rawReader();
    }

    fn rawReader(res: *Response) *std.Io.Reader {
        return switch (res.conn.body) {
            .none => |*r| r,
            .chunked => |*cr| &cr.reader,
            .limited => |*lr| &lr.reader,
            .until_close => res.conn.plainReader(),
            .h2 => |r| r,
            .unset => unreachable,
        };
    }

    /// The HTTP version the response came over: `.http2` when the request
    /// went over an h2 connection (`Options.http2`).
    pub fn proto(res: *const Response) Proto {
        if (res.conn.h2 != null) return .http2;
        return if (res.head.http1_0) .http1_0 else .http1_1;
    }

    /// First value of a trailer field (case-insensitive) — the h2 trailer
    /// section or a chunked HTTP/1.1 body's, Go's `Response.Trailer`. Known
    /// only once the body has been read to its end; null before and when
    /// there is none. An HTTP/1.1 trailer section shares `max_head_bytes`
    /// with the head: lines past it are dropped (`trailersTruncated`).
    /// Valid until `deinit`.
    pub fn trailer(res: *const Response, name: []const u8) ?[]const u8 {
        if (res.conn.h2 != null) return res.conn.client.options.http2.?.vt.trailer(res.conn, name);
        return switch (res.conn.body) {
            .chunked => |*cr| if (cr.state == .done) cr.trailer(name) else null,
            else => null,
        };
    }

    /// The HTTP/1.1 trailer section did not fit what `max_head_bytes` left
    /// after the head, so `trailer` may answer null for a field that was
    /// sent (the dropped lines were still read off the wire).
    pub fn trailersTruncated(res: *const Response) bool {
        if (res.conn.h2 != null) return false;
        return switch (res.conn.body) {
            // A head that filled `head_buf` leaves no capture buffer, and
            // `ChunkedReader` then discards without flagging: anything past
            // the closing CRLF was a dropped trailer line.
            .chunked => |*cr| cr.trailers_overflow or (cr.trailer_buf.len == 0 and cr.trailer_bytes_seen > 2),
            else => false,
        };
    }

    /// Recover the real cause behind an `error.ReadFailed` reported by
    /// `reader()` (or anything built on it — a line/SSE parser, a manual
    /// `readSliceShort`, …). `*std.Io.Reader`'s own error set is exactly
    /// `{ReadFailed, EndOfStream}` (CONVENTIONS.md §2) and cannot carry
    /// `error.Canceled`, so a caller driving `reader()` directly — unlike
    /// `readAllAlloc`, which already does this internally — has no way to
    /// tell a `std.Io` cancelation from a dead connection. This is that
    /// missing seam: it asks the same question `Conn.readFailure` answers
    /// for `readAllAlloc`, without making `Conn` itself public. Call it
    /// right after `reader()` (or a parser over it) reports
    /// `error.ReadFailed` — it describes that failure, not a future one.
    pub fn readFailure(res: *Response) Error {
        if (res.gunzip) |g| if (g.failure) |f| return f;
        if (res.conn.h2 != null) if (res.conn.client.options.http2.?.vt.read_failure(res.conn)) |f| return f;
        return res.conn.readFailure();
    }

    /// Read the whole remaining body into an allocated buffer
    /// (`error.BodyTooLarge` beyond `max_len`).
    pub fn readAllAlloc(res: *Response, gpa: std.mem.Allocator, max_len: usize) Error![]u8 {
        // `std.Io.Reader.LimitedAllocError` is exactly `{OutOfMemory,
        // ReadFailed, StreamTooLong}` — an `else` arm here used to fold
        // `ReadFailed` in blind, discarding the same `error.Canceled` that
        // `Conn.readFailure` already recovers one call away in `sendAndReadHead`
        // (see its doc comment: both TLS and plaintext funnel through the same
        // socket reader, so this one check covers a chunked, Content-Length,
        // or until-close body alike).
        return res.reader().allocRemaining(gpa, .limited(max_len)) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.StreamTooLong => error.BodyTooLarge,
            error.ReadFailed => res.readFailure(),
        };
    }

    /// After `101 Switching Protocols` to a request that asked for an
    /// upgrade (`Connection: Upgrade` + `Upgrade` in its headers): the
    /// connection itself, to speak the new protocol on — Go's 101 response
    /// body as an `io.ReadWriteCloser`. Its reader may already hold bytes
    /// the server sent behind the 101. Valid until `deinit`, which closes the
    /// connection (a 101 is never pooled). Null for any other status.
    pub fn upgraded(res: *Response) ?Upgraded {
        if (res.status != 101) return null;
        return .{ .conn = res.conn };
    }

    /// Return the connection to the pool when it left the exchange in a
    /// clean, fully-drained, keep-alive-eligible state (see
    /// `Conn.keep_alive_eligible` / `isBodyDrained`); otherwise close it.
    /// Over h2 a body not read to its end resets the stream (RST_STREAM
    /// CANCEL) and the connection is pooled anyway, as in Go. Either way,
    /// frees this response's per-request buffers.
    pub fn deinit(res: *Response) void {
        const conn = res.conn;
        const c = conn.client;
        if (res.gunzip) |g| c.gpa.destroy(g);
        c.retire(conn);
        res.* = undefined;
    }
};

/// Done with `conn` after a response: back to the pool when the exchange
/// left it reusable (h1: keep-alive and the body read to its end; h2: the
/// session healthy, the stream released or reset), else closed.
fn retire(c: *Client, conn: *Conn) void {
    const reusable = if (conn.h2 != null)
        c.options.http2.?.vt.release(conn)
    else
        conn.keep_alive_eligible and isBodyDrained(conn);
    if (c.options.pool.enabled and reusable) {
        c.pool.release(conn, c.nowMs());
    } else {
        conn.destroy();
    }
}

/// Whether a request must go over HTTP/1.1: it asks for a protocol upgrade
/// (`Connection: Upgrade` + `Upgrade`), which h2 has no way to carry (RFC
/// 9113 §8.6). Go asks the same of a WebSocket request (`requiresHTTP1`);
/// any upgrade counts here, as the h1 head writer passes any upgrade on.
fn needsHttp1(headers: []const http.Header) bool {
    var asks_upgrade = false;
    var has_upgrade = false;
    for (headers) |hd| {
        if (std.ascii.eqlIgnoreCase(hd.name, "connection") and h1.tokenListContains(hd.value, "upgrade")) asks_upgrade = true;
        if (std.ascii.eqlIgnoreCase(hd.name, "upgrade")) has_upgrade = true;
    }
    return asks_upgrade and has_upgrade;
}

/// An upgraded connection (see `Response.upgraded`).
pub const Upgraded = struct {
    conn: *Conn,

    /// Bytes from the server.
    pub fn reader(u: Upgraded) *std.Io.Reader {
        return u.conn.plainReader();
    }

    /// Bytes to the server; `flush` sends them.
    pub fn writer(u: Upgraded) *std.Io.Writer {
        return u.conn.plainWriter();
    }

    /// Push what was written onto the socket (through TLS on `https`).
    pub fn flush(u: Upgraded) Error!void {
        return u.conn.flushAll();
    }

    /// Shut the socket down both ways: a read blocked in another task
    /// returns. The connection is still closed by `Response.deinit`.
    pub fn shutdown(u: Upgraded) void {
        u.conn.stream.shutdown(u.conn.client.io, .both) catch {};
    }
};

// ── streaming uploads ───────────────────────────────────────────────────────

/// Whether this request asks for gzip (`Options.decompress`),
/// by Go's rule (transport.go, `requestedGzip`): not when the caller set its
/// own `Accept-Encoding` — the body is then the caller's to decode — nor
/// with a `Range` (a decoded slice of a gzip stream cannot be decoded), nor
/// on HEAD (nginx ticket 358). Go also treats an empty caller value as
/// unset; here any caller `Accept-Encoding` counts (a judged divergence: an
/// empty one is still a field the caller wrote, and goes on the wire).
fn requestsGzip(c: *const Client, method: http.Method, headers: []const http.Header) bool {
    if (c.options.decompress == null or method == .head) return false;
    for (headers) |hd| {
        if (std.ascii.eqlIgnoreCase(hd.name, "accept-encoding") or
            std.ascii.eqlIgnoreCase(hd.name, "range")) return false;
    }
    return true;
}

/// Frame the body of a response whose head was just read, and wrap it in
/// the gzip decoder when this client asked for gzip (`asked_gzip`, from
/// `requestsGzip`) and got it — `Content-Encoding: gzip` exactly
/// (case-insensitive), the only coding Go decodes; `x-gzip` or a coding
/// list are handed over as sent. Only a response that may have a body is
/// decoded: as in Go (whose `readLoop` wraps only when `hasBody`), a 204, a
/// 304 or a `Content-Length: 0` keeps its `Content-Encoding` and is not
/// `uncompressed`; a 101 hands the connection itself over. On error `conn`
/// is still the caller's.
fn makeResponse(c: *Client, conn: *Conn, method: http.Method, head: h1.ResponseHead, asked_gzip: bool) Error!Response {
    // h2 (Go's `http2Transport`): a body exists unless the HEADERS frame
    // ended the stream or the request was a HEAD; `Content-Length` frames
    // nothing there, so it does not decide this either.
    const has_body = if (conn.h2 != null) b: {
        c.options.http2.?.vt.setup_body(conn, method);
        break :b conn.body != .none;
    } else b: {
        setupBody(conn, method, head);
        break :b conn.body != .none and head.content_length != 0 and head.status != 101;
    };
    var res: Response = .{ .status = head.status, .reason = head.reason, .head = head, .conn = conn };
    if (asked_gzip and has_body) if (head.header("content-encoding")) |ce| {
        if (std.ascii.eqlIgnoreCase(ce, "gzip")) {
            const d = c.options.decompress.?;
            const g = try c.gpa.create(Gunzip);
            d.start(g, res.rawReader(), d.max_bytes);
            res.gunzip = g;
            res.uncompressed = true;
        }
    };
    return res;
}

/// The response-body gzip decoder (`Options.decompress`),
/// Go's `gzipReader` over a `gzip.Reader` in multistream mode: members back
/// to back, each with its CRC-32/ISIZE trailer checked; an empty body
/// decodes to nothing; anything after a member that is not another member
/// is corrupt. Decodes raw deflate itself (`gzip.DecodeScratch`, `.raw`) so
/// the header and trailer are parsed here — std's `.gzip` container reads
/// the trailer but checks nothing. The source is `DecodeScratch`'s padded
/// one, so a body cut short never reaches std's truncation abort (see
/// `gzip.PaddedSource`) and is refused instead.
///
/// The decoder only ever reads the framed body, so once it reports the end,
/// the framing reader is at the end of the body too and the connection can
/// go back to the pool (`isBodyDrained`). Not movable after `init`.
const Gunzip = struct {
    scratch: gzip.DecodeScratch,
    /// `scratch`'s padded reader: headers and trailers come off it.
    src: *std.Io.Reader,
    /// Decoded bytes still allowed.
    remaining: u64,
    state: enum { member_start, body, done },
    /// CRC-32 / byte count (mod 2^32) of the current member so far.
    crc: u32,
    size: u32,
    /// Why the last read failed, when it was the body and not the
    /// transport (`Response.readFailure`). Sticky.
    failure: ?Error,
    reader: std.Io.Reader,

    fn init(g: *Gunzip, raw: *std.Io.Reader, max_bytes: u64) void {
        g.src = g.scratch.start(raw, .raw);
        g.remaining = max_bytes;
        g.state = .member_start;
        g.crc = 0;
        g.size = 0;
        g.failure = null;
        g.reader = .{ .vtable = &.{ .stream = stream }, .buffer = &g.scratch.out, .seek = 0, .end = 0 };
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const g: *Gunzip = @alignCast(@fieldParentPtr("reader", r));
        if (g.failure != null) return error.ReadFailed;
        while (true) switch (g.state) {
            .done => return error.EndOfStream,
            .member_start => {
                if (try g.rawAtEnd()) {
                    g.state = .done;
                    return error.EndOfStream;
                }
                gzip.skipGzipHeader(g.src) catch |err| switch (err) {
                    error.ReadFailed => return error.ReadFailed,
                    error.EndOfStream, error.BadHeader => return g.fail(error.CorruptGzip),
                };
                g.scratch.decompress = .init(g.src, .raw, &g.scratch.window);
                if (g.scratch.paddingConsumed()) return g.fail(error.CorruptGzip);
                g.crc = 0;
                g.size = 0;
                g.state = .body;
            },
            .body => {
                const inner = &g.scratch.decompress.reader;
                if (g.remaining == 0) {
                    // At the cap: the member must end exactly here.
                    const n = inner.discard(.limited(1)) catch |err| switch (err) {
                        error.EndOfStream => {
                            try g.endMember();
                            continue;
                        },
                        error.ReadFailed => return g.decodeFailure(),
                    };
                    if (g.scratch.paddingConsumed()) return g.fail(error.CorruptGzip);
                    if (n != 0) return g.fail(error.BodyTooLarge);
                    continue;
                }
                // Decode into `w`'s free space without committing it: a read
                // that ate into the padding is refused whole.
                const dest = limit.min(.limited64(g.remaining)).slice(try w.writableSliceGreedy(1));
                if (dest.len == 0) return 0;
                var fw: std.Io.Writer = .fixed(dest);
                const n = inner.stream(&fw, .limited(dest.len)) catch |err| switch (err) {
                    error.EndOfStream => {
                        try g.endMember();
                        continue;
                    },
                    error.ReadFailed => return g.decodeFailure(),
                    // `fw` holds exactly the limit; a decoder writing past
                    // it would be a std bug — refuse, never crash.
                    error.WriteFailed => return g.fail(error.CorruptGzip),
                };
                if (g.scratch.paddingConsumed()) return g.fail(error.CorruptGzip);
                g.crc = crc32.extend(g.crc, dest[0..n]);
                g.size +%= @as(u32, @truncate(n));
                w.advance(n);
                g.remaining -= n;
                return n;
            },
        };
    }

    /// The current member's deflate stream ended: its trailer must follow.
    fn endMember(g: *Gunzip) error{ReadFailed}!void {
        gzip.checkTrailer(g.src, g.crc, g.size) catch |err| switch (err) {
            error.ReadFailed => return error.ReadFailed,
            error.EndOfStream, error.CrcMismatch, error.SizeMismatch => return g.fail(error.CorruptGzip),
        };
        if (g.scratch.paddingConsumed()) return g.fail(error.CorruptGzip);
        g.state = .member_start;
    }

    /// Whether the framed body has no byte left: none of the source's bytes
    /// still sit unread in the padded reader's buffer, and the source itself
    /// reports its end. Asked through the padded reader, not the source: a
    /// source need not have a buffer to peek into (std asserts one), and the
    /// padded reader never ends — what it pulls in is real bytes, or padding
    /// once the source is done.
    fn rawAtEnd(g: *Gunzip) error{ReadFailed}!bool {
        const p = &g.scratch.padded;
        if (g.realBuffered()) return false;
        if (p.source_done) return true;
        _ = p.reader.peekByte() catch |err| switch (err) {
            error.ReadFailed => return error.ReadFailed,
            error.EndOfStream => unreachable, // padding never ends
        };
        return !g.realBuffered();
    }

    /// Whether some of the source's bytes sit unread in the padded buffer.
    fn realBuffered(g: *const Gunzip) bool {
        const p = &g.scratch.padded;
        return p.delivered - (p.reader.end - p.reader.seek) < p.real;
    }

    /// std's decoder says `ReadFailed` both for its input failing (the
    /// transport — left to `Conn.readFailure`) and for bad data, and parks
    /// which one in `err`.
    fn decodeFailure(g: *Gunzip) error{ReadFailed} {
        if (g.scratch.decompress.err) |e| if (e != error.ReadFailed) return g.fail(error.CorruptGzip);
        return error.ReadFailed;
    }

    fn fail(g: *Gunzip, why: Error) error{ReadFailed} {
        g.failure = why;
        return error.ReadFailed;
    }
};

/// An in-flight streaming request body. Write via `writer`, then call
/// `finish` (or `abort`). Do not copy after calling `writer`.
pub const Upload = struct {
    conn: *Conn,
    method: http.Method,
    chunked: ?h1.ChunkedWriter,
    /// Whether the head asked for gzip (`requestsGzip`).
    ask_gzip: bool,
    /// The request URL, copied, when `Options.cookie_jar` is set: the jar
    /// takes the response's cookies in `finish`, long after the caller's
    /// URL text may be gone.
    jar_url: ?[]u8 = null,

    /// The request-body writer: plaintext bytes in, wire framing out (h2:
    /// DATA frames).
    pub fn writer(u: *Upload) *std.Io.Writer {
        if (u.conn.h2 != null) return u.conn.client.options.http2.?.vt.upload_writer(u.conn);
        if (u.chunked) |*cw| return &cw.writer;
        return u.conn.plainWriter();
    }

    /// Terminate the body (0-chunk when chunked), flush, and read the
    /// response. Consumes the Upload — on error the connection is closed.
    ///
    /// Bounded by `Options.total_timeout_ms`, measured from *this call*, not
    /// from `requestStreaming`: the caller owns the pacing of the body it
    /// streams, so a budget spanning that would be a budget on the caller.
    /// What this bounds is the part the peer owns — the final flush and the
    /// wait for the response head.
    pub fn finish(u: *Upload) Error!Response {
        const c = u.conn.client;
        const deadline = c.totalDeadline() orelse return u.finishInner();
        return runBounded(c.io, c.options.inline_blocking, deadline, finishInner, .{u}) catch |err| switch (err) {
            // Same fallback as `Client.request`; see `connectStream`.
            error.ConcurrencyUnavailable => u.finishInner(),
            else => |e| e,
        };
    }

    fn finishInner(u: *Upload) Error!Response {
        const c = u.conn.client;
        defer if (u.jar_url) |t| c.gpa.free(t);
        errdefer u.conn.destroy();
        const head = if (u.conn.h2 != null) try c.options.http2.?.vt.finish_upload(u.conn) else h: {
            if (u.chunked) |*cw| cw.finish() catch return u.conn.writeFailure();
            try u.conn.flushAll();
            break :h try readResponseHead(u.conn);
        };
        if (u.jar_url) |t| if (c.options.cookie_jar) |jar| jar.store(jar.ctx, http.Url.parse(t) catch unreachable, &head);
        return c.makeResponse(u.conn, u.method, head, u.ask_gzip);
    }

    /// Drop the request without reading a response.
    pub fn abort(u: *Upload) void {
        if (u.jar_url) |t| u.conn.client.gpa.free(t);
        u.conn.destroy();
        u.* = undefined;
    }
};

/// Open a request whose body is streamed by the caller. `content_length`
/// null selects chunked transfer-encoding. Redirects are NOT followed
/// (a streamed body cannot be replayed); `options.body` must be null.
pub fn requestStreaming(c: *Client, method: http.Method, url_text: []const u8, options: RequestOptions, content_length: ?u64) Error!Upload {
    std.debug.assert(options.body == null);
    const url = try http.Url.parse(url_text);
    try validateHeaders(options.headers);
    try validateMethod(method, options.method_token);
    const plan: BodyPlan = if (content_length) |n| .{ .content_length = n } else .chunked;
    const ask_gzip = c.requestsGzip(method, options.headers);

    // No exchange budget here (the caller paces the body); a wait for a
    // `max_conns_per_host` slot still gets `total_timeout_ms`.
    const deadline = c.totalDeadline();
    const h1_only = needsHttp1(options.headers);
    var reused = false;
    var conn = try c.acquireConn(url, &reused, deadline, h1_only);
    // See `requestInner`/`requestInnerPlain`'s `owned` doc comment: a bare
    // `errdefer conn.destroy()` would double-free if the redial below fails
    // (reproduced by the `requestInner` regression test — this site has the
    // identical shape, and its own regression test below reproduces it too).
    var owned = true;
    errdefer if (owned) conn.destroy();

    c.writeUploadHead(conn, method, options.method_token, url, options.headers, plan, ask_gzip) catch |err| {
        // Recover the real cause the same way `sendAndReadHead` does, and
        // BEFORE `isStaleConnError` looks at it: `writeRequestHead` itself
        // can only ever hand back `error.WriteFailed`, so without this a
        // cancelation would masquerade as a dead pooled connection and get
        // retried below with the cancelation already spent.
        const mapped = if (err == error.WriteFailed) conn.writeFailure() else err;
        // Narrower than `request`'s retry: safe here ONLY because nothing
        // of the caller-driven body has been touched yet — just the fixed
        // request head, which we can regenerate byte-for-byte on a fresh
        // connection. Once this function returns the `Upload` and the
        // caller starts writing/streaming the body through it, no further
        // retry is attempted anywhere in `Upload` (`writer`/`finish`): that
        // body may come from a non-seekable source (a pipe, a generator)
        // that cannot be replayed, so a stale connection discovered mid- or
        // post-body surfaces as a normal request failure instead — the
        // same class of failure any other backend outage already produces.
        if (!reused or !isStaleConnError(mapped)) return mapped;
        conn.destroy();
        owned = false;
        conn = try c.checkoutConn(url, &reused, deadline, false, h1_only, dialConn);
        owned = true;
        c.writeUploadHead(conn, method, options.method_token, url, options.headers, plan, ask_gzip) catch |e|
            return if (e == error.WriteFailed) conn.writeFailure() else e;
    };
    return .{
        .conn = conn,
        .method = method,
        .ask_gzip = ask_gzip,
        .chunked = if (content_length == null and conn.h2 == null) h1.ChunkedWriter.init(conn.plainWriter(), conn.body_buf) else null,
        .jar_url = if (c.options.cookie_jar != null) try c.gpa.dupe(u8, url_text) else null,
    };
}

/// `requestStreaming`'s request head: h1 bytes on the wire, or the HEADERS
/// of a new h2 stream (`Options.http2`) whose DATA the `Upload` sends.
fn writeUploadHead(c: *Client, conn: *Conn, method: http.Method, method_token: []const u8, url: http.Url, headers: []const http.Header, plan: BodyPlan, ask_gzip: bool) Error!void {
    if (conn.h2 != null) return c.options.http2.?.vt.open_upload(conn, method, method_token, url, headers, plan, ask_gzip);
    writeRequestHeadVia(conn.plainWriter(), conn.forward_proxy, c.options.cookie_jar, method, method_token, url, headers, c.options.user_agent, plan, false, !c.options.pool.enabled, ask_gzip) catch
        return error.WriteFailed;
}

/// `requestStreaming`'s plaintext-only twin — see `requestPlain`'s doc
/// comment for why this is a separate decl rather than a shared
/// implementation. `http://` only: `error.UnsupportedScheme` on `https://`,
/// checked before any dial. No redirect support either way (unchanged from
/// `requestStreaming`): a streamed body cannot be replayed.
pub fn requestStreamingPlain(c: *Client, method: http.Method, url_text: []const u8, options: RequestOptions, content_length: ?u64) Error!Upload {
    std.debug.assert(options.body == null);
    const url = try http.Url.parse(url_text);
    if (url.scheme != .http) return error.UnsupportedScheme;
    try validateHeaders(options.headers);
    try validateMethod(method, options.method_token);
    const plan: BodyPlan = if (content_length) |n| .{ .content_length = n } else .chunked;
    const ask_gzip = c.requestsGzip(method, options.headers);

    const deadline = c.totalDeadline();
    var reused = false;
    var conn = try c.acquireConnPlain(url, &reused, deadline);
    // See `requestInnerPlain`'s `owned` doc comment: a bare
    // `errdefer conn.destroy()` would double-free if the redial below fails.
    var owned = true;
    errdefer if (owned) conn.destroy();

    writeRequestHeadVia(conn.plainWriter(), conn.forward_proxy, c.options.cookie_jar, method, options.method_token, url, options.headers, c.options.user_agent, plan, false, !c.options.pool.enabled, ask_gzip) catch {
        // See `requestStreaming`'s identical catch for why this must consult
        // `conn.writeFailure()` before `isStaleConnError` rather than trust
        // `writeRequestHead`'s own always-`WriteFailed` result.
        const mapped = conn.writeFailure();
        if (!reused or !isStaleConnError(mapped)) return mapped;
        conn.destroy();
        owned = false;
        conn = try c.checkoutConn(url, &reused, deadline, false, false, dialPlain);
        owned = true;
        writeRequestHeadVia(conn.plainWriter(), conn.forward_proxy, c.options.cookie_jar, method, options.method_token, url, options.headers, c.options.user_agent, plan, false, !c.options.pool.enabled, ask_gzip) catch return conn.writeFailure();
    };
    return .{
        .conn = conn,
        .method = method,
        .ask_gzip = ask_gzip,
        .chunked = if (content_length == null) h1.ChunkedWriter.init(conn.plainWriter(), conn.body_buf) else null,
        .jar_url = if (c.options.cookie_jar != null) try c.gpa.dupe(u8, url_text) else null,
    };
}

// ── convenience helpers ─────────────────────────────────────────────────────

/// GET `url` and return the body (caller owns), requiring a 2xx status
/// (`error.UnexpectedStatus` otherwise).
pub fn getAlloc(c: *Client, gpa: std.mem.Allocator, url: []const u8, max_len: usize) Error![]u8 {
    var res = try c.request(.get, url, .{});
    defer res.deinit();
    if (res.status < 200 or res.status >= 300) return error.UnexpectedStatus;
    return res.readAllAlloc(gpa, max_len);
}

/// GET `url` streaming the body straight to `dir/sub_path` (no full-body
/// buffering). Returns bytes written; requires a 2xx status. File-system
/// failures map to `error.WriteFailed`; a cancelation that lands in one of
/// them stays `error.Canceled`.
pub fn getToFile(c: *Client, url: []const u8, dir: std.Io.Dir, sub_path: []const u8) Error!u64 {
    var res = try c.request(.get, url, .{});
    defer res.deinit();
    if (res.status < 200 or res.status >= 300) return error.UnexpectedStatus;

    var file = dir.createFile(c.io, sub_path, .{ .truncate = true }) catch |err|
        return fsFailure(err, error.WriteFailed);
    defer file.close(c.io);
    var fbuf: [64 * 1024]u8 = undefined;
    var fw = file.writer(c.io, &fbuf);
    // `Reader.StreamRemainingError` is exactly `{ReadFailed, WriteFailed}`.
    // `ReadFailed` is the network body read, and `Conn.readFailure` is what
    // recovers a cancelation from it instead of reporting a dead peer — see
    // `readAllAlloc` right above, the same collapse this one had.
    // `WriteFailed` is the local file write (`fw`), and `fileWriteFailure`
    // recovers a cancelation parked on `fw.err` the same way. Until
    // 2026-09-15 this arm, the `flush` below and `createFile` above all
    // reported a cancelation as a file-system failure (A1 G13).
    const n = res.reader().streamRemaining(&fw.interface) catch |err| switch (err) {
        error.WriteFailed => return fileWriteFailure(&fw),
        error.ReadFailed => return res.readFailure(),
    };
    fw.interface.flush() catch return fileWriteFailure(&fw);
    return n;
}

/// PUT the contents of `dir/sub_path` to `url`, streamed with a
/// Content-Length (never buffered whole). Returns the response status; the
/// response body is discarded. File-system failures map to
/// `error.ReadFailed`; a cancelation that lands in one of them stays
/// `error.Canceled`.
pub fn putFile(c: *Client, url: []const u8, dir: std.Io.Dir, sub_path: []const u8, options: RequestOptions) Error!u16 {
    var file = dir.openFile(c.io, sub_path, .{}) catch |err| return fsFailure(err, error.ReadFailed);
    defer file.close(c.io);
    const size = (file.stat(c.io) catch |err| return fsFailure(err, error.ReadFailed)).size;

    var up = try c.requestStreaming(.put, url, options, size);
    var fbuf: [64 * 1024]u8 = undefined;
    var fr = file.reader(c.io, &fbuf);
    fr.interface.streamExact64(up.writer(), size) catch |err| {
        // `Reader.StreamError` is exactly `{ReadFailed, WriteFailed,
        // EndOfStream}`. `WriteFailed` is the network body write
        // (`up.writer()`, draining into `up.conn`), and `Conn.writeFailure`
        // is what recovers a cancelation from it instead of reporting a dead
        // peer — the same collapse `readAllAlloc`/`getToFile` had on the read
        // side. Must run BEFORE `abort()`: that destroys `up.conn`, and
        // `writeFailure` needs it alive to read `conn.sw.err`.
        //
        // `ReadFailed` is the local file read (`fr`), and it can be a
        // cancelation too: the upload alternates file reads with socket
        // writes, so a cancel lands in either. `fr.err` carries it exactly as
        // `conn.sw.err` does. Until 2026-09-15 this arm mapped it to plain
        // `ReadFailed` — a canceled upload reported as a file-system failure;
        // measured 5/25 under CPU load once the cancel test stopped relying
        // on a sleep, every one with `fr.err = Canceled` and `sw.err = null`.
        // `EndOfStream` (the file shrank under us) stays a read failure.
        const mapped: Error = switch (err) {
            error.WriteFailed => up.conn.writeFailure(),
            error.ReadFailed => fileReadFailure(&fr),
            error.EndOfStream => error.ReadFailed,
        };
        up.abort();
        return mapped;
    };
    var res = try up.finish();
    defer res.deinit();
    return res.status;
}

/// The local-file counterpart of `Conn.readFailure`: `std.Io.Reader` reports
/// every failure of an upload's source file as bare `error.ReadFailed`, and
/// the real error — including `error.Canceled` — is parked on the
/// `File.Reader`. Shared by `putFile` and `putFilePlain` so the two copies
/// cannot drift apart.
fn fileReadFailure(fr: *const std.Io.File.Reader) Error {
    if (fr.err) |e| if (e == error.Canceled) return error.Canceled;
    return error.ReadFailed;
}

/// `fileReadFailure`'s write-side twin, for `getToFile`'s download target:
/// `std.Io.Writer` reports every failure of the file write as bare
/// `error.WriteFailed`, and the real error is parked on the `File.Writer`.
fn fileWriteFailure(fw: *const std.Io.File.Writer) Error {
    if (fw.err) |e| if (e == error.Canceled) return error.Canceled;
    return error.WriteFailed;
}

/// For a local file-system call that returns its error directly (open,
/// create, stat): every one of those error sets carries `Io.Cancelable`, and
/// a cancelation is not a file-system failure, so it stays `error.Canceled`;
/// anything else becomes `fallback`.
fn fsFailure(err: anyerror, fallback: Error) Error {
    return if (err == error.Canceled) error.Canceled else fallback;
}

/// `putFile`'s plaintext-only twin (see `requestPlain`'s doc comment for why
/// this is a separate decl): PUT `dir/sub_path` to `url` streamed with a
/// Content-Length, `http://` only. `Upload.finish`/`Upload.abort` are shared
/// with `putFile` — they operate on the already-dialed `*Conn` and name
/// nothing from `tls`.
pub fn putFilePlain(c: *Client, url: []const u8, dir: std.Io.Dir, sub_path: []const u8, options: RequestOptions) Error!u16 {
    var file = dir.openFile(c.io, sub_path, .{}) catch |err| return fsFailure(err, error.ReadFailed);
    defer file.close(c.io);
    const size = (file.stat(c.io) catch |err| return fsFailure(err, error.ReadFailed)).size;

    var up = try c.requestStreamingPlain(.put, url, options, size);
    var fbuf: [64 * 1024]u8 = undefined;
    var fr = file.reader(c.io, &fbuf);
    // See `putFile`'s identical catch for why `WriteFailed` alone routes
    // through `Conn.writeFailure`, why that must run before `abort()`, and
    // why `ReadFailed` routes through `fileReadFailure`.
    fr.interface.streamExact64(up.writer(), size) catch |err| {
        const mapped: Error = switch (err) {
            error.WriteFailed => up.conn.writeFailure(),
            error.ReadFailed => fileReadFailure(&fr),
            error.EndOfStream => error.ReadFailed,
        };
        up.abort();
        return mapped;
    };
    var res = try up.finish();
    defer res.deinit();
    return res.status;
}

// ── HTTP/2 cleartext (h2c, prior knowledge) ─────────────────────────────────

/// One HTTP/2 connection, multiplexing any number of requests: call
/// `request` N times, then `awaitResponse` each returned stream id in any
/// order. Created by `connectH2c` (cleartext h2c over an owned TCP socket,
/// RFC 9113 §3.3 prior knowledge — the peer must speak h2c, e.g. `Server`
/// with `enable_h2c`) or `connectH2Over` (caller-provided stream, e.g.
/// after a TLS handshake negotiated ALPN "h2"); released with `close`.
/// Single-owner like the h1 client: one task drives a session.
pub const H2Session = struct {
    gpa: std.mem.Allocator,
    /// The socket transport when this client opened it (`connectH2c`);
    /// null when the session runs over a caller-provided stream
    /// (`connectH2Over`) — then the caller owns the transport and closes
    /// it after `close`.
    owned: ?Owned,
    session: h2_client.Session,
    authority: []u8,

    const Owned = struct {
        client: *Client,
        stream: net.Stream,
        sr: net.Stream.Reader,
        sw: net.Stream.Writer,
        slab: []u8,
        /// When set, `slab` was checked out of this pool and is returned to
        /// it on `close` instead of freed (`Options.buffer_pool`).
        buffer_pool: ?*BufferPool,
    };

    /// Start a request on its own stream (many may be in flight at once).
    /// `:authority` defaults to the connected host[:port].
    pub fn request(
        hs: *H2Session,
        method: http.Method,
        path: []const u8,
        options: h2_client.RequestOptions,
    ) h2_client.Error!u31 {
        var opts = options;
        if (opts.authority == null) opts.authority = hs.authority;
        return hs.session.request(method, path, opts);
    }

    /// Block until the response for `stream_id` is complete (pumping the
    /// connection, which advances every in-flight stream) and hand it over.
    pub fn awaitResponse(hs: *H2Session, stream_id: u31) h2_client.Error!h2_client.Response {
        return hs.session.awaitResponse(stream_id);
    }

    /// Start a request whose body is fed **incrementally**: only the HEADERS
    /// go out here, then `hs.session.sendData`/`closeSend` push the body over
    /// time while `hs.session.awaitHead`/`readBody` consume the response as
    /// it arrives — both directions live on the one stream. `:authority`
    /// defaults to the connected host[:port], as for `request`.
    ///
    /// Only the opening needs a wrapper (for that default); the rest of the
    /// incremental surface is called on `hs.session` directly — see
    /// `h2_client`'s module doc for the whole shape.
    pub fn openStream(
        hs: *H2Session,
        method: http.Method,
        path: []const u8,
        options: h2_client.StreamOptions,
    ) h2_client.Error!u31 {
        var opts = options;
        if (opts.authority == null) opts.authority = hs.authority;
        return hs.session.openStream(method, path, opts);
    }

    /// Graceful GOAWAY (best effort), close the socket when this client
    /// owns it (`connectH2c`), free everything. Over a caller-provided
    /// stream (`connectH2Over`) the transport is left open — close it
    /// yourself afterwards (e.g. the TLS close_notify + socket close).
    pub fn close(hs: *H2Session) void {
        hs.session.shutdown();
        hs.session.deinit();
        const gpa = hs.gpa;
        if (hs.owned) |*o| {
            o.stream.close(o.client.io);
            if (o.buffer_pool) |bp| bp.release(o.slab) else gpa.free(o.slab);
        }
        gpa.free(hs.authority);
        gpa.destroy(hs);
    }
};

/// Open an HTTP/2 cleartext connection to `host:port` via prior knowledge
/// (RFC 9113 §3.3): the client preface + SETTINGS are sent immediately.
/// Reuses the client's connect plumbing, so the dial is bounded by
/// `connect_timeout_ms` (buffer sizing is shared too). The multiplexed
/// session that follows is NOT bounded by `total_timeout_ms` — see the
/// module doc's timeout model for why an h2 session has no single exchange
/// to put a budget on.
///
/// `Options.user_agent` carries over: it becomes the session's default
/// `user-agent` unless `options.user_agent` is set here (and either is still
/// overridden per request by a `user-agent` in that request's `headers`).
pub fn connectH2c(c: *Client, host: []const u8, port: u16, options: h2_client.Options) Error!*H2Session {
    const url: http.Url = .{ .scheme = .http, .host = host, .port = port, .path = "/", .query = "" };

    // Default `:authority` — the wire form of the authority, brackets and
    // non-default port included (same shape as the h1 Host header).
    var auth_buf: [280]u8 = undefined;
    var auth_w: std.Io.Writer = .fixed(&auth_buf);
    url.writeHostHeaderValue(&auth_w) catch return error.BadUrl;

    const slab_len = c.options.read_buffer_size + c.options.write_buffer_size;
    // Slab from the shared pool when one is configured (its size class must
    // match this layout), else a fresh allocation freed on close. Checked
    // BEFORE any allocation: `Options.buffer_pool` and
    // `read_buffer_size`/`write_buffer_size` are two independently
    // caller-supplied config points with no type-level link between them, so
    // a mismatch is an ordinary caller-config mistake, not something the
    // type system can rule out. This used to be `std.debug.assert`, which
    // compiles to nothing in ReleaseFast/ReleaseSmall; the very next lines
    // slice the acquired slab by fixed offset (`slab[0..read_buffer_size]`,
    // `slab[read_buffer_size..]`) with no length check of their own, so a
    // mismatched pool meant an unchecked out-of-bounds slice — or a silently
    // undersized write buffer — in exactly the modes people deploy.
    if (c.options.buffer_pool) |bp| {
        if (bp.slab_size != slab_len) return error.BufferPoolSizeMismatch;
    }
    // A client-wide `Options.user_agent` reaches h2 the same way it reaches
    // h1: as the session's connection-wide default, overridable per request.
    // An explicit `h2_client.Options.user_agent` on this call still wins — a
    // caller who says something here meant it.
    var h2_options = options;
    if (h2_options.user_agent == null) h2_options.user_agent = c.options.user_agent;

    const hs = try c.gpa.create(H2Session);
    errdefer c.gpa.destroy(hs);
    const slab = if (c.options.buffer_pool) |bp| try bp.acquire() else try c.gpa.alloc(u8, slab_len);
    errdefer if (c.options.buffer_pool) |bp| bp.release(slab) else c.gpa.free(slab);
    const authority = try c.gpa.dupe(u8, auth_w.buffered());
    errdefer c.gpa.free(authority);

    const stream = try c.connectStream(url);
    errdefer stream.close(c.io);

    hs.* = .{
        .gpa = c.gpa,
        .owned = .{
            .client = c,
            .stream = stream,
            .sr = undefined,
            .sw = undefined,
            .slab = slab,
            .buffer_pool = c.options.buffer_pool,
        },
        .session = undefined,
        .authority = authority,
    };
    // Reader/writer (and the session pointing at them) must be initialized
    // at the connection's final heap address.
    const o = &hs.owned.?;
    o.sr = stream.reader(c.io, slab[0..c.options.read_buffer_size]);
    o.sw = stream.writer(c.io, slab[c.options.read_buffer_size..]);
    hs.session = h2_client.Session.init(c.gpa, &o.sr.interface, &o.sw.interface, h2_options) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.WriteFailed,
        };
    return hs;
}

/// BYO-TLS entry point: run the multiplexing HTTP/2 client over an
/// **already-established** byte stream the caller owns — typically a TLS
/// connection whose handshake (offering `http.alpn_offer`) negotiated the
/// ALPN protocol "h2" (`http.protocolFromAlpn`; RFC 7301, RFC 9113 §3.3 —
/// over TLS h2 is selected only via ALPN, never an upgrade). The client
/// connection preface + SETTINGS are sent immediately (RFC 9113 §3.4),
/// exactly as on h2c — the wire is identical from here on.
///
/// `in`/`out` must outlive the session and stay untouched by the caller
/// while it lives; `close` releases the session but leaves the transport
/// open (closing it — TLS close_notify, socket — stays the caller's job).
/// `authority` is copied and becomes the default `:authority` pseudo-header
/// (host[:port] — what was presented as the TLS server name). Over TLS,
/// pass `.scheme = "https"` in each request's `RequestOptions`
/// (RFC 9113 §8.3.1).
///
/// Intended flow (no TLS library required or referenced here):
///
///     // caller's TLS layer: connect, handshake offering http.alpn_offer
///     // negotiated = the ALPN protocol the handshake selected
///     if (http.protocolFromAlpn(negotiated) == .h2) {
///         const hs = try Client.connectH2Over(gpa, tls_reader, tls_writer,
///             "example.com", .{});
///         defer hs.close();
///         const sid = try hs.request(.get, "/", .{ .scheme = "https" });
///         ...
///     } // else: the HTTP/1.1 client path over the same stream
pub fn connectH2Over(
    gpa: std.mem.Allocator,
    in: *std.Io.Reader,
    out: *std.Io.Writer,
    authority: []const u8,
    options: h2_client.Options,
) Error!*H2Session {
    const hs = try gpa.create(H2Session);
    errdefer gpa.destroy(hs);
    const auth = try gpa.dupe(u8, authority);
    errdefer gpa.free(auth);
    hs.* = .{
        .gpa = gpa,
        .owned = null,
        .session = undefined,
        .authority = auth,
    };
    hs.session = h2_client.Session.init(gpa, in, out, options) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.WriteFailed,
    };
    return hs;
}

// ── connection internals ────────────────────────────────────────────────────

/// Extra interface buffer for the body-framing readers / chunked writer.
const body_scratch_len = 4096;

const Conn = struct {
    client: *Client,
    stream: net.Stream,
    sr: net.Stream.Reader,
    sw: net.Stream.Writer,
    tls_client: ?tls.Client,
    slab: []u8,
    head_buf: []u8,
    /// Bytes of `head_buf` the current response head occupies (set by
    /// `readResponseHead`); the rest captures a chunked body's trailer
    /// section (`setupBody`), so trailers cost no memory of their own.
    head_len: usize = 0,
    body_buf: []u8,
    body: BodyState,
    /// The origin this connection is dialed to — set once at dial time,
    /// read back when a completed response decides whether to return the
    /// connection to the pool (`Pool.release`'s key).
    origin: Origin,
    /// Whether the last response read on this connection left it eligible
    /// for reuse (no `Connection: close`, not an HTTP/1.0 response without
    /// explicit `keep-alive`, not a `101` upgrade) — set by `setupBody`.
    /// Still requires `isBodyDrained` before actually pooling: an eligible
    /// framing with an only-partially-read body cannot be reused either.
    keep_alive_eligible: bool = false,
    /// Set when this plaintext connection goes to a forwarding proxy rather
    /// than the origin: requests on it carry an absolute-form target and
    /// the proxy's credentials. (A `CONNECT` tunnel leaves it null: inside
    /// the tunnel the origin is spoken to directly.)
    forward_proxy: ?client_proxy.Endpoint = null,
    /// Counted against `PoolOptions.max_conns_per_host`: `destroy` gives
    /// the origin's slot back. Set by `checkoutConn` after a dial it
    /// reserved a slot for; a connection dialed any other way (tests) is
    /// not counted.
    holds_slot: bool = false,
    /// Set when ALPN chose h2 (`Options.http2`): requests on this
    /// connection run as streams of this session, one at a time.
    h2: ?*H2Conn = null,

    const BodyState = union(enum) {
        unset,
        none: std.Io.Reader,
        chunked: h1.ChunkedReader,
        limited: h1.ContentLengthReader,
        until_close,
        /// The h2 stream's DATA (`H2Conn.body`).
        h2: *std.Io.Reader,
    };

    /// Decrypted (or plain) byte stream from the server.
    fn plainReader(conn: *Conn) *std.Io.Reader {
        if (conn.tls_client) |*t| return &t.reader;
        return &conn.sr.interface;
    }

    /// Plaintext writer towards the server (encrypting when TLS).
    fn plainWriter(conn: *Conn) *std.Io.Writer {
        if (conn.tls_client) |*t| return &t.writer;
        return &conn.sw.interface;
    }

    fn flushAll(conn: *Conn) Error!void {
        conn.plainWriter().flush() catch return conn.writeFailure();
        // The TLS writer drains ciphertext into the socket writer — flush
        // that too.
        if (conn.tls_client != null)
            conn.sw.interface.flush() catch return conn.writeFailure();
    }

    /// `std.Io.Reader`/`Writer` collapse every transport failure into the
    /// single `error.ReadFailed`/`error.WriteFailed`; the real errno-level
    /// error is parked on the socket reader/writer. Only one distinction
    /// matters to this client, and it matters a lot: `error.Canceled` — the
    /// task was interrupted (a `runBounded` deadline, or the caller canceling
    /// the whole request) — must NOT be laundered into a transport failure,
    /// because `isStaleConnError` would then treat it as a dead pooled
    /// connection and transparently retry the exchange, blocking a second
    /// time with the cancelation already consumed. Both TLS and plaintext
    /// funnel through the same socket reader/writer, so one check covers
    /// both.
    fn readFailure(conn: *Conn) Error {
        if (conn.sr.err) |err| if (err == error.Canceled) return error.Canceled;
        return error.ReadFailed;
    }

    fn writeFailure(conn: *Conn) Error {
        if (conn.sw.err) |err| if (err == error.Canceled) return error.Canceled;
        return error.WriteFailed;
    }

    fn destroy(conn: *Conn) void {
        const gpa = conn.client.gpa;
        if (conn.h2 != null) conn.client.options.http2.?.vt.destroy(conn);
        conn.stream.close(conn.client.io);
        // After the close: a waiter woken here dials at once, and the cap
        // is on sockets the peer sees, not on our bookkeeping.
        if (conn.holds_slot) conn.client.pool.freeSlot(&conn.origin);
        gpa.free(conn.slab);
        gpa.destroy(conn);
    }
};

/// An h2 connection's session and the one exchange running on it
/// (`Options.http2`), on the heap beside its `Conn`, whose plaintext reader
/// and writer it speaks through.
const H2Conn = struct {
    conn: *Conn,
    session: h2_client.Session,
    /// The session's writer: bytes go to the TLS writer, and `flush` pushes
    /// them on to the socket (`Conn.flushAll`) — the TLS writer's own flush
    /// only seals records into the socket writer's buffer.
    out: std.Io.Writer,
    /// The stream of the exchange in progress, until `release`.
    sid: ?u31 = null,
    /// The response body was read to END_STREAM.
    done: bool = false,
    /// Why the stream's last read or write failed (`Response.readFailure`).
    failure: ?Error = null,
    /// The response body (`Conn.BodyState.h2`), buffered in `Conn.body_buf`.
    body: std.Io.Reader,
    /// An `Upload`'s request body as DATA frames, buffered in
    /// `Conn.body_buf` (free until the response body uses it).
    upload: std.Io.Writer,

    /// A new exchange: forget the last one's outcome.
    fn begin(h: *H2Conn) void {
        h.done = false;
        h.failure = null;
        h.upload.end = 0;
    }
};

/// The h2 half of `Client`, reached only through `Http2.alpn`'s function
/// pointers. The request head is rendered by the h1 head writer and split
/// back into fields, so every rule about which fields go out — cookies,
/// credentials dropped on a cross-origin hop, `User-Agent`,
/// `Accept-Encoding`, `Content-Length`, a caller's `Host` — is one rule on
/// both protocols; the session drops the connection-specific ones (RFC 9113
/// §8.2.2) and a caller's `Host` becomes `:authority`, as in Go. The response
/// head comes back as an `h1.ResponseHead` over the same fields, so cookies,
/// redirects and `decompress` read it unchanged.
const h2glue = struct {
    const vtable: Http2.VTable = .{
        .start = start,
        .exchange = exchange,
        .open_upload = openUpload,
        .upload_writer = uploadWriter,
        .finish_upload = finishUpload,
        .setup_body = setupBodyH2,
        .drained = drained,
        .read_failure = readFailure,
        .trailer = trailer,
        .release = release,
        .destroy = destroy,
    };

    /// ALPN chose h2 on a fresh `conn`: send the connection preface.
    fn start(conn: *Conn) Error!void {
        const gpa = conn.client.gpa;
        const h = try gpa.create(H2Conn);
        errdefer gpa.destroy(h);
        h.* = .{
            .conn = conn,
            .session = undefined,
            .out = .{ .vtable = &.{ .drain = outDrain, .flush = outFlush }, .buffer = &.{} },
            .body = .{ .vtable = &.{ .stream = bodyStream }, .buffer = conn.body_buf, .seek = 0, .end = 0 },
            .upload = .{ .vtable = &.{ .drain = uploadDrain, .flush = uploadFlush }, .buffer = conn.body_buf },
        };
        // No session `user_agent`: the rendered head carries it.
        h.session = h2_client.Session.init(gpa, conn.plainReader(), &h.out, .{}) catch |err|
            return mapError(conn, err);
        conn.h2 = h;
    }

    fn destroy(conn: *Conn) void {
        const h = conn.h2.?;
        h.session.deinit();
        conn.client.gpa.destroy(h);
        conn.h2 = null;
    }

    fn exchange(conn: *Conn, method: http.Method, method_token: []const u8, url: http.Url, headers: []const http.Header, plan: BodyPlan, body: ?[]const u8, strip_sensitive: bool, ask_gzip: bool) Error!h1.ResponseHead {
        const h = conn.h2.?;
        var head: Rendered = try .init(conn, method, method_token, url, headers, plan, strip_sensitive, ask_gzip);
        defer head.deinit();
        h.begin();
        // An empty or absent body: END_STREAM on the HEADERS frame.
        h.sid = h.session.request(method, head.target, .{
            .method_token = if (method == .other) method_token else "",
            .scheme = @tagName(url.scheme),
            .authority = head.authority,
            .headers = head.fields,
            .body = body,
        }) catch |err| return fail(h, err);
        return awaitHead(h);
    }

    fn openUpload(conn: *Conn, method: http.Method, method_token: []const u8, url: http.Url, headers: []const http.Header, plan: BodyPlan, ask_gzip: bool) Error!void {
        const h = conn.h2.?;
        var head: Rendered = try .init(conn, method, method_token, url, headers, plan, false, ask_gzip);
        defer head.deinit();
        h.begin();
        h.sid = h.session.openStream(method, head.target, .{
            .method_token = if (method == .other) method_token else "",
            .scheme = @tagName(url.scheme),
            .authority = head.authority,
            .headers = head.fields,
        }) catch |err| return fail(h, err);
    }

    fn uploadWriter(conn: *Conn) *std.Io.Writer {
        return &conn.h2.?.upload;
    }

    fn finishUpload(conn: *Conn) Error!h1.ResponseHead {
        const h = conn.h2.?;
        if (h.failure) |f| return f;
        h.upload.flush() catch return h.failure orelse error.WriteFailed;
        h.session.closeSend(h.sid.?) catch |err| return fail(h, err);
        return awaitHead(h);
    }

    /// Frame the response body: none after a HEAD or when the HEADERS frame
    /// ended the stream, else the stream's DATA.
    fn setupBodyH2(conn: *Conn, method: http.Method) void {
        const h = conn.h2.?;
        const sid = h.sid.?;
        h.body.seek = 0;
        h.body.end = 0;
        if (method == .head or (h.session.ended(sid) and h.session.unreadLen(sid) == 0)) {
            conn.body = .{ .none = .fixed("") };
            h.done = true;
        } else {
            conn.body = .{ .h2 = &h.body };
        }
    }

    fn drained(conn: *const Conn) bool {
        const h = conn.h2.?;
        return h.done and h.failure == null;
    }

    fn readFailure(conn: *const Conn) ?Error {
        return conn.h2.?.failure;
    }

    fn trailer(conn: *const Conn, name: []const u8) ?[]const u8 {
        const h = conn.h2.?;
        // Like Go: the values are there after the body's EOF, not before,
        // even when the trailer section arrived with the first frames.
        if (!h.done) return null;
        const hl = h.session.trailers(h.sid orelse return null) orelse return null;
        for (hl.fields) |f| {
            if (std.ascii.eqlIgnoreCase(f.name, name)) return f.value;
        }
        return null;
    }

    /// End the exchange: a stream finished both ways is released, any other
    /// is reset (RST_STREAM CANCEL, as Go does for a body closed early).
    /// Whether the connection can take another request.
    fn release(conn: *Conn) bool {
        const h = conn.h2.?;
        if (h.sid) |sid| {
            const finished = h.session.ended(sid) and h.session.unreadLen(sid) == 0 and h.session.sendEnded(sid);
            if (finished) h.session.release(sid) else h.session.cancel(sid, .cancel);
            h.sid = null;
        }
        return h.session.broken == null and h.session.goaway == null;
    }

    fn awaitHead(h: *H2Conn) Error!h1.ResponseHead {
        const head = h.session.awaitHead(h.sid.?) catch |err| return fail(h, err);
        return headFromFields(head.status, head.headers.fields, h.conn.head_buf) catch |err| {
            h.failure = err;
            return err;
        };
    }

    /// An h2 response head as the `h1.ResponseHead` the rest of the client
    /// reads, its block written into `buf`. Pseudo-header fields are left
    /// out (`status` is `:status`).
    fn headFromFields(status: u16, fields: []const hpack.Field, buf: []u8) error{ MalformedResponse, HeadTooLarge }!h1.ResponseHead {
        var w: std.Io.Writer = .fixed(buf);
        var content_length: ?u64 = null;
        var lengths: usize = 0;
        for (fields) |f| {
            if (f.name.len != 0 and f.name[0] == ':') continue;
            // RFC 9113 §8.2.1: a name with an uppercase letter, or a value
            // h1 could not carry, makes the response malformed — and would
            // break the h1 block it is copied into. Go refuses both.
            if (!isLowerToken(f.name) or !h1.isValidFieldValue(f.value)) return error.MalformedResponse;
            w.print("{s}: {s}\r\n", .{ f.name, f.value }) catch return error.HeadTooLarge;
            if (std.mem.eql(u8, f.name, "content-length")) {
                lengths += 1;
                content_length = std.fmt.parseUnsigned(u64, f.value, 10) catch null;
            }
        }
        return .{
            .status = status,
            // h2 has no reason phrase; Go's `Status` uses `StatusText`.
            .reason = Server.reasonPhrase(status),
            .http1_0 = false,
            .header_block = w.buffered(),
            // Informational only: END_STREAM frames an h2 body.
            .content_length = if (lengths == 1) content_length else null,
        };
    }

    fn isLowerToken(name: []const u8) bool {
        if (!h1.isToken(name)) return false;
        for (name) |b| if (std.ascii.isUpper(b)) return false;
        return true;
    }

    fn fail(h: *H2Conn, err: h2_client.Error) Error {
        const e = mapError(h.conn, err);
        h.failure = e;
        return e;
    }

    fn mapError(conn: *Conn, err: h2_client.Error) Error {
        return switch (err) {
            error.StreamReset => error.StreamReset,
            // Not processed by the server (RFC 9113 §6.8): safe to send
            // again on a fresh connection, like a stale pooled h1 one.
            error.StreamRefused, error.GoawayReceived => error.ConnectionClosed,
            // The session folds a failed read into this; a cancelation must
            // stay one (see `Conn.readFailure`).
            error.ConnectionClosed => if (conn.readFailure() == error.Canceled) error.Canceled else error.ConnectionClosed,
            error.WriteFailed => conn.writeFailure(),
            error.ProtocolError, error.MalformedResponse, error.UnknownStream, error.SendClosed => error.MalformedResponse,
            error.InvalidHeader => error.InvalidHeader,
            error.OutOfMemory => error.OutOfMemory,
        };
    }

    fn outDrain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const h: *H2Conn = @alignCast(@fieldParentPtr("out", w));
        return h.conn.plainWriter().writeSplat(data, splat);
    }

    fn outFlush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const h: *H2Conn = @alignCast(@fieldParentPtr("out", w));
        h.conn.flushAll() catch return error.WriteFailed;
    }

    fn bodyStream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const h: *H2Conn = @alignCast(@fieldParentPtr("body", r));
        if (h.failure != null) return error.ReadFailed;
        if (h.done) return error.EndOfStream;
        const dest = limit.slice(try w.writableSliceGreedy(1));
        if (dest.len == 0) return 0;
        const n = h.session.readBody(h.sid.?, dest) catch |err| {
            h.failure = mapError(h.conn, err);
            return error.ReadFailed;
        };
        if (n == 0) {
            h.done = true;
            return error.EndOfStream;
        }
        w.advance(n);
        return n;
    }

    fn uploadDrain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const h: *H2Conn = @alignCast(@fieldParentPtr("upload", w));
        var total = w.end;
        try send(h, w.buffered());
        for (data[0 .. data.len - 1]) |d| {
            try send(h, d);
            total += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            try send(h, last);
            total += last.len;
        }
        return w.consume(total);
    }

    fn uploadFlush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const h: *H2Conn = @alignCast(@fieldParentPtr("upload", w));
        try send(h, w.buffered());
        w.end = 0;
    }

    fn send(h: *H2Conn, bytes: []const u8) std.Io.Writer.Error!void {
        if (bytes.len == 0) return;
        h.session.sendData(h.sid.?, bytes, false) catch |err| {
            h.failure = mapError(h.conn, err);
            return error.WriteFailed;
        };
    }

    /// The request head as h2 fields (see the struct doc).
    const Rendered = struct {
        arena: std.heap.ArenaAllocator,
        target: []const u8,
        authority: []const u8,
        fields: []const http.Header,

        fn init(conn: *Conn, method: http.Method, method_token: []const u8, url: http.Url, headers: []const http.Header, plan: BodyPlan, strip_sensitive: bool, ask_gzip: bool) Error!Rendered {
            const c = conn.client;
            var r: Rendered = .{ .arena = .init(c.gpa), .target = "", .authority = "", .fields = &.{} };
            errdefer r.arena.deinit();
            const arena = r.arena.allocator();
            var aw: std.Io.Writer.Allocating = .init(arena);
            // No proxy (an https origin is reached through a tunnel, if at
            // all) and no `Connection: close` (h2 has no such field).
            writeRequestHeadVia(&aw.writer, null, c.options.cookie_jar, method, method_token, url, headers, c.options.user_agent, plan, strip_sensitive, false, ask_gzip) catch
                return error.OutOfMemory;
            var lines = std.mem.splitSequence(u8, aw.written(), "\r\n");
            // "METHOD target HTTP/1.1"
            const request_line = lines.next().?;
            const sp = std.mem.indexOfScalar(u8, request_line, ' ').?;
            r.target = request_line[sp + 1 .. request_line.len - " HTTP/1.1".len];
            var fields: std.ArrayList(http.Header) = .empty;
            while (lines.next()) |line| {
                if (line.len == 0) continue;
                const colon = std.mem.indexOfScalar(u8, line, ':').?;
                const name = line[0..colon];
                const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
                if (std.ascii.eqlIgnoreCase(name, "host")) {
                    r.authority = value;
                    continue;
                }
                try fields.append(arena, .{ .name = name, .value = value });
            }
            r.fields = fields.items;
            return r;
        }

        fn deinit(r: *Rendered) void {
            r.arena.deinit();
        }
    };
};

/// A connection's origin (`scheme`, `host`, `port`) — the pool's key.
/// `host` is copied into a fixed inline buffer at dial time: the URL text
/// it was parsed from is caller-owned and, for a redirect hop, sometimes
/// freed before the connection this key describes is ever released back to
/// the pool (see `request`'s `url_owned`), so the key cannot merely borrow
/// it.
const Origin = struct {
    scheme: http.Url.Scheme,
    port: u16,
    host_buf: [max_origin_host]u8 = undefined,
    host_len: u8 = 0,

    /// DNS names top out at 253 octets; IP literals (with brackets) are
    /// shorter still. A host longer than this (never in practice) is
    /// truncated — worst case two such hosts sharing a 255-byte prefix
    /// collide in the pool key, which only costs a redial, never a
    /// correctness problem.
    const max_origin_host = 255;

    fn set(o: *Origin, scheme: http.Url.Scheme, port: u16, host_text: []const u8) void {
        const n: u8 = @intCast(@min(host_text.len, max_origin_host));
        o.* = .{ .scheme = scheme, .port = port, .host_len = n };
        @memcpy(o.host_buf[0..n], host_text[0..n]);
    }

    fn host(o: *const Origin) []const u8 {
        return o.host_buf[0..o.host_len];
    }

    fn eql(a: *const Origin, scheme: http.Url.Scheme, host_text: []const u8, port: u16) bool {
        return a.scheme == scheme and a.port == port and std.ascii.eqlIgnoreCase(a.host(), host_text);
    }
};

/// Keyed idle-connection pool (h1 only — see the module doc for the h2
/// seam). Bounded (`max_idle_per_host`/`max_idle_total`), reaps entries
/// older than `idle_timeout_ms`, internally synchronized (a tight
/// `std.atomic.Mutex` spinlock — this repo's era of `std` has no
/// `std.Thread.Mutex`/`Condition`; see `lockSpin`, the same idiom
/// `sessions`/`abuseguard`/`acme` already use for shared state touched from
/// every `http.Server` connection thread). No I/O ever happens while the
/// lock is held: `acquire`/`release`/`sweep` only mutate the idle list
/// under the lock, collecting anything to close into a stack buffer, and
/// only call `Conn.destroy` (a socket close + a free) after unlocking.
/// Takes `now_ms` as a plain parameter everywhere — it never reads a clock
/// itself (`Client` is the one real clock reader, via `nowMs`), so the pool
/// alone is fully deterministic to test.
const Pool = struct {
    gpa: std.mem.Allocator,
    /// Only for the futex wake that tells a `max_conns_per_host` waiter a
    /// slot or an idle connection may have appeared.
    io: std.Io,
    options: PoolOptions,
    mutex: std.atomic.Mutex = .unlocked,
    idle: std.ArrayList(Idle) = .empty,
    /// Connections held per origin under `max_conns_per_host` (dialing, in
    /// use or idle); an origin at 0 has no entry. Empty while the cap is 0.
    slots: std.ArrayList(Slot) = .empty,
    /// Bumped after anything a slot waiter could use appears (a slot freed,
    /// a connection pooled); the futex word waiters park on.
    epoch: std.atomic.Value(u32) = .init(0),
    /// Parked waiters — a release wakes nobody (no syscall) while 0.
    waiters: std.atomic.Value(u32) = .init(0),

    const Idle = struct {
        conn: *Conn,
        idle_since_ms: i64,
    };

    const Slot = struct {
        origin: Origin,
        n: u16,
    };

    /// What `checkout` found for an origin.
    const Checkout = union(enum) {
        /// A warm pooled connection — use it.
        idle: *Conn,
        /// Dial; a slot is reserved when the cap is on (`freeSlot` it if
        /// the dial fails). `evicted`, when set, is an idle connection of
        /// the same origin whose slot this dial took over: close it (its
        /// `holds_slot` is already cleared).
        dial: ?*Conn,
        /// The origin is at its cap; park on `epoch` while it still reads
        /// this value (`waiters` already counts the caller).
        wait: u32,
    };

    /// Hard upper bound on how many connections one call closes in a
    /// single pass — sized to cover any sane `max_idle_total` without
    /// needing an allocation on the reap path. `init` asserts the
    /// configured cap actually fits.
    const max_reap_batch = 4096;

    fn init(gpa: std.mem.Allocator, io: std.Io, options: PoolOptions) Pool {
        std.debug.assert(options.max_idle_total <= max_reap_batch);
        return .{ .gpa = gpa, .io = io, .options = options };
    }

    /// Close every idle connection and free the pool's own bookkeeping.
    /// Not synchronized — call only once nothing else can touch the pool
    /// (this mirrors `Client.deinit`'s own contract).
    fn deinit(p: *Pool) void {
        // Detach first: `destroy` gives a counted connection's slot back
        // through `freeSlot`, which must not see a list being walked.
        var idle = p.idle;
        p.idle = .empty;
        for (idle.items) |it| it.conn.destroy();
        idle.deinit(p.gpa);
        p.slots.deinit(p.gpa);
    }

    /// The `max_conns_per_host` gate, one decision under the lock. With
    /// `take_idle` a pooled connection of the origin is handed out first
    /// (an ordinary checkout); without it (a stale-connection retry, which
    /// wants a fresh dial) an idle one at the cap is evicted instead, so
    /// the retry never waits on a connection only it could have used.
    fn checkout(p: *Pool, scheme: http.Url.Scheme, host: []const u8, port: u16, now_ms: i64, take_idle: bool, h1_only: bool) error{OutOfMemory}!Checkout {
        if (take_idle and p.options.enabled) {
            if (p.acquire(scheme, host, port, now_ms, h1_only)) |conn| return .{ .idle = conn };
        }
        const cap = p.options.max_conns_per_host;
        if (cap == 0) return .{ .dial = null };
        // The key as `Origin.set` stores it (an over-long host truncated),
        // so `freeSlot`, which has only the stored key, finds this entry.
        const key = host[0..@min(host.len, Origin.max_origin_host)];

        lockSpin(&p.mutex);
        defer p.mutex.unlock();
        const slot: *Slot = for (p.slots.items) |*s| {
            if (s.origin.eql(scheme, key, port)) break s;
        } else s: {
            const s = try p.slots.addOne(p.gpa);
            s.n = 0;
            s.origin.set(scheme, port, key);
            break :s s;
        };
        if (slot.n < cap) {
            slot.n += 1;
            return .{ .dial = null };
        }
        // At the cap. An idle connection of this origin can only be here
        // without `take_idle` (or because it was pooled after `acquire`
        // above looked): evict the oldest, inherit its slot.
        var oldest: ?usize = null;
        for (p.idle.items, 0..) |it, idx| {
            if (!it.conn.origin.eql(scheme, key, port)) continue;
            if (oldest == null or it.idle_since_ms < p.idle.items[oldest.?].idle_since_ms) oldest = idx;
        }
        if (oldest) |idx| {
            const conn = p.idle.orderedRemove(idx).conn;
            // An h2 connection is no use to a request that needs HTTP/1.1.
            if (take_idle and !(h1_only and conn.h2 != null)) return .{ .idle = conn };
            conn.holds_slot = false;
            return .{ .dial = conn };
        }
        _ = p.waiters.fetchAdd(1, .monotonic);
        return .{ .wait = p.epoch.load(.acquire) };
    }

    /// Give an origin's slot back (`Conn.destroy`, a failed dial) and wake
    /// the waiters.
    fn freeSlot(p: *Pool, origin: *const Origin) void {
        {
            lockSpin(&p.mutex);
            defer p.mutex.unlock();
            for (p.slots.items, 0..) |*s, idx| {
                if (!s.origin.eql(origin.scheme, origin.host(), origin.port)) continue;
                s.n -= 1;
                if (s.n == 0) _ = p.slots.swapRemove(idx);
                break;
            } else unreachable; // a held slot has an entry
        }
        p.wake();
    }

    /// After the state a waiter checks has changed (outside the lock — a
    /// waiter that read `epoch` before the change sees it moved).
    fn wake(p: *Pool) void {
        _ = p.epoch.fetchAdd(1, .release);
        if (p.waiters.load(.acquire) > 0) p.io.futexWake(u32, &p.epoch.raw, std.math.maxInt(u32));
    }

    fn idleCount(p: *Pool) usize {
        lockSpin(&p.mutex);
        defer p.mutex.unlock();
        return p.idle.items.len;
    }

    /// Pop a warm idle connection matching `(scheme, host, port)`, or null
    /// (dial fresh). Opportunistically reaps any idle connection already
    /// older than `idle_timeout_ms` encountered along the way. When several
    /// idle connections match the key, the most recently released one wins
    /// (keeps the warmest socket in play; older same-key idle connections
    /// simply age out via the timeout or a later cap eviction).
    fn acquire(p: *Pool, scheme: http.Url.Scheme, host: []const u8, port: u16, now_ms: i64, h1_only: bool) ?*Conn {
        var reap_buf: [max_reap_batch]*Conn = undefined;
        var reap_n: usize = 0;
        var found: ?*Conn = null;
        {
            lockSpin(&p.mutex);
            defer p.mutex.unlock();

            var i: usize = 0;
            while (i < p.idle.items.len) {
                if (now_ms -| p.idle.items[i].idle_since_ms > p.options.idle_timeout_ms and reap_n < max_reap_batch) {
                    reap_buf[reap_n] = p.idle.swapRemove(i).conn;
                    reap_n += 1;
                    continue; // swapRemove moved the tail into i — recheck it
                }
                i += 1;
            }
            var match_idx: ?usize = null;
            for (p.idle.items, 0..) |it, idx| {
                if (h1_only and it.conn.h2 != null) continue;
                if (it.conn.origin.eql(scheme, host, port)) match_idx = idx;
            }
            if (match_idx) |idx| found = p.idle.orderedRemove(idx).conn;
        }
        for (reap_buf[0..reap_n]) |c| c.destroy();
        return found;
    }

    /// Return `conn` to the idle pool, evicting the oldest same-origin
    /// entry if `max_idle_per_host` would be exceeded and the oldest entry
    /// overall if `max_idle_total` would be exceeded (both closed after the
    /// lock is released). Fails closed under allocation pressure: if the
    /// pool's own bookkeeping cannot grow, `conn` is simply closed instead
    /// of pooled — a missed reuse opportunity, never a leak or a
    /// correctness problem (mirrors `ramcache.put`'s silent-no-op-on-OOM
    /// shape).
    fn release(p: *Pool, conn: *Conn, now_ms: i64) void {
        var evict_buf: [2]*Conn = undefined;
        var evict_n: usize = 0;
        var kept = true;
        {
            lockSpin(&p.mutex);
            defer p.mutex.unlock();

            var per_host: usize = 0;
            var oldest_host_idx: ?usize = null;
            var oldest_host_ms: i64 = std.math.maxInt(i64);
            for (p.idle.items, 0..) |it, idx| {
                if (!it.conn.origin.eql(conn.origin.scheme, conn.origin.host(), conn.origin.port)) continue;
                per_host += 1;
                if (it.idle_since_ms < oldest_host_ms) {
                    oldest_host_ms = it.idle_since_ms;
                    oldest_host_idx = idx;
                }
            }
            if (per_host >= p.options.max_idle_per_host) {
                if (oldest_host_idx) |idx| {
                    evict_buf[evict_n] = p.idle.orderedRemove(idx).conn;
                    evict_n += 1;
                }
            }
            if (p.idle.items.len >= p.options.max_idle_total) {
                var oldest_idx: ?usize = null;
                var oldest_ms: i64 = std.math.maxInt(i64);
                for (p.idle.items, 0..) |it, idx| {
                    if (it.idle_since_ms < oldest_ms) {
                        oldest_ms = it.idle_since_ms;
                        oldest_idx = idx;
                    }
                }
                if (oldest_idx) |idx| {
                    evict_buf[evict_n] = p.idle.orderedRemove(idx).conn;
                    evict_n += 1;
                }
            }
            p.idle.append(p.gpa, .{ .conn = conn, .idle_since_ms = now_ms }) catch {
                kept = false;
            };
        }
        for (evict_buf[0..evict_n]) |c| c.destroy();
        if (!kept) conn.destroy();
        // A `max_conns_per_host` waiter can take the pooled connection.
        if (kept and p.options.max_conns_per_host != 0) p.wake();
    }

    /// Reap every idle connection older than `idle_timeout_ms` right now
    /// (closed after the lock is released). `acquire` also reaps
    /// opportunistically, but only entries it happens to scan past —
    /// `sweep` is the thorough, explicit version for a caller-driven
    /// housekeeping tick (see `Client.poolSweep`).
    fn sweep(p: *Pool, now_ms: i64) void {
        var reap_buf: [max_reap_batch]*Conn = undefined;
        var reap_n: usize = 0;
        {
            lockSpin(&p.mutex);
            defer p.mutex.unlock();
            var i: usize = 0;
            while (i < p.idle.items.len) {
                if (now_ms -| p.idle.items[i].idle_since_ms > p.options.idle_timeout_ms and reap_n < max_reap_batch) {
                    reap_buf[reap_n] = p.idle.swapRemove(i).conn;
                    reap_n += 1;
                    continue;
                }
                i += 1;
            }
        }
        for (reap_buf[0..reap_n]) |c| c.destroy();
    }
};

/// Spin until `m` is acquired (this repo's era of `std` has no
/// `std.Thread.Mutex`; see the `Pool` doc comment).
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

/// Acquire a connection to `url`'s origin: a warm pooled one when pooling is
/// enabled and one is idle for that exact `(scheme, host, port)`, else a
/// freshly dialed one. `reused.*` reports which — callers use it to decide
/// whether a subsequent write/read failure is eligible for the transparent
/// one-shot retry (see `request`'s doc comment on that retry's safety
/// boundary).
fn acquireConn(c: *Client, url: http.Url, reused: *bool, deadline: ?std.Io.Clock.Timestamp, h1_only: bool) Error!*Conn {
    return c.checkoutConn(url, reused, deadline, true, h1_only, dialConn);
}

/// Get a connection to `url`'s origin within `PoolOptions.max_conns_per_host`
/// (when 0, exactly the old pool-then-dial): `take_idle` = an ordinary
/// checkout (`acquireConn`), false = a fresh dial for a stale-connection
/// retry. `dial` is passed in, never named here, so the plaintext entry
/// points stay TLS-free (`dialPlain`'s reachability contract). A wait for a
/// slot ends at `deadline` with `error.Timeout`, or with `error.Canceled`
/// when the task is canceled (`runBounded`'s deadline).
fn checkoutConn(
    c: *Client,
    url: http.Url,
    reused: *bool,
    deadline: ?std.Io.Clock.Timestamp,
    take_idle: bool,
    h1_only: bool,
    comptime dial: fn (*Client, http.Url, bool) Error!*Conn,
) Error!*Conn {
    const p = &c.pool;
    while (true) {
        switch (try p.checkout(url.scheme, url.host, url.port, c.nowMs(), take_idle, h1_only)) {
            .idle => |conn| {
                reused.* = true;
                return conn;
            },
            .dial => |evicted| {
                if (evicted) |e| e.destroy();
                reused.* = false;
                const counted = p.options.max_conns_per_host != 0;
                const conn = dial(c, url, h1_only) catch |err| {
                    if (counted) {
                        var o: Origin = undefined;
                        o.set(url.scheme, url.port, url.host);
                        p.freeSlot(&o);
                    }
                    return err;
                };
                conn.holds_slot = counted;
                return conn;
            },
            .wait => |epoch| {
                defer _ = p.waiters.fetchSub(1, .monotonic);
                const timeout: std.Io.Timeout = if (deadline) |d| t: {
                    if (d.durationFromNow(c.io).raw.nanoseconds <= 0) return error.Timeout;
                    break :t .{ .deadline = d };
                } else .none;
                // A timeout or a spurious wake just loops: the next
                // `checkout` decides, and the check above ends a spent budget.
                try c.io.futexWaitTimeout(u32, &p.epoch.raw, epoch, timeout);
            },
        }
    }
}

/// `acquireConn`'s plaintext-only twin: same pool checkout, but a miss dials
/// through `dialPlain` directly, never `dialConn` (see `dialPlain`'s doc
/// comment for why that indirection is the whole point). Rejects a
/// non-`http` scheme itself, before touching the pool or the network, so a
/// caller that got here via a redirect to `https://` fails the same way a
/// caller that started there does. The pool is shared with `acquireConn`'s
/// callers: it is keyed by `(scheme, host, port)`, so an entry a plaintext
/// caller can ever match was necessarily dialed with `scheme = .http` — by
/// `dialPlain` (this path) or by `dialConn`'s dispatch (the TLS-capable
/// path, which also plaintext-dials `.http` origins) — either way a
/// plaintext connection, safe to hand back here.
fn acquireConnPlain(c: *Client, url: http.Url, reused: *bool, deadline: ?std.Io.Clock.Timestamp) Error!*Conn {
    if (url.scheme != .http) return error.UnsupportedScheme;
    return c.checkoutConn(url, reused, deadline, true, false, dialPlain);
}

/// Write the request head + optional in-memory body, flush, and read back
/// the response head — one full h1 exchange on an already-acquired `conn`.
/// Factored out of `request`'s hop loop so the stale-pooled-connection retry
/// there can attempt it twice against two different connections without
/// duplicating the write/flush/read sequence.
fn sendAndReadHead(
    c: *Client,
    conn: *Conn,
    method: http.Method,
    method_token: []const u8,
    url: http.Url,
    headers: []const http.Header,
    plan: BodyPlan,
    body: ?[]const u8,
    strip_sensitive: bool,
    ask_gzip: bool,
) Error!h1.ResponseHead {
    // `writeRequestHead`'s own `w: *std.Io.Writer` parameter has nowhere to
    // carry `Canceled` — like every other `std.Io.Writer` call, it can only
    // ever report the bare `error.WriteFailed` — so a cancelation reaching
    // the head write must be recovered from `conn`'s own writer here,
    // exactly as the body write two lines down already does. Skipping this
    // would let a genuine cancelation surface as `WriteFailed`, which
    // `isStaleConnError` (see `requestInner`'s retry) treats as a dead
    // pooled connection worth retrying — with the cancelation already
    // spent, the retry then blocks a second time with nothing left to
    // interrupt it.
    const head = if (conn.h2 != null)
        try c.options.http2.?.vt.exchange(conn, method, method_token, url, headers, plan, body, strip_sensitive, ask_gzip)
    else h: {
        writeRequestHeadVia(conn.plainWriter(), conn.forward_proxy, c.options.cookie_jar, method, method_token, url, headers, c.options.user_agent, plan, strip_sensitive, !c.options.pool.enabled, ask_gzip) catch return conn.writeFailure();
        if (body) |b| conn.plainWriter().writeAll(b) catch return conn.writeFailure();
        try conn.flushAll();
        break :h try readResponseHead(conn);
    };
    // Every hop's answer, a redirect's included: a login that sets its
    // session cookie on the 302 is the common case.
    if (c.options.cookie_jar) |jar| jar.store(jar.ctx, url, &head);
    return head;
}

/// The narrow set of failures that mean *this* connection was already dead
/// before the exchange even produced a usable response — never bytes a live
/// peer actually sent back. See `request`'s retry-site doc comment for the
/// full reasoning. All three are purely transport-level and can only occur
/// while `sendAndReadHead` is still writing the request or waiting for the
/// response head:
///   * `error.WriteFailed` — the write/flush itself bounced off an
///     already-dead socket (e.g. `ECONNRESET`/`EPIPE` from a peer that
///     already tore the connection down).
///   * `error.ConnectionClosed` — the peer's FIN arrived with zero response
///     bytes behind it (a clean idle-timeout close raced our checkout).
///   * `error.ReadFailed` — the response-head read syscall itself failed
///     (most commonly `ECONNRESET`: on a fast loopback the peer's reset can
///     arrive *after* our write already succeeded locally, so the failure
///     surfaces on the read instead of the write — same dead-connection
///     cause, just discovered one step later).
/// `error.HeadTooLarge`/`MalformedResponse`/`UnsupportedHttpVersion` are
/// deliberately NOT included: those mean the peer *did* send real response
/// bytes back (just broken/oversized ones) — a live peer misbehaving, not a
/// stale connection, and redialing would not fix it.
fn isStaleConnError(err: anyerror) bool {
    return switch (err) {
        error.WriteFailed, error.ConnectionClosed, error.ReadFailed => true,
        else => false,
    };
}

/// Milliseconds on the `awake` (monotonic) clock — the pool's only time
/// source. Never called by `Pool` itself (it takes `now_ms` as a plain
/// parameter, per this repo's no-hidden-clock rule), only by `Client` at the
/// call sites that hand the pool its clock.
fn nowMs(c: *Client) i64 {
    const ts = std.Io.Clock.Timestamp.now(c.io, .awake);
    return @intCast(@divTrunc(ts.raw.nanoseconds, std.time.ns_per_ms));
}

/// Dial fresh, dispatching on `url.scheme`. Thin on purpose: this decl
/// (and `acquireConn`, its only caller) is what `request`/`requestStreaming`/
/// `putFile` still go through, so it must keep naming BOTH halves to keep
/// TLS support for those callers unchanged. That is also exactly why
/// `requestPlain`/`requestStreamingPlain`/`putFilePlain` do NOT call this —
/// see `dialPlain`'s doc comment for the reachability argument.
/// `h1_only` (`needsHttp1`): offer no h2 by ALPN.
fn dialConn(c: *Client, url: http.Url, h1_only: bool) Error!*Conn {
    if (url.scheme == .https) return c.dialTls(url, h1_only);
    return c.dialPlain(url, h1_only);
}

/// Dial a fresh plaintext (`http://`) connection: allocate the buffer slab,
/// connect the socket, done — no CA bundle, no TLS record layer.
///
/// **Reachability contract:** this function's own body must never name
/// `tls`, `ensureCaBundle`, or `Certificate` — that is the entire mechanism
/// behind the plaintext client's size saving (see `README.md`'s
/// "Plaintext-only client" section and `sizeprobe/`). Sema only has to
/// analyse a textually-referenced call; a plaintext-only entry point
/// (`requestPlain` et al.) reaches this decl directly and never reaches
/// `dialConn`/`dialTls`, so the TLS handshake state machine, X.509
/// parse/verify and every hash/curve/AEAD it pulls in are never part of that
/// binary's call graph. Splitting the branches *inside* one shared `dialConn`
/// was tried first and does not work: a dispatcher that still names both
/// `dialPlain` and `dialTls` keeps both reachable from every caller that
/// goes through it, TLS-only or not — only a caller that never mentions the
/// TLS-side decl at all drops the reference. Mirrors `dialTls` structurally;
/// keep the two in sync by hand if the shared parts (buffer accounting,
/// `Conn` init, dial bookkeeping) change.
fn dialPlain(c: *Client, url: http.Url, h1_only: bool) Error!*Conn {
    _ = h1_only; // plaintext is always HTTP/1.1 (h2c is `connectH2c`)
    const o = &c.options;
    const io = c.io;

    const total = o.read_buffer_size + o.write_buffer_size + o.max_head_bytes + body_scratch_len;

    const conn = try c.gpa.create(Conn);
    errdefer c.gpa.destroy(conn);
    const slab = try c.gpa.alloc(u8, total);
    errdefer c.gpa.free(slab);

    var off: usize = 0;
    const sock_r = slab[off..][0..o.read_buffer_size];
    off += o.read_buffer_size;
    const sock_w = slab[off..][0..o.write_buffer_size];
    off += o.write_buffer_size;
    const head_buf = slab[off..][0..o.max_head_bytes];
    off += o.max_head_bytes;
    const body_buf = slab[off..][0..body_scratch_len];

    const proxy = try c.proxyFor(url);
    const stream = try c.connectStream(if (proxy) |ep| proxyUrl(ep) else url);
    errdefer stream.close(io);
    _ = c.dial_count.fetchAdd(1, .monotonic);

    conn.* = .{
        .client = c,
        .stream = stream,
        .sr = undefined,
        .sw = undefined,
        .tls_client = null,
        .slab = slab,
        .head_buf = head_buf,
        .body_buf = body_buf,
        .body = .unset,
        .origin = undefined,
        .keep_alive_eligible = false,
        .forward_proxy = proxy,
    };
    // Keyed by the origin even when it goes through a proxy: the proxy
    // choice is a pure function of the URL and the client's fixed options,
    // so one origin is always reached the same way.
    conn.origin.set(url.scheme, url.port, url.host);
    // The stream reader/writer must be initialized at the connection's final
    // heap address.
    conn.sr = stream.reader(io, sock_r);
    conn.sw = stream.writer(io, sock_w);
    return conn;
}

/// The proxy `url` goes through, if any (`Options.proxy`).
fn proxyFor(c: *Client, url: http.Url) Error!?client_proxy.Endpoint {
    return c.options.proxy.forUrl(url) catch error.BadProxy;
}

/// A proxy as a URL to dial.
fn proxyUrl(ep: client_proxy.Endpoint) http.Url {
    return .{ .scheme = .http, .host = ep.host, .port = ep.port, .path = "/", .query = "" };
}

/// Open a `CONNECT` tunnel to `url`'s origin through the proxy `conn` is
/// dialed to (RFC 9110 §9.3.6): on a 2xx the connection is the origin's
/// from the next byte on. A 2xx to CONNECT has no body, so whatever the
/// proxy sends after the head already belongs to the origin and is left
/// in the reader for the TLS handshake.
fn connectTunnel(conn: *Conn, url: http.Url, ep: client_proxy.Endpoint) Error!void {
    const w = &conn.sw.interface;
    writeConnect(w, url, ep) catch return conn.writeFailure();
    w.flush() catch return conn.writeFailure();
    const block = h1.readHead(&conn.sr.interface, conn.head_buf) catch |err| switch (err) {
        error.ReadFailed => return conn.readFailure(),
        error.ConnectionClosed => return error.ConnectionClosed,
        error.HeadTooLarge => return error.HeadTooLarge,
        error.MalformedHead => return error.MalformedResponse,
    };
    const head = h1.ResponseHead.parse(block) catch |err| switch (err) {
        error.MalformedHead => return error.MalformedResponse,
        error.UnsupportedVersion => return error.UnsupportedHttpVersion,
    };
    if (head.status < 200 or head.status > 299) return error.ProxyRefused;
}

fn writeConnect(w: *std.Io.Writer, url: http.Url, ep: client_proxy.Endpoint) std.Io.Writer.Error!void {
    // authority-form, the port always explicit (RFC 9112 §3.2.3).
    const open, const close = if (url.hostIsV6()) .{ "[", "]" } else .{ "", "" };
    try w.print("CONNECT {s}{s}{s}:{d} HTTP/1.1\r\nHost: {s}{s}{s}:{d}\r\n", .{ open, url.host, close, url.port, open, url.host, close, url.port });
    try ep.writeAuthorization(w);
    try w.writeAll("\r\n");
}

/// Dial a fresh `https://` connection: same buffer-slab/`Conn`/dial-count
/// bookkeeping as `dialPlain`, plus the CA bundle load and the TLS handshake.
/// Never called except through `dialConn`'s dispatch — see that decl and
/// `dialPlain`'s doc comment for why that indirection matters for the
/// plaintext-only entry points.
fn dialTls(c: *Client, url: http.Url, h1_only: bool) Error!*Conn {
    const o = &c.options;
    const io = c.io;
    if (o.tls.verify == .strict) try c.ensureCaBundle();

    // Buffer slab layout. The socket-facing buffers must hold a full
    // ciphertext record; the plaintext read buffer additionally holds the
    // decoded response head (mirrors std.http.Client's sizing).
    const record_len = tls.Client.min_buffer_len;
    const sock_r_len = record_len;
    const sock_w_len = record_len;
    const tls_r_len = record_len + o.read_buffer_size;
    const tls_w_len = o.write_buffer_size;
    const total = sock_r_len + sock_w_len + tls_r_len + tls_w_len + o.max_head_bytes + body_scratch_len;

    const conn = try c.gpa.create(Conn);
    errdefer c.gpa.destroy(conn);
    const slab = try c.gpa.alloc(u8, total);
    errdefer c.gpa.free(slab);

    var off: usize = 0;
    const sock_r = slab[off..][0..sock_r_len];
    off += sock_r_len;
    const sock_w = slab[off..][0..sock_w_len];
    off += sock_w_len;
    const tls_r = slab[off..][0..tls_r_len];
    off += tls_r_len;
    const tls_w = slab[off..][0..tls_w_len];
    off += tls_w_len;
    const head_buf = slab[off..][0..o.max_head_bytes];
    off += o.max_head_bytes;
    const body_buf = slab[off..][0..body_scratch_len];

    const proxy = try c.proxyFor(url);
    const stream = try c.connectStream(if (proxy) |ep| proxyUrl(ep) else url);
    errdefer stream.close(io);
    _ = c.dial_count.fetchAdd(1, .monotonic);

    conn.* = .{
        .client = c,
        .stream = stream,
        .sr = undefined,
        .sw = undefined,
        .tls_client = null,
        .slab = slab,
        .head_buf = head_buf,
        .body_buf = body_buf,
        .body = .unset,
        .origin = undefined,
        .keep_alive_eligible = false,
    };
    conn.origin.set(url.scheme, url.port, url.host);
    // The stream reader/writer (and the TLS client pointing at them) must be
    // initialized at the connection's final heap address.
    conn.sr = stream.reader(io, sock_r);
    conn.sw = stream.writer(io, sock_w);
    if (proxy) |ep| try connectTunnel(conn, url, ep);

    var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
    // The caller handed us `io` for sockets; `random`'s silent fallback
    // on `EntropyUnavailable` would spend that same capability on TLS key
    // material too — this seeds the ClientHello random and key share for
    // every HTTPS request, so fail closed instead.
    try io.randomSecure(&entropy);
    // `initInto`, not `init`: the session (application traffic keys) is
    // written in place, with no by-value copy left on the dead stack.
    conn.tls_client = @as(tls.Client, undefined);
    tls.Client.initInto(&conn.tls_client.?, &conn.sr.interface, &conn.sw.interface, .{
        .host = switch (o.tls.verify) {
            .strict => .{ .explicit = url.host },
            .insecure_no_verify => .no_verification,
        },
        .ca = switch (o.tls.verify) {
            .strict => .{ .bundle = if (c.options.shared_ca) |ca| .{
                .gpa = c.gpa,
                .io = io,
                .lock = &ca.lock,
                .bundle = &ca.bundle,
            } else .{
                .gpa = c.gpa,
                .io = io,
                .lock = &c.ca_lock,
                .bundle = &c.ca_bundle,
            } },
            .insecure_no_verify => .no_verification,
        },
        .read_buffer = tls_r,
        .write_buffer = tls_w,
        .entropy = &entropy,
        .realtime_now = std.Io.Clock.real.now(io),
        // Fine for HTTP: framing (Content-Length/chunked) detects
        // truncation at the layer above.
        .allow_truncation_attacks = true,
        .alpn_protocols = if (o.http2 != null and !h1_only) &http.alpn_offer else &.{},
    }) catch |err| {
        conn.tls_client = null;
        return switch (err) {
            error.ReadFailed, error.WriteFailed => error.ConnectFailed,
            error.Canceled => error.Canceled,
            else => error.TlsFailed,
        };
    };
    // Only what we offered can come back (tlsclient refuses anything else).
    if (conn.tls_client.?.alpn_protocol) |chosen| {
        if (http.protocolFromAlpn(chosen) == .h2) try o.http2.?.vt.start(conn);
    }
    return conn;
}

/// Resolve + connect, bounded by `Options.connect_timeout_ms`.
///
/// The bound is imposed by `runBounded`, NOT by `ConnectOptions.timeout`:
/// std 0.16.0's `Io.Threaded` panics outright ("TODO implement
/// netConnectIpPosix with timeout") the moment that field is anything but
/// `.none`, on POSIX and Windows alike. So the field stays `.none` forever
/// here and the deadline is enforced one level up, by canceling the task the
/// `connect` syscall is blocked in. `std.Io.net`'s own resolver is inside
/// this bound too (name lookup is ordinary cancelable socket I/O), so a
/// nameserver black hole is bounded by `connect_timeout_ms` as well.
fn connectStream(c: *Client, url: http.Url) Error!net.Stream {
    const deadline = c.connectDeadline() orelse return c.connectStreamBlocking(url);
    return runBounded(c.io, c.options.inline_blocking, deadline, connectStreamBlocking, .{ c, url }) catch |err| switch (err) {
        // No spare unit of concurrency (single-threaded build, or a
        // `Threaded` whose `concurrent_limit` is exhausted). Connecting
        // anyway on this thread is the pre-existing behavior and keeps such
        // a caller working; it is unbounded, which `Options.connect_timeout_ms`
        // says out loud.
        error.ConcurrencyUnavailable => c.connectStreamBlocking(url),
        else => |e| e,
    };
}

fn connectStreamBlocking(c: *Client, url: http.Url) Error!net.Stream {
    const copts: net.IpAddress.ConnectOptions = .{
        .mode = .stream,
        // Deliberately `.none` — see `connectStream`'s doc comment.
        .timeout = .none,
    };
    if (netaddr.parseIp(url.host) != null) {
        const addr = net.IpAddress.parse(url.host, url.port) catch return error.BadUrl;
        return addr.connect(c.io, copts) catch |err| mapConnectError(err);
    }
    const host_name = net.HostName.init(url.host) catch return error.BadUrl;
    if (c.options.inline_blocking) return c.connectHostInline(host_name, url.port, copts);
    return host_name.connect(c.io, url.port, copts) catch |err| mapConnectError(err);
}

/// `HostName.connect` for `Options.inline_blocking`, on the calling thread.
///
/// std's `HostName.connect` does not run where it is called: it starts the
/// lookup and one connect per address as tasks (`io.async` + an `Io.Group`),
/// so with `std.Io.Threaded` they run on the pool -- outside a sandbox the
/// calling thread is in, whatever `runBounded` does (found by qap's jwks
/// probe: a Landlocked refresh thread still read `/etc/hosts`). Here the
/// lookup is called directly (`Threaded`'s resolver is synchronous: hosts
/// file, then DNS over a socket) into a local queue, and the addresses are
/// tried one after another. What is lost is std's parallel connect (the first
/// address to answer wins); what an unreachable first address costs is its
/// connect error, or its SYN timeout -- the price `inline_blocking` already
/// names.
///
/// The queue holds 256 results. `lookup` is documented not to block with 16,
/// but std 0.16's hosts-file reader puts one result per matching line with no
/// cap, and nothing drains the queue while `lookup` runs on this thread: a
/// name listed on more than 255 hosts-file lines would block here for good.
fn connectHostInline(c: *Client, host_name: net.HostName, port: u16, copts: net.IpAddress.ConnectOptions) Error!net.Stream {
    var results_buf: [256]net.HostName.LookupResult = undefined;
    var results: std.Io.Queue(net.HostName.LookupResult) = .init(&results_buf);
    host_name.lookup(c.io, &results, .{ .port = port }) catch |err| return mapConnectError(err);
    var last_err: ?Error = null;
    while (results.getOne(c.io)) |r| switch (r) {
        .address => |addr| {
            if (addr.connect(c.io, copts)) |stream| return stream else |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => last_err = mapConnectError(err),
            }
        },
        .canonical_name => {},
    } else |err| switch (err) {
        error.Closed => {},
        error.Canceled => return error.Canceled,
    }
    return last_err orelse error.UnknownHostName;
}

fn mapConnectError(err: anyerror) Error {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.Timeout => error.Timeout,
        error.UnknownHostName, error.NoAddressReturned => error.UnknownHostName,
        error.OutOfMemory => error.OutOfMemory,
        else => error.ConnectFailed,
    };
}

/// Load the system CA bundle once (lazily, like std.http.Client): the
/// shared one when `Options.shared_ca` is set, else the client's own.
fn ensureCaBundle(c: *Client) Error!void {
    if (c.options.shared_ca) |ca| return ca.load(c.gpa, c.io);
    return loadCa(c.gpa, c.io, &c.ca_lock, &c.ca_bundle, &c.ca_scanned);
}

/// Load the CA bundle now instead of on the first HTTPS request — for a
/// process that confines itself after startup and would then be unable to
/// read the system store. Idempotent. With `Options.shared_ca`, loads that.
pub fn loadCaBundle(c: *Client) Error!void {
    return c.ensureCaBundle();
}

fn loadCa(
    gpa: std.mem.Allocator,
    io: std.Io,
    lock: *std.Io.RwLock,
    target: *std.crypto.Certificate.Bundle,
    scanned: *bool,
) Error!void {
    {
        lock.lockShared(io) catch return error.Canceled;
        defer lock.unlockShared(io);
        if (scanned.*) return;
    }
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(gpa);
    bundle.rescan(gpa, io, std.Io.Clock.real.now(io)) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.CertificateBundleLoadFailure,
    };
    lock.lock(io) catch return error.Canceled;
    defer lock.unlock(io);
    if (!scanned.*) {
        scanned.* = true;
        std.mem.swap(std.crypto.Certificate.Bundle, target, &bundle);
    }
}

// ── timeouts ────────────────────────────────────────────────────────────────

/// The return type of `runBounded` for `func`: `func`'s own error union,
/// widened by the one failure only the runner can produce.
fn BoundedResult(comptime func: anytype) type {
    const eu = @typeInfo(@typeInfo(@TypeOf(func)).@"fn".return_type.?).error_union;
    return (eu.error_set || error{ConcurrencyUnavailable})!eu.payload;
}

/// Run `func(args)` on its own concurrent task and give it until `deadline`
/// (null = no bound). This is the client's ONLY way to bound a blocking
/// phase, and it exists because std 0.16.0 offers no per-read deadline: the
/// socket read/write/connect syscalls take no timeout, and `net.Stream` has
/// no `setOption` seam for `SO_RCVTIMEO` (which `Io.Threaded`'s reader could
/// not report anyway — it treats `EAGAIN` as a bug, not a timeout).
///
/// What *is* available is cancelation. `Io.Threaded` runs a task on a real
/// thread and implements `Future.cancel` by repeatedly signalling that thread
/// (`SIG.IO`) until the in-flight syscall returns `EINTR` and the wrapper's
/// cancel check fires, so the blocked `readv`/`connect` returns
/// `error.Canceled` instead of blocking forever. That only works for a task
/// the `Io` implementation owns — a syscall made on the caller's own thread
/// has no cancelation state attached (`Threaded.Syscall.start` no-ops when
/// `Thread.current` is null) — hence "run it over there, then cancel it",
/// rather than "ask the read to time out".
///
/// Contract:
///   * finished in time → `func`'s own result, untouched.
///   * deadline hit → the task is canceled and *waited for* (the frame it
///     borrows lives on this stack), then `error.Timeout`. If the task
///     nevertheless completed successfully inside that cancelation window,
///     its value is returned instead — a race with the deadline must never
///     drop a connection/response the task already allocated.
///   * *this* task canceled while waiting → same unwind, then
///     `error.Canceled`.
///   * no unit of concurrency available → `error.ConcurrencyUnavailable`,
///     never a silent unbounded run. Every call site decides what to do with
///     it, and each one documents the choice.
fn runBounded(
    io: std.Io,
    inline_only: bool,
    deadline: ?std.Io.Clock.Timestamp,
    comptime func: anytype,
    args: std.meta.ArgsTuple(@TypeOf(func)),
) BoundedResult(func) {
    const Result = @typeInfo(@TypeOf(func)).@"fn".return_type.?;
    const Ctx = struct {
        io: std.Io,
        args: std.meta.ArgsTuple(@TypeOf(func)),
        result: Result = undefined,
        /// 0 while the task runs, 1 once `result` is published. Doubles as
        /// the futex word the waiter parks on, so the normal (in-time) path
        /// costs one wake, not a poll.
        state: std.atomic.Value(u32) = .init(0),

        fn run(ctx: *@This()) void {
            ctx.result = @call(.auto, func, ctx.args);
            ctx.state.store(1, .release);
            ctx.io.futexWake(u32, &ctx.state.raw, 1);
        }
    };

    // `Options.inline_blocking`: take the call sites' existing
    // no-concurrency path — the caller's thread, unbounded.
    if (inline_only) return error.ConcurrencyUnavailable;
    var ctx: Ctx = .{ .io = io, .args = args };
    var future = try io.concurrent(Ctx.run, .{&ctx});

    var canceled = false;
    var expired = false;
    while (ctx.state.load(.acquire) == 0) {
        const timeout: std.Io.Timeout = if (deadline) |d| t: {
            if (d.durationFromNow(io).raw.nanoseconds <= 0) {
                expired = true;
                break;
            }
            break :t .{ .deadline = d };
        } else .none;
        // Spurious wakeups are allowed here; the loop re-reads `state`.
        io.futexWaitTimeout(u32, &ctx.state.raw, 0, timeout) catch {
            canceled = true;
            break;
        };
    }
    if (!expired and !canceled) {
        future.await(io);
        return ctx.result;
    }
    future.cancel(io);
    // `cancel` joined the task, so `result` is written either way. A success
    // that landed in the cancelation window is still a success.
    if (ctx.result) |value| return value else |_| {}
    return if (expired) error.Timeout else error.Canceled;
}

fn connectDeadline(c: *Client) ?std.Io.Clock.Timestamp {
    const ms = c.options.connect_timeout_ms;
    if (ms == 0) return null;
    return .fromNow(c.io, .{ .raw = .fromMilliseconds(ms), .clock = .awake });
}

fn totalDeadline(c: *Client) ?std.Io.Clock.Timestamp {
    const ms = c.options.total_timeout_ms;
    if (ms == 0) return null;
    const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
    return t.toTimestamp(c.io);
}

fn checkDeadline(c: *Client, deadline: ?std.Io.Clock.Timestamp) Error!void {
    const d = deadline orelse return;
    if (d.durationFromNow(c.io).raw.nanoseconds <= 0) return error.Timeout;
}

// ── wire helpers (pure, offline-testable) ───────────────────────────────────

const BodyPlan = union(enum) {
    none,
    content_length: u64,
    chunked,
};

/// True when `a` and `b` are different origins (RFC 6454): scheme, host
/// (case-insensitive — DNS names) and port must ALL match. `Url.parse`
/// already fills in the scheme's default port when the URL omits one, so a
/// bare port comparison here correctly treats an explicit `:443` and an
/// implicit `https://` origin as the same. Used to decide whether a redirect
/// hop must strip credential-bearing headers (`Authorization`, `Cookie`) —
/// a host-only check would keep sending them across a same-host scheme
/// downgrade (https→http) or a same-host port change.
fn crossOrigin(a: http.Url, b: http.Url) bool {
    return !(a.scheme == b.scheme and a.port == b.port and std.ascii.eqlIgnoreCase(a.host, b.host));
}

/// Emit a full request head. Pure writer logic so tests can assert exact
/// bytes. Managed headers: `Connection: close` when `send_close` (else
/// omitted — HTTP/1.1 defaults to persistent, which is what makes the
/// connection eligible for the pool afterwards); `Content-Length` /
/// `Transfer-Encoding` from `plan`; `Host`, `User-Agent`, `Accept-Encoding`
/// defaulted unless the caller supplies them. When `strip_sensitive` (a
/// cross-origin redirect hop — see `crossOrigin`): `Authorization`, `Cookie`
/// and `Proxy-Authorization` are dropped, since each carries credentials
/// that must not leak to a different scheme/host/port (the last is by
/// definition for the nearest proxy only, RFC 9110 §11.7.1 — A1 G4), and a
/// caller-supplied `Host` is replaced by the hop's own authority: it named
/// the ORIGINAL origin, and sending it to another host routes the request
/// as a vhost that host is not (A1 G3 — the client-side twin of the
/// absolute-form host confusion the server fixed). Same-origin hops keep all
/// four.
fn writeRequestHead(
    w: *std.Io.Writer,
    method: http.Method,
    url: http.Url,
    headers: []const http.Header,
    user_agent: []const u8,
    plan: BodyPlan,
    strip_sensitive: bool,
    send_close: bool,
) error{WriteFailed}!void {
    return writeRequestHeadVia(w, null, null, method, "", url, headers, user_agent, plan, strip_sensitive, send_close, false);
}

/// `writeRequestHead` for a connection that may be to a forwarding proxy:
/// with `proxy` set the target is absolute (`http://host[:port]/path`,
/// RFC 9112 §3.2.2) and the proxy's credentials ride along.
fn writeRequestHeadVia(
    w: *std.Io.Writer,
    proxy: ?client_proxy.Endpoint,
    jar: ?CookieJar,
    method: http.Method,
    method_token: []const u8,
    url: http.Url,
    headers: []const http.Header,
    user_agent: []const u8,
    plan: BodyPlan,
    strip_sensitive: bool,
    send_close: bool,
    ask_gzip: bool,
) error{WriteFailed}!void {
    var custom_host: ?[]const u8 = null;
    var custom_ua = false;
    var custom_ae = false;
    var asks_upgrade = false;
    var has_upgrade = false;
    for (headers) |hd| {
        if (std.ascii.eqlIgnoreCase(hd.name, "host")) custom_host = hd.value;
        if (std.ascii.eqlIgnoreCase(hd.name, "user-agent")) custom_ua = true;
        if (std.ascii.eqlIgnoreCase(hd.name, "accept-encoding")) custom_ae = true;
        if (std.ascii.eqlIgnoreCase(hd.name, "connection") and h1.tokenListContains(hd.value, "upgrade")) asks_upgrade = true;
        if (std.ascii.eqlIgnoreCase(hd.name, "upgrade")) has_upgrade = true;
    }
    // `Connection` is managed, except for the one token a caller must be
    // able to send: an upgrade request (RFC 9110 §7.8), as Go's Transport
    // passes it on. Its `Connection: Upgrade` replaces `close`.
    const connection: ConnectionHeader = if (asks_upgrade and has_upgrade) .upgrade else if (send_close) .close else .none;

    writeHead(w, proxy, jar, method, method_token, url, headers, user_agent, plan, strip_sensitive, connection, if (strip_sensitive) null else custom_host, custom_ua, custom_ae, ask_gzip) catch
        return error.WriteFailed;
}

const ConnectionHeader = enum { none, close, upgrade };

fn writeHead(
    w: *std.Io.Writer,
    proxy: ?client_proxy.Endpoint,
    jar: ?CookieJar,
    method: http.Method,
    method_token: []const u8,
    url: http.Url,
    headers: []const http.Header,
    user_agent: []const u8,
    plan: BodyPlan,
    strip_sensitive: bool,
    connection: ConnectionHeader,
    custom_host: ?[]const u8,
    custom_ua: bool,
    custom_ae: bool,
    ask_gzip: bool,
) std.Io.Writer.Error!void {
    try w.print("{s} ", .{methodWire(method, method_token)});
    if (proxy != null) {
        try w.writeAll("http://");
        try url.writeHostHeaderValue(w);
    }
    try w.writeAll(url.path);
    if (url.query.len != 0) try w.print("?{s}", .{url.query});
    try w.writeAll(" HTTP/1.1\r\nHost: ");
    if (custom_host) |hv| {
        try w.writeAll(hv);
    } else {
        try url.writeHostHeaderValue(w);
    }
    try w.writeAll("\r\n");
    const own_proxy_auth = if (proxy) |ep| ep.userinfo != null else false;
    var cookie_written = false;
    if (proxy) |ep| try ep.writeAuthorization(w);

    for (headers) |hd| {
        if (std.ascii.eqlIgnoreCase(hd.name, "host") or
            std.ascii.eqlIgnoreCase(hd.name, "connection") or
            std.ascii.eqlIgnoreCase(hd.name, "content-length") or
            std.ascii.eqlIgnoreCase(hd.name, "transfer-encoding")) continue;
        if (strip_sensitive and (std.ascii.eqlIgnoreCase(hd.name, "authorization") or
            std.ascii.eqlIgnoreCase(hd.name, "cookie") or
            std.ascii.eqlIgnoreCase(hd.name, "proxy-authorization"))) continue;
        // The configured proxy's own credentials win over a caller's.
        if (own_proxy_auth and std.ascii.eqlIgnoreCase(hd.name, "proxy-authorization")) continue;
        if (!cookie_written and std.ascii.eqlIgnoreCase(hd.name, "cookie")) {
            // One `Cookie` field (RFC 6265 §5.4): the jar's after the caller's.
            try w.print("{s}: {s}", .{ hd.name, hd.value });
            if (jar) |j| _ = try j.write_cookies(j.ctx, url, w, "; ");
            try w.writeAll("\r\n");
            cookie_written = true;
            continue;
        }
        try w.print("{s}: {s}\r\n", .{ hd.name, hd.value });
    }
    if (!cookie_written) if (jar) |j| {
        if (try j.write_cookies(j.ctx, url, w, "Cookie: ")) try w.writeAll("\r\n");
    };

    if (!custom_ua) try w.print("User-Agent: {s}\r\n", .{user_agent});
    // `identity` also when decoding is on but `requestsGzip` said no (HEAD,
    // a `Range`), where Go sends no field at all: same meaning, explicit.
    if (!custom_ae) try w.writeAll(if (ask_gzip) "Accept-Encoding: gzip\r\n" else "Accept-Encoding: identity\r\n");
    switch (connection) {
        .none => {},
        .close => try w.writeAll("Connection: close\r\n"),
        .upgrade => try w.writeAll("Connection: Upgrade\r\n"),
    }
    switch (plan) {
        .none => {},
        .content_length => |n| try w.print("Content-Length: {d}\r\n", .{n}),
        .chunked => try w.writeAll("Transfer-Encoding: chunked\r\n"),
    }
    try w.writeAll("\r\n");
}

/// Read + parse the response head, skipping interim 1xx responses
/// (100-continue etc.; 101 is returned as-is).
fn readResponseHead(conn: *Conn) Error!h1.ResponseHead {
    while (true) {
        const block = h1.readHead(conn.plainReader(), conn.head_buf) catch |err| switch (err) {
            error.ReadFailed => return conn.readFailure(),
            error.ConnectionClosed => return error.ConnectionClosed,
            error.HeadTooLarge => return error.HeadTooLarge,
            error.MalformedHead => return error.MalformedResponse,
        };
        // `block` is the front of `conn.head_buf`, which is ours to rewrite.
        h1.unfoldObsFold(conn.head_buf[0..block.len]);
        conn.head_len = block.len;
        const head = h1.ResponseHead.parse(block) catch |err| switch (err) {
            error.MalformedHead => return error.MalformedResponse,
            error.UnsupportedVersion => return error.UnsupportedHttpVersion,
        };
        // A transfer coding other than the sole `chunked` would hand the
        // caller a body still coded; and an HTTP/1.0 message with
        // Transfer-Encoding has faulty framing (RFC 9112 §6.1), which a user
        // agent must discard (§6.3).
        if (head.has_transfer_encoding and (!head.chunked or head.http1_0))
            return error.MalformedResponse;
        if (head.status >= 100 and head.status < 200 and head.status != 101) continue;
        return head;
    }
}

/// Select the body framing per RFC 7230 §3.3.3 (client side), and latch
/// whether this exchange leaves the connection eligible for the pool
/// (`conn.keep_alive_eligible`) — still gated on `isBodyDrained` once the
/// caller has actually read the body (or not) before it decides.
fn setupBody(conn: *Conn, method: http.Method, head: h1.ResponseHead) void {
    if (method == .head or head.status == 204 or head.status == 304) {
        conn.body = .{ .none = .fixed("") };
    } else if (head.chunked) {
        // Trailers land behind the head in `head_buf` (Go fills
        // `Response.Trailer` on HTTP/1.1 too).
        conn.body = .{ .chunked = h1.ChunkedReader.initCapturingTrailers(conn.plainReader(), conn.body_buf, conn.head_buf[conn.head_len..]) };
    } else if (head.content_length) |n| {
        conn.body = .{ .limited = h1.ContentLengthReader.init(conn.plainReader(), n, conn.body_buf) };
    } else {
        conn.body = .until_close; // read to connection close
    }
    conn.keep_alive_eligible = keepAliveEligible(head) and conn.body != .until_close;
}

/// Header-level poolability (RFC 7230 §6.3 client side): never on an
/// explicit `Connection: close`, never on a `101` (the connection's
/// semantics changed entirely — e.g. WebSocket upgrade — so h1 request/
/// response framing no longer applies), never on an HTTP/1.0 response
/// unless it opted into `keep-alive` (1.0 defaults to closing). Body-length
/// framing (`until_close` can never be pooled — see the caller) is handled
/// separately since it depends on the body union, not just the head.
fn keepAliveEligible(head: h1.ResponseHead) bool {
    if (head.status == 101) return false;
    if (head.connection_close) return false;
    if (head.http1_0 and !head.connection_keep_alive) return false;
    return true;
}

/// Whether `conn`'s response body was read to completion with no framing
/// error — the other half (with `Conn.keep_alive_eligible`) of "may this
/// connection go back to the pool". A caller that `deinit`s a `Response`
/// without reading the whole body (or that hit a body read error) leaves
/// the connection in an indeterminate wire state, so it is closed instead,
/// never pooled — silently draining the rest for them here would be
/// surprise I/O in a `deinit` call, so this module does not attempt it.
fn isBodyDrained(conn: *const Conn) bool {
    return switch (conn.body) {
        .none => true,
        .limited => |r| r.remaining == 0 and !r.truncated,
        .chunked => |r| r.state == .done and r.fail_reason == null,
        .h2 => conn.client.options.http2.?.vt.drained(conn),
        .until_close, .unset => false,
    };
}

// ── tests (offline) ─────────────────────────────────────────────────────────

const testing = std.testing;

test "writeRequestHead: defaults" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const url = try http.Url.parse("http://example.com/x/y?q=1");
    try writeRequestHead(&w, .get, url, &.{}, "test-agent/1.0", .none, false, true);
    try testing.expectEqualStrings(
        "GET /x/y?q=1 HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "User-Agent: test-agent/1.0\r\n" ++
            "Accept-Encoding: identity\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
        w.buffered(),
    );
}

test "writeRequestHead: body plans, custom + managed headers" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const url = try http.Url.parse("https://[2001:db8::1]:8443/upload");
    try writeRequestHead(&w, .post, url, &.{
        .{ .name = "User-Agent", .value = "custom/2" },
        .{ .name = "X-Extra", .value = "1" },
        .{ .name = "Connection", .value = "keep-alive" }, // managed → ignored
        .{ .name = "Content-Length", .value = "999" }, // managed → ignored
    }, "default-agent", .{ .content_length = 11 }, false, true);
    try testing.expectEqualStrings(
        "POST /upload HTTP/1.1\r\n" ++
            "Host: [2001:db8::1]:8443\r\n" ++
            "User-Agent: custom/2\r\n" ++
            "X-Extra: 1\r\n" ++
            "Accept-Encoding: identity\r\n" ++
            "Connection: close\r\n" ++
            "Content-Length: 11\r\n" ++
            "\r\n",
        w.buffered(),
    );

    w = .fixed(&buf);
    try writeRequestHead(&w, .put, url, &.{}, "a", .chunked, false, true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Transfer-Encoding: chunked\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Content-Length") == null);
}

test "writeRequestHead: Authorization stripped on cross-host redirect" {
    var buf: [512]u8 = undefined;
    const url = try http.Url.parse("http://other.example/");
    const hdrs = [_]http.Header{.{ .name = "Authorization", .value = "Bearer secret" }};

    var w: std.Io.Writer = .fixed(&buf);
    try writeRequestHead(&w, .get, url, &hdrs, "a", .none, false, true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization: Bearer secret") != null);

    w = .fixed(&buf);
    try writeRequestHead(&w, .get, url, &hdrs, "a", .none, true, true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization") == null);
}

test "crossOrigin: scheme, host and port must ALL match (CVE-2018-18074 class)" {
    const base = try http.Url.parse("https://example.com/a");

    // Same origin, different path/query — not cross-origin.
    try testing.expect(!crossOrigin(base, try http.Url.parse("https://example.com/b?x=1")));
    // Host comparison is case-insensitive (DNS names).
    try testing.expect(!crossOrigin(base, try http.Url.parse("https://EXAMPLE.com/a")));
    // Explicit default port == implicit default port (both normalized by Url.parse).
    try testing.expect(!crossOrigin(base, try http.Url.parse("https://example.com:443/a")));

    // Same host, scheme downgrade https→http — cross-origin (must strip).
    try testing.expect(crossOrigin(base, try http.Url.parse("http://example.com/a")));
    // Same host+scheme, different (non-default) port — cross-origin.
    try testing.expect(crossOrigin(base, try http.Url.parse("https://example.com:8443/a")));
    // Different host entirely — cross-origin.
    try testing.expect(crossOrigin(base, try http.Url.parse("https://other.example/a")));
}

test "writeRequestHead: Authorization and Cookie both stripped on cross-origin redirect, both kept on same-origin" {
    var buf: [512]u8 = undefined;
    const url = try http.Url.parse("http://other.example/");
    const hdrs = [_]http.Header{
        .{ .name = "Authorization", .value = "Bearer secret" },
        .{ .name = "Cookie", .value = "session=abc123" },
    };

    // Same-origin hop: both credential headers are forwarded.
    var w: std.Io.Writer = .fixed(&buf);
    try writeRequestHead(&w, .get, url, &hdrs, "a", .none, false, true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization: Bearer secret") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Cookie: session=abc123") != null);

    // Cross-origin hop: both are dropped (session-cookie / API-key leak
    // otherwise — Cookie is just as sensitive as Authorization here).
    w = .fixed(&buf);
    try writeRequestHead(&w, .get, url, &hdrs, "a", .none, true, true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization") == null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Cookie") == null);
}

test "writeRequestHead: a caller's Host and Proxy-Authorization do not survive a cross-origin hop either (A1 G3/G4)" {
    // Measured before the fix over two loopback hops: `Host: vhost.internal`
    // and `Proxy-Authorization: Basic SECRET` both arrived at the second
    // origin, while Authorization/Cookie were correctly gone — the strip
    // list had two names and `custom_host` was computed once for every hop.
    const url = try http.Url.parse("http://second.example:8081/final");
    const hdrs = [_]http.Header{
        .{ .name = "Host", .value = "vhost.internal" },
        .{ .name = "Proxy-Authorization", .value = "Basic SECRET" },
        .{ .name = "X-Keep", .value = "kept" },
    };
    var buf: [512]u8 = undefined;

    // Same-origin hop: the caller's Host is the vhost they asked for, and
    // the proxy credential is for the proxy in front of that origin.
    var w: std.Io.Writer = .fixed(&buf);
    try writeRequestHead(&w, .get, url, &hdrs, "a", .none, false, true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Host: vhost.internal\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Proxy-Authorization: Basic SECRET\r\n") != null);

    // Cross-origin hop: the hop's own authority as Host, no proxy credential,
    // the innocent header still there.
    w = .fixed(&buf);
    try writeRequestHead(&w, .get, url, &hdrs, "a", .none, true, true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Host: second.example:8081\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "vhost.internal") == null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Proxy-Authorization") == null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "X-Keep: kept\r\n") != null);
}

test "request(): same-host scheme downgrade and same-host port change both strip Authorization+Cookie" {
    // Exercises the same origin computation `request()` uses
    // (`crossOrigin(original_url, url)`), offline: no network needed since
    // the decision only depends on the two parsed URLs.
    const original = try http.Url.parse("https://api.example/v1");
    const hdrs = [_]http.Header{
        .{ .name = "Authorization", .value = "Bearer secret" },
        .{ .name = "Cookie", .value = "session=abc123" },
    };
    var buf: [512]u8 = undefined;

    // Same host, https → http downgrade: must strip.
    const downgraded = try http.Url.parse("http://api.example/v1");
    try testing.expect(crossOrigin(original, downgraded));
    var w: std.Io.Writer = .fixed(&buf);
    try writeRequestHead(&w, .get, downgraded, &hdrs, "a", .none, crossOrigin(original, downgraded), true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization") == null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Cookie") == null);

    // Same host+scheme, different port: must strip.
    const reported = try http.Url.parse("https://api.example:8443/v1");
    try testing.expect(crossOrigin(original, reported));
    w = .fixed(&buf);
    try writeRequestHead(&w, .get, reported, &hdrs, "a", .none, crossOrigin(original, reported), true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization") == null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Cookie") == null);

    // Truly same-origin hop (path-only change): both preserved.
    const same_origin = try http.Url.parse("https://api.example/v2");
    try testing.expect(!crossOrigin(original, same_origin));
    w = .fixed(&buf);
    try writeRequestHead(&w, .get, same_origin, &hdrs, "a", .none, crossOrigin(original, same_origin), true);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Authorization: Bearer secret") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Cookie: session=abc123") != null);
}

test "redirect chain on fabricated responses" {
    // Hop 1: parse a fabricated 301 and compute the follow-up request.
    var hop1: std.Io.Reader = .fixed("HTTP/1.1 301 Moved Permanently\r\n" ++
        "Location: /v2/data\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n");
    var head_buf: [1024]u8 = undefined;
    const head1 = try h1.ResponseHead.parse(try h1.readHead(&hop1, &head_buf));
    try testing.expectEqual(@as(u16, 301), head1.status);

    const base = try http.Url.parse("http://api.example:8080/v1/data?x=1");
    const method1 = http.redirectMethodFor(head1.status, .post).?;
    try testing.expectEqual(http.Method.get, method1); // POST → GET on 301

    var url_buf: [256]u8 = undefined;
    const next_url = try http.resolveLocation(base, head1.header("location").?, &url_buf);
    try testing.expectEqualStrings("http://api.example:8080/v2/data", next_url);

    // Hop 2: cross-host 307 — method preserved, host changes.
    var hop2: std.Io.Reader = .fixed("HTTP/1.1 307 Temporary Redirect\r\n" ++
        "Location: https://elsewhere.example/final\r\n" ++
        "\r\n");
    const head2 = try h1.ResponseHead.parse(try h1.readHead(&hop2, &head_buf));
    const method2 = http.redirectMethodFor(head2.status, .post).?;
    try testing.expectEqual(http.Method.post, method2);
    const hop2_url = try http.Url.parse(try http.resolveLocation(
        try http.Url.parse(next_url),
        head2.header("location").?,
        &url_buf,
    ));
    try testing.expectEqual(http.Url.Scheme.https, hop2_url.scheme);
    try testing.expectEqualStrings("elsewhere.example", hop2_url.host);

    // Hop 3: a 200 terminates the chain.
    var hop3: std.Io.Reader = .fixed("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    const head3 = try h1.ResponseHead.parse(try h1.readHead(&hop3, &head_buf));
    try testing.expectEqual(@as(?http.Method, null), http.redirectMethodFor(head3.status, method2));
}

test "Options.max_redirects default is 10 (G8) — the cap-on-the-chain mechanism was verified, not this value" {
    // A1 audit G8 (2026-09-04): mutating this literal 10 -> 255 left the
    // suite green — the existing coverage (`redirects` counted outside the
    // hop loop, `TooManyRedirects` at `Client.zig:448`/`:561`) exercises the
    // MECHANISM with its own small `redirects`/cap values, never this
    // shipped default.
    try testing.expectEqual(@as(u8, 10), (Options{}).max_redirects);
}

test "setupBody framing decisions on fabricated heads" {
    // Fabricate a Conn without a socket — only the fields setupBody and the
    // body readers touch.
    var src: std.Io.Reader = .fixed("5\r\nhello\r\n0\r\n\r\n");
    var body_buf: [64]u8 = undefined;
    var conn: Conn = undefined;
    conn.tls_client = null;
    conn.body_buf = &body_buf;
    // plainReader() would hand out conn.sr; give it a fixed reader instead.
    conn.sr = undefined;

    const chunked_head = try h1.ResponseHead.parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n");
    // Control: setupBody must SELECT chunked framing for this head. Without
    // this call the chunked branch of setupBody is never exercised here — the
    // body below was hand-built, so the decision under test was skipped.
    // The reader it installs points at conn.sr (not streamable in this
    // socket-free fixture), so only the selection is asserted.
    setupBody(&conn, .get, chunked_head);
    try testing.expect(conn.body == .chunked);
    // Re-point at a fixed reader to exercise the decode itself.
    conn.body = .{ .chunked = h1.ChunkedReader.init(&src, conn.body_buf) };
    var out: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    _ = try conn.body.chunked.reader.streamRemaining(&w);
    try testing.expectEqualStrings("hello", w.buffered());

    // HEAD → empty body regardless of headers.
    const cl_head = try h1.ResponseHead.parse("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n");
    setupBody(&conn, .head, cl_head);
    try testing.expect(conn.body == .none);
    setupBody(&conn, .get, try h1.ResponseHead.parse("HTTP/1.1 204 No Content\r\n"));
    try testing.expect(conn.body == .none);
    // Content-Length → limited.
    setupBody(&conn, .get, cl_head);
    try testing.expect(conn.body == .limited);
    // Neither → read-until-close.
    setupBody(&conn, .get, try h1.ResponseHead.parse("HTTP/1.1 200 OK\r\n"));
    try testing.expect(conn.body == .until_close);
}

test "connectH2c: buffer pool size mismatch is a checked error, not UB" {
    // The fail-open regression this guards: `std.debug.assert(bp.slab_size
    // == slab_len)` used to be the only thing standing between this
    // caller-config mistake and the very next lines, which slice the
    // acquired slab by fixed offset (`slab[0..read_buffer_size]`,
    // `slab[read_buffer_size..]`) with no length check of their own —
    // compiled to nothing in ReleaseFast/ReleaseSmall. This test is
    // meaningful in every optimize mode: the check now runs before any
    // allocation or I/O, so no live server is needed to exercise it.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var bp = BufferPool.init(gpa, 128, 0); // deliberately not read+write_buffer_size
    defer bp.deinit();
    var client = Client.init(io, gpa, .{
        .buffer_pool = &bp,
        .read_buffer_size = 4096,
        .write_buffer_size = 4096,
    });
    defer client.deinit();

    try testing.expectError(
        error.BufferPoolSizeMismatch,
        client.connectH2c("127.0.0.1", 1, .{}),
    );
    // The mismatch was caught before the pool (or the allocator) was ever
    // touched for this dial.
    try testing.expectEqual(@as(usize, 0), bp.checkoutCount());
}

// ── tests (h2c dogfood: our h2 client against our h2c server, loopback) ─────

const Server = @import("Server.zig");
const h2 = @import("h2.zig");

/// 200 KiB — far past the 65 535-octet initial flow-control window, so the
/// response only completes if the client keeps granting WINDOW_UPDATEs.
const huge_blocks = 200;

fn h2LoopbackHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    if (std.mem.eql(u8, req.path, "/hello")) {
        try rw.setHeader("Content-Type", "text/plain");
        try rw.writeAll("hello h2");
    } else if (std.mem.eql(u8, req.path, "/echo")) {
        var buf: [4096]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        _ = try req.reader().streamRemaining(&w);
        try rw.writeAll(w.buffered());
    } else if (std.mem.eql(u8, req.path, "/ua")) {
        // Echoes what actually arrived on the wire, so the assertion is about
        // the request the peer received and not about the option we set.
        try rw.writeAll(req.header("user-agent") orelse "(none)");
    } else if (std.mem.eql(u8, req.path, "/huge")) {
        var block: [1024]u8 = undefined;
        for (0..huge_blocks) |i| {
            @memset(&block, 'A' + @as(u8, @intCast(i % 26)));
            try rw.writeAll(&block);
        }
    } else {
        rw.setStatus(404);
        try rw.writeAll("nope");
    }
}

fn h2ServeWrap(s: *Server) void {
    s.serve() catch {};
}

fn h2LoopbackServer(io: std.Io) !*Server {
    const server = try testing.allocator.create(Server);
    errdefer testing.allocator.destroy(server);
    server.* = Server.init(io, testing.allocator, .{
        .handler = h2LoopbackHandler,
        .enable_h2c = true,
    });
    server.bind() catch |err| {
        server.deinit();
        testing.allocator.destroy(server);
        return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    };
    return server;
}

test "h2c dogfood: GET, POST and multiplexed requests on one connection (loopback)" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try h2LoopbackServer(io);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, h2ServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    const hs = client.connectH2c("127.0.0.1", port, .{}) catch |err| {
        return testkit.loopbackSkip("loopback connect failed ({t})", .{err});
    };
    defer hs.close();

    { // GET: status + headers + body.
        const sid = try hs.request(.get, "/hello", .{});
        var res = try hs.awaitResponse(sid);
        defer res.deinit(gpa);
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("text/plain", res.header("content-type").?);
        try testing.expectEqualStrings("hello h2", res.body);
    }
    { // POST: the body crosses and comes back through the shared handler.
        const sid = try hs.request(.post, "/echo", .{ .body = "h2 upload body" });
        var res = try hs.awaitResponse(sid);
        defer res.deinit(gpa);
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("h2 upload body", res.body);
    }
    { // Multiplexing: two requests in flight on the same connection before
        // either response is read; collected in reverse order, each response
        // must match its own request.
        const sid_a = try hs.request(.post, "/echo", .{ .body = "first stream" });
        const sid_b = try hs.request(.post, "/echo", .{ .body = "second stream" });
        var res_b = try hs.awaitResponse(sid_b);
        defer res_b.deinit(gpa);
        var res_a = try hs.awaitResponse(sid_a);
        defer res_a.deinit(gpa);
        try testing.expectEqualStrings("second stream", res_b.body);
        try testing.expectEqualStrings("first stream", res_a.body);
    }
    { // 404 still carries a full response (not an error).
        const sid = try hs.request(.get, "/missing", .{});
        var res = try hs.awaitResponse(sid);
        defer res.deinit(gpa);
        try testing.expectEqual(@as(u16, 404), res.status);
    }
}

test "h2c dogfood: a client-wide `user_agent` reaches HTTP/2, and a per-request one still wins (loopback)" {
    // The regression this pins: `Options.user_agent` was written by the h1
    // head writer and by nothing else, so the SAME client sent it over h1 and
    // dropped it silently over h2c — `/hello` reported `user-agent: null` for
    // us and `curl/8.x` for curl on the same route. Asserted against what the
    // server received, over a real socket, on both protocols in one test so
    // the two cannot drift apart again.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try h2LoopbackServer(io);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, h2ServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, gpa, .{ .user_agent = "ua-dogfood/9.9" });
    defer client.deinit();
    const hs = client.connectH2c("127.0.0.1", port, .{}) catch |err| {
        return testkit.loopbackSkip("loopback connect failed ({t})", .{err});
    };
    defer hs.close();

    { // The client-wide option, with no per-request header at all.
        const sid = try hs.request(.get, "/ua", .{});
        var res = try hs.awaitResponse(sid);
        defer res.deinit(gpa);
        try testing.expectEqualStrings("ua-dogfood/9.9", res.body);
    }
    { // A per-request header wins — and its NAME is matched case-insensitively,
        // even though §8.2.1 puts it on the wire lowercased, because a caller
        // writing `User-Agent` means the same thing.
        const headers = [_]http.Header{.{ .name = "User-Agent", .value = "per-request/1.0" }};
        const sid = try hs.request(.get, "/ua", .{ .headers = &headers });
        var res = try hs.awaitResponse(sid);
        defer res.deinit(gpa);
        try testing.expectEqualStrings("per-request/1.0", res.body);
    }
    { // The same client over HTTP/1.1: identical answer, which is the point.
        var url_buf: [64]u8 = undefined;
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/ua", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        const body = try res.readAllAlloc(gpa, 4096);
        defer gpa.free(body);
        try testing.expectEqualStrings("ua-dogfood/9.9", body);
    }
}

test "h2c dogfood: large response streams past the initial window (flow control, loopback)" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try h2LoopbackServer(io);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, h2ServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    const hs = client.connectH2c("127.0.0.1", port, .{}) catch |err| {
        return testkit.loopbackSkip("loopback connect failed ({t})", .{err});
    };
    defer hs.close();

    const sid = try hs.request(.get, "/huge", .{});
    var res = try hs.awaitResponse(sid);
    defer res.deinit(gpa);
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expectEqual(@as(usize, huge_blocks * 1024), res.body.len);
    for (0..huge_blocks) |i| {
        const expected: u8 = 'A' + @as(u8, @intCast(i % 26));
        try testing.expectEqual(expected, res.body[i * 1024]);
        try testing.expectEqual(expected, res.body[i * 1024 + 1023]);
    }
    // §6.9 reconciliation: every received octet was granted back, so the
    // connection receive window is back at its initial value — proof the
    // WINDOW_UPDATE path actually ran (the server could not have finished
    // a 200 KiB body inside a 64 KiB window otherwise).
    try testing.expectEqual(
        @as(i64, h2.default_initial_window_size),
        hs.session.conn.conn_recv_window,
    );
}

test "h2c dogfood: the same body read INCREMENTALLY over a real socket (loopback)" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try h2LoopbackServer(io);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, h2ServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    const hs = client.connectH2c("127.0.0.1", port, .{}) catch |err| {
        return testkit.loopbackSkip("loopback connect failed ({t})", .{err});
    };
    defer hs.close();

    // The condition the socket-free tests structurally cannot reach: a real
    // transport where one pump sees a partial frame, and a 200 KiB body that
    // only fits through a 64 KiB window if the consumption-driven
    // WINDOW_UPDATEs really leave the socket while the reader is mid-body.
    // A 4 KiB sink means the server is genuinely throttled by our reading.
    const sid = try hs.request(.get, "/huge", .{});
    const head = try hs.session.awaitHead(sid);
    try testing.expectEqual(@as(u16, 200), head.status);

    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (true) {
        const n = try hs.session.readBody(sid, &buf);
        if (n == 0) break;
        // Verify against the generator as we go, rather than buffering the
        // body — the point of reading it this way.
        for (buf[0..n], total..) |b, off| {
            try testing.expectEqual(@as(u8, 'A' + @as(u8, @intCast((off / 1024) % 26))), b);
        }
        total += n;
    }
    try testing.expectEqual(@as(usize, huge_blocks * 1024), total);
    try testing.expect(hs.session.ended(sid));
    try testing.expect(hs.session.trailers(sid) == null);
    // Every consumed octet was granted back (§6.9 reconciliation).
    try testing.expectEqual(
        @as(i64, h2.default_initial_window_size),
        hs.session.conn.conn_recv_window,
    );
    hs.session.release(sid);
}

// ── tests (BYO-TLS seam dogfood: in-memory duplex pipe, no TLS, no sockets) ──

const h2s = @import("h2_server.zig");

/// One direction of the in-memory duplex "TLS stream" stand-in: a blocking
/// byte queue with a `Reader` and a `Writer` endpoint — exactly the
/// plaintext reader/writer shape a TLS library hands out after its
/// handshake. One reader task + one writer task; `shutdown` is the
/// writer-side close (readers drain what is buffered, then EOF). Not
/// movable after the endpoints have been handed out.
const TestPipe = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    data: std.array_list.Managed(u8),
    closed: bool = false,
    reader: std.Io.Reader,
    writer: std.Io.Writer,

    fn init(io: std.Io, rbuf: []u8, wbuf: []u8) TestPipe {
        return .{
            .io = io,
            .data = .init(testing.allocator),
            .reader = .{
                .vtable = &.{ .stream = streamFn },
                .buffer = rbuf,
                .seek = 0,
                .end = 0,
            },
            .writer = .{
                .vtable = &.{ .drain = drainFn },
                .buffer = wbuf,
            },
        };
    }

    fn deinit(p: *TestPipe) void {
        p.data.deinit();
    }

    /// Writer side done: pending and future reads see EOF once drained.
    fn shutdown(p: *TestPipe) void {
        p.mutex.lockUncancelable(p.io);
        p.closed = true;
        p.cond.broadcast(p.io);
        p.mutex.unlock(p.io);
    }

    fn streamFn(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const p: *TestPipe = @alignCast(@fieldParentPtr("reader", r));
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        while (p.data.items.len == 0) {
            if (p.closed) return error.EndOfStream;
            p.cond.waitUncancelable(p.io, &p.mutex);
        }
        const n = limit.minInt(p.data.items.len);
        const sent = w.write(p.data.items[0..n]) catch return error.WriteFailed;
        const remaining = p.data.items.len - sent;
        std.mem.copyForwards(u8, p.data.items[0..remaining], p.data.items[sent..]);
        p.data.shrinkRetainingCapacity(remaining);
        return sent;
    }

    fn drainFn(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const p: *TestPipe = @alignCast(@fieldParentPtr("writer", w));
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        p.data.appendSlice(w.buffered()) catch return error.WriteFailed;
        w.end = 0;
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            p.data.appendSlice(d) catch return error.WriteFailed;
            consumed += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| p.data.appendSlice(last) catch return error.WriteFailed;
        consumed += last.len * splat;
        p.cond.signal(p.io);
        return consumed;
    }
};

/// The server side of the seam: HTTP/2 on one already-established stream,
/// exactly what a TLS accept loop calls when ALPN selected "h2".
fn tlsStandInServe(c2s: *TestPipe, s2c: *TestPipe) void {
    h2s.serveStream(testing.allocator, &c2s.reader, &s2c.writer, null, .{
        .handler = h2LoopbackHandler,
        .server_name = "h2tls",
    });
    s2c.shutdown(); // transport close after the h2 connection ended
}

test "BYO-TLS dogfood: connectH2Over ↔ serveStream over an in-memory duplex pipe" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The "TLS connection": one blocking in-memory byte queue per direction.
    // No TLS and no sockets anywhere — the seam only ever sees the plaintext
    // reader/writer pair, which is all a real TLS stream would present.
    var c2s_rbuf: [4096]u8 = undefined;
    var c2s_wbuf: [4096]u8 = undefined;
    var s2c_rbuf: [4096]u8 = undefined;
    var s2c_wbuf: [4096]u8 = undefined;
    var c2s: TestPipe = .init(io, &c2s_rbuf, &c2s_wbuf); // client → server
    defer c2s.deinit();
    var s2c: TestPipe = .init(io, &s2c_rbuf, &s2c_wbuf); // server → client
    defer s2c.deinit();

    // The caller's TLS layer negotiated ALPN (RFC 7301); dispatch on it.
    const negotiated = "h2"; // ← what the handshake would hand back
    try testing.expectEqual(http.AlpnProtocol.h2, http.protocolFromAlpn(negotiated));

    const thread = try std.Thread.spawn(.{}, tlsStandInServe, .{ &c2s, &s2c });
    defer thread.join();
    defer c2s.shutdown(); // client-side transport close (unblocks the server)

    const hs = try connectH2Over(gpa, &s2c.reader, &c2s.writer, "tls.test", .{});
    defer hs.close();

    { // GET round-trip.
        const sid = try hs.request(.get, "/hello", .{ .scheme = "https" });
        var res = try hs.awaitResponse(sid);
        defer res.deinit(gpa);
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("text/plain", res.header("content-type").?);
        try testing.expectEqualStrings("hello h2", res.body);
        try testing.expectEqualStrings("h2tls", res.header("server").?);
    }
    { // POST round-trip: the request body crosses the pipe and comes back.
        const sid = try hs.request(.post, "/echo", .{
            .scheme = "https",
            .body = "over the TLS stand-in",
        });
        var res = try hs.awaitResponse(sid);
        defer res.deinit(gpa);
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("over the TLS stand-in", res.body);
    }
    { // Two concurrent streams in flight before either response is read;
        // collected in reverse order — demux by stream id must hold.
        const sid_a = try hs.request(.post, "/echo", .{ .scheme = "https", .body = "stream A" });
        const sid_b = try hs.request(.post, "/echo", .{ .scheme = "https", .body = "stream B" });
        var res_b = try hs.awaitResponse(sid_b);
        defer res_b.deinit(gpa);
        var res_a = try hs.awaitResponse(sid_a);
        defer res_a.deinit(gpa);
        try testing.expectEqualStrings("stream B", res_b.body);
        try testing.expectEqualStrings("stream A", res_a.body);
    }
}

// ── tests (live network — skipped when unavailable) ─────────────────────────

/// A `std.Io` that behaves exactly like `inner` except that `randomSecure`
/// reports no entropy.
///
/// **The shape is the point.** The obvious double — copy the vtable and rebind
/// `userdata` to a probe struct — is unsound: `std.Io.VTable` has 109 slots at
/// Zig 0.16, and every slot left unoverridden then holds the inner
/// implementation's function pointer bound to a FOREIGN `userdata`. Nothing
/// crashes, so it survives review (see the `CountingIo` doc in `entropy`,
/// which records that hazard being hit for real). The rule it states — every
/// reachable `std.Io` function needs its own override — is unaffordable here:
/// a `Client` dial reaches most of the net, clock and async surface.
///
/// So this double inverts it. It keeps the **inner** `userdata` and replaces
/// exactly one function pointer with `std.Io.failingRandomSecure`, std's own
/// stateless implementation, whose body is `_ = userdata; return
/// error.EntropyUnavailable;`. Every other slot keeps the inner function AND
/// the inner `userdata` that function expects, so the binding is correct
/// everywhere rather than merely quiet — and the one overridden slot cannot
/// misread the pointer it is handed because it never looks at it.
/// Accepts one connection and closes it without saying anything.
const HangUpPeer = struct {
    io: std.Io,
    listener: *net.Server,

    fn run(p: *HangUpPeer) void {
        const s = p.listener.accept(p.io) catch return;
        s.close(p.io);
    }
};

const NoEntropyIo = struct {
    vtable: std.Io.VTable,
    userdata: ?*anyopaque,

    fn init(inner: std.Io) NoEntropyIo {
        var vt = inner.vtable.*;
        vt.randomSecure = std.Io.failingRandomSecure;
        return .{ .vtable = vt, .userdata = inner.userdata };
    }

    fn io(self: *const NoEntropyIo) std.Io {
        return .{ .userdata = self.userdata, .vtable = &self.vtable };
    }
};

test "dialConn: TLS key material fails CLOSED when randomSecure has no entropy" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const real_io = threaded.io();

    // A peer that accepts one connection and immediately closes it. `dialConn`
    // draws the entropy AFTER the socket is up (`:1070` connect, `:1099` draw)
    // and BEFORE a single TLS byte is written, so the passing run never needs
    // the peer to say anything — but the MUTATION does, and this is where the
    // shape was decided by measurement rather than by design:
    //
    // The first spelling used a listener that never accepted at all. With
    // `try io.randomSecure` replaced by the `io.random` this code rejects, the
    // dial walked on into the TLS handshake and blocked there **past ten
    // minutes** — and it did so with `.connect_timeout_ms` and
    // `.total_timeout_ms` both set, so those options did not bound the
    // handshake read. A mutation that hangs is not a red. Closing the
    // connection from the peer ends the handshake instead: the mutation then
    // reports `expected error.EntropyUnavailable, found error.TlsFailed`, in
    // Debug, ReleaseSafe and ReleaseFast alike.
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(real_io, .{}) catch |err| {
        return testkit.loopbackSkip("no-entropy listen failed ({t})", .{err});
    };
    defer listener.deinit(real_io);
    const port = listener.socket.address.getPort();

    // Exactly one connection is made whichever way this goes — `dialConn`
    // connects before it draws — so the peer thread always terminates.
    var peer: HangUpPeer = .{ .io = real_io, .listener = &listener };
    const peer_thread = try std.Thread.spawn(.{}, HangUpPeer.run, .{&peer});
    defer peer_thread.join();

    var no_entropy: NoEntropyIo = .init(real_io);
    // Check what the double actually does before trusting a test built on it.
    // A double that silently kept working would make everything below pass for
    // the wrong reason, and the failure mode of the unsound shape above is
    // precisely "passes quietly".
    var probe: [4]u8 = undefined;
    try testing.expectError(error.EntropyUnavailable, no_entropy.io().randomSecure(&probe));
    // The slots that were NOT overridden still work through it — and that is
    // proven by the final assertion rather than asserted here: reaching the
    // entropy draw at all means the socket, the DNS path and the clock all ran
    // through this `Io` first. A broken one answers `ConnectFailed`, which is
    // what distinguishes this double from `std.Io.failing` (whose network is
    // down, so the dial never reaches the draw).

    // `insecure_no_verify` keeps the CA bundle out of it: the claim under test
    // is the entropy draw, not certificate verification. The timeouts are a
    // belt-and-braces bound only — measured NOT to bound the handshake read
    // (see the peer comment above); the peer's hang-up is what does.
    var client = Client.init(no_entropy.io(), gpa, .{
        .tls = .{ .verify = .insecure_no_verify },
        .connect_timeout_ms = 2000,
        .total_timeout_ms = 3000,
    });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/", .{port});

    // Fail-closed: the documented contract of `Error.EntropyUnavailable`. The
    // alternative the code rejects is `io.random`, which "is seeded by
    // `randomSecure`, or a less secure mechanism upon failure" — it returns
    // void, so a client that used it would hand the ClientHello random and key
    // share a degraded seed with nothing to check.
    try testing.expectError(error.EntropyUnavailable, client.request(.get, url, .{}));
}

// ── tests (cancellation) ─────────────────────────────────────────────────────
//
// `Response.readAllAlloc` used to fold every body-read failure into
// `error.ReadFailed` via a bare `else` arm — a call after `Conn.readFailure`
// had already recovered `error.Canceled` from `conn.sr.err`/`.sw.err`, and
// erasing it a second time here made an `std.Io` cancelation indistinguishable
// from a dead peer. This peer answers the response head immediately
// (`Content-Length: 5`) and then sends none of the declared body, so the
// caller's body read really is parked in the kernel when the cancel arrives.

const HeadThenSilentPeer = struct {
    io: std.Io,
    listener: *net.Server,
    stop: std.atomic.Value(u32) = .init(0),
    accepted: std.atomic.Value(u32) = .init(0),

    fn run(p: *HeadThenSilentPeer) void {
        const s = p.listener.accept(p.io) catch return;
        p.accepted.store(1, .release);
        defer s.close(p.io);
        var rbuf: [1024]u8 = undefined;
        var wbuf: [1024]u8 = undefined;
        var sr = s.reader(p.io, &rbuf);
        var sw = s.writer(p.io, &wbuf);
        var head_buf: [1024]u8 = undefined;
        _ = h1.readHead(&sr.interface, &head_buf) catch {};
        sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n") catch {};
        sw.interface.flush() catch {};
        // Hold the connection open with no body bytes ever sent, until the
        // test is done with it — closing early would hand the client a clean
        // `EndOfStream` instead of leaving the read genuinely parked.
        while (p.stop.load(.acquire) == 0)
            p.io.sleep(.fromMilliseconds(5), .awake) catch return;
    }

    fn release(p: *HeadThenSilentPeer, port: u16) void {
        releaseCancelPeer(p.io, &p.stop, &p.accepted, port);
    }
};

/// Stop a cancel-test peer thread so it can be joined. A test that cancels a
/// concurrent client call can cancel it BEFORE it dials: `Syscall.start`
/// returns `error.Canceled` ahead of `connect`, so the client never reaches
/// the listener, the peer stays blocked in `accept` — a plain thread no
/// `stop` flag and no `std.Io` cancelation can reach — and the test's
/// `defer peer_thread.join()` waits forever. Measured 2026-09-15: the full
/// gate reported `request: a canceled request-head write …` as a 3-minute
/// timeout, and a probe that moved the cancel ahead of the dial hung 4/4 with
/// the peer thread in `inet_csk_accept`, the listener's accept queue empty
/// and `fut.cancel` having already returned `Canceled`. So poke `accept` with
/// one throwaway connection whenever it has not returned yet (the same fix
/// `StallPeer.release` carries).
fn releaseCancelPeer(io: std.Io, stop: *std.atomic.Value(u32), accepted: *std.atomic.Value(u32), port: u16) void {
    stop.store(1, .release);
    if (accepted.load(.acquire) != 0) return;
    const addr = net.IpAddress.parse("127.0.0.1", port) catch return;
    const s = addr.connect(io, .{ .mode = .stream }) catch return;
    s.close(io);
}

/// Poll for a flag a peer thread sets. The deadline is a watchdog, never the
/// synchronization: it turns a client that never reaches the peer into a red
/// instead of a hang. Returns whether the flag was seen.
fn awaitPeerFlag(io: std.Io, flag: *const std.atomic.Value(u32), watchdog_ms: i64) bool {
    const start = testNowMs(io);
    while (flag.load(.acquire) == 0) {
        if (testNowMs(io) - start > watchdog_ms) return false;
        io.sleep(.fromMilliseconds(1), .awake) catch return flag.load(.acquire) != 0;
    }
    return true;
}

fn readAllAllocOnce(res: *Response, gpa: std.mem.Allocator) Error![]u8 {
    return res.readAllAlloc(gpa, 64);
}

test "readAllAlloc: a canceled body read surfaces Canceled, not ReadFailed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("readAllAlloc cancel test listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var peer: HeadThenSilentPeer = .{ .io = io, .listener = &listener };
    const peer_thread = try std.Thread.spawn(.{}, HeadThenSilentPeer.run, .{&peer});
    defer peer_thread.join();
    defer peer.release(port);

    // Pooling off: a canceled connection must be destroyed, not recycled, and
    // that path is exercised elsewhere — keeping it out here isolates the one
    // property under test.
    var client = Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false } });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var res = try client.request(.get, url, .{});
    defer res.deinit();

    var fut = try io.concurrent(readAllAllocOnce, .{ &res, testing.allocator });
    // Long enough that the body read is certainly parked in the kernel.
    try io.sleep(.fromMilliseconds(200), .awake);
    try testing.expectError(error.Canceled, fut.cancel(io));
}

fn getToFileOnce(c: *Client, url: []const u8, dir: std.Io.Dir, sub_path: []const u8) Error!u64 {
    return c.getToFile(url, dir, sub_path);
}

// `getToFile` had the identical `else`-arm collapse `readAllAlloc` had (both
// catch the same `Reader.StreamRemainingError`) — same peer shape reused.
test "getToFile: a canceled body read surfaces Canceled, not ReadFailed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("getToFile cancel test listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var peer: HeadThenSilentPeer = .{ .io = io, .listener = &listener };
    const peer_thread = try std.Thread.spawn(.{}, HeadThenSilentPeer.run, .{&peer});
    defer peer_thread.join();
    defer peer.release(port);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var client = Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false } });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var fut = try io.concurrent(getToFileOnce, .{ &client, url, tmp.dir, "out.bin" });
    try io.sleep(.fromMilliseconds(200), .awake);
    try testing.expectError(error.Canceled, fut.cancel(io));
}

// The write-side counterpart: a peer that accepts and never reads a single
// byte, so a client body (or, with padded headers, a request head) big
// enough to overrun the kernel's send/receive buffers genuinely parks in a
// `write`, not merely in a wait for a response that never comes. RCVBUF is
// shrunk so a modest payload is enough to fill the pipe quickly.
const SilentReadPeer = struct {
    io: std.Io,
    listener: *net.Server,
    stop: std.atomic.Value(u32) = .init(0),
    accepted: std.atomic.Value(u32) = .init(0),
    /// Set once the first request byte has arrived (or the client hung up
    /// before sending one). THIS, not a sleep, is when the tests below cancel.
    /// A fixed sleep assumed the client dials and starts writing inside it;
    /// under the full gate's load the 16 MiB header validation that precedes
    /// the dial alone (~85 ms of CPU in Debug) can outlast a 300 ms window,
    /// and a cancel that lands before the dial both hung the test (see
    /// `releaseCancelPeer`) and would have passed by the wrong route —
    /// `Canceled` from `connect`, with the head-write recovery under test
    /// never reached. With a byte already here the client is past its dial
    /// and inside the request write, which the payload is too big to finish
    /// against this starved receiver.
    receiving: std.atomic.Value(u32) = .init(0),

    fn run(p: *SilentReadPeer) void {
        const s = p.listener.accept(p.io) catch return;
        p.accepted.store(1, .release);
        defer s.close(p.io);
        const small = std.mem.toBytes(@as(c_int, 2048));
        std.posix.setsockopt(s.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, &small) catch {};
        var one: [1]u8 = undefined;
        var sr = s.reader(p.io, &one);
        _ = sr.interface.takeByte() catch {};
        p.receiving.store(1, .release);
        while (p.stop.load(.acquire) == 0)
            p.io.sleep(.fromMilliseconds(5), .awake) catch return;
    }

    fn release(p: *SilentReadPeer, port: u16) void {
        releaseCancelPeer(p.io, &p.stop, &p.accepted, port);
    }
};

/// How long a cancel test waits for its peer before giving up with a red.
/// Only a watchdog — see `awaitPeerFlag`; well under the gate's 3-minute
/// per-test limit so a regression reports as a failure, not a timeout.
const cancel_peer_watchdog_ms = 60_000;

fn putFileOnce(c: *Client, url: []const u8, dir: std.Io.Dir, sub_path: []const u8) Error!u16 {
    return c.putFile(url, dir, sub_path, .{});
}

test "putFile: a canceled body write surfaces Canceled, not WriteFailed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("putFile cancel test listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var peer: SilentReadPeer = .{ .io = io, .listener = &listener };
    const peer_thread = try std.Thread.spawn(.{}, SilentReadPeer.run, .{&peer});
    defer peer_thread.join();
    defer peer.release(port);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // Large enough to overrun the shrunk receive window plus the OS's
    // default send buffer and genuinely block, without needing several
    // seconds to write on loopback.
    {
        var f = try tmp.dir.createFile(io, "upload.bin", .{});
        defer f.close(io);
        var wbuf: [64 * 1024]u8 = undefined;
        var fw = f.writer(io, &wbuf);
        const chunk: [64 * 1024]u8 = @splat('x');
        var left: usize = 4 << 20; // 4 MiB
        while (left != 0) : (left -= chunk.len) try fw.interface.writeAll(&chunk);
        try fw.interface.flush();
    }

    var client = Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false } });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var fut = try io.concurrent(putFileOnce, .{ &client, url, tmp.dir, "upload.bin" });
    // Cancel once the peer holds a request byte (see `SilentReadPeer.receiving`):
    // the client is then past its dial and inside the upload.
    const reached = awaitPeerFlag(io, &peer.receiving, cancel_peer_watchdog_ms);
    const result = fut.cancel(io);
    try testing.expect(reached);
    try testing.expectError(error.Canceled, result);
}

/// The local file operation `CancelInFileIo` turns into a pure cancelation
/// point.
const FileOp = enum { open, create, stat, read, write };

/// An `Io` in which ONE local file operation is nothing but a cancelation
/// point that waits for its cancel — so a test can put the cancel INSIDE that
/// operation deterministically, instead of hoping the scheduler lands it
/// there (under load it did, 5/25, which is how `putFile`'s collapse of a
/// canceled file read into `ReadFailed` was found, A1 G12; G13 is the same
/// collapse in open/create/stat/write). Same shape as `NoEntropyIo`: the
/// inner `userdata` is kept and exactly one slot is replaced, so every other
/// slot stays correctly bound. The replacement calls the INNER `checkCancel`
/// with that same `userdata`, which is precisely what the real call's
/// `Syscall.start` would have consulted.
fn CancelInFileIo(comptime op: FileOp) type {
    return struct {
        vtable: std.Io.VTable,
        userdata: ?*anyopaque,

        const Self = @This();
        var inner_vtable: *const std.Io.VTable = undefined;
        var entered: std.atomic.Value(u32) = .init(0);

        fn init(inner: std.Io) Self {
            inner_vtable = inner.vtable;
            entered.store(0, .release);
            var vt = inner.vtable.*;
            switch (op) {
                .open => vt.dirOpenFile = dirOpenFile,
                .create => vt.dirCreateFile = dirCreateFile,
                .stat => vt.fileStat = fileStat,
                .read => vt.fileReadPositional = fileReadPositional,
                .write => vt.fileWritePositional = fileWritePositional,
            }
            return .{ .vtable = vt, .userdata = inner.userdata };
        }

        fn io(self: *const Self) std.Io {
            return .{ .userdata = self.userdata, .vtable = &self.vtable };
        }

        fn park(userdata: ?*anyopaque) std.Io.Cancelable!noreturn {
            entered.store(1, .release);
            while (true) {
                try inner_vtable.checkCancel(userdata);
                std.atomic.spinLoopHint();
            }
        }

        fn dirOpenFile(userdata: ?*anyopaque, _: std.Io.Dir, _: []const u8, _: std.Io.Dir.OpenFileOptions) std.Io.File.OpenError!std.Io.File {
            try park(userdata);
        }

        fn dirCreateFile(userdata: ?*anyopaque, _: std.Io.Dir, _: []const u8, _: std.Io.Dir.CreateFileOptions) std.Io.File.OpenError!std.Io.File {
            try park(userdata);
        }

        fn fileStat(userdata: ?*anyopaque, _: std.Io.File) std.Io.File.StatError!std.Io.File.Stat {
            try park(userdata);
        }

        fn fileReadPositional(userdata: ?*anyopaque, _: std.Io.File, _: []const []u8, _: u64) std.Io.File.ReadPositionalError!usize {
            try park(userdata);
        }

        fn fileWritePositional(userdata: ?*anyopaque, _: std.Io.File, _: []const u8, _: []const []const u8, _: usize, _: u64) std.Io.File.WritePositionalError!usize {
            try park(userdata);
        }
    };
}

fn putFileVia(comptime plain: bool) fn (*Client, []const u8, std.Io.Dir, []const u8) Error!u16 {
    return struct {
        fn call(c: *Client, url: []const u8, dir: std.Io.Dir, sub_path: []const u8) Error!u16 {
            return if (plain) c.putFilePlain(url, dir, sub_path, .{}) else c.putFile(url, dir, sub_path, .{});
        }
    }.call;
}

test "putFile + putFilePlain: a cancel inside the local file read surfaces Canceled, not ReadFailed" {
    inline for (.{ false, true }) |plain| {
        var threaded = std.Io.Threaded.init(testing.allocator, .{});
        defer threaded.deinit();
        const real_io = threaded.io();

        const addr = try net.IpAddress.parse("127.0.0.1", 0);
        var listener = addr.listen(real_io, .{}) catch |err| {
            return testkit.loopbackSkip("file-read cancel test listen failed ({t})", .{err});
        };
        defer listener.deinit(real_io);
        const port = listener.socket.address.getPort();

        var peer: SilentReadPeer = .{ .io = real_io, .listener = &listener };
        const peer_thread = try std.Thread.spawn(.{}, SilentReadPeer.run, .{&peer});
        defer peer_thread.join();
        defer peer.release(port);

        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var f = try tmp.dir.createFile(real_io, "upload.bin", .{});
            defer f.close(real_io);
            try f.writeStreamingAll(real_io, "0123456789abcdef");
        }

        const Double = CancelInFileIo(.read);
        var double: Double = .init(real_io);
        var client = Client.init(double.io(), testing.allocator, .{ .pool = .{ .enabled = false } });
        defer client.deinit();
        var url_buf: [64]u8 = undefined;
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

        var fut = try real_io.concurrent(putFileVia(plain), .{ &client, url, tmp.dir, "upload.bin" });
        const reached = awaitPeerFlag(real_io, &Double.entered, cancel_peer_watchdog_ms);
        const result = fut.cancel(real_io);
        if (!reached) std.debug.print("file-read cancel test (plain={}): the upload never reached its file read\n", .{plain});
        try testing.expect(reached);
        testing.expectError(error.Canceled, result) catch |e| {
            std.debug.print("file-read cancel test (plain={}) failed\n", .{plain});
            return e;
        };
    }
}

// A1 G13: `putFile*` opens and stats the source file BEFORE dialing, so the
// cancel lands before any request exists and no peer is needed. The URL's
// port is never reached.
test "putFile + putFilePlain: a cancel inside opening or stat-ing the local file surfaces Canceled, not ReadFailed" {
    inline for (.{ FileOp.open, FileOp.stat }) |op| {
        inline for (.{ false, true }) |plain| {
            var threaded = std.Io.Threaded.init(testing.allocator, .{});
            defer threaded.deinit();
            const real_io = threaded.io();

            var tmp = testing.tmpDir(.{});
            defer tmp.cleanup();
            {
                var f = try tmp.dir.createFile(real_io, "upload.bin", .{});
                defer f.close(real_io);
                try f.writeStreamingAll(real_io, "0123456789abcdef");
            }

            const Double = CancelInFileIo(op);
            var double: Double = .init(real_io);
            var client = Client.init(double.io(), testing.allocator, .{ .pool = .{ .enabled = false } });
            defer client.deinit();

            var fut = try real_io.concurrent(putFileVia(plain), .{ &client, "http://127.0.0.1:9/", tmp.dir, "upload.bin" });
            const reached = awaitPeerFlag(real_io, &Double.entered, cancel_peer_watchdog_ms);
            const result = fut.cancel(real_io);
            if (!reached) std.debug.print("local file {t} cancel test (plain={}): the upload never reached it\n", .{ op, plain });
            try testing.expect(reached);
            testing.expectError(error.Canceled, result) catch |e| {
                std.debug.print("local file {t} cancel test (plain={}) failed\n", .{ op, plain });
                return e;
            };
        }
    }
}

/// Answers one request with a 200 whose whole `Content-Length` body it sends,
/// then holds the connection until released — so `getToFile` gets past its
/// status check into its local file create and write.
const HeadAndBodyPeer = struct {
    io: std.Io,
    listener: *net.Server,
    body_len: usize,
    stop: std.atomic.Value(u32) = .init(0),
    accepted: std.atomic.Value(u32) = .init(0),

    fn run(p: *HeadAndBodyPeer) void {
        const s = p.listener.accept(p.io) catch return;
        p.accepted.store(1, .release);
        defer s.close(p.io);
        var rbuf: [1024]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var sr = s.reader(p.io, &rbuf);
        var sw = s.writer(p.io, &wbuf);
        var head_buf: [1024]u8 = undefined;
        _ = h1.readHead(&sr.interface, &head_buf) catch {};
        sw.interface.print("HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n", .{p.body_len}) catch {};
        const chunk: [4096]u8 = @splat('x');
        var left = p.body_len;
        while (left != 0) {
            const k = @min(left, chunk.len);
            sw.interface.writeAll(chunk[0..k]) catch break;
            left -= k;
        }
        sw.interface.flush() catch {};
        while (p.stop.load(.acquire) == 0)
            p.io.sleep(.fromMilliseconds(5), .awake) catch return;
    }

    fn release(p: *HeadAndBodyPeer, port: u16) void {
        releaseCancelPeer(p.io, &p.stop, &p.accepted, port);
    }
};

// A1 G13. `body_len` picks which `getToFile` site the parked write is in: 5
// bytes fit its 64 KiB file buffer, so the write happens in the final
// `flush`; 100 KiB overruns it, so the write happens inside
// `streamRemaining`.
test "getToFile: a cancel inside creating, writing or flushing the local file surfaces Canceled, not WriteFailed" {
    const cases = .{
        .{ .op = FileOp.create, .body_len = 5, .site = "createFile" },
        .{ .op = FileOp.write, .body_len = 100 * 1024, .site = "streamRemaining" },
        .{ .op = FileOp.write, .body_len = 5, .site = "flush" },
    };
    inline for (cases) |case| {
        var threaded = std.Io.Threaded.init(testing.allocator, .{});
        defer threaded.deinit();
        const real_io = threaded.io();

        const addr = try net.IpAddress.parse("127.0.0.1", 0);
        var listener = addr.listen(real_io, .{}) catch |err| {
            return testkit.loopbackSkip("local file cancel test listen failed ({t})", .{err});
        };
        defer listener.deinit(real_io);
        const port = listener.socket.address.getPort();

        var peer: HeadAndBodyPeer = .{ .io = real_io, .listener = &listener, .body_len = case.body_len };
        const peer_thread = try std.Thread.spawn(.{}, HeadAndBodyPeer.run, .{&peer});
        defer peer_thread.join();
        defer peer.release(port);

        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();

        const Double = CancelInFileIo(case.op);
        var double: Double = .init(real_io);
        var client = Client.init(double.io(), testing.allocator, .{ .pool = .{ .enabled = false } });
        defer client.deinit();
        var url_buf: [64]u8 = undefined;
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

        var fut = try real_io.concurrent(getToFileOnce, .{ &client, url, tmp.dir, "out.bin" });
        const reached = awaitPeerFlag(real_io, &Double.entered, cancel_peer_watchdog_ms);
        const result = fut.cancel(real_io);
        if (!reached) std.debug.print("local file cancel test ({s}): the download never reached it\n", .{case.site});
        try testing.expect(reached);
        testing.expectError(error.Canceled, result) catch |e| {
            std.debug.print("local file cancel test ({s}) failed\n", .{case.site});
            return e;
        };
    }
}

fn requestOnce(c: *Client, url: []const u8, options: RequestOptions) Error!Response {
    return c.request(.get, url, options);
}

// The defect this guards is upstream of the body: `sendAndReadHead`'s call
// to `writeRequestHead` used a bare `try`, so a cancelation during the
// *head* write (before any body byte) surfaced as plain `WriteFailed` no
// matter how deliberately `Conn.writeFailure` recovered `Canceled` two
// lines below it. Worse than the read-side collapses above: `WriteFailed`
// is exactly what `isStaleConnError` treats as a dead pooled connection
// worth silently retrying — see `requestInner`'s retry comment on why a
// spent cancelation must never reach that check. A padded header, not a
// body, is what fills the pipe here, to isolate the head-write path
// specifically from the (already-correct) body-write line beside it.
test "request: a canceled request-head write surfaces Canceled, not WriteFailed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("request head-write cancel test listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var peer: SilentReadPeer = .{ .io = io, .listener = &listener };
    const peer_thread = try std.Thread.spawn(.{}, SilentReadPeer.run, .{&peer});
    defer peer_thread.join();
    defer peer.release(port);

    // Well past the kernel's `tcp_wmem` autotuning ceiling (4 MiB on this
    // host, which a smaller padding was observed to fit under entirely
    // without ever blocking) — heap-allocated, not stack: too big for a
    // test thread's stack.
    const padding = try testing.allocator.alloc(u8, 16 << 20);
    defer testing.allocator.free(padding);
    @memset(padding, 'x');

    // `total_timeout_ms = 0`: with the (30 s) default, `request` routes
    // through `runBounded`, whose OWN cancelation handling — already
    // correct, unrelated to this fix — would report `error.Canceled`
    // regardless of what `sendAndReadHead` does. Zeroing it makes `request`
    // call `requestInner` directly on *this* task, so the cancelation this
    // test issues is the one that has to reach the blocked write itself.
    var client = Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false }, .total_timeout_ms = 0 });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});
    const headers = [_]http.Header{.{ .name = "X-Pad", .value = padding }};

    var fut = try io.concurrent(requestOnce, .{ &client, url, RequestOptions{ .headers = &headers } });
    // Cancel once the peer holds a head byte (see `SilentReadPeer.receiving`),
    // never after a fixed sleep: the cancel has to land in the head write,
    // not ahead of the dial where it would pass without exercising it.
    const reached = awaitPeerFlag(io, &peer.receiving, cancel_peer_watchdog_ms);
    const result = fut.cancel(io);
    try testing.expect(reached);
    try testing.expectError(error.Canceled, result);
}

fn requestStreamingOnce(c: *Client, url: []const u8, options: RequestOptions) Error!Upload {
    return c.requestStreaming(.put, url, options, 5);
}

// `requestStreaming`'s own head-write catch had the identical bug
// `sendAndReadHead` did, with a sharper consequence: since
// `writeRequestHead` can only ever report `error.WriteFailed`, a canceled
// head write on a fresh (non-reused) connection used to be indistinguishable
// from any other write failure — harmless here only because `!reused` short
// circuits the retry. `requestStreaming` doesn't route through `runBounded`
// (unlike `request`), so no `total_timeout_ms` override is needed for this
// task's own cancelation to reach the blocked write directly.
test "requestStreaming: a canceled request-head write surfaces Canceled, not WriteFailed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("requestStreaming head-write cancel test listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var peer: SilentReadPeer = .{ .io = io, .listener = &listener };
    const peer_thread = try std.Thread.spawn(.{}, SilentReadPeer.run, .{&peer});
    defer peer_thread.join();
    defer peer.release(port);

    const padding = try testing.allocator.alloc(u8, 16 << 20);
    defer testing.allocator.free(padding);
    @memset(padding, 'x');

    var client = Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false } });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});
    const headers = [_]http.Header{.{ .name = "X-Pad", .value = padding }};

    var fut = try io.concurrent(requestStreamingOnce, .{ &client, url, RequestOptions{ .headers = &headers } });
    const reached = awaitPeerFlag(io, &peer.receiving, cancel_peer_watchdog_ms);
    const result = fut.cancel(io);
    try testing.expect(reached);
    try testing.expectError(error.Canceled, result);
}

// ── tests (timeout enforcement) ─────────────────────────────────────────────
//
// Every test here asserts the SAME property from a different blocking phase:
// an unresponsive peer must produce `error.Timeout` inside the configured
// budget. Each one runs the client call on its own task under a hard
// watchdog several times that budget, so a client that enforces nothing makes
// these RED rather than making the suite hang — a hung test is worse than a
// failing one, and every scenario below was measured hanging past 25 s (and
// once past ten minutes, see the `NoEntropyIo` test's comment) before the
// enforcement existed.

fn testNowMs(io: std.Io) i64 {
    const ts = std.Io.Clock.Timestamp.now(io, .awake);
    return @intCast(@divTrunc(ts.raw.nanoseconds, std.time.ns_per_ms));
}

/// A peer that completes the TCP handshake and then says nothing at all.
/// It holds the accepted connection OPEN until released: closing it would
/// hand the client an end-of-stream and end the wait for the wrong reason
/// (which is precisely the shape the `NoEntropyIo` test above relies on, from
/// the other side).
const StallPeer = struct {
    io: std.Io,
    listener: *net.Server,
    stop: std.atomic.Value(u32) = .init(0),
    accepted: std.atomic.Value(u32) = .init(0),

    fn run(p: *StallPeer) void {
        const s = p.listener.accept(p.io) catch return;
        _ = p.accepted.fetchAdd(1, .monotonic);
        defer s.close(p.io);
        while (p.stop.load(.acquire) == 0)
            p.io.sleep(.fromMilliseconds(5), .awake) catch return;
    }

    /// Release the peer thread before joining it. If the client never
    /// connected at all — a regression that fails before the dial — `accept`
    /// is still blocked and the join would hang, so poke it with one
    /// throwaway connection.
    fn release(p: *StallPeer, port: u16) void {
        p.stop.store(1, .release);
        if (p.accepted.load(.acquire) != 0) return;
        const addr = net.IpAddress.parse("127.0.0.1", port) catch return;
        const s = addr.connect(p.io, .{ .mode = .stream }) catch return;
        s.close(p.io);
    }
};

fn watchdogGet(c: *Client, url: []const u8) anyerror!void {
    var res = try c.request(.get, url, .{});
    res.deinit();
}

fn watchdogUploadFinish(c: *Client, url: []const u8) anyerror!void {
    var up = try c.requestStreaming(.post, url, .{}, "ping".len);
    up.writer().writeAll("ping") catch {
        up.abort();
        return error.WriteFailed;
    };
    var res = try up.finish();
    res.deinit();
}

/// One client call, run on its own task with a HARD outer bound.
///
/// The watchdog is many times the client budget under test, so `hung ==
/// false` is a statement about the client's enforcement rather than about the
/// watchdog's generosity. Note the watchdog cannot be built out of the thing
/// it is watching: it races the call from *outside* the client, on the test's
/// own `Io`, and its verdict (`hung`) is written by the waiter before the
/// canceled task gets to overwrite `outcome`.
const Watchdog = struct {
    io: std.Io,
    client: *Client,
    url: []const u8,
    call: *const fn (*Client, []const u8) anyerror!void,

    /// Written by the task, read only after it has been joined.
    outcome: ?anyerror = null,
    elapsed_ms: i64 = 0,
    state: std.atomic.Value(u32) = .init(0),
    /// Written by the WAITER, never by the task: the call did not return
    /// inside the watchdog budget.
    hung: bool = false,

    fn run(w: *Watchdog) void {
        const t0 = testNowMs(w.io);
        w.call(w.client, w.url) catch |err| {
            w.outcome = err;
        };
        w.elapsed_ms = testNowMs(w.io) - t0;
        w.state.store(1, .release);
        w.io.futexWake(u32, &w.state.raw, 1);
    }

    fn go(w: *Watchdog, watchdog_ms: u32) !void {
        const io = w.io;
        // Not a skip: the client documents its budgets as unenforceable
        // without a unit of concurrency, so a host that cannot give the TEST
        // one has not verified anything and must say so out loud.
        var future = try io.concurrent(Watchdog.run, .{w});
        const deadline: std.Io.Clock.Timestamp =
            .fromNow(io, .{ .raw = .fromMilliseconds(watchdog_ms), .clock = .awake });
        while (w.state.load(.acquire) == 0) {
            if (deadline.durationFromNow(io).raw.nanoseconds <= 0) break;
            io.futexWaitTimeout(u32, &w.state.raw, 0, .{ .deadline = deadline }) catch break;
        }
        if (w.state.load(.acquire) != 0) {
            future.await(io);
            return;
        }
        w.hung = true;
        // Interrupt the wedged call so the test binary can still finish and
        // report. The task will go on to write `outcome`; `hung` is what the
        // assertions read.
        future.cancel(io);
    }
};

/// Assert the shared property: not hung, and `error.Timeout` well inside the
/// watchdog.
fn expectTimedOut(w: *const Watchdog, budget_ms: i64) !void {
    try testing.expect(!w.hung);
    try testing.expectEqual(@as(?anyerror, error.Timeout), w.outcome);
    // Enforced, not merely eventual. Ten times the budget is loose enough for
    // a loaded CI box and still an order of magnitude under the watchdog.
    try testing.expect(w.elapsed_ms < budget_ms * 10);
}

test "timeout: total_timeout_ms bounds a stalling peer (plain http)" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{});
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var peer: StallPeer = .{ .io = io, .listener = &listener };
    const peer_thread = try std.Thread.spawn(.{}, StallPeer.run, .{&peer});
    defer peer_thread.join();
    defer peer.release(port);

    // `connect_timeout_ms = 0` removes the alternative explanation: the dial
    // to a listening loopback socket completes instantly and has no budget of
    // its own, so the only thing that can end this request is the total one.
    // Plain http also keeps TLS out of it — this is a bare response-head read.
    var client = Client.init(io, gpa, .{ .connect_timeout_ms = 0, .total_timeout_ms = 300 });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var w: Watchdog = .{ .io = io, .client = &client, .url = url, .call = watchdogGet };
    try w.go(8000);
    try expectTimedOut(&w, 300);
}

test "timeout: total_timeout_ms bounds a stalling peer during the TLS handshake" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{});
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var peer: StallPeer = .{ .io = io, .listener = &listener };
    const peer_thread = try std.Thread.spawn(.{}, StallPeer.run, .{&peer});
    defer peer_thread.join();
    defer peer.release(port);

    // The peer never answers the ClientHello, so this blocks inside
    // `tls.Client.init` — a phase with no deadline parameter anywhere in std,
    // reached before a single byte of HTTP exists. `insecure_no_verify` keeps
    // the CA bundle out of the measurement.
    var client = Client.init(io, gpa, .{
        .tls = .{ .verify = .insecure_no_verify },
        .connect_timeout_ms = 0,
        .total_timeout_ms = 300,
    });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/", .{port});

    var w: Watchdog = .{ .io = io, .client = &client, .url = url, .call = watchdogGet };
    try w.go(8000);
    try expectTimedOut(&w, 300);
}

test "timeout: total_timeout_ms bounds Upload.finish against a stalling peer" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{});
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var peer: StallPeer = .{ .io = io, .listener = &listener };
    const peer_thread = try std.Thread.spawn(.{}, StallPeer.run, .{&peer});
    defer peer_thread.join();
    defer peer.release(port);

    // The streaming path never goes through `request`, so it needed its own
    // bound: the dial and the head write succeed, and `finish` then waits on
    // a response head that never comes.
    var client = Client.init(io, gpa, .{ .connect_timeout_ms = 0, .total_timeout_ms = 300 });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var w: Watchdog = .{ .io = io, .client = &client, .url = url, .call = watchdogUploadFinish };
    try w.go(8000);
    try expectTimedOut(&w, 300);
}

fn testConnectOnce(io: std.Io, target: net.IpAddress) Error!net.Stream {
    return target.connect(io, .{ .mode = .stream }) catch |err| mapConnectError(err);
}

/// Connect to `target` until a further connect genuinely BLOCKS — i.e. until
/// the listener's accept queue is full and the kernel starts dropping the
/// SYN. Returns how many sockets the caller must close.
///
/// The exact queue depth is a kernel property, not a constant worth
/// hard-coding: measured here as 2 for `kernel_backlog = 1` on Linux
/// loopback, but a kernel that behaves differently must make the caller RED,
/// not quietly test a connect that in fact completed. Hence the error at the
/// end rather than a `return n`.
fn fillAcceptQueue(io: std.Io, target: net.IpAddress, held: []net.Stream) !usize {
    for (held, 0..) |*slot, n| {
        const d: std.Io.Clock.Timestamp = .fromNow(io, .{ .raw = .fromMilliseconds(250), .clock = .awake });
        slot.* = runBounded(io, false, d, testConnectOnce, .{ io, target }) catch |err| switch (err) {
            error.Timeout => return n,
            else => |e| return e,
        };
    }
    return error.AcceptQueueNeverFilled;
}

test "timeout: connect_timeout_ms bounds a connect the peer never accepts" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{ .kernel_backlog = 1 });
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();
    const target = try net.IpAddress.parse("127.0.0.1", port);

    // Nothing ever calls `accept` on this listener. Once its queue is full
    // the next `connect` sits in SYN_SENT — measured blocking past 60 s
    // against std's own `connect`, with no client involved.
    var held: [16]net.Stream = undefined;
    const held_n = try fillAcceptQueue(io, target, &held);
    defer {
        for (held[0..held_n]) |*s| s.close(io);
    }

    // `total_timeout_ms = 0` is the whole point: the only budget in play is
    // the connect one, so `error.Timeout` here cannot come from anywhere
    // else. If the dial were to complete after all, this peer never speaks
    // and the request would wedge with nothing left to bound it — the
    // watchdog would report `hung`, i.e. RED.
    var client = Client.init(io, gpa, .{ .connect_timeout_ms = 300, .total_timeout_ms = 0 });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var w: Watchdog = .{ .io = io, .client = &client, .url = url, .call = watchdogGet };
    try w.go(8000);
    try expectTimedOut(&w, 300);
}

test "timeout: an Io with no concurrency to give degrades to unbounded, not to broken" {
    // The documented hole, exercised rather than asserted. With
    // `concurrent_limit = .nothing` every `io.concurrent` fails, so NOTHING
    // here can be bounded — and nothing may be broken either: a request
    // against a responsive peer must still behave exactly as it did before
    // any of this existed. A peer that stalls *would* wedge this
    // configuration, which is why both option doc comments name it.
    //
    // `Server.serve` already reacts to the same failure the same way (serve
    // the connection inline rather than drop it, `Server.zig:455`), which is
    // also what keeps this loopback server working under that limit.
    var threaded = std.Io.Threaded.init(testing.allocator, .{ .concurrent_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();

    const server = try poolTestLoopback(io, 0);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, poolTestServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, testing.allocator, .{
        .connect_timeout_ms = 5000,
        .total_timeout_ms = 5000,
    });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    const body = try client.getAlloc(testing.allocator, url, 1 << 16);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("ok", body);
}

// ── tests (plaintext-only client: requestPlain / requestStreamingPlain / putFilePlain) ──

// What this test guarantees and what it does not: it proves requestPlain/
// requestStreamingPlain/putFilePlain reject https:// BEHAVIORALLY —
// error.UnsupportedScheme, and dialCount() stays 0 (the scheme check runs
// before acquireConnPlain, so no socket is ever opened, TLS or otherwise).
// It does NOT prove the compiled binary excludes TLS code — a Zig test only
// observes runtime behavior of one already-linked binary (the whole test
// suite, TLS included), so a symbol vanishing from the executable is not a
// thing this test, or any Zig test, can see. THAT property — the actual
// size/reachability saving this split exists for — is proved separately in
// sizeprobe/ (build two minimal executables, one importing only the
// plaintext entry points, and nm it for zero tls.Client/Certificate/curve/
// hash symbols; see its README and CHANGELOG.md's entry for the measured
// numbers). What THIS test catches is a different, real regression: someone
// routing requestPlain through acquireConn/dialConn again (e.g. "simplify
// away the duplication") — dial count would then jump on the https:// case,
// and if the target happened to be a real host it would dial TLS
// successfully instead of failing closed.
test "request/requestPlain/requestStreaming/requestStreamingPlain: a header that cannot be one line, or a URL with a byte a URI cannot hold, is refused before any dial" {
    // The outbound half of the header-injection defence (A1 G1): the
    // proxy forwards `req.iterateHeaders()` and `req.path` into this
    // client, so the client is the last place a CR/LF can be stopped
    // before it becomes a second header — or a second request — on the
    // backend's wire. Refused before `acquireConn`, so `dialCount` stays 0
    // and TEST-NET-1 is never contacted.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    const url = "http://192.0.2.1/";

    const bad_headers = [_][]const http.Header{
        &.{.{ .name = "X-Benign", .value = "v\r\nX-Injected: yes" }},
        &.{.{ .name = "X-Benign", .value = "v\nX-Injected: yes" }},
        &.{.{ .name = "X-Benign", .value = "v\x00" }},
        &.{.{ .name = "X-Benign", .value = "v\x7f" }},
        &.{.{ .name = "X-Benign\r\nX-Injected", .value = "yes" }},
        &.{.{ .name = "X Benign", .value = "v" }},
        &.{.{ .name = "X:Benign", .value = "v" }},
        &.{.{ .name = "", .value = "v" }},
        &.{ .{ .name = "X-Fine", .value = "v" }, .{ .name = "X-Bad", .value = "\r" } },
    };
    for (bad_headers) |headers| {
        try testing.expectError(error.InvalidHeader, client.request(.get, url, .{ .headers = headers }));
        try testing.expectError(error.InvalidHeader, client.requestPlain(.get, url, .{ .headers = headers }));
        try testing.expectError(error.InvalidHeader, client.requestStreaming(.put, url, .{ .headers = headers }, 0));
        try testing.expectError(error.InvalidHeader, client.requestStreamingPlain(.put, url, .{ .headers = headers }, 0));
    }
    // The URL side of the same rule is `Url.parse`'s, and it runs first.
    const bad_url = "http://192.0.2.1/a\r\nX-Path-Injected: yes\r\n\r\nGET /admin HTTP/1.1";
    try testing.expectError(error.BadUrl, client.request(.get, bad_url, .{}));
    try testing.expectError(error.BadUrl, client.requestPlain(.get, bad_url, .{}));
    try testing.expectError(error.BadUrl, client.requestStreaming(.put, bad_url, .{}, 0));
    try testing.expectError(error.BadUrl, client.requestStreamingPlain(.put, bad_url, .{}, 0));
    try testing.expectError(error.BadUrl, client.request(.get, "http://192.0.2.1/a HTTP/1.1", .{}));
    try testing.expectEqual(@as(usize, 0), client.dialCount());
}

test "requestPlain/requestStreamingPlain/putFilePlain: https:// is rejected before any dial" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();

    // Never resolved/dialed if the guard holds — RFC 5737 TEST-NET-1 would
    // hang or refuse if a real connect were attempted, which `dialCount()`
    // catches deterministically (no reliance on wall-clock timing).
    const https_url = "https://192.0.2.1/";

    try testing.expectError(error.UnsupportedScheme, client.requestPlain(.get, https_url, .{}));
    try testing.expectEqual(@as(usize, 0), client.dialCount());

    try testing.expectError(error.UnsupportedScheme, client.requestStreamingPlain(.put, https_url, .{}, 0));
    try testing.expectEqual(@as(usize, 0), client.dialCount());

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "f.txt", .data = "x" });
    try testing.expectError(error.UnsupportedScheme, client.putFilePlain(https_url, tmp.dir, "f.txt", .{}));
    try testing.expectEqual(@as(usize, 0), client.dialCount());

    // Also unsupported schemes entirely (never reaches the client at all —
    // `Url.parse` itself rejects it) behave the same way.
    try testing.expectError(error.UnsupportedScheme, client.requestPlain(.get, "ftp://192.0.2.1/", .{}));
    try testing.expectEqual(@as(usize, 0), client.dialCount());
}

test "requestPlain: a redirect to https:// fails closed instead of silently upgrading" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try testing.allocator.create(Server);
    defer testing.allocator.destroy(server);
    server.* = Server.init(io, testing.allocator, .{ .handler = plainRedirectToHttpsHandler });
    server.bind() catch |err| {
        server.deinit();
        return testkit.loopbackSkip("plaintext redirect test loopback bind failed ({t})", .{err});
    };
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, poolTestServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    try testing.expectError(error.UnsupportedScheme, client.requestPlain(.get, url, .{}));
    // The redirect hop itself dialed nothing new (this test's only dial is
    // the plaintext request that received the 302); the point under test is
    // that following it into `https://` never happens.
    try testing.expectEqual(@as(usize, 1), client.dialCount());
}

fn plainRedirectToHttpsHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    _ = req;
    rw.status = 302;
    try rw.setHeader("Location", "https://elsewhere.example/final");
    try rw.writeAll("");
}

fn refuseAllRedirects(_: ?*anyopaque, _: http.Url, _: http.Url) bool {
    return false;
}

const RecordingFilter = struct {
    calls: usize = 0,
    from_port: u16 = 0,
    to_host_buf: [64]u8 = undefined,
    to_host_len: usize = 0,
    verdict: bool,
    /// When true, also refuse the FIRST dial (`from == to`) — exercises the
    /// 2026-09-11 extension of A1 G5. Default false: the scenarios that use
    /// that default are specifically about redirect-hop gating, so the
    /// first dial is let through regardless of `verdict`, same as before
    /// that extension.
    refuse_first: bool = false,

    fn allow(ctx: ?*anyopaque, from: http.Url, to: http.Url) bool {
        const self: *RecordingFilter = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        self.from_port = from.port;
        self.to_host_len = @min(to.host.len, self.to_host_buf.len);
        @memcpy(self.to_host_buf[0..self.to_host_len], to.host[0..self.to_host_len]);
        // The first-dial call passes the exact same `Url` value for both
        // parameters (see `RedirectFilter.allow`'s doc) — a genuine redirect
        // hop's `to` is a freshly parsed `Location`, a different value even
        // when it happens to name the same host.
        const is_first_dial = from.host.ptr == to.host.ptr and from.port == to.port;
        if (is_first_dial) return !self.refuse_first;
        return self.verdict;
    }
};

test "request/requestPlain: redirect_filter gates the destination before any dial — refused means the host is never contacted (A1 G5)" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try testing.allocator.create(Server);
    defer testing.allocator.destroy(server);
    server.* = Server.init(io, testing.allocator, .{ .handler = redirectToPortOneHandler });
    server.bind() catch |err| {
        server.deinit();
        return testkit.loopbackSkip("redirect_filter test loopback bind failed ({t})", .{err});
    };
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, poolTestServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, gpa, .{ .pool = .{ .enabled = false } });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    // Refused: one dial (the request that got the 302), the target — port 1,
    // unbindable, so a dial would fail loudly — never attempted.
    var rec: RecordingFilter = .{ .verdict = false };
    const filter: RedirectFilter = .{ .ctx = &rec, .allow = RecordingFilter.allow };
    try testing.expectError(error.RedirectRefused, client.request(.get, url, .{ .redirect_filter = filter }));
    try testing.expectEqual(@as(usize, 1), client.dialCount());
    // 2 calls, not 1: the first-dial gate (A1 G5, extended 2026-09-11) fires
    // once for the original request (allowed — `refuse_first` defaults
    // false) and once more for the redirect hop (refused — `verdict`).
    try testing.expectEqual(@as(usize, 2), rec.calls);
    try testing.expectEqual(port, rec.from_port);
    try testing.expectEqualStrings("127.0.0.1", rec.to_host_buf[0..rec.to_host_len]);
    // `refuseAllRedirects` ignores `from`/`to` entirely and always says no —
    // so with the first dial now gated too, it refuses THAT, not just the
    // redirect: zero new dials, where before this extension it would have
    // been exactly one (the original request always got through; only the
    // redirect target was judged).
    try testing.expectError(error.RedirectRefused, client.requestPlain(.get, url, .{ .redirect_filter = .{ .allow = refuseAllRedirects } }));
    try testing.expectEqual(@as(usize, 1), client.dialCount());

    // Positive control: the same filter saying yes lets the hop happen — the
    // second dial is attempted (and refused by the kernel, port 1).
    rec = .{ .verdict = true };
    try testing.expectError(error.ConnectFailed, client.request(.get, url, .{ .redirect_filter = filter }));
    try testing.expectEqual(@as(usize, 2), rec.calls); // first dial + redirect hop
    // (`dialCount` counts connections that came up, not attempts — the
    // refused connect to port 1 does not add to it, so this is just the ONE
    // new successful dial since the count after the previous scenario (1):
    // the ConnectFailed above is the evidence that the hop was attempted.)
    try testing.expectEqual(@as(usize, 2), client.dialCount());
}

test "request: redirect_filter also gates the very FIRST dial, no redirect involved (A1 G5 extension, 2026-09-11)" {
    // Before this, the doc said outright: "The first hop is the caller's
    // own URL and is not gated here" — a consumer that lets a user supply
    // the request URL directly had no gate on THAT, only on where a 3xx
    // might later send it. `refuse_first` makes the filter say no to the
    // original destination itself.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var client = Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false } });
    defer client.deinit();

    var rec: RecordingFilter = .{ .verdict = true, .refuse_first = true };
    const filter: RedirectFilter = .{ .ctx = &rec, .allow = RecordingFilter.allow };
    // Port 1 is unbindable — a dial would fail loudly (`ConnectFailed`), so
    // reaching `RedirectRefused` instead is proof no dial was attempted at
    // all, not merely that one failed for an unrelated reason.
    try testing.expectError(error.RedirectRefused, client.request(.get, "http://127.0.0.1:1/", .{ .redirect_filter = filter }));
    try testing.expectEqual(@as(usize, 0), client.dialCount());
    try testing.expectEqual(@as(usize, 1), rec.calls);
    try testing.expectEqualStrings("127.0.0.1", rec.to_host_buf[0..rec.to_host_len]);

    // requestPlain goes through the identical gate in `requestInnerPlain`.
    rec = .{ .verdict = true, .refuse_first = true };
    try testing.expectError(error.RedirectRefused, client.requestPlain(.get, "http://127.0.0.1:1/", .{ .redirect_filter = filter }));
    try testing.expectEqual(@as(usize, 0), client.dialCount());
    try testing.expectEqual(@as(usize, 1), rec.calls);
}

fn redirectToPortOneHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    _ = req;
    rw.status = 302;
    try rw.setHeader("Location", "http://127.0.0.1:1/final");
    try rw.writeAll("");
}

test "requestPlain: plaintext GET/POST loopback works and pools exactly like request" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try poolTestLoopback(io, 0);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, poolTestServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var res1 = try client.requestPlain(.get, url, .{});
    drainAndDeinit(&res1);
    try testing.expectEqual(@as(usize, 1), client.dialCount());
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());

    // Second request to the same origin: pooled connection reused, exactly
    // as `acquireConn`'s own pool tests prove for `request` — the pool is
    // shared, so this is also indirect proof `acquireConnPlain` and
    // `acquireConn` agree on what is poolable.
    var res2 = try client.requestPlain(.get, url, .{});
    drainAndDeinit(&res2);
    try testing.expectEqual(@as(usize, 1), client.dialCount());
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());

    var up = try client.requestStreamingPlain(.post, url, .{}, 5);
    try up.writer().writeAll("hello");
    var res3 = try up.finish();
    defer res3.deinit();
    try testing.expectEqual(@as(u16, 200), res3.status);
    const body = try res3.readAllAlloc(testing.allocator, 64);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("hello", body);
}

test "putFilePlain: streams a real file over a plaintext loopback PUT" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try poolTestLoopback(io, 0);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, poolTestServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const payload = "the quick brown fox jumps over the lazy dog";
    try tmp.dir.writeFile(io, .{ .sub_path = "upload.bin", .data = payload });

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    const status = try client.putFilePlain(url, tmp.dir, "upload.bin", .{});
    try testing.expectEqual(@as(u16, 200), status);
}

// Regression tests for `requestInnerPlain`/`requestStreamingPlain`'s `owned`
// double-free fix (see their doc comments a few hundred lines up). The
// TLS-side equivalents — "pool: stale-conn retry whose redial ALSO fails
// does not double-free conn" and "pool: requestStreaming's stale-conn retry
// whose redial ALSO fails does not double-free conn", both further down —
// were added in the same commit that fixed `requestInner`/`requestStreaming`
// and reproduced by reverting the fix; `requestInnerPlain`/
// `requestStreamingPlain` got the identical idiom one commit earlier (caught
// pre-commit when it segfaulted a test during development) but shipped with
// no test of their own that survives to catch a regression. These two are
// that test, built by pointing the exact same origins at the Plain entry
// points instead — `staleConnNoRedialOrigin`/`staleConnRstNoRedialOrigin`
// (both defined further down, alongside their first use) are already
// TLS-free raw-socket servers, so nothing about the origin changes, only
// which client method dials it.
test "requestPlain: pool: stale-conn retry whose redial ALSO fails does not double-free conn" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("requestPlain stale-conn redial-fail test listen failed ({t})", .{err});
    };

    const port = listener.socket.address.getPort();
    var hung_up = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, staleConnNoRedialOrigin, .{ io, &listener, &hung_up });

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var res1 = try client.requestPlain(.get, url, .{});
    drainAndDeinit(&res1);
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());

    while (!hung_up.load(.acquire)) std.atomic.spinLoopHint();
    thread.join();

    // Close the listening socket entirely — nothing is left to accept the
    // retry's redial, so it fails with `error.ConnectFailed` instead of
    // succeeding, forcing `requestInnerPlain`'s retry branch to hit the
    // `conn.destroy(); conn = try c.dialPlain(url);` path and return an
    // error afterward — exactly the shape the fixed `owned` flag guards.
    listener.deinit(io);

    try testing.expectError(error.ConnectFailed, client.requestPlain(.get, url, .{}));
}

// `requestStreamingPlain`'s retry fires only off a WRITE failure, same as
// `requestStreaming`'s (see that test's comment further down): a plain FIN
// close does not fail a small buffered write, so this needs the hard-RST
// origin and a tiny `write_buffer_size` to force the request head through a
// real `write(2)` that the RST can actually fail.
test "requestStreamingPlain: pool: stale-conn retry whose redial ALSO fails does not double-free conn" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("requestStreamingPlain redial-fail test listen failed ({t})", .{err});
    };

    const port = listener.socket.address.getPort();
    var hung_up = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, staleConnRstNoRedialOrigin, .{ io, &listener, &hung_up });

    // Same reasoning as `requestStreaming`'s own test: without a tiny
    // buffer the whole request head stays under the default 4KB write
    // buffer and never touches the socket until a later flush, so the RST
    // would never be observed at this call at all.
    var client = Client.init(io, testing.allocator, .{ .write_buffer_size = 8 });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    // Populate the pool via an ordinary GET against the same origin
    // (`staleConnRstNoRedialOrigin` answers any request the same way).
    var res1 = try client.requestPlain(.get, url, .{});
    drainAndDeinit(&res1);
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());

    while (!hung_up.load(.acquire)) std.atomic.spinLoopHint();
    thread.join();
    listener.deinit(io);

    try testing.expectError(error.ConnectFailed, client.requestStreamingPlain(.put, url, .{}, 0));
}

// ── tests (connection pool: loopback + white-box) ────────────────────────────

/// GET → "ok"; POST → echoes the body. Used by every pool loopback test
/// below (a real `http.Server`, unmodified — it already supports h1
/// keep-alive, which is exactly what these tests exercise from the client
/// side).
fn poolTestHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    if (req.method == .post) {
        var buf: [256]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        _ = try req.reader().streamRemaining(&w);
        try rw.writeAll(w.buffered());
        return;
    }
    try rw.writeAll("ok");
}

fn poolTestServeWrap(s: *Server) void {
    s.serve() catch {};
}

/// Read the whole body to completion, then `deinit` — a `Response` is only
/// pool-eligible once its body has actually been drained (see
/// `isBodyDrained`); these loopback tests care about *pooling*, not body
/// content, so they always fully drain before releasing.
fn drainAndDeinit(res: *Response) void {
    var sink: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&sink);
    _ = res.reader().streamRemaining(&w) catch {};
    res.deinit();
}

/// Bind a loopback `poolTestHandler` server (`max_requests_per_conn` 0 =
/// `Server`'s own effectively-unlimited default for these short tests).
/// Caller must spawn `poolTestServeWrap` on it and `defer server.shutdown()`
/// / `defer server.deinit()` / `defer testing.allocator.destroy(server)`,
/// same shape as the existing h2c-dogfood / proxy-integration loopback
/// helpers in this module.
fn poolTestLoopback(io: std.Io, max_requests_per_conn: u32) !*Server {
    const server = try testing.allocator.create(Server);
    errdefer testing.allocator.destroy(server);
    server.* = Server.init(io, testing.allocator, .{
        .handler = poolTestHandler,
        .max_requests_per_conn = if (max_requests_per_conn == 0) 1000 else max_requests_per_conn,
    });
    server.bind() catch |err| {
        server.deinit();
        testing.allocator.destroy(server);
        return testkit.loopbackSkip("pool test loopback bind failed ({t})", .{err});
    };
    return server;
}

test "pool: two sequential requests to the same origin reuse one connection" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try poolTestLoopback(io, 0);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, poolTestServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var res1 = try client.request(.get, url, .{});
    drainAndDeinit(&res1);
    try testing.expectEqual(@as(usize, 1), client.dialCount());
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());

    // Second request to the exact same origin: no re-dial — proof the pool
    // handed back the warm connection instead of opening a new one.
    var res2 = try client.request(.get, url, .{});
    drainAndDeinit(&res2);
    try testing.expectEqual(@as(usize, 1), client.dialCount());
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());
}

test "pool: requestStreaming also reuses pooled connections" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try poolTestLoopback(io, 0);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, poolTestServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    {
        var up = try client.requestStreaming(.post, url, .{}, 5);
        try up.writer().writeAll("hello");
        var res = try up.finish();
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = try res.readAllAlloc(testing.allocator, 64);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("hello", body);
    }
    try testing.expectEqual(@as(usize, 1), client.dialCount());

    {
        var up = try client.requestStreaming(.post, url, .{}, 5);
        try up.writer().writeAll("world");
        var res = try up.finish();
        defer res.deinit();
        const body = try res.readAllAlloc(testing.allocator, 64);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("world", body);
    }
    try testing.expectEqual(@as(usize, 1), client.dialCount()); // reused, no re-dial
}

test "pool: distinct origins do not cross-pollinate" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server_a = try poolTestLoopback(io, 0);
    defer testing.allocator.destroy(server_a);
    defer server_a.deinit();
    const thread_a = try std.Thread.spawn(.{}, poolTestServeWrap, .{server_a});
    defer thread_a.join();
    defer server_a.shutdown();
    const port_a = server_a.boundAddress().getPort();

    const server_b = try poolTestLoopback(io, 0);
    defer testing.allocator.destroy(server_b);
    defer server_b.deinit();
    const thread_b = try std.Thread.spawn(.{}, poolTestServeWrap, .{server_b});
    defer thread_b.join();
    defer server_b.shutdown();
    const port_b = server_b.boundAddress().getPort();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var buf_a: [64]u8 = undefined;
    var buf_b: [64]u8 = undefined;
    const url_a = try std.fmt.bufPrint(&buf_a, "http://127.0.0.1:{d}/", .{port_a});
    const url_b = try std.fmt.bufPrint(&buf_b, "http://127.0.0.1:{d}/", .{port_b});

    var r1 = try client.request(.get, url_a, .{});
    drainAndDeinit(&r1);
    try testing.expectEqual(@as(usize, 1), client.dialCount());

    var r2 = try client.request(.get, url_b, .{});
    drainAndDeinit(&r2);
    try testing.expectEqual(@as(usize, 2), client.dialCount());
    try testing.expectEqual(@as(usize, 2), client.poolIdleCount());

    // Re-requesting either origin reuses its own warm connection — no
    // re-dial, and never the other origin's connection.
    var r3 = try client.request(.get, url_a, .{});
    drainAndDeinit(&r3);
    try testing.expectEqual(@as(usize, 2), client.dialCount());
    var r4 = try client.request(.get, url_b, .{});
    drainAndDeinit(&r4);
    try testing.expectEqual(@as(usize, 2), client.dialCount());
}

test "pool: a Connection: close response is not pooled" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // `max_requests_per_conn = 1` is an existing, unmodified `Server`
    // feature: it makes the server send `Connection: close` on the very
    // first response and end the connection — exactly the "server declined
    // to keep this alive" case the pool must respect.
    const server = try poolTestLoopback(io, 1);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, poolTestServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var res1 = try client.request(.get, url, .{});
    try testing.expect(res1.head.connection_close);
    res1.deinit();
    try testing.expectEqual(@as(usize, 1), client.dialCount());
    try testing.expectEqual(@as(usize, 0), client.poolIdleCount()); // NOT pooled

    // A second request to the same origin has nothing to reuse — it must
    // dial again.
    var res2 = try client.request(.get, url, .{});
    res2.deinit();
    try testing.expectEqual(@as(usize, 2), client.dialCount());
}

/// One canned HTTP/1.1 200 response (Content-Length framed, no explicit
/// `Connection: close` — keep-alive-eligible per the client's own framing
/// rules), served over a raw accepted `net.Stream` and then hung up on —
/// exactly a peer that idle-timed-out a connection it had otherwise agreed
/// to keep alive. Used by the stale-connection-retry test below: a real
/// `http.Server` cannot be made to behave this uncooperatively (it always
/// advertises `Connection: close` before ending a connection), so this
/// fakes the origin at the raw-socket level instead, the same plumbing
/// (`net.Stream.reader`/`.writer`, `h1.readHead`) `Client`/`Server` both
/// build on.
fn staleConnOrigin(io: std.Io, listener: *net.Server, hung_up: *std.atomic.Value(bool)) void {
    const s1 = listener.accept(io) catch return;
    {
        var rbuf: [1024]u8 = undefined;
        var wbuf: [1024]u8 = undefined;
        var sr = s1.reader(io, &rbuf);
        var sw = s1.writer(io, &wbuf);
        var head_buf: [1024]u8 = undefined;
        _ = h1.readHead(&sr.interface, &head_buf) catch {};
        sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") catch {};
        sw.interface.flush() catch {};
    }
    s1.close(io); // hang up — the client has no idea yet, it is not reading right now
    hung_up.store(true, .release);

    // The client's redial after it notices the first connection went stale.
    const s2 = listener.accept(io) catch return;
    var rbuf: [1024]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var sr = s2.reader(io, &rbuf);
    var sw = s2.writer(io, &wbuf);
    var head_buf: [1024]u8 = undefined;
    _ = h1.readHead(&sr.interface, &head_buf) catch {};
    sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") catch {};
    sw.interface.flush() catch {};
    s2.close(io);
}

test "pool: a stale reused connection (peer already closed it) is retried once transparently" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("stale-conn test listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var hung_up = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, staleConnOrigin, .{ io, &listener, &hung_up });
    defer thread.join();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var res1 = try client.request(.get, url, .{});
    drainAndDeinit(&res1);
    try testing.expectEqual(@as(usize, 1), client.dialCount());
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());

    // Wait until the origin has actually hung up on connection #1 — avoids
    // a timing race against the assertions below (the pool doesn't need to
    // be told; it still believes the connection is good, exactly the
    // scenario the retry exists for).
    while (!hung_up.load(.acquire)) std.atomic.spinLoopHint();

    // The pool hands back the now-dead connection; the write and/or
    // response-head read against it fails in a way `isStaleConnError`
    // recognizes, and `request` transparently redials and resends against
    // the origin's second accepted connection — the caller never sees an
    // error.
    var res2 = try client.request(.get, url, .{});
    defer res2.deinit();
    try testing.expectEqual(@as(u16, 200), res2.status);
    const body = try res2.readAllAlloc(testing.allocator, 64);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("ok", body);
    try testing.expectEqual(@as(usize, 2), client.dialCount()); // original dial + the retry's redial
}

/// Same shape as `staleConnOrigin` but deliberately does NOT accept a second
/// connection: the test closes the listener right after this returns, so the
/// stale-connection retry's redial has nowhere to connect and must fail.
fn staleConnNoRedialOrigin(io: std.Io, listener: *net.Server, hung_up: *std.atomic.Value(bool)) void {
    const s1 = listener.accept(io) catch return;
    {
        var rbuf: [1024]u8 = undefined;
        var wbuf: [1024]u8 = undefined;
        var sr = s1.reader(io, &rbuf);
        var sw = s1.writer(io, &wbuf);
        var head_buf: [1024]u8 = undefined;
        _ = h1.readHead(&sr.interface, &head_buf) catch {};
        sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") catch {};
        sw.interface.flush() catch {};
    }
    s1.close(io);
    hung_up.store(true, .release);
}

/// Same as `staleConnNoRedialOrigin`, but closes with a hard RST
/// (`SO_LINGER{onoff=1,linger=0}`) instead of a graceful FIN.
/// `requestStreaming`'s stale-conn retry triggers off a failed WRITE (it
/// never reads a response before deciding to retry) — a plain FIN close only
/// fails the pooled connection's *next read*, since a single write into an
/// already-half-closed socket is typically still accepted into the local
/// send buffer without error. Forcing RST makes the pooled connection's next
/// write genuinely fail, which is what this test needs to reach the retry
/// path at all.
fn staleConnRstNoRedialOrigin(io: std.Io, listener: *net.Server, hung_up: *std.atomic.Value(bool)) void {
    const s1 = listener.accept(io) catch return;
    {
        var rbuf: [1024]u8 = undefined;
        var wbuf: [1024]u8 = undefined;
        var sr = s1.reader(io, &rbuf);
        var sw = s1.writer(io, &wbuf);
        var head_buf: [1024]u8 = undefined;
        _ = h1.readHead(&sr.interface, &head_buf) catch {};
        sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") catch {};
        sw.interface.flush() catch {};
    }
    const l = std.posix.linger{ .onoff = 1, .linger = 0 };
    std.posix.setsockopt(s1.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.LINGER, std.mem.asBytes(&l)) catch {};
    s1.close(io);
    hung_up.store(true, .release);
}

// Regression test for the double-free `requestInner`/`requestStreaming` had
// in their stale-connection retry: `errdefer conn.destroy()` stayed armed
// across the explicit `conn.destroy()` that precedes the redial, so a
// redial failure (this test forces one by closing the listener before the
// retry) freed the same `conn` a second time. Before the fix this crashed
// under `testing.allocator`'s double-free detector instead of returning
// `error.ConnectFailed`.
test "pool: stale-conn retry whose redial ALSO fails does not double-free conn" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("stale-conn redial-fail test listen failed ({t})", .{err});
    };

    const port = listener.socket.address.getPort();
    var hung_up = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, staleConnNoRedialOrigin, .{ io, &listener, &hung_up });

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var res1 = try client.request(.get, url, .{});
    drainAndDeinit(&res1);
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());

    while (!hung_up.load(.acquire)) std.atomic.spinLoopHint();
    thread.join();

    // Close the listening socket entirely — nothing is left to accept the
    // retry's redial, so it fails with `error.ConnectFailed` instead of
    // succeeding the way the sibling test above exercises.
    listener.deinit(io);

    try testing.expectError(error.ConnectFailed, client.request(.get, url, .{}));
}

// `requestStreaming` has the byte-identical stale-retry shape as
// `requestInner` above (`conn.destroy(); conn = try c.dialConn(url);` under
// what used to be a bare `errdefer conn.destroy()`), fixed with the same
// `owned` idiom. This is its regression test.
test "pool: requestStreaming's stale-conn retry whose redial ALSO fails does not double-free conn" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("requestStreaming redial-fail test listen failed ({t})", .{err});
    };

    const port = listener.socket.address.getPort();
    var hung_up = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, staleConnRstNoRedialOrigin, .{ io, &listener, &hung_up });

    // A tiny `write_buffer_size` forces `writeRequestHead`'s buffered writer
    // to drain (an actual `write(2)`) partway through the request line —
    // otherwise the whole head (well under the 4KB default buffer) never
    // touches the socket until some later flush, and the RST above would
    // never be observed at this call at all.
    var client = Client.init(io, testing.allocator, .{ .write_buffer_size = 8 });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    // Populate the pool via an ordinary GET against the same origin
    // (`staleConnRstNoRedialOrigin` answers any request the same way).
    var res1 = try client.request(.get, url, .{});
    drainAndDeinit(&res1);
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());

    while (!hung_up.load(.acquire)) std.atomic.spinLoopHint();
    thread.join();
    listener.deinit(io);

    try testing.expectError(error.ConnectFailed, client.requestStreaming(.put, url, .{}, 0));
}

test "pool: max_idle_per_host and max_idle_total cap eviction (oldest first)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A bare listener is enough: `dialConn` only needs the TCP handshake to
    // complete, which the kernel does from its accept backlog even before
    // `accept()` is ever called — no need for a serving loop at all for
    // this bookkeeping-only test.
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("pool cap test listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();
    var url_buf: [64]u8 = undefined;
    const url = try http.Url.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port}));

    // Per-host cap: releasing a 3rd idle connection for the same origin
    // evicts the oldest (lowest `idle_since_ms`) of the first two.
    {
        var client = Client.init(io, testing.allocator, .{ .pool = .{ .max_idle_per_host = 2, .max_idle_total = 100 } });
        defer client.deinit();
        const c0 = try client.dialConn(url, false);
        const c1 = try client.dialConn(url, false);
        const c2 = try client.dialConn(url, false);
        client.pool.release(c0, 100);
        client.pool.release(c1, 200);
        try testing.expectEqual(@as(usize, 2), client.poolIdleCount());
        client.pool.release(c2, 300); // 3rd for this origin, cap = 2
        try testing.expectEqual(@as(usize, 2), client.poolIdleCount());
    }

    // Total cap: same shape, but the cap that binds is the pool-wide one.
    {
        var client = Client.init(io, testing.allocator, .{ .pool = .{ .max_idle_per_host = 100, .max_idle_total = 2 } });
        defer client.deinit();
        const c0 = try client.dialConn(url, false);
        const c1 = try client.dialConn(url, false);
        const c2 = try client.dialConn(url, false);
        client.pool.release(c0, 100);
        client.pool.release(c1, 200);
        try testing.expectEqual(@as(usize, 2), client.poolIdleCount());
        client.pool.release(c2, 300);
        try testing.expectEqual(@as(usize, 2), client.poolIdleCount());
    }
}

test "pool: idle_timeout_ms reaping via sweep" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("pool sweep test listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();
    var url_buf: [64]u8 = undefined;
    const url = try http.Url.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port}));

    var client = Client.init(io, testing.allocator, .{ .pool = .{ .idle_timeout_ms = 100 } });
    defer client.deinit();

    const conn = try client.dialConn(url, false);
    client.pool.release(conn, 0); // idle_since_ms = 0
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());

    client.pool.sweep(50); // age 50ms <= 100ms: not stale yet
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());

    client.pool.sweep(150); // age 150ms > 100ms: reaped
    try testing.expectEqual(@as(usize, 0), client.poolIdleCount());
}

test "pool: concurrent acquire/release from many threads is leak-free and race-free" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("pool concurrency test listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var client = Client.init(io, testing.allocator, .{ .pool = .{ .max_idle_per_host = 8, .max_idle_total = 8 } });
    defer client.deinit();

    var url_buf: [64]u8 = undefined;
    const url = try http.Url.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port}));

    const n_threads = 8;
    const iters = 200;

    const Worker = struct {
        fn run(c: *Client, u: http.Url, tid: usize) void {
            // Each thread only ever holds ONE connection object at a time —
            // exclusively either checked out (this thread's local `conn`)
            // or parked in the pool between `release` and the next
            // `acquire` — so there is never a concurrent touch of the same
            // `*Conn` from two threads; only the pool's own bookkeeping is
            // contended, which is exactly what this test exercises.
            var conn = c.dialConn(u, false) catch return;
            var now: i64 = @intCast(tid * 1_000_000);
            for (0..iters) |_| {
                c.pool.release(conn, now);
                now += 1;
                conn = c.pool.acquire(u.scheme, u.host, u.port, now, false) orelse (c.dialConn(u, false) catch return);
            }
            conn.destroy();
        }
    };

    var threads: [n_threads]std.Thread = undefined;
    for (0..n_threads) |i| threads[i] = try std.Thread.spawn(.{}, Worker.run, .{ &client, url, i });
    for (threads) |t| t.join();

    // Whatever is left idle is freed by `client.deinit()` (deferred above);
    // `testing.allocator` catches any leak or double-free across the whole
    // run.
    try testing.expect(client.poolIdleCount() <= 8);
}

/// A loopback listener nobody accepts on: connects still complete (the
/// kernel's backlog), which is all `checkoutConn`'s slot accounting needs.
fn capTestListener(io: std.Io) !struct { net.Server, http.Url } {
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err|
        return testkit.loopbackSkip("max_conns_per_host test listen failed ({t})", .{err});
    errdefer listener.deinit(io);
    const url: http.Url = .{ .scheme = .http, .host = "127.0.0.1", .port = listener.socket.address.getPort(), .path = "/", .query = "" };
    return .{ listener, url };
}

fn deadlineIn(io: std.Io, ms: i64) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .raw = .fromMilliseconds(ms), .clock = .awake });
}

test "max_conns_per_host: at the cap a checkout waits, takes a pooled connection, times out" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener, const url = try capTestListener(io);
    defer listener.deinit(io);

    var client = Client.init(io, testing.allocator, .{ .pool = .{ .max_conns_per_host = 2 } });
    defer client.deinit();
    var reused = false;
    const a = try client.acquireConn(url, &reused, null, false);
    const b = try client.acquireConn(url, &reused, null, false);
    try testing.expect(a.holds_slot and b.holds_slot);
    try testing.expectEqual(@as(usize, 2), client.dialCount());

    // Third: nothing idle, no slot — the budget runs out, nothing dialed.
    try testing.expectError(error.Timeout, client.acquireConn(url, &reused, deadlineIn(io, 30), false));
    try testing.expectEqual(@as(usize, 2), client.dialCount());
    try testing.expectEqual(@as(u32, 0), client.pool.waiters.load(.monotonic));

    // A connection back in the pool is the third request's.
    client.pool.release(a, client.nowMs());
    const c = try client.acquireConn(url, &reused, deadlineIn(io, 1000), false);
    try testing.expect(reused and c == a);
    try testing.expectEqual(@as(usize, 2), client.dialCount());

    // Another origin (port) has its own cap.
    var listener2, const other = try capTestListener(io);
    defer listener2.deinit(io);
    const d = try client.acquireConn(other, &reused, deadlineIn(io, 1000), false);
    d.destroy();

    b.destroy();
    c.destroy();
    try testing.expectEqual(@as(usize, 0), client.pool.slots.items.len);
}

test "max_conns_per_host: a parked waiter dials when a connection closes" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener, const url = try capTestListener(io);
    defer listener.deinit(io);

    var client = Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false, .max_conns_per_host = 1 } });
    defer client.deinit();
    var reused = false;
    const a = try client.acquireConn(url, &reused, null, false);

    const Waiter = struct {
        got: ?*Conn = null,
        err: ?Error = null,
        fn run(w: *@This(), cl: *Client, u: http.Url) void {
            var r = false;
            w.got = cl.acquireConn(u, &r, null, false) catch |e| {
                w.err = e;
                return;
            };
        }
    };
    var w: Waiter = .{};
    const t = try std.Thread.spawn(.{}, Waiter.run, .{ &w, &client, url });
    // Parked (no deadline) before the close, so the wake is what frees it.
    var spins: usize = 0;
    while (client.pool.waiters.load(.acquire) == 0) : (spins += 1) {
        if (spins > 5000) break;
        io.sleep(.fromMilliseconds(1), .awake) catch {};
    }
    const parked = client.pool.waiters.load(.acquire) == 1;
    a.destroy();
    t.join();
    try testing.expect(parked);
    try testing.expectEqual(@as(?Error, null), w.err);
    try testing.expectEqual(@as(usize, 2), client.dialCount());
    w.got.?.destroy();
}

test "max_conns_per_host: a fresh redial at the cap evicts the origin's idle connection" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener, const url = try capTestListener(io);
    defer listener.deinit(io);

    var client = Client.init(io, testing.allocator, .{ .pool = .{ .max_conns_per_host = 2 } });
    defer client.deinit();
    var reused = false;
    const a = try client.acquireConn(url, &reused, null, false);
    const b = try client.acquireConn(url, &reused, null, false);
    client.pool.release(b, client.nowMs());
    // `a` went stale: the retry destroys it and wants a FRESH dial; even
    // with `b` idle that must not wait (and must not hand `b` out).
    a.destroy();
    const a2 = try client.checkoutConn(url, &reused, deadlineIn(io, 1000), false, false, dialConn);
    try testing.expect(!reused and a2 != b);
    // Now at the cap with `b` idle: the fresh dial takes over its slot.
    const c = try client.checkoutConn(url, &reused, deadlineIn(io, 1000), false, false, dialConn);
    try testing.expect(!reused);
    try testing.expectEqual(@as(usize, 0), client.poolIdleCount());
    try testing.expectEqual(@as(usize, 4), client.dialCount());
    try testing.expectEqual(@as(u16, 2), client.pool.slots.items[0].n);
    a2.destroy();
    c.destroy();
    try testing.expectEqual(@as(usize, 0), client.pool.slots.items.len);
}

test "max_conns_per_host: a failed dial gives its slot back" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    // A port that was listening a moment ago: connects are refused.
    var listener, const url = try capTestListener(io);
    listener.deinit(io);

    var client = Client.init(io, testing.allocator, .{ .pool = .{ .max_conns_per_host = 1 } });
    defer client.deinit();
    var reused = false;
    for (0..3) |_| try testing.expectError(error.ConnectFailed, client.acquireConn(url, &reused, deadlineIn(io, 1000), false));
    try testing.expectEqual(@as(usize, 0), client.pool.slots.items.len);
}

test "max_conns_per_host: N+1 concurrent requests, N connections (Go MaxConnsPerHost)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try poolTestLoopback(io, 0);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, poolTestServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();

    var client = Client.init(io, testing.allocator, .{ .pool = .{ .max_conns_per_host = 2 } });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{server.boundAddress().getPort()});

    const Worker = struct {
        fn run(cl: *Client, u: []const u8, failures: *std.atomic.Value(u32)) void {
            for (0..20) |_| {
                var res = cl.request(.get, u, .{}) catch {
                    _ = failures.fetchAdd(1, .monotonic);
                    return;
                };
                drainAndDeinit(&res);
            }
        }
    };
    var failures: std.atomic.Value(u32) = .init(0);
    var threads: [6]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &client, url, &failures });
    for (threads) |t| t.join();
    try testing.expectEqual(@as(u32, 0), failures.load(.monotonic));
    try testing.expect(client.dialCount() <= 2);
}

test "max_conns_per_host: a request waiting for a slot ends at total_timeout_ms" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try poolTestLoopback(io, 0);
    defer testing.allocator.destroy(server);
    defer server.deinit();
    const thread = try std.Thread.spawn(.{}, poolTestServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{server.boundAddress().getPort()});

    // Bounded by cancelation (`runBounded`) and, inline, by the deadline
    // the wait itself carries.
    for ([_]bool{ false, true }) |inline_blocking| {
        var client = Client.init(io, testing.allocator, .{
            .total_timeout_ms = 100,
            .inline_blocking = inline_blocking,
            .pool = .{ .max_conns_per_host = 1 },
        });
        defer client.deinit();
        var held = try client.request(.get, url, .{}); // body unread: holds the slot
        try testing.expectError(error.Timeout, client.request(.get, url, .{}));
        try testing.expectError(error.Timeout, client.requestPlain(.get, url, .{}));
        drainAndDeinit(&held);
        var again = try client.request(.get, url, .{});
        drainAndDeinit(&again);
        try testing.expectEqual(@as(usize, 1), client.dialCount());
    }
}

test "runBounded: inline_only takes the caller's-thread path without starting a task" {
    const Probe = struct {
        var ran: bool = false;
        fn f() error{ Nope, Timeout, Canceled }!u8 {
            ran = true;
            return 7;
        }
    };
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try testing.expectError(error.ConcurrencyUnavailable, runBounded(io, true, null, Probe.f, .{}));
    try testing.expect(!Probe.ran);
    try testing.expectEqual(@as(u8, 7), try runBounded(io, false, null, Probe.f, .{}));
    try testing.expect(Probe.ran);
}

/// A `std.Io.Threaded` whose every task start -- `async`, `concurrent`,
/// `groupAsync`, `groupConcurrent` -- is counted and then done as usual:
/// "did this work stay on the calling thread" as a number.
const TaskCountingIo = struct {
    var inner: *const std.Io.VTable = undefined;
    var starts: std.atomic.Value(usize) = .init(0);

    fn wrap(threaded: *std.Io.Threaded, vtable: *std.Io.VTable) std.Io {
        const io = threaded.io();
        inner = io.vtable;
        vtable.* = io.vtable.*;
        vtable.async = async_;
        vtable.concurrent = concurrent;
        vtable.groupAsync = groupAsync;
        vtable.groupConcurrent = groupConcurrent;
        starts.store(0, .monotonic);
        return .{ .userdata = io.userdata, .vtable = vtable };
    }
    fn async_(ud: ?*anyopaque, r: []u8, ra: std.mem.Alignment, ctx: []const u8, ca: std.mem.Alignment, start: *const fn (*const anyopaque, *anyopaque) void) ?*std.Io.AnyFuture {
        _ = starts.fetchAdd(1, .monotonic);
        return inner.async(ud, r, ra, ctx, ca, start);
    }
    fn concurrent(ud: ?*anyopaque, rl: usize, ra: std.mem.Alignment, ctx: []const u8, ca: std.mem.Alignment, start: *const fn (*const anyopaque, *anyopaque) void) std.Io.ConcurrentError!*std.Io.AnyFuture {
        _ = starts.fetchAdd(1, .monotonic);
        return inner.concurrent(ud, rl, ra, ctx, ca, start);
    }
    fn groupAsync(ud: ?*anyopaque, g: *std.Io.Group, ctx: []const u8, ca: std.mem.Alignment, start: *const fn (*const anyopaque) void) void {
        _ = starts.fetchAdd(1, .monotonic);
        inner.groupAsync(ud, g, ctx, ca, start);
    }
    fn groupConcurrent(ud: ?*anyopaque, g: *std.Io.Group, ctx: []const u8, ca: std.mem.Alignment, start: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
        _ = starts.fetchAdd(1, .monotonic);
        return inner.groupConcurrent(ud, g, ctx, ca, start);
    }
};

test "inline_blocking: resolving and connecting a host name starts no task on the Io" {
    // qap's jwks probe (2026-09-28): with `inline_blocking`, a Landlocked
    // thread still resolved a name it had no grant for, because std's
    // `HostName.connect` runs the lookup and the connects as tasks. Counted
    // here instead of sandboxed: zero task starts is "all on this thread".
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var vtable: std.Io.VTable = undefined;
    const io = TaskCountingIo.wrap(&threaded, &vtable);

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| return testkit.loopbackSkip("loopback listen failed ({t})", .{err});
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();
    var url_buf: [64]u8 = undefined;
    // "localhost" is a NAME (it goes through the resolver), and on most hosts
    // it resolves to ::1 first, where nothing listens: the one-at-a-time
    // fallback to 127.0.0.1 is exercised too.
    const url = try http.Url.parse(try std.fmt.bufPrint(&url_buf, "http://localhost:{d}/", .{port}));

    var inline_client = Client.init(io, testing.allocator, .{ .inline_blocking = true });
    defer inline_client.deinit();
    TaskCountingIo.starts.store(0, .monotonic);
    const s = try inline_client.connectStream(url);
    s.close(io);
    try testing.expectEqual(@as(usize, 0), TaskCountingIo.starts.load(.monotonic));

    // Control: without it, the same connect does start tasks -- so the zero
    // above is the option's doing, not a counter that never counts.
    var pooled = Client.init(io, testing.allocator, .{});
    defer pooled.deinit();
    TaskCountingIo.starts.store(0, .monotonic);
    const s2 = try pooled.connectStream(url);
    s2.close(io);
    try testing.expect(TaskCountingIo.starts.load(.monotonic) > 0);
}

test "CaBundle: shared by two clients, loaded once, never freed by a client" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var ca: CaBundle = .{};
    defer ca.deinit(testing.allocator);
    var a = Client.init(io, testing.allocator, .{ .shared_ca = &ca });
    var b = Client.init(io, testing.allocator, .{ .shared_ca = &ca });
    a.loadCaBundle() catch |err| switch (err) {
        // A host without a readable system store: nothing to share.
        error.CertificateBundleLoadFailure => {
            a.deinit();
            b.deinit();
            return error.SkipZigTest;
        },
        else => return err,
    };
    try testing.expect(ca.scanned);
    try testing.expect(!a.ca_scanned and !b.ca_scanned); // neither loaded its own
    const n = ca.bundle.map.count();
    try b.loadCaBundle(); // already loaded: a no-op
    try testing.expectEqual(n, ca.bundle.map.count());
    a.deinit();
    b.deinit();
    // `ca` is still intact here and freed by its owner (the defer above);
    // a client freeing it would double-free under testing.allocator.
    try testing.expect(ca.scanned);
}

// ── outbound proxy (Options.proxy) ──────────────────────────────────────────

/// A proxy that answers one connection: records the request head, writes
/// `answer`, then records the first bytes the client sends after it (the
/// TLS ClientHello once a CONNECT tunnel is up) until the client hangs up.
const ProxyPeer = struct {
    io: std.Io,
    listener: *net.Server,
    answer: []const u8,
    head: [1024]u8 = undefined,
    head_len: usize = 0,
    after: [8]u8 = undefined,
    after_len: usize = 0,

    fn run(p: *ProxyPeer) void {
        const s = p.listener.accept(p.io) catch return;
        defer s.close(p.io);
        var rbuf: [2048]u8 = undefined;
        var sr = s.reader(p.io, &rbuf);
        var head_buf: [1024]u8 = undefined;
        const head = h1.readHead(&sr.interface, &head_buf) catch return;
        @memcpy(p.head[0..head.len], head);
        p.head_len = head.len;
        var wbuf: [256]u8 = undefined;
        var sw = s.writer(p.io, &wbuf);
        sw.interface.writeAll(p.answer) catch return;
        sw.interface.flush() catch return;
        p.after_len = sr.interface.readSliceShort(&p.after) catch 0;
    }

    fn recorded(p: *const ProxyPeer) []const u8 {
        return p.head[0..p.head_len];
    }
};

fn proxyText(buf: []u8, comptime fmt: []const u8, port: u16) []const u8 {
    return std.fmt.bufPrint(buf, fmt, .{port}) catch unreachable;
}

test "proxy: an http:// request goes to the proxy in absolute form, with the proxy's Basic credentials" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    inline for (.{ false, true }) |plain| {
        const addr = try net.IpAddress.parse("127.0.0.1", 0);
        var listener = addr.listen(io, .{}) catch |err| {
            return testkit.loopbackSkip("proxy test listen failed ({t})", .{err});
        };
        defer listener.deinit(io);
        var peer: ProxyPeer = .{ .io = io, .listener = &listener, .answer = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" };
        const thread = try std.Thread.spawn(.{}, ProxyPeer.run, .{&peer});

        var pbuf: [64]u8 = undefined;
        var client = Client.init(io, testing.allocator, .{
            .pool = .{ .enabled = false },
            // The origin is never resolved: the proxy is what gets dialed.
            .proxy = .{ .http = proxyText(&pbuf, "http://user:pw@127.0.0.1:{d}", listener.socket.address.getPort()) },
        });
        defer client.deinit();
        {
            var res = if (plain)
                try client.requestPlain(.get, "http://origin.test:8080/a?b=1", .{ .headers = &.{.{ .name = "Proxy-Authorization", .value = "Basic Y2FsbGVy" }} })
            else
                try client.request(.get, "http://origin.test:8080/a?b=1", .{});
            defer res.deinit();
            try testing.expectEqual(@as(u16, 200), res.status);
            const body = try res.readAllAlloc(testing.allocator, 64);
            defer testing.allocator.free(body);
            try testing.expectEqualStrings("ok", body);
        }
        thread.join();
        // Absolute-form target (RFC 9112 §3.2.2), Host still the origin, the
        // configured credentials (user:pw), and not the caller's own.
        try testing.expect(std.mem.startsWith(u8, peer.recorded(), "GET http://origin.test:8080/a?b=1 HTTP/1.1\r\n" ++
            "Host: origin.test:8080\r\nProxy-Authorization: Basic dXNlcjpwdw==\r\n"));
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, peer.recorded(), "Proxy-Authorization"));
        try testing.expectEqual(@as(usize, 1), client.dialCount());
    }
}

test "proxy: an https:// request opens a CONNECT tunnel and starts TLS to the origin inside it" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("proxy test listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    var peer: ProxyPeer = .{ .io = io, .listener = &listener, .answer = "HTTP/1.1 200 Connection established\r\n\r\n" };
    const thread = try std.Thread.spawn(.{}, ProxyPeer.run, .{&peer});

    var pbuf: [64]u8 = undefined;
    var client = Client.init(io, testing.allocator, .{
        .pool = .{ .enabled = false },
        .tls = .{ .verify = .insecure_no_verify },
        .proxy = .{ .https = proxyText(&pbuf, "127.0.0.1:{d}", listener.socket.address.getPort()) },
    });
    defer client.deinit();
    // The peer reads the start of the handshake and hangs up: the request
    // fails, but only after the tunnel carried the ClientHello.
    try testing.expect(std.meta.isError(client.request(.get, "https://origin.test/x", .{})));
    thread.join();
    try testing.expectEqualStrings("CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n", peer.recorded());
    try testing.expect(peer.after_len >= 2);
    try testing.expectEqual(@as(u8, 0x16), peer.after[0]); // TLS handshake record
    try testing.expectEqual(@as(u8, 0x03), peer.after[1]);
}

test "proxy: a CONNECT refused by the proxy is ProxyRefused, and nothing follows it" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("proxy test listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    var peer: ProxyPeer = .{ .io = io, .listener = &listener, .answer = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n" };
    const thread = try std.Thread.spawn(.{}, ProxyPeer.run, .{&peer});

    var pbuf: [64]u8 = undefined;
    var client = Client.init(io, testing.allocator, .{
        .pool = .{ .enabled = false },
        .tls = .{ .verify = .insecure_no_verify },
        .proxy = .{ .https = proxyText(&pbuf, "http://a:b@127.0.0.1:{d}", listener.socket.address.getPort()) },
    });
    defer client.deinit();
    try testing.expectError(error.ProxyRefused, client.request(.get, "https://origin.test:8443/", .{}));
    thread.join();
    try testing.expectEqualStrings("CONNECT origin.test:8443 HTTP/1.1\r\nHost: origin.test:8443\r\n" ++
        "Proxy-Authorization: Basic YTpi\r\n", peer.recorded());
    try testing.expectEqual(@as(usize, 0), peer.after_len);
}

test "proxy: an unusable proxy setting is BadProxy before any dial, never a direct connection" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]Proxy{
        .{ .http = "socks5://127.0.0.1:1080" },
        .{ .http = "proxy host:1" },
        .{ .http = "127.0.0.1:99999" },
        .{ .http = "127.0.0.1:3128", .cgi = true },
    }) |proxy| {
        var client = Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false }, .proxy = proxy });
        defer client.deinit();
        try testing.expectError(error.BadProxy, client.requestPlain(.get, "http://origin.test/", .{}));
        try testing.expectError(error.BadProxy, client.request(.get, "http://origin.test/", .{}));
        try testing.expectEqual(@as(usize, 0), client.dialCount());
    }
}

// ── cookie jar (Options.cookie_jar) ─────────────────────────────────────────

/// Answers `answers.len` connections in turn, recording each request head.
const ScriptedPeer = struct {
    io: std.Io,
    listener: *net.Server,
    answers: []const []const u8,
    heads: [4][1024]u8 = undefined,
    head_lens: [4]usize = @splat(0),

    fn run(p: *ScriptedPeer) void {
        for (p.answers, 0..) |answer, n| {
            const s = p.listener.accept(p.io) catch return;
            defer s.close(p.io);
            var rbuf: [2048]u8 = undefined;
            var sr = s.reader(p.io, &rbuf);
            var head_buf: [1024]u8 = undefined;
            const got = h1.readHead(&sr.interface, &head_buf) catch return;
            @memcpy(p.heads[n][0..got.len], got);
            p.head_lens[n] = got.len;
            var wbuf: [512]u8 = undefined;
            var sw = s.writer(p.io, &wbuf);
            sw.interface.writeAll(answer) catch return;
            sw.interface.flush() catch return;
        }
    }

    fn head(p: *const ScriptedPeer, n: usize) []const u8 {
        return p.heads[n][0..p.head_lens[n]];
    }
};

/// A jar that remembers the last `Set-Cookie` value it was handed, with the
/// path it came from, and sends it back as is.
const EchoJar = struct {
    value: [64]u8 = undefined,
    len: usize = 0,
    stored_from: [64]u8 = undefined,
    stored_from_len: usize = 0,
    stores: usize = 0,

    fn jar(e: *EchoJar) CookieJar {
        return .{ .ctx = e, .write_cookies = write, .store = store };
    }

    fn write(ctx: *anyopaque, url: http.Url, w: *std.Io.Writer, prefix: []const u8) std.Io.Writer.Error!bool {
        _ = url;
        const e: *EchoJar = @ptrCast(@alignCast(ctx));
        if (e.len == 0) return false;
        try w.writeAll(prefix);
        try w.writeAll(e.value[0..e.len]);
        return true;
    }

    fn store(ctx: *anyopaque, url: http.Url, head: *const h1.ResponseHead) void {
        const e: *EchoJar = @ptrCast(@alignCast(ctx));
        e.stores += 1;
        const v = head.header("set-cookie") orelse return;
        @memcpy(e.value[0..v.len], v);
        e.len = v.len;
        @memcpy(e.stored_from[0..url.path.len], url.path);
        e.stored_from_len = url.path.len;
    }
};

test "cookie jar: a cookie set on a redirect rides the next hop, after the caller's own Cookie" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    inline for (.{ false, true }) |plain| {
        const addr = try net.IpAddress.parse("127.0.0.1", 0);
        var listener = addr.listen(io, .{}) catch |err| {
            return testkit.loopbackSkip("cookie jar test listen failed ({t})", .{err});
        };
        defer listener.deinit(io);
        var peer: ScriptedPeer = .{ .io = io, .listener = &listener, .answers = &.{
            "HTTP/1.1 302 Found\r\nLocation: /home\r\nSet-Cookie: sid=42\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        } };
        const thread = try std.Thread.spawn(.{}, ScriptedPeer.run, .{&peer});

        var echo: EchoJar = .{};
        var client = Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false }, .cookie_jar = echo.jar() });
        defer client.deinit();
        var url_buf: [64]u8 = undefined;
        const url_text = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/login", .{listener.socket.address.getPort()});
        const opts: RequestOptions = .{ .headers = &.{.{ .name = "Cookie", .value = "mine=1" }} };
        {
            var res = if (plain) try client.requestPlain(.get, url_text, opts) else try client.request(.get, url_text, opts);
            defer res.deinit();
            try testing.expectEqual(@as(u16, 200), res.status);
        }
        thread.join();
        // The jar saw both responses; the cookie came from the 302 at /login.
        try testing.expectEqual(@as(usize, 2), echo.stores);
        try testing.expectEqualStrings("/login", echo.stored_from[0..echo.stored_from_len]);
        // Hop 1: only the caller's cookie (the jar was empty). Hop 2: one
        // Cookie field, the caller's first, the jar's appended.
        try testing.expect(std.mem.indexOf(u8, peer.head(0), "Cookie: mine=1\r\n") != null);
        try testing.expect(std.mem.indexOf(u8, peer.head(1), "Cookie: mine=1; sid=42\r\n") != null);
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, peer.head(1), "Cookie:"));
    }
}

test "cookie jar: without a caller Cookie the jar writes its own field, and nothing when empty" {
    var buf: [512]u8 = undefined;
    var echo: EchoJar = .{};
    const url = try http.Url.parse("http://h.test/x");
    var w: std.Io.Writer = .fixed(&buf);
    try writeRequestHeadVia(&w, null, echo.jar(), .get, "", url, &.{}, "a", .none, false, true, false);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "Cookie") == null);
    @memcpy(echo.value[0..3], "k=v");
    echo.len = 3;
    w = .fixed(&buf);
    try writeRequestHeadVia(&w, null, echo.jar(), .get, "", url, &.{}, "a", .none, false, true, false);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\r\nCookie: k=v\r\n") != null);
}

// ── transparent gzip (`Options.decompress`) ───────────

/// Keep-alive connections serving `answers` in order, recording each
/// request head; a `Content-Length` request body is read and dropped. When
/// the client drops a connection, the next answer goes to the next one it
/// dials. Ends when the answers run out. `release` dials it once more, so a
/// peer still waiting in `accept` after a failed assert cannot hang the join.
const KeepAlivePeer = struct {
    io: std.Io,
    listener: *net.Server,
    answers: []const []const u8,
    heads: [6][1024]u8 = undefined,
    head_lens: [6]usize = @splat(0),
    stop: std.atomic.Value(u32) = .init(0),
    accepted: std.atomic.Value(u32) = .init(0),

    fn run(p: *KeepAlivePeer) void {
        var n: usize = 0;
        while (n < p.answers.len) {
            const s = p.listener.accept(p.io) catch return;
            p.accepted.store(1, .release);
            defer s.close(p.io);
            if (p.stop.load(.acquire) != 0) return;
            p.serve(s, &n);
        }
    }

    fn serve(p: *KeepAlivePeer, s: net.Stream, n: *usize) void {
        var rbuf: [2048]u8 = undefined;
        var sr = s.reader(p.io, &rbuf);
        var wbuf: [4096]u8 = undefined;
        var sw = s.writer(p.io, &wbuf);
        while (n.* < p.answers.len) : (n.* += 1) {
            const answer = p.answers[n.*];
            var head_buf: [1024]u8 = undefined;
            const got = h1.readHead(&sr.interface, &head_buf) catch return;
            @memcpy(p.heads[n.*][0..got.len], got);
            p.head_lens[n.*] = got.len;
            if (std.mem.indexOf(u8, got, "Content-Length: ")) |at| {
                const digits = got[at + "Content-Length: ".len ..];
                const len = std.fmt.parseInt(usize, digits[0 .. std.mem.indexOfScalar(u8, digits, '\r') orelse return], 10) catch return;
                sr.interface.discardAll(len) catch return;
            }
            sw.interface.writeAll(answer) catch return;
            sw.interface.flush() catch return;
        }
    }

    fn head(p: *const KeepAlivePeer, n: usize) []const u8 {
        return p.heads[n][0..p.head_lens[n]];
    }

    fn release(p: *KeepAlivePeer, port: u16) void {
        p.stop.store(1, .release);
        const addr = net.IpAddress.parse("127.0.0.1", port) catch return;
        const s = addr.connect(p.io, .{ .mode = .stream }) catch return;
        s.close(p.io);
    }
};

/// A gzip member of `plain` from this module's own encoder.
fn testGzip(gpa: std.mem.Allocator, plain: []const u8, level: u4) ![]u8 {
    const s = try gpa.create(gzip.Scratch);
    defer gpa.destroy(s);
    var aw: std.Io.Writer.Allocating = try .initCapacity(gpa, 64);
    errdefer aw.deinit();
    const w = try s.begin(&aw.writer, level);
    try w.writeAll(plain);
    try s.finish();
    return aw.toOwnedSlice();
}

/// `HTTP/1.1 200` carrying `body` as `Content-Encoding: gzip`, framed with
/// Content-Length, or chunked in 1000-byte chunks.
fn gzipAnswer(gpa: std.mem.Allocator, body: []const u8, chunked: bool) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    const w = &aw.writer;
    try w.writeAll("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\n");
    if (!chunked) {
        try w.print("Content-Length: {d}\r\n\r\n{s}", .{ body.len, body });
    } else {
        try w.writeAll("Transfer-Encoding: chunked\r\n\r\n");
        var at: usize = 0;
        while (at < body.len) : (at += 1000) {
            const piece = body[at..@min(body.len, at + 1000)];
            try w.print("{x}\r\n{s}\r\n", .{ piece.len, piece });
        }
        try w.writeAll("0\r\n\r\n");
    }
    return aw.toOwnedSlice();
}

/// Text that compresses but still spans several decoder buffers.
fn testPlain(buf: []u8) []u8 {
    for (buf, 0..) |*b, i| b.* = "abcdefghij klmnopqrstuvwxyz\n"[(i * 7 + i / 97) % 28];
    return buf;
}

const GzipLoopback = struct {
    listener: net.Server,
    peer: KeepAlivePeer,
    thread: std.Thread,
    url_buf: [64]u8,
    url: []const u8,

    fn start(g: *GzipLoopback, io: std.Io, answers: []const []const u8, path: []const u8) !void {
        const addr = try net.IpAddress.parse("127.0.0.1", 0);
        g.listener = addr.listen(io, .{}) catch |err|
            return testkit.loopbackSkip("gzip test listen failed ({t})", .{err});
        errdefer g.listener.deinit(io);
        g.peer = .{ .io = io, .listener = &g.listener, .answers = answers };
        g.url = try std.fmt.bufPrint(&g.url_buf, "http://127.0.0.1:{d}{s}", .{ g.listener.socket.address.getPort(), path });
        g.thread = try std.Thread.spawn(.{}, KeepAlivePeer.run, .{&g.peer});
    }

    fn finish(g: *GzipLoopback, io: std.Io) void {
        g.peer.release(g.listener.socket.address.getPort());
        g.thread.join();
        g.listener.deinit(io);
    }
};

test "request: an extension method goes out as its token; 307 keeps it, 302 rewrites it to GET (Go)" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const ok = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    var lb: GzipLoopback = undefined;
    try lb.start(io, &.{
        ok,
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n",
        ok,
        "HTTP/1.1 302 Found\r\nLocation: /c\r\nContent-Length: 0\r\n\r\n",
        ok,
        ok,
    }, "/");
    defer lb.finish(io);
    var client = Client.init(io, gpa, .{ .total_timeout_ms = 5000 });
    defer client.deinit();

    // A method this client cannot send is refused before any dial.
    try testing.expectError(error.InvalidHeader, client.request(.other, lb.url, .{}));
    try testing.expectError(error.InvalidHeader, client.request(.other, lb.url, .{ .method_token = "PU RGE" }));
    try testing.expectError(error.InvalidHeader, client.request(.other, lb.url, .{ .method_token = "PURGE\r\n" }));
    try testing.expectError(error.InvalidHeader, client.request(.get, lb.url, .{ .method_token = "PURGE" }));
    try testing.expectError(error.InvalidHeader, client.request(.connect, lb.url, .{}));
    try testing.expectError(error.InvalidHeader, client.requestStreaming(.other, lb.url, .{}, 0));

    for (0..3) |_| {
        var res = try client.request(.other, lb.url, .{ .method_token = "PURGE" });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
    }
    var up = try client.requestStreaming(.other, lb.url, .{ .method_token = "PROPFIND" }, 3);
    try up.writer().writeAll("abc");
    var res = try up.finish();
    res.deinit();

    const want = [_][]const u8{ "PURGE / ", "PURGE / ", "PURGE /b ", "PURGE / ", "GET /c ", "PROPFIND / " };
    for (want, 0..) |w, i| {
        errdefer std.debug.print("head {d}: {s}\n", .{ i, lb.peer.head(i) });
        try testing.expect(std.mem.startsWith(u8, lb.peer.head(i), w));
    }
}

test "gzip: decoded at levels 1/6/9, Content-Length and chunked framing, one pooled connection" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var plain_buf: [50_000]u8 = undefined;
    const plain = testPlain(&plain_buf);
    var answers: [3][]u8 = undefined;
    var made: usize = 0;
    defer for (answers[0..made]) |a| gpa.free(a);
    for ([_]u4{ 1, 6, 9 }, 0..) |level, i| {
        const gz = try testGzip(gpa, plain, level);
        defer gpa.free(gz);
        answers[i] = try gzipAnswer(gpa, gz, i == 2);
        made += 1;
    }

    var lb: GzipLoopback = undefined;
    try lb.start(io, &answers, "/");
    defer lb.finish(io);
    var client = Client.init(io, gpa, .{ .decompress = .gzip(1 << 20), .total_timeout_ms = 5000 });
    defer client.deinit();
    for (0..3) |i| {
        var res = try client.request(.get, lb.url, .{});
        defer res.deinit();
        try testing.expect(res.uncompressed);
        // Go's view: the wire coding and length are gone ...
        try testing.expectEqual(@as(?[]const u8, null), res.header("Content-Encoding"));
        try testing.expectEqual(@as(?[]const u8, null), res.header("content-length"));
        try testing.expectEqualStrings("text/plain", res.header("content-type").?);
        // ... the raw head keeps them.
        try testing.expectEqualStrings("gzip", res.head.header("content-encoding").?);
        const body = try res.readAllAlloc(gpa, 1 << 20);
        defer gpa.free(body);
        try testing.expectEqualSlices(u8, plain, body);
        _ = i;
    }
    // Every decoded body left the framing drained: no redial.
    try testing.expectEqual(@as(usize, 1), client.dialCount());
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());
    try testing.expect(std.mem.indexOf(u8, lb.peer.head(0), "\r\nAccept-Encoding: gzip\r\n") != null);
}

test "HTTP/1.1 trailers: read behind the head after the body, next response starts clean, overflow flagged" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const with_trailers = "HTTP/1.1 200 OK\r\nTrailer: X-Checksum\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "5\r\nhello\r\n0\r\nX-Checksum: c0ffee\r\nX-Other: 1\r\n\r\n";
    const without = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n";
    // One trailer line longer than what a 128-byte head buffer leaves.
    const big = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\nX-Small: s\r\nX-Sig: " ++
        (strRepeat("a", 200)) ++ "\r\n\r\n";
    var lb: GzipLoopback = undefined;
    try lb.start(io, &.{ with_trailers, without }, "/");
    defer lb.finish(io);
    var client = Client.init(io, gpa, .{ .total_timeout_ms = 5000 });
    defer client.deinit();
    {
        var res = try client.request(.get, lb.url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(?[]const u8, null), res.trailer("x-checksum"));
        const body = try res.readAllAlloc(gpa, 1024);
        defer gpa.free(body);
        try testing.expectEqualStrings("hello", body);
        try testing.expectEqualStrings("c0ffee", res.trailer("X-Checksum").?);
        try testing.expectEqualStrings("1", res.trailer("x-other").?);
        try testing.expect(!res.trailersTruncated());
        // The head is untouched by the capture behind it.
        try testing.expectEqualStrings("X-Checksum", res.header("trailer").?);
    }
    {
        var res = try client.request(.get, lb.url, .{});
        defer res.deinit();
        const body = try res.readAllAlloc(gpa, 1024);
        defer gpa.free(body);
        try testing.expectEqualStrings("ok", body);
        try testing.expectEqual(@as(?[]const u8, null), res.trailer("x-checksum"));
    }
    try testing.expectEqual(@as(usize, 1), client.dialCount());

    var lb2: GzipLoopback = undefined;
    try lb2.start(io, &.{ big, big }, "/");
    defer lb2.finish(io);
    var small = Client.init(io, gpa, .{ .total_timeout_ms = 5000, .max_head_bytes = 128 });
    defer small.deinit();
    {
        var res = try small.request(.get, lb2.url, .{});
        defer res.deinit();
        const body = try res.readAllAlloc(gpa, 1024);
        defer gpa.free(body);
        try testing.expectEqualStrings("x", body);
        try testing.expectEqualStrings("s", res.trailer("x-small").?);
        try testing.expectEqual(@as(?[]const u8, null), res.trailer("x-sig"));
        try testing.expect(res.trailersTruncated());
    }
    { // The dropped line was still read off the wire: the connection pooled.
        var res = try small.request(.get, lb2.url, .{});
        defer res.deinit();
        const body = try res.readAllAlloc(gpa, 1024);
        defer gpa.free(body);
        try testing.expectEqualStrings("x", body);
    }
    try testing.expectEqual(@as(usize, 1), small.dialCount());
}

test "gzip: off by default — identity asked, a gzip body handed over as sent" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const gz = try testGzip(gpa, "hello", 6);
    defer gpa.free(gz);
    const answer = try gzipAnswer(gpa, gz, false);
    defer gpa.free(answer);
    var lb: GzipLoopback = undefined;
    try lb.start(io, &.{answer}, "/");
    defer lb.finish(io);
    var client = Client.init(io, gpa, .{ .total_timeout_ms = 5000 });
    defer client.deinit();
    var res = try client.request(.get, lb.url, .{});
    defer res.deinit();
    try testing.expect(!res.uncompressed);
    try testing.expectEqualStrings("gzip", res.header("content-encoding").?);
    const body = try res.readAllAlloc(gpa, 1024);
    defer gpa.free(body);
    try testing.expectEqualSlices(u8, gz, body);
    try testing.expect(std.mem.indexOf(u8, lb.peer.head(0), "\r\nAccept-Encoding: identity\r\n") != null);
}

test "gzip: a caller Accept-Encoding, a Range, HEAD, x-gzip — not asked or not decoded" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const gz = try testGzip(gpa, "hello", 6);
    defer gpa.free(gz);
    const answer = try gzipAnswer(gpa, gz, false);
    defer gpa.free(answer);
    const xgzip = try std.fmt.allocPrint(gpa, "HTTP/1.1 200 OK\r\nContent-Encoding: x-gzip\r\nContent-Length: {d}\r\n\r\n{s}", .{ gz.len, gz });
    defer gpa.free(xgzip);
    const head_answer = try std.fmt.allocPrint(gpa, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {d}\r\n\r\n", .{gz.len});
    defer gpa.free(head_answer);

    var lb: GzipLoopback = undefined;
    try lb.start(io, &.{ answer, answer, head_answer, xgzip }, "/");
    defer lb.finish(io);
    var client = Client.init(io, gpa, .{ .decompress = .gzip(1 << 20), .total_timeout_ms = 5000 });
    defer client.deinit();

    const cases = [_]struct { method: http.Method, headers: []const http.Header, sent: []const u8 }{
        // The caller asked: the body is the caller's to decode (Go).
        .{ .method = .get, .headers = &.{.{ .name = "accept-encoding", .value = "gzip" }}, .sent = "\r\naccept-encoding: gzip\r\n" },
        .{ .method = .get, .headers = &.{.{ .name = "Range", .value = "bytes=0-" }}, .sent = "\r\nAccept-Encoding: identity\r\n" },
        .{ .method = .head, .headers = &.{}, .sent = "\r\nAccept-Encoding: identity\r\n" },
        // Asked, but only `gzip` itself is decoded (Go's EqualFold).
        .{ .method = .get, .headers = &.{}, .sent = "\r\nAccept-Encoding: gzip\r\n" },
    };
    for (cases, 0..) |case, i| {
        var res = try client.request(case.method, lb.url, .{ .headers = case.headers });
        defer res.deinit();
        try testing.expect(!res.uncompressed);
        try testing.expect(res.header("content-encoding") != null);
        const body = try res.readAllAlloc(gpa, 1024);
        defer gpa.free(body);
        try testing.expectEqualSlices(u8, if (case.method == .head) "" else gz, body);
        try testing.expect(std.mem.indexOf(u8, lb.peer.head(i), case.sent) != null);
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, lb.peer.head(i), "ccept-")); // one Accept-Encoding
    }
}

test "gzip: concatenated members decode like Go's multistream reader; a bodiless answer is left alone" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const a = try testGzip(gpa, "first,", 1);
    defer gpa.free(a);
    const b = try testGzip(gpa, "second", 9);
    defer gpa.free(b);
    const both = try std.mem.concat(gpa, u8, &.{ a, b });
    defer gpa.free(both);
    const multi = try gzipAnswer(gpa, both, true);
    defer gpa.free(multi);
    const empty = try gzipAnswer(gpa, "", false);
    defer gpa.free(empty);
    const no_content = "HTTP/1.1 204 No Content\r\nContent-Encoding: gzip\r\n\r\n";

    var lb: GzipLoopback = undefined;
    try lb.start(io, &.{ multi, empty, no_content }, "/");
    defer lb.finish(io);
    var client = Client.init(io, gpa, .{ .decompress = .gzip(1 << 20), .total_timeout_ms = 5000 });
    defer client.deinit();
    for ([_][]const u8{ "first,second", "", "" }, 0..) |want, i| {
        var res = try client.request(.get, lb.url, .{});
        defer res.deinit();
        // Go wraps only a response that may have a body (CL 0 and 204: no).
        try testing.expectEqual(i == 0, res.uncompressed);
        try testing.expectEqual(i != 0, res.header("content-encoding") != null);
        const body = try res.readAllAlloc(gpa, 1024);
        defer gpa.free(body);
        try testing.expectEqualStrings(want, body);
    }
    try testing.expectEqual(@as(usize, 1), client.dialCount());
}

test "gzip: optional header fields (FEXTRA, FNAME, FCOMMENT, FHCRC) are skipped" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const gz = try testGzip(gpa, "flagged", 6);
    defer gpa.free(gz);
    // Same deflate data and trailer behind a header that declares all four.
    const flagged = try std.mem.concat(gpa, u8, &.{
        &.{ 0x1f, 0x8b, 8, 0b0001_1110, 0, 0, 0, 0, 0, 3 },
        &.{ 3, 0, 'x', 'y', 'z' }, // FEXTRA: XLEN 3
        "name.txt\x00",
        "a comment\x00",
        &.{ 0xab, 0xcd }, // FHCRC, not checked (see gzip.skipGzipHeader)
        gz[10..],
    });
    defer gpa.free(flagged);
    const answer = try gzipAnswer(gpa, flagged, false);
    defer gpa.free(answer);

    var lb: GzipLoopback = undefined;
    try lb.start(io, &.{answer}, "/");
    defer lb.finish(io);
    var client = Client.init(io, gpa, .{ .decompress = .gzip(1 << 20), .total_timeout_ms = 5000 });
    defer client.deinit();
    var res = try client.request(.get, lb.url, .{});
    defer res.deinit();
    const body = try res.readAllAlloc(gpa, 1024);
    defer gpa.free(body);
    try testing.expectEqualStrings("flagged", body);
}

test "gzip: corrupt, truncated or trailing-garbage bodies fail CorruptGzip; the next request is unharmed" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var plain_buf: [20_000]u8 = undefined;
    const gz = try testGzip(gpa, testPlain(&plain_buf), 6);
    defer gpa.free(gz);
    const Mutation = enum { crc, size, cut_deflate, cut_trailer, garbage, zeros_after, magic, deflate_bits };
    inline for (comptime std.enums.values(Mutation)) |m| {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        try body.appendSlice(gpa, gz);
        switch (m) {
            .crc => body.items[body.items.len - 8] ^= 1,
            .size => body.items[body.items.len - 1] ^= 1,
            .cut_deflate => body.shrinkRetainingCapacity(gz.len / 2),
            .cut_trailer => body.shrinkRetainingCapacity(gz.len - 3),
            .garbage => try body.appendSlice(gpa, "junk"),
            .zeros_after => try body.appendNTimes(gpa, 0, 10),
            .magic => body.items[1] = 0x8c,
            // A reserved block type (BTYPE 11) in the first block header.
            .deflate_bits => body.items[10] |= 0b110,
        }
        const good = try gzipAnswer(gpa, gz, false);
        defer gpa.free(good);
        for ([_]bool{ false, true }) |chunked| {
            const answer = try gzipAnswer(gpa, body.items, chunked);
            defer gpa.free(answer);
            var lb: GzipLoopback = undefined;
            try lb.start(io, &.{ answer, good }, "/");
            defer lb.finish(io);
            var client = Client.init(io, gpa, .{ .decompress = .gzip(1 << 20), .total_timeout_ms = 5000 });
            defer client.deinit();
            {
                var res = try client.request(.get, lb.url, .{});
                defer res.deinit();
                try testing.expectError(error.CorruptGzip, res.readAllAlloc(gpa, 1 << 20));
                // Sticky: the reader stays failed.
                try testing.expectError(error.ReadFailed, res.reader().discardRemaining());
                try testing.expectEqual(error.CorruptGzip, res.readFailure());
            }
            // The wire state, not the gzip verdict, decides pooling (as in
            // Go, whose pool sees the raw body's EOF): whether or not the
            // failed exchange left its connection reusable, the next
            // request reads its own answer, not the rest of the bad one.
            var res = try client.request(.get, lb.url, .{});
            defer res.deinit();
            const body2 = try res.readAllAlloc(gpa, 1 << 20);
            defer gpa.free(body2);
            try testing.expectEqualSlices(u8, &plain_buf, body2);
        }
    }
}

test "gzip: the decoded-size cap — exactly at it passes, one byte over is BodyTooLarge" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var plain_buf: [30_000]u8 = undefined;
    const plain = testPlain(&plain_buf);
    const gz = try testGzip(gpa, plain, 6);
    defer gpa.free(gz);
    const answer = try gzipAnswer(gpa, gz, false);
    defer gpa.free(answer);
    for ([_]u64{ plain.len, plain.len - 1 }) |cap| {
        var lb: GzipLoopback = undefined;
        try lb.start(io, &.{answer}, "/");
        defer lb.finish(io);
        var client = Client.init(io, gpa, .{ .decompress = .gzip(cap), .total_timeout_ms = 5000 });
        defer client.deinit();
        var res = try client.request(.get, lb.url, .{});
        defer res.deinit();
        if (cap == plain.len) {
            const body = try res.readAllAlloc(gpa, 1 << 20);
            defer gpa.free(body);
            try testing.expectEqualSlices(u8, plain, body);
        } else {
            try testing.expectError(error.BodyTooLarge, res.readAllAlloc(gpa, 1 << 20));
        }
    }
}

test "gzip: requestStreaming's Upload and getToFile decode too" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var plain_buf: [70_000]u8 = undefined;
    const plain = testPlain(&plain_buf);
    const gz = try testGzip(gpa, plain, 6);
    defer gpa.free(gz);
    const answer = try gzipAnswer(gpa, gz, true);
    defer gpa.free(answer);

    var lb: GzipLoopback = undefined;
    try lb.start(io, &.{ answer, answer }, "/");
    defer lb.finish(io);
    var client = Client.init(io, gpa, .{ .decompress = .gzip(1 << 20), .total_timeout_ms = 5000 });
    defer client.deinit();
    {
        var up = try client.requestStreaming(.post, lb.url, .{}, 3);
        try up.writer().writeAll("abc");
        var res = try up.finish();
        defer res.deinit();
        try testing.expect(res.uncompressed);
        const body = try res.readAllAlloc(gpa, 1 << 20);
        defer gpa.free(body);
        try testing.expectEqualSlices(u8, plain, body);
    }
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try testing.expectEqual(@as(u64, plain.len), try client.getToFile(lb.url, tmp.dir, "out"));
    const got = try tmp.dir.readFileAlloc(io, "out", gpa, .limited(1 << 20));
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, plain, got);
    try testing.expectEqual(@as(usize, 1), client.dialCount());
}

fn gzipServerHandler(_: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    var plain_buf: [40_000]u8 = undefined;
    try rw.setHeader("Content-Type", "text/plain");
    try rw.writer().writeAll(testPlain(&plain_buf));
}

test "gzip: against this module's own Server with compression on" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server = try gpa.create(Server);
    defer gpa.destroy(server);
    server.* = Server.init(io, gpa, .{ .handler = gzipServerHandler, .compression = .{} });
    defer server.deinit();
    server.bind() catch |err| return testkit.loopbackSkip("gzip server bind failed ({t})", .{err});
    const thread = try std.Thread.spawn(.{}, poolTestServeWrap, .{server});
    defer thread.join();
    defer server.shutdown();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{server.boundAddress().getPort()});

    var plain_buf: [40_000]u8 = undefined;
    const plain = testPlain(&plain_buf);
    var client = Client.init(io, gpa, .{ .decompress = .gzip(1 << 20) });
    defer client.deinit();
    for (0..2) |_| {
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expect(res.uncompressed);
        const body = try res.readAllAlloc(gpa, 1 << 20);
        defer gpa.free(body);
        try testing.expectEqualSlices(u8, plain, body);
    }
    try testing.expectEqual(@as(usize, 1), client.dialCount());
}

// ── fuzz: the response-body gzip decoder ────────────────────────────────────
//
// `Gunzip` reads bytes a server chose. On top of "no panic" (std's decoder
// aborts on a cut stream; the padded source is what keeps it away): the cap
// holds, a read that succeeds decoded members whose trailers all checked,
// and a failure is always a typed one, never a transport `ReadFailed`.

const fz = @import("fuzz_test.zig");
const GunzipMark = fz.Marker(enum { decoded, decoded_multi, empty, corrupt, too_large });

const gunzip_seeds = [_][]const u8{
    testkit.fuzz.seed("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xcb\x48\xcd\xc9\xc9\x57\x48\xaf\xca\x2c\x00\x00\x19\x6a\xd2\xdf\x0a\x00\x00\x00"),
    testkit.fuzz.seed("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\x4b\x4c\x4a\x4e\x1c\xca\x08\x00\x81\x45\x57\x33\xc0\x00\x00\x00"),
    testkit.fuzz.seed("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    // Two members back to back.
    testkit.fuzz.seed("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++
        "\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xcb\x48\xcd\xc9\xc9\x57\x48\xaf\xca\x2c\x00\x00\x19\x6a\xd2\xdf\x0a\x00\x00\x00"),
    // FNAME + FCOMMENT + FHCRC on an empty member.
    testkit.fuzz.seed("\x1f\x8b\x08\x1a\x00\x00\x00\x00\x02\xffn\x00c\x00\xab\xcd\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    testkit.fuzz.seed(""),
};

/// The raw body in pieces of at most `piece` bytes: a server's segments.
const PieceReader = struct {
    data: []const u8,
    piece: usize,
    reader: std.Io.Reader,

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const p: *PieceReader = @alignCast(@fieldParentPtr("reader", r));
        if (p.data.len == 0) return error.EndOfStream;
        const n = try w.write(p.data[0..limit.minInt(@min(p.data.len, p.piece))]);
        p.data = p.data[n..];
        return n;
    }
};

test "fuzz driver: HTTP_FUZZ (client gunzip)" {
    try fz.fuzz_driver.run(fuzzGunzip, .{ .prefix = "HTTP_FUZZ", .name = "http-client-gunzip" });
}

test "fuzz harness: client gunzip, 300 seeds, reaches every outcome" {
    try GunzipMark.reach(fuzzGunzip, "http-client-gunzip", 300);
}

test "fuzz: the client's gzip decoder never panics, keeps its cap, fails typed" {
    try testing.fuzz({}, fuzzGunzipSmith, .{ .corpus = &gunzip_seeds });
}

fn fuzzGunzipSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzGunzip, smith, script[0..n]);
}

fn fuzzGunzip(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var input: [512]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &input, &gunzip_seeds);
    const cap: u64 = src.valueRangeAtMost(u16, 1, 300);
    var raw: PieceReader = .{
        .data = input[0..len],
        .piece = src.valueRangeAtMost(u16, 1, 600),
        .reader = .{ .vtable = &.{ .stream = PieceReader.stream }, .buffer = &.{}, .seek = 0, .end = 0 },
    };
    const g = try gpa.create(Gunzip);
    defer gpa.destroy(g);
    g.init(&raw.reader, cap);

    var out: [400]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    const got = g.reader.streamRemaining(&w) catch |err| switch (err) {
        // `out` holds more than any cap: the decoder overran it.
        error.WriteFailed => return error.CapNotHeld,
        error.ReadFailed => {
            // The source never fails, so every failure is the body's own.
            const why = g.failure orelse return error.UntypedFailure;
            switch (why) {
                error.CorruptGzip => GunzipMark.mark(.corrupt),
                error.BodyTooLarge => GunzipMark.mark(.too_large),
                else => return error.UnexpectedFailure,
            }
            return;
        },
    };
    if (got > cap) return error.CapNotHeld;
    if (g.state != .done) return error.EndedEarly;
    // Success: every member's trailer checked and the source at its end.
    if (len == 0) return GunzipMark.mark(.empty);
    if (std.mem.count(u8, input[0..len], "\x1f\x8b\x08") > 1 and got > 0) GunzipMark.mark(.decoded_multi);
    GunzipMark.mark(.decoded);
}

// ── tests (Options.http2: the h2 exchange, over h2c prior knowledge) ────────
//
// No TLS server exists in this module, so ALPN itself is exercised by the
// interop lane (`tools/interop.zig`, a Go TLS server). Here the h2 exchange
// runs over a cleartext connection that `primeH2c` started an h2 session on
// — what `dialTls` does when ALPN picks h2 — and parked in the pool, where
// `request` finds it like any idle connection.

/// Dial `url`'s origin in the clear, start an h2 session on it and park it
/// in the pool.
fn primeH2c(client: *Client, url_text: []const u8) !void {
    const url = try http.Url.parse(url_text);
    const conn = try client.dialPlain(url, false);
    errdefer conn.destroy();
    try h2glue.start(conn);
    client.pool.release(conn, client.nowMs());
}

/// The gzip body `/gz` answers with (set by the test before serving).
var h2_test_gz: []const u8 = "";

fn h2ClientHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    if (std.mem.eql(u8, req.path, "/hello")) {
        try rw.setHeader("Content-Type", "text/plain");
        try rw.setHeader("Set-Cookie", "sid=h2; Path=/");
        try rw.writeAll("hello h2");
    } else if (std.mem.eql(u8, req.path, "/echo")) {
        var aw: std.Io.Writer.Allocating = .init(testing.allocator);
        defer aw.deinit();
        _ = try req.reader().streamRemaining(&aw.writer);
        try rw.setHeader("X-Method", req.methodName());
        try rw.writeAll(aw.written());
    } else if (std.mem.eql(u8, req.path, "/fields")) {
        // What arrived, one field per line, for the request-side checks.
        var it = req.iterateHeaders();
        while (it.next()) |f| try rw.writer().print("{s}={s}\n", .{ f.name, f.value });
    } else if (std.mem.eql(u8, req.path, "/trailers")) {
        try rw.declareTrailer("x-checksum");
        try rw.writeAll("body before trailers");
        try rw.setTrailer("x-checksum", "c0ffee");
    } else if (std.mem.eql(u8, req.path, "/gz")) {
        try rw.setHeader("Content-Encoding", "gzip");
        try rw.writeAll(h2_test_gz);
    } else if (std.mem.eql(u8, req.path, "/redirect")) {
        rw.setStatus(302);
        try rw.setHeader("Location", "/hello");
        try rw.writeAll("moved");
    } else if (std.mem.eql(u8, req.path, "/empty")) {
        rw.setStatus(204);
    } else if (std.mem.eql(u8, req.path, "/huge")) {
        var block: [1024]u8 = undefined;
        @memset(&block, 'h');
        for (0..huge_blocks) |_| try rw.writeAll(&block);
    } else {
        rw.setStatus(404);
        try rw.writeAll("nope");
    }
}

const H2ClientLoopback = struct {
    server: *Server,
    thread: std.Thread,
    url_buf: [64]u8,

    fn start(lb: *H2ClientLoopback, io: std.Io) !void {
        const server = try testing.allocator.create(Server);
        errdefer testing.allocator.destroy(server);
        server.* = Server.init(io, testing.allocator, .{ .handler = h2ClientHandler, .enable_h2c = true });
        server.bind() catch |err| {
            server.deinit();
            return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
        };
        errdefer server.deinit();
        lb.server = server;
        lb.thread = try std.Thread.spawn(.{}, h2ServeWrap, .{server});
    }

    fn url(lb: *H2ClientLoopback, path: []const u8) []const u8 {
        return std.fmt.bufPrint(&lb.url_buf, "http://127.0.0.1:{d}{s}", .{ lb.server.boundAddress().getPort(), path }) catch unreachable;
    }

    fn finish(lb: *H2ClientLoopback) void {
        lb.server.shutdown();
        lb.thread.join();
        lb.server.deinit();
        testing.allocator.destroy(lb.server);
    }
};

test "http2: request over an h2 connection — proto, head, body, cookies, one pooled connection" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var lb: H2ClientLoopback = undefined;
    try lb.start(io);
    defer lb.finish();

    var echo: EchoJar = .{};
    var client = Client.init(io, gpa, .{ .http2 = .alpn(), .total_timeout_ms = 5000, .cookie_jar = echo.jar() });
    defer client.deinit();
    try primeH2c(&client, lb.url("/"));

    {
        var res = try client.request(.get, lb.url("/hello"), .{});
        defer res.deinit();
        try testing.expectEqual(Proto.http2, res.proto());
        try testing.expectEqualStrings("HTTP/2.0", res.proto().text());
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("OK", res.reason);
        try testing.expectEqualStrings("text/plain", res.header("Content-Type").?);
        const body = try res.readAllAlloc(gpa, 1024);
        defer gpa.free(body);
        try testing.expectEqualStrings("hello h2", body);
    }
    { // The cookie the h2 answer set goes out on the next request, and the
        // fields arrive as the h1 head writer would have sent them.
        var res = try client.request(.get, lb.url("/fields"), .{ .headers = &.{.{ .name = "X-Custom", .value = "v" }} });
        defer res.deinit();
        const body = try res.readAllAlloc(gpa, 4096);
        defer gpa.free(body);
        try testing.expect(std.mem.indexOf(u8, body, "cookie=sid=h2; Path=/\n") != null);
        try testing.expect(std.mem.indexOf(u8, body, "x-custom=v\n") != null);
        try testing.expect(std.mem.indexOf(u8, body, "user-agent=zig-libs-http/0.1\n") != null);
        try testing.expect(std.mem.indexOf(u8, body, "accept-encoding=identity\n") != null);
        try testing.expect(std.mem.indexOf(u8, body, "connection") == null);
        // `:authority`, from the Host the h1 writer would have sent.
        try testing.expect(std.mem.indexOf(u8, body, "host=127.0.0.1:") != null);
    }
    { // In-memory body.
        var res = try client.request(.post, lb.url("/echo"), .{ .body = "posted over h2" });
        defer res.deinit();
        const body = try res.readAllAlloc(gpa, 1024);
        defer gpa.free(body);
        try testing.expectEqualStrings("posted over h2", body);
    }
    { // An extension method is `:method` as its token, buffered or streamed.
        var res = try client.request(.other, lb.url("/echo"), .{ .method_token = "PROPFIND", .body = "<p/>" });
        defer res.deinit();
        try testing.expectEqualStrings("PROPFIND", res.header("x-method").?);
        const body = try res.readAllAlloc(gpa, 1024);
        defer gpa.free(body);
        try testing.expectEqualStrings("<p/>", body);
    }
    { // (Its own block: one exchange per h2 connection, `res` above is done.)
        var up = try client.requestStreaming(.other, lb.url("/echo"), .{ .method_token = "PURGE" }, null);
        try up.writer().writeAll("streamed");
        var res = try up.finish();
        defer res.deinit();
        try testing.expectEqualStrings("PURGE", res.header("x-method").?);
        const body = try res.readAllAlloc(gpa, 1024);
        defer gpa.free(body);
        try testing.expectEqualStrings("streamed", body);
    }
    { // HEAD and 204: no body.
        var res = try client.request(.head, lb.url("/hello"), .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqual(@as(usize, 0), try res.reader().discardRemaining());
    }
    {
        var res = try client.request(.get, lb.url("/empty"), .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 204), res.status);
        try testing.expectEqual(@as(usize, 0), try res.reader().discardRemaining());
    }
    // Every exchange ran on the primed connection: no dial at all.
    try testing.expectEqual(@as(usize, 1), client.dialCount());
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());
}

test "http2: trailers, a redirect and an unread body keep the one connection" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var lb: H2ClientLoopback = undefined;
    try lb.start(io);
    defer lb.finish();

    var client = Client.init(io, gpa, .{ .http2 = .alpn(), .total_timeout_ms = 5000 });
    defer client.deinit();
    try primeH2c(&client, lb.url("/"));

    {
        var res = try client.request(.get, lb.url("/trailers"), .{});
        defer res.deinit();
        // Not known before the end of the body.
        try testing.expectEqual(@as(?[]const u8, null), res.trailer("x-checksum"));
        const body = try res.readAllAlloc(gpa, 1024);
        defer gpa.free(body);
        try testing.expectEqualStrings("body before trailers", body);
        try testing.expectEqualStrings("c0ffee", res.trailer("X-Checksum").?);
    }
    { // The 302's stream is reset, its connection carries the next hop.
        var res = try client.request(.get, lb.url("/redirect"), .{});
        defer res.deinit();
        const body = try res.readAllAlloc(gpa, 1024);
        defer gpa.free(body);
        try testing.expectEqualStrings("hello h2", body);
    }
    { // 200 KiB, past the 64 KiB window, abandoned after one read: the
        // stream is reset and the connection still serves.
        var res = try client.request(.get, lb.url("/huge"), .{});
        var one: [10]u8 = undefined;
        try res.reader().readSliceAll(&one);
        res.deinit();
    }
    {
        var res = try client.request(.get, lb.url("/hello"), .{});
        defer res.deinit();
        const body = try res.readAllAlloc(gpa, 1024);
        defer gpa.free(body);
        try testing.expectEqualStrings("hello h2", body);
    }
    try testing.expectEqual(@as(usize, 1), client.dialCount());
}

test "http2: gzip decoding and a streamed upload" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var plain_buf: [50_000]u8 = undefined;
    const plain = testPlain(&plain_buf);
    const gz = try testGzip(gpa, plain, 6);
    defer gpa.free(gz);
    h2_test_gz = gz;
    defer h2_test_gz = "";

    var lb: H2ClientLoopback = undefined;
    try lb.start(io);
    defer lb.finish();
    var client = Client.init(io, gpa, .{ .http2 = .alpn(), .decompress = .gzip(1 << 20), .total_timeout_ms = 5000 });
    defer client.deinit();
    try primeH2c(&client, lb.url("/"));

    {
        var res = try client.request(.get, lb.url("/gz"), .{});
        defer res.deinit();
        try testing.expectEqual(Proto.http2, res.proto());
        try testing.expect(res.uncompressed);
        try testing.expectEqual(@as(?[]const u8, null), res.header("content-encoding"));
        const body = try res.readAllAlloc(gpa, 1 << 20);
        defer gpa.free(body);
        try testing.expectEqualSlices(u8, plain, body);
    }
    // Unknown length, a declared one, and small writes the writer buffers.
    for ([_]?u64{ null, plain.len, null }, [_]usize{ 7000, 7000, 100 }) |length, piece| {
        var up = try client.requestStreaming(.post, lb.url("/echo"), .{}, length);
        var at: usize = 0;
        while (at < plain.len) : (at += piece) try up.writer().writeAll(plain[at..@min(plain.len, at + piece)]);
        var res = try up.finish();
        defer res.deinit();
        try testing.expectEqual(Proto.http2, res.proto());
        const body = try res.readAllAlloc(gpa, 1 << 20);
        defer gpa.free(body);
        try testing.expectEqualSlices(u8, plain, body);
    }
    try testing.expectEqual(@as(usize, 1), client.dialCount());
}

test "http2: an upgrade request never takes an h2 connection" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var lb: H2ClientLoopback = undefined;
    try lb.start(io);
    defer lb.finish();
    var client = Client.init(io, gpa, .{ .http2 = .alpn(), .total_timeout_ms = 5000 });
    defer client.deinit();
    try primeH2c(&client, lb.url("/"));

    var res = try client.request(.get, lb.url("/hello"), .{ .headers = &.{
        .{ .name = "Connection", .value = "Upgrade" },
        .{ .name = "Upgrade", .value = "websocket" },
    } });
    defer res.deinit();
    try testing.expectEqual(Proto.http1_1, res.proto());
    // A second connection, dialed for HTTP/1.1; the h2 one is still idle.
    try testing.expectEqual(@as(usize, 2), client.dialCount());
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());
}

test "http2: at max_conns_per_host, a request that needs HTTP/1.1 evicts the idle h2 connection" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var lb: H2ClientLoopback = undefined;
    try lb.start(io);
    defer lb.finish();
    var client = Client.init(io, gpa, .{ .http2 = .alpn(), .total_timeout_ms = 5000, .pool = .{ .max_conns_per_host = 1 } });
    defer client.deinit();
    // The origin's one slot: an h2 connection, idle in the pool.
    const url = try http.Url.parse(lb.url("/"));
    var reused = false;
    const conn = try client.checkoutConn(url, &reused, null, true, false, dialPlain);
    try h2glue.start(conn);
    client.pool.release(conn, client.nowMs());

    var res = try client.request(.get, lb.url("/hello"), .{ .headers = &.{
        .{ .name = "Connection", .value = "Upgrade" },
        .{ .name = "Upgrade", .value = "websocket" },
    } });
    defer res.deinit();
    try testing.expectEqual(Proto.http1_1, res.proto());
    try testing.expectEqual(@as(usize, 2), client.dialCount());
    try testing.expectEqual(@as(usize, 0), client.poolIdleCount());
}

test "http2: a session that saw GOAWAY or broke is not reused" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var lb: H2ClientLoopback = undefined;
    try lb.start(io);
    defer lb.finish();
    var client = Client.init(io, gpa, .{ .http2 = .alpn() });
    defer client.deinit();
    const url = try http.Url.parse(lb.url("/"));
    for (0..3) |case| {
        const conn = try client.dialPlain(url, false);
        defer conn.destroy();
        try h2glue.start(conn);
        const s = &conn.h2.?.session;
        switch (case) {
            0 => {},
            1 => s.goaway = .{ .last_stream_id = 0, .code = .no_error },
            else => s.broken = error.ProtocolError,
        }
        try testing.expectEqual(case == 0, h2glue.release(conn));
    }
}

test "http2: a response field h1 could not carry is a malformed response" {
    var buf: [256]u8 = undefined;
    const ok = try h2glue.headFromFields(204, &.{
        .{ .name = ":status", .value = "204" },
        .{ .name = "content-length", .value = "0" },
        .{ .name = "x-a", .value = "1" },
    }, &buf);
    try testing.expectEqual(@as(u16, 204), ok.status);
    try testing.expectEqualStrings("No Content", ok.reason);
    try testing.expectEqual(@as(?u64, 0), ok.content_length);
    try testing.expectEqualStrings("content-length: 0\r\nx-a: 1\r\n", ok.header_block);
    for ([_]hpack.Field{
        .{ .name = "Content-Type", .value = "text/plain" }, // uppercase (RFC 9113 §8.2.1)
        .{ .name = "bad name", .value = "x" },
        .{ .name = "", .value = "x" },
        .{ .name = "x-a", .value = "1\r\nx-injected: 2" },
    }) |f| {
        try testing.expectError(error.MalformedResponse, h2glue.headFromFields(200, &.{f}, &buf));
    }
    try testing.expectError(error.HeadTooLarge, h2glue.headFromFields(200, &.{.{ .name = "x-a", .value = "1" }}, buf[0..4]));
}

// ── fuzz: an h2 response head as the h1 block the client reads ──────────────
//
// `headFromFields` copies field names and values a server chose into an h1
// header block. Beyond "no panic": a block it accepts reads back as exactly
// the non-pseudo fields, in order — no field split, merged or injected (a CR
// or LF smuggled in a value would add a line) — and a refusal is typed.

const H2HeadMark = fz.Marker(enum { ok, malformed, too_large });

const h2_head_seeds = [_][]const u8{
    testkit.fuzz.seed("content-type\x00text/plain\x00set-cookie\x00a=1\x00:status\x00200"),
    testkit.fuzz.seed("content-length\x0012\x00content-length\x0013"),
    testkit.fuzz.seed("Bad\x00x"),
    testkit.fuzz.seed("x-a\x00v\r\nx-b: injected"),
    testkit.fuzz.seed("x\x00  padded  "),
    testkit.fuzz.seed(""),
};

test "fuzz driver: HTTP_FUZZ (client h2 head)" {
    try fz.fuzz_driver.run(fuzzH2Head, .{ .prefix = "HTTP_FUZZ", .name = "http-client-h2-head" });
}

test "fuzz harness: client h2 head, 300 seeds, reaches every outcome" {
    try H2HeadMark.reach(fuzzH2Head, "http-client-h2-head", 300);
}

test "fuzz: an h2 response head becomes the same fields in the h1 block, or a typed refusal" {
    try testing.fuzz({}, fuzzH2HeadSmith, .{ .corpus = &h2_head_seeds });
}

fn fuzzH2HeadSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzH2Head, smith, script[0..n]);
}

fn fuzzH2Head(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var input: [256]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &input, &h2_head_seeds);
    // NUL-separated name, value, name, value, …
    var fields_buf: [16]hpack.Field = undefined;
    var n: usize = 0;
    var parts = std.mem.splitScalar(u8, input[0..len], 0);
    while (n < fields_buf.len) {
        const name = parts.next() orelse break;
        fields_buf[n] = .{ .name = name, .value = parts.next() orelse "" };
        n += 1;
    }
    const fields = fields_buf[0..n];
    var buf: [128]u8 = undefined;
    const block_len = src.valueRangeAtMost(u8, 0, buf.len);
    const head = h2glue.headFromFields(200, fields, buf[0..block_len]) catch |err| switch (err) {
        error.MalformedResponse => {
            for (fields) |f| {
                if (f.name.len != 0 and f.name[0] == ':') continue;
                if (!h2glue.isLowerToken(f.name) or !h1.isValidFieldValue(f.value)) return H2HeadMark.mark(.malformed);
            }
            return error.RefusedValidFields;
        },
        error.HeadTooLarge => return H2HeadMark.mark(.too_large),
    };
    var it = head.iterate();
    for (fields) |f| {
        if (f.name.len != 0 and f.name[0] == ':') continue;
        const got = it.next() orelse return error.FieldLost;
        if (!std.mem.eql(u8, got.name, f.name)) return error.NameChanged;
        if (!std.mem.eql(u8, got.value, std.mem.trim(u8, f.value, " \t"))) return error.ValueChanged;
    }
    if (it.next() != null) return error.FieldInjected;
    H2HeadMark.mark(.ok);
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
