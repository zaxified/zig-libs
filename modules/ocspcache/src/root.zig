// SPDX-License-Identifier: MIT
//! ocspcache — OCSP-stapling support library: discover a certificate's OCSP
//! responder URL, **fetch** a fresh signed OCSP response for it, and
//! **cache** the verified response until it needs refreshing. This is the
//! P2 production HTTPS server's OCSP-stapling *feeder*: a TLS server staples
//! a cached OCSP response into its handshake instead of forcing every client
//! to query the CA itself. Embedding the cached response into the TLS
//! `status_request` extension (RFC 6066) is the TLS server's job, not
//! this module's — see SPEC.md "Out of scope".
//!
//! ## What this module does
//!
//! - `discoverResponderUrl` — extract the OCSP responder URL from a
//!   certificate's Authority Information Access extension (RFC 5280
//!   §4.2.2.1, OID 1.3.6.1.5.5.7.1.1), locating the `accessLocation` URI of
//!   the `id-ad-ocsp` (1.3.6.1.5.5.7.48.1) `AccessDescription`. Built on the
//!   sibling `x509` module's bounds-safe DER reader (`extensions.parseElement`
//!   / `findExtensions` / `iterate`) — never `std.crypto.Certificate.parse`
//!   on untrusted input.
//! - `Transport` — an injectable fetch seam (`fetchFn` + context pointer):
//!   `httpTransport` adapts the sibling `http` module's `Client` for
//!   production use; tests inject a mock that never touches the network.
//! - `Cache` — fetch + verify-before-cache + serve:
//!   - `refresh(subject, issuer, now_unix)` builds an OCSP request
//!     (`ocsp.buildRequest`), fetches it from the discovered responder URL
//!     (POST by default, or the RFC 6960 Appendix A.1.1 GET form via
//!     `Config.fetch_method`), and — **only if** `ocsp.verify` accepts the
//!     response AND its status is `good` — caches the raw response bytes.
//!     Every other outcome (unreachable responder, `tryLater`, a tampered or
//!     unverifiable response, a `revoked`/`unknown` status) returns a typed
//!     error and leaves any existing cache entry **untouched** — the
//!     soft-fail stapling posture (see SPEC.md).
//!   - `getStapled(subject, now_unix)` returns the cached raw OCSP-response
//!     DER to staple, or `null` if there is no entry or it has genuinely
//!     expired (`now_unix > nextUpdate`).
//!   - `needsRefresh(subject, now_unix)` — whether a scheduler should call
//!     `refresh` now: absent, or within `Config.refresh_margin_seconds` of
//!     `nextUpdate`, so a fresh response is ready before the cached one
//!     expires.
//!
//! ## Security posture
//!
//! Every fetched response is verified via `ocsp.verify` — with a
//! caller-supplied `now_unix`, never a system clock — **before** anything
//! from it is cached or returned by `getStapled`. Fetch and cache sizes are
//! both bounded (`Config.max_response_bytes`, `Config.max_entries`). No
//! panics on malformed/hostile input — every failure mode is a typed error.
//!
//! Provenance: clean-room from RFC 6960 §4.2.2 (OCSP over HTTP) and RFC 5280
//! §4.2.2.1 (Authority Information Access), built on this repo's `ocsp`,
//! `http`, and `x509` modules. See SPEC.md / README.md.

const std = @import("std");
const ocsp = @import("ocsp");
const http = @import("http");
const x509 = @import("x509");

const ext = x509.extensions;
const der = std.crypto.Certificate.der;
const Element = der.Element;

pub const meta = .{
    .platform = .any,
    .role = .util, // fetch + cache logic; I/O goes through the injectable Transport seam
    .concurrency = .single_owner, // one thread/loop owns a Cache; callers add their own locking if shared
    .model_after = "RFC 6960 §4.2.2 (OCSP over HTTP) + RFC 5280 §4.2.2.1 (AIA); nginx/Apache OCSP-stapling soft-fail posture",
    .deps = .{ "ocsp", "http", "x509" },
};

// ════════════════════════════════════════════════════════════════════════════
// Responder URL discovery (Authority Information Access, RFC 5280 §4.2.2.1)
// ════════════════════════════════════════════════════════════════════════════

const Malformed = error{Malformed};

fn el(bytes: []const u8, index: u32) Malformed!Element {
    return ext.parseElement(bytes, index) catch error.Malformed;
}

/// Raw identifier octet — for context-specific/unnamed tags where the `Tag`
/// enum has no variant, mirroring the idiom `ocsp`/`x509` use.
fn rawTag(e: Element) u8 {
    return @as(u8, @bitCast(e.identifier));
}

fn contentOf(bytes: []const u8, e: Element) []const u8 {
    return bytes[e.slice.start..e.slice.end];
}

/// `id-ad-ocsp` (1.3.6.1.5.5.7.48.1) — the `accessMethod` this module looks
/// for inside a certificate's Authority Information Access extension.
const oid_ad_ocsp = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01 };

pub const DiscoverError = error{Malformed};

/// Extract the OCSP responder URL from `cert_der`'s Authority Information
/// Access extension (RFC 5280 §4.2.2.1, OID 1.3.6.1.5.5.7.1.1 —
/// `std.crypto.Certificate.ExtensionId.info_access`): the `accessLocation`
/// URI of the first `AccessDescription` whose `accessMethod` is `id-ad-ocsp`
/// (1.3.6.1.5.5.7.48.1). Returns `null` when the certificate is not v3, has
/// no AIA extension, or the AIA extension carries no OCSP entry — all
/// legitimate "no stapling available for this cert" outcomes, not errors. A
/// structurally malformed extension (hostile/corrupt DER) yields
/// `error.Malformed`; this never panics (built on `x509`'s bounds-safe
/// `parseElement`, never `std.crypto.Certificate.parse`).
pub fn discoverResponderUrl(cert_der: []const u8) DiscoverError!?[]const u8 {
    const cert: std.crypto.Certificate = .{ .buffer = cert_der, .index = 0 };
    const slice = (ext.findExtensions(cert) catch return error.Malformed) orelse return null;
    var it = ext.iterate(slice, cert);
    while (it.next() catch return error.Malformed) |entry| {
        if (entry.id == .info_access) return try parseAiaOcspUrl(entry.value);
    }
    return null;
}

/// `value` is the extnValue OCTET STRING content:
/// `AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription`,
/// `AccessDescription ::= SEQUENCE { accessMethod OBJECT IDENTIFIER,
/// accessLocation GeneralName }`. Only the `uniformResourceIdentifier [6]`
/// GeneralName choice is recognized (the only form any real OCSP responder
/// publishes); a non-URI accessLocation on an `id-ad-ocsp` entry is treated
/// as "no usable entry" rather than an error — the extension itself is still
/// well-formed, just not something this module can fetch from.
fn parseAiaOcspUrl(value: []const u8) Malformed!?[]const u8 {
    const seq = try el(value, 0);
    if (seq.identifier.tag != .sequence) return error.Malformed;
    var pos = seq.slice.start;
    while (pos < seq.slice.end) {
        const ad = try el(value, pos); // AccessDescription
        if (ad.identifier.tag != .sequence) return error.Malformed;
        pos = ad.slice.end;
        const method = try el(value, ad.slice.start);
        if (method.identifier.tag != .object_identifier) return error.Malformed;
        const loc = try el(value, method.slice.end); // accessLocation GeneralName
        if (rawTag(loc) == 0x86 and std.mem.eql(u8, contentOf(value, method), &oid_ad_ocsp)) {
            return contentOf(value, loc); // uniformResourceIdentifier [6] IA5String content
        }
    }
    return null;
}

// ════════════════════════════════════════════════════════════════════════════
// Fetch transport seam
// ════════════════════════════════════════════════════════════════════════════

pub const FetchMethod = enum {
    /// RFC 6960 §4.2.1 — the DER `OCSPRequest` as the POST body,
    /// `Content-Type: application/ocsp-request`. The priority / default form.
    post,
    /// RFC 6960 Appendix A.1.1 — the base64-encoded `OCSPRequest` appended as
    /// a URL path segment. `FetchRequest.url` must already be the *full*
    /// GET-form URL (see `buildGetUrl`); `Cache.refresh` builds it.
    get,
};

pub const FetchRequest = struct {
    method: FetchMethod = .post,
    /// POST: the responder URL to POST to. GET: the full URL including the
    /// base64 request path segment.
    url: []const u8,
    /// POST body — the DER `OCSPRequest` bytes. Unused for GET.
    body: []const u8 = &.{},
    /// Bound on the response body a `Transport` implementation must enforce
    /// (e.g. via a limited read) — never buffer an unbounded responder reply.
    max_response_bytes: usize,
};

pub const FetchResponse = struct {
    /// HTTP status code. `Cache.refresh` only accepts 200.
    status: u16,
    /// `gpa`-owned response body bytes; `Cache.refresh` frees them.
    body: []u8,
};

pub const FetchError = error{
    /// Network/connect/protocol failure, or a non-2xx the transport chose to
    /// surface this way (implementations may also just return the status and
    /// let `Cache.refresh` reject it — either is fine, `refresh` checks both).
    TransportFailed,
    /// The response body exceeded `FetchRequest.max_response_bytes`.
    ResponseTooLarge,
    OutOfMemory,
};

/// An injectable fetch transport: `fetchFn` + an opaque context pointer,
/// the same vtable-by-hand idiom `std.mem.Allocator` uses. Production code
/// uses `httpTransport` (backed by the sibling `http` module's `Client`);
/// tests inject a mock so `refresh` is fully testable without a network.
pub const Transport = struct {
    context: *anyopaque,
    fetchFn: *const fn (context: *anyopaque, gpa: std.mem.Allocator, req: FetchRequest) FetchError!FetchResponse,

    pub fn fetch(self: Transport, gpa: std.mem.Allocator, req: FetchRequest) FetchError!FetchResponse {
        return self.fetchFn(self.context, gpa, req);
    }
};

const post_content_type_header = [_]http.Header{.{ .name = "Content-Type", .value = "application/ocsp-request" }};

/// A `Transport` backed by the sibling `http` module's `Client`
/// (`POST`/`GET`, `Content-Type: application/ocsp-request` on POST, bounded
/// via `Response.readAllAlloc`). `client` must outlive any `Cache` that uses
/// the returned `Transport`.
pub fn httpTransport(client: *http.Client) Transport {
    return .{ .context = client, .fetchFn = httpFetch };
}

fn httpFetch(context: *anyopaque, gpa: std.mem.Allocator, req: FetchRequest) FetchError!FetchResponse {
    const client: *http.Client = @ptrCast(@alignCast(context));
    const method: http.Method = if (req.method == .post) .post else .get;
    var response = client.request(method, req.url, .{
        .headers = if (req.method == .post) &post_content_type_header else &.{},
        .body = if (req.method == .post) req.body else null,
    }) catch return error.TransportFailed;
    defer response.deinit();

    const body = response.readAllAlloc(gpa, req.max_response_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.BodyTooLarge => return error.ResponseTooLarge,
        else => return error.TransportFailed,
    };
    return .{ .status = response.status, .body = body };
}

pub const BuildGetUrlError = error{OutOfMemory};

/// Build the RFC 6960 Appendix A.1.1 GET-form URL:
/// `{responder_url}/{base64(req_der)}`, with base64's reserved characters
/// (`+`, `/`, `=`) percent-encoded so the result is safe as a single URL path
/// segment. Returns `gpa`-owned bytes.
pub fn buildGetUrl(gpa: std.mem.Allocator, responder_url: []const u8, req_der: []const u8) BuildGetUrlError![]u8 {
    const b64_len = std.base64.standard.Encoder.calcSize(req_der.len);
    const b64_buf = try gpa.alloc(u8, b64_len);
    defer gpa.free(b64_buf);
    const b64 = std.base64.standard.Encoder.encode(b64_buf, req_der);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, responder_url);
    if (responder_url.len == 0 or responder_url[responder_url.len - 1] != '/') try out.append(gpa, '/');
    for (b64) |c| {
        switch (c) {
            '+' => try out.appendSlice(gpa, "%2B"),
            '/' => try out.appendSlice(gpa, "%2F"),
            '=' => try out.appendSlice(gpa, "%3D"),
            else => try out.append(gpa, c),
        }
    }
    return out.toOwnedSlice(gpa);
}

// ════════════════════════════════════════════════════════════════════════════
// Cache — fetch, verify-before-cache, serve
// ════════════════════════════════════════════════════════════════════════════

pub const Config = struct {
    /// `CertID` hash algorithm for the built request (see `ocsp.RequestOptions`).
    hash: ocsp.RequestHashAlgo = .sha1,
    /// POST (RFC 6960 §4.2.1, the priority form) or GET (Appendix A.1.1).
    fetch_method: FetchMethod = .post,
    /// Bound on a fetched response body.
    max_response_bytes: usize = 64 * 1024,
    /// Passed through to `ocsp.verify` — bounds acceptance of a response
    /// whose `nextUpdate` is absent, and is also used to synthesize this
    /// cache entry's own expiry in that case (see `refresh`).
    max_age_seconds: i64 = 24 * 60 * 60,
    /// How long before `nextUpdate` a scheduler should proactively refresh
    /// (`needsRefresh` flips true at `nextUpdate - refresh_margin_seconds`),
    /// so a replacement response is ready before the cached one expires.
    refresh_margin_seconds: i64 = 12 * 60 * 60,
    /// Cache-size guard. A TLS server staples a handful of its own
    /// certificates, not an open-ended set — this bounds memory against a
    /// caller accidentally calling `refresh` with unbounded distinct certs.
    max_entries: usize = 64,
};

const CacheKey = [32]u8;

/// Cache key = SHA-256 of the subject certificate DER — a fixed-size key
/// regardless of certificate size, and stable across calls for the same cert.
fn keyOf(subject_cert_der: []const u8) CacheKey {
    var key: CacheKey = undefined;
    std.crypto.hash.sha2.Sha256.hash(subject_cert_der, &key, .{});
    return key;
}

const Entry = struct {
    /// The verified raw `OCSPResponse` DER to staple. `gpa`-owned.
    response_der: []u8,
    this_update_unix: i64,
    /// Always set: `verdict.next_update_unix` when the response carried one,
    /// else `this_update_unix + Config.max_age_seconds` (mirroring the same
    /// bound `ocsp.verify` itself applied to accept the response).
    next_update_unix: i64,
};

pub const RefreshError = error{
    /// The subject certificate's AIA extension has no `id-ad-ocsp` entry.
    NoResponderUrl,
    /// The subject certificate (or its AIA extension) is malformed.
    Malformed,
    /// The responder was unreachable, or the transport failed otherwise.
    TransportFailed,
    /// The fetched response exceeded `Config.max_response_bytes`.
    ResponseTooLarge,
    /// The responder returned an HTTP status other than 200.
    ResponderHttpError,
    /// `OCSPResponse.responseStatus != successful` (e.g. `tryLater`).
    ResponderUnsuccessful,
    /// A successful response that isn't `id-pkix-ocsp-basic`.
    UnsupportedResponseType,
    /// `ocsp.verify` rejected the response (bad signature, untrusted
    /// responder, CertID mismatch, stale, nonce mismatch, ...).
    VerifyFailed,
    /// The response verified but the certificate's status is not `good`
    /// (revoked or unknown) — not cached/stapled; the caller decides policy.
    CertNotGood,
    /// `Config.max_entries` reached and this cert isn't already cached.
    CacheFull,
    OutOfMemory,
};

/// Every path above that returns an error leaves any existing cache entry
/// for this certificate **completely untouched** — this is the soft-fail
/// stapling posture (see SPEC.md "Soft-fail"): a responder outage or a
/// single bad fetch never evicts a still-valid cached response.
pub const Cache = struct {
    gpa: std.mem.Allocator,
    transport: Transport,
    config: Config,
    entries: std.AutoHashMapUnmanaged(CacheKey, Entry) = .empty,

    pub fn init(gpa: std.mem.Allocator, transport: Transport, config: Config) Cache {
        return .{ .gpa = gpa, .transport = transport, .config = config };
    }

    pub fn deinit(self: *Cache) void {
        var it = self.entries.valueIterator();
        while (it.next()) |entry| self.gpa.free(entry.response_der);
        self.entries.deinit(self.gpa);
        self.* = undefined;
    }

    /// The cached raw OCSP-response DER to staple for `subject_cert_der`, or
    /// `null` if there is no entry, or the entry has genuinely expired
    /// (`now_unix > nextUpdate`) — never staple a response known to be past
    /// its validity window, even as a soft-fail fallback.
    pub fn getStapled(self: *Cache, subject_cert_der: []const u8, now_unix: i64) ?[]const u8 {
        const entry = self.entries.get(keyOf(subject_cert_der)) orelse return null;
        if (now_unix > entry.next_update_unix) return null;
        return entry.response_der;
    }

    /// Whether a scheduler should call `refresh` now: no cached entry, or
    /// within `Config.refresh_margin_seconds` of `nextUpdate`.
    pub fn needsRefresh(self: *Cache, subject_cert_der: []const u8, now_unix: i64) bool {
        const entry = self.entries.get(keyOf(subject_cert_der)) orelse return true;
        return now_unix > entry.next_update_unix - self.config.refresh_margin_seconds;
    }

    /// Fetch a fresh OCSP response for `subject_cert_der` (issued by
    /// `issuer_cert_der`), verify it, and — only on full success — cache it.
    /// `now_unix` is used both for `ocsp.verify`'s freshness check and as
    /// this call's notion of "now"; never read from a system clock.
    pub fn refresh(
        self: *Cache,
        subject_cert_der: []const u8,
        issuer_cert_der: []const u8,
        now_unix: i64,
    ) RefreshError!void {
        const responder_url = (discoverResponderUrl(subject_cert_der) catch return error.Malformed) orelse
            return error.NoResponderUrl;

        const req_der = ocsp.buildRequest(self.gpa, subject_cert_der, issuer_cert_der, .{ .hash = self.config.hash }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Malformed => return error.Malformed,
        };
        defer self.gpa.free(req_der);

        var owned_get_url: ?[]u8 = null;
        defer if (owned_get_url) |u| self.gpa.free(u);

        const freq: FetchRequest = switch (self.config.fetch_method) {
            .post => .{ .method = .post, .url = responder_url, .body = req_der, .max_response_bytes = self.config.max_response_bytes },
            .get => blk: {
                const full = buildGetUrl(self.gpa, responder_url, req_der) catch return error.OutOfMemory;
                owned_get_url = full;
                break :blk .{ .method = .get, .url = full, .max_response_bytes = self.config.max_response_bytes };
            },
        };

        const resp = self.transport.fetch(self.gpa, freq) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ResponseTooLarge => return error.ResponseTooLarge,
            error.TransportFailed => return error.TransportFailed,
        };
        defer self.gpa.free(resp.body);

        if (resp.status != 200) return error.ResponderHttpError;

        const parsed = ocsp.parseResponse(resp.body) catch return error.Malformed;
        if (parsed.status != .successful) return error.ResponderUnsuccessful;
        const basic_present = parsed.basic != null;
        if (!basic_present) return error.UnsupportedResponseType;

        const verdict = ocsp.verify(parsed, issuer_cert_der, subject_cert_der, .{
            .now_unix = now_unix,
            .max_age_seconds = self.config.max_age_seconds,
        }) catch return error.VerifyFailed;

        if (verdict.status != .good) return error.CertNotGood;

        const next_update = verdict.next_update_unix orelse (verdict.this_update_unix + self.config.max_age_seconds);
        const key = keyOf(subject_cert_der);

        if (!self.entries.contains(key) and self.entries.count() >= self.config.max_entries) {
            return error.CacheFull;
        }

        const owned = self.gpa.dupe(u8, resp.body) catch return error.OutOfMemory;
        errdefer self.gpa.free(owned);

        const gop = self.entries.getOrPut(self.gpa, key) catch return error.OutOfMemory;
        if (gop.found_existing) self.gpa.free(gop.value_ptr.response_der);
        gop.value_ptr.* = .{
            .response_der = owned,
            .this_update_unix = verdict.this_update_unix,
            .next_update_unix = next_update,
        };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Low-level AIA-parsing tests (internal-function access; higher-level
// fetch/cache tests live in ocspcache_test.zig)
// ════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

test "parseAiaOcspUrl: single AccessDescription, id-ad-ocsp with a URI" {
    const url = "http://ocsp.example.org/";
    // AccessDescription ::= SEQUENCE { accessMethod, accessLocation [6] IA5String }
    const method = [_]u8{ 0x06, oid_ad_ocsp.len } ++ oid_ad_ocsp;
    const loc = [_]u8{ 0x86, url.len } ++ url.*;
    const ad = [_]u8{ 0x30, method.len + loc.len } ++ method ++ loc;
    const value = [_]u8{ 0x30, ad.len } ++ ad;

    const got = (try parseAiaOcspUrl(&value)).?;
    try testing.expectEqualStrings(url, got);
}

test "parseAiaOcspUrl: id-ad-ocsp with a non-URI accessLocation yields null (not the OID's content)" {
    // Same id-ad-ocsp OID as the matching case, but accessLocation is a
    // directoryName [4] choice, not a uniformResourceIdentifier [6] — the
    // module's documented contract treats this as "no usable entry", not an
    // error, and MUST NOT return the non-URI bytes as if they were a URL.
    const dir_name_content = "not a url, a directoryName content instead";
    const method = [_]u8{ 0x06, oid_ad_ocsp.len } ++ oid_ad_ocsp;
    const loc = [_]u8{ 0xa4, dir_name_content.len } ++ dir_name_content.*;
    const ad = [_]u8{ 0x30, method.len + loc.len } ++ method ++ loc;
    const value = [_]u8{ 0x30, ad.len } ++ ad;

    try testing.expect((try parseAiaOcspUrl(&value)) == null);
}

test "parseAiaOcspUrl: caIssuers-only (no id-ad-ocsp) yields null" {
    const oid_ad_ca_issuers = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02 }; // 1.3.6.1.5.5.7.48.2
    const url = "http://ca.example.org/issuer.crt";
    const method = [_]u8{ 0x06, oid_ad_ca_issuers.len } ++ oid_ad_ca_issuers;
    const loc = [_]u8{ 0x86, url.len } ++ url.*;
    const ad = [_]u8{ 0x30, method.len + loc.len } ++ method ++ loc;
    const value = [_]u8{ 0x30, ad.len } ++ ad;

    try testing.expect((try parseAiaOcspUrl(&value)) == null);
}

test "parseAiaOcspUrl: definitely-truncated inputs yield Malformed" {
    const cases = [_][]const u8{
        &.{}, // empty
        &.{0x30}, // outer tag with no length octet at all
        &.{ 0x30, 0x06, 0x30, 0x04, 0x06, 0x01 }, // AccessDescription's OID length overruns the buffer
    };
    for (cases) |c| {
        try testing.expectError(error.Malformed, parseAiaOcspUrl(c));
    }
}

test "parseAiaOcspUrl: hostile/oversized-length inputs never panic (typed error or a clean null)" {
    // Mirrors ocsp's own malformed-DER idiom (ocsp_test.zig): the only
    // contract here is "no panic" — an oversized/indefinite length is free to
    // surface as a typed error OR, if `x509`'s reader still resolves it to an
    // in-bounds (if meaningless) element, as a clean `null`.
    const cases = [_][]const u8{
        &.{ 0x30, 0x80 }, // indefinite/oversized length
        &.{ 0x30, 0x02, 0x06, 0x01 }, // AccessDescription is not a SEQUENCE
    };
    for (cases) |c| {
        _ = parseAiaOcspUrl(c) catch continue;
    }
}

test "buildGetUrl: percent-encodes reserved base64 characters" {
    const gpa = testing.allocator;
    // Bytes chosen so standard base64 definitely emits '+', '/' and '='.
    const req = [_]u8{ 0xff, 0xef, 0xfe };
    const url = try buildGetUrl(gpa, "http://ocsp.example.org", &req);
    defer gpa.free(url);
    const prefix = "http://ocsp.example.org/";
    try testing.expect(std.mem.startsWith(u8, url, prefix));
    const b64_segment = url[prefix.len..];
    // No raw base64 special characters leak into the path segment — every
    // '+'/'/'/'=' must have been percent-encoded away.
    try testing.expect(std.mem.indexOfScalar(u8, b64_segment, '+') == null);
    try testing.expect(std.mem.indexOfScalar(u8, b64_segment, '/') == null);
    try testing.expect(std.mem.indexOfScalar(u8, b64_segment, '=') == null);
    try testing.expect(std.mem.indexOf(u8, b64_segment, "%2B") != null or
        std.mem.indexOf(u8, b64_segment, "%2F") != null or
        std.mem.indexOf(u8, b64_segment, "%3D") != null);
}

// ════════════════════════════════════════════════════════════════════════════
// fuzz: the two untrusted surfaces
// ════════════════════════════════════════════════════════════════════════════
//
// This module had NO `testing.fuzz` target at all, and `scripts/fuzz-sweep.sh`
// derives its module list from exactly that grep — so `ocspcache` was absent
// from every repo-wide sweep ever run. It looked covered from outside and was
// not. Both of its untrusted inputs are real:
//
//   * `discoverResponderUrl`/`parseAiaOcspUrl` walk the Authority Information
//     Access extension of a certificate the module did not issue;
//   * `Cache.refresh` consumes an HTTP body chosen by whoever answers the
//     responder URL — an unauthenticated network peer — and hands it to
//     `ocsp.parseResponse`/`ocsp.verify`.
//
// Raw entropy is rejected by the first DER header, so both harnesses build the
// bytes into real structure: an `AccessDescription` around a fuzzed OID and
// URI, byte mutations of a real production certificate, and mutations of the
// real captured GoDaddy OCSP response. The reachability test below is the
// standing proof that these inputs traverse the whole path.

/// A `Transport` that returns caller-chosen bytes, so `refresh`'s response
/// handling can be fuzzed without a network.
const FuzzTransport = struct {
    status: u16 = 200,
    body: []const u8 = &.{},

    fn fetch(context: *anyopaque, gpa: std.mem.Allocator, req: FetchRequest) FetchError!FetchResponse {
        _ = req;
        const self: *FuzzTransport = @ptrCast(@alignCast(context));
        return .{ .status = self.status, .body = gpa.dupe(u8, self.body) catch return error.OutOfMemory };
    }

    fn transport(self: *FuzzTransport) Transport {
        return .{ .context = self, .fetchFn = fetch };
    }
};

/// Emit one DER TLV (`tag`, length, `content`) into `out`.
fn derTlv(alloc: std.mem.Allocator, tag: u8, content: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.append(alloc, tag);
    if (content.len < 0x80) {
        try out.append(alloc, @intCast(content.len));
    } else {
        try out.append(alloc, 0x82);
        var be: [2]u8 = undefined;
        std.mem.writeInt(u16, &be, @intCast(content.len), .big);
        try out.appendSlice(alloc, &be);
    }
    try out.appendSlice(alloc, content);
    return out.toOwnedSlice(alloc);
}

/// `SEQUENCE { SEQUENCE { OID <oid>, [tag] <loc> } }` — the AIA extnValue
/// shape `parseAiaOcspUrl` walks, with the fuzzed bytes as the OID content and
/// the accessLocation content.
fn buildAia(alloc: std.mem.Allocator, oid: []const u8, loc_tag: u8, loc: []const u8) ![]u8 {
    const method = try derTlv(alloc, 0x06, oid);
    const location = try derTlv(alloc, loc_tag, loc);
    const inner = try std.mem.concat(alloc, u8, &.{ method, location });
    const ad = try derTlv(alloc, 0x30, inner);
    return derTlv(alloc, 0x30, ad);
}

const fuzz_loc_tags = [_]u8{ 0x86, 0xa4, 0x82, 0x30, 0x04 };

fn fuzzAia(_: void, smith: *std.testing.Smith) !void {
    const goldens = @import("goldens.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var raw: [256]u8 = undefined;
    smith.bytes(&raw);
    const raw_len: usize = smith.valueRangeAtMost(u16, 0, raw.len);

    // 1. Structured: a real AccessDescription around fuzzed bytes. The OID is
    //    either the genuine id-ad-ocsp (so the URI branch is taken) or fuzzed.
    const oid: []const u8 = if (smith.value(bool)) &oid_ad_ocsp else raw[0..@min(raw_len, 16)];
    const loc_tag = fuzz_loc_tags[smith.index(fuzz_loc_tags.len)];
    const value = try buildAia(a, oid, loc_tag, raw[0..raw_len]);
    _ = parseAiaOcspUrl(value) catch {};

    // 2. Unstructured, straight at the extension parser.
    _ = parseAiaOcspUrl(raw[0..raw_len]) catch {};

    // 3. A real production certificate with a fuzzer-chosen byte overwritten,
    //    through the full `findExtensions` -> `iterate` -> AIA walk.
    const mutant = try a.dupe(u8, &goldens.godaddy_leaf_der);
    const n = @min(smith.valueRangeAtMost(u8, 0, 8), raw_len);
    for (0..n) |i| mutant[smith.index(mutant.len)] = raw[i];
    _ = discoverResponderUrl(mutant) catch {};

    // 4. And every truncation is a typed error, never a walk off the end.
    const cut = smith.valueRangeAtMost(u16, 0, @intCast(goldens.godaddy_leaf_der.len));
    _ = discoverResponderUrl(goldens.godaddy_leaf_der[0..cut]) catch {};
}

test "fuzz: the AIA responder-URL walk never panics" {
    try std.testing.fuzz({}, fuzzAia, .{});
}

fn fuzzRefresh(_: void, smith: *std.testing.Smith) !void {
    const goldens = @import("goldens.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const raw_len: usize = smith.valueRangeAtMost(u16, 0, raw.len);

    // The responder's answer: the real captured response, mutated or truncated
    // (so `ocsp.parseResponse` and `ocsp.verify` are actually reached), or
    // arbitrary bytes.
    const body: []const u8 = switch (smith.valueRangeAtMost(u8, 0, 3)) {
        0 => &goldens.godaddy_response_der,
        1 => blk: {
            const mutant = try a.dupe(u8, &goldens.godaddy_response_der);
            const n = @min(smith.valueRangeAtMost(u8, 0, 8), raw_len);
            for (0..n) |i| mutant[smith.index(mutant.len)] = raw[i];
            break :blk mutant;
        },
        2 => goldens.godaddy_response_der[0..smith.valueRangeAtMost(u16, 0, @intCast(goldens.godaddy_response_der.len))],
        else => raw[0..raw_len],
    };

    var mock: FuzzTransport = .{
        .status = if (smith.value(bool)) 200 else smith.valueRangeAtMost(u16, 0, 599),
        .body = body,
    };
    var cache = Cache.init(std.testing.allocator, mock.transport(), .{
        .fetch_method = if (smith.value(bool)) .post else .get,
        .max_response_bytes = 64 * 1024,
    });
    defer cache.deinit();

    const now: i64 = switch (smith.valueRangeAtMost(u8, 0, 2)) {
        0 => goldens.now_unix,
        1 => goldens.next_update_unix + 1,
        else => @as(i64, smith.value(i32)),
    };

    cache.refresh(&goldens.godaddy_leaf_der, &goldens.godaddy_issuer_der, now) catch {};
    _ = cache.getStapled(&goldens.godaddy_leaf_der, now);
    _ = cache.needsRefresh(&goldens.godaddy_leaf_der, now);

    // A fuzzed subject/issuer pair too — the request-building side.
    cache.refresh(raw[0..raw_len], &goldens.godaddy_issuer_der, now) catch {};
}

test "fuzz: Cache.refresh never panics on a hostile responder body" {
    try std.testing.fuzz({}, fuzzRefresh, .{});
}

test "the ocspcache fuzz harnesses reach the AIA walk and ocsp.verify (reachability)" {
    // Guards the class-B defect: a harness that cannot reach what it covers.
    const goldens = @import("goldens.zig");
    const a = testing.allocator;

    // 1. The AIA builder produces a document the parser resolves to a URL, so
    //    the fuzzed variants really are exercising the matching branch.
    {
        // `buildAia` composes intermediate TLVs; the fuzz harness runs it in an
        // arena, so do the same here rather than free four pieces by hand.
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const value = try buildAia(arena.allocator(), &oid_ad_ocsp, 0x86, "http://ocsp.example.org/");
        try testing.expectEqualStrings("http://ocsp.example.org/", (try parseAiaOcspUrl(value)).?);
    }

    // 2. The unmutated real certificate resolves through `discoverResponderUrl`
    //    — the path modes 3 and 4 mutate.
    try testing.expectEqualStrings(
        "http://ocsp.godaddy.com/",
        (try discoverResponderUrl(&goldens.godaddy_leaf_der)).?,
    );

    // 3. The refresh harness's own transport + cache reach `ocsp.verify` and a
    //    cached staple: with the unmutated captured response the whole
    //    fetch -> parse -> verify -> cache path completes.
    {
        var mock: FuzzTransport = .{ .status = 200, .body = &goldens.godaddy_response_der };
        var cache = Cache.init(a, mock.transport(), .{});
        defer cache.deinit();
        try cache.refresh(&goldens.godaddy_leaf_der, &goldens.godaddy_issuer_der, goldens.now_unix);
        try testing.expect(cache.getStapled(&goldens.godaddy_leaf_der, goldens.now_unix) != null);
    }

    // 4. And both harness bodies run to completion on fixed input.
    var s1: std.testing.Smith = .{ .in = &([_]u8{0x01} ** 32 ++ [_]u8{0x00} ** 1024) };
    try fuzzAia({}, &s1);
    var s2: std.testing.Smith = .{ .in = &([_]u8{0x00} ** 1024) };
    try fuzzRefresh({}, &s2);
}

test {
    _ = @import("ocspcache_test.zig");
    _ = @import("goldens.zig");
}
