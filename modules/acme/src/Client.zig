// SPDX-License-Identifier: MIT

//! The ACME v2 (RFC 8555) client: directory discovery, nonce management,
//! account registration, order → authorization → HTTP-01 challenge →
//! finalize (CSR) → certificate download. Modeled on
//! `golang.org/x/crypto/acme` (design only — clean-room from RFC 8555).
//!
//! All HTTP goes through the sibling `http.Client` (every ACME POST is an
//! ES256 JWS built by `jws.zig`); the HTTP-01 challenge is served by
//! `Responder`, an intercepting `router.Middleware` for the caller's
//! `http.Server` (a `router.Handler` is a stateless fn pointer, so the
//! token map travels as middleware state — same pattern as
//! `metrics.Endpoint`).
//!
//! **The default directory is the Let's Encrypt STAGING environment** —
//! its certificates are NOT publicly trusted. Production issuance (with
//! its strict rate limits) is a deliberate opt-in:
//! `.directory_url = acme.letsencrypt_production`.
//!
//! Nonce handling per RFC 8555 §6.5: the `Replay-Nonce` header of *every*
//! response (errors included) refills the cache; a `badNonce` problem is
//! retried with the fresh nonce, transparently. Malformed CA responses
//! surface as `error.MalformedResponse` — never a panic.
//!
//! Concurrency: the `Responder` is fully thread-safe (server connection
//! threads read it while the order flow writes). Client state (nonce cache)
//! is internally synchronized, but drive `register`/`obtain` from one
//! thread at a time — they share the account state machine.

const std = @import("std");
const http = @import("http");
const router = @import("router");
const jws = @import("jws.zig");
const x509 = @import("x509.zig");

const Allocator = std.mem.Allocator;
const Client = @This();

/// Let's Encrypt staging — fake certs, generous rate limits. The default.
pub const letsencrypt_staging = "https://acme-staging-v02.api.letsencrypt.org/directory";
/// Let's Encrypt production — real certs, strict rate limits. Opt-in only.
pub const letsencrypt_production = "https://acme-v02.api.letsencrypt.org/directory";

io: std.Io,
gpa: Allocator,
/// Caller-owned transport; all ACME requests go through it.
http_client: *http.Client,
/// The ES256 account key (see `jws.KeyPair`).
account_key: jws.KeyPair,
options: Options,
/// Resolved directory endpoints (owned), null until first use.
dir: ?Directory,
/// Account URL from newAccount (the JWS `kid`), owned.
kid: ?[]u8,
/// One cached anti-replay nonce (owned), refilled from every response.
nonce: ?[]u8,
nonce_lock: std.atomic.Mutex,
responder: Responder,
/// Last ACME problem document, for diagnostics (see `lastProblem`).
problem_buf: [256]u8,
problem_len: usize,

pub const Options = struct {
    /// ACME directory URL. **Defaults to Let's Encrypt STAGING** (untrusted
    /// test certificates!) so accidental runs cannot burn production rate
    /// limits — set `letsencrypt_production` explicitly to go live.
    directory_url: []const u8 = letsencrypt_staging,
    /// Optional account contact URLs, e.g. "mailto:admin@example.org".
    contact: []const []const u8 = &.{},
    /// RFC 8555 §7.3: account creation asserts agreement with the CA's
    /// terms of service. Leaving this true is what every ACME client does;
    /// false omits the assertion (CAs with ToS will then refuse).
    terms_of_service_agreed: bool = true,
    /// Delay between authorization/order status polls (a `Retry-After`
    /// header overrides it, capped at 15 s).
    poll_interval_ms: u32 = 1000,
    /// Poll attempts per phase before `error.PollTimeout`.
    max_polls: u32 = 60,
    /// Upper bound for one ACME response body.
    max_response_bytes: usize = 1 << 20,
};

pub const Error = error{
    OutOfMemory,
    /// Transport failure (connect/TLS/read/write) from `http.Client`.
    HttpFailed,
    Timeout,
    Canceled,
    /// The CA response was not the expected ACME JSON/headers.
    MalformedResponse,
    /// The CA refused with a problem document — `lastProblem` has details.
    AcmeProblem,
    /// An authorization ended in an error state (or offered no HTTP-01).
    AuthorizationFailed,
    /// The order ended `invalid`.
    OrderFailed,
    /// A status poll exceeded `Options.max_polls`.
    PollTimeout,
    /// Key generation / JWS / CSR signing failed (astronomically rare).
    SigningFailed,
    /// A requested identifier is not a valid LDH hostname (wildcards need
    /// dns-01, which this module does not implement).
    InvalidDomain,
    /// A `kid`-signed request was attempted before registration.
    NotRegistered,
};

const Directory = struct {
    new_nonce: []u8,
    new_account: []u8,
    new_order: []u8,

    fn deinit(d: *Directory, gpa: Allocator) void {
        gpa.free(d.new_nonce);
        gpa.free(d.new_account);
        gpa.free(d.new_order);
    }
};

/// `io` must support net + concurrency operations (e.g. `std.Io.Threaded`);
/// `http_client` stays caller-owned (share it with other subsystems freely).
/// Generate `account_key` once via `jws.KeyPair.generate(io)` and persist it
/// with `x509.ecPrivateKeyToPem` — the account key IS the account identity.
pub fn init(
    io: std.Io,
    gpa: Allocator,
    http_client: *http.Client,
    account_key: jws.KeyPair,
    options: Options,
) Client {
    return .{
        .io = io,
        .gpa = gpa,
        .http_client = http_client,
        .account_key = account_key,
        .options = options,
        .dir = null,
        .kid = null,
        .nonce = null,
        .nonce_lock = .unlocked,
        .responder = Responder.init(gpa),
        .problem_buf = undefined,
        .problem_len = 0,
    };
}

pub fn deinit(c: *Client) void {
    if (c.dir) |*d| d.deinit(c.gpa);
    if (c.kid) |k| c.gpa.free(k);
    if (c.nonce) |n| c.gpa.free(n);
    c.responder.deinit();
    c.* = undefined;
}

/// The account URL (JWS `kid`) once registered, or null.
pub fn accountUrl(c: *const Client) ?[]const u8 {
    return c.kid;
}

/// The most recent ACME problem document ("type: detail", truncated), for
/// diagnostics after `error.AcmeProblem` and friends. Borrowed — valid
/// until the next request through this client.
pub fn lastProblem(c: *const Client) ?[]const u8 {
    if (c.problem_len == 0) return null;
    return c.problem_buf[0..c.problem_len];
}

/// The HTTP-01 challenge responder to wire into the server that answers
/// for the ordered domains on port 80: register
/// `client.challengeResponder().middleware()` on the `router` (before
/// routes). The order flow populates and cleans its token map.
pub fn challengeResponder(c: *Client) *Responder {
    return &c.responder;
}

// ── account ─────────────────────────────────────────────────────────────────

/// Create (or fetch) the ACME account for the account key — RFC 8555 §7.3.
/// Idempotent: an existing account comes back 200 with the same URL, so
/// re-running with a persisted key is safe. `obtain` calls this
/// automatically; explicit use is for checking credentials early.
pub fn register(c: *Client) Error!void {
    try c.ensureDirectory();
    if (c.kid != null) return;

    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var out: std.Io.Writer.Allocating = .init(a);
    var js: std.json.Stringify = .{ .writer = &out.writer, .options = .{} };
    writeRegisterPayload(&js, c.options) catch return error.OutOfMemory;

    const pr = try c.postJws(a, c.dir.?.new_account, out.written(), .jwk);
    if (pr.status != 200 and pr.status != 201) {
        c.noteProblem(pr.body);
        return error.AcmeProblem;
    }
    const loc = pr.location orelse return error.MalformedResponse;
    c.kid = try c.gpa.dupe(u8, loc);
}

fn writeRegisterPayload(js: *std.json.Stringify, options: Options) !void {
    try js.beginObject();
    if (options.terms_of_service_agreed) {
        try js.objectField("termsOfServiceAgreed");
        try js.write(true);
    }
    if (options.contact.len != 0) {
        try js.objectField("contact");
        try js.write(options.contact);
    }
    try js.endObject();
}

// ── the order flow ──────────────────────────────────────────────────────────

/// An issued certificate: the PEM chain as the CA delivered it (leaf
/// first) plus the freshly generated leaf key.
pub const Certificate = struct {
    /// `application/pem-certificate-chain` body, gpa-owned.
    chain_pem: []u8,
    /// The leaf private key as an `EC PRIVATE KEY` PEM, gpa-owned.
    key_pem: []u8,
    /// Leaf `notAfter`, epoch seconds — feed it to `needsRenewal` later.
    not_after: u64,

    pub fn deinit(cert: *Certificate, gpa: Allocator) void {
        gpa.free(cert.chain_pem);
        gpa.free(cert.key_pem);
        cert.* = undefined;
    }
};

/// Run the whole RFC 8555 issuance for `domains` (dNSName identifiers):
/// newOrder → HTTP-01 authorizations (served via `challengeResponder`) →
/// finalize with a fresh P-256 CSR → download the chain. Registers the
/// account on first use. The challenge responder must already be reachable
/// through the domains' port 80 before calling this.
pub fn obtain(c: *Client, domains: []const []const u8) Error!Certificate {
    if (domains.len == 0) return error.InvalidDomain;
    for (domains) |name| {
        if (!x509.isValidDomain(name)) return error.InvalidDomain;
    }
    try c.register();

    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    const a = arena.allocator();

    // newOrder (§7.4).
    var out: std.Io.Writer.Allocating = .init(a);
    var js: std.json.Stringify = .{ .writer = &out.writer, .options = .{} };
    writeOrderPayload(&js, domains) catch return error.OutOfMemory;

    const pr = try c.postJws(a, c.dir.?.new_order, out.written(), .kid);
    if (pr.status != 201) {
        c.noteProblem(pr.body);
        return error.AcmeProblem;
    }
    const order_url = pr.location orelse return error.MalformedResponse;
    const order = try parseOrder(a, pr.body);

    // Authorizations (§7.5) — one HTTP-01 round per identifier.
    if (order.authorizations.len == 0) return error.MalformedResponse;
    for (order.authorizations) |authz_url| try c.solveAuthorization(a, authz_url);

    // All authorizations valid → the order becomes ready (it may have been
    // ready immediately when every authorization was already valid). A
    // pre-finalize `valid` would be a reused order whose certificate
    // belongs to a key we never had — refuse it rather than hand back a
    // chain that cannot match our fresh key.
    const ready = try c.awaitOrder(a, order_url, &.{ .ready, .valid });
    if (ready.status == .valid) {
        c.note("order already valid before finalize (reused order, no key)");
        return error.OrderFailed;
    }

    // Finalize with a CSR for a fresh certificate key (§7.4; the account
    // key MUST NOT be reused as the certificate key — §11.1).
    const cert_key = jws.KeyPair.generate(c.io);
    const csr_der = x509.csrDer(a, cert_key, domains) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidDomain => return error.InvalidDomain,
        error.SigningFailed, error.ValueTooLarge => return error.SigningFailed,
    };
    const csr_b64 = try jws.base64UrlEncodeAlloc(a, csr_der);

    var fout: std.Io.Writer.Allocating = .init(a);
    var fjs: std.json.Stringify = .{ .writer = &fout.writer, .options = .{} };
    writeFinalizePayload(&fjs, csr_b64) catch return error.OutOfMemory;

    const fpr = try c.postJws(a, ready.finalize, fout.written(), .kid);
    if (fpr.status != 200) {
        c.noteProblem(fpr.body);
        return error.AcmeProblem;
    }
    const done = try c.awaitOrder(a, order_url, &.{.valid});
    const cert_url = done.certificate orelse return error.MalformedResponse;

    // Download the chain (§7.4.2) — POST-as-GET, PEM body.
    const cpr = try c.postJws(a, cert_url, "", .kid);
    if (cpr.status != 200) {
        c.noteProblem(cpr.body);
        return error.AcmeProblem;
    }
    if (x509.pemBlockCount("CERTIFICATE", cpr.body) == 0) return error.MalformedResponse;
    const not_after = x509.certNotAfter(c.gpa, cpr.body) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };

    const chain_pem = try c.gpa.dupe(u8, cpr.body);
    errdefer c.gpa.free(chain_pem);
    const key_pem = try x509.ecPrivateKeyToPem(c.gpa, cert_key);
    return .{ .chain_pem = chain_pem, .key_pem = key_pem, .not_after = not_after };
}

fn writeOrderPayload(js: *std.json.Stringify, domains: []const []const u8) !void {
    try js.beginObject();
    try js.objectField("identifiers");
    try js.beginArray();
    for (domains) |name| {
        try js.beginObject();
        try js.objectField("type");
        try js.write("dns");
        try js.objectField("value");
        try js.write(name);
        try js.endObject();
    }
    try js.endArray();
    try js.endObject();
}

fn writeFinalizePayload(js: *std.json.Stringify, csr_b64: []const u8) !void {
    try js.beginObject();
    try js.objectField("csr");
    try js.write(csr_b64);
    try js.endObject();
}

/// One authorization: fetch it, serve + trigger its HTTP-01 challenge,
/// poll to `valid`. Already-valid authorizations are accepted as-is.
fn solveAuthorization(c: *Client, a: Allocator, authz_url: []const u8) Error!void {
    const pr = try c.postJws(a, authz_url, "", .kid);
    if (pr.status != 200) {
        c.noteProblem(pr.body);
        return error.AcmeProblem;
    }
    const authz = try parseAuthz(a, pr.body);
    switch (authz.status) {
        .valid => return,
        .pending => {},
        else => return error.AuthorizationFailed,
    }
    const challenge = authz.http01 orelse {
        c.note("authorization offers no http-01 challenge");
        return error.AuthorizationFailed;
    };

    // Publish the key authorization, then tell the CA to validate (§7.5.1).
    var ka_buf: [jws.max_key_authorization_len]u8 = undefined;
    const key_auth = jws.keyAuthorization(&ka_buf, challenge.token, c.account_key.public_key) catch
        return error.MalformedResponse; // CA sent a non-token
    try c.responder.set(challenge.token, key_auth);
    defer c.responder.remove(challenge.token);

    const tpr = try c.postJws(a, challenge.url, "{}", .kid);
    if (tpr.status != 200) {
        c.noteProblem(tpr.body);
        return error.AcmeProblem;
    }

    // Poll the authorization until the CA verdict (§7.5.1).
    var polls: u32 = 0;
    var wait_ms: ?u64 = null; // no wait before the first re-check
    while (polls < c.options.max_polls) : (polls += 1) {
        if (wait_ms) |ms| try c.sleepMs(ms);
        const ppr = try c.postJws(a, authz_url, "", .kid);
        if (ppr.status != 200) {
            c.noteProblem(ppr.body);
            return error.AcmeProblem;
        }
        const state = try parseAuthz(a, ppr.body);
        switch (state.status) {
            .valid => return,
            .pending, .processing => wait_ms = ppr.retry_after_ms orelse c.options.poll_interval_ms,
            else => {
                c.noteProblem(ppr.body);
                return error.AuthorizationFailed;
            },
        }
    }
    return error.PollTimeout;
}

/// Poll the order URL until its status is one of `targets` (or `invalid` →
/// `error.OrderFailed`).
fn awaitOrder(c: *Client, a: Allocator, order_url: []const u8, targets: []const Status) Error!OrderInfo {
    var polls: u32 = 0;
    var wait_ms: ?u64 = null;
    while (polls < c.options.max_polls) : (polls += 1) {
        if (wait_ms) |ms| try c.sleepMs(ms);
        const pr = try c.postJws(a, order_url, "", .kid);
        if (pr.status != 200) {
            c.noteProblem(pr.body);
            return error.AcmeProblem;
        }
        const order = try parseOrder(a, pr.body);
        if (std.mem.indexOfScalar(Status, targets, order.status) != null) return order;
        switch (order.status) {
            .invalid => {
                c.noteProblem(pr.body);
                return error.OrderFailed;
            },
            .pending, .ready, .processing => wait_ms = pr.retry_after_ms orelse c.options.poll_interval_ms,
            else => return error.MalformedResponse,
        }
    }
    return error.PollTimeout;
}

// ── ACME JSON vocabulary ────────────────────────────────────────────────────

/// RFC 8555 §7.1.6 resource states (orders, authorizations, challenges).
const Status = enum { pending, processing, ready, valid, invalid, deactivated, expired, revoked, unknown };

fn statusFromString(s: []const u8) Status {
    return std.meta.stringToEnum(Status, s) orelse .unknown;
}

const OrderInfo = struct {
    status: Status,
    finalize: []const u8,
    certificate: ?[]const u8,
    authorizations: []const []const u8,
};

fn parseOrder(a: Allocator, body: []const u8) Error!OrderInfo {
    const OrderJson = struct {
        status: []const u8 = "",
        authorizations: []const []const u8 = &.{},
        finalize: []const u8 = "",
        certificate: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSliceLeaky(OrderJson, a, body, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    return .{
        .status = statusFromString(parsed.status),
        .finalize = parsed.finalize,
        .certificate = parsed.certificate,
        .authorizations = parsed.authorizations,
    };
}

const AuthzInfo = struct {
    status: Status,
    http01: ?ChallengeInfo,
};

const ChallengeInfo = struct {
    url: []const u8,
    token: []const u8,
};

fn parseAuthz(a: Allocator, body: []const u8) Error!AuthzInfo {
    const AuthzJson = struct {
        status: []const u8 = "",
        challenges: []const ChallengeJson = &.{},

        const ChallengeJson = struct {
            type: []const u8 = "",
            url: []const u8 = "",
            token: []const u8 = "",
            status: []const u8 = "",
        };
    };
    const parsed = std.json.parseFromSliceLeaky(AuthzJson, a, body, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    var http01: ?ChallengeInfo = null;
    for (parsed.challenges) |ch| {
        if (std.mem.eql(u8, ch.type, "http-01")) {
            http01 = .{ .url = ch.url, .token = ch.token };
            break;
        }
    }
    return .{ .status = statusFromString(parsed.status), .http01 = http01 };
}

const Problem = struct {
    type: []const u8 = "",
    detail: []const u8 = "",
};

const bad_nonce_type = "urn:ietf:params:acme:error:badNonce";

fn isBadNonce(gpa: Allocator, body: []const u8) bool {
    const parsed = std.json.parseFromSlice(Problem, gpa, body, .{
        .ignore_unknown_fields = true,
    }) catch return false;
    defer parsed.deinit();
    return std.mem.eql(u8, parsed.value.type, bad_nonce_type);
}

/// Record a problem document (or a raw-body prefix) for `lastProblem`.
fn noteProblem(c: *Client, body: []const u8) void {
    if (std.json.parseFromSlice(Problem, c.gpa, body, .{ .ignore_unknown_fields = true })) |parsed| {
        defer parsed.deinit();
        if (parsed.value.type.len != 0) {
            var w: std.Io.Writer = .fixed(&c.problem_buf);
            w.print("{s}: {s}", .{ parsed.value.type, parsed.value.detail }) catch {}; // truncation is fine
            c.problem_len = w.buffered().len;
            return;
        }
    } else |_| {}
    const n = @min(body.len, c.problem_buf.len);
    @memcpy(c.problem_buf[0..n], body[0..n]);
    c.problem_len = n;
}

fn note(c: *Client, msg: []const u8) void {
    const n = @min(msg.len, c.problem_buf.len);
    @memcpy(c.problem_buf[0..n], msg[0..n]);
    c.problem_len = n;
}

// ── directory + nonces ──────────────────────────────────────────────────────

fn ensureDirectory(c: *Client) Error!void {
    if (c.dir != null) return;

    var res = c.http_client.request(.get, c.options.directory_url, .{}) catch |err|
        return mapHttpError(err);
    defer res.deinit();
    try c.harvestNonce(&res);
    if (res.status != 200) return error.MalformedResponse;
    const body = res.readAllAlloc(c.gpa, c.options.max_response_bytes) catch |err|
        return mapHttpError(err);
    defer c.gpa.free(body);

    const DirectoryJson = struct {
        newNonce: []const u8 = "",
        newAccount: []const u8 = "",
        newOrder: []const u8 = "",
    };
    const parsed = std.json.parseFromSlice(DirectoryJson, c.gpa, body, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    defer parsed.deinit();
    inline for (.{ parsed.value.newNonce, parsed.value.newAccount, parsed.value.newOrder }) |url| {
        _ = http.Url.parse(url) catch return error.MalformedResponse;
    }

    var dir: Directory = undefined;
    dir.new_nonce = try c.gpa.dupe(u8, parsed.value.newNonce);
    errdefer c.gpa.free(dir.new_nonce);
    dir.new_account = try c.gpa.dupe(u8, parsed.value.newAccount);
    errdefer c.gpa.free(dir.new_account);
    dir.new_order = try c.gpa.dupe(u8, parsed.value.newOrder);
    c.dir = dir;
}

/// Stash the `Replay-Nonce` of any response (RFC 8555 §6.5).
fn harvestNonce(c: *Client, res: *http.Client.Response) Error!void {
    const value = res.header("replay-nonce") orelse return;
    const copy = try c.gpa.dupe(u8, value);
    lockSpin(&c.nonce_lock);
    defer c.nonce_lock.unlock();
    if (c.nonce) |old| c.gpa.free(old);
    c.nonce = copy;
}

/// Take the cached nonce, or fetch a fresh one from newNonce (§7.2).
/// Caller owns the returned string.
fn takeNonce(c: *Client) Error![]u8 {
    {
        lockSpin(&c.nonce_lock);
        defer c.nonce_lock.unlock();
        if (c.nonce) |n| {
            c.nonce = null;
            return n;
        }
    }
    const dir = c.dir orelse return error.NotRegistered;
    var res = c.http_client.request(.head, dir.new_nonce, .{}) catch |err|
        return mapHttpError(err);
    defer res.deinit();
    const value = res.header("replay-nonce") orelse return error.MalformedResponse;
    return c.gpa.dupe(u8, value);
}

// ── the signed POST ─────────────────────────────────────────────────────────

const KeyMode = enum { jwk, kid };

const PostResult = struct {
    status: u16,
    /// Response body (allocated from the caller's allocator).
    body: []u8,
    /// `Location` header, if any (same allocator).
    location: ?[]u8,
    /// Parsed integer `Retry-After`, capped, in milliseconds.
    retry_after_ms: ?u64,
};

/// POST `payload` ("" = POST-as-GET, §6.3) to `url` as an ES256 JWS.
/// Handles nonce refill and transparently retries `badNonce` rejections
/// (§6.5). Returns whatever status the CA answered — callers decide.
/// `a` provides the result's memory (an arena in the flow).
fn postJws(c: *Client, a: Allocator, url: []const u8, payload: []const u8, mode: KeyMode) Error!PostResult {
    const kid: ?[]const u8 = switch (mode) {
        .jwk => null,
        .kid => c.kid orelse return error.NotRegistered,
    };
    var attempts_left: u8 = 3;
    while (true) {
        const nonce = try c.takeNonce();
        defer c.gpa.free(nonce);
        const body_json = jws.sign(c.gpa, c.account_key, payload, .{
            .nonce = nonce,
            .url = url,
            .kid = kid,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.SigningFailed => return error.SigningFailed,
        };
        defer c.gpa.free(body_json);

        var res = c.http_client.request(.post, url, .{
            .headers = &.{.{ .name = "Content-Type", .value = "application/jose+json" }},
            .body = body_json,
        }) catch |err| return mapHttpError(err);
        defer res.deinit();
        try c.harvestNonce(&res);

        const body = res.readAllAlloc(a, c.options.max_response_bytes) catch |err|
            return mapHttpError(err);
        if (res.status == 400 and attempts_left > 0 and isBadNonce(c.gpa, body)) {
            attempts_left -= 1;
            a.free(body);
            continue; // fresh nonce was already harvested from this response
        }
        return .{
            .status = res.status,
            .body = body,
            .location = if (res.header("location")) |l| try a.dupe(u8, l) else null,
            .retry_after_ms = parseRetryAfter(res.header("retry-after")),
        };
    }
}

/// Integer `Retry-After` seconds → capped milliseconds (HTTP-date form is
/// ignored — the default poll interval covers it).
fn parseRetryAfter(value: ?[]const u8) ?u64 {
    const v = value orelse return null;
    const secs = std.fmt.parseInt(u32, std.mem.trim(u8, v, " "), 10) catch return null;
    return @min(@as(u64, secs) * 1000, 15_000);
}

fn mapHttpError(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        error.Timeout => error.Timeout,
        else => error.HttpFailed,
    };
}

fn sleepMs(c: *Client, ms: u64) Error!void {
    const d: std.Io.Clock.Duration = .{
        .raw = .fromMilliseconds(@intCast(@min(ms, 60_000))),
        .clock = .awake,
    };
    d.sleep(c.io) catch return error.Canceled;
}

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// ── the HTTP-01 challenge responder ─────────────────────────────────────────

/// Serves `GET /.well-known/acme-challenge/<token>` → key authorization
/// (RFC 8555 §8.3) from a thread-safe token map that the order flow
/// populates. Use as an intercepting `router.Middleware` (register before
/// routes): requests outside the ACME path pass through untouched; unknown
/// tokens under it answer 404.
pub const Responder = struct {
    gpa: Allocator,
    lock: std.atomic.Mutex = .unlocked,
    map: std.StringHashMapUnmanaged([]const u8) = .empty,

    pub const path_prefix = "/.well-known/acme-challenge/";

    pub fn init(gpa: Allocator) Responder {
        return .{ .gpa = gpa };
    }

    pub fn deinit(r: *Responder) void {
        var it = r.map.iterator();
        while (it.next()) |e| {
            r.gpa.free(e.key_ptr.*);
            r.gpa.free(e.value_ptr.*);
        }
        r.map.deinit(r.gpa);
        r.* = undefined;
    }

    /// Publish `key_auth` under `token` (both copied); replaces an
    /// existing entry. The order flow calls this — manual use is only for
    /// out-of-band setups.
    pub fn set(r: *Responder, token: []const u8, key_auth: []const u8) error{OutOfMemory}!void {
        const value = try r.gpa.dupe(u8, key_auth);
        errdefer r.gpa.free(value);
        lockSpin(&r.lock);
        defer r.lock.unlock();
        const gop = try r.map.getOrPut(r.gpa, token);
        if (gop.found_existing) {
            r.gpa.free(gop.value_ptr.*);
        } else {
            gop.key_ptr.* = r.gpa.dupe(u8, token) catch |err| {
                _ = r.map.remove(token);
                return err;
            };
        }
        gop.value_ptr.* = value;
    }

    pub fn remove(r: *Responder, token: []const u8) void {
        lockSpin(&r.lock);
        const kv = r.map.fetchRemove(token);
        r.lock.unlock();
        if (kv) |e| {
            r.gpa.free(e.key);
            r.gpa.free(e.value);
        }
    }

    /// Copy the key authorization for `token` into `buf` (entries may be
    /// removed concurrently, so a borrowed slice would race).
    pub fn lookup(r: *Responder, token: []const u8, buf: []u8) ?[]const u8 {
        lockSpin(&r.lock);
        defer r.lock.unlock();
        const value = r.map.get(token) orelse return null;
        if (value.len > buf.len) return null;
        @memcpy(buf[0..value.len], value);
        return buf[0..value.len];
    }

    /// Number of tokens currently published.
    pub fn count(r: *Responder) usize {
        lockSpin(&r.lock);
        defer r.lock.unlock();
        return r.map.count();
    }

    /// The intercepting middleware — `router.Handler` is a stateless fn
    /// pointer, so the token map rides along as middleware state (the
    /// `metrics.Endpoint` pattern).
    pub fn middleware(r: *Responder) router.Middleware {
        return .{ .state = r, .run = respond };
    }

    fn respond(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
        const r: *Responder = @ptrCast(@alignCast(state.?));
        const path = ctx.req.path;
        if ((ctx.req.method != .get and ctx.req.method != .head) or
            !std.mem.startsWith(u8, path, path_prefix))
            return next.run(ctx);

        const token = path[path_prefix.len..];
        var buf: [jws.max_key_authorization_len]u8 = undefined;
        const key_auth = if (std.mem.indexOfScalar(u8, token, '/') == null)
            r.lookup(token, &buf)
        else
            null; // nested paths are never tokens
        if (key_auth) |ka| {
            ctx.res.setStatus(200);
            // §8.3: application/octet-stream for the key authorization.
            try ctx.res.setHeader("Content-Type", "application/octet-stream");
            try ctx.res.writeAll(ka);
        } else {
            ctx.res.setStatus(404);
            try ctx.res.setHeader("Content-Type", "text/plain");
            try ctx.res.writeAll("unknown ACME challenge token\n");
        }
    }
};

// ── tests (offline units) ───────────────────────────────────────────────────

const testing = std.testing;

test "defaults: staging directory, ToS agreement on" {
    const options: Options = .{};
    try testing.expectEqualStrings(letsencrypt_staging, options.directory_url);
    try testing.expect(options.terms_of_service_agreed);
    try testing.expect(std.mem.indexOf(u8, letsencrypt_staging, "staging") != null);
    try testing.expect(std.mem.indexOf(u8, letsencrypt_production, "staging") == null);
}

test "status + problem + retry-after parsing" {
    try testing.expectEqual(Status.valid, statusFromString("valid"));
    try testing.expectEqual(Status.unknown, statusFromString("weird"));

    try testing.expect(isBadNonce(
        testing.allocator,
        "{\"type\":\"urn:ietf:params:acme:error:badNonce\",\"detail\":\"stale\"}",
    ));
    try testing.expect(!isBadNonce(
        testing.allocator,
        "{\"type\":\"urn:ietf:params:acme:error:rateLimited\"}",
    ));
    try testing.expect(!isBadNonce(testing.allocator, "not json at all"));

    try testing.expectEqual(@as(?u64, null), parseRetryAfter(null));
    try testing.expectEqual(@as(?u64, 2000), parseRetryAfter("2"));
    try testing.expectEqual(@as(?u64, 15_000), parseRetryAfter("3600")); // capped
    try testing.expectEqual(@as(?u64, null), parseRetryAfter("Wed, 21 Oct 2026 07:28:00 GMT"));
}

test "order/authz JSON parsing tolerates unknown fields, rejects junk" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const order = try parseOrder(a,
        \\{"status":"ready","expires":"2026-01-01T00:00:00Z","identifiers":[],
        \\ "authorizations":["https://ca/authz/1","https://ca/authz/2"],
        \\ "finalize":"https://ca/finalize/9","wildcard":false}
    );
    try testing.expectEqual(Status.ready, order.status);
    try testing.expectEqual(@as(usize, 2), order.authorizations.len);
    try testing.expectEqualStrings("https://ca/finalize/9", order.finalize);
    try testing.expectEqual(@as(?[]const u8, null), order.certificate);

    const authz = try parseAuthz(a,
        \\{"status":"pending","identifier":{"type":"dns","value":"x.example"},
        \\ "challenges":[
        \\   {"type":"dns-01","url":"https://ca/ch/7","token":"ddd"},
        \\   {"type":"http-01","url":"https://ca/ch/8","token":"ttt","status":"pending"}]}
    );
    try testing.expectEqual(Status.pending, authz.status);
    try testing.expectEqualStrings("https://ca/ch/8", authz.http01.?.url);
    try testing.expectEqualStrings("ttt", authz.http01.?.token);

    const no_http = try parseAuthz(a, "{\"status\":\"pending\",\"challenges\":[]}");
    try testing.expect(no_http.http01 == null);

    try testing.expectError(error.MalformedResponse, parseOrder(a, "[1,2"));
    try testing.expectError(error.MalformedResponse, parseAuthz(a, "<html>oops</html>"));
}

test "Responder: set/lookup/remove semantics under copies" {
    var r = Responder.init(testing.allocator);
    defer r.deinit();

    {
        // Keys and values are copied — caller memory may die.
        var tok_buf: [8]u8 = undefined;
        var ka_buf: [8]u8 = undefined;
        @memcpy(tok_buf[0..5], "tok-1");
        @memcpy(ka_buf[0..4], "ka-1");
        try r.set(tok_buf[0..5], ka_buf[0..4]);
        tok_buf = @splat(0xAA);
        ka_buf = @splat(0xAA);
    }
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("ka-1", r.lookup("tok-1", &buf).?);
    try testing.expectEqual(@as(usize, 1), r.count());

    try r.set("tok-1", "ka-2"); // replace
    try testing.expectEqualStrings("ka-2", r.lookup("tok-1", &buf).?);
    try testing.expectEqual(@as(usize, 1), r.count());

    try testing.expect(r.lookup("other", &buf) == null);
    var tiny: [1]u8 = undefined;
    try testing.expect(r.lookup("tok-1", &tiny) == null); // too small → miss, not a crash

    r.remove("tok-1");
    r.remove("tok-1"); // idempotent
    try testing.expect(r.lookup("tok-1", &buf) == null);
    try testing.expectEqual(@as(usize, 0), r.count());
}

/// Drive a router through the socket-free server codec (router's runWire).
fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(bytes);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null,
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

fn hAppRoot(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("app");
}

test "Responder middleware: serves tokens, 404s unknowns, passes the rest through" {
    var responder = Responder.init(testing.allocator);
    defer responder.deinit();
    try responder.set("the-token", "the-token.THUMBPRINT");

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(responder.middleware());
    try r.get("/", hAppRoot);

    var buf: [1024]u8 = undefined;
    // Known token → 200 + octet-stream + exact key authorization.
    const hit = runWire(&r, wire("GET", "/.well-known/acme-challenge/the-token"), &buf);
    try testing.expect(std.mem.startsWith(u8, hit, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, hit, "\r\nContent-Type: application/octet-stream\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, hit, "\r\n\r\nthe-token.THUMBPRINT"));

    // HEAD frames like GET, no body.
    const head = runWire(&r, wire("HEAD", "/.well-known/acme-challenge/the-token"), &buf);
    try testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.endsWith(u8, head, "Content-Length: 20\r\n\r\n"));

    // Unknown / nested / non-GET under the prefix → 404 from the responder.
    const miss = runWire(&r, wire("GET", "/.well-known/acme-challenge/unknown"), &buf);
    try testing.expect(std.mem.startsWith(u8, miss, "HTTP/1.1 404"));
    const nested = runWire(&r, wire("GET", "/.well-known/acme-challenge/a/b"), &buf);
    try testing.expect(std.mem.startsWith(u8, nested, "HTTP/1.1 404"));

    // Anything else flows to the app router untouched.
    const app = runWire(&r, wire("GET", "/"), &buf);
    try testing.expect(std.mem.endsWith(u8, app, "\r\n\r\napp"));

    // POST to the prefix is not the responder's business → app 404 (no routes).
    const post = runWire(&r, wire("POST", "/.well-known/acme-challenge/the-token"), &buf);
    try testing.expect(std.mem.startsWith(u8, post, "HTTP/1.1 404"));
    try testing.expect(std.mem.indexOf(u8, post, "unknown ACME challenge token") == null);
}

// ── tests (mock-ACME integration — full RFC 8555 round on loopback) ─────────

/// A fake ACME CA on `http.Server` + `router`: canned RFC 8555 responses,
/// but real verification — every JWS signature is checked server-side,
/// nonces must be issued-and-unused, the HTTP-01 key authorization is
/// fetched from the client's responder over real HTTP, and the CSR is
/// parsed + signature-verified. One `badNonce` rejection is injected to
/// exercise the client's retry.
const MockCa = struct {
    gpa: Allocator,
    io: std.Io,

    // Absolute URLs (filled after bind, before serving).
    dir_url: []u8 = &.{},
    new_nonce_url: []u8 = &.{},
    new_account_url: []u8 = &.{},
    new_order_url: []u8 = &.{},
    account_url: []u8 = &.{},
    order_url: []u8 = &.{},
    authz_url: []u8 = &.{},
    challenge_url: []u8 = &.{},
    finalize_url: []u8 = &.{},
    cert_url: []u8 = &.{},
    /// Where the client's challenge responder listens.
    challenge_base: []u8 = &.{},

    lock: std.atomic.Mutex = .unlocked,
    nonce_store: [max_nonces][24]u8 = undefined,
    nonces_issued: u32 = 0,
    nonces_consumed: [max_nonces]bool = @splat(false),
    account_key: ?jws.Es256.PublicKey = null,
    badnonce_left: u8 = 1,
    authz_polls: u32 = 0,
    challenge_ok: bool = false,
    csr_ok: bool = false,
    finalized: bool = false,
    served_processing: bool = false,
    fail_count: u32 = 0,
    fail_note_buf: [256]u8 = undefined,
    fail_note_len: usize = 0,

    const max_nonces = 64;
    const token = "DGyRejmCefe7v4NfDGDKfA-mock0";
    const domain = "acme-poc.example";

    fn setUrls(m: *MockCa, ca_port: u16, challenge_port: u16) !void {
        const gpa = m.gpa;
        m.dir_url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/dir", .{ca_port});
        m.new_nonce_url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/new-nonce", .{ca_port});
        m.new_account_url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/new-acct", .{ca_port});
        m.new_order_url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/new-order", .{ca_port});
        m.account_url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/acct/1", .{ca_port});
        m.order_url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/order/1", .{ca_port});
        m.authz_url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/authz/1", .{ca_port});
        m.challenge_url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/chall/1", .{ca_port});
        m.finalize_url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/finalize/1", .{ca_port});
        m.cert_url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/cert/1", .{ca_port});
        m.challenge_base = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}", .{challenge_port});
    }

    fn deinitUrls(m: *MockCa) void {
        inline for (.{
            m.dir_url,      m.new_nonce_url, m.new_account_url, m.new_order_url,
            m.account_url,  m.order_url,     m.authz_url,       m.challenge_url,
            m.finalize_url, m.cert_url,      m.challenge_base,
        }) |s| m.gpa.free(s);
    }

    fn fail(m: *MockCa, what: []const u8) void {
        lockSpin(&m.lock);
        defer m.lock.unlock();
        m.fail_count += 1;
        if (m.fail_note_len == 0) {
            const n = @min(what.len, m.fail_note_buf.len);
            @memcpy(m.fail_note_buf[0..n], what[0..n]);
            m.fail_note_len = n;
        }
    }

    fn failNote(m: *const MockCa) []const u8 {
        return m.fail_note_buf[0..m.fail_note_len];
    }

    fn of(ctx: *router.Ctx) *MockCa {
        return @ptrCast(@alignCast(ctx.state.?));
    }

    /// Mint a nonce whose backing bytes live in the MockCa (response
    /// headers must outlive the handler frame).
    fn mintNonce(m: *MockCa) []const u8 {
        lockSpin(&m.lock);
        defer m.lock.unlock();
        const id = m.nonces_issued;
        std.debug.assert(id < max_nonces); // the flow uses ~a dozen
        m.nonces_issued += 1;
        const text = std.fmt.bufPrint(&m.nonce_store[id], "nonce-{d}", .{id}) catch unreachable;
        return text;
    }

    /// A nonce is good exactly once, and only if we issued it (§6.5).
    fn consumeNonce(m: *MockCa, nonce: []const u8) bool {
        if (!std.mem.startsWith(u8, nonce, "nonce-")) return false;
        const id = std.fmt.parseInt(u32, nonce["nonce-".len..], 10) catch return false;
        lockSpin(&m.lock);
        defer m.lock.unlock();
        if (id >= m.nonces_issued or m.nonces_consumed[id]) return false;
        m.nonces_consumed[id] = true;
        return true;
    }

    fn stampNonce(m: *MockCa, ctx: *router.Ctx) !void {
        try ctx.res.setHeader("Replay-Nonce", m.mintNonce());
    }

    /// Read the request body, verify the JWS (signature/nonce/url/key
    /// mode), return the Verified handle. Records failures; errors answer
    /// 400 so the client also notices.
    fn readVerified(m: *MockCa, ctx: *router.Ctx, expected_url: []const u8, mode: enum { jwk, kid }) !jws.Verified {
        const body = ctx.req.reader().allocRemaining(m.gpa, .limited(64 * 1024)) catch {
            m.fail("request body unreadable");
            return error.MockJwsRejected;
        };
        defer m.gpa.free(body);

        const expected_key: ?jws.Es256.PublicKey = switch (mode) {
            .jwk => null,
            .kid => m.account_key orelse {
                m.fail("kid-mode request before newAccount");
                return error.MockJwsRejected;
            },
        };
        var v = jws.verifyFlattened(m.gpa, body, expected_key) catch |err| {
            m.fail(@errorName(err));
            return error.MockJwsRejected;
        };
        errdefer v.deinit();

        if (!std.mem.eql(u8, v.url, expected_url)) {
            m.fail("protected url mismatch");
            return error.MockJwsRejected;
        }
        if (!m.consumeNonce(v.nonce)) {
            m.fail("nonce not issued or already used");
            return error.MockJwsRejected;
        }
        switch (mode) {
            .jwk => if (v.jwk_key == null or v.kid != null) {
                m.fail("expected jwk header");
                return error.MockJwsRejected;
            },
            .kid => {
                const kid = v.kid orelse {
                    m.fail("expected kid header");
                    return error.MockJwsRejected;
                };
                if (!std.mem.eql(u8, kid, m.account_url)) {
                    m.fail("kid is not the account url");
                    return error.MockJwsRejected;
                }
            },
        }
        return v;
    }

    fn respondJson(m: *MockCa, ctx: *router.Ctx, status: u16, body: []const u8) !void {
        try m.stampNonce(ctx);
        ctx.res.setStatus(status);
        try ctx.res.setHeader("Content-Type", "application/json");
        try ctx.res.writeAll(body);
    }

    fn orderBody(m: *MockCa, buf: []u8, status: []const u8, with_cert: bool) []const u8 {
        var w: std.Io.Writer = .fixed(buf);
        w.print(
            \\{{"status":"{s}","identifiers":[{{"type":"dns","value":"{s}"}}],
            \\ "authorizations":["{s}"],"finalize":"{s}"
        , .{ status, domain, m.authz_url, m.finalize_url }) catch unreachable;
        if (with_cert) w.print(",\"certificate\":\"{s}\"", .{m.cert_url}) catch unreachable;
        w.writeAll("}") catch unreachable;
        return w.buffered();
    }
};

fn mcRejected(ctx: *router.Ctx) !void {
    ctx.res.setStatus(400);
    try ctx.res.setHeader("Content-Type", "application/problem+json");
    try ctx.res.writeAll("{\"type\":\"urn:ietf:params:acme:error:malformed\",\"detail\":\"mock rejected\"}");
}

fn mcDirectory(ctx: *router.Ctx) anyerror!void {
    const m = MockCa.of(ctx);
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print(
        \\{{"newNonce":"{s}","newAccount":"{s}","newOrder":"{s}",
        \\ "meta":{{"termsOfService":"data:text/plain,mock-tos"}}}}
    , .{ m.new_nonce_url, m.new_account_url, m.new_order_url });
    try m.respondJson(ctx, 200, w.buffered());
}

fn mcNewNonce(ctx: *router.Ctx) anyerror!void {
    const m = MockCa.of(ctx);
    try m.stampNonce(ctx);
    ctx.res.setStatus(200);
}

fn mcNewAccount(ctx: *router.Ctx) anyerror!void {
    const m = MockCa.of(ctx);
    var v = m.readVerified(ctx, m.new_account_url, .jwk) catch return mcRejected(ctx);
    defer v.deinit();

    const Payload = struct { termsOfServiceAgreed: bool = false };
    const payload = std.json.parseFromSlice(Payload, m.gpa, v.payload, .{
        .ignore_unknown_fields = true,
    }) catch {
        m.fail("newAccount payload not JSON");
        return mcRejected(ctx);
    };
    defer payload.deinit();
    if (!payload.value.termsOfServiceAgreed) m.fail("ToS not agreed");

    lockSpin(&m.lock);
    m.account_key = v.jwk_key.?;
    m.lock.unlock();

    try ctx.res.setHeader("Location", m.account_url);
    try m.respondJson(ctx, 201, "{\"status\":\"valid\"}");
}

fn mcNewOrder(ctx: *router.Ctx) anyerror!void {
    const m = MockCa.of(ctx);
    var v = m.readVerified(ctx, m.new_order_url, .kid) catch return mcRejected(ctx);
    defer v.deinit();

    // Inject one badNonce rejection to exercise the client's §6.5 retry
    // (the response still carries a fresh nonce).
    {
        lockSpin(&m.lock);
        const inject = m.badnonce_left > 0;
        if (inject) m.badnonce_left -= 1;
        m.lock.unlock();
        if (inject) {
            try m.stampNonce(ctx);
            ctx.res.setStatus(400);
            try ctx.res.setHeader("Content-Type", "application/problem+json");
            try ctx.res.writeAll("{\"type\":\"urn:ietf:params:acme:error:badNonce\",\"detail\":\"injected\"}");
            return;
        }
    }

    const Payload = struct {
        identifiers: []const struct { type: []const u8 = "", value: []const u8 = "" } = &.{},
    };
    const payload = std.json.parseFromSlice(Payload, m.gpa, v.payload, .{
        .ignore_unknown_fields = true,
    }) catch {
        m.fail("newOrder payload not JSON");
        return mcRejected(ctx);
    };
    defer payload.deinit();
    if (payload.value.identifiers.len != 1 or
        !std.mem.eql(u8, payload.value.identifiers[0].type, "dns") or
        !std.mem.eql(u8, payload.value.identifiers[0].value, MockCa.domain))
        m.fail("newOrder identifiers wrong");

    var buf: [1024]u8 = undefined;
    try ctx.res.setHeader("Location", m.order_url);
    try m.respondJson(ctx, 201, m.orderBody(&buf, "pending", false));
}

fn mcAuthz(ctx: *router.Ctx) anyerror!void {
    const m = MockCa.of(ctx);
    var v = m.readVerified(ctx, m.authz_url, .kid) catch return mcRejected(ctx);
    defer v.deinit();
    if (v.payload.len != 0) m.fail("authz fetch must be POST-as-GET");

    lockSpin(&m.lock);
    const valid = m.challenge_ok;
    m.authz_polls += 1;
    m.lock.unlock();

    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    // A dns-01 decoy first — the client must pick the http-01 entry.
    try w.print(
        \\{{"status":"{s}","identifier":{{"type":"dns","value":"{s}"}},
        \\ "challenges":[
        \\  {{"type":"dns-01","url":"{s}-nope","token":"never-this-one"}},
        \\  {{"type":"http-01","url":"{s}","token":"{s}","status":"{s}"}}]}}
    , .{
        if (valid) "valid" else @as([]const u8, "pending"),
        MockCa.domain,
        m.challenge_url,
        m.challenge_url,
        MockCa.token,
        if (valid) "valid" else @as([]const u8, "pending"),
    });
    try m.respondJson(ctx, 200, w.buffered());
}

fn mcChallenge(ctx: *router.Ctx) anyerror!void {
    const m = MockCa.of(ctx);
    var v = m.readVerified(ctx, m.challenge_url, .kid) catch return mcRejected(ctx);
    defer v.deinit();
    if (!std.mem.eql(u8, v.payload, "{}")) m.fail("challenge trigger payload must be {}");

    // Validate like a real CA: fetch the key authorization from the
    // client's responder over HTTP and compare against the account key's
    // thumbprint (§8.3). Also probe that unknown tokens 404.
    var fetcher = http.Client.init(m.io, m.gpa, .{});
    defer fetcher.deinit();

    var url_buf: [128]u8 = undefined;
    const ka_url = std.fmt.bufPrint(&url_buf, "{s}{s}{s}", .{
        m.challenge_base, Responder.path_prefix, MockCa.token,
    }) catch unreachable;
    const got = fetcher.getAlloc(m.gpa, ka_url, 4096) catch {
        m.fail("key authorization fetch failed");
        return mcRejected(ctx);
    };
    defer m.gpa.free(got);

    var expect_buf: [jws.max_key_authorization_len]u8 = undefined;
    const expected = jws.keyAuthorization(&expect_buf, MockCa.token, m.account_key.?) catch unreachable;
    if (!std.mem.eql(u8, got, expected)) {
        m.fail("key authorization mismatch");
        return mcRejected(ctx);
    }

    const bogus_url = std.fmt.bufPrint(&url_buf, "{s}{s}not-a-token", .{
        m.challenge_base, Responder.path_prefix,
    }) catch unreachable;
    var bogus = fetcher.request(.get, bogus_url, .{}) catch {
        m.fail("bogus-token probe failed");
        return mcRejected(ctx);
    };
    defer bogus.deinit();
    if (bogus.status != 404) m.fail("unknown token must 404");

    lockSpin(&m.lock);
    m.challenge_ok = true;
    m.lock.unlock();

    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("{{\"type\":\"http-01\",\"url\":\"{s}\",\"token\":\"{s}\",\"status\":\"processing\"}}", .{
        m.challenge_url, MockCa.token,
    });
    try m.respondJson(ctx, 200, w.buffered());
}

fn mcOrder(ctx: *router.Ctx) anyerror!void {
    const m = MockCa.of(ctx);
    var v = m.readVerified(ctx, m.order_url, .kid) catch return mcRejected(ctx);
    defer v.deinit();
    if (v.payload.len != 0) m.fail("order fetch must be POST-as-GET");

    lockSpin(&m.lock);
    const challenge_ok = m.challenge_ok;
    const finalized = m.finalized;
    // Serve one interim "processing" after finalize to exercise polling.
    const processing = finalized and !m.served_processing;
    if (processing) m.served_processing = true;
    m.lock.unlock();

    var buf: [1024]u8 = undefined;
    const body = if (!challenge_ok)
        m.orderBody(&buf, "pending", false)
    else if (!finalized)
        m.orderBody(&buf, "ready", false)
    else if (processing)
        m.orderBody(&buf, "processing", false)
    else
        m.orderBody(&buf, "valid", true);
    try m.respondJson(ctx, 200, body);
}

fn mcFinalize(ctx: *router.Ctx) anyerror!void {
    const m = MockCa.of(ctx);
    var v = m.readVerified(ctx, m.finalize_url, .kid) catch return mcRejected(ctx);
    defer v.deinit();
    if (!m.challenge_ok) m.fail("finalize before authorization was valid");

    const Payload = struct { csr: []const u8 = "" };
    const payload = std.json.parseFromSlice(Payload, m.gpa, v.payload, .{
        .ignore_unknown_fields = true,
    }) catch {
        m.fail("finalize payload not JSON");
        return mcRejected(ctx);
    };
    defer payload.deinit();

    // Full CSR validation: base64url DER, parse, verify signature, check
    // the SAN set matches the order, and the key differs from the account
    // key (§11.1).
    const csr_der = jws.base64UrlDecodeAlloc(m.gpa, payload.value.csr) catch {
        m.fail("csr not base64url");
        return mcRejected(ctx);
    };
    defer m.gpa.free(csr_der);
    var parsed = x509.parseCsr(m.gpa, csr_der) catch {
        m.fail("csr does not parse/verify");
        return mcRejected(ctx);
    };
    defer parsed.deinit();
    const sans_ok = parsed.sans.len == 1 and std.mem.eql(u8, parsed.sans[0], MockCa.domain);
    if (!sans_ok) m.fail("csr SAN set mismatch");
    const fresh_key = !std.mem.eql(
        u8,
        &parsed.public_key.toUncompressedSec1(),
        &m.account_key.?.toUncompressedSec1(),
    );
    if (!fresh_key) m.fail("certificate key must not be the account key");

    lockSpin(&m.lock);
    m.csr_ok = sans_ok and fresh_key;
    m.finalized = true;
    m.lock.unlock();

    var buf: [1024]u8 = undefined;
    try m.respondJson(ctx, 200, m.orderBody(&buf, "processing", false));
}

fn mcCert(ctx: *router.Ctx) anyerror!void {
    const m = MockCa.of(ctx);
    var v = m.readVerified(ctx, m.cert_url, .kid) catch return mcRejected(ctx);
    defer v.deinit();
    if (!m.finalized) m.fail("certificate fetched before finalize");

    try m.stampNonce(ctx);
    ctx.res.setStatus(200);
    try ctx.res.setHeader("Content-Type", "application/pem-certificate-chain");
    try ctx.res.writeAll(x509.test_cert_pem ++ x509.test_root_cert_pem);
}

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

test "integration: full issuance against a mock ACME CA (dogfood, JWS-verified)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var mock: MockCa = .{ .gpa = testing.allocator, .io = io };

    // ── mock CA server ──
    var ca_router = router.Router.init(testing.allocator);
    defer ca_router.deinit();
    ca_router.state = &mock;
    try ca_router.get("/dir", mcDirectory);
    try ca_router.head("/new-nonce", mcNewNonce);
    try ca_router.get("/new-nonce", mcNewNonce);
    try ca_router.post("/new-acct", mcNewAccount);
    try ca_router.post("/new-order", mcNewOrder);
    try ca_router.post("/authz/1", mcAuthz);
    try ca_router.post("/chall/1", mcChallenge);
    try ca_router.post("/order/1", mcOrder);
    try ca_router.post("/finalize/1", mcFinalize);
    try ca_router.post("/cert/1", mcCert);

    var ca_server = http.Server.init(io, testing.allocator, .{
        .handler = ca_router.handler(),
        .context = &ca_router,
    });
    defer ca_server.deinit();
    ca_server.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };

    // ── the real ACME client under test ──
    var transport = http.Client.init(io, testing.allocator, .{});
    defer transport.deinit();
    const account_key = try jws.Es256.KeyPair.generateDeterministic(@splat(11));

    var dir_url_buf: [64]u8 = undefined;
    const dir_url = try std.fmt.bufPrint(&dir_url_buf, "http://127.0.0.1:{d}/dir", .{
        ca_server.boundAddress().getPort(),
    });
    var client = Client.init(io, testing.allocator, &transport, account_key, .{
        .directory_url = dir_url,
        .contact = &.{"mailto:ops@acme-poc.example"},
        .poll_interval_ms = 10,
        .max_polls = 50,
    });
    defer client.deinit();

    // ── the client's challenge server (the "domain" the CA validates) ──
    var challenge_router = router.Router.init(testing.allocator);
    defer challenge_router.deinit();
    try challenge_router.use(client.challengeResponder().middleware());

    var challenge_server = http.Server.init(io, testing.allocator, .{
        .handler = challenge_router.handler(),
        .context = &challenge_router,
    });
    defer challenge_server.deinit();
    challenge_server.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };

    try mock.setUrls(
        ca_server.boundAddress().getPort(),
        challenge_server.boundAddress().getPort(),
    );
    defer mock.deinitUrls();

    const ca_thread = try std.Thread.spawn(.{}, serveWrap, .{&ca_server});
    defer ca_thread.join();
    defer ca_server.shutdown();
    const ch_thread = try std.Thread.spawn(.{}, serveWrap, .{&challenge_server});
    defer ch_thread.join();
    defer challenge_server.shutdown();

    // ── the whole flow ──
    var cert = try client.obtain(&.{MockCa.domain});
    defer cert.deinit(testing.allocator);

    // The mock's server-side verdicts: every JWS verified, nonces fresh,
    // key authorization served correctly, CSR well-formed.
    if (mock.fail_count != 0)
        std.debug.print("mock CA recorded failures: {d} — first: {s}\n", .{ mock.fail_count, mock.failNote() });
    try testing.expectEqual(@as(u32, 0), mock.fail_count);
    try testing.expect(mock.challenge_ok);
    try testing.expect(mock.csr_ok);
    try testing.expect(mock.finalized);
    try testing.expect(mock.served_processing); // polling really happened
    try testing.expectEqual(@as(u8, 0), mock.badnonce_left); // retry exercised

    // Client-side results.
    try testing.expectEqualStrings(x509.test_cert_pem ++ x509.test_root_cert_pem, cert.chain_pem);
    try testing.expectEqual(x509.test_cert_not_after, cert.not_after);
    const key = try x509.ecPrivateKeyFromPem(testing.allocator, cert.key_pem);
    _ = key; // parses back — a usable leaf key
    try testing.expectEqualStrings(mock.account_url, client.accountUrl().?);
    // Tokens are cleaned up after each authorization.
    try testing.expectEqual(@as(usize, 0), client.challengeResponder().count());

    // register() is idempotent — no second newAccount round.
    const nonces_before = mock.nonces_issued;
    try client.register();
    try testing.expectEqual(nonces_before, mock.nonces_issued);
}
