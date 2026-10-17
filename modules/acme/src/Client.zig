// SPDX-License-Identifier: MIT

//! The ACME v2 (RFC 8555) client: directory discovery, nonce management,
//! account registration, order → authorization → HTTP-01 / TLS-ALPN-01 /
//! DNS-01 challenge →
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
const testkit = @import("testkit");
const http = @import("http");
const datefmt = @import("datefmt");
const router = @import("router");
const jws = @import("jws.zig");
const x509 = @import("x509.zig");
const pkix = @import("x509"); // the x509 module: reads CA-supplied certificates
const rsa = @import("rsa");
const netaddr = @import("netaddr");

const Allocator = std.mem.Allocator;
const Client = @This();

/// Let's Encrypt staging — fake certs, generous rate limits. The default.
pub const letsencrypt_staging = "https://acme-staging-v02.api.letsencrypt.org/directory";
/// Let's Encrypt production — real certs, strict rate limits. Opt-in only.
pub const letsencrypt_production = "https://acme-v02.api.letsencrypt.org/directory";
/// ZeroSSL production — needs external account binding (`Options.eab`,
/// credentials from the ZeroSSL dashboard or its EAB API). No staging.
pub const zerossl = "https://acme.zerossl.com/v2/DV90";
/// Google Trust Services production — needs EAB (Google Cloud
/// `publicca` external account keys).
pub const google_trust_services = "https://dv.acme-v02.api.pki.goog/directory";
/// Google Trust Services staging — EAB from the staging `publicca` API.
pub const google_trust_services_staging = "https://dv.acme-v02.test-api.pki.goog/directory";

io: std.Io,
gpa: Allocator,
/// Caller-owned transport; all ACME requests go through it.
http_client: *http.Client,
/// The account key, ES256 or ES384 (see `jws.AnyKeyPair`); replaced by
/// `rolloverKey`.
account_key: jws.AnyKeyPair,
options: Options,
/// Resolved directory endpoints (owned), null until first use.
dir: ?Directory,
/// Account URL from newAccount (the JWS `kid`), owned.
kid: ?[]u8,
/// One cached anti-replay nonce (owned), refilled from every response.
nonce: ?[]u8,
nonce_lock: std.atomic.Mutex,
responder: Responder,
tls_alpn: TlsAlpnResponder,
/// Last ACME problem document, for diagnostics (see `lastProblem`).
problem_buf: [256]u8,
problem_len: usize,
/// `Retry-After` of the last refused request, seconds from then (see `retryAfter`).
problem_retry_after_s: ?u64,

/// Which RFC 8555 challenge the order flow solves for each authorization.
/// `http_01` serves the key authorization over port 80 (via
/// `challengeResponder`); `tls_alpn_01` (RFC 8737) serves a validation
/// certificate over TLS under ALPN `acme-tls/1` (via `tlsAlpnResponder`, whose
/// store the caller's TLS listener must consult); `dns_01` (RFC 8555 §8.4)
/// publishes a TXT record through `Options.dns_publisher` — the only one that
/// needs no port reachable from the CA, and the only one that can validate a
/// wildcard. All share the account, order, notify and poll machinery — only
/// the proof differs.
pub const ChallengeType = enum { http_01, tls_alpn_01, dns_01 };

/// How the order flow publishes a DNS-01 TXT record. Publishing is the one
/// part of DNS-01 that depends on the DNS provider (a provider's API, an RFC
/// 2136 update, a zone file a local server reloads), so it is the caller's;
/// the library computes the name and value and drives the rest.
pub const DnsPublisher = struct {
    ctx: ?*anyopaque = null,
    /// Publish TXT `value` at `name` (`_acme-challenge.<domain>`, no trailing
    /// dot) and return only once the CA's resolvers can see it: waiting out
    /// propagation is part of the job, because the CA is told to validate the
    /// moment this returns. Return false to abort the authorization
    /// (`error.DnsPublishFailed`). **Add** the value, do not replace the
    /// record set: a wildcard and its base domain validate at the same name.
    present: *const fn (ctx: ?*anyopaque, name: []const u8, value: []const u8) bool,
    /// Remove exactly that value again. Called once for every `present` that
    /// returned true, whatever the authorization's outcome.
    cleanup: *const fn (ctx: ?*anyopaque, name: []const u8, value: []const u8) void,
};

/// The DNS-01 record name for `domain`: `_acme-challenge.<domain>` (RFC 8555
/// §8.4). For a wildcard order the authorization's identifier is already the
/// base name, so this is never given a `*.`.
pub fn dns01RecordName(buf: *[dns01_max_name_len]u8, domain: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "{s}{s}", .{ dns01_label, domain }) catch unreachable; // domain <= 253
}

pub const dns01_label = "_acme-challenge.";
pub const dns01_max_name_len = dns01_label.len + 253;

/// External account binding credentials (RFC 8555 §7.3.4) a CA such as
/// ZeroSSL or Google Trust Services hands out for a pre-existing customer
/// account. Both slices stay caller-owned and must outlive the `Client`.
pub const ExternalAccountBinding = struct {
    /// The CA's key identifier (the inner JWS's `kid`).
    kid: []const u8,
    /// The raw MAC key. CAs publish it base64url-encoded: decode it with
    /// `jws.base64UrlDecodeAlloc` first, and wipe the result afterwards.
    hmac_key: []const u8,
};

/// RFC 5280 §5.3.1 CRLReason code for `revoke` (RFC 8555 §7.6). The named
/// values are the ones a CA can honour for a certificate that cannot come
/// back; the enum is non-exhaustive so any other code the CA accepts can
/// be sent as `@enumFromInt(n)` (a CA refuses an unwanted one with
/// `badRevocationReason`).
pub const Reason = enum(u8) {
    unspecified = 0,
    key_compromise = 1,
    affiliation_changed = 3,
    superseded = 4,
    cessation_of_operation = 5,
    privilege_withdrawn = 9,
    _,
};

/// Per-call knobs of `obtainWith`.
pub const ObtainOptions = struct {
    /// RFC 9773 §5: the ARI CertID of the certificate this order replaces
    /// (`x509.ariCertId`); sent as the new-order `replaces` member.
    replaces: ?[]const u8 = null,
    /// A certificate profile the CA advertises in its directory
    /// (draft-ietf-acme-profiles; Let's Encrypt: "classic", "tlsserver",
    /// "shortlived"). See `profiles`; `profile_mode` says what happens when
    /// the CA does not offer it.
    profile: ?[]const u8 = null,
    profile_mode: ProfileMode = .required,
    /// Requested validity, epoch seconds (RFC 8555 §7.4 `notBefore` /
    /// `notAfter`). Many CAs, Let's Encrypt among them, refuse orders that
    /// carry them; leave null unless the CA documents support.
    not_before: ?u64 = null,
    not_after: ?u64 = null,
    /// Pick the chain whose topmost certificate was issued by this subject
    /// common name, among the default chain and the CA's alternates
    /// (RFC 8555 §7.4.2 `Link: rel="alternate"`). No match → the default
    /// chain (the certbot and lego behaviour).
    preferred_chain: ?[]const u8 = null,
    /// Extra CSR extensions (`x509.must_staple`, or any other the CA
    /// honours); not with `obtainWithCsr`, whose CSR is the caller's.
    csr_extensions: []const x509.Extension = &.{},
};

/// What `obtainWith` does when `ObtainOptions.profile` is not in the
/// directory: fail with `error.NotSupported`, or order without a profile.
pub const ProfileMode = enum { required, preferred };

/// A certificate profile from the directory's `meta.profiles`.
pub const Profile = struct {
    name: []const u8,
    /// The CA's human-readable description (often a URL).
    description: []const u8,
};

pub const Options = struct {
    /// External account binding for `register` (default none).
    eab: ?ExternalAccountBinding = null,
    /// Algorithm of the certificate keys `obtain` mints (default ES256).
    cert_key_alg: jws.Alg = .es256,
    /// Modulus size of the certificate keys `obtain` mints when
    /// `cert_key_alg = .rs256`: 2048, 3072 or 4096 (else
    /// `error.UnsupportedKeySize`). Generation takes a while — seconds for
    /// 4096 bits in an optimized build.
    cert_rsa_bits: u16 = 2048,
    /// ACME directory URL. **Defaults to Let's Encrypt STAGING** (untrusted
    /// test certificates!) so accidental runs cannot burn production rate
    /// limits — set `letsencrypt_production` explicitly to go live.
    directory_url: []const u8 = letsencrypt_staging,
    /// Challenge type the order flow uses (default HTTP-01). Selecting
    /// `tls_alpn_01` requires the caller to have wired `tlsAlpnResponder()`
    /// into a TLS listener serving ALPN `acme-tls/1` for the ordered domains;
    /// `dns_01` requires `dns_publisher`.
    challenge_type: ChallengeType = .http_01,
    /// Publishes DNS-01 TXT records. Required for `challenge_type = .dns_01`
    /// unless `solvers` has a DNS-01 one (`obtain` refuses with
    /// `error.DnsPublisherMissing` otherwise).
    dns_publisher: ?DnsPublisher = null,
    /// Caller-supplied challenge solvers (`Solver`); the first of a type
    /// replaces the built-in solver of that type. Caller-owned.
    solvers: []const Solver = &.{},
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
    /// Resends of a request the CA answered `503 Service Unavailable`
    /// (back-off 1 s, 2 s, … or its `Retry-After` when that is at most 30 s;
    /// a longer one returns the problem with `retryAfter` set). 0 = never.
    max_unavailable_retries: u8 = 2,
};

const max_unavailable_wait_ms = 30_000;

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
    /// The CA refused with `urn:ietf:params:acme:error:rateLimited`
    /// (RFC 8555 §6.6). `retryAfter` says when to try again, if the CA said.
    RateLimited,
    /// An authorization ended in an error state (or offered no challenge of
    /// the configured type).
    AuthorizationFailed,
    /// `Options.dns_publisher.present` (or a DNS-01 `Solver`) failed.
    DnsPublishFailed,
    /// A `Solver` from `Options.solvers` failed to present its proof.
    SolverFailed,
    /// `challenge_type = .dns_01` without an `Options.dns_publisher`.
    DnsPublisherMissing,
    /// The order ended `invalid`.
    OrderFailed,
    /// A status poll exceeded `Options.max_polls`.
    PollTimeout,
    /// Key generation / JWS / CSR signing failed (astronomically rare).
    SigningFailed,
    /// A requested identifier is not a valid LDH hostname, or is a wildcard
    /// (`*.example.org`) while `challenge_type` is not `dns_01` — no other
    /// challenge can validate one (RFC 8555 §7.1.3, and CA policy).
    InvalidDomain,
    /// `Options.cert_rsa_bits` is not 2048, 3072 or 4096.
    UnsupportedKeySize,
    /// `obtainWithCsr`: the CSR does not parse, or its self-signature does
    /// not verify; `obtainWith`: `csr_extensions` repeats an OID or names
    /// the subjectAltName.
    InvalidCsr,
    /// A `kid`-signed request was attempted before registration.
    NotRegistered,
    /// The CA's directory lacks the endpoint the call needs (`keyChange`,
    /// `revokeCert`, `renewalInfo`): this CA does not offer it. For ARI the
    /// caller falls back to `needsRenewal`.
    NotSupported,
};

const Directory = struct {
    new_nonce: []u8,
    new_account: []u8,
    new_order: []u8,
    /// Optional resources (RFC 8555 §7.1.1, RFC 9773 §4), owned.
    key_change: ?[]u8 = null,
    revoke_cert: ?[]u8 = null,
    renewal_info: ?[]u8 = null,
    /// `meta.profiles` (draft-ietf-acme-profiles), owned, directory order.
    profiles: []Profile = &.{},

    fn deinit(d: *Directory, gpa: Allocator) void {
        for (d.profiles) |pr| {
            gpa.free(pr.name);
            gpa.free(pr.description);
        }
        gpa.free(d.profiles);
        gpa.free(d.new_nonce);
        gpa.free(d.new_account);
        gpa.free(d.new_order);
        if (d.key_change) |u| gpa.free(u);
        if (d.revoke_cert) |u| gpa.free(u);
        if (d.renewal_info) |u| gpa.free(u);
    }
};

/// `io` must support net + concurrency operations (e.g. `std.Io.Threaded`);
/// `http_client` stays caller-owned (share it with other subsystems freely).
/// Generate `account_key` once via `jws.generateKeyPair(&key, io)` and persist
/// it with `x509.ecPrivateKeyToPem` — the account key IS the account identity.
/// Not `jws.KeyPair.generate(io)`: that seeds from `io.random` (see
/// `jws.generateKeyPair`). `account_key` is taken by pointer (no by-value copy
/// of the private key in the caller's frame) and copied into the client, which
/// wipes its copy in `deinit`; wipe the caller's own pair after this call.
// secret-api-ok: Client holds the account key by design (zeroed in deinit); init is a field-wise construction into the caller's result slot, which IS the caller's Client variable, and takes the key by pointer; an out-form would only move the same bytes.
pub fn init(
    io: std.Io,
    gpa: Allocator,
    http_client: *http.Client,
    account_key: anytype, // *const jws.KeyPair, *const jws.Es384.KeyPair or *const jws.AnyKeyPair
    options: Options,
) Client {
    var key: jws.AnyKeyPair = undefined;
    jws.copyPairInto(&key, account_key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key)); // runs after the result is built
    return .{
        .io = io,
        .gpa = gpa,
        .http_client = http_client,
        .account_key = key,
        .options = options,
        .dir = null,
        .kid = null,
        .nonce = null,
        .nonce_lock = .unlocked,
        .responder = Responder.init(gpa),
        .tls_alpn = TlsAlpnResponder.init(gpa),
        .problem_buf = undefined,
        .problem_len = 0,
        .problem_retry_after_s = null,
    };
}

pub fn deinit(c: *Client) void {
    if (c.dir) |*d| d.deinit(c.gpa);
    if (c.kid) |k| c.gpa.free(k);
    if (c.nonce) |n| c.gpa.free(n);
    c.responder.deinit();
    c.tls_alpn.deinit();
    // `account_key` is the account's private key — it lives on this
    // struct for the whole Client lifetime (every `postJws` call signs with
    // it), so this is its one wipe point. Do this BEFORE `c.* = undefined`
    // below: assigning `undefined` is not a zeroing guarantee (ReleaseFast
    // may elide it entirely as a dead store), so the explicit secureZero
    // must run first.
    std.crypto.secureZero(u8, std.mem.asBytes(&c.account_key));
    c.* = undefined;
}

/// The account URL (JWS `kid`) once registered, or null.
pub fn accountUrl(c: *const Client) ?[]const u8 {
    return c.kid;
}

/// Seconds the CA asked to wait (`Retry-After`) on the last refused request,
/// or null when it did not say. Set together with `lastProblem`; most useful
/// after `error.RateLimited`.
pub fn retryAfter(c: *const Client) ?u64 {
    return c.problem_retry_after_s;
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

/// The TLS-ALPN-01 validation-cert store (RFC 8737) to wire into the caller's
/// TLS listener: on a ClientHello for one of the ordered domains that offers
/// ALPN `acme-tls/1`, the listener looks up the SNI via
/// `tlsAlpnResponder().getMaterial()` and serves the returned certificate +
/// key, completing the handshake under that ALPN protocol. The order flow
/// (with `Options.challenge_type == .tls_alpn_01`) populates and cleans the
/// store; running the TLS listener itself is app-side (out of scope here).
pub fn tlsAlpnResponder(c: *Client) *TlsAlpnResponder {
    return &c.tls_alpn;
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

    // RFC 8555 §7.3.4: the inner JWS MACs the account JWK with the CA's key
    // and names the newAccount URL, so it is built per request URL.
    var eab_jws: ?[]u8 = null;
    if (c.options.eab) |eab| {
        eab_jws = jws.signEab(a, c.account_key.publicKey(), eab.kid, eab.hmac_key, c.dir.?.new_account) catch
            return error.OutOfMemory;
    }

    var out: std.Io.Writer.Allocating = .init(a);
    var js: std.json.Stringify = .{ .writer = &out.writer, .options = .{} };
    writeRegisterPayload(&js, c.options, eab_jws) catch return error.OutOfMemory;

    const pr = try c.postJws(a, c.dir.?.new_account, out.written(), .jwk);
    if (pr.status != 200 and pr.status != 201) {
        return c.problemError(pr.body, pr.retry_after_s);
    }
    const loc = pr.location orelse return error.MalformedResponse;
    c.kid = try c.gpa.dupe(u8, loc);
}

fn writeRegisterPayload(js: *std.json.Stringify, options: Options, eab_jws: ?[]const u8) !void {
    try js.beginObject();
    if (options.terms_of_service_agreed) {
        try js.objectField("termsOfServiceAgreed");
        try js.write(true);
    }
    if (options.contact.len != 0) {
        try js.objectField("contact");
        try js.write(options.contact);
    }
    if (eab_jws) |inner| {
        try js.objectField("externalAccountBinding");
        try js.beginWriteRaw();
        try js.writer.writeAll(inner);
        js.endWriteRaw();
    }
    try js.endObject();
}

// ── account lifecycle (RFC 8555 §7.3.2, §7.3.5, §7.3.6) ─────────────────────

/// Replace the account's contact URLs (`UpdateReg` in x/crypto/acme): POST
/// `{"contact":[…]}` to the account URL. Registers first when needed. Pass an
/// empty slice to clear them.
pub fn updateContact(c: *Client, contacts: []const []const u8) Error!void {
    try c.register();

    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var out: std.Io.Writer.Allocating = .init(a);
    var js: std.json.Stringify = .{ .writer = &out.writer, .options = .{} };
    writeContactPayload(&js, contacts) catch return error.OutOfMemory;
    const pr = try c.postJws(a, c.kid.?, out.written(), .kid);
    if (pr.status != 200) {
        return c.problemError(pr.body, pr.retry_after_s);
    }
}

fn writeContactPayload(js: *std.json.Stringify, contacts: []const []const u8) !void {
    try js.beginObject();
    try js.objectField("contact");
    try js.write(contacts);
    try js.endObject();
}

/// Switch the account to `new_key` (`AccountKeyRollover`; RFC 8555 §7.3.5): a
/// pointer to an `Es256.KeyPair`, an `Es384.KeyPair` or an `AnyKeyPair`. The
/// outer JWS is signed with the current key (kid = account URL), the inner
/// one with the new key (`jwk`, no nonce) over `{account, oldKey}`, both for
/// the directory's `keyChange` URL (`error.NotSupported` without one). On
/// success the client signs with `new_key` from then on and has wiped the old
/// one; persist `new_key` — the old key no longer opens the account. On
/// failure (e.g. 409, the new key already belongs to an account) nothing
/// changes.
pub fn rolloverKey(c: *Client, new_key: anytype) Error!void {
    try c.register();
    const key_change = c.dir.?.key_change orelse return error.NotSupported;

    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    const a = arena.allocator();

    // Inner payload: {"account": <account URL>, "oldKey": <old JWK>}.
    var old_jwk_buf: [jws.max_canonical_jwk_len]u8 = undefined;
    const old_jwk = jws.canonicalJwk(&old_jwk_buf, c.account_key.publicKey());
    var inner_payload: std.Io.Writer.Allocating = .init(a);
    {
        var js: std.json.Stringify = .{ .writer = &inner_payload.writer, .options = .{} };
        writeRolloverPayload(&js, c.kid.?, old_jwk) catch return error.OutOfMemory;
    }
    const inner = jws.sign(a, new_key, inner_payload.written(), .{
        .nonce = null,
        .url = key_change,
        .kid = null, // embed the NEW key's jwk
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.SigningFailed => return error.SigningFailed,
    };

    const pr = try c.postJws(a, key_change, inner, .kid);
    if (pr.status != 200) {
        return c.problemError(pr.body, pr.retry_after_s);
    }
    // The CA now knows only the new key.
    std.crypto.secureZero(u8, std.mem.asBytes(&c.account_key));
    jws.copyPairInto(&c.account_key, new_key);
}

fn writeRolloverPayload(js: *std.json.Stringify, account_url: []const u8, old_jwk: []const u8) !void {
    try js.beginObject();
    try js.objectField("account");
    try js.write(account_url);
    try js.objectField("oldKey");
    try js.beginWriteRaw();
    try js.writer.writeAll(old_jwk);
    js.endWriteRaw();
    try js.endObject();
}

/// Deactivate the account (`DeactivateReg`; RFC 8555 §7.3.6): POST
/// `{"status":"deactivated"}` to the account URL. Irreversible — the CA stops
/// accepting requests for this account and its pending orders end. On success
/// `accountUrl` is null again, and the client must not be used for issuance.
pub fn deactivate(c: *Client) Error!void {
    try c.register();

    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const pr = try c.postJws(a, c.kid.?, "{\"status\":\"deactivated\"}", .kid);
    if (pr.status != 200) {
        return c.problemError(pr.body, pr.retry_after_s);
    }
    c.gpa.free(c.kid.?);
    c.kid = null;
}

// ── revocation (RFC 8555 §7.6) ──────────────────────────────────────────────

/// Revoke `cert_der` (DER) as the account that holds it (`kid`-signed). The
/// CA must list `revokeCert` in its directory (`error.NotSupported` else).
/// `reason` null leaves the member out, which the CA reads as `unspecified`.
pub fn revoke(c: *Client, cert_der: []const u8, reason: ?Reason) Error!void {
    try c.register();
    const url = c.dir.?.revoke_cert orelse return error.NotSupported;
    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const payload = try revokePayload(a, cert_der, reason);
    const pr = try c.postSigned(a, url, payload, .kid, &c.account_key);
    if (pr.status != 200) {
        return c.problemError(pr.body, pr.retry_after_s);
    }
}

/// Revoke `cert_der` signed with the certificate's own key (`RevokeCert` with
/// the certificate key; the `jwk` form of RFC 8555 §7.6) — for a lost or
/// compromised account where the certificate key is still at hand. `cert_key`
/// is a pointer to an `Es256.KeyPair`, an `Es384.KeyPair` or an `AnyKeyPair`.
/// Needs no registered account.
pub fn revokeWithCertKey(c: *Client, cert_der: []const u8, cert_key: anytype, reason: ?Reason) Error!void {
    try c.ensureDirectory();
    const url = c.dir.?.revoke_cert orelse return error.NotSupported;
    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const payload = try revokePayload(a, cert_der, reason);
    const pr = try c.postSigned(a, url, payload, .jwk, cert_key);
    if (pr.status != 200) {
        return c.problemError(pr.body, pr.retry_after_s);
    }
}

fn revokePayload(a: Allocator, cert_der: []const u8, reason: ?Reason) Error![]const u8 {
    const cert_b64 = try jws.base64UrlEncodeAlloc(a, cert_der);
    var out: std.Io.Writer.Allocating = .init(a);
    var js: std.json.Stringify = .{ .writer = &out.writer, .options = .{} };
    writeRevokePayload(&js, cert_b64, reason) catch return error.OutOfMemory;
    return out.written();
}

fn writeRevokePayload(js: *std.json.Stringify, cert_b64: []const u8, reason: ?Reason) !void {
    try js.beginObject();
    try js.objectField("certificate");
    try js.write(cert_b64);
    if (reason) |r| {
        try js.objectField("reason");
        try js.write(@intFromEnum(r));
    }
    try js.endObject();
}

// ── ARI (RFC 9773) ──────────────────────────────────────────────────────────

/// The CA's suggested renewal window for a certificate (RFC 9773 §4.2).
pub const RenewalInfo = struct {
    /// Window start and end, epoch seconds. Renew at a time chosen in
    /// `[window_start, window_end]` (`pickTime`); at or after the end, now.
    window_start: i64,
    window_end: i64,
    /// A page explaining a window that was moved (incident, revocation), gpa-owned.
    explanation_url: ?[]u8,
    /// `Retry-After`, seconds: when to ask again (RFC 9773 §4.3), or null.
    retry_after_s: ?u64,

    pub fn deinit(r: *RenewalInfo, gpa: Allocator) void {
        if (r.explanation_url) |u| gpa.free(u);
        r.* = undefined;
    }

    /// A uniformly random second inside the window (RFC 9773 §4.2 asks
    /// clients to spread over it rather than all renew at the start).
    pub fn pickTime(r: RenewalInfo, random: std.Random) i64 {
        if (r.window_end <= r.window_start) return r.window_start;
        const span: u64 = @intCast(r.window_end - r.window_start);
        return r.window_start + @as(i64, @intCast(random.uintLessThan(u64, span + 1)));
    }
};

/// Ask the CA when `cert_der` should be renewed (RFC 9773 §4.2): an
/// unauthenticated GET of `<renewalInfo>/<CertID>`. `error.NotSupported` when
/// the directory has no `renewalInfo` — fall back to `needsRenewal`. The
/// certificate must carry an authorityKeyIdentifier (`x509.ariCertId`).
pub fn renewalInfo(c: *Client, cert_der: []const u8) Error!RenewalInfo {
    try c.ensureDirectory();
    const base = c.dir.?.renewal_info orelse return error.NotSupported;
    const cert_id = x509.ariCertId(c.gpa, cert_der) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.MalformedCertificate => return error.MalformedResponse,
        error.NoAuthorityKeyIdentifier => {
            c.note("certificate has no authorityKeyIdentifier; no ARI CertID");
            return error.MalformedResponse;
        },
    };
    defer c.gpa.free(cert_id);
    const url = try std.fmt.allocPrint(c.gpa, "{s}/{s}", .{ std.mem.trimEnd(u8, base, "/"), cert_id });
    defer c.gpa.free(url);

    var res = c.http_client.request(.get, url, .{}) catch |err| return mapHttpError(err);
    defer res.deinit();
    try c.harvestNonce(&res);
    const body = res.readAllAlloc(c.gpa, c.options.max_response_bytes) catch |err|
        return mapHttpError(err);
    defer c.gpa.free(body);
    if (res.status != 200)
        return c.problemError(body, c.retryAfterHeader(res.header("retry-after")));
    var info = try parseRenewalInfo(c.gpa, body);
    info.retry_after_s = c.retryAfterHeader(res.header("retry-after"));
    return info;
}

/// The certificate profiles the CA advertises (`meta.profiles`), empty when
/// it has none. Borrowed from the client; valid until `deinit`.
pub fn profiles(c: *Client) Error![]const Profile {
    try c.ensureDirectory();
    return c.dir.?.profiles;
}

/// `renewalInfo` for the first certificate of a PEM chain (`Certificate.chain_pem`).
pub fn renewalInfoPem(c: *Client, chain_pem: []const u8) Error!RenewalInfo {
    const der_bytes = x509.pemDecode(c.gpa, "CERTIFICATE", chain_pem) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    defer c.gpa.free(der_bytes);
    return c.renewalInfo(der_bytes);
}

fn parseRenewalInfo(gpa: Allocator, body: []const u8) Error!RenewalInfo {
    const Json = struct {
        suggestedWindow: struct { start: []const u8 = "", end: []const u8 = "" } = .{},
        explanationURL: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(Json, gpa, body, .{ .ignore_unknown_fields = true }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    defer parsed.deinit();
    const start = parseRfc3339(parsed.value.suggestedWindow.start) orelse return error.MalformedResponse;
    const end = parseRfc3339(parsed.value.suggestedWindow.end) orelse return error.MalformedResponse;
    if (end < start) return error.MalformedResponse;
    const url: ?[]u8 = if (parsed.value.explanationURL) |u| try gpa.dupe(u8, u) else null;
    return .{ .window_start = start, .window_end = end, .explanation_url = url, .retry_after_s = null };
}

/// RFC 3339 `date-time` → epoch seconds: `YYYY-MM-DDThh:mm:ss[.frac](Z|±hh:mm)`
/// (`T` may be `t`, `Z` may be `z`), parsed by `datefmt`. Fractions are
/// dropped; a leap second (`:60`) is refused, as in Go's `time.Parse`. Null on
/// anything else.
fn parseRfc3339(s: []const u8) ?i64 {
    const p = datefmt.parseRfc3339(s) catch return null;
    const off_min = p.off_min orelse return null; // always set: the offset is required
    return datefmt.partsToUnix(p) - @as(i64, off_min) * 60;
}

const rfc3339_len = "YYYY-MM-DDThh:mm:ssZ".len;

/// Epoch seconds → `YYYY-MM-DDThh:mm:ssZ` (UTC; years past 9999 are not
/// representable in four digits and clamp there).
fn formatRfc3339(buf: *[rfc3339_len]u8, epoch: u64) []const u8 {
    const max: u64 = 253402300799; // 9999-12-31T23:59:59Z
    const es: std.time.epoch.EpochSeconds = .{ .secs = @min(epoch, max) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,              md.month.numeric(),      @as(u8, md.day_index) + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable; // exactly rfc3339_len
}

// ── the order flow ──────────────────────────────────────────────────────────

/// An issued certificate: the PEM chain as the CA delivered it (leaf
/// first) plus the freshly generated leaf key.
pub const Certificate = struct {
    /// `application/pem-certificate-chain` body, gpa-owned.
    chain_pem: []u8,
    /// The leaf private key, gpa-owned: an `EC PRIVATE KEY` PEM (RFC 5915), or
    /// an `RSA PRIVATE KEY` PEM (PKCS#1) for `cert_key_alg = .rs256`.
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
/// newOrder → one authorization per identifier, solved with
/// `Options.challenge_type` → finalize with a fresh P-256 CSR → download the
/// chain. Registers the account on first use. The proof channel must be
/// ready before calling this: the HTTP-01 responder reachable on port 80, the
/// TLS-ALPN-01 store wired into a listener on 443, or the DNS-01 publisher
/// set. A wildcard (`*.example.org`) is accepted with `dns_01` only.
///
/// The same steps one by one, for a caller that needs them apart (an order
/// resumed after a restart, a challenge type per authorization, a manual
/// DNS step): `newOrder`, `solveAuthorization` (or `fetchAuthorization` +
/// `acceptChallenge` + `waitAuthorization`), `waitOrder`, `finalize`,
/// `downloadChain`.
pub fn obtain(c: *Client, domains: []const []const u8) Error!Certificate {
    return c.obtainWith(domains, .{});
}

/// `obtain` with per-call options (`ObtainOptions`): ARI `replaces`, a
/// profile, validity, a preferred chain. The certificate key follows
/// `Options.cert_key_alg`.
pub fn obtainWith(c: *Client, domains: []const []const u8, opts: ObtainOptions) Error!Certificate {
    // Refused before an order is placed (keygen comes after the authorizations).
    if (c.options.cert_key_alg == .rs256) switch (c.options.cert_rsa_bits) {
        2048, 3072, 4096 => {},
        else => {
            c.note("cert_rsa_bits must be 2048, 3072 or 4096");
            return error.UnsupportedKeySize;
        },
    };
    var order = try c.orderReady(domains, opts);
    defer order.deinit();

    // Finalize with a CSR for a fresh certificate key (§7.4; the account
    // key MUST NOT be reused as the certificate key — §11.1). `cert_key`
    // itself is transient scratch: the actual output is `key_pem` below
    // (a separate PEM-encoded copy), so the raw in-memory KeyPair is wiped
    // at scope exit rather than left resident for the rest of the request.
    // Fail-closed draw: this key is what the issued certificate will
    // attest to, and it goes on to terminate TLS for the domain.
    var cert_key: jws.AnyKeyPair = undefined;
    // An RSA pair is tens of KiB: it lives on the heap (wiped, then freed)
    // and the union holds a pointer to it.
    var rsa_pair: ?*rsa.KeyPair = null;
    defer if (rsa_pair) |kp| {
        std.crypto.secureZero(u8, std.mem.asBytes(kp));
        c.gpa.destroy(kp);
    };
    switch (c.options.cert_key_alg) {
        .rs256 => {
            const kp = try c.gpa.create(rsa.KeyPair);
            rsa_pair = kp;
            jws.generateRsaKeyPair(kp, c.options.cert_rsa_bits, c.io) catch unreachable; // bits checked above
            cert_key = .{ .rs256 = kp };
        },
        else => |alg| jws.generateAnyKeyPair(&cert_key, alg, c.io),
    }
    defer std.crypto.secureZero(u8, std.mem.asBytes(&cert_key));
    const csr_der = x509.csrDerWith(c.gpa, &cert_key, domains, opts.csr_extensions) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidDomain => return error.InvalidDomain,
        error.DuplicateExtension => return error.InvalidCsr,
        error.SigningFailed, error.ValueTooLarge => return error.SigningFailed,
    };
    defer c.gpa.free(csr_der);

    var chain = try c.finalizeAndDownload(&order, csr_der, opts.preferred_chain);
    errdefer chain.deinit(c.gpa);
    const key_pem = if (rsa_pair) |kp|
        try x509.rsaPrivateKeyToPem(c.gpa, kp)
    else
        try x509.ecPrivateKeyToPem(c.gpa, &cert_key);
    return .{ .chain_pem = chain.chain_pem, .key_pem = key_pem, .not_after = chain.not_after };
}

/// A chain issued for a caller's CSR (`obtainWithCsr`): no key — the caller
/// holds it.
pub const IssuedChain = struct {
    /// `application/pem-certificate-chain` body, gpa-owned.
    chain_pem: []u8,
    /// Leaf `notAfter`, epoch seconds.
    not_after: u64,

    pub fn deinit(ch: *IssuedChain, gpa: Allocator) void {
        gpa.free(ch.chain_pem);
        ch.* = undefined;
    }
};

/// Issue a certificate for an existing CSR (DER), whose key never leaves the
/// caller (an HSM, a key reused across renewals, a CSR from another tool;
/// lego `--csr`, certbot `certonly --csr`). The identifiers ordered are the
/// CSR's dNSName SANs, checked like `obtain`'s domains; the self-signature
/// must verify (`x509.parseCsrAny`).
pub fn obtainWithCsr(c: *Client, csr_der: []const u8, opts: ObtainOptions) Error!IssuedChain {
    var csr = x509.parseCsrAny(c.gpa, csr_der) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            c.note("the CSR does not parse or its signature does not verify");
            return error.InvalidCsr;
        },
    };
    defer csr.deinit();

    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    const a = arena.allocator();

    // The identifiers: the dNSName SANs, then the iPAddress ones as text.
    const names = try a.alloc([]const u8, csr.sans.len + csr.ip_sans.len);
    @memcpy(names[0..csr.sans.len], csr.sans);
    for (names[csr.sans.len..], csr.ip_sans) |*slot, octets| {
        const ip: netaddr.Ip = if (octets.len == 4) .{ .v4 = octets[0..4].* } else .{ .v6 = octets[0..16].* };
        var buf: [netaddr.max_ip_text_len]u8 = undefined;
        slot.* = try a.dupe(u8, netaddr.formatIp(ip, &buf));
    }
    var order = try c.orderReady(names, opts);
    defer order.deinit();
    return c.finalizeAndDownload(&order, csr_der, opts.preferred_chain);
}

/// Validate the identifiers against the configured challenge, place the
/// order and solve every authorization; returns once the order is `ready`.
fn orderReady(c: *Client, domains: []const []const u8, opts: ObtainOptions) Error!Order {
    if (domains.len == 0) return error.InvalidDomain;
    for (domains) |name| {
        if (try ipIdentifier(name) != null) {
            // RFC 8738 §7: an IP is never validated over DNS.
            if (c.options.challenge_type == .dns_01) return error.InvalidDomain;
            continue;
        }
        if (x509.isValidDomain(name)) continue;
        if (c.options.challenge_type == .dns_01 and x509.isValidWildcardDomain(name)) continue;
        return error.InvalidDomain;
    }
    if (c.solverFor(c.options.challenge_type) == null) return error.DnsPublisherMissing;

    var order = try c.newOrder(domains, .{
        .replaces = opts.replaces,
        .profile = opts.profile,
        .profile_mode = opts.profile_mode,
        .not_before = opts.not_before,
        .not_after = opts.not_after,
    });
    errdefer order.deinit();

    // Authorizations (§7.5) — one round per identifier.
    if (order.authorizations.len == 0) return error.MalformedResponse;
    for (order.authorizations) |authz_url| try c.solveAuthorization(authz_url);

    // All authorizations valid → the order becomes ready (it may have been
    // ready immediately when every authorization was already valid). A
    // pre-finalize `valid` would be a reused order whose certificate
    // belongs to a key we never had — refuse it rather than hand back a
    // chain that cannot match our fresh key.
    try c.waitOrder(&order, .ready);
    if (order.status == .valid) {
        c.note("order already valid before finalize (reused order, no key)");
        return error.OrderFailed;
    }
    return order;
}

fn finalizeAndDownload(c: *Client, order: *Order, csr_der: []const u8, preferred_chain: ?[]const u8) Error!IssuedChain {
    try c.finalize(order, csr_der);
    try c.waitOrder(order, .valid);
    return c.downloadChain(order, preferred_chain);
}

// ── the order flow, step by step (instant-acme / lego-style handles) ────────

/// Per-order knobs of `newOrder` (the order half of `ObtainOptions`).
pub const OrderOptions = struct {
    /// RFC 9773 §5: the ARI CertID of the certificate this order replaces.
    replaces: ?[]const u8 = null,
    /// A profile the CA advertises (`profiles`); see `ObtainOptions.profile`.
    profile: ?[]const u8 = null,
    profile_mode: ProfileMode = .required,
    /// Requested validity, epoch seconds (RFC 8555 §7.4).
    not_before: ?u64 = null,
    not_after: ?u64 = null,
};

/// An order (RFC 8555 §7.1.3) as the CA last described it. Owns its memory;
/// `waitOrder` and `finalize` refresh it in place.
pub const Order = struct {
    arena: std.heap.ArenaAllocator,
    /// The order URL (newOrder's `Location`) — persist it to resume the
    /// order later with `fetchOrder`.
    url: []const u8,
    status: Status,
    /// The identifier values, as the CA lists them.
    identifiers: []const []const u8,
    /// Authorization URLs, one per identifier (`fetchAuthorization`,
    /// `solveAuthorization`).
    authorizations: []const []const u8,
    finalize: []const u8,
    /// Present once the order is `valid` (`downloadChain`).
    certificate: ?[]const u8,
    /// RFC 3339, as the CA sent it.
    expires: ?[]const u8,

    pub fn deinit(o: *Order) void {
        o.arena.deinit();
        o.* = undefined;
    }
};

/// One challenge of an authorization (RFC 8555 §7.1.5).
pub const Challenge = struct {
    /// The CA's type string ("http-01", "dns-account-01", …).
    type: []const u8,
    /// `type` as a challenge this client can solve, else null.
    kind: ?ChallengeType,
    url: []const u8,
    token: []const u8,
    status: Status,
};

/// An authorization (RFC 8555 §7.1.4) as the CA last described it. Owns its
/// memory.
pub const Authorization = struct {
    arena: std.heap.ArenaAllocator,
    url: []const u8,
    status: Status,
    /// The identifier value: a domain (the base name for a wildcard) or an IP
    /// literal (`ip`).
    identifier: []const u8,
    ip: bool,
    /// §7.1.4: the authorization is for `*.<identifier>`.
    wildcard: bool,
    expires: ?[]const u8,
    challenges: []const Challenge,

    /// The first challenge of `kind`, or null when the CA does not offer it.
    pub fn challenge(az: *const Authorization, kind: ChallengeType) ?Challenge {
        for (az.challenges) |ch| if (ch.kind == kind) return ch;
        return null;
    }

    pub fn deinit(az: *Authorization) void {
        az.arena.deinit();
        az.* = undefined;
    }
};

/// Place an order (RFC 8555 §7.4) for `identifiers`: domains, wildcards
/// (`*.example.org`) and IP literals in canonical form (RFC 8738).
/// Registers the account on first use. Which identifiers a challenge can
/// validate is checked by `solveAuthorization`, not here.
pub fn newOrder(c: *Client, identifiers: []const []const u8, opts: OrderOptions) Error!Order {
    if (identifiers.len == 0) return error.InvalidDomain;
    for (identifiers) |name| {
        if (try ipIdentifier(name) != null) continue;
        if (!x509.isValidDomain(name) and !x509.isValidWildcardDomain(name)) return error.InvalidDomain;
    }
    try c.register();

    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var out: std.Io.Writer.Allocating = .init(a);
    var js: std.json.Stringify = .{ .writer = &out.writer, .options = .{} };
    const profile: ?[]const u8 = if (opts.profile) |want| blk: {
        for (c.dir.?.profiles) |offered| {
            if (std.mem.eql(u8, offered.name, want)) break :blk want;
        }
        switch (opts.profile_mode) {
            .required => {
                c.note("the CA does not advertise the requested profile");
                return error.NotSupported;
            },
            .preferred => break :blk null,
        }
    } else null;
    writeOrderPayload(&js, identifiers, .{
        .replaces = opts.replaces,
        .profile = profile,
        .not_before = opts.not_before,
        .not_after = opts.not_after,
    }) catch return error.OutOfMemory;

    const pr = try c.postJws(a, c.dir.?.new_order, out.written(), .kid);
    if (pr.status != 201) return c.problemError(pr.body, pr.retry_after_s);
    return loadOrder(c.gpa, pr.location orelse return error.MalformedResponse, pr.body);
}

/// The order at `url` (POST-as-GET, RFC 8555 §7.4) — resume an order whose
/// URL was persisted.
pub fn fetchOrder(c: *Client, url: []const u8) Error!Order {
    try c.register();
    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    const pr = try c.postJws(arena.allocator(), url, "", .kid);
    if (pr.status != 200) return c.problemError(pr.body, pr.retry_after_s);
    return loadOrder(c.gpa, url, pr.body);
}

/// Which state `waitOrder` waits for.
pub const OrderTarget = enum {
    /// Every authorization is valid: finalize next. A CA may skip to
    /// `valid` (an order it had already finalized); `order.status` says.
    ready,
    /// Finalized and issued: `order.certificate` is set.
    valid,
};

/// Poll `order` (pacing from `Retry-After`, else `Options.poll_interval_ms`;
/// `Options.max_polls` tries) until it reaches `target`; refreshes `order`.
/// `invalid` → `error.OrderFailed`.
pub fn waitOrder(c: *Client, order: *Order, target: OrderTarget) Error!void {
    var polls: u32 = 0;
    var wait_ms: ?u64 = null;
    while (polls < c.options.max_polls) : (polls += 1) {
        if (wait_ms) |ms| try c.sleepMs(ms);
        var arena = std.heap.ArenaAllocator.init(c.gpa);
        defer arena.deinit();
        const pr = try c.postJws(arena.allocator(), order.url, "", .kid);
        if (pr.status != 200) return c.problemError(pr.body, pr.retry_after_s);
        try replaceOrder(c.gpa, order, pr.body);
        switch (order.status) {
            .valid => return,
            .ready => if (target == .ready) return,
            .invalid => {
                c.noteProblem(pr.body);
                return error.OrderFailed;
            },
            .pending, .processing => {},
            else => return error.MalformedResponse,
        }
        wait_ms = pr.retry_after_ms orelse c.options.poll_interval_ms;
    }
    return error.PollTimeout;
}

/// Finalize a `ready` order with `csr_der` (RFC 8555 §7.4) and refresh
/// `order` from the CA's answer; `waitOrder(.valid)` next.
pub fn finalize(c: *Client, order: *Order, csr_der: []const u8) Error!void {
    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const csr_b64 = try jws.base64UrlEncodeAlloc(a, csr_der);
    var fout: std.Io.Writer.Allocating = .init(a);
    var fjs: std.json.Stringify = .{ .writer = &fout.writer, .options = .{} };
    writeFinalizePayload(&fjs, csr_b64) catch return error.OutOfMemory;

    const fpr = try c.postJws(a, order.finalize, fout.written(), .kid);
    if (fpr.status != 200) return c.problemError(fpr.body, fpr.retry_after_s);
    try replaceOrder(c.gpa, order, fpr.body);
}

/// Download the chain of a `valid` order (RFC 8555 §7.4.2) — or, with
/// `preferred_chain`, the first of the default and alternate chains whose
/// topmost certificate's issuer CN matches (no match: the default).
pub fn downloadChain(c: *Client, order: *const Order, preferred_chain: ?[]const u8) Error!IssuedChain {
    const cert_url = order.certificate orelse {
        c.note("the order has no certificate yet (not valid)");
        return error.MalformedResponse;
    };
    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const cpr = try c.postJws(a, cert_url, "", .kid);
    if (cpr.status != 200) return c.problemError(cpr.body, cpr.retry_after_s);
    var pem: []const u8 = cpr.body;
    if (preferred_chain) |want| {
        if (!try topIssuerIs(a, pem, want)) {
            for (cpr.alternates) |alt_url| {
                const apr = try c.postJws(a, alt_url, "", .kid);
                if (apr.status != 200) continue; // an alternate is optional; keep the default
                if (try topIssuerIs(a, apr.body, want)) {
                    pem = apr.body;
                    break;
                }
            }
        }
    }
    // The label is a literal well under `max_pem_label_len`, so `LabelTooLong`
    // cannot occur here; mapping it to 0 keeps the branch fail-closed anyway
    // rather than widening `Error` with a variant no caller can trigger.
    const chain_blocks = x509.pemBlockCount("CERTIFICATE", pem) catch 0;
    if (chain_blocks == 0) return error.MalformedResponse;
    const not_after = x509.certNotAfter(c.gpa, pem) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    return .{ .chain_pem = try c.gpa.dupe(u8, pem), .not_after = not_after };
}

/// Whether the issuer of the LAST certificate in `chain_pem` has the common
/// name `cn` (the certbot / lego `--preferred-chain` rule). A chain that does
/// not parse is no match.
fn topIssuerIs(a: Allocator, chain_pem: []const u8, cn: []const u8) Error!bool {
    const begin = "-----BEGIN CERTIFICATE-----";
    const last = std.mem.lastIndexOf(u8, chain_pem, begin) orelse return false;
    const der_bytes = x509.pemDecode(a, "CERTIFICATE", chain_pem[last..]) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return false,
    };
    const issuer_cn = x509.issuerCommonName(der_bytes) orelse return false;
    return std.mem.eql(u8, issuer_cn, cn);
}

/// The authorization at `url` (POST-as-GET, RFC 8555 §7.5).
pub fn fetchAuthorization(c: *Client, url: []const u8) Error!Authorization {
    try c.register();
    var arena = std.heap.ArenaAllocator.init(c.gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    const pr = try c.postJws(a, url, "", .kid);
    if (pr.status != 200) return c.problemError(pr.body, pr.retry_after_s);
    const info = try parseAuthz(a, pr.body);
    return .{
        .arena = arena,
        .url = try a.dupe(u8, url),
        .status = info.status,
        .identifier = info.identifier,
        .ip = info.ip,
        .wildcard = info.wildcard,
        .expires = info.expires,
        .challenges = info.challenges,
    };
}

/// The RFC 8555 §8.1 key authorization of `token` under the account key —
/// what an HTTP-01 response carries, and what DNS-01 and TLS-ALPN-01 hash.
pub fn keyAuthorization(c: *const Client, buf: *[jws.max_key_authorization_len]u8, token: []const u8) Error![]const u8 {
    return jws.keyAuthorization(buf, token, c.account_key.publicKey()) catch error.MalformedResponse; // a non-token
}

/// Tell the CA the challenge at `url` is ready to be validated (POST `{}`,
/// RFC 8555 §7.5.1). The proof must be in place first.
pub fn acceptChallenge(c: *Client, url: []const u8) Error!void {
    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    const pr = try c.postJws(arena.allocator(), url, "{}", .kid);
    if (pr.status != 200) return c.problemError(pr.body, pr.retry_after_s);
}

/// Poll the authorization at `url` until it is `valid`; `invalid` (or any
/// other final state) → `error.AuthorizationFailed` with the challenge's
/// error in `lastProblem`.
pub fn waitAuthorization(c: *Client, url: []const u8) Error!void {
    var polls: u32 = 0;
    var wait_ms: ?u64 = null; // no wait before the first re-check
    while (polls < c.options.max_polls) : (polls += 1) {
        if (wait_ms) |ms| try c.sleepMs(ms);
        var arena = std.heap.ArenaAllocator.init(c.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const ppr = try c.postJws(a, url, "", .kid);
        if (ppr.status != 200) return c.problemError(ppr.body, ppr.retry_after_s);
        const state = try parseAuthz(a, ppr.body);
        switch (state.status) {
            .valid => return,
            .pending, .processing => wait_ms = ppr.retry_after_ms orelse c.options.poll_interval_ms,
            else => {
                c.noteAuthzProblem(ppr.body);
                return error.AuthorizationFailed;
            },
        }
    }
    return error.PollTimeout;
}

/// Give up an authorization (RFC 8555 §7.5.2: POST `{"status":"deactivated"}`)
/// — e.g. one for a name the caller no longer controls, so it cannot be
/// reused by a later order.
pub fn deactivateAuthorization(c: *Client, url: []const u8) Error!void {
    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const pr = try c.postJws(a, url, "{\"status\":\"deactivated\"}", .kid);
    if (pr.status != 200) return c.problemError(pr.body, pr.retry_after_s);
    const state = try parseAuthz(a, pr.body);
    if (state.status != .deactivated) return error.MalformedResponse;
}

/// One authorization the way `obtain` does it: fetch it, present the proof
/// for `Options.challenge_type` through its `Solver` (`Options.solvers`, else
/// the built-in one), accept the challenge, wait for `valid`, clean up.
/// An already-valid authorization is accepted as-is.
pub fn solveAuthorization(c: *Client, url: []const u8) Error!void {
    var authz = try c.fetchAuthorization(url);
    defer authz.deinit();
    switch (authz.status) {
        .valid => return,
        .pending => {},
        else => {
            c.note("authorization is neither pending nor valid");
            return error.AuthorizationFailed;
        },
    }
    const kind = c.options.challenge_type;
    const ch = authz.challenge(kind) orelse {
        c.note(switch (kind) {
            .http_01 => "authorization offers no http-01 challenge",
            .tls_alpn_01 => "authorization offers no tls-alpn-01 challenge",
            .dns_01 => "authorization offers no dns-01 challenge",
        });
        return error.AuthorizationFailed;
    };
    switch (kind) {
        .http_01 => {},
        // RFC 8738 §6: an IP goes under its reverse name; else a host name.
        .tls_alpn_01 => if (!authz.ip and !x509.isValidDomain(authz.identifier)) return error.MalformedResponse,
        // The identifier is the base name even for a wildcard order (§7.1.4:
        // `wildcard: true` rides beside it); an IP never goes over DNS.
        .dns_01 => if (authz.ip or !x509.isValidDomain(authz.identifier)) return error.MalformedResponse,
    }
    if (authz.ip and netaddr.parseIp(authz.identifier) == null) return error.MalformedResponse;
    var ka_buf: [jws.max_key_authorization_len]u8 = undefined;
    const req: ChallengeRequest = .{
        .type = kind,
        .identifier = authz.identifier,
        .ip = authz.ip,
        .wildcard = authz.wildcard,
        .token = ch.token,
        .key_authorization = try c.keyAuthorization(&ka_buf, ch.token),
    };
    const solver = c.solverFor(kind) orelse return error.DnsPublisherMissing;
    solver.present(solver.ctx, &req) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.SolverFailed => {
            c.note(if (kind == .dns_01) "DNS-01 TXT record was not published" else "the challenge solver failed to present the proof");
            return if (kind == .dns_01) error.DnsPublishFailed else error.SolverFailed;
        },
    };
    defer solver.cleanup(solver.ctx, &req);
    try c.acceptChallenge(ch.url);
    try c.waitAuthorization(url);
}

// ── challenge solvers ───────────────────────────────────────────────────────

/// What a `Solver` must put in place for one challenge.
pub const ChallengeRequest = struct {
    type: ChallengeType,
    /// The authorization's identifier: a domain (the base name for a
    /// wildcard) or, when `ip`, an IP literal.
    identifier: []const u8,
    ip: bool,
    wildcard: bool,
    token: []const u8,
    /// RFC 8555 §8.1 `token "." base64url(JWK thumbprint)`. HTTP-01 serves it
    /// verbatim at `/.well-known/acme-challenge/<token>`.
    key_authorization: []const u8,

    /// DNS-01: the TXT record name, `_acme-challenge.<identifier>`.
    pub fn dnsRecordName(r: *const ChallengeRequest, buf: *[dns01_max_name_len]u8) []const u8 {
        return dns01RecordName(buf, r.identifier);
    }

    /// DNS-01: the TXT value, base64url(SHA-256(key authorization)).
    pub fn dnsTxtValue(r: *const ChallengeRequest) [jws.dns01_txt_len]u8 {
        return jws.dns01TxtValueFromKeyAuthorization(r.key_authorization);
    }

    /// TLS-ALPN-01: the acmeIdentifier extension value, SHA-256(key
    /// authorization) (RFC 8737 §3).
    pub fn tlsAlpnIdentifier(r: *const ChallengeRequest) [32]u8 {
        return jws.acmeIdentifierFromKeyAuthorization(r.key_authorization);
    }

    /// TLS-ALPN-01: the SNI the CA sends — the domain, or an IP's reverse
    /// name (RFC 8738 §6).
    pub fn tlsAlpnSni(r: *const ChallengeRequest, buf: *[max_reverse_name_len]u8) []const u8 {
        if (r.ip) if (netaddr.parseIp(r.identifier)) |addr| return reverseName(buf, addr);
        return r.identifier;
    }
};

pub const SolverError = error{ OutOfMemory, SolverFailed };

/// A challenge solver (lego's provider, certmagic's `acmez.Solver`): put the
/// proof in place, and take it away again. The three built-ins
/// (`challengeResponder`, `tlsAlpnResponder`, `Options.dns_publisher`) are
/// solvers too; one in `Options.solvers` replaces the built-in of its type.
pub const Solver = struct {
    ctx: ?*anyopaque = null,
    type: ChallengeType,
    /// Make the proof visible to the CA and return once it is (for DNS-01:
    /// after propagation). `error.SolverFailed` aborts the authorization
    /// (`error.SolverFailed`, `error.DnsPublishFailed` for DNS-01).
    present: *const fn (ctx: ?*anyopaque, req: *const ChallengeRequest) SolverError!void,
    /// Called once for every `present` that succeeded, whatever the outcome.
    cleanup: *const fn (ctx: ?*anyopaque, req: *const ChallengeRequest) void,
};

/// The solver `solveAuthorization` uses for `kind`: the caller's from
/// `Options.solvers`, else the built-in (null: DNS-01 without a publisher).
fn solverFor(c: *Client, kind: ChallengeType) ?Solver {
    for (c.options.solvers) |s| if (s.type == kind) return s;
    return switch (kind) {
        .http_01 => .{ .ctx = c, .type = .http_01, .present = presentHttp01, .cleanup = cleanupHttp01 },
        .tls_alpn_01 => .{ .ctx = c, .type = .tls_alpn_01, .present = presentTlsAlpn01, .cleanup = cleanupTlsAlpn01 },
        .dns_01 => if (c.options.dns_publisher == null) null else .{ .ctx = c, .type = .dns_01, .present = presentDns01, .cleanup = cleanupDns01 },
    };
}

fn clientOf(ctx: ?*anyopaque) *Client {
    return @ptrCast(@alignCast(ctx.?));
}

fn presentHttp01(ctx: ?*anyopaque, req: *const ChallengeRequest) SolverError!void {
    try clientOf(ctx).responder.set(req.token, req.key_authorization);
}

fn cleanupHttp01(ctx: ?*anyopaque, req: *const ChallengeRequest) void {
    clientOf(ctx).responder.remove(req.token);
}

fn presentDns01(ctx: ?*anyopaque, req: *const ChallengeRequest) SolverError!void {
    const publisher = clientOf(ctx).options.dns_publisher.?;
    var name_buf: [dns01_max_name_len]u8 = undefined;
    const value = req.dnsTxtValue();
    if (!publisher.present(publisher.ctx, req.dnsRecordName(&name_buf), &value)) return error.SolverFailed;
}

fn cleanupDns01(ctx: ?*anyopaque, req: *const ChallengeRequest) void {
    const publisher = clientOf(ctx).options.dns_publisher.?;
    var name_buf: [dns01_max_name_len]u8 = undefined;
    const value = req.dnsTxtValue();
    publisher.cleanup(publisher.ctx, req.dnsRecordName(&name_buf), &value);
}

/// Build the RFC 8737 validation certificate for the identifier and publish
/// it in the TLS-ALPN store under the SNI the CA sends (the caller's TLS
/// listener serves it under ALPN `acme-tls/1`). The fresh leaf key is
/// transient scratch — only its PEM copy is stored, so the raw KeyPair is
/// wiped at scope exit.
fn presentTlsAlpn01(ctx: ?*anyopaque, req: *const ChallengeRequest) SolverError!void {
    const c = clientOf(ctx);
    var material = try tlsAlpnValidation(c.io, c.gpa, req);
    defer material.deinit(c.gpa);
    var sni_buf: [max_reverse_name_len]u8 = undefined;
    try c.tls_alpn.set(req.tlsAlpnSni(&sni_buf), material.cert_der, material.key_pem);
}

/// The RFC 8737 validation certificate for a TLS-ALPN-01 `req` (a fresh
/// P-256 key, self-signed, the critical `acmeIdentifier` extension), for a
/// solver of the caller's own (`Solver`) that serves it under ALPN
/// `acme-tls/1` for `req.tlsAlpnSni`. Caller frees with `Material.deinit`
/// (which wipes the key).
pub fn tlsAlpnValidation(io: std.Io, gpa: Allocator, req: *const ChallengeRequest) SolverError!TlsAlpnResponder.Material {
    const acme_id = req.tlsAlpnIdentifier();
    // Short-lived and never published, but it still signs a certificate a
    // TLS client is about to accept — same draw as the issuance key.
    var cert_key: jws.KeyPair = undefined;
    jws.generateKeyPair(&cert_key, io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&cert_key));

    // Deterministic positive, minimal serial derived from the identifier.
    var serial: [16]u8 = acme_id[0..16].*;
    serial[0] = (serial[0] & 0x7f) | 0x01;

    const cert_der = x509.tlsAlpnCertDer(
        gpa,
        &cert_key,
        req.identifier,
        acme_id,
        &serial,
        x509.tls_alpn_not_before,
        x509.tls_alpn_not_after,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // The identifier was checked before; a signing failure is
        // astronomically rare.
        error.InvalidDomain, error.SigningFailed, error.ValueTooLarge => return error.SolverFailed,
    };
    errdefer gpa.free(cert_der);
    const key_pem = try x509.ecPrivateKeyToPem(gpa, &cert_key);
    return .{ .cert_der = cert_der, .key_pem = key_pem };
}

fn cleanupTlsAlpn01(ctx: ?*anyopaque, req: *const ChallengeRequest) void {
    var sni_buf: [max_reverse_name_len]u8 = undefined;
    clientOf(ctx).tls_alpn.remove(req.tlsAlpnSni(&sni_buf));
}

/// Longest reverse-DNS name: 32 nibble labels of an IPv6 address + "ip6.arpa".
pub const max_reverse_name_len = 32 * 2 + "ip6.arpa".len;

/// The reverse-DNS name of `ip` (RFC 1035 §3.5 `in-addr.arpa`, RFC 3596 §2.5
/// `ip6.arpa`) — the SNI a CA sends for an IP's TLS-ALPN-01 (RFC 8738 §6).
fn reverseName(buf: *[max_reverse_name_len]u8, ip: netaddr.Ip) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    switch (ip) {
        .v4 => |q| w.print("{d}.{d}.{d}.{d}.in-addr.arpa", .{ q[3], q[2], q[1], q[0] }) catch unreachable,
        .v6 => |b| {
            var i: usize = 16;
            while (i > 0) {
                i -= 1;
                w.print("{x}.{x}.", .{ b[i] & 0xf, b[i] >> 4 }) catch unreachable;
            }
            w.writeAll("ip6.arpa") catch unreachable;
        },
    }
    return w.buffered();
}

/// RFC 8738 §3: an IP identifier's value is the canonical textual form
/// (dotted quad; RFC 5952 for IPv6). Null when `name` is not an IP literal;
/// `error.InvalidDomain` when it is one in another spelling.
fn ipIdentifier(name: []const u8) error{InvalidDomain}!?netaddr.Ip {
    const ip = netaddr.parseIp(name) orelse return null;
    var buf: [netaddr.max_ip_text_len]u8 = undefined;
    if (!std.mem.eql(u8, netaddr.formatIp(ip, &buf), name)) return error.InvalidDomain;
    return ip;
}

const OrderExtras = struct {
    replaces: ?[]const u8 = null,
    profile: ?[]const u8 = null,
    not_before: ?u64 = null,
    not_after: ?u64 = null,
};

fn writeOrderPayload(js: *std.json.Stringify, domains: []const []const u8, extras: OrderExtras) !void {
    try js.beginObject();
    try js.objectField("identifiers");
    try js.beginArray();
    for (domains) |name| {
        try js.beginObject();
        try js.objectField("type");
        try js.write(if (netaddr.parseIp(name) != null) "ip" else "dns");
        try js.objectField("value");
        try js.write(name);
        try js.endObject();
    }
    try js.endArray();
    if (extras.replaces) |cert_id| {
        try js.objectField("replaces");
        try js.write(cert_id);
    }
    if (extras.profile) |name| {
        try js.objectField("profile");
        try js.write(name);
    }
    var tbuf: [rfc3339_len]u8 = undefined;
    if (extras.not_before) |t| {
        try js.objectField("notBefore");
        try js.write(formatRfc3339(&tbuf, t));
    }
    if (extras.not_after) |t| {
        try js.objectField("notAfter");
        try js.write(formatRfc3339(&tbuf, t));
    }
    try js.endObject();
}

fn writeFinalizePayload(js: *std.json.Stringify, csr_b64: []const u8) !void {
    try js.beginObject();
    try js.objectField("csr");
    try js.write(csr_b64);
    try js.endObject();
}

/// An `Order` owning a parse of `body`, at `url`.
fn loadOrder(gpa: Allocator, url: []const u8, body: []const u8) Error!Order {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    // `parseOrder`'s strings may point into the body it parsed: keep a copy.
    const info = try parseOrder(a, try a.dupe(u8, body));
    return .{
        .arena = arena,
        .url = try a.dupe(u8, url),
        .status = info.status,
        .identifiers = info.identifiers,
        .authorizations = info.authorizations,
        .finalize = info.finalize,
        .certificate = info.certificate,
        .expires = info.expires,
    };
}

/// Refresh `order` from `body`; on error `order` is unchanged.
fn replaceOrder(gpa: Allocator, order: *Order, body: []const u8) Error!void {
    const fresh = try loadOrder(gpa, order.url, body);
    order.deinit();
    order.* = fresh;
}

// ── ACME JSON vocabulary ────────────────────────────────────────────────────

/// RFC 8555 §7.1.6 resource states (orders, authorizations, challenges).
pub const Status = enum { pending, processing, ready, valid, invalid, deactivated, expired, revoked, unknown };

fn statusFromString(s: []const u8) Status {
    return std.meta.stringToEnum(Status, s) orelse .unknown;
}

const OrderInfo = struct {
    status: Status,
    finalize: []const u8,
    certificate: ?[]const u8,
    authorizations: []const []const u8,
    identifiers: []const []const u8,
    expires: ?[]const u8,
};

fn parseOrder(a: Allocator, body: []const u8) Error!OrderInfo {
    const OrderJson = struct {
        status: []const u8 = "",
        authorizations: []const []const u8 = &.{},
        finalize: []const u8 = "",
        certificate: ?[]const u8 = null,
        identifiers: []const struct { type: []const u8 = "", value: []const u8 = "" } = &.{},
        expires: ?[]const u8 = null,
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
        .identifiers = ids: {
            const ids = try a.alloc([]const u8, parsed.identifiers.len);
            for (ids, parsed.identifiers) |*d, id| d.* = id.value;
            break :ids ids;
        },
        .expires = parsed.expires,
    };
}

const AuthzInfo = struct {
    status: Status,
    /// The authorization's dNS identifier value (the domain) — the SAN and
    /// SNI key for the TLS-ALPN-01 validation certificate.
    identifier: []const u8,
    /// The identifier's type is "ip" (RFC 8738).
    ip: bool,
    /// §7.1.4: the authorization is for `*.<identifier>`.
    wildcard: bool,
    expires: ?[]const u8,
    /// Every challenge offered, in the CA's order.
    challenges: []const Challenge,
    http01: ?ChallengeInfo,
    tls_alpn01: ?ChallengeInfo,
    dns01: ?ChallengeInfo,
};

const ChallengeInfo = struct {
    url: []const u8,
    token: []const u8,
};

fn parseAuthz(a: Allocator, body: []const u8) Error!AuthzInfo {
    const AuthzJson = struct {
        status: []const u8 = "",
        identifier: IdentifierJson = .{},
        wildcard: bool = false,
        expires: ?[]const u8 = null,
        challenges: []const ChallengeJson = &.{},

        const IdentifierJson = struct {
            type: []const u8 = "",
            value: []const u8 = "",
        };
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
    var tls_alpn01: ?ChallengeInfo = null;
    var dns01: ?ChallengeInfo = null;
    const all = try a.alloc(Challenge, parsed.challenges.len);
    for (all, parsed.challenges) |*d, ch| d.* = .{
        .type = ch.type,
        .kind = challengeKind(ch.type),
        .url = ch.url,
        .token = ch.token,
        .status = statusFromString(ch.status),
    };
    for (parsed.challenges) |ch| {
        if (http01 == null and std.mem.eql(u8, ch.type, "http-01")) {
            http01 = .{ .url = ch.url, .token = ch.token };
        } else if (tls_alpn01 == null and std.mem.eql(u8, ch.type, "tls-alpn-01")) {
            tls_alpn01 = .{ .url = ch.url, .token = ch.token };
        } else if (dns01 == null and std.mem.eql(u8, ch.type, "dns-01")) {
            dns01 = .{ .url = ch.url, .token = ch.token };
        }
    }
    return .{
        .status = statusFromString(parsed.status),
        .identifier = parsed.identifier.value,
        .ip = std.mem.eql(u8, parsed.identifier.type, "ip"),
        .wildcard = parsed.wildcard,
        .expires = parsed.expires,
        .challenges = all,
        .http01 = http01,
        .tls_alpn01 = tls_alpn01,
        .dns01 = dns01,
    };
}

fn challengeKind(t: []const u8) ?ChallengeType {
    if (std.mem.eql(u8, t, "http-01")) return .http_01;
    if (std.mem.eql(u8, t, "tls-alpn-01")) return .tls_alpn_01;
    if (std.mem.eql(u8, t, "dns-01")) return .dns_01;
    return null;
}

const Problem = struct {
    type: []const u8 = "",
    detail: []const u8 = "",
};

const bad_nonce_type = "urn:ietf:params:acme:error:badNonce";
const rate_limited_type = "urn:ietf:params:acme:error:rateLimited";

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

/// Record why an authorization failed: the first challenge's `error`
/// problem (RFC 8555 §8, "the error that caused the challenge to fail"),
/// else the body as `noteProblem` takes it.
///
/// ⛔ The authorization body went to `noteProblem` whole. It is not a
/// problem document, so `lastProblem` held the first bytes of the
/// authorization JSON -- `{ "status": "invalid", "identifier": …` -- and
/// never the reason (Pebble, `tools/pebble.sh`, 2026-10-06).
fn noteAuthzProblem(c: *Client, body: []const u8) void {
    const Authz = struct {
        challenges: []const struct { @"error": ?Problem = null } = &.{},
    };
    if (std.json.parseFromSlice(Authz, c.gpa, body, .{ .ignore_unknown_fields = true })) |parsed| {
        defer parsed.deinit();
        for (parsed.value.challenges) |ch| if (ch.@"error") |p| if (p.type.len != 0) {
            var w: std.Io.Writer = .fixed(&c.problem_buf);
            w.print("{s}: {s}", .{ p.type, p.detail }) catch {}; // truncation is fine
            c.problem_len = w.buffered().len;
            return;
        };
    } else |_| {}
    c.noteProblem(body);
}

/// Record the refusal `body` and turn it into the matching error:
/// `RateLimited` for RFC 8555 §6.6's `rateLimited`, else `AcmeProblem`.
fn problemError(c: *Client, body: []const u8, retry_after_s: ?u64) Error {
    c.noteProblem(body);
    c.problem_retry_after_s = retry_after_s;
    const parsed = std.json.parseFromSlice(Problem, c.gpa, body, .{
        .ignore_unknown_fields = true,
    }) catch return error.AcmeProblem;
    defer parsed.deinit();
    return if (std.mem.eql(u8, parsed.value.type, rate_limited_type)) error.RateLimited else error.AcmeProblem;
}

/// `Retry-After` (delay-seconds or an HTTP-date, RFC 9110 §10.2.3) as
/// seconds from now; a date in the past is 0.
fn retryAfterHeader(c: *Client, value: ?[]const u8) ?u64 {
    const v = std.mem.trim(u8, value orelse return null, " \t");
    if (std.fmt.parseInt(u64, v, 10)) |secs| return secs else |_| {}
    const at = http.conditional.parseHttpDate(v) orelse return null;
    const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(c.io).nanoseconds, std.time.ns_per_s));
    return if (at <= now) 0 else @intCast(at - now);
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
        keyChange: ?[]const u8 = null,
        revokeCert: ?[]const u8 = null,
        renewalInfo: ?[]const u8 = null,
        meta: struct {
            profiles: ?std.json.ArrayHashMap([]const u8) = null,
        } = .{},
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
    // The optional resources: absent is fine, present must be a URL.
    inline for (.{ parsed.value.keyChange, parsed.value.revokeCert, parsed.value.renewalInfo }) |opt| {
        if (opt) |url| _ = http.Url.parse(url) catch return error.MalformedResponse;
    }

    const new_nonce = try c.gpa.dupe(u8, parsed.value.newNonce);
    errdefer c.gpa.free(new_nonce);
    const new_account = try c.gpa.dupe(u8, parsed.value.newAccount);
    errdefer c.gpa.free(new_account);
    const new_order = try c.gpa.dupe(u8, parsed.value.newOrder);
    errdefer c.gpa.free(new_order);
    const key_change = try dupeOpt(c.gpa, parsed.value.keyChange);
    errdefer if (key_change) |u| c.gpa.free(u);
    const revoke_cert = try dupeOpt(c.gpa, parsed.value.revokeCert);
    errdefer if (revoke_cert) |u| c.gpa.free(u);
    const renewal_info = try dupeOpt(c.gpa, parsed.value.renewalInfo);
    errdefer if (renewal_info) |u| c.gpa.free(u);
    const offered = try dupeProfiles(c.gpa, parsed.value.meta.profiles);
    c.dir = .{
        .new_nonce = new_nonce,
        .new_account = new_account,
        .new_order = new_order,
        .key_change = key_change,
        .revoke_cert = revoke_cert,
        .renewal_info = renewal_info,
        .profiles = offered,
    };
}

fn dupeProfiles(gpa: Allocator, map: ?std.json.ArrayHashMap([]const u8)) Allocator.Error![]Profile {
    const m = map orelse return &.{};
    const out = try gpa.alloc(Profile, m.map.count());
    var done: usize = 0;
    errdefer {
        for (out[0..done]) |pr| {
            gpa.free(pr.name);
            gpa.free(pr.description);
        }
        gpa.free(out);
    }
    var it = m.map.iterator();
    while (it.next()) |e| {
        const name = try gpa.dupe(u8, e.key_ptr.*);
        errdefer gpa.free(name);
        out[done] = .{ .name = name, .description = try gpa.dupe(u8, e.value_ptr.*) };
        done += 1;
    }
    return out;
}

fn dupeOpt(gpa: Allocator, s: ?[]const u8) Allocator.Error!?[]u8 {
    return if (s) |v| try gpa.dupe(u8, v) else null;
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
    /// Parsed integer `Retry-After`, capped, in milliseconds (poll pacing).
    retry_after_ms: ?u64,
    /// `Retry-After` in seconds from now, uncapped, either form (`problemError`).
    retry_after_s: ?u64,
    /// `Link: <url>;rel="alternate"` targets (RFC 8555 §7.4.2), same allocator.
    alternates: []const []const u8 = &.{},
};

/// POST `payload` ("" = POST-as-GET, §6.3) to `url` as an ES256 JWS.
/// Handles nonce refill and transparently retries `badNonce` rejections
/// (§6.5). Returns whatever status the CA answered — callers decide.
/// `a` provides the result's memory (an arena in the flow).
fn postJws(c: *Client, a: Allocator, url: []const u8, payload: []const u8, mode: KeyMode) Error!PostResult {
    return c.postSigned(a, url, payload, mode, &c.account_key);
}

/// `postJws` signing with `key` (a pointer to any supported key pair) instead
/// of the account key — revocation by the certificate key. `.jwk` mode embeds
/// `key`'s public half; `.kid` mode names the account URL.
fn postSigned(c: *Client, a: Allocator, url: []const u8, payload: []const u8, mode: KeyMode, key: anytype) Error!PostResult {
    const kid: ?[]const u8 = switch (mode) {
        .jwk => null,
        .kid => c.kid orelse return error.NotRegistered,
    };
    var attempts_left: u8 = 3;
    var unavailable_left: u8 = c.options.max_unavailable_retries;
    while (true) {
        const nonce = try c.takeNonce();
        defer c.gpa.free(nonce);
        const body_json = jws.sign(c.gpa, key, payload, .{
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
        // 503 = the CA is overloaded or in maintenance and did not act on the
        // request (RFC 9110 §15.6.4), so a resend cannot double an action.
        // A short `Retry-After` is honoured; a long one is the caller's call.
        if (res.status == 503 and unavailable_left > 0) {
            const wait_ms: u64 = if (c.retryAfterHeader(res.header("retry-after"))) |secs|
                secs * 1000
            else
                @as(u64, 1000) << @intCast(c.options.max_unavailable_retries - unavailable_left);
            if (wait_ms <= max_unavailable_wait_ms) {
                unavailable_left -= 1;
                a.free(body);
                try c.sleepMs(wait_ms);
                continue;
            }
        }
        return .{
            .status = res.status,
            .body = body,
            .location = if (res.header("location")) |l| try a.dupe(u8, l) else null,
            .retry_after_ms = parseRetryAfter(res.header("retry-after")),
            .retry_after_s = c.retryAfterHeader(res.header("retry-after")),
            .alternates = try alternateLinks(a, &res.head),
        };
    }
}

/// Every `Link` target with `rel="alternate"` (RFC 8288; one header may
/// carry several comma-separated links, and the header may repeat).
fn alternateLinks(a: Allocator, head: anytype) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = head.iterate();
    while (it.next()) |h| {
        if (!std.ascii.eqlIgnoreCase(h.name, "link")) continue;
        var rest = h.value;
        while (std.mem.indexOfScalar(u8, rest, '<')) |lt| {
            const gt = std.mem.indexOfScalarPos(u8, rest, lt, '>') orelse break;
            const target = rest[lt + 1 .. gt];
            const params_end = std.mem.indexOfScalarPos(u8, rest, gt, ',') orelse rest.len;
            if (isAlternateRel(rest[gt + 1 .. params_end])) try out.append(a, try a.dupe(u8, target));
            rest = rest[params_end..];
        }
    }
    return out.toOwnedSlice(a);
}

/// `;rel="alternate"` / `;rel=alternate` among a link's parameters (the
/// relation type is case-insensitive, and `rel` may list several).
fn isAlternateRel(params: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, params, ';');
    while (it.next()) |raw| {
        const param = std.mem.trim(u8, raw, " \t");
        const eq = std.mem.indexOfScalar(u8, param, '=') orelse continue;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, param[0..eq], " \t"), "rel")) continue;
        const value = std.mem.trim(u8, std.mem.trim(u8, param[eq + 1 ..], " \t"), "\"");
        var rels = std.mem.tokenizeScalar(u8, value, ' ');
        while (rels.next()) |r| if (std.ascii.eqlIgnoreCase(r, "alternate")) return true;
    }
    return false;
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
    // secret-api-ok: the key authorization is public by design — this responder serves it to anyone over plain HTTP (RFC 8555 §8.3).
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

// ── the TLS-ALPN-01 validation-cert store (RFC 8737) ────────────────────────

/// A thread-safe store of TLS-ALPN-01 validation certificates keyed by domain
/// (SNI). The order flow builds an entry per authorization
/// (`SHA-256(keyAuthorization)` → self-signed cert with the critical
/// `id-pe-acmeIdentifier` extension) and removes it when the authorization
/// settles. The caller's TLS listener, on a ClientHello that offers ALPN
/// `acme-tls/1`, looks the SNI up with `getMaterial` and serves the returned
/// certificate + key, completing the handshake under that protocol. Running
/// the TLS listener is app-side (out of scope); this store is the seam.
pub const TlsAlpnResponder = struct {
    gpa: Allocator,
    lock: std.atomic.Mutex = .unlocked,
    map: std.StringHashMapUnmanaged(Entry) = .empty,

    /// The ALPN protocol the validation certificate must be served under.
    pub const alpn_protocol = x509.tls_alpn_protocol; // "acme-tls/1"

    const Entry = struct { cert_der: []u8, key_pem: []u8 };

    /// A caller-owned copy of a validation cert + its leaf key (free with
    /// `deinit`). `key_pem` is an `EC PRIVATE KEY` PEM (RFC 5915).
    pub const Material = struct {
        cert_der: []u8,
        key_pem: []u8,

        pub fn deinit(self: *Material, gpa: Allocator) void {
            gpa.free(self.cert_der);
            std.crypto.secureZero(u8, self.key_pem);
            gpa.free(self.key_pem);
            self.* = undefined;
        }
    };

    pub fn init(gpa: Allocator) TlsAlpnResponder {
        return .{ .gpa = gpa };
    }

    pub fn deinit(r: *TlsAlpnResponder) void {
        var it = r.map.iterator();
        while (it.next()) |e| {
            r.gpa.free(e.key_ptr.*);
            r.gpa.free(e.value_ptr.cert_der);
            std.crypto.secureZero(u8, e.value_ptr.key_pem);
            r.gpa.free(e.value_ptr.key_pem);
        }
        r.map.deinit(r.gpa);
        r.* = undefined;
    }

    /// Publish (`domain` → `cert_der` + `key_pem`); all three are copied,
    /// replacing any existing entry. The order flow calls this.
    // secret-api-ok: `key_pem` is the throwaway TLS-ALPN-01 validation key, copied into the store on purpose so the caller's listener can serve it; the store wipes it on replace/remove/deinit (and on a failed insert), and nothing of it reaches this frame beyond the copy.
    pub fn set(r: *TlsAlpnResponder, domain: []const u8, cert_der: []const u8, key_pem: []const u8) error{OutOfMemory}!void {
        const cert_copy = try r.gpa.dupe(u8, cert_der);
        errdefer r.gpa.free(cert_copy);
        const key_copy = try r.gpa.dupe(u8, key_pem);
        errdefer {
            std.crypto.secureZero(u8, key_copy);
            r.gpa.free(key_copy);
        }
        lockSpin(&r.lock);
        defer r.lock.unlock();
        const gop = try r.map.getOrPut(r.gpa, domain);
        if (gop.found_existing) {
            r.gpa.free(gop.value_ptr.cert_der);
            std.crypto.secureZero(u8, gop.value_ptr.key_pem);
            r.gpa.free(gop.value_ptr.key_pem);
        } else {
            gop.key_ptr.* = r.gpa.dupe(u8, domain) catch |err| {
                _ = r.map.remove(domain);
                return err;
            };
        }
        gop.value_ptr.* = .{ .cert_der = cert_copy, .key_pem = key_copy };
    }

    pub fn remove(r: *TlsAlpnResponder, domain: []const u8) void {
        lockSpin(&r.lock);
        const kv = r.map.fetchRemove(domain);
        r.lock.unlock();
        if (kv) |e| {
            r.gpa.free(e.key);
            r.gpa.free(e.value.cert_der);
            std.crypto.secureZero(u8, e.value.key_pem);
            r.gpa.free(e.value.key_pem);
        }
    }

    /// A caller-owned copy of the validation material for `sni`, or null when
    /// no challenge is in flight for it (entries can be removed concurrently,
    /// so returning a borrowed slice would race). The TLS listener serves the
    /// result and frees it after the handshake.
    pub fn getMaterial(r: *TlsAlpnResponder, gpa: Allocator, sni: []const u8) error{OutOfMemory}!?Material {
        lockSpin(&r.lock);
        defer r.lock.unlock();
        const e = r.map.get(sni) orelse return null;
        const cert_copy = try gpa.dupe(u8, e.cert_der);
        errdefer gpa.free(cert_copy);
        const key_copy = try gpa.dupe(u8, e.key_pem);
        return .{ .cert_der = cert_copy, .key_pem = key_copy };
    }

    /// Number of validation certs currently published.
    pub fn count(r: *TlsAlpnResponder) usize {
        lockSpin(&r.lock);
        defer r.lock.unlock();
        return r.map.count();
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

// ── fuzz: the CA's two JSON response decoders ──────────────────────
//
// ⚠ Both harnesses used to open with `smith.bytes(&buf)` followed by
// `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes` copies `min(buf.len,
// in.len)` octets and the ranged draw then reads EIGHT more as a little-endian
// u64, returning the range minimum when fewer remain -- so `len` was 0 for
// every input a corpus can carry and both decoders were handed an EMPTY body
// while the response sat unread in `buf`. One `slice` draw reads the corpus
// entry's own length header and hands the bytes over intact.

/// `testkit.fuzz.seed`, aliased so the corpora below read as the CA responses
/// they are. A corpus entry is not the frame: the length draw reads a
/// little-endian `u32` first, so a raw body would arrive minus its own first
/// four octets. `testkit/src/fuzz.zig` carries the other two hazards.
const seed = @import("testkit").fuzz.seed;

/// Order responses (RFC 8555 §7.1.3), in the format the length draw reads.
///
/// ⚠ Every member of `OrderJson` has a default, so `parseOrder("{}")`
/// SUCCEEDS. That is why the guard below cannot use acceptance as its measure
/// of reach, and it is the reason a `{}` seed is in the corpus on purpose.
const order_seeds = [_][]const u8{
    seed("{\"status\":\"pending\",\"authorizations\":[\"https://ca/authz/1\",\"https://ca/authz/2\"],\"finalize\":\"https://ca/finalize/9\"}"), // the ordinary pending order
    seed("{\"status\":\"valid\",\"finalize\":\"https://ca/finalize/9\",\"certificate\":\"https://ca/cert/9\"}"), // the issued order: `certificate` present
    seed("{\"status\":\"ready\",\"authorizations\":[],\"finalize\":\"f\"}"), // ready with nothing left to validate
    seed("{\"status\":\"invalid\",\"finalize\":\"f\"}"), // the state `pollOrder` turns into `error.OrderFailed`
    seed("{\"status\":\"processing\",\"finalize\":\"f\",\"certificate\":null}"), // an explicit null certificate
    seed("{\"status\":\"deactivated\",\"finalize\":\"\"}"), // a status `pollOrder` refuses as MalformedResponse
    seed("{\"status\":\"brand-new-state\",\"finalize\":\"f\"}"), // an unregistered status maps to `.unknown`, not an error
    seed("{\"finalize\":\"f\",\"unknownExtension\":{\"a\":[1,2]}}"), // ignore_unknown_fields, and no `status` at all
    seed("{\"status\":\"pending\",\"authorizations\":[\"" ++ ("a" ** 200) ++ "\"],\"finalize\":\"f\"}"), // a very long authorization URL
    seed("{}"), // ⚠ a legal order response: every member defaults
    seed("{\"status\":42}"), // a wrong-typed member
    seed("{\"authorizations\":\"not-a-list\"}"), // a wrong-typed list
    seed("[1,2"), // truncated JSON
    seed("<html>oops</html>"), // an HTML error page where JSON was promised
    seed("null"), // valid JSON, wrong top-level type
};

test "fuzz: parseOrder never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzParseOrder, .{ .corpus = &order_seeds });
}

fn fuzzParseOrder(_: void, smith: *std.testing.Smith) !void {
    return orderHarness(std.testing.Smith, smith, testing.allocator);
}

const fuzz_driver = @import("testkit").fuzz.driver;
const JsonLabel = enum { raw_rejected, raw_accepted, genuine_parsed, truncated_rejected, flipped };
var json_reach: [@typeInfo(JsonLabel).@"enum".fields.len]usize = @splat(0);

fn markJson(comptime l: JsonLabel) void {
    json_reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

const alnum = "abcdefghijklmnopqrstuvwxyz0123456789-_";

fn word(rnd: std.Random, out: []u8) []const u8 {
    const n = 1 + rnd.uintAtMost(usize, out.len - 1);
    for (out[0..n]) |*c| c.* = alnum[rnd.uintLessThan(usize, alnum.len)];
    return out[0..n];
}

/// Generic over its source (`Smith` under `--fuzz`, `fuzz_driver.Rng` under the
/// driver). The drawn octets are parsed raw (any outcome, no panic); then they
/// seed a PRNG that writes a genuine order response, which must parse to the
/// very fields it was written from. Every truncation must be refused.
fn orderHarness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [512]u8 = undefined;
    const len: usize = smith.slice(&buf);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    if (parseOrder(arena.allocator(), buf[0..len])) |_| markJson(.raw_accepted) else |_| markJson(.raw_rejected);

    var prng = std.Random.DefaultPrng.init(std.hash.Wyhash.hash(0, buf[0..len]));
    const rnd = prng.random();
    const statuses = [_][]const u8{ "pending", "processing", "ready", "valid", "invalid", "deactivated", "expired", "revoked", "brand-new" };
    const st = statuses[rnd.uintLessThan(usize, statuses.len)];
    var json_buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&json_buf);
    var fin_store: [24]u8 = undefined;
    const fin = word(rnd, &fin_store);
    try w.print("{{\"status\":\"{s}\",\"authorizations\":[", .{st});
    var urls: [4][24]u8 = undefined;
    var url_lens: [4]usize = undefined;
    const n_auth = rnd.uintAtMost(usize, 4);
    for (0..n_auth) |i| {
        const u = word(rnd, &urls[i]);
        url_lens[i] = u.len;
        try w.print("{s}\"https://ca/authz/{s}\"", .{ if (i == 0) "" else ",", u });
    }
    var cert_store: [24]u8 = undefined;
    const cert: ?[]const u8 = if (rnd.boolean()) word(rnd, &cert_store) else null;
    try w.print("],\"finalize\":\"{s}\"", .{fin});
    if (cert) |c| try w.print(",\"certificate\":\"{s}\"", .{c});
    try w.writeAll("}");
    const json = w.buffered();

    const order = parseOrder(arena.allocator(), json) catch return error.GenuineResponseRejected;
    if (order.status != statusFromString(st) or !std.mem.eql(u8, order.finalize, fin) or
        order.authorizations.len != n_auth or (order.certificate == null) != (cert == null))
        return error.RoundTripMismatch;
    if (cert) |c| if (!std.mem.eql(u8, order.certificate.?, c)) return error.RoundTripMismatch;
    for (order.authorizations, 0..) |u, i| {
        if (!std.mem.endsWith(u8, u, urls[i][0..url_lens[i]])) return error.RoundTripMismatch;
    }
    markJson(.genuine_parsed);

    const cut = rnd.uintLessThan(usize, json.len);
    if (parseOrder(arena.allocator(), json[0..cut])) |_| return error.TruncatedResponseAccepted else |_| {}
    markJson(.truncated_rejected);

    json_buf[rnd.uintLessThan(usize, json.len)] ^= @as(u8, 1) << rnd.int(u3);
    _ = parseOrder(arena.allocator(), json) catch {};
    markJson(.flipped);
}

test "fuzz driver: ACME_FUZZ (acme-order)" {
    try fuzz_driver.run(orderHarness, .{ .prefix = "ACME_FUZZ", .name = "acme-order" });
}

fn jsonReachCheck(comptime harness: anytype, name: []const u8, seeds: usize) !void {
    json_reach = @splat(0);
    for (0..seeds) |sd| {
        var prng = std.Random.DefaultPrng.init(sd);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("{s} seed {d}: {t}\n", .{ name, sd, err });
            return err;
        };
    }
    for (json_reach, 0..) |n, i| {
        const l: JsonLabel = @enumFromInt(i);
        // Random octets are not JSON of the right shape: `raw_accepted` is
        // reached through the corpus only.
        if (l == .raw_accepted) continue;
        if (n == 0) {
            std.debug.print("reach: {s}: label {t} never hit in {d} seeds\n", .{ name, l, seeds });
            return error.HarnessDoesNotReach;
        }
    }
}

test "fuzz harness: 300 seeds per CA-response harness in every test run, and they get everywhere" {
    try jsonReachCheck(orderHarness, "acme-order", 300);
    try jsonReachCheck(authzHarness, "acme-authz", 300);
}

test "corpus: every order seed reaches parseOrder, and what it extracted is pinned" {
    // ⛔ `accepted > 0` would be a lie here, and it is worth spelling out
    // why: every member of `OrderJson` has a default, so `parseOrder("{}")`
    // succeeds. A corpus of fifteen empty objects would score 15 of 15
    // "accepted" while never once reaching a URL, a status word or the
    // authorization list. The numbers only a real body can produce are the
    // authorizations collected and the finalize octets; those are pinned.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var authorizations: usize = 0;
    var finalize_octets: usize = 0;
    var typed_statuses: usize = 0;
    for (order_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const order = parseOrder(arena.allocator(), buf[0..len]) catch continue;
        accepted += 1;
        authorizations += order.authorizations.len;
        finalize_octets += order.finalize.len;
        if (order.status != .unknown) typed_statuses += 1;
    }
    try testing.expectEqual(order_seeds.len, nonempty);
    // Measured 2026-09-07: 0 of 15 seeds non-empty before the draw was fixed,
    // and `parseOrder("")` is `error.MalformedResponse`, so every counter was 0.
    try testing.expectEqual(@as(usize, 10), accepted);
    try testing.expectEqual(@as(usize, 3), authorizations);
    try testing.expectEqual(@as(usize, 48), finalize_octets);
    try testing.expectEqual(@as(usize, 7), typed_statuses);
}

/// Authorization responses (RFC 8555 §7.1.4), in the format the length draw
/// reads. Same warning as the orders: `parseAuthz("{}")` succeeds, so the
/// discriminating numbers are the challenges actually matched.
const authz_seeds = [_][]const u8{
    seed("{\"status\":\"pending\",\"identifier\":{\"type\":\"dns\",\"value\":\"x.example\"},\"challenges\":[{\"type\":\"dns-01\",\"url\":\"u7\",\"token\":\"ddd\"},{\"type\":\"http-01\",\"url\":\"u8\",\"token\":\"ttt\",\"status\":\"pending\"}]}"), // http-01 found past a dns-01 the client ignores
    seed("{\"status\":\"pending\",\"identifier\":{\"type\":\"dns\",\"value\":\"y.example\"},\"challenges\":[{\"type\":\"tls-alpn-01\",\"url\":\"u9\",\"token\":\"aaa\"}]}"), // the TLS-ALPN-01 branch
    seed("{\"status\":\"valid\",\"identifier\":{\"type\":\"dns\",\"value\":\"z.example\"},\"challenges\":[{\"type\":\"http-01\",\"url\":\"u\",\"token\":\"t\"},{\"type\":\"tls-alpn-01\",\"url\":\"v\",\"token\":\"s\"}]}"), // both challenge types offered
    seed("{\"status\":\"pending\",\"challenges\":[{\"type\":\"http-01\",\"url\":\"a\",\"token\":\"1\"},{\"type\":\"http-01\",\"url\":\"b\",\"token\":\"2\"}]}"), // duplicate http-01: the FIRST wins
    seed("{\"status\":\"pending\",\"challenges\":[]}"), // no challenges at all: both stay null
    seed("{\"status\":\"invalid\",\"identifier\":{\"type\":\"dns\",\"value\":\"bad.example\"},\"challenges\":[{\"type\":\"http-01\",\"url\":\"u\",\"token\":\"\"}]}"), // an EMPTY token from the CA
    seed("{\"identifier\":{\"type\":\"ip\",\"value\":\"192.0.2.1\"},\"challenges\":[{\"type\":\"http-01\",\"url\":\"u\",\"token\":\"t\"}]}"), // an identifier type this client does not order
    seed("{\"status\":\"pending\",\"challenges\":[{\"type\":\"HTTP-01\",\"url\":\"u\",\"token\":\"t\"}]}"), // the type match is case-SENSITIVE: no challenge found
    seed("{}"), // ⚠ a legal authorization response: every member defaults
    seed("{\"challenges\":{}}"), // a wrong-typed challenge list
    seed("{\"challenges\":[{\"type\":42}]}"), // a wrong-typed member inside a challenge
    seed("{\"identifier\":\"x.example\"}"), // identifier is a string, not an object
    seed("<html>oops</html>"), // an HTML error page where JSON was promised
    seed("[1,2"), // truncated JSON
};

test "fuzz: parseAuthz never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzParseAuthz, .{ .corpus = &authz_seeds });
}

fn fuzzParseAuthz(_: void, smith: *std.testing.Smith) !void {
    return authzHarness(std.testing.Smith, smith, testing.allocator);
}

test "fuzz driver: ACME_FUZZ (acme-authz)" {
    try fuzz_driver.run(authzHarness, .{ .prefix = "ACME_FUZZ", .name = "acme-authz" });
}

/// Same contract as `orderHarness`, for the authorization response: the genuine
/// one must yield the FIRST challenge of each recognised type.
fn authzHarness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [512]u8 = undefined;
    const len: usize = smith.slice(&buf);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    if (parseAuthz(arena.allocator(), buf[0..len])) |_| markJson(.raw_accepted) else |_| markJson(.raw_rejected);

    var prng = std.Random.DefaultPrng.init(std.hash.Wyhash.hash(0, buf[0..len]));
    const rnd = prng.random();
    const types = [_][]const u8{ "http-01", "dns-01", "tls-alpn-01", "other-01" };
    var json_buf: [1536]u8 = undefined;
    var w: std.Io.Writer = .fixed(&json_buf);
    var dom_store: [24]u8 = undefined;
    const dom = word(rnd, &dom_store);
    const wildcard = rnd.boolean();
    try w.print("{{\"status\":\"pending\",\"identifier\":{{\"type\":\"dns\",\"value\":\"{s}\"}},\"wildcard\":{},\"challenges\":[", .{ dom, wildcard });
    // First (url, token) seen per type, to compare with what the parser picked.
    var first_tok: [4]?[8]u8 = @splat(null);
    const n_ch = rnd.uintAtMost(usize, 6);
    for (0..n_ch) |i| {
        const ti = rnd.uintLessThan(usize, types.len);
        var tok: [8]u8 = undefined;
        for (&tok) |*c| c.* = alnum[rnd.uintLessThan(usize, alnum.len)];
        if (first_tok[ti] == null) first_tok[ti] = tok;
        try w.print("{s}{{\"type\":\"{s}\",\"url\":\"https://ca/chall/{d}\",\"token\":\"{s}\"}}", .{ if (i == 0) "" else ",", types[ti], i, tok });
    }
    try w.writeAll("]}");
    const json = w.buffered();

    const az = parseAuthz(arena.allocator(), json) catch return error.GenuineResponseRejected;
    if (!std.mem.eql(u8, az.identifier, dom) or az.wildcard != wildcard) return error.RoundTripMismatch;
    const got = [_]?ChallengeInfo{ az.http01, az.dns01, az.tls_alpn01 };
    const want_idx = [_]usize{ 0, 1, 2 };
    for (got, want_idx) |g, ti| {
        if ((g == null) != (first_tok[ti] == null)) return error.RoundTripMismatch;
        if (g) |c| if (!std.mem.eql(u8, c.token, &first_tok[ti].?)) return error.RoundTripMismatch;
    }
    markJson(.genuine_parsed);

    const cut = rnd.uintLessThan(usize, json.len);
    if (parseAuthz(arena.allocator(), json[0..cut])) |_| return error.TruncatedResponseAccepted else |_| {}
    markJson(.truncated_rejected);

    json_buf[rnd.uintLessThan(usize, json.len)] ^= @as(u8, 1) << rnd.int(u3);
    _ = parseAuthz(arena.allocator(), json) catch {};
    markJson(.flipped);
}

test "corpus: every authz seed reaches parseAuthz, and the challenges matched are pinned" {
    // Same trap as the orders, same answer: `{}` is a legal authorization, so
    // the pinned numbers are the challenges this client actually recognised and
    // the identifier octets it read out -- neither of which an empty or default
    // body can produce.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var http01_found: usize = 0;
    var tls_alpn01_found: usize = 0;
    var identifier_octets: usize = 0;
    for (authz_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const authz = parseAuthz(arena.allocator(), buf[0..len]) catch continue;
        accepted += 1;
        if (authz.http01 != null) http01_found += 1;
        if (authz.tls_alpn01 != null) tls_alpn01_found += 1;
        identifier_octets += authz.identifier.len;
    }
    try testing.expectEqual(authz_seeds.len, nonempty);
    // Measured 2026-09-07: 0 of 14 seeds non-empty and every counter 0 before
    // the draw was fixed.
    try testing.expectEqual(@as(usize, 9), accepted);
    try testing.expectEqual(@as(usize, 5), http01_found);
    try testing.expectEqual(@as(usize, 2), tls_alpn01_found);
    try testing.expectEqual(@as(usize, 47), identifier_octets);
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

test "TlsAlpnResponder: set/getMaterial/remove keyed by domain (copies)" {
    var r = TlsAlpnResponder.init(testing.allocator);
    defer r.deinit();

    try testing.expectEqualStrings("acme-tls/1", TlsAlpnResponder.alpn_protocol);
    try testing.expectEqual(@as(usize, 0), r.count());

    {
        // Domain, cert and key are all copied — caller memory may die.
        var dom_buf: [16]u8 = undefined;
        var cert_buf: [8]u8 = undefined;
        var key_buf: [8]u8 = undefined;
        @memcpy(dom_buf[0..11], "example.org");
        @memcpy(cert_buf[0..6], "CERTde");
        @memcpy(key_buf[0..5], "KEYpm");
        try r.set(dom_buf[0..11], cert_buf[0..6], key_buf[0..5]);
        dom_buf = @splat(0xAA);
        cert_buf = @splat(0xAA);
        key_buf = @splat(0xAA);
    }
    try testing.expectEqual(@as(usize, 1), r.count());

    var mat = (try r.getMaterial(testing.allocator, "example.org")).?;
    try testing.expectEqualStrings("CERTde", mat.cert_der);
    try testing.expectEqualStrings("KEYpm", mat.key_pem);
    mat.deinit(testing.allocator);

    try testing.expect((try r.getMaterial(testing.allocator, "other.example")) == null);

    try r.set("example.org", "CERT2", "KEY2"); // replace
    var mat2 = (try r.getMaterial(testing.allocator, "example.org")).?;
    try testing.expectEqualStrings("CERT2", mat2.cert_der);
    mat2.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), r.count());

    r.remove("example.org");
    r.remove("example.org"); // idempotent
    try testing.expect((try r.getMaterial(testing.allocator, "example.org")) == null);
    try testing.expectEqual(@as(usize, 0), r.count());
}

test "parseAuthz: selects tls-alpn-01 and captures the identifier" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const authz = try parseAuthz(a,
        \\{"status":"pending","identifier":{"type":"dns","value":"x.example"},
        \\ "challenges":[
        \\   {"type":"http-01","url":"https://ca/ch/8","token":"ttt"},
        \\   {"type":"tls-alpn-01","url":"https://ca/ch/9","token":"aaa","status":"pending"}]}
    );
    try testing.expectEqualStrings("x.example", authz.identifier);
    try testing.expectEqualStrings("https://ca/ch/8", authz.http01.?.url);
    try testing.expectEqualStrings("https://ca/ch/9", authz.tls_alpn01.?.url);
    try testing.expectEqualStrings("aaa", authz.tls_alpn01.?.token);

    const no_alpn = try parseAuthz(a, "{\"status\":\"pending\",\"challenges\":[]}");
    try testing.expect(no_alpn.tls_alpn01 == null);
    try testing.expect(no_alpn.http01 == null);
    try testing.expectEqualStrings("", no_alpn.identifier);
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
    account_key: ?jws.AnyPublicKey = null,
    /// Lifecycle extras (EAB, rollover, revocation, ARI): the directory lists
    /// `keyChange`, `revokeCert` and `renewalInfo` when set.
    extras: bool = false,
    /// newAccount must carry an external account binding MAC'd with this
    /// (`eab_kid` / `eab_key`); `eab_seen` records that one verified.
    eab_kid: ?[]const u8 = null,
    eab_key: []const u8 = "",
    eab_seen: bool = false,
    key_change_url: []u8 = &.{},
    revoke_url: []u8 = &.{},
    ari_url: []u8 = &.{},
    rollovers: u32 = 0,
    deactivated: bool = false,
    contact_seen: [2][64]u8 = undefined,
    contact_seen_len: [2]usize = .{ 0, 0 },
    contact_count: usize = 0,
    /// Revocation: how the request was authorized and with what reason.
    revoked_by: enum { none, account, cert_key } = .none,
    revoke_reason: ?u8 = null,
    /// ARI: the last CertID requested, and the `replaces` of the last newOrder.
    ari_id: [96]u8 = undefined,
    ari_id_len: usize = 0,
    replaces_seen: [96]u8 = undefined,
    replaces_len: usize = 0,
    /// Alg a newAccount used (`jwk` header), for the ES384 tests.
    account_alg: ?jws.Alg = null,
    /// The certificate DER the revoke tests expect.
    revoke_expect: []const u8 = "",
    /// Alg of the certificate key in the finalize CSR.
    csr_alg: ?jws.Alg = null,
    badnonce_left: u8 = 1,
    // W1 (2026-10-16): new-order members seen, injected refusals, alternates.
    profile_seen: [32]u8 = undefined,
    profile_len: usize = 0,
    validity_seen: [64]u8 = undefined,
    validity_len: usize = 0,
    unavailable_left: u8 = 0,
    rate_limit: bool = false,
    alt_chain: bool = false,
    alt_fetches: u32 = 0,
    authz_polls: u32 = 0,
    challenge_ok: bool = false,
    csr_ok: bool = false,
    finalized: bool = false,
    served_processing: bool = false,
    /// W3: the client deactivated the authorization (RFC 8555 §7.5.2).
    authz_deactivated: bool = false,
    /// Which challenge the mock offers and validates.
    mode: ChallengeType = .http_01,
    /// The one identifier the order carries (`*.` = a wildcard order).
    order_domain: []const u8 = domain,
    /// DNS-01: the "DNS" the mock resolves — the zone the client's publisher
    /// writes into.
    zone: ?*TestZone = null,
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
        m.key_change_url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/key-change", .{ca_port});
        m.revoke_url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/revoke", .{ca_port});
        m.ari_url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/ari", .{ca_port});
    }

    fn deinitUrls(m: *MockCa) void {
        inline for (.{
            m.dir_url,      m.new_nonce_url, m.new_account_url, m.new_order_url,
            m.account_url,  m.order_url,     m.authz_url,       m.challenge_url,
            m.finalize_url, m.cert_url,      m.challenge_base,  m.key_change_url,
            m.revoke_url,   m.ari_url,
        }) |s| m.gpa.free(s);
    }

    /// Forget recorded failures (a test that provokes one on purpose).
    fn resetFails(m: *MockCa) void {
        lockSpin(&m.lock);
        defer m.lock.unlock();
        m.fail_count = 0;
        m.fail_note_len = 0;
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
    fn readVerified(m: *MockCa, ctx: *router.Ctx, expected_url: []const u8, mode: JwsMode) !jws.VerifiedAny {
        const body = ctx.req.reader().allocRemaining(m.gpa, .limited(64 * 1024)) catch {
            m.fail("request body unreadable");
            return error.MockJwsRejected;
        };
        defer m.gpa.free(body);
        return m.checkJws(body, expected_url, mode);
    }

    const JwsMode = enum { jwk, kid };

    /// Verify a JWS body like a CA: signature (by the embedded jwk, or by the
    /// account key for `kid`), url, fresh nonce, header shape.
    fn checkJws(m: *MockCa, body: []const u8, expected_url: []const u8, mode: JwsMode) !jws.VerifiedAny {
        const expected_key: ?jws.AnyPublicKey = switch (mode) {
            .jwk => null,
            .kid => m.account_key orelse {
                m.fail("kid-mode request before newAccount");
                return error.MockJwsRejected;
            },
        };
        var v = jws.verifyFlattenedAny(m.gpa, body, expected_key) catch |err| {
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
        , .{ status, m.order_domain, m.authz_url, m.finalize_url }) catch unreachable;
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
        \\ "meta":{{"termsOfService":"data:text/plain,mock-tos",
        \\  "profiles":{{"classic":"the default","shortlived":"https://ca/docs#shortlived"}}}}
    , .{ m.new_nonce_url, m.new_account_url, m.new_order_url });
    if (m.extras) try w.print(
        \\,"keyChange":"{s}","revokeCert":"{s}","renewalInfo":"{s}"
    , .{ m.key_change_url, m.revoke_url, m.ari_url });
    try w.writeAll("}");
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

    const Payload = struct {
        termsOfServiceAgreed: bool = false,
        externalAccountBinding: ?std.json.Value = null,
    };
    const payload = std.json.parseFromSlice(Payload, m.gpa, v.payload, .{
        .ignore_unknown_fields = true,
    }) catch {
        m.fail("newAccount payload not JSON");
        return mcRejected(ctx);
    };
    defer payload.deinit();
    if (!payload.value.termsOfServiceAgreed) m.fail("ToS not agreed");

    if (m.eab_kid) |want_kid| {
        // RFC 8555 §7.3.4: the binding is a flattened JWS, HS256, `kid` as
        // issued, `url` the newAccount URL, no nonce, payload = the account JWK.
        const binding = payload.value.externalAccountBinding orelse {
            m.fail("newAccount without externalAccountBinding");
            return mcRejected(ctx);
        };
        const text = std.json.Stringify.valueAlloc(m.gpa, binding, .{}) catch {
            m.fail("binding not serialisable");
            return mcRejected(ctx);
        };
        defer m.gpa.free(text);
        var inner = jws.verifyEab(m.gpa, text, m.eab_key) catch |err| {
            m.fail(@errorName(err));
            return mcRejected(ctx);
        };
        defer inner.deinit();
        var jwk_buf: [jws.max_canonical_jwk_len]u8 = undefined;
        const want_jwk = jws.canonicalJwk(&jwk_buf, v.jwk_key.?);
        if (!std.mem.eql(u8, inner.kid, want_kid)) m.fail("binding kid wrong");
        if (!std.mem.eql(u8, inner.url, m.new_account_url)) m.fail("binding url wrong");
        if (inner.has_nonce) m.fail("binding carries a nonce");
        if (!std.mem.eql(u8, inner.payload, want_jwk)) m.fail("binding payload is not the account JWK");
        lockSpin(&m.lock);
        m.eab_seen = true;
        m.lock.unlock();
    } else if (payload.value.externalAccountBinding != null) {
        m.fail("unexpected externalAccountBinding");
    }

    lockSpin(&m.lock);
    m.account_key = v.jwk_key.?;
    m.account_alg = v.alg;
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

    // W1: a 503 (the client resends) or a rateLimited refusal (it must not).
    {
        lockSpin(&m.lock);
        const unavailable = m.unavailable_left > 0;
        if (unavailable) m.unavailable_left -= 1;
        const limited = m.rate_limit;
        m.lock.unlock();
        if (unavailable or limited) {
            try m.stampNonce(ctx);
            ctx.res.setStatus(if (unavailable) 503 else 429);
            try ctx.res.setHeader("Retry-After", if (unavailable) "0" else "3600");
            try ctx.res.setHeader("Content-Type", "application/problem+json");
            try ctx.res.writeAll(if (unavailable)
                "{\"type\":\"urn:ietf:params:acme:error:serverInternal\",\"detail\":\"maintenance\"}"
            else
                "{\"type\":\"urn:ietf:params:acme:error:rateLimited\",\"detail\":\"too many orders\"}");
            return;
        }
    }

    const Payload = struct {
        identifiers: []const struct { type: []const u8 = "", value: []const u8 = "" } = &.{},
        replaces: ?[]const u8 = null,
        profile: ?[]const u8 = null,
        notBefore: ?[]const u8 = null,
        notAfter: ?[]const u8 = null,
    };
    const payload = std.json.parseFromSlice(Payload, m.gpa, v.payload, .{
        .ignore_unknown_fields = true,
    }) catch {
        m.fail("newOrder payload not JSON");
        return mcRejected(ctx);
    };
    defer payload.deinit();
    if (payload.value.replaces) |r| {
        lockSpin(&m.lock);
        const n = @min(r.len, m.replaces_seen.len);
        @memcpy(m.replaces_seen[0..n], r[0..n]);
        m.replaces_len = n;
        m.lock.unlock();
    }
    if (payload.value.profile) |pf| {
        lockSpin(&m.lock);
        const n = @min(pf.len, m.profile_seen.len);
        @memcpy(m.profile_seen[0..n], pf[0..n]);
        m.profile_len = n;
        m.lock.unlock();
    }
    if (payload.value.notBefore != null or payload.value.notAfter != null) {
        lockSpin(&m.lock);
        var w: std.Io.Writer = .fixed(&m.validity_seen);
        w.print("{s}/{s}", .{ payload.value.notBefore orelse "-", payload.value.notAfter orelse "-" }) catch {};
        m.validity_len = w.buffered().len;
        m.lock.unlock();
    }
    const want_type: []const u8 = if (netaddr.parseIp(m.order_domain) != null) "ip" else "dns";
    if (payload.value.identifiers.len != 1 or
        !std.mem.eql(u8, payload.value.identifiers[0].type, want_type) or
        !std.mem.eql(u8, payload.value.identifiers[0].value, m.order_domain))
        m.fail("newOrder identifiers wrong");

    // A fresh order: its authorization starts pending again, so a client
    // placing several orders on one mock walks the whole flow each time.
    lockSpin(&m.lock);
    m.challenge_ok = false;
    m.finalized = false;
    m.served_processing = false;
    m.authz_deactivated = false;
    m.lock.unlock();

    var buf: [1024]u8 = undefined;
    try ctx.res.setHeader("Location", m.order_url);
    try m.respondJson(ctx, 201, m.orderBody(&buf, "pending", false));
}

fn mcAuthz(ctx: *router.Ctx) anyerror!void {
    const m = MockCa.of(ctx);
    var v = m.readVerified(ctx, m.authz_url, .kid) catch return mcRejected(ctx);
    defer v.deinit();
    // RFC 8555 §7.5.2: the one non-empty payload an authorization takes.
    const deactivating = std.mem.eql(u8, v.payload, "{\"status\":\"deactivated\"}");
    if (v.payload.len != 0 and !deactivating) m.fail("authz fetch must be POST-as-GET");

    lockSpin(&m.lock);
    if (deactivating) m.authz_deactivated = true;
    const gone = m.authz_deactivated;
    const valid = m.challenge_ok;
    m.authz_polls += 1;
    m.lock.unlock();
    if (gone) {
        var gbuf: [256]u8 = undefined;
        const body = try std.fmt.bufPrint(&gbuf,
            \\{{"status":"deactivated","identifier":{{"type":"dns","value":"{s}"}},"challenges":[]}}
        , .{m.order_domain});
        return m.respondJson(ctx, 200, body);
    }

    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    if (m.mode == .dns_01) {
        // §7.1.4: a wildcard order's authorization names the base domain and
        // says `wildcard: true`; the CA offers dns-01 only. An http-01 decoy
        // rides along to prove the client picks by type.
        const wildcard = std.mem.startsWith(u8, m.order_domain, "*.");
        const base = if (wildcard) m.order_domain[2..] else m.order_domain;
        try w.print(
            \\{{"status":"{s}","identifier":{{"type":"dns","value":"{s}"}},"wildcard":{},
            \\ "challenges":[
            \\  {{"type":"http-01","url":"{s}-nope","token":"never-this-one"}},
            \\  {{"type":"dns-01","url":"{s}","token":"{s}","status":"{s}"}}]}}
        , .{
            if (valid) "valid" else @as([]const u8, "pending"),
            base,
            wildcard,
            m.challenge_url,
            m.challenge_url,
            MockCa.token,
            if (valid) "valid" else @as([]const u8, "pending"),
        });
        return m.respondJson(ctx, 200, w.buffered());
    }
    // A dns-01 decoy first — the client must pick the http-01 entry.
    try w.print(
        \\{{"status":"{s}","identifier":{{"type":"{s}","value":"{s}"}},
        \\ "challenges":[
        \\  {{"type":"dns-01","url":"{s}-nope","token":"never-this-one"}},
        \\  {{"type":"http-01","url":"{s}","token":"{s}","status":"{s}"}}]}}
    , .{
        if (valid) "valid" else @as([]const u8, "pending"),
        if (netaddr.parseIp(m.order_domain) != null) "ip" else @as([]const u8, "dns"),
        m.order_domain,
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

    if (m.mode == .dns_01) return mcChallengeDns(m, ctx);

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

/// DNS-01 validation, as a CA does it: resolve the TXT record at
/// `_acme-challenge.<base domain>` and compare it with the value the account
/// key implies (RFC 8555 §8.4). The "resolver" is the test zone.
fn mcChallengeDns(m: *MockCa, ctx: *router.Ctx) anyerror!void {
    const zone = m.zone orelse {
        m.fail("dns-01 mock without a zone");
        return mcRejected(ctx);
    };
    const base = if (std.mem.startsWith(u8, m.order_domain, "*.")) m.order_domain[2..] else m.order_domain;
    var name_buf: [dns01_max_name_len]u8 = undefined;
    const want_name = dns01RecordName(&name_buf, base);
    const want_value = jws.dns01TxtValue(MockCa.token, m.account_key.?) catch unreachable;
    var got_value: [jws.dns01_txt_len]u8 = undefined;
    if (!zone.lookup(want_name, &got_value)) {
        m.fail("no TXT record at the challenge name");
        return mcRejected(ctx);
    }
    if (!std.mem.eql(u8, &got_value, &want_value)) {
        m.fail("TXT record value mismatch");
        return mcRejected(ctx);
    }

    lockSpin(&m.lock);
    m.challenge_ok = true;
    m.lock.unlock();

    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("{{\"type\":\"dns-01\",\"url\":\"{s}\",\"token\":\"{s}\",\"status\":\"processing\"}}", .{
        m.challenge_url, MockCa.token,
    });
    try m.respondJson(ctx, 200, w.buffered());
}

/// A one-record DNS zone standing in for the caller's DNS provider: the
/// client's `DnsPublisher` writes into it, the mock CA resolves from it.
const TestZone = struct {
    lock: std.atomic.Mutex = .unlocked,
    name_buf: [dns01_max_name_len]u8 = undefined,
    name_len: usize = 0,
    value: [jws.dns01_txt_len]u8 = undefined,
    live: bool = false,
    presents: u32 = 0,
    cleanups: u32 = 0,
    /// Make `present` report failure (the provider refused).
    refuse: bool = false,
    bad_cleanup: bool = false,

    fn publisher(z: *TestZone) DnsPublisher {
        return .{ .ctx = z, .present = present, .cleanup = cleanup };
    }

    fn present(ctx: ?*anyopaque, name: []const u8, value: []const u8) bool {
        const z: *TestZone = @ptrCast(@alignCast(ctx.?));
        lockSpin(&z.lock);
        defer z.lock.unlock();
        z.presents += 1;
        if (z.refuse or value.len != z.value.len or name.len > z.name_buf.len) return false;
        @memcpy(z.name_buf[0..name.len], name);
        z.name_len = name.len;
        @memcpy(&z.value, value);
        z.live = true;
        return true;
    }

    fn cleanup(ctx: ?*anyopaque, name: []const u8, value: []const u8) void {
        const z: *TestZone = @ptrCast(@alignCast(ctx.?));
        lockSpin(&z.lock);
        defer z.lock.unlock();
        z.cleanups += 1;
        // Cleanup must name exactly the record it published.
        if (!z.live or !std.mem.eql(u8, name, z.name_buf[0..z.name_len]) or !std.mem.eql(u8, value, &z.value))
            z.bad_cleanup = true;
        z.live = false;
    }

    fn lookup(z: *TestZone, name: []const u8, out: *[jws.dns01_txt_len]u8) bool {
        lockSpin(&z.lock);
        defer z.lock.unlock();
        if (!z.live or !std.mem.eql(u8, name, z.name_buf[0..z.name_len])) return false;
        out.* = z.value;
        return true;
    }
};

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
    var parsed = x509.parseCsrAny(m.gpa, csr_der) catch {
        m.fail("csr does not parse/verify");
        return mcRejected(ctx);
    };
    defer parsed.deinit();
    const sans_ok = if (netaddr.parseIp(m.order_domain)) |ip| switch (ip) {
        // RFC 8738 §3: an IP identifier is an iPAddress SAN, not a dNSName.
        .v4 => |q| parsed.sans.len == 0 and parsed.ip_sans.len == 1 and std.mem.eql(u8, parsed.ip_sans[0], &q),
        .v6 => |b| parsed.sans.len == 0 and parsed.ip_sans.len == 1 and std.mem.eql(u8, parsed.ip_sans[0], &b),
    } else parsed.sans.len == 1 and parsed.ip_sans.len == 0 and std.mem.eql(u8, parsed.sans[0], m.order_domain);
    if (!sans_ok) m.fail("csr SAN set mismatch");
    const fresh_key = !parsed.public_key.eql(m.account_key.?);
    if (!fresh_key) m.fail("certificate key must not be the account key");

    lockSpin(&m.lock);
    m.csr_ok = sans_ok and fresh_key;
    m.csr_alg = parsed.public_key.alg();
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
    if (m.alt_chain) {
        // An unrelated relation first: only `rel="alternate"` is a chain.
        var buf: [256]u8 = undefined;
        const link = try std.fmt.bufPrint(&buf, "<{s}>;rel=\"index\", <{s}/alt>;rel=\"alternate\"", .{
            m.dir_url, m.cert_url,
        });
        try ctx.res.setHeader("Link", link);
    }
    try ctx.res.writeAll(x509.test_cert_pem ++ x509.test_root_cert_pem);
}

/// The alternate chain: the leaf alone, so its topmost certificate's issuer
/// is `acme-test-fixture` where the default chain's is `acme-test-root`.
fn mcCertAlt(ctx: *router.Ctx) anyerror!void {
    const m = MockCa.of(ctx);
    var alt_buf: [128]u8 = undefined;
    const alt_url = try std.fmt.bufPrint(&alt_buf, "{s}/alt", .{m.cert_url});
    var v = m.readVerified(ctx, alt_url, .kid) catch return mcRejected(ctx);
    defer v.deinit();
    lockSpin(&m.lock);
    m.alt_fetches += 1;
    m.lock.unlock();
    try m.stampNonce(ctx);
    ctx.res.setStatus(200);
    try ctx.res.setHeader("Content-Type", "application/pem-certificate-chain");
    try ctx.res.writeAll(x509.test_cert_pem);
}

/// POST /acct/1 — contact update (§7.3.2) and deactivation (§7.3.6).
fn mcAccount(ctx: *router.Ctx) anyerror!void {
    const m = MockCa.of(ctx);
    var v = m.readVerified(ctx, m.account_url, .kid) catch return mcRejected(ctx);
    defer v.deinit();
    const Payload = struct { contact: ?[]const []const u8 = null, status: ?[]const u8 = null };
    const payload = std.json.parseFromSlice(Payload, m.gpa, v.payload, .{ .ignore_unknown_fields = true }) catch {
        m.fail("account payload not JSON");
        return mcRejected(ctx);
    };
    defer payload.deinit();
    lockSpin(&m.lock);
    if (payload.value.contact) |list| {
        m.contact_count = list.len;
        for (list, 0..) |item, i| {
            if (i >= m.contact_seen.len) break;
            const n = @min(item.len, m.contact_seen[i].len);
            @memcpy(m.contact_seen[i][0..n], item[0..n]);
            m.contact_seen_len[i] = n;
        }
    }
    if (payload.value.status) |s| {
        if (std.mem.eql(u8, s, "deactivated")) m.deactivated = true;
    }
    m.lock.unlock();
    try m.respondJson(ctx, 200, if (m.deactivated) "{\"status\":\"deactivated\"}" else "{\"status\":\"valid\"}");
}

/// POST /key-change — RFC 8555 §7.3.5, both JWS layers checked.
fn mcKeyChange(ctx: *router.Ctx) anyerror!void {
    const m = MockCa.of(ctx);
    var outer = m.readVerified(ctx, m.key_change_url, .kid) catch return mcRejected(ctx);
    defer outer.deinit();
    var inner = jws.verifyFlattenedAny(m.gpa, outer.payload, null) catch |err| {
        m.fail(@errorName(err));
        return mcRejected(ctx);
    };
    defer inner.deinit();
    if (!std.mem.eql(u8, inner.url, m.key_change_url)) m.fail("inner url is not the outer url");
    if (inner.nonce.len != 0) m.fail("inner JWS carries a nonce");
    if (inner.kid != null or inner.jwk_key == null) m.fail("inner JWS must carry the new jwk");

    const Payload = struct {
        account: []const u8 = "",
        oldKey: struct { crv: []const u8 = "", kty: []const u8 = "", x: []const u8 = "", y: []const u8 = "" } = .{},
    };
    const payload = std.json.parseFromSlice(Payload, m.gpa, inner.payload, .{ .ignore_unknown_fields = true }) catch {
        m.fail("inner payload not JSON");
        return mcRejected(ctx);
    };
    defer payload.deinit();
    if (!std.mem.eql(u8, payload.value.account, m.account_url)) m.fail("inner account is not the account URL");
    var want_buf: [jws.max_canonical_jwk_len]u8 = undefined;
    const want = jws.canonicalJwk(&want_buf, m.account_key.?);
    var got_buf: [jws.max_canonical_jwk_len]u8 = undefined;
    const old = payload.value.oldKey;
    const got = std.fmt.bufPrint(&got_buf, "{{\"crv\":\"{s}\",\"kty\":\"{s}\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ old.crv, old.kty, old.x, old.y }) catch "";
    if (!std.mem.eql(u8, want, got)) m.fail("oldKey is not the current account key");
    const key_in_use = if (inner.jwk_key) |k| k.eql(m.account_key.?) else false;
    if (key_in_use) {
        // §7.3.5: a key that already belongs to an account is 409 Conflict.
        m.fail("new key already in use");
        try m.stampNonce(ctx);
        ctx.res.setStatus(409);
        try ctx.res.setHeader("Content-Type", "application/problem+json");
        try ctx.res.writeAll("{\"type\":\"urn:ietf:params:acme:error:malformed\",\"detail\":\"key in use\"}");
        return;
    }

    lockSpin(&m.lock);
    if (inner.jwk_key) |k| m.account_key = k;
    m.rollovers += 1;
    m.lock.unlock();
    try m.respondJson(ctx, 200, "{\"status\":\"valid\"}");
}

/// POST /revoke — RFC 8555 §7.6, by account (`kid`) or by certificate key (`jwk`).
fn mcRevoke(ctx: *router.Ctx) anyerror!void {
    const m = MockCa.of(ctx);
    const body = ctx.req.reader().allocRemaining(m.gpa, .limited(64 * 1024)) catch {
        m.fail("request body unreadable");
        return mcRejected(ctx);
    };
    defer m.gpa.free(body);
    const mode: MockCa.JwsMode = if (jwsHasKid(m.gpa, body)) .kid else .jwk;
    var v = m.checkJws(body, m.revoke_url, mode) catch return mcRejected(ctx);
    defer v.deinit();

    const Payload = struct { certificate: []const u8 = "", reason: ?u8 = null };
    const payload = std.json.parseFromSlice(Payload, m.gpa, v.payload, .{ .ignore_unknown_fields = true }) catch {
        m.fail("revoke payload not JSON");
        return mcRejected(ctx);
    };
    defer payload.deinit();
    const cert = jws.base64UrlDecodeAlloc(m.gpa, payload.value.certificate) catch {
        m.fail("certificate not base64url");
        return mcRejected(ctx);
    };
    defer m.gpa.free(cert);
    if (!std.mem.eql(u8, cert, m.revoke_expect)) m.fail("revoked certificate is not the expected one");
    if (mode == .jwk) {
        // A certificate-key revocation must be signed by the certificate's own key.
        const spki = pkix.spkiOf(cert) catch {
            m.fail("certificate does not parse");
            return mcRejected(ctx);
        };
        if (!v.jwk_key.?.alg().isEc()) {
            m.fail("the mock models certificate-key revocation for EC keys only");
            return mcRejected(ctx);
        }
        var sec1_buf: [jws.AnyPublicKey.max_sec1_len]u8 = undefined;
        const signer = v.jwk_key.?.uncompressedSec1(&sec1_buf);
        if (!std.mem.eql(u8, spki.key_bits, signer)) m.fail("signer key is not the certificate key");
    }
    lockSpin(&m.lock);
    m.revoked_by = if (mode == .kid) .account else .cert_key;
    m.revoke_reason = payload.value.reason;
    m.lock.unlock();
    try m.respondJson(ctx, 200, "{}");
}

/// Is `kid` in the protected header of this flattened JWS?
fn jwsHasKid(gpa: Allocator, body: []const u8) bool {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const Flat = struct { protected: []const u8 = "" };
    const flat = std.json.parseFromSliceLeaky(Flat, a, body, .{ .ignore_unknown_fields = true }) catch return false;
    const protected = jws.base64UrlDecodeAlloc(a, flat.protected) catch return false;
    const Head = struct { kid: ?[]const u8 = null };
    const head = std.json.parseFromSliceLeaky(Head, a, protected, .{ .ignore_unknown_fields = true }) catch return false;
    return head.kid != null;
}

/// GET /ari/:id — RFC 9773 §4.2, the example response of the RFC.
fn mcRenewalInfo(ctx: *router.Ctx) anyerror!void {
    const m = MockCa.of(ctx);
    const id = ctx.params.get("id") orelse "";
    lockSpin(&m.lock);
    const n = @min(id.len, m.ari_id.len);
    @memcpy(m.ari_id[0..n], id[0..n]);
    m.ari_id_len = n;
    m.lock.unlock();
    ctx.res.setStatus(200);
    try ctx.res.setHeader("Content-Type", "application/json");
    try ctx.res.setHeader("Retry-After", "21600");
    try ctx.res.writeAll(
        \\{"suggestedWindow":{"start":"2025-01-02T04:00:00Z","end":"2025-01-03T04:00:00Z"},
        \\ "explanationURL":"https://acme.example.com/docs/ari"}
    );
}

/// The standard mock-CA routes (+ the lifecycle ones when `extras`).
fn mockRoutes(r: *router.Router, extras: bool) !void {
    try r.get("/dir", mcDirectory);
    try r.head("/new-nonce", mcNewNonce);
    try r.get("/new-nonce", mcNewNonce);
    try r.post("/new-acct", mcNewAccount);
    try r.post("/new-order", mcNewOrder);
    try r.post("/authz/1", mcAuthz);
    try r.post("/chall/1", mcChallenge);
    try r.post("/order/1", mcOrder);
    try r.post("/finalize/1", mcFinalize);
    try r.post("/cert/1", mcCert);
    try r.post("/cert/1/alt", mcCertAlt);
    if (extras) {
        try r.post("/acct/1", mcAccount);
        try r.post("/key-change", mcKeyChange);
        try r.post("/revoke", mcRevoke);
        try r.get("/ari/:id", mcRenewalInfo);
    }
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
        return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    };

    // ── the real ACME client under test ──
    var transport = http.Client.init(io, testing.allocator, .{});
    defer transport.deinit();
    var account_key: jws.KeyPair = undefined;
    try jws.Es256.KeyPair.generateDeterministicInto(&account_key, &@as([32]u8, @splat(11)));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));

    var dir_url_buf: [64]u8 = undefined;
    const dir_url = try std.fmt.bufPrint(&dir_url_buf, "http://127.0.0.1:{d}/dir", .{
        ca_server.boundAddress().getPort(),
    });
    var client = Client.init(io, testing.allocator, &transport, &account_key, .{
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
        return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
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
    var key: jws.KeyPair = undefined;
    try x509.ecPrivateKeyFromPem(&key, testing.allocator, cert.key_pem); // parses back — a usable leaf key
    std.crypto.secureZero(u8, std.mem.asBytes(&key));
    try testing.expectEqualStrings(mock.account_url, client.accountUrl().?);
    // Tokens are cleaned up after each authorization.
    try testing.expectEqual(@as(usize, 0), client.challengeResponder().count());

    // register() is idempotent — no second newAccount round.
    const nonces_before = mock.nonces_issued;
    try client.register();
    try testing.expectEqual(nonces_before, mock.nonces_issued);
}

test "integration: a wildcard certificate over DNS-01 against the mock CA" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var zone: TestZone = .{};
    var mock: MockCa = .{
        .gpa = testing.allocator,
        .io = io,
        .mode = .dns_01,
        .order_domain = "*." ++ MockCa.domain,
        .zone = &zone,
        .badnonce_left = 0,
    };

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
        return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    };
    const ca_port = ca_server.boundAddress().getPort();
    // DNS-01 needs no challenge server; the URL is unused.
    try mock.setUrls(ca_port, ca_port);
    defer mock.deinitUrls();

    var transport = http.Client.init(io, testing.allocator, .{});
    defer transport.deinit();
    var account_key: jws.KeyPair = undefined;
    try jws.Es256.KeyPair.generateDeterministicInto(&account_key, &@as([32]u8, @splat(12)));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));

    var client = Client.init(io, testing.allocator, &transport, &account_key, .{
        .directory_url = mock.dir_url,
        .challenge_type = .dns_01,
        .dns_publisher = zone.publisher(),
        .poll_interval_ms = 10,
        .max_polls = 50,
    });
    defer client.deinit();

    const ca_thread = try std.Thread.spawn(.{}, serveWrap, .{&ca_server});
    defer ca_thread.join();
    defer ca_server.shutdown();

    var cert = try client.obtain(&.{"*." ++ MockCa.domain});
    defer cert.deinit(testing.allocator);

    if (mock.fail_count != 0)
        std.debug.print("mock CA recorded failures: {d} — first: {s}\n", .{ mock.fail_count, mock.failNote() });
    try testing.expectEqual(@as(u32, 0), mock.fail_count);
    try testing.expect(mock.challenge_ok); // the CA resolved the right TXT value
    try testing.expect(mock.csr_ok); // the CSR's SAN is the wildcard
    // Published once at the base name, removed once, exactly that record.
    try testing.expectEqual(@as(u32, 1), zone.presents);
    try testing.expectEqual(@as(u32, 1), zone.cleanups);
    try testing.expect(!zone.live and !zone.bad_cleanup);
    try testing.expectEqualStrings("_acme-challenge." ++ MockCa.domain, zone.name_buf[0..zone.name_len]);
    try testing.expectEqualStrings(x509.test_cert_pem ++ x509.test_root_cert_pem, cert.chain_pem);
}

test "DNS-01 preconditions: wildcard needs dns_01, dns_01 needs a publisher, a refused publish aborts" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var transport = http.Client.init(io, testing.allocator, .{});
    defer transport.deinit();
    var account_key: jws.KeyPair = undefined;
    try jws.Es256.KeyPair.generateDeterministicInto(&account_key, &@as([32]u8, @splat(13)));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));

    // Refused before any network I/O: the directory URL is never contacted.
    {
        var c = Client.init(io, testing.allocator, &transport, &account_key, .{ .directory_url = "http://127.0.0.1:1/dir" });
        defer c.deinit();
        try testing.expectError(error.InvalidDomain, c.obtain(&.{"*.example.org"}));
    }
    {
        var c = Client.init(io, testing.allocator, &transport, &account_key, .{
            .directory_url = "http://127.0.0.1:1/dir",
            .challenge_type = .dns_01,
        });
        defer c.deinit();
        try testing.expectError(error.DnsPublisherMissing, c.obtain(&.{"*.example.org"}));
        // Malformed wildcards stay malformed under dns_01 too.
        var zone: TestZone = .{};
        c.options.dns_publisher = zone.publisher();
        try testing.expectError(error.InvalidDomain, c.obtain(&.{"a.*.example.org"}));
        try testing.expectError(error.InvalidDomain, c.obtain(&.{"*"}));
    }

    var buf: [dns01_max_name_len]u8 = undefined;
    try testing.expectEqualStrings("_acme-challenge.example.org", dns01RecordName(&buf, "example.org"));
    try testing.expectEqualStrings("_acme-challenge." ++ "x" ** 253, dns01RecordName(&buf, "x" ** 253));
}

test "parseAuthz: selects dns-01 and reads the wildcard flag" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const authz = try parseAuthz(a,
        \\{"status":"pending","identifier":{"type":"dns","value":"example.org"},"wildcard":true,
        \\ "challenges":[{"type":"dns-01","url":"https://ca/ch/9","token":"tok9"}]}
    );
    try testing.expect(authz.wildcard);
    try testing.expectEqualStrings("example.org", authz.identifier);
    try testing.expectEqualStrings("https://ca/ch/9", authz.dns01.?.url);
    try testing.expectEqualStrings("tok9", authz.dns01.?.token);
    try testing.expect(authz.http01 == null);
    const plain = try parseAuthz(a, "{\"status\":\"pending\",\"challenges\":[]}");
    try testing.expect(!plain.wildcard and plain.dns01 == null);
}

// ── audit 2026-10-04: test asked for by a mutation survivor ──────────────────

test "Responder: a path with a '/' after the prefix is never a token, even one that was set" {
    // RFC 8555 §8.3: the token is a single path segment (base64url, §8.1 —
    // no '/'); the responder answers only that shape, so a key authorization
    // stored under a slash-bearing name (only `set` by hand can do it) is
    // never served.
    var responder = Responder.init(testing.allocator);
    defer responder.deinit();
    try responder.set("a/b", "a/b.THUMBPRINT");
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(responder.middleware());
    var buf: [1024]u8 = undefined;
    const nested = runWire(&r, wire("GET", "/.well-known/acme-challenge/a/b"), &buf);
    try testing.expect(std.mem.startsWith(u8, nested, "HTTP/1.1 404"));
}

// ── lifecycle: EAB, rollover, revocation, ARI, ES384 (2026-10-13) ───────────

/// A mock CA on loopback with the lifecycle routes, plus a client against it.
/// Fields are set up by `start`; the caller defers `stop`.
const Lab = struct {
    threaded: std.Io.Threaded,
    mock: MockCa,
    ca_router: router.Router,
    ca_server: http.Server,
    transport: http.Client,
    ca_thread: ?std.Thread = null,

    fn start(lab: *Lab, extras: bool) !void {
        lab.threaded = std.Io.Threaded.init(testing.allocator, .{});
        errdefer lab.threaded.deinit();
        const io = lab.threaded.io();
        lab.mock = .{ .gpa = testing.allocator, .io = io, .extras = extras, .badnonce_left = 0 };
        lab.ca_router = router.Router.init(testing.allocator);
        errdefer lab.ca_router.deinit();
        lab.ca_router.state = &lab.mock;
        try mockRoutes(&lab.ca_router, extras);
        lab.ca_server = http.Server.init(io, testing.allocator, .{
            .handler = lab.ca_router.handler(),
            .context = &lab.ca_router,
        });
        errdefer lab.ca_server.deinit();
        lab.ca_server.bind() catch |err| {
            return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
        };
        const port = lab.ca_server.boundAddress().getPort();
        try lab.mock.setUrls(port, port);
        errdefer lab.mock.deinitUrls();
        lab.transport = http.Client.init(io, testing.allocator, .{});
        lab.ca_thread = try std.Thread.spawn(.{}, serveWrap, .{&lab.ca_server});
    }

    fn stop(lab: *Lab) void {
        if (lab.ca_thread) |t| {
            lab.ca_server.shutdown();
            t.join();
        }
        lab.transport.deinit();
        lab.mock.deinitUrls();
        lab.ca_server.deinit();
        lab.ca_router.deinit();
        lab.threaded.deinit();
    }

    fn client(lab: *Lab, account_key: anytype, options: Options) Client {
        var o = options;
        o.directory_url = lab.mock.dir_url;
        o.poll_interval_ms = 10;
        o.max_polls = 50;
        return Client.init(lab.threaded.io(), testing.allocator, &lab.transport, account_key, o);
    }

    fn expectClean(lab: *Lab) !void {
        if (lab.mock.fail_count != 0)
            std.debug.print("mock CA recorded failures: {d} — first: {s}\n", .{ lab.mock.fail_count, lab.mock.failNote() });
        try testing.expectEqual(@as(u32, 0), lab.mock.fail_count);
    }
};

fn labKey(comptime E: type, comptime seed_byte: u8) E.KeyPair {
    var kp: E.KeyPair = undefined;
    E.KeyPair.generateDeterministicInto(&kp, &@as([E.KeyPair.seed_length]u8, @splat(seed_byte))) catch unreachable;
    return kp;
}

test "EAB (RFC 8555 §7.3.4): the inner HS256 JWS is the one std's HMAC computes, and the CA verifies it" {
    var lab: Lab = undefined;
    try lab.start(true);
    defer lab.stop();
    lab.mock.eab_kid = "kid-1";
    lab.mock.eab_key = "an hmac key the CA issued";

    var account_key = labKey(jws.Es256, 21);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var c = lab.client(&account_key, .{
        .eab = .{ .kid = "kid-1", .hmac_key = "an hmac key the CA issued" },
    });
    defer c.deinit();
    try c.register();
    try testing.expect(lab.mock.eab_seen);
    try lab.expectClean();

    // Wrong MAC key: the CA refuses the registration, and says why.
    var other = lab.client(&account_key, .{
        .eab = .{ .kid = "kid-1", .hmac_key = "not the key" },
    });
    defer other.deinit();
    lab.mock.eab_seen = false;
    try testing.expectError(error.AcmeProblem, other.register());
    try testing.expect(!lab.mock.eab_seen);
    try testing.expectEqualStrings("BadSignature", lab.mock.failNote());
    lab.mock.resetFails();

    // No binding at all against a CA that wants one.
    var none = lab.client(&account_key, .{});
    defer none.deinit();
    try testing.expectError(error.AcmeProblem, none.register());
    lab.mock.resetFails();
}

test "EAB: the JWS bytes against an independent HMAC-SHA256 (std) over the RFC 8555 §7.3.4 layout" {
    const kp = labKey(jws.Es256, 22);
    const key = "0123456789abcdef0123456789abcdef";
    const url = "https://ca.example/acme/new-account";
    const out = try jws.signEab(testing.allocator, kp.public_key, "10", key, url);
    defer testing.allocator.free(out);

    const Flat = struct { protected: []const u8, payload: []const u8, signature: []const u8 };
    const flat = try std.json.parseFromSlice(Flat, testing.allocator, out, .{});
    defer flat.deinit();
    // protected = {"alg":"HS256","kid":"10","url":...} — no nonce.
    const protected = try jws.base64UrlDecodeAlloc(testing.allocator, flat.value.protected);
    defer testing.allocator.free(protected);
    try testing.expectEqualStrings("{\"alg\":\"HS256\",\"kid\":\"10\",\"url\":\"https://ca.example/acme/new-account\"}", protected);
    // payload = the account's canonical JWK.
    const payload = try jws.base64UrlDecodeAlloc(testing.allocator, flat.value.payload);
    defer testing.allocator.free(payload);
    var jwk_buf: [jws.max_canonical_jwk_len]u8 = undefined;
    try testing.expectEqualStrings(jws.canonicalJwk(&jwk_buf, kp.public_key), payload);
    // signature = HMAC-SHA256(key, protected_b64 "." payload_b64).
    const input = try std.mem.concat(testing.allocator, u8, &.{ flat.value.protected, ".", flat.value.payload });
    defer testing.allocator.free(input);
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, input, key);
    var want: [43]u8 = undefined;
    try testing.expectEqualStrings(jws.base64UrlEncode(&want, &mac), flat.value.signature);

    // The verifier agrees, and a wrong key or a flipped byte does not.
    var v = try jws.verifyEab(testing.allocator, out, key);
    v.deinit();
    try testing.expectError(error.BadSignature, jws.verifyEab(testing.allocator, out, "another key entirely"));
    const bent = try testing.allocator.dupe(u8, out);
    defer testing.allocator.free(bent);
    const at = std.mem.indexOf(u8, bent, "\"payload\":\"").? + 11;
    bent[at] = if (bent[at] == 'A') 'B' else 'A';
    try testing.expectError(error.BadSignature, jws.verifyEab(testing.allocator, bent, key));
}

test "account lifecycle: contact update, rollover ES256 -> ES384 (both JWS layers), stale key refused, deactivation" {
    var lab: Lab = undefined;
    try lab.start(true);
    defer lab.stop();

    var old_key = labKey(jws.Es256, 31);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&old_key));
    var c = lab.client(&old_key, .{});
    defer c.deinit();

    try c.updateContact(&.{ "mailto:a@example.org", "mailto:b@example.org" });
    try testing.expectEqual(@as(usize, 2), lab.mock.contact_count);
    try testing.expectEqualStrings("mailto:b@example.org", lab.mock.contact_seen[1][0..lab.mock.contact_seen_len[1]]);

    // Rollover to a P-384 key. The mock checked outer (old key, kid, nonce)
    // and inner (new jwk, no nonce, same url, account + oldKey).
    var new_key = labKey(jws.Es384, 32);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&new_key));
    try c.rolloverKey(&new_key);
    try testing.expectEqual(@as(u32, 1), lab.mock.rollovers);
    try testing.expectEqual(jws.Alg.es384, lab.mock.account_key.?.alg());
    try lab.expectClean();
    try testing.expectEqual(jws.Alg.es384, c.account_key.alg());

    // The client now signs with the new key (the mock verifies with it only).
    try c.updateContact(&.{});
    try testing.expectEqual(@as(usize, 0), lab.mock.contact_count);
    try lab.expectClean();

    // A client still holding the old (P-256) key is refused: the account's key
    // is P-384 now, which an ES256 signature cannot be checked against.
    var stale = lab.client(&old_key, .{});
    defer stale.deinit();
    stale.kid = try testing.allocator.dupe(u8, lab.mock.account_url);
    try testing.expectError(error.AcmeProblem, stale.updateContact(&.{"mailto:c@example.org"}));
    try testing.expectEqual(@as(u32, 1), lab.mock.fail_count);
    try testing.expectEqualStrings("UnsupportedJws", lab.mock.failNote());
    lab.mock.resetFails();

    // A rollover onto the key already in use is a 409; the client keeps its key.
    try testing.expectError(error.AcmeProblem, c.rolloverKey(&new_key));
    try testing.expectEqualStrings("new key already in use", lab.mock.failNote());
    lab.mock.resetFails();
    try testing.expectEqual(jws.Alg.es384, c.account_key.alg()); // unchanged by the failure
    try c.updateContact(&.{}); // and it still works

    // A second rollover, P-384 to P-384: now the previous key is the stale one,
    // refused on its signature alone.
    var third = labKey(jws.Es384, 33);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&third));
    try c.rolloverKey(&third);
    try testing.expectEqual(@as(u32, 2), lab.mock.rollovers);
    var stale2 = lab.client(&new_key, .{});
    defer stale2.deinit();
    stale2.kid = try testing.allocator.dupe(u8, lab.mock.account_url);
    try testing.expectError(error.AcmeProblem, stale2.updateContact(&.{"mailto:d@example.org"}));
    try testing.expectEqualStrings("BadSignature", lab.mock.failNote());
    lab.mock.resetFails();
    try lab.expectClean();

    try c.deactivate();
    try testing.expect(lab.mock.deactivated);
    try testing.expect(c.accountUrl() == null);
}

test "revocation (RFC 8555 §7.6): by account key and by certificate key; reasons; NotSupported without revokeCert" {
    var lab: Lab = undefined;
    try lab.start(true);
    defer lab.stop();

    // A certificate whose key we hold: the TLS-ALPN-01 shape, self-signed.
    var cert_key = labKey(jws.Es384, 41);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&cert_key));
    const id: [32]u8 = @splat(7);
    const cert_der = try x509.tlsAlpnCertDer(testing.allocator, &cert_key, "example.org", id, "\x05", x509.tls_alpn_not_before, x509.tls_alpn_not_after);
    defer testing.allocator.free(cert_der);
    lab.mock.revoke_expect = cert_der;

    var account_key = labKey(jws.Es256, 42);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var c = lab.client(&account_key, .{});
    defer c.deinit();

    try c.revoke(cert_der, .key_compromise);
    try testing.expectEqual(.account, lab.mock.revoked_by);
    try testing.expectEqual(@as(?u8, 1), lab.mock.revoke_reason);
    try lab.expectClean();

    // By the certificate key, no registration needed (a fresh client).
    var anon = lab.client(&account_key, .{});
    defer anon.deinit();
    lab.mock.revoked_by = .none;
    try anon.revokeWithCertKey(cert_der, &cert_key, null);
    try testing.expectEqual(.cert_key, lab.mock.revoked_by);
    try testing.expectEqual(@as(?u8, null), lab.mock.revoke_reason);
    try testing.expect(anon.accountUrl() == null);
    try lab.expectClean();

    // The CA rejects a certificate-key revocation signed by some other key.
    var stranger = labKey(jws.Es384, 43);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&stranger));
    try anon.revokeWithCertKey(cert_der, &stranger, .superseded);
    try testing.expectEqual(@as(?u8, 4), lab.mock.revoke_reason);
    try testing.expectEqualStrings("signer key is not the certificate key", lab.mock.failNote());
    lab.mock.resetFails();

    // `Reason` carries the RFC 5280 codes numerically and stays open.
    try testing.expectEqual(@as(u8, 9), @intFromEnum(Reason.privilege_withdrawn));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(@as(Reason, @enumFromInt(2))));
}

test "NotSupported: a CA without keyChange, revokeCert, renewalInfo" {
    var lab: Lab = undefined;
    try lab.start(false);
    defer lab.stop();
    var account_key = labKey(jws.Es256, 44);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var c = lab.client(&account_key, .{});
    defer c.deinit();
    var new_key = labKey(jws.Es256, 45);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&new_key));
    try testing.expectError(error.NotSupported, c.rolloverKey(&new_key));
    try testing.expectError(error.NotSupported, c.revoke("x", null));
    try testing.expectError(error.NotSupported, c.revokeWithCertKey("x", &new_key, null));
    try testing.expectError(error.NotSupported, c.renewalInfo("x"));
    try lab.expectClean();
}

const rfc9773_cert_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBQzCB66ADAgECAgUAh2VDITAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwpFeGFt
    \\cGxlIENBMCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMBYxFDAS
    \\BgNVBAMTC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeBZu
    \\7cbpAYNXZLbbh8rNIzuOoqOOtmxA1v7cRm//AwyMwWxyHz4zfwmBhcSrf47NUAFf
    \\qzLQ2PPQxdTXREYEnKMjMCEwHwYDVR0jBBgwFoAUaYhba4dGQEHhs3uEe6CuLN4B
    \\yNQwCgYIKoZIzj0EAwIDRwAwRAIge09+S5TZAlw5tgtiVvuERV6cT4mfutXIlwTb
    \\+FYN/8oCIClDsqBklhB9KAelFiYt9+6FDj3z4KGVelYM5MdsO3pK
    \\-----END CERTIFICATE-----
    \\
;

test "ARI (RFC 9773): the CertID on the wire, the window, Retry-After, explanationURL" {
    var lab: Lab = undefined;
    try lab.start(true);
    defer lab.stop();
    var account_key = labKey(jws.Es256, 51);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var c = lab.client(&account_key, .{});
    defer c.deinit();

    var info = try c.renewalInfoPem(rfc9773_cert_pem);
    defer info.deinit(testing.allocator);
    // GET <renewalInfo>/<CertID>, the RFC 9773 §4.1 example value.
    try testing.expectEqualStrings("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE", lab.mock.ari_id[0..lab.mock.ari_id_len]);
    try testing.expectEqual(@as(i64, 1735790400), info.window_start); // 2025-01-02T04:00:00Z
    try testing.expectEqual(@as(i64, 1735876800), info.window_end); // 2025-01-03T04:00:00Z
    try testing.expectEqualStrings("https://acme.example.com/docs/ari", info.explanation_url.?);
    try testing.expectEqual(@as(?u64, 21600), info.retry_after_s);
    // No account was needed for it.
    try testing.expect(c.accountUrl() == null);
    try lab.expectClean();

    // pickTime stays inside the window and covers both ends' neighbourhood.
    var prng = std.Random.DefaultPrng.init(1);
    for (0..200) |_| {
        const t = info.pickTime(prng.random());
        try testing.expect(t >= info.window_start and t <= info.window_end);
    }
    const point: RenewalInfo = .{ .window_start = 5, .window_end = 5, .explanation_url = null, .retry_after_s = null };
    try testing.expectEqual(@as(i64, 5), point.pickTime(prng.random()));

    // A certificate without an AKI cannot be asked about (the TLS-ALPN-01
    // validation certificate is one), nor can junk.
    var key = labKey(jws.Es256, 52);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
    const id: [32]u8 = @splat(1);
    const no_aki = try x509.tlsAlpnCertDer(testing.allocator, &key, "example.org", id, "\x01", x509.tls_alpn_not_before, x509.tls_alpn_not_after);
    defer testing.allocator.free(no_aki);
    try testing.expectError(error.MalformedResponse, c.renewalInfo(no_aki));
    try testing.expectError(error.MalformedResponse, c.renewalInfo("junk"));
}

test "parseRenewalInfo / parseRfc3339: offsets, fractions, leap days, and what is refused" {
    try testing.expectEqual(@as(?i64, 0), parseRfc3339("1970-01-01T00:00:00Z"));
    try testing.expectEqual(@as(?i64, -1), parseRfc3339("1969-12-31T23:59:59Z"));
    try testing.expectEqual(@as(?i64, 1791894896), parseRfc3339("2026-10-13T12:34:56Z"));
    try testing.expectEqual(@as(?i64, 1709251199), parseRfc3339("2024-02-29T23:59:59Z"));
    try testing.expectEqual(@as(?i64, 1791894896), parseRfc3339("2026-10-13T12:34:56.789Z"));
    try testing.expectEqual(@as(?i64, 1791894896), parseRfc3339("2026-10-13t12:34:56z"));
    try testing.expectEqual(@as(?i64, 1791894896), parseRfc3339("2026-10-13T14:34:56+02:00"));
    try testing.expectEqual(@as(?i64, 1791894896), parseRfc3339("2026-10-13T07:04:56-05:30"));
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2016-12-31T23:59:60Z")); // leap second: refused (was read as :59 before datefmt)
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2023-02-29T00:00:00Z")); // not a leap year
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2026-13-01T00:00:00Z"));
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2026-10-13 12:34:56Z"));
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2026-10-13T12:34:56"));
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2026-10-13T12:34:56.Z"));
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2026-10-13T12:34:56Zjunk"));
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2026-10-13T12:34:56+0200"));
    try testing.expectEqual(@as(?i64, null), parseRfc3339(""));

    const ok = try parseRenewalInfo(testing.allocator,
        \\{"suggestedWindow":{"start":"2025-01-02T04:00:00Z","end":"2025-01-03T04:00:00Z"},"extra":1}
    );
    try testing.expectEqual(@as(i64, 1735790400), ok.window_start);
    try testing.expect(ok.explanation_url == null);
    try testing.expectError(error.MalformedResponse, parseRenewalInfo(testing.allocator, "{}"));
    try testing.expectError(error.MalformedResponse, parseRenewalInfo(testing.allocator, "not json"));
    // end before start is not a window.
    try testing.expectError(error.MalformedResponse, parseRenewalInfo(testing.allocator,
        \\{"suggestedWindow":{"start":"2025-01-03T04:00:00Z","end":"2025-01-02T04:00:00Z"}}
    ));
}

test "new-order payload: the optional replaces member (RFC 9773 §5)" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var js: std.json.Stringify = .{ .writer = &out.writer, .options = .{} };
    try writeOrderPayload(&js, &.{"example.org"}, .{ .replaces = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE" });
    try testing.expectEqualStrings(
        "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"example.org\"}],\"replaces\":\"aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE\"}",
        out.written(),
    );
    var plain: std.Io.Writer.Allocating = .init(testing.allocator);
    defer plain.deinit();
    var js2: std.json.Stringify = .{ .writer = &plain.writer, .options = .{} };
    try writeOrderPayload(&js2, &.{"example.org"}, .{});
    try testing.expect(std.mem.indexOf(u8, plain.written(), "replaces") == null);
}

test "integration: ES384 account key and ES384 certificate key through the whole flow, with replaces" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var mock: MockCa = .{ .gpa = testing.allocator, .io = io, .badnonce_left = 0 };
    var ca_router = router.Router.init(testing.allocator);
    defer ca_router.deinit();
    ca_router.state = &mock;
    try mockRoutes(&ca_router, false);
    var ca_server = http.Server.init(io, testing.allocator, .{
        .handler = ca_router.handler(),
        .context = &ca_router,
    });
    defer ca_server.deinit();
    ca_server.bind() catch |err| {
        return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    };

    var transport = http.Client.init(io, testing.allocator, .{});
    defer transport.deinit();
    var account_key = labKey(jws.Es384, 61);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));

    var dir_url_buf: [64]u8 = undefined;
    const dir_url = try std.fmt.bufPrint(&dir_url_buf, "http://127.0.0.1:{d}/dir", .{ca_server.boundAddress().getPort()});
    var client = Client.init(io, testing.allocator, &transport, &account_key, .{
        .directory_url = dir_url,
        .cert_key_alg = .es384,
        .poll_interval_ms = 10,
        .max_polls = 50,
    });
    defer client.deinit();

    var challenge_router = router.Router.init(testing.allocator);
    defer challenge_router.deinit();
    try challenge_router.use(client.challengeResponder().middleware());
    var challenge_server = http.Server.init(io, testing.allocator, .{
        .handler = challenge_router.handler(),
        .context = &challenge_router,
    });
    defer challenge_server.deinit();
    challenge_server.bind() catch |err| {
        return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    };
    try mock.setUrls(ca_server.boundAddress().getPort(), challenge_server.boundAddress().getPort());
    defer mock.deinitUrls();

    const ca_thread = try std.Thread.spawn(.{}, serveWrap, .{&ca_server});
    defer ca_thread.join();
    defer ca_server.shutdown();
    const ch_thread = try std.Thread.spawn(.{}, serveWrap, .{&challenge_server});
    defer ch_thread.join();
    defer challenge_server.shutdown();

    var cert = try client.obtainWith(&.{MockCa.domain}, .{ .replaces = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE" });
    defer cert.deinit(testing.allocator);

    if (mock.fail_count != 0)
        std.debug.print("mock CA recorded failures: {d} — first: {s}\n", .{ mock.fail_count, mock.failNote() });
    try testing.expectEqual(@as(u32, 0), mock.fail_count);
    try testing.expect(mock.challenge_ok and mock.csr_ok and mock.finalized);
    try testing.expectEqual(@as(?jws.Alg, .es384), mock.account_alg); // newAccount carried alg ES384 + a P-384 jwk
    try testing.expectEqual(@as(?jws.Alg, .es384), mock.csr_alg); // the CSR key is P-384
    try testing.expectEqualStrings("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE", mock.replaces_seen[0..mock.replaces_len]);
    // The key-authorization served over HTTP used the P-384 thumbprint (checked by the mock).
    // The certificate key PEM is a P-384 SEC1 key and loads back.
    var back: jws.AnyKeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&back));
    try x509.privateKeyFromPem(&back, testing.allocator, cert.key_pem);
    try testing.expectEqual(jws.Alg.es384, back.alg());
}

// ── W1 (2026-10-16): profiles, validity, alternate chains, 503, rateLimited, CSR input ──

/// A Lab issuing over DNS-01 (no challenge server needed).
fn w1Client(lab: *Lab, zone: *TestZone, key_seed: u8, account_key: *jws.KeyPair) !Client {
    try jws.Es256.KeyPair.generateDeterministicInto(account_key, &@as([32]u8, @splat(key_seed)));
    lab.mock.mode = .dns_01;
    lab.mock.zone = zone;
    return lab.client(account_key, .{ .challenge_type = .dns_01, .dns_publisher = zone.publisher() });
}

test "W1: profiles from the directory; required vs preferred; notBefore/notAfter on the order" {
    var lab: Lab = undefined;
    try lab.start(false);
    defer lab.stop();
    var zone: TestZone = .{};
    var account_key: jws.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var c = try w1Client(&lab, &zone, 71, &account_key);
    defer c.deinit();

    const offered = try c.profiles();
    try testing.expectEqual(@as(usize, 2), offered.len);
    try testing.expectEqualStrings("classic", offered[0].name);
    try testing.expectEqualStrings("shortlived", offered[1].name);
    try testing.expectEqualStrings("https://ca/docs#shortlived", offered[1].description);

    // Not offered + required: refused before any order is placed.
    try testing.expectError(error.NotSupported, c.obtainWith(&.{MockCa.domain}, .{ .profile = "tlsserver" }));
    try testing.expectEqual(@as(usize, 0), lab.mock.profile_len);

    var cert = try c.obtainWith(&.{MockCa.domain}, .{
        .profile = "shortlived",
        .not_before = 1767225600, // 2026-01-01T00:00:00Z
        .not_after = 1767830399, // 2026-01-07T23:59:59Z
    });
    cert.deinit(testing.allocator);
    try testing.expectEqualStrings("shortlived", lab.mock.profile_seen[0..lab.mock.profile_len]);
    try testing.expectEqualStrings("2026-01-01T00:00:00Z/2026-01-07T23:59:59Z", lab.mock.validity_seen[0..lab.mock.validity_len]);

    // Not offered + preferred: the order goes out without a profile.
    lab.mock.profile_len = 0;
    var cert2 = try c.obtainWith(&.{MockCa.domain}, .{ .profile = "tlsserver", .profile_mode = .preferred });
    cert2.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), lab.mock.profile_len);
    try lab.expectClean();
}

test "W1: preferred chain picks the alternate by its topmost issuer CN, else keeps the default" {
    var lab: Lab = undefined;
    try lab.start(false);
    defer lab.stop();
    lab.mock.alt_chain = true;
    var zone: TestZone = .{};
    var account_key: jws.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var c = try w1Client(&lab, &zone, 72, &account_key);
    defer c.deinit();

    // No preference: the default chain, no alternate fetched.
    var plain = try c.obtain(&.{MockCa.domain});
    plain.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 0), lab.mock.alt_fetches);

    // The default already matches: no alternate fetched either.
    var dflt = try c.obtainWith(&.{MockCa.domain}, .{ .preferred_chain = "acme-test-root" });
    defer dflt.deinit(testing.allocator);
    try testing.expectEqualStrings(x509.test_cert_pem ++ x509.test_root_cert_pem, dflt.chain_pem);
    try testing.expectEqual(@as(u32, 0), lab.mock.alt_fetches);

    var alt = try c.obtainWith(&.{MockCa.domain}, .{ .preferred_chain = "acme-test-fixture" });
    defer alt.deinit(testing.allocator);
    try testing.expectEqualStrings(x509.test_cert_pem, alt.chain_pem);
    try testing.expectEqual(@as(u32, 1), lab.mock.alt_fetches);

    // Nothing matches: the default chain, after looking at the alternate.
    var none = try c.obtainWith(&.{MockCa.domain}, .{ .preferred_chain = "Nobody Root X9" });
    defer none.deinit(testing.allocator);
    try testing.expectEqualStrings(x509.test_cert_pem ++ x509.test_root_cert_pem, none.chain_pem);
    try testing.expectEqual(@as(u32, 2), lab.mock.alt_fetches);
    try lab.expectClean();
}

test "W1: a 503 is resent; rateLimited is error.RateLimited with retryAfter, not resent" {
    var lab: Lab = undefined;
    try lab.start(false);
    defer lab.stop();
    var zone: TestZone = .{};
    var account_key: jws.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var c = try w1Client(&lab, &zone, 73, &account_key);
    defer c.deinit();

    lab.mock.unavailable_left = 2; // = max_unavailable_retries
    var cert = try c.obtain(&.{MockCa.domain});
    cert.deinit(testing.allocator);
    try testing.expectEqual(@as(u8, 0), lab.mock.unavailable_left);

    lab.mock.unavailable_left = 3; // one more than the client resends
    try testing.expectError(error.AcmeProblem, c.obtain(&.{MockCa.domain}));
    try testing.expectEqual(@as(u8, 0), lab.mock.unavailable_left);
    try testing.expectEqual(@as(?u64, 0), c.retryAfter());

    lab.mock.rate_limit = true;
    const before = lab.mock.nonces_issued;
    try testing.expectError(error.RateLimited, c.obtain(&.{MockCa.domain}));
    try testing.expectEqual(@as(?u64, 3600), c.retryAfter());
    try testing.expect(std.mem.indexOf(u8, c.lastProblem().?, "rateLimited") != null);
    try testing.expectEqual(before + 1, lab.mock.nonces_issued); // one refusal, no resend
    try lab.expectClean();
}

test "W1: Retry-After as delay-seconds and as an HTTP-date" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var transport = http.Client.init(io, testing.allocator, .{});
    defer transport.deinit();
    var account_key: jws.KeyPair = undefined;
    try jws.Es256.KeyPair.generateDeterministicInto(&account_key, &@as([32]u8, @splat(74)));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var c = Client.init(io, testing.allocator, &transport, &account_key, .{});
    defer c.deinit();
    try testing.expectEqual(@as(?u64, 120), c.retryAfterHeader(" 120 "));
    try testing.expectEqual(@as(?u64, 0), c.retryAfterHeader("Sun, 06 Nov 1994 08:49:37 GMT")); // past
    const future = c.retryAfterHeader("Fri, 31 Dec 9999 23:59:59 GMT").?;
    try testing.expect(future > 200 * 365 * std.time.s_per_day);
    try testing.expectEqual(@as(?u64, null), c.retryAfterHeader("soon"));
    try testing.expectEqual(@as(?u64, null), c.retryAfterHeader(null));
}

test "W1: Link header parsing keeps only rel=alternate targets" {
    const head: struct {
        block: []const u8,
        fn iterate(h: *const @This()) http.h1.HeaderIterator {
            return .{ .lines = std.mem.splitScalar(u8, h.block, '\n') };
        }
    } = .{ .block = "Link: <https://ca/a1>;rel=\"alternate\", <https://ca/dir>;rel=\"index\"\r\n" ++
        "Content-Type: x\r\nlink: <https://ca/a2> ; REL=\"up Alternate\"\r\nLink: <https://ca/x>\r\n" };
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const got = try alternateLinks(arena.allocator(), &head);
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expectEqualStrings("https://ca/a1", got[0]);
    try testing.expectEqualStrings("https://ca/a2", got[1]);
}

test "W1: RFC 3339 formatting of order validity" {
    var buf: [rfc3339_len]u8 = undefined;
    try testing.expectEqualStrings("1970-01-01T00:00:00Z", formatRfc3339(&buf, 0));
    try testing.expectEqualStrings("2024-02-29T12:34:56Z", formatRfc3339(&buf, 1709210096));
    try testing.expectEqual(@as(?i64, 1709210096), parseRfc3339(formatRfc3339(&buf, 1709210096)));
    try testing.expectEqualStrings("9999-12-31T23:59:59Z", formatRfc3339(&buf, std.math.maxInt(u64)));
}

/// `openssl ecparam -name prime256v1 -genkey -noout -out k.pem;
/// openssl req -new -key k.pem -subj "/CN=acme-poc.example/O=Some Org"
///   -addext "subjectAltName=DNS:acme-poc.example"
///   -addext "keyUsage=critical,digitalSignature" -outform DER -out csr.der`
/// (OpenSSL 3.5.5; `openssl req -verify` OK). A subject and a second
/// extension our own `csrDer` never writes.
const openssl_csr_hex = "308201273081ce020100302e3119301706035504030c1061636d652d706f632e6578616d706c653111300f060355040a0c08536f6d65204f72673059301306072a8648ce3d020106082a8648ce3d03010703420004f45aeeb349ed660135e274eacec814bbd7eb0a10ae13397b6a1d1a99fa64ee8b9ddabd6aedf91d8a236927a8c0c97936275d3b418c099475f5b7f74cb71f6145a03e303c06092a864886f70d01090e312f302d301b0603551d1104143012821061636d652d706f632e6578616d706c65300e0603551d0f0101ff040403020780300a06082a8648ce3d04030203480030450220059138aafbecafdea2f5b7e4ad1a0965de0ece3d889f030e16e2d1ed7eb350330221009a67d5861e830daeb12d246451aeb31db28959273aece3bcd18b51d35d5f5dfb";

test "W1: obtainWithCsr issues for a foreign (openssl) CSR; a broken one is InvalidCsr" {
    var lab: Lab = undefined;
    try lab.start(false);
    defer lab.stop();
    var zone: TestZone = .{};
    var account_key: jws.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var c = try w1Client(&lab, &zone, 75, &account_key);
    defer c.deinit();

    var csr: [openssl_csr_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&csr, openssl_csr_hex);
    var chain = try c.obtainWithCsr(&csr, .{});
    defer chain.deinit(testing.allocator);
    try testing.expectEqualStrings(x509.test_cert_pem ++ x509.test_root_cert_pem, chain.chain_pem);
    try testing.expectEqual(x509.test_cert_not_after, chain.not_after);
    try testing.expect(lab.mock.csr_ok);

    const orders_before = lab.mock.nonces_issued;
    csr[csr.len - 1] ^= 1; // the signature no longer verifies
    try testing.expectError(error.InvalidCsr, c.obtainWithCsr(&csr, .{}));
    try testing.expectEqual(orders_before, lab.mock.nonces_issued); // refused before any request
    try lab.expectClean();
}

test "W1: ES512 account key and ES512 certificate key through the whole flow" {
    var lab: Lab = undefined;
    try lab.start(false);
    defer lab.stop();
    var zone: TestZone = .{};
    lab.mock.mode = .dns_01;
    lab.mock.zone = &zone;
    var account_key: jws.Es512.KeyPair = undefined;
    try jws.Es512.KeyPair.generateDeterministicInto(&account_key, &@as([jws.Es512.KeyPair.seed_length]u8, @splat(76)));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var c = lab.client(&account_key, .{
        .challenge_type = .dns_01,
        .dns_publisher = zone.publisher(),
        .cert_key_alg = .es512,
    });
    defer c.deinit();

    var cert = try c.obtain(&.{MockCa.domain});
    defer cert.deinit(testing.allocator);
    try lab.expectClean();
    try testing.expectEqual(@as(?jws.Alg, .es512), lab.mock.account_alg); // newAccount: alg ES512 + a P-521 jwk
    try testing.expectEqual(@as(?jws.Alg, .es512), lab.mock.csr_alg); // the CSR key is P-521
    try testing.expect(lab.mock.csr_ok);
    var back: jws.AnyKeyPair = undefined;
    try x509.privateKeyFromPem(&back, testing.allocator, cert.key_pem);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&back));
    try testing.expectEqual(jws.Alg.es512, back.alg());
}

// ── W2 (2026-10-16): IP identifiers (RFC 8738) ──────────────────────────────

test "W2: reverse names for TLS-ALPN-01 SNI (RFC 8738 §6)" {
    var buf: [max_reverse_name_len]u8 = undefined;
    try testing.expectEqualStrings("1.2.0.192.in-addr.arpa", reverseName(&buf, netaddr.parseIp("192.0.2.1").?));
    // RFC 3596 §2.5's own example, 4321:0:1:2:3:4:567:89ab.
    try testing.expectEqualStrings(
        "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa",
        reverseName(&buf, netaddr.parseIp("4321:0:1:2:3:4:567:89ab").?),
    );
    try testing.expectEqual(max_reverse_name_len, reverseName(&buf, netaddr.parseIp("::").?).len);
}

test "W2: IP identifiers — canonical text only, never over DNS-01, typed ip on the order" {
    try testing.expect((try ipIdentifier("192.0.2.1")) != null);
    try testing.expect((try ipIdentifier("2001:db8::1")) != null);
    try testing.expect((try ipIdentifier("example.org")) == null);
    try testing.expectError(error.InvalidDomain, ipIdentifier("2001:DB8::1")); // RFC 5952: lowercase
    try testing.expectError(error.InvalidDomain, ipIdentifier("2001:db8:0:0:0:0:0:1")); // RFC 5952: compressed

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var js: std.json.Stringify = .{ .writer = &out.writer, .options = .{} };
    try writeOrderPayload(&js, &.{ "example.org", "192.0.2.1", "2001:db8::1" }, .{});
    try testing.expectEqualStrings(
        "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"example.org\"},{\"type\":\"ip\",\"value\":\"192.0.2.1\"}," ++
            "{\"type\":\"ip\",\"value\":\"2001:db8::1\"}]}",
        out.written(),
    );

    // Refused before any network I/O.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var transport = http.Client.init(threaded.io(), testing.allocator, .{});
    defer transport.deinit();
    var account_key: jws.KeyPair = undefined;
    try jws.Es256.KeyPair.generateDeterministicInto(&account_key, &@as([32]u8, @splat(81)));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var zone: TestZone = .{};
    var c = Client.init(threaded.io(), testing.allocator, &transport, &account_key, .{
        .directory_url = "http://127.0.0.1:1/dir",
        .challenge_type = .dns_01,
        .dns_publisher = zone.publisher(),
    });
    defer c.deinit();
    try testing.expectError(error.InvalidDomain, c.obtain(&.{"192.0.2.1"}));
    c.options.challenge_type = .http_01;
    try testing.expectError(error.InvalidDomain, c.obtain(&.{"2001:DB8::1"})); // not the RFC 5952 spelling
}

test "W2: RSA account key and RSA certificate key through the whole flow" {
    var lab: Lab = undefined;
    try lab.start(false);
    defer lab.stop();
    var zone: TestZone = .{};
    lab.mock.mode = .dns_01;
    lab.mock.zone = &zone;
    // The account key: openssl's 2048-bit fixture (generation is slow in Debug).
    const account_key = try testing.allocator.create(rsa.KeyPair);
    defer {
        std.crypto.secureZero(u8, std.mem.asBytes(account_key));
        testing.allocator.destroy(account_key);
    }
    try x509.rsaPrivateKeyFromPem(account_key, x509.test_rsa_pkcs1_pem);
    var c = lab.client(account_key, .{
        .challenge_type = .dns_01,
        .dns_publisher = zone.publisher(),
        .cert_key_alg = .rs256,
    });
    defer c.deinit();

    var cert = try c.obtain(&.{MockCa.domain});
    defer cert.deinit(testing.allocator);
    try lab.expectClean();
    try testing.expectEqual(@as(?jws.Alg, .rs256), lab.mock.account_alg); // newAccount: alg RS256 + an RSA jwk
    try testing.expectEqual(@as(?jws.Alg, .rs256), lab.mock.csr_alg); // the CSR key is RSA
    try testing.expect(lab.mock.csr_ok); // a fresh key, not the account's
    try testing.expect(std.mem.startsWith(u8, cert.key_pem, "-----BEGIN RSA PRIVATE KEY-----"));
    const back = try testing.allocator.create(rsa.KeyPair);
    defer {
        std.crypto.secureZero(u8, std.mem.asBytes(back));
        testing.allocator.destroy(back);
    }
    try x509.rsaPrivateKeyFromPem(back, cert.key_pem);
    try testing.expectEqual(@as(usize, 2048), back.public_key.bits());

    c.options.cert_rsa_bits = 1024;
    try testing.expectError(error.UnsupportedKeySize, c.obtain(&.{MockCa.domain}));
}

test "W2: an IPv6 identifier over HTTP-01 against the mock CA, typed ip with an iPAddress SAN" {
    var lab: Lab = undefined;
    try lab.start(false);
    defer lab.stop();
    lab.mock.order_domain = "2001:db8::7";
    var account_key: jws.KeyPair = undefined;
    try jws.Es256.KeyPair.generateDeterministicInto(&account_key, &@as([32]u8, @splat(82)));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var c = lab.client(&account_key, .{});
    defer c.deinit();

    // The CA fetches the key authorization from the client's responder.
    var challenge_router = router.Router.init(testing.allocator);
    defer challenge_router.deinit();
    try challenge_router.use(c.challengeResponder().middleware());
    var challenge_server = http.Server.init(lab.threaded.io(), testing.allocator, .{
        .handler = challenge_router.handler(),
        .context = &challenge_router,
    });
    defer challenge_server.deinit();
    challenge_server.bind() catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    lab.mock.deinitUrls();
    try lab.mock.setUrls(lab.ca_server.boundAddress().getPort(), challenge_server.boundAddress().getPort());
    c.options.directory_url = lab.mock.dir_url;
    const ch_thread = try std.Thread.spawn(.{}, serveWrap, .{&challenge_server});
    defer ch_thread.join();
    defer challenge_server.shutdown();

    var cert = try c.obtain(&.{"2001:db8::7"});
    defer cert.deinit(testing.allocator);
    try lab.expectClean();
    try testing.expect(lab.mock.challenge_ok and lab.mock.csr_ok);
}

/// A DNS-01 `Solver` over a `TestZone` (no `dns_publisher`), counting its calls.
const ZoneSolver = struct {
    zone: *TestZone,
    presents: u32 = 0,
    cleanups: u32 = 0,
    fail: bool = false,
    wildcard_seen: bool = false,

    fn solver(z: *ZoneSolver) Solver {
        return .{ .ctx = z, .type = .dns_01, .present = present, .cleanup = cleanup };
    }

    fn present(ctx: ?*anyopaque, req: *const ChallengeRequest) SolverError!void {
        const z: *ZoneSolver = @ptrCast(@alignCast(ctx.?));
        z.presents += 1;
        z.wildcard_seen = req.wildcard;
        if (z.fail) return error.SolverFailed;
        var name_buf: [dns01_max_name_len]u8 = undefined;
        const value = req.dnsTxtValue();
        if (!TestZone.present(z.zone, req.dnsRecordName(&name_buf), &value)) return error.SolverFailed;
    }

    fn cleanup(ctx: ?*anyopaque, req: *const ChallengeRequest) void {
        const z: *ZoneSolver = @ptrCast(@alignCast(ctx.?));
        z.cleanups += 1;
        var name_buf: [dns01_max_name_len]u8 = undefined;
        const value = req.dnsTxtValue();
        TestZone.cleanup(z.zone, req.dnsRecordName(&name_buf), &value);
    }
};

test "W3: the order flow step by step — newOrder, fetchOrder by URL, authorization handle, finalize, download" {
    var lab: Lab = undefined;
    try lab.start(false);
    defer lab.stop();
    var zone: TestZone = .{};
    var account_key: jws.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var c = try w1Client(&lab, &zone, 81, &account_key);
    defer c.deinit();

    var order = try c.newOrder(&.{MockCa.domain}, .{});
    defer order.deinit();
    try testing.expectEqual(Status.pending, order.status);
    try testing.expectEqualStrings(lab.mock.order_url, order.url);
    try testing.expectEqual(@as(usize, 1), order.identifiers.len);
    try testing.expectEqualStrings(MockCa.domain, order.identifiers[0]);
    try testing.expectEqual(@as(?[]const u8, null), order.certificate);

    // The same order again by its URL (a resumed order).
    var again = try c.fetchOrder(order.url);
    defer again.deinit();
    try testing.expectEqualStrings(order.authorizations[0], again.authorizations[0]);
    try testing.expectEqualStrings(order.finalize, again.finalize);

    var authz = try c.fetchAuthorization(order.authorizations[0]);
    defer authz.deinit();
    try testing.expectEqual(Status.pending, authz.status);
    try testing.expectEqualStrings(MockCa.domain, authz.identifier);
    try testing.expect(!authz.ip and !authz.wildcard);
    // The mock offers an http-01 decoy and dns-01; both are listed, by kind.
    try testing.expectEqual(@as(usize, 2), authz.challenges.len);
    try testing.expectEqual(@as(?ChallengeType, .http_01), authz.challenges[0].kind);
    const ch = authz.challenge(.dns_01).?;
    try testing.expectEqualStrings(MockCa.token, ch.token);
    try testing.expectEqual(@as(?Challenge, null), authz.challenge(.tls_alpn_01));

    // The proof by hand: the record the key authorization implies.
    var ka_buf: [jws.max_key_authorization_len]u8 = undefined;
    const ka = try c.keyAuthorization(&ka_buf, ch.token);
    var name_buf: [dns01_max_name_len]u8 = undefined;
    const value = jws.dns01TxtValueFromKeyAuthorization(ka);
    try testing.expectEqualSlices(u8, &(try jws.dns01TxtValue(ch.token, account_key.public_key)), &value);
    try testing.expect(TestZone.present(&zone, dns01RecordName(&name_buf, authz.identifier), &value));
    try c.acceptChallenge(ch.url);
    try c.waitAuthorization(authz.url);
    TestZone.cleanup(&zone, dns01RecordName(&name_buf, authz.identifier), &value);

    try c.waitOrder(&order, .ready);
    try testing.expectEqual(Status.ready, order.status);
    // Downloading before the order is valid is refused, not attempted.
    try testing.expectError(error.MalformedResponse, c.downloadChain(&order, null));

    var cert_key: jws.KeyPair = undefined;
    jws.generateKeyPair(&cert_key, lab.threaded.io());
    defer std.crypto.secureZero(u8, std.mem.asBytes(&cert_key));
    const csr = try x509.csrDer(testing.allocator, &cert_key, &.{MockCa.domain});
    defer testing.allocator.free(csr);
    try c.finalize(&order, csr);
    try c.waitOrder(&order, .valid);
    try testing.expectEqual(Status.valid, order.status);
    try testing.expectEqualStrings(lab.mock.cert_url, order.certificate.?);
    var chain = try c.downloadChain(&order, null);
    defer chain.deinit(testing.allocator);
    try testing.expectEqualStrings(x509.test_cert_pem ++ x509.test_root_cert_pem, chain.chain_pem);
    try testing.expect(chain.not_after > 0);
    try testing.expect(!zone.bad_cleanup);
    try lab.expectClean();
}

test "W5: AcmeIssuer through the mock CA, HTTP-01 answered by the Manager's solver and middleware" {
    const Manager = @import("Manager.zig");
    const storage = @import("storage.zig");
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var mock: MockCa = .{ .gpa = testing.allocator, .io = io, .badnonce_left = 0 };

    var ca_router = router.Router.init(testing.allocator);
    defer ca_router.deinit();
    ca_router.state = &mock;
    try mockRoutes(&ca_router, false);
    var ca_server = http.Server.init(io, testing.allocator, .{ .handler = ca_router.handler(), .context = &ca_router });
    defer ca_server.deinit();
    ca_server.bind() catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});

    var mem = storage.MemStorage.init(testing.allocator);
    defer mem.deinit();
    var manager = Manager.init(io, testing.allocator, .{ .storage = mem.storage(), .random_seed = 1 });
    defer manager.deinit();

    // The "domain": port 80 is the manager's middleware, nothing else.
    var challenge_router = router.Router.init(testing.allocator);
    defer challenge_router.deinit();
    try challenge_router.use(manager.httpMiddleware());
    var challenge_server = http.Server.init(io, testing.allocator, .{ .handler = challenge_router.handler(), .context = &challenge_router });
    defer challenge_server.deinit();
    challenge_server.bind() catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});

    try mock.setUrls(ca_server.boundAddress().getPort(), challenge_server.boundAddress().getPort());
    defer mock.deinitUrls();
    const ca_thread = try std.Thread.spawn(.{}, serveWrap, .{&ca_server});
    defer ca_thread.join();
    defer ca_server.shutdown();
    const ch_thread = try std.Thread.spawn(.{}, serveWrap, .{&challenge_server});
    defer ch_thread.join();
    defer challenge_server.shutdown();

    var transport = http.Client.init(io, testing.allocator, .{});
    defer transport.deinit();
    var account_key: jws.KeyPair = undefined;
    try jws.Es256.KeyPair.generateDeterministicInto(&account_key, &@as([32]u8, @splat(91)));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var client = Client.init(io, testing.allocator, &transport, &account_key, .{
        .directory_url = mock.dir_url,
        .poll_interval_ms = 10,
        .max_polls = 50,
        .solvers = manager.challengeSolvers(),
    });
    defer client.deinit();

    var acme_issuer: Manager.AcmeIssuer = .{ .client = &client, .name = "mock" };
    const iss = acme_issuer.issuer();

    // The issuer alone: the mock fetched the key authorization from the
    // manager's middleware, and the tokens are gone afterwards.
    var diag: Manager.Diagnostics = .{};
    var issued = try iss.issue(iss.ctx, testing.allocator, &.{ .names = &.{MockCa.domain} }, &diag);
    defer issued.deinit(testing.allocator);
    try testing.expect(mock.challenge_ok);
    try testing.expectEqualStrings(x509.test_cert_pem ++ x509.test_root_cert_pem, issued.chain_pem);
    try testing.expectEqual(@as(usize, 0), manager.http_tokens.count());
    try testing.expectEqual(@as(usize, 0), client.challengeResponder().count()); // the built-in was never used
    // No renewalInfo in this directory: the window hook says so.
    try testing.expectError(error.NotSupported, iss.renewal_window.?(iss.ctx, issued.chain_pem, &diag));

    // Through the manager: the mock CA hands out a fixed test chain, not one
    // for the freshly generated key — the manager refuses to store or serve
    // it (the chain check is the first of `checkPair`'s to trip).
    const Rec = struct {
        failed: u32 = 0,
        installed: u32 = 0,
        problem: [96]u8 = @splat(0),
        fn call(ctx: ?*anyopaque, ev: *const Manager.Event) void {
            const r: *@This() = @ptrCast(@alignCast(ctx.?));
            switch (ev.*) {
                .installed => r.installed += 1,
                .failed => |f| {
                    r.failed += 1;
                    @memcpy(r.problem[0..@min(f.problem.len, 96)], f.problem[0..@min(f.problem.len, 96)]);
                },
                .storage_failed => {},
            }
        }
    };
    var rec: Rec = .{};
    manager.options.on_event = .{ .ctx = &rec, .call = Rec.call };
    try manager.addIssuer(iss);
    try manager.manage(&.{MockCa.domain});
    _ = manager.maintain();
    try testing.expectEqual(@as(u32, 1), rec.failed);
    try testing.expectEqual(@as(u32, 0), rec.installed);
    try testing.expectEqualStrings("issued chain does not verify", std.mem.sliceTo(&rec.problem, 0));
    try testing.expectEqual(@as(usize, 0), mem.count());
    if (mock.fail_count != 0) std.debug.print("mock CA: {s}\n", .{mock.failNote()});
    try testing.expectEqual(@as(u32, 0), mock.fail_count);
}

test "W3: a caller's Solver replaces the built-in (no dns_publisher needed); a failing one aborts, no cleanup" {
    var lab: Lab = undefined;
    try lab.start(false);
    defer lab.stop();
    var zone: TestZone = .{};
    var zs: ZoneSolver = .{ .zone = &zone };
    const solvers = [_]Solver{zs.solver()};
    var account_key: jws.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    try jws.Es256.KeyPair.generateDeterministicInto(&account_key, &@as([32]u8, @splat(82)));
    lab.mock.mode = .dns_01;
    lab.mock.zone = &zone;
    lab.mock.order_domain = "*.acme-poc.example";
    var c = lab.client(&account_key, .{ .challenge_type = .dns_01, .solvers = &solvers });
    defer c.deinit();

    var cert = try c.obtain(&.{"*.acme-poc.example"});
    cert.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 1), zs.presents);
    try testing.expectEqual(@as(u32, 1), zs.cleanups);
    try testing.expect(zs.wildcard_seen);
    try testing.expect(!zone.live and !zone.bad_cleanup);
    try lab.expectClean();

    // The solver refuses: DnsPublishFailed for DNS-01, and no cleanup.
    zs.fail = true;
    try testing.expectError(error.DnsPublishFailed, c.obtain(&.{"*.acme-poc.example"}));
    try testing.expectEqual(@as(u32, 2), zs.presents);
    try testing.expectEqual(@as(u32, 1), zs.cleanups);

    // Without the solver and without a publisher there is nothing to solve with.
    var bare = lab.client(&account_key, .{ .challenge_type = .dns_01 });
    defer bare.deinit();
    try testing.expectError(error.DnsPublisherMissing, bare.obtain(&.{"*.acme-poc.example"}));
}

test "W3: deactivateAuthorization (RFC 8555 §7.5.2); newOrder checks identifier syntax only" {
    var lab: Lab = undefined;
    try lab.start(false);
    defer lab.stop();
    var zone: TestZone = .{};
    var account_key: jws.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var c = try w1Client(&lab, &zone, 83, &account_key);
    defer c.deinit();

    try testing.expectError(error.InvalidDomain, c.newOrder(&.{}, .{}));
    try testing.expectError(error.InvalidDomain, c.newOrder(&.{"not a name"}, .{}));
    try testing.expectError(error.InvalidDomain, c.newOrder(&.{"2001:DB8::1"}, .{})); // not RFC 5952 text (upper case)

    var order = try c.newOrder(&.{MockCa.domain}, .{});
    defer order.deinit();
    try c.deactivateAuthorization(order.authorizations[0]);
    try testing.expect(lab.mock.authz_deactivated);
    var authz = try c.fetchAuthorization(order.authorizations[0]);
    defer authz.deinit();
    try testing.expectEqual(Status.deactivated, authz.status);
    // A deactivated authorization is not solved again.
    try testing.expectError(error.AuthorizationFailed, c.solveAuthorization(order.authorizations[0]));
    try testing.expectEqual(@as(u32, 0), zone.presents);
    try lab.expectClean();
}

test "W3: ChallengeRequest helpers agree with the token-based ones" {
    var kp: jws.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));
    try jws.Es256.KeyPair.generateDeterministicInto(&kp, &@as([32]u8, @splat(84)));
    const token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
    var ka_buf: [jws.max_key_authorization_len]u8 = undefined;
    const ka = try jws.keyAuthorization(&ka_buf, token, kp.public_key);
    const req: ChallengeRequest = .{ .type = .tls_alpn_01, .identifier = "2001:db8::1", .ip = true, .wildcard = false, .token = token, .key_authorization = ka };
    try testing.expectEqualSlices(u8, &(try jws.dns01TxtValue(token, kp.public_key)), &req.dnsTxtValue());
    try testing.expectEqualSlices(u8, &(try jws.acmeIdentifier(token, kp.public_key)), &req.tlsAlpnIdentifier());
    var sni_buf: [max_reverse_name_len]u8 = undefined;
    // RFC 3596 §2.5 order: nibbles reversed.
    try testing.expectEqualStrings("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", req.tlsAlpnSni(&sni_buf));
    const named: ChallengeRequest = .{ .type = .dns_01, .identifier = "example.org", .ip = false, .wildcard = true, .token = token, .key_authorization = ka };
    try testing.expectEqualStrings("example.org", named.tlsAlpnSni(&sni_buf));
    var name_buf: [dns01_max_name_len]u8 = undefined;
    try testing.expectEqualStrings("_acme-challenge.example.org", named.dnsRecordName(&name_buf));
}
