// SPDX-License-Identifier: MIT

//! Certificates that obtain and renew themselves: the layer
//! `golang.org/x/crypto/acme/autocert` and CertMagic put over an ACME client
//! (design only — clean-room).
//!
//! A `Manager` keeps a set of certificates current. Each `manage` call adds
//! one certificate for a list of names. `maintain` is one step of the
//! upkeep — load from `Storage`, renew when due, back off on failure — and
//! returns when it next has work; `run` is the loop around it for a caller
//! that has no clock of its own. The current certificates go out two ways: a
//! TLS listener asks `certificate` per handshake (and `tlsAlpnMaterial` for
//! ALPN `acme-tls/1`), and `Options.on_event` reports every certificate
//! installed so a caller with its own certificate store can swap it in.
//!
//! What the pieces map to:
//! - **storage** (autocert `Cache`, CertMagic `Storage`): `Options.storage`,
//!   `DirStorage` on disk. A stored certificate is served before any
//!   network call, so a restart with the CA unreachable still serves.
//! - **renewal** (autocert `RenewBefore`, CertMagic ARI): the CA's ARI
//!   window (RFC 9773) when an issuer offers it, else two thirds into the
//!   lifetime (half for certificates of ten days or less); failures back off
//!   from one minute, doubling, to `Options.max_backoff_s`, never sooner than
//!   the CA's `Retry-After`. A certificate that is still valid keeps serving.
//! - **issuers** (CertMagic `Issuer`, `IssuerPolicy`): `addIssuer`, tried in
//!   order (or shuffled); `AcmeIssuer` wraps a `Client`.
//! - **challenges**: the manager answers HTTP-01 (`httpMiddleware`, with
//!   autocert's redirect-to-HTTPS fallback) and TLS-ALPN-01
//!   (`tlsAlpnMaterial`) itself — give `challengeSolvers()` to the
//!   `Client`s. DNS-01 stays the client's (`Options.dns_publisher`, `acmedns`).
//! - **on-demand** (autocert `HostPolicy`, CertMagic `OnDemandConfig`):
//!   `Options.on_demand` obtains a certificate during the first handshake
//!   for a name the policy allows, rate-limited.
//! - **fleet** (CertMagic `Locker`): issuance runs under a storage lock, and
//!   `Options.distributed_challenges` puts challenge data into storage so
//!   whichever node the CA reaches can answer.
//!
//! Every issued chain is checked before it is stored or served: it verifies
//! (RFC 5280, `x509.verifyChain`) up to `Options.trust_anchors` — by
//! default to its own topmost certificate, which still proves the links —
//! the leaf covers every managed name, and the leaf's key is the key that
//! came with it.
//!
//! Concurrency: `certificate`, `tlsAlpnMaterial`, the middleware and the
//! solvers may be called from any thread while `maintain` runs; drive
//! `maintain`/`run` from one thread. Not movable after `init` (the
//! middleware and the solvers point at it).

const std = @import("std");
const http = @import("http");
const router = @import("router");
const pkix = @import("x509");
const rsa = @import("rsa");
const netaddr = @import("netaddr");
const Client = @import("Client.zig");
const jws = @import("jws.zig");
const x509 = @import("x509.zig");
const storage_mod = @import("storage.zig");

const Allocator = std.mem.Allocator;
const Manager = @This();

pub const Storage = storage_mod.Storage;

io: std.Io,
gpa: Allocator,
options: Options,
mutex: std.Io.Mutex = .init,
/// Signalled when an entry stops being busy (on-demand waiters).
idle: std.Io.Condition = .init,
/// Heap slots (stable addresses): each issuer's calls are serialized by its
/// slot's lock — a `Client` must be driven by one thread at a time.
issuers: std.ArrayList(*IssuerSlot) = .empty,
/// Set by `manage`/`addIssuer`, so `run` stops sleeping early.
wake: std.atomic.Value(bool) = .init(false),
entries: std.ArrayList(*Entry) = .empty,
/// Every managed name → its entry; keys borrow the entry's names.
by_name: std.StringHashMapUnmanaged(*Entry) = .empty,
http_tokens: Client.Responder,
tls_alpn: Client.TlsAlpnResponder,
prng: std.Random.DefaultPrng,
node_id_buf: [32]u8 = undefined,
node_id_len: u8 = 0,
limiter: RateLimiter = .{},
/// `maintain` rounds, to visit each entry once per call.
round: u64 = 0,
solver_array: [2]Client.Solver = undefined,

// ── public types ────────────────────────────────────────────────────────────

pub const Options = struct {
    /// Where accounts, certificates and locks live. Required.
    storage: Storage,
    /// Order in which `addIssuer`'s issuers are tried for one certificate.
    issuer_policy: IssuerPolicy = .in_order,
    /// DER trust anchors an issued chain must verify to. Empty: the chain's
    /// own topmost certificate is the anchor — every link and the leaf are
    /// still checked, but not that the top is a root you trust.
    trust_anchors: []const []const u8 = &.{},
    /// Ask issuers for an ARI renewal window (RFC 9773) when they offer one.
    use_ari: bool = true,
    /// Without ARI, renew once this percentage of the lifetime remains
    /// (CertMagic `RenewalWindowRatio`, autocert `RenewBefore`); 0: a
    /// third, half for certificates of ten days or less. 1..99.
    renewal_window_pct: u8 = 0,
    /// The name whose certificate a ClientHello without SNI gets (CertMagic
    /// `DefaultServerName`); null: none.
    default_server_name: ?[]const u8 = null,
    /// How often to re-ask for the ARI window when the CA sends no
    /// `Retry-After` (RFC 9773 §4.3 suggests six hours).
    ari_poll_s: u32 = 6 * 3600,
    /// Ceiling of the failure back-off (1 min, 2 min, 4 min, …).
    max_backoff_s: u32 = 6 * 3600,
    /// How long one node's issuance lock lasts; longer than any issuance.
    lock_lease_s: u32 = 15 * 60,
    /// How soon to look again while another node holds the issuance lock.
    lock_poll_s: u32 = 60,
    /// This node's lock-owner name (1..32 of `[A-Za-z0-9._@+-]`, else `init`
    /// panics); null: a random one per `Manager`.
    node_id: ?[]const u8 = null,
    /// Also write HTTP-01 / TLS-ALPN-01 challenge data to `storage`, and
    /// fall back to it when a token is not found locally: the node the CA
    /// connects to need not be the node that placed the order.
    distributed_challenges: bool = false,
    /// HTTP requests outside the challenge path: redirect GET/HEAD to
    /// `https://` (302) and refuse the rest (400), as autocert's
    /// `HTTPHandler(nil)`; false passes them to the next handler.
    http_redirect: bool = false,
    on_event: ?EventHook = null,
    on_demand: ?OnDemand = null,
    /// Time source, epoch seconds; null: the io's real clock.
    clock: ?Clock = null,
    /// Seed for the renewal-time jitter; null: drawn from the io.
    random_seed: ?u64 = null,
};

pub const IssuerPolicy = enum { in_order, random };

const IssuerSlot = struct {
    issuer: Issuer,
    lock: std.Io.Mutex = .init,
};

/// Most issuers one manager tries (`addIssuer` refuses more).
pub const max_issuers = 16;

pub const Clock = struct {
    ctx: ?*anyopaque = null,
    now: *const fn (ctx: ?*anyopaque) i64,
};

/// On-demand issuance: a certificate is obtained during the first TLS
/// handshake for a name nobody `manage`d. Without `allow` an attacker could
/// make the server order a certificate for every name it sends — so it is
/// required.
pub const OnDemand = struct {
    ctx: ?*anyopaque = null,
    /// May a certificate be obtained for `name` (lower-case, no trailing
    /// dot)? Called outside the manager's lock; may block briefly.
    allow: *const fn (ctx: ?*anyopaque, name: []const u8) bool,
    /// At most `rate.max` on-demand issuances per `rate.window_s` seconds
    /// (CertMagic's ring-buffer limiter); `max` is capped at 256.
    rate: RateLimit = .{},
    /// After a failed on-demand issuance, handshakes for that name get no
    /// certificate for this long, without asking the CA again.
    failure_backoff_s: u32 = 5 * 60,
};

/// `window_s` 0 means no limit; `max` 0 means no on-demand issuance at all.
pub const RateLimit = struct { max: u16 = 10, window_s: u32 = 60 };

/// Something that issues certificates: an ACME CA (`AcmeIssuer`) or
/// anything else that can.
pub const Issuer = struct {
    ctx: *anyopaque,
    /// A storage-safe name (`storage.validKey` characters, no `/`), used in
    /// events and as the account directory (`accountKeyPath`).
    name: []const u8,
    /// Issue a certificate for `req.names`. The result is allocated with
    /// `gpa` and owned by the manager.
    issue: *const fn (ctx: *anyopaque, gpa: Allocator, req: *const IssueRequest, diag: *Diagnostics) IssueError!Issued,
    /// The CA's ARI renewal window for a certificate it issued (RFC 9773);
    /// null when this issuer has none. `error.NotSupported` for "not this
    /// issuer's" or "no ARI here".
    renewal_window: ?*const fn (ctx: *anyopaque, chain_pem: []const u8, diag: *Diagnostics) IssueError!Window = null,
};

pub const IssueRequest = struct {
    /// The names, lower-case, as `manage` was given them.
    names: []const []const u8,
    /// RFC 9773 §5: the ARI CertID of the certificate being replaced.
    replaces: ?[]const u8 = null,
};

/// An issued certificate: PEM chain (leaf first) + leaf key PEM + notAfter.
pub const Issued = Client.Certificate;

pub const Window = struct { start: i64, end: i64, retry_after_s: ?u64 = null };

pub const IssueError = error{ OutOfMemory, IssueFailed, RateLimited, NotSupported };

/// What went wrong in an issuer call, for events and back-off.
pub const Diagnostics = struct {
    retry_after_s: ?u64 = null,
    problem_buf: [256]u8 = undefined,
    problem_len: usize = 0,

    pub fn note(d: *Diagnostics, msg: []const u8) void {
        const n = @min(msg.len, d.problem_buf.len);
        @memcpy(d.problem_buf[0..n], msg[0..n]);
        d.problem_len = n;
    }

    pub fn problem(d: *const Diagnostics) []const u8 {
        return d.problem_buf[0..d.problem_len];
    }
};

pub const EventHook = struct {
    ctx: ?*anyopaque = null,
    /// Called from the thread that did the work, outside the manager's
    /// lock. Everything in `event` is borrowed for the call. The hook must
    /// not call `certificate` for the names of the event (an on-demand entry
    /// is still busy then, and the call would wait for itself).
    call: *const fn (ctx: ?*anyopaque, event: *const Event) void,
};

pub const Event = union(enum) {
    /// A certificate became current for `names`.
    installed: struct {
        names: []const []const u8,
        chain_pem: []const u8,
        key_pem: []const u8,
        not_after: i64,
        source: Source,
        /// The issuer's name for `.issued`, null for `.storage`.
        issuer: ?[]const u8,
    },
    /// Obtaining or renewing failed; the next attempt is at `retry_at`. A
    /// certificate that is still valid keeps serving meanwhile.
    failed: struct {
        names: []const []const u8,
        problem: []const u8,
        retry_at: i64,
    },
    /// A certificate was issued and is served, but writing it to storage
    /// failed: a restart before the next renewal will order it again.
    storage_failed: struct {
        names: []const []const u8,
    },

    pub const Source = enum { storage, issued };
};

/// A caller-owned copy of a current certificate (free with `deinit`, which
/// wipes the key).
pub const Material = struct {
    chain_pem: []u8,
    key_pem: []u8,
    not_after: i64,

    pub fn deinit(mt: *Material, gpa: Allocator) void {
        gpa.free(mt.chain_pem);
        std.crypto.secureZero(u8, mt.key_pem);
        gpa.free(mt.key_pem);
        mt.* = undefined;
    }
};

pub const Error = error{
    OutOfMemory,
    /// A name is not a valid hostname, wildcard or IP literal, or the list
    /// is empty or too long.
    InvalidName,
    /// A name is already managed (by this or another `manage` call).
    AlreadyManaged,
};

/// Most names on one certificate (Let's Encrypt allows 100).
pub const max_names = 100;

// ── lifecycle ───────────────────────────────────────────────────────────────

pub fn init(io: std.Io, gpa: Allocator, options: Options) Manager {
    var seed: u64 = undefined;
    if (options.random_seed) |s| seed = s else io.random(std.mem.asBytes(&seed));
    var m: Manager = .{
        .io = io,
        .gpa = gpa,
        .options = options,
        .http_tokens = Client.Responder.init(gpa),
        .tls_alpn = Client.TlsAlpnResponder.init(gpa),
        .prng = std.Random.DefaultPrng.init(seed),
    };
    if (options.node_id) |id| {
        // A configuration error, not input: a truncated id could collide
        // with another node's and defeat the (re-entrant) issuance lock.
        if (id.len == 0 or id.len > m.node_id_buf.len or !storage_mod.validKey(id) or std.mem.indexOfScalar(u8, id, '/') != null)
            @panic("acme.Manager: Options.node_id must be 1..32 of [A-Za-z0-9._@+-]");
        @memcpy(m.node_id_buf[0..id.len], id);
        m.node_id_len = @intCast(id.len);
    } else {
        var raw: [8]u8 = undefined;
        io.random(&raw);
        const hex = std.fmt.bytesToHex(raw, .lower);
        @memcpy(m.node_id_buf[0..hex.len], &hex);
        m.node_id_len = hex.len;
    }
    return m;
}

/// No call may be in flight.
pub fn deinit(m: *Manager) void {
    for (m.entries.items) |e| m.freeEntry(e);
    m.entries.deinit(m.gpa);
    m.by_name.deinit(m.gpa);
    for (m.issuers.items) |slot| m.gpa.destroy(slot);
    m.issuers.deinit(m.gpa);
    m.http_tokens.deinit();
    m.tls_alpn.deinit();
    m.* = undefined;
}

fn nodeId(m: *const Manager) []const u8 {
    return m.node_id_buf[0..m.node_id_len];
}

fn now(m: *Manager) i64 {
    if (m.options.clock) |c| return c.now(c.ctx);
    return std.Io.Clock.real.now(m.io).toSeconds();
}

/// Add an issuer (at most `max_issuers`); `Issuer.ctx` must outlive the
/// manager. The manager calls one issuer from one thread at a time (on-demand
/// handshakes and `maintain` take turns), so a `Client` behind an
/// `AcmeIssuer` is never driven concurrently — do not share one `Client`
/// between two issuers.
pub fn addIssuer(m: *Manager, issuer: Issuer) error{ OutOfMemory, TooManyIssuers }!void {
    const slot = try m.gpa.create(IssuerSlot);
    errdefer m.gpa.destroy(slot);
    slot.* = .{ .issuer = issuer };
    m.mutex.lockUncancelable(m.io);
    defer m.mutex.unlock(m.io);
    if (m.issuers.items.len >= max_issuers) return error.TooManyIssuers;
    try m.issuers.append(m.gpa, slot);
    m.wake.store(true, .release);
}

/// The HTTP-01 and TLS-ALPN-01 solvers that publish through this manager:
/// set them as `Client.Options.solvers` of every client an `AcmeIssuer`
/// wraps. Valid for the manager's lifetime.
pub fn challengeSolvers(m: *Manager) []const Client.Solver {
    m.solver_array = .{
        .{ .ctx = m, .type = .http_01, .present = presentHttp01, .cleanup = cleanupHttp01 },
        .{ .ctx = m, .type = .tls_alpn_01, .present = presentTlsAlpn01, .cleanup = cleanupTlsAlpn01 },
    };
    return &m.solver_array;
}

// ── the managed set ─────────────────────────────────────────────────────────

const Cert = struct {
    chain_pem: []u8,
    key_pem: []u8,
    not_before: i64,
    not_after: i64,

    fn deinit(ct: *Cert, gpa: Allocator) void {
        gpa.free(ct.chain_pem);
        std.crypto.secureZero(u8, ct.key_pem);
        gpa.free(ct.key_pem);
        ct.* = undefined;
    }
};

const Entry = struct {
    /// Lower-case names, owned; `names[0]` names the storage files.
    names: [][]u8,
    /// Storage key stem, `certificates/<names[0], sanitized>`, owned.
    stem: []u8,
    on_demand: bool,
    cert: ?Cert = null,
    renew_at: i64 = 0,
    /// Next ARI poll; null = no ARI for this certificate.
    ari_at: ?i64 = null,
    ari_start: i64 = 0,
    ari_end: i64 = 0,
    failures: u32 = 0,
    /// Set after a failure or while another node holds the lock: the next
    /// attempt, overriding the renewal schedule. 0 = none.
    retry_at: i64 = 0,
    /// A step (maintain or on-demand) is working on it outside the lock.
    busy: bool = false,
    /// `unmanage`d while busy: freed when the step finishes.
    removed: bool = false,
    visited_round: u64 = 0,

    fn dueAt(e: *const Entry) i64 {
        if (e.retry_at != 0) return e.retry_at;
        if (e.cert == null) return 0;
        return @min(e.renew_at, e.ari_at orelse std.math.maxInt(i64));
    }
};

/// Keep one certificate covering `names` current: loaded from storage or
/// obtained on the next `maintain`. Names are hostnames, `*.` wildcards
/// (they need a DNS-01 issuer) or IP literals; they are lower-cased.
pub fn manage(m: *Manager, names: []const []const u8) Error!void {
    _ = try m.addEntry(names, false);
    m.wake.store(true, .release);
}

/// `on_demand` entries are created busy, in the same lock hold that makes
/// them findable: no other thread can free or start one before its creator
/// has it.
fn addEntry(m: *Manager, names: []const []const u8, on_demand: bool) Error!*Entry {
    if (names.len == 0 or names.len > max_names) return error.InvalidName;
    for (names) |n| if (!validName(n)) return error.InvalidName;

    const e = try m.gpa.create(Entry);
    errdefer m.gpa.destroy(e);
    const owned = try m.gpa.alloc([]u8, names.len);
    var filled: usize = 0;
    errdefer {
        for (owned[0..filled]) |n| m.gpa.free(n);
        m.gpa.free(owned);
    }
    for (names, owned) |n, *slot| {
        slot.* = try std.ascii.allocLowerString(m.gpa, n);
        filled += 1;
    }
    var stem_buf: [storage_mod.max_key_len]u8 = undefined;
    const stem = try m.gpa.dupe(u8, certStem(&stem_buf, owned[0]));
    errdefer m.gpa.free(stem);
    e.* = .{ .names = owned, .stem = stem, .on_demand = on_demand, .busy = on_demand };

    m.mutex.lockUncancelable(m.io);
    defer m.mutex.unlock(m.io);
    for (owned) |n| if (m.by_name.contains(n)) return error.AlreadyManaged;
    try m.entries.ensureUnusedCapacity(m.gpa, 1);
    try m.by_name.ensureUnusedCapacity(m.gpa, @intCast(owned.len));
    for (owned) |n| m.by_name.putAssumeCapacityNoClobber(n, e);
    m.entries.appendAssumeCapacity(e);
    return e;
}

/// Stop managing the certificate whose first name is `name` (stored files
/// are kept). False when no such certificate.
pub fn unmanage(m: *Manager, name: []const u8) bool {
    var lower_buf: [253]u8 = undefined;
    if (name.len > lower_buf.len) return false;
    const lower = std.ascii.lowerString(&lower_buf, name);
    m.mutex.lockUncancelable(m.io);
    defer m.mutex.unlock(m.io);
    const e = m.by_name.get(lower) orelse return false;
    if (!std.mem.eql(u8, e.names[0], lower)) return false;
    for (e.names) |n| _ = m.by_name.remove(n);
    for (m.entries.items, 0..) |x, i| if (x == e) {
        _ = m.entries.orderedRemove(i);
        break;
    };
    if (e.busy) e.removed = true else m.freeEntry(e);
    return true;
}

/// Unlink `e` from the set and free it (lock held, `e` not busy).
fn dropEntryLocked(m: *Manager, e: *Entry) void {
    for (e.names) |n| _ = m.by_name.remove(n);
    for (m.entries.items, 0..) |x, i| if (x == e) {
        _ = m.entries.orderedRemove(i);
        break;
    };
    m.freeEntry(e);
}

fn freeEntry(m: *Manager, e: *Entry) void {
    if (e.cert) |*ct| ct.deinit(m.gpa);
    for (e.names) |n| m.gpa.free(n);
    m.gpa.free(e.names);
    m.gpa.free(e.stem);
    m.gpa.destroy(e);
}

fn validName(name: []const u8) bool {
    const ok = x509.isValidDomain(name) or x509.isValidWildcardDomain(name) or netaddr.parseIp(name) != null;
    if (!ok) return false;
    var buf: [storage_mod.max_key_len]u8 = undefined;
    return storage_mod.validKey(certStem(&buf, name));
}

/// `certificates/<name>` with `*` → `_` and `:` → `+` (storage-key safe;
/// `_` never appears in a hostname a CA issues for).
fn certStem(buf: *[storage_mod.max_key_len]u8, name: []const u8) []const u8 {
    const prefix = "certificates/";
    @memcpy(buf[0..prefix.len], prefix);
    for (name, buf[prefix.len..][0..name.len]) |ch, *o| o.* = switch (ch) {
        '*' => '_',
        ':' => '+',
        else => ch,
    };
    return buf[0 .. prefix.len + name.len];
}

// ── maintain / run ──────────────────────────────────────────────────────────

/// One round of upkeep: every entry that is due is loaded, renewed or has
/// its ARI window refreshed (each at most once per call). Returns the epoch
/// second at which the next entry falls due — call again then (at once
/// when it is not in the future). Failures are reported through
/// `Options.on_event` and rescheduled, never returned.
pub fn maintain(m: *Manager) i64 {
    m.mutex.lockUncancelable(m.io);
    m.round += 1;
    const round = m.round;
    m.mutex.unlock(m.io);

    while (true) {
        const t = m.now();
        m.mutex.lockUncancelable(m.io);
        var pick: ?*Entry = null;
        for (m.entries.items) |e| {
            if (e.busy or e.visited_round == round) continue;
            if (idleOnDemand(e)) continue;
            if (e.dueAt() > t) continue;
            pick = e;
            break;
        }
        const e = pick orelse {
            m.mutex.unlock(m.io);
            break;
        };
        e.busy = true;
        e.visited_round = round;
        m.mutex.unlock(m.io);
        m.step(e, t);
        m.finishStep(e);
    }
    return m.nextDue();
}

fn nextDue(m: *Manager) i64 {
    const t = m.now();
    m.mutex.lockUncancelable(m.io);
    defer m.mutex.unlock(m.io);
    // A failed on-demand name is kept only for its back-off (to refuse fast);
    // after that it is forgotten, and the next handshake goes through the
    // policy and the rate limit again. Keeps the set bounded.
    var i = m.entries.items.len;
    while (i > 0) {
        i -= 1;
        const e = m.entries.items[i];
        if (!e.busy and idleOnDemand(e) and t >= e.retry_at) m.dropEntryLocked(e);
    }
    var next: i64 = std.math.maxInt(i64);
    for (m.entries.items) |e| if (!e.busy and !idleOnDemand(e)) {
        next = @min(next, e.dueAt());
    };
    // Nothing managed (or all busy elsewhere): look again in an hour.
    return if (next == std.math.maxInt(i64)) t + 3600 else next;
}

/// `maintain` forever, sleeping in between (at most an hour at a time, so
/// a wall-clock jump is noticed). Returns only when the io cancels it.
pub fn run(m: *Manager) error{Canceled}!void {
    while (true) {
        m.wake.store(false, .release);
        const next = m.maintain();
        var wait_s = std.math.clamp(next - m.now(), 0, 3600);
        // In one-second steps, so a `manage` or `addIssuer` meanwhile is
        // served within a second rather than at the next due time.
        while (wait_s > 0 and !m.wake.load(.acquire)) : (wait_s -= 1) {
            const d: std.Io.Clock.Duration = .{ .raw = .fromSeconds(1), .clock = .awake };
            d.sleep(m.io) catch return error.Canceled;
        }
    }
}

/// An on-demand name that never got a certificate is retried by the next
/// handshake that asks for it, not in the background (as CertMagic): a name
/// someone sent once and that cannot validate would otherwise be ordered
/// every few hours forever.
fn idleOnDemand(e: *const Entry) bool {
    return e.on_demand and e.cert == null;
}

fn finishStep(m: *Manager, e: *Entry) void {
    m.mutex.lockUncancelable(m.io);
    defer m.mutex.unlock(m.io);
    e.busy = false;
    if (e.removed) m.freeEntry(e);
    m.idle.broadcast(m.io);
}

/// The work for one due entry (it is busy; we are outside the lock).
fn step(m: *Manager, e: *Entry, t: i64) void {
    const needs_cert = e.cert == null or t >= e.renew_at or e.retry_at != 0;
    if (needs_cert) m.obtain(e, t) else m.pollAri(e, t);
}

/// Load from storage, else (under the fleet lock) issue.
fn obtain(m: *Manager, e: *Entry, t: i64) void {
    if (m.adoptStored(e, t)) return;

    var lock_buf: [storage_mod.max_key_len]u8 = undefined;
    const lock_name = std.fmt.bufPrint(&lock_buf, "issue/{s}", .{e.stem["certificates/".len..]}) catch unreachable;
    const locked = m.options.storage.tryLock(lock_name, m.nodeId(), t, m.options.lock_lease_s) catch |err| {
        var d: Diagnostics = .{};
        d.note(@errorName(err));
        return m.failed(e, t, &d, "storage lock failed");
    };
    if (!locked) {
        // Another node is issuing; its result lands in storage.
        m.mutex.lockUncancelable(m.io);
        e.retry_at = t + m.options.lock_poll_s;
        m.mutex.unlock(m.io);
        return;
    }
    defer m.options.storage.unlock(lock_name, m.nodeId());
    // The other node may have finished between our first look and the lock.
    if (m.adoptStored(e, t)) return;
    m.issue(e, t);
}

/// Install the stored certificate when it is usable and newer than the
/// current one; true when nothing more is needed now.
fn adoptStored(m: *Manager, e: *Entry, t: i64) bool {
    const blob = m.options.storage.load(m.gpa, m.keyOf(e, ".pem").slice()) catch return false;
    defer {
        std.crypto.secureZero(u8, blob);
        m.gpa.free(blob);
    }
    const split = std.mem.indexOf(u8, blob, "-----BEGIN CERTIFICATE-----") orelse return false;
    const leaf = checkPair(m.gpa, e.names, blob[split..], blob[0..split], t, m.options.trust_anchors) catch return false;
    // Newer = issued later (a shorter-lived replacement still counts).
    if (e.cert) |ct| if (leaf.not_before <= ct.not_before) return false;
    const chain_pem = m.gpa.dupe(u8, blob[split..]) catch return false;
    const key_pem = m.gpa.dupe(u8, blob[0..split]) catch {
        m.gpa.free(chain_pem);
        return false;
    };
    m.install(e, .{ .chain_pem = chain_pem, .key_pem = key_pem, .not_before = leaf.not_before, .not_after = leaf.not_after }, t, .storage, null);
    m.mutex.lockUncancelable(m.io);
    defer m.mutex.unlock(m.io);
    return t < e.renew_at;
}

const KeyBuf = struct {
    buf: [storage_mod.max_key_len + 8]u8 = undefined,
    len: usize = 0,
    fn slice(k: *const KeyBuf) []const u8 {
        return k.buf[0..k.len];
    }
};

fn keyOf(m: *const Manager, e: *const Entry, ext: []const u8) KeyBuf {
    _ = m;
    var k: KeyBuf = .{};
    k.len = (std.fmt.bufPrint(&k.buf, "{s}{s}", .{ e.stem, ext }) catch unreachable).len;
    return k;
}

/// Ask the issuers in policy order; the first verified result wins.
fn issue(m: *Manager, e: *Entry, t: i64) void {
    var order_buf: [max_issuers]usize = undefined;
    m.mutex.lockUncancelable(m.io);
    const count = m.issuers.items.len;
    var issuers_buf: [max_issuers]*IssuerSlot = undefined;
    @memcpy(issuers_buf[0..count], m.issuers.items);
    for (order_buf[0..count], 0..) |*o, i| o.* = i;
    if (m.options.issuer_policy == .random) m.prng.random().shuffle(usize, order_buf[0..count]);
    // ARI `replaces`: the certificate being renewed, if any.
    const replaces: ?[]u8 = if (e.cert) |ct| (x509.ariCertIdFromPem(m.gpa, ct.chain_pem) catch null) else null;
    m.mutex.unlock(m.io);
    defer if (replaces) |r| m.gpa.free(r);

    var d: Diagnostics = .{};
    if (count == 0) d.note("no issuer configured");
    // The longest Retry-After any issuer asked for: a rate-limited first CA
    // must not be lost behind a second one's plain failure.
    var retry_after: ?u64 = null;
    for (order_buf[0..count]) |idx| {
        const slot = issuers_buf[idx];
        const iss = slot.issuer;
        d = .{};
        const req: IssueRequest = .{ .names = e.names, .replaces = if (m.options.use_ari) replaces else null };
        slot.lock.lockUncancelable(m.io);
        const result = iss.issue(iss.ctx, m.gpa, &req, &d);
        slot.lock.unlock(m.io);
        var got = result catch {
            if (d.retry_after_s) |ra| retry_after = @max(retry_after orelse 0, ra);
            continue;
        };
        const leaf = checkPair(m.gpa, e.names, got.chain_pem, got.key_pem, t, m.options.trust_anchors) catch |err| {
            d.note(switch (err) {
                error.KeyMismatch => "issued certificate does not match its key",
                error.NameNotCovered => "issued certificate does not cover every name",
                error.Expired => "issued certificate is not valid now",
                else => "issued chain does not verify",
            });
            freeIssued(m.gpa, &got);
            continue;
        };
        m.mutex.lockUncancelable(m.io);
        const removed = e.removed;
        m.mutex.unlock(m.io);
        if (removed) {
            // `unmanage`d meanwhile: neither stored nor reported.
            freeIssued(m.gpa, &got);
            return;
        }
        // Key and chain in one value, one atomic write (autocert's layout):
        // a crash can never leave a new key beside an old certificate. A
        // storage failure does not stop serving what was just issued, but it
        // is reported: the next start would have to order again.
        const stored = m.storePair(e, got.key_pem, got.chain_pem);
        m.install(e, .{ .chain_pem = got.chain_pem, .key_pem = got.key_pem, .not_before = leaf.not_before, .not_after = leaf.not_after }, t, .issued, iss.name);
        if (!stored) m.emit(&.{ .storage_failed = .{ .names = namesView(e) } });
        return;
    }
    if (retry_after) |ra| d.retry_after_s = @max(d.retry_after_s orelse 0, ra);
    m.failed(e, t, &d, "issuance failed");
}

fn storePair(m: *Manager, e: *const Entry, key_pem: []const u8, chain_pem: []const u8) bool {
    const blob = std.mem.concat(m.gpa, u8, &.{ key_pem, "\n", chain_pem }) catch return false;
    defer {
        std.crypto.secureZero(u8, blob);
        m.gpa.free(blob);
    }
    m.options.storage.store(m.keyOf(e, ".pem").slice(), blob) catch return false;
    return true;
}

fn freeIssued(gpa: Allocator, got: *Issued) void {
    std.crypto.secureZero(u8, got.key_pem);
    got.deinit(gpa);
}

/// Make `ct` (ownership taken) current and reschedule, then report it.
fn install(m: *Manager, e: *Entry, ct: Cert, t: i64, source: Event.Source, issuer: ?[]const u8) void {
    var has_ari = false;
    m.mutex.lockUncancelable(m.io);
    if (m.options.use_ari) for (m.issuers.items) |slot| {
        if (slot.issuer.renewal_window != null) has_ari = true;
    };
    if (e.cert) |*old| old.deinit(m.gpa);
    e.cert = ct;
    e.renew_at = ratioRenewAt(ct.not_before, ct.not_after, m.options.renewal_window_pct);
    e.ari_at = if (has_ari) t else null;
    e.ari_start = 0;
    e.ari_end = 0;
    e.failures = 0;
    e.retry_at = 0;
    m.mutex.unlock(m.io);
    // The entry is busy, so `e.cert` cannot change under the hook.
    m.emit(&.{ .installed = .{
        .names = namesView(e),
        .chain_pem = ct.chain_pem,
        .key_pem = ct.key_pem,
        .not_after = ct.not_after,
        .source = source,
        .issuer = issuer,
    } });
}

fn namesView(e: *const Entry) []const []const u8 {
    return @ptrCast(e.names);
}

/// When `pct` percent of the lifetime remains; for `pct` 0, two thirds into
/// the lifetime, half for ten days or less.
fn ratioRenewAt(not_before: i64, not_after: i64, pct: u8) i64 {
    const life = @max(not_after - not_before, 0);
    if (pct >= 1 and pct <= 99) return not_after - @divFloor(life * pct, 100);
    if (life <= 10 * std.time.s_per_day) return not_before + @divFloor(life, 2);
    return not_before + @divFloor(life * 2, 3);
}

/// Back-off after `failures` failures: 1 min doubling, capped.
fn backoffS(failures: u32, cap: u32) i64 {
    const shift: u6 = @intCast(@min(failures -| 1, 20));
    return @min(@as(i64, 60) << shift, cap);
}

fn failed(m: *Manager, e: *Entry, t: i64, d: *const Diagnostics, fallback: []const u8) void {
    m.mutex.lockUncancelable(m.io);
    e.failures +|= 1;
    var wait = backoffS(e.failures, m.options.max_backoff_s);
    if (e.on_demand and e.cert == null) if (m.options.on_demand) |od| {
        wait = @max(wait, od.failure_backoff_s);
    };
    if (d.retry_after_s) |ra| wait = @max(wait, @as(i64, @intCast(@min(ra, 365 * std.time.s_per_day))));
    e.retry_at = t + wait;
    // A valid certificate is retried before it expires, whatever the CA's
    // Retry-After said.
    if (e.cert) |ct| e.retry_at = @min(e.retry_at, @max(t + 60, ct.not_after - 3600));
    const retry_at = e.retry_at;
    m.mutex.unlock(m.io);
    m.emit(&.{ .failed = .{
        .names = namesView(e),
        .problem = if (d.problem_len != 0) d.problem() else fallback,
        .retry_at = retry_at,
    } });
}

/// Refresh the ARI window (the entry has a certificate and is not due for
/// renewal). The first issuer that answers decides.
fn pollAri(m: *Manager, e: *Entry, t: i64) void {
    var issuers_buf: [max_issuers]*IssuerSlot = undefined;
    m.mutex.lockUncancelable(m.io);
    const count = m.issuers.items.len;
    @memcpy(issuers_buf[0..count], m.issuers.items);
    m.mutex.unlock(m.io);

    const ct = e.cert.?; // busy: stable
    var unsupported = true;
    for (issuers_buf[0..count]) |slot| {
        const iss = slot.issuer;
        const window_fn = iss.renewal_window orelse continue;
        var d: Diagnostics = .{};
        slot.lock.lockUncancelable(m.io);
        const result = window_fn(iss.ctx, ct.chain_pem, &d);
        slot.lock.unlock(m.io);
        const w = result catch |err| {
            if (err != error.NotSupported) unsupported = false;
            continue;
        };
        m.mutex.lockUncancelable(m.io);
        defer m.mutex.unlock(m.io);
        if (w.start != e.ari_start or w.end != e.ari_end) {
            // RFC 9773 §4.2: a random time inside the window, kept until the
            // window moves. Never past the certificate's own end, and never
            // before a tenth of its lifetime: a CA answering a past window
            // for every new certificate would otherwise get an order per
            // `maintain` round (an incident window for an OLD certificate
            // is past that floor and still renews at once).
            e.ari_start = w.start;
            e.ari_end = w.end;
            const info: Client.RenewalInfo = .{ .window_start = w.start, .window_end = w.end, .explanation_url = null, .retry_after_s = null };
            const floor = ct.not_before + @divFloor(@max(ct.not_after - ct.not_before, 0), 10);
            e.renew_at = std.math.clamp(info.pickTime(m.prng.random()), floor, @max(floor, ct.not_after - 3600));
        }
        const poll: i64 = if (w.retry_after_s) |ra| @intCast(@min(ra, 7 * std.time.s_per_day)) else m.options.ari_poll_s;
        e.ari_at = t + @max(poll, 60);
        return;
    }
    m.mutex.lockUncancelable(m.io);
    defer m.mutex.unlock(m.io);
    e.ari_at = if (unsupported) null else t + m.options.ari_poll_s;
}

fn emit(m: *Manager, event: *const Event) void {
    const hook = m.options.on_event orelse return;
    hook.call(hook.ctx, event);
}

// ── serving ─────────────────────────────────────────────────────────────────

/// The current certificate for a TLS ClientHello's SNI (exact name first,
/// then a single-label wildcard), as a copy the caller frees; null when
/// there is none. An empty `sni` means `Options.default_server_name`.
/// With `Options.on_demand`, an unmanaged name the policy allows is
/// obtained now — the call then blocks for the issuance, and concurrent
/// calls for the same name wait for the same result. (Two allocations per
/// call; a server with a certificate store of its own installs from
/// `Options.on_event` instead and asks here only for on-demand names.)
pub fn certificate(m: *Manager, gpa: Allocator, sni: []const u8) error{OutOfMemory}!?Material {
    var lower_buf: [253]u8 = undefined;
    const want = if (sni.len == 0) m.options.default_server_name orelse return null else sni;
    if (want.len == 0 or want.len > lower_buf.len) return null;
    const name = std.ascii.lowerString(&lower_buf, std.mem.trimEnd(u8, want, "."));
    // Only a hostname is looked up (no `.example.com`, no `*.example.com`).
    if (!x509.isValidDomain(name)) return null;
    const t = m.now(); // the caller's clock, read outside the lock

    m.mutex.lockUncancelable(m.io);
    while (m.lookup(name)) |e| {
        if (e.cert) |ct| {
            defer m.mutex.unlock(m.io);
            return try copyMaterial(gpa, ct);
        }
        // Another handshake is obtaining this on-demand name: wait for
        // that result. A `manage`d name's first issuance (which may take
        // minutes) is not waited for — the handshake gets nothing.
        if (e.busy and e.on_demand) {
            m.idle.waitUncancelable(m.io, &m.mutex);
            continue;
        }
        if (e.on_demand and !e.busy and t >= e.retry_at) {
            // A failed on-demand name whose back-off is over: forget it and
            // go through the policy and the rate limit like a new name.
            m.dropEntryLocked(e);
            break;
        }
        m.mutex.unlock(m.io);
        return null;
    }
    m.mutex.unlock(m.io);

    const od = m.options.on_demand orelse return null;
    if (!od.allow(od.ctx, name)) return null;

    m.mutex.lockUncancelable(m.io);
    const allowed = m.limiter.take(t, od.rate);
    m.mutex.unlock(m.io);
    if (!allowed) return null;

    // Created busy (see `addEntry`): ours alone until onDemandObtain ends.
    const e = m.addEntry(&.{name}, true) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // Another handshake added it meanwhile: serve (or wait for) that.
        error.AlreadyManaged => return m.certificate(gpa, name),
        error.InvalidName => return null,
    };
    return m.onDemandObtain(gpa, e);
}

fn onDemandObtain(m: *Manager, gpa: Allocator, e: *Entry) error{OutOfMemory}!?Material {
    m.obtain(e, m.now());
    m.mutex.lockUncancelable(m.io);
    defer m.mutex.unlock(m.io);
    const result: ?Material = if (e.cert) |ct| copyMaterial(gpa, ct) catch null else null;
    e.busy = false;
    if (e.removed) m.freeEntry(e);
    m.idle.broadcast(m.io);
    return result;
}

fn copyMaterial(gpa: Allocator, ct: Cert) error{OutOfMemory}!Material {
    const chain = try gpa.dupe(u8, ct.chain_pem);
    errdefer gpa.free(chain);
    const key = try gpa.dupe(u8, ct.key_pem);
    return .{ .chain_pem = chain, .key_pem = key, .not_after = ct.not_after };
}

/// Exact name, then `*.` + parent (one label only). Lock held.
fn lookup(m: *Manager, name: []const u8) ?*Entry {
    if (m.by_name.get(name)) |e| return e;
    const dot = std.mem.indexOfScalar(u8, name, '.') orelse return null;
    var buf: [255]u8 = undefined;
    if (name.len - dot + 1 > buf.len) return null;
    const wild = std.fmt.bufPrint(&buf, "*{s}", .{name[dot..]}) catch return null;
    return m.by_name.get(wild);
}

/// The TLS-ALPN-01 validation certificate for `sni` while a challenge is in
/// flight (serve it when the ClientHello offers ALPN `acme-tls/1`), else
/// null. With `distributed_challenges`, another node's challenge is found
/// in storage. Caller frees.
pub fn tlsAlpnMaterial(m: *Manager, gpa: Allocator, sni_in: []const u8) error{OutOfMemory}!?Client.TlsAlpnResponder.Material {
    var lower_buf: [253]u8 = undefined;
    const trimmed = std.mem.trimEnd(u8, sni_in, ".");
    if (trimmed.len == 0 or trimmed.len > lower_buf.len) return null;
    const sni = std.ascii.lowerString(&lower_buf, trimmed);
    if (try m.tls_alpn.getMaterial(gpa, sni)) |mat| return mat;
    if (!m.options.distributed_challenges) return null;
    // Every handshake can reach this: only a hostname (reverse names for IPs
    // are hostnames too) costs a storage read.
    if (!x509.isValidDomain(sni)) return null;
    var key_buf: [storage_mod.max_key_len]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "challenges/tls-alpn-01/{s}", .{sni}) catch return null;
    const blob = m.options.storage.load(gpa, key) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    defer {
        std.crypto.secureZero(u8, blob);
        gpa.free(blob);
    }
    const cert_der = x509.pemDecode(gpa, "CERTIFICATE", blob) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    errdefer gpa.free(cert_der);
    const at = std.mem.indexOf(u8, blob, "-----BEGIN EC PRIVATE KEY-----") orelse {
        gpa.free(cert_der);
        return null;
    };
    const key_pem = try gpa.dupe(u8, blob[at..]);
    return .{ .cert_der = cert_der, .key_pem = key_pem };
}

/// The HTTP-01 responder (+ the optional HTTPS redirect), as `router`
/// middleware for the port-80 server.
pub fn httpMiddleware(m: *Manager) router.Middleware {
    return .{ .state = m, .run = httpRun };
}

fn httpRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const m: *Manager = @ptrCast(@alignCast(state.?));
    const req = ctx.req;
    const get_or_head = req.method == .get or req.method == .head;
    const prefix = Client.Responder.path_prefix;
    if (get_or_head and std.mem.startsWith(u8, req.path, prefix)) {
        const token = req.path[prefix.len..];
        var buf: [jws.max_key_authorization_len]u8 = undefined;
        if (try m.httpKeyAuthorization(token, &buf)) |ka| {
            ctx.res.setStatus(200);
            try ctx.res.setHeader("Content-Type", "application/octet-stream");
            return ctx.res.writeAll(ka);
        }
        ctx.res.setStatus(404);
        try ctx.res.setHeader("Content-Type", "text/plain");
        return ctx.res.writeAll("unknown ACME challenge token\n");
    }
    if (!m.options.http_redirect) return next.run(ctx);
    if (!get_or_head) {
        ctx.res.setStatus(400);
        try ctx.res.setHeader("Content-Type", "text/plain");
        return ctx.res.writeAll("Use HTTPS\n");
    }
    // Host without the port (autocert does the same): the HTTPS listener
    // is on 443.
    const host_hdr = req.header("host") orelse "";
    const host = hostOnly(host_hdr);
    if (host.len == 0 or !validRedirectHost(host)) {
        ctx.res.setStatus(400);
        try ctx.res.setHeader("Content-Type", "text/plain");
        return ctx.res.writeAll("missing or invalid Host\n");
    }
    var loc_buf: [2048]u8 = undefined;
    const target = if (req.target.len > 0 and req.target[0] == '/') req.target else "/";
    for (target) |ch| if (ch < 0x21 or ch > 0x7e) {
        ctx.res.setStatus(400);
        return;
    };
    const location = std.fmt.bufPrint(&loc_buf, "https://{s}{s}", .{ host, target }) catch {
        ctx.res.setStatus(414);
        return;
    };
    ctx.res.setStatus(302);
    try ctx.res.setHeader("Location", location);
}

fn hostOnly(h: []const u8) []const u8 {
    if (h.len > 0 and h[0] == '[') { // [v6]:port
        const close = std.mem.indexOfScalar(u8, h, ']') orelse return "";
        return h[0 .. close + 1];
    }
    const colon = std.mem.lastIndexOfScalar(u8, h, ':') orelse return h;
    return h[0..colon];
}

/// No header splitting or open redirects through a crafted Host.
fn validRedirectHost(h: []const u8) bool {
    for (h) |ch| switch (ch) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '-', '[', ']', ':' => {},
        else => return false,
    };
    return true;
}

fn httpKeyAuthorization(m: *Manager, token: []const u8, buf: []u8) error{OutOfMemory}!?[]const u8 {
    // RFC 8555 §8.1: a token is base64url, at least 128 bits; anything else
    // is not looked up (and never costs a storage read).
    if (token.len == 0 or token.len > 256) return null;
    for (token) |ch| if (!(std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_')) return null;
    if (m.http_tokens.lookup(token, buf)) |ka| return ka;
    if (!m.options.distributed_challenges) return null;
    var key_buf: [storage_mod.max_key_len]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "challenges/http-01/{s}", .{token}) catch return null;
    const v = m.options.storage.load(m.gpa, key) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    defer m.gpa.free(v);
    if (v.len > buf.len) return null;
    @memcpy(buf[0..v.len], v);
    return buf[0..v.len];
}

// ── the solvers ─────────────────────────────────────────────────────────────

fn managerOf(ctx: ?*anyopaque) *Manager {
    return @ptrCast(@alignCast(ctx.?));
}

fn presentHttp01(ctx: ?*anyopaque, req: *const Client.ChallengeRequest) Client.SolverError!void {
    const m = managerOf(ctx);
    try m.http_tokens.set(req.token, req.key_authorization);
    if (!m.options.distributed_challenges) return;
    var key_buf: [storage_mod.max_key_len]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "challenges/http-01/{s}", .{req.token}) catch return error.SolverFailed;
    m.options.storage.store(key, req.key_authorization) catch |err| {
        m.http_tokens.remove(req.token);
        return if (err == error.OutOfMemory) error.OutOfMemory else error.SolverFailed;
    };
}

fn cleanupHttp01(ctx: ?*anyopaque, req: *const Client.ChallengeRequest) void {
    const m = managerOf(ctx);
    m.http_tokens.remove(req.token);
    if (!m.options.distributed_challenges) return;
    var key_buf: [storage_mod.max_key_len]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "challenges/http-01/{s}", .{req.token}) catch return;
    m.options.storage.delete(key) catch {};
}

fn presentTlsAlpn01(ctx: ?*anyopaque, req: *const Client.ChallengeRequest) Client.SolverError!void {
    const m = managerOf(ctx);
    var material = try Client.tlsAlpnValidation(m.io, m.gpa, req);
    defer material.deinit(m.gpa);
    var sni_buf: [Client.max_reverse_name_len]u8 = undefined;
    const sni = req.tlsAlpnSni(&sni_buf);
    try m.tls_alpn.set(sni, material.cert_der, material.key_pem);
    if (!m.options.distributed_challenges) return;
    errdefer m.tls_alpn.remove(sni);
    const cert_pem = try x509.pemEncode(m.gpa, "CERTIFICATE", material.cert_der);
    defer m.gpa.free(cert_pem);
    const blob = try std.mem.concat(m.gpa, u8, &.{ cert_pem, material.key_pem });
    defer {
        std.crypto.secureZero(u8, blob);
        m.gpa.free(blob);
    }
    var key_buf: [storage_mod.max_key_len]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "challenges/tls-alpn-01/{s}", .{sni}) catch return error.SolverFailed;
    m.options.storage.store(key, blob) catch |err|
        return if (err == error.OutOfMemory) error.OutOfMemory else error.SolverFailed;
}

fn cleanupTlsAlpn01(ctx: ?*anyopaque, req: *const Client.ChallengeRequest) void {
    const m = managerOf(ctx);
    var sni_buf: [Client.max_reverse_name_len]u8 = undefined;
    const sni = req.tlsAlpnSni(&sni_buf);
    m.tls_alpn.remove(sni);
    if (!m.options.distributed_challenges) return;
    var key_buf: [storage_mod.max_key_len]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "challenges/tls-alpn-01/{s}", .{sni}) catch return;
    m.options.storage.delete(key) catch {};
}

// ── checking a certificate before it is served ──────────────────────────────

pub const CheckError = error{
    OutOfMemory,
    /// The PEM holds no certificate, or a certificate does not parse.
    MalformedChain,
    /// The chain does not verify to the anchors (signature, CA flags, EKU).
    Untrusted,
    /// Outside its validity window at the time of the check.
    Expired,
    /// A managed name is not in the leaf's subjectAltName.
    NameNotCovered,
    /// The key PEM does not parse, or is not the leaf's key.
    KeyMismatch,
};

pub const LeafValidity = struct { not_before: i64, not_after: i64 };

/// The checks a certificate passes before a `Manager` stores or serves it:
/// `chain_pem` (leaf first) verifies under RFC 5280 at time `t` to
/// `trust_anchors` (DER; empty: the chain's topmost certificate), with the
/// serverAuth purpose; every one of `names` is covered by the leaf; and
/// `key_pem` (EC or RSA) is the leaf's key.
pub fn checkPair(
    gpa: Allocator,
    names: []const []const u8,
    chain_pem: []const u8,
    key_pem: []const u8,
    t: i64,
    trust_anchors: []const []const u8,
) CheckError!LeafValidity {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const chain = try splitPemChain(arena, chain_pem);
    if (chain.len == 0) return error.MalformedChain;
    const leaf = chain[0];
    const validity = pkix.chain.certValidity(leaf) catch return error.MalformedChain;
    const nb: i64 = @intCast(validity.not_before);
    const na: i64 = @intCast(validity.not_after);
    if (t >= na) return error.Expired;

    // A fresh certificate may start a little in the future (clock skew; CAs
    // backdate, not all of them): judge the chain from its own start then.
    const anchors: []const []const u8 = if (trust_anchors.len != 0) trust_anchors else chain[chain.len - 1 ..];
    var verified = pkix.verifyChain(arena, chain, anchors, .{
        .now_sec = @max(t, nb),
        .required_eku = .server_auth,
    }) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Untrusted,
    };
    _ = &verified;

    for (names) |name| {
        if (netaddr.parseIp(name) == null and !x509.isValidDomain(name) and !x509.isValidWildcardDomain(name))
            return error.NameNotCovered;
        if (!leafCovers(leaf, name)) return error.NameNotCovered;
    }
    try checkKey(gpa, leaf, key_pem);
    return .{ .not_before = nb, .not_after = na };
}

/// Every CERTIFICATE block of a PEM text, decoded (arena-owned).
fn splitPemChain(arena: Allocator, text: []const u8) CheckError![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    const end_marker = "-----END CERTIFICATE-----";
    var rest = text;
    while (std.mem.indexOf(u8, rest, "-----BEGIN CERTIFICATE-----")) |begin| {
        const end_rel = std.mem.indexOf(u8, rest[begin..], end_marker) orelse return error.MalformedChain;
        const block = rest[begin .. begin + end_rel + end_marker.len];
        const der = x509.pemDecode(arena, "CERTIFICATE", block) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.MalformedChain,
        };
        try list.append(arena, der);
        rest = rest[begin + end_rel + end_marker.len ..];
    }
    return list.items;
}

/// Does the leaf's SAN cover `name`? A plain name may be covered by an exact
/// entry or a wildcard; a wildcard name only by the same literal wildcard
/// (`hostname.verify` compares a host that is not a valid hostname — `*.x`
/// is not — byte for byte, case-insensitively).
fn leafCovers(leaf: []const u8, name: []const u8) bool {
    pkix.hostname.verify(leaf, name) catch return false;
    return true;
}

fn checkKey(gpa: Allocator, leaf: []const u8, key_pem: []const u8) CheckError!void {
    const spki = pkix.spkiOf(leaf) catch return error.MalformedChain;
    if (std.mem.indexOf(u8, key_pem, "-----BEGIN RSA PRIVATE KEY-----") != null) return checkRsaKey(gpa, spki.der, key_pem);
    var pair: jws.AnyKeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
    x509.privateKeyFromPem(&pair, gpa, key_pem) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // A PKCS#8 `PRIVATE KEY` may hold an RSA key.
        else => return checkRsaKey(gpa, spki.der, key_pem),
    };
    var sec1_buf: [jws.AnyPublicKey.max_sec1_len]u8 = undefined;
    const sec1 = pair.publicKey().uncompressedSec1(&sec1_buf);
    if (!std.mem.eql(u8, sec1, spki.key_bits)) return error.KeyMismatch;
}

/// `key_pem` (PKCS#1 or PKCS#8) is the RSA key of the SPKI `spki_der`.
fn checkRsaKey(gpa: Allocator, spki_der: []const u8, key_pem: []const u8) CheckError!void {
    const kp = try gpa.create(rsa.KeyPair);
    defer {
        std.crypto.secureZero(u8, std.mem.asBytes(kp));
        gpa.destroy(kp);
    }
    x509.rsaPrivateKeyFromPem(kp, key_pem) catch return error.KeyMismatch;
    const cert_pub = rsa.PublicKey.fromDer(spki_der) catch return error.KeyMismatch;
    if (!rsaPublicEql(&cert_pub, &kp.public_key)) return error.KeyMismatch;
}

fn rsaPublicEql(a: *const rsa.PublicKey, b: *const rsa.PublicKey) bool {
    var ab: [rsa.max_modulus_len]u8 = undefined;
    var bb: [rsa.max_modulus_len]u8 = undefined;
    const al = a.n.bits();
    if (al != b.n.bits()) return false;
    const len = (al + 7) / 8;
    a.n.toBytes(ab[0..len], .big) catch return false;
    b.n.toBytes(bb[0..len], .big) catch return false;
    if (!std.mem.eql(u8, ab[0..len], bb[0..len])) return false;
    const ae = a.e.toPrimitive(u32) catch return false;
    const be = b.e.toPrimitive(u32) catch return false;
    return ae == be;
}

// ── account keys ────────────────────────────────────────────────────────────

/// The storage key of an issuer's account key: `accounts/<issuer>/account.key`.
pub fn accountKeyPath(buf: *[storage_mod.max_key_len]u8, issuer_name: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "accounts/{s}/account.key", .{issuer_name}) catch buf[0..0];
}

pub const AccountKeyError = error{ OutOfMemory, InvalidKey, StorageFailed, MalformedKey, UnsupportedKeyType };

/// The account key for `issuer_name` from `storage`, or a fresh one of `alg`
/// (ES256/ES384/ES512) generated and stored (autocert keeps its account key
/// in the cache the same way). The account key IS the ACME account: losing
/// it means a new account. `out` is written in place; wipe it when done.
pub fn loadOrCreateAccountKey(
    out: *jws.AnyKeyPair,
    io: std.Io,
    gpa: Allocator,
    store: Storage,
    issuer_name: []const u8,
    alg: jws.Alg,
) AccountKeyError!void {
    if (alg == .rs256) return error.UnsupportedKeyType;
    var path_buf: [storage_mod.max_key_len]u8 = undefined;
    const path = accountKeyPath(&path_buf, issuer_name);
    if (store.load(gpa, path)) |pem| {
        defer {
            std.crypto.secureZero(u8, pem);
            gpa.free(pem);
        }
        x509.privateKeyFromPem(out, gpa, pem) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.MalformedKey,
        };
        return;
    } else |err| switch (err) {
        error.NotFound => {},
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidKey => return error.InvalidKey,
        error.StorageFailed => return error.StorageFailed,
    }
    jws.generateAnyKeyPair(out, alg, io);
    const pem = try x509.ecPrivateKeyToPem(gpa, out);
    defer {
        std.crypto.secureZero(u8, pem);
        gpa.free(pem);
    }
    store.store(path, pem) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidKey => error.InvalidKey,
        else => error.StorageFailed,
    };
}

/// A storage-safe issuer name from a directory URL: the host and path with
/// every character outside `[A-Za-z0-9.-]` replaced by `-` (CertMagic keys
/// its storage the same way), e.g.
/// `acme-v02.api.letsencrypt.org-directory`.
pub fn issuerName(buf: *[128]u8, directory_url: []const u8) []const u8 {
    var s = directory_url;
    if (std.mem.indexOf(u8, s, "://")) |i| s = s[i + 3 ..];
    s = std.mem.trim(u8, s, "/");
    const n = @min(s.len, buf.len);
    for (s[0..n], buf[0..n]) |ch, *o| o.* = if (std.ascii.isAlphanumeric(ch) or ch == '.' or ch == '-') ch else '-';
    if (n == 0) {
        buf[0] = '-';
        return buf[0..1];
    }
    return buf[0..n];
}

// ── the ACME issuer ─────────────────────────────────────────────────────────

/// An `Issuer` over a `Client`. The client must use the manager's
/// `challengeSolvers()` for HTTP-01 / TLS-ALPN-01 (or a DNS-01 publisher).
/// Not movable once `issuer()` was taken.
pub const AcmeIssuer = struct {
    client: *Client,
    /// Storage-safe name (`issuerName` of the directory URL is customary).
    name: []const u8,
    /// Per-order options (profile, preferred chain, CSR extensions);
    /// `replaces` is filled per renewal.
    obtain: Client.ObtainOptions = .{},

    pub fn issuer(a: *AcmeIssuer) Issuer {
        return .{ .ctx = a, .name = a.name, .issue = issueFn, .renewal_window = windowFn };
    }

    fn of(ctx: *anyopaque) *AcmeIssuer {
        return @ptrCast(@alignCast(ctx));
    }

    fn issueFn(ctx: *anyopaque, gpa: Allocator, req: *const IssueRequest, diag: *Diagnostics) IssueError!Issued {
        const a = of(ctx);
        var opts = a.obtain;
        opts.replaces = req.replaces;
        var cert = a.client.obtainWith(req.names, opts) catch |err| retry: {
            // A CA may refuse `replaces` (already replaced, another
            // account's certificate): order once more without it.
            if (req.replaces != null and err == error.AcmeProblem) {
                opts.replaces = null;
                break :retry a.client.obtainWith(req.names, opts) catch |err2| return a.fail(diag, err2);
            }
            return a.fail(diag, err);
        };
        defer freeIssued(a.client.gpa, &cert);
        // Hand back memory of the manager's allocator, whatever the client's is.
        const chain = try gpa.dupe(u8, cert.chain_pem);
        errdefer gpa.free(chain);
        const key = try gpa.dupe(u8, cert.key_pem);
        return .{ .chain_pem = chain, .key_pem = key, .not_after = cert.not_after };
    }

    fn fail(a: *AcmeIssuer, diag: *Diagnostics, err: Client.Error) IssueError {
        diag.note(a.client.lastProblem() orelse @errorName(err));
        diag.retry_after_s = a.client.retryAfter();
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.RateLimited => error.RateLimited,
            else => error.IssueFailed,
        };
    }

    fn windowFn(ctx: *anyopaque, chain_pem: []const u8, diag: *Diagnostics) IssueError!Window {
        const a = of(ctx);
        var info = a.client.renewalInfoPem(chain_pem) catch |err| switch (err) {
            error.NotSupported => return error.NotSupported,
            else => return a.fail(diag, err),
        };
        defer info.deinit(a.client.gpa);
        return .{ .start = info.window_start, .end = info.window_end, .retry_after_s = info.retry_after_s };
    }
};

// ── on-demand rate limiter ──────────────────────────────────────────────────

/// At most `max` events per sliding `window_s` (a ring of timestamps).
const RateLimiter = struct {
    ring: [256]i64 = @splat(std.math.minInt(i64)),
    next: u16 = 0,

    fn take(r: *RateLimiter, t: i64, rate: RateLimit) bool {
        const max = @min(rate.max, r.ring.len);
        if (max == 0) return false;
        // The slot we would overwrite holds the max-th most recent event.
        const slot = r.next % max;
        if (r.ring[slot] != std.math.minInt(i64) and t - r.ring[slot] < rate.window_s) return false;
        r.ring[slot] = t;
        r.next = @intCast((slot + 1) % max);
        return true;
    }
};
