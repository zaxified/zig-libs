// SPDX-License-Identifier: MIT

//! Stateless sessions: the whole session lives in the cookie, sealed with
//! `cookies.private` (AES-256-GCM, the default) or signed with
//! `cookies.signed` (HMAC-SHA256, readable by the client). The server keeps no
//! state: gorilla/sessions `CookieStore`, Rails `CookieStore`, Flask's default
//! session, express `cookie-session`.
//!
//! `CookieManager` is the stateless sibling of `Manager`. It fills the same
//! `Session`, attaches it the same way (`sessionOf(ctx)`), and the handler API
//! is the same: `putValue`/`getValue`/`popValue`, `setData`, `keep`,
//! `rememberMe`, `revoke`, plus `CookieManager.regenerate`.
//!
//! ## Cookie value
//!
//! The plaintext is `[version 1][created u64 LE, bit 63 = remember]
//! [last_seen i64 LE][id_len u8][raw id][data]`.
//! - `.encrypted` seals it with `cookies.private.seal` under the cookie name.
//! - `.signed` writes base64url (no padding) of it and signs that with
//!   `cookies.signed.sign` (`.bound`: the MAC covers the cookie name).
//!
//! `keys[0]` seals and signs; every key in `keys` opens and verifies, which is
//! how a key is rotated.
//!
//! ## What a cookie store cannot do (gorilla, Rails, Flask alike)
//!
//! - **No server-side revocation.** `revoke` clears the browser's cookie.
//!   A copy of the old value, kept by an attacker or replayed by the client,
//!   still opens until its idle or absolute timeout (both are inside the
//!   sealed value, so they cannot be extended). Keep the timeouts short, or
//!   use `Manager` with a store when a logout must end the session everywhere.
//! - **Rollback.** A client may present an older value of its own cookie,
//!   e.g. one from before a flash message was popped. Do not keep
//!   anything in it whose reuse matters (a one-time nonce, a balance).
//! - **Last writer wins.** Two concurrent requests each send back their own
//!   cookie. There is no CAS, and no `Manager.iterate`.
//! - **Size.** The data must fit one cookie. `dataLimit()` says how much fits.
//!   `setData`/`putValue` refuse more with `error.Overflow` while the handler
//!   runs, not later at save time.
//!
//! ## Clock
//!
//! The timestamps sit in the browser and outlive the process, so the clock
//! must be wall time: `init` refuses `Clock.monotonic`, as `Manager` does for
//! a persistent store.

const std = @import("std");
const router = @import("router");
const http = @import("http");
const cookies = @import("cookies");
const entropy = @import("entropy");

const root = @import("root.zig");
const common = @import("common.zig");
const idhex = @import("idhex.zig");

const Session = root.Session;
const Clock = root.Clock;

/// How the session is protected in the cookie.
pub const CookieMode = enum {
    /// AES-256-GCM (`cookies.private`): the client cannot read or change it.
    encrypted,
    /// HMAC-SHA256 (`cookies.signed`, `.bound`): the client can read the
    /// session (base64url) but cannot change it. Never put a secret in it.
    signed,
};

/// Plaintext header: version, created word, last_seen, id length.
const header_len = 1 + 8 + 8 + 1;
const format_version: u8 = 1;
const plain_max = header_len + root.max_id_bytes + root.max_session_bytes;

/// The largest Set-Cookie line `CookieManager` writes: `cookies`' own bound,
/// which is also `http`'s header copy budget for a whole response.
pub const max_cookie_line = cookies.max_set_cookie_bytes;

/// Default `CookieOptions.max_cookie_bytes`. Below `max_cookie_line` on
/// purpose: the response's other headers (a CSRF cookie, a CSP) share the
/// same 4 KiB budget in `http`, and a session cookie that does not fit there
/// is lost.
pub const default_max_cookie_bytes = 3072;

/// Longest hex session id `CookieManager.sessionId` writes.
pub const session_id_max = 2 * root.max_id_bytes;

/// Longest cookie value `load` looks at (the cookie bound minus "n=").
const max_value_len = max_cookie_line - 2;

pub const CookieOptions = struct {
    /// CSPRNG for session ids and AEAD nonces.
    io: std.Io,
    /// `keys[0]` seals or signs, every key opens or verifies (rotation:
    /// put the new key first, keep the old one until its cookies expired).
    /// Borrowed: the slice must outlive the manager. Generate keys with
    /// `cookies.Key.generateInto` or derive them with `deriveInto`.
    keys: []const cookies.Key,
    mode: CookieMode = .encrypted,
    /// Wall clock (ns since the epoch). `Clock.monotonic` is refused.
    clock: Clock = .realtime,
    /// Raw session-id length, for `Csrf` binding and `regenerate`. Same
    /// bounds as `Options.id_bytes`. 16 by default: the id travels inside
    /// the cookie, which an attacker cannot forge, so it only has to be
    /// unique, and a shorter id leaves room for data.
    id_bytes: usize = root.min_id_bytes,
    idle_timeout_ns: i64 = root.default_idle_timeout_ns,
    absolute_timeout_ns: i64 = root.default_absolute_timeout_ns,
    cookie_name: []const u8 = root.default_cookie_name,
    cookie_path: ?[]const u8 = "/",
    cookie_domain: ?[]const u8 = null,
    same_site: cookies.SameSite = .lax,
    secure: bool = true,
    allow_insecure_cookie: bool = false,
    /// As `Options.persist_untouched_sessions`.
    persist_untouched_sessions: bool = false,
    /// As `Options.persist_cookie`.
    persist_cookie: bool = true,
    /// Longest Set-Cookie line (name, value and attributes), at most
    /// `max_cookie_line`. Decides `dataLimit()`.
    max_cookie_bytes: usize = default_max_cookie_bytes,
};

/// Stateless session manager. Immutable once built; share it across threads.
pub const CookieManager = struct {
    io: std.Io,
    keys: []const cookies.Key,
    mode: CookieMode,
    clock: Clock,
    id_bytes: usize,
    idle_timeout_ns: i64,
    absolute_timeout_ns: i64,
    cookie_name: []const u8,
    cookie_path: ?[]const u8,
    cookie_domain: ?[]const u8,
    same_site: cookies.SameSite,
    secure: bool,
    persist_untouched_sessions: bool,
    persist_cookie: bool,
    max_cookie_bytes: usize,
    /// Longest cookie value that keeps the line within `max_cookie_bytes`.
    max_value: usize,
    /// Largest session payload that still fits (`dataLimit`).
    data_limit: usize,

    pub const InitError = error{
        /// `keys` is empty.
        NoKeys,
        /// `id_bytes` outside `[min_id_bytes, max_id_bytes]`.
        InvalidIdBytes,
        EmptyCookieName,
        /// The cookie these options describe cannot be written (a byte a
        /// Set-Cookie may not carry, `SameSite=None` without `Secure`).
        InvalidCookieOptions,
        /// `max_cookie_bytes` above `max_cookie_line`, or too small for the
        /// attributes plus an empty session.
        InvalidCookieSize,
        /// `Clock.monotonic`: its origin resets at reboot, the cookie's
        /// timestamps would not.
        MonotonicClock,
    };

    pub fn init(options: CookieOptions) InitError!CookieManager {
        if (options.keys.len == 0) return error.NoKeys;
        if (options.id_bytes < root.min_id_bytes or options.id_bytes > root.max_id_bytes)
            return error.InvalidIdBytes;
        if (options.cookie_name.len == 0) return error.EmptyCookieName;
        if (options.clock.nowFn == Clock.monotonic.nowFn) return error.MonotonicClock;
        if (options.max_cookie_bytes > max_cookie_line) return error.InvalidCookieSize;
        const secure = options.secure and !options.allow_insecure_cookie;
        // The line without its value, with the longest Max-Age: what the
        // attributes cost. bufPrint also validates every attribute.
        const probe: cookies.SetCookie = .{
            .name = options.cookie_name,
            .value = "",
            .path = options.cookie_path,
            .domain = options.cookie_domain,
            .max_age = std.math.minInt(i64),
            .secure = secure,
            .http_only = true,
            .same_site = options.same_site,
        };
        var probe_buf: [max_cookie_line]u8 = undefined;
        const bare = probe.bufPrint(&probe_buf) catch |err| switch (err) {
            error.BufferTooSmall => return error.InvalidCookieSize,
            else => return error.InvalidCookieOptions,
        };
        if (bare.len >= options.max_cookie_bytes) return error.InvalidCookieSize;
        const max_value = @min(options.max_cookie_bytes - bare.len, max_value_len);
        const fixed = header_len + options.id_bytes;
        const plain_fit = plainFit(options.mode, max_value);
        if (plain_fit < fixed) return error.InvalidCookieSize;
        return .{
            .io = options.io,
            .keys = options.keys,
            .mode = options.mode,
            .clock = options.clock,
            .id_bytes = options.id_bytes,
            .idle_timeout_ns = options.idle_timeout_ns,
            .absolute_timeout_ns = options.absolute_timeout_ns,
            .cookie_name = options.cookie_name,
            .cookie_path = options.cookie_path,
            .cookie_domain = options.cookie_domain,
            .same_site = options.same_site,
            .secure = secure,
            .persist_untouched_sessions = options.persist_untouched_sessions,
            .persist_cookie = options.persist_cookie,
            .max_cookie_bytes = options.max_cookie_bytes,
            .max_value = max_value,
            .data_limit = @min(plain_fit - fixed, root.max_session_bytes),
        };
    }

    /// The largest session payload (`Session.data()`) that fits the cookie.
    pub fn dataLimit(m: *const CookieManager) usize {
        return m.data_limit;
    }

    /// A brand-new session: fresh id, created = last_seen = now, no data.
    pub fn create(m: *const CookieManager, out: *Session) void {
        out.* = .{};
        m.newId(out);
        const now = m.clock.now();
        out.created_ns = now;
        out.last_seen_ns = now;
        out.data_limit = m.data_limit;
    }

    /// Open the session cookie of `req` into `out`. `.expired` = it opened
    /// but is past a timeout; `.absent` = no cookie, or one that does not
    /// open (forged, foreign key, another cookie name, malformed).
    pub fn load(m: *const CookieManager, req: *const http.Server.Request, out: *Session) root.Manager.LoadResult {
        const value = cookies.get(req, m.cookie_name) orelse return .absent;
        return m.open(value, out);
    }

    /// `load` without a request: open a cookie value.
    pub fn open(m: *const CookieManager, value: []const u8, out: *Session) root.Manager.LoadResult {
        var plain_buf: [plain_open_max]u8 = undefined;
        defer std.crypto.secureZero(u8, &plain_buf);
        const plain = m.unseal(value, &plain_buf) orelse return .absent;
        return m.decode(plain, out);
    }

    /// Room for any plaintext a cookie of `max_value_len` can carry.
    const plain_open_max = cookies.private.openBufLen(max_value_len);

    fn unseal(m: *const CookieManager, value: []const u8, buf: *[plain_open_max]u8) ?[]const u8 {
        if (value.len > max_value_len) return null;
        switch (m.mode) {
            .encrypted => return cookies.private.open(m.keys, m.cookie_name, value, buf),
            .signed => {
                const text = cookies.signed.verify(m.keys, m.cookie_name, value, .{}) orelse return null;
                const n = b64.Decoder.calcSizeForSlice(text) catch return null;
                if (n > buf.len) return null;
                b64.Decoder.decode(buf[0..n], text) catch return null;
                return buf[0..n];
            },
        }
    }

    fn decode(m: *const CookieManager, plain: []const u8, out: *Session) root.Manager.LoadResult {
        if (plain.len < header_len or plain[0] != format_version) return .absent;
        const word = common.decodeCreated(std.mem.readInt(u64, plain[1..9], .little));
        const last_seen = std.mem.readInt(i64, plain[9..17], .little);
        const id_len: usize = plain[17];
        if (id_len < root.min_id_bytes or id_len > root.max_id_bytes) return .absent;
        if (plain.len - header_len < id_len) return .absent;
        const payload = plain[header_len + id_len ..];
        if (payload.len > m.data_limit) return .absent;

        const now = m.clock.now();
        if (m.absolute_timeout_ns > 0 and now -| word.created > m.absolute_timeout_ns) return .expired;
        if (m.idle_timeout_ns > 0 and now -| last_seen > m.idle_timeout_ns) return .expired;

        out.* = .{};
        idhex.encode(out.id_buf[0 .. 2 * id_len], plain[header_len..][0..id_len]);
        out.id_len = 2 * id_len;
        out.created_ns = word.created;
        out.last_seen_ns = now;
        out.remember = word.remember;
        @memcpy(out.data_buf[0..payload.len], payload);
        out.data_len = payload.len;
        out.is_new = false;
        out.data_limit = m.data_limit;
        return .loaded;
    }

    pub const SealError = error{
        /// The session does not fit `max_cookie_bytes` (only possible when a
        /// caller wrote `data_len`/`data_limit` by hand: the API refuses it).
        SessionTooLarge,
        /// `id_len` is not an even length in `[2*min_id_bytes, 2*max_id_bytes]`
        /// of hex digits (a `Session` this manager did not fill).
        InvalidSessionId,
    } || std.Io.RandomSecureError;

    /// The cookie value for `s` (`last_seen` = now), written into `out`.
    pub fn seal(m: *const CookieManager, s: *Session, out: *[max_cookie_line]u8) SealError![]const u8 {
        if (s.data_len > m.data_limit or s.data_len > s.data_buf.len) return error.SessionTooLarge;
        if (s.id_len % 2 != 0 or s.id_len < 2 * root.min_id_bytes or s.id_len > s.id_buf.len)
            return error.InvalidSessionId;
        s.last_seen_ns = m.clock.now();
        var plain: [plain_max]u8 = undefined;
        defer std.crypto.secureZero(u8, &plain);
        const id_len = s.id_len / 2;
        plain[0] = format_version;
        std.mem.writeInt(u64, plain[1..9], common.encodeCreated(s.created_ns, s.remember), .little);
        std.mem.writeInt(i64, plain[9..17], s.last_seen_ns, .little);
        plain[17] = @intCast(id_len);
        if (idhex.decode(plain[header_len..][0..id_len], s.id()) != 1) return error.InvalidSessionId;
        @memcpy(plain[header_len + id_len ..][0..s.data_len], s.data());
        const p = plain[0 .. header_len + id_len + s.data_len];
        switch (m.mode) {
            .encrypted => {
                if (cookies.private.len(p.len) > m.max_value) return error.SessionTooLarge;
                return cookies.private.sealRandom(m.io, &m.keys[0], m.cookie_name, p, out) catch |err| return switch (err) {
                    error.NoSpaceLeft, error.InvalidValue => error.SessionTooLarge,
                    else => |e| e,
                };
            },
            .signed => {
                const enc = b64.Encoder.calcSize(p.len);
                if (cookies.signed.len(enc) > m.max_value) return error.SessionTooLarge;
                // Encoded in place after the tag, then signed in place.
                const text = b64.Encoder.encode(out[cookies.signed.tag_b64_len..][0..enc], p);
                return cookies.signed.sign(&m.keys[0], m.cookie_name, text, out, .{}) catch return error.SessionTooLarge;
            },
        }
    }

    pub const SaveError = SealError || http.Server.ResponseWriter.SetHeaderError;

    /// Seal `s` and stamp it as `Set-Cookie` on `res`. Unlike `Manager.save`
    /// this reports failure: the cookie IS the session, so a cookie that is
    /// not written is a lost write. Sets `s.persisted`.
    pub fn save(m: *const CookieManager, res: *http.Server.ResponseWriter, s: *Session) SaveError!void {
        s.persisted = false;
        var value_buf: [max_cookie_line]u8 = undefined;
        const value = try m.seal(s, &value_buf);
        const max_age: ?i64 = if (m.persist_cookie or s.remember) common.maxAgeSeconds(m.idle_timeout_ns) else null;
        var line_buf: [max_cookie_line]u8 = undefined;
        const line = m.cookieLine(&line_buf, value, max_age) catch return error.SessionTooLarge;
        try res.addSetCookie(line);
        s.persisted = true;
    }

    /// Clear the browser's cookie (`Max-Age=-1`). Best effort, like
    /// `Manager.destroy`. Earlier copies of the value stay valid until their
    /// timeouts: see the module notes.
    pub fn destroy(m: *const CookieManager, res: *http.Server.ResponseWriter) void {
        var line_buf: [max_cookie_line]u8 = undefined;
        const line = m.cookieLine(&line_buf, "", -1) catch return;
        res.addSetCookie(line) catch {};
    }

    /// Give `s` a new id (a new CSRF binding), data kept. With no server
    /// state there is nothing to kill; the old cookie value still opens
    /// until its timeouts (module notes).
    pub fn regenerate(m: *const CookieManager, s: *Session) void {
        m.newId(s);
        s.regenerated = true;
    }

    /// The session id inside `req`'s cookie, hex, into `buf`, when it opens
    /// and is live. What `Csrf.cookie_sessions` binds tokens to: the cookie
    /// value itself changes on every response, the id does not.
    pub fn sessionId(m: *const CookieManager, req: *const http.Server.Request, buf: *[session_id_max]u8) ?[]const u8 {
        var s: Session = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&s.data_buf));
        if (m.load(req, &s) != .loaded) return null;
        @memcpy(buf[0..s.id_len], s.id());
        return buf[0..s.id_len];
    }

    /// A `router.Middleware`: open or create the session, attach it to
    /// `ctx.data`, run the chain, then write the cookie back (or clear it
    /// after `revoke`). A session whose cookie cannot be written fails the
    /// request with the `save` error when the handler changed it; the
    /// manager must outlive the router.
    pub fn middleware(m: *CookieManager) router.Middleware {
        return .{ .state = m, .run = middlewareRun };
    }

    fn newId(m: *const CookieManager, out: *Session) void {
        var raw: [root.max_id_bytes]u8 = undefined;
        const slice = raw[0..m.id_bytes];
        entropy.fill(m.io, slice);
        idhex.encode(out.id_buf[0 .. 2 * slice.len], slice);
        out.id_len = 2 * m.id_bytes;
    }

    fn cookieLine(m: *const CookieManager, buf: []u8, value: []const u8, max_age: ?i64) error{ NoSpaceLeft, InvalidCookie }![]const u8 {
        const sc: cookies.SetCookie = .{
            .name = m.cookie_name,
            .value = value,
            .path = m.cookie_path,
            .domain = m.cookie_domain,
            .max_age = max_age,
            .secure = m.secure,
            .http_only = true,
            .same_site = m.same_site,
        };
        const line = sc.bufPrint(buf) catch |err| return switch (err) {
            error.BufferTooSmall => error.NoSpaceLeft,
            else => error.InvalidCookie,
        };
        if (line.len > m.max_cookie_bytes) return error.NoSpaceLeft;
        return line;
    }
};

/// base64url without padding: every character is a cookie-octet.
const b64 = std.base64.url_safe_no_pad;

/// The longest plaintext whose sealed form is at most `max_value` bytes.
fn plainFit(mode: CookieMode, max_value: usize) usize {
    return switch (mode) {
        // base64 with padding of overhead + n bytes: 4 * ceil((overhead + n) / 3).
        .encrypted => (max_value / 4 * 3) -| cookies.private.overhead,
        // 44-byte tag, then unpadded base64url of n bytes: ceil(4n / 3).
        .signed => (max_value -| cookies.signed.tag_b64_len) * 3 / 4,
    };
}

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const m: *CookieManager = @ptrCast(@alignCast(state.?));

    var s: Session = .{};
    defer std.crypto.secureZero(u8, std.mem.asBytes(&s.data_buf));
    switch (m.load(ctx.req, &s)) {
        .loaded => {},
        .absent, .expired => m.create(&s),
    }

    const saved = ctx.data;
    ctx.data = &s;
    defer ctx.data = saved;

    next.run(ctx) catch |err| {
        if (s.revoked) m.destroy(ctx.res);
        return err;
    };

    if (s.revoked) {
        m.destroy(ctx.res);
    } else if (s.is_new and !s.kept and !s.regenerated and !m.persist_untouched_sessions) {
        // nothing to write
    } else {
        m.save(ctx.res, &s) catch |err| {
            // A loaded session only rolling its idle window keeps working
            // with the cookie it has; a changed one would lose the change
            // without a word, so the request fails.
            if (s.kept or s.regenerated) return err;
        };
    }
}

// ── tests (the rest: cookiestore_test.zig) ──────────────────────────────────

const TestClock = struct {
    now_ns: i64 = 1_700_000_000 * std.time.ns_per_s,
    fn clock(c: *TestClock) Clock {
        return .{ .ctx = c, .nowFn = read };
    }
    fn read(ctx: ?*anyopaque) i64 {
        const c: *TestClock = @ptrCast(@alignCast(ctx.?));
        return c.now_ns;
    }
};

test "CookieManager: plaintext decode never panics on arbitrary bytes (PRNG, 20k inputs)" {
    var clk: TestClock = .{};
    const keys = [_]cookies.Key{.{ .signing = @splat(1), .encryption = @splat(2) }};
    const m = try CookieManager.init(.{ .io = std.testing.io, .keys = &keys, .clock = clk.clock(), .idle_timeout_ns = 10, .absolute_timeout_ns = 10 });
    var prng = std.Random.DefaultPrng.init(0x5e55_1075);
    const r = prng.random();
    var buf: [max_cookie_line]u8 = undefined;
    var out: Session = undefined;
    var loaded: usize = 0;
    for (0..20_000) |_| {
        const n = r.uintAtMost(usize, 120);
        r.bytes(buf[0..n]);
        // Bias towards the header shape so the id/payload checks are reached.
        if (n > 0 and r.boolean()) buf[0] = 1;
        if (n > 17 and r.boolean()) buf[17] = r.intRangeAtMost(u8, 14, 66);
        if (n > 17 and r.boolean()) {
            std.mem.writeInt(u64, buf[1..9], @bitCast(clk.now_ns), .little);
            std.mem.writeInt(i64, buf[9..17], clk.now_ns, .little);
        }
        switch (m.decode(buf[0..n], &out)) {
            .loaded => {
                loaded += 1;
                try std.testing.expect(out.id_len >= 32 and out.id_len <= 128 and out.data_len <= m.dataLimit());
            },
            .absent, .expired => {},
        }
    }
    try std.testing.expect(loaded > 0);
}
