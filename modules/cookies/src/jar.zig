// SPDX-License-Identifier: MIT

//! A client-side cookie jar: what a user agent keeps from `Set-Cookie` and
//! sends back in `Cookie` (RFC 6265 §5.2 parsing, §5.3 storage, §5.4
//! retrieval), with RFC 6265bis's two Secure rules (a `Secure` cookie only
//! from an `https://` response, and a plain response cannot shadow a secure
//! cookie). Plug it into `http.Client` with `jar.cookieJar()`.
//!
//! **Which domains a response may set cookies for** is the Public Suffix
//! List's call (`Options.psl`): `bank.co.uk` must not set one for `co.uk`.
//! Without a list the jar is fail-closed: every `Domain` attribute counts as
//! a public suffix, so a cookie is kept host-only when `Domain` names the
//! responding host itself and dropped otherwise. (Go's jar without a list
//! does the opposite -- any server can set cookies for any domain.)
//!
//! Held to Go's `net/http/cookiejar` by `go_jar_oracle.zig`.

const std = @import("std");
const http = @import("http");
const PublicSuffixList = @import("psl.zig").PublicSuffixList;

pub const Options = struct {
    /// The list that decides which `Domain` attributes are allowed. null =
    /// host-only cookies only (see the file doc). Borrowed: must outlive
    /// the jar.
    psl: ?*const PublicSuffixList = null,
    /// Beyond this many cookies the least recently used are evicted
    /// (RFC 6265 §6.1 asks for at least 3000).
    max_cookies: usize = 3000,
    /// Per cookie domain (§6.1: at least 50).
    max_per_domain: usize = 50,
};

/// RFC 6265bis §5.6: a name plus value longer than this is ignored.
pub const max_name_value_bytes = 4096;
/// RFC 6265bis §5.6: an attribute value longer than this is ignored.
pub const max_attribute_bytes = 1024;

/// One `Set-Cookie` field value, parsed (§5.2). Slices borrow the input.
pub const SetCookie = struct {
    name: []const u8,
    value: []const u8,
    /// Expires, as Unix seconds.
    expires: ?i64 = null,
    /// Max-Age in seconds; zero or negative means "expire now".
    max_age: ?i64 = null,
    /// Without its leading dot; never empty (an empty one is ignored).
    domain: ?[]const u8 = null,
    /// Only a value that starts with `/`; anything else is ignored.
    path: ?[]const u8 = null,
    secure: bool = false,
    http_only: bool = false,
    same_site: ?SameSite = null,

    pub const SameSite = enum { strict, lax, none };

    /// Parse one field value; null when the cookie is to be ignored (no `=`
    /// in the name-value pair, an empty name, a control byte, or name plus
    /// value over 4096 bytes). Unknown and malformed attributes are skipped;
    /// the last of each kind wins.
    pub fn parse(field: []const u8) ?SetCookie {
        const nv_end = std.mem.indexOfScalar(u8, field, ';') orelse field.len;
        const nv = field[0..nv_end];
        const eq = std.mem.indexOfScalar(u8, nv, '=') orelse return null;
        var sc: SetCookie = .{
            .name = std.mem.trim(u8, nv[0..eq], wsp),
            .value = std.mem.trim(u8, nv[eq + 1 ..], wsp),
        };
        if (sc.name.len == 0) return null;
        if (hasControl(sc.name) or hasControl(sc.value)) return null;
        if (sc.name.len + sc.value.len > max_name_value_bytes) return null;

        var attrs = std.mem.splitScalar(u8, field[nv_end..], ';');
        _ = attrs.next(); // the (empty) part before the first `;`
        while (attrs.next()) |av| {
            const a_eq = std.mem.indexOfScalar(u8, av, '=');
            const name = std.mem.trim(u8, av[0 .. a_eq orelse av.len], wsp);
            const value = if (a_eq) |e| std.mem.trim(u8, av[e + 1 ..], wsp) else "";
            if (value.len > max_attribute_bytes) continue;
            if (std.ascii.eqlIgnoreCase(name, "expires")) {
                if (parseCookieDate(value)) |t| sc.expires = t;
            } else if (std.ascii.eqlIgnoreCase(name, "max-age")) {
                if (parseMaxAge(value)) |v| sc.max_age = v;
            } else if (std.ascii.eqlIgnoreCase(name, "domain")) {
                // §5.2.3: an empty value SHOULD make the UA ignore the attribute.
                const d = if (value.len != 0 and value[0] == '.') value[1..] else value;
                if (d.len != 0) sc.domain = d;
            } else if (std.ascii.eqlIgnoreCase(name, "path")) {
                sc.path = if (value.len != 0 and value[0] == '/') value else null;
            } else if (std.ascii.eqlIgnoreCase(name, "secure")) {
                sc.secure = true;
            } else if (std.ascii.eqlIgnoreCase(name, "httponly")) {
                sc.http_only = true;
            } else if (std.ascii.eqlIgnoreCase(name, "samesite")) {
                sc.same_site = if (std.ascii.eqlIgnoreCase(value, "strict")) .strict else if (std.ascii.eqlIgnoreCase(value, "lax")) .lax else if (std.ascii.eqlIgnoreCase(value, "none")) .none else null;
            }
        }
        return sc;
    }
};

const wsp = " \t";

/// RFC 6265bis §5.6: CTL other than HTAB makes the cookie ignored.
fn hasControl(s: []const u8) bool {
    for (s) |c| if ((c < 0x20 and c != '\t') or c == 0x7f) return true;
    return false;
}

/// `-? 1*DIGIT`, saturating; null for anything else (§5.2.2).
fn parseMaxAge(v: []const u8) ?i64 {
    const neg = v.len != 0 and v[0] == '-';
    const digits = if (neg) v[1..] else v;
    if (digits.len == 0) return null;
    var n: i64 = 0;
    for (digits) |c| {
        if (c < '0' or c > '9') return null;
        n = std.math.mul(i64, n, 10) catch std.math.maxInt(i64);
        n = std.math.add(i64, n, c - '0') catch std.math.maxInt(i64);
    }
    return if (neg) -n else n;
}

// ── §5.1.1 cookie-date ───────────────────────────────────────────────────

fn isDelimiter(c: u8) bool {
    return c == 0x09 or (c >= 0x20 and c <= 0x2f) or (c >= 0x3b and c <= 0x40) or
        (c >= 0x5b and c <= 0x60) or (c >= 0x7b and c <= 0x7e);
}

/// `n` leading digits (min..max of them) and then a non-digit or the end.
fn leadingDigits(tok: []const u8, min: usize, max: usize) ?u32 {
    var i: usize = 0;
    var v: u32 = 0;
    while (i < tok.len and std.ascii.isDigit(tok[i])) : (i += 1) {
        if (i == max) return null;
        v = v * 10 + (tok[i] - '0');
    }
    if (i < min) return null;
    return v;
}

/// The cookie-date algorithm: tokens in any order, the first that fits
/// each of time, day, month and year is taken. Unix seconds, or null when
/// a part is missing or the date does not exist.
pub fn parseCookieDate(s: []const u8) ?i64 {
    var time: ?[3]u32 = null;
    var day: ?u32 = null;
    var month: ?u32 = null;
    var year: ?u32 = null;
    var i: usize = 0;
    while (i < s.len) {
        while (i < s.len and isDelimiter(s[i])) i += 1;
        const start = i;
        while (i < s.len and !isDelimiter(s[i])) i += 1;
        const tok = s[start..i];
        if (tok.len == 0) continue;
        if (time == null) if (parseTime(tok)) |t| {
            time = t;
            continue;
        };
        if (day == null) if (leadingDigits(tok, 1, 2)) |d| {
            day = d;
            continue;
        };
        if (month == null) if (monthOf(tok)) |m| {
            month = m;
            continue;
        };
        if (year == null) if (leadingDigits(tok, 2, 4)) |y| {
            year = y;
            continue;
        };
    }
    var y = year orelse return null;
    if (y >= 70 and y <= 99) y += 1900 else if (y <= 69) y += 2000;
    const t = time orelse return null;
    const d = day orelse return null;
    const m = month orelse return null;
    if (d < 1 or d > 31 or y < 1601 or t[0] > 23 or t[1] > 59 or t[2] > 59) return null;
    if (d > daysInMonth(y, m)) return null;
    return daysFromCivil(y, m, d) * std.time.s_per_day + @as(i64, t[0]) * 3600 + @as(i64, t[1]) * 60 + t[2];
}

/// `1*2DIGIT ":" 1*2DIGIT ":" 1*2DIGIT ( non-digit *OCTET )`.
fn parseTime(tok: []const u8) ?[3]u32 {
    var out: [3]u32 = undefined;
    var rest = tok;
    for (&out, 0..) |*part, n| {
        var i: usize = 0;
        var v: u32 = 0;
        while (i < rest.len and std.ascii.isDigit(rest[i])) : (i += 1) {
            if (i == 2) return null;
            v = v * 10 + (rest[i] - '0');
        }
        if (i == 0) return null;
        part.* = v;
        rest = rest[i..];
        if (n < 2) {
            if (rest.len == 0 or rest[0] != ':') return null;
            rest = rest[1..];
        }
    }
    return out;
}

fn monthOf(tok: []const u8) ?u32 {
    if (tok.len < 3) return null;
    const names = [_][]const u8{ "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec" };
    for (names, 1..) |n, m| if (std.ascii.eqlIgnoreCase(tok[0..3], n)) return @intCast(m);
    return null;
}

fn daysInMonth(y: u32, m: u32) u32 {
    return switch (m) {
        2 => if (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) 29 else 28,
        4, 6, 9, 11 => 30,
        else => 31,
    };
}

fn daysFromCivil(year: u32, month: u32, day: u32) i64 {
    const y: i64 = @as(i64, year) - @intFromBool(month <= 2);
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const doy: i64 = @divTrunc(153 * @as(i64, (month + 9) % 12) + 2, 5) + day - 1;
    const doe = yoe * 365 + @divTrunc(yoe, 4) - @divTrunc(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

// ── the jar ──────────────────────────────────────────────────────────────

const Entry = struct {
    /// name, value, domain and path, in one allocation.
    buf: []u8,
    name: []const u8,
    value: []const u8,
    domain: []const u8,
    path: []const u8,
    /// Unix seconds; null = a session cookie.
    expiry: ?i64,
    host_only: bool,
    secure: bool,
    http_only: bool,
    /// Insertion order (kept across a replacement): the retrieval tie-break.
    created: u64,
    /// Last time it was sent or set: the eviction order.
    used: u64,

    fn expired(e: *const Entry, now: i64) bool {
        return if (e.expiry) |x| x <= now else false;
    }
};

pub const Jar = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    options: Options,
    mutex: std.atomic.Mutex = .unlocked,
    entries: std.ArrayList(Entry) = .empty,
    clock: u64 = 0,

    pub fn init(gpa: std.mem.Allocator, io: std.Io, options: Options) Jar {
        return .{ .gpa = gpa, .io = io, .options = options };
    }

    pub fn deinit(j: *Jar) void {
        for (j.entries.items) |e| j.gpa.free(e.buf);
        j.entries.deinit(j.gpa);
    }

    fn lock(j: *Jar) void {
        while (!j.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    /// Cookies held, expired ones included until a lookup drops them.
    pub fn count(j: *Jar) usize {
        j.lock();
        defer j.mutex.unlock();
        return j.entries.items.len;
    }

    /// Store what one `Set-Cookie` field value received from `url` says, at
    /// `now` (Unix seconds). A cookie the rules refuse is dropped silently,
    /// as a browser drops it.
    pub fn setCookieAt(j: *Jar, url: http.Url, field: []const u8, now: i64) error{OutOfMemory}!void {
        const sc = SetCookie.parse(field) orelse return;
        var host_buf: [256]u8 = undefined;
        const host = lowerInto(&host_buf, url.host) orelse return;
        const secure_origin = url.scheme == .https;
        // 6265bis §5.7 step 12: Secure only from a secure origin.
        if (sc.secure and !secure_origin) return;

        // §5.3 steps 5-6: the domain.
        var dom_buf: [256]u8 = undefined;
        var domain = host;
        var host_only = true;
        if (sc.domain) |raw| {
            const d = lowerInto(&dom_buf, raw) orelse return;
            const is_ip = isIp(host);
            const public = if (is_ip) false else if (j.options.psl) |list| list.isPublicSuffix(d) else true;
            if (is_ip or public) {
                // An IP or a public suffix may only name the host itself,
                // and then the cookie is host-only.
                if (!std.mem.eql(u8, d, host)) return;
            } else {
                if (!domainMatch(host, d)) return;
                domain = d;
                host_only = false;
            }
        }
        // §5.3 step 7.
        const path = sc.path orelse defaultPath(url.path);
        // §5.3 step 3: Max-Age wins over Expires.
        const expiry: ?i64 = if (sc.max_age) |ma|
            (if (ma <= 0) std.math.minInt(i64) else std.math.add(i64, now, ma) catch std.math.maxInt(i64))
        else
            sc.expires;

        j.lock();
        defer j.mutex.unlock();
        // 6265bis §5.7 step 13: a plain origin cannot shadow a secure cookie.
        if (!secure_origin) for (j.entries.items) |*e| {
            if (e.secure and std.mem.eql(u8, e.name, sc.name) and
                (domainMatch(e.domain, domain) or domainMatch(domain, e.domain)) and
                pathMatch(path, e.path)) return;
        };
        // §5.3 step 11: same name, domain, host-only-ness and path replace.
        var created = j.tick();
        var i: usize = 0;
        while (i < j.entries.items.len) {
            const e = &j.entries.items[i];
            if (std.mem.eql(u8, e.name, sc.name) and std.mem.eql(u8, e.domain, domain) and
                e.host_only == host_only and std.mem.eql(u8, e.path, path))
            {
                created = e.created;
                j.gpa.free(e.buf);
                _ = j.entries.orderedRemove(i);
                continue;
            }
            i += 1;
        }
        // An expiry in the past only deletes. (`evict` below would drop such
        // a cookie anyway; this spares the allocation. Mutation 2026-10-05:
        // removing it is an equivalent mutant.)
        if (expiry) |x| if (x <= now) return;

        const buf = try j.gpa.alloc(u8, sc.name.len + sc.value.len + domain.len + path.len);
        errdefer j.gpa.free(buf);
        var off: usize = 0;
        const parts = [_][]const u8{ sc.name, sc.value, domain, path };
        var slices: [4][]const u8 = undefined;
        for (parts, &slices) |p, *s| {
            @memcpy(buf[off..][0..p.len], p);
            s.* = buf[off..][0..p.len];
            off += p.len;
        }
        try j.entries.append(j.gpa, .{
            .buf = buf,
            .name = slices[0],
            .value = slices[1],
            .domain = slices[2],
            .path = slices[3],
            .expiry = expiry,
            .host_only = host_only,
            .secure = sc.secure,
            .http_only = sc.http_only,
            .created = created,
            .used = j.tick(),
        });
        j.evict(slices[2], now);
    }

    fn tick(j: *Jar) u64 {
        j.clock += 1;
        return j.clock;
    }

    /// §6.1 limits: expired cookies first, then the least recently used --
    /// within the domain that grew, then across the jar.
    fn evict(j: *Jar, domain: []const u8, now: i64) void {
        var i: usize = 0;
        while (i < j.entries.items.len) {
            if (j.entries.items[i].expired(now)) {
                j.gpa.free(j.entries.items[i].buf);
                _ = j.entries.orderedRemove(i);
            } else i += 1;
        }
        while (true) {
            var n: usize = 0;
            var lru: ?usize = null;
            for (j.entries.items, 0..) |e, k| if (std.mem.eql(u8, e.domain, domain)) {
                n += 1;
                if (lru == null or e.used < j.entries.items[lru.?].used) lru = k;
            };
            if (n <= j.options.max_per_domain) break;
            j.gpa.free(j.entries.items[lru.?].buf);
            _ = j.entries.orderedRemove(lru.?);
        }
        while (j.entries.items.len > j.options.max_cookies) {
            var lru: usize = 0;
            for (j.entries.items, 0..) |e, k| if (e.used < j.entries.items[lru].used) {
                lru = k;
            };
            j.gpa.free(j.entries.items[lru].buf);
            _ = j.entries.orderedRemove(lru);
        }
    }

    /// Write the `Cookie` value for a request to `url` at `now` (§5.4):
    /// `prefix` first, then `name=value` pairs joined by `; `, longest path
    /// first, then oldest first. Nothing at all -- not even `prefix` -- when
    /// no cookie applies; the return says which.
    pub fn writeCookiesAt(j: *Jar, url: http.Url, now: i64, w: *std.Io.Writer, prefix: []const u8) std.Io.Writer.Error!bool {
        var host_buf: [256]u8 = undefined;
        const host = lowerInto(&host_buf, url.host) orelse return false;
        const secure_ok = url.scheme == .https;

        j.lock();
        defer j.mutex.unlock();
        // Drop the expired first: removing while picking would shift the
        // indices already picked.
        var i: usize = 0;
        while (i < j.entries.items.len) {
            if (j.entries.items[i].expired(now)) {
                j.gpa.free(j.entries.items[i].buf);
                _ = j.entries.orderedRemove(i);
            } else i += 1;
        }
        var picked_buf: [256]u32 = undefined;
        var picked: std.ArrayList(u32) = .initBuffer(&picked_buf);
        for (j.entries.items, 0..) |*e, k| {
            const domain_ok = if (e.host_only) std.mem.eql(u8, host, e.domain) else domainMatch(host, e.domain);
            if (domain_ok and pathMatch(url.path, e.path) and (secure_ok or !e.secure)) {
                picked.appendBounded(@intCast(k)) catch break;
            }
        }
        if (picked.items.len == 0) return false;
        const entries = j.entries.items;
        std.sort.pdq(u32, picked.items, entries, struct {
            fn lt(es: []Entry, a: u32, b: u32) bool {
                if (es[a].path.len != es[b].path.len) return es[a].path.len > es[b].path.len;
                return es[a].created < es[b].created;
            }
        }.lt);
        try w.writeAll(prefix);
        for (picked.items, 0..) |k, n| {
            if (n > 0) try w.writeAll("; ");
            try w.print("{s}={s}", .{ entries[k].name, entries[k].value });
            entries[k].used = j.tick();
        }
        return true;
    }

    fn clockNow(j: *Jar) i64 {
        const ts = std.Io.Clock.real.now(j.io);
        return @intCast(@divFloor(ts.nanoseconds, std.time.ns_per_s));
    }

    /// The `http.Client.CookieJar` view of this jar, on the jar's clock.
    pub fn cookieJar(j: *Jar) http.Client.CookieJar {
        return .{ .ctx = j, .write_cookies = clientWrite, .store = clientStore };
    }

    fn clientWrite(ctx: *anyopaque, url: http.Url, w: *std.Io.Writer, prefix: []const u8) std.Io.Writer.Error!bool {
        const j: *Jar = @ptrCast(@alignCast(ctx));
        return j.writeCookiesAt(url, j.clockNow(), w, prefix);
    }

    fn clientStore(ctx: *anyopaque, url: http.Url, head: *const http.h1.ResponseHead) void {
        const j: *Jar = @ptrCast(@alignCast(ctx));
        const now_s = j.clockNow();
        var it = head.iterate();
        while (it.next()) |h| {
            if (!std.ascii.eqlIgnoreCase(h.name, "set-cookie")) continue;
            // Out of memory loses that cookie, as an over-full jar would.
            j.setCookieAt(url, h.value, now_s) catch {};
        }
    }
};

fn lowerInto(buf: *[256]u8, s: []const u8) ?[]const u8 {
    if (s.len > buf.len) return null;
    for (s, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..s.len];
}

fn isIp(host: []const u8) bool {
    if (std.mem.indexOfScalar(u8, host, ':') != null) return true;
    var dots: usize = 0;
    for (host) |c| {
        if (c == '.') dots += 1 else if (!std.ascii.isDigit(c)) return false;
    }
    return dots == 3;
}

/// §5.1.3: identical, or `domain` a dot-separated suffix of a host name.
fn domainMatch(host: []const u8, domain: []const u8) bool {
    if (std.mem.eql(u8, host, domain)) return true;
    if (isIp(host)) return false;
    return host.len > domain.len and std.mem.endsWith(u8, host, domain) and host[host.len - domain.len - 1] == '.';
}

/// §5.1.4.
fn pathMatch(req: []const u8, cookie: []const u8) bool {
    if (std.mem.eql(u8, req, cookie)) return true;
    if (!std.mem.startsWith(u8, req, cookie)) return false;
    return cookie[cookie.len - 1] == '/' or req[cookie.len] == '/';
}

/// §5.1.4 default-path: the request path up to, not including, its last
/// `/` -- or `/`.
fn defaultPath(uri_path: []const u8) []const u8 {
    if (uri_path.len == 0 or uri_path[0] != '/') return "/";
    const last = std.mem.lastIndexOfScalar(u8, uri_path, '/').?;
    return if (last == 0) "/" else uri_path[0..last];
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

fn u(text: []const u8) http.Url {
    return http.Url.parse(text) catch unreachable;
}

const t0: i64 = 1_800_000_000; // 2027-01-15

fn header(j: *Jar, url_text: []const u8, now_s: i64) ![]const u8 {
    const S = struct {
        var buf: [1024]u8 = undefined;
    };
    var w: std.Io.Writer = .fixed(&S.buf);
    _ = try j.writeCookiesAt(u(url_text), now_s, &w, "");
    return w.buffered();
}

test "SetCookie.parse: name-value, attributes, last one wins, refusals" {
    const sc = SetCookie.parse(" sid = a b ; Path=/x; path=/y ;DOMAIN=.Example.COM; Max-Age=60; Secure; HttpOnly; SameSite=lax; Unknown=1").?;
    try testing.expectEqualStrings("sid", sc.name);
    try testing.expectEqualStrings("a b", sc.value);
    try testing.expectEqualStrings("/y", sc.path.?);
    try testing.expectEqualStrings("Example.COM", sc.domain.?);
    try testing.expectEqual(@as(?i64, 60), sc.max_age);
    try testing.expect(sc.secure and sc.http_only and sc.same_site.? == .lax);
    // Ignored attributes: empty Domain, a Path not starting with `/`, a bad Max-Age.
    const ig = SetCookie.parse("a=1; Domain=; Path=rel; Max-Age=1x; Max-Age=-5").?;
    try testing.expect(ig.domain == null and ig.path == null);
    try testing.expectEqual(@as(?i64, -5), ig.max_age);
    // Ignored cookies.
    for ([_][]const u8{ "noequals", "=v", " =v", "a=b\x01c", "a\x7f=b", "" }) |bad| try testing.expect(SetCookie.parse(bad) == null);
    // Name plus value (the `=` not counted): 4096 is kept, 4097 is not.
    var big: [max_name_value_bytes + 2]u8 = @splat('v');
    big[0] = 'n';
    big[1] = '=';
    try testing.expect(SetCookie.parse(&big) == null);
    try testing.expect(SetCookie.parse(big[0 .. max_name_value_bytes + 1]) != null);
    // An over-long attribute value is dropped, the cookie kept.
    var attr: [16 + max_attribute_bytes + 1]u8 = @splat('/');
    @memcpy(attr[0..16], "a=1; Path=/aaaaa");
    try testing.expect(SetCookie.parse(&attr).?.path == null);
}

test "parseCookieDate: RFC 6265 §5.1.1 forms, two-digit years, impossible dates" {
    const want: i64 = 784111777; // Sun, 06 Nov 1994 08:49:37 GMT
    for ([_][]const u8{
        "Sun, 06 Nov 1994 08:49:37 GMT",
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "Sun Nov  6 08:49:37 1994",
        "06 nov 1994 08:49:37",
        "08:49:37 1994 november 6",
        "Sun, 06-Nov-1994 08:49:37 GMT",
    }) |s| try testing.expectEqual(@as(?i64, want), parseCookieDate(s));
    try testing.expectEqual(@as(?i64, 0), parseCookieDate("Thu, 01 Jan 1970 00:00:00 GMT"));
    try testing.expectEqual(parseCookieDate("1 Jan 2069 00:00:00").?, parseCookieDate("1 Jan 69 00:00:00").?);
    for ([_][]const u8{
        "Sun, 31 Feb 1994 08:49:37 GMT", // no such day
        "Sun, 06 Nov 1600 08:49:37 GMT", // year < 1601
        "Sun, 06 Nov 1994 24:00:00 GMT",
        "Sun, 06 Nov 1994 08:60:00 GMT",
        "Sun, 06 Nov 1994", // no time
        "06 1994 08:49:37", // no month
        "",
    }) |s| try testing.expectEqual(@as(?i64, null), parseCookieDate(s));
}

test "store and send: host-only, Domain, Path default and match, order" {
    var list = try PublicSuffixList.parse(testing.allocator, "com\n");
    defer list.deinit();
    var j = Jar.init(testing.allocator, undefined, .{ .psl = &list });
    defer j.deinit();
    try j.setCookieAt(u("http://www.example.com/a/b/page"), "host=1", t0);
    try j.setCookieAt(u("http://www.example.com/a/b/page"), "dom=2; Domain=example.com; Path=/", t0);
    try j.setCookieAt(u("http://www.example.com/a/b/page"), "deep=3; Path=/a/b", t0);
    // Default path = /a/b (up to the last `/`): sent below it, not above.
    // `host` and `deep` have equally long paths, so the older goes first.
    try testing.expectEqualStrings("host=1; deep=3; dom=2", try header(&j, "http://www.example.com/a/b/x", t0));
    try testing.expectEqualStrings("dom=2", try header(&j, "http://www.example.com/a", t0));
    try testing.expectEqualStrings("dom=2", try header(&j, "http://other.example.com/a/b/x", t0));
    try testing.expectEqualStrings("", try header(&j, "http://example.org/", t0));
    // `/a/bc` is not under `/a/b`.
    try testing.expectEqualStrings("dom=2", try header(&j, "http://www.example.com/a/bc", t0));
}

test "PSL: a public suffix Domain is refused unless it is the host, then host-only" {
    var list = try PublicSuffixList.parse(testing.allocator, "uk\nco.uk\n");
    defer list.deinit();
    var j = Jar.init(testing.allocator, undefined, .{ .psl = &list });
    defer j.deinit();
    try j.setCookieAt(u("http://bank.co.uk/"), "evil=1; Domain=co.uk", t0);
    try testing.expectEqual(@as(usize, 0), j.count());
    try j.setCookieAt(u("http://co.uk/"), "self=1; Domain=co.uk", t0);
    try testing.expectEqualStrings("self=1", try header(&j, "http://co.uk/", t0));
    try testing.expectEqualStrings("", try header(&j, "http://bank.co.uk/", t0)); // host-only
    try j.setCookieAt(u("http://www.bank.co.uk/"), "ok=1; Domain=bank.co.uk", t0);
    try testing.expectEqualStrings("ok=1", try header(&j, "http://bank.co.uk/", t0));
    // A Domain the host is not under.
    try j.setCookieAt(u("http://bank.co.uk/"), "x=1; Domain=other.co.uk", t0);
    try testing.expectEqualStrings("", try header(&j, "http://other.co.uk/", t0));
}

test "no list: every Domain counts as a public suffix (fail-closed)" {
    var j = Jar.init(testing.allocator, undefined, .{});
    defer j.deinit();
    try j.setCookieAt(u("http://www.example.com/"), "a=1; Domain=example.com", t0);
    try testing.expectEqual(@as(usize, 0), j.count());
    try j.setCookieAt(u("http://www.example.com/"), "b=1; Domain=WWW.example.com", t0);
    try testing.expectEqualStrings("b=1", try header(&j, "http://www.example.com/", t0));
    try testing.expectEqualStrings("", try header(&j, "http://x.www.example.com/", t0));
}

test "IP hosts: Domain only as the IP itself, then host-only" {
    var j = Jar.init(testing.allocator, undefined, .{});
    defer j.deinit();
    try j.setCookieAt(u("http://192.0.2.1/"), "a=1; Domain=192.0.2.1", t0);
    try j.setCookieAt(u("http://192.0.2.1/"), "b=1; Domain=0.2.1", t0);
    try testing.expectEqualStrings("a=1", try header(&j, "http://192.0.2.1/", t0));
    try testing.expectEqualStrings("", try header(&j, "http://9.192.0.2.1/", t0));
}

test "expiry: Max-Age over Expires, past dates delete, sessions stay" {
    var j = Jar.init(testing.allocator, undefined, .{});
    defer j.deinit();
    const url = "http://h.test/";
    try j.setCookieAt(u(url), "ma=1; Max-Age=10; Expires=Thu, 01 Jan 1970 00:00:00 GMT", t0);
    try j.setCookieAt(u(url), "ex=1; Expires=Fri, 01 Jan 2100 00:00:00 GMT", t0);
    try j.setCookieAt(u(url), "sess=1", t0);
    try testing.expectEqualStrings("ma=1; ex=1; sess=1", try header(&j, url, t0));
    try testing.expectEqualStrings("ex=1; sess=1", try header(&j, url, t0 + 10)); // expiry is exclusive
    try j.setCookieAt(u(url), "ex=gone; Max-Age=0", t0 + 11);
    try j.setCookieAt(u(url), "sess=gone; Expires=Thu, 01 Jan 1970 00:00:00 GMT", t0 + 11);
    try testing.expectEqualStrings("", try header(&j, url, t0 + 11));
    try testing.expectEqual(@as(usize, 0), j.count());
}

test "replacement keeps the creation time; name, domain and path all must match" {
    var j = Jar.init(testing.allocator, undefined, .{});
    defer j.deinit();
    const url = "http://h.test/";
    try j.setCookieAt(u(url), "a=1", t0);
    try j.setCookieAt(u(url), "b=1", t0);
    try j.setCookieAt(u(url), "a=2", t0); // replaces, stays first
    try j.setCookieAt(u(url), "a=3; Path=/x", t0); // a different cookie
    try testing.expectEqualStrings("a=2; b=1", try header(&j, url, t0));
    try testing.expectEqualStrings("a=3; a=2; b=1", try header(&j, "http://h.test/x", t0));
}

test "Secure: only from https, only sent over https, not shadowed from http" {
    var j = Jar.init(testing.allocator, undefined, .{});
    defer j.deinit();
    try j.setCookieAt(u("http://h.test/"), "s=plain; Secure", t0);
    try testing.expectEqual(@as(usize, 0), j.count());
    try j.setCookieAt(u("https://h.test/"), "s=1; Secure", t0);
    try testing.expectEqualStrings("", try header(&j, "http://h.test/", t0));
    try testing.expectEqualStrings("s=1", try header(&j, "https://h.test/", t0));
    try j.setCookieAt(u("http://h.test/"), "s=shadow", t0);
    try j.setCookieAt(u("http://h.test/"), "s=deeper; Path=/a", t0);
    try testing.expectEqual(@as(usize, 1), j.count());
    try j.setCookieAt(u("https://h.test/"), "s=fine; Path=/b", t0); // a secure origin may
    try testing.expectEqual(@as(usize, 2), j.count());
    // ... and may replace the secure one with a plain one.
    try j.setCookieAt(u("https://h.test/"), "s=plain", t0);
    try testing.expectEqualStrings("s=plain", try header(&j, "http://h.test/", t0));
}

test "limits: per domain and overall, least recently used out first" {
    var j = Jar.init(testing.allocator, undefined, .{ .max_per_domain = 3, .max_cookies = 4 });
    defer j.deinit();
    try j.setCookieAt(u("http://a.test/"), "a1=1", t0);
    try j.setCookieAt(u("http://a.test/"), "a2=1", t0);
    try j.setCookieAt(u("http://a.test/"), "a3=1", t0);
    _ = try header(&j, "http://a.test/", t0); // all three used now; a1 used first
    try j.setCookieAt(u("http://a.test/"), "a4=1", t0);
    try testing.expectEqualStrings("a2=1; a3=1; a4=1", try header(&j, "http://a.test/", t0));
    try j.setCookieAt(u("http://b.test/"), "b1=1", t0);
    try j.setCookieAt(u("http://b.test/"), "b2=1", t0);
    try testing.expectEqual(@as(usize, 4), j.count());
    try testing.expectEqualStrings("b1=1; b2=1", try header(&j, "http://b.test/", t0));
}

test "domainMatch, pathMatch, defaultPath" {
    try testing.expect(domainMatch("a.example.com", "example.com"));
    try testing.expect(!domainMatch("aexample.com", "example.com"));
    try testing.expect(!domainMatch("192.0.2.1", "0.2.1")); // an IP host matches only itself
    try testing.expect(domainMatch("192.0.2.1", "192.0.2.1"));
    try testing.expect(pathMatch("/a/b", "/a"));
    try testing.expect(pathMatch("/a/b", "/a/"));
    try testing.expect(!pathMatch("/ab", "/a"));
    try testing.expectEqualStrings("/", defaultPath("/"));
    try testing.expectEqualStrings("/", defaultPath("/page"));
    try testing.expectEqualStrings("/a/b", defaultPath("/a/b/page"));
    try testing.expectEqualStrings("/a/b", defaultPath("/a/b/"));
}

// ── fuzz: arbitrary Set-Cookie fields from several origins, then requests ──

const fuzz_driver = @import("testkit").fuzz.driver;

const fz_urls = [_][]const u8{
    "http://www.example.test/",
    "https://www.example.test/a/b",
    "http://example.test/x/y",
    "https://a.www.example.test/a",
    "http://192.0.2.1/",
    "https://test/",
};

/// Pieces a `Set-Cookie` field is made of; the harness strings them
/// together with arbitrary bytes in between.
const fz_pieces = [_][]const u8{
    "a=1",                                     "b=2",                                     "a=",                          "=x",
    "; Domain=example.test",                   "; Domain=.www.example.test",              "; Domain=test",               "; Domain=192.0.2.1",
    "; Path=/",                                "; Path=/a",                               "; Path=rel",                  "; Secure",
    "; HttpOnly",                              "; Max-Age=0",                             "; Max-Age=60",                "; Max-Age=-1",
    "; Expires=Thu, 01 Jan 1970 00:00:00 GMT", "; Expires=Fri, 01 Jan 2100 00:00:00 GMT", "; Expires=31 Feb 2030 1:2:3", "\"q v\"",
    " ",                                       ";",                                       "=",                           "\x01",
};

fn jarHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var list = try PublicSuffixList.parse(gpa, "test\n");
    defer list.deinit();
    var j = Jar.init(gpa, undefined, .{ .psl = &list, .max_cookies = 8, .max_per_domain = 4 });
    defer j.deinit();

    var field_buf: [256]u8 = undefined;
    const fields = src.valueRangeAtMost(u8, 1, 8);
    for (0..fields) |_| {
        var len: usize = 0;
        const pieces = src.valueRangeAtMost(u8, 1, 6);
        for (0..pieces) |_| {
            const piece = if (src.valueRangeAtMost(u8, 0, 7) == 0) blk: {
                var one: [1]u8 = undefined;
                one[0] = src.value(u8);
                break :blk one[0..];
            } else fz_pieces[src.index(fz_pieces.len)];
            if (len + piece.len > field_buf.len) break;
            @memcpy(field_buf[len..][0..piece.len], piece);
            len += piece.len;
        }
        const url = http.Url.parse(fz_urls[src.index(fz_urls.len)]) catch unreachable;
        try j.setCookieAt(url, field_buf[0..len], t0);
    }

    // What the jar keeps obeys its rules, whatever arrived.
    if (j.entries.items.len > 8) return error.OverMaxCookies;
    for (j.entries.items) |e| {
        if (e.name.len == 0 or hasControl(e.name) or hasControl(e.value)) return error.BadStoredName;
        if (e.name.len + e.value.len > max_name_value_bytes) return error.OverSize;
        if (e.path.len == 0 or e.path[0] != '/') return error.BadPath;
        if (e.expired(t0)) return error.KeptExpired;
        for (e.domain) |c| if (std.ascii.isUpper(c)) return error.DomainNotLowercase;
        if (!e.host_only) {
            if (list.isPublicSuffix(e.domain)) return error.PublicSuffixDomain;
            fuzz_driver.hit("domain_cookie");
        }
        if (e.secure) fuzz_driver.hit("secure_cookie");
    }
    if (j.entries.items.len != 0) fuzz_driver.hit("stored");

    // What a request carries: only cookies the jar holds for that URL, and
    // never a Secure one over http.
    for (fz_urls) |text| {
        const url = http.Url.parse(text) catch unreachable;
        var out: [4096]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        if (!try j.writeCookiesAt(url, t0, &w, "")) continue;
        fuzz_driver.hit("sent");
        var pairs = std.mem.splitSequence(u8, w.buffered(), "; ");
        while (pairs.next()) |pair| {
            const held = for (j.entries.items) |e| {
                if (pair.len == e.name.len + 1 + e.value.len and std.mem.startsWith(u8, pair, e.name) and
                    pair[e.name.len] == '=' and std.mem.endsWith(u8, pair, e.value))
                {
                    if (url.scheme == .https or !e.secure) break true;
                }
            } else false;
            if (!held) return error.SentUnheldCookie;
        }
    }
}

test "fuzz driver: the jar keeps only what its rules allow (COOKIES_FUZZ)" {
    try fuzz_driver.run(jarHarness, .{ .prefix = "COOKIES_FUZZ", .name = "jar" });
}

test "fuzz: the jar keeps only what its rules allow (coverage-guided exploration)" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *std.testing.Smith) !void {
            try jarHarness(std.testing.Smith, smith, testing.allocator);
        }
    }.one, .{});
}
