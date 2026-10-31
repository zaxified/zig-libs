// SPDX-License-Identifier: MIT

//! The four generic DNS-01 publishers — the ones that cover a DNS setup
//! without a vendor API (owner's choice, 2026-10-16; lego has 200+ vendor
//! providers, these are its generic ones):
//!
//! - `Rfc2136`: RFC 2136 dynamic update to the zone's primary, TSIG-signed
//!   (`dns.update`, `dns.tsig`) — lego `rfc2136`, certbot `dns-rfc2136`.
//! - `AcmeDns`: joohoi/acme-dns's `POST /update` with `X-Api-User` /
//!   `X-Api-Key` — lego `acme-dns`, certbot `acme-dns-auth`.
//! - `HttpReq`: lego's `httpreq` — `POST <endpoint>/present` and
//!   `/cleanup`, JSON `{fqdn, value}` (or RAW `{domain, token, keyAuth}`),
//!   optional basic auth.
//! - `Exec`: lego's `exec` — `<program> present <fqdn.> <value>` and
//!   `cleanup` (or RAW `present -- <domain> <token> <keyAuth>`), exit 0 =
//!   done.
//!
//! Each holds its configuration and a `note` (a static string: why the last
//! call failed), and hands out a `Publisher` that points at itself — keep it
//! in place while the solver uses it.

const std = @import("std");
const dns = @import("dns");
const b64ct = @import("b64ct");
const http = @import("http");
const netaddr = @import("netaddr");
const procrun = @import("procrun");
const root = @import("root.zig");
const zone = @import("zone.zig");

const Record = root.Record;
const PublishError = root.PublishError;

// ── RFC 2136 ────────────────────────────────────────────────────────────────

pub const Rfc2136 = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    options: Options,
    note: []const u8 = "",
    /// The rcode of the last update the server answered.
    last_rcode: ?dns.Rcode = null,

    pub const Options = struct {
        /// The zone's primary (the server that accepts updates).
        server: netaddr.Ip,
        port: u16 = 53,
        /// Sign with TSIG; null sends unsigned updates (a server that allows
        /// them by source address).
        key: ?*const dns.tsig.Key = null,
        /// TTL of the TXT record (lego's default: 120).
        ttl: u32 = 120,
        timeout_ms: u32 = 5000,
        attempts: u8 = 2,
        transport: dns.Resolver.Transport = .auto,
    };

    pub fn init(io: std.Io, gpa: std.mem.Allocator, options: Options) Rfc2136 {
        return .{ .io = io, .gpa = gpa, .options = options };
    }

    pub fn publisher(p: *Rfc2136) root.Publisher {
        return .{ .ctx = p, .present = present, .cleanup = cleanup };
    }

    fn present(ctx: ?*anyopaque, rec: *const Record) PublishError!void {
        const p: *Rfc2136 = @ptrCast(@alignCast(ctx.?));
        p.note = "";
        p.change(rec, .add) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                if (p.note.len == 0) p.note = "the update did not reach the server, or its reply was not accepted";
                return error.PublishFailed;
            },
        };
    }

    fn cleanup(ctx: ?*anyopaque, rec: *const Record) void {
        const p: *Rfc2136 = @ptrCast(@alignCast(ctx.?));
        p.change(rec, .delete) catch {};
    }

    fn change(p: *Rfc2136, rec: *const Record, op: enum { add, delete }) !void {
        var buf: [2048]u8 = undefined;
        var rd: [300]u8 = undefined;
        var b = try dns.update.Builder.init(&buf, rec.zone);
        const rdata = try dns.update.txtRdata(&rd, rec.value);
        switch (op) {
            .add => try b.add(rec.fqdn, .txt, p.options.ttl, rdata),
            .delete => try b.delete(rec.fqdn, .txt, rdata),
        }
        var r = dns.Resolver.init(p.io, p.gpa, .{
            .servers = &.{p.options.server},
            .port = p.options.port,
            .timeout_ms = p.options.timeout_ms,
            .attempts = p.options.attempts,
            .transport = p.options.transport,
            .use_hosts = false,
            .use_search = false,
        });
        defer r.deinit();
        const rcode = dns.update.send(&r, p.options.server, &b, .{ .key = p.options.key }) catch |err| {
            p.note = switch (err) {
                error.PeerBadKey => "the server does not know the TSIG key (BADKEY)",
                error.PeerBadSig => "the server rejected the TSIG signature (BADSIG): wrong secret?",
                error.PeerBadTime => "the server rejected the TSIG time (BADTIME): clocks apart",
                error.Unsigned, error.BadSig, error.BadKey, error.BadTime, error.BadTrunc => "the server's reply failed TSIG verification",
                error.Timeout => "the server did not answer",
                error.RequestTooLarge => "the update message is over 65535 bytes (nothing was sent)",
                else => "",
            };
            return err;
        };
        p.last_rcode = rcode;
        if (rcode != .no_error) {
            p.note = "the server refused the update (see last_rcode)";
            return error.PublishFailed;
        }
    }
};

// ── acme-dns ────────────────────────────────────────────────────────────────

pub const AcmeDns = struct {
    gpa: std.mem.Allocator,
    client: http.Client,
    options: Options,
    note: []const u8 = "",
    /// HTTP status of the last request, 0 before any.
    last_status: u16 = 0,

    /// An acme-dns registration (`POST /register`'s answer) and the domain
    /// it serves: `_acme-challenge.<domain>` must be a CNAME to `fulldomain`.
    pub const Account = struct {
        domain: []const u8,
        username: []const u8,
        password: []const u8,
        subdomain: []const u8,
        /// Checked against the solver's CNAME-followed name when non-empty:
        /// a missing CNAME is the usual setup error, and acme-dns would
        /// accept the update anyway.
        fulldomain: []const u8 = "",
    };

    pub const Options = struct {
        /// The acme-dns API base, e.g. "https://auth.acme-dns.io".
        server_url: []const u8,
        accounts: []const Account,
        http: http.Client.Options = .{},
    };

    pub fn init(io: std.Io, gpa: std.mem.Allocator, options: Options) AcmeDns {
        return .{ .gpa = gpa, .client = .init(io, gpa, options.http), .options = options };
    }

    pub fn deinit(p: *AcmeDns) void {
        p.client.deinit();
    }

    pub fn publisher(p: *AcmeDns) root.Publisher {
        return .{ .ctx = p, .present = present, .cleanup = cleanup };
    }

    fn present(ctx: ?*anyopaque, rec: *const Record) PublishError!void {
        const p: *AcmeDns = @ptrCast(@alignCast(ctx.?));
        p.note = "";
        const acct = for (p.options.accounts) |*a| {
            if (zone.eqlName(a.domain, rec.domain)) break a;
        } else {
            p.note = "no acme-dns account for this domain";
            return error.PublishFailed;
        };
        if (acct.fulldomain.len != 0 and !zone.eqlName(acct.fulldomain, rec.fqdn)) {
            p.note = "_acme-challenge.<domain> is not a CNAME to the account's fulldomain";
            return error.PublishFailed;
        }
        const body = try std.json.Stringify.valueAlloc(p.gpa, .{ .subdomain = acct.subdomain, .txt = rec.value }, .{});
        defer p.gpa.free(body);
        const url = try joinPath(p.gpa, p.options.server_url, "update");
        defer p.gpa.free(url);
        p.last_status = post(&p.client, p.gpa, url, body, &.{
            .{ .name = "X-Api-User", .value = acct.username },
            .{ .name = "X-Api-Key", .value = acct.password },
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                p.note = "the acme-dns server could not be reached";
                return error.PublishFailed;
            },
        };
        if (p.last_status != 200) {
            p.note = "acme-dns refused the update (see last_status)";
            return error.PublishFailed;
        }
    }

    /// acme-dns has no delete: it keeps the two most recent values per
    /// subdomain (a wildcard and its base name fit) and the next update
    /// replaces the older one.
    fn cleanup(_: ?*anyopaque, _: *const Record) void {}

    /// `POST /register` — a new acme-dns account (lego registers on first
    /// use). `allow_from` is acme-dns's optional CIDR allow-list. The
    /// strings are owned by the result; `deinit` it.
    pub fn register(
        io: std.Io,
        gpa: std.mem.Allocator,
        server_url: []const u8,
        http_options: http.Client.Options,
        allow_from: []const []const u8,
    ) !std.json.Parsed(Registration) {
        var client: http.Client = .init(io, gpa, http_options);
        defer client.deinit();
        const url = try joinPath(gpa, server_url, "register");
        defer gpa.free(url);
        const req_body = if (allow_from.len == 0) try gpa.dupe(u8, "{}") else try std.json.Stringify.valueAlloc(gpa, .{ .allowfrom = allow_from }, .{});
        defer gpa.free(req_body);
        var res = try client.request(.post, url, .{
            .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
            .body = req_body,
        });
        defer res.deinit();
        const body = try res.readAllAlloc(gpa, 64 * 1024);
        defer gpa.free(body);
        if (res.status != 201 and res.status != 200) return error.RegistrationRefused;
        return parseRegistration(gpa, body);
    }

    /// The `/register` reply: four strings, anything else ignored. Hostile
    /// input (the server's reply) — fuzzed in `fuzz_test.zig`.
    pub fn parseRegistration(gpa: std.mem.Allocator, body: []const u8) std.json.ParseError(std.json.Scanner)!std.json.Parsed(Registration) {
        return std.json.parseFromSlice(Registration, gpa, body, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
    }

    pub const Registration = struct {
        username: []const u8,
        password: []const u8,
        fulldomain: []const u8,
        subdomain: []const u8,
    };
};

// ── httpreq ─────────────────────────────────────────────────────────────────

pub const HttpReq = struct {
    gpa: std.mem.Allocator,
    client: http.Client,
    options: Options,
    note: []const u8 = "",
    last_status: u16 = 0,

    pub const Mode = enum {
        /// `{"fqdn": "<fqdn>.", "value": "<txt value>"}` — lego's default.
        default,
        /// `{"domain": "<domain>", "token": "...", "keyAuth": "..."}` — the
        /// endpoint computes the record itself (lego `HTTPREQ_MODE=RAW`).
        raw,
    };

    pub const Options = struct {
        /// Base URL; `/present` and `/cleanup` are appended.
        endpoint: []const u8,
        mode: Mode = .default,
        /// HTTP basic auth, sent when `username` is non-empty.
        username: []const u8 = "",
        password: []const u8 = "",
        http: http.Client.Options = .{},
    };

    pub fn init(io: std.Io, gpa: std.mem.Allocator, options: Options) HttpReq {
        return .{ .gpa = gpa, .client = .init(io, gpa, options.http), .options = options };
    }

    pub fn deinit(p: *HttpReq) void {
        p.client.deinit();
    }

    pub fn publisher(p: *HttpReq) root.Publisher {
        return .{ .ctx = p, .present = present, .cleanup = cleanup };
    }

    fn present(ctx: ?*anyopaque, rec: *const Record) PublishError!void {
        const p: *HttpReq = @ptrCast(@alignCast(ctx.?));
        p.note = "";
        const status = p.call("present", rec) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidCredentials => {
                p.note = "basic-auth credentials too long, or the username contains ':' (RFC 7617)";
                return error.PublishFailed;
            },
            else => {
                p.note = "the endpoint could not be reached";
                return error.PublishFailed;
            },
        };
        if (status / 100 != 2) {
            p.note = "the endpoint refused /present (see last_status)";
            return error.PublishFailed;
        }
    }

    fn cleanup(ctx: ?*anyopaque, rec: *const Record) void {
        const p: *HttpReq = @ptrCast(@alignCast(ctx.?));
        _ = p.call("cleanup", rec) catch {};
    }

    fn call(p: *HttpReq, action: []const u8, rec: *const Record) !u16 {
        const body = switch (p.options.mode) {
            .default => blk: {
                const fqdn = try p.gpa.print("{s}.", .{zone.trimDot(rec.fqdn)});
                defer p.gpa.free(fqdn);
                break :blk try std.json.Stringify.valueAlloc(p.gpa, .{ .fqdn = fqdn, .value = rec.value }, .{});
            },
            .raw => try std.json.Stringify.valueAlloc(p.gpa, .{ .domain = rec.domain, .token = rec.token, .keyAuth = rec.key_authorization }, .{}),
        };
        defer p.gpa.free(body);
        const url = try joinPath(p.gpa, p.options.endpoint, action);
        defer p.gpa.free(url);

        var auth_buf: [512]u8 = undefined;
        // The header is the credentials, base64'd: as secret as the password.
        defer std.crypto.secureZero(u8, &auth_buf);
        var headers_buf: [1]http.Header = undefined;
        var headers: []const http.Header = &.{};
        if (p.options.username.len != 0) {
            headers_buf[0] = .{ .name = "Authorization", .value = try basicAuth(&auth_buf, p.options.username, p.options.password) };
            headers = &headers_buf;
        }
        p.last_status = try post(&p.client, p.gpa, url, body, headers);
        return p.last_status;
    }
};

/// `Basic base64(user ":" password)` (RFC 7617). A user-id containing ':'
/// cannot be represented (RFC 7617 §2) and is refused, as are credentials
/// over 379 bytes.
fn basicAuth(buf: *[512]u8, user: []const u8, password: []const u8) error{InvalidCredentials}![]const u8 {
    if (std.mem.findScalar(u8, user, ':') != null) return error.InvalidCredentials;
    var plain: [380]u8 = undefined;
    defer std.crypto.secureZero(u8, &plain);
    const joined = std.mem.print(&plain, "{s}:{s}", .{ user, password }) catch return error.InvalidCredentials;
    // b64ct, not std.base64: the password is secret, and std indexes its
    // encode table by each secret sextet (cache side channel).
    const enc = b64ct.standard;
    const prefix = "Basic ";
    if (prefix.len + enc.encodedLen(joined.len) > buf.len) return error.InvalidCredentials;
    @memcpy(buf[0..prefix.len], prefix);
    return buf[0 .. prefix.len + enc.encode(buf[prefix.len..], joined).len];
}

/// `endpoint` + "/" + `segment`, the segment inserted before any query or
/// fragment (lego joins with `URL.JoinPath`, which keeps them).
fn joinPath(gpa: std.mem.Allocator, endpoint: []const u8, segment: []const u8) error{OutOfMemory}![]u8 {
    const cut = std.mem.findAny(u8, endpoint, "?#") orelse endpoint.len;
    return gpa.print("{s}/{s}{s}", .{ std.mem.trimEnd(u8, endpoint[0..cut], "/"), segment, endpoint[cut..] });
}

/// POST a JSON body; return the status (the body is drained and dropped).
fn post(client: *http.Client, gpa: std.mem.Allocator, url: []const u8, body: []const u8, extra: []const http.Header) !u16 {
    var headers: [4]http.Header = undefined;
    headers[0] = .{ .name = "Content-Type", .value = "application/json" };
    if (extra.len > headers.len - 1) return error.NoSpaceLeft;
    @memcpy(headers[1..][0..extra.len], extra);
    var res = try client.request(.post, url, .{
        .headers = headers[0 .. 1 + extra.len],
        .body = body,
        // A publisher talks to one configured endpoint; a redirect elsewhere
        // would carry the credentials along.
        .follow_redirects = false,
    });
    defer res.deinit();
    const drained = try res.readAllAlloc(gpa, 64 * 1024);
    gpa.free(drained);
    return res.status;
}

// ── exec ────────────────────────────────────────────────────────────────────

pub const Exec = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    options: Options,
    note: []const u8 = "",
    /// The last run's exit, for the caller's log.
    last_term: ?procrun.Term = null,
    /// The tail of the last run's stderr (what the program said on failure).
    stderr_buf: [512]u8 = undefined,
    stderr_len: usize = 0,

    pub fn lastStderr(p: *const Exec) []const u8 {
        return p.stderr_buf[0..p.stderr_len];
    }

    pub const Mode = enum {
        /// `<program> present <fqdn.> <value>` — lego's default.
        default,
        /// `<program> present -- <domain> <token> <keyAuth>` — lego RAW.
        raw,
    };

    /// The program inherits the environment of the `std.Io` this publisher
    /// was given: a `std.Io.Threaded` built without `.environ =
    /// init.environ` spawns it with an EMPTY environment (Zig 0.16).
    pub const Options = struct {
        program: []const u8,
        mode: Mode = .default,
        /// Kill the program after this long (lego: propagation timeout).
        timeout_ms: u32 = 60_000,
    };

    pub fn init(io: std.Io, gpa: std.mem.Allocator, options: Options) Exec {
        return .{ .gpa = gpa, .io = io, .options = options };
    }

    pub fn publisher(p: *Exec) root.Publisher {
        return .{ .ctx = p, .present = present, .cleanup = cleanup };
    }

    fn present(ctx: ?*anyopaque, rec: *const Record) PublishError!void {
        const p: *Exec = @ptrCast(@alignCast(ctx.?));
        p.note = "";
        const ok = p.run("present", rec) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                p.note = "the program could not be started";
                return error.PublishFailed;
            },
        };
        if (!ok) {
            p.note = "the program did not exit 0 (see last_term)";
            return error.PublishFailed;
        }
    }

    fn cleanup(ctx: ?*anyopaque, rec: *const Record) void {
        const p: *Exec = @ptrCast(@alignCast(ctx.?));
        _ = p.run("cleanup", rec) catch {};
    }

    fn run(p: *Exec, action: []const u8, rec: *const Record) !bool {
        var fqdn_buf: [zone.max_name_len + 1]u8 = undefined;
        const fqdn = try std.mem.print(&fqdn_buf, "{s}.", .{zone.trimDot(rec.fqdn)});
        const default_argv = [_][]const u8{ p.options.program, action, fqdn, rec.value };
        const raw_argv = [_][]const u8{ p.options.program, action, "--", rec.domain, rec.token, rec.key_authorization };
        const argv: []const []const u8 = switch (p.options.mode) {
            .default => &default_argv,
            .raw => &raw_argv,
        };
        var out = try procrun.runTimeout(p.gpa, p.io, .{
            .argv = argv,
            .new_process_group = true,
            .max_output_bytes = 64 * 1024,
        }, "", @as(u64, p.options.timeout_ms) * std.time.ns_per_ms);
        defer out.deinit(p.gpa);
        p.last_term = out.term;
        const tail = out.stderr[out.stderr.len -| p.stderr_buf.len..];
        @memcpy(p.stderr_buf[0..tail.len], tail);
        p.stderr_len = tail.len;
        return switch (out.term) {
            .exited => |code| code == 0,
            else => false,
        };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "basicAuth: RFC 7617 §2 example" {
    var buf: [512]u8 = undefined;
    try testing.expectEqualStrings("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", try basicAuth(&buf, "Aladdin", "open sesame"));
    const long: [400]u8 = @splat('x');
    try testing.expectError(error.InvalidCredentials, basicAuth(&buf, &long, "p"));
    try testing.expectError(error.InvalidCredentials, basicAuth(&buf, "us:er", "p"));
}

test "joinPath: the segment goes before a query or fragment (lego URL.JoinPath)" {
    const gpa = testing.allocator;
    const cases = [_][3][]const u8{
        .{ "https://h/api", "present", "https://h/api/present" },
        .{ "https://h/api/", "present", "https://h/api/present" },
        .{ "https://h/api?token=x", "present", "https://h/api/present?token=x" },
        .{ "https://h/api/?token=x#f", "cleanup", "https://h/api/cleanup?token=x#f" },
        .{ "https://h", "update", "https://h/update" },
    };
    for (cases) |c| {
        const got = try joinPath(gpa, c[0], c[1]);
        defer gpa.free(got);
        try testing.expectEqualStrings(c[2], got);
    }
}
