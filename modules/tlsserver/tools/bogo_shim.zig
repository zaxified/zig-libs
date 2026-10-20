// SPDX-License-Identifier: MIT

//! The BoGo shim: `tlsserver` as the program BoringSSL's test runner
//! (`ssl/test/runner`) drives. `tools/interop.zig --bogo` builds the runner
//! and hands it its own executable as `-shim-path`; when the runner starts
//! that executable with `-port …` this file takes over (`isShimInvocation`).
//!
//! The contract (runner at BoringSSL 784fcafc, `runner.go:1356` newShimProcess,
//! `shim_dispatcher.go`, `runner.go:1158` doExchange, `runner.go:1888` exit
//! codes):
//!
//! - argv: `-port N -shim-id ID [-ipv6]`, `-server` for a server test, then
//!   the test's flags and the credential (`-cert-file`, `-key-file`);
//! - the shim connects to `[::1]:N` (or 127.0.0.1 without `-ipv6`), sends
//!   the shim ID as 8 octets little-endian, then speaks TLS;
//! - the runner sends each test message; the shim echoes it with every octet
//!   XOR 0xff, until the runner's close_notify;
//! - a flag the shim does not implement exits 89 (the runner counts the test
//!   as skipped); a failure prints `:<error>:` to stderr (the config's
//!   `ErrorMap` relates BoringSSL's error names to ours) and exits 1; a
//!   success prints nothing to stderr (the runner fails a passing test that
//!   wrote any);
//! - `-is-handshaker-supported` prints "No" (no split handshakes).
//!
//! - `-resume-count N`: N more connections after the first, each starting
//!   with the shim ID again, sharing one ticket key; a flag prefixed
//!   `-on-initial-` or `-on-resume-` applies to the first or to the later
//!   ones only. The first must not resume; a later one must, unless
//!   `-expect-session-miss`.
//!
//! - client certificates: `-require-any-client-certificate` (mandatory) and
//!   `-verify-peer` (optional) with BoringSSL's shim verifier, which accepts
//!   any chain unless `-verify-fail`; `-verify-prefs` are the
//!   CertificateRequest's schemes, `-use-client-ca-list` its CA names
//!   (hex DER, comma-separated; `<NULL>` / `<EMPTY>`: none);
//!   `-expect-peer-cert-file` compares the leaf (a file with a chain is exit
//!   89: the server keeps only the leaf); `-trust-cert` makes the verifier
//!   `X509Verifier` over that file's certificates (clientAuth, the wall
//!   clock), as BoringSSL's X.509 verification with `SSL_VERIFY_PEER`.
//!
//! - the ClientHello is seen through `Config.certificate.select` (BoringSSL's
//!   early callback, so `-use-early-callback` changes nothing): it checks
//!   `-expect-advertised-alpn` (the client's protocol list on the wire) and
//!   `-expect-peer-verify-pref` (its `signature_algorithms`, in order).
//!
//! - `-resumption-delay S` moves the ticket clock S seconds forward before
//!   each resumption (BoringSSL's shim clock); `-expect-ticket-age-skew`
//!   compares `Server.ticketAgeSkew`.
//!
//! - `-decline-alpn` is a server without protocols (no ALPN, whatever the
//!   client offers); `-reject-alpn` one whose protocols no client offers
//!   (`no_application_protocol` when the client sends ALPN) — what
//!   BoringSSL's callback returning NOACK / ALERT_FATAL does.
//!
//! Only server tests at TLS 1.3 run: a client test, a version range without
//! TLS 1.3, or any feature the server lacks is exit 89.

const std = @import("std");
const net = std.Io.net;
const tlsserver = @import("tlsserver");
const tlsresume = @import("tlsresume");

const record = tlsserver.record;
const server_mod = tlsserver.server;

pub const exit_unimplemented: u8 = 89;

/// Whether `args` (after argv[0]) is the runner starting a shim.
pub fn isShimInvocation(first: ?[]const u8) bool {
    const a = first orelse return false;
    return std.mem.eql(u8, a, "-port") or std.mem.eql(u8, a, "-is-handshaker-supported");
}

const Options = struct {
    resume_count: u32 = 0,
    expect_session_miss: bool = false,
    port: u16 = 0,
    shim_id: u64 = 0,
    ipv6: bool = false,
    handshaker_probe: bool = false,
    server: bool = false,
    cert_file: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
    shim_writes_first: bool = false,
    shim_shuts_down: bool = false,
    /// BoringSSL `SSL_key_update(NOT_REQUESTED)` once after the handshake,
    /// or before every read.
    key_update: bool = false,
    key_update_before_read: bool = false,
    expect_server_name: ?[]const u8 = null,
    expect_curve_id: ?u16 = null,
    alpn: std.ArrayList([]const u8) = .empty,
    groups: std.ArrayList(u16) = .empty,
    client_auth: enum { off, optional, mandatory } = .off,
    verify_fail: bool = false,
    verify_prefs: std.ArrayList(u16) = .empty,
    ca_names: std.ArrayList([]const u8) = .empty,
    expect_peer_signature_algorithm: ?u16 = null,
    expect_peer_cert_file: ?[]const u8 = null,
    trust_cert: ?[]const u8 = null,
    /// The credential's OCSP staple and SCT list (base64 on the command line).
    ocsp_response: ?[]const u8 = null,
    sct_list: ?[]const u8 = null,
    expect_hrr: ?bool = null,
    signing_prefs: std.ArrayList(u16) = .empty,
    server_preference: bool = false,
    max_send_fragment: ?u16 = null,
    no_ticket: bool = false,
    resumption_delay_s: i64 = 0,
    expect_ticket_age_skew: ?i64 = null,
    expect_advertised_alpn: ?[]const u8 = null,
    alpn_mode: enum { select, decline, reject } = .select,
    expect_peer_verify_prefs: std.ArrayList(u16) = .empty,
};

const Unimplemented = error{Unimplemented};

/// Flags that change nothing here: the versions below TLS 1.3 (never
/// spoken); `-async` (BoringSSL's own callbacks returning "retry"; the
/// sans-I/O core has no such retries to exercise, so the protocol is the
/// same); `-implicit-handshake` (`Connection.read` runs the handshake);
/// `-expect-no-session-id` (no stateful session cache, so never an ID);
/// `-expect-verify-result` (OpenSSL's verify result: a handshake that
/// completed verified, or had nothing to verify); `-use-custom-verify-callback`
/// (the shim's verifier is always a callback); `-use-early-callback` (the
/// ClientHello always goes through `Config.certificate.select`);
/// `-expect-extended-master-secret` (BoringSSL `SSL_get_extms_support`
/// reports TLS 1.3 as having it: its key schedule hashes the transcript);
/// `-enable-ocsp-stapling` (a client's request for a staple; a server
/// staples what its `CertifiedKey` holds, and refuses an extension on the
/// client's Certificate whatever it enabled).
const ignored_flags = [_][]const u8{
    "-no-tls1",              "-no-tls11",                   "-no-tls12",           "-no-ssl3",                       "-async",                "-implicit-handshake", "-expect-no-session-id",
    "-expect-verify-result", "-use-custom-verify-callback", "-use-early-callback", "-expect-extended-master-secret", "-enable-ocsp-stapling",
};

/// The flag that made this run exit 89, for `run` to log.
var unimplemented_flag: []const u8 = "";

fn unimplemented(flag: []const u8) Unimplemented {
    std.debug.print("unimplemented flag: {s}\n", .{flag});
    unimplemented_flag = flag;
    return error.Unimplemented;
}

/// With `TLSSERVER_BOGO_LOG=<dir>` (set by `interop.zig --bogo`), each exit
/// 89 leaves one file there (named by the process id: the workers run in
/// parallel and std has no append mode) holding the flag — the runner
/// reports a skip without the shim's stderr, so these are the triage list
/// of what is missing.
fn logUnimplemented(io: std.Io, environ: *const std.process.Environ.Map) void {
    const dir_path = environ.get("TLSSERVER_BOGO_LOG") orelse return;
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{}) catch return;
    defer dir.close(io);
    var name: [24]u8 = undefined;
    const n = std.mem.print(&name, "{d}", .{std.os.linux.getpid()}) catch return;
    dir.writeFile(io, .{ .sub_path = n, .data = unimplemented_flag }) catch {};
}

/// The arguments, walked once per connection kind.
const Tokens = struct {
    toks: []const []const u8,
    at: usize = 0,

    fn next(t: *Tokens) ?[]const u8 {
        if (t.at == t.toks.len) return null;
        defer t.at += 1;
        return t.toks[t.at];
    }
};

/// `initial` gets every flag but the `-on-resume-` ones, `resumed` every
/// flag but the `-on-initial-` ones (without the prefix).
fn parseArgs(gpa: std.mem.Allocator, it: *std.process.Args.Iterator, initial: *Options, resumed: *Options) !void {
    var list: std.ArrayList([]const u8) = .empty;
    while (it.next()) |a| try list.append(gpa, a);
    var t: Tokens = .{ .toks = list.items };
    while (t.next()) |raw| {
        const start = t.at;
        if (std.mem.startsWith(u8, raw, "-on-initial-")) {
            try parseFlag(gpa, raw["-on-initial".len..], &t, initial);
        } else if (std.mem.startsWith(u8, raw, "-on-resume-")) {
            try parseFlag(gpa, raw["-on-resume".len..], &t, resumed);
        } else if (std.mem.startsWith(u8, raw, "-on-")) {
            return unimplemented(raw);
        } else {
            try parseFlag(gpa, raw, &t, initial);
            t.at = start;
            try parseFlag(gpa, raw, &t, resumed);
        }
    }
}

fn parseFlag(gpa: std.mem.Allocator, flag: []const u8, it: *Tokens, o: *Options) !void {
    {
        const value = struct {
            fn f(i: *Tokens, name: []const u8) ![]const u8 {
                return i.next() orelse {
                    std.debug.print("flag {s} needs a value\n", .{name});
                    return error.BadArgs;
                };
            }
        }.f;
        if (std.mem.eql(u8, flag, "-port")) {
            o.port = try std.fmt.parseInt(u16, try value(it, flag), 10);
        } else if (std.mem.eql(u8, flag, "-shim-id")) {
            o.shim_id = try std.fmt.parseInt(u64, try value(it, flag), 10);
        } else if (std.mem.eql(u8, flag, "-is-handshaker-supported")) {
            o.handshaker_probe = true;
        } else if (std.mem.eql(u8, flag, "-ipv6")) {
            o.ipv6 = true;
        } else if (std.mem.eql(u8, flag, "-server")) {
            o.server = true;
        } else if (std.mem.eql(u8, flag, "-cert-file")) {
            o.cert_file = try value(it, flag);
        } else if (std.mem.eql(u8, flag, "-key-file")) {
            o.key_file = try value(it, flag);
        } else if (std.mem.eql(u8, flag, "-shim-writes-first")) {
            o.shim_writes_first = true;
        } else if (std.mem.eql(u8, flag, "-shim-shuts-down")) {
            o.shim_shuts_down = true;
        } else if (std.mem.eql(u8, flag, "-key-update")) {
            o.key_update = true;
        } else if (std.mem.eql(u8, flag, "-key-update-before-read")) {
            o.key_update_before_read = true;
        } else if (std.mem.eql(u8, flag, "-expect-server-name")) {
            o.expect_server_name = try value(it, flag);
        } else if (std.mem.eql(u8, flag, "-resume-count")) {
            o.resume_count = try std.fmt.parseInt(u32, try value(it, flag), 10);
        } else if (std.mem.eql(u8, flag, "-expect-session-miss")) {
            o.expect_session_miss = true;
        } else if (std.mem.eql(u8, flag, "-max-version")) {
            if (try std.fmt.parseInt(u16, try value(it, flag), 10) < 0x0304) return unimplemented(flag);
        } else if (std.mem.eql(u8, flag, "-min-version")) {
            if (try std.fmt.parseInt(u16, try value(it, flag), 10) > 0x0304) return unimplemented(flag);
        } else if (std.mem.eql(u8, flag, "-curves")) {
            const g = try std.fmt.parseInt(u16, try value(it, flag), 10);
            if (std.mem.indexOfScalar(u16, &server_mod.default_groups, g) == null) return unimplemented(flag);
            try o.groups.append(gpa, g);
        } else if (std.mem.eql(u8, flag, "-expect-curve-id")) {
            o.expect_curve_id = try std.fmt.parseInt(u16, try value(it, flag), 10);
        } else if (std.mem.eql(u8, flag, "-select-alpn")) {
            try o.alpn.append(gpa, try value(it, flag));
        } else if (std.mem.eql(u8, flag, "-require-any-client-certificate")) {
            o.client_auth = .mandatory;
        } else if (std.mem.eql(u8, flag, "-verify-peer")) {
            if (o.client_auth == .off) o.client_auth = .optional;
        } else if (std.mem.eql(u8, flag, "-verify-fail")) {
            o.verify_fail = true;
        } else if (std.mem.eql(u8, flag, "-verify-prefs")) {
            // 0xff01 is BoringSSL's internal RSA PKCS#1 MD5-SHA1 (TLS 1.0
            // and 1.1), which it never names in a TLS 1.3 CertificateRequest.
            const v = try std.fmt.parseInt(u16, try value(it, flag), 10);
            if (v != 0xff01) try o.verify_prefs.append(gpa, v);
        } else if (std.mem.eql(u8, flag, "-expect-peer-signature-algorithm")) {
            o.expect_peer_signature_algorithm = try std.fmt.parseInt(u16, try value(it, flag), 10);
        } else if (std.mem.eql(u8, flag, "-trust-cert")) {
            // The runner passes its credential's root, "" for one without
            // (the garbage certificate): no anchor, as BoringSSL's shim.
            const v = try value(it, flag);
            o.trust_cert = if (v.len == 0) null else v;
        } else if (std.mem.eql(u8, flag, "-ocsp-response")) {
            o.ocsp_response = try base64(gpa, try value(it, flag));
        } else if (std.mem.eql(u8, flag, "-signed-cert-timestamps")) {
            o.sct_list = try base64(gpa, try value(it, flag));
        } else if (std.mem.eql(u8, flag, "-expect-peer-cert-file")) {
            o.expect_peer_cert_file = try value(it, flag);
        } else if (std.mem.eql(u8, flag, "-expect-hrr")) {
            o.expect_hrr = true;
        } else if (std.mem.eql(u8, flag, "-expect-no-hrr")) {
            o.expect_hrr = false;
        } else if (std.mem.eql(u8, flag, "-signing-prefs")) {
            try o.signing_prefs.append(gpa, try std.fmt.parseInt(u16, try value(it, flag), 10));
        } else if (std.mem.eql(u8, flag, "-server-preference")) {
            o.server_preference = true;
        } else if (std.mem.eql(u8, flag, "-max-send-fragment")) {
            const v = try std.fmt.parseInt(u16, try value(it, flag), 10);
            // Below BoringSSL's floor the module clamps: not what was asked.
            if (v < tlsserver.outbound.min_fragment) return unimplemented(flag);
            o.max_send_fragment = v;
        } else if (std.mem.eql(u8, flag, "-read-size")) {
            // How much the shim reads at a time: `Connection` reads what the
            // socket has, which covers every size.
            _ = try value(it, flag);
        } else if (std.mem.eql(u8, flag, "-no-ticket")) {
            o.no_ticket = true;
        } else if (std.mem.eql(u8, flag, "-resumption-delay")) {
            o.resumption_delay_s = try std.fmt.parseInt(i64, try value(it, flag), 10);
        } else if (std.mem.eql(u8, flag, "-expect-ticket-age-skew")) {
            o.expect_ticket_age_skew = try std.fmt.parseInt(i64, try value(it, flag), 10);
        } else if (std.mem.eql(u8, flag, "-expect-early-data-reason")) {
            // Early data is never accepted: `disabled` is the only reason
            // there is (the server enables none).
            if (!std.mem.eql(u8, try value(it, flag), "disabled")) return unimplemented(flag);
        } else if (std.mem.eql(u8, flag, "-expect-advertised-alpn")) {
            o.expect_advertised_alpn = try value(it, flag);
        } else if (std.mem.eql(u8, flag, "-decline-alpn")) {
            o.alpn_mode = .decline;
        } else if (std.mem.eql(u8, flag, "-reject-alpn")) {
            o.alpn_mode = .reject;
        } else if (std.mem.eql(u8, flag, "-expect-peer-verify-pref")) {
            try o.expect_peer_verify_prefs.append(gpa, try std.fmt.parseInt(u16, try value(it, flag), 10));
        } else if (std.mem.eql(u8, flag, "-use-client-ca-list")) {
            const v = try value(it, flag);
            if (!std.mem.eql(u8, v, "<NULL>") and !std.mem.eql(u8, v, "<EMPTY>")) {
                var names = std.mem.splitScalar(u8, v, ',');
                while (names.next()) |h| {
                    const der = try gpa.alloc(u8, h.len / 2);
                    _ = try std.fmt.hexToBytes(der, h);
                    try o.ca_names.append(gpa, der);
                }
            }
        } else {
            for (ignored_flags) |f| {
                if (std.mem.eql(u8, flag, f)) break;
            } else return unimplemented(flag);
        }
    }
}

fn base64(gpa: std.mem.Allocator, text: []const u8) ![]u8 {
    const D = std.base64.standard.Decoder;
    const out = try gpa.alloc(u8, try D.calcSizeForSlice(text));
    try D.decode(out, text);
    return out;
}

fn readFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20));
}

/// Run as the shim; the process's exit status.
pub fn run(gpa: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, args: *std.process.Args.Iterator) u8 {
    var o: Options = .{};
    var on_resume: Options = .{};
    parseArgs(gpa, args, &o, &on_resume) catch |err| return switch (err) {
        error.Unimplemented => blk: {
            logUnimplemented(io, environ);
            break :blk exit_unimplemented;
        },
        else => blk: {
            std.debug.print("bad arguments: {t}\n", .{err});
            break :blk 1;
        },
    };
    // The startup probe (`runner.go:2070`).
    if (o.handshaker_probe) {
        std.Io.File.stdout().writeStreamingAll(io, "No\n") catch return 1;
        return 0;
    }
    if (!o.server) {
        unimplemented("(client test)") catch {};
        logUnimplemented(io, environ);
        return exit_unimplemented;
    }
    serve(gpa, io, &o, &on_resume) catch |err| {
        // A credential the module cannot load (P-521, ML-DSA, …) is a
        // feature it lacks, not a failure.
        if (err == error.UnsupportedKey or err == error.Unimplemented) {
            if (err == error.UnsupportedKey) unimplemented("(credential key type)") catch {};
            logUnimplemented(io, environ);
            return exit_unimplemented;
        }
        // BoringSSL names a received alert by its description
        // (`:SSLV3_ALERT_HANDSHAKE_FAILURE:`); the ErrorMap matches
        // `alert=<name>`.
        if (peer_alert) |d| {
            std.debug.print(":{t}: alert={s}\n", .{ err, std.enums.tagName(tlsserver.alert.Description, d) orelse "unknown" });
        } else std.debug.print(":{t}:\n", .{err});
        return 1;
    };
    return 0;
}

/// The alert the client sent, if a failure came from one.
var peer_alert: ?tlsserver.alert.Description = null;

/// The shim's clock: the wall clock, moved forward by `-resumption-delay`.
const ShimClock = struct {
    io: std.Io,
    offset_ms: i64 = 0,

    fn clock(self: *ShimClock) server_mod.Clock {
        return .{ .ctx = self, .now_ms = nowMs };
    }

    fn nowMs(ctx: ?*anyopaque) i64 {
        const self: *ShimClock = @ptrCast(@alignCast(ctx.?));
        return std.Io.Clock.real.now(self.io).toMilliseconds() + self.offset_ms;
    }
};

/// The ClientHello as BoringSSL's early callback sees it: what the
/// `-expect-advertised-alpn` and `-expect-peer-verify-pref` flags check,
/// reported after the handshake (the callback can only refuse).
const HelloCheck = struct {
    key: *const tlsserver.CertifiedKey,
    o: *const Options,
    failure: ?anyerror = null,

    fn select(ctx: ?*anyopaque, _: ?[]const u8, ch: *const tlsserver.hello.ClientHello) ?*const tlsserver.CertifiedKey {
        const self: *HelloCheck = @ptrCast(@alignCast(ctx.?));
        if (self.o.expect_advertised_alpn) |want| {
            if (!std.mem.eql(u8, ch.alpn_raw orelse "", want)) self.failure = error.AdvertisedAlpnMismatch;
        }
        if (self.o.expect_peer_verify_prefs.items.len != 0) {
            var it = ch.signatureAlgorithms() orelse return self.refuse(error.PeerVerifyPrefsMismatch);
            for (self.o.expect_peer_verify_prefs.items) |want| {
                if (it.next() != want) self.failure = error.PeerVerifyPrefsMismatch;
            }
            if (it.next() != null) self.failure = error.PeerVerifyPrefsMismatch;
        }
        return self.key;
    }

    fn refuse(self: *HelloCheck, err: anyerror) ?*const tlsserver.CertifiedKey {
        self.failure = err;
        return self.key;
    }
};

/// BoringSSL's shim verifier: any chain, unless `-verify-fail`.
const ShimVerifier = struct {
    fn accept(_: ?*const anyopaque, _: []const []const u8, _: i64) tlsserver.clientauth.VerifyError!void {}
    fn refuse(_: ?*const anyopaque, _: []const []const u8, _: i64) tlsserver.clientauth.VerifyError!void {
        return error.CertificateUnknown;
    }
};

/// Every certificate of a PEM file (DER), in order.
fn pemCertificates(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]const []const u8 {
    const text = try readFile(gpa, io, path);
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    var out: std.ArrayList([]const u8) = .empty;
    var at: usize = 0;
    while (std.mem.findPos(u8, text, at, begin)) |a| {
        const b = std.mem.findPos(u8, text, a, end) orelse return error.TruncatedPem;
        var b64: std.ArrayList(u8) = .empty;
        for (text[a + begin.len .. b]) |ch| if (!std.ascii.isWhitespace(ch)) try b64.append(gpa, ch);
        const D = std.base64.standard.Decoder;
        const der = try gpa.alloc(u8, try D.calcSizeForSlice(b64.items));
        try D.decode(der, b64.items);
        try out.append(gpa, der);
        at = b + end.len;
    }
    if (out.items.len == 0) return error.NoCertificateInFile;
    return out.items;
}

/// The leaf of a PEM file, if it holds exactly one certificate.
fn singlePemCertificate(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]const u8 {
    const all = try pemCertificates(gpa, io, path);
    if (all.len != 1) return unimplemented("-expect-peer-cert-file (a chain)");
    return all[0];
}

fn serve(gpa: std.mem.Allocator, io: std.Io, initial: *const Options, on_resume: *const Options) !void {
    const cert_pem = try readFile(gpa, io, initial.cert_file orelse return error.NoCertificate);
    const key_pem = try readFile(gpa, io, initial.key_file orelse return error.NoKey);
    var pair: tlsserver.keys.CertKeyPair = undefined;
    try tlsserver.keys.CertKeyPair.fromPem(&pair, gpa, cert_pem, key_pem);
    defer pair.deinit(gpa);
    const ck = pair.certifiedKey();

    var seed: [32]u8 = undefined;
    io.randomSecure(&seed) catch return error.NoEntropy;
    var csprng = std.Random.DefaultCsprng.init(seed);

    // One ticket key for every connection of this run (BoringSSL's
    // SSL_CTX), installed now.
    var ring: tlsresume.stek.DefaultRing = .init();
    var stek_key: [32]u8 = undefined;
    csprng.random().bytes(&stek_key);
    var clock: ShimClock = .{ .io = io };
    ring.rotate(1, &stek_key, @divFloor(ShimClock.nowMs(&clock), 1000));
    const stek: server_mod.StekTicketer(tlsresume.stek.DefaultRing) = .{ .ring = &ring };
    const tickets: server_mod.Tickets = .{ .ticketer = stek.ticketer(), .clock = clock.clock() };

    for (0..initial.resume_count + 1) |i| {
        const o = if (i == 0) initial else on_resume;
        // BoringSSL's shim advances its clock after each connection.
        if (i != 0) clock.offset_ms += initial.resumption_delay_s * 1000;
        const resumed = try connection(gpa, io, &ck, if (o.no_ticket) null else &tickets, csprng.random(), o, &clock);
        const want = i != 0 and !o.expect_session_miss;
        if (resumed != want) return if (resumed) error.UnexpectedSessionReuse else error.SessionNotReused;
    }
}

/// One connection; whether it resumed a session.
fn connection(gpa: std.mem.Allocator, io: std.Io, ck: *const tlsserver.CertifiedKey, tickets: ?*const server_mod.Tickets, random: std.Random, o: *const Options, clock: *ShimClock) !bool {
    const want_peer: ?[]const u8 = if (o.expect_peer_cert_file) |f| try singlePemCertificate(gpa, io, f) else null;
    const x509_verifier: tlsserver.X509Verifier = .{
        .gpa = gpa,
        .anchors = if (o.trust_cert) |f| try pemCertificates(gpa, io, f) else &.{},
    };
    const client_auth: server_mod.ClientAuth = .{
        .verifier = if (o.verify_fail)
            .{ .verify = ShimVerifier.refuse }
        else if (o.trust_cert != null)
            x509_verifier.verifier()
        else
            .{ .verify = ShimVerifier.accept },
        .mandatory = o.client_auth == .mandatory,
        .schemes = if (o.verify_prefs.items.len != 0) o.verify_prefs.items else &server_mod.default_client_auth_schemes,
        .authorities = o.ca_names.items,
        .clock = clock.clock(),
    };
    var leaf = ck.*;
    leaf.ocsp_response = o.ocsp_response;
    leaf.sct_list = o.sct_list;
    if (o.signing_prefs.items.len != 0) leaf.signature_schemes = o.signing_prefs.items;
    try leaf.check();
    var hello_check: HelloCheck = .{ .key = &leaf, .o = o };
    const cfg: server_mod.Config = .{
        .certificate = .{ .select = .{ .ctx = &hello_check, .select = HelloCheck.select } },
        .groups = if (o.groups.items.len != 0) o.groups.items else &server_mod.default_groups,
        .server_order = o.server_preference,
        .max_fragment_len = o.max_send_fragment orelse tlsserver.record.max_plaintext_len,
        .alpn_protocols = switch (o.alpn_mode) {
            .select => o.alpn.items,
            .decline => &.{},
            .reject => &.{"tlsserver-bogo-shim-rejects-every-protocol"},
        },
        .random = random,
        .tickets = tickets,
        .client_auth = if (o.client_auth != .off) &client_auth else null,
    };

    const addr: net.IpAddress = if (o.ipv6) .{ .ip6 = .loopback(o.port) } else .{ .ip4 = .loopback(o.port) };
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var rbuf: [record.max_record_len]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var wbuf: [4096]u8 = undefined;
    var sw = stream.writer(io, &wbuf);
    var id: [8]u8 = undefined;
    std.mem.writeInt(u64, &id, o.shim_id, .little);
    try sw.interface.writeAll(&id);
    try sw.interface.flush();

    const joiner = try gpa.alloc(u8, tlsserver.inbound.Joiner.bufferLen(tlsserver.inbound.default_max_message));
    defer gpa.free(joiner);
    const out = try gpa.alloc(u8, server_mod.minOutputLen(&cfg, &leaf) + 4096);
    defer gpa.free(out);
    var c: tlsserver.Connection = .init(&cfg, &sr.interface, &sw.interface, joiner, out);
    defer c.deinit();
    defer peer_alert = c.server.inbound.peer_alert;
    return converse(&c, o, want_peer, &hello_check) catch |err| {
        // A lingering close: the alert is out; closing with the runner's
        // unread records in the receive buffer would send a reset, which
        // can beat the alert to the runner (its next write then fails with
        // EPIPE instead of it reading the alert).
        stream.shutdown(io, .send) catch {};
        // Bounded in time too: a runner that never closes ends the drain
        // after 2 s of silence.
        const tv: std.posix.timeval = .{ .sec = 2, .usec = 0 };
        std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
        var sink: [4096]u8 = undefined;
        var drained: usize = 0;
        while (drained < 1 << 20) {
            const n = sr.interface.readSliceShort(&sink) catch break;
            if (n == 0) break;
            drained += n;
        }
        return err;
    };
}

fn converse(c: *tlsserver.Connection, o: *const Options, want_peer: ?[]const u8, hello_check: *const HelloCheck) !bool {
    try c.handshake();
    if (hello_check.failure) |err| return err;
    if (o.expect_hrr) |want| if (c.server.usedHelloRetryRequest() != want) return error.HelloRetryRequestMismatch;
    // BoringSSL checks the skew on a resumption only, and only a non-zero one.
    if (o.expect_ticket_age_skew) |want| if (want != 0) if (c.server.ticketAgeSkew()) |got| {
        if (got != want) return error.TicketAgeSkewMismatch;
    };
    if (o.expect_server_name) |want| {
        const got = c.server.serverName() orelse return error.ServerNameMissing;
        if (!std.mem.eql(u8, got, want)) return error.ServerNameMismatch;
    }
    if (o.expect_curve_id) |want| if (c.server.negotiatedGroup() != want) return error.CurveMismatch;
    if (want_peer) |want| {
        const got = c.server.peerCertificate() orelse return error.NoPeerCertificate;
        if (!std.mem.eql(u8, got, want)) return error.PeerCertificateMismatch;
    }
    if (o.expect_peer_signature_algorithm) |want| if (c.server.peerSignatureScheme() != want) return error.PeerSignatureAlgorithmMismatch;
    if (o.key_update) try c.keyUpdate(.update_not_requested);
    if (o.shim_writes_first) try c.writeAll("hello");
    if (o.shim_shuts_down) {
        try c.close();
        // Read to the runner's close_notify.
        while (try c.read()) |_| {}
        return c.server.isResumed();
    }
    var echo: [record.max_plaintext_len]u8 = undefined;
    while (true) {
        if (o.key_update_before_read) try c.keyUpdate(.update_not_requested);
        const d = try c.read() orelse break;
        for (echo[0..d.len], d) |*e, b| e.* = b ^ 0xff;
        try c.writeAll(echo[0..d.len]);
    }
    try c.close();
    return c.server.isResumed();
}
