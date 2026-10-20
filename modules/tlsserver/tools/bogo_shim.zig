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
//! Only server tests at TLS 1.3 run: a client test, a resumption, a version
//! range without TLS 1.3, or any feature the server lacks is exit 89.

const std = @import("std");
const net = std.Io.net;
const tlsserver = @import("tlsserver");

const record = tlsserver.record;
const server_mod = tlsserver.server;

pub const exit_unimplemented: u8 = 89;

/// Whether `args` (after argv[0]) is the runner starting a shim.
pub fn isShimInvocation(first: ?[]const u8) bool {
    const a = first orelse return false;
    return std.mem.eql(u8, a, "-port") or std.mem.eql(u8, a, "-is-handshaker-supported");
}

const Options = struct {
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
};

const Unimplemented = error{Unimplemented};

/// Flags that change nothing here: the versions below TLS 1.3 (never
/// spoken); `-async` (BoringSSL's own callbacks returning "retry"; the
/// sans-I/O core has no such retries to exercise, so the protocol is the
/// same); `-implicit-handshake` (`Connection.read` runs the handshake);
/// `-expect-no-session-id` (no stateful session cache, so never an ID).
const ignored_flags = [_][]const u8{
    "-no-tls1", "-no-tls11", "-no-tls12", "-no-ssl3", "-async", "-implicit-handshake", "-expect-no-session-id",
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

fn parseArgs(gpa: std.mem.Allocator, it: *std.process.Args.Iterator, o: *Options) !void {
    while (it.next()) |flag| {
        const value = struct {
            fn f(i: *std.process.Args.Iterator, name: []const u8) ![]const u8 {
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
            if (try std.fmt.parseInt(u32, try value(it, flag), 10) != 0) return unimplemented(flag);
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
        } else {
            for (ignored_flags) |f| {
                if (std.mem.eql(u8, flag, f)) break;
            } else return unimplemented(flag);
        }
    }
}

fn readFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20));
}

/// Run as the shim; the process's exit status.
pub fn run(gpa: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, args: *std.process.Args.Iterator) u8 {
    var o: Options = .{};
    parseArgs(gpa, args, &o) catch |err| return switch (err) {
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
    serve(gpa, io, &o) catch |err| {
        // A credential the module cannot load (P-521, ML-DSA, …) is a
        // feature it lacks, not a failure.
        if (err == error.UnsupportedKey) {
            unimplemented("(credential key type)") catch {};
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

fn serve(gpa: std.mem.Allocator, io: std.Io, o: *const Options) !void {
    const cert_pem = try readFile(gpa, io, o.cert_file orelse return error.NoCertificate);
    const key_pem = try readFile(gpa, io, o.key_file orelse return error.NoKey);
    var pair: tlsserver.keys.CertKeyPair = undefined;
    try tlsserver.keys.CertKeyPair.fromPem(&pair, gpa, cert_pem, key_pem);
    defer pair.deinit(gpa);
    const ck = pair.certifiedKey();

    var seed: [32]u8 = undefined;
    io.randomSecure(&seed) catch return error.NoEntropy;
    var csprng = std.Random.DefaultCsprng.init(seed);
    const cfg: server_mod.Config = .{
        .certificate = .{ .fixed = &ck },
        .groups = if (o.groups.items.len != 0) o.groups.items else &server_mod.default_groups,
        .alpn_protocols = o.alpn.items,
        .random = csprng.random(),
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
    const out = try gpa.alloc(u8, server_mod.minOutputLen(&ck) + 4096);
    defer gpa.free(out);
    var c: tlsserver.Connection = .init(&cfg, &sr.interface, &sw.interface, joiner, out);
    defer c.deinit();
    defer peer_alert = c.server.inbound.peer_alert;

    try c.handshake();
    if (o.expect_server_name) |want| {
        const got = c.server.serverName() orelse return error.ServerNameMissing;
        if (!std.mem.eql(u8, got, want)) return error.ServerNameMismatch;
    }
    if (o.expect_curve_id) |want| if (c.server.negotiatedGroup() != want) return error.CurveMismatch;
    if (o.key_update) try c.keyUpdate(.update_not_requested);
    if (o.shim_writes_first) try c.writeAll("hello");
    if (o.shim_shuts_down) {
        try c.close();
        // Read to the runner's close_notify.
        while (try c.read()) |_| {}
        return;
    }
    var echo: [record.max_plaintext_len]u8 = undefined;
    while (true) {
        if (o.key_update_before_read) try c.keyUpdate(.update_not_requested);
        const d = try c.read() orelse break;
        for (echo[0..d.len], d) |*e, b| e.* = b ^ 0xff;
        try c.writeAll(echo[0..d.len]);
    }
    try c.close();
}
