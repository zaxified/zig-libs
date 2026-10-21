// SPDX-License-Identifier: MIT

//! tlsfuzzer (GPL-2.0, executed only, never linked or copied) against
//! `tlsserver` over loopback TCP: `interop-tlsserver --tlsfuzzer DIR`, DIR a
//! tlsfuzzer checkout with a Python that has tlslite-ng and ecdsa (by
//! default `DIR/../venv/bin/python`, the layout qap's
//! `scripts/fetch-conformance-tools.sh tlsfuzzer` leaves).
//!
//! The server: every connection on its own thread, a `Connection` whose
//! certificate is the first of RSA-2048, ECDSA P-256, ECDSA P-384 and
//! Ed25519 the client's `signature_algorithms` allow
//! (`server.firstUsableKey`), session tickets (two per handshake), no ALPN.
//! Three listeners: `plain` asks for no client certificate, `echo` neither
//! and sends application data back as it came, `mtls` asks for an
//! optional one (`X509Verifier` over the test client CA,
//! `tlsserver.test_client_fixtures`, whose certificates and keys are
//! written to the log directory for the scripts' `-c`/`-k`: an argument
//! `@NAME` in the baseline is that file). The application: each "\r\n\r\n"-terminated
//! request gets one HTTP/1.0 response ("GET /keyupdate" a KeyUpdate asking
//! for one back first); the client's close_notify gets ours.
//!
//! The scripts run, and the counts each must give, are in
//! `tools/tlsfuzzer/baseline.tsv` (script, listener, its arguments, `PASS n FAIL m`,
//! why the failures are what they are). More failures than listed is a
//! FAIL; fewer is a NOTE (update the line); a script without a summary is
//! a FAIL.

const std = @import("std");
const net = std.Io.net;
const tlsserver = @import("tlsserver");
const rsa = @import("rsa");
const tlsresume = @import("tlsresume");
const certs = tlsserver.test_fixtures;
const client_certs = tlsserver.test_client_fixtures;

const server_mod = tlsserver.server;
const record = tlsserver.record;

const baseline_path = "modules/tlsserver/tools/tlsfuzzer/baseline.tsv";

/// What every connection shares; read-only after `run` set it up.
const Shared = struct {
    io: std.Io,
    keys: [4]tlsserver.CertifiedKey,
    tickets: server_mod.Tickets,
    clock: Clock,

    fn select(ctx: ?*anyopaque, _: ?[]const u8, ch: *const tlsserver.hello.ClientHello) ?*const tlsserver.CertifiedKey {
        const self: *const Shared = @ptrCast(@alignCast(ctx.?));
        return server_mod.firstUsableKey(&self.keys, ch);
    }
};

const Clock = struct {
    io: std.Io,

    fn nowMs(ctx: ?*anyopaque) i64 {
        const self: *const Clock = @ptrCast(@alignCast(ctx.?));
        return std.Io.Clock.real.now(self.io).toMilliseconds();
    }
};

const Mode = enum { plain, mtls, echo };

/// One listener's server.
const Listener = struct {
    shared: *Shared,
    client_auth: ?*const tlsserver.ClientAuth,
    /// Application data comes back as it is, instead of the HTTP answer.
    echo: bool = false,
};

fn acceptLoop(l: *const Listener, listener: *net.Server) void {
    while (true) {
        const stream = listener.accept(l.shared.io) catch return;
        const t = std.Thread.spawn(.{}, connectionThread, .{ l, stream }) catch {
            stream.close(l.shared.io);
            continue;
        };
        t.detach();
    }
}

fn connectionThread(l: *const Listener, stream: net.Stream) void {
    const shared = l.shared;
    const io = shared.io;
    defer stream.close(io);
    // Per connection: a `std.Random` is not for sharing between threads.
    var seed: [32]u8 = undefined;
    io.randomSecure(&seed) catch return;
    var csprng = std.Random.DefaultCsprng.init(seed);
    const cfg: tlsserver.Config = .{
        .certificate = .{ .select = .{ .ctx = shared, .select = Shared.select } },
        .random = csprng.random(),
        .tickets = &shared.tickets,
        .client_auth = l.client_auth,
    };
    // Room for a full record: `test-tls13-lengths` wants each echo in one.
    var out_len: usize = server_mod.full_record_output_len;
    for (&shared.keys) |*k| out_len = @max(out_len, server_mod.minOutputLen(&cfg, k));
    const gpa = std.heap.page_allocator;
    const joiner = gpa.alloc(u8, tlsserver.inbound.Joiner.bufferLen(tlsserver.inbound.default_max_message)) catch return;
    defer gpa.free(joiner);
    // The writer's buffer is the server's output buffer.
    const wbuf = gpa.alloc(u8, out_len + 4096) catch return;
    defer gpa.free(wbuf);

    var rbuf: [record.max_record_len]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, wbuf);
    var c: tlsserver.Connection = .init(&cfg, &sr.interface, &sw.interface, joiner);
    defer c.deinit();
    (if (l.echo) echo(&c) else converse(&c)) catch {
        // A lingering close (as the BoGo shim's): the alert is out, and
        // closing on unread records would send a reset that can beat it.
        stream.shutdown(io, .send) catch {};
        const tv: std.posix.timeval = .{ .sec = 2, .usec = 0 };
        std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
        var sink: [4096]u8 = undefined;
        var drained: usize = 0;
        while (drained < 1 << 20) {
            const n = sr.interface.readSliceShort(&sink) catch break;
            if (n == 0) break;
            drained += n;
        }
    };
}

const response = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 15\r\n\r\ntlsserver says\n";

/// tlsfuzzer's convention (`test-tls13-keyupdate-from-server.py`): this
/// request gets a KeyUpdate(update_requested) before its response.
const keyupdate_request = "GET /keyupdate ";

/// What `test-tls13-lengths.py` and its kind expect.
fn echo(c: *tlsserver.Connection) !void {
    try c.handshake();
    while (try c.read()) |d| try c.writeAll(d);
    try c.close();
}

fn converse(c: *tlsserver.Connection) !void {
    try c.handshake();
    // The tail of the request so far, enough to find "\r\n\r\n" across
    // reads, and its start, enough to recognise `keyupdate_request`.
    var tail: [3]u8 = @splat(0);
    var head: [keyupdate_request.len]u8 = undefined;
    var head_len: usize = 0;
    while (try c.read()) |d| {
        for (d) |b| {
            if (head_len < head.len) {
                head[head_len] = b;
                head_len += 1;
            }
            const end = tail[0] == '\r' and tail[1] == '\n' and tail[2] == '\r' and b == '\n';
            tail = .{ tail[1], tail[2], b };
            if (!end) continue;
            if (head_len == head.len and std.mem.eql(u8, &head, keyupdate_request)) try c.keyUpdate(.update_requested);
            try c.writeAll(response);
            head_len = 0;
        }
    }
    try c.close();
}

const Entry = struct {
    script: []const u8,
    mode: Mode,
    args: []const []const u8,
    /// Null: any (`PASS *`, a script whose number of conversations is
    /// random by design).
    want_pass: ?u32,
    want_fail: u32,
};

fn parseBaseline(gpa: std.mem.Allocator, text: []const u8) ![]Entry {
    var out: std.ArrayList(Entry) = .empty;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line[0] == '#') continue;
        var cols = std.mem.splitScalar(u8, line, '\t');
        const script = cols.next() orelse return error.BadBaseline;
        const mode = std.meta.stringToEnum(Mode, cols.next() orelse return error.BadBaseline) orelse return error.BadBaseline;
        const args_s = cols.next() orelse return error.BadBaseline;
        const counts = cols.next() orelse return error.BadBaseline;
        var args: std.ArrayList([]const u8) = .empty;
        if (!std.mem.eql(u8, args_s, "-")) {
            var it = std.mem.tokenizeScalar(u8, args_s, ';');
            while (it.next()) |a| try args.append(gpa, a);
        }
        var cit = std.mem.tokenizeScalar(u8, counts, ' ');
        if (!std.mem.eql(u8, cit.next() orelse "", "PASS")) return error.BadBaseline;
        const p_s = cit.next() orelse return error.BadBaseline;
        const p: ?u32 = if (std.mem.eql(u8, p_s, "*")) null else try std.fmt.parseInt(u32, p_s, 10);
        if (!std.mem.eql(u8, cit.next() orelse "", "FAIL")) return error.BadBaseline;
        const f = try std.fmt.parseInt(u32, cit.next() orelse return error.BadBaseline, 10);
        try out.append(gpa, .{ .script = script, .mode = mode, .args = args.items, .want_pass = p, .want_fail = f });
    }
    return out.items;
}

/// The number after `label` at the start of a line of `out`.
fn summaryCount(out: []const u8, label: []const u8) ?u32 {
    var lines = std.mem.splitScalar(u8, out, '\n');
    while (lines.next()) |l| {
        if (!std.mem.startsWith(u8, l, label)) continue;
        const rest = std.mem.trim(u8, l[label.len..], " \t\r");
        return std.fmt.parseInt(u32, rest, 10) catch null;
    }
    return null;
}

/// `only`: the scripts to run (none: every baseline line). A name not in
/// the baseline runs too, without arguments (on the `mtls` or `echo`
/// listener when written `mtls:NAME`, `echo:NAME`), and is reported as a
/// NOTE. `update`: rewrite the counts of the baseline lines that ran.
pub fn run(gpa: std.mem.Allocator, io: std.Io, root: std.Io.Dir, dir: []const u8, python_opt: ?[]const u8, only: []const []const u8, update: bool, env: *const std.process.Environ.Map) !u8 {
    const abs_dir = root.realPathFileAlloc(io, dir, gpa) catch {
        std.debug.print("no tlsfuzzer checkout at {s} (qap: scripts/fetch-conformance-tools.sh tlsfuzzer)\n", .{dir});
        return 2;
    };
    const python = python_opt orelse try std.fs.path.join(gpa, &.{ abs_dir, "../venv/bin/python" });
    var tf_dir = try std.Io.Dir.cwd().openDir(io, abs_dir, .{});
    defer tf_dir.close(io);

    const text = try root.readFileAlloc(io, baseline_path, gpa, .limited(1 << 20));
    const baseline = try parseBaseline(gpa, text);
    var entries: std.ArrayList(Entry) = .empty;
    if (only.len == 0) {
        try entries.appendSlice(gpa, baseline);
    } else for (only) |arg| {
        const colon = std.mem.indexOfScalar(u8, arg, ':');
        const mode: Mode = if (colon) |i| std.meta.stringToEnum(Mode, arg[0..i]) orelse return error.UnknownListener else .plain;
        const name = if (colon) |i| arg[i + 1 ..] else arg;
        const e = for (baseline) |b| {
            if (std.mem.eql(u8, b.script, name)) break b;
        } else Entry{ .script = name, .mode = mode, .args = &.{}, .want_pass = 0, .want_fail = std.math.maxInt(u32) };
        try entries.append(gpa, e);
    }

    var shared: Shared = undefined;
    shared.io = io;
    shared.clock = .{ .io = io };
    var p256 = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(certs.p256_scalar);
    var p384 = try std.crypto.sign.ecdsa.EcdsaP384Sha384.SecretKey.fromBytes(certs.p384_scalar);
    var ed = try std.crypto.sign.Ed25519.SecretKey.fromBytes(certs.ed25519_secret);
    var rsa_key: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromDer(&rsa_key, &certs.rsa2048_pkcs1);
    const chains = [4][1][]const u8{ .{&certs.rsa2048_cert}, .{&certs.p256_cert}, .{&certs.p384_cert}, .{&certs.ed25519_cert} };
    // RSA first: most scripts offer RSA schemes beside the ECDSA ones and
    // assume an RSA server (qap's rig does the same).
    shared.keys = .{
        .{ .chain = &chains[0], .key = .{ .rsa = &rsa_key } },
        .{ .chain = &chains[1], .key = .{ .ecdsa_p256 = &p256 } },
        .{ .chain = &chains[2], .key = .{ .ecdsa_p384 = &p384 } },
        .{ .chain = &chains[3], .key = .{ .ed25519 = &ed } },
    };
    for (&shared.keys) |*k| try k.check();
    var ring: tlsresume.stek.DefaultRing = .init();
    var stek_key: [32]u8 = undefined;
    io.randomSecure(&stek_key) catch return error.NoEntropy;
    ring.rotate(1, &stek_key, @divFloor(Clock.nowMs(&shared.clock), 1000));
    const stek: server_mod.StekTicketer(tlsresume.stek.DefaultRing) = .{ .ring = &ring };
    shared.tickets = .{ .ticketer = stek.ticketer(), .clock = .{ .ctx = &shared.clock, .now_ms = Clock.nowMs } };

    // Every script's full output, for the failing conversations' details,
    // and the client certificates and keys `@NAME` arguments name.
    const log_rel = ".zig-cache/tlsserver-interop/tlsfuzzer";
    try root.createDirPath(io, log_rel);
    var log_dir = try root.openDir(io, log_rel, .{});
    defer log_dir.close(io);
    const abs_log = try root.realPathFileAlloc(io, log_rel, gpa);
    for ([_]struct { []const u8, []const u8, []const u8 }{
        .{ "client-p256", &client_certs.p256_cert, &client_certs.p256_pkcs8 },
        .{ "client-rsa2048", &client_certs.rsa2048_cert, &client_certs.rsa2048_pkcs8 },
        .{ "client-ed25519", &client_certs.ed25519_cert, &client_certs.ed25519_pkcs8 },
    }) |cc| {
        try log_dir.writeFile(io, .{ .sub_path = try std.mem.concat(gpa, u8, &.{ cc[0], ".pem" }), .data = try pem(gpa, "CERTIFICATE", cc[1]) });
        try log_dir.writeFile(io, .{ .sub_path = try std.mem.concat(gpa, u8, &.{ cc[0], ".key" }), .data = try pem(gpa, "PRIVATE KEY", cc[2]) });
    }

    const verifier: tlsserver.X509Verifier = .{ .gpa = std.heap.page_allocator, .anchors = &.{&client_certs.ca_cert} };
    const client_auth: tlsserver.ClientAuth = .{ .verifier = verifier.verifier(), .mandatory = false, .clock = shared.tickets.clock };
    // In `Mode` order.
    const listeners = [_]Listener{
        .{ .shared = &shared, .client_auth = null },
        .{ .shared = &shared, .client_auth = &client_auth },
        .{ .shared = &shared, .client_auth = null, .echo = true },
    };
    var sockets: [listeners.len]net.Server = undefined;
    var ports: [listeners.len][8]u8 = undefined;
    var port: [listeners.len][]const u8 = undefined;
    for (&listeners, &sockets, &ports, &port) |*l, *sock, *buf, *p| {
        const local: net.IpAddress = .{ .ip4 = .loopback(0) };
        sock.* = try local.listen(io, .{ .reuse_address = true });
        // Never joined: the process ends with the accept loop still blocked.
        const t = try std.Thread.spawn(.{}, acceptLoop, .{ l, sock });
        t.detach();
        p.* = try std.mem.print(buf, "{d}", .{sock.socket.address.getPort()});
    }

    var failed: usize = 0;
    var got: std.StringHashMapUnmanaged([2]u32) = .empty;
    for (entries.items) |e| {
        var argv: std.ArrayList([]const u8) = .empty;
        const script = try std.mem.concat(gpa, u8, &.{ "scripts/", e.script });
        try argv.appendSlice(gpa, &.{ python, script, "-h", "127.0.0.1", "-p", port[@backingInt(e.mode)] });
        for (e.args) |a| try argv.append(gpa, if (a.len > 1 and a[0] == '@') try std.fs.path.join(gpa, &.{ abs_log, a[1..] }) else a);
        var child = try std.process.spawn(io, .{
            .argv = argv.items,
            .cwd = .{ .dir = tf_dir },
            .environ_map = env,
            .stdin = .close,
            .stdout = .pipe,
            .stderr = .pipe,
        });
        var ob: [4096]u8 = undefined;
        var or_ = child.stdout.?.reader(io, &ob);
        const stdout = try or_.interface.allocRemaining(gpa, .unlimited);
        var eb: [4096]u8 = undefined;
        var er = child.stderr.?.reader(io, &eb);
        const stderr = try er.interface.allocRemaining(gpa, .unlimited);
        _ = try child.wait(io);
        const log_name = try std.mem.concat(gpa, u8, &.{ e.script, ".log" });
        try log_dir.writeFile(io, .{ .sub_path = log_name, .data = try std.mem.concat(gpa, u8, &.{ stdout, "\n--- stderr\n", stderr }) });

        const pass = summaryCount(stdout, "PASS:");
        const fail = summaryCount(stdout, "FAIL:") orelse 0;
        const p = pass orelse {
            std.debug.print("FAIL {s}: no summary\n{s}\n{s}\n", .{ e.script, stdout[stdout.len -| 2000..], stderr[stderr.len -| 2000..] });
            failed += 1;
            continue;
        };
        if (e.want_pass != null) try got.put(gpa, e.script, .{ p, fail });
        if (e.want_fail == std.math.maxInt(u32)) {
            std.debug.print("NOTE {s}: PASS {d} FAIL {d}; not in {s}\n", .{ e.script, p, fail, baseline_path });
        } else if (fail > e.want_fail) {
            std.debug.print("FAIL {s}: PASS {d} FAIL {d}, baseline PASS {?d} FAIL {d}\n", .{ e.script, p, fail, e.want_pass, e.want_fail });
            failed += 1;
        } else if (fail < e.want_fail or (e.want_pass != null and p != e.want_pass.?)) {
            std.debug.print("NOTE {s}: PASS {d} FAIL {d}, baseline PASS {?d} FAIL {d} -- update the line\n", .{ e.script, p, fail, e.want_pass, e.want_fail });
        } else std.debug.print("PASS {s}: PASS {d} FAIL {d}\n", .{ e.script, p, fail });
        // The failing conversations, for the record.
        if (fail != 0) printFailures(stdout);
    }
    std.debug.print("tlsfuzzer: {d} script(s), {d} worse than {s}; output in {s}\n", .{ entries.items.len, failed, baseline_path, log_rel });
    if (update) {
        var out: std.Io.Writer.Allocating = .init(gpa);
        var lines = std.mem.splitScalar(u8, text, '\n');
        var first = true;
        while (lines.next()) |line| {
            if (!first) try out.writer.writeByte('\n');
            first = false;
            const tab = std.mem.indexOfScalar(u8, line, '\t') orelse {
                try out.writer.writeAll(line);
                continue;
            };
            const counts = if (line[0] != '#') got.get(line[0..tab]) else null;
            const c = counts orelse {
                try out.writer.writeAll(line);
                continue;
            };
            var cols = std.mem.splitScalar(u8, line, '\t');
            var i: usize = 0;
            while (cols.next()) |col| : (i += 1) {
                if (i != 0) try out.writer.writeByte('\t');
                if (i == 3) try out.writer.print("PASS {d} FAIL {d}", .{ c[0], c[1] }) else try out.writer.writeAll(col);
            }
        }
        try root.writeFile(io, .{ .sub_path = baseline_path, .data = out.written() });
        std.debug.print("rewrote the counts in {s}\n", .{baseline_path});
    }
    return if (failed == 0) 0 else 1;
}

fn pem(gpa: std.mem.Allocator, label: []const u8, der: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.print(gpa, "-----BEGIN {s}-----\n", .{label});
    var b64: [4096]u8 = undefined;
    const enc = std.base64.standard.Encoder.encode(&b64, der);
    var i: usize = 0;
    while (i < enc.len) : (i += 64) try out.print(gpa, "{s}\n", .{enc[i..@min(enc.len, i + 64)]});
    try out.print(gpa, "-----END {s}-----\n", .{label});
    return out.items;
}

/// tlsfuzzer's "Test end" block lists the failed conversations after
/// "FAILED:" (one per line, indented with a tab or spaces).
fn printFailures(out: []const u8) void {
    const at = std.mem.lastIndexOf(u8, out, "FAILED:") orelse return;
    var lines = std.mem.splitScalar(u8, out[at + "FAILED:".len ..], '\n');
    _ = lines.next();
    while (lines.next()) |l| {
        const s = std.mem.trim(u8, l, " \t\r");
        if (s.len == 0 or l.len == s.len) break;
        std.debug.print("       - {s}\n", .{s});
    }
}
