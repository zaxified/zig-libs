// SPDX-License-Identifier: MIT

//! Live interop against real OpenSSH (test-only; `root.zig` pulls it in from
//! its `test` block). Two fixtures:
//!
//!   - `Sshd`: a real `sshd` on a loopback port, our whole client stack
//!     connected and authenticated to it;
//!   - `SshClient`: a real `ssh` client dialling our server, with our server
//!     handshake done and userauth (ours) left to the test.
//!
//! Every test skips (`error.SkipZigTest`) when OpenSSH is not installed or
//! the spawned `sshd` never listens, the same convention as the module's
//! older live tests in `server.zig`/`connection.zig`. A run that reports no
//! skips is the one that proves interop.

const std = @import("std");
const transport = @import("transport.zig");
const messages = @import("messages.zig");
const server = @import("server.zig");
const userauth = @import("userauth.zig");
const connection = @import("connection.zig");

const Ed25519 = std.crypto.sign.Ed25519;

fn fillRandom(buf: []u8) void {
    var off: usize = 0;
    while (off < buf.len) {
        const rc = std.os.linux.getrandom(buf.ptr + off, buf.len - off, 0);
        const signed: isize = @bitCast(rc);
        if (signed < 0) @panic("getrandom failed");
        off += @intCast(signed);
    }
}

/// `sshd` not running as root can only authenticate the user it runs as.
fn currentUser() ?[]const u8 {
    const v = std.process.Environ.getPosix(std.testing.environ, "USER") orelse
        std.process.Environ.getPosix(std.testing.environ, "LOGNAME") orelse return null;
    if (v.len == 0 or v.len > 64) return null;
    return v;
}

fn writeFile(io: std.Io, path: []const u8, contents: []const u8) !void {
    var f = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer f.close(io);
    var buf: [4096]u8 = undefined;
    var fw = f.writer(io, &buf);
    try fw.interface.writeAll(contents);
    try fw.interface.flush();
}

fn keygen(io: std.Io, key_type: []const u8, path: []const u8) !void {
    var child = std.process.spawn(io, .{
        .argv = &.{ "ssh-keygen", "-q", "-t", key_type, "-N", "", "-C", "zig-ssh-interop", "-f", path },
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return error.SkipZigTest;
    switch (child.wait(io) catch return error.SkipZigTest) {
        .exited => |c| if (c != 0) return error.SkipZigTest,
        else => return error.SkipZigTest,
    }
}

fn makeWorkDir(gpa: std.mem.Allocator, io: std.Io, tag: []const u8) ![]u8 {
    var rnd: [8]u8 = undefined;
    fillRandom(&rnd);
    const hex = std.fmt.bytesToHex(&rnd, .lower);
    const dir_path = try std.fmt.allocPrint(gpa, "/tmp/zig_ssh_{s}_{s}", .{ tag, &hex });
    errdefer gpa.free(dir_path);
    var d = std.Io.Dir.cwd().createDirPathOpen(io, dir_path, .{}) catch return error.SkipZigTest;
    d.close(io);
    return dir_path;
}

const accept_any_host_key: transport.HostKeyPolicy = .{ .verifier = .{ .verifyFn = struct {
    fn f(_: *anyopaque, _: transport.HostKeyInfo) transport.HostKeyVerdict {
        return .accept;
    }
}.f }, .host = "127.0.0.1" };

// ── fixture: our client → a real sshd ──────────────────────────────────────

pub const SshdOptions = struct {
    /// Extra `-o` settings for `sshd`, e.g. `"RekeyLimit=32K"`.
    extra: []const []const u8 = &.{},
    client_key_type: []const u8 = "ed25519",
    /// Authenticate before returning (publickey, the fixture's own key).
    authenticate: bool = true,
    /// `Transport.offer_strict_kex` for our client.
    strict: bool = true,
};

/// A real `sshd` on a random loopback port and our client connected to it.
/// Heap-allocated: `t` borrows the stream buffers inside.
pub const Sshd = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    dir_path: []u8,
    child: std.process.Child,
    stream: std.Io.net.Stream,
    rbuf: [64 * 1024]u8 = undefined,
    wbuf: [64 * 1024]u8 = undefined,
    sr: std.Io.net.Stream.Reader = undefined,
    sw: std.Io.net.Stream.Writer = undefined,
    t: transport.Transport = undefined,
    user: []const u8,
    client_key: userauth.AuthKey,

    pub fn start(gpa: std.mem.Allocator, io: std.Io, opts: SshdOptions) !*Sshd {
        const cwd = std.Io.Dir.cwd();
        const sshd_path = "/usr/sbin/sshd";
        cwd.access(io, sshd_path, .{}) catch return error.SkipZigTest;
        const user = currentUser() orelse return error.SkipZigTest;

        const dir_path = try makeWorkDir(gpa, io, "sshd");
        errdefer {
            cwd.deleteTree(io, dir_path) catch {};
            gpa.free(dir_path);
        }
        const hk_path = try std.fmt.allocPrint(gpa, "{s}/hk", .{dir_path});
        defer gpa.free(hk_path);
        const ck_path = try std.fmt.allocPrint(gpa, "{s}/ck", .{dir_path});
        defer gpa.free(ck_path);
        try keygen(io, "ed25519", hk_path);
        try keygen(io, opts.client_key_type, ck_path);

        const ck_pub_path = try std.fmt.allocPrint(gpa, "{s}.pub", .{ck_path});
        defer gpa.free(ck_pub_path);
        const ck_pub = cwd.readFileAlloc(io, ck_pub_path, gpa, .limited(4096)) catch return error.SkipZigTest;
        defer gpa.free(ck_pub);
        const ak_path = try std.fmt.allocPrint(gpa, "{s}/authorized_keys", .{dir_path});
        defer gpa.free(ak_path);
        writeFile(io, ak_path, ck_pub) catch return error.SkipZigTest;

        const ck_text = cwd.readFileAlloc(io, ck_path, gpa, .limited(16384)) catch return error.SkipZigTest;
        defer gpa.free(ck_text);
        const client_key = userauth.AuthKey.fromOpenSSH(ck_text, null) catch return error.SkipZigTest;

        var portbuf: [2]u8 = undefined;
        fillRandom(&portbuf);
        const port: u16 = 20000 + (std.mem.readInt(u16, &portbuf, .big) % 20000);

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        var owned: std.ArrayList([]u8) = .empty;
        defer {
            for (owned.items) |o| gpa.free(o);
            owned.deinit(gpa);
        }
        const port_opt = try std.fmt.allocPrint(gpa, "Port={d}", .{port});
        try owned.append(gpa, port_opt);
        const ak_opt = try std.fmt.allocPrint(gpa, "AuthorizedKeysFile={s}", .{ak_path});
        try owned.append(gpa, ak_opt);
        const log_path = try std.fmt.allocPrint(gpa, "{s}/sshd.log", .{dir_path});
        try owned.append(gpa, log_path);
        try argv.appendSlice(gpa, &.{ sshd_path, "-D", "-E", log_path, "-f", "/dev/null", "-h", hk_path });
        const base = [_][]const u8{
            port_opt,                          "ListenAddress=127.0.0.1",
            "UsePAM=no",                       "StrictModes=no",
            "PidFile=none",                    "LogLevel=VERBOSE",
            "PubkeyAuthentication=yes",        "PasswordAuthentication=no",
            "KbdInteractiveAuthentication=no", ak_opt,
        };
        for (base) |o| try argv.appendSlice(gpa, &.{ "-o", o });
        for (opts.extra) |o| try argv.appendSlice(gpa, &.{ "-o", o });

        var child = std.process.spawn(io, .{
            .argv = argv.items,
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch return error.SkipZigTest;
        errdefer child.kill(io);

        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
        const stream: std.Io.net.Stream = blk: {
            var tries: usize = 0;
            while (tries < 60) : (tries += 1) {
                if (addr.connect(io, .{ .mode = .stream })) |s| break :blk s else |_| {}
                var ts = std.os.linux.timespec{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
                _ = std.os.linux.nanosleep(&ts, null);
            }
            return error.SkipZigTest; // sshd never came up here
        };

        const self = try gpa.create(Sshd);
        self.* = .{
            .gpa = gpa,
            .io = io,
            .dir_path = dir_path,
            .child = child,
            .stream = stream,
            .user = user,
            .client_key = client_key,
        };
        errdefer {
            self.stream.close(io);
            gpa.destroy(self);
        }
        self.sr = self.stream.reader(io, &self.rbuf);
        self.sw = self.stream.writer(io, &self.wbuf);
        self.t = transport.Transport.init(&self.sr.interface, &self.sw.interface);
        self.t.offer_strict_kex = opts.strict;
        errdefer self.t.deinit();
        try self.t.clientHandshake(gpa, accept_any_host_key);
        if (opts.authenticate) try userauth.authenticate(&self.t, gpa, user, client_key);
        return self;
    }

    /// The tail of `sshd`'s own log — for a failure message only (a passing
    /// test must write nothing to stderr).
    pub fn dumpLog(self: *Sshd) void {
        const p = std.fmt.allocPrint(self.gpa, "{s}/sshd.log", .{self.dir_path}) catch return;
        defer self.gpa.free(p);
        const text = std.Io.Dir.cwd().readFileAlloc(self.io, p, self.gpa, .limited(1 << 20)) catch return;
        defer self.gpa.free(text);
        const tail = text[text.len -| 4000..];
        std.debug.print("--- sshd log tail ---\n{s}\n---\n", .{tail});
    }

    pub fn deinit(self: *Sshd) void {
        const gpa = self.gpa;
        const io = self.io;
        self.t.deinit();
        self.stream.close(io);
        self.child.kill(io);
        std.Io.Dir.cwd().deleteTree(io, self.dir_path) catch {};
        gpa.free(self.dir_path);
        gpa.destroy(self);
    }
};

// ── fixture: a real ssh client → our server ────────────────────────────────

pub const SshClientOptions = struct {
    user_key_type: []const u8 = "ed25519",
    /// Extra `ssh` arguments, spliced into the command line verbatim.
    ssh_args: []const u8 = "",
    /// What follows `alice@127.0.0.1` (the remote command, if any).
    remote: []const u8 = "'uname -a'",
    /// Shell redirection for the client's stdin (default `/dev/null`).
    stdin_from: []const u8 = "/dev/null",
};

/// A real `ssh` dialling our server; `start` returns after OUR server
/// handshake, with userauth and everything after it left to the test.
pub const SshClient = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    dir_path: []u8,
    out_path: []u8,
    child: std.process.Child,
    listener: std.Io.net.Server,
    stream: std.Io.net.Stream,
    stream_open: bool = true,
    rbuf: [64 * 1024]u8 = undefined,
    wbuf: [64 * 1024]u8 = undefined,
    sr: std.Io.net.Stream.Reader = undefined,
    sw: std.Io.net.Stream.Writer = undefined,
    t: transport.Transport = undefined,
    host_keys: [1]server.HostKey,
    authorized_blob: [1024]u8 = undefined,
    authorized_len: usize = 0,

    pub fn start(gpa: std.mem.Allocator, io: std.Io, opts: SshClientOptions) !*SshClient {
        const cwd = std.Io.Dir.cwd();
        cwd.access(io, "/usr/bin/ssh", .{}) catch return error.SkipZigTest;
        const dir_path = try makeWorkDir(gpa, io, "client");
        errdefer {
            cwd.deleteTree(io, dir_path) catch {};
            gpa.free(dir_path);
        }
        const ck_path = try std.fmt.allocPrint(gpa, "{s}/ck", .{dir_path});
        defer gpa.free(ck_path);
        try keygen(io, opts.user_key_type, ck_path);

        var blob: [1024]u8 = undefined;
        var blob_len: usize = 0;
        {
            const pub_path = try std.fmt.allocPrint(gpa, "{s}.pub", .{ck_path});
            defer gpa.free(pub_path);
            const text = cwd.readFileAlloc(io, pub_path, gpa, .limited(4096)) catch return error.SkipZigTest;
            defer gpa.free(text);
            var it = std.mem.tokenizeScalar(u8, text, ' ');
            _ = it.next() orelse return error.SkipZigTest;
            const b64 = it.next() orelse return error.SkipZigTest;
            const dec = std.base64.standard.Decoder;
            const n = dec.calcSizeForSlice(b64) catch return error.SkipZigTest;
            if (n > blob.len) return error.SkipZigTest;
            dec.decode(blob[0..n], b64) catch return error.SkipZigTest;
            blob_len = n;
        }

        var port: u16 = 0;
        var listener = try listenLoopback(io, &port);
        errdefer listener.deinit(io);

        const out_path = try std.fmt.allocPrint(gpa, "{s}/out", .{dir_path});
        errdefer gpa.free(out_path);
        const cmdline = try std.fmt.allocPrint(gpa,
            \\/usr/bin/ssh -p {d} -F /dev/null -i {s} -o IdentitiesOnly=yes \
            \\ -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            \\ -o GlobalKnownHostsFile=/dev/null -o PreferredAuthentications=publickey \
            \\ -o BatchMode=yes -o ConnectTimeout=10 {s} \
            \\ alice@127.0.0.1 {s} < {s} > {s} 2>{s}.err; echo $? >> {s}
        , .{ port, ck_path, opts.ssh_args, opts.remote, opts.stdin_from, out_path, out_path, out_path });
        defer gpa.free(cmdline);

        var child = std.process.spawn(io, .{
            .argv = &.{ "/bin/sh", "-c", cmdline },
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch return error.SkipZigTest;
        errdefer child.kill(io);

        const stream = try acceptBounded(io, &listener, 30_000);

        const self = try gpa.create(SshClient);
        self.* = .{
            .gpa = gpa,
            .io = io,
            .dir_path = dir_path,
            .out_path = out_path,
            .child = child,
            .listener = listener,
            .stream = stream,
            .host_keys = .{testHostKey(0x44)},
            .authorized_len = blob_len,
        };
        @memcpy(self.authorized_blob[0..blob_len], blob[0..blob_len]);
        errdefer {
            self.stream.close(io);
            gpa.destroy(self);
        }
        self.sr = self.stream.reader(io, &self.rbuf);
        self.sw = self.stream.writer(io, &self.wbuf);
        self.t = try server.accept(&self.sr.interface, &self.sw.interface, gpa, .{ .host_keys = &self.host_keys });
        return self;
    }

    fn checkKey(ctx: *anyopaque, user: []const u8, algorithm: []const u8, key_blob: []const u8) bool {
        const self: *SshClient = @ptrCast(@alignCast(ctx));
        _ = user;
        _ = algorithm;
        return std.mem.eql(u8, key_blob, self.authorized_blob[0..self.authorized_len]);
    }

    /// Our userauth server, accepting exactly the client's key.
    pub fn authenticate(self: *SshClient) !userauth.AuthResult {
        return userauth.serveUserauth(&self.t, self.gpa, .{
            .authorized_key = .{ .ctx = self, .checkFn = checkKey },
        });
    }

    /// Wait for the client to exit; returns its stdout followed by its exit
    /// status on a line of its own (caller frees).
    pub fn finish(self: *SshClient) ![]u8 {
        self.stream.close(self.io);
        self.stream_open = false;
        _ = self.child.wait(self.io) catch {};
        return std.Io.Dir.cwd().readFileAlloc(self.io, self.out_path, self.gpa, .limited(16 << 20));
    }

    /// The client's own stderr — for a failure message only.
    pub fn dumpErr(self: *SshClient) void {
        const p = std.fmt.allocPrint(self.gpa, "{s}.err", .{self.out_path}) catch return;
        defer self.gpa.free(p);
        const text = std.Io.Dir.cwd().readFileAlloc(self.io, p, self.gpa, .limited(1 << 20)) catch return;
        defer self.gpa.free(text);
        std.debug.print("--- ssh stderr ---\n{s}\n---\n", .{text[text.len -| 4000..]});
    }

    pub fn deinit(self: *SshClient) void {
        const gpa = self.gpa;
        const io = self.io;
        self.t.deinit();
        if (self.stream_open) self.stream.close(io);
        self.child.kill(io);
        self.listener.deinit(io);
        std.Io.Dir.cwd().deleteTree(io, self.dir_path) catch {};
        gpa.free(self.out_path);
        gpa.free(self.dir_path);
        gpa.destroy(self);
    }
};

fn testHostKey(seed_byte: u8) server.HostKey {
    const seed: [32]u8 = [_]u8{seed_byte} ** 32;
    return .{ .ed25519 = Ed25519.KeyPair.generateDeterministic(seed) catch unreachable };
}

fn listenLoopback(io: std.Io, port_out: *u16) !std.Io.net.Server {
    var tries: usize = 0;
    while (tries < 32) : (tries += 1) {
        var pb: [2]u8 = undefined;
        fillRandom(&pb);
        const port: u16 = 20000 + (std.mem.readInt(u16, &pb, .big) % 20000);
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
        const s = addr.listen(io, .{ .reuse_address = true }) catch continue;
        port_out.* = port;
        return s;
    }
    return error.SkipZigTest;
}

/// `accept` with a deadline (see `connection.zig`'s twin for why poll(2)).
fn acceptBounded(io: std.Io, listener: *std.Io.net.Server, timeout_ms: i32) !std.Io.net.Stream {
    var fds = [_]std.posix.pollfd{.{
        .fd = listener.socket.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const n = std.posix.poll(&fds, timeout_ms) catch return error.AcceptPollFailed;
    if (n == 0) return error.PeerNeverConnected;
    return listener.accept(io);
}

const big_output_len = 3_000_000;

const big_output_handler: connection.CommandHandler = .{
    .runFn = struct {
        fn f(
            _: *anyopaque,
            gpa: std.mem.Allocator,
            _: []const u8,
            _: []const u8,
            _: []const u8,
            stdout: *std.ArrayList(u8),
            _: *std.ArrayList(u8),
        ) connection.CommandError!u32 {
            // 3 MB — past OpenSSH's 2 MiB channel window, so the server has to
            // read (WINDOW_ADJUST) mid-stream and re-exchanges run inside the
            // transfer, not only at its end — of a pattern whose every offset
            // is checkable.
            try stdout.ensureTotalCapacity(gpa, big_output_len);
            var i: usize = 0;
            while (i < big_output_len) : (i += 1) stdout.appendAssumeCapacity(@intCast('a' + i % 26));
            return 0;
        }
    }.f,
};

fn expectPattern(data: []const u8, len: usize) !void {
    try std.testing.expectEqual(len, data.len);
    for (data, 0..) |b, i| if (b != @as(u8, @intCast('a' + i % 26))) return error.TestUnexpectedResult;
}

// ── transport: strict KEX, UNIMPLEMENTED, rekey ────────────────────────────

test "live: our client and sshd agree on strict KEX (sequence numbers restart at 0)" {
    // Both sides advertise `kex-strict-*-v00@openssh.com`; from NEWKEYS on,
    // each side numbers packets from 0. Had our client kept counting from the
    // plaintext phase, the very first encrypted packet would fail sshd's MAC.
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try Sshd.start(gpa, threaded.io(), .{});
    defer fx.deinit();
    try std.testing.expect(fx.t.strict_kex);
    var res = connection.exec(&fx.t, gpa, "printf ok", .{}) catch |e| {
        fx.dumpLog();
        return e;
    };
    defer res.deinit(gpa);
    try std.testing.expectEqualStrings("ok", res.stdout);
}

test "live: without strict KEX, sequence numbers run on from the plaintext phase and across re-keys" {
    // The pre-strict-KEX path (RFC 4253 §6.4 as written): our client does
    // not offer the indicator, so sshd does not reset either; the first
    // encrypted packet carries 3, and every re-exchange continues the count.
    // sshd's MAC check is the oracle for both.
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try Sshd.start(gpa, threaded.io(), .{ .strict = false, .extra = &.{"RekeyLimit=32K"} });
    defer fx.deinit();
    try std.testing.expect(!fx.t.strict_kex);
    var res = connection.exec(&fx.t, gpa, "/bin/sh -c 'i=0; while [ $i -lt 1000 ]; do printf %0100d 0; i=$((i+1)); done'", .{}) catch |e| {
        fx.dumpLog();
        return e;
    };
    defer res.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 100_000), res.stdout.len);
    try std.testing.expect(fx.t.kex_count >= 2);
}

test "live: sshd answers an unrecognized message with SSH_MSG_UNIMPLEMENTED naming its sequence number" {
    // RFC 4253 §11.4 from the receiving side: we send message 254 (the
    // "local extensions" range; not 192/193, which OpenSSH uses for its
    // `ping@openssh.com` PING/PONG and parses as such), sshd must answer
    // UNIMPLEMENTED with OUR packet's sequence number, and the connection
    // must carry on. `recvPacket` absorbs the reply and records the number.
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try Sshd.start(gpa, threaded.io(), .{});
    defer fx.deinit();
    const seq = fx.t.write_cipher.sequenceNumber();
    try fx.t.sendPacket(&[_]u8{ 254, 'x' });
    var res = connection.exec(&fx.t, gpa, "printf still-alive", .{}) catch |e| {
        fx.dumpLog();
        return e;
    };
    defer res.deinit(gpa);
    try std.testing.expectEqualStrings("still-alive", res.stdout);
    try std.testing.expectEqual(@as(?u32, seq), fx.t.peer_unimplemented);
}

test "live: sshd re-keys every 32 KiB (RekeyLimit) while we read 300 KB — our client follows" {
    // sshd STARTS each re-exchange (its KEXINIT arrives in the middle of the
    // channel data); `recvPacket` must run it as the responder and keep the
    // byte stream intact across every key change.
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try Sshd.start(gpa, threaded.io(), .{ .extra = &.{"RekeyLimit=32K"} });
    defer fx.deinit();
    var res = connection.exec(&fx.t, gpa, "/bin/sh -c 'i=0; while [ $i -lt 3000 ]; do printf %0100d 0; i=$((i+1)); done'", .{}) catch |e| {
        fx.dumpLog();
        return e;
    };
    defer res.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 300_000), res.stdout.len);
    try std.testing.expect(std.mem.allEqual(u8, res.stdout, '0'));
    try std.testing.expect(fx.t.kex_count >= 5);
}

test "live: our client re-keys every 16 KiB while sending 200 KB to sshd — sshd follows" {
    // Now WE start each re-exchange (`rekey_limit_bytes`), from inside
    // `sendPacket`, while sshd may still be sending (window adjusts); those
    // packets must be queued and delivered after the exchange.
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try Sshd.start(gpa, threaded.io(), .{});
    defer fx.deinit();
    fx.t.rekey_limit_bytes = 16 * 1024;
    const input = try gpa.alloc(u8, 200_000);
    defer gpa.free(input);
    for (input, 0..) |*b, i| b.* = @intCast('a' + i % 26);
    var res = connection.exec(&fx.t, gpa, "wc -c", .{ .stdin = input }) catch |e| {
        fx.dumpLog();
        return e;
    };
    defer res.deinit(gpa);
    try std.testing.expectEqualStrings("200000", std.mem.trim(u8, res.stdout, " \n"));
    try std.testing.expect(fx.t.kex_count >= 10);
}

test "live: an explicit rekey() mid-connection, then the session carries on" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try Sshd.start(gpa, threaded.io(), .{});
    defer fx.deinit();
    const sid_before = fx.t.session_id.?;
    try fx.t.rekey();
    try fx.t.rekey();
    try std.testing.expectEqual(@as(u32, 3), fx.t.kex_count);
    // RFC 4253 §7.2: the session id is the FIRST exchange's hash, for good.
    try std.testing.expectEqualSlices(u8, sid_before.slice(), fx.t.session_id.?.slice());
    var res = try connection.exec(&fx.t, gpa, "printf after-rekey", .{});
    defer res.deinit(gpa);
    try std.testing.expectEqualStrings("after-rekey", res.stdout);
}

test "live: a real ssh client re-keys every 32 KiB against our server — we follow" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try SshClient.start(gpa, threaded.io(), .{ .ssh_args = "-o RekeyLimit=32K" });
    defer fx.deinit();
    const auth = try fx.authenticate();
    connection.serveSession(&fx.t, gpa, .{ .user = auth.user(), .exec = big_output_handler, .stdin_mode = .ignore }) catch |e| {
        const out = fx.finish() catch null;
        if (out) |o| gpa.free(o);
        fx.dumpErr();
        return e;
    };
    const kex_count = fx.t.kex_count;
    const out = try fx.finish();
    defer gpa.free(out);
    try expectPattern(out[0..out.len -| 2], big_output_len);
    try std.testing.expectEqualStrings("0\n", out[out.len -| 2..]);
    try std.testing.expect(kex_count >= 2);
}

test "live: our server re-keys every 16 KiB against a real ssh client — it follows" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try SshClient.start(gpa, threaded.io(), .{});
    defer fx.deinit();
    const auth = try fx.authenticate();
    fx.t.rekey_limit_bytes = 16 * 1024;
    try connection.serveSession(&fx.t, gpa, .{ .user = auth.user(), .exec = big_output_handler, .stdin_mode = .ignore });
    const kex_count = fx.t.kex_count;
    const out = try fx.finish();
    defer gpa.free(out);
    try expectPattern(out[0..out.len -| 2], big_output_len);
    try std.testing.expectEqualStrings("0\n", out[out.len -| 2..]);
    try std.testing.expect(kex_count >= 10);
}
