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
        var client_key: userauth.AuthKey = undefined;
        userauth.AuthKey.fromOpenSSH(&client_key, ck_text, null) catch return error.SkipZigTest;

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
        if (opts.authenticate) try userauth.authenticate(&self.t, gpa, user, &client_key);
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
    /// A whole shell script instead of the single `ssh` call: `$SSH` is the
    /// client with every option above (no host), `$H` the `user@host`
    /// argument, `$OUT` the output file (its last line must be a status).
    script: ?[]const u8 = null,
    /// Authenticate with keyboard-interactive instead of the key: the client
    /// answers each prompt by running this shell script (`$1` = the prompt)
    /// through `SSH_ASKPASS_REQUIRE=force`.
    askpass_script: ?[]const u8 = null,
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
        var auth_buf: [512]u8 = undefined;
        const auth_opts = if (opts.askpass_script) |script| blk: {
            const ap = try std.fmt.allocPrint(gpa, "{s}/askpass", .{dir_path});
            defer gpa.free(ap);
            var f = try cwd.createFile(io, ap, .{ .permissions = @enumFromInt(0o755) });
            defer f.close(io);
            var fbuf: [1024]u8 = undefined;
            var fw = f.writer(io, &fbuf);
            try fw.interface.print("#!/bin/sh\n{s}\n", .{script});
            try fw.interface.flush();
            break :blk try std.fmt.bufPrint(&auth_buf, "env SSH_ASKPASS={s} SSH_ASKPASS_REQUIRE=force", .{ap});
        } else "";
        const methods = if (opts.askpass_script != null)
            "-o PreferredAuthentications=keyboard-interactive -o BatchMode=no -o NumberOfPasswordPrompts=1"
        else
            "-o PreferredAuthentications=publickey -o BatchMode=yes";
        const ssh_cmd = try std.fmt.allocPrint(gpa, "{s} /usr/bin/ssh -p {d} -F /dev/null -i {s} -o IdentitiesOnly=yes" ++
            " -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null" ++
            " {s} -o ConnectTimeout=10 {s}", .{ auth_opts, port, ck_path, methods, opts.ssh_args });
        defer gpa.free(ssh_cmd);
        const cmdline = if (opts.script) |script|
            try std.fmt.allocPrint(gpa, "SSH='{s}'; H=alice@127.0.0.1; OUT={s}; exec 2>{s}.err; {s}", .{ ssh_cmd, out_path, out_path, script })
        else
            try std.fmt.allocPrint(gpa, "{s} alice@127.0.0.1 {s} < {s} > {s} 2>{s}.err; echo $? >> {s}", .{ ssh_cmd, opts.remote, opts.stdin_from, out_path, out_path, out_path });
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

    /// Accept the client's next connection (a script that runs `ssh`
    /// twice) and run our server handshake on it, replacing `t`.
    pub fn acceptNext(self: *SshClient) !void {
        self.t.deinit();
        self.stream.close(self.io);
        self.stream_open = false;
        self.stream = try acceptBounded(self.io, &self.listener, 30_000);
        self.stream_open = true;
        self.sr = self.stream.reader(self.io, &self.rbuf);
        self.sw = self.stream.writer(self.io, &self.wbuf);
        self.t = try server.accept(&self.sr.interface, &self.sw.interface, self.gpa, .{ .host_keys = &self.host_keys });
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
        // The test runner reports only "failed"; name the error for the next one.
        std.debug.print("serveSession: {t} after {d} key exchange(s)\n", .{ e, fx.t.kex_count });
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

// ── channels: several at once, session requests, TCP/IP forwarding ─────────

test "live: three sessions side by side on one connection to sshd (Connection)" {
    // RFC 4254 §5: channels are independent. The slow one is drained LAST,
    // so its output arrives while the other two are being pumped and must
    // be applied to the right channel.
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try Sshd.start(gpa, threaded.io(), .{});
    defer fx.deinit();
    var conn = try connection.Connection.init(&fx.t, gpa);
    defer conn.deinit();

    const slow = try conn.openSession(.{});
    defer slow.deinit();
    const a = try conn.openSession(.{});
    defer a.deinit();
    const b = try conn.openSession(.{});
    defer b.deinit();
    try std.testing.expect(slow.ch.local_id != a.ch.local_id and a.ch.local_id != b.ch.local_id);

    try slow.exec("/bin/sh -c 'i=0; while [ $i -lt 200 ]; do printf S; i=$((i+1)); done; exit 4'");
    try a.exec("printf A; printf a >&2; exit 5");
    try b.exec("/bin/sh -c 'cat; exit 6'");
    try b.writeData("from-b");
    try b.sendEof();
    try a.drain();
    try b.drain();
    try slow.drain();
    try std.testing.expectEqualStrings("A", a.stdout.items);
    try std.testing.expectEqualStrings("a", a.stderr.items);
    try std.testing.expectEqualStrings("from-b", b.stdout.items);
    try std.testing.expectEqual(@as(usize, 200), slow.stdout.items.len);
    try std.testing.expectEqual(@as(?u32, 5), a.exitStatus());
    try std.testing.expectEqual(@as(?u32, 6), b.exitStatus());
    try std.testing.expectEqual(@as(?u32, 4), slow.exitStatus());

    // A channel opened after others closed works the same.
    const again = try conn.openSession(.{});
    defer again.deinit();
    try again.exec("printf again");
    try again.drain();
    try std.testing.expectEqualStrings("again", again.stdout.items);
}

test "live: pty-req + window-change against sshd — the command runs on a terminal of that size" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try Sshd.start(gpa, threaded.io(), .{});
    defer fx.deinit();
    var conn = try connection.Connection.init(&fx.t, gpa);
    defer conn.deinit();
    const s = try conn.openSession(.{});
    defer s.deinit();
    try s.requestPty(.{ .term = "vt100", .cols = 80, .rows = 24 });
    try s.windowChange(132, 43, 0, 0);
    try s.exec("/bin/sh -c 'echo \"T=$TERM\"; stty size; tty; exit 3'");
    try s.drain();
    const out = s.stdout.items;
    try std.testing.expect(std.mem.indexOf(u8, out, "T=vt100") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "43 132") != null); // rows cols, after the resize
    try std.testing.expect(std.mem.indexOf(u8, out, "/dev/pts/") != null);
    try std.testing.expectEqual(@as(?u32, 3), s.exitStatus());
}

test "live: shell against sshd — the login shell reads its commands from the channel" {
    // No pty: an interactive shell on a terminal may query the terminal and
    // wait for an answer (fish does), which says nothing about SSH. The
    // commands are valid in sh, bash and fish alike.
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try Sshd.start(gpa, threaded.io(), .{});
    defer fx.deinit();
    var conn = try connection.Connection.init(&fx.t, gpa);
    defer conn.deinit();
    const s = try conn.openSession(.{});
    defer s.deinit();
    try s.shell();
    try s.writeData("echo shell-ok\nexit 3\n");
    try s.sendEof();
    try s.drain();
    try std.testing.expect(std.mem.indexOf(u8, s.stdout.items, "shell-ok") != null);
    try std.testing.expectEqual(@as(?u32, 3), s.exitStatus());
}

test "live: env is delivered only for names sshd accepts (AcceptEnv)" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try Sshd.start(gpa, threaded.io(), .{ .extra = &.{"AcceptEnv=ZIGTEST_*"} });
    defer fx.deinit();
    var conn = try connection.Connection.init(&fx.t, gpa);
    defer conn.deinit();
    const s = try conn.openSession(.{});
    defer s.deinit();
    try s.setEnv("ZIGTEST_GREETING", "hello env");
    // A name outside AcceptEnv: sshd answers CHANNEL_FAILURE.
    try std.testing.expectError(error.ChannelRequestFailed, s.setEnv("NOT_ACCEPTED", "x"));
    try s.exec("printf '%s|%s' \"$ZIGTEST_GREETING\" \"$NOT_ACCEPTED\"");
    try s.drain();
    try std.testing.expectEqualStrings("hello env|", s.stdout.items);
}

test "live: signal TERM reaches the remote command, which reports exit-signal" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try Sshd.start(gpa, threaded.io(), .{});
    defer fx.deinit();
    var conn = try connection.Connection.init(&fx.t, gpa);
    defer conn.deinit();
    const s = try conn.openSession(.{});
    defer s.deinit();
    // `exec` so the signal hits sleep itself, not a shell waiting on it.
    try s.exec("exec sleep 30");
    try s.signal("TERM");
    try s.drain();
    try std.testing.expect(s.exit_signal != null);
    try std.testing.expectEqualStrings("TERM", s.exit_signal.?.name());
    try std.testing.expectEqual(@as(?u32, null), s.exitStatus());
}

/// A one-shot TCP echo peer for the forwarding tests: accepts one
/// connection, reads to EOF, writes back `prefix ++ what it read`, closes.
const EchoPeer = struct {
    listener: std.Io.net.Server,
    port: u16,
    prefix: []const u8 = "echo:",
    err: ?anyerror = null,

    fn run(self: *EchoPeer, io: std.Io) void {
        self.serve(io) catch |e| {
            self.err = e;
        };
    }

    fn serve(self: *EchoPeer, io: std.Io) !void {
        const stream = try acceptBounded(io, &self.listener, 30_000);
        defer stream.close(io);
        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var r = stream.reader(io, &rbuf);
        var w = stream.writer(io, &wbuf);
        var got: [4096]u8 = undefined;
        var n: usize = 0;
        while (n < got.len) {
            const k = r.interface.readSliceShort(got[n..]) catch break;
            if (k == 0) break;
            n += k;
        }
        try w.interface.writeAll(self.prefix);
        try w.interface.writeAll(got[0..n]);
        try w.interface.flush();
    }
};

test "live: direct-tcpip — sshd connects to a local port for us and relays both ways (ssh -L)" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fx = try Sshd.start(gpa, io, .{ .extra = &.{"AllowTcpForwarding=yes"} });
    defer fx.deinit();

    var peer: EchoPeer = .{ .listener = undefined, .port = 0 };
    peer.listener = try listenLoopback(io, &peer.port);
    defer peer.listener.deinit(io);
    const th = try std.Thread.spawn(.{}, EchoPeer.run, .{ &peer, io });
    var joined = false;
    defer if (!joined) th.join();

    var conn = try connection.Connection.init(&fx.t, gpa);
    defer conn.deinit();
    const fwd = try conn.openDirectTcpip(.{ .host = "127.0.0.1", .port = peer.port });
    defer fwd.deinit();
    try fwd.writeData("ping over ssh");
    try fwd.sendEof();
    try fwd.drain();
    th.join();
    joined = true;
    if (peer.err) |e| return e;
    try std.testing.expectEqualStrings("echo:ping over ssh", fwd.stdout.items);

    // A port nothing listens on: sshd refuses the channel.
    try std.testing.expectError(error.ChannelOpenFailed, conn.openDirectTcpip(.{ .host = "127.0.0.1", .port = 1 }));
}

const ForwardDialer = struct {
    port: u32,
    reply: [256]u8 = undefined,
    reply_len: usize = 0,
    err: ?anyerror = null,

    fn run(self: *ForwardDialer, io: std.Io) void {
        self.dial(io) catch |e| {
            self.err = e;
        };
    }

    fn dial(self: *ForwardDialer, io: std.Io) !void {
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", @intCast(self.port));
        const stream = try addr.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        var rbuf: [1024]u8 = undefined;
        var wbuf: [1024]u8 = undefined;
        var r = stream.reader(io, &rbuf);
        var w = stream.writer(io, &wbuf);
        try w.interface.writeAll("hello from a dialer");
        try w.interface.flush();
        try stream.shutdown(io, .send);
        while (self.reply_len < self.reply.len) {
            const k = r.interface.readSliceShort(self.reply[self.reply_len..]) catch break;
            if (k == 0) break;
            self.reply_len += k;
        }
    }
};

test "live: tcpip-forward — sshd listens for us and opens forwarded-tcpip channels back (ssh -R)" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fx = try Sshd.start(gpa, io, .{ .extra = &.{"AllowTcpForwarding=yes"} });
    defer fx.deinit();
    var conn = try connection.Connection.init(&fx.t, gpa);
    defer conn.deinit();

    // Port 0: sshd picks one and says which (RFC 4254 §7.1).
    const port = conn.requestRemoteForward("127.0.0.1", 0) catch |e| {
        fx.dumpLog();
        return e;
    };
    try std.testing.expect(port != 0);

    var dialer: ForwardDialer = .{ .port = port };
    const th = try std.Thread.spawn(.{}, ForwardDialer.run, .{ &dialer, io });
    var joined = false;
    defer if (!joined) th.join();

    const got = try conn.acceptForwarded();
    defer got.session.deinit();
    try std.testing.expectEqual(port, got.origin.connected_port);
    // Read the dialer's bytes to its EOF, answer, close.
    while (!got.session.ch.got_eof) _ = try got.session.pumpOnce();
    try std.testing.expectEqualStrings("hello from a dialer", got.session.stdout.items);
    try got.session.writeData("reply from our client");
    try got.session.sendEof();
    try got.session.drain();
    th.join();
    joined = true;
    if (dialer.err) |e| return e;
    try std.testing.expectEqualStrings("reply from our client", dialer.reply[0..dialer.reply_len]);

    try conn.cancelRemoteForward("127.0.0.1", port);
}

// ── our server: several channels, pty, env, shell (real ssh client) ─────────

const info_handler: connection.CommandHandler = .{ .runInfoFn = struct {
    fn f(
        _: *anyopaque,
        gpa: std.mem.Allocator,
        info: *const connection.RequestInfo,
        stdin: []const u8,
        stdout: *std.ArrayList(u8),
        _: *std.ArrayList(u8),
    ) connection.CommandError!u32 {
        try stdout.print(gpa, "kind={t} cmd={s} ch={d}", .{ info.kind, info.command, info.channel });
        if (info.pty) |pty| try stdout.print(gpa, " pty={s}:{d}x{d}", .{ pty.term(), pty.cols, pty.rows });
        for (info.env) |e| try stdout.print(gpa, " env:{s}={s}", .{ e.name, e.value });
        if (stdin.len > 0) try stdout.print(gpa, " stdin={s}", .{stdin});
        try stdout.append(gpa, '\n');
        return 0;
    }
}.f };

test "live: our server serves several channels of one ssh connection (ControlMaster multiplexing)" {
    // The master holds the connection (-N: no session of its own); three
    // clients run through its socket, two of them at the same time, each a
    // separate session channel on OUR connection; then the master is told
    // to exit, which disconnects.
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try SshClient.start(gpa, threaded.io(), .{ .script =
        \\S=$OUT.sock; $SSH -o ControlMaster=yes -o ControlPath=$S -N -f $H &&
        \\{ $SSH -o ControlPath=$S $H first > $OUT.1 & $SSH -o ControlPath=$S $H second > $OUT.2 & wait; } &&
        \\$SSH -o ControlPath=$S $H third > $OUT.3; r=$?;
        \\cat $OUT.1 $OUT.2 $OUT.3 > $OUT; echo $r >> $OUT; $SSH -o ControlPath=$S -O exit $H 2>/dev/null
    });
    defer fx.deinit();
    const auth = try fx.authenticate();
    connection.serveConnection(&fx.t, gpa, .{ .user = auth.user(), .exec = info_handler, .stdin_mode = .ignore }) catch |e| {
        fx.dumpErr();
        return e;
    };
    const out = try fx.finish();
    defer gpa.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "kind=exec cmd=first") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "kind=exec cmd=second") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "kind=exec cmd=third") != null);
    try std.testing.expect(std.mem.endsWith(u8, out, "0\n"));
}

test "live: our server — ssh -tt gets a pty, SetEnv passes AcceptEnv-style names, a shell reads stdin" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try SshClient.start(gpa, threaded.io(), .{ .script =
        \\$SSH -tt -o SetEnv="ZIGTEST_ONE=1 OTHER=2" $H 'echo hi' > $OUT.1 </dev/null;
        \\printf 'typed into the shell' | $SSH -T $H > $OUT.2; r=$?;
        \\cat $OUT.1 $OUT.2 > $OUT; echo $r >> $OUT
    });
    defer fx.deinit();
    // First connection: the -tt exec.
    {
        const auth = try fx.authenticate();
        try connection.serveSession(&fx.t, gpa, .{
            .user = auth.user(),
            .exec = info_handler,
            .accept_env = &.{"ZIGTEST_*"},
            .stdin_mode = .ignore,
        });
    }
    // Second connection: a shell with stdin.
    try fx.acceptNext();
    {
        const auth = try fx.authenticate();
        try connection.serveSession(&fx.t, gpa, .{ .user = auth.user(), .shell = info_handler });
    }
    const out = try fx.finish();
    defer gpa.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "kind=exec cmd=echo hi") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, " pty=") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, " env:ZIGTEST_ONE=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "OTHER") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "kind=shell cmd= ch=0 stdin=typed into the shell") != null);
}

test "envAccepted: exact names and trailing-* prefixes only" {
    const t = std.testing;
    const pats = [_][]const u8{ "LANG", "LC_*", "ZIG" };
    try t.expect(connection.envAcceptedForTest(&pats, "LANG"));
    try t.expect(connection.envAcceptedForTest(&pats, "LC_ALL"));
    try t.expect(connection.envAcceptedForTest(&pats, "LC_"));
    try t.expect(!connection.envAcceptedForTest(&pats, "LANGUAGE"));
    try t.expect(!connection.envAcceptedForTest(&pats, "ZIGGY"));
    try t.expect(!connection.envAcceptedForTest(&.{}, "LANG"));
}

// ── keyboard-interactive (RFC 4256) ────────────────────────────────────────

/// Our client's keyboard-interactive against our own server, over a loopback
/// socket — the hermetic half; Go `x/crypto/ssh` (multi-round) is
/// `tools/interop.zig` (`zig build interop-ssh`), OpenSSH the live tests below.
const LoopbackKbd = struct {
    port: u16,
    answer: []const u8,
    err: ?anyerror = null,
    seen_prompts: u32 = 0,
    saw_instruction: bool = false,

    fn respond(ctx: *anyopaque, ch: *const userauth.KbdChallenge, answers: [][]const u8) bool {
        const self: *LoopbackKbd = @ptrCast(@alignCast(ctx));
        self.saw_instruction = std.mem.eql(u8, ch.instruction, "two factors");
        for (ch.prompts, answers) |p, *a| {
            self.seen_prompts += 1;
            a.* = if (!p.echo) "correct horse" else self.answer;
        }
        return true;
    }

    fn run(self: *LoopbackKbd, io: std.Io) void {
        self.client(io) catch |e| {
            self.err = e;
        };
    }

    fn client(self: *LoopbackKbd, io: std.Io) !void {
        const gpa = std.testing.allocator;
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", self.port);
        const stream = try addr.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        var rbuf: [32 * 1024]u8 = undefined;
        var wbuf: [32 * 1024]u8 = undefined;
        var sr = stream.reader(io, &rbuf);
        var sw = stream.writer(io, &wbuf);
        var t = try transport.connect(&sr.interface, &sw.interface, gpa, accept_any_host_key);
        defer t.deinit();
        var scratch: [4096]u8 = undefined;
        try t.requestService("ssh-userauth", &scratch);
        try userauth.authenticateKeyboardInteractive(&t, gpa, "alice", .{ .ctx = self, .respondFn = respond }, .{});
    }
};

fn loopbackKbd(answer: []const u8) !struct { client: LoopbackKbd, server: anyerror!userauth.AuthResult, why: ?userauth.AuthFailure } {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var port: u16 = 0;
    var listener = try listenLoopback(io, &port);
    defer listener.deinit(io);
    var c: LoopbackKbd = .{ .port = port, .answer = answer };
    const th = try std.Thread.spawn(.{}, LoopbackKbd.run, .{ &c, io });
    var joined = false;
    defer if (!joined) th.join();
    const stream = try acceptBounded(io, &listener, 30_000);
    defer stream.close(io);
    var rbuf: [32 * 1024]u8 = undefined;
    var wbuf: [32 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    const keys = [_]server.HostKey{testHostKey(0x55)};
    var t = try server.accept(&sr.interface, &sw.interface, gpa, .{ .host_keys = &keys });
    defer t.deinit();
    var why: ?userauth.AuthFailure = null;
    const RejectRec = struct {
        fn on(ctx: *anyopaque, _: ?[]const u8, reason: userauth.AuthFailure) void {
            const w: *?userauth.AuthFailure = @ptrCast(@alignCast(ctx));
            w.* = reason;
        }
    };
    const r = userauth.serveUserauth(&t, gpa, .{
        .keyboard_interactive = .{ .instruction = "two factors", .prompts = &kbd_prompts, .checkFn = KbdPolicy.check },
        .max_attempts = 1,
        .on_rejected = .{ .ctx = &why, .onFn = RejectRec.on },
    });
    th.join();
    joined = true;
    return .{ .client = c, .server = r, .why = why };
}

test "loopback: keyboard-interactive, our client against our server — accepted, then a wrong code refused" {
    const ok = try loopbackKbd("424242");
    if (ok.client.err) |e| return e;
    const res = try ok.server;
    try std.testing.expectEqual(userauth.AuthMethod.keyboard_interactive, res.method);
    try std.testing.expectEqualStrings("alice", res.user());
    try std.testing.expectEqual(@as(u32, 2), ok.client.seen_prompts);
    try std.testing.expect(ok.client.saw_instruction);

    const no = try loopbackKbd("000000");
    const client_err = no.client.err orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(error.AuthenticationFailed, client_err);
    try std.testing.expect(std.meta.isError(no.server));
    try std.testing.expectEqual(@as(?userauth.AuthFailure, .wrong_answers), no.why);
}

const KbdPolicy = struct {
    fn check(_: *anyopaque, user: []const u8, answers: []const []const u8) bool {
        return std.mem.eql(u8, user, "alice") and answers.len == 2 and
            std.mem.eql(u8, answers[0], "correct horse") and std.mem.eql(u8, answers[1], "424242");
    }
};

const kbd_prompts = [_]userauth.KbdPrompt{
    .{ .text = "Password: ", .echo = false },
    .{ .text = "One-time code: ", .echo = true },
};

test "live: a real ssh client logs in to our server with keyboard-interactive (askpass answers)" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try SshClient.start(gpa, threaded.io(), .{ .askpass_script =
        \\case "$1" in *Password*) echo 'correct horse';; *code*) echo 424242;; *) exit 1;; esac
    });
    defer fx.deinit();
    const auth = userauth.serveUserauth(&fx.t, gpa, .{ .keyboard_interactive = .{
        .instruction = "two factors",
        .prompts = &kbd_prompts,
        .checkFn = KbdPolicy.check,
    } }) catch |e| {
        _ = fx.finish() catch null;
        fx.dumpErr();
        return e;
    };
    try std.testing.expectEqual(userauth.AuthMethod.keyboard_interactive, auth.method);
    try std.testing.expectEqualStrings("alice", auth.user());
    try connection.serveSession(&fx.t, gpa, .{ .user = auth.user(), .exec = info_handler, .stdin_mode = .ignore });
    const out = try fx.finish();
    defer gpa.free(out);
    try std.testing.expect(std.mem.startsWith(u8, out, "kind=exec cmd=uname -a"));
}

test "live: a real ssh client with the wrong one-time code is refused by our server" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try SshClient.start(gpa, threaded.io(), .{ .askpass_script =
        \\case "$1" in *Password*) echo 'correct horse';; *code*) echo 999999;; *) exit 1;; esac
    });
    defer fx.deinit();
    var why: userauth.AuthFailure = undefined;
    const r = userauth.serveUserauth(&fx.t, gpa, .{
        .keyboard_interactive = .{ .prompts = &kbd_prompts, .checkFn = KbdPolicy.check },
        .failure = &why,
    });
    try std.testing.expect(std.meta.isError(r));
    try std.testing.expectEqual(userauth.AuthFailure.wrong_answers, why);
}

test "live: a Session freed mid-command is closed for us; the next channel on the connection is unaffected" {
    // Review 2026-10-06 M2: freeing a `Connection` channel used to leave it
    // open at sshd, and its late output then failed whichever channel was
    // pumping (`error.ChannelClosed`).
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try Sshd.start(gpa, threaded.io(), .{});
    defer fx.deinit();
    var conn = try connection.Connection.init(&fx.t, gpa);
    defer conn.deinit();
    {
        const abandoned = try conn.openSession(.{});
        try abandoned.exec("/bin/sh -c 'sleep 1; printf late-output; exit 9'");
        abandoned.deinit(); // no drain: sends our CLOSE, keeps the id as a zombie
    }
    const next = try conn.openSession(.{});
    defer next.deinit();
    try next.exec("/bin/sh -c 'sleep 2; printf next'");
    try next.drain();
    try std.testing.expectEqualStrings("next", next.stdout.items);
}

test "live: rekey_limit_bytes = 0 re-keys after every packet instead of looping" {
    // Review 2026-10-06 L6.
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var fx = try Sshd.start(gpa, threaded.io(), .{});
    defer fx.deinit();
    fx.t.rekey_limit_bytes = 0;
    var res = try connection.exec(&fx.t, gpa, "printf zero", .{});
    defer res.deinit(gpa);
    try std.testing.expectEqualStrings("zero", res.stdout);
    try std.testing.expect(fx.t.kex_count > 3);
}
