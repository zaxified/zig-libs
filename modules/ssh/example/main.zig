// SPDX-License-Identifier: MIT

//! `ssh-demo` — one binary, two modes (`client` and `server`), showing what a
//! real caller has to build on top of this module. Run it against a local
//! `sshd`, or against the other mode of itself.
//!
//! **The thing worth reading this for is the host-key decision.** The module
//! hands the caller a `HostKeyVerifier` callback and takes no position on
//! trust — it has no idea where your `known_hosts` lives, whether you want
//! trust-on-first-use, or whether a mismatch should abort or prompt. That is
//! deliberate and it is the norm (Go's `HostKeyCallback`, russh's
//! `check_server_key` have the same shape). It also means an example that
//! writes `return true` teaches the reader the one lesson we do not want them
//! to learn. So this one parses `known_hosts` for real: literal and hashed
//! host patterns, per-key-type entries, `@revoked` markers, the OpenSSH
//! mismatch warning, and a TOFU prompt that appends the accepted key.
//!
//! The whole policy is one `KnownHosts` value on `runClient`'s stack, reached
//! through `HostKeyVerifier.ctx`; it says *why* it refused with a
//! `HostKeyVerdict`, and reads the module's own reason back out of
//! `HostKeyPolicy.failure`. Two connections in one process would just be two
//! of these.
//!
//! What this module does NOT have, and what this demo therefore refuses
//! plainly rather than failing somewhere obscure: no PTY, no interactive
//! shell, no port forwarding, no agent (SPEC.md "Backlog / deferred"). One
//! command per connection, or one subsystem.
//!
//! Built against the PUBLISHED module (`@import("ssh")`) only — no
//! `test_deps`, no reaching into `src/`.

const std = @import("std");
const ssh = @import("ssh");

const Allocator = std.mem.Allocator;

/// `ssh(1)` reserves 255 for its own failures, so that a remote command's own
/// exit status can occupy the whole 0..254 range unambiguously. Same here.
const local_failure_exit: u8 = 255;

const usage_text =
    \\ssh-demo — an SSH-2.0 client/server demo for the `ssh` module.
    \\
    \\usage:
    \\  ssh-demo client [options] [command ...]
    \\  ssh-demo server [options]
    \\
    \\client options:
    \\  --host <host>          host to connect to            (default 127.0.0.1)
    \\  --port <port>          TCP port                      (default 22)
    \\  --user <name>          remote user                   (default $USER)
    \\  --identity <file>      OpenSSH private key           (default ~/.ssh/id_ed25519)
    \\  --known-hosts <file>   host-key database             (default ~/.ssh/known_hosts)
    \\  --subsystem <name>     start a subsystem instead of running a command
    \\  --accept-new           trust an unknown host without asking (still refuses
    \\                         a MISMATCH — this is OpenSSH's `accept-new`, not `no`)
    \\  --password             skip the identity file and ask for a password
    \\  -v                     print the negotiated algorithms, `ssh -v` style
    \\  -h, --help             this text
    \\  --                     end of options; the rest is the command
    \\
    \\With `--subsystem`, any trailing words are written to the subsystem as its
    \\first input and everything it writes back is streamed to stdout.
    \\
    \\The remote command's exit status becomes this process's exit status, as in
    \\`ssh(1)`; 255 means the demo itself failed (connect, host key, auth).
    \\
    \\not implemented by the `ssh` module (SPEC.md "Backlog / deferred"), so not
    \\offered here: PTY allocation, an interactive shell, port forwarding, agent
    \\forwarding, `keyboard-interactive`.
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    // A `DebugAllocator` that panics on leak makes the example a leak detector
    // for the module's ownership contract (CONVENTIONS.md §7.2) — every
    // `deinit`/`free` below is therefore load-bearing, not decoration.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.skip(); // argv[0]

    const mode = args.next() orelse {
        std.debug.print("{s}", .{usage_text});
        return local_failure_exit;
    };

    if (std.mem.eql(u8, mode, "client")) return runClient(gpa, io, init, &args);
    if (std.mem.eql(u8, mode, "server")) return runServer();
    if (std.mem.eql(u8, mode, "-h") or std.mem.eql(u8, mode, "--help")) {
        std.debug.print("{s}", .{usage_text});
        return 0;
    }

    std.debug.print("ssh-demo: unknown mode '{s}' (expected `client` or `server`)\n\n{s}", .{ mode, usage_text });
    return local_failure_exit;
}

// ─────────────────────────────────────────────────────────────────────────────
// server mode — STUB
// ─────────────────────────────────────────────────────────────────────────────

/// Not written yet. The mirror image of the client below: listen, offer a host
/// key, and discharge `userauth.AuthorizedKeyCheck` against a real
/// `authorized_keys` file the same way the client discharges
/// `transport.HostKeyVerifier` against `known_hosts` — over its own `ctx`,
/// and reporting its refusals through `AuthConfig.failure`. Deliberately left as a
/// stub rather than half-built, so that whoever writes it starts from the
/// module's `server.zig` / `connection.serveSession` API and not from a shape
/// guessed here.
fn runServer() u8 {
    std.debug.print("ssh-demo: server mode is not implemented yet\n", .{});
    return local_failure_exit;
}

// ─────────────────────────────────────────────────────────────────────────────
// client mode
// ─────────────────────────────────────────────────────────────────────────────

const ClientOptions = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 22,
    user: []const u8,
    /// Both of these may be heap-allocated defaults derived from `$HOME`;
    /// `owns_identity`/`owns_known_hosts` say whether to free them.
    identity: []const u8,
    known_hosts: []const u8,
    owns_identity: bool = false,
    owns_known_hosts: bool = false,
    subsystem: ?[]const u8 = null,
    accept_new: bool = false,
    force_password: bool = false,
    verbose: bool = false,
    /// The command line, or (with `--subsystem`) the initial payload. Owned.
    command: []const u8 = "",

    fn deinit(self: *ClientOptions, gpa: Allocator) void {
        if (self.owns_identity) gpa.free(self.identity);
        if (self.owns_known_hosts) gpa.free(self.known_hosts);
        gpa.free(self.command);
    }
};

/// Options this demo recognises only in order to say "no" clearly. Silently
/// ignoring `-L` would be worse than refusing it: the user would believe a
/// forward exists. Failing with `error.ProtocolError` three layers down would
/// be worse still.
const unsupported_flags = [_]struct { flag: []const u8, what: []const u8 }{
    .{ .flag = "-t", .what = "PTY allocation (`pty-req`)" },
    .{ .flag = "--pty", .what = "PTY allocation (`pty-req`)" },
    .{ .flag = "--shell", .what = "an interactive shell (`shell`)" },
    .{ .flag = "-L", .what = "local port forwarding" },
    .{ .flag = "-R", .what = "remote port forwarding" },
    .{ .flag = "-D", .what = "dynamic (SOCKS) forwarding" },
    .{ .flag = "-A", .what = "agent forwarding" },
};

fn runClient(
    gpa: Allocator,
    io: std.Io,
    init: std.process.Init.Minimal,
    args: *std.process.Args.Iterator,
) !u8 {
    var opts = parseClientArgs(gpa, init, args) catch |err| switch (err) {
        error.UsagePrinted => return 0,
        error.BadUsage => return local_failure_exit,
        else => return err,
    };
    defer opts.deinit(gpa);

    // The host pattern is what goes into (and is looked up in) known_hosts:
    // bare `host` on port 22, `[host]:port` otherwise — OpenSSH's rule, and
    // the string that gets HMAC'd for a hashed entry.
    const pattern = try hostPattern(gpa, opts.host, opts.port);
    defer gpa.free(pattern);

    // ── the trust decision ────────────────────────────────────────────────
    //
    // Everything the policy needs lives in this one struct, on this stack, and
    // reaches the callback through `HostKeyVerifier.ctx`. Two connections in
    // one process would simply be two of these — no globals, no per-thread
    // state, which is exactly what the seam's context pointer buys.
    var policy: KnownHosts = .{
        .io = io,
        .gpa = gpa,
        .path = opts.known_hosts,
        .pattern = pattern,
        .accept_new = opts.accept_new,
    };

    // ── connect ───────────────────────────────────────────────────────────
    const addr = std.Io.net.IpAddress.parse(opts.host, opts.port) catch |err| {
        std.debug.print("ssh-demo: cannot parse address {s}:{d}: {t}\n", .{ opts.host, opts.port, err });
        return local_failure_exit;
    };
    var stream = addr.connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("ssh-demo: cannot connect to {s}:{d}: {t}\n", .{ opts.host, opts.port, err });
        return local_failure_exit;
    };
    defer stream.close(io);

    var rbuf: [64 * 1024]u8 = undefined;
    var wbuf: [64 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    // `failure` is where the module writes WHY the host key was refused —
    // our own verdict, or its own signature/algorithm checks. Without it a
    // caller sees one `error.HostKeyVerificationFailed` for four different
    // situations and has to keep its own bookkeeping to tell them apart.
    var failure: ssh.transport.HostKeyFailure = undefined;
    var transport = ssh.transport.connect(&sr.interface, &sw.interface, gpa, .{
        .verifier = policy.verifier(),
        // The host and port the verifier looks up in known_hosts. The module
        // cannot know them — it is handed a reader and a writer, never an
        // address — so the caller says.
        .host = opts.host,
        .port = opts.port,
        .failure = &failure,
    }) catch |err| switch (err) {
        // The two errors that mean "we refused this server's identity";
        // `failure` is meaningful for exactly these.
        error.HostKeyVerificationFailed, error.UnsupportedAlgorithm => {
            reportHostKeyFailure(failure);
            return local_failure_exit;
        },
        else => {
            std.debug.print("ssh-demo: handshake failed: {t}\n", .{err});
            return local_failure_exit;
        },
    };

    if (opts.verbose) printNegotiated(&transport);

    // ── authenticate ──────────────────────────────────────────────────────
    if (!authenticateClient(gpa, io, &transport, &opts)) return local_failure_exit;

    // ── do the one thing this connection is for ───────────────────────────
    if (opts.subsystem) |name| return runSubsystem(gpa, io, &transport, name, opts.command);
    return runCommand(gpa, io, &transport, opts.command);
}

fn parseClientArgs(
    gpa: Allocator,
    init: std.process.Init.Minimal,
    args: *std.process.Args.Iterator,
) !ClientOptions {
    var opts: ClientOptions = .{
        .user = std.process.Environ.getPosix(init.environ, "USER") orelse "root",
        .identity = "",
        .known_hosts = "",
    };
    errdefer opts.deinit(gpa);

    var command: std.ArrayList([]const u8) = .empty;
    defer command.deinit(gpa);
    var rest_is_command = false;

    while (args.next()) |arg| {
        if (rest_is_command) {
            try command.append(gpa, arg);
            continue;
        }
        if (std.mem.eql(u8, arg, "--")) {
            rest_is_command = true;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage_text});
            return error.UsagePrinted;
        } else if (std.mem.eql(u8, arg, "-v")) {
            opts.verbose = true;
        } else if (std.mem.eql(u8, arg, "--accept-new")) {
            opts.accept_new = true;
        } else if (std.mem.eql(u8, arg, "--password")) {
            opts.force_password = true;
        } else if (std.mem.eql(u8, arg, "--host")) {
            opts.host = try nextValue(args, "--host");
        } else if (std.mem.eql(u8, arg, "--user")) {
            opts.user = try nextValue(args, "--user");
        } else if (std.mem.eql(u8, arg, "--identity")) {
            if (opts.owns_identity) gpa.free(opts.identity);
            opts.identity = try nextValue(args, "--identity");
            opts.owns_identity = false;
        } else if (std.mem.eql(u8, arg, "--known-hosts")) {
            if (opts.owns_known_hosts) gpa.free(opts.known_hosts);
            opts.known_hosts = try nextValue(args, "--known-hosts");
            opts.owns_known_hosts = false;
        } else if (std.mem.eql(u8, arg, "--subsystem")) {
            opts.subsystem = try nextValue(args, "--subsystem");
        } else if (std.mem.eql(u8, arg, "--port")) {
            const text = try nextValue(args, "--port");
            opts.port = std.fmt.parseInt(u16, text, 10) catch {
                std.debug.print("ssh-demo: --port wants a number, got '{s}'\n", .{text});
                return error.BadUsage;
            };
        } else if (unsupportedFlag(arg)) |what| {
            std.debug.print(
                \\ssh-demo: {s} is not implemented by the `ssh` module.
                \\  The connection protocol here covers `exec`, `subsystem` and `exit-status`
                \\  only; `pty-req`, `shell` and the forwarding requests are in SPEC.md's
                \\  "Backlog / deferred". Refusing rather than pretending.
                \\
            , .{what});
            return error.BadUsage;
        } else if (arg.len > 1 and arg[0] == '-') {
            std.debug.print("ssh-demo: unknown option '{s}' (try --help)\n", .{arg});
            return error.BadUsage;
        } else {
            try command.append(gpa, arg);
        }
    }

    // `$HOME`-derived defaults, applied only where the user did not choose.
    const home = std.process.Environ.getPosix(init.environ, "HOME");
    if (opts.identity.len == 0) {
        opts.identity = try defaultPath(gpa, home, ".ssh/id_ed25519");
        opts.owns_identity = true;
    }
    if (opts.known_hosts.len == 0) {
        opts.known_hosts = try defaultPath(gpa, home, ".ssh/known_hosts");
        opts.owns_known_hosts = true;
    }

    opts.command = try std.mem.join(gpa, " ", command.items);
    if (opts.subsystem == null and opts.command.len == 0) {
        std.debug.print("ssh-demo: nothing to do — give a command, or --subsystem <name>\n", .{});
        return error.BadUsage;
    }
    return opts;
}

fn nextValue(args: *std.process.Args.Iterator, flag: []const u8) ![]const u8 {
    return args.next() orelse {
        std.debug.print("ssh-demo: {s} needs a value\n", .{flag});
        return error.BadUsage;
    };
}

fn unsupportedFlag(arg: []const u8) ?[]const u8 {
    for (unsupported_flags) |u| {
        if (std.mem.eql(u8, arg, u.flag)) return u.what;
    }
    return null;
}

fn defaultPath(gpa: Allocator, home: ?[]const u8, suffix: []const u8) ![]u8 {
    // No `$HOME` (a daemon, a container): keep the relative name rather than
    // inventing an absolute path that is certainly wrong.
    const h = home orelse return gpa.dupe(u8, suffix);
    return std.fmt.allocPrint(gpa, "{s}/{s}", .{ h, suffix });
}

fn hostPattern(gpa: Allocator, host: []const u8, port: u16) ![]u8 {
    if (port == 22) return gpa.dupe(u8, host);
    return std.fmt.allocPrint(gpa, "[{s}]:{d}", .{ host, port });
}

// ─────────────────────────────────────────────────────────────────────────────
// `-v` — what the handshake actually negotiated
// ─────────────────────────────────────────────────────────────────────────────

/// Deliberately formatted to line up with real `ssh -v` output, so the reader
/// can run both against the same `sshd` and diff them. `Transport.negotiated`
/// is what makes this possible at all: the names used to be locals inside the
/// handshake and were dropped when it returned.
fn printNegotiated(t: *const ssh.transport.Transport) void {
    const neg = t.negotiated orelse {
        std.debug.print("debug1: no negotiated algorithms recorded\n", .{});
        return;
    };
    std.debug.print("debug1: kex: algorithm: {s}\n", .{neg.kex});
    std.debug.print("debug1: kex: host key algorithm: {s}\n", .{neg.host_key});
    // A `null` MAC is not "none": it means the cipher is an AEAD that
    // authenticates its own packets, which is exactly what `ssh -v` calls
    // `<implicit>`.
    std.debug.print("debug1: kex: server->client cipher: {s} MAC: {s} compression: none\n", .{
        neg.cipher_s2c,
        neg.mac_s2c orelse "<implicit>",
    });
    std.debug.print("debug1: kex: client->server cipher: {s} MAC: {s} compression: none\n", .{
        neg.cipher_c2s,
        neg.mac_c2s orelse "<implicit>",
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// known_hosts — the caller's half of the trust decision
// ─────────────────────────────────────────────────────────────────────────────

/// The caller's half of the trust decision, in one struct: where the
/// `known_hosts` file is, which host pattern to look up in it, and what to do
/// about a host that is not there yet.
///
/// It used to be a set of file-scope `var`s — the seam handed the callback
/// nothing but the key type and the blob, so there was nowhere else to put
/// this. `HostKeyVerifier.ctx` is what makes it an ordinary value on
/// `runClient`'s stack instead.
const KnownHosts = struct {
    io: std.Io,
    gpa: Allocator,
    /// `known_hosts` path, and the host pattern to look up in it.
    path: []const u8,
    /// This is also the name printed in every user-facing message: it is
    /// exactly what the file records, so naming anything else would tell the
    /// user to go looking for a line that is not there.
    pattern: []const u8,
    accept_new: bool,

    fn verifier(self: *KnownHosts) ssh.transport.HostKeyVerifier {
        return .{ .ctx = self, .verifyFn = verify };
    }

    /// The `transport.HostKeyVerifier` callback. Called from inside the key
    /// exchange with the server's `K_S` blob.
    ///
    /// ⚠ `key.key_blob` (and `key.key_type`, which points into it) is a slice
    /// into the handshake's scratch buffer and does NOT outlive this call, so
    /// anything kept — the known_hosts line appended below — is copied here
    /// and now.
    fn verify(ctx: *anyopaque, key: ssh.transport.HostKeyInfo) ssh.transport.HostKeyVerdict {
        const self: *KnownHosts = @ptrCast(@alignCast(ctx));

        const text = std.Io.Dir.cwd().readFileAlloc(self.io, self.path, self.gpa, .limited(4 * 1024 * 1024)) catch |err| switch (err) {
            // No known_hosts yet is the normal first-run state, not an error.
            error.FileNotFound => "",
            else => {
                std.debug.print("ssh-demo: cannot read {s}: {t}\n", .{ self.path, err });
                return .{ .reject = .other };
            },
        };
        defer if (text.len != 0) self.gpa.free(text);

        switch (lookupKnownHost(text, self.pattern, key.key_type, key.key_blob)) {
            .match => {
                std.debug.print("debug1: Host '{s}' is known and matches the {s} host key.\n", .{
                    self.pattern,
                    displayKeyType(key.key_type),
                });
                return .accept;
            },
            .revoked => |line| {
                std.debug.print(
                    \\@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                    \\@       WARNING: REVOKED HOST KEY WAS OFFERED!             @
                    \\@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                    \\The {s} host key for {s} is marked @revoked in {s}:{d}.
                    \\
                , .{ displayKeyType(key.key_type), self.pattern, self.path, line });
                return .{ .reject = .revoked };
            },
            .mismatch => |line| {
                self.warnMismatch(key, line);
                return .{ .reject = .key_mismatch };
            },
            .unknown => return self.trustOnFirstUse(key),
        }
    }

    /// The loud one. A key that changed is either an administrator who rotated
    /// it or someone sitting between us and the server, and the client cannot
    /// tell the two apart — so it refuses and says so in a way nobody scrolls
    /// past.
    fn warnMismatch(self: *KnownHosts, key: ssh.transport.HostKeyInfo, line: usize) void {
        var fp_buf: [64]u8 = undefined;
        std.debug.print(
            \\@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
            \\@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!      @
            \\@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
            \\IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
            \\Someone could be eavesdropping on you right now (man-in-the-middle attack)!
            \\It is also possible that a host key has just been changed.
            \\The fingerprint for the {s} key sent by the remote host is
            \\SHA256:{s}.
            \\Please contact your system administrator.
            \\Add correct host key in {s} to get rid of this message.
            \\Offending {s} key in {s}:{d}
            \\Host key verification failed.
            \\
        , .{
            displayKeyType(key.key_type),
            fingerprint(key.key_blob, &fp_buf),
            self.path,
            displayKeyType(key.key_type),
            self.path,
            line,
        });
    }

    /// First contact. There is no cryptographic way to check a key we have
    /// never seen — the honest options are to ask the human or to refuse, and
    /// every real client asks. `--accept-new` answers "yes" in advance
    /// (OpenSSH's `StrictHostKeyChecking=accept-new`), which still refuses a
    /// *mismatch*: the two cases are not the same risk and must not share a
    /// switch.
    fn trustOnFirstUse(self: *KnownHosts, key: ssh.transport.HostKeyInfo) ssh.transport.HostKeyVerdict {
        var fp_buf: [64]u8 = undefined;
        const fp = fingerprint(key.key_blob, &fp_buf);

        if (!self.accept_new) {
            std.debug.print(
                \\The authenticity of host '{s}' can't be established.
                \\{s} key fingerprint is SHA256:{s}.
                \\This key is not known by any other names.
                \\
            , .{ self.pattern, displayKeyType(key.key_type), fp });
            // Separate call so the trailing space survives — the prompt must
            // not end in a newline, and a trailing space inside a `\\` literal
            // is exactly the kind of thing an editor silently strips.
            std.debug.print("Are you sure you want to continue connecting (yes/no)? ", .{});

            if (!self.readYes()) {
                std.debug.print("Host key verification failed.\n", .{});
                return .{ .reject = .declined };
            }
        }

        self.appendKnownHost(key) catch |err| {
            // OpenSSH warns and continues here, and so do we: the connection
            // is no less safe than the user just said it was — they simply get
            // asked again next time.
            std.debug.print("Failed to add the host to the list of known hosts ({s}): {t}\n", .{ self.path, err });
            return .accept;
        };
        std.debug.print("Warning: Permanently added '{s}' ({s}) to the list of known hosts.\n", .{
            self.pattern,
            displayKeyType(key.key_type),
        });
        return .accept;
    }

    /// Read one line from stdin and accept only a literal `yes`, the way `ssh`
    /// does — a bare `y` or an empty line (someone leaning on return) must not
    /// be enough to pin a key forever.
    fn readYes(self: *KnownHosts) bool {
        var buf: [64]u8 = undefined;
        var r = std.Io.File.stdin().reader(self.io, &buf);
        const line = (r.interface.takeDelimiter('\n') catch return false) orelse return false;
        return std.mem.eql(u8, std.mem.trim(u8, line, " \t\r"), "yes");
    }

    /// Append `pattern keytype base64` — the exact OpenSSH line format, so the
    /// file this demo writes stays usable by `ssh` and `ssh-keygen -F`.
    ///
    /// Read-modify-write rather than an append-mode open: `std.Io.Dir` has no
    /// append flag, and for a file this size the difference is not worth a
    /// second mechanism. A production client would use `createFileAtomic` and
    /// hold a lock so two concurrent connections cannot interleave.
    fn appendKnownHost(self: *KnownHosts, key: ssh.transport.HostKeyInfo) !void {
        const cwd = std.Io.Dir.cwd();

        const old = cwd.readFileAlloc(self.io, self.path, self.gpa, .limited(4 * 1024 * 1024)) catch |err| switch (err) {
            error.FileNotFound => try self.gpa.dupe(u8, ""),
            else => return err,
        };
        defer self.gpa.free(old);

        const enc = std.base64.standard.Encoder;
        const b64 = try self.gpa.alloc(u8, enc.calcSize(key.key_blob.len));
        defer self.gpa.free(b64);
        _ = enc.encode(b64, key.key_blob);

        var file = try cwd.createFile(self.io, self.path, .{ .truncate = true });
        defer file.close(self.io);
        var buf: [4096]u8 = undefined;
        var fw = file.writer(self.io, &buf);
        try fw.interface.writeAll(old);
        if (old.len != 0 and old[old.len - 1] != '\n') try fw.interface.writeAll("\n");
        try fw.interface.print("{s} {s} {s}\n", .{ self.pattern, key.key_type, b64 });
        try fw.interface.flush();
    }
};

/// Printed once the handshake error has come back out of the module. The
/// module fills in `HostKeyFailure` before it returns, so this is a plain
/// switch over what actually happened — no "did my verifier even run?"
/// bookkeeping, which is what this used to be.
fn reportHostKeyFailure(failure: ssh.transport.HostKeyFailure) void {
    switch (failure) {
        // Our own policy already said its piece, loudly, at the moment it
        // decided — except for the cases it cannot reach from here.
        .policy => |why| switch (why) {
            .key_mismatch, .revoked, .declined => {},
            .unknown_host => std.debug.print("ssh-demo: host is not in the known_hosts file\n", .{}),
            .other => std.debug.print("ssh-demo: the host key was refused by local policy\n", .{}),
        },
        // The three below are the module's refusals, not ours, and each names
        // a different thing for the user to go and check.
        .algorithm_mismatch => std.debug.print(
            "ssh-demo: the server signed with a different host-key algorithm than it negotiated\n",
            .{},
        ),
        .bad_signature => std.debug.print(
            "ssh-demo: we trusted the host key, but the server could not prove it holds the private half\n",
            .{},
        ),
        .unsupported_algorithm => std.debug.print(
            "ssh-demo: the server's host-key algorithm is not one this module can verify\n",
            .{},
        ),
    }
}

const Verdict = union(enum) {
    unknown,
    match,
    /// Line number (1-based) of the entry that disagrees.
    mismatch: usize,
    revoked: usize,
};

/// Walk a `known_hosts` file for `pattern`.
///
/// The subtlety worth copying: an entry only *contradicts* the offered key
/// when it is for the same host AND the same key type. A host legitimately has
/// an ed25519 and an rsa key on file at once, and treating "we have your rsa
/// key, you offered ed25519" as tampering would make the warning meaningless
/// through overuse. So a type mismatch is skipped, and only a same-type,
/// different-bytes entry is a mismatch.
fn lookupKnownHost(text: []const u8, pattern: []const u8, key_type: []const u8, key_blob: []const u8) Verdict {
    var verdict: Verdict = .unknown;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var line_no: usize = 0;
    while (lines.next()) |raw| {
        line_no += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        var fields = std.mem.tokenizeAny(u8, line, " \t");
        var first = fields.next() orelse continue;

        // Optional marker. `@cert-authority` entries delegate trust to a CA
        // key, which this module cannot verify (no certificate key types), so
        // they are skipped rather than misread as a plain host key.
        var revoked = false;
        if (first.len != 0 and first[0] == '@') {
            if (std.mem.eql(u8, first, "@revoked")) {
                revoked = true;
            } else {
                continue;
            }
            first = fields.next() orelse continue;
        }

        if (!matchHostField(first, pattern)) continue;

        const entry_type = fields.next() orelse continue;
        const entry_b64 = fields.next() orelse continue;

        // A revoked entry for this host applies whatever key type it names:
        // the point of the marker is "never trust this key material again".
        if (revoked) {
            if (base64Eql(entry_b64, key_blob)) return .{ .revoked = line_no };
            continue;
        }

        if (!std.mem.eql(u8, entry_type, key_type)) continue;
        if (base64Eql(entry_b64, key_blob)) return .match;
        // Keep looking — a later line may hold the current key — but remember
        // this one in case nothing matches.
        if (verdict == .unknown) verdict = .{ .mismatch = line_no };
    }
    return verdict;
}

/// One `known_hosts` host field: a comma-separated list of patterns, each
/// either a literal (`host`, `[host]:port`) or the hashed form
/// `|1|<b64 salt>|<b64 HMAC-SHA1(salt, host)>`.
///
/// Hashed entries are handled because `HashKnownHosts yes` is the default on
/// several distributions, so refusing them would mean the demo silently
/// re-prompts on hosts the user demonstrably already trusts. What is NOT
/// handled is wildcard/negation patterns (`*.example.com`, `!host`): OpenSSH
/// never writes those itself, they only appear in hand-edited files.
fn matchHostField(field: []const u8, pattern: []const u8) bool {
    var it = std.mem.splitScalar(u8, field, ',');
    while (it.next()) |entry| {
        if (entry.len == 0) continue;
        if (std.mem.startsWith(u8, entry, "|1|")) {
            if (matchHashedHost(entry, pattern)) return true;
            continue;
        }
        if (std.mem.eql(u8, entry, pattern)) return true;
    }
    return false;
}

fn matchHashedHost(entry: []const u8, pattern: []const u8) bool {
    const body = entry["|1|".len..];
    const bar = std.mem.indexOfScalar(u8, body, '|') orelse return false;
    const salt_b64 = body[0..bar];
    const hash_b64 = body[bar + 1 ..];

    const dec = std.base64.standard.Decoder;
    var salt: [64]u8 = undefined;
    var want: [64]u8 = undefined;
    const salt_len = dec.calcSizeForSlice(salt_b64) catch return false;
    const want_len = dec.calcSizeForSlice(hash_b64) catch return false;
    if (salt_len > salt.len or want_len != std.crypto.auth.hmac.HmacSha1.mac_length) return false;
    dec.decode(salt[0..salt_len], salt_b64) catch return false;
    dec.decode(want[0..want_len], hash_b64) catch return false;

    var got: [std.crypto.auth.hmac.HmacSha1.mac_length]u8 = undefined;
    std.crypto.auth.hmac.HmacSha1.create(&got, pattern, salt[0..salt_len]);
    return std.mem.eql(u8, &got, want[0..want_len]);
}

/// Compare a base64 field against raw key-blob bytes without allocating.
fn base64Eql(b64: []const u8, raw: []const u8) bool {
    const dec = std.base64.standard.Decoder;
    var buf: [8 * 1024]u8 = undefined;
    const n = dec.calcSizeForSlice(b64) catch return false;
    if (n != raw.len or n > buf.len) return false;
    dec.decode(buf[0..n], b64) catch return false;
    return std.mem.eql(u8, buf[0..n], raw);
}

/// `SHA256:<base64, unpadded>` over the whole key blob — byte-identical to
/// what `ssh-keygen -lf` prints, which is the point: a reader must be able to
/// check our fingerprint against the standard tool.
fn fingerprint(key_blob: []const u8, out: *[64]u8) []const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key_blob, &digest, .{});
    const enc = std.base64.standard_no_pad.Encoder;
    const n = enc.calcSize(digest.len);
    _ = enc.encode(out[0..n], &digest);
    return out[0..n];
}

/// `ssh` names key types in upper case in its human-facing messages while
/// `known_hosts` stores the wire name; keep both straight.
fn displayKeyType(key_type: []const u8) []const u8 {
    if (std.mem.eql(u8, key_type, "ssh-ed25519")) return "ED25519";
    if (std.mem.eql(u8, key_type, "ssh-rsa")) return "RSA";
    if (std.mem.startsWith(u8, key_type, "ecdsa-sha2-")) return "ECDSA";
    return key_type;
}

// ─────────────────────────────────────────────────────────────────────────────
// authentication
// ─────────────────────────────────────────────────────────────────────────────

/// `publickey` first, `password` as the fallback — the order every SSH client
/// uses, and the reason the module's `authenticate` takes a key rather than a
/// list of methods: choosing between them is policy, so it is ours.
fn authenticateClient(
    gpa: Allocator,
    io: std.Io,
    transport: *ssh.transport.Transport,
    opts: *const ClientOptions,
) bool {
    if (!opts.force_password) {
        if (loadIdentity(gpa, io, opts.identity)) |key| {
            if (ssh.authenticate(transport, gpa, opts.user, key)) |_| {
                std.debug.print("debug1: Authentication succeeded (publickey).\n", .{});
                return true;
            } else |err| switch (err) {
                // Named explicitly: this is the one failure a user must be
                // able to act on, and it is not a bug in the connection.
                error.AuthenticationFailed => std.debug.print(
                    "ssh-demo: {s} was rejected for user {s}; falling back to password\n",
                    .{ opts.identity, opts.user },
                ),
                else => {
                    std.debug.print("ssh-demo: publickey authentication failed: {t}\n", .{err});
                    return false;
                },
            }
        }
    }

    // The password path re-uses the same already-authenticated-service
    // transport; `authenticate` above already requested `ssh-userauth`, and
    // requesting it twice is a protocol error, so the fallback goes through
    // the per-method entry point rather than through `authenticate` again.
    const password = readPassword(gpa, io, opts.user, opts.host) catch |err| {
        std.debug.print("ssh-demo: cannot read a password: {t}\n", .{err});
        return false;
    };
    defer {
        std.crypto.secureZero(u8, password);
        gpa.free(password);
    }

    if (opts.force_password) {
        // Nothing has requested `ssh-userauth` yet on this path.
        var buf: [8 * 1024]u8 = undefined;
        transport.requestService("ssh-userauth", &buf) catch |err| {
            std.debug.print("ssh-demo: ssh-userauth was refused: {t}\n", .{err});
            return false;
        };
    }

    ssh.userauth.authenticatePassword(transport, gpa, opts.user, password) catch |err| switch (err) {
        error.AuthenticationFailed => {
            std.debug.print("ssh-demo: permission denied for user {s}\n", .{opts.user});
            return false;
        },
        else => {
            std.debug.print("ssh-demo: password authentication failed: {t}\n", .{err});
            return false;
        },
    };
    std.debug.print("debug1: Authentication succeeded (password).\n", .{});
    return true;
}

/// Load an OpenSSH private key. `AuthKey.fromOpenSSH` reads the
/// `openssh-key-v1` container and dispatches on the key type it names, so
/// ed25519 and rsa keys both just work; an `ecdsa` private key is rejected
/// with `error.UnsupportedKeyType` even though the module can *sign* with
/// `AuthKey.ecdsa_p256` — the loader is the gap, not the algorithm.
fn loadIdentity(gpa: Allocator, io: std.Io, path: []const u8) ?ssh.userauth.AuthKey {
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 * 1024)) catch |err| {
        std.debug.print("debug1: no usable identity at {s}: {t}\n", .{ path, err });
        return null;
    };
    defer {
        // Private key material: do not leave it in the heap for the next
        // allocation to inherit.
        std.crypto.secureZero(u8, text);
        gpa.free(text);
    }
    return ssh.userauth.AuthKey.fromOpenSSH(text, null) catch |err| {
        std.debug.print("debug1: cannot load {s}: {t}\n", .{ path, err });
        return null;
    };
}

/// Prompt without echoing. Turning `ECHO` off is the caller's job in every
/// language; getting it wrong leaves the password in the user's scrollback and
/// in their terminal's copy buffer.
fn readPassword(gpa: Allocator, io: std.Io, user: []const u8, host: []const u8) ![]u8 {
    std.debug.print("{s}@{s}'s password: ", .{ user, host });

    const stdin = std.Io.File.stdin();
    // Not a terminal (a pipe, a CI runner): read the line as-is rather than
    // failing — but say so, because the secret is then not being hidden.
    const saved: ?std.posix.termios = std.posix.tcgetattr(stdin.handle) catch |err| blk: {
        if (err == error.NotATerminal) break :blk null;
        return err;
    };
    if (saved) |term| {
        var quiet = term;
        quiet.lflag.ECHO = false;
        try std.posix.tcsetattr(stdin.handle, .FLUSH, quiet);
    }
    defer if (saved) |term| {
        std.posix.tcsetattr(stdin.handle, .FLUSH, term) catch {};
        std.debug.print("\n", .{});
    };

    var buf: [1024]u8 = undefined;
    var r = stdin.reader(io, &buf);
    const line = (try r.interface.takeDelimiter('\n')) orelse return error.EndOfStream;
    return gpa.dupe(u8, std.mem.trim(u8, line, "\r"));
}

// ─────────────────────────────────────────────────────────────────────────────
// running something on the far end
// ─────────────────────────────────────────────────────────────────────────────

/// One command, one connection — `exec` opens the session channel, sends the
/// RFC 4254 §6.5 request, drains stdout/stderr and collects the §6.10 exit
/// status.
///
/// `exit_status` is optional because `exit-signal` is not implemented (SPEC.md
/// says so): a command killed by a signal reports no status at all. `ssh(1)`
/// answers 255 in that case and so do we, rather than inventing a 0.
fn runCommand(gpa: Allocator, io: std.Io, transport: *ssh.transport.Transport, command: []const u8) !u8 {
    var result = ssh.exec(transport, gpa, command, .{}) catch |err| {
        std.debug.print("ssh-demo: cannot run the command: {t}\n", .{err});
        return local_failure_exit;
    };
    defer result.deinit(gpa);

    try writeOut(io, std.Io.File.stdout(), result.stdout);
    try writeOut(io, std.Io.File.stderr(), result.stderr);

    if (result.exit_status) |status| {
        // RFC 4254 §6.10 carries a uint32; a POSIX wait status is 8 bits.
        return @truncate(status);
    }
    std.debug.print("ssh-demo: the remote command reported no exit status (killed by a signal?)\n", .{});
    return local_failure_exit;
}

/// The streaming path: `openSession` → `subsystem` → `pumpOnce`. This is the
/// shape a NETCONF-over-SSH (RFC 6242) caller drives — the `netconf` module's
/// `SshTransport` is exactly this loop behind a byte-stream interface — and it
/// is why `Session` exposes a pump at all instead of only the one-shot `exec`.
///
/// A long-lived subsystem client would not send EOF here; it would keep
/// writing requests between pumps. A one-shot demo has to terminate, so it
/// half-closes after the initial payload and reads until the peer closes.
fn runSubsystem(
    gpa: Allocator,
    io: std.Io,
    transport: *ssh.transport.Transport,
    name: []const u8,
    payload: []const u8,
) !u8 {
    var session = ssh.openSession(transport, gpa, .{}) catch |err| {
        std.debug.print("ssh-demo: cannot open a session channel: {t}\n", .{err});
        return local_failure_exit;
    };
    defer session.deinit();

    session.subsystem(name) catch |err| switch (err) {
        // The peer answering CHANNEL_FAILURE is the normal "no such
        // subsystem" answer, and it deserves its own message.
        error.ChannelRequestFailed => {
            std.debug.print("ssh-demo: the server refused subsystem '{s}'\n", .{name});
            return local_failure_exit;
        },
        else => {
            std.debug.print("ssh-demo: subsystem '{s}' failed: {t}\n", .{ name, err });
            return local_failure_exit;
        },
    };

    if (payload.len != 0) try session.writeData(payload);
    try session.sendEof();

    var out_buf: [16 * 1024]u8 = undefined;
    var out = std.Io.File.stdout().writer(io, &out_buf);
    defer out.interface.flush() catch {};

    while (true) {
        const event = session.pumpOnce() catch |err| {
            std.debug.print("ssh-demo: subsystem stream failed: {t}\n", .{err});
            return local_failure_exit;
        };
        // Drain as we go and hand the bytes straight on, so the reader can see
        // that this really is a stream and not a buffer that happens to be
        // printed at the end. Clearing `session.stdout` is also what keeps a
        // long-running subsystem from growing it without bound.
        if (session.stdout.items.len != 0) {
            try out.interface.writeAll(session.stdout.items);
            try out.interface.flush();
            session.stdout.clearRetainingCapacity();
        }
        if (session.stderr.items.len != 0) {
            try writeOut(io, std.Io.File.stderr(), session.stderr.items);
            session.stderr.clearRetainingCapacity();
        }
        if (event == .closed) break;
        if (event == .eof) {
            // The peer will not send more data; answer its close and stop.
            session.close() catch {};
            break;
        }
    }

    if (session.exitStatus()) |status| return @truncate(status);
    return 0;
}

fn writeOut(io: std.Io, file: std.Io.File, bytes: []const u8) !void {
    if (bytes.len == 0) return;
    var buf: [4096]u8 = undefined;
    var w = file.writer(io, &buf);
    try w.interface.writeAll(bytes);
    try w.interface.flush();
}
