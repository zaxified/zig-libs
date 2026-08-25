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
//! The server mode is the same lesson from the other side. `AuthorizedKeyCheck`
//! is the seam there, and this one discharges it against a real
//! `authorized_keys` file — `@revoked` and `@cert-authority` markers, quoted
//! option fields including `command="..."`, one key type per line, the decoded
//! blob compared — and logs *why* it refused, both in its own words and in the
//! module's, through `AuthConfig.failure`. It loads several host keys so the
//! client gets to pick the algorithm, runs a real command through
//! `CommandHandler` under a byte cap and a deadline, and offers one small
//! subsystem that is honestly not SFTP.
//!
//! What this module does NOT have, and what this demo therefore refuses
//! plainly rather than failing somewhere obscure: no PTY, no interactive
//! shell, no port forwarding, no agent (SPEC.md "Backlog / deferred"); one
//! session channel at a time, so a concurrent second one is refused. Every one
//! of those is said out loud at startup rather than left to be discovered as a
//! hang.
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
    \\server options:
    \\  --listen <addr>        address to bind               (default 127.0.0.1)
    \\  --port <port>          TCP port                      (default 2222)
    \\  --host-key <file>      OpenSSH private host key; REPEAT it to offer more
    \\                         than one algorithm and let the client choose
    \\  --authorized-keys <f>  authorized_keys database      (default ~/.ssh/authorized_keys)
    \\  --user <name>          the one account that file belongs to (default $USER)
    \\  --shell <path>         program an `exec` command runs under (default /bin/sh -c)
    \\  --max-output <bytes>   cap on one command's stdout/stderr    (default 65536)
    \\  --exec-timeout <ms>    kill a command that outlives this     (default 10000)
    \\  --collect-stdin        hand the client's stdin to the command; a client that
    \\                         never sends EOF then never gets any output
    \\  --strict-rsa           accept rsa-sha2-512 user keys only, not -256
    \\  --password-is <secret> EXAMPLE ONLY: also accept this literal password
    \\  --max-auth-tries <n>   rejected credentials before disconnect (default 3;
    \\                         the `none` probe an OpenSSH client sends first spends
    \\                         one of them, so 1 locks everybody out)
    \\  --once                 serve one connection, then exit
    \\  -v                     print the negotiated algorithms, `ssh -v` style
    \\
    \\A server has to have a host key: `--host-key` is required. Make one with
    \\  ssh-keygen -q -t ed25519 -N "" -f ./demo_host_ed25519
    \\and point a real client at it with
    \\  ssh -p 2222 -o UserKnownHostsFile=./demo_known_hosts you@127.0.0.1 'uname -a'
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
    if (std.mem.eql(u8, mode, "server")) return runServer(gpa, io, init, &args);
    if (std.mem.eql(u8, mode, "-h") or std.mem.eql(u8, mode, "--help")) {
        std.debug.print("{s}", .{usage_text});
        return 0;
    }

    std.debug.print("ssh-demo: unknown mode '{s}' (expected `client` or `server`)\n\n{s}", .{ mode, usage_text });
    return local_failure_exit;
}

// ─────────────────────────────────────────────────────────────────────────────
// server mode
// ─────────────────────────────────────────────────────────────────────────────
//
// The mirror image of the client, and it exists for the same reason. The module
// hands the caller `userauth.AuthorizedKeyCheck` and takes no position on who
// may log in; a hook that answered `return true` would teach the one lesson
// this demo exists to prevent. So this one parses `authorized_keys` for real —
// `@revoked` and `@cert-authority` markers, quoted option fields, one key type
// per line — compares the decoded blob, and says WHY it refused through both
// `AuthConfig.failure` (the module's own vocabulary) and its own `ctx` (the
// richer reason the module deliberately does not model).
//
// Everything the server needs is one `ServerState` on `runServer`'s stack. Two
// servers in one process, or one server per virtual host, would be two of
// these — no globals anywhere, which is exactly what the seams' `ctx` buys.

/// Session channels served on one connection before the server gives up on it.
/// `serveSession` serves exactly one and returns, so a client that keeps the
/// transport open (OpenSSH's `ControlMaster` does) gets more than one — one
/// after another, never two at a time.
const max_sessions_per_connection: usize = 16;

/// The `subsystem` name this server implements. NOT `sftp`: there is no SFTP
/// anywhere in this module, and answering to that name would be a lie a reader
/// would find out about only after `sftp -P 2222` hung.
const demo_subsystem_name = "demo-info@zig-libs";

const server_banner =
    \\*** ssh-demo: the `ssh` module's EXAMPLE server. Not an sshd. ***
    \\
;

const server_banner_with_password =
    \\*** ssh-demo: the `ssh` module's EXAMPLE server. Not an sshd. ***
    \\*** Password authentication is ON and the secret came from the command line
    \\*** of this process, where `ps` can read it. It exists to show the RFC 4252
    \\*** section 8 method working end to end; do not copy this into anything real.
    \\
;

const ServerOptions = struct {
    listen: []const u8 = "127.0.0.1",
    port: u16 = 2222,
    /// May be a `$HOME`-derived default this struct owns.
    authorized_keys: []const u8 = "",
    owns_authorized_keys: bool = false,
    /// The single account `authorized_keys` belongs to — OpenSSH's file has no
    /// user column because it IS one user's file, so the server has to know
    /// whose it is rather than matching it against any name a client claims.
    user: []const u8,
    /// Set only by `--password-is`; `null` leaves the `password` method
    /// disabled, which is what `AuthConfig.password = null` means.
    password: ?[]const u8 = null,
    max_auth_tries: u32 = 3,
    max_output: usize = 64 * 1024,
    exec_timeout_ms: u32 = 10_000,
    collect_stdin: bool = false,
    strict_rsa: bool = false,
    once: bool = false,
    verbose: bool = false,
    shell: []const u8 = "/bin/sh",
    /// Paths, borrowed from argv; the loaded keys live in `runServer`.
    host_key_paths: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *ServerOptions, gpa: Allocator) void {
        if (self.owns_authorized_keys) gpa.free(self.authorized_keys);
        self.host_key_paths.deinit(gpa);
    }
};

fn runServer(
    gpa: Allocator,
    io: std.Io,
    init: std.process.Init.Minimal,
    args: *std.process.Args.Iterator,
) !u8 {
    var opts = parseServerArgs(gpa, init, args) catch |err| switch (err) {
        error.UsagePrinted => return 0,
        error.BadUsage => return local_failure_exit,
        else => return err,
    };
    defer opts.deinit(gpa);

    // ── the keys this server can prove its identity with ──────────────────
    var host_keys: std.ArrayList(ssh.server.HostKey) = .empty;
    defer host_keys.deinit(gpa);
    loadHostKeys(gpa, io, opts.host_key_paths.items, &host_keys) catch |err| {
        std.debug.print("ssh-demo: loading host keys failed: {t}\n", .{err});
        return local_failure_exit;
    };
    if (host_keys.items.len == 0) {
        std.debug.print("ssh-demo: no usable host key — refusing to start\n", .{});
        return local_failure_exit;
    }
    printHostKeys(gpa, host_keys.items);

    // ── the policies, all of them values on this stack ────────────────────
    var state: ServerState = .{
        .gpa = gpa,
        .io = io,
        .opts = &opts,
        .host_keys = host_keys.items,
        .keys = .{
            .io = io,
            .gpa = gpa,
            .path = opts.authorized_keys,
            .user = opts.user,
            .strict_rsa = opts.strict_rsa,
            .verbose = opts.verbose,
        },
        .passwords = .{ .user = opts.user, .secret = opts.password orelse "" },
        .commands = .{
            .io = io,
            .shell = opts.shell,
            .max_output = opts.max_output,
            .timeout_ms = opts.exec_timeout_ms,
            .verbose = opts.verbose,
        },
        .subsystems = .{ .verbose = opts.verbose },
    };
    // The exec handler asks the authorized_keys policy for a `command="..."`
    // option, so it needs a pointer to it. Set after construction because both
    // live in the same struct.
    state.commands.keys = &state.keys;

    // ── listen ────────────────────────────────────────────────────────────
    const addr = std.Io.net.IpAddress.parse(opts.listen, opts.port) catch |err| {
        std.debug.print("ssh-demo: cannot parse listen address {s}:{d}: {t}\n", .{ opts.listen, opts.port, err });
        return local_failure_exit;
    };
    // ⚠ Deliberately NOT `reuse_address`. In `std.Io.net` that flag sets
    // SO_REUSEADDR **and SO_REUSEPORT**, and SO_REUSEPORT means a second
    // `ssh-demo server` on this port does not fail to bind: it silently shares
    // the port with the first, and the kernel deals connections out between
    // them. A reader who left one running in another terminal would then see
    // roughly half their connections answered by a server they cannot see —
    // which costs far more than the convenience of rebinding a port that is
    // still in TIME_WAIT. Failing loudly is the better trade here.
    var listener = addr.listen(io, .{}) catch |err| {
        std.debug.print("ssh-demo: cannot listen on {s}:{d}: {t}\n", .{ opts.listen, opts.port, err });
        if (err == error.AddressInUse) std.debug.print(
            \\  Either another ssh-demo server is already on that port, or a connection
            \\  this one served is still in TIME_WAIT — wait a moment, or pass --port.
            \\
        , .{});
        return local_failure_exit;
    };
    defer listener.deinit(io);

    std.debug.print("ssh-demo: listening on {s} port {d} for user {s}\n", .{ opts.listen, opts.port, opts.user });
    std.debug.print("ssh-demo: authorized_keys is {s}\n", .{opts.authorized_keys});
    printServerBoundaries(&opts);

    while (true) {
        var stream = listener.accept(io) catch |err| {
            std.debug.print("ssh-demo: accept failed: {t}\n", .{err});
            return local_failure_exit;
        };
        state.serveConnection(&stream);
        stream.close(io);
        if (opts.once) break;
    }
    return 0;
}

/// What this server advertises in RFC 8308 `server-sig-algs` by default:
/// everything `ssh.userauth.serveUserauth` can verify, which is the module's
/// own `transport.public_key_algorithms`. Spelled out rather than referenced
/// so the two lines below can differ, and so the startup banner can print the
/// same text the wire carries.
const default_sig_algs = [_][]const u8{ "ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256" };
const default_sig_algs_text = "ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256";

/// …and what it advertises under `--strict-rsa`, whose whole point is that
/// `rsa-sha2-256` is refused. Advertising a name this server's own hook then
/// refuses is worse than saying nothing: the client offers it, gets one
/// USERAUTH_FAILURE, and has no second algorithm to fall back to.
const strict_rsa_sig_algs = [_][]const u8{ "ssh-ed25519", "rsa-sha2-512", "ecdsa-sha2-nistp256" };
const strict_rsa_sig_algs_text = "ssh-ed25519,rsa-sha2-512,ecdsa-sha2-nistp256";

/// Printed once at startup. Every line is a place where this module stops and
/// a reader would otherwise meet a hang or a silence instead of an answer —
/// the module's boundaries said out loud, which is the whole reason this
/// example is worth reading next to the README.
fn printServerBoundaries(opts: *const ServerOptions) void {
    std.debug.print(
        \\ssh-demo: what this server does NOT do, so nothing surprises you:
        \\  - one connection at a time. A second dialler waits in the kernel's
        \\    accept backlog until this one is finished.
        \\  - one session channel at a time. `connection.serveSession` answers a
        \\    CONCURRENT second SSH_MSG_CHANNEL_OPEN with CHANNEL_OPEN_FAILURE
        \\    (resource_shortage) itself and gives the server no hook to log it,
        \\    so you will see that refusal on the CLIENT side, not here.
        \\    Sequential channels on one transport are fine (up to {d}).
        \\  - no PTY, no shell, no forwarding, no agent, no SFTP: `pty-req`,
        \\    `shell`, `env` and the forwarding requests are answered
        \\    SSH_MSG_CHANNEL_FAILURE by the module (SPEC.md "Backlog").
        \\  - no rekeying, so do not leave a connection up under load.
        \\  - a command's output is buffered whole before ANY of it is sent:
        \\    `CommandHandler` is a one-shot function, not a pipe, so `tail -f`
        \\    would produce nothing until it ended. Capped at {d} bytes.
        \\  - no keyboard-interactive, no hostbased, no certificates: an OpenSSH
        \\    client with only one of those is out of luck (SPEC.md "Backlog").
        \\
        \\ssh-demo: what it DOES advertise (RFC 8308 SSH_MSG_EXT_INFO):
        \\  server-sig-algs = {s}
        \\  That name-list is why a real `ssh` will offer an RSA user key here:
        \\  an `ssh-rsa` blob names no hash, so a client that is not told will
        \\  not guess ("send_pubkey_test: no mutual signature algorithm").
        \\
    , .{ max_sessions_per_connection, opts.max_output, if (opts.strict_rsa)
        strict_rsa_sig_algs_text
    else
        default_sig_algs_text });
}

fn parseServerArgs(
    gpa: Allocator,
    init: std.process.Init.Minimal,
    args: *std.process.Args.Iterator,
) !ServerOptions {
    var opts: ServerOptions = .{
        .user = std.process.Environ.getPosix(init.environ, "USER") orelse "root",
    };
    errdefer opts.deinit(gpa);

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage_text});
            return error.UsagePrinted;
        } else if (std.mem.eql(u8, arg, "-v")) {
            opts.verbose = true;
        } else if (std.mem.eql(u8, arg, "--once")) {
            opts.once = true;
        } else if (std.mem.eql(u8, arg, "--collect-stdin")) {
            opts.collect_stdin = true;
        } else if (std.mem.eql(u8, arg, "--strict-rsa")) {
            opts.strict_rsa = true;
        } else if (std.mem.eql(u8, arg, "--listen")) {
            opts.listen = try nextValue(args, "--listen");
        } else if (std.mem.eql(u8, arg, "--user")) {
            opts.user = try nextValue(args, "--user");
        } else if (std.mem.eql(u8, arg, "--shell")) {
            opts.shell = try nextValue(args, "--shell");
        } else if (std.mem.eql(u8, arg, "--host-key")) {
            try opts.host_key_paths.append(gpa, try nextValue(args, "--host-key"));
        } else if (std.mem.eql(u8, arg, "--authorized-keys")) {
            if (opts.owns_authorized_keys) gpa.free(opts.authorized_keys);
            opts.authorized_keys = try nextValue(args, "--authorized-keys");
            opts.owns_authorized_keys = false;
        } else if (std.mem.eql(u8, arg, "--password-is")) {
            opts.password = try nextValue(args, "--password-is");
        } else if (std.mem.eql(u8, arg, "--port")) {
            opts.port = try parseServerInt(u16, args, "--port");
        } else if (std.mem.eql(u8, arg, "--max-auth-tries")) {
            opts.max_auth_tries = try parseServerInt(u32, args, "--max-auth-tries");
        } else if (std.mem.eql(u8, arg, "--max-output")) {
            opts.max_output = try parseServerInt(usize, args, "--max-output");
        } else if (std.mem.eql(u8, arg, "--exec-timeout")) {
            opts.exec_timeout_ms = try parseServerInt(u32, args, "--exec-timeout");
        } else {
            std.debug.print("ssh-demo: unknown server option '{s}' (try --help)\n", .{arg});
            return error.BadUsage;
        }
    }

    if (opts.authorized_keys.len == 0) {
        const home = std.process.Environ.getPosix(init.environ, "HOME");
        opts.authorized_keys = try defaultPath(gpa, home, ".ssh/authorized_keys");
        opts.owns_authorized_keys = true;
    }
    if (opts.host_key_paths.items.len == 0) {
        std.debug.print(
            \\ssh-demo: --host-key is required. A server with no host key cannot
            \\  authenticate itself, and this demo will not invent one for you:
            \\  a key generated per run would make every client warn about a
            \\  changed host key. Make one that stays put:
            \\    ssh-keygen -q -t ed25519 -N "" -f ./demo_host_ed25519
            \\
        , .{});
        return error.BadUsage;
    }
    if (opts.max_output == 0) {
        std.debug.print("ssh-demo: --max-output 0 would discard every command's output\n", .{});
        return error.BadUsage;
    }
    return opts;
}

fn parseServerInt(comptime T: type, args: *std.process.Args.Iterator, flag: []const u8) !T {
    const text = try nextValue(args, flag);
    return std.fmt.parseInt(T, text, 10) catch {
        std.debug.print("ssh-demo: {s} wants a number, got '{s}'\n", .{ flag, text });
        return error.BadUsage;
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// host keys — loading several, so the CLIENT gets to choose
// ─────────────────────────────────────────────────────────────────────────────

/// Load every `--host-key` file into `out`, most-preferred first.
///
/// Offering more than one is the point: `serverHandshake` walks the CLIENT's
/// `server_host_key_algorithms` name-list and picks the first entry it holds a
/// key for (RFC 4253 §7.1 is client-preference-ordered), so a reader can run
/// `ssh -o HostKeyAlgorithms=rsa-sha2-512 ...` against this and watch the
/// negotiation land somewhere else.
fn loadHostKeys(
    gpa: Allocator,
    io: std.Io,
    paths: []const []const u8,
    out: *std.ArrayList(ssh.server.HostKey),
) !void {
    for (paths) |path| {
        const text = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 * 1024)) catch |err| {
            std.debug.print("ssh-demo: cannot read host key {s}: {t}\n", .{ path, err });
            continue;
        };
        defer {
            // Host private key material: do not leave it in freed heap.
            std.crypto.secureZero(u8, text);
            gpa.free(text);
        }

        const key = ssh.server.HostKey.fromOpenSSH(text, null) catch |err| switch (err) {
            error.UnsupportedKeyType => {
                try loadUnsupportedHostKey(gpa, path, text, out);
                continue;
            },
            else => {
                std.debug.print("ssh-demo: cannot load host key {s}: {t}\n", .{ path, err });
                continue;
            },
        };

        switch (key) {
            // One RSA key is TWO offers. `fromOpenSSH` pins `.hash` to
            // `.sha2_256` because the openssh-key-v1 container does not encode
            // which rsa-sha2-* variant to sign with — RFC 8332 leaves that to
            // negotiation. The field is public precisely so a caller can do
            // this, and OpenSSH offers both names off one key too.
            .rsa => {
                var stronger = key;
                stronger.rsa.hash = .sha2_512;
                try out.append(gpa, stronger);
                try out.append(gpa, key);
            },
            else => try out.append(gpa, key),
        }
    }
}

/// ⚠ MODULE GAP, worked around here rather than fought.
///
/// `ssh.server.HostKey.fromOpenSSH` dispatches on the key type named inside
/// the openssh-key-v1 container and handles `ssh-rsa` and `ssh-ed25519` only,
/// so an `ssh-keygen -t ecdsa` host key comes back `error.UnsupportedKeyType`
/// — even though `HostKey` HAS an `.ecdsa_p256` variant, `publicBlob` and
/// `sign` both implement it, and `ecdsa-sha2-nistp256` is on the module's own
/// offered algorithm list. **The loader is the gap, not the algorithm.** So
/// this example parses that one container shape itself and hands the module
/// the variant it already knows what to do with.
///
/// The parse is checked before it is trusted: the public blob rebuilt from the
/// parsed private scalar has to equal the container's own (always plaintext)
/// public blob, byte for byte. A key that does not round-trip is not offered.
fn loadUnsupportedHostKey(
    gpa: Allocator,
    path: []const u8,
    text: []const u8,
    out: *std.ArrayList(ssh.server.HostKey),
) !void {
    const kp = parseEcdsaP256OpenSSH(gpa, text) catch |err| {
        std.debug.print(
            \\ssh-demo: {s}: `HostKey.fromOpenSSH` reports UnsupportedKeyType, and this
            \\  example's own ecdsa fallback could not read it either ({t}). Loadable
            \\  host key types: ssh-ed25519, ssh-rsa, and ecdsa-sha2-nistp256 through
            \\  the fallback below.
            \\
        , .{ path, err });
        return;
    };
    std.debug.print(
        "ssh-demo: {s}: loaded through this example's own ecdsa-sha2-nistp256 parser " ++
            "(HostKey.fromOpenSSH cannot — module gap; K_S verified against the container's own public blob)\n",
        .{path},
    );
    try out.append(gpa, .{ .ecdsa_p256 = kp });
}

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// Parse an unencrypted `openssh-key-v1` container holding one
/// `ecdsa-sha2-nistp256` private key (OpenSSH `PROTOCOL.key`):
///
///     "openssh-key-v1\0" || string ciphername || string kdfname ||
///     string kdfoptions || uint32 nkeys || string publickey ||
///     string (checkint || checkint || string keytype || string curve ||
///             string Q || string d || string comment || padding)
fn parseEcdsaP256OpenSSH(gpa: Allocator, text: []const u8) !EcdsaP256.KeyPair {
    const bin = try pemDecodeOpenssh(gpa, text);
    defer {
        std.crypto.secureZero(u8, bin);
        gpa.free(bin);
    }

    const magic = "openssh-key-v1\x00";
    if (bin.len < magic.len or !std.mem.eql(u8, bin[0..magic.len], magic)) return error.NotAnOpensshKey;

    var cur: ssh.messages.Cursor = .{ .b = bin[magic.len..] };
    const ciphername = try cur.string();
    const kdfname = try cur.string();
    _ = try cur.string(); // kdfoptions
    // A host key with a passphrase is not something a daemon can use anyway,
    // and bcrypt-pbkdf is not this example's business.
    if (!std.mem.eql(u8, ciphername, "none") or !std.mem.eql(u8, kdfname, "none"))
        return error.EncryptedKeyUnsupported;
    if (try cur.uint32() != 1) return error.MultipleKeysUnsupported;

    const public_blob = try cur.string();
    const private_section = try cur.string();

    var priv: ssh.messages.Cursor = .{ .b = private_section };
    const check1 = try priv.uint32();
    const check2 = try priv.uint32();
    // The two check words are the container's own "did this decrypt?" test.
    if (check1 != check2) return error.InvalidPrivateKey;

    const key_type = try priv.string();
    if (!std.mem.eql(u8, key_type, "ecdsa-sha2-nistp256")) return error.UnsupportedKeyType;
    const curve = try priv.string();
    if (!std.mem.eql(u8, curve, "nistp256")) return error.UnsupportedCurve;
    _ = try priv.string(); // Q, rebuilt from d below and compared instead
    const d = try priv.string();

    // `d` is stored the mpint way: big-endian, with a leading zero byte when
    // the top bit would otherwise read as a sign bit. Right-align it.
    var scalar: [32]u8 = @splat(0);
    const trimmed = std.mem.trimStart(u8, d, &.{0});
    if (trimmed.len > scalar.len or trimmed.len == 0) return error.InvalidPrivateKey;
    @memcpy(scalar[scalar.len - trimmed.len ..], trimmed);
    defer std.crypto.secureZero(u8, &scalar);

    const secret = try EcdsaP256.SecretKey.fromBytes(scalar);
    const kp = try EcdsaP256.KeyPair.fromSecretKey(secret);

    // Do not trust our own parse: rebuild `K_S` through the module's own
    // `publicBlob` and require it to match what the container says the public
    // half is. A misparsed scalar would produce a key that signs fine and that
    // no client can verify — a failure that would surface only over the wire.
    const rebuilt = try (ssh.server.HostKey{ .ecdsa_p256 = kp }).publicBlob(gpa);
    defer gpa.free(rebuilt);
    if (!std.mem.eql(u8, rebuilt, public_blob)) return error.PublicKeyMismatch;

    return kp;
}

/// Base64 body of a `-----BEGIN OPENSSH PRIVATE KEY-----` block, decoded.
fn pemDecodeOpenssh(gpa: Allocator, text: []const u8) ![]u8 {
    const begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const end = "-----END OPENSSH PRIVATE KEY-----";
    const bi = std.mem.indexOf(u8, text, begin) orelse return error.MissingPemBlock;
    const body_start = bi + begin.len;
    const ei = std.mem.indexOfPos(u8, text, body_start, end) orelse return error.MissingPemBlock;

    var packed_b64: std.ArrayList(u8) = .empty;
    defer packed_b64.deinit(gpa);
    for (text[body_start..ei]) |ch| {
        if (!std.ascii.isWhitespace(ch)) try packed_b64.append(gpa, ch);
    }

    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(packed_b64.items) catch return error.InvalidBase64;
    const out = try gpa.alloc(u8, n);
    errdefer gpa.free(out);
    dec.decode(out, packed_b64.items) catch return error.InvalidBase64;
    return out;
}

/// The fingerprints a reader checks against `ssh-keygen -lf`, and the algorithm
/// names to put after `ssh -o HostKeyAlgorithms=`.
///
/// One RSA key produces two lines with the SAME fingerprint and different
/// algorithm names — the fingerprint is over `K_S`, which RFC 8332 §3 types
/// `ssh-rsa` for both, while only the SIGNATURE names the hash.
fn printHostKeys(gpa: Allocator, keys: []const ssh.server.HostKey) void {
    for (keys) |hk| {
        const blob = hk.publicBlob(gpa) catch continue;
        defer gpa.free(blob);
        var fp_buf: [64]u8 = undefined;
        std.debug.print("ssh-demo: offering host key {s} SHA256:{s}\n", .{
            hk.algorithmName(),
            fingerprint(blob, &fp_buf),
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// one server's state, and one connection's life
// ─────────────────────────────────────────────────────────────────────────────

const ServerState = struct {
    gpa: Allocator,
    io: std.Io,
    opts: *const ServerOptions,
    host_keys: []const ssh.server.HostKey,
    keys: AuthorizedKeys,
    passwords: PasswordPolicy,
    commands: Commands,
    subsystems: Subsystems,

    /// Handshake → authenticate → serve session channels until the peer goes
    /// away. Never returns an error: a bad connection is one line in the log,
    /// not the end of the server.
    fn serveConnection(self: *ServerState, stream: *std.Io.net.Stream) void {
        var peer_buf: [64]u8 = undefined;
        const peer = peerDescription(stream, &peer_buf);
        std.debug.print("Connection from {s}\n", .{peer});

        var rbuf: [64 * 1024]u8 = undefined;
        var wbuf: [64 * 1024]u8 = undefined;
        var sr = stream.reader(self.io, &rbuf);
        var sw = stream.writer(self.io, &wbuf);

        var t = ssh.server.accept(&sr.interface, &sw.interface, self.gpa, .{
            .host_keys = self.host_keys,
            // RFC 8308 §3.1 says a server "MUST enumerate all public key
            // algorithms it might accept" — *might accept*, so the answer is
            // this server's policy, not the module's capability. `--strict-rsa`
            // makes `AuthorizedKeys.check` refuse `rsa-sha2-256`, so leaving it
            // in the advertised list would send an RSA client to sign with a
            // hash we then reject, with nothing left to try. Narrowing here
            // instead makes an OpenSSH client sign SHA-512 the first time.
            .server_sig_algs = if (self.opts.strict_rsa) &strict_rsa_sig_algs else &default_sig_algs,
        }) catch |err| {
            std.debug.print("ssh-demo: handshake with {s} failed: {t}\n", .{ peer, err });
            return;
        };

        if (self.opts.verbose) printNegotiated(&t);
        if (t.negotiated) |neg| {
            // Which of the offered host keys the CLIENT picked. This is the
            // observable half of `--host-key` being repeatable.
            std.debug.print("debug1: signed the exchange hash with {s}\n", .{neg.host_key});
        }

        // ── authenticate ──────────────────────────────────────────────────
        self.keys.reset();
        self.passwords.reset();
        var why: ssh.userauth.AuthFailure = undefined;
        const auth = ssh.userauth.serveUserauth(&t, self.gpa, .{
            .authorized_key = self.keys.hook(),
            // `null` here is what actually disables the method: the module
            // never offers a method it has no hook for.
            .password = if (self.opts.password != null) self.passwords.hook() else null,
            .banner = if (self.opts.password != null) server_banner_with_password else server_banner,
            .max_attempts = self.opts.max_auth_tries,
            .failure = &why,
        }) catch |err| switch (err) {
            error.AuthenticationFailed => {
                // The newest thing this module can do, and the reason a server
                // is its natural showcase: RFC 4252 gives the WIRE no field for
                // a reason (telling an unauthenticated peer why it failed is an
                // oracle), so the reason comes back out of band, to the log,
                // exactly where `sshd` puts it.
                self.reportAuthFailure(peer, why);
                t.sendDisconnect(.no_more_auth_methods_available, "authentication failed") catch {};
                return;
            },
            else => {
                std.debug.print("ssh-demo: userauth with {s} ended: {t}\n", .{ peer, err });
                // ⚠ `AuthConfig.failure` is only readable when the call returns
                // `error.AuthenticationFailed`, and a client that gives up
                // before the credential budget runs out makes it return
                // `error.EndOfStream` instead — so the module's OWN refusals
                // (the ones that happen before any hook of ours runs) are
                // recorded and then unreadable. This is the most common one,
                // named here so a reader is not left guessing.
                if (self.keys.why == .not_called and self.passwords.attempts == 0) {
                    std.debug.print(
                        \\ssh-demo: no credential ever reached this server's hooks — the client gave
                        \\  up before offering one. With OpenSSH, `ssh -v` says which: "no mutual
                        \\  signature algorithm" means its key type is not in the `server-sig-algs`
                        \\  this server advertised (see the startup banner); "no more authentication
                        \\  methods" means it had no key of any advertised type to offer.
                        \\
                    , .{});
                }
                return;
            },
        };

        std.debug.print("Accepted {s} for {s} from {s}\n", .{
            @tagName(auth.method),
            auth.user(),
            peer,
        });
        if (self.keys.optionsOfMatchedLine()) |o| {
            std.debug.print("ssh-demo: the matching authorized_keys line carries options: {s}\n", .{o});
        }

        // ── serve session channels, one at a time ─────────────────────────
        const before = self.commands.runs + self.subsystems.runs;
        var served: usize = 0;
        while (served < max_sessions_per_connection) : (served += 1) {
            ssh.connection.serveSession(&t, self.gpa, .{
                .user = auth.user(),
                .exec = self.commands.handler(),
                .subsystem = self.subsystems.handler(),
                // `.ignore` runs the handler when the request arrives, with no
                // stdin at all. It is the default here because a real `ssh`
                // holds its stdin open unless told not to (`-n`, `< /dev/null`),
                // and `.collect_until_eof` would then wait for an EOF that
                // never comes — a hang with no error, the worst shape.
                .stdin_mode = if (self.opts.collect_stdin) .collect_until_eof else .ignore,
            }) catch |err| switch (err) {
                // The peer hung up. Normal: it is how a client ends a session.
                error.EndOfStream, error.ReadFailed, error.WriteFailed => {
                    if (self.opts.verbose)
                        std.debug.print("debug1: {s} went away between channels: {t}\n", .{ peer, err });
                    break;
                },
                else => {
                    std.debug.print("ssh-demo: session channel failed: {t}\n", .{err});
                    break;
                },
            };
        }
        const ran = self.commands.runs + self.subsystems.runs - before;
        std.debug.print("Connection from {s} closed after {d} request(s)\n", .{ peer, ran });
        if (served >= max_sessions_per_connection) {
            std.debug.print("ssh-demo: hit the {d}-session cap on one connection\n", .{max_sessions_per_connection});
        }
    }

    /// Two reasons, side by side: the module's own vocabulary from
    /// `AuthConfig.failure`, and our policy's richer one out of its `ctx`.
    /// Neither reaches the client — deliberately, per RFC 4252 §5.1.
    fn reportAuthFailure(self: *ServerState, peer: []const u8, why: ssh.userauth.AuthFailure) void {
        const detail = switch (why) {
            .unauthorized_key => self.keys.explain(),
            .wrong_password => "the password did not match (this example's literal --password-is secret)",
            .no_acceptable_method => "the client offered no method this server has enabled",
            .unsupported_algorithm => "the signature algorithm is not one this module can verify",
            .algorithm_mismatch => "the key blob's type does not match the algorithm the request named",
            .bad_signature => "the key was authorized, but the signature did not verify under it",
            .peer_disconnected => "the client sent SSH_MSG_DISCONNECT instead of another credential",
        };
        std.debug.print("Failed authentication from {s}: {t} — {s}\n", .{ peer, why, detail });
    }
};

/// `127.0.0.1 port 41234`, the way `sshd` names a peer in its log. `accept`
/// hands back a `Stream` and no address, so this asks the socket.
fn peerDescription(stream: *std.Io.net.Stream, buf: *[64]u8) []const u8 {
    var sa: std.posix.sockaddr.storage = undefined;
    var len: std.posix.socklen_t = @sizeOf(@TypeOf(sa));
    std.posix.getpeername(stream.socket.handle, @ptrCast(&sa), &len) catch return "an unnamed peer";
    if (sa.family != std.posix.AF.INET) return "a non-IPv4 peer";
    const in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(&sa));
    const octets: [4]u8 = @bitCast(in.addr);
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d} port {d}", .{
        octets[0], octets[1], octets[2], octets[3], std.mem.bigToNative(u16, in.port),
    }) catch "a peer with an unprintable address";
}

// ─────────────────────────────────────────────────────────────────────────────
// authorized_keys — the server's half of the trust decision
// ─────────────────────────────────────────────────────────────────────────────

/// The whole `publickey` policy in one value, reached through
/// `AuthorizedKeyCheck.ctx`. The mirror of the client's `KnownHosts`: the
/// module will not read a file for you, and it must not — where the file is,
/// whose it is, and what a marker means are all deployment questions.
const AuthorizedKeys = struct {
    io: std.Io,
    gpa: Allocator,
    path: []const u8,
    /// `authorized_keys` has no user column because it IS one user's file.
    user: []const u8,
    /// Refuse `rsa-sha2-256` and accept only `-512`. The one honest use of the
    /// `algorithm` argument: it is policy input, never what the line is
    /// matched on.
    strict_rsa: bool,
    verbose: bool,

    /// Why the last refusal happened. `AuthConfig.failure` reports every one
    /// of these as `.unauthorized_key`, which is right — it is the module's
    /// vocabulary, not ours. The module's own doc comment says the richer
    /// reason belongs in the hook's `ctx`; this is it.
    why: Why = .not_called,
    /// The matched line's option field and its `command="..."`, both copied:
    /// the file text is freed before the exec handler ever runs.
    options_buf: [512]u8 = undefined,
    options_len: usize = 0,
    forced_buf: [512]u8 = undefined,
    forced_len: usize = 0,

    const Why = enum {
        not_called,
        unreadable,
        wrong_user,
        no_matching_line,
        revoked,
        weak_rsa_hash,
        restriction_too_long,
    };

    fn hook(self: *AuthorizedKeys) ssh.userauth.AuthorizedKeyCheck {
        return .{ .ctx = self, .checkFn = check };
    }

    fn reset(self: *AuthorizedKeys) void {
        self.why = .not_called;
        self.options_len = 0;
        self.forced_len = 0;
    }

    fn optionsOfMatchedLine(self: *const AuthorizedKeys) ?[]const u8 {
        if (self.options_len == 0) return null;
        return self.options_buf[0..self.options_len];
    }

    fn forcedCommand(self: *const AuthorizedKeys) ?[]const u8 {
        if (self.forced_len == 0) return null;
        return self.forced_buf[0..self.forced_len];
    }

    /// Record a refusal and say so at once.
    ///
    /// The end-of-authentication summary in `ServerState.reportAuthFailure` is
    /// NOT enough on its own: `serveUserauth` only returns
    /// `error.AuthenticationFailed` once the credential budget is spent, and a
    /// client that gives up first (or drops the connection, which is what a
    /// client with one rejected key does) makes it return `error.EndOfStream`
    /// instead — with the reason never read. `sshd` logs each refusal as it
    /// happens for exactly this reason.
    fn refuse(self: *AuthorizedKeys, why: Why, user: []const u8, key_type: []const u8) bool {
        self.why = why;
        std.debug.print("Refused {s} key for {s}: {s}\n", .{ displayKeyType(key_type), user, self.explain() });
        return false;
    }

    fn explain(self: *const AuthorizedKeys) []const u8 {
        return switch (self.why) {
            .not_called => "the publickey hook never ran (the client offered no key)",
            .unreadable => "the authorized_keys file could not be read",
            .wrong_user => "that key may belong to somebody, but not to this account",
            .no_matching_line => "no line of authorized_keys carries that key",
            .revoked => "the key is on a @revoked line",
            .weak_rsa_hash => "rsa-sha2-256 refused by --strict-rsa; offer rsa-sha2-512",
            .restriction_too_long => "the line's options/forced-command exceed this server's 512-byte buffer; refused rather than enforced truncated",
        };
    }

    /// The `userauth.AuthorizedKeyCheck` callback.
    ///
    /// Called TWICE per successful login: once for the RFC 4252 §7
    /// signature-less query (which decides whether to answer
    /// SSH_MSG_USERAUTH_PK_OK) and again before the real signature is
    /// verified. Saying yes does not authenticate anybody — `serveUserauth`
    /// still requires a session-id-bound signature under that key.
    ///
    /// ⚠ `user`, `algorithm` and `key_blob` all point into the packet scratch
    /// buffer the next packet reuses. Anything kept is copied here and now.
    fn check(ctx: *anyopaque, user: []const u8, algorithm: []const u8, key_blob: []const u8) bool {
        const self: *AuthorizedKeys = @ptrCast(@alignCast(ctx));
        self.options_len = 0;
        self.forced_len = 0;

        // `algorithm` is the SIGNATURE algorithm, which is NOT always the key
        // blob's own type: RFC 8332 §3 pairs both `rsa-sha2-256` and
        // `rsa-sha2-512` with an `ssh-rsa`-typed blob, and an authorized_keys
        // line spells the BLOB type. So the line is matched on `key_blob` and
        // `algorithm` is only ever policy input, as here.
        if (self.strict_rsa and std.mem.eql(u8, algorithm, "rsa-sha2-256")) {
            return self.refuse(.weak_rsa_hash, user, algorithm);
        }

        const blob_type = keyBlobType(key_blob) orelse
            return self.refuse(.no_matching_line, user, "a malformed");

        if (!std.mem.eql(u8, user, self.user)) {
            return self.refuse(.wrong_user, user, blob_type);
        }

        const text = std.Io.Dir.cwd().readFileAlloc(self.io, self.path, self.gpa, .limited(4 * 1024 * 1024)) catch |err| {
            // Unlike known_hosts, a missing authorized_keys is NOT a benign
            // first-run state: it means nobody may log in, and it is worth
            // saying so rather than answering a silent "no".
            std.debug.print("ssh-demo: cannot read {s}: {t}\n", .{ self.path, err });
            return self.refuse(.unreadable, user, blob_type);
        };
        defer self.gpa.free(text);

        self.why = .no_matching_line;
        var lines = std.mem.splitScalar(u8, text, '\n');
        var line_no: usize = 0;
        while (lines.next()) |raw| {
            line_no += 1;
            const entry = parseAuthorizedKeyLine(raw) orelse continue;

            // `@cert-authority` delegates trust to a CA key, and this module
            // has no certificate key types at all — so the line is skipped
            // rather than misread as a plain host key. Saying so out loud is
            // the point: silently ignoring it would look like a rejection.
            if (entry.marker == .cert_authority) {
                if (self.verbose) std.debug.print(
                    "debug1: {s}:{d}: skipping @cert-authority (no certificate key types in this module)\n",
                    .{ self.path, line_no },
                );
                continue;
            }

            // A different key type on the line is "not this line", not a
            // refusal. An account normally lists an ed25519 AND an rsa key;
            // treating the first non-match as a rejection would lock out the
            // second and make the log lie about why.
            if (!std.mem.eql(u8, entry.key_type, blob_type)) continue;
            if (!base64Eql(entry.key_b64, key_blob)) continue;

            if (entry.marker == .revoked) {
                std.debug.print("ssh-demo: {s}:{d} carries the @revoked marker\n", .{ self.path, line_no });
                return self.refuse(.revoked, user, blob_type);
            }

            // A restriction that does not FIT must refuse the key, never be
            // silently truncated: a cut `command="…"` or option string is a
            // DIFFERENT, likely weaker restriction than the admin wrote, and
            // enforcing the wrong restriction is worse than rejecting the key.
            if (entry.options.len > self.options_buf.len)
                return self.refuse(.restriction_too_long, user, blob_type);
            self.options_len = entry.options.len;
            @memcpy(self.options_buf[0..self.options_len], entry.options);
            if (authorizedKeyOption(entry.options, "command")) |forced| {
                if (forced.len > self.forced_buf.len)
                    return self.refuse(.restriction_too_long, user, blob_type);
                self.forced_len = forced.len;
                @memcpy(self.forced_buf[0..self.forced_len], forced);
            }
            if (self.verbose) std.debug.print(
                "debug1: {s}:{d} authorizes this {s} key for {s}\n",
                .{ self.path, line_no, displayKeyType(blob_type), user },
            );
            return true;
        }
        return self.refuse(.no_matching_line, user, blob_type);
    }
};

/// One parsed `authorized_keys` line: `[marker] [options] keytype base64 [comment]`.
const AuthorizedKeyEntry = struct {
    marker: enum { none, revoked, cert_authority },
    options: []const u8,
    key_type: []const u8,
    key_b64: []const u8,
};

/// Key-type names that may open the key field of an `authorized_keys` line.
///
/// The list is longer than what this module can verify on purpose: it is how
/// the parser tells a KEY TYPE from an OPTION FIELD, which is the one
/// genuinely ambiguous thing about the format (`ssh-dss ...` is a key,
/// `no-pty,ssh-...` is not). A type this module cannot verify then simply
/// never equals any offered blob's type, and the line is skipped — which is
/// the correct outcome, reached without a special case.
const authorized_key_types = [_][]const u8{
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
};

fn isAuthorizedKeyType(field: []const u8) bool {
    for (authorized_key_types) |k| {
        if (std.mem.eql(u8, field, k)) return true;
    }
    return false;
}

/// Parse one line, or `null` for anything that is not an entry (blank, a
/// comment, a marker we do not know, a truncated line).
///
/// Order matters and is OpenSSH's: marker first, then the optional option
/// field, then the key. The option field is not tokenised on spaces because it
/// may contain quoted ones (`command="sh -c echo"`), so it is scanned with the
/// quotes respected — getting that wrong is how a parser ends up reading
/// `-c` as the key type.
fn parseAuthorizedKeyLine(raw: []const u8) ?AuthorizedKeyEntry {
    var rest = std.mem.trim(u8, raw, " \t\r");
    if (rest.len == 0 or rest[0] == '#') return null;

    var marker: @FieldType(AuthorizedKeyEntry, "marker") = .none;
    if (rest[0] == '@') {
        const end = std.mem.indexOfAny(u8, rest, " \t") orelse return null;
        const word = rest[0..end];
        if (std.mem.eql(u8, word, "@revoked")) {
            marker = .revoked;
        } else if (std.mem.eql(u8, word, "@cert-authority")) {
            marker = .cert_authority;
        } else {
            return null; // an unknown marker is not a line we may guess at
        }
        rest = std.mem.trimStart(u8, rest[end..], " \t");
    }

    var options: []const u8 = "";
    const first_end = quotedFieldEnd(rest);
    if (first_end == 0) return null;
    if (!isAuthorizedKeyType(rest[0..first_end])) {
        options = rest[0..first_end];
        rest = std.mem.trimStart(u8, rest[first_end..], " \t");
    }

    const type_end = std.mem.indexOfAny(u8, rest, " \t") orelse return null;
    const key_type = rest[0..type_end];
    rest = std.mem.trimStart(u8, rest[type_end..], " \t");
    if (rest.len == 0) return null;
    const b64_end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;

    return .{
        .marker = marker,
        .options = options,
        .key_type = key_type,
        .key_b64 = rest[0..b64_end],
    };
}

/// Index of the first whitespace that is NOT inside a double-quoted section.
fn quotedFieldEnd(s: []const u8) usize {
    var in_quotes = false;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        switch (s[i]) {
            '"' => in_quotes = !in_quotes,
            '\\' => if (in_quotes and i + 1 < s.len) {
                i += 1; // `\"` inside a value is a literal quote
            },
            ' ', '\t' => if (!in_quotes) return i,
            else => {},
        }
    }
    return s.len;
}

/// Value of `name="..."` in an `authorized_keys` option field, or `null`.
/// Only `command=` is acted on by this demo; the rest are reported and not
/// enforced, which is said out loud rather than left to be discovered.
fn authorizedKeyOption(options: []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    var at_start = true;
    while (i < options.len) {
        if (at_start and
            options.len - i > name.len + 1 and
            std.ascii.eqlIgnoreCase(options[i..][0..name.len], name) and
            options[i + name.len] == '=' and
            options[i + name.len + 1] == '"')
        {
            var j = i + name.len + 2;
            while (j < options.len) : (j += 1) {
                if (options[j] == '\\' and j + 1 < options.len) {
                    j += 1;
                    continue;
                }
                if (options[j] == '"') return options[i + name.len + 2 .. j];
            }
            return null; // unterminated quote: not a value we may guess at
        }
        // Advance to the next option, stepping over any quoted value.
        at_start = false;
        if (options[i] == '"') {
            i += 1;
            while (i < options.len and options[i] != '"') : (i += 1) {
                if (options[i] == '\\') i += 1;
            }
        } else if (options[i] == ',') {
            at_start = true;
        }
        i += 1;
    }
    return null;
}

/// The key type named INSIDE a wire key blob (its first `string` field) — what
/// an `authorized_keys` line's second field has to equal.
fn keyBlobType(key_blob: []const u8) ?[]const u8 {
    var cur: ssh.messages.Cursor = .{ .b = key_blob };
    return cur.string() catch null;
}

// ─────────────────────────────────────────────────────────────────────────────
// password — the example-only fallback
// ─────────────────────────────────────────────────────────────────────────────

/// ⚠ EXAMPLE ONLY, and loudly so: the secret arrives on this process's command
/// line, where any `ps` can read it, and it is compared against a literal
/// rather than against a stored verifier. A real server keeps an argon2id /
/// bcrypt / PBKDF2 verifier, never the password, and rate-limits per source
/// address. This exists so that RFC 4252 §8 can be seen working end to end,
/// and it announces itself in the SSH_MSG_USERAUTH_BANNER before it ever says
/// yes to anybody.
const PasswordPolicy = struct {
    user: []const u8,
    secret: []const u8,
    attempts: usize = 0,

    fn hook(self: *PasswordPolicy) ssh.userauth.PasswordCheck {
        return .{ .ctx = self, .checkFn = check };
    }

    fn reset(self: *PasswordPolicy) void {
        self.attempts = 0;
    }

    /// ⚠ `password` points at the peer's plaintext inside `serveUserauth`'s
    /// scratch buffer, which that function scrubs when it returns. Nothing is
    /// copied out of it here.
    fn check(ctx: *anyopaque, user: []const u8, password: []const u8) bool {
        const self: *PasswordPolicy = @ptrCast(@alignCast(ctx));
        self.attempts += 1;
        if (self.secret.len == 0) {
            std.debug.print("Refused password for {s}: no password is configured\n", .{user});
            return false;
        }
        if (!std.mem.eql(u8, user, self.user)) {
            std.debug.print("Refused password for {s}: not this server's account\n", .{user});
            return false;
        }

        // Compare digests, not the strings: `timing_safe.eql` needs two equal
        // fixed-size arrays, and two passwords are rarely the same length —
        // hashing first removes both the length and the common-prefix signal.
        // (SHA-256 is doing constant-time comparison here, NOT password
        // storage. Never store this.)
        var got: [32]u8 = undefined;
        var want: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(password, &got, .{});
        std.crypto.hash.sha2.Sha256.hash(self.secret, &want, .{});
        defer std.crypto.secureZero(u8, &got);
        defer std.crypto.secureZero(u8, &want);
        const ok = std.crypto.timing_safe.eql([32]u8, got, want);
        if (!ok) std.debug.print(
            "Refused password for {s}: attempt {d} did not match\n",
            .{ user, self.attempts },
        );
        return ok;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// exec — running a real command
// ─────────────────────────────────────────────────────────────────────────────

/// The `"exec"` handler's state. `CommandHandler.ctx` is what makes this
/// possible at all: the handler signature has no `std.Io` in it, and spawning
/// a process needs one.
const Commands = struct {
    io: std.Io,
    shell: []const u8,
    max_output: usize,
    timeout_ms: u32,
    verbose: bool,
    /// For the `command="..."` option of the authorized_keys line that let
    /// this session in. Wired up after construction.
    keys: ?*const AuthorizedKeys = null,
    runs: usize = 0,

    fn handler(self: *Commands) ssh.connection.CommandHandler {
        return .{ .ctx = self, .runFn = run };
    }

    /// ⚠ `command` and `stdin` point into `serveSession`'s buffers; both are
    /// used within the call and neither is kept.
    ///
    /// This never returns `error.CommandFailed`: that would take the whole
    /// connection down. A command that cannot run is a non-zero exit status
    /// and a line on stderr — which is precisely what RFC 4254 §6.10 and
    /// §5.2's extended data are for, and how the client learns why.
    fn run(
        ctx: *anyopaque,
        gpa: Allocator,
        user: []const u8,
        command: []const u8,
        stdin: []const u8,
        stdout: *std.ArrayList(u8),
        stderr: *std.ArrayList(u8),
    ) ssh.connection.CommandError!u32 {
        const self: *Commands = @ptrCast(@alignCast(ctx));
        self.runs += 1;

        var effective = command;
        if (self.keys) |k| if (k.forcedCommand()) |forced| {
            // OpenSSH's `command="..."` option: the client's command is not
            // run at all. `sshd` would also pass the original in
            // `$SSH_ORIGINAL_COMMAND`; this demo does not plumb an
            // environment, and says so instead of pretending.
            try stderr.print(gpa, "ssh-demo: authorized_keys forces a command; yours was not run\n", .{});
            std.debug.print("ssh-demo: forced command from authorized_keys: {s}\n", .{forced});
            effective = forced;
        };

        std.debug.print("ssh-demo: exec for {s}: {s}\n", .{ user, effective });
        if (stdin.len != 0) std.debug.print("ssh-demo: {d} byte(s) of client stdin\n", .{stdin.len});

        const result = self.spawnCapped(gpa, effective, stdin) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                try stderr.print(gpa, "ssh-demo: could not run the command: {t}\n", .{err});
                return local_failure_exit;
            },
        };
        defer gpa.free(result.stdout);
        defer gpa.free(result.stderr);

        try stdout.appendSlice(gpa, result.stdout);
        try stderr.appendSlice(gpa, result.stderr);
        if (result.truncated) {
            try stderr.print(
                gpa,
                "ssh-demo: output passed the {d}-byte cap; the command was killed and this is what it had written\n",
                .{self.max_output},
            );
        }
        if (result.timed_out) {
            try stderr.print(gpa, "ssh-demo: the command outlived the {d} ms limit and was killed\n", .{self.timeout_ms});
        }
        return result.status;
    }

    const Captured = struct {
        stdout: []u8,
        stderr: []u8,
        status: u32,
        truncated: bool,
        timed_out: bool,
    };

    /// Run `command` under `--shell`, capped in both bytes and time.
    ///
    /// Both pipes are drained through one `MultiReader` rather than one after
    /// the other, because a command that fills the pipe we are NOT reading
    /// blocks forever — the classic two-pipe deadlock, and not something an
    /// example should teach by accident. The cap and the deadline exist for
    /// the same reason SPEC.md gives for having none inside the module: this
    /// process owns the socket, so the limits are this process's job.
    fn spawnCapped(self: *Commands, gpa: Allocator, command: []const u8, stdin: []const u8) !Captured {
        var stdin_path_buf: [96]u8 = undefined;
        var stdin_path: ?[]const u8 = null;
        var stdin_file: ?std.Io.File = null;
        defer if (stdin_file) |f| f.close(self.io);
        defer if (stdin_path) |p| std.Io.Dir.cwd().deleteFile(self.io, p) catch {};

        if (stdin.len != 0) {
            // `CommandHandler` hands over the client's stdin as one finished
            // slice, so there is nothing to stream: a temporary file is an
            // honest fd for it, and cannot deadlock the way a pipe we also
            // have to drain would.
            //
            // ⚠ The path is PREDICTABLE (`pid`-`runs`), so the create is
            // EXCLUSIVE: on a shared host a local attacker who reads our pid
            // could pre-plant a symlink here, and a following (non-exclusive)
            // create would then overwrite whatever it points at with the
            // client's stdin — an arbitrary-file-write. `exclusive = true`
            // makes the create fail instead of following the link. Confidence
            // is still the caller's problem (umask, and a secret on stdin
            // wants `memfd_create`/`O_TMPFILE`), but integrity is covered.
            const p = std.fmt.bufPrint(&stdin_path_buf, "/tmp/ssh-demo-stdin-{d}-{d}", .{
                std.os.linux.getpid(), self.runs,
            }) catch unreachable;
            // Clear a stale file first. A previous incarnation holding this pid
            // may have been SIGKILLed before its deferred delete ran, and an
            // exclusive create would then fail on that path forever. Unlinking
            // does not weaken the guard above: it removes the LINK, never its
            // target, and a symlink re-planted between the two calls still
            // meets `exclusive` and is refused.
            std.Io.Dir.cwd().deleteFile(self.io, p) catch {};
            var f = std.Io.Dir.cwd().createFile(self.io, p, .{ .truncate = true, .exclusive = true }) catch |err| {
                std.debug.print("ssh-demo: cannot create stdin temp {s}: {t}\n", .{ p, err });
                return err;
            };
            // We own the file now — arm the cleanup BEFORE the write, so a
            // failed/partial write still deletes it rather than leaking it.
            stdin_path = p;
            {
                defer f.close(self.io);
                var wbuf: [4096]u8 = undefined;
                var fw = f.writer(self.io, &wbuf);
                try fw.interface.writeAll(stdin);
                try fw.interface.flush();
            }
            stdin_file = try std.Io.Dir.cwd().openFile(self.io, p, .{});
        }

        var child = try std.process.spawn(self.io, .{
            .argv = &.{ self.shell, "-c", command },
            .stdin = if (stdin_file) |f| .{ .file = f } else .ignore,
            .stdout = .pipe,
            .stderr = .pipe,
        });
        defer child.kill(self.io);

        var mr_buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
        var mr: std.Io.File.MultiReader = undefined;
        mr.init(gpa, self.io, mr_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
        defer mr.deinit();

        // One DEADLINE, computed once, not a duration: `fill` is called many
        // times and a per-call duration would restart the clock on every one,
        // so a command producing a trickle of output would never time out.
        const deadline: std.Io.Timeout = (std.Io.Timeout{ .duration = .{
            .raw = .fromMilliseconds(self.timeout_ms),
            .clock = .awake,
        } }).toDeadline(self.io);

        var truncated = false;
        var timed_out = false;
        while (mr.fill(256, deadline)) |_| {
            if (mr.reader(0).buffered().len > self.max_output or
                mr.reader(1).buffered().len > self.max_output)
            {
                truncated = true;
                break;
            }
        } else |err| switch (err) {
            // "Every stream ended" — which also covers "every stream failed",
            // so ask which it was rather than reporting a truncated read as a
            // finished one.
            error.EndOfStream => try mr.checkAnyError(),
            error.Timeout => timed_out = true,
            else => |e| return e,
        }

        const out = try mr.toOwnedSlice(0);
        errdefer gpa.free(out);
        const err_out = try mr.toOwnedSlice(1);
        errdefer gpa.free(err_out);

        // A killed child has no exit status to report. `ssh(1)` answers 255
        // when a remote command produced none, and so does this.
        if (truncated or timed_out) return .{
            .stdout = out,
            .stderr = err_out,
            .status = local_failure_exit,
            .truncated = truncated,
            .timed_out = timed_out,
        };

        const status: u32 = switch (try child.wait(self.io)) {
            .exited => |code| code,
            // RFC 4254 §6.11 `exit-signal` is not implemented here (SPEC.md
            // says so), so a signalled command cannot be reported as one.
            else => local_failure_exit,
        };
        return .{
            .stdout = out,
            .stderr = err_out,
            .status = status,
            .truncated = false,
            .timed_out = false,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// subsystem — a small honest one, and NOT SFTP
// ─────────────────────────────────────────────────────────────────────────────

/// The `"subsystem"` handler. A subsystem is just a named service on a session
/// channel (RFC 4254 §6.5) — `sftp` is the famous one, and this module has no
/// SFTP in it, so this offers a small one of its own instead of answering to a
/// name it cannot honour.
///
/// ⚠ BOUNDARY: `ServeConfig.subsystem` is ONE handler for every subsystem
/// name, and `serveSession` has already answered SSH_MSG_CHANNEL_SUCCESS by
/// the time it is called. So an unknown name cannot be refused with
/// CHANNEL_FAILURE the way `sshd` refuses it — the best a handler can do is
/// what this one does: say so on stderr and exit non-zero.
const Subsystems = struct {
    verbose: bool,
    runs: usize = 0,

    fn handler(self: *Subsystems) ssh.connection.CommandHandler {
        return .{ .ctx = self, .runFn = run };
    }

    fn run(
        ctx: *anyopaque,
        gpa: Allocator,
        user: []const u8,
        command: []const u8,
        stdin: []const u8,
        stdout: *std.ArrayList(u8),
        stderr: *std.ArrayList(u8),
    ) ssh.connection.CommandError!u32 {
        const self: *Subsystems = @ptrCast(@alignCast(ctx));
        self.runs += 1;
        std.debug.print("ssh-demo: subsystem request from {s}: {s}\n", .{ user, command });

        if (!std.mem.eql(u8, command, demo_subsystem_name)) {
            try stderr.print(gpa,
                \\ssh-demo: no subsystem named "{s}" here. This server implements
                \\  "{s}" and nothing else — in particular there is NO sftp
                \\  anywhere in this module, so `sftp` would have hung waiting for
                \\  a version packet that never came.
                \\  (The channel request was already answered SSH_MSG_CHANNEL_SUCCESS
                \\  before this handler ran: ServeConfig.subsystem is one hook for
                \\  every name, so a real CHANNEL_FAILURE is not reachable from here.)
                \\
            , .{ command, demo_subsystem_name });
            return 1;
        }

        try stdout.print(gpa,
            \\subsystem: {s}
            \\user: {s}
            \\server: ssh-demo, the `ssh` module's example
            \\stdin-bytes: {d}
            \\note: this is not SFTP and does not speak it
            \\
        , .{ demo_subsystem_name, user, stdin.len });
        if (stdin.len != 0) {
            try stdout.appendSlice(gpa, "echo: ");
            try stdout.appendSlice(gpa, stdin);
            if (stdin[stdin.len - 1] != '\n') try stdout.append(gpa, '\n');
        } else {
            try stdout.appendSlice(gpa,
                \\stdin: none — the server runs with `stdin_mode = .ignore` unless
                \\  started with --collect-stdin, because a real `ssh` that holds its
                \\  stdin open would otherwise never get an answer at all.
                \\
            );
        }
        return 0;
    }
};

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

/// Show the server's SSH_MSG_USERAUTH_BANNER (RFC 4252 §5.4) the way real
/// `ssh` does: on stderr, before the login concludes, with the text
/// SANITISED. §5.4 warns the message "may contain control character
/// sequences" — it arrives from an as-yet-unauthenticated server, so printing
/// it raw would let that server drive the user's terminal (cursor moves,
/// colour, a fake password prompt). OpenSSH filters it through `strnvis`;
/// this keeps printable ASCII plus newline and tab, and shows anything else
/// as `?`.
const banner_printer: ssh.userauth.BannerHandler = .{
    .showFn = struct {
        fn f(_: *anyopaque, message: []const u8, language: []const u8) void {
            _ = language; // §5.4 sends one; nothing here is localised.
            var line: [256]u8 = undefined;
            var n: usize = 0;
            for (message) |c| {
                line[n] = if (c == '\n' or c == '\t' or (c >= 0x20 and c < 0x7f)) c else '?';
                n += 1;
                if (n == line.len) {
                    std.debug.print("{s}", .{line[0..n]});
                    n = 0;
                }
            }
            if (n > 0) std.debug.print("{s}", .{line[0..n]});
        }
    }.f,
};

/// `publickey` first, `password` as the fallback — the order every SSH client
/// uses, and the reason the module's `authenticate` takes a key rather than a
/// list of methods: choosing between them is policy, so it is ours.
fn authenticateClient(
    gpa: Allocator,
    io: std.Io,
    transport: *ssh.transport.Transport,
    opts: *const ClientOptions,
) bool {
    // RFC 4252 §5: the `ssh-userauth` service is requested ONCE per
    // connection, whichever method follows — requesting it twice is a
    // protocol error. Doing it here rather than inside the publickey branch
    // is what lets both methods go through the per-method entry points, which
    // is in turn what lets both pass a `BannerHandler`.
    {
        var buf: [8 * 1024]u8 = undefined;
        transport.requestService("ssh-userauth", &buf) catch |err| {
            std.debug.print("ssh-demo: ssh-userauth was refused: {t}\n", .{err});
            return false;
        };
    }

    if (!opts.force_password) {
        if (loadIdentity(gpa, io, opts.identity)) |key| {
            if (ssh.userauth.authenticatePublickey(transport, gpa, opts.user, key, .{
                .banner = banner_printer,
            })) |_| {
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

    ssh.userauth.authenticatePassword(transport, gpa, opts.user, password, .{
        .banner = banner_printer,
    }) catch |err| switch (err) {
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
