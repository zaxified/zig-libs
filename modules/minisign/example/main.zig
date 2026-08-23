// SPDX-License-Identifier: MIT

//! `minisign-demo` — a `-G`/`-S`/`-V` command-line tool built on the
//! `minisign` module, the file-I/O layer the module deliberately does not
//! own itself (SPEC.md "Out of scope": "the minisign CLI itself ... this
//! module is the format + crypto library underneath such a tool, not the
//! tool"). `-R`/`-C` are included too — turning them into real commands
//! needed nothing the module does not already publish.
//!
//! **Streaming.** The default (prehashed, `"ED"`) algorithm signs a
//! BLAKE2b-512 digest, not the file itself, so `-S`/`-V` here read the file
//! in fixed 64 KiB chunks and never hold more than one chunk resident —
//! `digestFile` below, feeding `minisign.signDigest`/`verifyDigest` (the
//! module additions this example drove: `signMessage`/`verifyMessage` need
//! the whole message in RAM even for `.prehashed`, because they compute the
//! digest internally). `-l` (legacy `"Ed"`) signs the raw file bytes
//! directly and **cannot** stream by construction (module doc comment); its
//! path here reads the whole file with `readFileAlloc`, capped at
//! `legacy_max_size`, and says why when that cap is hit.
//!
//! **Default paths**, matching real `minisign(1)`: secret key
//! `~/.minisign/minisign.key`, public key `./minisign.pub`, signature
//! `<file>.minisig`. None of this lives in the module — it is exactly the
//! kind of OS/environment-specific policy SPEC.md's "Out of scope" section
//! points at.
//!
//! **Deliberately simplified vs. real `minisign`**, so this file stays
//! about the module and not a terminal-handling exercise: passwords are
//! read as a plain visible line from stdin (no termios echo suppression, no
//! confirmation prompt), and `-S`/`-V` take exactly one `-m file` rather
//! than the CLI's `file [file ...]`. Neither affects wire-format
//! correctness or interop with the real binary — both are proven in the
//! module's KAT suite and, for this CLI specifically, by running it against
//! the real `minisign` binary in both directions (see the module's
//! CHANGELOG for the transcript).
//!
//! Built against the PUBLISHED module (`@import("minisign")`) only.

const std = @import("std");
const minisign = @import("minisign");

const Allocator = std.mem.Allocator;

const chunk_size = 64 * 1024;
/// Legacy (`-l`) mode signs the raw file bytes and therefore cannot stream
/// (module doc comment) — this cap is a demo safety valve, not a format
/// limit; a real integrator would size it to their own RAM budget.
const legacy_max_size: usize = 256 * 1024 * 1024;

const usage_text =
    \\minisign-demo -- a -G/-S/-V/-R/-C command-line tool for the `minisign` module.
    \\
    \\usage:
    \\  minisign-demo -G [-f] [-p pubkey_file] [-s seckey_file] [-W] [-c comment]
    \\  minisign-demo -R [-s seckey_file] [-p pubkey_file]
    \\  minisign-demo -C [-s seckey_file] [-W]
    \\  minisign-demo -S [-l] [-x sig_file] [-s seckey_file] [-c comment] [-t comment] -m file
    \\  minisign-demo -V [-H] [-x sig_file] [-p pubkey_file | -P pubkey] [-o] [-q] [-Q] -m file
    \\
    \\  -G            generate a new key pair
    \\  -R            recreate a public key file from a secret key file
    \\  -C            change/remove the password of the secret key
    \\  -S            sign a file
    \\  -V            verify a file
    \\  -l            sign using the legacy (non-streaming) format
    \\  -H            (with -V) require the signature to be the prehashed/streaming kind
    \\  -m <file>     file to sign/verify
    \\  -o            (with -V) print the file content after verification
    \\  -p <file>     public key file           (default: ./minisign.pub)
    \\  -P <base64>   public key, inline
    \\  -s <file>     secret key file           (default: ~/.minisign/minisign.key)
    \\  -W            do not encrypt/decrypt the secret key with a password
    \\  -x <file>     signature file            (default: <file>.minisig)
    \\  -c <comment>  untrusted comment
    \\  -t <comment>  trusted comment
    \\  -q            quiet: print nothing on success
    \\  -Q            pretty quiet: print only the trusted comment
    \\  -f            force: overwrite an existing key pair (-G only)
    \\  -h, --help    this text
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    // A `DebugAllocator` that panics on leak makes the example a leak
    // detector for the module's ownership contract (CONVENTIONS.md §7.2).
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.next(); // argv[0]

    // No arguments at all -> self-demo. `probe` is a value copy (the POSIX
    // iterator is just a slice), so peeking here consumes nothing `parseArgs`
    // below would otherwise see.
    var probe = args;
    if (probe.next() == null) return runSelfDemo(gpa, io);

    var opts = parseArgs(gpa, init, &args) catch |err| switch (err) {
        error.BadUsage => {
            try printOut(io, "{s}", .{usage_text});
            return 1;
        },
        else => return err,
    };
    defer opts.deinit(gpa);

    return switch (opts.mode) {
        .help => blk: {
            try printOut(io, "{s}", .{usage_text});
            break :blk 0;
        },
        .generate => runGenerate(gpa, io, opts),
        .recreate_pub => runRecreate(gpa, io, opts),
        .change_password => runChangePassword(gpa, io, opts),
        .sign => runSign(gpa, io, opts),
        .verify => runVerify(gpa, io, opts),
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// no arguments — self-demo
// ─────────────────────────────────────────────────────────────────────────────
//
// A throwaway key pair, entirely in memory: sign a message, verify it, then
// prove the two ways verification MUST fail — a tampered message and a wrong
// public key — are each rejected by a distinct named error rather than one
// generic "no". No files touch disk here; `-G`/`-S`/`-V` above are what
// exercises the on-disk formats this module does not own itself (see the
// file doc comment).

fn runSelfDemo(gpa: Allocator, io: std.Io) !u8 {
    var kp = minisign.KeyPair.generate(io);
    defer kp.wipe();

    const message = "zig-libs minisign module -- self-demo message, signed and verified in one process.";
    const trusted_comment = "self-demo trusted comment";

    const signed = try minisign.signFile(gpa, kp, message, .prehashed, trusted_comment);
    const parsed: minisign.ParsedSignature = .{
        .untrusted_comment = "",
        .signature = signed.signature,
        .algorithm = .prehashed,
        .trusted_comment = trusted_comment,
        .global_signature = signed.global_signature,
    };

    // 1. The honest path: right message, right key.
    try minisign.verifyFile(gpa, kp.publicKey(), message, parsed);
    std.debug.print("[1] signed and verified a {d}-byte message with a fresh key pair\n", .{message.len});

    // 2. A tampered message must be rejected, and rejected by the SPECIFIC
    // error the crypto layer names for a bad signature -- not swallowed into
    // a generic failure.
    var tampered_buf: [message.len]u8 = undefined;
    @memcpy(&tampered_buf, message);
    tampered_buf[0] ^= 0x01;
    if (minisign.verifyFile(gpa, kp.publicKey(), &tampered_buf, parsed)) |_| {
        @panic("minisign-demo: self-demo: a tampered message was ACCEPTED");
    } else |err| {
        if (err != error.SignatureVerificationFailed) return err;
    }
    std.debug.print("[2] a one-byte-flipped message was correctly rejected: error.SignatureVerificationFailed\n", .{});

    // 3. A different key pair's public key must also be rejected. Two
    // independently random 8-byte key ids collide with probability ~2^-64,
    // so `verifyMessage`'s own key-id check is expected to fire first
    // (`KeyIdMismatch`); the crypto check (`SignatureVerificationFailed`) is
    // accepted too so this cannot flake on that astronomically unlikely
    // coincidence.
    var wrong_kp = minisign.KeyPair.generate(io);
    defer wrong_kp.wipe();
    if (minisign.verifyFile(gpa, wrong_kp.publicKey(), message, parsed)) |_| {
        @panic("minisign-demo: self-demo: a signature verified against the WRONG public key");
    } else |err| {
        if (err != error.KeyIdMismatch and err != error.SignatureVerificationFailed) return err;
        std.debug.print("[3] verifying against a different key pair's public key was correctly rejected: {t}\n", .{err});
    }

    std.debug.print("minisign-demo: self-demo passed — see -G/-S/-V for the on-disk file formats\n", .{});
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// argument parsing
// ─────────────────────────────────────────────────────────────────────────────

const Mode = enum { help, generate, recreate_pub, change_password, sign, verify };

const Options = struct {
    mode: Mode,
    pubkey_path: []u8,
    seckey_path: []u8,
    message_path: []u8,
    sig_path: []u8,
    inline_pubkey: ?[]u8 = null,
    untrusted_comment: ?[]u8 = null,
    trusted_comment: ?[]u8 = null,
    force: bool = false,
    no_password: bool = false,
    legacy: bool = false,
    require_prehashed: bool = false,
    output_content: bool = false,
    quiet: bool = false,
    pretty_quiet: bool = false,

    fn deinit(self: *Options, gpa: Allocator) void {
        gpa.free(self.pubkey_path);
        gpa.free(self.seckey_path);
        gpa.free(self.message_path);
        gpa.free(self.sig_path);
        if (self.inline_pubkey) |s| gpa.free(s);
        if (self.untrusted_comment) |s| gpa.free(s);
        if (self.trusted_comment) |s| gpa.free(s);
    }
};

fn parseArgs(gpa: Allocator, init: std.process.Init.Minimal, args: *std.process.Args.Iterator) !Options {
    var mode: ?Mode = null;
    var pubkey_path: ?[]u8 = null;
    var seckey_path: ?[]u8 = null;
    var message_path: ?[]u8 = null;
    var sig_path: ?[]u8 = null;
    var inline_pubkey: ?[]u8 = null;
    var untrusted_comment: ?[]u8 = null;
    var trusted_comment: ?[]u8 = null;
    var force = false;
    var no_password = false;
    var legacy = false;
    var require_prehashed = false;
    var output_content = false;
    var quiet = false;
    var pretty_quiet = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-G")) {
            if (mode != null) return error.BadUsage;
            mode = .generate;
        } else if (std.mem.eql(u8, arg, "-R")) {
            if (mode != null) return error.BadUsage;
            mode = .recreate_pub;
        } else if (std.mem.eql(u8, arg, "-C")) {
            if (mode != null) return error.BadUsage;
            mode = .change_password;
        } else if (std.mem.eql(u8, arg, "-S")) {
            if (mode != null) return error.BadUsage;
            mode = .sign;
        } else if (std.mem.eql(u8, arg, "-V")) {
            if (mode != null) return error.BadUsage;
            mode = .verify;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            if (mode != null) return error.BadUsage;
            mode = .help;
        } else if (std.mem.eql(u8, arg, "-f")) {
            force = true;
        } else if (std.mem.eql(u8, arg, "-W")) {
            no_password = true;
        } else if (std.mem.eql(u8, arg, "-l")) {
            legacy = true;
        } else if (std.mem.eql(u8, arg, "-H")) {
            require_prehashed = true;
        } else if (std.mem.eql(u8, arg, "-o")) {
            output_content = true;
        } else if (std.mem.eql(u8, arg, "-q")) {
            quiet = true;
        } else if (std.mem.eql(u8, arg, "-Q")) {
            pretty_quiet = true;
        } else if (std.mem.eql(u8, arg, "-m")) {
            message_path = try gpa.dupe(u8, try nextValue(args, "-m"));
        } else if (std.mem.eql(u8, arg, "-p")) {
            pubkey_path = try gpa.dupe(u8, try nextValue(args, "-p"));
        } else if (std.mem.eql(u8, arg, "-s")) {
            seckey_path = try gpa.dupe(u8, try nextValue(args, "-s"));
        } else if (std.mem.eql(u8, arg, "-x")) {
            sig_path = try gpa.dupe(u8, try nextValue(args, "-x"));
        } else if (std.mem.eql(u8, arg, "-P")) {
            inline_pubkey = try gpa.dupe(u8, try nextValue(args, "-P"));
        } else if (std.mem.eql(u8, arg, "-c")) {
            untrusted_comment = try gpa.dupe(u8, try nextValue(args, "-c"));
        } else if (std.mem.eql(u8, arg, "-t")) {
            trusted_comment = try gpa.dupe(u8, try nextValue(args, "-t"));
        } else {
            std.debug.print("minisign-demo: unknown argument '{s}'\n", .{arg});
            return error.BadUsage;
        }
    }

    const m = mode orelse return error.BadUsage;
    if (m == .help) {
        return .{
            .mode = .help,
            .pubkey_path = try gpa.dupe(u8, ""),
            .seckey_path = try gpa.dupe(u8, ""),
            .message_path = try gpa.dupe(u8, ""),
            .sig_path = try gpa.dupe(u8, ""),
        };
    }

    if ((m == .sign or m == .verify) and message_path == null) {
        std.debug.print("minisign-demo: {s} needs -m <file>\n", .{if (m == .sign) "-S" else "-V"});
        return error.BadUsage;
    }

    const home = std.process.Environ.getPosix(init.environ, "HOME");
    if (pubkey_path == null) pubkey_path = try gpa.dupe(u8, "minisign.pub");
    if (seckey_path == null) seckey_path = try defaultSeckeyPath(gpa, home);
    if (message_path == null) message_path = try gpa.dupe(u8, "");
    if (sig_path == null) {
        sig_path = if (message_path.?.len != 0)
            try defaultSigPath(gpa, message_path.?)
        else
            try gpa.dupe(u8, "");
    }

    return .{
        .mode = m,
        .pubkey_path = pubkey_path.?,
        .seckey_path = seckey_path.?,
        .message_path = message_path.?,
        .sig_path = sig_path.?,
        .inline_pubkey = inline_pubkey,
        .untrusted_comment = untrusted_comment,
        .trusted_comment = trusted_comment,
        .force = force,
        .no_password = no_password,
        .legacy = legacy,
        .require_prehashed = require_prehashed,
        .output_content = output_content,
        .quiet = quiet,
        .pretty_quiet = pretty_quiet,
    };
}

fn nextValue(args: *std.process.Args.Iterator, flag: []const u8) ![]const u8 {
    return args.next() orelse {
        std.debug.print("minisign-demo: {s} needs a value\n", .{flag});
        return error.BadUsage;
    };
}

/// `~/.minisign/minisign.key` — real `minisign(1)`'s own default. No
/// `$HOME` (a container, a script running under a stripped environment):
/// keep the relative name rather than inventing an absolute path that is
/// certainly wrong.
fn defaultSeckeyPath(gpa: Allocator, home: ?[:0]const u8) ![]u8 {
    const h = home orelse return gpa.dupe(u8, ".minisign/minisign.key");
    return std.fmt.allocPrint(gpa, "{s}/.minisign/minisign.key", .{h});
}

fn defaultSigPath(gpa: Allocator, message_path: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "{s}.minisig", .{message_path});
}

// ─────────────────────────────────────────────────────────────────────────────
// file I/O helpers — everything below is what the module itself never does
// ─────────────────────────────────────────────────────────────────────────────

/// Real `minisign(1)` writes its usage banner and its success/status output
/// (the verify confirmation, `-Q`'s trusted comment, `-S`'s "signed" line,
/// ...) to **stdout** — confirmed by running the real binary with `-V` both
/// clean and with a bad path and diffing what lands on each stream — and
/// reserves stderr for actual failures. `std.debug.print` always writes to
/// stderr, which would make `-Q`/`-o`'s output unpipeable, so those call
/// sites go through this instead; genuine error/diagnostic messages stay on
/// `std.debug.print` (stderr), matching the real tool.
fn printOut(io: std.Io, comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try w.interface.print(fmt, args);
    try w.interface.flush();
}

/// Read a whole (small — key/signature) file. `null` on any I/O error, with
/// the error already printed, so callers can `orelse return 1` instead of
/// repeating the same message everywhere.
fn tryReadWholeFile(gpa: Allocator, io: std.Io, path: []const u8, limit: std.Io.Limit, what: []const u8) !?[]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, limit) catch |err| {
        std.debug.print("minisign-demo: cannot read {s} ({s}): {t}\n", .{ path, what, err });
        return null;
    };
}

fn writeWholeFile(io: std.Io, path: []const u8, bytes: []const u8, exclusive: bool) !void {
    var file = try std.Io.Dir.cwd().createFile(io, path, .{ .exclusive = exclusive });
    defer file.close(io);
    var wbuf: [4096]u8 = undefined;
    var fw = file.writer(io, &wbuf);
    try fw.interface.writeAll(bytes);
    try fw.interface.flush();
}

const Digest = struct { bytes: [minisign.prehash_length]u8, len: u64 };

/// Streams `path` in `chunk_size` pieces through `Blake2b512.update`,
/// holding one chunk resident at a time — this is the whole reason
/// `signDigest`/`verifyDigest`/`signFileDigest`/`verifyFileDigest` exist on
/// the module: a multi-gigabyte file never has to fit in RAM to be signed
/// or verified in the default (prehashed) mode.
fn digestFile(io: std.Io, path: []const u8) !Digest {
    var file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    var rbuf: [chunk_size]u8 = undefined;
    var fr = file.reader(io, &rbuf);

    var hasher = std.crypto.hash.blake2.Blake2b512.init(.{});
    var total: u64 = 0;
    var chunk: [chunk_size]u8 = undefined;
    while (true) {
        const n = try fr.interface.readSliceShort(&chunk);
        if (n > 0) {
            hasher.update(chunk[0..n]);
            total += n;
        }
        if (n < chunk.len) break; // short read == EOF (Reader.readSliceShort)
    }

    var digest: [minisign.prehash_length]u8 = undefined;
    hasher.final(&digest);
    return .{ .bytes = digest, .len = total };
}

fn tryDigestFile(io: std.Io, path: []const u8) !?Digest {
    return digestFile(io, path) catch |err| {
        std.debug.print("minisign-demo: cannot read {s}: {t}\n", .{ path, err });
        return null;
    };
}

fn streamFileToStdout(io: std.Io, path: []const u8) !void {
    var file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var rbuf: [chunk_size]u8 = undefined;
    var fr = file.reader(io, &rbuf);
    var wbuf: [chunk_size]u8 = undefined;
    var out = std.Io.File.stdout().writer(io, &wbuf);

    // A manual read/write loop, not `Reader.streamRemaining`: that helper
    // opportunistically tries the kernel `sendfile(2)`-backed `sendFile`
    // fast path whenever the source is file-backed, and that path returned
    // `EBADF` against a real terminal fd on this host both in `.positional`
    // and in `.writerStreaming`'s `.streaming` mode (it worked fine once
    // stdout was redirected to a regular file) — found only by running this
    // example against an actual tty, not by `zig build test-minisign`.
    // `readSliceShort` + `writeAll` never invokes that path, so it is
    // portable to whatever stdout happens to be.
    var chunk: [chunk_size]u8 = undefined;
    while (true) {
        const n = try fr.interface.readSliceShort(&chunk);
        if (n > 0) try out.interface.writeAll(chunk[0..n]);
        if (n < chunk.len) break;
    }
    try out.interface.flush();
}

/// Read one line from stdin (visible — see the module doc comment on why
/// this demo does not suppress terminal echo). Empty/EOF is `null`.
fn readLine(io: std.Io, prompt: []const u8, buf: []u8) ?[]const u8 {
    std.debug.print("{s}", .{prompt});
    var r = std.Io.File.stdin().reader(io, buf);
    const line = (r.interface.takeDelimiter('\n') catch return null) orelse return null;
    const trimmed = std.mem.trim(u8, line, " \t\r");
    return if (trimmed.len == 0) null else trimmed;
}

fn timestampSec() i64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts)) != .SUCCESS) return 0;
    return @intCast(ts.sec);
}

fn defaultTrustedComment(gpa: Allocator, message_path: []const u8, algorithm: minisign.Algorithm) ![]u8 {
    const base = std.Io.Dir.path.basename(message_path);
    return std.fmt.allocPrint(gpa, "timestamp:{d}\tfile:{s}\t{s}", .{
        timestampSec(),
        base,
        if (algorithm == .prehashed) "hashed" else "legacy",
    });
}

/// Prompt for a password only if the on-disk key is actually encrypted —
/// mirrors real `minisign`'s own behaviour of never asking for a password
/// an unencrypted (`-W`) key does not have.
fn openWithPasswordIfNeeded(gpa: Allocator, io: std.Io, raw: minisign.RawSecretKey) !minisign.KeyPair {
    if (std.mem.eql(u8, &raw.kdf_alg, &minisign.kdf_alg_none)) {
        return minisign.openSecretKey(gpa, raw, null);
    }
    var pw_buf: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &pw_buf);
    const pw = readLine(io, "Password: ", &pw_buf) orelse "";
    return minisign.openSecretKey(gpa, raw, pw);
}

// ─────────────────────────────────────────────────────────────────────────────
// -G
// ─────────────────────────────────────────────────────────────────────────────

fn runGenerate(gpa: Allocator, io: std.Io, opts: Options) !u8 {
    var kp = minisign.KeyPair.generate(io);
    defer kp.wipe();

    const raw_sec: minisign.RawSecretKey = blk: {
        if (opts.no_password) break :blk kp.toRawSecretKeyPlain();
        var pw_buf: [256]u8 = undefined;
        defer std.crypto.secureZero(u8, &pw_buf);
        const pw = readLine(io, "Password: ", &pw_buf) orelse {
            std.debug.print("minisign-demo: empty password; pass -W to skip encryption\n", .{});
            return 1;
        };
        var salt: [minisign.salt_length]u8 = undefined;
        io.random(&salt);
        break :blk try minisign.sealSecretKey(gpa, kp, pw, salt, minisign.ops_limit_sensitive, minisign.mem_limit_sensitive);
    };

    if (std.Io.Dir.path.dirname(opts.seckey_path)) |dir| {
        try std.Io.Dir.cwd().createDirPath(io, dir);
    }

    {
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        const comment = opts.untrusted_comment orelse minisign.default_secret_key_comment;
        try minisign.writeSecretKeyFile(&aw.writer, comment, raw_sec);
        writeWholeFile(io, opts.seckey_path, aw.written(), !opts.force) catch |err| switch (err) {
            error.PathAlreadyExists => {
                std.debug.print("minisign-demo: {s} already exists (use -f to overwrite)\n", .{opts.seckey_path});
                return 1;
            },
            else => return err,
        };
    }

    {
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        var comment_buf: [64]u8 = undefined;
        const key_id = minisign.formatKeyId(kp.key_number);
        const comment = try std.fmt.bufPrint(&comment_buf, "{s}{s}", .{ minisign.public_key_comment_prefix, key_id });
        try minisign.writePublicKeyFile(&aw.writer, comment, kp.publicKey());
        writeWholeFile(io, opts.pubkey_path, aw.written(), !opts.force) catch |err| switch (err) {
            error.PathAlreadyExists => {
                std.debug.print("minisign-demo: {s} already exists (use -f to overwrite)\n", .{opts.pubkey_path});
                return 1;
            },
            else => return err,
        };
    }

    try printOut(io, "generated key pair {s}: {s} / {s}\n", .{
        minisign.formatKeyId(kp.key_number),
        opts.seckey_path,
        opts.pubkey_path,
    });
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// -R
// ─────────────────────────────────────────────────────────────────────────────

fn runRecreate(gpa: Allocator, io: std.Io, opts: Options) !u8 {
    const text = (try tryReadWholeFile(gpa, io, opts.seckey_path, .limited(4096), "secret key")) orelse return 1;
    defer gpa.free(text);
    const parsed = minisign.parseSecretKeyFile(text) catch {
        std.debug.print("minisign-demo: {s} is not a minisign secret key\n", .{opts.seckey_path});
        return 1;
    };

    var kp = try openWithPasswordIfNeeded(gpa, io, parsed.key);
    defer kp.wipe();

    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    var comment_buf: [64]u8 = undefined;
    const key_id = minisign.formatKeyId(kp.key_number);
    const comment = try std.fmt.bufPrint(&comment_buf, "{s}{s}", .{ minisign.public_key_comment_prefix, key_id });
    try minisign.writePublicKeyFile(&aw.writer, comment, kp.publicKey());
    try writeWholeFile(io, opts.pubkey_path, aw.written(), false);

    try printOut(io, "recreated {s} from {s}\n", .{ opts.pubkey_path, opts.seckey_path });
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// -C
// ─────────────────────────────────────────────────────────────────────────────

fn runChangePassword(gpa: Allocator, io: std.Io, opts: Options) !u8 {
    const text = (try tryReadWholeFile(gpa, io, opts.seckey_path, .limited(4096), "secret key")) orelse return 1;
    defer gpa.free(text);
    const parsed = minisign.parseSecretKeyFile(text) catch {
        std.debug.print("minisign-demo: {s} is not a minisign secret key\n", .{opts.seckey_path});
        return 1;
    };

    var kp = try openWithPasswordIfNeeded(gpa, io, parsed.key);
    defer kp.wipe();

    const raw_sec: minisign.RawSecretKey = blk: {
        if (opts.no_password) break :blk kp.toRawSecretKeyPlain();
        var pw_buf: [256]u8 = undefined;
        defer std.crypto.secureZero(u8, &pw_buf);
        const pw = readLine(io, "New password: ", &pw_buf) orelse {
            std.debug.print("minisign-demo: empty password; pass -W to remove encryption instead\n", .{});
            return 1;
        };
        var salt: [minisign.salt_length]u8 = undefined;
        io.random(&salt);
        break :blk try minisign.sealSecretKey(gpa, kp, pw, salt, minisign.ops_limit_sensitive, minisign.mem_limit_sensitive);
    };

    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try minisign.writeSecretKeyFile(&aw.writer, parsed.untrusted_comment, raw_sec);
    try writeWholeFile(io, opts.seckey_path, aw.written(), false);

    try printOut(io, "updated {s}\n", .{opts.seckey_path});
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// -S
// ─────────────────────────────────────────────────────────────────────────────

fn runSign(gpa: Allocator, io: std.Io, opts: Options) !u8 {
    const text = (try tryReadWholeFile(gpa, io, opts.seckey_path, .limited(4096), "secret key")) orelse return 1;
    defer gpa.free(text);
    const parsed = minisign.parseSecretKeyFile(text) catch {
        std.debug.print("minisign-demo: {s} is not a minisign secret key\n", .{opts.seckey_path});
        return 1;
    };

    var kp = try openWithPasswordIfNeeded(gpa, io, parsed.key);
    defer kp.wipe();

    const algorithm: minisign.Algorithm = if (opts.legacy) .legacy else .prehashed;

    var trusted_comment_owned: ?[]u8 = null;
    defer if (trusted_comment_owned) |b| gpa.free(b);
    const trusted_comment: []const u8 = opts.trusted_comment orelse blk: {
        const b = try defaultTrustedComment(gpa, opts.message_path, algorithm);
        trusted_comment_owned = b;
        break :blk b;
    };
    const untrusted_comment: []const u8 = opts.untrusted_comment orelse minisign.default_signature_comment;

    const signed: minisign.SignedFile = switch (algorithm) {
        .legacy => blk: {
            const message = std.Io.Dir.cwd().readFileAlloc(io, opts.message_path, gpa, .limited(legacy_max_size)) catch |err| switch (err) {
                error.StreamTooLong => {
                    std.debug.print(
                        "minisign-demo: {s} exceeds the {d}-byte legacy (-l) cap -- legacy mode cannot stream " ++
                            "(it signs raw file bytes directly); omit -l to sign the BLAKE2b-512 digest instead\n",
                        .{ opts.message_path, legacy_max_size },
                    );
                    return 1;
                },
                else => {
                    std.debug.print("minisign-demo: cannot read {s}: {t}\n", .{ opts.message_path, err });
                    return 1;
                },
            };
            defer gpa.free(message);
            break :blk try minisign.signFile(gpa, kp, message, .legacy, trusted_comment);
        },
        .prehashed => blk: {
            const d = (try tryDigestFile(io, opts.message_path)) orelse return 1;
            break :blk try minisign.signFileDigest(gpa, kp, d.bytes, trusted_comment);
        },
    };

    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try minisign.writeSignatureFile(&aw.writer, untrusted_comment, signed.signature, trusted_comment, signed.global_signature);
    try writeWholeFile(io, opts.sig_path, aw.written(), false);

    if (!opts.quiet) try printOut(io, "signed {s} -> {s}\n", .{ opts.message_path, opts.sig_path });
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// -V
// ─────────────────────────────────────────────────────────────────────────────

fn runVerify(gpa: Allocator, io: std.Io, opts: Options) !u8 {
    const pubkey: minisign.RawPublicKey = if (opts.inline_pubkey) |b64|
        minisign.parsePublicKeyBase64(b64) catch {
            std.debug.print("minisign-demo: -P value is not a valid minisign public key\n", .{});
            return 1;
        }
    else blk: {
        const text = (try tryReadWholeFile(gpa, io, opts.pubkey_path, .limited(4096), "public key")) orelse return 1;
        defer gpa.free(text);
        const parsed_pk = minisign.parsePublicKeyFile(text) catch {
            std.debug.print("minisign-demo: {s} is not a minisign public key\n", .{opts.pubkey_path});
            return 1;
        };
        break :blk parsed_pk.key;
    };

    const sig_text = (try tryReadWholeFile(gpa, io, opts.sig_path, .limited(4096), "signature")) orelse return 1;
    defer gpa.free(sig_text);
    const parsed = minisign.parseSignatureFile(sig_text) catch {
        std.debug.print("minisign-demo: {s} is not a minisign signature file\n", .{opts.sig_path});
        return 1;
    };

    if (opts.require_prehashed and parsed.algorithm != .prehashed) {
        std.debug.print("minisign-demo: -H requires a prehashed signature; {s} is legacy\n", .{opts.sig_path});
        return 1;
    }

    var verify_err: ?anyerror = null;
    switch (parsed.algorithm) {
        .prehashed => {
            const d = (try tryDigestFile(io, opts.message_path)) orelse return 1;
            minisign.verifyFileDigest(gpa, pubkey, d.bytes, parsed) catch |err| {
                verify_err = err;
            };
        },
        .legacy => {
            const message = (try tryReadWholeFile(gpa, io, opts.message_path, .limited(legacy_max_size), "message")) orelse return 1;
            defer gpa.free(message);
            minisign.verifyFile(gpa, pubkey, message, parsed) catch |err| {
                verify_err = err;
            };
        },
    }

    if (verify_err) |err| {
        std.debug.print("minisign-demo: {t}\n", .{err});
        return 1;
    }

    if (opts.pretty_quiet) {
        try printOut(io, "{s}\n", .{parsed.trusted_comment});
    } else if (!opts.quiet) {
        try printOut(io, "Signature and comment signature verified\nTrusted comment: {s}\n", .{parsed.trusted_comment});
    }

    if (opts.output_content) try streamFileToStdout(io, opts.message_path);
    return 0;
}
