// SPDX-License-Identifier: MIT

//! timecapsule — encrypt a file so it can be opened only AFTER a chosen
//! wall-clock time, and only BY a chosen recipient.
//!
//! Two locks, both required (`timelock_envelope`'s AND composition):
//!
//!  1. TIME — `tlock` timelock encryption to a future round of the drand
//!     "quicknet" randomness beacon. Until the League of Entropy publishes
//!     that round's threshold-BLS signature, the key to this lock does not
//!     exist anywhere: not on this machine, not on the beacon's, nowhere.
//!  2. RECIPIENT — an HQC post-quantum KEM keypair. Recording the capsule
//!     today and breaking BLS with a quantum computer later still yields
//!     nothing without the recipient's secret key.
//!
//! The round signature that unlocks a capsule is public data; anyone can
//! fetch it. That is the point — the sender needs no further involvement,
//! there is no server of ours to keep alive, and only the recipient's key
//! turns the published signature into the plaintext.

const std = @import("std");
const beacon = @import("beacon.zig");
const drand = @import("drand");
const hqc = @import("hqc");
const tle = @import("timelock_envelope");

const Env = tle.Envelope128;
const Kem = hqc.Hqc128;

const usage =
    \\timecapsule — encrypt to the future (drand timelock + HQC post-quantum lock)
    \\
    \\  timecapsule keygen [--out <stem>]
    \\  timecapsule seal --to <stem.pk> --at <when> --in <file> --out <file.tc>
    \\  timecapsule open --key <stem.sk> --in <file.tc> --out <file>
    \\  timecapsule info --in <file.tc>
    \\
    \\<when> (seal):
    \\  +<n>[smhd]      duration from now, e.g. +90s, +15m, +2h, +7d
    \\  @<unix>         absolute unix time, e.g. @1735689600
    \\  round:<n>       an explicit quicknet round number
    \\
    \\Beacon access (seal/open/info):
    \\  --beacon <url>       drand HTTP API base   (default https://api.drand.sh)
    \\  --chain-info <file>  read the /info document from a file instead of
    \\                       fetching it — offline use, or a pinned trust root
    \\  --round-file <file>  (open) read the /public/<round> document from a
    \\                       file instead of fetching it
    \\  --wait               (open) instead of exiting 3 while locked, sleep
    \\                       until the round's publish time and keep polling
    \\                       the source (the beacon, or --round-file) until
    \\                       the signature appears — then open
    \\
    \\Exit status: 0 done · 1 error · 3 capsule still locked (round not
    \\published yet; `open`/`info` print when it will be).
    \\
;

/// Capsule file = this header, then `timelock_envelope`'s self-describing
/// wire (which carries the round and both lock ciphertexts, and
/// authenticates everything). The header adds the one fact the envelope
/// does not know: WHICH beacon chain the round number counts on.
///
/// `seal` writes the envelope's version-2 STREAM wire, so a payload of any
/// size is sealed and opened in bounded memory. `open` also reads the
/// version-1 one-shot wire that earlier releases of this app wrote — a time
/// capsule exists to be opened later, so the old format stays readable.
const capsule_magic = "TCAP";
const capsule_version: u8 = 1;
const capsule_header_bytes = capsule_magic.len + 1 + 32;

/// Both envelope versions start with the same 15 bytes: magic, version,
/// suite, flags, round (u64 LE).
/// zig-libs request: timelock_envelope — no header parser for the v2 stream
/// wire (`Envelope.parse` answers UnsupportedVersion); this app reads the
/// shared prefix itself. Backlog in modules/timelock_envelope/SPEC.md.
const envelope_prefix_bytes = tle.stream.stream_header_bytes;
const envelope_round_off = 7;

const failure_exit: u8 = 1;
const locked_exit: u8 = 3;

/// Upper bound for the in-memory version-1 path only; version 2 streams.
const max_v1_plaintext_bytes = 16 * 1024 * 1024;
const io_buffer_bytes = 64 * 1024;

pub fn main(init: std.process.Init.Minimal) !u8 {
    // DebugAllocator panicking on leak makes the app a leak detector for the
    // three modules' ownership contracts, same as the sibling apps.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.skip(); // argv[0]

    const mode = args.next() orelse {
        std.debug.print("{s}", .{usage});
        return failure_exit;
    };
    if (std.mem.eql(u8, mode, "-h") or std.mem.eql(u8, mode, "--help")) {
        std.debug.print("{s}", .{usage});
        return 0;
    }

    if (std.mem.eql(u8, mode, "keygen")) return keygen(gpa, io, &args);
    if (std.mem.eql(u8, mode, "seal")) return seal(gpa, io, &args);
    if (std.mem.eql(u8, mode, "open")) return open(gpa, io, &args);
    if (std.mem.eql(u8, mode, "info")) return capsuleInfo(gpa, io, &args);

    std.debug.print("timecapsule: unknown command '{s}'\n{s}", .{ mode, usage });
    return failure_exit;
}

// ---------------------------------------------------------------------------
// keygen

fn keygen(gpa: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !u8 {
    var stem: []const u8 = "capsule";
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--out")) {
            stem = try nextValue(args, "--out");
        } else return unknown(arg);
    }

    var seed: [hqc.params.seed_bytes]u8 = undefined;
    try io.randomSecure(&seed);
    var kp: Kem.KeyPair = undefined;
    Kem.keypair(&kp, &seed);
    defer std.crypto.secureZero(u8, &kp.dk);
    std.crypto.secureZero(u8, &seed);

    const pk_path = try std.fmt.allocPrint(gpa, "{s}.pk", .{stem});
    defer gpa.free(pk_path);
    const sk_path = try std.fmt.allocPrint(gpa, "{s}.sk", .{stem});
    defer gpa.free(sk_path);

    // Never clobber an existing keypair. Overwriting a `.sk` is irreversible
    // and orphans every capsule already sealed to the matching `.pk` — for a
    // tool whose whole job is guarding that key, a silent truncate is the
    // worst possible default. Refuse if either file exists (checked before
    // writing either, so a half-written pair is impossible), and let the user
    // pick another `--out` or delete the old pair deliberately.
    if (fileExists(io, pk_path) or fileExists(io, sk_path)) {
        std.debug.print("timecapsule: {s}.pk / {s}.sk already exist — refusing to overwrite a keypair; use --out or remove them first\n", .{ stem, stem });
        return failure_exit;
    }

    try writeWholeFile(io, pk_path, &kp.ek, false);
    try writeWholeFile(io, sk_path, &kp.dk, true);

    std.debug.print(
        "timecapsule: wrote {s} ({d} bytes, share this) and {s} ({d} bytes, mode 0600 — KEEP this)\n",
        .{ pk_path, kp.ek.len, sk_path, kp.dk.len },
    );
    return 0;
}

// ---------------------------------------------------------------------------
// seal

fn seal(gpa: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !u8 {
    var to_path: ?[]const u8 = null;
    var at: ?[]const u8 = null;
    var in_path: ?[]const u8 = null;
    var out_path: ?[]const u8 = null;
    var chain_info_path: ?[]const u8 = null;
    var base: []const u8 = beacon.default_base_url;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--to")) {
            to_path = try nextValue(args, "--to");
        } else if (std.mem.eql(u8, arg, "--at")) {
            at = try nextValue(args, "--at");
        } else if (std.mem.eql(u8, arg, "--in")) {
            in_path = try nextValue(args, "--in");
        } else if (std.mem.eql(u8, arg, "--out")) {
            out_path = try nextValue(args, "--out");
        } else if (std.mem.eql(u8, arg, "--chain-info")) {
            chain_info_path = try nextValue(args, "--chain-info");
        } else if (std.mem.eql(u8, arg, "--beacon")) {
            base = try nextValue(args, "--beacon");
        } else return unknown(arg);
    }
    const to = to_path orelse return missing("--to");
    const when = at orelse return missing("--at");
    const in_file = in_path orelse return missing("--in");
    const out_file = out_path orelse return missing("--out");

    // Recipient public key: exact length or it is not an HQC-128 key.
    const ek_bytes = std.Io.Dir.cwd().readFileAlloc(io, to, gpa, .limited(Kem.ek_bytes + 1)) catch |err| {
        std.debug.print("timecapsule: cannot read {s}: {t}\n", .{ to, err });
        return failure_exit;
    };
    defer gpa.free(ek_bytes);
    if (ek_bytes.len != Kem.ek_bytes) {
        std.debug.print("timecapsule: {s} is {d} bytes, an HQC-128 public key is {d}\n", .{ to, ek_bytes.len, Kem.ek_bytes });
        return failure_exit;
    }
    var ek: Kem.EncapsKey = undefined;
    @memcpy(&ek, ek_bytes);

    const info = loadInfo(gpa, io, chain_info_path, base) orelse return failure_exit;
    const p_pub = info.pubkey_g2 orelse {
        std.debug.print("timecapsule: beacon scheme '{t}' is not the quicknet sig-on-G1 scheme\n", .{info.scheme});
        return failure_exit;
    };

    const round = parseWhen(when, &info) orelse return failure_exit;
    const unlock_at = beacon.publishTime(&info, round);
    const now = beacon.wallNow();

    var in_f = std.Io.Dir.cwd().openFile(io, in_file, .{}) catch |err| {
        std.debug.print("timecapsule: cannot read {s}: {t}\n", .{ in_file, err });
        return failure_exit;
    };
    defer in_f.close(io);
    var in_buf: [io_buffer_bytes]u8 = undefined;
    var in_r = in_f.readerStreaming(io, &in_buf);

    var out = PartialFile.create(gpa, io, out_file) orelse return failure_exit;
    defer out.deinit(gpa);
    var out_buf: [io_buffer_bytes]u8 = undefined;
    var out_w = out.file.writer(io, &out_buf);

    // `rnd` is half the raw material of the derived content key; zero it after
    // sealing, the same hygiene keygen/open apply to every other secret here.
    var rnd: Env.SealRandomness = undefined;
    Env.SealRandomness.generate(&rnd, io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&rnd));
    sealed: {
        out_w.interface.writeAll(capsule_magic) catch break :sealed;
        out_w.interface.writeByte(capsule_version) catch break :sealed;
        out_w.interface.writeAll(&info.chain_hash) catch break :sealed;
        Env.sealStream(gpa, &out_w.interface, &in_r.interface, &ek, p_pub, round, &rnd) catch |err| {
            if (err == error.ReadFailed) {
                std.debug.print("timecapsule: reading {s} failed: {t}\n", .{ in_file, in_r.err.? });
                out.abort(io);
                return failure_exit;
            }
            break :sealed;
        };
        out_w.interface.flush() catch break :sealed;
        if (!out.commit(io)) return failure_exit;
        break :sealed;
    }
    if (!out.committed) {
        std.debug.print("timecapsule: writing {s} failed: {s}\n", .{ out_file, errName(out_w.err) });
        out.abort(io);
        return failure_exit;
    }

    var when_buf: [40]u8 = undefined;
    std.debug.print("timecapsule: sealed {s} -> {s} (round {d}, publishes {s}{s})\n", .{
        in_file,
        out_file,
        round,
        beacon.formatUtc(&when_buf, unlock_at),
        if (unlock_at <= now) " — already published" else "",
    });
    return 0;
}

// ---------------------------------------------------------------------------
// open

fn open(gpa: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !u8 {
    var key_path: ?[]const u8 = null;
    var in_path: ?[]const u8 = null;
    var out_path: ?[]const u8 = null;
    var chain_info_path: ?[]const u8 = null;
    var round_file: ?[]const u8 = null;
    var wait = false;
    var base: []const u8 = beacon.default_base_url;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--wait")) {
            wait = true;
        } else if (std.mem.eql(u8, arg, "--key")) {
            key_path = try nextValue(args, "--key");
        } else if (std.mem.eql(u8, arg, "--in")) {
            in_path = try nextValue(args, "--in");
        } else if (std.mem.eql(u8, arg, "--out")) {
            out_path = try nextValue(args, "--out");
        } else if (std.mem.eql(u8, arg, "--chain-info")) {
            chain_info_path = try nextValue(args, "--chain-info");
        } else if (std.mem.eql(u8, arg, "--round-file")) {
            round_file = try nextValue(args, "--round-file");
        } else if (std.mem.eql(u8, arg, "--beacon")) {
            base = try nextValue(args, "--beacon");
        } else return unknown(arg);
    }
    const key = key_path orelse return missing("--key");
    const in_file = in_path orelse return missing("--in");
    const out_file = out_path orelse return missing("--out");

    const dk_bytes = std.Io.Dir.cwd().readFileAlloc(io, key, gpa, .limited(Kem.dk_bytes + 1)) catch |err| {
        std.debug.print("timecapsule: cannot read {s}: {t}\n", .{ key, err });
        return failure_exit;
    };
    defer {
        std.crypto.secureZero(u8, dk_bytes);
        gpa.free(dk_bytes);
    }
    if (dk_bytes.len != Kem.dk_bytes) {
        std.debug.print("timecapsule: {s} is {d} bytes, an HQC-128 secret key is {d}\n", .{ key, dk_bytes.len, Kem.dk_bytes });
        return failure_exit;
    }
    var dk: Kem.DecapsKey = undefined;
    @memcpy(&dk, dk_bytes);
    defer std.crypto.secureZero(u8, &dk);

    const cap = readHead(gpa, io, in_file) orelse return failure_exit;

    const info = loadInfo(gpa, io, chain_info_path, base) orelse return failure_exit;
    if (!std.mem.eql(u8, &info.chain_hash, &cap.chain_hash)) {
        std.debug.print("timecapsule: capsule was sealed on a different beacon chain than this /info describes\n", .{});
        return failure_exit;
    }

    // Fetch (or load) the round's signature. A 425/404 is the time lock
    // holding; with --wait, so is a --round-file that does not exist yet.
    // Acquire the round's signature, polling under --wait. "Not ready yet"
    // has two shapes while polling a --round-file: the file is absent
    // (FileNotFound), or it is present but mid-write, which surfaces LATER as
    // a parse error on a truncated document. Both are retryable under --wait;
    // treating the parse error as fatal (it was, before) turned a non-atomic
    // writer racing the poll into a permanent exit 1, and `--round-file` is
    // exactly the pattern smoke.sh feeds.
    var announced = false;
    const round = while (true) {
        not_ready: {
            const doc = beacon.roundDoc(gpa, io, round_file, base, cap.round) catch |err| {
                const retryable = err == error.RoundNotPublished or
                    (wait and round_file != null and err == error.FileNotFound);
                if (!retryable) {
                    std.debug.print("timecapsule: fetching round {d} failed: {t}\n", .{ cap.round, err });
                    return failure_exit;
                }
                break :not_ready;
            };
            defer gpa.free(doc);
            const parsed = drand.parseRound(gpa, doc) catch |err| {
                // Retryable only while WAITING on a file that may still be
                // half-written; a fetched-and-broken document, or a broken
                // file without --wait, is a real error.
                if (!(wait and round_file != null)) {
                    std.debug.print("timecapsule: round document does not parse: {t}\n", .{err});
                    return failure_exit;
                }
                break :not_ready;
            };
            if (parsed.round != cap.round) {
                std.debug.print("timecapsule: signature is for round {d}, capsule unlocks at round {d}\n", .{ parsed.round, cap.round });
                return failure_exit;
            }
            break parsed;
        }

        // Reaching here means "not published / not ready yet".
        const unlock_at = beacon.publishTime(&info, cap.round);
        const remaining = @max(unlock_at - beacon.wallNow(), 0);
        if (!wait) {
            var when_buf: [40]u8 = undefined;
            std.debug.print("timecapsule: still locked — round {d} publishes {s} ({d}s from now)\n", .{
                cap.round,
                beacon.formatUtc(&when_buf, unlock_at),
                remaining,
            });
            return locked_exit;
        }
        if (!announced) {
            var when_buf: [40]u8 = undefined;
            std.debug.print("timecapsule: waiting — round {d} publishes {s} ({d}s from now)\n", .{
                cap.round,
                beacon.formatUtc(&when_buf, unlock_at),
                remaining,
            });
            announced = true;
        }
        // One long sleep to just short of the publish time, then poll on the
        // beacon's own cadence. Chunked so a Ctrl+C lands promptly.
        const step_s: u64 = if (remaining > 5)
            @min(@as(u64, @intCast(remaining - 2)), 60)
        else
            @max(info.period_seconds, 2);
        io.sleep(.fromMilliseconds(@intCast(step_s * 1000)), .awake) catch return failure_exit;
    };
    // BLS-verify the signature against the chain public key BEFORE using it
    // as a decryption key: a fabricated signature must fail here, loudly,
    // not as an opaque envelope error.
    drand.verifyRound(&info, &round) catch |err| {
        std.debug.print("timecapsule: round {d} signature REFUSED by BLS verification: {t}\n", .{ cap.round, err });
        return failure_exit;
    };
    const sig = round.signatureG1() catch unreachable; // verifyRound already required G1

    if (cap.version == tle.envelope.version) return openV1(gpa, io, in_file, out_file, &dk, sig);

    var in_f = std.Io.Dir.cwd().openFile(io, in_file, .{}) catch |err| {
        std.debug.print("timecapsule: cannot read {s}: {t}\n", .{ in_file, err });
        return failure_exit;
    };
    defer in_f.close(io);
    var in_buf: [io_buffer_bytes]u8 = undefined;
    var in_r = in_f.readerStreaming(io, &in_buf);

    // The stream releases each chunk once its own tag verifies, but the
    // payload is complete only when `openStream` returns cleanly — a
    // truncated or tampered tail shows up only when it is reached. So the
    // plaintext goes to `<out>.partial` and becomes `<out>` only on success;
    // on any refusal there is no output file at all, never a partial one.
    var out = PartialFile.create(gpa, io, out_file) orelse return failure_exit;
    defer out.deinit(gpa);
    var out_buf: [io_buffer_bytes]u8 = undefined;
    var out_w = out.file.writer(io, &out_buf);

    opened: {
        in_r.interface.discardAll(capsule_header_bytes) catch break :opened;
        Env.openStream(gpa, &out_w.interface, &in_r.interface, &dk, sig) catch |err| switch (err) {
            error.ReadFailed, error.WriteFailed => break :opened,
            else => {
                std.debug.print("timecapsule: open REFUSED: {t}\n", .{err});
                out.abort(io);
                return failure_exit;
            },
        };
        out_w.interface.flush() catch break :opened;
        if (!out.commit(io)) return failure_exit;
    }
    if (!out.committed) {
        std.debug.print("timecapsule: I/O failed while opening {s}: read {s}, write {s}\n", .{
            in_file, errName(in_r.err), errName(out_w.err),
        });
        out.abort(io);
        return failure_exit;
    }
    std.debug.print("timecapsule: opened {s} -> {s} ({d} bytes)\n", .{ in_file, out_file, out_w.logicalPos() });
    return 0;
}

/// The version-1 one-shot wire, as earlier releases of this app sealed it:
/// read whole (bounded), opened in memory.
fn openV1(
    gpa: std.mem.Allocator,
    io: std.Io,
    in_file: []const u8,
    out_file: []const u8,
    dk: *const Kem.DecapsKey,
    sig: drand.bls12_381.g1.Affine,
) !u8 {
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, in_file, gpa, .limited(capsule_header_bytes + Env.overhead + max_v1_plaintext_bytes)) catch |err| {
        std.debug.print("timecapsule: cannot read {s}: {t}\n", .{ in_file, err });
        return failure_exit;
    };
    defer gpa.free(bytes);
    const plaintext = Env.open(gpa, bytes[capsule_header_bytes..], dk, sig) catch |err| {
        std.debug.print("timecapsule: open REFUSED: {t}\n", .{err});
        return failure_exit;
    };
    defer gpa.free(plaintext);

    try writeWholeFile(io, out_file, plaintext, false);
    std.debug.print("timecapsule: opened {s} -> {s} ({d} bytes, version-1 capsule)\n", .{ in_file, out_file, plaintext.len });
    return 0;
}

// ---------------------------------------------------------------------------
// info

fn capsuleInfo(gpa: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !u8 {
    var in_path: ?[]const u8 = null;
    var chain_info_path: ?[]const u8 = null;
    var base: []const u8 = beacon.default_base_url;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--in")) {
            in_path = try nextValue(args, "--in");
        } else if (std.mem.eql(u8, arg, "--chain-info")) {
            chain_info_path = try nextValue(args, "--chain-info");
        } else if (std.mem.eql(u8, arg, "--beacon")) {
            base = try nextValue(args, "--beacon");
        } else return unknown(arg);
    }
    const in_file = in_path orelse return missing("--in");

    const cap = readHead(gpa, io, in_file) orelse return failure_exit;

    const info = loadInfo(gpa, io, chain_info_path, base) orelse return failure_exit;
    const unlock_at = beacon.publishTime(&info, cap.round);
    const now = beacon.wallNow();
    var when_buf: [40]u8 = undefined;
    var hash_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hash_hex, "{x}", .{&cap.chain_hash}) catch unreachable;

    std.debug.print("capsule:  {s}\n", .{in_file});
    std.debug.print("chain:    {s}\n", .{hash_hex});
    std.debug.print("round:    {d}\n", .{cap.round});
    if (unlock_at <= now) {
        std.debug.print("unlocks:  {s} — PUBLISHED, openable now\n", .{beacon.formatUtc(&when_buf, unlock_at)});
        return 0;
    }
    std.debug.print("unlocks:  {s} ({d}s from now) — still locked\n", .{
        beacon.formatUtc(&when_buf, unlock_at),
        unlock_at - now,
    });
    return locked_exit;
}

// ---------------------------------------------------------------------------
// helpers

/// What `open`/`info` need before touching any secret: which chain, which
/// round, which envelope version. Only the prefix is read for version 2; a
/// version-1 capsule is small and is framing-checked whole, as before.
const Head = struct {
    chain_hash: [32]u8,
    version: u8,
    round: u64,
};

fn readHead(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ?Head {
    var f = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| {
        std.debug.print("timecapsule: cannot read {s}: {t}\n", .{ path, err });
        return null;
    };
    defer f.close(io);
    const size = f.length(io) catch |err| {
        std.debug.print("timecapsule: cannot read {s}: {t}\n", .{ path, err });
        return null;
    };
    var buf: [capsule_header_bytes + envelope_prefix_bytes]u8 = undefined;
    var r = f.readerStreaming(io, &.{});
    const got = r.interface.readSliceShort(&buf) catch |err| {
        std.debug.print("timecapsule: cannot read {s}: {t}\n", .{ path, err });
        return null;
    };
    if (got < capsule_header_bytes or !std.mem.eql(u8, buf[0..4], capsule_magic) or buf[4] != capsule_version) {
        std.debug.print("timecapsule: {s} is not a version-{d} capsule\n", .{ path, capsule_version });
        return null;
    }
    const env = buf[capsule_header_bytes..got];
    if (env.len < envelope_prefix_bytes or !std.mem.eql(u8, env[0..4], &tle.envelope.magic)) {
        std.debug.print("timecapsule: {s}: envelope framing rejected: BadMagic or Truncated\n", .{path});
        return null;
    }
    const version = env[4];
    if (version == tle.envelope.version) {
        // Version 1: full framing check, exactly as earlier releases did.
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(capsule_header_bytes + Env.overhead + max_v1_plaintext_bytes)) catch |err| {
            std.debug.print("timecapsule: cannot read {s}: {t}\n", .{ path, err });
            return null;
        };
        defer gpa.free(bytes);
        _ = Env.parse(bytes[capsule_header_bytes..]) catch |err| {
            std.debug.print("timecapsule: {s}: envelope framing rejected: {t}\n", .{ path, err });
            return null;
        };
    } else if (version == tle.stream.stream_version) {
        if (env[5] != Env.suite_id) {
            std.debug.print("timecapsule: {s}: envelope framing rejected: SuiteMismatch\n", .{path});
            return null;
        }
        // The smallest valid stream (empty plaintext: one empty last chunk).
        if (size < capsule_header_bytes + Env.streamSealedLen(0)) {
            std.debug.print("timecapsule: {s}: envelope framing rejected: Truncated\n", .{path});
            return null;
        }
    } else {
        std.debug.print("timecapsule: {s}: envelope framing rejected: UnsupportedVersion ({d})\n", .{ path, version });
        return null;
    }
    const round = std.mem.readInt(u64, env[envelope_round_off..][0..8], .little);
    // drand rounds are 1-based; round 0 is not a point on any chain, so a
    // capsule claiming it could never have been sealed legitimately and can
    // never be opened. Reject it here rather than downstream — the beacon
    // arithmetic is saturating and would not crash, but "round 0" is a
    // malformed capsule, and saying so is clearer than computing a fictional
    // unlock time for it.
    if (round == 0) {
        std.debug.print("timecapsule: {s}: capsule names round 0, which no drand chain has\n", .{path});
        return null;
    }
    var head: Head = .{ .chain_hash = undefined, .version = version, .round = round };
    @memcpy(&head.chain_hash, buf[5..][0..32]);
    return head;
}

/// An output file that appears under its real name only once it is
/// complete: everything is written to `<path>.partial`, renamed over
/// `<path>` by `commit`, removed by `abort`.
const PartialFile = struct {
    final: []const u8,
    tmp: []u8,
    file: std.Io.File,
    open: bool = true,
    committed: bool = false,

    fn create(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ?PartialFile {
        const tmp = std.fmt.allocPrint(gpa, "{s}.partial", .{path}) catch {
            std.debug.print("timecapsule: out of memory\n", .{});
            return null;
        };
        const file = std.Io.Dir.cwd().createFile(io, tmp, .{ .truncate = true }) catch |err| {
            std.debug.print("timecapsule: cannot create {s}: {t}\n", .{ tmp, err });
            gpa.free(tmp);
            return null;
        };
        return .{ .final = path, .tmp = tmp, .file = file };
    }

    fn close(p: *PartialFile, io: std.Io) void {
        if (p.open) p.file.close(io);
        p.open = false;
    }

    fn commit(p: *PartialFile, io: std.Io) bool {
        p.close(io);
        std.Io.Dir.cwd().rename(p.tmp, std.Io.Dir.cwd(), p.final, io) catch |err| {
            std.debug.print("timecapsule: cannot rename {s} -> {s}: {t}\n", .{ p.tmp, p.final, err });
            p.abort(io);
            return false;
        };
        p.committed = true;
        return true;
    }

    fn abort(p: *PartialFile, io: std.Io) void {
        p.close(io);
        if (!p.committed) std.Io.Dir.cwd().deleteFile(io, p.tmp) catch {};
    }

    fn deinit(p: *PartialFile, gpa: std.mem.Allocator) void {
        std.debug.assert(!p.open); // every path ends in commit or abort
        gpa.free(p.tmp);
    }
};

fn loadInfo(gpa: std.mem.Allocator, io: std.Io, file_path: ?[]const u8, base: []const u8) ?drand.ChainInfo {
    const doc = beacon.infoDoc(gpa, io, file_path, base) catch |err| {
        std.debug.print("timecapsule: cannot load chain info: {t}\n", .{err});
        return null;
    };
    defer gpa.free(doc);
    return drand.parseInfo(gpa, doc) catch |err| {
        std.debug.print("timecapsule: chain info does not parse: {t}\n", .{err});
        return null;
    };
}

fn parseWhen(s: []const u8, info: *const drand.ChainInfo) ?u64 {
    if (std.mem.startsWith(u8, s, "round:")) {
        const n = std.fmt.parseInt(u64, s["round:".len..], 10) catch 0;
        if (n == 0) {
            std.debug.print("timecapsule: --at round:<n> needs a round number >= 1\n", .{});
            return null;
        }
        return n;
    }
    if (s.len > 1 and s[0] == '@') {
        const t = std.fmt.parseInt(i64, s[1..], 10) catch {
            std.debug.print("timecapsule: --at @<unix> does not parse: {s}\n", .{s});
            return null;
        };
        return beacon.roundAtOrAfter(info, t);
    }
    if (s.len > 2 and s[0] == '+') {
        const n = std.fmt.parseInt(u32, s[1 .. s.len - 1], 10) catch {
            std.debug.print("timecapsule: --at +<n>[smhd] does not parse: {s}\n", .{s});
            return null;
        };
        const mult: i64 = switch (s[s.len - 1]) {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            else => {
                std.debug.print("timecapsule: --at duration unit must be s, m, h or d: {s}\n", .{s});
                return null;
            },
        };
        return beacon.roundAtOrAfter(info, beacon.wallNow() + @as(i64, n) * mult);
    }
    std.debug.print("timecapsule: --at must be +<n>[smhd], @<unix>, or round:<n> — got '{s}'\n", .{s});
    return null;
}

fn fileExists(io: std.Io, path: []const u8) bool {
    const f = std.Io.Dir.cwd().openFile(io, path, .{}) catch return false;
    f.close(io);
    return true;
}

fn writeWholeFile(io: std.Io, path: []const u8, bytes: []const u8, secret: bool) !void {
    var file = try std.Io.Dir.cwd().createFile(io, path, .{
        .truncate = true,
        // 0600 at creation — never a window where the secret key is readable.
        .permissions = if (secret) @enumFromInt(0o600) else .default_file,
    });
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var fw = file.writer(io, &buf);
    try fw.interface.writeAll(bytes);
    try fw.interface.flush();
}

fn errName(err: anytype) []const u8 {
    return if (err) |e| @errorName(e) else "ok";
}

fn nextValue(args: *std.process.Args.Iterator, flag: []const u8) ![]const u8 {
    return args.next() orelse {
        std.debug.print("timecapsule: {s} needs a value\n{s}", .{ flag, usage });
        return error.MissingValue;
    };
}

fn missing(flag: []const u8) u8 {
    std.debug.print("timecapsule: {s} is required\n{s}", .{ flag, usage });
    return failure_exit;
}

fn unknown(arg: []const u8) !u8 {
    std.debug.print("timecapsule: unknown option '{s}'\n{s}", .{ arg, usage });
    return failure_exit;
}
