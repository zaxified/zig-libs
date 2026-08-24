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
    \\
    \\Exit status: 0 done · 1 error · 3 capsule still locked (round not
    \\published yet; `open`/`info` print when it will be).
    \\
;

/// Capsule file = this header, then `timelock_envelope`'s self-describing
/// wire (which carries the round and both lock ciphertexts, and
/// authenticates everything). The header adds the one fact the envelope
/// does not know: WHICH beacon chain the round number counts on.
const capsule_magic = "TCAP";
const capsule_version: u8 = 1;
const capsule_header_bytes = capsule_magic.len + 1 + 32;

const failure_exit: u8 = 1;
const locked_exit: u8 = 3;

const max_plaintext_bytes = 16 * 1024 * 1024;

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
    var kp = Kem.keypair(&seed);
    defer std.crypto.secureZero(u8, &kp.dk);
    std.crypto.secureZero(u8, &seed);

    const pk_path = try std.fmt.allocPrint(gpa, "{s}.pk", .{stem});
    defer gpa.free(pk_path);
    const sk_path = try std.fmt.allocPrint(gpa, "{s}.sk", .{stem});
    defer gpa.free(sk_path);

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

    const plaintext = std.Io.Dir.cwd().readFileAlloc(io, in_file, gpa, .limited(max_plaintext_bytes)) catch |err| {
        std.debug.print("timecapsule: cannot read {s}: {t}\n", .{ in_file, err });
        return failure_exit;
    };
    defer gpa.free(plaintext);

    const rnd = Env.SealRandomness.generate(io);
    const wire = Env.seal(gpa, plaintext, ek, p_pub, round, rnd) catch |err| {
        std.debug.print("timecapsule: seal failed: {t}\n", .{err});
        return failure_exit;
    };
    defer gpa.free(wire);

    const capsule = try gpa.alloc(u8, capsule_header_bytes + wire.len);
    defer gpa.free(capsule);
    @memcpy(capsule[0..4], capsule_magic);
    capsule[4] = capsule_version;
    @memcpy(capsule[5..][0..32], &info.chain_hash);
    @memcpy(capsule[capsule_header_bytes..], wire);
    try writeWholeFile(io, out_file, capsule, false);

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
    var base: []const u8 = beacon.default_base_url;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--key")) {
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

    const cap = readCapsule(gpa, io, in_file) orelse return failure_exit;
    defer gpa.free(cap.bytes);

    const info = loadInfo(gpa, io, chain_info_path, base) orelse return failure_exit;
    if (!std.mem.eql(u8, &info.chain_hash, &cap.chain_hash)) {
        std.debug.print("timecapsule: capsule was sealed on a different beacon chain than this /info describes\n", .{});
        return failure_exit;
    }

    // Fetch (or load) the round's signature. A 404 is the time lock holding.
    const round_json = beacon.roundDoc(gpa, io, round_file, base, cap.round) catch |err| switch (err) {
        error.RoundNotPublished => {
            const unlock_at = beacon.publishTime(&info, cap.round);
            var when_buf: [40]u8 = undefined;
            std.debug.print("timecapsule: still locked — round {d} publishes {s} ({d}s from now)\n", .{
                cap.round,
                beacon.formatUtc(&when_buf, unlock_at),
                @max(unlock_at - beacon.wallNow(), 0),
            });
            return locked_exit;
        },
        else => {
            std.debug.print("timecapsule: fetching round {d} failed: {t}\n", .{ cap.round, err });
            return failure_exit;
        },
    };
    defer gpa.free(round_json);

    const round = drand.parseRound(gpa, round_json) catch |err| {
        std.debug.print("timecapsule: round document does not parse: {t}\n", .{err});
        return failure_exit;
    };
    if (round.round != cap.round) {
        std.debug.print("timecapsule: signature is for round {d}, capsule unlocks at round {d}\n", .{ round.round, cap.round });
        return failure_exit;
    }
    // BLS-verify the signature against the chain public key BEFORE using it
    // as a decryption key: a fabricated signature must fail here, loudly,
    // not as an opaque envelope error.
    drand.verifyRound(&info, &round) catch |err| {
        std.debug.print("timecapsule: round {d} signature REFUSED by BLS verification: {t}\n", .{ cap.round, err });
        return failure_exit;
    };
    const sig = round.signatureG1() catch unreachable; // verifyRound already required G1

    const plaintext = Env.open(gpa, cap.bytes[capsule_header_bytes..], dk, sig) catch |err| {
        std.debug.print("timecapsule: open REFUSED: {t}\n", .{err});
        return failure_exit;
    };
    defer gpa.free(plaintext);

    try writeWholeFile(io, out_file, plaintext, false);
    std.debug.print("timecapsule: opened {s} -> {s} ({d} bytes)\n", .{ in_file, out_file, plaintext.len });
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

    const cap = readCapsule(gpa, io, in_file) orelse return failure_exit;
    defer gpa.free(cap.bytes);

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

const Capsule = struct {
    bytes: []u8, // whole file; envelope wire starts at capsule_header_bytes
    chain_hash: [32]u8,
    round: u64,
};

fn readCapsule(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ?Capsule {
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(capsule_header_bytes + Env.overhead + max_plaintext_bytes)) catch |err| {
        std.debug.print("timecapsule: cannot read {s}: {t}\n", .{ path, err });
        return null;
    };
    errdefer comptime unreachable;
    if (bytes.len < capsule_header_bytes or !std.mem.eql(u8, bytes[0..4], capsule_magic) or bytes[4] != capsule_version) {
        std.debug.print("timecapsule: {s} is not a version-{d} capsule\n", .{ path, capsule_version });
        gpa.free(bytes);
        return null;
    }
    const parsed = Env.parse(bytes[capsule_header_bytes..]) catch |err| {
        std.debug.print("timecapsule: {s}: envelope framing rejected: {t}\n", .{ path, err });
        gpa.free(bytes);
        return null;
    };
    var cap: Capsule = .{ .bytes = bytes, .chain_hash = undefined, .round = parsed.round };
    @memcpy(&cap.chain_hash, bytes[5..][0..32]);
    return cap;
}

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
