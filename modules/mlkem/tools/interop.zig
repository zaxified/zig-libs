// SPDX-License-Identifier: MIT

//! Live differential oracle: `mlkem` against OpenSSL 3.5's libcrypto (the
//! reference named by the maturity card; system `libcrypto.so.3`, path below or
//! `LIBCRYPTO_SO`, no headers needed).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-mlkem` runs it;
//! `zig build check-interop` compiles it. It needs `zig` on PATH (it builds the
//! C side, `tools/c_oracle/oracle.c`, with `zig cc`) and OpenSSL 3.5. Run from
//! the repository root.
//!
//!     zig build interop-mlkem                          # seed 0x6d6c6b656d, >= 360 rows
//!     zig build interop-mlkem -- --seed 7 --cases 3000 # another draw, more rows
//!
//! All three parameter sets, every row judged by OpenSSL, inputs drawn from the
//! seed (`--seed`, `--cases` = the least number of rows; whole rounds of all
//! three sets are run until it is reached):
//!   keygen_ek / keygen_dk   OpenSSL keygen from a random seed d || z
//!                           (OSSL_PKEY_PARAM_ML_KEM_SEED) gives our ek and dk bytes.
//!   ours_ek_ossl_encaps     our ek -> OpenSSL encapsulates -> our decaps gives its secret.
//!   encaps_det              OpenSSL's encapsulation with a given m (OSSL_KEM_PARAM_IKME)
//!                           equals ours byte for byte (ciphertext and secret).
//!   ossl_ek_ours_encaps     OpenSSL's ek -> our `encaps(io)` -> OpenSSL decapsulates
//!                           to our secret.
//!   ct_mutation             a bit flipped in u, in v, or a random ciphertext: both
//!                           implicit rejections agree (the 32 octets J(z || c)).
//!   ek_verdict / ek_encaps  a non-canonical, a flipped-t, a flipped-rho encapsulation
//!                           key: both accept or both refuse; when both accept,
//!                           they encapsulate to the same bytes.
//!   dk_verdict / dk_decaps  a decapsulation key with a flipped H(ek), z, embedded ek
//!                           coefficient (non-canonical) or s octet: the import
//!                           verdicts agree (a changed s is a KNOWN difference: OpenSSL
//!                           refuses, ours imports, counted separately); when both accept, they decapsulate alike.
//! A verdict that differs is a DISAGREE line and a non-zero exit; nothing is
//! filtered. The last line is `cases=N agree=N`.

const std = @import("std");
const bench = @import("testkit").bench;
const mlkem = @import("mlkem");

const prog = "interop-mlkem";
const work_dir = ".zig-cache/interop-mlkem";
const c_source = "modules/mlkem/tools/c_oracle/oracle.c";
const default_crypto = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const default_seed: u64 = 0x6d6c6b656d;
const default_cases: usize = 360;

// ---- the peer ----

const Oracle = struct {
    arena: std.mem.Allocator,
    io: std.Io,
    child: std.process.Child,
    rbuf: [1 << 16]u8 = undefined,
    wbuf: [1 << 16]u8 = undefined,
    r: std.Io.File.Reader = undefined,
    w: std.Io.File.Writer = undefined,

    fn start(o: *Oracle) void {
        o.r = o.child.stdout.?.readerStreaming(o.io, &o.rbuf);
        o.w = o.child.stdin.?.writerStreaming(o.io, &o.wbuf);
    }

    fn stop(o: *Oracle) void {
        o.child.stdin.?.close(o.io);
        o.child.stdin = null;
        _ = o.child.wait(o.io) catch {};
    }

    /// One request, one reply: the text after `OK`, or null for `ERR`.
    fn ask(o: *Oracle, line: []const u8) !?[]const u8 {
        try o.w.interface.writeAll(line);
        try o.w.interface.writeByte('\n');
        try o.w.interface.flush();
        const reply = (try o.r.interface.takeDelimiter('\n')) orelse {
            std.debug.print(prog ++ ": the C side ended while answering `{s}`\n", .{line[0..@min(line.len, 40)]});
            return error.PeerGone;
        };
        if (std.mem.eql(u8, reply, "ERR")) return null;
        if (!std.mem.startsWith(u8, reply, "OK")) return error.BadReply;
        return try o.arena.dupe(u8, std.mem.trimStart(u8, reply[2..], " "));
    }
};

const Check = enum {
    keygen_ek,
    keygen_dk,
    ours_ek_ossl_encaps,
    encaps_det,
    ossl_ek_ours_encaps,
    ct_mutation,
    ek_verdict,
    ek_encaps,
    dk_verdict,
    dk_decaps,
};
const n_checks = @typeInfo(Check).@"enum".field_names.len;
const set_names = [_][]const u8{ "512", "768", "1024" };

const Tally = struct { n: usize = 0, ok: usize = 0 };

const Run = struct {
    arena: std.mem.Allocator,
    o: *Oracle,
    prng: std.Random.DefaultPrng,
    cases: usize = 0,
    agree: usize = 0,
    known: usize = 0,
    tally: [3][n_checks]Tally = @splat(@splat(.{})),

    fn rnd(r: *Run) std.Random {
        return r.prng.random();
    }

    fn row(r: *Run, set: usize, check: Check, ok: bool, comptime fmt: []const u8, args: anytype) void {
        r.cases += 1;
        const t = &r.tally[set][@backingInt(check)];
        t.n += 1;
        if (ok) {
            r.agree += 1;
            t.ok += 1;
            return;
        }
        std.debug.print("DISAGREE ML-KEM-{s} {t}: " ++ fmt ++ "\n", .{ set_names[set], check } ++ args);
    }

    fn hex(r: *Run, b: []const u8) ![]const u8 {
        return r.arena.print("{x}", .{b});
    }

    fn ask(r: *Run, comptime fmt: []const u8, args: anytype) !?[]const u8 {
        return r.o.ask(try r.arena.print(fmt, args));
    }

    /// The reply's `i`-th space-separated token, decoded into `out`.
    fn field(reply: []const u8, i: usize, out: []u8) !void {
        var it = std.mem.splitScalar(u8, reply, ' ');
        var k: usize = 0;
        while (it.next()) |t| : (k += 1) {
            if (k == i) {
                if (t.len != 2 * out.len) return error.BadReply;
                _ = try std.fmt.hexToBytes(out, t);
                return;
            }
        }
        return error.BadReply;
    }
};

fn oneSet(comptime K: type, r: *Run, si: usize) !void {
    const sn = set_names[si];
    const ek_len = K.PublicKey.encoded_length;
    const dk_len = K.SecretKey.encoded_length;
    const ct_len = K.ciphertext_length;
    const t_len = ek_len - 32; // the t-hat part; rho follows
    const rng = r.rnd();

    // (1) keygen from a seed.
    var seed: [64]u8 = undefined;
    rng.bytes(&seed);
    const kp = K.KeyPair.generateDeterministic(seed);
    const our_ek = kp.public_key.toBytes();
    const our_dk = kp.secret_key.toBytes();
    const gen = (try r.ask("KEYGEN {s} {s}", .{ sn, try r.hex(&seed) })) orelse return error.OpenSslRefusedSeed;
    var ossl_ek: [ek_len]u8 = undefined;
    var ossl_dk: [dk_len]u8 = undefined;
    try Run.field(gen, 0, &ossl_ek);
    try Run.field(gen, 1, &ossl_dk);
    r.row(si, .keygen_ek, std.mem.eql(u8, &ossl_ek, &our_ek), "ek differs for seed {x}", .{seed});
    r.row(si, .keygen_dk, std.mem.eql(u8, &ossl_dk, &our_dk), "dk differs for seed {x}", .{seed});

    // (2) our ek, OpenSSL encapsulates with m; (4) the same m through ours.
    var m: [32]u8 = undefined;
    rng.bytes(&m);
    const enc = (try r.ask("ENCAPS {s} {s} {s}", .{ sn, try r.hex(&our_ek), try r.hex(&m) })) orelse return error.OpenSslRefusedOurEk;
    var o_ct: [ct_len]u8 = undefined;
    var o_ss: [32]u8 = undefined;
    try Run.field(enc, 0, &o_ct);
    try Run.field(enc, 1, &o_ss);
    const dec = kp.secret_key.decaps(&o_ct);
    r.row(si, .ours_ek_ossl_encaps, std.mem.eql(u8, &dec, &o_ss), "our decaps of OpenSSL's ciphertext differs, m={x}", .{m});
    const mine = kp.public_key.encapsDeterministic(&m);
    r.row(si, .encaps_det, std.mem.eql(u8, &mine.ciphertext, &o_ct) and std.mem.eql(u8, &mine.shared_secret, &o_ss), "encapsulation with m={x} differs", .{m});

    // (3) OpenSSL's ek (imported by us), our random encapsulation, OpenSSL decapsulates.
    {
        const pk = try K.PublicKey.fromBytes(&ossl_ek);
        const es = pk.encaps(r.o.io);
        const back = try r.ask("DECAPS {s} {s} {s}", .{ sn, try r.hex(&ossl_dk), try r.hex(&es.ciphertext) });
        var ss: [32]u8 = undefined;
        if (back) |b| try Run.field(b, 0, &ss);
        r.row(si, .ossl_ek_ours_encaps, back != null and std.mem.eql(u8, &ss, &es.shared_secret), "OpenSSL decapsulation of our ciphertext differs", .{});
    }

    // (5) mutated ciphertexts: implicit rejection must agree.
    const u_len = ct_len - (if (ct_len == 1568) @as(usize, 160) else 128); // v is 32 * dv octets
    for (0..3) |variant| {
        var c = o_ct;
        switch (variant) {
            0 => c[rng.uintLessThan(usize, u_len)] ^= @as(u8, 1) << rng.int(u3), // in u
            1 => c[u_len + rng.uintLessThan(usize, ct_len - u_len)] ^= @as(u8, 1) << rng.int(u3), // in v
            else => rng.bytes(&c),
        }
        const theirs = try r.ask("DECAPS {s} {s} {s}", .{ sn, try r.hex(&ossl_dk), try r.hex(&c) });
        var ss: [32]u8 = undefined;
        if (theirs) |b| try Run.field(b, 0, &ss);
        const ours = kp.secret_key.decaps(&c);
        r.row(si, .ct_mutation, theirs != null and std.mem.eql(u8, &ss, &ours), "variant {d}: implicit rejection differs", .{variant});
    }

    // (6) mutated encapsulation keys.
    for (0..3) |variant| {
        var e = our_ek;
        var pos: usize = 0;
        switch (variant) {
            0 => { // a 12-bit coefficient pair forced to 4095
                pos = 3 * rng.uintLessThan(usize, t_len / 3);
                e[pos] = 0xff;
                e[pos + 1] = 0xff;
                e[pos + 2] = 0xff;
            },
            1 => { // a random flip inside t-hat (may or may not leave it canonical)
                pos = rng.uintLessThan(usize, t_len);
                e[pos] ^= @as(u8, 1) << rng.int(u3);
            },
            else => { // a flip in rho
                pos = t_len + rng.uintLessThan(usize, 32);
                e[pos] ^= @as(u8, 1) << rng.int(u3);
            },
        }
        const theirs = try r.ask("IMPEK {s} {s}", .{ sn, try r.hex(&e) });
        const ours: ?K.PublicKey = K.PublicKey.fromBytes(&e) catch null;
        r.row(si, .ek_verdict, (theirs != null) == (ours != null), "variant {d} pos {d}: OpenSSL {s}, ours {s}", .{ variant, pos, if (theirs != null) "accepts" else "refuses", if (ours != null) "accepts" else "refuses" });
        if (theirs != null and ours != null) {
            const t = (try r.ask("ENCAPS {s} {s} {s}", .{ sn, try r.hex(&e), try r.hex(&m) })).?;
            var tct: [ct_len]u8 = undefined;
            var tss: [32]u8 = undefined;
            try Run.field(t, 0, &tct);
            try Run.field(t, 1, &tss);
            const o = ours.?.encapsDeterministic(&m);
            r.row(si, .ek_encaps, std.mem.eql(u8, &tct, &o.ciphertext) and std.mem.eql(u8, &tss, &o.shared_secret), "variant {d} pos {d}: encapsulation to the mutated ek differs", .{ variant, pos });
        }
    }

    // (7) mutated decapsulation keys: dk = s || ek || H(ek) || z.
    for (0..5) |variant| {
        var d = our_dk;
        var pos: usize = 0;
        switch (variant) {
            0 => pos = dk_len - 64 + rng.uintLessThan(usize, 32), // H(ek)
            1 => pos = dk_len - 32 + rng.uintLessThan(usize, 32), // z
            2 => { // the embedded ek: a coefficient pair forced to 4095
                pos = t_len + 3 * rng.uintLessThan(usize, t_len / 3);
                d[pos] = 0xff;
                d[pos + 1] = 0xff;
                d[pos + 2] = 0xff;
            },
            3 => pos = rng.uintLessThan(usize, t_len), // s
            else => pos = 3 * rng.uintLessThan(usize, t_len / 3), // s, the low bit of a coefficient
        }
        if (variant == 4) d[pos] ^= 1 else if (variant != 2) d[pos] ^= @as(u8, 1) << rng.int(u3);
        const theirs = try r.ask("IMPDK {s} {s}", .{ sn, try r.hex(&d) });
        const ours: ?K.SecretKey = K.SecretKey.fromBytes(&d) catch null;
        // Known, recorded difference: OpenSSL's parser refuses a dk whose s part
        // was changed in ANY way (measured: even one low bit of a coefficient),
        // a check FIPS 203 section 7.3 does not ask for; ours imports it.
        const known = variant >= 3 and theirs == null and ours != null;
        if (known) r.known += 1;
        r.row(si, .dk_verdict, (theirs != null) == (ours != null) or known, "variant {d} pos {d}: OpenSSL {s}, ours {s}", .{ variant, pos, if (theirs != null) "accepts" else "refuses", if (ours != null) "accepts" else "refuses" });
        if (theirs != null and ours != null) {
            const t = (try r.ask("DECAPS {s} {s} {s}", .{ sn, try r.hex(&d), try r.hex(&o_ct) })).?;
            var tss: [32]u8 = undefined;
            try Run.field(t, 0, &tss);
            const o = ours.?.decaps(&o_ct);
            r.row(si, .dk_decaps, std.mem.eql(u8, &tss, &o), "variant {d} pos {d}: decapsulation with the mutated dk differs", .{ variant, pos });
        }
    }
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    var seed: u64 = default_seed;
    var cases: usize = default_cases;
    const args = try init.minimal.args.toSlice(arena);
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--seed") and i + 1 < args.len) {
            i += 1;
            seed = try std.fmt.parseInt(u64, args[i], 0);
        } else if (std.mem.eql(u8, a, "--cases") and i + 1 < args.len) {
            i += 1;
            cases = try std.fmt.parseInt(usize, args[i], 10);
        } else {
            std.debug.print("usage: zig build interop-mlkem [-- [--seed N] [--cases N]]\n", .{});
            return 2;
        }
    }

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const crypto_so = init.environ_map.get("LIBCRYPTO_SO") orelse default_crypto;
    const exe = try bench.buildForeign(arena, io, prog, &.{ "zig", "cc" }, abs, c_source, &.{crypto_so});

    const o = try arena.create(Oracle);
    o.* = .{
        .arena = arena,
        .io = io,
        .child = std.process.spawn(io, .{ .argv = &.{exe}, .stdin = .pipe, .stdout = .pipe, .stderr = .inherit }) catch |e| {
            std.debug.print(prog ++ ": could not start {s} ({t})\n", .{ exe, e });
            return 1;
        },
    };
    o.start();
    defer o.stop();

    const version = (try o.ask("VERSION")).?;
    std.debug.print(prog ++ ": {s}, seed 0x{x}, at least {d} rows\n", .{ version, seed, cases });

    var r: Run = .{ .arena = arena, .o = o, .prng = .init(seed) };
    while (r.cases < cases) {
        try oneSet(mlkem.MLKem512, &r, 0);
        try oneSet(mlkem.MLKem768, &r, 1);
        try oneSet(mlkem.MLKem1024, &r, 2);
    }

    std.debug.print("\n{s:<22} {s:>12} {s:>12} {s:>12}\n", .{ "check", "512 ok/n", "768 ok/n", "1024 ok/n" });
    inline for (0..n_checks) |ci| {
        const name = @tagName(@as(Check, @fromBackingInt(@intCast(ci))));
        var cell: [3][16]u8 = undefined;
        var s: [3][]const u8 = undefined;
        for (0..3) |k| {
            const t = r.tally[k][ci];
            s[k] = std.fmt.bufPrint(&cell[k], "{d}/{d}", .{ t.ok, t.n }) catch "?";
        }
        std.debug.print("{s:<22} {s:>12} {s:>12} {s:>12}\n", .{ name, s[0], s[1], s[2] });
    }
    std.debug.print("(of the agreeing rows, {d} are the known OpenSSL-refuses-a-changed-s difference in dk_verdict)\n", .{r.known});
    std.debug.print("cases={d} agree={d}\n", .{ r.cases, r.agree });
    return if (r.agree == r.cases) 0 else 1;
}
