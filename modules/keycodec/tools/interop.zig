// SPDX-License-Identifier: MIT

//! Live differential oracle: keycodec's encrypted PKCS#8 (PBES2) against the
//! system `openssl` binary (3.x), over a fixed-seed run of random cases.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-keycodec` runs it and
//! `zig build check-interop` compiles it. Needs `openssl` 3.x on PATH (prints
//! its version; exit 2 with a message when it is missing or older). No
//! network. Run from the repository root; work files live in
//! `.zig-cache/interop-keycodec/`. Exit 0 = every case agrees; 1 = a
//! disagreement (the first is printed in full: key kind, parameters, password
//! in hex, both sides' bytes) or an oracle failure.
//!
//! Keys: one fresh key per kind from `openssl genpkey` (Ed25519, X25519,
//! Ed448, X448, EC P-256/P-384/P-521/secp256k1, RSA 2048, ML-DSA-44, ML-KEM-768;
//! a kind this OpenSSL cannot generate is skipped and named). Cases come from
//! a fixed PRNG seed: a key kind, a password (1..40 bytes: ASCII, spaces,
//! multi-byte UTF-8, now and then a raw 0x80..0xff byte), and a PBES2 variant:
//! PBKDF2 with one of the five PRFs and 1..~100 000 iterations, or scrypt with
//! N = 2^1..2^14 (N * r <= 2^17, so OpenSSL's default 32 MiB maxmem holds), r in
//! {1, 2, 4, 8}, p in 1..3; AES-128/192/256-CBC; a salt of 1..64 bytes.
//!
//!   (a) keycodec encrypts (`writeEncryptedPrivateKeyPem`) and `openssl pkcs8 -topk8 -nocrypt
//!       -passin` decrypts: the DER OpenSSL prints equals the PKCS#8 that
//!       `openssl genpkey` wrote and keycodec's own `writePkcs8` of the parsed key;
//!   (b) `openssl pkcs8 -topk8 -v2 .. [-v2prf ..] [-iter ..] [-saltlen ..]` or
//!       `-scrypt ..` encrypts and keycodec reads it: `parseEncryptedInfo` names
//!       the cipher, KDF, parameters and salt length that were asked for, and
//!       `decryptPkcs8` / `parseEncryptedPrivateKeyPem` give back the original key;
//!   (c) a wrong password (one byte changed, appended or cut): keycodec's
//!       `parseEncryptedPkcs8` (decrypt, then parse — what `openssl pkcs8` does)
//!       answers `IncorrectPasswordOrCorrupt` on both files and `openssl` exits
//!       nonzero on keycodec's file. `decryptPkcs8` alone checks only the PKCS#7
//!       padding (CBC has no MAC), so a wrong password passes it about once in
//!       256 files — the salt and IV are fresh on every run, so which case that
//!       is changes from run to run; such a pass is counted (`padding
//!       coincidences`) and must not give back the key's bytes.
//!
//! The empty password is not in the cases: `openssl pkcs8 -passout pass:` takes
//! it as "no password" on some paths, so there is no unambiguous oracle for it
//! (keycodec's tests cover it, `pbes2_test.zig`).

const std = @import("std");
const kc = @import("keycodec");

const work_dir = ".zig-cache/interop-keycodec";
const n_cases = 80;
const seed = 0x6b63_5f6f_7373_6c31;

const KeyKind = struct {
    name: []const u8,
    genpkey: []const []const u8,
};

const kinds = [_]KeyKind{
    .{ .name = "ed25519", .genpkey = &.{ "-algorithm", "ED25519" } },
    .{ .name = "x25519", .genpkey = &.{ "-algorithm", "X25519" } },
    .{ .name = "ed448", .genpkey = &.{ "-algorithm", "ED448" } },
    .{ .name = "x448", .genpkey = &.{ "-algorithm", "X448" } },
    .{ .name = "p256", .genpkey = &.{ "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256" } },
    .{ .name = "p384", .genpkey = &.{ "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384" } },
    .{ .name = "p521", .genpkey = &.{ "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-521" } },
    .{ .name = "secp256k1", .genpkey = &.{ "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp256k1" } },
    .{ .name = "rsa2048", .genpkey = &.{ "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048" } },
    .{ .name = "ml-dsa-44", .genpkey = &.{ "-algorithm", "ML-DSA-44" } },
    .{ .name = "ml-kem-768", .genpkey = &.{ "-algorithm", "ML-KEM-768" } },
};

const prf_names = [_][]const u8{ "hmacWithSHA1", "hmacWithSHA224", "hmacWithSHA256", "hmacWithSHA384", "hmacWithSHA512" };
const cipher_names = [_][]const u8{ "aes-128-cbc", "aes-192-cbc", "aes-256-cbc" };

const Key = struct {
    name: []const u8,
    pem_path: []const u8,
    /// The PKCS#8 DER `openssl genpkey` wrote.
    plain_der: []const u8,
    /// keycodec's reading of it (the parts point into `der_buf`).
    parsed: kc.PrivateKey,
    der_buf: []u8,
};

const Ctx = struct {
    io: std.Io,
    arena: std.mem.Allocator,
    cwd: std.Io.Dir,
    abs: []const u8,
    version: []const u8,
    work: []u8,
    mismatches: usize = 0,
    n_a: usize = 0,
    n_b: usize = 0,
    n_c: usize = 0,
    n_pad_coincidence: usize = 0,
    n_scrypt: usize = 0,
};

fn run(c: *Ctx, argv: []const []const u8) !std.process.RunResult {
    return std.process.run(c.arena, c.io, .{ .argv = argv });
}

fn ok(res: std.process.RunResult) bool {
    return res.term == .exited and res.term.exited == 0;
}

fn hex(c: *Ctx, b: []const u8) []const u8 {
    return c.arena.print("{x}", .{b}) catch @panic("OOM");
}

/// Print and count a disagreement; only the first is printed in full.
fn disagree(c: *Ctx, comptime fmt: []const u8, args: anytype) void {
    c.mismatches += 1;
    if (c.mismatches == 1) std.debug.print("interop-keycodec: DISAGREEMENT\n  " ++ fmt ++ "\n", args);
}

/// (c) on one file (`der`, the EncryptedPrivateKeyInfo; `plain`, the key's PKCS#8): the
/// full read refuses the wrong password with the one documented error, and a
/// `decryptPkcs8` that passes on a lucky padding does not return the key.
fn checkWrongPassword(c: *Ctx, der: []const u8, pw: []const u8, wrong: []const u8, plain: []const u8, idx: usize, name: []const u8, desc: []const u8, which: []const u8) void {
    var dec: [kc.max_encrypted_der_len]u8 = undefined;
    if (kc.parseEncryptedPkcs8(der, wrong, &dec, .{ .scrypt_work = c.work })) |_| {
        disagree(c, "(c) case {d} {s} {s}: keycodec accepted a wrong password on {s} file\n  right: {s}\n  wrong: {s}", .{ idx, name, desc, which, hex(c, pw), hex(c, wrong) });
    } else |err| if (err != error.IncorrectPasswordOrCorrupt) {
        disagree(c, "(c) case {d} {s} {s}: keycodec answered {s} to a wrong password on {s} file", .{ idx, name, desc, @errorName(err), which });
    }
    if (kc.decryptPkcs8(der, wrong, &dec, .{ .scrypt_work = c.work })) |got| {
        c.n_pad_coincidence += 1;
        if (std.mem.eql(u8, got, plain)) disagree(c, "(c) case {d} {s} {s}: a wrong password decrypts {s} file to the key", .{ idx, name, desc, which });
    } else |err| if (err != error.IncorrectPasswordOrCorrupt) {
        disagree(c, "(c) case {d} {s} {s}: decryptPkcs8 answered {s} to a wrong password on {s} file", .{ idx, name, desc, @errorName(err), which });
    }
}

const Variant = struct {
    cipher: kc.pbes2.Cipher,
    kdf: kc.pbes2.Kdf,
    salt_len: u8,
};

fn describe(c: *Ctx, v: Variant) []const u8 {
    return switch (v.kdf) {
        .pbkdf2 => |k| c.arena.print("pbkdf2 prf={s} iter={d} {s} salt={d}", .{ @tagName(k.prf), k.iterations, @tagName(v.cipher), v.salt_len }) catch @panic("OOM"),
        .scrypt => |s| c.arena.print("scrypt N=2^{d} r={d} p={d} {s} salt={d}", .{ s.log2_n, s.r, s.p, @tagName(v.cipher), v.salt_len }) catch @panic("OOM"),
    };
}

fn randomVariant(r: std.Random) Variant {
    const cipher = r.enumValue(kc.pbes2.Cipher);
    const salt_len: u8 = 1 + r.uintLessThan(u8, 64);
    if (r.uintLessThan(u8, 3) == 0) {
        const rr = [_]u32{ 1, 2, 4, 8 };
        const res = rr[r.uintLessThan(usize, rr.len)];
        // N * r <= 2^17: OpenSSL's default maxmem (32 MiB) holds 128 * N * r.
        var max_log2: u6 = 14;
        while (@as(u64, res) << max_log2 > (1 << 17)) max_log2 -= 1;
        return .{
            .cipher = cipher,
            .kdf = .{ .scrypt = .{ .log2_n = @intCast(1 + r.uintLessThan(u8, max_log2)), .r = res, .p = 1 + r.uintLessThan(u32, 3) } },
            .salt_len = salt_len,
        };
    }
    const iterations: u64 = switch (r.uintLessThan(u8, 8)) {
        0 => 1,
        1 => 2,
        2 => 2048,
        3 => 1 + r.uintLessThan(u64, 100_000),
        else => 1 + r.uintLessThan(u64, 3000),
    };
    return .{
        .cipher = cipher,
        .kdf = .{ .pbkdf2 = .{ .prf = r.enumValue(kc.pbes2.Prf), .iterations = iterations } },
        .salt_len = salt_len,
    };
}

fn randomPassword(c: *Ctx, r: std.Random) []u8 {
    const n = 1 + r.uintLessThan(usize, 40);
    var out: std.ArrayList(u8) = .empty;
    while (out.items.len < n) {
        const roll = r.uintLessThan(u8, 20);
        if (roll == 0) {
            out.appendSlice(c.arena, "\xc3\xa9") catch @panic("OOM");
        } else if (roll == 1) {
            out.appendSlice(c.arena, "\xe2\x82\xac") catch @panic("OOM");
        } else if (roll == 2) {
            out.append(c.arena, 0x80 + r.uintLessThan(u8, 0x80)) catch @panic("OOM");
        } else if (roll == 3) {
            out.append(c.arena, ' ') catch @panic("OOM");
        } else {
            out.append(c.arena, 0x21 + r.uintLessThan(u8, 0x5e)) catch @panic("OOM");
        }
    }
    // No trailing blank: a password file's last line may be trimmed by the tool.
    if (out.items[out.items.len - 1] == ' ') out.items[out.items.len - 1] = 'x';
    return out.items;
}

fn wrongPassword(c: *Ctx, r: std.Random, pw: []const u8) []u8 {
    const w = c.arena.dupe(u8, pw) catch @panic("OOM");
    switch (r.uintLessThan(u8, 3)) {
        0 => {
            const i = r.uintLessThan(usize, w.len);
            w[i] = if (w[i] == 'a') 'b' else 'a';
            return w;
        },
        1 => return std.mem.concat(c.arena, u8, &.{ pw, "x" }) catch @panic("OOM"),
        else => {
            if (w.len > 1) return w[0 .. w.len - 1];
            w[0] = if (w[0] == 'a') 'b' else 'a';
            return w;
        },
    }
}

fn writeFile(c: *Ctx, path: []const u8, data: []const u8) !void {
    try c.cwd.writeFile(c.io, .{ .sub_path = path, .data = data });
}

fn genKey(c: *Ctx, kind: KeyKind) !?Key {
    const path = try c.arena.print("{s}/key-{s}.pem", .{ work_dir, kind.name });
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(c.arena, &.{ "openssl", "genpkey" });
    try argv.appendSlice(c.arena, kind.genpkey);
    try argv.appendSlice(c.arena, &.{ "-out", path });
    const res = try run(c, argv.items);
    if (!ok(res)) {
        std.debug.print("interop-keycodec: skipping {s}: this openssl cannot generate it ({s})\n", .{ kind.name, std.mem.trim(u8, res.stderr, " \n") });
        return null;
    }
    const text = try c.cwd.readFileAlloc(c.io, path, c.arena, .limited(1 << 20));
    const der_buf = try c.arena.alloc(u8, kc.max_private_der_len);
    const copy = try c.arena.alloc(u8, kc.max_private_der_len);
    const block = (kc.pem.find(text, "PRIVATE KEY") catch return error.BadGenpkeyOutput) orelse return error.BadGenpkeyOutput;
    const plain = try block.decode(copy);
    const parsed = kc.parsePrivateKeyPem(text, der_buf) catch |err| {
        std.debug.print("interop-keycodec: keycodec cannot read OpenSSL's own {s} key: {s}\n", .{ kind.name, @errorName(err) });
        return error.KeycodecRefusesOpensslKey;
    };
    return .{ .name = kind.name, .pem_path = path, .plain_der = plain, .parsed = parsed, .der_buf = der_buf };
}

fn passwordPath(c: *Ctx, tag: []const u8) ![]const u8 {
    return c.arena.print("{s}/pw-{s}", .{ work_dir, tag });
}

fn caseA(c: *Ctx, r: std.Random, key: Key, v: Variant, pw: []const u8, idx: usize) !void {
    const desc = describe(c, v);
    var pem_buf: [kc.max_encrypted_pem_len]u8 = undefined;
    const eo: kc.EncryptOptions = .{ .cipher = v.cipher, .kdf = v.kdf, .salt_len = v.salt_len, .scrypt_work = c.work };
    const text = kc.writeEncryptedPrivateKeyPem(&pem_buf, key.parsed, pw, r, eo) catch |err| {
        disagree(c, "(a) case {d} {s} {s}: keycodec refuses to encrypt: {s}", .{ idx, key.name, desc, @errorName(err) });
        return;
    };
    // keycodec's own plain encoding of the parsed key is OpenSSL's.
    var own: [kc.max_private_der_len]u8 = undefined;
    const own_der = try kc.writePkcs8(&own, key.parsed);
    if (!std.mem.eql(u8, own_der, key.plain_der)) {
        disagree(c, "(a) case {d} {s}: writePkcs8 differs from openssl genpkey's DER\n  openssl:  {s}\n  keycodec: {s}", .{ idx, key.name, hex(c, key.plain_der), hex(c, own_der) });
        return;
    }
    const enc_path = try c.arena.print("{s}/a-enc.pem", .{work_dir});
    const pw_path = try passwordPath(c, "a");
    try writeFile(c, enc_path, text);
    try writeFile(c, pw_path, pw);
    const pass_arg = try c.arena.print("file:{s}", .{pw_path});
    const res = try run(c, &.{ "openssl", "pkcs8", "-topk8", "-nocrypt", "-in", enc_path, "-passin", pass_arg, "-outform", "DER" });
    c.n_a += 1;
    if (!ok(res)) {
        disagree(c, "(a) case {d} {s} {s}: openssl refuses keycodec's file: {s}\n  password hex: {s}\n  file:\n{s}", .{ idx, key.name, desc, std.mem.trim(u8, res.stderr, " \n"), hex(c, pw), text });
        return;
    }
    if (!std.mem.eql(u8, res.stdout, key.plain_der)) {
        disagree(c, "(a) case {d} {s} {s}: openssl decrypts to different bytes\n  password hex: {s}\n  expected: {s}\n  openssl:  {s}", .{ idx, key.name, desc, hex(c, pw), hex(c, key.plain_der), hex(c, res.stdout) });
        return;
    }
    // (c) openssl refuses a wrong password on this file.
    const wrong = wrongPassword(c, r, pw);
    const wrong_path = try passwordPath(c, "wrong");
    try writeFile(c, wrong_path, wrong);
    const wrong_arg = try c.arena.print("file:{s}", .{wrong_path});
    const bad = try run(c, &.{ "openssl", "pkcs8", "-topk8", "-nocrypt", "-in", enc_path, "-passin", wrong_arg, "-outform", "DER" });
    c.n_c += 1;
    if (ok(bad) or bad.stdout.len != 0) {
        disagree(c, "(c) case {d} {s} {s}: openssl accepted a wrong password\n  right: {s}\n  wrong: {s}", .{ idx, key.name, desc, hex(c, pw), hex(c, wrong) });
        return;
    }
    // ... and so does keycodec, with the one documented error.
    var dec: [kc.max_encrypted_der_len]u8 = undefined;
    const block = (try kc.pem.find(text, "ENCRYPTED PRIVATE KEY")).?;
    var enc_der: [kc.max_encrypted_der_len]u8 = undefined;
    const der = try block.decode(&enc_der);
    checkWrongPassword(c, der, pw, wrong, key.plain_der, idx, key.name, desc, "its own");
    // Round trip through keycodec itself, as a control.
    const back = kc.decryptPkcs8(der, pw, &dec, .{ .scrypt_work = c.work }) catch |err| {
        disagree(c, "(a) case {d} {s} {s}: keycodec cannot read its own file: {s}", .{ idx, key.name, desc, @errorName(err) });
        return;
    };
    if (!std.mem.eql(u8, back, key.plain_der)) disagree(c, "(a) case {d} {s} {s}: keycodec's own round trip differs", .{ idx, key.name, desc });
}

fn caseB(c: *Ctx, r: std.Random, key: Key, v: Variant, pw: []const u8, idx: usize) !void {
    const desc = describe(c, v);
    const enc_path = try c.arena.print("{s}/b-enc.pem", .{work_dir});
    const pw_path = try passwordPath(c, "b");
    try writeFile(c, pw_path, pw);
    const pass_arg = try c.arena.print("file:{s}", .{pw_path});
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(c.arena, &.{ "openssl", "pkcs8", "-topk8", "-in", key.pem_path, "-out", enc_path, "-passout", pass_arg, "-v2", cipher_names[@backingInt(v.cipher)], "-saltlen" });
    try argv.append(c.arena, try c.arena.print("{d}", .{v.salt_len}));
    switch (v.kdf) {
        .pbkdf2 => |k| try argv.appendSlice(c.arena, &.{ "-v2prf", prf_names[@backingInt(k.prf)], "-iter", try c.arena.print("{d}", .{k.iterations}) }),
        .scrypt => |s| {
            c.n_scrypt += 1;
            try argv.appendSlice(c.arena, &.{
                "-scrypt",
                "-scrypt_N",
                try c.arena.print("{d}", .{@as(u64, 1) << s.log2_n}),
                "-scrypt_r",
                try c.arena.print("{d}", .{s.r}),
                "-scrypt_p",
                try c.arena.print("{d}", .{s.p}),
            });
        },
    }
    const res = try run(c, argv.items);
    if (!ok(res)) {
        // OpenSSL cannot write this variant: not keycodec's disagreement, but say so.
        std.debug.print("interop-keycodec: openssl could not write case {d} ({s}): {s}\n", .{ idx, desc, std.mem.trim(u8, res.stderr, " \n") });
        c.mismatches += 1;
        return;
    }
    c.n_b += 1;
    const text = try c.cwd.readFileAlloc(c.io, enc_path, c.arena, .limited(1 << 22));
    const block = (try kc.pem.find(text, "ENCRYPTED PRIVATE KEY")) orelse {
        disagree(c, "(b) case {d} {s} {s}: openssl wrote no ENCRYPTED PRIVATE KEY block", .{ idx, key.name, desc });
        return;
    };
    var enc_der: [kc.max_encrypted_der_len]u8 = undefined;
    const der = try block.decode(&enc_der);
    const info = kc.parseEncryptedInfo(der) catch |err| {
        disagree(c, "(b) case {d} {s} {s}: keycodec cannot parse openssl's file: {s}\n{s}", .{ idx, key.name, desc, @errorName(err), text });
        return;
    };
    const same_kdf = switch (v.kdf) {
        .pbkdf2 => |k| info.kdf == .pbkdf2 and info.kdf.pbkdf2.prf == k.prf and info.kdf.pbkdf2.iterations == k.iterations,
        .scrypt => |s| info.kdf == .scrypt and info.kdf.scrypt.log2_n == s.log2_n and info.kdf.scrypt.r == s.r and info.kdf.scrypt.p == s.p,
    };
    if (info.cipher != v.cipher or !same_kdf or info.salt.len != v.salt_len) {
        disagree(c, "(b) case {d} {s}: parameters read differ from the ones asked of openssl\n  asked: {s}\n  read:  {s} {s} salt={d}", .{
            idx,
            key.name,
            desc,
            @tagName(info.kdf),
            @tagName(info.cipher),
            info.salt.len,
        });
        return;
    }
    var dec: [kc.max_encrypted_der_len]u8 = undefined;
    const plain = kc.decryptPkcs8(der, pw, &dec, .{ .scrypt_work = c.work }) catch |err| {
        disagree(c, "(b) case {d} {s} {s}: keycodec cannot decrypt openssl's file: {s}\n  password hex: {s}\n{s}", .{ idx, key.name, desc, @errorName(err), hex(c, pw), text });
        return;
    };
    if (!std.mem.eql(u8, plain, key.plain_der)) {
        disagree(c, "(b) case {d} {s} {s}: keycodec decrypts to different bytes\n  expected: {s}\n  keycodec: {s}", .{ idx, key.name, desc, hex(c, key.plain_der), hex(c, plain) });
        return;
    }
    // The PEM entry point on the same file gives the same key.
    var pem_der: [kc.max_encrypted_der_len]u8 = undefined;
    const k2 = kc.parseEncryptedPrivateKeyPem(text, pw, &pem_der, .{ .scrypt_work = c.work }) catch |err| {
        disagree(c, "(b) case {d} {s} {s}: parseEncryptedPrivateKeyPem fails on openssl's file: {s}", .{ idx, key.name, desc, @errorName(err) });
        return;
    };
    if (k2.algorithm != key.parsed.algorithm or !std.mem.eql(u8, k2.secret, key.parsed.secret)) {
        disagree(c, "(b) case {d} {s} {s}: parseEncryptedPrivateKeyPem returns a different key", .{ idx, key.name, desc });
        return;
    }
    // (c) a wrong password on openssl's file.
    const wrong = wrongPassword(c, r, pw);
    c.n_c += 1;
    checkWrongPassword(c, der, pw, wrong, key.plain_der, idx, key.name, desc, "openssl's");
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);

    const ver_res = std.process.run(arena, io, .{ .argv = &.{ "openssl", "version" } }) catch {
        std.debug.print("interop-keycodec: `openssl` not found on PATH (OpenSSL 3.x needed)\n", .{});
        return 2;
    };
    const version = std.mem.trim(u8, ver_res.stdout, " \n");
    if (!ok(ver_res) or !std.mem.startsWith(u8, version, "OpenSSL 3.")) {
        std.debug.print("interop-keycodec: needs OpenSSL 3.x on PATH, found \"{s}\"\n", .{version});
        return 2;
    }
    std.debug.print("interop-keycodec: {s}\n", .{version});

    var c: Ctx = .{
        .io = io,
        .arena = arena,
        .cwd = cwd,
        .abs = abs,
        .version = version,
        // N * r <= 2^17 and p <= 3: 128 * N * r + 128 * p * r + slack < 18 MiB.
        .work = try arena.alloc(u8, 18 * 1024 * 1024),
    };

    var pool: std.ArrayList(Key) = .empty;
    for (kinds) |kind| if (try genKey(&c, kind)) |k| try pool.append(arena, k);
    if (pool.items.len == 0) {
        std.debug.print("interop-keycodec: no key could be generated\n", .{});
        return 2;
    }

    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    for (0..n_cases) |i| {
        const key = pool.items[r.uintLessThan(usize, pool.items.len)];
        const v = randomVariant(r);
        const pw = randomPassword(&c, r);
        try caseA(&c, r, key, v, pw, i);
        try caseB(&c, r, key, v, pw, i);
        if (c.mismatches != 0) break;
    }
    if (c.mismatches != 0) {
        std.debug.print("interop-keycodec: {d} disagreement(s) with {s}\n", .{ c.mismatches, version });
        return 1;
    }
    std.debug.print("interop-keycodec: OK {d} cases ({d} key kinds; keycodec->openssl {d}, openssl->keycodec {d} of which {d} scrypt, wrong-password {d}, padding coincidences {d}) agree with {s}\n", .{ n_cases, pool.items.len, c.n_a, c.n_b, c.n_scrypt, c.n_c, c.n_pad_coincidence, version });
    return 0;
}
