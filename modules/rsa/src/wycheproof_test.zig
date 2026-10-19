// SPDX-License-Identifier: MIT

//! Wycheproof RSA vectors (Apache-2.0 test data, see ../NOTICE): PKCS#1 v1.5
//! verify, RSASSA-PSS verify, RSAES-OAEP decrypt. The data files are generated
//! by `tools/wycheproof.py` (format described there) and parsed here at run
//! time. Every vector runs; the first mismatch fails with family + tcId.
//!
//! Deliberate readings of Wycheproof's "acceptable" results:
//!  * `MissingNull` (PKCS#1 v1.5 DigestInfo without the NULL parameters):
//!    REJECTED -- verify re-derives the full EMSA encoding and compares bytes.
//!  * `SmallIntegerCiphertext` (OAEP, ciphertext integer far below n):
//!    ACCEPTED -- RFC 8017 §7.1.2 only requires 0 <= c < n and len == k.

const std = @import("std");
const rsa = @import("root.zig");
const hash = std.crypto.hash;

const files = struct {
    const pkcs1v15 = @embedFile("testdata/wycheproof_pkcs1v15.txt");
    const pss = @embedFile("testdata/wycheproof_pss.txt");
    const oaep = @embedFile("testdata/wycheproof_oaep.txt");
};

const Family = enum { pkcs1v15, pss, oaep };

fn fail(fam: Family, tc: []const u8, comptime fmt: []const u8, args: anytype) error{WycheproofMismatch} {
    std.debug.print("wycheproof rsa {s} tcId={s}: " ++ fmt ++ "\n", .{ @tagName(fam), tc } ++ args);
    return error.WycheproofMismatch;
}

fn unhex(a: std.mem.Allocator, s: []const u8) ![]u8 {
    if (std.mem.eql(u8, s, "-")) return a.alloc(u8, 0);
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

const Group = struct {
    sha: []const u8,
    mgf: []const u8,
    slen: usize,
    key: []u8,
};

const Counts = struct { tests: usize = 0, valid: usize = 0, invalid: usize = 0, acceptable: usize = 0 };

fn run(comptime fam: Family, text: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var g: ?Group = null;
    var c: Counts = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = f.next().?;
        if (std.mem.eql(u8, kind, "G")) {
            _ = f.next().?; // source file
            const sha = f.next().?;
            const mgf = f.next().?;
            const slen = try std.fmt.parseInt(usize, f.next().?, 10);
            g = .{ .sha = sha, .mgf = mgf, .slen = slen, .key = try unhex(a, f.next().?) };
            continue;
        }
        std.debug.assert(std.mem.eql(u8, kind, "T"));
        const tc = f.next().?;
        const result = f.next().?;
        const flags = f.next().?;
        const msg = try unhex(a, f.next().?);
        const second = try unhex(a, f.next().?); // sig or ct
        const label = if (fam == .oaep) try unhex(a, f.next().?) else &[_]u8{};
        const grp = g.?;
        c.tests += 1;
        const want: enum { accept, reject } = blk: {
            if (std.mem.eql(u8, result, "valid")) {
                c.valid += 1;
                break :blk .accept;
            } else if (std.mem.eql(u8, result, "invalid")) {
                c.invalid += 1;
                break :blk .reject;
            }
            c.acceptable += 1;
            if (fam == .pkcs1v15 and std.mem.eql(u8, flags, "MissingNull")) break :blk .reject;
            if (fam == .oaep and std.mem.find(u8, flags, "SmallIntegerCiphertext") != null) break :blk .accept;
            return fail(fam, tc, "unmapped acceptable flags {s}", .{flags});
        };
        const got_ok = switch (fam) {
            .pkcs1v15, .pss => try verifyOne(fam, tc, grp, msg, second),
            .oaep => try decryptOne(tc, grp, msg, second, label),
        };
        if (got_ok != (want == .accept)) {
            return fail(fam, tc, "expected {s}, got {s} (result={s} flags={s} sha={s} mgf={s} slen={d})", .{
                @tagName(want), if (got_ok) "accept" else "reject", result, flags, grp.sha, grp.mgf, grp.slen,
            });
        }
    }
    // Silent on success: the lane treats stderr from a passing test as a
    // failure. A vector file that parsed to nothing must not pass, though.
    try std.testing.expect(c.tests != 0 and c.valid != 0 and c.invalid != 0);
}

const Hashes = .{
    .{ "sha1", hash.Sha1 },
    .{ "sha224", hash.sha2.Sha224 },
    .{ "sha256", hash.sha2.Sha256 },
    .{ "sha384", hash.sha2.Sha384 },
    .{ "sha512", hash.sha2.Sha512 },
};

/// Verifies through both `PublicKey` and `VerifyKey` and requires them to agree.
fn verifyOne(comptime fam: Family, tc: []const u8, grp: Group, msg: []const u8, sig: []const u8) !bool {
    const pk = rsa.PublicKey.fromDer(grp.key) catch return fail(fam, tc, "PublicKey.fromDer rejected the group key", .{});
    const vk = rsa.VerifyKey.fromDer(grp.key) catch return fail(fam, tc, "VerifyKey.fromDer rejected the group key", .{});
    inline for (Hashes) |h| {
        if (std.mem.eql(u8, grp.sha, h[0])) {
            const a = switch (fam) {
                .pkcs1v15 => if (rsa.verifyPkcs1v15(pk, h[1], msg, sig)) true else |_| false,
                else => if (rsa.verifyPss(pk, h[1], msg, sig, grp.slen)) true else |_| false,
            };
            const b = switch (fam) {
                .pkcs1v15 => if (vk.verifyPkcs1v15(h[1], msg, sig)) true else |_| false,
                else => if (vk.verifyPss(h[1], msg, sig, grp.slen)) true else |_| false,
            };
            if (a != b) return fail(fam, tc, "PublicKey ({}) and VerifyKey ({}) disagree", .{ a, b });
            return a;
        }
    }
    unreachable;
}

fn decryptOne(tc: []const u8, grp: Group, msg: []const u8, ct: []const u8, label: []const u8) !bool {
    var sk: rsa.SecretKey = undefined;
    rsa.fromPkcs8(&sk, grp.key) catch |e| return fail(.oaep, tc, "fromPkcs8 rejected the group key: {s}", .{@errorName(e)});
    var out: [rsa.max_modulus_len]u8 = undefined;
    inline for (Hashes) |lh| {
        inline for (Hashes) |mh| {
            if (std.mem.eql(u8, grp.sha, lh[0]) and std.mem.eql(u8, grp.mgf, mh[0])) {
                const pt = rsa.decryptOaepH(&sk, lh[1], mh[1], ct, label, &out) catch return false;
                if (!std.mem.eql(u8, pt, msg)) return fail(.oaep, tc, "decrypted to a different plaintext", .{});
                return true;
            }
        }
    }
    unreachable;
}

test "wycheproof rsa PKCS#1 v1.5 verify" {
    try run(.pkcs1v15, files.pkcs1v15);
}

test "wycheproof rsa PSS verify" {
    try run(.pss, files.pss);
}

test "wycheproof rsa OAEP decrypt" {
    try run(.oaep, files.oaep);
}
