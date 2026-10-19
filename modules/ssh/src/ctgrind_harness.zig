// SPDX-License-Identifier: MIT
//! ctgrind harness for `ssh` — the classic MODP Diffie-Hellman exponent
//! (`transport.dhPowModPrime`, `diffie-hellman-group14-sha256` /
//! `group16-sha512`).
//!
//! Usage: ctgrind-ssh <target> <yes|no>
//!   targets: dh | ffpow | ecdh | gex | pem | pemstd
//!
//! * `dh` — taints the DH secret `x` and computes `e = g^x` and `K = f^x` in
//!   both groups through `dhPowModPrime` (montint `powMont`). Until
//!   2026-10-02 that function used `std.crypto.ff`'s `powWithEncodedExponent`,
//!   whose window select LLVM compiles to a conditional jump in ReleaseFast
//!   (found by threshold_ecdsa's `fac` target, objdump-confirmed).
//! * `ffpow` — the POSITIVE CONTROL: the same `K = f^x` through ff's pow, the
//!   code `dh` replaced. Its row must stay non-zero in `ff.zig`; if it ever
//!   reads zero, either std fixed its pow or this instrument stopped seeing
//!   the leak, and the `dh` zero means nothing until it is understood.
//! * `ecdh` — `ecdh-sha2-nistp256` / `-nistp384` (2026-10-10): taints the
//!   ephemeral scalar and runs our key-pair construction (`fromScalar`), the
//!   shared secret against a peer point (`ecdhNistShared`, std's `mul`) and
//!   `K`'s encoding plus the exchange hash (`ecdhNistFinish`).
//! * `gex` — `diffie-hellman-group-exchange-sha256` client (2026-10-10): the
//!   exponent `x` through `gexPow` on montint's run-time modulus (`DynModint`,
//!   the server-chosen prime), for the group14 and group16 primes.
//! * `pem` — `HostKey.fromOpenSSH` on the ed25519 fixture (2026-10-18) with
//!   the base64 characters that carry only bits of the 32-byte secret seed
//!   tainted (the edge characters it shares with the length before it and the
//!   public-key copy after it are not): the PEM decoder's END search and
//!   `b64ct` decode, then the container parse and the public-key
//!   re-derivation (std re-derives only under runtime safety, so not in the
//!   ReleaseFast build measured here). Witness: the loaded seed.
//! * `pemstd` — the POSITIVE CONTROL for `pem`: the same tainted text through
//!   the decoder `pemDecodeOpensshBlock` used until 2026-10-18
//!   (`std.mem.findPos` = Boyer-Moore-Horspool for the END line,
//!   `std.base64.standard.Decoder`; its whitespace branch is left out, see
//!   `pem`). Its row must stay non-zero in the `std.mem` and `std.base64` sources.
//!
//! `K` is printed as `ctgrind_result=` (the witness and the output pin). The
//! one in-file context `dh` keeps is `stripLeadingZeros` on `K`: an SSH mpint
//! drops leading zero bytes by definition (RFC 4251 §5), so `K`'s length
//! reaches the exchange hash whatever this module does — the protocol's
//! property, not an implementation branch.
//!
//! ReleaseFast only, as every harness here (safety checks flood the report;
//! Debug's self-hosted DWARF is unreadable to valgrind).

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const transport = root.transport;

const Taint = enum { yes, no };

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

const groups = [_][]const u8{ "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512" };

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = it.next() orelse return error.MissingTarget;
    const t = try parseTaint(it.next() orelse return error.MissingTaint);
    std.debug.print("valgrind_support={} target={s}\n", .{ builtin.valgrind_support, target });

    var prng = std.Random.DefaultPrng.init(0x7373_685f_6468); // "ssh_dh"
    const random = prng.random();

    if (std.mem.eql(u8, target, "ecdh")) {
        inline for (.{ transport.EcdhNist.p256, transport.EcdhNist.p384, transport.EcdhNist.p521 }) |c| try ecdh(c, random, t);
        return;
    }

    if (std.mem.eql(u8, target, "pem") or std.mem.eql(u8, target, "pemstd")) {
        return pem(std.mem.eql(u8, target, "pemstd"), t);
    }

    if (std.mem.eql(u8, target, "gex")) {
        for (groups) |name| try gex(name, random, t);
        return;
    }

    for (groups) |name| {
        const prime = (transport.DhGroup.forName(name) orelse return error.UnknownGroup).prime;
        // The peer's public value f = g^y for a public y, computed untainted.
        var y: [transport.dh_max_prime_len]u8 = undefined;
        random.bytes(y[0..prime.len]);
        y[0] &= 0x7f;
        var fbuf: [transport.dh_max_prime_len]u8 = undefined;
        const f = try transport.dhPowModPrime(prime, &[_]u8{2}, y[0..prime.len], &fbuf);

        var x: [transport.dh_max_prime_len]u8 = undefined;
        const xb = x[0..prime.len];
        random.bytes(xb);
        xb[0] &= 0x7f;
        xb[xb.len - 1] |= 1;
        if (t == .yes) std.valgrind.memcheck.makeMemUndefined(xb);

        var kbuf: [transport.dh_max_prime_len]u8 = undefined;
        if (std.mem.eql(u8, target, "dh")) {
            var ebuf: [transport.dh_max_prime_len]u8 = undefined;
            const e = try transport.dhPowModPrime(prime, &[_]u8{2}, xb, &ebuf);
            const k = try transport.dhPowModPrime(prime, f, xb, &kbuf);
            std.debug.print("e_len={d} ctgrind_result={x}\n", .{ e.len, k });
        } else if (std.mem.eql(u8, target, "ffpow")) {
            const Ff = std.crypto.ff.Modulus(4096);
            const m = try Ff.fromBytes(prime, .big);
            const k = try m.powWithEncodedExponent(try Ff.Fe.fromBytes(m, f, .big), xb, .big);
            var full: [512]u8 = undefined;
            try k.toBytes(&full, .big);
            std.debug.print("ctgrind_result={x}\n", .{full[512 - prime.len ..]});
        } else return error.UnknownTarget;
    }
}

fn ecdh(comptime c: transport.EcdhNist, random: std.Random, t: Taint) !void {
    const Kp = transport.EcdhNistKeyPair(c);
    // The peer's point, from a public scalar, untainted.
    const peer = while (true) {
        var y: [c.len()]u8 = undefined;
        random.bytes(&y);
        y[0] &= c.topMask();
        if (Kp.fromScalar(y)) |kp| break kp.public;
    };
    var x: [c.len()]u8 = undefined;
    while (true) {
        random.bytes(&x);
        x[0] &= c.topMask();
        if (Kp.fromScalar(x) != null) break;
    }
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(&x);
    const kp = Kp.fromScalar(x) orelse return error.Rejected;
    const shared = try transport.ecdhNistShared(c, &kp.secret, &peer);
    var res: transport.KexResult = .{};
    try transport.ecdhNistFinish(c, &res, &shared, "SSH-2.0-a", "SSH-2.0-b", "ic", "is", "ks", &kp.public, &peer);
    std.debug.print("ctgrind_result={x}\n", .{res.hash()});
}

fn gex(name: []const u8, random: std.Random, t: Taint) !void {
    const prime = (transport.DhGroup.forName(name) orelse return error.UnknownGroup).prime;
    const m = try transport.GexMod.fromBytesBE(prime);
    var y: [transport.dh_max_prime_len]u8 = undefined;
    random.bytes(y[0 .. prime.len - 1]);
    var fbuf: [transport.gex_max_prime_len]u8 = undefined;
    const f = try transport.gexPow(&m, &[_]u8{2}, y[0 .. prime.len - 1], &fbuf);
    var x: [transport.dh_max_prime_len]u8 = undefined;
    const xb = x[0 .. prime.len - 1];
    random.bytes(xb);
    xb[xb.len - 1] |= 1;
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(xb);
    var ebuf: [transport.gex_max_prime_len]u8 = undefined;
    const e = try transport.gexPow(&m, &[_]u8{2}, xb, &ebuf);
    var kbuf: [transport.gex_max_prime_len]u8 = undefined;
    const k = try transport.gexPow(&m, f, xb, &kbuf);
    std.debug.print("e_len={d} ctgrind_result={x}\n", .{ e.len, k });
}

const pem_begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
const pem_end = "-----END OPENSSH PRIVATE KEY-----";

fn isPemSpace(c: u8) bool {
    return c == '\r' or c == '\n' or c == ' ' or c == '\t';
}

fn pem(control: bool, t: Taint) !void {
    const fixture = @import("hostkey_vectors.zig").ed25519_key;
    var text_buf: [fixture.len]u8 = fixture.*;
    const text: []u8 = &text_buf;

    // Locate the seed untainted: the private key string is seed || public
    // key, the last of the public key's three copies in the container.
    var hk: root.server.HostKey = undefined;
    try root.server.HostKey.fromOpenSSH(&hk, text, null);
    const public = hk.ed25519.public_key.toBytes();
    const body_start = (std.mem.find(u8, text, pem_begin) orelse return error.NoPem) + pem_begin.len;
    const body_end = std.mem.findPos(u8, text, body_start, pem_end) orelse return error.NoPem;
    var b64: [4096]u8 = undefined;
    var n: usize = 0;
    for (text[body_start..body_end]) |c| {
        if (isPemSpace(c)) continue;
        b64[n] = c;
        n += 1;
    }
    var bin: [3072]u8 = undefined;
    const bin_len = try std.base64.standard.Decoder.calcSizeForSlice(b64[0..n]);
    try std.base64.standard.Decoder.decode(bin[0..bin_len], b64[0..n]);
    const seed_off = (std.mem.findLast(u8, bin[0..bin_len], &public) orelse return error.NoSeed) - 32;

    // Base64 characters [first, last) carry ONLY the seed's bits. The (at
    // most two) edge characters that share bits with the private string's
    // length and the public-key copy stay untainted: tainting them taints that
    // length, and every layout decision after it reads as a finding (measured
    // 2026-10-18: 11 contexts, all string/padding bounds on the 0x40 length).
    const first = (seed_off * 8 + 5) / 6;
    const last = (seed_off + 32) * 8 / 6;
    if (t == .yes) {
        var k: usize = 0;
        for (text[body_start..body_end]) |*c| {
            if (isPemSpace(c.*)) continue;
            if (k >= first and k < last) std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(c));
            k += 1;
        }
    }

    if (!control) {
        var out: root.server.HostKey = undefined;
        try root.server.HostKey.fromOpenSSH(&out, text, null);
        std.debug.print("seed_chars={d} ctgrind_result={x}\n", .{ last - first, out.ed25519.secret_key.seed() });
        return;
    }
    // The pre-2026-10-18 decoder: the BMH END search over the tainted text,
    // then std's table decoder over the stripped copy (stripped from the
    // untainted text above, then tainted the same way). Its per-character
    // whitespace branch is not reproduced: whether a key character is
    // whitespace is public by the alphabet, and the branch would land in this
    // file, which no pattern may name.
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(b64[first..last]);
    const ei = std.mem.findPos(u8, text, body_start, pem_end) orelse return error.NoPem;
    if (ei != body_end) return error.NoPem;
    var out2: [3072]u8 = undefined;
    const dec = std.base64.standard.Decoder;
    const dlen = try dec.calcSizeForSlice(b64[0..n]);
    try dec.decode(out2[0..dlen], b64[0..n]);
    std.debug.print("seed_chars={d} ctgrind_result={x}\n", .{ last - first, out2[seed_off..][0..32] });
}
