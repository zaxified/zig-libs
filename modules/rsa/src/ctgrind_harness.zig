// SPDX-License-Identifier: MIT
//! ctgrind harness for `rsa` — the instrument for `SPEC.md`'s "Threat model /
//! out of scope" sentence:
//!
//!   "Constant-time requirements on every secret-dependent operation
//!    (`rsadp`/`rsadpCrt`/`rsasp1`/CRT parameter handling — routes through
//!    `montint`/`Modulus.pow`, never a public-exponent path, and never
//!    branches on secret data)"
//!
//! Until this harness that sentence had no measurement behind it. Run it
//! through `../../../scripts/checks/ctgrind.sh rsa`; that script's header has the
//! exact commands.
//!
//! ## What is tainted, and what is deliberately NOT
//!
//! The private key: the CRT primes `p`/`q`, the CRT exponents `dp`/`dq`, the
//! CRT coefficient `qinv`, their precomputed Montgomery params `p_mont`/
//! `q_mont` (target `crt`, driving `rsadpCrt` — the fast default path every
//! real caller uses), or the non-CRT exponent `d` (target `noncrt`, driving
//! `rsadp`). The modulus `n`, its Montgomery params `n_mont`, and the public
//! exponent `e` stay untainted in both targets: they are public, derived from
//! `n` alone, and a harness that flags branches on them would be measuring
//! the wrong thing (the module's own SPEC calls out "never a public-exponent
//! path" as the thing that must stay clean).
//!
//! Only the private-key operations are driven — `rsaep`/`rsavp1` (the
//! public-key path: verification, encryption with `e`) are out of scope by
//! the same reasoning and are not reachable from this file's `Target` enum.
//! The ciphertext fed to both targets IS built with `rsaep` first, but that
//! call runs BEFORE any taint is applied — it is the attacker-chosen public
//! input, not part of the claim.
//!
//! ## The fixed key
//!
//! `p`/`q`/`e` below are the module's own 2048-bit OpenSSL KAT (`kat2048` in
//! `root.zig`'s test suite; not `pub`, so the literal bytes are duplicated
//! here rather than imported) — a committed, reproducible key rather than a
//! freshly generated one, so repeated runs of the table are comparable and no
//! run pays RSA keygen's cost. Sized so the CRT halves land on montint's
//! `L=16` slot (1024-bit primes -> 16 64-bit limbs), the portable CIOS path
//! `root.zig`'s own comment calls out as the common RSA-2048 case (`L=16 <
//! montint's asm_min_limbs=32`) — the textbook 61/53/17 key used elsewhere in
//! this module's tests would instead force the smallest slot (`L=4`) and
//! exercise a width no real RSA-2048 key ever uses.
//!
//! ## Why the pattern also names `montint`'s files
//!
//! `rsadpCrt`/`rsadp` bridge bytes into limbs in THIS module's `root.zig`,
//! but every operation on the secrets — the reduction of `c` mod p/q, both
//! ladders, the Garner recombination, the unblinding — runs inside the
//! sibling `montint` module (`dyn.zig`/`montint.zig`/`limbs.zig`/
//! `asm_core.zig`), the same "our own arithmetic, not std's" reasoning
//! `bolt8`'s harness applies to `k256`. `std.crypto.ff` is on the private
//! path only as the carrier of `dp`/`dq`/`qinv`, read limb by limb; until
//! 2026-10-02 its `reduce`/`mul` did the CRT recombination and were most of
//! this row's count. `ff.zig` stays in the pattern so a regression back onto
//! it is counted.
//!
//! ## The two traps (see `ct25519`'s harness or `scripts/checks/ctgrind.sh`'s header)
//!
//! 1. `std.valgrind.doClientRequest` compiles to nothing without `-fvalgrind`
//!    (off by default outside Debug) — the driver script builds both ways so
//!    this shows up as its own trap row, not a silent false clean.
//! 2. The optimizer could in principle keep a defined copy of a tainted field
//!    from before `makeMemUndefined` ran (this harness builds the whole
//!    `SecretKey` untainted first, then taints specific fields in place).
//!    `reloadVolatile` forces one real byte-by-byte load of the WHOLE struct
//!    through a volatile pointer immediately before the call under test, so
//!    the private op cannot be fed a pre-taint copy.
//!
//! ## The propagation proof
//!
//! After the call, the result is formatted through `std.debug.print`, which
//! is NOT constant-time by design (digit/hex formatting branches on the
//! value). Its contexts are reported separately (the WITNESS bucket) from
//! the target's own contexts, so a zero count inside `root.zig`/`montint`
//! means "no branch found", not "taint never arrived".

const std = @import("std");
const builtin = @import("builtin");
const rsa = @import("root.zig");

/// Duplicated from `root.zig`'s private `hexLit` — same shape, not `pub`
/// there so not importable.
fn hexLit(comptime hex: []const u8) [hex.len / 2]u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        var out: [hex.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
        return out;
    }
}

// The module's own committed 2048-bit OpenSSL KAT (`kat2048` in
// `root.zig`'s tests) — see the module doc comment above for why this key
// and not the textbook 61/53/17 one used elsewhere in the test suite.
const kat_e = [_]u8{ 0x01, 0x00, 0x01 }; // 65537
const kat_p = hexLit("cd91a6496cfb79576c073ddea09edc423deebdaa3b103017d00572ebb61b1a05b9e7340239fd8019790b76ec74233842f786d620f80362ca455e6c0b26859db9e5c50d71c551759ffd2ef2facc98c10d6c2e8e0662a5d25a0d847c4fc54a062fc4bb75c552ae1cdef197916cd81c4dd102f314a8a4eb8c73c5c6b3e85c40a11d");
const kat_q = hexLit("c9c4dbb594569066caaaadbf5be98990357e0ea3d3619601b2155bac8ed96b28d6eec9578163dd3b08e0132a0f91a99c98a139b3e7b016f7e83dfe6e18d97b4448dccab617a3ac3aa6aa1359c3f5396473f4b0b20038252ae1d77e8cdf1fce2a9f4ea3208269f79d516e7b9a22e2fe4b4dad87621173348f896e2303cae5b59f");
const kat_n = hexLit("a2056f805f21fbf8815681fc5f7bb07bb8c7cba3be6e10ef3c3905981d666aa60adde3a7ebd258efae4e0d120e109c42cde35c6c322287135644e25eb79640aa91bc69a63b96fc3a72d85641cf567f4d4775c70c11d3c319989e764bc94c68002eb159d8fb05b73cafe489fb33b99e8f58ada35d59577e657f5097bb0e7a3f53e74b3592dbb31772092b96ab5aac70cef3b2afb54d1a35da41e895222c898f0306f9cd9ecb5b4e3bee111dcd5bfc44b976e7620b0e01b3072d0d3f5e995dcf20aa78d6633ef658bc1468f311ac4e6e005b2cf37d18f82cdc661f7d8cbd93709a4c122dd732bd243632b4a9d51da2f1d3c677a54d0f36c8f8458165d2fefe9203");

const modulus_len = 256; // 2048 bits / 8

/// Force one real byte-by-byte load of `s` through a volatile pointer, so the
/// private op cannot be fed a copy of `T` that predates `makeMemUndefined` —
/// see trap 2 in the module doc comment above.
fn reloadVolatile(comptime T: type, s: *const T) T {
    var out: T = undefined;
    const src = std.mem.asBytes(s);
    const dst = std.mem.asBytes(&out);
    for (dst, src) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const Target = enum { crt, crtbl, crtcache, noncrt, keygen, oaepnf, pemenc, pemdec };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "crt")) return .crt;
    if (std.mem.eql(u8, s, "crtbl")) return .crtbl;
    if (std.mem.eql(u8, s, "crtcache")) return .crtcache;
    if (std.mem.eql(u8, s, "noncrt")) return .noncrt;
    if (std.mem.eql(u8, s, "keygen")) return .keygen;
    if (std.mem.eql(u8, s, "oaepnf")) return .oaepnf;
    if (std.mem.eql(u8, s, "pemenc")) return .pemenc;
    if (std.mem.eql(u8, s, "pemdec")) return .pemdec;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn taintBytes(t: Taint, bytes: []u8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

/// Taint a `montint.DynModint`'s value fields, but not its slot `L`: the
/// slot is the prime's limb count rounded up — the key size, public — and
/// every operation dispatches on it, so tainting it would report one
/// artifact context per call site rather than anything about the prime.
fn taintMont(t: Taint, mp: anytype) void {
    taintBytes(t, std.mem.asBytes(&mp.m));
    taintBytes(t, std.mem.asBytes(&mp.n0inv));
    taintBytes(t, std.mem.asBytes(&mp.r2));
    taintBytes(t, std.mem.asBytes(&mp.one_mont));
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const target = try parseTarget(target_arg);
    const taint = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={} target={s}\n", .{ builtin.valgrind_support, target_arg });

    // Target `keygen` (2026-10-03): `fromPrimes` itself on TAINTED p, q —
    // n, λ = lcm(p−1, q−1), d/dP/dQ (inverses modulo even secrets), qInv by
    // Fermat, all montint since that day. What it still branches on is the
    // documented residue (ff's `Modulus` carriers for p, q; the verdicts).
    if (target == .keygen) {
        var p = kat_p;
        var q = kat_q;
        taintBytes(taint, &p);
        taintBytes(taint, &q);
        const pr = reloadVolatile([kat_p.len]u8, &p);
        const qr = reloadVolatile([kat_q.len]u8, &q);
        var key: rsa.SecretKey = undefined;
        try rsa.SecretKey.fromPrimes(&key, &pr, &qr, &kat_e);
        defer key.deinit();
        var d_out: [modulus_len]u8 = undefined;
        try key.d.toBytes(&d_out, .big);
        std.debug.print("d={x}\n", .{d_out});
        return;
    }

    if (target == .pemenc) return pemEnc(taint);
    if (target == .pemdec) return pemDec(taint);

    // For `crt`/`noncrt`, key construction runs on the UNTAINTED fixed KAT
    // bytes — the per-operation path is what those targets measure; the
    // import itself is target `keygen`'s.
    var sk: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromPrimes(&sk, &kat_p, &kat_q, &kat_e);
    const pk = try rsa.PublicKey.fromBytes(&kat_n, &kat_e);

    // A fixed, public "attacker-chosen" ciphertext: encrypt a fixed message
    // representative (< n: top byte held at 0) with the PUBLIC key, before
    // any taint exists. This is RSAEP -- the public-key path -- and is
    // deliberately built outside the measured region.
    var m: [modulus_len]u8 = undefined;
    for (&m, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    m[0] = 0;
    const c = try rsa.rsaep(modulus_len, m, pk);

    // Taint exactly the fields the target's private op reads, and nothing
    // else -- see the module doc comment for why n/n_mont/e stay public in
    // both targets.
    switch (target) {
        .crt, .crtbl, .crtcache, .oaepnf => {
            taintBytes(taint, std.mem.asBytes(&sk.p));
            taintBytes(taint, std.mem.asBytes(&sk.q));
            taintBytes(taint, std.mem.asBytes(&sk.dp));
            taintBytes(taint, std.mem.asBytes(&sk.dq));
            taintBytes(taint, std.mem.asBytes(&sk.qinv));
            // p_mont/q_mont are separate memory from p/q (precomputed at key
            // construction), carrying the same secret value plus its
            // Montgomery constants -- the private op reads THESE as the
            // moduli, so leaving them untainted would let it consume the
            // secret primes through a channel the taint never reached.
            taintMont(taint, &sk.p_mont);
            taintMont(taint, &sk.q_mont);
        },
        .noncrt => {
            taintBytes(taint, std.mem.asBytes(&sk.d));
        },
        .keygen, .pemenc, .pemdec => unreachable, // returned above
    }

    const sk_reloaded = reloadVolatile(rsa.SecretKey, &sk);

    // `crtbl`/`crtcache` (2026-10-18): the same CRT op with base blinding
    // on, `.csprng` (a fresh pair drawn and inverted) and `.cached` (two
    // ops on one cache: the first draws the pair, the second squares it).
    // The generator is a fixed-seed ChaCha: `r` is random, not secret input
    // to the claim, and its rejection against the PUBLIC n is a branch on
    // it by design; everything mod p, q is covered by the key taint.
    var chacha = std.Random.ChaCha.init(@splat(0x42));
    var out: [modulus_len]u8 = undefined;
    switch (target) {
        .crt => out = try rsa.rsadpCrt(modulus_len, c, &sk_reloaded),
        .crtbl => out = try rsa.rsadpCrtBlinded(modulus_len, c, &sk_reloaded, .{ .csprng = chacha.random() }),
        .crtcache => {
            var cache = rsa.BlindingCache.init(chacha.random());
            defer cache.deinit();
            out = try rsa.rsadpCrtBlinded(modulus_len, c, &sk_reloaded, .{ .cached = &cache });
            out = try rsa.rsadpCrtBlinded(modulus_len, c, &sk_reloaded, .{ .cached = &cache });
        },
        .noncrt => out = try rsa.rsadp(modulus_len, c, &sk_reloaded),
        .oaepnf => {
            // `decryptOaepHNoFail` (2026-11-13): the whole OAEP unwrap, CRT op
            // plus the branch-free unpadding, on a real OAEP ciphertext of a
            // 32-byte message (built with the PUBLIC key before any taint
            // matters). `ok` is returned as data and is NOT branched on here;
            // only the witness print below touches it.
            var drbg = std.Random.ChaCha.init(@splat(0x24));
            var cbuf: [modulus_len]u8 = undefined;
            const cek: [32]u8 = @splat(0x5a);
            const oct = try rsa.encryptOaep(pk, std.crypto.hash.sha2.Sha256, drbg.random(), &cek, "", &cbuf);
            var msg_out: [32]u8 = undefined;
            var raw_out: [modulus_len]u8 = undefined;
            const r = try rsa.decryptOaepHNoFail(&sk_reloaded, std.crypto.hash.sha2.Sha256, std.crypto.hash.sha2.Sha256, .none, oct, "", 32, &msg_out, &raw_out);
            std.debug.print("ok={} msg={x}\n", .{ r.ok, r.msg });
            out = raw_out;
        },
        .keygen, .pemenc, .pemdec => unreachable,
    }

    // Propagation proof: format the (tainted, if taint=yes) result through a
    // non-constant-time path. See the module doc comment above.
    std.debug.print("m={x}\n", .{out});
}

// ── targets `pemenc` / `pemdec` (2026-11-17) ───────────────────────────────
//
// Private-key PEM, split in two rows so that each counts only its own code.
// What DER publishes about a secret INTEGER — its length and its 0x00 sign
// pad — is public by format; neither row taints it.

/// `pemenc`: `SecretKey.toPem(.pkcs1)` of a key whose secret members (`d`,
/// `dP`, `dQ`, `qInv`, the primes and their Montgomery params) are tainted:
/// the DER writer (`marshal.zig`, whose INTEGER trim declassifies only the
/// length and the pad bit) and the constant-time base64 encoder (`b64ct`).
fn pemEnc(taint: Taint) !void {
    var sk0: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromPrimes(&sk0, &kat_p, &kat_q, &kat_e);
    defer sk0.deinit();
    taintBytes(taint, std.mem.asBytes(&sk0.d));
    taintBytes(taint, std.mem.asBytes(&sk0.dp));
    taintBytes(taint, std.mem.asBytes(&sk0.dq));
    taintBytes(taint, std.mem.asBytes(&sk0.qinv));
    taintMont(taint, &sk0.p_mont);
    taintMont(taint, &sk0.q_mont);
    const skr = reloadVolatile(rsa.SecretKey, &sk0);
    var buf: [rsa.max_private_pem_len]u8 = undefined;
    const text = try skr.toPem(.pkcs1, &buf);
    // The witness and the output pin: SHA-256 (constant-time) of the text.
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(text, &h, .{});
    std.debug.print("ctgrind_result={x}\n", .{h});
}

/// `pemdec`: `SecretKey.fromPem` of the PEM text of an UNTAINTED key in
/// which exactly the base64 characters whose six bits all come from the
/// CONTENT bytes of `d`, `dP`, `dQ`, `qInv` are tainted (tags, lengths, the
/// armor and line breaks stay defined): the constant-time base64 decoder,
/// the DER walk, and `checkWireFields`' comparison and adoption of the wire
/// `d`. `p` and `q` stay untainted on purpose: `fromPem` re-derives the key
/// from them through `fromPrimes`, which is target `keygen`'s claim and
/// residue — tainting them here would count that row a second time.
fn pemDec(taint: Taint) !void {
    var sk0: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromPrimes(&sk0, &kat_p, &kat_q, &kat_e);
    defer sk0.deinit();
    var buf: [rsa.max_private_pem_len]u8 = undefined;
    const text = try sk0.toPem(.pkcs1, &buf);

    // Locate the body (between the BEGIN line and the END line) and decode
    // it here, untainted, to find the INTEGER content ranges.
    const body_start = (std.mem.indexOfScalar(u8, text, '\n') orelse return error.BadPem) + 1;
    const body_end = std.mem.indexOf(u8, text, "-----END") orelse return error.BadPem;
    var b64: [rsa.max_private_pem_len]u8 = undefined;
    var nb: usize = 0;
    for (text[body_start..body_end]) |c| {
        if (c == '\n') continue;
        b64[nb] = c;
        nb += 1;
    }
    var der: [rsa.max_private_pem_len]u8 = undefined;
    const dlen = try std.base64.standard.Decoder.calcSizeForSlice(b64[0..nb]);
    try std.base64.standard.Decoder.decode(der[0..dlen], b64[0..nb]);

    // SEQUENCE { version, n, e, d, p, q, dP, dQ, qInv }: secret = 3, 6, 7, 8.
    var secret: [9]struct { start: usize, end: usize } = undefined;
    var at: usize = derHeaderLen(der[0..dlen], 0);
    for (&secret) |*r| {
        const hl = derHeaderLen(der[0..dlen], at);
        const cl = derContentLen(der[0..dlen], at);
        r.* = .{ .start = at + hl, .end = at + hl + cl };
        at += hl + cl;
    }
    if (at != dlen) return error.BadDer;
    const secret_fields = [_]usize{ 3, 6, 7, 8 };

    // Taint each body character whose bits all fall in secret content.
    var k: usize = 0;
    for (text[body_start..body_end], body_start..) |c, pos| {
        if (c == '\n') continue;
        defer k += 1;
        if (c == '=') continue;
        const first = (6 * k) / 8;
        const last = (6 * k + 5) / 8;
        var all = true;
        for ([_]usize{ first, last }) |byte_at| {
            var in = false;
            for (secret_fields) |f| {
                if (byte_at >= secret[f].start and byte_at < secret[f].end) in = true;
            }
            all = all and in;
        }
        if (all) taintBytes(taint, buf[pos..][0..1]);
    }

    var back: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromPem(&back, text);
    defer back.deinit();
    var d_out: [modulus_len]u8 = undefined;
    try back.d.toBytes(&d_out, .big);
    std.debug.print("d={x}\n", .{d_out});
}

/// Header length of the (definite, short- or long-form) DER element at `at`.
fn derHeaderLen(der: []const u8, at: usize) usize {
    const l = der[at + 1];
    return if (l < 0x80) 2 else 2 + (l & 0x7f);
}

/// Content length of the DER element at `at`.
fn derContentLen(der: []const u8, at: usize) usize {
    const l = der[at + 1];
    if (l < 0x80) return l;
    var v: usize = 0;
    for (der[at + 2 ..][0 .. l & 0x7f]) |b| v = (v << 8) | b;
    return v;
}
