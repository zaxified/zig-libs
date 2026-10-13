// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh tlsresume`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-tlsresume`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `stek` — the ticket-encryption key (STEK) and the sealed session state
//!    (resumption master secret inside it) tainted through `StekRing.seal`,
//!    `open` of the blob, and `open` of a copy with one ciphertext byte
//!    flipped (rejected on the AES-256-GCM tag, std's verdict). Key id, nonce
//!    and the sealed blob are public; the blob is marked defined before the
//!    tampered copy is made.
//!  * `psk` — the resumption master secret tainted through `derivePsk`,
//!    `earlySecret`, `binderKey`, `computeBinder` and `verifyBinder` (accepting
//!    a good binder, rejecting a flipped one). SHA-256 and SHA-384 suites.
//!    Transcript hashes and ticket nonce are public.
//!  * `early` — the PSK tainted through the 0-RTT key schedule:
//!    `clientEarlyTrafficSecret`, `earlyExporterMasterSecret`,
//!    `earlyTrafficKeyIv` (16- and 32-byte keys) and `EarlyDataContext.derive`.
//!
//! ## Why `select.selectPsk` is not a target
//!
//! It was measured (2026-10-13) with the STEK tainted and a ticket sealed
//! under it: 47 contexts, 43 in the module's files, none a secret-handling
//! finding. Tainting the STEK makes the whole unsealed plaintext undefined,
//! including the fields that are not secret (nonce length byte,
//! `issued_at_ms`, `ticket_age_add`) which the server branches on by design
//! (parse bounds, freshness window), and the undefined nonce length then
//! reaches `hkdfExpandLabel`'s label buffer, so every sha2/memcpy length
//! decision downstream reads as secret-dependent. Such a row would pin std's
//! internals and the tainting artefact, not the module. What `selectPsk` adds
//! over its parts is covered above: the unseal (`stek`), the PSK/binder chain
//! and the constant-time binder compare (`psk`); the rest (parse, freshness,
//! the binder verdict, the strike register) runs on STEK-authenticated
//! metadata and on the public verdict.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const tr = @import("root.zig");

const Target = enum { stek, psk, early };
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(label, &full, .{});
    return full[0..n].*;
}

fn publicBytes(comptime n: usize, label: []const u8) [n]u8 {
    return secretBytes(n, label);
}

fn show(bytes: []const u8) void {
    std.debug.print("ctgrind_result={x}\n", .{bytes});
}

fn runStek(t: Taint) !void {
    var key = secretBytes(tr.stek.key_length, "ctgrind-tlsresume-stek-v1");
    var state = secretBytes(64, "ctgrind-tlsresume-state-v1");
    if (t == .yes) {
        std.valgrind.memcheck.makeMemUndefined(&key);
        std.valgrind.memcheck.makeMemUndefined(&state);
    }
    var ring = tr.stek.DefaultRing.init();
    ring.rotate(7, &key, 1000);

    const nonce = publicBytes(tr.stek.nonce_length, "ctgrind-tlsresume-nonce-v1");
    var blob_buf: [64 + tr.stek.overhead]u8 = undefined;
    const blob = try ring.seal(&state, nonce, &blob_buf);
    show(blob);
    std.valgrind.memcheck.makeMemDefined(blob);

    var back: [64]u8 = undefined;
    const got = try ring.open(blob, &back);
    show(got);

    var bad = blob_buf;
    bad[20] ^= 0x01;
    const rejected = if (ring.open(&bad, &back)) |_| false else |_| true;
    show(&[1]u8{@intFromBool(rejected)});
}

fn runPsk(comptime Hkdf: type, comptime Hmac: type, t: Taint) void {
    const L = Hkdf.prk_length;
    var rms = secretBytes(L, "ctgrind-tlsresume-rms-v1");
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(&rms);
    const nonce = [_]u8{ 0, 0 };
    const empty_hash = publicBytes(L, "ctgrind-tlsresume-empty-hash-v1");
    const ch_hash = publicBytes(L, "ctgrind-tlsresume-trunc-ch-v1");

    var p: [L]u8 = undefined;
    tr.psk.derivePsk(Hkdf, L, &p, &rms, &nonce);
    show(&p);
    var es: [L]u8 = undefined;
    tr.psk.earlySecret(Hkdf, &es, &p);
    show(&es);
    var bk: [L]u8 = undefined;
    tr.psk.binderKey(Hkdf, &bk, &es, &empty_hash);
    show(&bk);
    var binder: [Hmac.mac_length]u8 = undefined;
    tr.psk.computeBinder(Hkdf, Hmac, &binder, &bk, &ch_hash);
    show(&binder);

    // The offered binder is what the client sent: public wire bytes. Take a
    // copy of the (tainted) computed one and declare the copy defined.
    var offered = binder;
    std.valgrind.memcheck.makeMemDefined(&offered);
    const ok = tr.psk.verifyBinder(Hkdf, Hmac, &bk, &ch_hash, offered);
    show(&[1]u8{@intFromBool(ok)});
    var wrong = offered;
    wrong[3] ^= 0x01;
    const bad = tr.psk.verifyBinder(Hkdf, Hmac, &bk, &ch_hash, wrong);
    show(&[1]u8{@intFromBool(bad)});
}

fn runEarly(comptime Hkdf: type, t: Taint) void {
    const L = Hkdf.prk_length;
    var psk = secretBytes(L, "ctgrind-tlsresume-psk-v1");
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(&psk);
    const ch_hash = publicBytes(L, "ctgrind-tlsresume-full-ch-v1");

    var es: [L]u8 = undefined;
    tr.psk.earlySecret(Hkdf, &es, &psk);
    var cets: [L]u8 = undefined;
    tr.earlydata.clientEarlyTrafficSecret(Hkdf, &cets, &es, &ch_hash);
    show(&cets);
    var eems: [L]u8 = undefined;
    tr.earlydata.earlyExporterMasterSecret(Hkdf, &eems, &es, &ch_hash);
    show(&eems);
    var k16: tr.earlydata.TrafficKeyIv(16) = undefined;
    tr.earlydata.earlyTrafficKeyIv(Hkdf, 16, &k16, &cets);
    show(&k16.key);
    show(&k16.iv);
    var k32: tr.earlydata.TrafficKeyIv(32) = undefined;
    tr.earlydata.earlyTrafficKeyIv(Hkdf, 32, &k32, &cets);
    show(&k32.key);
    show(&k32.iv);

    var ctx: tr.earlydata.EarlyDataContext(Hkdf, 32) = undefined;
    ctx.derive(&psk, &ch_hash);
    show(&ctx.key);
    show(&ctx.iv);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });
    const Sha384Hkdf = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);
    switch (target) {
        .stek => try runStek(taint),
        .psk => {
            runPsk(std.crypto.kdf.hkdf.HkdfSha256, std.crypto.auth.hmac.sha2.HmacSha256, taint);
            runPsk(Sha384Hkdf, std.crypto.auth.hmac.sha2.HmacSha384, taint);
        },
        .early => {
            runEarly(std.crypto.kdf.hkdf.HkdfSha256, taint);
            runEarly(Sha384Hkdf, taint);
        },
    }
}
