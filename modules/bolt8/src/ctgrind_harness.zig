// SPDX-License-Identifier: MIT
//! ctgrind harness for `bolt8` — a standalone program that marks the module's
//! secrets `MAKE_MEM_UNDEFINED` and drives them through the code whose
//! constant-time property `SPEC.md` claims. Not a test: memcheck's context
//! count is valgrind's own verdict, not something a Zig test can assert on.
//! `scripts/checks/ctgrind.sh` drives it; `SPEC.md` § Constant-time carries the table.
//!
//! Usage: ctgrind-bolt8 <target> <yes|no>
//!   targets: dh | keygen | act3 | transport
//!
//! ## Why this module has one at all
//!
//! Until 2026-09-08 `bolt8` was outside the ctgrind table and its ledger
//! recorded the constant-time verdict as "PASS (inherited)" — read, never
//! instrumented — while the module holds the node's long-term static private
//! key, the ephemeral keys, `temp_k*` and both transport keys. Audit finding
//! F10.
//!
//! ## Which targets exist, and one that deliberately does not
//!
//! `act1` is NOT a target. The initiator's Act One never touches the static
//! key (it draws its ephemeral inside), so the taint has no path into it and
//! the row would read 0 for a reason that has nothing to do with constant
//! time. A row that cannot fail is not evidence, and printing one next to four
//! that can is worse than leaving it out — someone would read that zero.
//!
//! ## Why the pattern names k256's and std's files too
//!
//! Deliberate, and the same reasoning `chachapoly`'s `aead` target is written
//! with. `bolt8` DELEGATES its scalar multiplication to `k256` and its AEAD to
//! std's ChaCha20-Poly1305; their constant-time property IS this module's
//! property for every byte that flows through them. Attributing those contexts
//! to someone else and calling them not our problem would be the same evasion
//! as widening a pattern to make a count go away. The expected non-zeros are
//! named one by one in `SPEC.md`.
//!
//! ## ReleaseFast only
//!
//! `Debug` and `ReleaseSafe` turn the checked arithmetic inside `k256` and
//! std's ChaCha20 into overflow branches on secret-derived values, which flood
//! the report. And Debug cannot be measured at all: valgrind's DWARF reader
//! cannot parse what Zig's self-hosted backend emits, and Debug is the only
//! mode where that backend is the default (`scripts/checks/ctgrind.sh` § MODES).
//!
//! ## The propagation witness
//!
//! Every target formats its result through `std.debug.print`, which is not
//! constant-time by design. A tainted byte reaching it is what makes an
//! in-file zero mean "no branch found" rather than "the taint never arrived".

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

const Taint = enum { yes, no };

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn taint(t: Taint, bytes: []u8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

/// Force a volatile reload so the optimizer cannot keep a defined register
/// copy of a value we have just marked undefined — the same guard every other
/// harness in this repository uses.
fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const t = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={} target={s}\n", .{ builtin.valgrind_support, target });

    // Deterministic keys: this harness must print the same bytes on every run,
    // because `scripts/checks/ctgrind.sh --check` pins a digest of what it printed.
    var ils = try root.Secp256k1DH.KeyPair.generateDeterministic([_]u8{0x11} ** 32);
    const rls = try root.Secp256k1DH.KeyPair.generateDeterministic([_]u8{0x21} ** 32);
    var prng = std.Random.DefaultPrng.init(0xb01783);
    const e: root.handshake.Ephemeral = .{ .seeded_for_test = prng.random() };

    if (std.mem.eql(u8, target, "dh")) {
        // The long-term static private scalar is the secret.
        taint(t, ils.secret_key[0..]);
        const sk = reloadVolatile(32, &ils.secret_key);
        const s = try root.Secp256k1DH.dh(sk, rls.public_key);
        std.debug.print("dh={x}\n", .{s});
    } else if (std.mem.eql(u8, target, "keygen")) {
        var seed: [32]u8 = [_]u8{0x42} ** 32;
        taint(t, seed[0..]);
        const sd = reloadVolatile(32, &seed);
        const kp = try root.Secp256k1DH.KeyPair.generateDeterministic(sd);
        std.debug.print("pk={x}\n", .{kp.public_key});
    } else if (std.mem.eql(u8, target, "act3")) {
        // Responder Act Three: decrypts the peer's static key under temp_k2 and
        // runs one ECDH with its own ephemeral secret.
        var i = root.Initiator.init(ils, rls.public_key);
        var r = root.Responder.init(rls);
        const a1 = try i.genAct1(e);
        try r.readAct1(a1);
        const a2 = try r.genAct2(e);
        try i.readAct2(a2);
        const fin = try i.genAct3();
        taint(t, r.ephemeral.?.secret_key[0..]);
        taint(t, r.ss.cipher_state.k[0..]);
        const res = try r.readAct3(fin.msg);
        std.debug.print("rk={x}\n", .{res.rk});
    } else if (std.mem.eql(u8, target, "transport")) {
        var i = root.Initiator.init(ils, rls.public_key);
        var r = root.Responder.init(rls);
        const a1 = try i.genAct1(e);
        try r.readAct1(a1);
        const a2 = try r.genAct2(e);
        try i.readAct2(a2);
        const fin = try i.genAct3();
        const rres = try r.readAct3(fin.msg);
        var tx = root.Transport.init(fin.result);
        var rx = root.Transport.init(rres);
        // The transport keys and the rotation chaining key are the secrets.
        taint(t, tx.tx.cipher.k[0..]);
        taint(t, tx.tx.chain[0..]);
        taint(t, rx.rx.cipher.k[0..]);
        taint(t, rx.rx.chain[0..]);
        var frame: [18 + 64 + 16]u8 = undefined;
        var msg: [64]u8 = [_]u8{0xa5} ** 64;
        // Enough messages to cross a key rotation (500 per direction), so the
        // rotation path is measured and not merely present.
        for (0..600) |_| {
            try tx.sendMessage(&msg, &frame);
            const l = try rx.recvLength(frame[0..18]);
            try rx.recvMessage(frame[18..], msg[0..l]);
        }
        std.debug.print("msg={x}\n", .{msg});
    } else {
        return error.UnknownTarget;
    }
}
