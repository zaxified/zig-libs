// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh megolm`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-megolm`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! The secrets are the Megolm ratchet (the 128-byte `R0..R3`) and the
//! session's Ed25519 signing key.
//!
//!  * `msg` — an outbound session built from a tainted ratchet and signing
//!    key: `encrypt` (ratchet → AES-256-CBC/HMAC-SHA-256 keys, CBC, MAC,
//!    Ed25519 signature, ratchet advance) twice; an inbound session from the
//!    exported (tainted) ratchet, `decrypt` both messages (MAC verify, CBC
//!    decrypt + PKCS#7 unpad, ratchet `advanceTo`). The wire message and
//!    the decrypted length are marked defined (both public; see `main`).
//!  * `skey` — the session-sharing key: `sessionKey`, `SessionKey.encode`,
//!    `toBase64`, `fromBase64` + `decode` (Ed25519 verify over the secret
//!    signed part), and the same for `ExportedSessionKey`. Until
//!    2026-10-10 this found a leak, fixed by `b64ct.zig`: std.base64 indexed
//!    its tables by the secret ratchet's sextets and characters.
//!  * `pickle` — `pickleSealed` / `fromSealedPickle` (outbound and inbound)
//!    with the session AND the pickle key tainted.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const megolm = @import("root.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Target = enum { msg, skey, pickle };
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var block: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &block, .{});
    var i: usize = 0;
    while (i < n) : (i += 32) {
        std.crypto.hash.sha2.Sha256.hash(&block, &block, .{});
        @memcpy(out[i..@min(n, i + 32)], block[0..@min(32, n - i)]);
    }
    return out;
}

fn taintBytes(t: Taint, bytes: []u8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

/// An outbound session from fixed bytes, its secret halves tainted. The
/// public signing key stays defined: it is published in every message.
fn outbound(t: Taint, out: *megolm.OutboundSession) !void {
    const data = secretBytes(megolm.ratchet.ratchet_len, "ctgrind-megolm-ratchet-v1");
    megolm.Ratchet.init(&data, 7, &out.ratchet);
    out.signing_key = try Ed25519.KeyPair.generateDeterministic(secretBytes(32, "ctgrind-megolm-sign-v1"));
    taintBytes(t, &out.ratchet.data);
    taintBytes(t, &out.signing_key.secret_key.bytes);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var heap: [1 << 16]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&heap);
    const gpa = fba.allocator();

    var out: megolm.OutboundSession = undefined;
    try outbound(taint, &out);

    switch (target) {
        .msg => {
            var sk: megolm.SessionKey = undefined;
            try out.sessionKey(&sk);
            var in: megolm.InboundGroupSession = undefined;
            try megolm.InboundGroupSession.fromSessionKey(&sk, &in);
            for ([_][]const u8{ "first megolm plaintext", "a second, longer plaintext crossing a block" }) |pt| {
                var m = try out.encrypt(gpa, pt);
                // What goes on the wire is public: the ciphertext, the MAC
                // and the signature. Left tainted, the receiver's Ed25519
                // verify of a public signature reports std's
                // variable-time (public-input) double-base multiplication.
                std.valgrind.memcheck.makeMemDefined(m.ciphertext);
                std.valgrind.memcheck.makeMemDefined(&m.mac);
                std.valgrind.memcheck.makeMemDefined(&m.signature);
                var d = try in.decrypt(gpa, &m);
                // The plaintext LENGTH comes out of the PKCS#7 unpad, so it
                // is tainted; it is the message's public length, and left
                // tainted it poisons the harness's own allocator.
                std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(&d.plaintext.len));
                // So is the harness allocator's bump index, which moved by it:
                // left tainted, every later allocation's ADDRESS is tainted.
                std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(&fba.end_index));
                std.debug.print("ctgrind_result={x}\n", .{d.plaintext});
                d.deinit(gpa);
                m.deinit(gpa);
            }
        },
        .skey => {
            var sk: megolm.SessionKey = undefined;
            try out.sessionKey(&sk);
            const b64 = try sk.toBase64(gpa);
            var back: megolm.SessionKey = undefined;
            try megolm.SessionKey.fromBase64(gpa, b64, &back);
            std.debug.print("ctgrind_result={x}\n", .{back.inner.ratchet});

            var in: megolm.InboundGroupSession = undefined;
            try megolm.InboundGroupSession.fromSessionKey(&sk, &in);
            var ex: megolm.ExportedSessionKey = undefined;
            if (!in.exportAt(9, &ex)) return error.ExportFailed;
            const eb64 = try ex.toBase64(gpa);
            var eback: megolm.ExportedSessionKey = undefined;
            try megolm.ExportedSessionKey.fromBase64(gpa, eb64, &eback);
            std.debug.print("ctgrind_result={x}\n", .{eback.ratchet});
        },
        .pickle => {
            var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{}); // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from
            defer threaded.deinit();
            const io = threaded.io();
            var key = secretBytes(@sizeOf(megolm.PickleKey), "ctgrind-megolm-pickle-key-v1");
            taintBytes(taint, &key);

            var sealed: [megolm.pickle.sealed_outbound_len]u8 = undefined;
            out.pickleSealed(io, &key, &sealed);
            var back: megolm.OutboundSession = undefined;
            try megolm.OutboundSession.fromSealedPickle(&sealed, &key, &back);
            std.debug.print("ctgrind_result={x}\n", .{back.ratchet.data});

            var sk: megolm.SessionKey = undefined;
            try out.sessionKey(&sk);
            var in: megolm.InboundGroupSession = undefined;
            try megolm.InboundGroupSession.fromSessionKey(&sk, &in);
            var sealed_in: [megolm.pickle.sealed_inbound_len]u8 = undefined;
            in.pickleSealed(io, &key, &sealed_in);
            var in_back: megolm.InboundGroupSession = undefined;
            try megolm.InboundGroupSession.fromSealedPickle(&sealed_in, &key, &in_back);
            std.debug.print("ctgrind_result={x}\n", .{in_back.latest_ratchet.data});
        },
    }
}
