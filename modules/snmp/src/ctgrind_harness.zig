// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh snmp`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-snmp`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures (SNMPv3 USM, RFC 3414 / 7860 / 3826)
//!
//!  * `kdf` — the user's password tainted through `usm.passwordToUserKey`
//!    (the 1 MiB password expansion) and `usm.localizeKey`, MD5 and SHA-1.
//!  * `auth` — the localized auth key tainted through `usm.computeDigestInto`
//!    for every auth protocol (HMAC-MD5-96 .. HMAC-SHA-512). The message is
//!    public.
//!  * `aes` — the localized privacy key and the scopedPDU tainted through
//!    `priv.encrypt`/`decrypt` with AES-128-CFB (RFC 3826).
//!  * `des` — the same with DES-CBC (RFC 3414 §8). EXPECTED NON-ZERO: the
//!    module's `des.zig` is a table-driven DES (S-boxes and permutation
//!    tables indexed by key- and data-dependent values). Recorded as an open
//!    finding; SNMPv3 DES is legacy and replacing it is the owner's call.
//!
//! The salt, engine boots/time and lengths are public.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const snmp = @import("root.zig");

const usm = snmp.usm;
const priv = snmp.priv;
const Target = enum { kdf, auth, aes, des };
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

fn privRoundTrip(proto: priv.PrivProtocol, t: Taint) !void {
    var key = secretBytes(16, "ctgrind-snmp-priv-key-v1");
    var pdu = secretBytes(48, "ctgrind-snmp-scoped-pdu-v1");
    taintBytes(t, &key);
    taintBytes(t, &pdu);
    var salt = priv.SaltSource.counter(0x5a17);
    var ct_buf: [64]u8 = undefined;
    const enc = try priv.encrypt(proto, &key, 3, 1234, &salt, &pdu, &ct_buf);
    std.debug.print("ctgrind_result={x}\n", .{enc.ciphertext});
    std.valgrind.memcheck.makeMemDefined(enc.ciphertext); // on the wire
    var pt_buf: [64]u8 = undefined;
    const pt = try priv.decrypt(proto, &key, 3, 1234, &enc.salt, enc.ciphertext, &pt_buf);
    std.debug.print("ctgrind_result={x}\n", .{pt});
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });
    const engine_id = "\x80\x00\x1f\x88\x80ctgrind-engine";

    switch (target) {
        .kdf => {
            var pw = "maplesyrup-ctgrind".*;
            taintBytes(taint, &pw);
            for ([_]usm.AuthProtocol{ .hmac_md5, .hmac_sha1 }) |proto| {
                var uk_buf: [64]u8 = undefined;
                const uk = try usm.passwordToUserKey(proto, &pw, &uk_buf);
                var lk_buf: [64]u8 = undefined;
                const lk = usm.localizeKey(proto, uk, engine_id, &lk_buf);
                std.debug.print("ctgrind_result={x}\n", .{lk});
            }
        },
        .auth => {
            var key = secretBytes(64, "ctgrind-snmp-auth-key-v1");
            taintBytes(taint, &key);
            var msg: [120]u8 = undefined;
            for (&msg, 0..) |*b, i| b.* = @truncate(i *% 29 +% 3);
            @memset(msg[40..88], 0); // the zeroed msgAuthenticationParameters
            for ([_]usm.AuthProtocol{ .hmac_md5, .hmac_sha1, .hmac_sha224, .hmac_sha256, .hmac_sha384, .hmac_sha512 }) |proto| {
                var out: [64]u8 = undefined;
                const d = try usm.computeDigestInto(proto, key[0..proto.keyLen()], &msg, 40, &out);
                std.debug.print("ctgrind_result={x}\n", .{d});
            }
        },
        .aes => try privRoundTrip(.aes128_cfb, taint),
        .des => try privRoundTrip(.des_cbc, taint),
    }
}
