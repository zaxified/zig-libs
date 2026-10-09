// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh sessions`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-sessions`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! The module's two secrets:
//!
//!  * `csrf` — the CSRF HMAC key (`Csrf.key`). Tainted, then `Csrf.token`
//!    (HMAC-SHA256 + hex) and `Csrf.verify` on a valid and a forged token
//!    (HMAC + `timing_safe.eql`). The session id and the presented token are
//!    public inputs and stay defined; so is every length.
//!  * `newid` — the raw random bytes of a session id, hex-encoded by
//!    `idhex.encode`, the exact routine `Manager.newId` runs on its
//!    `entropy.fill` draw. (`newId` itself is private and draws from the OS,
//!    so its bytes cannot be tainted from outside; the encoding is the only
//!    thing it does to them.)
//!
//! Before 2026-10-09 both sites hex-encoded through a 16-byte table indexed
//! by the secret nibble (`std.fmt.bytesToHex` in `Csrf.token`, a literal
//! `"0123456789abcdef"[b >> 4]` in `newId`) — memcheck counts each such load
//! as a use of an uninitialised value in an address. `idhex` replaced both.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero — which is what makes the zero mean "no branch" rather than
//! "the taint never arrived".

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const idhex = @import("idhex.zig");

const Target = enum { csrf, newid };
const Taint = enum { yes, no };

/// A runtime (not comptime-foldable) stand-in for a secret, so tainting it
/// marks real memory.
fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    var out: [n]u8 = undefined;
    for (&out, 0..) |*o, i| o.* = full[i % 32] +% @as(u8, @truncate(i / 32));
    return out;
}

fn reloadVolatile(comptime n: usize, src: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, src) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    switch (target) {
        .csrf => {
            // The forged token is computed from the UNTAINTED key before the
            // taint, flipped in one byte: verify must reject it on the MAC.
            const session_id = "3f1c0e9d5b7a2c4e6f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6";
            var raw = secretBytes(32, "ctgrind-sessions-csrf-key-v1");
            var forged: [root.csrf_token_hex_len]u8 = undefined;
            _ = (root.Csrf{ .key = raw }).token(session_id, &forged);
            forged[7] = if (forged[7] == '0') '1' else '0';

            if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&raw);
            const guard: root.Csrf = .{ .key = reloadVolatile(32, &raw) };

            var tok: [root.csrf_token_hex_len]u8 = undefined;
            _ = guard.token(session_id, &tok);
            const ok_good = guard.verify(session_id, &tok);
            const ok_forged = guard.verify(session_id, &forged);

            var res: [root.csrf_token_hex_len + 2]u8 = undefined;
            @memcpy(res[0..tok.len], &tok);
            res[tok.len] = @intFromBool(ok_good);
            res[tok.len + 1] = @intFromBool(ok_forged);
            std.debug.print("ctgrind_result={x}\n", .{res});
        },
        .newid => {
            // 32 B (the default id_bytes) and 64 B (max_id_bytes).
            var raw = secretBytes(root.max_id_bytes, "ctgrind-sessions-id-v1");
            if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&raw);
            const id = reloadVolatile(root.max_id_bytes, &raw);
            var text: [2 * root.max_id_bytes]u8 = undefined;
            idhex.encode(text[0..64], id[0..32]);
            std.debug.print("ctgrind_result={x}\n", .{text[0..64].*});
            idhex.encode(&text, &id);
            std.debug.print("ctgrind_result={x}\n", .{text});
        },
    }
}
