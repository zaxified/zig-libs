// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh b64ct`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-b64ct`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! - `encode`: the OCTETS are secret (a private key on its way into a PEM).
//!   Every variant at 0..5, 32, 121 and 223 octets (the last two: P-256 and
//!   P-521 `EC PRIVATE KEY` DERs), `encodeWrapped` at 64/LF and 76/CRLF.
//! - `decode`: the TEXT is secret — produced untainted, then marked
//!   undefined before it is decoded, every variant and the same lengths.
//! - `ignore`: the text of a wrapped PEM body through `decodeIgnoring` and,
//!   with a trailer after it, through `decodePrefix`.
//!
//! What the module declassifies (`public` in root.zig) is exactly what its
//! contract makes public: the number of `=`, which characters are ignored,
//! where a prefix stops, the verdict. So the claim is 0 contexts in
//! `root.zig` for every row: no branch and no load address on a secret.
//!
//! ## The propagation witness
//!
//! Every result is printed through `std.debug.print`, whose hex formatting is
//! not constant-time. The total count is therefore non-zero while the
//! `root.zig` count is zero — that is what makes the zero mean "no branch in
//! the codec" rather than "the taint never arrived".

const std = @import("std");
const builtin = @import("builtin");
const b64ct = @import("root.zig");

const Taint = enum { yes, no };
const Target = enum { encode, decode, ignore };

const sizes = [_]usize{ 0, 1, 2, 3, 4, 5, 32, 121, 223 };
const max = 223;

/// Deterministic "secret" octets, computed at runtime so tainting them marks
/// the memory the codec reads. Not a KAT.
fn secretBytes(buf: []u8) void {
    var prng = std.Random.DefaultPrng.init(0x6236_3463_7400_0001);
    prng.random().bytes(buf);
}

/// Forces one real load from `s` through a volatile pointer, so the codec
/// cannot be fed a register copy that predates `makeMemUndefined`.
fn reloadVolatile(dst: []u8, s: []const u8) void {
    for (dst, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
}

fn taintCopy(taint: Taint, dst: []u8, s: []const u8) void {
    var raw: [1024]u8 = undefined;
    @memcpy(raw[0..s.len], s);
    if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(raw[0..s.len]);
    reloadVolatile(dst, raw[0..s.len]);
}

const codecs = .{ b64ct.standard, b64ct.standard_no_pad, b64ct.url_safe, b64ct.url_safe_no_pad };

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var plain: [max]u8 = undefined;
    secretBytes(&plain);
    // The output pin (`ctgrind_result=`): a digest of every result printed.
    var pin = std.hash.Wyhash.init(0);

    switch (target) {
        .encode => {
            var msg: [max]u8 = undefined;
            taintCopy(taint, &msg, &plain);
            inline for (codecs) |C| for (sizes) |n| {
                var out: [400]u8 = undefined;
                const e = C.encode(&out, msg[0..n]);
                std.debug.print("enc[{d}]={s}\n", .{ n, e });
                pin.update(e);
            };
            var w: [400]u8 = undefined;
            std.debug.print("pem={s}\n", .{b64ct.standard.encodeWrapped(&w, &msg, 64, .lf)});
            const mime = b64ct.standard.encodeWrapped(&w, &msg, 76, .crlf);
            std.debug.print("mime={s}\n", .{mime});
            pin.update(mime);
        },
        .decode => {
            inline for (codecs) |C| for (sizes) |n| {
                var enc_buf: [400]u8 = undefined;
                const enc = C.encode(&enc_buf, plain[0..n]);
                var text: [400]u8 = undefined;
                taintCopy(taint, text[0..enc.len], enc);
                var out: [max]u8 = undefined;
                const d = try C.decode(&out, text[0..enc.len]);
                std.debug.print("dec[{d}]={x}\n", .{ n, d });
                pin.update(d);
            };
        },
        .ignore => {
            var pem_buf: [400]u8 = undefined;
            const pem = b64ct.standard.encodeWrapped(&pem_buf, &plain, 64, .lf);
            var text: [420]u8 = undefined;
            taintCopy(taint, text[0..pem.len], pem);
            var out: [max]u8 = undefined;
            const d = try b64ct.standard.decodeIgnoring(&out, text[0..pem.len], b64ct.pem_whitespace);
            std.debug.print("ign={x}\n", .{d});
            var ign_copy: [max]u8 = undefined;
            @memcpy(ign_copy[0..d.len], d);
            const d_kept = ign_copy[0..d.len];
            // The END line after the body is public text: only the body is
            // tainted.
            const trailer = "-----END EC PRIVATE KEY-----\n";
            @memcpy(text[pem.len..][0..trailer.len], trailer);
            const r = try b64ct.standard.decodePrefix(&out, text[0 .. pem.len + trailer.len], b64ct.pem_whitespace);
            std.debug.print("prefix[{d}]={x}\n", .{ r.consumed, r.data });
            pin.update(d_kept);
            pin.update(r.data);
        },
    }
    std.debug.print("ctgrind_result={x:0>16}\n", .{pin.final()});
}
