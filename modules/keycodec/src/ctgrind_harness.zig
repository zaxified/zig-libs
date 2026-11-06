// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh keycodec`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-keycodec`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! The keys are OpenSSL's (`vectors.zig`): EC P-256 SEC1, P-384 PKCS#8, P-521
//! SEC1, Ed25519 and X25519 PKCS#8, ML-DSA-44 `both`, ML-KEM-512 seed. RSA is
//! left out: its secret is the whole PKCS#1 DER, whose INTEGER layout is the
//! `rsa` module's to read (keycodec only checks its outer shape).
//!
//! - `der`: `parsePrivateKeyDer` with ONLY the secret octets tainted (the
//!   EC scalar, the Ed/X key, the ML seed and expanded key); the DER
//!   structure around them is public. The claim: no branch and no load
//!   address on a secret in keycodec's files, except the EC scalar range
//!   check's VERDICT (`scalarInRange`'s result, one branch per EC key: a key
//!   that loads is public, as b64ct's validity verdict is).
//! - `write`: `writePrivateKeyPem` of the same keys with the secret parts
//!   tainted (built from the parsed parts, re-pointed at a tainted copy).
//!   Same claim: the writer's own scalar range verdict, nothing else.
//! - `pem`: the PEM layer alone, `pem.find` + `Block.decode`, with the whole
//!   base64 body tainted. The claim: the block walk crosses a body only by
//!   scans whose compare is false on every base64 character (the END line's
//!   first '-', `startsHeader`'s '\n' and ':'), and b64ct decodes in
//!   constant time. Whole-body taint through the DER walk as well (what the
//!   acme rows measure) only re-counts layout: a base64 character carries
//!   bits of two or three octets, so tag and length octets come out tainted.
//!
//! ## The propagation witness
//!
//! Every result is printed through `std.debug.print` (hex), which is not
//! constant-time: the total is non-zero while the in-file count is the
//! claim's.

const std = @import("std");
const builtin = @import("builtin");
const kc = @import("root.zig");
const vectors = @import("vectors.zig");

const Taint = enum { yes, no };
const Target = enum { der, write, pem };

const names = [_][]const u8{
    "ec_p256-sec1",
    "ec_p384-pkcs8",
    "ec_p521-sec1",
    "ed25519-pkcs8",
    "x25519-pkcs8",
    "ml_dsa_44-both",
    "ml_kem_512-seed",
};

fn caseNamed(name: []const u8) !vectors.Case {
    for (vectors.cases) |c| if (std.mem.eql(u8, c.name, name)) return c;
    return error.NoSuchCase;
}

/// Forces one real load per byte through a volatile pointer, so the code
/// under test cannot be fed a register copy that predates the taint.
fn reloadVolatile(dst: []u8, s: []const u8) void {
    for (dst, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
}

fn taint(t: Taint, bytes: []u8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

/// `part`'s offset inside `whole` (both slices of the same buffer).
fn offsetIn(whole: []const u8, part: []const u8) usize {
    return @intFromPtr(part.ptr) - @intFromPtr(whole.ptr);
}

var der_buf: [kc.max_private_der_len]u8 = undefined;
var work: [kc.max_private_der_len]u8 = undefined;
var secret_copy: [8192]u8 = undefined;
var expanded_copy: [8192]u8 = undefined;
var text_buf: [kc.max_private_pem_len]u8 = undefined;
var out_buf: [kc.max_private_pem_len]u8 = undefined;

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const t = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });
    // The output pin (`ctgrind_result=`): a digest of every result printed.
    var pin = std.hash.Wyhash.init(0);

    for (names) |name| {
        const c = try caseNamed(name);
        // The key's DER and its parts, untainted.
        const label = (std.meta.stringToEnum(kc.Encoding, c.encoding) orelse return error.BadCase).pemLabel();
        const block = (try kc.pem.find(c.pem, label)) orelse return error.BadCase;
        const der = try block.decode(&der_buf);
        const k0 = try kc.parsePrivateKeyDer(der);

        switch (target) {
            .der => {
                const w = work[0..der.len];
                reloadVolatile(w, der);
                taint(t, w[offsetIn(der, k0.secret)..][0..k0.secret.len]);
                if (k0.expanded.len != 0) taint(t, w[offsetIn(der, k0.expanded)..][0..k0.expanded.len]);
                reloadVolatile(w, w);
                const k = try kc.parsePrivateKeyDer(w);
                std.debug.print("{s} der secret={x}\n", .{ name, k.secret });
                pin.update(k.secret);
            },
            .write => {
                var k = k0;
                const s = secret_copy[0..k0.secret.len];
                reloadVolatile(s, k0.secret);
                taint(t, s);
                reloadVolatile(s, s);
                k.secret = s;
                if (k0.expanded.len != 0) {
                    const e = expanded_copy[0..k0.expanded.len];
                    reloadVolatile(e, k0.expanded);
                    taint(t, e);
                    reloadVolatile(e, e);
                    k.expanded = e;
                }
                const pem = try kc.writePrivateKeyPem(&out_buf, k);
                std.debug.print("{s} pem={s}\n", .{ name, pem });
                pin.update(pem);
            },
            .pem => {
                // The PEM layer alone: the block walk and the base64 decode.
                // The DER under it is the `der` row's.
                const text = text_buf[0..c.pem.len];
                reloadVolatile(text, c.pem);
                taint(t, text[offsetIn(c.pem, block.body)..][0..block.body.len]);
                reloadVolatile(text, text);
                const b = (try kc.pem.find(text, label)) orelse return error.BadCase;
                const d = try b.decode(&der_buf);
                std.debug.print("{s} pem der={x}\n", .{ name, d });
                pin.update(d);
            },
        }
    }
    std.debug.print("ctgrind_result={x:0>16}\n", .{pin.final()});
}
