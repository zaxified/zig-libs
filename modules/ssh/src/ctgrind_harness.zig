// SPDX-License-Identifier: MIT
//! ctgrind harness for `ssh` — the classic MODP Diffie-Hellman exponent
//! (`transport.dhPowModPrime`, `diffie-hellman-group14-sha256` /
//! `group16-sha512`).
//!
//! Usage: ctgrind-ssh <target> <yes|no>
//!   targets: dh | ffpow
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
