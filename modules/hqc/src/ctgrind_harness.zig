// SPDX-License-Identifier: MIT
//! ctgrind harness for `hqc`.
//!
//! ⛔ THIS MODULE'S ROWS ARE A RECORDED DEFECT, not a clean claim. `SPEC.md`
//! and several doc comments used to say the implementation has no
//! secret-dependent branches because it structurally matches the reference.
//! It does structurally match — and the compiler undoes it. `prng.zig`'s
//! `writeSupportToVector` was a masked select with no `if` in the source, and
//! LLVM recognised the identity and rewrote it back into a branch that loads
//! `bit_tab[k]` only on the taken path. Adjudicated in the disassembly as real
//! `je`/`jne`/`jb`, not the known `cmov` false positive (audit finding, 2026).
//!
//! ⭐ THE HARNESS DID ITS JOB ON 2026-09-09. The scatter is now behind an
//! `asm volatile ("" : "+r" (mask))` barrier and the pinned counts moved
//! `decaps` 52 → 14, `keygen` 26 → 4, `encaps` 33 → 6 — the rows went red on a
//! FIX, which is exactly the direction this file was written to catch. What is
//! left is elsewhere in the module (`gf256`'s multiply, the rejection loop) and
//! is still a recorded defect.
//!
//! So the point of this harness is not to prove the module clean. It is to
//! make the defect VISIBLE and to fail the moment its size changes — in either
//! direction. A row that goes red when the leak is FIXED is how the fix gets
//! noticed; a row that goes red when a compiler upgrade makes it worse is how
//! a silent regression gets noticed. Without it, every fix quietly falls apart
//! at the next Zig upgrade and nothing says so — and that now includes the
//! barrier itself, which is one deletable line holding 38 contexts shut.
//!
//! Usage: ctgrind-hqc <target> <yes|no>
//!   targets: decaps | keygen | encaps | sampler
//!
//! ## Why ReleaseFast only, when the count is WORSE elsewhere
//!
//! Measured across modes on `decaps`, post-barrier: ReleaseFast 14,
//! ReleaseSafe 92 (pre-barrier those were 52 and 130).
//! ReleaseSafe is worse because the overflow checks in
//! `reedmuller.decodeSymbol` become branches on secret-derived data — and
//! ReleaseSafe is the mode a security-conscious consumer deploys. That is
//! itself a finding and it is written down in `SPEC.md`; it is not pinned here
//! because a second mode doubles the rows for a claim of the same shape, and
//! because Debug cannot be measured at all (valgrind's DWARF reader cannot
//! parse what Zig's self-hosted backend emits, `scripts/ctgrind.sh` § MODES).
//!
//! ## The propagation witness
//!
//! Each target formats its result through `std.debug.print`, which is not
//! constant-time by design, so an in-file count means "branches found in the
//! module" rather than "the taint never arrived".

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const params = root.params;
const Kem = root.Hqc128;

const Taint = enum { yes, no };

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn taint(t: Taint, bytes: []u8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const t = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={} target={s}\n", .{ builtin.valgrind_support, target });

    var seed: [32]u8 = [_]u8{0x5A} ** 32;
    var kp = Kem.keypair(&seed);
    var coins: [Kem.coins_bytes]u8 = [_]u8{0x21} ** Kem.coins_bytes;
    const enc = Kem.encaps(kp.ek, &coins);

    if (std.mem.eql(u8, target, "decaps")) {
        // Taint the SECRET half of the decapsulation key: dk_pke (= seed_dk,
        // from which `y` is re-derived on every call) and sigma (the
        // implicit-rejection secret). `ek` and `seed_kem` stay public.
        taint(t, kp.dk[Kem.ek_bytes .. Kem.ek_bytes + params.seed_bytes + Kem.security_bytes]);
        const ss = Kem.decaps(kp.dk, enc.ct);
        std.debug.print("ss={x}\n", .{ss});
    } else if (std.mem.eql(u8, target, "keygen")) {
        taint(t, seed[0..]);
        const kp2 = Kem.keypair(&seed);
        std.debug.print("ek={x}\n", .{kp2.ek[0..32]});
    } else if (std.mem.eql(u8, target, "encaps")) {
        // `coins` = m ‖ salt; `m` is the secret the Fujisaki-Okamoto transform
        // protects, so only its first `security_bytes` are tainted.
        taint(t, coins[0..Kem.security_bytes]);
        const e2 = Kem.encaps(kp.ek, &coins);
        std.debug.print("ct={x}\n", .{e2.ct[0..32]});
    } else if (std.mem.eql(u8, target, "sampler")) {
        // The hottest secret path in the module: the fixed-weight sampler that
        // scatters the long-term secret vector `y`, run on every decapsulation.
        // This is where `writeSupportToVector` lives.
        var sd: [32]u8 = [_]u8{0x11} ** 32;
        taint(t, sd[0..]);
        var xof = root.prng.Xof.init(&sd);
        const P = params.hqc128;
        var sup: [P.omega]u32 = undefined;
        root.prng.sampleFixedWeightRejection(&xof, P.n, P.nMu(), P.rejectionThreshold(), P.omega, &sup);
        // Hex, and at least 32 digits of it: the `--check` output pin matches
        // `name=<32+ hex>`, so a decimal print is invisible to it (measured --
        // the row pinned NO-OUTPUT).
        std.debug.print("sup={x}\n", .{std.mem.sliceAsBytes(sup[0..16])});
    } else {
        return error.UnknownTarget;
    }
}
