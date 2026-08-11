// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "Verified, not
//! asserted" bullet, as an actual committed program. Run it through
//! `../../../scripts/ctgrind.sh ecvrf`.
//!
//! That bullet quoted "11 errors / 10 contexts before, 4 / 3 after" with no
//! harness in the repo. The "before" half describes code that no longer exists
//! (`ecvrf` carried its own copy of std's ladder, `rejectIdentity` and all,
//! until it moved to `ct25519`), so it is not reproducible by construction and
//! is now labelled as history rather than as a number a reader can re-take.
//! The "after" half IS reproducible, and this file is what re-takes it.
//!
//! NOT wired into `zig build test-ecvrf` — memcheck's context count is
//! valgrind's output, not something a Zig test can assert on. `zig build
//! check-ctgrind` compiles it so it cannot rot into an unbuildable recipe.
//!
//! ## What this measures
//!
//! The 32-byte VRF secret key is marked `MAKE_MEM_UNDEFINED` and driven
//! through `publicKey` and `prove` — the two entry points that touch it. Both
//! reach `ct25519.mulBase`/`ct25519.mul` for every secret scalar (`x` and the
//! nonce `k`), which is the whole reason this module depends on `ct25519`
//! instead of `std.crypto.ecc.Edwards25519.mul`.
//!
//! The counts are reported per file so the "which lines" question is
//! answerable from the table rather than from prose:
//!
//! * contexts in `ecvrf.zig` — `encodeToCurve`'s try-and-increment loop,
//!   whose `Edwards25519.fromBytes` validity branch and `rejectIdentity`
//!   retry are branches on `Y`/`H`. `Y` is the PUBLISHED public key and
//!   `H = encode_to_curve(PK_string, alpha)` is recomputed by every verifier
//!   from public inputs, so a timing dependence there leaks nothing secret —
//!   it is the RFC-acknowledged try-and-increment property, documented in
//!   `SPEC.md` separately. They show up here only because this harness taints
//!   `sk`, from which `Y` is derived, and memcheck has no notion of "public
//!   function of a secret".
//! * contexts in `ct25519`'s `root.zig` — this is the number the module's
//!   dependency choice is about, and it is expected to be **zero**. `ct25519`
//!   has its own harness (`scripts/ctgrind.sh ct25519`) proving the same
//!   property against std as a negative control; what this table adds is that
//!   `ecvrf`'s own call sites really route through it.
//!
//! Run the driver with `--stacks` to read the frames instead of trusting the
//! attribution above.
//!
//! ## The traps
//!
//! 1. Without `-fvalgrind` every row reads 0 regardless
//!    (`std.valgrind.doClientRequest` returns early unless
//!    `builtin.valgrind_support`, which the release modes disable). The driver
//!    prints that as its own row.
//! 2. `reloadVolatile` forces a real load from freshly-tainted memory.
//!    Defensive, not demonstrated.
//! 3. ReleaseFast only — `Debug`/`ReleaseSafe` add overflow branches inside
//!    `std.crypto.25519.field` that flood the report.
//!
//! ## The propagation witness
//!
//! The public key and the proof are formatted through `std.debug.print`, which
//! is not constant-time.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

fn secretKey() root.SecretKey {
    var sk: root.SecretKey = undefined;
    std.crypto.hash.sha2.Sha256.hash("ctgrind-ecvrf-harness-secret-key-v1", &sk, .{});
    return sk;
}

fn reloadVolatile(s: *const root.SecretKey) root.SecretKey {
    var out: root.SecretKey = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const Taint = enum { yes, no };

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    if (!std.mem.eql(u8, target_arg, "prove")) return error.UnknownTarget;
    const taint = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    var sk = secretKey();
    if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&sk);
    const secret = reloadVolatile(&sk);

    // `alpha_string` is a PUBLIC VRF input and is never tainted, so the
    // try-and-increment loop's dependence on it cannot be mistaken for a
    // dependence on `sk`.
    const alpha = "ctgrind harness alpha";

    const pk = root.publicKey(secret);
    const pi = root.prove(secret, alpha);

    // Propagation witnesses: hex formatting is not constant-time.
    std.debug.print("pk={x}\n", .{pk});
    std.debug.print("pi={x}\n", .{pi});
}
