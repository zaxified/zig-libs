// SPDX-License-Identifier: MIT

//! Audit A1 B12 instrument, moved into the module per `CONVENTIONS.md` §9
//! (an instrument that checks ONE module belongs to that module, not to the
//! audit record). Dead-stack scan: after `prove()` returns, does the stack
//! below it still hold a copy of the secret value `v`?
//!
//! `A1/bulletproofs.md` B12 measured **1 hit** when `v` was taken by value
//! (`prove(v: u64, ...)`): the parameter's own argument-passing slot is a
//! copy `prove`'s body has no way to reach, unlike `v_bytes` (which the
//! body constructs itself and does `secureZero`). The fix applied here
//! takes `v` **by pointer** and reads it into a local exactly once
//! (`v_val`), which this function owns and `secureZero`s -- closing both
//! the original by-value parameter slot AND a second copy this probe found
//! while measuring the first fix (dereferencing `v.*` 64 times in the
//! bit-decomposition loop gave the optimizer room to spill it elsewhere).
//!
//! ⚠ **Diagnostic, not a gate, and the finding is NOT fully closed.** This
//! probe still measures **1 hit** after both fixes above -- but it is a
//! DIFFERENT copy than either fix targeted: byte-dumping the match's
//! context (see the disposition in `A1/bulletproofs.md`, B12) shows it is
//! `v_bytes`, the 32-byte scalar encoding `prove` builds and *does*
//! `secureZero` via `defer` before returning. The same needle still finds
//! it, which means the optimizer materialized a second, short-lived copy
//! of `v_bytes` at some point during `commit(gens, v_bytes, gamma)` (a
//! call-boundary temporary, or a mid-function register spill) whose
//! address the `defer secureZero(&v_bytes)` -- which clears v_bytes's own,
//! *final* storage location -- never reaches. Forcing `commit` to inline
//! at the call site (`@call(.always_inline, ...)`) did not change the
//! result. This is the same class of leak recorded for `blindrsa` B6/B9
//! (`std.crypto.ff`-internal spills a module-level fix cannot reach) and in
//! `zig_std_crypto_leaves_key_schedules_on_stack` (CML memory): a single
//! `secureZero` call clears a value's current home, not every historical
//! spill location the optimizer used for it during the function's
//! lifetime. Closing it would mean auditing (or compiler-barrier-wrapping)
//! every intermediate use of `v_bytes`, which is out of scope for this
//! fixer's budget -- printed here, not asserted, so this does not silently
//! regress AND does not claim a fix this repository does not have.
//!
//! ReleaseFast only: Debug/ReleaseSafe fill freed stack space with a fixed
//! poison pattern rather than leaving genuine dead-frame residue, so a scan
//! run there would measure the poison fill, not the property under test
//! (same caveat `sealedbox`'s and `ctap2pin`'s equivalent probes record).
//!
//! The scan window is 96 KiB, not the 512 KiB the original audit probe used
//! as a standalone `zig build-exe` (`A1/repro/bulletproofs/reach.zig`):
//! declaring a 512 KiB local array here, inside `zig build test-bulletproofs`'s
//! own test runner, overran that runner's stack before a single byte was
//! read (a guard-page SIGSEGV with no output at all, not a test failure).

const std = @import("std");
const bp = @import("root.zig");

const secret_gamma: [32]u8 = .{
    0xa7, 0x3d, 0x91, 0xe4, 0x5c, 0x08, 0xbb, 0x27, 0x6f, 0xd2, 0x14, 0x8a, 0x39, 0xc6, 0x70, 0x1b,
    0x4e, 0xf5, 0x82, 0x2c, 0x9b, 0x60, 0xa3, 0x17, 0xd8, 0x45, 0xee, 0x03, 0x7a, 0x51, 0xcf, 0x0d,
};
// Genuinely high-entropy: a low-entropy needle (the original audit probe
// used an ascending-nibble pattern) risks a coincidental match against
// unrelated internal state.
const secret_v: u64 = 0x7ae2_c519_0f6b_83d4;

noinline fn runProve(gpa: std.mem.Allocator, gens: bp.Generators, v: *const u64, gamma: [32]u8) !void {
    var t = bp.Transcript.init(bp.rangeproof_domain);
    const p = try bp.prove(gpa, gens, &t, v, gamma);
    p.deinit(gpa);
}

const WINDOW = 96 * 1024;

noinline fn scanForU64(needle_le: *const [8]u8) usize {
    var frame: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&frame);
    var hits: usize = 0;
    var i: usize = 0;
    const limit = WINDOW - 8;
    outer: while (i <= limit) : (i += 1) {
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            if (p[i + j] != needle_le[j]) continue :outer;
        }
        hits += 1;
    }
    std.mem.doNotOptimizeAway(&frame);
    return hits;
}

test "STACKPROBE (B12): dead-stack copies of v after prove() -- diagnostic, see module doc comment" {
    if (@import("builtin").mode != .ReleaseFast) return error.SkipZigTest;

    var v_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &v_le, secret_v, .little);

    const gens = try bp.Generators.init(std.testing.allocator, 64);
    defer gens.deinit(std.testing.allocator);
    try runProve(std.testing.allocator, gens, &secret_v, secret_gamma);
    const prove_hits = scanForU64(&v_le);
    std.debug.print(
        "B12 dead-stack scan: copies of v after prove() = {d} (0 = the two module-level fixes closed it; " ++
            "any other number is diagnostic only -- see this file's doc comment, this was 1 before AND after " ++
            "both fixes here, traced to a v_bytes copy secureZero's defer does not reach)\n",
        .{prove_hits},
    );
}
