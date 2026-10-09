// SPDX-License-Identifier: MIT

//! ctgrind_harness — constant-time evidence for the zkey prover's
//! `.constant_time` MSM choice (`zkprove.proveWith`), and a positive control
//! on the default Pippenger MSM it is the alternative to. Run it through
//! `../../../scripts/checks/ctgrind.sh groth16`.
//!
//! NOT wired into `zig build test-groth16` — memcheck's context count is
//! valgrind's output, not something a Zig test can assert on. `zig build
//! check-ctgrind` compiles it so it cannot rot into an unbuildable recipe.
//!
//! ## The two targets
//!
//! * `zkprove_ct` — the claim. `proveWith(…, .{ .msm = .constant_time })` on
//!   the committed snarkjs fixture (`t1.zkey`, circom's `t.wtns`), with the
//!   PRIVATE witness signals and both randomizers `r`, `s` tainted. Every step
//!   between them and the proof — A·w/B·w accumulation, the coset NTTs, the
//!   per-term `scalarMul`, the `ctSelect` additions — must not branch on them.
//! * `zkprove_vt` — the positive control: the same call with the default
//!   Pippenger MSM, which SPEC.md § 5b item 4 says is variable-time in the
//!   witness. Its in-file count must be well above `zkprove_ct`'s; if it were
//!   not, the taint would not be reaching the MSM and the claim row's count
//!   would mean nothing.
//!
//! ## Deliberate choices
//!
//! 1. The witness is parsed CLEAN and its private part tainted afterwards:
//!    `parseWitness`'s canonicality checks are parse-path validation. Signal
//!    0 (the constant 1) and the public inputs are public by definition and
//!    stay defined.
//! 2. The key (`.zkey`) is public: every base point and coefficient.
//! 3. The proof is public too, but its last step — `toAffine` on π_A, π_B,
//!    π_C — runs inside the prover and branches on whether the point is the
//!    identity. Those are the contexts `zkprove_ct` is pinned at (counted in
//!    `scripts/checks/ctgrind-expected.tsv`): a branch on the published
//!    output, after every secret has been blinded by `r`/`s`, not a leak.
//! 4. ReleaseFast only, as everywhere else (overflow checks in the limb
//!    arithmetic flood the other modes).
//! 5. Hex formatting of the proof is the propagation witness.

const std = @import("std");
const builtin = @import("builtin");
const bn254 = @import("bn254");
const zkprove = @import("zkprove.zig");
const zkey = @import("zkey.zig");
const circom = @import("circom.zig");
const field = @import("field.zig");

const Fr = bn254.Fr;

const t1_zkey = @embedFile("testdata/snarkjs/t1.zkey");
const t_wtns = @embedFile("testdata/snarkjs/t.wtns");

const Target = enum { zkprove_ct, zkprove_vt };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "zkprove_ct")) return .zkprove_ct;
    if (std.mem.eql(u8, s, "zkprove_vt")) return .zkprove_vt;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn taint(bytes: []u8, tainted: bool) void {
    if (tainted) std.valgrind.memcheck.makeMemUndefined(bytes);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    const gpa = std.heap.page_allocator; // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from
    var z = try zkey.parse(gpa, t1_zkey);
    defer z.deinit(gpa);
    const w = try circom.parseWitness(gpa, t_wtns);
    defer circom.freeWitness(gpa, w);

    // Randomizers computed at runtime, so the tainted memory is what the
    // prover actually reads.
    var rand: @import("prover.zig").Randomizers = .{ .r = field.frFromU64(11), .s = field.frFromU64(13) };
    std.mem.doNotOptimizeAway(&rand);

    taint(std.mem.sliceAsBytes(w[z.n_public + 1 ..]), tainted);
    taint(std.mem.asBytes(&rand), tainted);

    const opts: zkprove.Options = switch (target) {
        .zkprove_ct => .{ .msm = .constant_time },
        .zkprove_vt => .{ .msm = .pippenger },
    };
    const proof = try zkprove.proveWith(gpa, z, w, &rand, opts);

    std.debug.print("a.x={x}\n", .{proof.a.x.toBytes()});
    std.debug.print("a.y={x}\n", .{proof.a.y.toBytes()});
    std.debug.print("c.x={x}\n", .{proof.c.x.toBytes()});
    std.debug.print("c.y={x}\n", .{proof.c.y.toBytes()});
}
