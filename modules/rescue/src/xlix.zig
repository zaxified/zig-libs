// SPDX-License-Identifier: MIT

//! **Rescue-XLIX** — the *original* Rescue-Prime permutation (eprint 2020/1143,
//! Algorithm 3), as instantiated by Winterfell's `Rp64_256`.
//!
//! This exists so the difference between "Rescue-Prime" and "Rescue-Prime
//! Optimized" is a thing you can execute rather than a thing you read. The
//! round function is:
//!
//! ```text
//!   half 1:  state <- state^alpha      ;  state <- MDS * state ;  state += ARK1[r]
//!   half 2:  state <- state^(1/alpha)  ;  state <- MDS * state ;  state += ARK2[r]
//! ```
//!
//! Compare `perm.zig`: RPO moved the MDS multiply to the *front* of each half
//! round (`MDS -> ARK -> S-box`). Same field, same `alpha = 7`, same circulant
//! MDS row — and a completely different permutation. Feeding `[0, 1, .., 11]`
//! through both gives no shared element.
//!
//! ## What is and is not here
//!
//! **The permutation only.** No sponge. Winterfell's `Rp64_256` hasher does
//! have one (capacity at `0..4`, *additive* absorption rather than overwrite,
//! `state[0] = num_elements`), but Winterfell publishes no digest KAT for it —
//! only this permutation KAT — so a sponge here would be grade-3 wearing a
//! grade-1 module's name. Callers who need Winterfell-compatible digests should
//! say so and it can be added against vectors generated from Winterfell itself.
//!
//! ## Where the constants come from
//!
//! `xlix_constants.zig`, embedded from Winterfell's source rather than derived.
//! Winterfell's comment says they were "computed using algorithm 5 from
//! eprint 2020/1143" — that is the SHAKE256 generator this module already
//! implements for RPO, but **it does not reproduce these numbers** under any
//! seed variation tried. See `SPEC.md`, "The constants I could not re-derive".

const std = @import("std");
const gl = @import("goldilocks.zig");
const consts = @import("xlix_constants.zig");

pub const width = 12;
pub const rounds = 7;
pub const State = [width]gl.Fe;

/// Winterfell's MDS is the circulant matrix over the same first row RPO uses.
fn applyMds(state: *State) void {
    var out: State = undefined;
    for (0..width) |i| {
        var acc: u128 = 0;
        for (0..width) |j| {
            acc += @as(u128, state[j]) * @as(u128, consts.mds_row[(j + width - i) % width]);
        }
        out[i] = gl.reduce128(acc);
    }
    state.* = out;
}

fn addConstants(state: *State, ark: *const [width]gl.Fe) void {
    for (state, ark) |*s, k| s.* = gl.add(s.*, k);
}

/// One Rescue-XLIX round.
pub fn applyRound(state: *State, r: usize) void {
    gl.sboxLayer(width, state);
    applyMds(state);
    addConstants(state, &consts.ark1[r]);

    gl.sboxInvLayer(width, state);
    applyMds(state);
    addConstants(state, &consts.ark2[r]);
}

/// The full 7-round Rescue-XLIX permutation, in place.
pub fn permute(state: *State) void {
    for (0..rounds) |r| applyRound(state, r);
}

test "the MDS row is literally RPO's — only the round order differs" {
    const params = @import("params.zig");
    const rpo_row = params.mdsRow(params.Instance.bits128);
    try std.testing.expectEqualSlices(gl.Fe, &rpo_row, &consts.mds_row);
}

test "Rescue-XLIX and RPO are different permutations" {
    const perm = @import("perm.zig");
    const Rpo = perm.Permutation(@import("params.zig").Instance.bits128);

    var a: State = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    var b: Rpo.State = a;
    permute(&a);
    Rpo.permute(&b);
    for (a, b) |x, y| try std.testing.expect(x != y);
}
