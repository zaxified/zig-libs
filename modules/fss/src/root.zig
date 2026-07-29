// SPDX-License-Identifier: MIT

//! fss — Function Secret Sharing: a 2-party single-point Distributed Point
//! Function (DPF) via the Boyle–Gilboa–Ishai optimized tree construction
//! (ACM CCS 2016). Secret-shares a point function `f_{α,β}(x) = β if x==α
//! else 0` into two compact keys `(k0,k1)` such that
//! `Eval(0,k0,x) + Eval(1,k1,x) == f_{α,β}(x)` in `Z_{2^{8L}}` for all `x`,
//! while each key alone hides `(α,β)`. This is the primitive under private
//! analytics (Prio/Poplar), metadata-private messaging (Riposte), and
//! 2-server PIR.
//!
//! **Status: Phase-1 COMPLETE.** The PRG, output group, key types + codec,
//! full-domain checker, and the entire verification harness are REAL and
//! tested — and the Fable-irreducible core (the correction-word construction
//! `dpf.Dpf(...).genWithSeeds` + its matching traversal `.eval`) is
//! implemented (`gate.core_implemented = true`): full-domain reconstruction
//! and the byte-exact KAT vs the independent reference vectors all execute.
//! See `gate.zig`, `SPEC.md`, and `dpf.zig`'s module doc.
//!
//! ## Entry points
//!   - `Dpf(n, L)` — a DPF over domain `{0,1}^n`, output group `Z_{2^{8L}}`.
//!     `.genWithSeeds(α, β, s0, s1)` → `[2]Key`; `.eval(b, key, x)`;
//!     `.evalAll(b, key, out)`; `.firstMismatch(...)` (verification oracle).
//!   - `Mpf(n, L, k)` — the **multi-point** scheme: shares of a function
//!     non-zero at `k` chosen points. `k` independent `Dpf` instances summed —
//!     no failure probability, no new cryptographic surface, key size linear in
//!     `k`; see `mpf.zig` for the trade-off against the cuckoo/batch-code
//!     constructions and for what would justify revisiting it.
//!     `.genWithSeeds(αs, βs, s0s, s1s)`, `.eval` (the summed multi-point
//!     value) and `.evalEach` (the `k` components, unsummed — what a consumer
//!     wanting `k` *separate* results needs).
//!   - `prg` / `group` — the mechanical building blocks (both usable alone).
//!
//! Room to grow (all OUT of Phase 1, see SPEC.md): a `dcf.zig` Distributed
//! Comparison Function and a fixed-key-AES PRG. The 2-server PIR layer landed
//! as its own module (`pir`), and multi-point FSS — listed there as
//! "General FSS" — is `mpf.zig`.

const std = @import("std");

pub const meta = .{
    .platform = .any, // pure computation — no threads / OS / libc
    .role = .util,
    .concurrency = .reentrant, // no shared state; caller supplies all inputs
    .model_after = "Boyle-Gilboa-Ishai DPF (Function Secret Sharing: Improvements and Extensions, CCS 2016)",
    .deps = .{}, // std-only (std.crypto SHA-256)
};

pub const gate = @import("gate.zig");
pub const prg = @import("prg.zig");
pub const group = @import("group.zig");

const dpf = @import("dpf.zig");
/// `Dpf(n, L)` — a 2-party single-point DPF over `{0,1}^n` with output group
/// `Z_{2^{8L}}`. See `dpf.zig`.
pub const Dpf = dpf.Dpf;

const mpf = @import("mpf.zig");
/// `Mpf(n, L, k)` — a 2-party `k`-point FSS scheme over `{0,1}^n`, built as
/// `k` independent `Dpf` instances summed in the output group. See `mpf.zig`.
pub const Mpf = mpf.Mpf;
/// The one way `Mpf.genWithSeeds` can fail (`error.SeedReuse`). See `mpf.zig`.
pub const GenError = mpf.GenError;

pub const kat_vectors = @import("kat_vectors.zig");

// Pull every submodule's tests into the test binary (CONVENTIONS.md §6
// dark-tests rule: a bare re-export does NOT pull a file's tests in).
test {
    std.testing.refAllDecls(@This());
    _ = prg;
    _ = group;
    _ = dpf;
    _ = mpf;
    _ = kat_vectors;
    _ = @import("kat_test.zig");
    _ = @import("mpf_test.zig");
}

test "meta.model_after names the BGI DPF construction" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "DPF") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "Boyle") != null);
}
