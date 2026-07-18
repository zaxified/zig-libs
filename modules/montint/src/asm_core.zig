// SPDX-License-Identifier: MIT

//! asm_core — the GATED irreducible x86-64 core (SCAFFOLD stub).
//!
//! This is the one function this scaffold intentionally leaves for a Fable
//! agent: the hand-written `MULX/ADCX/ADOX` dual-carry-chain CIOS Montgomery
//! multiply. Everything else in the module (the portable CIOS oracle, to/from
//! Montgomery, add/sub, windowed modexp, and the whole verification + bench
//! harness) is real and tested. See `gate.zig` for the cut-line and
//! `SPEC.md` for the exact algorithm + the Zig-inline-asm ABI/clobber notes.
//!
//! Signature contract (do NOT change without updating `montint.zig`'s dispatch
//! and the differential harness): compute `z = a·b·R⁻¹ mod m` where all of
//! `z,a,b,m` are `n`-limb little-endian **full 2^64** limbs (`n = m.len`),
//! `n0inv = -m[0]⁻¹ mod 2^64`, and the inputs satisfy `a,b < m`. The result
//! must be fully reduced (`z < m`) and byte-for-byte identical to the portable
//! `montMulCios` in `montint.zig` — that is what the asm-vs-portable
//! differential test enforces once `gate.asm_core_implemented` is `true`.

const std = @import("std");
const builtin = @import("builtin");

/// True at comptime iff this target can host the amd64 core (x86-64 with the
/// ADX + BMI2 feature flags that supply `ADCX/ADOX` and `MULX`). On every other
/// target the dispatch in `montint.zig` stays on the portable path forever.
pub const supported = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .adx) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2);

/// GATED. `z = a·b·R⁻¹ mod m` over `n = m.len` full 2^64 limbs.
///
/// STUB — the Fable agent replaces the body with the `MULX/ADCX/ADOX`
/// dual-carry-chain CIOS inner loop. The signature is final; only the body
/// changes. It is never reached at runtime while `gate.asm_core_implemented`
/// is `false` (the dispatcher routes to the portable oracle), so this `@panic`
/// is a compile-time-visible marker, not a live code path.
pub fn montMul(z: []u64, a: []const u64, b: []const u64, m: []const u64, n0inv: u64) void {
    _ = z;
    _ = a;
    _ = b;
    _ = m;
    _ = n0inv;
    @panic("TODO(fable/core): x86-64 MULX/ADCX/ADOX dual-carry-chain CIOS Montgomery multiply");
}
