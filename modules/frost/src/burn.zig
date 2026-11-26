// SPDX-License-Identifier: MIT
//! The dead-stack burn of `frost`'s secret-touching entry points (`root.zig`
//! signing rounds, `dkg.zig`). Internal: not exported from `root.zig`.

/// Audit 2026-10-08 (HIGH). `generateNonces`, `round1Commit` and
/// `round2Sign` had no stack burn: measured with `stackprobe_test.zig`
/// (ReleaseFast), each left the signing share and/or the secret nonces on
/// the dead stack — and a nonce next to the published signature share is
/// `lambda_i·sk_i`, i.e. the share. Same fix as `bip340.sign`: each runs its
/// work one `noinline` frame down (secrets passed on by value — taking a
/// parameter's address makes Zig copy it into the public function's own
/// frame, above the burn, as bip340's review R1 measured) and `stack_burn` bytes at that depth
/// are zeroed after it returns. `stackprobe_test.zig` asserts zero residue
/// and prints how deep each call dirtied the stack (19 KB for `round2Sign`).
pub const stack_burn = 32 * 1024;

/// `noinline` is load-bearing (as `bip340`'s `burnSignStack`): inlined, the
/// buffer lands in the caller's frame, above the region to clear.
/// Volatile stores keep the dead store.
pub noinline fn burnStack() void {
    // Volatile 16-byte vector stores (`secureZero` is a volatile byte memset,
    // ~3 B/ns without libc; this is ~50 B/ns, 2026-10-09). 16, not 32: with a
    // 32-byte vector LLVM raised the buffer's alignment to 32 for small burns
    // (n <= 2 KiB) and realigned the frame (`and $-32, %rsp`), leaving 32..63 bytes
    // between the buffer top and the saved frame pointer unzeroed -- a callee's
    // 32-byte scalar survived there (voprf stack probe, 2026-10-09; `align(16)` on
    // the buffer alone did not stop it). At 16 the frame needs no realignment and
    // the buffer ends at the saved frame pointer.
    const V = @Vector(2, u64);
    var buf: [stack_burn / @sizeOf(V)]V align(16) = undefined;
    const p: [*]align(16) volatile V = &buf;
    for (0..buf.len) |i| p[i] = @splat(0);
}

/// The burn of `dkg.zig`'s three parts. `stack_burn` (32 KiB) is too shallow
/// for them: measured with `stackprobe_test.zig` (ReleaseFast, direct-region
/// engine, 2026-11-25) the dirty stack below `dkg.part1` / `part2` / `part3`
/// reaches 33 087 / 32 927 / 36 047 B (the public-point multiplications of the
/// proof-of-knowledge and vss checks, plus the Horner evaluation), and the
/// shared residue rule found bytes below the 32 KiB burn after `part3`. The
/// burn has to cover the call's depth, so it is 64 KiB here; the signing paths
/// (measured 19 KB) keep `stack_burn`.
pub const dkg_burn = 64 * 1024;

/// `burnStack` with `dkg_burn` bytes; the same body (see there for why
/// `noinline`, the volatile 16-byte stores and the alignment).
pub noinline fn burnStackDkg() void {
    const V = @Vector(2, u64);
    var buf: [dkg_burn / @sizeOf(V)]V align(16) = undefined;
    const p: [*]align(16) volatile V = &buf;
    for (0..buf.len) |i| p[i] = @splat(0);
}
