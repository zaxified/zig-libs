// SPDX-License-Identifier: MIT

//! Constant-time helpers shared by the module.

const std = @import("std");

/// Mark `v` as defined for memcheck: a no-op unless the build has
/// `-fvalgrind`. Used ONLY on a value the API reveals anyway — an error
/// verdict on a secret's range, `r`/`s` of a published signature, the
/// RFC 6979 retry bit (probability < 2^-259 per signature) — so ctgrind keeps
/// measuring the secret instead of flagging the one branch every such API
/// must take. Each call site names which of these it is.
/// Optimization barrier: launder a value through an empty inline asm so LLVM
/// loses what it knows about it. Every mask built from a secret bit goes
/// through it, otherwise LLVM turns `(a & m) | (b & ~m)` / `a ^ ((a ^ b) & m)`
/// back into a select and lowers that to a conditional jump (ctgrind finding
/// in `Fe.cMov`, 2026-11-13). Same pattern as p256's `blackBox`; the
/// `@inComptime()` guard keeps it out of the comptime interpreter.
pub inline fn blackBox(x: u64) u64 {
    if (@inComptime()) return x;
    return asm volatile (""
        : [ret] "=r" (-> u64),
        : [x] "0" (x),
    );
}

pub inline fn declassify(v: anytype) void {
    std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(v));
}
