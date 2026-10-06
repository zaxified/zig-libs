// SPDX-License-Identifier: MIT

//! `std.Io.fiber` with two changes on aarch64: the context switch does not
//! list `ffr` (the SVE first-fault register) as clobbered, and it saves and
//! restores `x18` and `x30` itself instead of trusting the clobber list.
//!
//! ⛔ A `std` issue, not ours: on an SVE CPU (the arm64 CI runners —
//! reproduced locally with `-mcpu=neoverse_n2`/`neoverse_v1`, not with
//! `neoverse_n1`) LLVM warns "inline asm clobber list contains reserved
//! registers: FFR" for `std.Io.fiber.contextSwitch`, and every lane treats a
//! warning on stderr as a failure. FFR is reserved, so naming it buys
//! nothing (LLVM says so itself: it "may not be preserved across the asm
//! statement"). Zig upstream does not take agent reports, so the switch is
//! copied here with that one line dropped; every other architecture uses
//! `std`'s unchanged. Delete this file once `std` drops `.ffr` and preserves
//! `x18`/`x30` (below).
//!
//! ⛔ Also `std`'s: a value live across the switch in `x18` or `x30` came back
//! as whatever the other fiber left there. `x18` is not in `std`'s clobber
//! list (on Linux it is an ordinary temporary LLVM allocates), and `x30` is,
//! but a ReleaseSafe build for an SVE CPU still kept the current `*Fiber` in
//! `x30` across the asm (llvm-objdump of `maybeYield`). Seen as a Bus error in
//! `example-simio` on the arm64 CI runner (tag 2026-10-06 matrix) and as a
//! wild `Host` pointer after `maybeYield` under qemu-aarch64 (`cortex-a72`
//! for x18, `neoverse-n2` for x30). The asm now pushes both before it saves
//! `sp` and pops them where it resumes, so neither depends on the clobber
//! list; a new fiber starts at its own entry and pops nothing.

const std = @import("std");
const builtin = @import("builtin");
const std_fiber = std.Io.fiber;

pub const supported = std_fiber.supported;
pub const Context = std_fiber.Context;
pub const Switch = std_fiber.Switch;

/// Fills `s.old` with the current cpu state, and restores the cpu state
/// stored in `s.new` — `std.Io.fiber.contextSwitch`, minus `ffr` on aarch64,
/// plus a push/pop of `x18` and `x30` around the switch.
pub inline fn contextSwitch(s: *const Switch) *const Switch {
    if (builtin.cpu.arch != .aarch64) return std_fiber.contextSwitch(s);
    return asm volatile (
        \\ stp x18, x30, [sp, #-16]!
        \\ ldp x0, x2, [x1]
        \\ ldr x3, [x2, #16]
        \\ mov x4, sp
        \\ stp x4, fp, [x0]
        \\ adr x5, 0f
        \\ ldp x4, fp, [x2]
        \\ str x5, [x0, #16]
        \\ mov sp, x4
        \\ br x3
        \\0:
        \\ ldp x18, x30, [sp], #16
        : [received_message] "={x1}" (-> *const Switch),
        : [message_to_send] "{x1}" (s),
        : .{
          .x0 = true,
          .x1 = true,
          .x2 = true,
          .x3 = true,
          .x4 = true,
          .x5 = true,
          .x6 = true,
          .x7 = true,
          .x8 = true,
          .x9 = true,
          .x10 = true,
          .x11 = true,
          .x12 = true,
          .x13 = true,
          .x14 = true,
          .x15 = true,
          .x16 = true,
          .x17 = true,
          .x19 = true,
          .x20 = true,
          .x21 = true,
          .x22 = true,
          .x23 = true,
          .x24 = true,
          .x25 = true,
          .x26 = true,
          .x27 = true,
          .x28 = true,
          .x30 = true,
          .z0 = true,
          .z1 = true,
          .z2 = true,
          .z3 = true,
          .z4 = true,
          .z5 = true,
          .z6 = true,
          .z7 = true,
          .z8 = true,
          .z9 = true,
          .z10 = true,
          .z11 = true,
          .z12 = true,
          .z13 = true,
          .z14 = true,
          .z15 = true,
          .z16 = true,
          .z17 = true,
          .z18 = true,
          .z19 = true,
          .z20 = true,
          .z21 = true,
          .z22 = true,
          .z23 = true,
          .z24 = true,
          .z25 = true,
          .z26 = true,
          .z27 = true,
          .z28 = true,
          .z29 = true,
          .z30 = true,
          .z31 = true,
          .p0 = true,
          .p1 = true,
          .p2 = true,
          .p3 = true,
          .p4 = true,
          .p5 = true,
          .p6 = true,
          .p7 = true,
          .p8 = true,
          .p9 = true,
          .p10 = true,
          .p11 = true,
          .p12 = true,
          .p13 = true,
          .p14 = true,
          .p15 = true,
          .fpcr = true,
          .fpsr = true,
          .memory = true,
        });
}
