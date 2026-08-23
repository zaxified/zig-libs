// SPDX-License-Identifier: MIT

//! What a consumer minting key/nonce material does with `entropy`: draw
//! through `fill` and through the `SecureSource` → `std.Random` adapter, and
//! check the properties the module actually documents — NOT specific byte
//! values, since every byte comes straight from the OS RNG.
//!
//! `fill`'s only failure mode is `@panic` (there is no error channel by
//! design — see the module doc comment on why a `fillOrError` twin was
//! rejected), so there is no named error to catch on `fill` itself without
//! crashing this whole example, which would defeat the "exit non-zero on
//! failure, not abort" contract every other example here follows. What CAN
//! be named is the exact fault `fill` exists to turn into that panic:
//! `std.Io.failing` is std's own most extreme statement of "no entropy here",
//! and its `randomSecure` refuses with `error.EntropyUnavailable` — the one
//! error `fill`'s internal `switch` names. Checking that directly is checking
//! the premise `fill`'s abort rests on, without ever calling `fill` on it.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const entropy = @import("entropy");

pub fn main() !void {
    // A DebugAllocator that panics on leak makes this example a leak
    // detector too, even though `fill`/`SecureSource` hold no state and
    // allocate nothing themselves — the buffers below are ours.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // ── property 1: two draws differ (never a stuck source) ────────────────
    {
        var a: [32]u8 = undefined;
        var b: [32]u8 = undefined;
        entropy.fill(io, &a);
        entropy.fill(io, &b);
        std.debug.assert(!std.mem.eql(u8, &a, &b));
        std.debug.print("fill: two 32-byte draws differ\n", .{});
    }

    // ── property 2: the WHOLE buffer is written, not a prefix/suffix ───────
    // A sliding 16-byte window that never lands back on the sentinel is a
    // coverage check, not a statistical one (16 bytes all landing on one
    // chosen value by chance is 2^-128) — this is exactly how the module's
    // own SPEC.md frames it, and it is what caught a real short-fill defect
    // in this module's history (`SecureSource` writing nothing).
    {
        const sentinel: u8 = 0xa5;
        const buf = try gpa.alloc(u8, 4096);
        defer gpa.free(buf);
        @memset(buf, sentinel);
        entropy.fill(io, buf);

        var i: usize = 0;
        while (i + 16 <= buf.len) : (i += 1) {
            std.debug.assert(!std.mem.allEqual(u8, buf[i..][0..16], sentinel));
        }
        std.debug.print("fill: whole 4096-byte buffer overwritten, sliding-window check clean\n", .{});
    }

    // ── property 3: a zero-length draw is legal and still real (no skip) ───
    entropy.fill(io, &.{});
    std.debug.print("fill: zero-length buffer accepted\n", .{});

    // ── property 4: SecureSource routes std.Random draws through the same
    // fail-closed source, end to end (this is the exact adapter shape all
    // twelve bfv/tfhe key-generation call sites use) ───────────────────────
    {
        var src: entropy.SecureSource = .{ .io = io };
        const random = src.interface();

        const sentinel: u8 = 0x5a;
        var buf: [64]u8 = @splat(sentinel);
        random.bytes(&buf);
        var i: usize = 0;
        while (i + 16 <= buf.len) : (i += 1) {
            std.debug.assert(!std.mem.allEqual(u8, buf[i..][0..16], sentinel));
        }

        const x = random.int(u64);
        const y = random.int(u64);
        std.debug.assert(x != y);
        std.debug.print("SecureSource: std.Random.bytes fully overwritten, two int(u64) draws differ\n", .{});
    }

    // ── property 5, the fault `fill` exists to catch: `std.Io.failing`'s
    // `randomSecure` refuses by NAME. `fill` itself cannot be called on
    // `std.Io.failing` without a DIFFERENT panic (it does not implement
    // `swapCancelProtection`, which `fill` requires — see the module doc),
    // so this checks the underlying std contract directly instead: the one
    // fault `fill`'s internal switch turns into `unavailable_message`. ─────
    {
        var buf: [16]u8 = undefined;
        if (std.Io.failing.randomSecure(&buf)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.EntropyUnavailable => std.debug.print(
                "std.Io.failing.randomSecure: EntropyUnavailable (expected — the fault fill() turns into an abort)\n",
                .{},
            ),
            else => return err,
        }
    }

    // The panic message itself is public API worth pinning: it must name
    // its cause so whoever reads the crash knows what to check.
    std.debug.assert(std.mem.indexOf(u8, entropy.unavailable_message, "EntropyUnavailable") != null);
    std.debug.assert(std.mem.indexOf(u8, entropy.unavailable_message, "getrandom(2)") != null);
    std.debug.print("unavailable_message: names its cause\n", .{});
}
