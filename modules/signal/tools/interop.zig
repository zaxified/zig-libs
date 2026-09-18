// SPDX-License-Identifier: MIT

//! Re-takes PQXDH's KDF-chain anchor from its independent implementation.
//!
//! THIS IS A PROGRAM, NOT A TEST. It is built and run by
//! `zig build interop-signal`, compiled (never run) by
//! `zig build check-interop`, and is not part of `test-signal` or of the
//! `signal` module.
//!
//! Signal publishes no byte-exact PQXDH vectors, so the anchor for
//! `SK = HKDF(F || DH1..DH4 || SS)` is a second implementation of the same
//! arithmetic, `tools/pqxdh-kdf-check.py`, written from Python's
//! `hmac`/`hashlib` alone. The chain is split the way every interop program
//! here splits it:
//!
//!   - this program asks the Python implementation to re-derive every vector
//!     and diff it against the pin in `src/interop_vectors.zig`;
//!   - `test-signal` compares the module's `deriveSharedSecret` against that
//!     same pin, hermetically, on every lane.
//!
//! So a module change that moves `SK` turns `test-signal` red, and a pin that
//! drifted from the independent derivation turns this program red. Until
//! 2026-09-18 the script lived in `scripts/gen/` and nothing ran it: the pin was
//! compared against the module on every push and against its own source never.
//!
//! Usage, from the repository root:
//!
//!   zig build interop-signal
//!
//! Needs `python3` (standard library only). It does not skip: an absent
//! interpreter is a failure, because running this program IS the request to
//! consult the second implementation.

const std = @import("std");

const driver = "modules/signal/tools/pqxdh-kdf-check.py";

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.skip();
    if (args.next()) |a| {
        std.debug.print("unknown argument '{s}' -- usage: zig build interop-signal\n", .{a});
        return 2;
    }

    var child = std.process.spawn(io, .{
        .argv = &.{ "python3", driver, "--check" },
        .stdin = .close,
        .stdout = .inherit,
        .stderr = .inherit,
    }) catch |e| {
        std.debug.print(
            \\could not run '{s}': {s}
            \\
            \\This program needs python3, and it must be run from the repository
            \\root (`zig build interop-signal`).
            \\
        , .{ driver, @errorName(e) });
        return 2;
    };
    const term = try child.wait(io);
    return switch (term) {
        .exited => |code| code,
        else => 1,
    };
}
