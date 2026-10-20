// SPDX-License-Identifier: MIT

//! Dead-stack burn for the secret-touching public entry points of the TLS 1.3
//! server (`record.Protection.init` / `seal` / `open` so far). Each body runs
//! one frame down (`run`, a `never_inline` call), then the bytes that body
//! dirtied at that depth are zeroed. Copied from `tls13/src/burn.zig`
//! (`stack` and `run` identical in every module). `stackprobe_test.zig` goes
//! red when a body outgrows its burn.

/// Zero `n` bytes of stack below the caller.
pub noinline fn stack(comptime n: usize) void {
    // Volatile 16-byte vector stores (`secureZero` is a volatile byte memset,
    // ~3 B/ns without libc; this is ~50 B/ns, 2026-10-09). 16, not 32: with a
    // 32-byte vector LLVM raised the buffer's alignment to 32 for small burns
    // (n <= 2 KiB) and realigned the frame (`and $-32, %rsp`), leaving 32..63 bytes
    // between the buffer top and the saved frame pointer unzeroed -- a callee's
    // 32-byte scalar survived there (voprf stack probe, 2026-10-09; `align(16)` on
    // the buffer alone did not stop it). At 16 the frame needs no realignment and
    // the buffer ends at the saved frame pointer.
    const V = @Vector(2, u64);
    var buf: [n / @sizeOf(V)]V align(16) = undefined;
    const p: [*]align(16) volatile V = &buf;
    for (0..buf.len) |i| p[i] = @splat(0);
}

/// `f(args)` in a frame of its own, then `stack(n)` at the same depth.
/// `inline`, so the argument tuple lives in the caller's frame — it holds
/// only pointers and public values, never a secret by value.
pub inline fn run(comptime n: usize, comptime R: type, comptime f: anytype, args: anytype) R {
    const r: R = @call(.never_inline, f, args);
    stack(n);
    return r;
}

// Depths are the dirty stack of the unburned bodies in ReleaseFast, from
// `stackprobe_test.zig` (2026-10-20).

/// `Protection.init` / `initKeyIv`: the body's own frame is 0.2 KiB; the
/// HKDF-Expand-Label (`tls13`, 8 KiB burn) and the AES key expansion
/// (`aesgcm`, 8 KiB burn) below it clean up after themselves.
pub const init_burn = 1024;

/// `Protection.seal` / `open`, once per record: AES-GCM in place reaches
/// 1.2 / 1.4 KiB (AES-128 / AES-256, 32 B and 16 KiB records alike);
/// ChaCha20-Poly1305 burns its own (2–4 KiB). ~3x the deepest, ~80 ns of
/// zeroing per record.
pub const record_burn = 4 * 1024;
