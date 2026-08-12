// SPDX-License-Identifier: MIT

//! entropy — one blessed fail-closed entropy source for secret-bearing draws.
//!
//! ## The gap
//!
//! std 0.16 ships two entropy entry points on `std.Io` and they differ in
//! exactly the way that matters for key material:
//!
//! - `std.Io.random` is a CSPRNG **with a documented silent-degrade clause** —
//!   "The randomness is seeded by `randomSecure`, or a less secure mechanism
//!   upon failure" (`std/Io.zig`). The default implementation honours that
//!   literally: on `error.EntropyUnavailable` `std.Io.Threaded` seeds from
//!   `fallbackSeed`, which is a zeroed buffer plus an ASLR pointer, the pid
//!   and a clock reading. Measured on this host, 17 of the 32 seed bytes come
//!   out non-zero, the pid is in there in plaintext, and two bytes differ
//!   between consecutive calls. A key minted from that is not a key.
//! - `std.Io.randomSecure` is the fail-closed twin — "Does not have any
//!   fallback mechanisms; returns `error.EntropyUnavailable` if any problems
//!   occur." On Linux it is a bare `getrandom(2)` syscall (or `arc4random_buf`
//!   when libc is linked).
//!
//! The two are one letter apart at a call site and nothing in the type system
//! separates them. Worse, the only bridge std ships from `std.Io` to
//! `std.Random` — `std.Random.IoSource` — binds `io.random`, the degrading
//! one, and there is **no** std-provided bridge from `randomSecure` to
//! anything. So the safe call is the one you have to know to reach for, and
//! for any API whose signature cannot return an error it is not reachable at
//! all.
//!
//! This module is that missing binding, and nothing else. It implements no
//! generator, holds no state, and adds no algorithm: every byte it returns
//! came out of `std.Io.randomSecure` on this call.
//!
//! ## The trade-off, stated plainly
//!
//! `fill` **`@panic`s** when entropy is unavailable, which aborts the host
//! process. A library taking down its host is a serious thing to do and it is
//! not the default posture anywhere else in this repo. It is the right call
//! here for one narrow reason: the alternative on a `void`-returning draw is
//! not "degrade a little", it is to hand back a buffer the caller will turn
//! into a long-lived secret — a key, a nonce, a session id — with no
//! indication anything went wrong. A loud abort is recoverable operationally
//! (the operator sees it, fixes the sandbox policy, restarts). A key minted
//! from a pid and a clock is not recoverable at all, and nothing downstream
//! will ever notice.
//!
//! **So: if your signature can return an error, do not use this module.**
//! Call `try io.randomSecure(buf)` directly and let the caller decide. `fill`
//! exists for the call sites that genuinely have no error channel —
//! `std.Random` adapters, constructors, `keyGen`-shaped APIs that return a
//! value. It is the floor, not the recommendation.
//!
//! The same posture already exists in this repo, hand-rolled: `ssh`'s and
//! `bulletproofs`' `fillRandom` each loop on `getrandom(2)` and
//! `@panic("getrandom failed")`. Those two stay as they are (they are
//! deliberately `platform = .linux` and predate this module); what is new is
//! that a portable, `platform = .any` version of the same decision now exists
//! and does not have to be written a third time.
//!
//! ## Why there is no `fillOrError`
//!
//! A `try`-shaped twin was considered and rejected on a concrete point, not on
//! taste. `std.Io.RandomSecureError` is `error{EntropyUnavailable} ||
//! std.Io.Cancelable`, i.e. it also carries `error.Canceled`. So a
//! `fillOrError(io, buf) error{EntropyUnavailable}!void` would have to report
//! a **cancellation** as an entropy failure, which is a false statement about
//! what happened; and the honest signature — one returning the full
//! `std.Io.RandomSecureError` — is `io.randomSecure` with a different name and
//! an extra import. Callers that can return an error already have the right
//! function and it is in std. Nothing here improves on it.
//!
//! That same error set is why `fill` does not collapse both failures into one
//! message: see `unavailable_message` / `canceled_message`, which say
//! different things because they mean different things.

const std = @import("std");

pub const meta = .{
    .platform = .any, // no syscall of its own; `std.Io` carries the OS-specific half
    .role = .util,
    // No state whatsoever — `fill` is a pure function of its arguments, and
    // `std.Io.randomSecure` is documented Threadsafe, so concurrent calls
    // against one `std.Io` are fine. Nothing here needs synchronizing, which
    // is why this is `.reentrant` and not `.threadsafe`.
    .concurrency = .reentrant,
    // Nothing is modelled after anything: this module is a binding over
    // `std.Io.randomSecure`, not an implementation of anything. The
    // abort-rather-than-return-weak-entropy posture it takes is the one
    // `ssh/src/transport.zig` and `bulletproofs/src/rangeproof.zig` already
    // take against raw `getrandom(2)`, in this repo, verifiably.
    .model_after = null,
    .deps = .{}, // std only
};

// ── public API ──────────────────────────────────────────────────────────────

/// The message `fill` aborts with when the OS has no entropy for us.
///
/// It aborts the host process, so it is written for whoever reads the crash:
/// what was refused, what was NOT produced, and where to look.
pub const unavailable_message =
    "entropy.fill: std.Io.randomSecure returned error.EntropyUnavailable — " ++
    "the OS entropy source is unreachable, so NO secret was produced and this " ++
    "process aborted rather than mint one from a weak seed. Check whether a " ++
    "sandbox policy (seccomp/Landlock/container profile) is blocking getrandom(2), " ++
    "and on a libc build whether arc4random_buf is reachable.";

/// The message `fill` aborts with when the draw was cancelled.
///
/// A different fault entirely from the one above — nothing is wrong with the
/// machine's entropy; the caller's own `std.Io` cancelled an operation that had
/// no error channel to report it on.
pub const canceled_message =
    "entropy.fill: std.Io.randomSecure returned error.Canceled — a secret-bearing " ++
    "entropy draw was cancelled mid-flight. entropy.fill returns void and has " ++
    "nowhere to report that, so it aborts. If cancellation is expected at this " ++
    "call site, call std.Io.randomSecure directly from a function that can return " ++
    "an error.";

/// Fail-closed entropy for secret-bearing material. Fills `buf` from
/// `std.Io.randomSecure`, or aborts the process.
///
/// Use this **only** where the signature cannot return an error. Anywhere that
/// can, `try io.randomSecure(buf)` is better in every way: same source, and the
/// caller gets to decide what an entropy failure means for them. See this
/// module's doc comment for why there is deliberately no error-returning twin
/// here.
///
/// Never call this for anything that is not a secret. Jitter, a retry delay, a
/// load-balancing tiebreak, a test fixture, a hash-table seed: those are what
/// `io.random` is for, and paying a syscall — let alone a process abort — for
/// them is wrong.
///
/// A zero-length `buf` is legal and still makes the call (so a caller cannot
/// accidentally treat "no entropy needed" as "entropy is fine here").
pub fn fill(io: std.Io, buf: []u8) void {
    io.randomSecure(buf) catch |err| switch (err) {
        error.EntropyUnavailable => @panic(unavailable_message),
        error.Canceled => @panic(canceled_message),
    };
}

/// A `std.Random` bound to `fill`, i.e. to `randomSecure` — the fail-closed
/// counterpart of `std.Random.IoSource`, which binds the degrading
/// `io.random`.
///
/// This exists for one concrete shape that is already all over this repo: a
/// module whose public entry point takes `io: std.Io` but whose internals are
/// written against `std.Random`, so the entry point adapts one to the other
/// and immediately loses the distinction. Twelve such call sites exist today
/// —
///
/// ```zig
/// // modules/bfv/src/bfv.zig:674 (keyGen), :711, :1010
/// // modules/tfhe/src/tfhe.zig:284, :312, :352, :400, :428, :481, :515, :542, :569
/// var src: std.Random.IoSource = .{ .io = io };
/// return self.keyGenForTest(src.interface());
/// ```
///
/// — every one of them drawing a secret key or its noise, and both modules'
/// own doc comments name failing closed via `randomSecure` as an open
/// decision they have not been able to act on. Swapping `std.Random.IoSource`
/// for this type is the whole change at each site. Whether those modules take
/// it is their owners' call; the binding they would need is here rather than
/// twelve copies of it there.
///
/// The `std.Random` vtable's `fillFn` returns `void`, so this inherits `fill`'s
/// abort semantics by construction — there is no error channel to add.
///
/// Not a general-purpose `std.Random`: every draw is a syscall, including the
/// single bytes `std.Random.int`/`uintLessThan` take. That is correct for key
/// and nonce material and wasteful for anything else.
pub const SecureSource = struct {
    io: std.Io,

    pub fn interface(self: *const SecureSource) std.Random {
        return .{
            .ptr = @constCast(self),
            .fillFn = fillFn,
        };
    }

    fn fillFn(ptr: *anyopaque, buffer: []u8) void {
        const self: *const SecureSource = @ptrCast(@alignCast(ptr));
        fill(self.io, buffer);
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A `std.Io` that counts which of the two entropy vtable slots was called,
/// then delegates to a real one.
///
/// The whole vtable is copied from the inner `std.Io` and exactly two entries
/// are replaced, so this stays a fully working `std.Io` (and keeps working if
/// std grows more vtable entries) while making the choice between `random` and
/// `randomSecure` directly observable. `userdata` becomes the probe, which is
/// why the overrides have to carry the inner `std.Io` to delegate through.
const CountingIo = struct {
    inner: std.Io,
    vtable: std.Io.VTable = undefined,
    random_calls: usize = 0,
    secure_calls: usize = 0,

    fn io(self: *CountingIo) std.Io {
        self.vtable = self.inner.vtable.*;
        self.vtable.random = onRandom;
        self.vtable.randomSecure = onRandomSecure;
        return .{ .userdata = self, .vtable = &self.vtable };
    }

    fn onRandom(userdata: ?*anyopaque, buffer: []u8) void {
        const self: *CountingIo = @ptrCast(@alignCast(userdata.?));
        self.random_calls += 1;
        self.inner.random(buffer);
    }

    fn onRandomSecure(userdata: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
        const self: *CountingIo = @ptrCast(@alignCast(userdata.?));
        self.secure_calls += 1;
        return self.inner.randomSecure(buffer);
    }
};

// THE LOAD-BEARING TEST. Everything else here would stay green if `fill` were
// "simplified" to `io.random(buf)` — bytes out of `io.random` are random, so
// difference-across-calls, whole-buffer-coverage and not-all-zero all pass
// under either implementation. This one does not: it observes which vtable
// slot the call actually went to.
test "fill draws from randomSecure and never from random" {
    var probe: CountingIo = .{ .inner = testing.io };
    const io = probe.io();

    var buf: [32]u8 = undefined;
    fill(io, &buf);

    try testing.expectEqual(@as(usize, 1), probe.secure_calls);
    try testing.expectEqual(@as(usize, 0), probe.random_calls);
}

// The same distinction for the `std.Random` adapter, which has its own way of
// going wrong: `SecureSource` collapsing back into `std.Random.IoSource` is a
// one-word edit and no output-shaped test would see it.
test "SecureSource routes every draw through randomSecure" {
    var probe: CountingIo = .{ .inner = testing.io };
    var src: SecureSource = .{ .io = probe.io() };
    const random = src.interface();

    var buf: [16]u8 = undefined;
    random.bytes(&buf);
    _ = random.int(u64);

    try testing.expectEqual(@as(usize, 2), probe.secure_calls);
    try testing.expectEqual(@as(usize, 0), probe.random_calls);
}

// Why the distinction above is worth a syscall, pinned against std itself
// rather than asserted in prose: `std.Io.failing` is a std-provided `Io` whose
// `random` hands back a buffer of ZEROS and whose `randomSecure` refuses. That
// is the degrade the module doc describes, in the most extreme form std ships,
// and it is what `fill` turns into an abort. If std ever changes either half of
// this contract, this test says so.
test "std.Io.failing: random yields zeros where randomSecure refuses" {
    var buf: [64]u8 = @splat(0xa5);
    std.Io.failing.random(&buf);
    try testing.expect(std.mem.allEqual(u8, &buf, 0));

    try testing.expectError(error.EntropyUnavailable, std.Io.failing.randomSecure(&buf));
}

test "fill yields different bytes across calls" {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    fill(testing.io, &a);
    fill(testing.io, &b);
    try testing.expect(!std.mem.eql(u8, &a, &b));
}

test "fill writes the whole buffer, including its last byte" {
    const sentinel: u8 = 0xa5;
    var buf: [4096]u8 = @splat(sentinel);
    fill(testing.io, &buf);

    // A 16-byte window still holding the sentinel means those 16 bytes were
    // not written: 16 random bytes all landing on one chosen value is 2^-128,
    // so this is a coverage assertion, not a statistical one. Sliding the
    // window over the whole buffer catches a short fill anywhere in it,
    // including the classic off-by-one at the tail.
    var i: usize = 0;
    while (i + 16 <= buf.len) : (i += 1) {
        try testing.expect(!std.mem.allEqual(u8, buf[i..][0..16], sentinel));
    }
}

test "fill accepts a zero-length buffer" {
    var buf: [0]u8 = undefined;
    fill(testing.io, &buf);

    // And it still makes the call — a zero-length draw is not quietly skipped,
    // so a caller cannot read "no bytes needed" as "entropy works here".
    var probe: CountingIo = .{ .inner = testing.io };
    fill(probe.io(), &buf);
    try testing.expectEqual(@as(usize, 1), probe.secure_calls);
}

test "fill handles a large buffer in one call" {
    const buf = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(buf);
    @memset(buf, 0);

    var probe: CountingIo = .{ .inner = testing.io };
    fill(probe.io(), buf);

    // One call, not a chunked loop: short reads are `std.Io`'s problem, and
    // pretending otherwise here would mean this module has a retry policy.
    try testing.expectEqual(@as(usize, 1), probe.secure_calls);
    try testing.expect(!std.mem.allEqual(u8, buf[buf.len - 16 ..], 0));
}

// The abort paths themselves have no in-process test and cannot have one: Zig
// has no catchable panic, so observing `@panic` needs a child process, and a
// module test that re-execs the test binary buys a fork per run to assert a
// two-line `catch`. What IS pinned is everything that decides whether those
// panics are reachable and correct — that `fill` calls `randomSecure` (above),
// and that both arms of `std.Io.RandomSecureError` are handled with distinct
// messages (below; the switch is exhaustive, so std adding an error member
// breaks the build rather than silently folding into one of these).
test "the two abort messages are distinct and each names its cause" {
    try testing.expect(!std.mem.eql(u8, unavailable_message, canceled_message));
    try testing.expect(std.mem.indexOf(u8, unavailable_message, "EntropyUnavailable") != null);
    try testing.expect(std.mem.indexOf(u8, canceled_message, "Canceled") != null);
}
