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
//! ## Cancellation is blocked for the duration of the draw
//!
//! `std.Io.RandomSecureError` is `error{EntropyUnavailable} ||
//! std.Io.Cancelable`, so `randomSecure` can also return `error.Canceled` —
//! and that is **routine control flow**, not an entropy fault: a cancel already
//! outstanding on the task makes the call fail before the entropy source is
//! touched at all, and an EINTR mid-draw routes to the same error. A request
//! timeout on a peer-driven path is enough to produce it.
//!
//! Aborting on that would be a library killing its host over a normal timeout,
//! so `fill` does what std does at the identical site: it blocks cancellation
//! around the draw (`std.Io.swapCancelProtection(.blocked)`, restored by
//! `defer`) and the `error.Canceled` arm becomes `unreachable`. Compare
//! `std.Io.Threaded`'s `randomMainThread`, which wraps its own `randomSecure`
//! call the same way; `std.Io.swapCancelProtection`'s doc comment carries this
//! exact idiom as its worked example.
//!
//! What that costs, stated plainly: a cancel aimed at a task that is inside
//! `fill` is not observed until the draw returns. On a healthy host that is one
//! non-blocking `getrandom(2)`. It is *not* bounded on a machine whose entropy
//! pool is not yet initialised (early boot, a fresh VM), where `getrandom(2)`
//! with `flags = 0` blocks until it is — so do not `fill` a buffer larger than
//! the secret you are about to use, and do not use `fill` as a bulk random-byte
//! source. The alternative on that same path is not "cancel promptly", it is
//! "abort the process", which is strictly worse.
//!
//! One consequence worth knowing: `fill` now calls `swapCancelProtection` on
//! the `std.Io` it is handed, so it requires an implementation that supports
//! it. `std.Io.failing` does **not** — every cancellation slot on it is
//! `unreachable` — so `fill(std.Io.failing, buf)` panics with "reached
//! unreachable code" from inside std rather than with `unavailable_message`.
//! That `Io` simulates a machine with no `Io` operations at all and a draw on
//! it was already fatal; the loss is the diagnostic text, on a path no
//! production consumer takes. `std.Io.Threaded`, `Evented`, `Uring` and
//! `Dispatch` all implement the slot.
//!
//! ## Why there is no `fillOrError`
//!
//! A `try`-shaped twin was considered and rejected. The honest signature — one
//! returning the full `std.Io.RandomSecureError` — is `io.randomSecure` with a
//! different name and an extra import. A narrowed
//! `fillOrError(io, buf) error{EntropyUnavailable}!void` would now be
//! *truthful* (cancellation is blocked, so `error.Canceled` cannot come out),
//! but it would be imposing this module's cancellation policy on a caller who
//! by construction has an error channel and can make that choice itself.
//! Callers that can return an error already have the right function and it is
//! in std. Nothing here improves on it.

const std = @import("std");

pub const meta = .{
    .targets = .{.linux64},
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
///
/// This is the only message `fill` can abort with. There used to be a second
/// one for `error.Canceled`; that arm is `unreachable` now that the draw runs
/// under blocked cancellation, so the constant is gone.
pub const unavailable_message =
    "entropy.fill: std.Io.randomSecure returned error.EntropyUnavailable — " ++
    "the OS entropy source is unreachable, so NO secret was produced and this " ++
    "process aborted rather than mint one from a weak seed. Check whether a " ++
    "sandbox policy (seccomp/Landlock/container profile) is blocking getrandom(2), " ++
    "and on a libc build whether arc4random_buf is reachable.";

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
///
/// Cancellation is blocked across the draw, so a cancel aimed at the calling
/// task is observed after `fill` returns rather than aborting the process. That
/// means `io` must implement `swapCancelProtection`; `std.Io.failing` does not.
/// See the module doc comment for both halves of that trade.
pub fn fill(io: std.Io, buf: []u8) void {
    // A half-drawn secret is not a thing we can hand back, and `fill` has no
    // error channel to report a cancellation on. Blocking cancellation for the
    // length of one draw is what std does at the same site
    // (`std.Io.Threaded.randomMainThread`) and is the documented use of this
    // API. It is what reduces `error.Canceled` below to `unreachable`.
    const prev = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(prev);

    io.randomSecure(buf) catch |err| switch (err) {
        error.EntropyUnavailable => @panic(unavailable_message),
        // Unreachable because of the two lines above, not because it cannot
        // happen: `randomSecure` returns this whenever a non-blocked cancel is
        // outstanding. Delete the protection and this becomes live again.
        error.Canceled => unreachable,
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
/// ## The ceiling: `interface()` erases the property, so guard the twin
///
/// What comes back from `interface()` is a plain `std.Random`. It is
/// structurally indistinguishable from `DefaultPrng.init(0).random()` at every
/// downstream signature, and nothing in the type system carries the
/// fail-closedness past this point. So swapping `std.Random.IoSource` for this
/// type is only **half** the change at a call site. The other half is that the
/// `std.Random`-taking twin the swap exists to feed must not be reachable from
/// production code, and the way this repo says that is a comptime guard on the
/// twin itself:
///
/// ```zig
/// // The production entry point: takes `std.Io`, adapts it here, and the
/// // caller cannot substitute the source.
/// pub fn lweKeyGen(comptime dim: usize, io: std.Io) LweKey(dim) {
///     var src: SecureSource = .{ .io = io };
///     return lweKeyGenForTest(dim, src.interface());
/// }
///
/// // Its `std.Random`-taking twin, which the swap above exists to feed. The
/// // `ForTest` name warns; this is what makes it true.
/// pub fn lweKeyGenForTest(comptime dim: usize, random: std.Random) LweKey(dim) {
///     comptime if (!builtin.is_test) @compileError(
///         "this is a TEST-ONLY entry point: it takes a caller-supplied std.Random. " ++
///             "Production code must use the std.Io entry point of the same name, " ++
///             "which cannot be handed a seeded PRNG.",
///     );
///     ...
/// }
/// ```
///
/// All twelve existing sites carry that guard — `modules/tfhe/src/tfhe.zig`
/// (`lweKeyGen` / `lweKeyGenForTest`) is the worked example, verbatim above —
/// so this is a documentation requirement, not an outstanding defect. A
/// thirteenth consumer that follows the paragraph above without adding the
/// guard has widened a `std.Random`-shaped hole into a secret-key path.
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

/// A `std.Io` that observes the vtable slots `fill` uses, then delegates each
/// one to a real `std.Io`.
///
/// ## What this is NOT, and read this before adding a call to `fill`
///
/// It is **not** a fully working `std.Io`, and it cannot be made into one. It
/// copies the inner implementation's whole vtable and then sets
/// `userdata = self`, because the overriding slots have to find the probe. Every
/// slot that is *not* overridden therefore holds the inner implementation's
/// function pointer and will be handed the **probe's** `userdata` — a
/// `*CountingIo` where a `*std.Io.Threaded` is expected. Calling one is
/// undefined behaviour.
///
/// `std.Io.VTable` has 109 slots at Zig 0.16; the three below are overridden
/// and the other 106 are mis-bound. Copying the vtable buys compilation
/// against a moving std, nothing more — so **the rule is: every `std.Io`
/// function reachable from `fill` or `SecureSource` must have an override
/// here.** Today that set is exactly `random`, `randomSecure` and
/// `swapCancelProtection`.
///
/// This was not a theoretical hazard. `swapCancelProtection` was added to
/// `fill` in 2026-08-13 and had no override; it did not crash, because
/// `std.Io.Threaded.swapCancelProtection` happens to discard its `userdata`
/// (`_ = t;`) and read a thread-local instead, and because `@alignOf` of both
/// structs is 8, so even the `@alignCast` safety check stayed quiet. A silent
/// pass under a mis-bound pointer is exactly the shape that survives an audit,
/// which is why the constraint is written down here rather than left implied.
const CountingIo = struct {
    inner: std.Io,
    vtable: std.Io.VTable = undefined,
    random_calls: usize = 0,
    secure_calls: usize = 0,
    /// How many times the cancel-protection state was swapped (2 per `fill`:
    /// block, then restore).
    protection_swaps: usize = 0,
    /// The probe's own model of the current task's cancel-protection state.
    ///
    /// It is modelled here rather than read back off `inner` for a measured
    /// reason: under the Zig test runner the main thread is not a
    /// `std.Io.Threaded` task, so `Thread.current` is `null` and
    /// `Threaded.swapCancelProtection` stores nothing and always answers
    /// `.unblocked`. Delegating and reading back would therefore report
    /// `.unblocked` whether or not `fill` blocks anything — an assertion with
    /// no teeth. The inner `Io` is still driven, so the two stay in step where
    /// the inner one has any state at all; the probe's copy is authoritative.
    protection: std.Io.CancelProtection = .unblocked,
    /// The protection state in force when `randomSecure` was entered. `null`
    /// until a draw has happened.
    protection_at_draw: ?std.Io.CancelProtection = null,

    fn io(self: *CountingIo) std.Io {
        self.vtable = self.inner.vtable.*;
        self.vtable.random = onRandom;
        self.vtable.randomSecure = onRandomSecure;
        self.vtable.swapCancelProtection = onSwapCancelProtection;
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
        self.protection_at_draw = self.protection;
        return self.inner.randomSecure(buffer);
    }

    fn onSwapCancelProtection(
        userdata: ?*anyopaque,
        new: std.Io.CancelProtection,
    ) std.Io.CancelProtection {
        const self: *CountingIo = @ptrCast(@alignCast(userdata.?));
        self.protection_swaps += 1;
        const prev = self.protection;
        self.protection = new;
        _ = self.inner.swapCancelProtection(new);
        return prev;
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

// `error.Canceled` is `unreachable` in `fill` only because the draw runs under
// blocked cancellation. Nothing about the *output* of a draw can show that, so
// this asserts the mechanism directly: the state was `.blocked` at the moment
// `randomSecure` was entered, it was swapped exactly twice, and it came back
// to where it started. Delete either line of the protection pair in `fill` and
// this goes red; leave out the `defer` restore and it goes red differently.
test "fill blocks cancellation across the draw and restores it after" {
    var probe: CountingIo = .{ .inner = testing.io };
    const io = probe.io();

    try testing.expectEqual(std.Io.CancelProtection.unblocked, probe.protection);

    var buf: [32]u8 = undefined;
    fill(io, &buf);

    try testing.expectEqual(std.Io.CancelProtection.blocked, probe.protection_at_draw.?);
    try testing.expectEqual(@as(usize, 2), probe.protection_swaps);
    try testing.expectEqual(std.Io.CancelProtection.unblocked, probe.protection);
}

// The restore is by `defer` off whatever was there before, not a hard reset to
// `.unblocked`, so a caller that was already inside a protected region gets its
// own state back rather than having protection silently dropped underneath it.
test "fill restores an already-blocked protection state rather than clearing it" {
    var probe: CountingIo = .{ .inner = testing.io };
    const io = probe.io();
    probe.protection = .blocked;

    var buf: [32]u8 = undefined;
    fill(io, &buf);

    try testing.expectEqual(std.Io.CancelProtection.blocked, probe.protection_at_draw.?);
    try testing.expectEqual(std.Io.CancelProtection.blocked, probe.protection);
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

// The route assertions above count syscalls and check no bytes, which leaves a
// `fillFn` that writes NOTHING — every drawn key left as whatever was on the
// stack — indistinguishable from a correct one. `fill` has had the sliding-
// window coverage assertion since the module was written; the adapter that
// actually carries the bfv/tfhe secret keys did not, and that asymmetry is what
// these two tests close. Same shape as `fill writes the whole buffer`, on the
// other entry point.
test "SecureSource writes the whole buffer, including its last byte" {
    const sentinel: u8 = 0xa5;
    var buf: [4096]u8 = @splat(sentinel);

    var src: SecureSource = .{ .io = testing.io };
    src.interface().bytes(&buf);

    // 16 random bytes all landing on one chosen value is 2^-128, so a window
    // still holding the sentinel means those bytes were never written. Sliding
    // it catches a short fill anywhere, including the off-by-one at the tail.
    var i: usize = 0;
    while (i + 16 <= buf.len) : (i += 1) {
        try testing.expect(!std.mem.allEqual(u8, buf[i..][0..16], sentinel));
    }
}

test "SecureSource writes a large buffer completely, in one draw" {
    const sentinel: u8 = 0x5a;
    const buf = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(buf);
    @memset(buf, sentinel);

    var probe: CountingIo = .{ .inner = testing.io };
    var src: SecureSource = .{ .io = probe.io() };
    src.interface().bytes(buf);

    try testing.expectEqual(@as(usize, 1), probe.secure_calls);
    try testing.expect(!std.mem.allEqual(u8, buf[0..16], sentinel));
    try testing.expect(!std.mem.allEqual(u8, buf[buf.len / 2 ..][0..16], sentinel));
    try testing.expect(!std.mem.allEqual(u8, buf[buf.len - 16 ..], sentinel));
}

// The abort path itself has no in-process test and cannot have one: Zig has no
// catchable panic, so observing `@panic` needs a child process, and a module
// test that re-execs the test binary buys a fork per run to assert a one-line
// `catch`. What IS pinned is everything that decides whether that panic is
// reachable and correct — that `fill` calls `randomSecure` (above), that the
// draw runs under blocked cancellation so the other arm of
// `std.Io.RandomSecureError` is genuinely `unreachable` (above), and that the
// one surviving message names its cause (below). The switch is exhaustive, so
// std adding an error member breaks the build rather than folding into this.
//
// Note what this test no longer has to do. There used to be two messages and
// two `@panic` arms, and no test could tell which message was on which arm —
// swapping them stayed green. There is one arm now, so the binding is
// structural: the only `@panic` in the module is the `EntropyUnavailable` one.
test "the abort message names its cause" {
    try testing.expect(std.mem.indexOf(u8, unavailable_message, "EntropyUnavailable") != null);
    try testing.expect(std.mem.indexOf(u8, unavailable_message, "getrandom(2)") != null);
}
