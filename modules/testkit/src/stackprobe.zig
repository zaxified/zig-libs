// SPDX-License-Identifier: MIT

//! Dead-stack residue probe — the shared engine.
//!
//! 55 modules carried a hand-written probe each (27.8k lines, 2026-10-09),
//! every one a copy of the same engine plus per-algorithm "needles": the
//! bytes of every intermediate secret (an ECDSA nonce recovered from `(r,s)`,
//! a WOTS+ chain value, an HKDF pad), re-derived by hand. Deriving those was
//! most of the cost of a dead-stack wave. This engine needs none of them:
//!
//!   * **Residue** (needle-free). Every public entry point that touches a
//!     secret ends with a burn: a run of zeros below its frame as deep as
//!     the burn. A byte that is neither the paint nor zero, DEEPER than the
//!     top of the longest zero run, is a frame the burn did not reach — the
//!     body outgrew its burn, or a call after the burn left a frame. That
//!     covers every intermediate secret without naming one.
//!   * **Needles** only for what the caller can hand over without math: the
//!     secret INPUTS and the OUTPUT buffers (`out` params), read after the
//!     call so an output is a needle the moment it exists. These are what
//!     sits ABOVE the burn — a by-value copy in a wrapper's frame — where
//!     the residue rule cannot look.
//!
//! What it cannot see: an intermediate secret in an UNBURNED wrapper's frame
//! above the burn (not an input, not an output). `scripts/checks/
//! check-secret-api.py` closes most of that statically (no by-value secret
//! parameters or results on the public surface).
//!
//! Method (as the direct-region probes of 2026-10-08): the region is
//! addressed directly, `pad` bytes under the probe's own stack position; the
//! call runs under a `pad`-deep frame (`shim`) so its frames start inside the
//! region, and `paint`/`snapshot` run at the probe's depth with frames far
//! smaller than `pad`. ReleaseFast/ReleaseSmall only: Debug and ReleaseSafe
//! fill `undefined` with 0xaa, so a dead frame cannot be read there. The
//! skip is RUNTIME (`enabled`), so a probe body is type-checked in every
//! mode — a comptime skip left probes compiled only by the ReleaseFast run,
//! and half of all dead-stack builds of 2026-10-08..09 failed on errors a
//! Debug `zig build check` would have shown in seconds.
//!
//! Every `run` re-measures three controls in the same binary first: a
//! NEGATIVE needle control (public work, must find no needle), a POSITIVE
//! one (parks a needle in a local, must find it) and a RESIDUE control (a
//! deliberately short burn under a deep body, must report residue). A zero
//! from the probe is only readable next to those.

const std = @import("std");
const builtin = @import("builtin");

/// Runtime-known, so the code after `skipUnlessOptimized` is analysed in
/// every optimize mode (see the module doc).
pub var enabled: bool = builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSmall;

pub fn skipUnlessOptimized() error{SkipZigTest}!void {
    if (!@as(*volatile bool, &enabled).*) return error.SkipZigTest;
}

pub const Config = struct {
    /// Bytes of stack measured below the call's entry. Must exceed the
    /// deepest burn the probed entry points carry.
    window: usize = 256 * 1024,
    /// Distance between the probe's own frame and the region top.
    pad: usize = 2048,
    /// Needle window: any `w` consecutive bytes of a secret.
    w: usize = 16,
    /// A window needs this many distinct bytes to be a needle (limb padding
    /// and zero runs are on every dead stack).
    min_distinct: usize = 8,
    max_windows: usize = 1 << 16,
    /// The shortest zero run taken for a burn (a zeroed local is not one;
    /// the smallest burn in the collection is 1 KiB).
    min_burn: usize = 512,
    /// Calls per measurement: residue that depends on timing or entropy
    /// shows up in some runs only.
    repeats: usize = 3,
    /// Print every call's numbers (sizes a burn), not only failures.
    verbose: bool = false,
};

pub const Report = struct {
    /// 16-byte needle windows found (one per run of overlapping windows).
    needle_hits: usize = 0,
    needle_shallowest: usize = 0,
    needle_deepest: usize = 0,
    /// Non-zero, non-paint bytes deeper than the burn's top.
    residue_bytes: usize = 0,
    residue_deepest: usize = 0,
    /// Depth of the longest zero run's top (the burn), 0 = no burn seen.
    burn_top: usize = 0,
    burn_len: usize = 0,
    /// How deep the call reached at all (first non-paint byte from below).
    dirty_depth: usize = 0,

    fn add(self: *Report, o: Report) void {
        self.needle_hits += o.needle_hits;
        if (o.needle_hits != 0) {
            if (self.needle_shallowest == 0 or o.needle_shallowest < self.needle_shallowest) self.needle_shallowest = o.needle_shallowest;
            self.needle_deepest = @max(self.needle_deepest, o.needle_deepest);
        }
        self.residue_bytes += o.residue_bytes;
        self.residue_deepest = @max(self.residue_deepest, o.residue_deepest);
        self.dirty_depth = @max(self.dirty_depth, o.dirty_depth);
        if (o.burn_len > self.burn_len) {
            self.burn_len = o.burn_len;
            self.burn_top = o.burn_top;
        }
    }
};

pub const Expect = struct {
    /// The entry point burns (a zero run must exist). `false` for a call
    /// that needs no burn and is probed for needles only.
    burn: bool = true,
};

pub fn Probe(comptime cfg: Config) type {
    return struct {
        const Self = @This();
        const WINDOW = cfg.window;
        const PAD = cfg.pad;
        const W = cfg.w;
        const PAINT: u8 = 0xC7;

        var region_lo: usize = 0;
        var snap: [WINDOW]u8 = undefined;

        // ── needles ───────────────────────────────────────────────────────

        var win: [cfg.max_windows]u128 = undefined;
        var n_win: usize = 0;
        var overflow: bool = false;

        fn resetNeedles() void {
            n_win = 0;
            overflow = false;
        }

        fn addImage(image: []const u8) void {
            var i: usize = 0;
            while (i + W <= image.len) : (i += 1) {
                const s = image[i..][0..W];
                if (distinct(s) < cfg.min_distinct) continue;
                if (n_win == cfg.max_windows) {
                    overflow = true;
                    return;
                }
                win[n_win] = std.mem.readInt(u128, s, .little);
                n_win += 1;
            }
        }

        fn distinct(s: *const [W]u8) usize {
            var seen: [256]bool = @splat(false);
            var c: usize = 0;
            for (s) |b| {
                if (!seen[b]) c += 1;
                seen[b] = true;
            }
            return c;
        }

        fn sortNeedles() void {
            std.mem.sort(u128, win[0..n_win], {}, std.sort.asc(u128));
        }

        fn isNeedle(v: u128) bool {
            var lo: usize = 0;
            var hi: usize = n_win;
            while (lo < hi) {
                const mid = (lo + hi) / 2;
                if (win[mid] < v) lo = mid + 1 else hi = mid;
            }
            return lo < n_win and win[lo] == v;
        }

        // ── the region ────────────────────────────────────────────────────

        noinline fn stackHere() usize {
            var x: u8 = 0;
            std.mem.doNotOptimizeAway(&x);
            return @intFromPtr(&x);
        }

        noinline fn paint() void {
            const p: [*]volatile u8 = @ptrFromInt(region_lo);
            for (0..WINDOW) |i| p[i] = PAINT;
        }

        noinline fn shim(call: *const fn () void) void {
            var pad: [PAD]u8 = undefined;
            std.mem.doNotOptimizeAway(&pad);
            call();
            std.mem.doNotOptimizeAway(&pad);
        }

        noinline fn snapshot() void {
            const p: [*]const volatile u8 = @ptrFromInt(region_lo);
            for (&snap, 0..) |*d, i| d.* = p[i];
        }

        /// The callee-saved registers still hold the TEST's values (needles it
        /// just computed); the call's prologue spills them into its frame.
        inline fn scrubCalleeSaved() void {
            if (builtin.cpu.arch == .x86_64) asm volatile (
                \\xorl %%ebx, %%ebx
                \\xorl %%r12d, %%r12d
                \\xorl %%r13d, %%r13d
                \\xorl %%r14d, %%r14d
                \\xorl %%r15d, %%r15d
                ::: .{ .rbx = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true });
        }

        /// `inline`: as a frame of its own it ran the call deeper than the
        /// region top `run` computed (2026-10-08).
        inline fn measureOnce(call: *const fn () void) void {
            scrubCalleeSaved();
            paint();
            shim(call);
            snapshot();
        }

        /// Depth below the region top of snapshot index `i`.
        inline fn depthOf(i: usize) usize {
            return WINDOW - i;
        }

        fn analyse() Report {
            var r: Report = .{};
            // dirty depth: lowest index that is not paint
            var lo: usize = 0;
            while (lo < WINDOW and snap[lo] == PAINT) : (lo += 1) {}
            r.dirty_depth = WINDOW - lo;

            // longest zero run in the dirtied part
            var best_start: usize = WINDOW;
            var best_len: usize = 0;
            var i: usize = lo;
            while (i < WINDOW) {
                if (snap[i] != 0) {
                    i += 1;
                    continue;
                }
                const s = i;
                while (i < WINDOW and snap[i] == 0) : (i += 1) {}
                if (i - s > best_len) {
                    best_len = i - s;
                    best_start = s;
                }
            }
            if (best_len >= cfg.min_burn) {
                r.burn_len = best_len;
                r.burn_top = depthOf(best_start + best_len);
                // residue: deeper (lower index) than the run's top
                const top = best_start + best_len;
                for (snap[lo..top], lo..) |b, j| {
                    if (b != 0 and b != PAINT) {
                        r.residue_bytes += 1;
                        r.residue_deepest = @max(r.residue_deepest, depthOf(j));
                    }
                }
            }

            // needles
            var skip_until: usize = 0;
            var k: usize = 0;
            while (k + W <= WINDOW) : (k += 1) {
                if (k < skip_until) continue;
                if (isNeedle(std.mem.readInt(u128, snap[k..][0..W], .little))) {
                    r.needle_hits += 1;
                    const d = depthOf(k);
                    if (r.needle_shallowest == 0 or d < r.needle_shallowest) r.needle_shallowest = d;
                    r.needle_deepest = @max(r.needle_deepest, d);
                    skip_until = k + W;
                }
            }
            return r;
        }

        // ── controls ──────────────────────────────────────────────────────

        var leak_src: [64]u8 = undefined;

        noinline fn callInnocent() void {
            var out: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash("public", &out, .{});
            std.mem.doNotOptimizeAway(&out);
        }

        noinline fn callLeaky() void {
            var local: [512]u8 = undefined;
            @memset(&local, 0);
            local[100..][0..leak_src.len].* = leak_src;
            std.mem.doNotOptimizeAway(&local);
        }

        noinline fn deepBody() void {
            var local: [4096]u8 = undefined;
            for (&local, 0..) |*b, j| b.* = @truncate(j *% 131 +% 7);
            std.mem.doNotOptimizeAway(&local);
        }

        noinline fn shortBurn() void {
            var buf: [1024]u8 = undefined;
            const p: [*]volatile u8 = &buf;
            for (0..buf.len) |j| p[j] = 0;
        }

        noinline fn longBurn() void {
            var buf: [8192]u8 = undefined;
            const p: [*]volatile u8 = &buf;
            for (0..buf.len) |j| p[j] = 0;
        }

        /// A 4 KiB body under a 1 KiB burn: must report residue.
        noinline fn callUnderBurned() void {
            deepBody();
            shortBurn();
        }

        /// The same body under an 8 KiB burn: must report none.
        noinline fn callBurned() void {
            deepBody();
            longBurn();
        }

        fn controls() !void {
            var seed: [8]u8 = undefined;
            std.mem.writeInt(u64, &seed, @intCast(stackHere()), .little);
            std.crypto.hash.sha2.Sha512.hash(&seed, &leak_src, .{});
            resetNeedles();
            addImage(&leak_src);
            sortNeedles();
            measureOnce(callInnocent);
            const neg = analyse();
            measureOnce(callLeaky);
            const pos = analyse();
            measureOnce(callUnderBurned);
            const under = analyse();
            measureOnce(callBurned);
            const burned = analyse();
            if (neg.needle_hits != 0 or pos.needle_hits == 0 or under.residue_bytes == 0 or
                burned.residue_bytes != 0 or burned.burn_top == 0)
            {
                std.debug.print(
                    "\n=== STACKPROBE controls FAILED ({t}): neg hits {d} (want 0), pos hits {d} (want >0), " ++
                        "short-burn residue {d} (want >0), long-burn residue {d} (want 0, burn top {d})\n",
                    .{ builtin.mode, neg.needle_hits, pos.needle_hits, under.residue_bytes, burned.residue_bytes, burned.burn_top },
                );
                return error.ProbeControlFailed;
            }
        }

        // ── the probe ─────────────────────────────────────────────────────

        /// Measure `f(args...)` and fail on residue or a needle.
        ///
        /// `secrets`: the secret inputs and the `out` buffers that receive a
        /// secret, as byte slices. Read AFTER the call (an output exists only
        /// then), so pass slices of storage the call writes into.
        /// `args` are stored in static memory and the call reads them from
        /// there: pass secrets by pointer, as the API takes them.
        pub fn run(
            comptime label: []const u8,
            comptime f: anytype,
            args: std.meta.ArgsTuple(@TypeOf(f)),
            secrets: []const []const u8,
            expect: Expect,
        ) !Report {
            const Args = @TypeOf(args);
            const Call = struct {
                var a: Args = undefined;
                noinline fn call() void {
                    const r = @call(.never_inline, f, a);
                    switch (@typeInfo(@TypeOf(r))) {
                        .error_union => if (r) |v| std.mem.doNotOptimizeAway(&v) else |_| {},
                        else => std.mem.doNotOptimizeAway(&r),
                    }
                }
            };
            Call.a = args;

            const region_hi = stackHere() - PAD;
            region_lo = region_hi - WINDOW;
            try controls();

            var total: Report = .{};
            for (0..cfg.repeats) |_| {
                measureOnce(Call.call);
                resetNeedles();
                for (secrets) |s| addImage(s);
                sortNeedles();
                total.add(analyse());
            }
            if (overflow) {
                std.debug.print("\n=== STACKPROBE {s}: more than {d} needle windows — raise max_windows\n", .{ label, cfg.max_windows });
                return error.TooManyNeedles;
            }
            const no_burn = expect.burn and total.burn_top == 0;
            const bad = total.needle_hits != 0 or total.residue_bytes != 0 or no_burn;
            if (cfg.verbose or bad) {
                std.debug.print(
                    "\n=== STACKPROBE {s} ({t}): needles {d} ({d} windows, {d}..{d} B deep), residue {d} B (to {d} B), " ++
                        "burn {d} B from {d} B, dirty {d} B ===\n",
                    .{ label, builtin.mode, total.needle_hits, n_win, total.needle_shallowest, total.needle_deepest, total.residue_bytes, total.residue_deepest, total.burn_len, total.burn_top, total.dirty_depth },
                );
                if (no_burn) std.debug.print("    no zero run: the entry point does not burn\n", .{});
                if (total.residue_bytes != 0) std.debug.print("    the body reached {d} B below the region top; the burn ends at {d} B\n", .{ total.residue_deepest, total.burn_top + total.burn_len });
            }
            if (bad) return error.DeadStackResidue;
            return total;
        }
    };
}

// ── self-test: the engine against hand-made entry points ─────────────────

const T = Probe(.{ .window = 64 * 1024 });

var t_secret: [48]u8 = undefined;
var t_out: [32]u8 = undefined;

fn burnStack(comptime n: usize) void {
    const S = struct {
        noinline fn stack() void {
            const V = @Vector(2, u64);
            var buf: [n / @sizeOf(V)]V align(16) = undefined;
            const p: [*]align(16) volatile V = &buf;
            for (0..buf.len) |i| p[i] = @splat(0);
        }
    };
    S.stack();
}

noinline fn derive(secret: *const [48]u8, out: *[32]u8) void {
    var tmp: [512]u8 = undefined;
    for (&tmp, 0..) |*b, i| b.* = secret[i % 48] ^ @as(u8, @truncate(i));
    std.crypto.hash.sha2.Sha256.hash(&tmp, out, .{});
    std.mem.doNotOptimizeAway(&tmp);
}

fn goodEntry(secret: *const [48]u8, out: *[32]u8) void {
    @call(.never_inline, derive, .{ secret, out });
    burnStack(4096);
}

fn unburnedEntry(secret: *const [48]u8, out: *[32]u8) void {
    @call(.never_inline, derive, .{ secret, out });
}

test "stackprobe: a burned entry is clean, an unburned one is caught" {
    try skipUnlessOptimized();
    std.crypto.hash.sha2.Sha384.hash("testkit stackprobe", &t_secret, .{});
    _ = try T.run("good", goodEntry, .{ &t_secret, &t_out }, &.{ &t_secret, &t_out }, .{});
    try std.testing.expectError(error.DeadStackResidue, T.run("unburned (expected to fail)", unburnedEntry, .{ &t_secret, &t_out }, &.{ &t_secret, &t_out }, .{}));
}
