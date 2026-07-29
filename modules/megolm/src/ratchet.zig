// SPDX-License-Identifier: MIT

//! ratchet.zig — the Megolm one-way hash ratchet itself: 128 bytes held as
//! four 32-byte parts `R0..R3` plus a 32-bit counter, advanced so that
//! going forward is cheap (>=1 hash, <=1020 in the worst case, per the
//! spec) and going backward is cryptographically impossible (there is no
//! operation that recovers `R_{i-1}` from `R_i` — SHA-256/HMAC are one-way).
//!
//! ## The algorithm, and why it looks the way it does
//!
//! The spec (megolm.md "The Megolm ratchet algorithm") writes the advance
//! as a per-part piecewise recurrence indexed by 2^24/2^16/2^8 boundaries.
//! That description is correct but not directly an algorithm: it describes
//! what the state IS at index `i`, not how to get there from an arbitrary
//! earlier index without visiting every intermediate `i`. The reference
//! implementations (libolm's `megolm.c`, vodozemac's `ratchet.rs`) both
//! implement the same two operations, and this module is a direct,
//! byte-for-byte port of theirs (see NOTICE — their test vectors anchor
//! this file; see "Verification" in SPEC.md):
//!
//!   - `advance()` — one step. Find the SLOWEST part that must change (the
//!     lowest-order byte boundary the new counter crosses — part 3 changes
//!     every step, part 2 every 256 steps, part 1 every 2^16, part 0 every
//!     2^24), then rehash that part FROM ITSELF and every part to its right
//!     FROM the (freshly rehashed) slow part. That "reset every part to the
//!     right" step is the one a naive reading of the spec's recurrence
//!     misses if implemented per-part independently instead of as one
//!     cascading update — see `advanceStep`'s doc comment for the mutation
//!     this module's own tests specifically catch.
//!   - `advanceTo(target)` — fast-forward directly to an arbitrary index
//!     without 2^32 single steps: walk parts 0..3 (most- to least-
//!     significant byte of the counter), and for each part, rehash it
//!     `steps` times where `steps` is exactly the number of times that
//!     byte-position would have incremented under repeated `advance()`
//!     calls — the LAST of those `steps` also cascades into every part to
//!     its right, exactly like `advance()`'s single-step cascade. This is
//!     what lets a recipient jump from ratchet index 0 to index
//!     4_000_000_000 in at most 4*255 ~= 1020 hash operations rather than
//!     four billion.
//!
//! `advanceTo`'s raw form (`advanceToUnchecked`) is UNCONDITIONAL: given a
//! `target` numerically less than the current counter, it does not error —
//! it treats the 32-bit counter as a wraparound odometer and rehashes
//! forward around the wraparound point (this is a real, intentional edge
//! case: see `Megolm::advance wraparound`/`overflow` in libolm's test
//! suite, ported into this file's tests). That is the CORRECT behavior for
//! the primitive (a 32-bit counter genuinely does wrap), but it is also
//! exactly the footgun the spec's headline security property forbids
//! ("wound forwards but not backwards") if a caller mistakes "wraps
//! forward around 2^32" for "moves to an earlier index for free". The
//! guarded `advanceTo` wrapper is this module's answer: it refuses any
//! `target` numerically less than the current counter with a typed error,
//! and every session-level caller in this module goes through it, never
//! `advanceToUnchecked` directly (that stays available only for the
//! wraparound-specific KATs below and any caller who has genuinely thought
//! about 2^32-message sessions, which is not a real deployment scenario).

const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// Bytes per ratchet part (== the HMAC-SHA-256 output length; the spec
/// ties these together explicitly — "256 bits for this version of
/// Megolm").
pub const part_len = 32;
/// Number of parts (`R0..R3`) — the advance algorithms below are written
/// for exactly 4 and are not generic over this constant.
pub const num_parts = 4;
/// Total ratchet size in bytes (128).
pub const ratchet_len = part_len * num_parts;

/// Attempting to move the ratchet to an earlier index than its current
/// one through the guarded `advanceTo` API.
pub const RatchetError = error{CannotRatchetBackward};

/// The Megolm ratchet: 128 bytes of state (`R0 || R1 || R2 || R3`) plus the
/// counter `i` it currently represents.
pub const Ratchet = struct {
    data: [ratchet_len]u8,
    counter: u32,

    /// Build a ratchet from already-known bytes at a known index — the
    /// shape every decoder in this module (`SessionKey`/`ExportedSessionKey`
    /// import) constructs from wire bytes.
    pub fn init(data: [ratchet_len]u8, counter: u32) Ratchet {
        return .{ .data = data, .counter = counter };
    }

    /// A fresh outbound ratchet: 1024 bits (128 bytes) of randomness at
    /// index 0, exactly as the spec's "Session setup" specifies. Uses
    /// `io.random` (not `randomSecure`) to match this repo's other
    /// randomized-keypair call sites (e.g. `signal`'s
    /// `X25519.KeyPair.generate(io)`, `std.crypto.sign.Ed25519.KeyPair.
    /// generate(io)` — both non-error-returning `io.random` under the
    /// hood).
    pub fn generate(io: std.Io) Ratchet {
        var data: [ratchet_len]u8 = undefined;
        io.random(&data);
        return .{ .data = data, .counter = 0 };
    }

    /// Zero the ratchet's secret bytes. Does not zero `counter` (not
    /// secret — every message on the wire already carries it in cleartext).
    pub fn secureZero(self: *Ratchet) void {
        std.crypto.secureZero(u8, &self.data);
    }

    fn part(self: *Ratchet, i: usize) *[part_len]u8 {
        return self.data[i * part_len ..][0..part_len];
    }

    fn partConst(self: *const Ratchet, i: usize) *const [part_len]u8 {
        return self.data[i * part_len ..][0..part_len];
    }

    /// `H_to(from) = HMAC-SHA-256(key = R_from, message = single byte
    /// `to`)` — the spec's "Advancing the ratchet" section, `H_0..H_3`.
    /// The ratchet PART is the HMAC KEY (not the message) — a detail only
    /// visible in the reference implementations, not the spec's math
    /// notation, which writes `H_j(A)` without saying which HMAC argument
    /// `A` binds to.
    fn rehash(self: *Ratchet, from: usize, to: usize) void {
        var out: [part_len]u8 = undefined;
        const seed = [1]u8{@as(u8, @intCast(to))};
        HmacSha256.create(&out, &seed, self.partConst(from));
        @memcpy(self.part(to), &out);
    }

    /// Advance the ratchet by exactly one message (spec: "After each
    /// message is encrypted, the ratchet is advanced"). Direct port of
    /// libolm's `megolm_advance`/vodozemac's `Ratchet::advance`.
    ///
    /// **The mutation this guards against:** advancing ONLY the part that
    /// crosses its boundary, without also re-deriving every part to its
    /// right from the fresh value, is the signature Megolm-specific bug —
    /// it still round-trips locally (encrypt/decrypt agree with each
    /// other, since both sides run the same broken code), but diverges
    /// byte-for-byte from any correct implementation the instant a boundary
    /// is crossed. `kat_test.zig`'s libolm-vector tests at indices
    /// 0x1000000 and 0x1041506 (which cross a 2^24 AND several finer
    /// boundaries) are specifically chosen to catch this — a from-scratch
    /// per-part-independent implementation passes trivially at index 1 but
    /// fails at 0x1000000.
    pub fn advanceStep(self: *Ratchet) void {
        self.counter +%= 1;

        // Find `h`, the slowest (most-significant) part whose boundary the
        // new counter just crossed: mask starts at the bottom 3 bytes
        // (2^24 boundary, part 0) and narrows by one byte each iteration
        // (2^16 -> part 1, 2^8 -> part 2); by h==3 the mask is all-zero so
        // `counter & mask == 0` trivially, guaranteeing part 3 changes
        // every single step (the spec's "every iteration, R3 advances").
        var mask: u32 = 0x00FFFFFF;
        var h: usize = 0;
        while (h < num_parts) : (h += 1) {
            if ((self.counter & mask) == 0) break;
            mask >>= 8;
        }

        // Cascade: rehash parts 3, 2, ..., h all FROM the ORIGINAL part h
        // (read before this loop overwrites it) — the last iteration
        // (i == h) overwrites part h itself using itself as both source
        // and destination, which is safe only because it runs last.
        var i: usize = num_parts;
        while (i > h) {
            i -= 1;
            self.rehash(h, i);
        }
    }

    /// The raw, UNCONDITIONAL fast-forward primitive — see this file's
    /// module doc comment for why a real caller should use `advanceTo`
    /// instead. Direct port of libolm's `megolm_advance_to`/vodozemac's
    /// `Ratchet::advance_to`; byte-for-byte anchored by libolm's own test
    /// vectors (`kat_test.zig`).
    pub fn advanceToUnchecked(self: *Ratchet, target: u32) void {
        var j: usize = 0;
        while (j < num_parts) : (j += 1) {
            const shift: u5 = @intCast((num_parts - j - 1) * 8);
            const mask: u32 = ~@as(u32, 0) << shift;

            // How many times this part's byte-position needs to rehash.
            // `& 0xff` makes the wrapping subtraction correct even when
            // `target`'s byte is numerically smaller (mod-256 wraparound
            // of a single odometer digit, not "go backward").
            var steps: u32 = ((target >> shift) -% (self.counter >> shift)) & 0xff;

            if (steps == 0) {
                // `target`'s digit already matches `counter`'s at this
                // position — UNLESS `target` as a whole has wrapped all
                // the way around past `counter` (only possible at j==0,
                // the top byte), in which case this digit needs a full
                // 256-step cycle to land back where it already appears to
                // be.
                if (target < self.counter) {
                    steps = 0x100;
                } else {
                    continue;
                }
            }

            // All but the last step: bump part j from itself, ignoring
            // parts to its right (they get corrected on the last step
            // below, so redoing them every intermediate step would be
            // wasted work, not wrong — but doing it only once is why this
            // primitive stays O(255) per part instead of O(2^32)).
            while (steps > 1) {
                self.rehash(j, j);
                steps -= 1;
            }

            // Last step: cascade into every part to the right too, exactly
            // like `advanceStep`'s single-step cascade.
            var k: usize = num_parts;
            while (k > j) {
                k -= 1;
                self.rehash(j, k);
            }

            self.counter = target & mask;
        }
    }

    /// Fast-forward to `target`, refusing to move to an earlier index.
    /// This is the entry point every session-level API in this module
    /// uses; see the module doc comment for why the unconditional
    /// primitive is not the default.
    pub fn advanceTo(self: *Ratchet, target: u32) RatchetError!void {
        if (target < self.counter) return error.CannotRatchetBackward;
        self.advanceToUnchecked(target);
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "advanceStep and advanceTo(counter+1) agree, at every boundary depth" {
    // `advanceStep` (the "single message" path) and `advanceToUnchecked`
    // (the "fast-forward" path) implement the SAME algorithm and must
    // agree on every single-step transition -- including the three
    // counters below that each cross a DIFFERENT boundary (h=0, h=1,
    // h=2; an ordinary step with no boundary crossed is h=3, covered by
    // starting_counter 0). This is the test that actually distinguishes a
    // correct cascade from the "reseed only the named part, not the
    // parts to its right" mutation described in ratchet.zig's module doc
    // comment: a step that crosses NO boundary (h=3) looks identical
    // under that mutation (there is nothing to its right to skip), so a
    // test using only `starting_counter = 0` would miss it entirely.
    const starting_counters = [_]u32{
        0, // h=3: ordinary step, nothing to the right of the last part
        0x000000FF, // -> 0x00000100, crosses h=2 (part 2's 2^8 boundary)
        0x0000FFFF, // -> 0x00010000, crosses h=1 (part 1's 2^16 boundary)
        0x00FFFFFF, // -> 0x01000000, crosses h=0 (part 0's 2^24 boundary)
    };
    for (starting_counters) |c| {
        var a = Ratchet.init([_]u8{0} ** ratchet_len, c);
        var b = Ratchet.init([_]u8{0} ** ratchet_len, c);
        a.advanceStep();
        try b.advanceTo(c + 1);
        try testing.expectEqual(a.counter, b.counter);
        try testing.expectEqualSlices(u8, &a.data, &b.data);
    }
}

test "advanceTo refuses to move backward" {
    var r = Ratchet.init([_]u8{0xAB} ** ratchet_len, 5);
    const before = r.data;
    try testing.expectError(error.CannotRatchetBackward, r.advanceTo(3));
    // Fail-closed: the rejected call must not have mutated anything.
    try testing.expectEqual(@as(u32, 5), r.counter);
    try testing.expectEqualSlices(u8, &before, &r.data);
}

test "advanceTo(same index) is a no-op, not an error" {
    var r = Ratchet.init([_]u8{0x11} ** ratchet_len, 7);
    const before = r.data;
    try r.advanceTo(7);
    try testing.expectEqual(@as(u32, 7), r.counter);
    try testing.expectEqualSlices(u8, &before, &r.data);
}

test "advanceStep at a high counter does not panic (no overflow trap)" {
    var r = Ratchet.init([_]u8{0} ** ratchet_len, 0x00FFFFFF);
    r.advanceStep();
    try testing.expectEqual(@as(u32, 0x01000000), r.counter);
}
