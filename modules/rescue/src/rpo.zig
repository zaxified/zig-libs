// SPDX-License-Identifier: MIT

//! The two RPO **sponge framings** that exist in the wild, over the one
//! permutation in `perm.zig`.
//!
//! They are not variants of a hash — they are two different hashes built from
//! the same permutation, and they disagree on every digest. Which one a caller
//! wants is decided entirely by what it has to interoperate with:
//!
//! | | `spec` | `Rpo256` |
//! |---|---|---|
//! | source | the authors' `rescue_prime_optimized.sage` | miden-crypto (Miden VM) |
//! | capacity | elements `0 .. c` | elements `8 .. 12` |
//! | rate | elements `c .. m` | elements `0 .. 8` |
//! | digest | `state[c .. c + r/2]` | `state[0 .. 4]` |
//! | padding | append `1`, then zeros; set `state[0] = 1` | zeros only |
//! | domain separation | the `state[0] = 1` padding flag | `state[8] = len mod 8` |
//! | empty input | rejected | zero digest, no permutation |
//! | widths | `m = 12` (128-bit) and `m = 16` (160-bit) | `m = 12` only |
//!
//! Both are anchored on published vectors — see `vectors_test.zig`. Neither is
//! "more correct"; `SPEC.md` records why both ship.

const std = @import("std");
const gl = @import("goldilocks.zig");
const params = @import("params.zig");
const perm = @import("perm.zig");

// ── framing 1: the specification's own sponge ───────────────────────────────

/// `rpo_hash` from the reference implementation, for either published
/// instance. Overwrite-mode sponge with the capacity in the *low* indices.
pub fn Spec(comptime inst: params.Instance) type {
    return struct {
        pub const Perm = perm.Permutation(inst);
        pub const State = Perm.State;
        pub const rate = inst.rate();
        pub const capacity = inst.capacity;
        pub const digest_len = inst.digestLen();
        pub const Digest = [digest_len]gl.Fe;

        /// The bare permutation, for callers building their own construction.
        pub fn permute(state: *State) void {
            Perm.permute(state);
        }

        /// Hash a non-empty sequence of field elements.
        ///
        /// Empty input is **rejected**, exactly as the reference implementation
        /// does (`assert(len(input_sequence) > 0)`). Hashing nothing is not
        /// defined by this construction: with `len % rate == 0` the padding
        /// branch is skipped, so the sponge would never permute and the digest
        /// would be a constant zero that no domain separator distinguishes from
        /// anything. Callers who need a value for "no input" must pick their own
        /// convention (`Rpo256` picked the zero digest; see there).
        pub fn hash(input: []const gl.Fe) Digest {
            std.debug.assert(input.len > 0);
            var state: State = @splat(0);
            var i: usize = 0;

            if (input.len % rate != 0) {
                // Padded absorption: input ++ [1] ++ 0*, with the domain
                // separation bit in the capacity.
                state[0] = 1;
                const padded_len = (input.len / rate + 1) * rate;
                while (i < padded_len) : (i += rate) {
                    var block: [rate]gl.Fe = @splat(0);
                    for (0..rate) |j| {
                        const k = i + j;
                        block[j] = if (k < input.len)
                            input[k]
                        else if (k == input.len)
                            1
                        else
                            0;
                    }
                    @memcpy(state[capacity..][0..rate], &block);
                    Perm.permute(&state);
                }
            } else {
                while (i < input.len) : (i += rate) {
                    @memcpy(state[capacity..][0..rate], input[i..][0..rate]);
                    Perm.permute(&state);
                }
            }

            var out: Digest = undefined;
            @memcpy(&out, state[capacity..][0..digest_len]);
            return out;
        }
    };
}

/// The 128-bit instance: `m = 12`, `c = 4`, 4-element (256-bit) digest.
pub const spec128 = Spec(params.Instance.bits128);

/// The 160-bit instance: `m = 16`, `c = 6`, 5-element (320-bit) digest.
pub const spec160 = Spec(params.Instance.bits160);

// ── framing 2: miden-crypto's Rpo256 ────────────────────────────────────────

/// `Rpo256` as deployed by the Miden VM — the framing anything reading a Miden
/// Merkle root or account commitment must speak.
///
/// State layout `[RATE0, RATE1, CAPACITY]`: rate at `0..8`, capacity at `8..12`,
/// digest at `0..4`. **This is miden-crypto's post-`#755` layout**; releases
/// before that breaking change laid the state out as `[CAPACITY, RATE1, RATE0]`
/// and produce different digests from the same permutation. `SPEC.md` says how
/// to tell which one a given corpus of digests came from.
pub const Rpo256 = struct {
    pub const Perm = perm.Permutation(params.Instance.bits128);
    pub const State = Perm.State;

    pub const state_width = 12;
    pub const rate_range = .{ .start = 0, .end = 8 };
    pub const capacity_start = 8;
    pub const rate_width = 8;
    pub const digest_len = 4;

    /// Four field elements, 32 bytes once serialised. Miden calls this a `Word`.
    pub const Digest = [digest_len]gl.Fe;

    /// Bytes-per-element when packing a byte string into field elements: 7,
    /// so that every 7-byte chunk is unconditionally `< p` and needs no
    /// rejection.
    const binary_chunk_size = 7;

    pub fn permute(state: *State) void {
        Perm.permute(state);
    }

    fn digestOf(state: State) Digest {
        return .{ state[0], state[1], state[2], state[3] };
    }

    /// Serialise a digest the way Miden does: four little-endian `u64`s.
    pub fn digestToBytes(d: Digest) [32]u8 {
        var out: [32]u8 = undefined;
        for (d, 0..) |e, i| std.mem.writeInt(u64, out[i * 8 ..][0..8], e, .little);
        return out;
    }

    fn absorbElements(state: *State, elements: []const gl.Fe) Digest {
        state[capacity_start] = @intCast(elements.len % rate_width);
        var i: usize = 0;
        for (elements) |e| {
            state[i] = e;
            i += 1;
            if (i == rate_width) {
                Perm.permute(state);
                i = 0;
            }
        }
        if (i > 0) {
            while (i < rate_width) : (i += 1) state[i] = 0;
            Perm.permute(state);
        }
        return digestOf(state.*);
    }

    /// Hash a sequence of field elements. Empty input hashes to the all-zero
    /// digest without touching the permutation — miden-crypto's documented
    /// choice, not an accident of this port.
    pub fn hashElements(elements: []const gl.Fe) Digest {
        var state: State = @splat(0);
        return absorbElements(&state, elements);
    }

    /// `hash_elements_in_domain`: same, with a caller-chosen domain identifier
    /// in the *second* capacity element (the first carries the length flag).
    pub fn hashElementsInDomain(elements: []const gl.Fe, domain: gl.Fe) Digest {
        var state: State = @splat(0);
        state[capacity_start + 1] = domain;
        return absorbElements(&state, elements);
    }

    /// Hash an arbitrary byte string.
    ///
    /// Deliberately **not** consistent with `hashElements`: bytes are packed 7
    /// at a time with a trailing `1` byte in the final element, and the
    /// capacity flag is `8 + (n mod 8)` rather than `n mod 8`, which domain
    /// separates byte hashing from element hashing.
    pub fn hash(bytes: []const u8) Digest {
        var state: State = @splat(0);
        const num_elems = std.math.divCeil(usize, bytes.len, binary_chunk_size) catch unreachable;
        state[capacity_start] = @intCast(rate_width + (num_elems % rate_width));

        var rate_pos: usize = 0;
        var off: usize = 0;
        var idx: usize = 0;
        while (off < bytes.len) : (idx += 1) {
            const end = @min(off + binary_chunk_size, bytes.len);
            var buf: [8]u8 = @splat(0);
            const chunk = bytes[off..end];
            @memcpy(buf[0..chunk.len], chunk);
            if (idx + 1 == num_elems) buf[chunk.len] = 1; // final-chunk marker
            state[rate_pos] = std.mem.readInt(u64, &buf, .little);
            off = end;

            if (rate_pos == rate_width - 1) {
                Perm.permute(&state);
                rate_pos = 0;
            } else {
                rate_pos += 1;
            }
        }
        if (rate_pos != 0) {
            while (rate_pos < rate_width) : (rate_pos += 1) state[rate_pos] = 0;
            Perm.permute(&state);
        }
        return digestOf(state);
    }

    /// The 2-to-1 Merkle node function: absorb both digests into a full rate
    /// with a zero capacity, permute once, take the first word.
    pub fn merge(a: Digest, b: Digest) Digest {
        var state: State = @splat(0);
        @memcpy(state[0..4], &a);
        @memcpy(state[4..8], &b);
        Perm.permute(&state);
        return digestOf(state);
    }

    /// `merge` with a domain identifier in the second capacity element.
    pub fn mergeInDomain(a: Digest, b: Digest, domain: gl.Fe) Digest {
        var state: State = @splat(0);
        @memcpy(state[0..4], &a);
        @memcpy(state[4..8], &b);
        state[capacity_start + 1] = domain;
        Perm.permute(&state);
        return digestOf(state);
    }

    /// `merge_many`: flatten the digests and run `hashElements`.
    pub fn mergeMany(values: []const Digest) Digest {
        var state: State = @splat(0);
        const total = values.len * digest_len;
        state[capacity_start] = @intCast(total % rate_width);
        var i: usize = 0;
        for (values) |v| {
            for (v) |e| {
                state[i] = e;
                i += 1;
                if (i == rate_width) {
                    Perm.permute(&state);
                    i = 0;
                }
            }
        }
        if (i > 0) {
            while (i < rate_width) : (i += 1) state[i] = 0;
            Perm.permute(&state);
        }
        return digestOf(state);
    }
};

// ── structural tests (the external vectors live in vectors_test.zig) ─────────

test "Rpo256: merge agrees with hashing the eight elements" {
    // miden-crypto's own `hash_elements_vs_merge` invariant.
    var elems: [8]gl.Fe = undefined;
    var prng = std.Random.DefaultPrng.init(11);
    for (&elems) |*e| e.* = gl.fromU64(prng.random().int(u64));
    const a: Rpo256.Digest = elems[0..4].*;
    const b: Rpo256.Digest = elems[4..8].*;
    try std.testing.expectEqual(Rpo256.merge(a, b), Rpo256.hashElements(&elems));
    try std.testing.expectEqual(Rpo256.merge(a, b), Rpo256.mergeMany(&.{ a, b }));
}

test "Rpo256: domain separation actually separates" {
    const a: Rpo256.Digest = .{ 1, 2, 3, 4 };
    const b: Rpo256.Digest = .{ 5, 6, 7, 8 };
    try std.testing.expectEqual(Rpo256.merge(a, b), Rpo256.mergeInDomain(a, b, 0));
    try std.testing.expect(!std.meta.eql(Rpo256.merge(a, b), Rpo256.mergeInDomain(a, b, 1)));
    // Byte hashing is separated from element hashing by the +8 capacity flag.
    const eight_zero_bytes = [_]u8{0} ** 8;
    try std.testing.expect(!std.meta.eql(
        Rpo256.hash(&eight_zero_bytes),
        Rpo256.hashElements(&.{ 0, 0 }),
    ));
}

test "Rpo256: empty input is the zero digest, per miden-crypto" {
    try std.testing.expectEqual(Rpo256.Digest{ 0, 0, 0, 0 }, Rpo256.hashElements(&.{}));
    try std.testing.expectEqual(Rpo256.Digest{ 0, 0, 0, 0 }, Rpo256.hash(&.{}));
}

test "Rpo256: miden's hash_padding — a trailing zero byte always changes the digest" {
    // miden-crypto `fn hash_padding`, ported case for case. The byte path has
    // no published KAT, so its upstream test suite is the next best thing.
    const pairs = .{
        .{ [_]u8{ 1, 2, 3 }, [_]u8{ 1, 2, 3, 0 } },
        .{ [_]u8{ 1, 2, 3, 4, 5, 6 }, [_]u8{ 1, 2, 3, 4, 5, 6, 0 } },
        .{ [_]u8{ 1, 2, 3, 4, 5, 6, 7 }, [_]u8{ 1, 2, 3, 4, 5, 6, 7, 0 } }, // splits chunks
        .{ [_]u8{ 1, 2, 3, 4, 5, 6, 7, 0, 0 }, [_]u8{ 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0 } },
    };
    inline for (pairs) |p| {
        const a = p[0];
        const b = p[1];
        try std.testing.expect(!std.meta.eql(Rpo256.hash(&a), Rpo256.hash(&b)));
    }
}

test "Rpo256: miden's hash_padding_no_extra_permutation_call" {
    // The strongest check available for the byte path: build the expected
    // digest from the *permutation* (which IS externally anchored) plus the
    // packing rule stated in miden's source, and require `hash` to agree.
    // A wrong capacity flag, a wrong 1-byte marker position, a wrong chunk
    // endianness or one permutation too many all fail here.
    const num_bytes = 7 * 8; // BINARY_CHUNK_SIZE * RATE_WIDTH — exactly one rate
    var buffer: [num_bytes]u8 = @splat(0);
    buffer[num_bytes - 1] = 97;

    const final_chunk = [_]u8{ 0, 0, 0, 0, 0, 0, 97, 1 };
    var state: Rpo256.State = @splat(0);
    state[Rpo256.capacity_start] = Rpo256.rate_width; // 8 + (8 mod 8) = 8
    state[Rpo256.rate_width - 1] = std.mem.readInt(u64, &final_chunk, .little);
    Rpo256.Perm.permute(&state);

    try std.testing.expectEqualSlices(gl.Fe, state[0..4], &Rpo256.hash(&buffer));
}

test "Rpo256: domain zero is a no-op, domain non-zero is not" {
    // miden-crypto `fn hash_elements_vs_hash_elements_in_domain`, at m = 16
    // elements so two full rate blocks are absorbed.
    var input: [16]gl.Fe = undefined;
    for (&input, 1..) |*e, i| e.* = i;
    try std.testing.expectEqual(
        Rpo256.hashElements(&input),
        Rpo256.hashElementsInDomain(&input, 0),
    );
    try std.testing.expect(!std.meta.eql(
        Rpo256.hashElements(&input),
        Rpo256.hashElementsInDomain(&input, 1),
    ));
}

test "Rpo256: 255 different lengths of zero bytes give 255 different digests" {
    // miden-crypto's `sponge_zeroes_collision`; catches a padding rule that
    // forgets the length flag.
    var seen: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
    defer seen.deinit(std.testing.allocator);
    var buf: [255]u8 = @splat(0);
    for (0..255) |n| {
        const d = Rpo256.digestToBytes(Rpo256.hash(buf[0..n]));
        const gop = try seen.getOrPut(std.testing.allocator, d);
        try std.testing.expect(!gop.found_existing);
    }
}

test "spec: the padding flag separates a padded absorb from an exact one" {
    // rate = 8; 8 elements take the no-padding branch, 7 take the padded one.
    const eight = [_]gl.Fe{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const seven = eight[0..7];
    const d8 = spec128.hash(&eight);
    const d7 = spec128.hash(seven);
    try std.testing.expect(!std.meta.eql(d8, d7));
    // ...and a hand-built "padded" input must not collide with the real one.
    const manual = [_]gl.Fe{ 1, 2, 3, 4, 5, 6, 7, 1 };
    try std.testing.expect(!std.meta.eql(d7, spec128.hash(&manual)));
}

test "spec: digest lengths follow rate/2" {
    try std.testing.expectEqual(@as(usize, 4), spec128.hash(&.{1}).len);
    try std.testing.expectEqual(@as(usize, 5), spec160.hash(&.{1}).len);
}
