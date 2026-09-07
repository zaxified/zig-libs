// SPDX-License-Identifier: MIT

//! Test-only: turn one corpus seed into one sample of `/proc` text.
//!
//! ## Why this file exists
//!
//! Every parser in this module had its own copy of a `mutateSample` helper —
//! five copies, one per `/proc` file — and all five collapsed the same way.
//! Each opened with
//!
//!     if (smith.valueRangeAtMost(u8, 0, 4) == 0) { ... }
//!
//! A `Smith` ranged draw reads EIGHT octets as a little-endian `u64` and
//! returns the range MINIMUM unless that word already lies inside the range,
//! and after the first short read `Smith` discards the rest of the input. So
//! outside `--fuzz` the test was always 0, the "one draw in five is pure
//! arbitrary bytes" branch was taken **every** time, and the length drawn
//! after `smith.bytes(buf)` was 0 — so every parser in this module was handed
//! an EMPTY string, on every iteration, for the life of the harness. The real
//! `/proc` fixtures the corpora carry were never parsed once.
//!
//! ⛔ Two of the five had a second, worse symptom. `process.zig` and
//! `sockets.zig` chose their mutation seed with `smith.index(corpus.len)`,
//! which is a ranged draw as well and so returned 0 — always `corpus[0]`. In
//! `process.zig` that draw is a **previous audit's fix**: the comment beside
//! it reads *"Was `proc_stat_corpus[0]`, so the two paren-heavy samples this
//! harness exists for — `((sd-pam))` and `my weird) name` — were never
//! mutation seeds"*. Replacing the constant with `smith.index(...)` bought
//! nothing at all; the index was 0 either way, and the two samples the fix was
//! written for stayed unreached. In `sockets.zig` the same draw meant four of
//! the five address-family fixtures — including both IPv6 tables and both
//! big-endian MIPS ones — were never selected.
//!
//! ## What replaces it
//!
//! One `smith.slice` draw, read as a byte SCRIPT through `testkit.fuzz.Cursor`.
//! A knob cannot be drawn after the bytes, because there are no draws after the
//! bytes: the octets say which sample, how to damage it and how far to truncate
//! it. That makes a seed reviewable, keeps the fuzzer in charge of every choice
//! under `--fuzz` (it drives the slice), and puts one copy of the logic where
//! all five parsers can share it.

const std = @import("std");
const testkit = @import("testkit");

pub const Script = testkit.fuzz.Cursor;
pub const seed = testkit.fuzz.seed;
pub const seedInto = testkit.fuzz.seedInto;

/// What a script asked for, so a corpus guard can measure the spread rather
/// than assert the harness merely ran.
pub const Choice = struct {
    /// Index into the sample table.
    sample: usize = 0,
    /// True when the script asked for arbitrary bytes instead of a real sample.
    arbitrary: bool = false,
    /// Octets overwritten in the copied sample.
    mutations: usize = 0,
    /// Length of the text handed to the parser.
    len: usize = 0,
};

/// The script layout, one octet per line unless noted:
///
///     0      sample index, modulo `samples.len`
///     1      mode: 0 asks for arbitrary bytes, anything else mutates a sample
///     2      mutation count, modulo 25
///     3..4   truncation length, big-endian; anything at or over the sample's
///            own length means "do not truncate", so `FFFF` is the full sample
///     5..    per mutation: offset (2 octets, big-endian) then the value octet
///
/// A short script CYCLES rather than running out, so a five-octet seed is a
/// repeating pattern instead of a run of range minima. An empty script reads as
/// all zeroes, which reproduces the collapsed helper exactly: mode 0, the
/// arbitrary branch, length 0 — the empty string.
pub fn build(
    script: []const u8,
    samples: []const []const u8,
    buf: []u8,
    choice: *Choice,
) []const u8 {
    std.debug.assert(samples.len != 0);
    var s = Script{ .bytes = script };
    choice.* = .{};
    choice.sample = s.byte() % samples.len;
    const mode = s.byte();
    const want_mutations: usize = s.byte() % 25;
    const truncate: usize = s.word();

    if (mode == 0) {
        choice.arbitrary = true;
        // ⚠ The length comes from the SCRIPT, not from a draw after the bytes.
        // Filling the buffer first and asking for a length afterwards is what
        // made the old helper return an empty string for every seed.
        const n = @min(@as(usize, s.word()) % (buf.len + 1), buf.len);
        for (buf[0..n]) |*b| b.* = s.byte();
        choice.len = n;
        return buf[0..n];
    }

    const sample = samples[choice.sample];
    const len = @min(sample.len, buf.len);
    @memcpy(buf[0..len], sample[0..len]);
    if (len != 0) {
        var i: usize = 0;
        while (i < want_mutations) : (i += 1) {
            buf[@as(usize, s.word()) % len] = s.byte();
            choice.mutations += 1;
        }
    }
    choice.len = if (truncate < len) truncate else len;
    return buf[0..choice.len];
}
