// SPDX-License-Identifier: MIT

//! What a `jwe`/`dnp3`-style consumer does with `aeskw`: wrap a fresh 40-byte
//! key blob (5 semiblocks — deliberately not the RFC 3394 examples' 16/24/32)
//! under an AES-256 KEK, unwrap it back, and reject a corrupted wrapped blob
//! by NAME (never a partial-key leak) rather than silently returning garbage.
//!
//! External oracle actually run (see the report): `openssl enc -id-aes256-wrap
//! -K <kek> -iv A6A6A6A6A6A6A6A6` on this exact fresh KEK/plaintext (none of
//! it drawn from the module's own RFC 3394 §4 test vectors) reproduces the
//! `expected_ct` bytes below byte-for-byte — checked by the
//! `std.debug.assert` right after `wrap`, so a regression here fails the
//! example, not just a comment.
//!
//! `wrap`/`unwrap` never allocate — every buffer below is caller-owned and
//! sized by hand from the RFC 3394 §2.2 shape (`plaintext.len + 8` to wrap,
//! `ciphertext.len - 8` to unwrap). There is nothing for a `DebugAllocator`
//! to catch here: this example holds no heap allocation at all, by
//! construction of the module it exercises.

const std = @import("std");
const aeskw = @import("aeskw");

pub fn main() !void {
    // Fresh throwaway AES-256 KEK and 40-byte (5-semiblock) key blob —
    // invented for this example, NOT copied from the module's RFC 3394 §4.1/
    // §4.3/§4.5/§4.6 KATs (which only cover 16/24/32-byte plaintexts).
    // Independently reproduced with `openssl enc -id-aes256-wrap -K <kek>
    // -iv A6A6A6A6A6A6A6A6` while authoring this file (see module doc above).
    const kek = hexN(32, "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00");
    var plaintext: [40]u8 = undefined;
    for (&plaintext, 0..) |*b, i| b.* = @intCast(i); // 0x00..0x27, fresh, non-vector

    // openssl's ciphertext for the exact same KEK/plaintext (openssl's
    // AES-Wrap defaults to RFC 3394's default IV, matching `aeskw.default_iv`)
    // — the external oracle this example checks against, not a value this
    // module computed for itself.
    const expected_ct = hexN(48, "e76bec29879af07611130ae9afa7f01c6157c2e83263521b9b12c6ae7cfb10c" ++
        "d7d26a0310cd83f2db15d6a0ba2ceb959");

    // Buffer sizing is the caller's job and the RFC's own shape: wrap output
    // is always exactly plaintext.len + 8 (one extra semiblock, the integrity
    // register); unwrap output is ciphertext.len - 8.
    var wrapped: [40 + 8]u8 = undefined;
    const w = try aeskw.wrap(&kek, &plaintext, &wrapped);
    std.debug.assert(w.len == wrapped.len);
    std.debug.assert(std.mem.eql(u8, &expected_ct, w));
    std.debug.print("wrap: byte-exact match against openssl's independent AES256-WRAP ciphertext\n", .{});

    var recovered: [40]u8 = undefined;
    const r = try aeskw.unwrap(&kek, w, &recovered);
    try std.testing.expectEqualSlices(u8, &plaintext, r);
    std.debug.print("unwrap: recovered the original {d}-byte key blob\n", .{r.len});

    // ── negative path: corrupted wrapped blob -> Unauthentic, no leak ──────
    //
    // Flip one byte inside the wrapped ciphertext (not the integrity
    // register itself, to show the corruption is caught deep in the
    // unwrapping recurrence, not just at the register comparison). `unwrap`
    // must fail closed by NAME and, per its documented contract, wipe `out`
    // rather than hand back a partially-recovered key.
    var corrupt = wrapped;
    corrupt[20] ^= 0x01;
    var out_on_failure: [40]u8 = [_]u8{0xAA} ** 40; // pre-poisoned, to prove it gets wiped
    if (aeskw.unwrap(&kek, &corrupt, &out_on_failure)) |_| {
        unreachable; // a single flipped byte cannot survive the integrity check
    } else |err| switch (err) {
        error.Unauthentic => {
            std.debug.print("corrupted wrap: unwrap -> Unauthentic (expected)\n", .{});
            const all_zero = for (out_on_failure) |b| {
                if (b != 0) break false;
            } else true;
            std.debug.assert(all_zero); // no partial-key leak on failure
            std.debug.print("out buffer wiped to zero on failure: confirmed\n", .{});
        },
        else => return err,
    }

    // ── the awkward part an outside caller trips on: `out` sizing is off by
    // the 8-byte integrity register, in OPPOSITE directions for wrap/unwrap.
    //
    // `wrap(plaintext, out)` needs `out.len >= plaintext.len + 8`;
    // `unwrap(ciphertext, out)` needs `out.len >= ciphertext.len - 8`. A
    // caller who reuses one "add 8 bytes of framing" mental model for both
    // directions undersizes `unwrap`'s `out` by 16 instead of the correct 8.
    // Demonstrated here one byte short of the real minimum, against the real
    // 48-byte wrapped blob from above (not a truncated/reshaped one, so this
    // is purely a buffer-size check, not also an integrity failure).
    var too_small_out: [40 - 1]u8 = undefined;
    if (aeskw.unwrap(&kek, w, &too_small_out)) |_| {
        unreachable;
    } else |err| switch (err) {
        error.BufferTooSmall => std.debug.print("out buffer one byte short of ciphertext.len-8: BufferTooSmall (expected)\n", .{}),
        else => return err,
    }
}

fn hexN(comptime n: usize, comptime s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
