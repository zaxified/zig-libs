// SPDX-License-Identifier: MIT

//! bip39 — BIP-39 mnemonic seed phrases (English wordlist only).
//!
//! `entropyToMnemonic` (128/160/192/224/256-bit entropy → 12/15/18/21/24
//! words, SHA-256 checksum appended before the 11-bit-group word mapping),
//! `mnemonicToEntropy`/`validateMnemonic` (the inverse, checksum-verified,
//! fail-closed), and `mnemonicToSeed` (PBKDF2-HMAC-SHA512, 2048 rounds, salt
//! `"mnemonic" ‖ passphrase` → the 64-byte BIP-32 master seed).
//!
//! **Scope caveat**: words are matched byte-for-byte and split on a single
//! ASCII space (`' '`) — exactly the shape of every official test vector and
//! every mnemonic this module itself produces. BIP-39's mandatory Unicode
//! NFKD normalization of the mnemonic/passphrase is NOT implemented (the
//! English wordlist is pure ASCII, where NFKD is the identity, so this is a
//! no-op for `entropyToMnemonic`'s own output and any ASCII passphrase); a
//! caller mixing in non-ASCII passphrases or non-normalized mnemonic text
//! from elsewhere must pre-normalize it themselves. See SPEC.md.

const std = @import("std");
const wordlist = @import("wordlist.zig");

/// Entropy byte lengths BIP-39 defines (128/160/192/224/256 bits).
pub const min_entropy_bytes = 16;
pub const max_entropy_bytes = 32;
/// Word counts BIP-39 defines (12/15/18/21/24), one per valid entropy length.
pub const min_words = 12;
pub const max_words = 24;

/// Generous bound on a rendered mnemonic string: 24 words, each ≤ 8 bytes
/// (the English wordlist's longest entry) plus a separating space.
pub const max_mnemonic_len = max_words * (8 + 1);

pub const Error = error{
    /// `entropyToMnemonic`'s input isn't 16/20/24/28/32 bytes.
    InvalidEntropyLength,
    /// Caller-supplied output buffer too small.
    BufferTooSmall,
    /// Word count isn't 12/15/18/21/24.
    InvalidWordCount,
    /// A word isn't in the English wordlist.
    WordNotInList,
    /// The trailing checksum bits don't match SHA-256(entropy).
    InvalidChecksum,
};

/// `entropyToMnemonic`: `entropy.len` must be one of 16/20/24/28/32 bytes.
/// Writes the space-separated lowercase mnemonic into `out` (no allocation)
/// and returns the written slice.
pub fn entropyToMnemonic(entropy: []const u8, out: []u8) Error![]const u8 {
    switch (entropy.len) {
        16, 20, 24, 28, 32 => {},
        else => return error.InvalidEntropyLength,
    }
    const ent_bits = entropy.len * 8;
    const cs_bits = ent_bits / 32;
    const total_bits = ent_bits + cs_bits;

    var checksum: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(entropy, &checksum, .{});

    var out_len: usize = 0;
    var bit_pos: usize = 0;
    var first = true;
    while (bit_pos < total_bits) : (bit_pos += 11) {
        const idx = readBits11(entropy, &checksum, ent_bits, bit_pos);
        const word = wordlist.english[idx];
        if (!first) {
            if (out_len >= out.len) return error.BufferTooSmall;
            out[out_len] = ' ';
            out_len += 1;
        }
        if (out_len + word.len > out.len) return error.BufferTooSmall;
        @memcpy(out[out_len..][0..word.len], word);
        out_len += word.len;
        first = false;
    }
    return out[0..out_len];
}

/// `mnemonicToEntropy`: parses + checksum-verifies `mnemonic` (single-space
/// separated words), writing the raw entropy bytes into `out`. Fail-closed:
/// a bad word count, unknown word, or checksum mismatch is a typed error,
/// never a best-effort partial result.
pub fn mnemonicToEntropy(mnemonic: []const u8, out: []u8) Error![]const u8 {
    var idxs: [max_words]u11 = undefined;
    var count: usize = 0;
    var it = std.mem.tokenizeScalar(u8, mnemonic, ' ');
    while (it.next()) |w| {
        if (count >= max_words) return error.InvalidWordCount;
        idxs[count] = wordIndex(w) orelse return error.WordNotInList;
        count += 1;
    }
    switch (count) {
        min_words, 15, 18, 21, max_words => {},
        else => return error.InvalidWordCount,
    }

    const total_bits = count * 11;
    // total_bits = ent_bits + ent_bits/32 = ent_bits * 33/32, so ent_bits = total_bits * 32/33.
    const ent_bits = (total_bits * 32) / 33;
    const cs_bits = total_bits - ent_bits;
    const ent_bytes = ent_bits / 8;
    if (ent_bytes > out.len) return error.BufferTooSmall;

    @memset(out[0..ent_bytes], 0);
    var bit: usize = 0;
    while (bit < ent_bits) : (bit += 1) {
        if (wordBit(idxs[bit / 11], bit % 11) == 1) {
            out[bit / 8] |= @as(u8, 1) << @intCast(7 - (bit % 8));
        }
    }

    var checksum: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(out[0..ent_bytes], &checksum, .{});
    var cbit: usize = 0;
    while (cbit < cs_bits) : (cbit += 1) {
        const abs_bit = ent_bits + cbit;
        const mnemonic_bit = wordBit(idxs[abs_bit / 11], abs_bit % 11);
        const checksum_bit: u1 = @truncate(checksum[cbit / 8] >> @intCast(7 - (cbit % 8)));
        if (mnemonic_bit != checksum_bit) return error.InvalidChecksum;
    }
    return out[0..ent_bytes];
}

/// Validates `mnemonic` (word count, wordlist membership, checksum) without
/// returning the entropy.
pub fn validateMnemonic(mnemonic: []const u8) Error!void {
    var buf: [max_entropy_bytes]u8 = undefined;
    _ = try mnemonicToEntropy(mnemonic, &buf);
}

/// Generous bound on the passphrase `mnemonicToSeed` accepts (real BIP-39
/// passphrases are short; this is headroom, not a spec limit).
pub const max_passphrase_len = 256;

pub const SeedError = error{PassphraseTooLong};

/// `mnemonicToSeed`: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" ‖ passphrase,
/// 2048 rounds) → the 64-byte BIP-32 master seed. `mnemonic` is NOT
/// checksum-validated here (BIP-39 defines seed derivation for any mnemonic
/// text, valid or not — validity is a separate, optional check via
/// `validateMnemonic`). The passphrase buffer is zeroized before return.
pub fn mnemonicToSeed(mnemonic: []const u8, passphrase: []const u8, out: *[64]u8) SeedError!void {
    if (passphrase.len > max_passphrase_len) return error.PassphraseTooLong;
    var salt_buf: [8 + max_passphrase_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &salt_buf);
    @memcpy(salt_buf[0..8], "mnemonic");
    @memcpy(salt_buf[8..][0..passphrase.len], passphrase);
    const salt = salt_buf[0 .. 8 + passphrase.len];

    // rounds=2048 >= 1 and dk_len(64)/h_len(64) = 1 < maxInt(u32): pbkdf2's
    // only two failure modes are structurally unreachable with these fixed
    // parameters.
    std.crypto.pwhash.pbkdf2(out, mnemonic, salt, 2048, std.crypto.auth.hmac.sha2.HmacSha512) catch unreachable;
}

// ── internal helpers ─────────────────────────────────────────────────────

/// Read an 11-bit big-endian group starting at absolute bit `bit_pos` from
/// the logical `entropy ‖ checksum` bitstream.
fn readBits11(entropy: []const u8, checksum: *const [32]u8, ent_bits: usize, bit_pos: usize) u11 {
    var idx: u11 = 0;
    var b: usize = 0;
    while (b < 11) : (b += 1) {
        const abs_bit = bit_pos + b;
        const byte = if (abs_bit < ent_bits) entropy[abs_bit / 8] else checksum[(abs_bit - ent_bits) / 8];
        const bit_val: u1 = @truncate(byte >> @intCast(7 - (abs_bit % 8)));
        idx = (idx << 1) | bit_val;
    }
    return idx;
}

/// Bit `n` (0 = MSB) of an 11-bit word index.
fn wordBit(word_idx: u11, n: usize) u1 {
    return @truncate(word_idx >> @intCast(10 - n));
}

/// Binary search `wordlist.english` (sorted, verified in `kat_test.zig`).
fn wordIndex(w: []const u8) ?u11 {
    var lo: usize = 0;
    var hi: usize = wordlist.count;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, wordlist.english[mid], w)) {
            .eq => return @intCast(mid),
            .lt => lo = mid + 1,
            .gt => hi = mid,
        }
    }
    return null;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "wordlist is sorted and has 2048 unique entries" {
    try testing.expectEqual(@as(usize, 2048), wordlist.count);
    var i: usize = 1;
    while (i < wordlist.count) : (i += 1) {
        try testing.expect(std.mem.order(u8, wordlist.english[i - 1], wordlist.english[i]) == .lt);
    }
}

test "wordIndex round-trips every wordlist entry" {
    for (wordlist.english, 0..) |w, i| {
        try testing.expectEqual(@as(?u11, @intCast(i)), wordIndex(w));
    }
    try testing.expectEqual(@as(?u11, null), wordIndex("notaword"));
    try testing.expectEqual(@as(?u11, null), wordIndex(""));
}

test "entropyToMnemonic rejects a bad entropy length" {
    var out: [max_mnemonic_len]u8 = undefined;
    try testing.expectError(error.InvalidEntropyLength, entropyToMnemonic(&[_]u8{0} ** 15, &out));
    try testing.expectError(error.InvalidEntropyLength, entropyToMnemonic(&[_]u8{0} ** 33, &out));
}

test "entropyToMnemonic / mnemonicToEntropy round-trip at every valid length" {
    var prng = std.Random.DefaultPrng.init(0xB1D3_9B1D_39);
    const rand = prng.random();
    inline for (.{ 16, 20, 24, 28, 32 }) |len| {
        var entropy: [len]u8 = undefined;
        rand.bytes(&entropy);

        var mnemonic_buf: [max_mnemonic_len]u8 = undefined;
        const mnemonic = try entropyToMnemonic(&entropy, &mnemonic_buf);

        try validateMnemonic(mnemonic);

        var entropy_buf: [max_entropy_bytes]u8 = undefined;
        const got = try mnemonicToEntropy(mnemonic, &entropy_buf);
        try testing.expectEqualSlices(u8, &entropy, got);
    }
}

test "mnemonicToEntropy rejects a tampered checksum word (positive control)" {
    var entropy = [_]u8{0} ** 16;
    var mnemonic_buf: [max_mnemonic_len]u8 = undefined;
    const mnemonic = try entropyToMnemonic(&entropy, &mnemonic_buf);
    _ = &entropy;

    // Flip the last word (carries the checksum bits) to a different, still
    // wordlist-valid word.
    const last_space = std.mem.lastIndexOfScalar(u8, mnemonic, ' ').?;
    var tampered_buf: [max_mnemonic_len]u8 = undefined;
    @memcpy(tampered_buf[0 .. last_space + 1], mnemonic[0 .. last_space + 1]);
    const replacement = if (std.mem.eql(u8, mnemonic[last_space + 1 ..], "abandon")) "ability" else "abandon";
    @memcpy(tampered_buf[last_space + 1 ..][0..replacement.len], replacement);
    const tampered = tampered_buf[0 .. last_space + 1 + replacement.len];

    var buf: [max_entropy_bytes]u8 = undefined;
    try testing.expectError(error.InvalidChecksum, mnemonicToEntropy(tampered, &buf));
    try testing.expectError(error.InvalidChecksum, validateMnemonic(tampered));
}

test "mnemonicToEntropy rejects wrong word count and unknown words" {
    var buf: [max_entropy_bytes]u8 = undefined;
    try testing.expectError(error.InvalidWordCount, mnemonicToEntropy("abandon abandon abandon", &buf));
    try testing.expectError(error.WordNotInList, mnemonicToEntropy(
        "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        &buf,
    ));
}

test "mnemonicToSeed matches a hand-computed PBKDF2-HMAC-SHA512 call" {
    const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    var got: [64]u8 = undefined;
    try mnemonicToSeed(mnemonic, "TREZOR", &got);

    var want: [64]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&want, mnemonic, "mnemonicTREZOR", 2048, std.crypto.auth.hmac.sha2.HmacSha512);
    try testing.expectEqualSlices(u8, &want, &got);
}

test "mnemonicToSeed rejects an over-long passphrase" {
    var got: [64]u8 = undefined;
    const too_long = [_]u8{'x'} ** (max_passphrase_len + 1);
    try testing.expectError(error.PassphraseTooLong, mnemonicToSeed("abandon", &too_long, &got));
}
