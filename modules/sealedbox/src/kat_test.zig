// SPDX-License-Identifier: MIT
//! External-vector verification for `crypto_box_seal` (the full
//! seal/open composition, not just its X25519 math) — see `kat_vectors.zig`
//! for full provenance of every hex string and the deterministic-ephemeral
//! technique used here.

const std = @import("std");
const testing = std.testing;
const sealedbox = @import("root.zig");
const SealedBox = std.crypto.nacl.SealedBox;
const kat = @import("kat_vectors.zig");

fn hexDecode32(comptime hex: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn hexDecodeAlloc(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, hex.len / 2);
    return try std.fmt.hexToBytes(out, hex);
}

/// Wraps `std.testing.io` but overrides only the `.random` vtable entry, so
/// `SealedBox.seal`'s ephemeral-keypair generation (`X25519.KeyPair.generate`
/// -> `io.random(&seed)`) reads a fixed 32-byte seed instead of real entropy.
/// Every other `Io` operation (unused here) still goes through the real
/// vtable/userdata — only `random` is intercepted.
const FixedRandom = struct {
    bytes: [32]u8,
    fn randomFn(userdata: ?*anyopaque, buffer: []u8) void {
        const self: *const FixedRandom = @ptrCast(@alignCast(userdata.?));
        std.debug.assert(buffer.len <= self.bytes.len);
        @memcpy(buffer, self.bytes[0..buffer.len]);
    }
};

fn fixedIo(io: std.Io, vt: *std.Io.VTable, fixed: *FixedRandom) std.Io {
    vt.* = io.vtable.*;
    vt.random = FixedRandom.randomFn;
    return .{ .userdata = fixed, .vtable = vt };
}

test "external anchor: deterministic-ephemeral seal() matches an independently-computed libsodium (PyNaCl) vector" {
    const recipient_pk = hexDecode32(kat.recipient_pk_hex);
    const recipient_sk = hexDecode32(kat.recipient_sk_hex);

    var fixed = FixedRandom{ .bytes = hexDecode32(kat.fixed_ephemeral_seed_hex) };
    var vt: std.Io.VTable = undefined;
    const io = fixedIo(std.testing.io, &vt, &fixed);

    var sealed: [kat.message.len + sealedbox.overhead]u8 = undefined;
    try sealedbox.seal(io, &sealed, kat.message, recipient_pk);

    var expected_buf: [sealed.len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_buf, kat.expected_sealed_hex);
    try testing.expectEqualSlices(u8, &expected_buf, &sealed);

    // And it opens correctly with the recipient keypair (module's real API).
    var opened: [kat.message.len]u8 = undefined;
    try sealedbox.open(&opened, &sealed, .{ .public_key = recipient_pk, .secret_key = recipient_sk });
    try testing.expectEqualSlices(u8, kat.message, &opened);
}

test "TEETH CHECK: corrupting the expected vector's last byte makes the comparison fail" {
    const recipient_pk = hexDecode32(kat.recipient_pk_hex);
    var fixed = FixedRandom{ .bytes = hexDecode32(kat.fixed_ephemeral_seed_hex) };
    var vt: std.Io.VTable = undefined;
    const io = fixedIo(std.testing.io, &vt, &fixed);

    var sealed: [kat.message.len + sealedbox.overhead]u8 = undefined;
    try sealedbox.seal(io, &sealed, kat.message, recipient_pk);

    var corrupted: [sealed.len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&corrupted, kat.expected_sealed_hex);
    corrupted[corrupted.len - 1] ^= 0x01;
    // Proves the vector actually constrains the output: flipping one byte
    // of the "expected" side must break the match.
    try testing.expect(!std.mem.eql(u8, &corrupted, &sealed));
}

test "external anchor: classic djb/NaCl crypto_box vector (libsodium test/default/box.c) round-trips byte-exact" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const alice_sk = hexDecode32(kat.box_alice_sk_hex);
    const bob_pk = hexDecode32(kat.box_bob_pk_hex);
    var nonce: [std.crypto.nacl.Box.nonce_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&nonce, kat.box_nonce_hex);
    const msg = try hexDecodeAlloc(a, kat.box_message_hex);
    const expected_ct = try hexDecodeAlloc(a, kat.box_expected_ciphertext_hex);

    const c = try a.alloc(u8, msg.len + std.crypto.nacl.Box.tag_length);
    try std.crypto.nacl.Box.seal(c, msg, nonce, bob_pk, alice_sk);
    try testing.expectEqualSlices(u8, expected_ct, c);

    const m2 = try a.alloc(u8, msg.len);
    try std.crypto.nacl.Box.open(m2, c, nonce, bob_pk, alice_sk);
    try testing.expectEqualSlices(u8, msg, m2);
}

test "TEETH CHECK: corrupting the classic box vector's expected ciphertext makes the comparison fail" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const alice_sk = hexDecode32(kat.box_alice_sk_hex);
    const bob_pk = hexDecode32(kat.box_bob_pk_hex);
    var nonce: [std.crypto.nacl.Box.nonce_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&nonce, kat.box_nonce_hex);
    const msg = try hexDecodeAlloc(a, kat.box_message_hex);
    const expected_ct = try hexDecodeAlloc(a, kat.box_expected_ciphertext_hex);
    expected_ct[0] ^= 0x01;

    const c = try a.alloc(u8, msg.len + std.crypto.nacl.Box.tag_length);
    try std.crypto.nacl.Box.seal(c, msg, nonce, bob_pk, alice_sk);
    try testing.expect(!std.mem.eql(u8, expected_ct, c));
}

// ── fuzz: open on hostile ciphertext bytes ──────────────────────────────
//
// `open` is the module's untrusted-input entry point: an anonymous sender
// hands the recipient an arbitrary byte string claiming to be a sealed
// box, and it must return an error (`InvalidCiphertext`/
// `AuthenticationFailed`) — never panic, never read out of bounds — for
// any length or content. `kp` is pinned to the module's own KAT keypair
// (`recipient_pk_hex`/`recipient_sk_hex`); the ciphertext bytes and
// output-buffer length are both fully fuzzed (unlike the other harnesses
// in this repo, there is no "nearly valid" bias to lean on here — the
// AEAD tag makes every byte equally load-bearing, so pure random input
// already reaches the interesting authentication-failure path).
/// `testkit.fuzz.seed`: a corpus entry is NOT the ciphertext. `Smith.slice`
/// reads a little-endian `u32` length first, so the sealed box handed to the
/// corpus raw would reach `open` with four octets of its ephemeral public key
/// missing — which is an authentication failure for an uninteresting reason.
const seed = @import("testkit").fuzz.seed;

/// The module's own KAT sealed box, decoded at comptime so the corpus can
/// carry it and the three mutants below.
const kat_sealed = blk: {
    var out: [kat.expected_sealed_hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, kat.expected_sealed_hex) catch unreachable;
    break :blk out;
};
const kat_sealed_bad_epk = blk: {
    var b = kat_sealed;
    b[0] ^= 0x01; // inside the ephemeral public key
    break :blk b;
};
const kat_sealed_bad_tag = blk: {
    var b = kat_sealed;
    b[32] ^= 0x01; // inside the Poly1305 tag
    break :blk b;
};
const kat_sealed_bad_body = blk: {
    var b = kat_sealed;
    b[b.len - 1] ^= 0x01; // inside the message
    break :blk b;
};

/// Ciphertexts in the format `Smith.slice` reads (see `testkit.fuzz`).
///
/// The file comment above argues that pure random input already reaches the
/// authentication-failure path, and that is true — but it reaches ONLY that
/// path. Nothing random ever opens, so without the KAT box below the success
/// branch of `open`, and every line after it, was unreachable from this
/// target. That is the gap a corpus closes here, not the refusal coverage.
const open_seeds = [_][]const u8{
    seed(&kat_sealed), // the real sealed box: opens
    seed(&kat_sealed_bad_epk), // a flipped ephemeral public key
    seed(&kat_sealed_bad_tag), // a flipped Poly1305 tag
    seed(&kat_sealed_bad_body), // a flipped message byte
    seed(&[_]u8{0} ** sealedbox.overhead), // exactly `overhead`: a zero-length plaintext
    seed(&[_]u8{0} ** (sealedbox.overhead - 1)), // one octet short of `overhead`
    seed(&[_]u8{0xAA} ** 256), // the full harness buffer
    seed(""), // the ONE input the collapsed harness ever ran
};

test "fuzz: open never panics on arbitrary ciphertext bytes" {
    try std.testing.fuzz({}, fuzzOpen, .{ .corpus = &open_seeds });
}

fn fuzzOpen(_: void, smith: *std.testing.Smith) !void {
    const kp = sealedbox.KeyPair{
        .public_key = hexDecode32(kat.recipient_pk_hex),
        .secret_key = hexDecode32(kat.recipient_sk_hex),
    };

    var sealed_buf: [256]u8 = undefined;
    // ⚠ One `smith.slice` call. The length used to be drawn FIRST, with
    // `smith.valueRangeAtMost(u16, 0, 256)`, and the bytes read into
    // `sealed_buf[0..sealed_len]` afterwards — but a ranged `Smith` draw reads
    // eight octets as a little-endian u64 and returns the range MINIMUM unless
    // that whole word lands inside the range, so `sealed_len` was 0 and the
    // `bytes` call that followed it copied nothing at all. `open` was handed a
    // zero-length ciphertext, refused it on the `sealed.len < overhead` line,
    // and no other line of this module ever ran from the fuzzer. Measured
    // 2026-09-07 over the corpus above: **0 of 8 seeds non-empty and 0 boxes
    // opened before, 7 of 8 non-empty (one seed IS the empty ciphertext) and 1
    // opened after.**
    const sealed_len: usize = smith.slice(&sealed_buf);
    const sealed = sealed_buf[0..sealed_len];

    var out_buf: [256]u8 = undefined;
    const out_len = if (sealed_len >= sealedbox.overhead) sealed_len - sealedbox.overhead else 0;
    sealedbox.open(out_buf[0..out_len], sealed, kp) catch return;
}

test "corpus: every ciphertext reaches open, and the opened count is pinned" {
    // ⭐ The measurement, executable rather than written in a comment. A seed
    // longer than the harness's buffer reads back EMPTY (`Smith.slice` falls
    // back to the range minimum) and nothing else would notice.
    //
    // `opened` is the number the collapsed harness could not produce by
    // construction: a zero-length ciphertext is shorter than `overhead`, so it
    // dies before the AEAD. `recovered` pins the plaintext length beside it,
    // so shortening the KAT seed is caught too.
    const kp = sealedbox.KeyPair{
        .public_key = hexDecode32(kat.recipient_pk_hex),
        .secret_key = hexDecode32(kat.recipient_sk_hex),
    };
    var nonempty: usize = 0;
    var opened: usize = 0;
    var recovered: usize = 0;
    for (open_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var sealed_buf: [256]u8 = undefined;
        const sealed_len: usize = smith.slice(&sealed_buf);
        if (sealed_len != 0) nonempty += 1;
        var out_buf: [256]u8 = undefined;
        const out_len = if (sealed_len >= sealedbox.overhead) sealed_len - sealedbox.overhead else 0;
        if (sealedbox.open(out_buf[0..out_len], sealed_buf[0..sealed_len], kp)) |_| {
            opened += 1;
            recovered += out_len;
        } else |_| {}
    }
    // One seed IS the empty ciphertext, a legal member of a refusal corpus.
    try testing.expectEqual(open_seeds.len - 1, nonempty);
    // Measured 2026-09-07: with the length drawn first, 0 non-empty, 0 opened
    // and 0 plaintext octets — the same empty ciphertext eight times. After:
    try testing.expectEqual(@as(usize, 1), opened);
    try testing.expectEqual(kat.message.len, recovered);
}
