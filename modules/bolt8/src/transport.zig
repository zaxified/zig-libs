// SPDX-License-Identifier: MIT

//! Post-handshake BOLT#8 transport: the `2-byte-length ‖ 16-byte tag ‖
//! payload ‖ 16-byte tag` wire framing ("Lightning Message Specification")
//! plus the every-1000-messages key-rotation ratchet ("Lightning Message
//! Key Rotation").
//!
//! REAL, not a Fable stub — once a `handshake.HandshakeResult` exists
//! (today only reachable via `handshake.zig`'s stubbed act driver, or
//! constructed by hand for testing, as this file's own tests do), every
//! function here runs for real: it is built entirely on `noise`'s
//! already-real, already-KAT-verified `CipherState`/`SymmetricState` (see
//! ../SPEC.md's "Noise-reuse decision" and this file's own doc comments
//! below for exactly how the rotation ratchet reuses `SymmetricState.
//! mixKey` rather than hand-rolling a second HKDF chain).

const std = @import("std");
const handshake = @import("handshake.zig");
const Suite = handshake.Suite;
const CipherState = Suite.CipherState;

/// BOLT#8 "Lightning Message Specification": "The *maximum* size of _any_
/// Lightning message MUST NOT exceed 65535 bytes."
pub const max_message_len: usize = 65535;
/// The encrypted 2-byte length prefix plus its 16-byte AEAD tag (BOLT#8's
/// wire diagram: "2-byte encrypted message length" + "16-byte MAC").
pub const length_frame_len: usize = 2 + 16;
/// BOLT#8 "Lightning Message Key Rotation": "A key is to be rotated after
/// a party encrypts or decrypts 1000 times with it... This can be properly
/// accounted for by rotating the key once the nonce dedicated to it
/// reaches 1000."
pub const rotation_interval: u64 = 1000;

/// One direction's live cipher state (`sk`+`sn` or `rk`+`rn` in the spec)
/// plus the rotation chaining key (`sck`/`rck`) the vanilla Noise
/// `CipherState` doesn't track on its own once the handshake is over —
/// BOLT#8 needs it ONLY to re-key every `rotation_interval` messages.
pub const Direction = struct {
    cipher: CipherState,
    /// The rotation chaining key. BOLT#8 Act Three initializes this to
    /// the final handshake `ck` (spec: "8. `rck = sck = ck`" /
    /// "10. `rck = sck = ck`" on the initiator/responder side
    /// respectively) — see `handshake.HandshakeResult.ck`'s doc comment
    /// for why that value is exactly `SymmetricState.ck` right after
    /// `split()`.
    chain: [32]u8,

    pub fn init(key: [32]u8, chain: [32]u8) Direction {
        var cipher: CipherState = .{};
        cipher.initializeKey(key);
        return .{ .cipher = cipher, .chain = chain };
    }

    /// BOLT#8 "Lightning Message Key Rotation", steps 1-5 for a single key
    /// `k` with chaining key `ck`:
    ///
    ///   1. `ck` is the chaining key (`self.chain`).
    ///   2. `ck', k' = HKDF(ck, k)`.
    ///   3. Reset the nonce for the key to `n = 0`.
    ///   4. `k = k'`.
    ///   5. `ck = ck'`.
    ///
    /// This is EXACTLY `SymmetricState.mixKey(ikm)`'s formula
    /// (`noise/src/state.zig`: `out = noiseHkdf(2, &self.ck, ikm); self.ck
    /// = out[0]; self.cipher_state.initializeKey(out[1])` — and
    /// `initializeKey` also resets `n` to 0, covering step 3 for free) run
    /// over a throwaway `SymmetricState` shell seeded with THIS
    /// direction's own `(chain, cipher.k)` as `(ck, ikm)` — reusing
    /// `noise`'s real, already-KAT-verified HKDF chain instead of
    /// hand-rolling a second copy of the same construction. Verified
    /// byte-exact against BOLT#8's own published rotation intermediates in
    /// `kat_test.zig`.
    fn rotate(self: *Direction) void {
        var shell: Suite.SymmetricState = .{ .ck = self.chain };
        shell.mixKey(&self.cipher.k);
        self.chain = shell.ck;
        self.cipher = shell.cipher_state;
    }

    /// Rotate iff this direction's nonce counter has just reached
    /// `rotation_interval` — call after every encrypt/decrypt operation
    /// using this direction's cipher (mirrors the spec's "after a party
    /// encrypts or decrypts 1000 times with it").
    fn maybeRotate(self: *Direction) void {
        if (self.cipher.n == rotation_interval) self.rotate();
    }
};

pub const SendError = error{ MessageTooLong, BufferWrongSize, NonceExhausted };
pub const RecvError = error{ DecryptionFailed, NonceExhausted, BufferWrongSize };

/// A live, post-handshake BOLT#8 connection: one send direction, one
/// receive direction, each independently key-rotated.
pub const Transport = struct {
    tx: Direction,
    rx: Direction,

    /// Wires up `tx`/`rx` from a completed handshake's `sk`/`rk`/`ck`
    /// (`handshake.HandshakeResult`) per BOLT#8 Act Three steps 6-8 (or
    /// the receiver's mirrored 9-11): `rn = sn = 0` (`Direction.init` via
    /// `CipherState.initializeKey`), `rck = sck = ck`.
    pub fn init(result: handshake.HandshakeResult) Transport {
        return .{
            .tx = Direction.init(result.sk, result.ck),
            .rx = Direction.init(result.rk, result.ck),
        };
    }

    /// BOLT#8 "Encrypting and Sending Messages": encrypts the 2-byte
    /// big-endian length prefix, then the message itself, both under `tx`
    /// (auto-rotating after either operation lands the nonce on
    /// `rotation_interval`). `out` must be exactly `length_frame_len +
    /// m.len + 16` bytes; writes `lc || c` into it ready to send as-is.
    pub fn sendMessage(self: *Transport, m: []const u8, out: []u8) SendError!void {
        if (m.len > max_message_len) return error.MessageTooLong;
        if (out.len != length_frame_len + m.len + 16) return error.BufferWrongSize;

        var l_be: [2]u8 = undefined;
        std.mem.writeInt(u16, &l_be, @intCast(m.len), .big);
        self.tx.cipher.encryptWithAd("", &l_be, out[0..length_frame_len]) catch |e| return switch (e) {
            error.BufferTooSmall => error.BufferWrongSize,
            else => |other| other,
        };
        self.tx.maybeRotate();

        self.tx.cipher.encryptWithAd("", m, out[length_frame_len..]) catch |e| return switch (e) {
            error.BufferTooSmall => error.BufferWrongSize,
            else => |other| other,
        };
        self.tx.maybeRotate();
    }

    /// "Receiving and Decrypting Messages" steps 1-3: decrypt the 18-byte
    /// encrypted length prefix, returning the plaintext length `l` the
    /// caller must then read `l + 16` more bytes for (`recvMessage`).
    pub fn recvLength(self: *Transport, lc: *const [length_frame_len]u8) RecvError!u16 {
        var l_be: [2]u8 = undefined;
        self.rx.cipher.decryptWithAd("", lc, &l_be) catch |e| return switch (e) {
            error.BufferTooSmall => error.BufferWrongSize,
            else => |other| other,
        };
        self.rx.maybeRotate();
        return std.mem.readInt(u16, &l_be, .big);
    }

    /// Steps 4-5: decrypt the message body once `l + 16` bytes are in
    /// hand (`c.len == out.len + 16`).
    pub fn recvMessage(self: *Transport, c: []const u8, out: []u8) RecvError!void {
        if (c.len != out.len + 16) return error.BufferWrongSize;
        self.rx.cipher.decryptWithAd("", c, out) catch |e| return switch (e) {
            error.BufferTooSmall => error.BufferWrongSize,
            else => |other| other,
        };
        self.rx.maybeRotate();
    }
};

// ── tests: real KATs (BOLT#8 Appendix A "Message Encryption Tests") ─────
//
// Hex constants + the published output/rotation tables live in
// `kat_vectors.zig` (single source of truth).

const testing = std.testing;
const kv = @import("kat_vectors.zig");
const msg_test_ck = kv.msg_test_ck;
const msg_test_sk = kv.msg_test_sk;
const msg_test_rk = kv.msg_test_rk;

test "Direction.rotate: matches the published rotation intermediates byte-exact (twice)" {
    var d = Direction.init(msg_test_sk.*, msg_test_ck.*);
    d.rotate();
    try testing.expectEqualSlices(u8, kv.rotation_1.chain, &d.chain);
    try testing.expectEqualSlices(u8, kv.rotation_1.key, &d.cipher.k);
    try testing.expectEqual(@as(u64, 0), d.cipher.n);

    d.rotate();
    try testing.expectEqualSlices(u8, kv.rotation_2.chain, &d.chain);
    try testing.expectEqualSlices(u8, kv.rotation_2.key, &d.cipher.k);
}

test "Transport.sendMessage: 1001x 'hello' reproduces all 6 published outputs, auto-rotating at message 500/1000" {
    var t = Transport.init(.{ .sk = msg_test_sk.*, .rk = msg_test_rk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32 });

    var want_i: usize = 0;
    var out: [length_frame_len + 5 + 16]u8 = undefined;
    var i: usize = 0;
    while (i <= 1001) : (i += 1) {
        try t.sendMessage("hello", &out);
        if (want_i < kv.msg_outputs.len and kv.msg_outputs[want_i].idx == i) {
            try testing.expectEqualSlices(u8, kv.msg_outputs[want_i].bytes, &out);
            want_i += 1;
        }
    }
    try testing.expectEqual(kv.msg_outputs.len, want_i);
}

test "Transport: round-trip send/recv across a rotation boundary (real decrypt of the published outputs)" {
    // Two independent Transports sharing the same handshake result, one
    // used only to send, one only to receive — decrypting the SAME
    // messages the sender produced (both directions rotate identically
    // since both start from the same (ck, sk) as "their own" tx key).
    var sender = Transport.init(.{ .sk = msg_test_sk.*, .rk = msg_test_rk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32 });
    var receiver = Transport.init(.{ .sk = msg_test_rk.*, .rk = msg_test_sk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32 });

    var i: usize = 0;
    while (i < 1002) : (i += 1) {
        var out: [length_frame_len + 5 + 16]u8 = undefined;
        try sender.sendMessage("hello", &out);

        const l = try receiver.recvLength(out[0..length_frame_len]);
        try testing.expectEqual(@as(u16, 5), l);
        var plain: [5]u8 = undefined;
        try receiver.recvMessage(out[length_frame_len..], &plain);
        try testing.expectEqualStrings("hello", &plain);
    }
}

test "Transport.sendMessage: rejects an oversized message and a wrong-size buffer" {
    var t = Transport.init(.{ .sk = msg_test_sk.*, .rk = msg_test_rk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32 });
    var out: [length_frame_len + 5 + 16]u8 = undefined;
    try testing.expectError(error.BufferWrongSize, t.sendMessage("hello", out[0 .. out.len - 1]));

    // Heap-allocated: max_message_len+1 (~64KiB) is too large to comfortably
    // put on the test-runner's stack twice over (message + output buffer).
    const too_big = try testing.allocator.alloc(u8, max_message_len + 1);
    defer testing.allocator.free(too_big);
    const big_out = try testing.allocator.alloc(u8, length_frame_len + too_big.len + 16);
    defer testing.allocator.free(big_out);
    try testing.expectError(error.MessageTooLong, t.sendMessage(too_big, big_out));
}

test "Transport.recvMessage: rejects a mismatched-size out buffer BEFORE decrypting anything into it" {
    // Unlike sendMessage's own wrong-size check (tested above),
    // recvMessage's `c.len != out.len + 16` guard had no direct test —
    // `noise`'s underlying `CipherState.decryptWithAd` only asserts
    // `out.len >= msg_len` (see its own doc), so an oversized `out` here
    // would otherwise silently decrypt into just the LEADING bytes of
    // `out`, leaving the rest of the caller's buffer untouched (stale/
    // uninitialized) while looking like a normal successful call — this
    // guard is what turns that into an explicit, loud rejection instead.
    var sender = Transport.init(.{ .sk = msg_test_sk.*, .rk = msg_test_rk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32 });
    var receiver = Transport.init(.{ .sk = msg_test_rk.*, .rk = msg_test_sk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32 });

    var out: [length_frame_len + 5 + 16]u8 = undefined;
    try sender.sendMessage("hello", &out);
    _ = try receiver.recvLength(out[0..length_frame_len]);

    const c = out[length_frame_len..]; // 5 + 16 = 21 bytes of real ciphertext
    var too_big_out: [10]u8 = undefined; // out.len + 16 = 26 != c.len (21)
    try testing.expectError(error.BufferWrongSize, receiver.recvMessage(c, &too_big_out));
    var too_small_out: [2]u8 = undefined;
    try testing.expectError(error.BufferWrongSize, receiver.recvMessage(c, &too_small_out));
}

test "Transport.recvMessage: a tampered ciphertext fails closed with DecryptionFailed" {
    var sender = Transport.init(.{ .sk = msg_test_sk.*, .rk = msg_test_rk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32 });
    var receiver = Transport.init(.{ .sk = msg_test_rk.*, .rk = msg_test_sk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32 });

    var out: [length_frame_len + 5 + 16]u8 = undefined;
    try sender.sendMessage("hello", &out);
    out[out.len - 1] ^= 0x01;

    const l = try receiver.recvLength(out[0..length_frame_len]);
    var plain: [5]u8 = undefined;
    try testing.expectError(error.DecryptionFailed, receiver.recvMessage(out[length_frame_len..][0 .. l + 16], &plain));
}
