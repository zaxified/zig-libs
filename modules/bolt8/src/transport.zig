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

/// ⚠ Audit finding F13 (2026-09-05): `NonceExhausted` in both error sets is
/// structurally UNREACHABLE today. `maybeRotate` resets `n` to 0 the instant
/// it reaches `rotation_interval` (1000), so `n` can never climb toward
/// `CipherState`'s actual exhaustion point (2^64-1) — a `Direction` that
/// only ever goes through this module's own `sendMessage`/`recvLength`/
/// `recvMessage` cannot produce it (measured: 4000 messages, `max(n) ==
/// 1000`; see the "F13" test below). Left in the error set
/// rather than removed: it is what `CipherState.encryptWithAd`/
/// `decryptWithAd` themselves can still return if `Direction`'s invariant
/// is ever broken by a future change (e.g. a rotation call site skipped),
/// and a caller that already handles it costs nothing extra. Pinned by the
/// "F13: NonceExhausted is structurally unreachable" test below.
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

    /// Zero both directions' live cipher key and rotation chaining key.
    /// Audit finding F2 (2026-09-05): additive, no existing signature
    /// changes (`DECISIONS.md` P1/P3, zero in-repo consumers). See
    /// `handshake.Initiator.deinit`'s doc comment for the same caveat about
    /// dead-stack copies this does not reach.
    pub fn deinit(self: *Transport) void {
        std.crypto.secureZero(u8, &self.tx.cipher.k);
        std.crypto.secureZero(u8, &self.tx.chain);
        std.crypto.secureZero(u8, &self.rx.cipher.k);
        std.crypto.secureZero(u8, &self.rx.chain);
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
    ///
    /// ⚠ Audit finding F6 (2026-09-05): `rx`'s nonce advances on EVERY call
    /// to `recvLength` OR `recvMessage`, in strict alternation — there is no
    /// state tracking which one is expected next. A `recvLength` whose
    /// matching `recvMessage` never arrives (the caller read a header, then
    /// hit a timeout or a lower-layer error before the body) permanently
    /// desyncs `rx`: every later frame decrypts with the wrong nonce and
    /// fails closed with `error.DecryptionFailed` forever, not just once.
    /// `brontide`'s own `ReadHeader`/`ReadBody` carry the identical warning
    /// ("SHOULD NOT be used in the case that the io.Reader may be
    /// adversarial"). If your transport layer can fail between the two
    /// calls, rebuild the `Transport` (a fresh handshake) rather than retry
    /// on the same one.
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
    var t = Transport.init(.{ .sk = msg_test_sk.*, .rk = msg_test_rk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32, .remote_static = [_]u8{0} ** 33 });

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
    var sender = Transport.init(.{ .sk = msg_test_sk.*, .rk = msg_test_rk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32, .remote_static = [_]u8{0} ** 33 });
    var receiver = Transport.init(.{ .sk = msg_test_rk.*, .rk = msg_test_sk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32, .remote_static = [_]u8{0} ** 33 });

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
    var t = Transport.init(.{ .sk = msg_test_sk.*, .rk = msg_test_rk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32, .remote_static = [_]u8{0} ** 33 });
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
    var sender = Transport.init(.{ .sk = msg_test_sk.*, .rk = msg_test_rk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32, .remote_static = [_]u8{0} ** 33 });
    var receiver = Transport.init(.{ .sk = msg_test_rk.*, .rk = msg_test_sk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32, .remote_static = [_]u8{0} ** 33 });

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
    var sender = Transport.init(.{ .sk = msg_test_sk.*, .rk = msg_test_rk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32, .remote_static = [_]u8{0} ** 33 });
    var receiver = Transport.init(.{ .sk = msg_test_rk.*, .rk = msg_test_sk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32, .remote_static = [_]u8{0} ** 33 });

    var out: [length_frame_len + 5 + 16]u8 = undefined;
    try sender.sendMessage("hello", &out);
    out[out.len - 1] ^= 0x01;

    const l = try receiver.recvLength(out[0..length_frame_len]);
    var plain: [5]u8 = undefined;
    try testing.expectError(error.DecryptionFailed, receiver.recvMessage(out[length_frame_len..][0 .. l + 16], &plain));
}

test "F13: NonceExhausted is structurally unreachable through this module's own send/recv" {
    // Audit finding F13 (2026-09-05): `maybeRotate` resets `n` to 0 at
    // `rotation_interval` (1000), so a `Direction` driven only through
    // `sendMessage`/`recvLength`/`recvMessage` can never approach
    // `CipherState`'s real exhaustion point (2^64-1). 4000 messages spans
    // four rotation boundaries; `n` must never exceed `rotation_interval`.
    var sender = Transport.init(.{ .sk = msg_test_sk.*, .rk = msg_test_rk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32, .remote_static = [_]u8{0} ** 33 });
    var receiver = Transport.init(.{ .sk = msg_test_rk.*, .rk = msg_test_sk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32, .remote_static = [_]u8{0} ** 33 });
    var max_tx_n: u64 = 0;
    var max_rx_n: u64 = 0;
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        var out: [length_frame_len + 5 + 16]u8 = undefined;
        try sender.sendMessage("hello", &out);
        max_tx_n = @max(max_tx_n, sender.tx.cipher.n);
        const l = try receiver.recvLength(out[0..length_frame_len]);
        var plain: [5]u8 = undefined;
        try receiver.recvMessage(out[length_frame_len..][0 .. l + 16], &plain);
        max_rx_n = @max(max_rx_n, receiver.rx.cipher.n);
    }
    try testing.expect(max_tx_n <= rotation_interval);
    try testing.expect(max_rx_n <= rotation_interval);
}

// ── fuzz: the untrusted-wire transport decoders never panic/OOB ────────────
//
// Audit finding F3 (2026-09-05), second half: `act.zig`'s framing decoders
// got real corpora in a prior session, but "transport `decode`" (this
// file's `recvLength`/`recvMessage`) had NO harness at all — a fixed-size
// `Transport`, wired from the published KAT keys so every draw exercises a
// real AEAD decrypt rather than failing on an uninitialised cipher.

fn freshReceiver() Transport {
    return Transport.init(.{ .sk = msg_test_rk.*, .rk = msg_test_sk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32, .remote_static = [_]u8{0} ** 33 });
}

fn fuzzRecvLength(_: void, smith: *std.testing.Smith) !void {
    var t = freshReceiver();
    // Fixed-size read (not a ranged draw before it), so every input, fuzzed
    // or not, reaches `decryptWithAd` for real -- no `Smith` length-draw
    // collapse for this harness to fall into.
    var lc: [length_frame_len]u8 = undefined;
    smith.bytes(&lc);
    _ = t.recvLength(&lc) catch return;
}
test "fuzz Transport.recvLength never panics" {
    // Seeded with a genuine encrypted length frame (from the published
    // message-test fixture) so the corpus reaches the accept path at least
    // once, not just the near-certain AEAD-tag rejection of random bytes.
    var seed_out: [length_frame_len + 5 + 16]u8 = undefined;
    var seed_sender = Transport.init(.{ .sk = msg_test_sk.*, .rk = msg_test_rk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32, .remote_static = [_]u8{0} ** 33 });
    try seed_sender.sendMessage("hello", &seed_out);
    try testing.fuzz({}, fuzzRecvLength, .{ .corpus = &.{seed_out[0..length_frame_len]} });
}

/// `recvMessage`'s nonce is the SECOND use of `rx.cipher` in a real
/// send/recv pair (`recvLength` took the first). A fresh `Transport` handed
/// straight to `recvMessage` would decrypt every fuzzed input at nonce 0,
/// which is never what a real message body is keyed with -- so this target
/// first spends one genuine `recvLength` call (on the published seed's own
/// length frame, result ignored) purely to advance the nonce the way real
/// usage would, THEN fuzzes only the message body.
fn fuzzRecvMessage(_: void, smith: *std.testing.Smith) !void {
    var t = freshReceiver();
    _ = t.recvLength(&fixed_seed_length_frame) catch {};
    var c: [5 + 16]u8 = undefined;
    smith.bytes(&c);
    var out: [5]u8 = undefined;
    _ = t.recvMessage(&c, &out) catch return;
}
var fixed_seed_length_frame: [length_frame_len]u8 = undefined;
test "fuzz Transport.recvMessage never panics" {
    var seed_out: [length_frame_len + 5 + 16]u8 = undefined;
    var seed_sender = Transport.init(.{ .sk = msg_test_sk.*, .rk = msg_test_rk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32, .remote_static = [_]u8{0} ** 33 });
    try seed_sender.sendMessage("hello", &seed_out);
    fixed_seed_length_frame = seed_out[0..length_frame_len].*;
    try testing.fuzz({}, fuzzRecvMessage, .{ .corpus = &.{seed_out[length_frame_len..]} });
}

test "corpus: the transport seeds reach a real AEAD decrypt, not just the length gate" {
    var seed_out: [length_frame_len + 5 + 16]u8 = undefined;
    var seed_sender = Transport.init(.{ .sk = msg_test_sk.*, .rk = msg_test_rk.*, .ck = msg_test_ck.*, .handshake_hash = [_]u8{0} ** 32, .remote_static = [_]u8{0} ** 33 });
    try seed_sender.sendMessage("hello", &seed_out);

    var recv_len: Transport = freshReceiver();
    var smith_len: std.testing.Smith = .{ .in = seed_out[0..length_frame_len] };
    var lc: [length_frame_len]u8 = undefined;
    smith_len.bytes(&lc);
    const l = try recv_len.recvLength(&lc);
    try testing.expectEqual(@as(u16, 5), l);

    // recvMessage's nonce is the SECOND use of `rx.cipher` (recvLength took
    // the first), so this check must consume that first nonce the same way
    // real usage does before decrypting the body.
    var recv_msg: Transport = freshReceiver();
    _ = try recv_msg.recvLength(&lc);
    var smith_msg: std.testing.Smith = .{ .in = seed_out[length_frame_len..] };
    var c: [5 + 16]u8 = undefined;
    smith_msg.bytes(&c);
    var out: [5]u8 = undefined;
    try recv_msg.recvMessage(&c, &out);
    try testing.expectEqualStrings("hello", &out);
}
