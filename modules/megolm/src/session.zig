// SPDX-License-Identifier: MIT

//! session.zig — the two session roles megolm.md's "The Megolm protocol"
//! section describes: `OutboundSession` (the sender's ratchet + Ed25519
//! keypair, "session setup") and `InboundGroupSession` (a recipient's copy,
//! built from a `SessionKey`/`ExportedSessionKey`). This is the only file
//! in the module that holds both the ratchet AND the Ed25519 keys
//! together, and therefore the only place that actually computes/verifies
//! a MAC or a signature — `message.zig` only knows the byte ranges those
//! cover, `cipher.zig` only knows how to run HMAC/AES given key material.
//!
//! ## The four reject-teeth, and why each is its own error
//!
//! `decrypt` distinguishes four failure modes that a naive implementation
//! could collapse into one generic "decrypt failed":
//!
//!   - `error.InvalidSignature` — the Ed25519 signature over the message
//!     frame doesn't verify. Checked FIRST (before even looking up the
//!     ratchet), matching vodozemac's `InboundGroupSession::decrypt` order
//!     — an unauthenticated message shouldn't get to influence which
//!     ratchet state gets fast-forwarded.
//!   - `error.MessageIndexTooOld` — the message's signature is fine, but
//!     its index is EARLIER than this session's `first_known_index` (this
//!     session has already forgotten, or was never given, that ratchet
//!     state — the whole point of the one-way ratchet: it CANNOT be
//!     recovered). This is a SESSION-level "we don't have the key"
//!     outcome, not a ratchet-primitive guard.
//!   - `error.InvalidMac` — the message's signature and index are fine
//!     (so the right key material was located), but the HMAC over the
//!     ciphertext doesn't match. In practice, since the signature covers
//!     the MAC bytes too, an attacker who has tampered the ciphertext
//!     without the signing key has ALREADY been caught by the signature
//!     check above — this path is reachable in the wild only via key
//!     mismatch (decrypting under the wrong session), and is exercised
//!     directly in `kat_test.zig` by a message deliberately re-signed
//!     over a wrong MAC (see that file for why this is an honest test
//!     construction, not a scenario that can't occur).
//!   - `error.InvalidPadding` — the MAC passed but the decrypted bytes
//!     aren't validly PKCS#7-padded. `cipher.decryptCbc`'s doc comment
//!     covers the padding-oracle reason this path is only ever reached
//!     AFTER the MAC check, never before.
//!
//! Separately, `ratchet.Ratchet.advanceTo` has its own
//! `error.CannotRatchetBackward` for a caller that tries to move the raw
//! ratchet primitive to an earlier index directly — see ratchet.zig's
//! module doc comment for why that is a DIFFERENT scenario from
//! `MessageIndexTooOld` above (a proactive guard on the primitive, vs. a
//! reactive "we already forgot that state" outcome at the session level).

const std = @import("std");
const ratchet_mod = @import("ratchet.zig");
const cipher_mod = @import("cipher.zig");
const message_mod = @import("message.zig");
const session_key_mod = @import("session_key.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Ratchet = ratchet_mod.Ratchet;
const Message = message_mod.Message;
const SessionKey = session_key_mod.SessionKey;
const ExportedSessionKey = session_key_mod.ExportedSessionKey;

/// The sending side: a fresh random ratchet plus an Ed25519 signing
/// keypair (megolm.md "Session setup").
pub const OutboundSession = struct {
    ratchet: Ratchet,
    signing_key: Ed25519.KeyPair,

    pub fn init(io: std.Io) OutboundSession {
        return .{
            .ratchet = Ratchet.generate(io),
            .signing_key = Ed25519.KeyPair.generate(io),
        };
    }

    pub fn deinit(self: *OutboundSession) void {
        self.ratchet.secureZero();
        std.crypto.secureZero(u8, &self.signing_key.secret_key.bytes);
    }

    /// The ratchet index the NEXT `encrypt` call will use (spec's counter
    /// `i`; starts at 0).
    pub fn messageIndex(self: *const OutboundSession) u32 {
        return self.ratchet.counter;
    }

    /// Base64(Ed25519 public key) — a session's globally-unique identifier
    /// (the spec: "The public part of K is used as an identifier to
    /// discriminate between sessions").
    pub fn sessionId(self: *const OutboundSession, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return base64EncodeBytes(allocator, &self.signing_key.public_key.toBytes());
    }

    /// The signed session-sharing format at the CURRENT ratchet index —
    /// what gets sent to other participants so they can build an
    /// `InboundGroupSession`.
    pub fn sessionKey(self: *const OutboundSession) !SessionKey {
        const inner = ExportedSessionKey{
            .ratchet_index = self.ratchet.counter,
            .ratchet = self.ratchet.data,
            .signing_key = self.signing_key.public_key.toBytes(),
        };
        var signed_part: [session_key_mod.signed_part_len]u8 = undefined;
        inner.encodeSignedPart(session_key_mod.share_version, &signed_part);
        const sig = try self.signing_key.sign(&signed_part, null);
        return .{ .inner = inner, .signature = sig.toBytes() };
    }

    /// Encrypt `plaintext` at the current index, sign, then advance the
    /// ratchet by one (spec: "After each message is encrypted, the
    /// ratchet is advanced"). Caller owns the returned `Message`
    /// (`msg.deinit(allocator)`).
    pub fn encrypt(self: *OutboundSession, allocator: std.mem.Allocator, plaintext: []const u8) !Message {
        var keys = cipher_mod.deriveKeys(&self.ratchet.data);
        defer keys.deinit();

        const ciphertext = try cipher_mod.encryptCbc(allocator, &keys, plaintext);
        errdefer allocator.free(ciphertext);

        var msg = Message{
            .message_index = self.ratchet.counter,
            .ciphertext = ciphertext,
            .mac = undefined,
            .signature = undefined,
        };

        const mac_bytes = try msg.macBytes(allocator);
        defer allocator.free(mac_bytes);
        const full_mac = cipher_mod.fullMac(&keys.hmac_key, mac_bytes);
        msg.mac = full_mac[0..message_mod.wire_mac_len].*;

        const sig_bytes = try msg.signatureBytes(allocator);
        defer allocator.free(sig_bytes);
        const sig = try self.signing_key.sign(sig_bytes, null);
        msg.signature = sig.toBytes();

        self.ratchet.advanceStep();
        return msg;
    }
};

pub const DecryptedMessage = struct {
    plaintext: []u8,
    message_index: u32,

    pub fn deinit(self: *DecryptedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.plaintext);
        self.* = undefined;
    }
};

pub const DecryptError = error{
    InvalidSignature,
    MessageIndexTooOld,
    InvalidMac,
    InvalidPadding,
} || std.mem.Allocator.Error;

/// The receiving side: an earliest-known ratchet state (`initial_ratchet`)
/// plus a cache of the furthest index fast-forwarded to so far
/// (`latest_ratchet`, an optimization only — correctness never depends on
/// it, `findRatchet` recomputes from `initial_ratchet` whenever the cache
/// doesn't cover the requested index) and the sender's Ed25519 public key.
pub const InboundGroupSession = struct {
    initial_ratchet: Ratchet,
    latest_ratchet: Ratchet,
    signing_key: Ed25519.PublicKey,
    /// Whether `signing_key` itself has been authenticated as belonging to
    /// the claimed sender. `fromSessionKey` sets this `true` (the
    /// session-sharing format self-verifies its embedded key against its
    /// own signature — see session_key.zig); `fromExportedKey` sets it
    /// `false` (an export carries no signature at all; the caller's
    /// out-of-band channel is what would authenticate it, if anything
    /// does — mirrors vodozemac's identical distinction).
    signing_key_verified: bool,

    pub fn fromSessionKey(key: SessionKey) !InboundGroupSession {
        const pk = try Ed25519.PublicKey.fromBytes(key.inner.signing_key);
        const r = Ratchet.init(key.inner.ratchet, key.inner.ratchet_index);
        return .{ .initial_ratchet = r, .latest_ratchet = r, .signing_key = pk, .signing_key_verified = true };
    }

    /// **Caution**: an `ExportedSessionKey` carries no signature (see
    /// session_key.zig's module doc comment) — authenticating the
    /// embedded `signing_key` is entirely this caller's responsibility if
    /// it matters for the caller's threat model.
    pub fn fromExportedKey(key: ExportedSessionKey) !InboundGroupSession {
        const pk = try Ed25519.PublicKey.fromBytes(key.signing_key);
        const r = Ratchet.init(key.ratchet, key.ratchet_index);
        return .{ .initial_ratchet = r, .latest_ratchet = r, .signing_key = pk, .signing_key_verified = false };
    }

    pub fn deinit(self: *InboundGroupSession) void {
        self.initial_ratchet.secureZero();
        self.latest_ratchet.secureZero();
    }

    /// The earliest message index this session can decrypt. Messages
    /// before this index are permanently unrecoverable (the ratchet is
    /// one-way) — decrypting one returns `error.MessageIndexTooOld`.
    pub fn firstKnownIndex(self: *const InboundGroupSession) u32 {
        return self.initial_ratchet.counter;
    }

    pub fn sessionId(self: *const InboundGroupSession, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return base64EncodeBytes(allocator, &self.signing_key.toBytes());
    }

    /// Locate (fast-forwarding `latest_ratchet` if needed) the ratchet
    /// state at `index`. Returns `null` if `index` is earlier than
    /// `initial_ratchet`'s — the one case this module cannot recover from,
    /// by design.
    fn findRatchet(self: *InboundGroupSession, index: u32) ?*const Ratchet {
        if (self.initial_ratchet.counter == index) return &self.initial_ratchet;
        if (self.latest_ratchet.counter == index) return &self.latest_ratchet;
        if (self.latest_ratchet.counter < index) {
            // Always reachable: `latest_ratchet.counter < index` here.
            self.latest_ratchet.advanceTo(index) catch unreachable;
            return &self.latest_ratchet;
        }
        if (self.initial_ratchet.counter < index) {
            self.latest_ratchet = self.initial_ratchet;
            self.latest_ratchet.advanceTo(index) catch unreachable;
            return &self.latest_ratchet;
        }
        return null;
    }

    /// Verify the signature, locate the ratchet, verify the MAC, then
    /// decrypt. See this file's module doc comment for why these are four
    /// distinct typed errors. Caller owns the returned plaintext.
    pub fn decrypt(self: *InboundGroupSession, allocator: std.mem.Allocator, msg: *const Message) DecryptError!DecryptedMessage {
        const sig_bytes = try msg.signatureBytes(allocator);
        defer allocator.free(sig_bytes);
        const sig = Ed25519.Signature.fromBytes(msg.signature);
        sig.verify(sig_bytes, self.signing_key) catch return error.InvalidSignature;

        const ratchet = self.findRatchet(msg.message_index) orelse return error.MessageIndexTooOld;

        var keys = cipher_mod.deriveKeys(&ratchet.data);
        defer keys.deinit();

        const mac_bytes = try msg.macBytes(allocator);
        defer allocator.free(mac_bytes);
        if (!cipher_mod.verifyTruncatedMac(&keys.hmac_key, mac_bytes, &msg.mac)) return error.InvalidMac;

        const plaintext = cipher_mod.decryptCbc(allocator, &keys, msg.ciphertext) catch |err| switch (err) {
            error.InvalidPadding => return error.InvalidPadding,
            error.OutOfMemory => return error.OutOfMemory,
        };
        return .{ .plaintext = plaintext, .message_index = msg.message_index };
    }

    /// Permanently forget the ability to decrypt anything before `index`
    /// (megolm.md "Partial Forward Secrecy" mitigation: "wind forward any
    /// stored ratchet values"). Returns `false` (no-op) if `index` is not
    /// past the current `firstKnownIndex()`.
    pub fn forgetBefore(self: *InboundGroupSession, index: u32) bool {
        if (self.initial_ratchet.counter >= index) return false;
        self.initial_ratchet.advanceTo(index) catch unreachable; // always forward here
        if (self.latest_ratchet.counter < index) self.latest_ratchet = self.initial_ratchet;
        return true;
    }

    /// Export the ratchet state at `index` (must be `>= firstKnownIndex()`)
    /// as an `ExportedSessionKey` — e.g. to hand a less-trusted party the
    /// ability to decrypt from `index` onward but not before.
    pub fn exportAt(self: *InboundGroupSession, index: u32) ?ExportedSessionKey {
        const r = self.findRatchet(index) orelse return null;
        return .{ .ratchet_index = r.counter, .ratchet = r.data, .signing_key = self.signing_key.toBytes() };
    }
};

/// Unpadded-standard-base64 of an arbitrary byte slice — used for
/// `sessionId()` (base64 of the raw Ed25519 public key, per megolm.md:
/// "The public part of K is used as an identifier"), distinct from
/// session_key.zig's wire-format `toBase64` methods.
fn base64EncodeBytes(allocator: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error![]u8 {
    const codec = std.base64.standard_no_pad;
    const out = try allocator.alloc(u8, codec.Encoder.calcSize(bytes.len));
    _ = codec.Encoder.encode(out, bytes);
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn testIo() std.Io.Threaded {
    return std.Io.Threaded.init(testing.allocator, .{});
}

test "outbound encrypt -> inbound decrypt round-trip, several messages" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    var out = OutboundSession.init(io);
    defer out.deinit();
    var in = try InboundGroupSession.fromSessionKey(try out.sessionKey());
    defer in.deinit();

    const plaintexts = [_][]const u8{ "hello", "megolm group ratchet", "", "the quick brown fox jumps over the lazy dog, twice, to cross a block boundary reliably" };
    for (plaintexts, 0..) |pt, i| {
        var msg = try out.encrypt(testing.allocator, pt);
        defer msg.deinit(testing.allocator);
        try testing.expectEqual(@as(u32, @intCast(i)), msg.message_index);

        var decrypted = try in.decrypt(testing.allocator, &msg);
        defer decrypted.deinit(testing.allocator);
        try testing.expectEqualStrings(pt, decrypted.plaintext);
        try testing.expectEqual(@as(u32, @intCast(i)), decrypted.message_index);
    }
}

test "out-of-order delivery: inbound session fast-forwards correctly" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    var out = OutboundSession.init(io);
    defer out.deinit();
    var in = try InboundGroupSession.fromSessionKey(try out.sessionKey());
    defer in.deinit();

    var msg0 = try out.encrypt(testing.allocator, "first");
    defer msg0.deinit(testing.allocator);
    var msg1 = try out.encrypt(testing.allocator, "second");
    defer msg1.deinit(testing.allocator);
    var msg2 = try out.encrypt(testing.allocator, "third");
    defer msg2.deinit(testing.allocator);

    // Deliver 2, then 0, then 1 -- the ratchet must fast-forward and then
    // rewind-via-initial_ratchet without losing any message.
    var d2 = try in.decrypt(testing.allocator, &msg2);
    defer d2.deinit(testing.allocator);
    try testing.expectEqualStrings("third", d2.plaintext);

    var d0 = try in.decrypt(testing.allocator, &msg0);
    defer d0.deinit(testing.allocator);
    try testing.expectEqualStrings("first", d0.plaintext);

    var d1 = try in.decrypt(testing.allocator, &msg1);
    defer d1.deinit(testing.allocator);
    try testing.expectEqualStrings("second", d1.plaintext);
}

test "session sharing at a nonzero index: recipient cannot decrypt earlier messages" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    var out = OutboundSession.init(io);
    defer out.deinit();

    var early = try out.encrypt(testing.allocator, "before sharing");
    defer early.deinit(testing.allocator);
    var late = try out.encrypt(testing.allocator, "after sharing");
    defer late.deinit(testing.allocator);

    // Share the session key only NOW (index 2).
    var in = try InboundGroupSession.fromSessionKey(try out.sessionKey());
    defer in.deinit();
    try testing.expectEqual(@as(u32, 2), in.firstKnownIndex());

    try testing.expectError(error.MessageIndexTooOld, in.decrypt(testing.allocator, &early));
    try testing.expectError(error.MessageIndexTooOld, in.decrypt(testing.allocator, &late));

    var future = try out.encrypt(testing.allocator, "future message");
    defer future.deinit(testing.allocator);
    var d = try in.decrypt(testing.allocator, &future);
    defer d.deinit(testing.allocator);
    try testing.expectEqualStrings("future message", d.plaintext);
}

test "exportAt then import: imported session can't decrypt what was forgotten" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    var out = OutboundSession.init(io);
    defer out.deinit();
    var in = try InboundGroupSession.fromSessionKey(try out.sessionKey());
    defer in.deinit();

    var first = try out.encrypt(testing.allocator, "first secret");
    defer first.deinit(testing.allocator);
    var second = try out.encrypt(testing.allocator, "second secret");
    defer second.deinit(testing.allocator);

    var d = try in.decrypt(testing.allocator, &first);
    d.deinit(testing.allocator);

    const exported = in.exportAt(1) orelse return error.TestUnexpectedResult;
    var imported = try InboundGroupSession.fromExportedKey(exported);
    defer imported.deinit();
    try testing.expect(!imported.signing_key_verified);

    try testing.expectError(error.MessageIndexTooOld, imported.decrypt(testing.allocator, &first));
    var d2 = try imported.decrypt(testing.allocator, &second);
    defer d2.deinit(testing.allocator);
    try testing.expectEqualStrings("second secret", d2.plaintext);
}

test "tampered ciphertext byte is rejected as an invalid signature" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    var out = OutboundSession.init(io);
    defer out.deinit();
    var in = try InboundGroupSession.fromSessionKey(try out.sessionKey());
    defer in.deinit();

    var msg = try out.encrypt(testing.allocator, "authentic message");
    defer msg.deinit(testing.allocator);
    msg.ciphertext[0] ^= 0xFF;

    // The signature covers the ciphertext, so tampering it invalidates the
    // signature before the MAC is ever checked -- see this file's module
    // doc comment for why `InvalidMac` needs a dedicated construction
    // (in kat_test.zig) to reach at all.
    try testing.expectError(error.InvalidSignature, in.decrypt(testing.allocator, &msg));
}

test "tampered signature byte is rejected" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    var out = OutboundSession.init(io);
    defer out.deinit();
    var in = try InboundGroupSession.fromSessionKey(try out.sessionKey());
    defer in.deinit();

    var msg = try out.encrypt(testing.allocator, "authentic message");
    defer msg.deinit(testing.allocator);
    msg.signature[0] ^= 0xFF;

    try testing.expectError(error.InvalidSignature, in.decrypt(testing.allocator, &msg));
}
