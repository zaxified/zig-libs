// SPDX-License-Identifier: MIT

//! pickle.zig — session persistence ("pickling") for `OutboundSession` and
//! `InboundGroupSession`: a versioned, fixed-width plain byte layout that
//! carries every field of the session, and an optional sealed form that
//! wraps that layout in ChaCha20-Poly1305 (RFC 8439, the sibling
//! `chachapoly` module) under a caller-supplied 32-byte key.
//!
//! Why this exists: before it, an outbound session could not be saved at
//! all (its ratchet and Ed25519 secret are only reachable through the struct
//! fields), and the only way to rebuild an inbound one was `exportAt` →
//! `fromExportedKey`, which forgets that the signing key was authenticated
//! (`signing_key_verified` comes back `false`) and collapses the fast-forward
//! cache. libolm and vodozemac pickle every session for the same reason: a
//! client restarting mid-conversation must resume with the state it had.
//!
//! ## Layout (all integers big-endian, like the spec's own formats)
//!
//! ```
//! header (6):  "MGPK" ‖ version(1) = 0x01 ‖ kind(1)
//!
//! kind 0x01, outbound (202 bytes):
//!   header ‖ counter(4) ‖ ratchet(128) ‖ ed25519 seed(32) ‖ ed25519 public(32)
//!
//! kind 0x02, inbound (303 bytes):
//!   header ‖ initial counter(4) ‖ initial ratchet(128)
//!          ‖ latest counter(4) ‖ latest ratchet(128)
//!          ‖ signing key(32) ‖ flags(1)          flags bit 0 = signing_key_verified
//!
//! kind 0x81 / 0x82, sealed outbound / inbound (236 / 337 bytes):
//!   header ‖ nonce(12) ‖ ChaCha20-Poly1305(plain pickle) ‖ tag(16)
//!   key = caller's 32-byte pickle key, AD = the 6-byte header.
//! ```
//!
//! The sealed body is the WHOLE plain pickle, its own header included, so
//! the kind is bound twice: by the AEAD's associated data and again by the
//! inner header the plain decoder checks. The framing follows the shape
//! libolm/vodozemac pickles have conceptually (a version tag, then the
//! session's raw state, encrypted and authenticated under a caller key) —
//! the bytes are this module's own and are NOT interchangeable with either
//! library's pickles; nothing of theirs was read beyond public docs.
//!
//! ## ⚠ A pickle is a snapshot: never restore an outbound one twice
//!
//! Restoring an `OutboundSession` pickle rewinds the ratchet to the index it
//! was taken at. Encrypting from there again reuses message indices, so two
//! different plaintexts go out under the same message key — and receivers
//! that already saw those indices refuse the new ones as replays. Treat the
//! pickle like the live session: re-pickle after every encrypt that matters,
//! keep only the newest, and never resume one copy in two places. (The
//! sealing cannot prevent this: an old pickle is still a genuine one.) An
//! inbound pickle restored from earlier only loses fast-forward state and
//! is safe.
//!
//! ## Decoding is strict and fail-closed
//!
//! Every decoder checks, in order: length ≥ header (`error.Truncated`),
//! magic (`error.BadMagic`), version (`error.UnsupportedVersion`), kind
//! (`error.WrongKind` — a sealed pickle handed to the plain decoder, or an
//! inbound one to the outbound decoder), then the exact length for that
//! kind (`error.Truncated` short, `error.TrailingBytes` long). The sealed
//! path then verifies the tag (`error.AuthenticationFailed`) before a single
//! byte of the decrypted body is looked at. Field checks after that:
//!
//!   - outbound: the seed must yield a valid key pair whose public half
//!     equals the stored one (`error.InvalidSigningKey` /
//!     `error.InconsistentState`) — a corrupted plain pickle does not
//!     silently become a session signing under somebody else's key;
//!   - inbound: the signing key must be a canonical Ed25519 point
//!     (`error.InvalidSigningKey`); flag bits other than bit 0 must be zero
//!     (`error.InvalidFlags`); and `latest` must be `initial` ratcheted
//!     forward — `latest.counter >= initial.counter` and the bytes equal to
//!     `initial` advanced to that counter (`error.InconsistentState`). That
//!     last check matters: `latest_ratchet` is only a cache, but
//!     `findRatchet` trusts it, so a pickle whose cache sat BEHIND
//!     `initial` would quietly undo a `forgetBefore`.
//!
//! The plain form is NOT authenticated — anyone who can write it can
//! substitute a session. Use the sealed form for anything stored where an
//! attacker could reach it.
//!
//! ## Secrets
//!
//! A plain pickle contains the raw ratchet (and, for outbound, the Ed25519
//! seed): the caller owns the output buffer and should `secureZero` it once
//! written out. Internally every temporary that holds secret bytes — the
//! plain buffer inside `seal*`/`open*`, the re-derived key pair's seed, the
//! ratchet copy used for the consistency check, a half-built session on a
//! failed decode — is wiped here.
//!
//! Sealed pickles draw a fresh random 96-bit nonce per call from `entropy`
//! (the module's existing RNG seam). With random nonces a single pickle key
//! stays well inside ChaCha20-Poly1305's limits for 2^32 seals; rotate the
//! key long before that.

const std = @import("std");
const entropy = @import("entropy");
const chachapoly = @import("chachapoly");
/// Test-only (`build.zig`'s `test_deps`, never `deps`): fuzz corpus framing.
const testkit = @import("testkit");
const ratchet_mod = @import("ratchet.zig");
const session_mod = @import("session.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Aead = chachapoly.ChaCha20Poly1305;
const Ratchet = ratchet_mod.Ratchet;
const OutboundSession = session_mod.OutboundSession;
const InboundGroupSession = session_mod.InboundGroupSession;

pub const magic = "MGPK".*;
pub const version: u8 = 0x01;

pub const Kind = enum(u8) {
    outbound = 0x01,
    inbound = 0x02,
    sealed_outbound = 0x81,
    sealed_inbound = 0x82,
};

pub const key_length = Aead.key_length;
pub const PickleKey = [key_length]u8;

pub const header_len = magic.len + 2;
const counter_len = 4;
const ratchet_len = ratchet_mod.ratchet_len;
const seed_len = Ed25519.KeyPair.seed_length;
const pk_len = Ed25519.PublicKey.encoded_length;

pub const outbound_len = header_len + counter_len + ratchet_len + seed_len + pk_len;
pub const inbound_len = header_len + 2 * (counter_len + ratchet_len) + pk_len + 1;
const seal_overhead = header_len + Aead.nonce_length + Aead.tag_length;
pub const sealed_outbound_len = seal_overhead + outbound_len;
pub const sealed_inbound_len = seal_overhead + inbound_len;

const flag_verified: u8 = 0x01;

pub const PickleError = error{
    /// Shorter than the header, or than the exact length its kind requires.
    Truncated,
    /// Longer than the exact length its kind requires.
    TrailingBytes,
    BadMagic,
    UnsupportedVersion,
    /// A valid header for a different session type or form.
    WrongKind,
    /// Sealed pickle: tag mismatch (wrong key, or any byte altered).
    AuthenticationFailed,
    /// Reserved flag bits set.
    InvalidFlags,
    /// Not a usable Ed25519 key.
    InvalidSigningKey,
    /// Fields that must agree do not (outbound seed vs public key; inbound
    /// latest ratchet vs initial ratchet).
    InconsistentState,
};

fn writeHeader(out: *[header_len]u8, kind: Kind) void {
    out[0..magic.len].* = magic;
    out[magic.len] = version;
    out[magic.len + 1] = @intFromEnum(kind);
}

/// Header + exact-length gate shared by all four decoders.
fn checkFrame(bytes: []const u8, kind: Kind, exact_len: usize) PickleError!void {
    if (bytes.len < header_len) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
    if (bytes[magic.len] != version) return error.UnsupportedVersion;
    if (bytes[magic.len + 1] != @intFromEnum(kind)) return error.WrongKind;
    if (bytes.len < exact_len) return error.Truncated;
    if (bytes.len > exact_len) return error.TrailingBytes;
}

// ── outbound ─────────────────────────────────────────────────────────────

pub fn encodeOutbound(s: *const OutboundSession, out: *[outbound_len]u8) void {
    writeHeader(out[0..header_len], .outbound);
    var at: usize = header_len;
    std.mem.writeInt(u32, out[at..][0..counter_len], s.ratchet.counter, .big);
    at += counter_len;
    out[at..][0..ratchet_len].* = s.ratchet.data;
    at += ratchet_len;
    out[at..][0..seed_len].* = s.signing_key.secret_key.seed();
    at += seed_len;
    out[at..][0..pk_len].* = s.signing_key.public_key.toBytes();
}

pub fn decodeOutbound(bytes: []const u8) PickleError!OutboundSession {
    try checkFrame(bytes, .outbound, outbound_len);
    var at: usize = header_len;
    const counter = std.mem.readInt(u32, bytes[at..][0..counter_len], .big);
    at += counter_len;
    const data = bytes[at..][0..ratchet_len];
    at += ratchet_len;
    var seed: [seed_len]u8 = bytes[at..][0..seed_len].*;
    defer std.crypto.secureZero(u8, &seed);
    at += seed_len;
    const stored_pk = bytes[at..][0..pk_len];

    var kp = Ed25519.KeyPair.generateDeterministic(seed) catch return error.InvalidSigningKey;
    // The public key is not secret; a plain compare is fine here.
    if (!std.mem.eql(u8, &kp.public_key.toBytes(), stored_pk)) {
        std.crypto.secureZero(u8, &kp.secret_key.bytes);
        return error.InconsistentState;
    }
    return .{ .ratchet = Ratchet.init(data.*, counter), .signing_key = kp };
}

// ── inbound ──────────────────────────────────────────────────────────────

pub fn encodeInbound(s: *const InboundGroupSession, out: *[inbound_len]u8) void {
    writeHeader(out[0..header_len], .inbound);
    var at: usize = header_len;
    for ([_]*const Ratchet{ &s.initial_ratchet, &s.latest_ratchet }) |r| {
        std.mem.writeInt(u32, out[at..][0..counter_len], r.counter, .big);
        at += counter_len;
        out[at..][0..ratchet_len].* = r.data;
        at += ratchet_len;
    }
    out[at..][0..pk_len].* = s.signing_key.toBytes();
    at += pk_len;
    out[at] = if (s.signing_key_verified) flag_verified else 0;
}

pub fn decodeInbound(bytes: []const u8) PickleError!InboundGroupSession {
    try checkFrame(bytes, .inbound, inbound_len);
    var at: usize = header_len;
    var initial = Ratchet.init(bytes[at + counter_len ..][0..ratchet_len].*, std.mem.readInt(u32, bytes[at..][0..counter_len], .big));
    errdefer initial.secureZero();
    at += counter_len + ratchet_len;
    var latest = Ratchet.init(bytes[at + counter_len ..][0..ratchet_len].*, std.mem.readInt(u32, bytes[at..][0..counter_len], .big));
    errdefer latest.secureZero();
    at += counter_len + ratchet_len;
    const pk = Ed25519.PublicKey.fromBytes(bytes[at..][0..pk_len].*) catch return error.InvalidSigningKey;
    at += pk_len;
    const flags = bytes[at];
    if (flags & ~flag_verified != 0) return error.InvalidFlags;

    // `latest` is a cache of `initial` fast-forwarded; prove it is one.
    if (latest.counter < initial.counter) return error.InconsistentState;
    var check = initial;
    defer check.secureZero();
    check.advanceTo(latest.counter) catch unreachable; // forward: checked above
    if (!std.crypto.timing_safe.eql([ratchet_len]u8, check.data, latest.data)) return error.InconsistentState;

    return .{
        .initial_ratchet = initial,
        .latest_ratchet = latest,
        .signing_key = pk,
        .signing_key_verified = flags & flag_verified != 0,
    };
}

// ── sealed (ChaCha20-Poly1305) ───────────────────────────────────────────

fn sealInto(io: std.Io, key: *const PickleKey, kind: Kind, plain: []const u8, out: []u8) void {
    std.debug.assert(out.len == seal_overhead + plain.len);
    const header = out[0..header_len];
    writeHeader(header, kind);
    const nonce = out[header_len..][0..Aead.nonce_length];
    entropy.fill(io, nonce);
    const ct = out[header_len + Aead.nonce_length ..][0..plain.len];
    const tag = out[header_len + Aead.nonce_length + plain.len ..][0..Aead.tag_length];
    Aead.encrypt(ct, tag, plain, header, nonce.*, key.*);
}

fn openInto(bytes: []const u8, key: *const PickleKey, kind: Kind, plain: []u8) PickleError!void {
    try checkFrame(bytes, kind, seal_overhead + plain.len);
    const header = bytes[0..header_len];
    const nonce = bytes[header_len..][0..Aead.nonce_length];
    const ct = bytes[header_len + Aead.nonce_length ..][0..plain.len];
    const tag = bytes[header_len + Aead.nonce_length + plain.len ..][0..Aead.tag_length];
    // `decrypt` zeroes `plain` on failure (chachapoly's documented contract).
    Aead.decrypt(plain, ct, tag.*, header, nonce.*, key.*) catch return error.AuthenticationFailed;
}

pub fn sealOutbound(io: std.Io, s: *const OutboundSession, key: *const PickleKey, out: *[sealed_outbound_len]u8) void {
    var plain: [outbound_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &plain);
    encodeOutbound(s, &plain);
    sealInto(io, key, .sealed_outbound, &plain, out);
}

pub fn openOutbound(bytes: []const u8, key: *const PickleKey) PickleError!OutboundSession {
    var plain: [outbound_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &plain);
    try openInto(bytes, key, .sealed_outbound, &plain);
    return decodeOutbound(&plain);
}

pub fn sealInbound(io: std.Io, s: *const InboundGroupSession, key: *const PickleKey, out: *[sealed_inbound_len]u8) void {
    var plain: [inbound_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &plain);
    encodeInbound(s, &plain);
    sealInto(io, key, .sealed_inbound, &plain, out);
}

pub fn openInbound(bytes: []const u8, key: *const PickleKey) PickleError!InboundGroupSession {
    var plain: [inbound_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &plain);
    try openInto(bytes, key, .sealed_inbound, &plain);
    return decodeInbound(&plain);
}

// ── tests ────────────────────────────────────────────────────────────────
//
// Anchor: SELF-DERIVED. There is no external vector for this layout — it is
// this module's own format, deliberately not libolm's or vodozemac's. The
// tests prove the property that matters: a restored session behaves
// byte-for-byte like the one it was taken from (identical ciphertexts and
// signatures from a restored outbound session, identical decrypts and
// errors from a restored inbound one), and every malformed or tampered
// input is refused with its own typed error. The AEAD itself is anchored in
// `chachapoly` (RFC 8439 KATs + differential against std).

const testing = std.testing;

fn testIo() std.Io.Threaded {
    return std.Io.Threaded.init(testing.allocator, .{});
}

const test_key: PickleKey = [_]u8{0x42} ** key_length;

fn expectSameMessage(a: anytype, b: anytype) !void {
    try testing.expectEqual(a.message_index, b.message_index);
    try testing.expectEqualSlices(u8, a.ciphertext, b.ciphertext);
    try testing.expectEqualSlices(u8, &a.mac, &b.mac);
    try testing.expectEqualSlices(u8, &a.signature, &b.signature);
}

test "layout lengths are the documented ones" {
    try testing.expectEqual(@as(usize, 202), outbound_len);
    try testing.expectEqual(@as(usize, 303), inbound_len);
    try testing.expectEqual(@as(usize, 236), sealed_outbound_len);
    try testing.expectEqual(@as(usize, 337), sealed_inbound_len);
}

test "outbound pickle round trip mid-ratchet: the restored session continues identically" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const a = testing.allocator;

    var out = OutboundSession.init(io);
    defer out.deinit();
    var in = try InboundGroupSession.fromSessionKey(try out.sessionKey());
    defer in.deinit();
    for (0..300) |_| { // cross a 2^8 boundary so a part-2 rehash is in the state
        var m = try out.encrypt(a, "warm-up");
        m.deinit(a);
    }

    var plain: [outbound_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &plain);
    out.pickle(&plain);
    var sealed: [sealed_outbound_len]u8 = undefined;
    out.pickleSealed(io, &test_key, &sealed);

    var restored = try OutboundSession.fromPickle(&plain);
    defer restored.deinit();
    var restored_sealed = try OutboundSession.fromSealedPickle(&sealed, &test_key);
    defer restored_sealed.deinit();

    try testing.expectEqual(@as(u32, 300), restored.messageIndex());
    const id = try out.sessionId(a);
    defer a.free(id);
    const id2 = try restored.sessionId(a);
    defer a.free(id2);
    try testing.expectEqualStrings(id, id2);

    // Ed25519 is deterministic, so identical state ⇒ identical frames.
    for ([_][]const u8{ "after restart", "and again", "" }) |pt| {
        var m0 = try out.encrypt(a, pt);
        defer m0.deinit(a);
        var m1 = try restored.encrypt(a, pt);
        defer m1.deinit(a);
        var m2 = try restored_sealed.encrypt(a, pt);
        defer m2.deinit(a);
        try expectSameMessage(m0, m1);
        try expectSameMessage(m0, m2);
        var d = try in.decrypt(a, &m1);
        defer d.deinit(a);
        try testing.expectEqualStrings(pt, d.plaintext);
    }
}

test "inbound pickle round trip mid-ratchet: decrypts and refusals continue identically, verified flag survives" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const a = testing.allocator;

    var out = OutboundSession.init(io);
    defer out.deinit();
    var early = try out.encrypt(a, "before share");
    defer early.deinit(a);
    var in = try InboundGroupSession.fromSessionKey(try out.sessionKey());
    defer in.deinit();
    try testing.expect(in.signing_key_verified);

    var msgs: [6]@import("message.zig").Message = undefined;
    for (&msgs, 0..) |*m, i| {
        var buf: [16]u8 = undefined;
        m.* = try out.encrypt(a, try std.fmt.bufPrint(&buf, "msg {d}", .{i}));
    }
    defer for (&msgs) |*m| m.deinit(a);

    // Advance the cache past where `initial` is, so latest != initial.
    var d4 = try in.decrypt(a, &msgs[4]);
    d4.deinit(a);
    try testing.expect(in.latest_ratchet.counter != in.initial_ratchet.counter);

    var plain: [inbound_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &plain);
    in.pickle(&plain);
    var sealed: [sealed_inbound_len]u8 = undefined;
    in.pickleSealed(io, &test_key, &sealed);

    var r1 = try InboundGroupSession.fromPickle(&plain);
    defer r1.deinit();
    var r2 = try InboundGroupSession.fromSealedPickle(&sealed, &test_key);
    defer r2.deinit();
    for ([_]*InboundGroupSession{ &r1, &r2 }) |r| {
        try testing.expect(r.signing_key_verified);
        try testing.expectEqual(in.firstKnownIndex(), r.firstKnownIndex());
        try testing.expectEqual(in.latest_ratchet.counter, r.latest_ratchet.counter);
        try testing.expectEqualSlices(u8, &in.latest_ratchet.data, &r.latest_ratchet.data);
    }
    for ([_]*InboundGroupSession{ &r1, &r2 }) |r| {
        try testing.expectError(error.MessageIndexTooOld, r.decrypt(a, &early));
        // Out of order, behind and ahead of the cache.
        for ([_]usize{ 5, 0, 3, 1 }) |i| {
            var want = try in.decrypt(a, &msgs[i]);
            defer want.deinit(a);
            var got = try r.decrypt(a, &msgs[i]);
            defer got.deinit(a);
            try testing.expectEqualStrings(want.plaintext, got.plaintext);
        }
    }

    // An unverified session stays unverified (the flag is carried, not
    // re-derived), and a forgetBefore survives the round trip.
    var imported = try InboundGroupSession.fromExportedKey(in.exportAt(2).?);
    defer imported.deinit();
    try testing.expect(imported.forgetBefore(3));
    imported.pickle(&plain);
    var r3 = try InboundGroupSession.fromPickle(&plain);
    defer r3.deinit();
    try testing.expect(!r3.signing_key_verified);
    try testing.expectEqual(@as(u32, 3), r3.firstKnownIndex());
    try testing.expectError(error.MessageIndexTooOld, r3.decrypt(a, &msgs[1]));
}

test "plain decoders: header, kind and length refusals" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    var out = OutboundSession.init(io);
    defer out.deinit();
    var in = try InboundGroupSession.fromSessionKey(try out.sessionKey());
    defer in.deinit();
    var ob: [outbound_len]u8 = undefined;
    out.pickle(&ob);
    var ib: [inbound_len]u8 = undefined;
    in.pickle(&ib);

    try testing.expectError(error.Truncated, OutboundSession.fromPickle(""));
    try testing.expectError(error.Truncated, OutboundSession.fromPickle(ob[0 .. header_len - 1]));
    try testing.expectError(error.Truncated, OutboundSession.fromPickle(ob[0 .. outbound_len - 1]));
    try testing.expectError(error.Truncated, InboundGroupSession.fromPickle(ib[0 .. inbound_len - 1]));
    var long: [inbound_len + 1]u8 = undefined;
    @memcpy(long[0..outbound_len], &ob);
    long[outbound_len] = 0;
    try testing.expectError(error.TrailingBytes, OutboundSession.fromPickle(long[0 .. outbound_len + 1]));
    @memcpy(long[0..inbound_len], &ib);
    long[inbound_len] = 0;
    try testing.expectError(error.TrailingBytes, InboundGroupSession.fromPickle(&long));

    try testing.expectError(error.WrongKind, OutboundSession.fromPickle(&ib));
    try testing.expectError(error.WrongKind, InboundGroupSession.fromPickle(&ob));
    try testing.expectError(error.WrongKind, OutboundSession.fromSealedPickle(&ob, &test_key));

    var t = ob;
    t[0] ^= 1;
    try testing.expectError(error.BadMagic, OutboundSession.fromPickle(&t));
    t = ob;
    t[magic.len] = 0x02;
    try testing.expectError(error.UnsupportedVersion, OutboundSession.fromPickle(&t));
}

test "plain decoders: field refusals" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    var out = OutboundSession.init(io);
    defer out.deinit();
    var ob: [outbound_len]u8 = undefined;
    out.pickle(&ob);
    // Seed and public key disagree.
    var t = ob;
    t[outbound_len - 1] ^= 1;
    try testing.expectError(error.InconsistentState, OutboundSession.fromPickle(&t));
    t = ob;
    t[outbound_len - pk_len - 1] ^= 1;
    try testing.expectError(error.InconsistentState, OutboundSession.fromPickle(&t));

    var in = try InboundGroupSession.fromSessionKey(try out.sessionKey());
    defer in.deinit();
    var m = try out.encrypt(testing.allocator, "x");
    defer m.deinit(testing.allocator);
    var m2 = try out.encrypt(testing.allocator, "y");
    defer m2.deinit(testing.allocator);
    var d = try in.decrypt(testing.allocator, &m2);
    d.deinit(testing.allocator);
    var ib: [inbound_len]u8 = undefined;
    in.pickle(&ib);

    const flags_at = inbound_len - 1;
    const pk_at = flags_at - pk_len;
    const latest_counter_at = header_len + counter_len + ratchet_len;
    const latest_data_at = latest_counter_at + counter_len;

    var u = ib;
    u[flags_at] = 0x02;
    try testing.expectError(error.InvalidFlags, InboundGroupSession.fromPickle(&u));
    u = ib;
    u[pk_at..][0..pk_len].* = [_]u8{0xff} ** pk_len; // non-canonical point
    try testing.expectError(error.InvalidSigningKey, InboundGroupSession.fromPickle(&u));
    u = ib;
    u[latest_data_at + 5] ^= 1; // cache bytes not derivable from initial
    try testing.expectError(error.InconsistentState, InboundGroupSession.fromPickle(&u));
    u = ib;
    std.mem.writeInt(u32, u[latest_counter_at..][0..4], 3, .big); // cache counter moved
    try testing.expectError(error.InconsistentState, InboundGroupSession.fromPickle(&u));
    // Cache BEHIND initial: would undo a forgetBefore.
    u = ib;
    std.mem.writeInt(u32, u[header_len..][0..4], 7, .big);
    try testing.expectError(error.InconsistentState, InboundGroupSession.fromPickle(&u));
}

test "sealed decoders: wrong key, every single-byte tamper and every truncation are refused" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    var out = OutboundSession.init(io);
    defer out.deinit();
    var in = try InboundGroupSession.fromSessionKey(try out.sessionKey());
    defer in.deinit();
    var so: [sealed_outbound_len]u8 = undefined;
    out.pickleSealed(io, &test_key, &so);
    var si: [sealed_inbound_len]u8 = undefined;
    in.pickleSealed(io, &test_key, &si);

    var wrong = test_key;
    wrong[31] ^= 1;
    try testing.expectError(error.AuthenticationFailed, OutboundSession.fromSealedPickle(&so, &wrong));
    try testing.expectError(error.AuthenticationFailed, InboundGroupSession.fromSealedPickle(&si, &wrong));
    try testing.expectError(error.WrongKind, OutboundSession.fromSealedPickle(&si, &test_key));
    try testing.expectError(error.WrongKind, InboundGroupSession.fromPickle(&si));

    // Two seals of the same session differ (fresh nonce) and both open.
    var so2: [sealed_outbound_len]u8 = undefined;
    out.pickleSealed(io, &test_key, &so2);
    try testing.expect(!std.mem.eql(u8, &so, &so2));
    var again = try OutboundSession.fromSealedPickle(&so2, &test_key);
    again.deinit();

    for (0..so.len) |i| {
        var t = so;
        t[i] ^= 0x01;
        if (OutboundSession.fromSealedPickle(&t, &test_key)) |s| {
            var ss = s;
            ss.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    for (0..si.len) |i| {
        var t = si;
        t[i] ^= 0x80;
        if (InboundGroupSession.fromSealedPickle(&t, &test_key)) |s| {
            var ss = s;
            ss.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    // Byte i past the header: always the AEAD that refuses.
    var t = si;
    t[header_len] ^= 1;
    try testing.expectError(error.AuthenticationFailed, InboundGroupSession.fromSealedPickle(&t, &test_key));
    t = si;
    t[si.len - 1] ^= 1;
    try testing.expectError(error.AuthenticationFailed, InboundGroupSession.fromSealedPickle(&t, &test_key));

    for (0..so.len) |n| {
        try testing.expectError(error.Truncated, OutboundSession.fromSealedPickle(so[0..n], &test_key));
    }
    var long: [sealed_inbound_len + 1]u8 = undefined;
    @memcpy(long[0..sealed_inbound_len], &si);
    long[sealed_inbound_len] = 0;
    try testing.expectError(error.TrailingBytes, InboundGroupSession.fromSealedPickle(&long, &test_key));
}

// ── fuzz: the pickle decoders ────────────────────────────────────────────
//
// Pickles come back from storage this module does not control, so all four
// decoders are untrusted-input surfaces. They are fixed-width, so — as in
// `session_key.zig` — the harness biases lengths toward the four exact
// lengths and their off-by-ones, and rewrites the header most of the time so
// the field checks and the AEAD get real budget behind the gates.
//
// A seed is a `testkit.fuzz` slice seed (the frame), then the `u64` words the
// knobs read: `[length_mode, (near: base, delta, plus) | (any: len),
// header_mode]`. The byte draw comes FIRST, into the whole buffer.

const fuzz_buf_len = 400;
const exact_lens = [_]usize{ outbound_len, inbound_len, sealed_outbound_len, sealed_inbound_len };
const kinds = [_]Kind{ .outbound, .inbound, .sealed_outbound, .sealed_inbound };

const PickleCorpus = struct {
    store: [10 * (4 + fuzz_buf_len + 6 * 8)]u8 = undefined,
    used: usize = 0,
    entries: [10][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *PickleCorpus, frame: []const u8, words: []const u64) void {
        const start = self.used;
        var at = start + testkit.fuzz.seedInto(self.store[start..], frame).len;
        for (words) |w| {
            std.mem.writeInt(u64, self.store[at..][0..8], w, .little);
            at += 8;
        }
        self.entries[self.n] = self.store[start..at];
        self.used = at;
        self.n += 1;
    }

    fn build(self: *PickleCorpus, io: std.Io) []const []const u8 {
        // Fixed state so the guard below can pin what decodes.
        var out = OutboundSession{
            .ratchet = Ratchet.init([_]u8{0x33} ** ratchet_len, 0x1ff),
            .signing_key = Ed25519.KeyPair.generateDeterministic([_]u8{0x11} ** seed_len) catch unreachable,
        };
        defer out.deinit();
        var in = InboundGroupSession{
            .initial_ratchet = out.ratchet,
            .latest_ratchet = out.ratchet,
            .signing_key = out.signing_key.public_key,
            .signing_key_verified = true,
        };
        in.latest_ratchet.advanceTo(0x301) catch unreachable;
        defer in.deinit();

        var ob: [outbound_len]u8 = undefined;
        encodeOutbound(&out, &ob);
        var ib: [inbound_len]u8 = undefined;
        encodeInbound(&in, &ib);
        var so: [sealed_outbound_len]u8 = undefined;
        sealOutbound(io, &out, &fuzz_key, &so);
        var si: [sealed_inbound_len]u8 = undefined;
        sealInbound(io, &in, &fuzz_key, &si);

        // header_mode 0 = keep the frame's own header.
        self.push(&ob, &.{ 0, 0 }); // decodes as outbound
        self.push(&ib, &.{ 1, 0 }); // decodes as inbound
        self.push(&so, &.{ 2, 0 }); // opens as sealed outbound
        self.push(&si, &.{ 3, 0 }); // opens as sealed inbound
        var t = si;
        t[sealed_inbound_len - 1] ^= 1; // tag
        self.push(&t, &.{ 3, 0 });
        var u = ib;
        u[inbound_len - 1] = 0x04; // reserved flag
        self.push(&u, &.{ 1, 0 });
        self.push(&ib, &.{ 4, 1, 1, 1, 0 }); // near: inbound_len + 1
        self.push(&ob, &.{ 4, 0, 2, 0, 0 }); // near: outbound_len - 2
        self.push(&so, &.{ 5, 7, 3 }); // any: 7 octets, header rewritten as sealed_outbound
        self.push("", &.{});
        return self.entries[0..self.n];
    }
};

const fuzz_key: PickleKey = [_]u8{0x5a} ** key_length;

const FuzzOutcome = struct { len: usize, decoded: usize };

fn pickleRound(smith: *std.testing.Smith) FuzzOutcome {
    var buf = [_]u8{0} ** fuzz_buf_len;
    _ = smith.slice(&buf);
    const mode = smith.value(u64) % 6;
    const len: usize = switch (mode) {
        0, 1, 2, 3 => exact_lens[@intCast(mode)],
        4 => blk: {
            const base = exact_lens[@intCast(smith.value(u64) % 4)];
            const delta: usize = @intCast(smith.value(u64) % 4);
            break :blk if (smith.value(u64) % 2 == 1) base + delta else base -| delta;
        },
        else => @intCast(smith.value(u64) % (buf.len + 1)),
    };
    // 0 keeps the drawn header; 1..4 write a valid header of that kind; 5 a
    // valid magic+version with an arbitrary kind byte.
    const header_mode = smith.value(u64) % 6;
    if (header_mode != 0 and len >= header_len) {
        if (header_mode <= 4) {
            writeHeader(buf[0..header_len], kinds[@intCast(header_mode - 1)]);
        } else {
            buf[0..magic.len].* = magic;
            buf[magic.len] = version;
            buf[magic.len + 1] = @truncate(smith.value(u64));
        }
    }
    const bytes = buf[0..len];
    var decoded: usize = 0;
    if (decodeOutbound(bytes)) |s| {
        var ss = s;
        ss.deinit();
        decoded += 1;
    } else |_| {}
    if (decodeInbound(bytes)) |s| {
        var ss = s;
        ss.deinit();
        decoded += 1;
    } else |_| {}
    if (openOutbound(bytes, &fuzz_key)) |s| {
        var ss = s;
        ss.deinit();
        decoded += 1;
    } else |_| {}
    if (openInbound(bytes, &fuzz_key)) |s| {
        var ss = s;
        ss.deinit();
        decoded += 1;
    } else |_| {}
    return .{ .len = len, .decoded = decoded };
}

fn fuzzPickleDecode(_: void, smith: *std.testing.Smith) !void {
    _ = pickleRound(smith);
}

test "fuzz: pickle decoders never panic on arbitrary bytes" {
    var threaded = testIo();
    defer threaded.deinit();
    var corpus: PickleCorpus = .{};
    try testing.fuzz({}, fuzzPickleDecode, .{ .corpus = corpus.build(threaded.io()) });
}

test "corpus: the pickle seeds reach every decoder past its gates, and the counts are pinned" {
    var threaded = testIo();
    defer threaded.deinit();
    var corpus: PickleCorpus = .{};
    var decoded: usize = 0;
    var len_total: usize = 0;
    for (corpus.build(threaded.io())) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        const r = pickleRound(&smith);
        decoded += r.decoded;
        len_total += r.len;
    }
    // Four real pickles decode (one per decoder); the tampered tag, the
    // reserved flag and the near/any lengths do not. Measured 2026-10-06.
    try testing.expectEqual(@as(usize, 4), decoded);
    try testing.expectEqual(@as(usize, 202 + 303 + 236 + 337 + 337 + 303 + 304 + 200 + 7 + 202), len_total);
}
