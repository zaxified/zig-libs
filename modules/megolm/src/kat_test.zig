// SPDX-License-Identifier: MIT

//! kat_test.zig — external anchors (see SPEC.md for the anchoring-grade
//! breakdown of every area this module covers) plus the reject-teeth
//! battery: four distinct typed errors, each individually exercised.
//!
//! ## Where every vector below came from (reproduce it yourself)
//!
//! All of it is libolm's OWN C test suite (Apache-2.0) — a real reference
//! implementation, not this module's own output:
//!
//!   - Ratchet-advance vectors (`expected1`/`expected2`/`expected3`):
//!     `curl -sL https://gitlab.matrix.org/matrix-org/olm/-/raw/master/tests/test_megolm.cpp`
//!     extracted with:
//!     `python3 -c "import re; txt=open('test_megolm.cpp').read(); [print(n, re.findall(r'0x[0-9a-fA-F]{2}', re.search(n+r'\[\]\s*=\s*\{([^;]*)\};', txt, re.S).group(1))) for n in ['expected1','expected2','expected3']]"`
//!   - The `random_bytes` seed for those vectors is the literal
//!     `"0123456789ABCDEF"` repeated 8 times (128 bytes) — verified with
//!     `python3 -c "import re; txt=open('test_megolm.cpp').read(); m=re.search(r'random_bytes\[\]\s*=\s*((?:\s*\"[^\"]*\"\s*)+);', txt, re.S); print(''.join(re.findall(r'\"([^\"]*)\"', m.group(1))))"`
//!     (this module's own re-transcription by eye first misread it as
//!     `"...ABDEF..."` missing a `C` — the python extraction caught the
//!     error; a lesson in not hand-copying hex/ASCII test data).
//!   - The payload tag/varint header vector (`0x03 0x08 0xC8 0x01 0x12
//!     0x0A`) — `tests/test_message.cpp`, "Group message encode test"
//!     (`_olm_encode_group_message(3, 200, 10, ...)`), already anchored in
//!     `message.zig`'s own test.
//!   - The two full session-key + message base64 pairs (`export/import`
//!     and `Invalid signature group message` test cases):
//!     `curl -sL https://gitlab.matrix.org/matrix-org/olm/-/raw/master/tests/test_group_session.cpp`
//!     extracted with a similar regex over the `session_key[]`/`message[]`
//!     C string literals in each `TEST_CASE`.
//!
//! **Independent re-derivation (grade 2), on top of the grade-1 vectors
//! above**: both full session-key+message pairs were also decoded and
//! decrypted with a SEPARATE toolchain — Python's `cryptography` (AES-CBC,
//! HKDF-SHA256), stdlib `hmac`/`hashlib` (HMAC-SHA256), and PyNaCl 1.5
//! (Ed25519) — none of which share code with libolm, vodozemac, or this
//! module. That run reproduced: the session-key self-signature verifying,
//! the message signature verifying against the SAME embedded public key,
//! the derived `AES_KEY`/`HMAC_KEY`/`IV` producing a matching truncated
//! MAC, and AES-256-CBC/PKCS#7 decryption yielding the plaintext
//! `"Message"` at index 0 — for BOTH vectors. This is what gives high
//! confidence the byte layout implemented across `message.zig`/
//! `session_key.zig`/`cipher.zig` is correct, independent of any shared
//! misreading of the spec between this module and libolm's authors.

const std = @import("std");
const testing = std.testing;

const ratchet_mod = @import("ratchet.zig");
const session_key_mod = @import("session_key.zig");
const message_mod = @import("message.zig");
const session_mod = @import("session.zig");

const Ratchet = ratchet_mod.Ratchet;
const SessionKey = session_key_mod.SessionKey;
const Message = message_mod.Message;
const InboundGroupSession = session_mod.InboundGroupSession;

// ── the libolm ratchet-advance seed ─────────────────────────────────────

fn buildLibolmSeed() [ratchet_mod.ratchet_len]u8 {
    const pattern = "0123456789ABCDEF";
    var out: [ratchet_mod.ratchet_len]u8 = undefined;
    var i: usize = 0;
    while (i < out.len) : (i += 1) out[i] = pattern[i % pattern.len];
    return out;
}
const libolm_seed = buildLibolmSeed();

// ── EXTERNAL ANCHOR (grade 1): libolm `Megolm::advance` ─────────────────

test "libolm vector: single-step advance from index 0" {
    var r = Ratchet.init(libolm_seed, 0);
    r.advanceStep();
    try testing.expectEqual(@as(u32, 1), r.counter);

    const expected = [_]u8{
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0xba, 0x9c, 0xd9, 0x55, 0x74, 0x1d, 0x1c, 0x16, 0x23, 0x23, 0xec, 0x82, 0x5e, 0x7c, 0x5c, 0xe8,
        0x89, 0xbb, 0xb4, 0x23, 0xa1, 0x8f, 0x23, 0x82, 0x8f, 0xb2, 0x09, 0x0d, 0x6e, 0x2a, 0xf8, 0x6a,
    };
    try testing.expectEqualSlices(u8, &expected, &r.data);

    // "repeat with complex advance" -- advanceTo(1) from index 0 must land
    // on the identical bytes as one advanceStep().
    var r2 = Ratchet.init(libolm_seed, 0);
    try r2.advanceTo(1);
    try testing.expectEqual(@as(u32, 1), r2.counter);
    try testing.expectEqualSlices(u8, &expected, &r2.data);
}

test "libolm vector: advanceTo crossing a 2^24 boundary" {
    var r = Ratchet.init(libolm_seed, 0);
    try r.advanceTo(0x1000000);
    try testing.expectEqual(@as(u32, 0x1000000), r.counter);

    const expected = [_]u8{
        0x54, 0x02, 0x2d, 0x7d, 0xc0, 0x29, 0x8e, 0x16, 0x37, 0xe2, 0x1c, 0x97, 0x15, 0x30, 0x92, 0xf9,
        0x33, 0xc0, 0x56, 0xff, 0x74, 0xfe, 0x1b, 0x92, 0x2d, 0x97, 0x1f, 0x24, 0x82, 0xc2, 0x85, 0x9c,
        0x70, 0x04, 0xc0, 0x1e, 0xe4, 0x9b, 0xd6, 0xef, 0xe0, 0x07, 0x35, 0x25, 0xaf, 0x9b, 0x16, 0x32,
        0xc5, 0xbe, 0x72, 0x6d, 0x12, 0x34, 0x9c, 0xc5, 0xbd, 0x47, 0x2b, 0xdc, 0x2d, 0xf6, 0x54, 0x0f,
        0x31, 0x12, 0x59, 0x11, 0x94, 0xfd, 0xa6, 0x17, 0xe5, 0x68, 0xc6, 0x83, 0x10, 0x1e, 0xae, 0xcd,
        0x7e, 0xdd, 0xd6, 0xde, 0x1f, 0xbc, 0x07, 0x67, 0xae, 0x34, 0xda, 0x1a, 0x09, 0xa5, 0x4e, 0xab,
        0xba, 0x9c, 0xd9, 0x55, 0x74, 0x1d, 0x1c, 0x16, 0x23, 0x23, 0xec, 0x82, 0x5e, 0x7c, 0x5c, 0xe8,
        0x89, 0xbb, 0xb4, 0x23, 0xa1, 0x8f, 0x23, 0x82, 0x8f, 0xb2, 0x09, 0x0d, 0x6e, 0x2a, 0xf8, 0x6a,
    };
    try testing.expectEqualSlices(u8, &expected, &r.data);

    // Continuing to advance to a further, finer-grained index (crossing
    // 2^16 and 2^8 boundaries too) from THIS state must land here:
    try r.advanceTo(0x1041506);
    try testing.expectEqual(@as(u32, 0x1041506), r.counter);
    const expected2 = [_]u8{
        0x54, 0x02, 0x2d, 0x7d, 0xc0, 0x29, 0x8e, 0x16, 0x37, 0xe2, 0x1c, 0x97, 0x15, 0x30, 0x92, 0xf9,
        0x33, 0xc0, 0x56, 0xff, 0x74, 0xfe, 0x1b, 0x92, 0x2d, 0x97, 0x1f, 0x24, 0x82, 0xc2, 0x85, 0x9c,
        0x55, 0x58, 0x8d, 0xf5, 0xb7, 0xa4, 0x88, 0x78, 0x42, 0x89, 0x27, 0x86, 0x81, 0x64, 0x58, 0x9f,
        0x36, 0x63, 0x44, 0x7b, 0x51, 0xed, 0xc3, 0x59, 0x5b, 0x03, 0x6c, 0xa6, 0x04, 0xc4, 0x6d, 0xcd,
        0x5c, 0x54, 0x85, 0x0b, 0xfa, 0x98, 0xa1, 0xfd, 0x79, 0xa9, 0xdf, 0x1c, 0xbe, 0x8f, 0xc5, 0x68,
        0x19, 0x37, 0xd3, 0x0c, 0x85, 0xc8, 0xc3, 0x1f, 0x7b, 0xb8, 0x28, 0x81, 0x6c, 0xf9, 0xff, 0x3b,
        0x95, 0x6c, 0xbf, 0x80, 0x7e, 0x65, 0x12, 0x6a, 0x49, 0x55, 0x8d, 0x45, 0xc8, 0x4a, 0x2e, 0x4c,
        0xd5, 0x6f, 0x03, 0xe2, 0x44, 0x16, 0xb9, 0x8e, 0x1c, 0xfd, 0x97, 0xc2, 0x06, 0xaa, 0x90, 0x7a,
    };
    try testing.expectEqualSlices(u8, &expected2, &r.data);
}

test "libolm vector: advanceToUnchecked wraparound (counter 0xffffffff -> 0x1000000 == fresh -> 0x2000000)" {
    var r1 = Ratchet.init(libolm_seed, 0xffffffff);
    r1.advanceToUnchecked(0x1000000);
    try testing.expectEqual(@as(u32, 0x1000000), r1.counter);

    var r2 = Ratchet.init(libolm_seed, 0);
    r2.advanceToUnchecked(0x2000000);
    try testing.expectEqual(@as(u32, 0x2000000), r2.counter);

    try testing.expectEqualSlices(u8, &r2.data, &r1.data);
}

test "libolm vector: advanceToUnchecked overflow by one (0xffffffff -> 0 == a single advanceStep)" {
    var r1 = Ratchet.init(libolm_seed, 0xffffffff);
    r1.advanceToUnchecked(0);
    try testing.expectEqual(@as(u32, 0), r1.counter);

    var r2 = Ratchet.init(libolm_seed, 0xffffffff);
    r2.advanceStep();
    try testing.expectEqual(@as(u32, 0), r2.counter);

    try testing.expectEqualSlices(u8, &r2.data, &r1.data);
}

test "libolm vector: advanceToUnchecked double wraparound" {
    var r1 = Ratchet.init(libolm_seed, 1);
    r1.advanceToUnchecked(0x80000000);
    r1.advanceToUnchecked(0);
    try testing.expectEqual(@as(u32, 0), r1.counter);

    var r2 = Ratchet.init(libolm_seed, 1);
    r2.advanceToUnchecked(0);
    try testing.expectEqual(@as(u32, 0), r2.counter);

    try testing.expectEqualSlices(u8, &r2.data, &r1.data);
}

// ── mutation-catching note ──────────────────────────────────────────────
//
// These KATs are exactly the ones that catch the Megolm-specific mistake
// this module's SPEC.md/report calls out: advancing only the named
// ratchet part without resetting the parts to its right still round-trips
// against ITSELF (encrypt/decrypt agree, since both run the same broken
// code) but diverges from the real algorithm at the very first boundary
// crossing. The single-step vector above (index 1) does not cross any
// boundary and would pass even under that mutation; the 0x1000000 vector
// (crossing 2^24) and the 0x1041506 vector (crossing 2^24, 2^16, AND 2^8)
// are what actually catch it -- see this module's report for the specific
// mutation applied and which of these tests went red.

// ── EXTERNAL ANCHOR (grade 1) + independent re-derivation (grade 2):
// a real libolm-produced session key + message, decoded and decrypted
// byte-exactly ─────────────────────────────────────────────────────────

test "libolm vector: real session-key + message decrypts to plaintext 'Message' at index 0" {
    const session_key_b64 =
        "AgAAAAAwMTIzNDU2Nzg5QUJERUYwMTIzNDU2Nzg5QUJDREVGMDEyMzQ1Njc4OUFCREVGM" ++
        "DEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkRFRjAxMjM0NTY3ODlBQkNERUYwMTIzND" ++
        "U2Nzg5QUJERUYwMTIzNDU2Nzg5QUJDREVGMDEyMw0bdg1BDq4Px/slBow06q8n/B9WBfw" ++
        "WYyNOB8DlUmXGGwrFmaSb9bR/eY8xgERrxmP07hFmD9uqA2p8PMHdnV5ysmgufE6oLZ5+" ++
        "8/mWQOW3VVTnDIlnwd8oHUYRuk8TCQ";
    const message_b64 =
        "AwgAEhAcbh6UpbByoyZxufQ+h2B+8XHMjhR69G8F4+qjMaFlnIXusJZX3r8LnRORG9T3D" ++
        "XFdbVuvIWrLyRfm4i8QRbe8VPwGRFG57B1CtmxanuP8bHtnnYqlwPsD";

    const key = try SessionKey.fromBase64(testing.allocator, session_key_b64);
    var session = try InboundGroupSession.fromSessionKey(key);
    defer session.deinit();
    try testing.expectEqual(@as(u32, 0), session.firstKnownIndex());

    var msg = try Message.fromBase64(testing.allocator, message_b64);
    defer msg.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 0), msg.message_index);

    var decrypted = try session.decrypt(testing.allocator, &msg);
    defer decrypted.deinit(testing.allocator);
    try testing.expectEqualStrings("Message", decrypted.plaintext);
}

test "libolm vector: tampered final byte (part of the signature) is rejected as InvalidSignature" {
    const session_key_b64 =
        "AgAAAAAwMTIzNDU2Nzg5QUJERUYwMTIzNDU2Nzg5QUJDREVGMDEyMzQ1Njc4OUFCREVGM" ++
        "DEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkRFRjAxMjM0NTY3ODlBQkNERUYwMTIzND" ++
        "U2Nzg5QUJERUYwMTIzNDU2Nzg5QUJDREVGMDEyMztqJ7zOtqQtYqOo0CpvDXNlMhV3HeJ" ++
        "DpjrASKGLWdop4lx1cSN3Xv1TgfLPW8rhGiW+hHiMxd36nRuxscNv9k4oJA/KP+o0mi1w" ++
        "v44StrEJ1wwx9WZHBUIWkQbaBSuBDw";
    const message_ok_b64 =
        "AwgAEhAcbh6UpbByoyZxufQ+h2B+8XHMjhR69G8nP4pNZGl/3QMgrzCZPmP+F2aPLyKPz" ++
        "xRPBMUkeXRJ6Iqm5NeOdx2eERgTW7P20CM+lL3Xpk+ZUOOPvsSQNaAL";
    // Same message with libolm's own test-suite mutation applied: the
    // final byte (last byte of the 64-byte Ed25519 signature) changed to
    // ASCII 'E', reproduced by decoding, flipping the last raw byte, and
    // re-encoding -- NOT a re-transcription of a base64 string by eye.
    const message_tampered_b64 =
        "AwgAEhAcbh6UpbByoyZxufQ+h2B+8XHMjhR69G8nP4pNZGl/3QMgrzCZPmP+F2aPLyKPz" ++
        "xRPBMUkeXRJ6Iqm5NeOdx2eERgTW7P20CM+lL3Xpk+ZUOOPvsSQNaBF";

    const key = try SessionKey.fromBase64(testing.allocator, session_key_b64);
    var session = try InboundGroupSession.fromSessionKey(key);
    defer session.deinit();

    var msg_ok = try Message.fromBase64(testing.allocator, message_ok_b64);
    defer msg_ok.deinit(testing.allocator);
    var decrypted = try session.decrypt(testing.allocator, &msg_ok);
    defer decrypted.deinit(testing.allocator);
    try testing.expectEqualStrings("Message", decrypted.plaintext);

    var msg_bad = try Message.fromBase64(testing.allocator, message_tampered_b64);
    defer msg_bad.deinit(testing.allocator);
    try testing.expectError(error.InvalidSignature, session.decrypt(testing.allocator, &msg_bad));
}

// ── reject-teeth: InvalidMac, constructed honestly ──────────────────────
//
// Under the real protocol, the Ed25519 signature covers `payload || mac`
// (see message.zig), so ANY tamper to the ciphertext or the MAC also
// invalidates the signature -- there is no way for an outside attacker to
// produce a message with a valid signature but a wrong MAC without the
// signing key. To still exercise the MAC-verification code path
// specifically (proving it is a real, independent guard and not dead
// code shadowed by the signature check), this test holds the signing key
// (it constructed the session) and deliberately signs a message whose MAC
// does not match its ciphertext -- an honest unit-test construction of an
// otherwise-unreachable-from-outside state, not a claim that real
// attackers can do this.
test "InvalidMac is reachable and distinct from InvalidSignature (honest construction)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var out = session_mod.OutboundSession.init(io);
    defer out.deinit();
    var in = try InboundGroupSession.fromSessionKey(try out.sessionKey());
    defer in.deinit();

    var msg = try out.encrypt(testing.allocator, "authentic content");
    defer msg.deinit(testing.allocator);

    // Corrupt the MAC field, then RE-SIGN over the corrupted bytes using
    // the (test-held) private signing key, so the signature check passes
    // and decrypt reaches the MAC check.
    msg.mac[0] ^= 0xFF;
    const sig_bytes = try msg.signatureBytes(testing.allocator);
    defer testing.allocator.free(sig_bytes);
    const sig = try out.signing_key.sign(sig_bytes, null);
    msg.signature = sig.toBytes();

    try testing.expectError(error.InvalidMac, in.decrypt(testing.allocator, &msg));
}

// ── reject-teeth: CannotRatchetBackward vs. MessageIndexTooOld ──────────

test "CannotRatchetBackward (Ratchet primitive) is distinct from MessageIndexTooOld (session level)" {
    // Primitive-level: a direct caller of Ratchet.advanceTo trying to move
    // backward gets a typed error, fail-closed (state untouched).
    var r = Ratchet.init(libolm_seed, 10);
    const before = r.data;
    try testing.expectError(error.CannotRatchetBackward, r.advanceTo(3));
    try testing.expectEqual(@as(u32, 10), r.counter);
    try testing.expectEqualSlices(u8, &before, &r.data);

    // Session-level: an InboundGroupSession asked to decrypt a message
    // whose index is earlier than its first_known_index gets a DIFFERENT
    // typed error -- it never calls the backward-refusing primitive at
    // all, because `findRatchet` returns null first.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var out = session_mod.OutboundSession.init(io);
    defer out.deinit();
    var early = try out.encrypt(testing.allocator, "too early");
    defer early.deinit(testing.allocator);
    var skipped = try out.encrypt(testing.allocator, "skipped"); // advance past index 0
    skipped.deinit(testing.allocator);

    var in = try InboundGroupSession.fromSessionKey(try out.sessionKey()); // shared at index 2
    defer in.deinit();
    try testing.expectError(error.MessageIndexTooOld, in.decrypt(testing.allocator, &early));
}
