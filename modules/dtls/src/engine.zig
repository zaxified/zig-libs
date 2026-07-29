// SPDX-License-Identifier: MIT

//! dtls.engine — pure, `Connection`-agnostic helper for the ONE piece of
//! state the handshake flight engine needs that none of the sibling files
//! provide: a running SHA-256 hash of the handshake message transcript
//! (RFC 8446 §4.4.1's `Transcript-Hash`, reused unchanged by DTLS 1.3 —
//! RFC 9147 §5.8/§5.9).
//!
//! **Framing subtlety (RFC 9147 §5.2):** the transcript hash is computed
//! over messages framed with TLS 1.3's plain 4-byte handshake header
//! (`msg_type: u8, length: u24`) — NOT DTLS's 12-byte header
//! (`handshake.zig`'s `HandshakeHeader`, which additionally carries
//! `message_seq`/`fragment_offset`/`fragment_length` for the unreliable-
//! transport reassembly `handshake.zig` implements). Mixing the two up is a
//! classic DTLS 1.3 interop bug: it would silently produce a transcript hash
//! (and therefore every downstream secret) that no compliant peer agrees
//! with. This file only ever appends the TLS-style header.
//!
//! `keyschedule.zig`'s functions take a caller-supplied transcript-hash
//! byte slice; `Transcript` is what the handshake engine (`Connection.zig`)
//! uses to produce that slice at each of the several distinct points the
//! key schedule needs it (through ClientHello alone, truncated before its
//! PSK binders — RFC 8446 §4.2.11.2; through ServerHello; through
//! EncryptedExtensions + the server's Finished; ...).

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Transcript = struct {
    hasher: Sha256 = Sha256.init(.{}),

    /// Commits one handshake message to the running transcript: `msg_type
    /// (1 byte) || length (u24, big-endian) || body`. `length` is always
    /// `body.len` here — DTLS 1.3's transcript never sees the DTLS-specific
    /// header fields (see the module doc comment).
    pub fn append(self: *Transcript, msg_type: u8, body: []const u8) void {
        var hdr: [4]u8 = undefined;
        writeHeader(&hdr, msg_type, body.len);
        self.hasher.update(&hdr);
        self.hasher.update(body);
    }

    /// The RFC 8446 §4.2.11.2 PSK-binder case: computes the transcript hash
    /// AS IF `msg_type`/`partial_body` had been `append`-ed, WITHOUT
    /// mutating `self` (the real, full ClientHello — binders included — is
    /// `append`-ed separately once its binder value is known). `full_len`
    /// is the TRUE total body length (including the not-yet-computed
    /// binders) — RFC 8446 §4.2.11.2's `Truncate()` removes the binders
    /// list's VALUE bytes from the hash input but the header's declared
    /// length still reflects the complete message, matching what the peer's
    /// own transcript will contain once the binder is filled in.
    pub fn wouldBeHash(self: Transcript, msg_type: u8, full_len: usize, partial_body: []const u8) [32]u8 {
        var copy = self.hasher;
        var hdr: [4]u8 = undefined;
        writeHeader(&hdr, msg_type, full_len);
        copy.update(&hdr);
        copy.update(partial_body);
        return copy.finalResult();
    }

    /// The transcript hash of everything `append`-ed so far. Non-destructive
    /// (operates on a copy of the hasher) — more messages can be appended
    /// afterward, matching the key schedule's need for several different
    /// "through message X" hashes over the SAME growing transcript.
    pub fn currentHash(self: Transcript) [32]u8 {
        var copy = self.hasher;
        return copy.finalResult();
    }

    /// RFC 8446 §4.4.1's HelloRetryRequest transcript rewrite. When a server
    /// answers ClientHello1 with a HelloRetryRequest, the transcript is NOT
    /// "CH1 || HRR || CH2" — CH1 is replaced by a synthetic `message_hash`
    /// message carrying its hash:
    ///
    ///     Hash(message_hash || 00 00 Hash.length || Hash(ClientHello1)
    ///          || HelloRetryRequest || ClientHello2 || ...)
    ///
    /// `client_hello1_hash` is the transcript hash as it stood immediately
    /// after ClientHello1 was appended — which, CH1 being the first message,
    /// is exactly `Hash(ClientHello1)`.
    ///
    /// The rewrite exists so that a stateless server, which kept nothing
    /// between the two ClientHellos, can reconstruct the same transcript from
    /// the cookie it handed out. Getting it wrong is invisible until a real
    /// peer is on the other end: both sides of a self-interop suite would
    /// simply agree on "CH1 || HRR || CH2" and every test would pass.
    pub fn resetToMessageHash(self: *Transcript, client_hello1_hash: [32]u8) void {
        self.hasher = Sha256.init(.{});
        var hdr: [4]u8 = undefined;
        writeHeader(&hdr, message_hash_type, client_hello1_hash.len);
        self.hasher.update(&hdr);
        self.hasher.update(&client_hello1_hash);
    }

    /// RFC 8446 §4.4.1's synthetic handshake type (254) — never sent on the
    /// wire, only ever hashed.
    pub const message_hash_type: u8 = 254;

    fn writeHeader(out: *[4]u8, msg_type: u8, len: usize) void {
        out[0] = msg_type;
        out[1] = @truncate(len >> 16);
        out[2] = @truncate(len >> 8);
        out[3] = @truncate(len);
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Transcript.append: matches a direct hash of header+body" {
    var t = Transcript{};
    t.append(1, "hello");

    var want_input: [4 + 5]u8 = undefined;
    want_input[0] = 1;
    want_input[1] = 0;
    want_input[2] = 0;
    want_input[3] = 5;
    @memcpy(want_input[4..], "hello");
    var want: [32]u8 = undefined;
    Sha256.hash(&want_input, &want, .{});

    try testing.expectEqualSlices(u8, &want, &t.currentHash());
}

test "Transcript: multiple appends accumulate (order-sensitive)" {
    var a = Transcript{};
    a.append(1, "AAAA");
    a.append(2, "BB");

    var b = Transcript{};
    b.append(2, "BB");
    b.append(1, "AAAA");

    try testing.expect(!std.mem.eql(u8, &a.currentHash(), &b.currentHash()));
}

test "Transcript.currentHash: non-destructive, more can be appended after" {
    var t = Transcript{};
    t.append(1, "first");
    const h1 = t.currentHash();
    const h1_again = t.currentHash();
    try testing.expectEqualSlices(u8, &h1, &h1_again);

    t.append(2, "second");
    const h2 = t.currentHash();
    try testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "Transcript.wouldBeHash: equals append+currentHash for the SAME final bytes" {
    var t = Transcript{};
    const body = "the-full-message-body";
    const want = blk: {
        var copy = t;
        copy.append(1, body);
        break :blk copy.currentHash();
    };
    const got = t.wouldBeHash(1, body.len, body);
    try testing.expectEqualSlices(u8, &want, &got);
}

test "Transcript.wouldBeHash: does not mutate the original transcript" {
    var t = Transcript{};
    t.append(9, "unrelated");
    const before = t.currentHash();
    _ = t.wouldBeHash(1, 100, "partial-only-prefix");
    const after = t.currentHash();
    try testing.expectEqualSlices(u8, &before, &after);
}

test "Transcript.wouldBeHash: truncation semantics — full_len drives the header, not partial_body.len" {
    // Simulates the PSK-binder case: the ClientHello's declared length
    // includes the binder bytes, but the hash input stops short of them.
    var t = Transcript{};
    const full_len: usize = 50; // as if 18 more (binder) bytes will follow
    const partial = "only-the-first-part-of-the-message";
    const h = t.wouldBeHash(1, full_len, partial);

    var want_input: [4 + partial.len]u8 = undefined;
    want_input[0] = 1;
    want_input[1] = 0;
    want_input[2] = 0;
    want_input[3] = 50;
    @memcpy(want_input[4..], partial);
    var want: [32]u8 = undefined;
    Sha256.hash(&want_input, &want, .{});
    try testing.expectEqualSlices(u8, &want, &h);
}
