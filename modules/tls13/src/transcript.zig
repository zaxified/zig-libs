// SPDX-License-Identifier: MIT

//! tls13.transcript — the running handshake transcript hash (RFC 8446
//! §4.4.1's `Transcript-Hash`), generic over the suite's hash: SHA-256 for
//! `TLS_AES_128_GCM_SHA256` / `TLS_CHACHA20_POLY1305_SHA256`, SHA-384 for
//! `TLS_AES_256_GCM_SHA384`. DTLS 1.3 reuses it unchanged (RFC 9147 §5.8/§5.9).
//! Moved from `dtls/src/engine.zig` (SHA-256 only there) on 2026-10-20;
//! `dtls.engine.Transcript` is `Transcript(Sha256)`.
//!
//! **Framing (RFC 9147 §5.2):** the hash runs over messages framed with TLS
//! 1.3's plain 4-byte handshake header (`msg_type: u8, length: u24`) — NOT
//! DTLS's 12-byte header with `message_seq` / `fragment_offset` /
//! `fragment_length`. Mixing the two up is a classic DTLS 1.3 interop bug: it
//! silently produces a transcript hash (and every downstream secret) that no
//! compliant peer agrees with. This file only ever appends the TLS header.
//!
//! The key schedule (`keyschedule.zig`) takes a caller-supplied transcript
//! hash; `Transcript` produces it at each point the schedule needs (through
//! ClientHello truncated before its PSK binders — RFC 8446 §4.2.11.2; through
//! ServerHello; through the server Finished; through the client Finished).
//! The hash is of public handshake bytes, not a secret.

const std = @import("std");

/// A transcript over `Hash` (a std hash with `init`, `update`, `finalResult`
/// and `digest_length`, e.g. `std.crypto.hash.sha2.Sha384`).
pub fn Transcript(comptime Hash: type) type {
    return struct {
        const Self = @This();

        pub const digest_length = Hash.digest_length;

        hasher: Hash = Hash.init(.{}),

        /// Commits one handshake message to the running transcript: `msg_type
        /// (1 byte) || length (u24, big-endian) || body`. `length` is always
        /// `body.len` here — the transcript never sees DTLS-specific header
        /// fields (see the file doc comment). Panics when `body.len` is over
        /// the u24 length field (2^24 - 1).
        pub fn append(self: *Self, msg_type: u8, body: []const u8) void {
            var hdr: [4]u8 = undefined;
            writeHeader(&hdr, msg_type, body.len);
            self.hasher.update(&hdr);
            self.hasher.update(body);
        }

        /// The RFC 8446 §4.2.11.2 PSK-binder case: computes the transcript
        /// hash AS IF `msg_type`/`partial_body` had been `append`-ed, WITHOUT
        /// mutating `self` (the full ClientHello — binders included — is
        /// `append`-ed separately once its binder value is known). `full_len`
        /// is the TRUE total body length (including the not-yet-computed
        /// binders): `Truncate()` removes the binders list's bytes from the
        /// hash input, but the header's declared length still reflects the
        /// complete message, matching what the peer's transcript will contain.
        /// Panics when `full_len` is over 2^24 - 1, as `append`.
        pub fn wouldBeHash(self: Self, msg_type: u8, full_len: usize, partial_body: []const u8) [digest_length]u8 {
            var copy = self.hasher;
            var hdr: [4]u8 = undefined;
            writeHeader(&hdr, msg_type, full_len);
            copy.update(&hdr);
            copy.update(partial_body);
            return copy.finalResult();
        }

        /// The transcript hash of everything `append`-ed so far.
        /// Non-destructive (works on a copy of the hasher), so more messages
        /// can be appended afterwards — the key schedule needs several
        /// "through message X" hashes over the SAME growing transcript.
        pub fn currentHash(self: Self) [digest_length]u8 {
            var copy = self.hasher;
            return copy.finalResult();
        }

        /// RFC 8446 §4.4.1's HelloRetryRequest transcript rewrite. When a
        /// server answers ClientHello1 with a HelloRetryRequest, the
        /// transcript is NOT "CH1 || HRR || CH2" — CH1 is replaced by a
        /// synthetic `message_hash` message carrying its hash:
        ///
        ///     Hash(message_hash || 00 00 Hash.length || Hash(ClientHello1)
        ///          || HelloRetryRequest || ClientHello2 || ...)
        ///
        /// `client_hello1_hash` is the transcript hash as it stood right
        /// after ClientHello1 was appended — CH1 being the first message,
        /// exactly `Hash(ClientHello1)`. The hash is the suite's: a server
        /// that picks a SHA-384 suite hashes ClientHello1 with SHA-384.
        ///
        /// The rewrite lets a stateless server, which kept nothing between
        /// the two ClientHellos, rebuild the same transcript from its cookie.
        /// Getting it wrong is invisible until a real peer is on the other
        /// end: both sides of a self-interop suite would simply agree on
        /// "CH1 || HRR || CH2" and every test would pass.
        pub fn resetToMessageHash(self: *Self, client_hello1_hash: [digest_length]u8) void {
            self.hasher = Hash.init(.{});
            var hdr: [4]u8 = undefined;
            writeHeader(&hdr, message_hash_type, digest_length);
            self.hasher.update(&hdr);
            self.hasher.update(&client_hello1_hash);
        }
    };
}

/// RFC 8446 §4.4.1's synthetic handshake type (254) — never sent on the
/// wire, only ever hashed.
pub const message_hash_type: u8 = 254;

fn writeHeader(out: *[4]u8, msg_type: u8, len: usize) void {
    // The wire's u24; a longer message is no handshake message, and a wrapped
    // length would be a silently wrong transcript.
    if (len > 0xFF_FFFF) @panic("tls13: transcript message over 2^24 - 1 octets");
    out[0] = msg_type;
    out[1] = @truncate(len >> 16);
    out[2] = @truncate(len >> 8);
    out[3] = @truncate(len);
}

// ── tests (moved from dtls/src/engine.zig, now over both hashes) ─────────

const testing = std.testing;
const sha2 = std.crypto.hash.sha2;
/// Hex literal decoded at comptime; the RFC 8448 §5 messages need more than
/// the default branch quota (`testkit.hex.bytes` keeps the default).
fn hx(comptime n: usize, comptime hex: []const u8) [n]u8 {
    return comptime blk: {
        @setEvalBranchQuota(100_000);
        var out: [n]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
        break :blk out;
    };
}

fn expectAppendMatchesDirectHash(comptime Hash: type) !void {
    var t = Transcript(Hash){};
    t.append(1, "hello");

    var want_input: [4 + 5]u8 = undefined;
    want_input[0..4].* = .{ 1, 0, 0, 5 };
    @memcpy(want_input[4..], "hello");
    var want: [Hash.digest_length]u8 = undefined;
    Hash.hash(&want_input, &want, .{});
    try testing.expectEqualSlices(u8, &want, &t.currentHash());
}

test "Transcript.append: matches a direct hash of header+body (SHA-256, SHA-384)" {
    try expectAppendMatchesDirectHash(sha2.Sha256);
    try expectAppendMatchesDirectHash(sha2.Sha384);
}

test "Transcript: multiple appends accumulate (order-sensitive)" {
    var a = Transcript(sha2.Sha256){};
    a.append(1, "AAAA");
    a.append(2, "BB");

    var b = Transcript(sha2.Sha256){};
    b.append(2, "BB");
    b.append(1, "AAAA");

    try testing.expect(!std.mem.eql(u8, &a.currentHash(), &b.currentHash()));
}

test "Transcript.currentHash: non-destructive, more can be appended after" {
    var t = Transcript(sha2.Sha384){};
    t.append(1, "first");
    const h1 = t.currentHash();
    const h1_again = t.currentHash();
    try testing.expectEqualSlices(u8, &h1, &h1_again);

    t.append(2, "second");
    const h2 = t.currentHash();
    try testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "Transcript.wouldBeHash: equals append+currentHash for the SAME final bytes" {
    inline for (.{ sha2.Sha256, sha2.Sha384 }) |Hash| {
        var t = Transcript(Hash){};
        const body = "the-full-message-body";
        const want = blk: {
            var copy = t;
            copy.append(1, body);
            break :blk copy.currentHash();
        };
        const got = t.wouldBeHash(1, body.len, body);
        try testing.expectEqualSlices(u8, &want, &got);
    }
}

test "Transcript.wouldBeHash: does not mutate the original transcript" {
    var t = Transcript(sha2.Sha256){};
    t.append(9, "unrelated");
    const before = t.currentHash();
    _ = t.wouldBeHash(1, 100, "partial-only-prefix");
    const after = t.currentHash();
    try testing.expectEqualSlices(u8, &before, &after);
}

test "Transcript.wouldBeHash: truncation semantics — full_len drives the header, not partial_body.len" {
    // Simulates the PSK-binder case: the ClientHello's declared length
    // includes the binder bytes, but the hash input stops short of them.
    var t = Transcript(sha2.Sha256){};
    const full_len: usize = 50; // as if 18 more (binder) bytes will follow
    const partial = "only-the-first-part-of-the-message";
    const h = t.wouldBeHash(1, full_len, partial);

    var want_input: [4 + partial.len]u8 = undefined;
    want_input[0..4].* = .{ 1, 0, 0, 50 };
    @memcpy(want_input[4..], partial);
    var want: [32]u8 = undefined;
    sha2.Sha256.hash(&want_input, &want, .{});
    try testing.expectEqualSlices(u8, &want, &h);
}

test "Transcript.resetToMessageHash: message_hash header carries the suite hash's length" {
    // RFC 8446 §4.4.1: `message_hash (254) || 00 00 Hash.length || Hash(CH1)`.
    // The length octet is 0x20 under SHA-256 and 0x30 under SHA-384 — a
    // transcript that hard-coded 32 would agree with itself and with no
    // SHA-384 peer.
    inline for (.{ sha2.Sha256, sha2.Sha384 }) |Hash| {
        var ch1 = Transcript(Hash){};
        ch1.append(1, "client-hello-1");
        const ch1_hash = ch1.currentHash();

        var t = Transcript(Hash){};
        t.append(1, "client-hello-1");
        t.resetToMessageHash(ch1_hash);
        t.append(2, "hello-retry-request");

        var direct = Hash.init(.{});
        direct.update(&.{ 254, 0, 0, Hash.digest_length });
        direct.update(&ch1_hash);
        direct.update(&.{ 2, 0, 0, 19 });
        direct.update("hello-retry-request");
        try testing.expectEqualSlices(u8, &direct.finalResult(), &t.currentHash());
    }
}

test "Transcript(Sha256) over RFC 8448 §3: ClientHello || ServerHello hashes to the RFC's value" {
    // RFC 8448 §3's ClientHello (196 octets) and ServerHello (90 octets),
    // transcribed from the RFC text; the hash is the one its "tls13 c hs
    // traffic" derivation prints (and the key schedule's KAT uses).
    const ch = hx(196, "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece700000613011303130201" ++
        "0000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400" ++
        "230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b00" ++
        "03020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c" ++
        "00024001");
    const sh = hx(90, "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024" ++
        "001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304");
    const want = hx(32, "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    var t = Transcript(sha2.Sha256){};
    t.append(ch[0], ch[4..]);
    t.append(sh[0], sh[4..]);
    try testing.expectEqualSlices(u8, &want, &t.currentHash());
}

test "Transcript.resetToMessageHash over RFC 8448 §5: CH1, HRR, CH2, SH hash to the RFC's value" {
    // RFC 8448 §5 (HelloRetryRequest): ClientHello1 (180), the HRR (176),
    // ClientHello2 (512), ServerHello (123), transcribed from the RFC text.
    // The expected hash is the one §5's "tls13 c hs traffic" derivation
    // prints — the transcript with CH1 replaced by message_hash(Hash(CH1)).
    const ch1 = hx(180, "010000b00303b0b1c5a5aa37c5919f2ed1d5c6fff7fcb7849716945a2b8cee9258a346677b6f00000613011303130201" ++
        "0000810000000b0009000006736572766572ff01000100000a00080006001d00170018003300260024001d0020e8e8e3" ++
        "f3b93a25ed97a14a7dcacb8a272c6288e585c6484d05262fcad062ad1f002b0003020304000d0020001e040305030603" ++
        "020308040805080604010501060102010402050206020202002d00020101001c00024001");
    const hrr = hx(176, "020000ac0303cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c00130100008400330002" ++
        "0017002c0074007271dcd04bb88bc3189119398a00000000eefafc76c146b823b096f8aacad365dd0030953f4edf6256" ++
        "36e5f21bb2e23fcc654b1b5b40318d10d137abcbb87574e36e8a1f025f7dfa5d6e50781b5eda4aa15b0c8be778257d16" ++
        "aa3030e9e7841dd9e4c0342267e8ca0caf571fb2b7cff0f934b0002b00020304");
    const ch2 = hx(512, "010001fc0303b0b1c5a5aa37c5919f2ed1d5c6fff7fcb7849716945a2b8cee9258a346677b6f00000613011303130201" ++
        "0001cd0000000b0009000006736572766572ff01000100000a00080006001d001700180033004700450017004104a6da" ++
        "7392ec591e17abfd535964b99894d13befb221b3def2ebe3830eac8f0151812677c4d6d2237e85cf01d6910cfb83954e" ++
        "76ba7352830534159897e8065780002b0003020304000d0020001e040305030603020308040805080604010501060102" ++
        "010402050206020202002c0074007271dcd04bb88bc3189119398a00000000eefafc76c146b823b096f8aacad365dd00" ++
        "30953f4edf625636e5f21bb2e23fcc654b1b5b40318d10d137abcbb87574e36e8a1f025f7dfa5d6e50781b5eda4aa15b" ++
        "0c8be778257d16aa3030e9e7841dd9e4c0342267e8ca0caf571fb2b7cff0f934b0002d00020101001c00024001001500" ++
        "af0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "0000000000000000000000000000000000000000000000000000000000000000");
    const sh2 = hx(123, "020000770303bb341d847fd789c47c387172dc0c9bf147fccacb5043d86ca4c598d3ff571b9800130100004f00330045" ++
        "0017004104583e054b7a66672ae020ad9d2686fcc85b5ad41a134a0f03ee72b893052bd85b4c8de6776f5b04ac07d835" ++
        "40eab3e3d9c547bc6528c4317d294686093a6cad7d002b00020304");
    const want = hx(32, "8aa8e828ec2f8a884fec95a3139de01c15a3daa7ff5bfc3f4bfcc21b438d7bf8");
    var t = Transcript(sha2.Sha256){};
    t.append(ch1[0], ch1[4..]);
    t.resetToMessageHash(t.currentHash());
    for ([_][]const u8{ &hrr, &ch2, &sh2 }) |m| t.append(m[0], m[4..]);
    try testing.expectEqualSlices(u8, &want, &t.currentHash());
}
