// SPDX-License-Identifier: MIT

//! Real DTLS 1.3 frames for this module's fuzz corpora, read out of the
//! recorded wolfSSL transcript instead of being written by hand.
//!
//! ## Why a hand-written seed cannot work here
//!
//! Outside `zig build --fuzz` the test runner replays exactly what a target
//! declares as its `corpus`, plus one empty input. So the corpus IS the input
//! set, and for this module every level of it is length-framed, versioned and
//! cross-checked: a record carries a 13- or 4-octet header whose length field
//! must agree with the datagram, a handshake message carries a 12-octet header
//! whose `fragment_offset + fragment_length` must agree with `length`, and a
//! ClientHello's extension block is a length-prefixed list of length-prefixed
//! entries. A literal edited by hand is refused at the first of those, and the
//! corpus ends up exercising nothing but the refusal path.
//!
//! `testdata/wolfssl_transcript.txt` already holds 120 datagrams that a real
//! wolfSSL 5.9.1 sent or accepted — 13 distinct ClientHello bodies, 20
//! ServerHello bodies, and the extension blocks inside them, including the
//! 1222-octet hybrid X25519MLKEM768 `key_share`. They are frames no one has to
//! keep in step with anything, because `wolfssl_replay.zig` already fails if
//! they stop being what this module speaks.
//!
//! ## ⚠ Sizes measured, not assumed
//!
//! A seed longer than the harness's buffer is not a large seed, it is the
//! EMPTY one: `Smith.slice` clamps the declared length to what remains and then
//! checks it against `rangeAtMost(0, buf.len)`, and a length over `buf.len`
//! fails that check and falls back to the range minimum, zero. The largest
//! frames here are a 1554-octet ClientHello body, a 1512-octet extension block
//! and a 1222-octet `key_share` — every one of them larger than the 256- and
//! 1024-octet buffers the harnesses in `messages.zig` used to have, so the
//! module's own hybrid handshake could not have passed through its own
//! harnesses. `Store` counts what it had to drop and the corpus guards pin that
//! count at zero.
//!
//! ## ⚠ `Store` must not be copied
//!
//! Every returned slice aliases the `Store`'s own array, exactly like the
//! corpus builders in `iec61850/presentation.zig` and `ethtool/bitset.zig`.
//! Declare it as a `var` in the test body that uses it and pass a pointer.

const std = @import("std");
const testkit = @import("testkit");

pub const transcript = @embedFile("testdata/wolfssl_transcript.txt");

/// Every recorded datagram fits this; asserted at the bottom of this file
/// rather than believed, because a datagram that does not fit is silently
/// skipped and a corpus is then quietly smaller than it reads.
pub const max_datagram = 2048;

const plaintext_header_len = 13;
const legacy_version_dtls12 = [2]u8{ 0xFE, 0xFD };
const content_type_handshake = 22;
const handshake_header_len = 12;

/// Every byte string in the transcript that was **on the wire**, hex-decoded
/// one at a time into a caller-supplied buffer.
///
/// ⚠ Not every `in=`/`out=` is a datagram, and the difference matters: `send
/// in=` is the application plaintext handed to `send`, and `recv out=` is the
/// plaintext it recovered. Taking those too puts "hello from zig-libs" in a
/// corpus of record headers — arbitrary bytes wearing a record's name, which
/// is exactly the kind of entry that makes a pinned count meaningless. Only
/// `start out`, `flight in`, `flight out`, `send out` and `recv in` are
/// datagrams.
pub const DatagramIterator = struct {
    lines: std.mem.SplitIterator(u8, .scalar) = std.mem.splitScalar(u8, transcript, '\n'),
    toks: ?std.mem.TokenIterator(u8, .scalar) = null,
    want_in: bool = false,
    want_out: bool = false,
    /// Datagrams whose hex was longer than the caller's buffer. Not a warning:
    /// a skipped datagram is a corpus entry that silently does not exist.
    too_large: usize = 0,

    pub fn next(self: *DatagramIterator, out: []u8) ?[]u8 {
        while (true) {
            if (self.toks) |*t| {
                while (t.next()) |tok| {
                    const eq = std.mem.indexOfScalar(u8, tok, '=') orelse continue;
                    const key = tok[0..eq];
                    const wanted = if (std.mem.eql(u8, key, "in"))
                        self.want_in
                    else if (std.mem.eql(u8, key, "out"))
                        self.want_out
                    else
                        false;
                    if (!wanted) continue;
                    const hex = tok[eq + 1 ..];
                    if (hex.len == 0 or hex.len % 2 != 0) continue;
                    if (hex.len / 2 > out.len) {
                        self.too_large += 1;
                        continue;
                    }
                    const bytes = std.fmt.hexToBytes(out[0 .. hex.len / 2], hex) catch continue;
                    return bytes;
                }
                self.toks = null;
            }
            const raw = self.lines.next() orelse return null;
            const line = std.mem.trim(u8, raw, " \r\t");
            if (line.len == 0 or line[0] == '#') continue;
            const op = line[0 .. std.mem.indexOfScalar(u8, line, ' ') orelse line.len];
            self.want_in = std.mem.eql(u8, op, "flight") or std.mem.eql(u8, op, "recv");
            self.want_out = std.mem.eql(u8, op, "flight") or std.mem.eql(u8, op, "start") or
                std.mem.eql(u8, op, "send");
            if (!self.want_in and !self.want_out) continue;
            self.toks = std.mem.tokenizeScalar(u8, line, ' ');
        }
    }
};

/// A fixed-capacity corpus: the frames themselves, and the same frames wrapped
/// in the `u32` little-endian length header `Smith.slice` reads first.
///
/// `tail`, when given, is appended to a seed as an eight-octet little-endian
/// word — the shape a draw AFTER the byte draw reads. Without it every such
/// draw is its range minimum on a corpus replay, which is how eight harnesses
/// in one tranche elsewhere in this tree ran with every knob pinned.
pub fn Store(comptime bytes_cap: usize, comptime max_entries: usize) type {
    return struct {
        const Self = @This();

        buf: [bytes_cap]u8 = undefined,
        used: usize = 0,
        frames: [max_entries][]const u8 = undefined,
        seeds: [max_entries][]const u8 = undefined,
        n: usize = 0,
        /// Frames that did not fit the capacity. Pinned at zero by the guards.
        dropped: usize = 0,

        pub fn push(self: *Self, frame: []const u8, tail: ?u64) void {
            const need = 4 + frame.len + @as(usize, if (tail == null) 0 else 8);
            if (self.n == max_entries or self.used + need > bytes_cap) {
                self.dropped += 1;
                return;
            }
            const dest = self.buf[self.used..];
            const head = testkit.fuzz.seedInto(dest, frame);
            if (tail) |t| std.mem.writeInt(u64, dest[head.len..][0..8], t, .little);
            self.frames[self.n] = dest[4 .. 4 + frame.len];
            self.seeds[self.n] = dest[0..need];
            self.used += need;
            self.n += 1;
        }

        /// `push`, unless a byte-identical frame is already in. The transcript
        /// records the same ClientHello under several cases; a corpus of
        /// twenty copies of thirteen frames measures the same thirteen inputs
        /// and costs the fuzzer the difference.
        pub fn pushUnique(self: *Self, frame: []const u8, tail: ?u64) void {
            for (self.frames[0..self.n]) |f| {
                if (std.mem.eql(u8, f, frame)) return;
            }
            self.push(frame, tail);
        }

        pub fn corpus(self: *const Self) []const []const u8 {
            return self.seeds[0..self.n];
        }
    };
}

/// Complete, unfragmented handshake message bodies of `msg_type` carried in
/// epoch-0 `DTLSPlaintext` records, in transcript order, deduplicated.
///
/// Epoch-0 is the only epoch a recording can offer in the clear: everything
/// after the ServerHello is AEAD-protected, so `Certificate`,
/// `CertificateVerify` and `CertificateRequest` bodies have to come from this
/// module's own encoders instead (which is what their corpora do).
pub fn collectHandshakeBodies(store: anytype, msg_type: u8, tail: ?u64) void {
    var dg: [max_datagram]u8 = undefined;
    var it: DatagramIterator = .{};
    while (it.next(&dg)) |d| {
        var off: usize = 0;
        while (off + plaintext_header_len <= d.len) {
            if (!std.mem.eql(u8, d[off + 1 ..][0..2], &legacy_version_dtls12)) break;
            const rec_len: usize = std.mem.readInt(u16, d[off + 11 ..][0..2], .big);
            if (off + plaintext_header_len + rec_len > d.len) break;
            const frag = d[off + plaintext_header_len ..][0..rec_len];
            defer off += plaintext_header_len + rec_len;
            if (d[off] != content_type_handshake or frag.len < handshake_header_len) continue;
            if (frag[0] != msg_type) continue;
            const total = readU24(frag[1..4]);
            const frag_off = readU24(frag[6..9]);
            const frag_len = readU24(frag[9..12]);
            if (frag_off != 0 or frag_len != total) continue; // a fragment is not a message
            if (handshake_header_len + @as(usize, frag_len) > frag.len) continue;
            store.pushUnique(frag[handshake_header_len..][0..frag_len], tail);
        }
    }
}

/// The whole extension block of every `msg_type` body — the `Extension
/// extensions<>` list including its own two-octet length, which is exactly
/// what `messages.decodeExtensions` takes.
pub fn collectExtensionBlocks(store: anytype, msg_type: u8, tail: ?u64) void {
    var bodies: Store(8192, 32) = .{};
    collectHandshakeBodies(&bodies, msg_type, null);
    for (bodies.frames[0..bodies.n]) |body| {
        const exts = extensionBlockOf(msg_type, body) orelse continue;
        store.pushUnique(exts, tail);
    }
}

/// The `extension_data` of every extension of type `ext_type` found in a
/// `msg_type` body — a real `key_share`, `cookie`, `psk_key_exchange_modes`,
/// `supported_groups` or `pre_shared_key` body, as a peer actually sent it.
pub fn collectExtensionData(store: anytype, msg_type: u8, ext_type: u16, tail: ?u64) void {
    var blocks: Store(8192, 32) = .{};
    collectExtensionBlocks(&blocks, msg_type, null);
    for (blocks.frames[0..blocks.n]) |block| {
        const total: usize = std.mem.readInt(u16, block[0..2], .big);
        var i: usize = 2;
        while (i + 4 <= 2 + total) {
            const t = std.mem.readInt(u16, block[i..][0..2], .big);
            const l: usize = std.mem.readInt(u16, block[i + 2 ..][0..2], .big);
            i += 4;
            if (i + l > block.len) break;
            if (t == ext_type) store.pushUnique(block[i..][0..l], tail);
            i += l;
        }
    }
}

/// Skips a ClientHello's or ServerHello's fixed prefix and returns the
/// extension block. Deliberately its own walk rather than a call into
/// `messages.zig`: a corpus that disappears when the decoder under test breaks
/// is not a corpus.
fn extensionBlockOf(msg_type: u8, body: []const u8) ?[]const u8 {
    if (body.len < 2 + 32 + 1) return null;
    var i: usize = 2 + 32;
    const sid_len = body[i];
    i += 1 + @as(usize, sid_len);
    if (i >= body.len) return null;
    if (msg_type == 1) {
        const cookie_len = body[i]; // DTLS's legacy_cookie<0..2^8-1>
        i += 1 + @as(usize, cookie_len);
        if (i + 2 > body.len) return null;
        const cs_len: usize = std.mem.readInt(u16, body[i..][0..2], .big);
        i += 2 + cs_len;
        if (i >= body.len) return null;
        const comp_len = body[i];
        i += 1 + @as(usize, comp_len);
    } else {
        i += 2 + 1; // cipher_suite, legacy_compression_method
    }
    if (i + 2 > body.len) return null;
    return body[i..];
}

fn readU24(b: *const [3]u8) u24 {
    return (@as(u24, b[0]) << 16) | (@as(u24, b[1]) << 8) | b[2];
}

// ── the instrument's own anchors ─────────────────────────────────────────────

const testing = std.testing;

test "every recorded datagram fits the buffer this file hands its callers" {
    // The trap this closes: a datagram over `max_datagram` is skipped, and a
    // corpus is then quietly smaller than it reads. The largest recording today
    // is 1830 octets (the hybrid ML-KEM ClientHello flight).
    var dg: [max_datagram]u8 = undefined;
    var it: DatagramIterator = .{};
    var count: usize = 0;
    var largest: usize = 0;
    while (it.next(&dg)) |d| {
        count += 1;
        largest = @max(largest, d.len);
    }
    try testing.expectEqual(@as(usize, 0), it.too_large);
    try testing.expectEqual(@as(usize, 120), count);
    try testing.expect(largest > 1500); // a recording that lost its big flights
}

test "the transcript still yields the frames the corpora are built from" {
    // A floor, not a mirror: a transcript re-captured with more cases may hold
    // more. What must never happen silently is FEWER — a corpus built from an
    // emptied transcript is an empty corpus, and every guard downstream would
    // still pass with `expectEqual(0, 0)`.
    var ch: Store(8192, 32) = .{};
    collectHandshakeBodies(&ch, 1, null);
    try testing.expectEqual(@as(usize, 0), ch.dropped);
    try testing.expectEqual(@as(usize, 13), ch.n);

    var sh: Store(8192, 32) = .{};
    collectHandshakeBodies(&sh, 2, null);
    try testing.expectEqual(@as(usize, 0), sh.dropped);
    try testing.expectEqual(@as(usize, 20), sh.n);

    // The one that matters most: the hybrid key_share, which is bigger than
    // every fuzz buffer this module had before the corpora were written.
    var ks: Store(8192, 32) = .{};
    collectExtensionData(&ks, 1, 51, null);
    try testing.expectEqual(@as(usize, 0), ks.dropped);
    var largest: usize = 0;
    for (ks.frames[0..ks.n]) |f| largest = @max(largest, f.len);
    try testing.expectEqual(@as(usize, 1222), largest);
}

test "a tail is eight little-endian octets after the frame, and Smith reads it back" {
    var s: Store(64, 4) = .{};
    s.push("abc", 0x1234);
    var smith: std.testing.Smith = .{ .in = s.corpus()[0] };
    var buf: [16]u8 = undefined;
    const n = smith.slice(&buf);
    try testing.expectEqualStrings("abc", buf[0..n]);
    try testing.expectEqual(@as(u64, 0x1234), smith.value(u64));
}

test "Store drops rather than overruns, and says so" {
    var s: Store(16, 4) = .{};
    s.push("abcd", null); // 4 + 4 = 8 used
    s.push("abcdefghij", null); // 4 + 10 > 8 remaining
    try testing.expectEqual(@as(usize, 1), s.n);
    try testing.expectEqual(@as(usize, 1), s.dropped);
    s.pushUnique("abcd", null); // already in
    try testing.expectEqual(@as(usize, 1), s.n);
    try testing.expectEqual(@as(usize, 1), s.dropped);
}
