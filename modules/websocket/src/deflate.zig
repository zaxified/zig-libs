// SPDX-License-Identifier: MIT

//! RFC 7692 permessage-deflate: the extension offer/response grammar
//! (§5, §7.1), message compression (§7.2.1) and bounded decompression
//! (§7.2.2). Pure, allocation-free: the caller owns every buffer.
//!
//! **One mode: no context takeover, both directions.** Every message is
//! compressed and decompressed on its own, the shape gorilla/websocket
//! implements and coder/websocket's `CompressionNoContextTakeover`. The
//! server's response always names `server_no_context_takeover` and
//! `client_no_context_takeover` (RFC 7692 §7.1.1.1/§7.1.1.2 let a server
//! add both even when the offer did not), the client's offer asks for both.
//! What it buys: no 32 KiB sliding window per connection and direction, and
//! a back-reference can never reach outside the message it is in — the
//! decompressor writes straight into the caller's message buffer, which is
//! both the LZ77 history and the decompression-bomb cap.
//!
//! The engine is std's `flate` (raw DEFLATE, RFC 1951).

const std = @import("std");
const http = @import("http");
const flate = std.compress.flate;

pub const extension_name = "permessage-deflate";

/// What `selectOffer` (server) and `verifyResponse` (client) agreed on.
/// Both context-takeover flags are always true in this module (see the file
/// comment); the struct exists so a later mode can be added without
/// changing a signature.
pub const Params = struct {
    server_no_context_takeover: bool = true,
    client_no_context_takeover: bool = true,
    /// The window the server said it compresses with (client side; 15 when
    /// the response did not name one). Informational: a fresh decompressor
    /// per message accepts any window up to 15.
    server_max_window_bits: u4 = 15,
};

/// The `Sec-WebSocket-Extensions` value a server writes when it accepted an
/// offer (`selectOffer` returned non-null).
pub const response_value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover";

/// The `Sec-WebSocket-Extensions` value a client sends to offer the
/// extension (`ClientRequestOptions.permessage_deflate`).
pub const offer_value = "permessage-deflate; client_no_context_takeover; server_no_context_takeover";

// ── extension header grammar (RFC 6455 §9.1, RFC 7692 §5) ───────────────────

/// One element of a `Sec-WebSocket-Extensions` list: an extension name and
/// its raw `; param[=value]` tail (parsed lazily by `params`).
pub const Extension = struct {
    name: []const u8,
    /// Everything after the name up to the element's end, unparsed.
    rest: []const u8,

    pub fn params(e: Extension) ParamIterator {
        return .{ .s = e.rest };
    }
};

pub const Param = struct {
    name: []const u8,
    /// null = the parameter has no value. A quoted-string value is
    /// unescaped into the iterator's `value_buf` (valid until the next
    /// `next` call); values longer than it (none of RFC 7692's are) come
    /// back as `error.Malformed`.
    value: ?[]const u8,
};

/// Splits one header value into its comma-separated elements. Commas inside
/// a quoted string do not split. An element that is not
/// `token *( ";" param )` is reported as `error.Malformed` and skipped by
/// the next call, so one bad element does not hide the ones after it.
pub const ExtensionIterator = struct {
    s: []const u8,
    i: usize = 0,

    pub fn next(it: *ExtensionIterator) error{Malformed}!?Extension {
        while (it.i < it.s.len) {
            const start = it.i;
            var in_quotes = false;
            var j = start;
            while (j < it.s.len) : (j += 1) {
                const c = it.s[j];
                if (in_quotes) {
                    if (c == '\\') {
                        j += 1;
                    } else if (c == '"') in_quotes = false;
                } else if (c == '"') {
                    in_quotes = true;
                } else if (c == ',') break;
            }
            it.i = @min(j + 1, it.s.len);
            if (j >= it.s.len) it.i = it.s.len;
            const elem = std.mem.trim(u8, it.s[start..@min(j, it.s.len)], " \t");
            if (elem.len == 0) continue; // `a, , b`: empty list elements are allowed (RFC 9110 §5.6.1)
            if (in_quotes) return error.Malformed;
            const semi = std.mem.findScalar(u8, elem, ';') orelse elem.len;
            const name = std.mem.trimEnd(u8, elem[0..semi], " \t");
            if (!http.h1.isToken(name)) return error.Malformed;
            const e: Extension = .{ .name = name, .rest = elem[semi..] };
            var pit = e.params();
            while (try pit.next()) |_| {}
            return e;
        }
        return null;
    }
};

pub const ParamIterator = struct {
    s: []const u8,
    // zig 0.17: the unescape buffer lives here, not in the returned `Param`
    // (a slice into a by-value `Param` dangled once it was copied out).
    value_buf: [16]u8 = undefined,

    pub fn next(it: *ParamIterator) error{Malformed}!?Param {
        var s = std.mem.trimStart(u8, it.s, " \t");
        if (s.len == 0) return null;
        if (s[0] != ';') return error.Malformed;
        s = std.mem.trimStart(u8, s[1..], " \t");
        var n: usize = 0;
        while (n < s.len and s[n] != '=' and s[n] != ';' and s[n] != ' ' and s[n] != '\t') n += 1;
        var p: Param = .{ .name = s[0..n], .value = null };
        if (!http.h1.isToken(p.name)) return error.Malformed;
        s = std.mem.trimStart(u8, s[n..], " \t");
        if (s.len != 0 and s[0] == '=') {
            s = std.mem.trimStart(u8, s[1..], " \t");
            if (s.len != 0 and s[0] == '"') {
                var k: usize = 1;
                var out: usize = 0;
                while (true) : (k += 1) {
                    if (k >= s.len) return error.Malformed;
                    var c = s[k];
                    if (c == '"') break;
                    if (c == '\\') {
                        k += 1;
                        if (k >= s.len) return error.Malformed;
                        c = s[k];
                    }
                    if (out == it.value_buf.len) return error.Malformed;
                    it.value_buf[out] = c;
                    out += 1;
                }
                s = s[k + 1 ..];
                // RFC 7692 §5: a quoted value must still be a token once unescaped.
                if (!http.h1.isToken(it.value_buf[0..out])) return error.Malformed;
                p.value = it.value_buf[0..out];
            } else {
                var v: usize = 0;
                while (v < s.len and s[v] != ';' and s[v] != ' ' and s[v] != '\t') v += 1;
                if (!http.h1.isToken(s[0..v])) return error.Malformed;
                p.value = s[0..v];
                s = s[v..];
            }
        }
        it.s = s;
        return p;
    }
};

/// `server_max_window_bits` / `client_max_window_bits` value: an integer
/// 8..15 with no leading zero (RFC 7692 §7.1.2.1/§7.1.2.2).
fn windowBits(v: []const u8) ?u4 {
    if (v.len == 1 and (v[0] == '8' or v[0] == '9')) return @intCast(v[0] - '0');
    if (v.len == 2 and v[0] == '1' and v[1] >= '0' and v[1] <= '5') return @intCast(10 + (v[1] - '0'));
    return null;
}

/// Whether this server can accept one `permessage-deflate` offer (RFC 7692
/// §7.1): every parameter known and at most once, with a valid value. A
/// `server_max_window_bits` below 15 is declined — std's compressor always
/// uses the full 32 KiB window (coder/websocket declines it the same way,
/// accept.go `acceptDeflate`). `client_max_window_bits` is only the client
/// saying it understands the parameter; not answering it leaves the client
/// at 15, which a fresh decompressor per message handles.
fn acceptableOffer(e: Extension) bool {
    var seen: [4]bool = @splat(false);
    var it = e.params();
    while (it.next() catch return false) |p| {
        const idx: usize = if (std.mem.eql(u8, p.name, "server_no_context_takeover"))
            0
        else if (std.mem.eql(u8, p.name, "client_no_context_takeover"))
            1
        else if (std.mem.eql(u8, p.name, "server_max_window_bits"))
            2
        else if (std.mem.eql(u8, p.name, "client_max_window_bits"))
            3
        else
            return false; // unknown parameter: decline this offer (§7.1)
        if (seen[idx]) return false; // §7.1: a parameter twice declines the offer
        seen[idx] = true;
        switch (idx) {
            0, 1 => if (p.value != null) return false,
            2 => {
                const v = p.value orelse return false;
                if ((windowBits(v) orelse return false) != 15) return false;
            },
            3 => if (p.value) |v| {
                _ = windowBits(v) orelse return false;
            },
            else => unreachable,
        }
    }
    return true;
}

/// Server side: walk every `Sec-WebSocket-Extensions` value of a request
/// (pass each header line's value in order) and pick the first acceptable
/// `permessage-deflate` offer (RFC 7692 §5.1: offers are in the client's
/// preference order). Malformed elements and offers this module cannot
/// honour are skipped, as are other extensions.
pub fn selectOffer(values: []const []const u8) ?Params {
    for (values) |v| {
        var it: ExtensionIterator = .{ .s = v };
        while (true) {
            const e = (it.next() catch continue) orelse break;
            if (!std.mem.eql(u8, e.name, extension_name)) continue;
            if (acceptableOffer(e)) return .{};
        }
    }
    return null;
}

/// Client side: check a server's `Sec-WebSocket-Extensions` values against
/// `offer_value` (RFC 7692 §7.1, RFC 6455 §4.1 point 5). Exactly one
/// element, `permessage-deflate`; `server_no_context_takeover` must be
/// there (§7.1.1.1: a server accepting an offer with it MUST echo it);
/// `client_no_context_takeover` and `server_max_window_bits` may be;
/// `client_max_window_bits` may not (it was not offered), nor may anything
/// else, nor any parameter twice. Returns null when there is no element at
/// all (the server declined), `error.Rejected` for anything else that is
/// not that.
pub fn verifyResponse(values: []const []const u8) error{Rejected}!?Params {
    var found: ?Params = null;
    for (values) |v| {
        var it: ExtensionIterator = .{ .s = v };
        while (it.next() catch return error.Rejected) |e| {
            if (found != null) return error.Rejected;
            if (!std.mem.eql(u8, e.name, extension_name)) return error.Rejected;
            var params: Params = .{};
            var seen: [3]bool = @splat(false);
            var pit = e.params();
            while (pit.next() catch return error.Rejected) |p| {
                const idx: usize = if (std.mem.eql(u8, p.name, "server_no_context_takeover"))
                    0
                else if (std.mem.eql(u8, p.name, "client_no_context_takeover"))
                    1
                else if (std.mem.eql(u8, p.name, "server_max_window_bits"))
                    2
                else
                    return error.Rejected;
                if (seen[idx]) return error.Rejected;
                seen[idx] = true;
                if (idx == 2) {
                    params.server_max_window_bits = windowBits(p.value orelse return error.Rejected) orelse return error.Rejected;
                } else if (p.value != null) return error.Rejected;
            }
            if (!seen[0]) return error.Rejected;
            found = params;
        }
    }
    return found;
}

// ── decompression (RFC 7692 §7.2.2) ─────────────────────────────────────────

/// What `inflate` appends after the peer's bytes: the `00 00 ff ff` the
/// sender removed (§7.2.2), then an empty FINAL stored block so that std's
/// decoder ends cleanly instead of asking for more input.
pub const inflate_tail = [_]u8{ 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0xff, 0xff };

pub const InflateError = error{
    /// The decompressed message does not fit `out` — the caller's message
    /// budget. Reported as soon as the output passes it, so a few bytes of
    /// input cannot make the decoder produce more than `out.len`. Close 1009.
    MessageTooLarge,
    /// Not a DEFLATE stream, a back-reference reaching before the start of
    /// the message (no context takeover), or bytes after a final block.
    /// Close 1007.
    InvalidCompressedData,
};

/// The decoder's sliding window: std's `flate.Decompress` decodes into it and
/// copies out. Used only during one `inflate` call and starting empty every
/// time, so one window serves any number of connections that never receive
/// at the same moment (one per thread, say).
pub const Window = [flate.max_window_len]u8;

/// The decoder's input: the message bytes, then zero bytes for as long as
/// the decoder asks. std 0.16's `flate.Decompress` must never reach the end
/// of its input: `tossBitsShort` checks `bufferedLen() * 8 + consumed_bits`
/// where it means `-`, so it can drop bits past the end, and the next
/// `peekBitsEnding` computes `left.len * 8 - consumed_bits` with
/// `left.len == 0` -- an integer-overflow panic in safe builds (found by
/// WEBSOCKET_FUZZ `inflate`, 2026-10-11, on a flipped compressed message).
/// With padding the end is never reached, so those paths never run; the
/// padding cannot make an invalid message pass (`inflate` refuses any
/// decode that consumed it), and it cannot keep the decoder busy: zero bits
/// end a fixed block at once, open a stored block whose LEN/NLEN (0/0)
/// mismatch, or decode symbols that each write output, which `out.len`
/// bounds.
const ZeroPadded = struct {
    reader: std.Io.Reader,
    /// Zero bytes handed out beyond the input.
    padded: usize = 0,

    const vtable: std.Io.Reader.VTable = .{
        .stream = stream,
        .readVec = readVec,
        .rebase = std.Io.Reader.defaultRebase,
    };

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *ZeroPadded = @fieldParentPtr("reader", r);
        const dest = limit.slice(try w.writableSliceGreedy(1));
        @memset(dest, 0);
        w.advance(dest.len);
        self.padded += dest.len;
        return dest.len;
    }

    fn readVec(r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
        _ = data; // allowed: fill `buffer` instead and return 0
        const self: *ZeroPadded = @fieldParentPtr("reader", r);
        if (r.end == r.buffer.len) {
            // Full: keep the unread bytes, at the front. Without this a
            // fully consumed buffer had no room, every call returned 0 with
            // nothing added, and the caller looped forever.
            const unread = r.buffer[r.seek..r.end];
            @memmove(r.buffer[0..unread.len], unread);
            r.seek = 0;
            r.end = unread.len;
        }
        const room = r.buffer[r.end..];
        @memset(room, 0);
        r.end += room.len;
        self.padded += room.len;
        return 0;
    }
};

/// Decompress one message. `buf[0..len]` holds the compressed payload as it
/// arrived (all fragments, concatenated); `buf` must have
/// `inflate_tail.len` bytes of room after it, which this overwrites. The
/// plain message goes to `out` and is returned as a prefix of it; `out.len`
/// is the cap, and a message of exactly that size fits.
///
/// An empty payload is an empty message (RFC 7692 §7.2.3.6 has the sender
/// put at least one `0x00` there; coder/websocket, read.go, accepts nothing
/// at all as the end of the message too).
///
/// RFC 7692 §7.2.3.4 lets a sender end the data with a final (`BFINAL`)
/// block instead of a sync flush; that is accepted, followed by nothing or
/// by the single `0x00` of the RFC's example. Any other peer bytes after a
/// final block are `error.InvalidCompressedData` (zlib and Go's flate stop
/// reading and ignore them; a payload whose bytes a decoder silently skips
/// is the kind two implementations disagree on).
pub fn inflate(buf: []u8, len: usize, out: []u8, window: *Window) InflateError![]u8 {
    std.debug.assert(buf.len >= len + inflate_tail.len);
    if (len == 0) return out[0..0];
    @memcpy(buf[len..][0..inflate_tail.len], &inflate_tail);
    const input = buf[0 .. len + inflate_tail.len];
    var in: ZeroPadded = .{ .reader = .{ .vtable = &ZeroPadded.vtable, .buffer = input, .seek = 0, .end = input.len } };
    var w: std.Io.Writer = .fixed(out);
    // The window starts empty, so a distance reaching before the start of
    // this message is `InvalidMatch` — the no-context-takeover rule.
    // Not std's direct mode (history read back out of `out` itself): there
    // every stored block, even an empty one, asks the writer for one free
    // byte, so a message that fills `out` exactly failed as too large.
    var d: flate.Decompress = .init(&in.reader, .raw, window);
    _ = d.reader.streamRemaining(&w) catch |err| switch (err) {
        error.WriteFailed => return error.MessageTooLarge,
        error.ReadFailed => return error.InvalidCompressedData,
    };
    // How much of `input` the decoder took. A decoder that needed the
    // padding ran past our final block: the peer's bytes swallowed it.
    const consumed = input.len + in.padded - (in.reader.end - in.reader.seek);
    if (consumed > input.len) return error.InvalidCompressedData;
    // Ours ends the stream with nothing unread. A final block of the peer's
    // own leaves part of our tail unread — fine, no peer byte was skipped —
    // plus, in RFC 7692 §7.2.3.4's own example (`f3 48 cd c9 c9 07 00 00`),
    // one more peer byte: the `0x00` that would have opened the empty
    // stored block. Any other peer byte left unread is refused.
    const unread = input.len - consumed;
    if (unread > inflate_tail.len) {
        if (unread != inflate_tail.len + 1 or input[len - 1] != 0x00) return error.InvalidCompressedData;
    }
    return w.buffered();
}

// ── compression (RFC 7692 §7.2.1) ───────────────────────────────────────────

/// Deflate state for the sending side, ~225 KiB (std's `flate.Compress` and
/// its 64 KiB window). Reset per message (no context takeover), so one can
/// be shared by connections that never write at the same time (a pool, a
/// per-thread instance). Never needs init or deinit.
pub const Compressor = struct {
    compress: flate.Compress,
    window: [flate.max_window_len]u8,

    /// Compress `payload` as one message into `out`. Returns the bytes to
    /// put on the wire (RFC 7692 §7.2.1: the DEFLATE data with its trailing
    /// `00 00 ff ff` removed), or null when they would not be shorter than
    /// `payload` or do not fit `out` — the caller then sends the message
    /// uncompressed (RSV1 clear), which §6 allows per message.
    ///
    /// The data is std's sync flush followed by one `0x00` byte: an empty
    /// stored block (`00 00 00 ff ff`) with its last four bytes removed.
    /// std's flush ends byte-aligned but not always with an empty stored
    /// block (it pads with empty fixed blocks when that is shorter), and
    /// telling the two apart from the output bytes alone is not reliable, so
    /// the block is always added: one byte, up to five when std's own flush
    /// already ended with one.
    pub fn compressMessage(c: *Compressor, payload: []const u8, out: []u8, level: u4) ?[]u8 {
        if (out.len <= 9) return null;
        // The last byte of `out` is kept for the closing 0x00.
        var w: std.Io.Writer = .fixed(out[0 .. out.len - 1]);
        http.gzip.initCompress(&c.compress, &w, &c.window, .raw, http.gzip.levelOptions(level)) catch return null;
        c.compress.writer.writeAll(payload) catch return null;
        c.compress.writer.flush() catch return null;
        const n = w.end;
        out[n] = 0x00;
        if (n + 1 >= payload.len) return null;
        return out[0 .. n + 1];
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

var test_window: Window = undefined;

fn inflateBytes(peer: []const u8, out: []u8) InflateError![]u8 {
    var buf: [256]u8 = undefined;
    @memcpy(buf[0..peer.len], peer);
    return inflate(&buf, peer.len, out, &test_window);
}

// RFC 7692 §7.2.3: every example payload that this mode can receive.
test "inflate: RFC 7692 7.2.3.1 one compressed block" {
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("Hello", try inflateBytes(&.{ 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00 }, &out));
}

test "inflate: RFC 7692 7.2.3.3 a block with no compression" {
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("Hello", try inflateBytes(&.{ 0x00, 0x05, 0x00, 0xfa, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00 }, &out));
}

test "inflate: RFC 7692 7.2.3.4 BFINAL block, its trailing 0x00 accepted, other trailing bytes refused" {
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("Hello", try inflateBytes(&.{ 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00 }, &out));
    // The final block alone, with nothing after it.
    try testing.expectEqualStrings("Hello", try inflateBytes(&.{ 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00 }, &out));
    // Peer bytes a decoder would silently skip.
    try testing.expectError(error.InvalidCompressedData, inflateBytes(&.{ 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00, 0x00 }, &out));
    try testing.expectError(error.InvalidCompressedData, inflateBytes(&.{ 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x41 }, &out));
}

test "inflate: RFC 7692 7.2.3.5 two blocks in one message" {
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("Hello", try inflateBytes(&.{ 0xf2, 0x48, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0xc9, 0xc9, 0x07, 0x00 }, &out));
}

test "inflate: RFC 7692 7.2.3.6 empty message" {
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("", try inflateBytes(&.{0x00}, &out));
    try testing.expectEqualStrings("", try inflateBytes(&.{}, &out));
}

test "inflate: RFC 7692 7.2.3.2 context-takeover payload is refused (no context takeover)" {
    // "Hello" again, by reference to the PREVIOUS message's window -- which
    // this mode never keeps, so the back-reference reaches before the start.
    var out: [64]u8 = undefined;
    try testing.expectError(error.InvalidCompressedData, inflateBytes(&.{ 0xf2, 0x00, 0x11, 0x00, 0x00 }, &out));
}

test "inflate: output is capped at out.len (decompression bomb), exact fit is fine" {
    const gpa = testing.allocator;
    const c = try gpa.create(Compressor);
    defer gpa.destroy(c);
    const plain = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(plain);
    @memset(plain, 'a');
    var comp: [8192]u8 = undefined;
    const z = c.compressMessage(plain, &comp, 6).?;
    try testing.expect(z.len < 4096); // ~1000:1 -- the shape of a bomb
    var buf: [8192 + inflate_tail.len]u8 = undefined;
    const small = try gpa.alloc(u8, 64 * 1024);
    defer gpa.free(small);
    @memcpy(buf[0..z.len], z);
    try testing.expectError(error.MessageTooLarge, inflate(&buf, z.len, small, &test_window));
    const exact = try gpa.alloc(u8, plain.len);
    defer gpa.free(exact);
    @memcpy(buf[0..z.len], z);
    try testing.expectEqualSlices(u8, plain, try inflate(&buf, z.len, exact, &test_window));
    // One byte short of the plain size is over the cap.
    @memcpy(buf[0..z.len], z);
    try testing.expectError(error.MessageTooLarge, inflate(&buf, z.len, exact[0 .. exact.len - 1], &test_window));
}

test "inflate: malformed DEFLATE is an error, never a crash" {
    var out: [64]u8 = undefined;
    for ([_][]const u8{
        &.{0x06}, // BTYPE 11: reserved
        &.{0x07},
        &.{ 0x00, 0x05, 0x00, 0x00, 0x00 }, // stored LEN/NLEN mismatch
        &.{ 0x00, 0x14, 0x00, 0xeb, 0xff, 0x48 }, // stored block of 20 cut short
        &.{0xff},
    }) |peer| try testing.expectError(error.InvalidCompressedData, inflateBytes(peer, &out));
    // A stored block of 5 holding one byte: the `00 00 ff ff` that §7.2.2
    // appends completes it, as it would in any decoder following the RFC.
    try testing.expectEqualSlices(u8, &.{ 'H', 0, 0, 0xff, 0xff }, try inflateBytes(&.{ 0x00, 0x05, 0x00, 0xfa, 0xff, 0x48 }, &out));
}

test "compressMessage: round trip over sizes and contents; null when not smaller" {
    const gpa = testing.allocator;
    const c = try gpa.create(Compressor);
    defer gpa.destroy(c);
    var prng: std.Random.DefaultPrng = .init(0x7692);
    const r = prng.random();
    var plain: [5000]u8 = undefined;
    var comp: [6000]u8 = undefined;
    var buf: [6000 + inflate_tail.len]u8 = undefined;
    var back: [5000]u8 = undefined;
    var compressed_any = false;
    for (0..300) |i| {
        const n = r.uintAtMost(usize, plain.len);
        // Half text-like (compressible), half random bytes (not).
        if (i % 2 == 0) {
            for (plain[0..n]) |*b| b.* = "abc{}\":, 0123"[r.uintLessThan(usize, 13)];
        } else r.bytes(plain[0..n]);
        const level: u4 = @intCast(1 + i % 9);
        if (c.compressMessage(plain[0..n], &comp, level)) |z| {
            compressed_any = true;
            try testing.expect(z.len < n);
            @memcpy(buf[0..z.len], z);
            try testing.expectEqualSlices(u8, plain[0..n], try inflate(&buf, z.len, &back, &test_window));
        } else if (i % 2 == 0 and n > 256) {
            return error.TestUnexpectedResult; // text this size always compresses
        }
    }
    try testing.expect(compressed_any);
    // Random bytes do not shrink: sent uncompressed.
    r.bytes(plain[0..1000]);
    try testing.expectEqual(@as(?[]u8, null), c.compressMessage(plain[0..1000], &comp, 6));
    // Output that does not fit `out` is not an error either.
    @memset(plain[0..1000], 'x');
    try testing.expectEqual(@as(?[]u8, null), c.compressMessage(plain[0..1000], comp[0..5], 6));
}

test "selectOffer: browser and library offers, declines, preference order" {
    // Chrome / Firefox send exactly this.
    try testing.expect(selectOffer(&.{"permessage-deflate; client_max_window_bits"}) != null);
    try testing.expect(selectOffer(&.{offer_value}) != null);
    try testing.expect(selectOffer(&.{"permessage-deflate; server_max_window_bits=15; client_max_window_bits=10"}) != null);
    try testing.expect(selectOffer(&.{"permessage-deflate; server_max_window_bits=\"15\""}) != null);
    try testing.expect(selectOffer(&.{"permessage-deflate"}) != null);
    // Declined: a window this compressor cannot honour, unknown or doubled
    // parameters, bad values.
    for ([_][]const u8{
        "permessage-deflate; server_max_window_bits=10",
        "permessage-deflate; server_max_window_bits",
        "permessage-deflate; client_max_window_bits=16",
        "permessage-deflate; client_max_window_bits=7",
        "permessage-deflate; client_max_window_bits=09",
        "permessage-deflate; server_no_context_takeover=1",
        "permessage-deflate; client_no_context_takeover; client_no_context_takeover",
        "permessage-deflate; x_unknown",
        "permessage-deflate; server_max_window_bits=\"1 5\"",
        "permessage-deflate; server_max_window_bits=\"15",
        "x-webkit-deflate-frame",
        "permessage-deflate;",
        "permessage-deflate x",
        "",
    }) |v| {
        if (selectOffer(&.{v}) != null) {
            std.debug.print("accepted: {s}\n", .{v});
            return error.TestUnexpectedResult;
        }
    }
    // A declined offer does not hide an acceptable one after it, in the
    // same line or a later one.
    try testing.expect(selectOffer(&.{"permessage-deflate; server_max_window_bits=10, permessage-deflate"}) != null);
    try testing.expect(selectOffer(&.{ "foo, permessage-deflate; x", "permessage-deflate; client_max_window_bits" }) != null);
    try testing.expect(selectOffer(&.{"bad\"quote, permessage-deflate"}) == null); // an open quote swallows the rest
}

test "verifyResponse: what a client accepts from a server" {
    const p = (try verifyResponse(&.{response_value})).?;
    try testing.expect(p.server_no_context_takeover and p.client_no_context_takeover);
    try testing.expectEqual(@as(u4, 15), p.server_max_window_bits);
    // coder/websocket's NoContextTakeover response order.
    _ = (try verifyResponse(&.{"permessage-deflate; client_no_context_takeover; server_no_context_takeover"})).?;
    try testing.expectEqual(@as(u4, 10), (try verifyResponse(&.{"permessage-deflate; server_no_context_takeover; server_max_window_bits=10"})).?.server_max_window_bits);
    try testing.expectEqual(@as(?Params, null), try verifyResponse(&.{}));
    for ([_][]const []const u8{
        &.{"permessage-deflate"}, // server_no_context_takeover was offered and MUST be echoed
        &.{"permessage-deflate; client_no_context_takeover"},
        &.{"permessage-deflate; server_no_context_takeover; client_max_window_bits=10"}, // not offered
        &.{"permessage-deflate; server_no_context_takeover; server_no_context_takeover"},
        &.{"permessage-deflate; server_no_context_takeover; server_max_window_bits=16"},
        &.{"permessage-deflate; server_no_context_takeover; x"},
        &.{"x-webkit-deflate-frame"},
        &.{ response_value, response_value }, // two acceptances
        &.{response_value ++ ", " ++ response_value},
        &.{"permessage-deflate; server_no_context_takeover; \""},
    }) |v| try testing.expectError(error.Rejected, verifyResponse(v));
}

// ── fuzz (WEBSOCKET_FUZZ: extensions, inflate, deflate-connection) ────────

const fz = @import("fuzz_test.zig");
const fuzz_driver = @import("testkit").fuzz.driver;
const connection = @import("connection.zig");
const frame = @import("frame.zig");

const extension_seeds = [_][]const u8{
    offer_value,
    response_value,
    "permessage-deflate; client_max_window_bits",
    "permessage-deflate; server_max_window_bits=\"15\"; client_max_window_bits=10",
    "permessage-deflate; server_no_context_takeover; server_max_window_bits=10",
    "x-foo, permessage-deflate; server_max_window_bits=9, permessage-deflate",
    "permessage-deflate; client_no_context_takeover; client_no_context_takeover",
};

/// One seed header value with a few octets flipped, then both sides of the
/// negotiation over it (split at a drawn point into two field lines).
/// Oracle: whatever the server accepts, it accepts as no-context-takeover,
/// and a client that accepted a response saw `server_no_context_takeover`.
fn extensionsHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    const text = extension_seeds[src.index(extension_seeds.len)];
    var buf: [128]u8 = undefined;
    @memcpy(buf[0..text.len], text);
    const flips = src.valueRangeAtMost(u8, 0, 3);
    for (0..flips) |_| buf[src.index(text.len)] ^= src.value(u8);
    const cut = src.valueRangeAtMost(u8, 0, @intCast(text.len));
    const lines = [_][]const u8{ buf[0..cut], buf[cut..text.len] };
    if (selectOffer(&lines)) |p| {
        fz.mark(.ext_offer_accepted);
        if (!p.server_no_context_takeover or !p.client_no_context_takeover) return error.OfferNotNoContextTakeover;
    } else fz.mark(.ext_offer_declined);
    if (verifyResponse(&lines)) |maybe| {
        fz.mark(.ext_response_accepted);
        if (maybe) |p| if (p.server_max_window_bits < 8) return error.WindowBitsOutOfRange;
    } else |_| fz.mark(.ext_response_rejected);
}

/// A message compressed by `Compressor`, then a few octets flipped (or none),
/// inflated into a drawn-size buffer. Oracle: unflipped, it must come back
/// byte for byte (or be `MessageTooLarge` exactly when it does not fit);
/// flipped, any outcome but a crash, and never more than `out.len` bytes.
fn inflateHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const c = try gpa.create(Compressor);
    defer gpa.destroy(c);
    const window = try gpa.create(Window);
    defer gpa.destroy(window);
    var plain: [600]u8 = undefined;
    const n = src.valueRangeAtMost(u16, 0, plain.len);
    const alphabet = src.valueRangeAtMost(u8, 1, 255);
    for (plain[0..n]) |*b| b.* = src.valueRangeAtMost(u8, 0, alphabet);
    var comp: [700]u8 = undefined;
    const z = c.compressMessage(plain[0..n], &comp, @intCast(src.valueRangeAtMost(u8, 1, 9))) orelse return;
    var buf: [700 + inflate_tail.len]u8 = undefined;
    @memcpy(buf[0..z.len], z);
    const flips = src.valueRangeAtMost(u8, 0, 2);
    for (0..flips) |_| buf[src.index(z.len)] ^= src.value(u8);
    var out: [600]u8 = undefined;
    const cap = src.valueRangeAtMost(u16, 0, out.len);
    const got = inflate(&buf, z.len, out[0..cap], window) catch |err| switch (err) {
        error.MessageTooLarge => {
            fz.mark(.inflate_too_large);
            if (flips == 0 and n <= cap) return error.FitButRefused;
            return;
        },
        error.InvalidCompressedData => {
            fz.mark(.inflate_invalid);
            if (flips == 0) return error.OwnOutputRefused;
            return;
        },
    };
    fz.mark(.inflate_ok);
    if (got.len > cap) return error.OverCap;
    if (flips == 0 and !std.mem.eql(u8, got, plain[0..n])) return error.RoundTripMismatch;
}

/// Server-role `Connection` with deflate on, fed masked frames built from a
/// compressed message (split into a drawn number of fragments, RSV1 on a
/// drawn frame, a control frame maybe in between), then a few octets
/// flipped. Oracle: unflipped and well-formed, the message comes back.
fn deflateConnectionHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const c = try gpa.create(Compressor);
    defer gpa.destroy(c);
    const window = try gpa.create(Window);
    defer gpa.destroy(window);
    var plain: [300]u8 = undefined;
    const n = src.valueRangeAtMost(u16, 0, plain.len);
    for (plain[0..n]) |*b| b.* = "ab{}\": 01\xc3\xa9"[src.index(12)];
    var comp: [400]u8 = undefined;
    const z = c.compressMessage(plain[0..n], &comp, 1) orelse return;

    var wire: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wire);
    const key: [4]u8 = .{ src.value(u8), src.value(u8), src.value(u8), src.value(u8) };
    const parts = src.valueRangeAtMost(u8, 1, 4);
    const rsv1_on: u8 = src.valueRangeAtMost(u8, 0, parts); // == parts: on none -- refused or garbage
    const opcode: frame.Opcode = if (src.value(bool)) .text else .binary;
    var at: usize = 0;
    for (0..parts) |i| {
        const end = if (i + 1 == parts) z.len else @min(z.len, at + src.valueRangeAtMost(u16, 0, @intCast(z.len)));
        try frame.writeFrame(&w, .{
            .fin = i + 1 == parts,
            .opcode = if (i == 0) opcode else .continuation,
            .payload = z[at..end],
            .mask_key = key,
            .compressed = i == rsv1_on and i == 0,
        });
        // A non-first frame with RSV1: written by hand, writeFrame refuses it.
        if (i == rsv1_on and i != 0) wire[w.end - (end - at) - 4 - (if (end - at > 125) @as(usize, 2) else 0) - 2] |= 0x40;
        at = end;
        if (src.value(bool)) try frame.writeFrame(&w, .{ .opcode = .ping, .payload = "p", .mask_key = key });
    }
    const flips = src.valueRangeAtMost(u8, 0, 2);
    for (0..flips) |_| wire[src.index(w.end)] ^= src.value(u8);

    var msg: [256]u8 = undefined;
    var cbuf: [200]u8 = undefined;
    var conn: connection.Connection = .init(.server, &msg, 1 << 16);
    conn.enableDeflate(&cbuf, window);
    var off: usize = 0;
    var got: ?[]const u8 = null;
    var iterations: usize = 0;
    while (off < w.end and iterations < 16) : (iterations += 1) {
        const r = conn.receive(wire[off..w.end]) catch {
            fz.mark(.deflate_conn_refused);
            if (flips == 0 and rsv1_on == 0 and n <= msg.len and z.len + inflate_tail.len <= cbuf.len and (opcode == .binary or std.unicode.utf8ValidateSlice(plain[0..n])))
                return error.ValidMessageRefused;
            return;
        };
        if (r.event == .need_more) return;
        if (r.event == .message) {
            got = r.event.message.payload;
            fz.mark(.deflate_conn_message);
        }
        off += r.consumed;
    }
    if (flips == 0 and rsv1_on == 0) {
        if (got) |g| if (!std.mem.eql(u8, g, plain[0..n])) return error.RoundTripMismatch;
    }
}

// One test per harness: `run` returns `SkipZigTest` when `_ONLY` names
// another harness, and a `try` on it would skip the ones after it too.
test "fuzz driver: WEBSOCKET_FUZZ (extensions)" {
    try fuzz_driver.run(extensionsHarness, .{ .prefix = "WEBSOCKET_FUZZ", .name = "extensions" });
}

test "fuzz driver: WEBSOCKET_FUZZ (inflate)" {
    try fuzz_driver.run(inflateHarness, .{ .prefix = "WEBSOCKET_FUZZ", .name = "inflate" });
}

test "fuzz driver: WEBSOCKET_FUZZ (deflate-connection)" {
    try fuzz_driver.run(deflateConnectionHarness, .{ .prefix = "WEBSOCKET_FUZZ", .name = "deflate-connection" });
}

test "fuzz harnesses: 500 seeds each in every test run, and the deflate paths get everywhere" {
    fz.resetReach();
    inline for (.{ extensionsHarness, inflateHarness, deflateConnectionHarness }, .{ "extensions", "inflate", "deflate-connection" }) |h, name| {
        for (0..500) |sd| {
            var prng = std.Random.DefaultPrng.init(sd);
            var rng: fuzz_driver.Rng = .{ .r = prng.random() };
            h(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                std.debug.print("websocket {s} seed {d}: {t}\n", .{ name, sd, err });
                return err;
            };
        }
    }
    try fz.expectReached(&.{
        .ext_offer_accepted,   .ext_offer_declined, .ext_response_accepted, .ext_response_rejected,
        .inflate_ok,           .inflate_too_large,  .inflate_invalid,       .deflate_conn_message,
        .deflate_conn_refused,
    });
}
