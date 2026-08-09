// SPDX-License-Identifier: MIT

//! A small per-connection state machine on top of `frame`: reassembles a
//! fragmented message (§5.4), tracks the close handshake (§7.1.1/§5.5.1),
//! and enforces an aggregate max-message-size cap (§5.4 doesn't bound
//! this — a fragmented message can otherwise grow unboundedly even with
//! every individual frame under `max_frame_size`).
//!
//! `Connection` owns no I/O: `receive` is fed the caller's read buffer
//! (same streaming `.need_more` contract as `frame.parseFrame`) and
//! returns an `Event` describing what happened; writing replies (pong,
//! close) is the caller's job via `frame.writeFrame` — `frame.pongFor`
//! and `frame.encodeCloseBody` are the matching helpers.

const std = @import("std");
const frame = @import("frame.zig");

pub const Connection = struct {
    role: frame.Role,
    /// Per-frame payload cap, forwarded to `frame.parseFrame` (close 1009).
    max_frame_size: u64,
    /// Reassembly scratch space, caller-owned. Its length *is* the
    /// aggregate max-message-size cap: a fragmented (or oversized single-
    /// frame) message that would not fit triggers `error.MessageTooLarge`
    /// (close 1009).
    message_buf: []u8,
    message_len: usize = 0,
    /// Non-null while a fragmented text/binary message is in progress —
    /// the opcode of the frame that started it (continuation frames don't
    /// carry it). Control frames may still interleave freely while this
    /// is set (§5.4): `receive` dispatches control opcodes before
    /// touching fragmentation state.
    fragment_opcode: ?frame.Opcode = null,
    /// This side has sent a close frame.
    close_sent: bool = false,
    /// This side has received a close frame.
    close_received: bool = false,

    pub fn init(role: frame.Role, message_buf: []u8, max_frame_size: u64) Connection {
        return .{ .role = role, .max_frame_size = max_frame_size, .message_buf = message_buf };
    }

    pub const Message = struct { opcode: frame.Opcode, payload: []const u8 };

    pub const Event = union(enum) {
        /// `buf` did not contain a complete frame; read more and retry.
        need_more,
        /// A non-final fragment was consumed; no message is ready yet.
        frame_consumed,
        /// A complete text or binary message (single-frame or reassembled
        /// from fragments). `payload` borrows either the input `buf`
        /// (single-frame case) or `message_buf` (reassembled case) —
        /// valid until the next `receive` call.
        message: Message,
        /// A ping was received; reply with `frame.pongFor(payload, ..)`.
        ping: []const u8,
        /// A pong was received (a reply to a ping, or unsolicited).
        pong: []const u8,
        /// A close frame was received (§5.5.1); `Connection.close_received`
        /// is now true. Reply with a close frame (echoing the code is
        /// conventional) to complete the closing handshake, then close
        /// the transport once `bothClosed()` is true.
        close: frame.CloseInfo,
    };

    pub const Result = struct { event: Event, consumed: usize };

    /// `frame.FrameError` plus the two errors only a multi-frame `Connection`
    /// can detect: an aggregate message over the `message_buf` cap, and an
    /// invalid frame sequence (a continuation with nothing to continue, or a
    /// new data frame starting before the previous one finished). Every
    /// variant maps to a close code via `frame.closeCode`.
    pub const Error = frame.FrameError || error{
        /// Reassembled (or single-frame) message exceeds `message_buf.len`.
        /// Close 1009.
        MessageTooLarge,
        /// A continuation frame with no message in progress, or a new
        /// text/binary frame while one is already in progress (§5.4).
        /// Close 1002.
        InvalidFragmentation,
        /// The complete text message (or the close reason) is not valid
        /// UTF-8 (§5.6/§5.5.1). Close 1007.
        InvalidUtf8,
        /// W2-A8/websocket-F3: a data frame (text/binary/continuation)
        /// arrived after a close frame was already received. RFC 6455 §1.4:
        /// "after receiving a control frame indicating the connection
        /// should be closed, a peer discards any further data received."
        /// Close 1002.
        DataAfterClose,
    };

    /// Feed the next available bytes. Consumes at most one frame per call
    /// (mirrors `frame.parseFrame`); loop, advancing by `consumed`, until
    /// `.need_more`.
    pub fn receive(self: *Connection, buf: []u8) Error!Result {
        const parsed = switch (try frame.parseFrame(buf, self.role, self.max_frame_size)) {
            .need_more => return .{ .event = .need_more, .consumed = 0 },
            .frame => |f| f,
        };

        if (parsed.opcode.isControl()) {
            return switch (parsed.opcode) {
                .close => blk: {
                    self.close_received = true;
                    const info = try frame.decodeCloseBody(parsed.payload);
                    break :blk .{ .event = .{ .close = info }, .consumed = parsed.consumed };
                },
                .ping => .{ .event = .{ .ping = parsed.payload }, .consumed = parsed.consumed },
                .pong => .{ .event = .{ .pong = parsed.payload }, .consumed = parsed.consumed },
                else => unreachable,
            };
        }

        // W2-A8/websocket-F3: `close_received` existed but `receive` never
        // consulted it — a data frame arriving after the peer's close frame
        // was silently delivered as an ordinary message. RFC 6455 §1.4
        // requires discarding it instead. Checked once, after control-frame
        // dispatch (a peer's own close/ping/pong in response is unaffected)
        // and before the fragmentation-state machine runs, so a stray data
        // frame post-close can never start or continue a reassembly.
        if (self.close_received) return error.DataAfterClose;

        switch (parsed.opcode) {
            .continuation => {
                const start_opcode = self.fragment_opcode orelse return error.InvalidFragmentation;
                try self.appendFragment(parsed.payload);
                if (!parsed.fin) return .{ .event = .frame_consumed, .consumed = parsed.consumed };

                self.fragment_opcode = null;
                const payload = self.message_buf[0..self.message_len];
                if (start_opcode == .text and !std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
                return .{ .event = .{ .message = .{ .opcode = start_opcode, .payload = payload } }, .consumed = parsed.consumed };
            },
            .text, .binary => {
                if (self.fragment_opcode != null) return error.InvalidFragmentation;
                if (parsed.fin) {
                    // The cap is the caller's memory budget, so it has to apply
                    // to a one-frame message too — the doc comment on
                    // `message_buf` says so, and before this check the only
                    // bound on an unfragmented message was `max_frame_size`.
                    // The payload is still returned borrowed from `buf` (no
                    // copy into `message_buf`); the buffer's *length* is what
                    // is being honoured here, not its storage.
                    if (parsed.payload.len > self.message_buf.len) return error.MessageTooLarge;
                    if (parsed.opcode == .text and !std.unicode.utf8ValidateSlice(parsed.payload))
                        return error.InvalidUtf8;
                    return .{ .event = .{ .message = .{ .opcode = parsed.opcode, .payload = parsed.payload } }, .consumed = parsed.consumed };
                }
                self.fragment_opcode = parsed.opcode;
                self.message_len = 0;
                try self.appendFragment(parsed.payload);
                return .{ .event = .frame_consumed, .consumed = parsed.consumed };
            },
            else => unreachable, // control opcodes handled above
        }
    }

    fn appendFragment(self: *Connection, payload: []const u8) Error!void {
        if (self.message_len + payload.len > self.message_buf.len) return error.MessageTooLarge;
        @memcpy(self.message_buf[self.message_len..][0..payload.len], payload);
        self.message_len += payload.len;
    }

    /// The closing handshake (§7.1.1) is done on both sides — the
    /// transport may now be closed.
    pub fn bothClosed(self: *const Connection) bool {
        return self.close_sent and self.close_received;
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn unmaskedFrame(comptime opcode_byte: u8, payload: []const u8, comptime buf_len: usize) [buf_len]u8 {
    var out: [buf_len]u8 = undefined;
    out[0] = opcode_byte;
    out[1] = @intCast(payload.len);
    @memcpy(out[2..], payload);
    return out;
}

test "reassembles a fragmented text message (RFC 5.7 'Hel'+'lo')" {
    var scratch: [64]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);

    var wire1 = [_]u8{ 0x01, 0x03, 'H', 'e', 'l' }; // text, fin=0
    const r1 = try conn.receive(&wire1);
    try testing.expectEqual(Connection.Event.frame_consumed, r1.event);

    var wire2 = [_]u8{ 0x80, 0x02, 'l', 'o' }; // continuation, fin=1
    const r2 = try conn.receive(&wire2);
    switch (r2.event) {
        .message => |m| {
            try testing.expectEqual(frame.Opcode.text, m.opcode);
            try testing.expectEqualStrings("Hello", m.payload);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "a UTF-8 codepoint split across fragment boundaries validates correctly" {
    // "A€B" where '€' = 0xE2 0x82 0xAC, split mid-codepoint across two frames.
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);

    var wire1 = [_]u8{ 0x01, 0x02, 'A', 0xE2 }; // text, fin=0, "A" + first byte of €
    try testing.expectEqual(Connection.Event.frame_consumed, (try conn.receive(&wire1)).event);

    // continuation, fin=1: remaining 2 bytes of '€' + "B"
    var wire2 = [_]u8{ 0x80, 0x03, 0x82, 0xAC, 'B' };
    const r2 = try conn.receive(&wire2);
    switch (r2.event) {
        .message => |m| try testing.expectEqualStrings("A€B", m.payload),
        else => return error.TestUnexpectedResult,
    }
}

// External anchor (F5, 2026-08-08): the real `Autobahn|Testsuite` run this
// finding asks for is unobtainable on this host — `wstest` is a Python-2-era
// package broken under Python 3 (`from _version import __version__`, an
// implicit relative import Python 3 removed; confirmed by running it, see
// SPEC.md "External-anchor investigation"). But the suite's §6 UTF-8 cases
// are *data*, not runner logic: `autobahntestsuite/case/case6_x_x.py`
// (installed locally, readable even though the package cannot be imported)
// embeds Markus Kuhn's UTF-8 decoder stress test verbatim
// (http://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt) as
// `(is_valid, byte_string)` pairs. That corpus predates this module, RFC
// 6455 and this repository, and is not something "our reading of RFC 6455"
// would reproduce — RFC 6455 §5.6 only says a text payload must be valid
// UTF-8 per RFC 3629; it does not enumerate overlong encodings, lonely
// continuation bytes or surrogate halves. This is therefore the genuine
// external anchor F5 asked for, obtained without running the dead suite.
//
// A representative subset (every category Kuhn's file distinguishes:
// boundary conditions, unexpected continuation bytes, lonely start bytes,
// truncated sequences, overlong encodings of three different code points,
// UTF-16 surrogate halves and pairs, and the non-character code points that
// RFC 3629 permits) is transcribed below, each wrapped in a real single-frame
// unmasked text message and fed through `Connection.receive` — the same
// code path (`std.unicode.utf8ValidateSlice` at connection.zig:131/145) a
// live Autobahn run would have exercised.
const Utf8Vector = struct { bytes: []const u8, valid: bool, label: []const u8 };
const kuhn_utf8_vectors = [_]Utf8Vector{
    // 1 — some correct UTF-8 text.
    .{ .bytes = "hello\x24world", .valid = true, .label = "1: U+0024" },
    .{ .bytes = "hello\xC2\xA2world", .valid = true, .label = "1: U+00A2" },
    .{ .bytes = "hello\xE2\x82\xACworld", .valid = true, .label = "1: U+20AC" },
    .{ .bytes = "hello\xF0\xA4\xAD\xA2world", .valid = true, .label = "1: U+24B62" },
    .{ .bytes = "\xCE\xBA\xE1\xBD\xB9\xCF\x83\xCE\xBC\xCE\xB5", .valid = true, .label = "1: kosme" },
    // 2.1 — first possible sequence of a certain length.
    .{ .bytes = "\x00", .valid = true, .label = "2.1: 1-byte min" },
    .{ .bytes = "\xC2\x80", .valid = true, .label = "2.1: 2-byte min" },
    .{ .bytes = "\xE0\xA0\x80", .valid = true, .label = "2.1: 3-byte min" },
    .{ .bytes = "\xF0\x90\x80\x80", .valid = true, .label = "2.1: 4-byte min" },
    .{ .bytes = "\xF8\x88\x80\x80\x80", .valid = false, .label = "2.1: 5-byte (never valid)" },
    .{ .bytes = "\xFC\x84\x80\x80\x80\x80", .valid = false, .label = "2.1: 6-byte (never valid)" },
    // 2.2 — last possible sequence of a certain length.
    .{ .bytes = "\x7F", .valid = true, .label = "2.2: 1-byte max" },
    .{ .bytes = "\xDF\xBF", .valid = true, .label = "2.2: 2-byte max" },
    .{ .bytes = "\xEF\xBF\xBF", .valid = true, .label = "2.2: 3-byte max" },
    .{ .bytes = "\xF4\x8F\xBF\xBF", .valid = true, .label = "2.2: 4-byte max (U+10FFFF)" },
    .{ .bytes = "\xF7\xBF\xBF\xBF", .valid = false, .label = "2.2: 4-byte (never valid)" },
    // 2.3 — other boundary conditions.
    .{ .bytes = "\xED\x9F\xBF", .valid = true, .label = "2.3: U+D7FF (just below surrogates)" },
    .{ .bytes = "\xEE\x80\x80", .valid = true, .label = "2.3: U+E000 (just above surrogates)" },
    .{ .bytes = "\xF4\x90\x80\x80", .valid = false, .label = "2.3: U+110000 (just past max)" },
    // 3.1 — unexpected continuation bytes.
    .{ .bytes = "\x80", .valid = false, .label = "3.1: lone continuation 0x80" },
    .{ .bytes = "\xBF", .valid = false, .label = "3.1: lone continuation 0xBF" },
    .{ .bytes = "\x80\xBF\x80\xBF", .valid = false, .label = "3.1: four lone continuations" },
    // 3.2 — lonely start characters.
    .{ .bytes = "\xC0 \xDF ", .valid = false, .label = "3.2: lonely 2-byte starts" },
    .{ .bytes = "\xE0 \xEF ", .valid = false, .label = "3.2: lonely 3-byte starts" },
    .{ .bytes = "\xF0 \xF7 ", .valid = false, .label = "3.2: lonely 4-byte starts" },
    // 3.3 — sequences with the last continuation byte missing.
    .{ .bytes = "\xC0", .valid = false, .label = "3.3: truncated 2-byte" },
    .{ .bytes = "\xE0\x80", .valid = false, .label = "3.3: truncated 3-byte" },
    .{ .bytes = "\xF0\x80\x80", .valid = false, .label = "3.3: truncated 4-byte" },
    .{ .bytes = "\xDF", .valid = false, .label = "3.3: truncated 2-byte (max lead)" },
    .{ .bytes = "\xEF\xBF", .valid = false, .label = "3.3: truncated 3-byte (max lead)" },
    // 3.5 — impossible bytes.
    .{ .bytes = "\xFE", .valid = false, .label = "3.5: impossible byte 0xFE" },
    .{ .bytes = "\xFF", .valid = false, .label = "3.5: impossible byte 0xFF" },
    .{ .bytes = "\xFE\xFE\xFF\xFF", .valid = false, .label = "3.5: impossible bytes run" },
    // 4.1/4.2/4.3 — overlong encodings of '/' (U+002F), U+0000 and the
    // largest overlong 2-byte form.
    .{ .bytes = "\xC0\xAF", .valid = false, .label = "4.1: overlong '/' (2-byte)" },
    .{ .bytes = "\xE0\x80\xAF", .valid = false, .label = "4.1: overlong '/' (3-byte)" },
    .{ .bytes = "\xF0\x80\x80\xAF", .valid = false, .label = "4.1: overlong '/' (4-byte)" },
    .{ .bytes = "\xC1\xBF", .valid = false, .label = "4.2: maximum overlong 2-byte" },
    .{ .bytes = "\xE0\x9F\xBF", .valid = false, .label = "4.2: maximum overlong 3-byte" },
    .{ .bytes = "\xC0\x80", .valid = false, .label = "4.3: overlong NUL (2-byte)" },
    .{ .bytes = "\xE0\x80\x80", .valid = false, .label = "4.3: overlong NUL (3-byte)" },
    .{ .bytes = "\xF0\x80\x80\x80", .valid = false, .label = "4.3: overlong NUL (4-byte)" },
    // 5.1 — single UTF-16 surrogates (never valid UTF-8).
    .{ .bytes = "\xED\xA0\x80", .valid = false, .label = "5.1: high surrogate D800" },
    .{ .bytes = "\xED\xAD\xBF", .valid = false, .label = "5.1: high surrogate DB7F" },
    .{ .bytes = "\xED\xB0\x80", .valid = false, .label = "5.1: low surrogate DC00" },
    .{ .bytes = "\xED\xBF\xBF", .valid = false, .label = "5.1: low surrogate DFFF" },
    // 5.2 — paired UTF-16 surrogates (still never valid UTF-8).
    .{ .bytes = "\xED\xA0\x80\xED\xB0\x80", .valid = false, .label = "5.2: paired surrogates" },
    // 5.3 — non-character code points: illegal in some interpretations but
    // *valid* UTF-8 per RFC 3629 — the positive control against a validator
    // that over-rejects the FFFE/FFFF range.
    .{ .bytes = "\xEF\xBF\xBE", .valid = true, .label = "5.3: U+FFFE (non-char, valid UTF-8)" },
    .{ .bytes = "\xEF\xBF\xBF", .valid = true, .label = "5.3: U+FFFF (non-char, valid UTF-8)" },
    .{ .bytes = "\xEF\xBF\xBD", .valid = true, .label = "5.3: U+FFFD (replacement char)" },
};

test "external anchor: Autobahn|Testsuite's frozen UTF-8 stress-test corpus (Markus Kuhn, frozen 2026-08-08)" {
    var scratch: [32]u8 = undefined;
    for (kuhn_utf8_vectors) |v| {
        std.debug.assert(v.bytes.len < 126); // every vector fits the 7-bit length form
        var wire_buf: [2 + 32]u8 = undefined;
        wire_buf[0] = 0x81; // FIN=1, opcode=text
        wire_buf[1] = @intCast(v.bytes.len); // unmasked, 7-bit length
        @memcpy(wire_buf[2..][0..v.bytes.len], v.bytes);
        var conn: Connection = .init(.client, &scratch, 1 << 20);
        const result = conn.receive(wire_buf[0 .. 2 + v.bytes.len]);
        if (v.valid) {
            const r = result catch |e| {
                std.debug.print("expected VALID ({s}) but got {t}\n", .{ v.label, e });
                return e;
            };
            switch (r.event) {
                .message => |m| try testing.expectEqualSlices(u8, v.bytes, m.payload),
                else => return error.TestUnexpectedResult,
            }
        } else {
            testing.expectError(error.InvalidUtf8, result) catch |e| {
                std.debug.print("expected INVALID ({s}) but validation accepted it\n", .{v.label});
                return e;
            };
        }
    }
}

// ── external anchor: three foreign WebSocket implementations, executed ──────
//
// F5 asked for an `Autobahn|Testsuite` result. `wstest` is dead on this host
// (Python-2-era package, see SPEC.md "External-anchor investigation"), and its
// §7.9 close-code *case data* was deliberately refused as a freeze target
// because it is only RFC 6455 §7.4.1 restated in Python — our own reading of
// the spec wearing someone else's name. That refusal stands.
//
// What replaces it is not a suite but three real peers, **run**, not read:
//
//   * python-websockets 15.0.1 (BSD-3-Clause) — its sans-io `ServerProtocol`
//     state machine, driven directly with the bytes below;
//   * github.com/coder/websocket v1.8.15 (ISC) — a real server on loopback;
//   * github.com/gorilla/websocket v1.5.3 (BSD-2-Clause) — likewise.
//
// Each `wire` field is the exact masked client→server byte string that was put
// in front of all three (mask key `37 fa 21 3d`, the RFC 6455 §5.7 key), and
// each `peers` field records what they actually did with it — for the two Go
// servers, decoded from the close frame they wrote back onto the socket. The
// distinction from the refused §7.9 case data is the whole point: nobody's
// source was transcribed, three independently-authored implementations were
// executed and their behaviour recorded. It is an oracle that can disagree
// with us, and on its first run it did — see `close_code_1012`/`1013`.
//
// Frozen 2026-08-09 by ~/.cache/zig-libs-websocket/{cases,oracle_python,
// emit_zig}.py + a Go harness. These tests run offline and never skip; all
// three implementations can be deleted and nothing here changes. Licences are
// all permissive and nothing is copied, translated or redistributed from any
// of them — what is frozen is observed numeric behaviour on a public wire
// format, which is not a copyrightable expression of theirs.
//
// Verdicts:
//   .accept      all three accepted; this module must too.
//   .reject      all three rejected; this module must too, with `close_code`
//                when they agreed on one.
//   .divergence  all three accepted, this module deliberately rejects. Two
//                independent causes, both of them findings in their own right:
//                (a) RFC 6455 §5.2's minimal-length-encoding MUST ("the
//                minimal number of bytes MUST be used to encode the length"),
//                which none of the three enforces — a 126/127 form carrying a
//                value the shorter form could hold sails through all of them;
//                (b) RFC 6455 §8.1's MUST to fail a text message that is not
//                valid UTF-8 with close 1007 — none of the three validates
//                UTF-8 on receive, which is precisely why Autobahn's §6
//                section exists and why the Kuhn corpus above is carrying
//                that half of the anchor rather than these peers. Pinned so
//                the choice cannot drift silently.
//   .split       the three disagreed with each other, so there is no foreign
//                verdict to assert against — manufacturing a majority here
//                would be inventing an anchor that does not exist. Their
//                three answers are kept in `peers`, and `ours_rejects` /
//                `close_code` pin *this module's* answer so the choice made
//                in the presence of a genuine disagreement cannot drift
//                silently either.
const ForeignVerdict = enum { accept, reject, divergence, split };
const ForeignCase = struct {
    label: []const u8,
    wire: []const u8,
    verdict: ForeignVerdict,
    /// For `.reject`/`.divergence`: the close code the peers agreed on, if
    /// they agreed on one. For `.split`: the close code *this module*
    /// produces. Unused for `.accept`.
    close_code: ?u16,
    /// `.split` only: whether this module rejects these bytes.
    ours_rejects: bool = false,
    peers: []const u8,
};

const foreign_peer_corpus = [_]ForeignCase{
    .{ .label = "valid_text_hello", .wire = "\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "valid_ping_hello", .wire = "\x89\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "valid_pong_hello", .wire = "\x8a\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "valid_text_125", .wire = "\x81\xfd\x37\xfa\x21\x3d" ++ ("\x56\x9b\x40\x5c" ** 31) ++ "\x56", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "valid_text_126_16bit", .wire = "\x81\xfe\x00\x7e\x37\xfa\x21\x3d" ++ ("\x56\x9b\x40\x5c" ** 31) ++ "\x56\x9b", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "valid_text_empty", .wire = "\x81\x80\x37\xfa\x21\x3d", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "valid_ctrl_125", .wire = "\x89\xfd\x37\xfa\x21\x3d" ++ ("\x56\x9b\x40\x5c" ** 31) ++ "\x56", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "valid_close_1000", .wire = "\x88\x82\x37\xfa\x21\x3d\x34\x12", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT/1000 gorilla=ACCEPT/1000" },
    .{ .label = "valid_close_1000_reason", .wire = "\x88\x85\x37\xfa\x21\x3d\x34\x12\x43\x44\x52", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT/1000 gorilla=ACCEPT/1000" },
    .{ .label = "valid_close_empty", .wire = "\x88\x80\x37\xfa\x21\x3d", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "valid_close_1001", .wire = "\x88\x82\x37\xfa\x21\x3d\x34\x13", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT/1001 gorilla=ACCEPT/1001" },
    .{ .label = "valid_close_1003", .wire = "\x88\x82\x37\xfa\x21\x3d\x34\x11", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT/1003 gorilla=ACCEPT/1003" },
    .{ .label = "valid_close_1007", .wire = "\x88\x82\x37\xfa\x21\x3d\x34\x15", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT/1007 gorilla=ACCEPT/1007" },
    .{ .label = "valid_close_1011", .wire = "\x88\x82\x37\xfa\x21\x3d\x34\x09", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT/1011 gorilla=ACCEPT/1011" },
    .{ .label = "valid_close_3000", .wire = "\x88\x82\x37\xfa\x21\x3d\x3c\x42", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT/3000 gorilla=ACCEPT/3000" },
    .{ .label = "valid_close_4999", .wire = "\x88\x82\x37\xfa\x21\x3d\x24\x7d", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT/4999 gorilla=ACCEPT/4999" },
    .{ .label = "valid_utf8_2byte", .wire = "\x81\x82\x37\xfa\x21\x3d\xf4\x53", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "valid_utf8_4byte", .wire = "\x81\x84\x37\xfa\x21\x3d\xc7\x65\xb3\x94", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "rsv1_set", .wire = "\xc1\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "rsv2_set", .wire = "\xa1\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "rsv3_set", .wire = "\x91\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "opcode_0x3_reserved", .wire = "\x83\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "opcode_0x7_reserved", .wire = "\x87\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "opcode_0xB_reserved", .wire = "\x8b\x80\x37\xfa\x21\x3d", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "opcode_0xF_reserved", .wire = "\x8f\x80\x37\xfa\x21\x3d", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "fragmented_ping", .wire = "\x09\x81\x37\xfa\x21\x3d\x4f", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "fragmented_close", .wire = "\x08\x82\x37\xfa\x21\x3d\x34\x12", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "control_payload_126", .wire = "\x89\xfe\x00\x7e\x37\xfa\x21\x3d" ++ ("\x56\x9b\x40\x5c" ** 31) ++ "\x56\x9b", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "nonminimal_len16", .wire = "\x81\xfe\x00\x05\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", .verdict = .divergence, .close_code = 1002, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "nonminimal_len16_zero", .wire = "\x81\xfe\x00\x00\x37\xfa\x21\x3d", .verdict = .divergence, .close_code = 1002, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "nonminimal_len64", .wire = "\x81\xff\x00\x00\x00\x00\x00\x00\x00\x05\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", .verdict = .divergence, .close_code = 1002, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    // SPLIT: py=ACCEPT coder=REJECT gorilla=REJECT
    .{ .label = "len64_msb_set", .wire = "\x81\xff\x80\x00\x00\x00\x00\x00\x00\x00\x37\xfa\x21\x3d", .verdict = .split, .close_code = 1002, .ours_rejects = true, .peers = "py=ACCEPT coder=REJECT gorilla=REJECT" },
    .{ .label = "orphan_continuation", .wire = "\x80\x86\x37\xfa\x21\x3d\x58\x88\x51\x55\x56\x94", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "bad_utf8_text", .wire = "\x81\x82\x37\xfa\x21\x3d\xc8\x04", .verdict = .divergence, .close_code = 1007, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "bad_utf8_overlong", .wire = "\x81\x82\x37\xfa\x21\x3d\xf7\x55", .verdict = .divergence, .close_code = 1007, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "bad_utf8_surrogate", .wire = "\x81\x83\x37\xfa\x21\x3d\xda\x5a\xa1", .verdict = .divergence, .close_code = 1007, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "bad_utf8_truncated", .wire = "\x81\x82\x37\xfa\x21\x3d\xd5\x78", .verdict = .divergence, .close_code = 1007, .peers = "py=ACCEPT coder=ACCEPT gorilla=ACCEPT" },
    .{ .label = "close_code_0", .wire = "\x88\x82\x37\xfa\x21\x3d\x37\xfa", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "close_code_999", .wire = "\x88\x82\x37\xfa\x21\x3d\x34\x1d", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "close_code_1004", .wire = "\x88\x82\x37\xfa\x21\x3d\x34\x16", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "close_code_1005", .wire = "\x88\x82\x37\xfa\x21\x3d\x34\x17", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "close_code_1006", .wire = "\x88\x82\x37\xfa\x21\x3d\x34\x14", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "close_code_1012", .wire = "\x88\x82\x37\xfa\x21\x3d\x34\x0e", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT/1012 gorilla=ACCEPT/1012" },
    .{ .label = "close_code_1013", .wire = "\x88\x82\x37\xfa\x21\x3d\x34\x0f", .verdict = .accept, .close_code = null, .peers = "py=ACCEPT coder=ACCEPT/1013 gorilla=ACCEPT/1013" },
    // SPLIT: py=ACCEPT coder=ACCEPT/1014 gorilla=REJECT/1002
    .{ .label = "close_code_1014", .wire = "\x88\x82\x37\xfa\x21\x3d\x34\x0c", .verdict = .split, .close_code = null, .ours_rejects = false, .peers = "py=ACCEPT coder=ACCEPT/1014 gorilla=REJECT/1002" },
    .{ .label = "close_code_1015", .wire = "\x88\x82\x37\xfa\x21\x3d\x34\x0d", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "close_code_1016", .wire = "\x88\x82\x37\xfa\x21\x3d\x34\x02", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "close_code_1100", .wire = "\x88\x82\x37\xfa\x21\x3d\x33\xb6", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "close_code_2000", .wire = "\x88\x82\x37\xfa\x21\x3d\x30\x2a", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "close_code_2999", .wire = "\x88\x82\x37\xfa\x21\x3d\x3c\x4d", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "close_code_5000", .wire = "\x88\x82\x37\xfa\x21\x3d\x24\x72", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    .{ .label = "close_code_65535", .wire = "\x88\x82\x37\xfa\x21\x3d\xc8\x05", .verdict = .reject, .close_code = 1002, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=REJECT/1002" },
    // SPLIT: py=REJECT/1002 coder=REJECT/1002 gorilla=ACCEPT
    .{ .label = "close_body_1byte", .wire = "\x88\x81\x37\xfa\x21\x3d\x34", .verdict = .split, .close_code = 1002, .ours_rejects = true, .peers = "py=REJECT/1002 coder=REJECT/1002 gorilla=ACCEPT" },
    // SPLIT: py=REJECT/1007 coder=ACCEPT/1000 gorilla=REJECT/1002
    .{ .label = "close_reason_bad_utf8", .wire = "\x88\x84\x37\xfa\x21\x3d\x34\x12\xde\xc3", .verdict = .split, .close_code = 1007, .ours_rejects = true, .peers = "py=REJECT/1007 coder=ACCEPT/1000 gorilla=REJECT/1002" },
};

/// Do to `wire` exactly what the three foreign servers did with it: hand the
/// bytes to a full server-role connection. This has to be the `Connection`
/// layer, not bare `parseFrame` — the peers are complete stacks, and rules
/// like "a continuation frame with nothing to continue" live above the frame
/// codec here (`orphan_continuation` in the table below is exactly that case,
/// and it is what caught this when the driver was written one layer too low).
fn peerVerdict(buf: []u8) struct { rejected: bool, code: ?u16 } {
    var msg_buf: [1024]u8 = undefined;
    var conn: Connection = .init(.server, &msg_buf, 1 << 20);
    const r = conn.receive(buf) catch |e| return .{ .rejected = true, .code = frame.closeCode(e) };
    return switch (r.event) {
        .need_more => .{ .rejected = true, .code = null },
        else => .{ .rejected = false, .code = null },
    };
}

test "external anchor: frozen verdicts of three foreign WebSocket peers (2026-08-09)" {
    var scratch: [1024]u8 = undefined;
    var checked: usize = 0;
    var splits: usize = 0;
    for (foreign_peer_corpus) |c| {
        @memcpy(scratch[0..c.wire.len], c.wire);
        const buf = scratch[0..c.wire.len];
        const ours = peerVerdict(buf);
        switch (c.verdict) {
            .accept => {
                if (ours.rejected) {
                    std.debug.print("{s}: all three peers accepted ({s}) but we rejected with close {?d}\n", .{ c.label, c.peers, ours.code });
                    return error.TestUnexpectedResult;
                }
                checked += 1;
            },
            .reject, .divergence => {
                if (!ours.rejected) {
                    std.debug.print("{s}: expected rejection ({s}) but we accepted\n", .{ c.label, c.peers });
                    return error.TestUnexpectedResult;
                }
                if (c.close_code) |want| {
                    if (ours.code != want) {
                        std.debug.print("{s}: peers said close {d} ({s}), we said {?d}\n", .{ c.label, want, c.peers, ours.code });
                        return error.TestUnexpectedResult;
                    }
                }
                checked += 1;
            },
            .split => {
                if (ours.rejected != c.ours_rejects) {
                    std.debug.print("{s}: peers disagreed ({s}); this module's pinned answer changed\n", .{ c.label, c.peers });
                    return error.TestUnexpectedResult;
                }
                if (c.ours_rejects and ours.code != c.close_code) {
                    std.debug.print("{s}: peers disagreed ({s}); our close code moved to {?d}\n", .{ c.label, c.peers, ours.code });
                    return error.TestUnexpectedResult;
                }
                splits += 1;
            },
        }
    }
    // Guard against the table being emptied or the loop being short-circuited:
    // a corpus that asserts nothing passes silently otherwise.
    try testing.expect(checked >= 45);
    try testing.expectEqual(@as(usize, 4), splits);
}

test "control frame (ping) interleaves mid-fragmentation without disturbing it" {
    var scratch: [64]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);

    var wire1 = [_]u8{ 0x01, 0x03, 'H', 'e', 'l' };
    _ = try conn.receive(&wire1);

    var ping_wire = [_]u8{ 0x89, 0x02, 'h', 'i' };
    const rp = try conn.receive(&ping_wire);
    switch (rp.event) {
        .ping => |p| try testing.expectEqualStrings("hi", p),
        else => return error.TestUnexpectedResult,
    }

    var wire2 = [_]u8{ 0x80, 0x02, 'l', 'o' };
    const r2 = try conn.receive(&wire2);
    switch (r2.event) {
        .message => |m| try testing.expectEqualStrings("Hello", m.payload),
        else => return error.TestUnexpectedResult,
    }
}

test "continuation frame with no start is rejected (close 1002)" {
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);
    var wire = [_]u8{ 0x80, 0x02, 'l', 'o' };
    try testing.expectError(error.InvalidFragmentation, conn.receive(&wire));
    try testing.expectEqual(@as(u16, 1002), frame.closeCode(error.InvalidFragmentation));
}

test "a new data frame before finishing the previous one is rejected (close 1002)" {
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);
    var wire1 = [_]u8{ 0x01, 0x03, 'H', 'e', 'l' };
    _ = try conn.receive(&wire1);

    var wire2 = [_]u8{ 0x02, 0x01, 0xAA }; // binary, fin=0 -- a second start before finishing
    try testing.expectError(error.InvalidFragmentation, conn.receive(&wire2));
}

test "aggregate message over message_buf cap is rejected (close 1009)" {
    var scratch: [4]u8 = undefined; // tiny cap
    var conn: Connection = .init(.client, &scratch, 1 << 20);
    var wire1 = [_]u8{ 0x01, 0x03, 'H', 'e', 'l' }; // 3 bytes, fits
    _ = try conn.receive(&wire1);

    var wire2 = [_]u8{ 0x80, 0x02, 'l', 'o' }; // +2 bytes = 5 > 4-byte cap
    try testing.expectError(error.MessageTooLarge, conn.receive(&wire2));
    try testing.expectEqual(@as(u16, 1009), frame.closeCode(error.MessageTooLarge));
}

test "an UNFRAGMENTED message over message_buf cap is rejected too (close 1009)" {
    // The cap the doc comment on `message_buf` promises used to apply only to
    // the reassembly path: a single FIN frame was returned borrowed from the
    // read buffer with no size check at all, so the only bound on a one-frame
    // message was `max_frame_size` and a caller who sized `message_buf` as its
    // memory budget did not have one. A 4-byte `message_buf` accepted a 10-byte
    // one-shot text frame.
    var scratch: [4]u8 = undefined; // the caller's stated memory budget
    var conn: Connection = .init(.client, &scratch, 1 << 20);

    var wire = [_]u8{ 0x81, 0x0a } ++ "abcdefghij".*; // text, FIN, 10 bytes
    try testing.expectError(error.MessageTooLarge, conn.receive(&wire));
    try testing.expectEqual(@as(u16, 1009), frame.closeCode(error.MessageTooLarge));

    // ...and the same for binary, which has no UTF-8 check to hide behind.
    var bin = [_]u8{ 0x82, 0x05, 1, 2, 3, 4, 5 };
    try testing.expectError(error.MessageTooLarge, conn.receive(&bin));

    // POSITIVE CONTROL: exactly the cap still goes through, and still borrows
    // the caller's read buffer rather than being copied into `message_buf`.
    var fits = [_]u8{ 0x81, 0x04 } ++ "abcd".*;
    const r = try conn.receive(&fits);
    switch (r.event) {
        .message => |m| {
            try testing.expectEqualStrings("abcd", m.payload);
            try testing.expect(m.payload.ptr == fits[2..].ptr);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "invalid UTF-8 single-frame text message is rejected (close 1007)" {
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);
    var wire = [_]u8{ 0x81, 0x02, 0xff, 0xfe }; // text, invalid UTF-8
    try testing.expectError(error.InvalidUtf8, conn.receive(&wire));
    try testing.expectEqual(@as(u16, 1007), frame.closeCode(error.InvalidUtf8));
}

test "invalid UTF-8 reassembled text message is rejected (close 1007)" {
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);
    var wire1 = [_]u8{ 0x01, 0x01, 0xff }; // text, fin=0, invalid lead byte
    _ = try conn.receive(&wire1);
    var wire2 = [_]u8{ 0x80, 0x01, 'x' };
    try testing.expectError(error.InvalidUtf8, conn.receive(&wire2));
}

test "close frame surfaces code + reason and updates close_received" {
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);

    // 2 status-code bytes + the 6-byte reason. The buffer was [7]u8, one short
    // of "normal", so this test never compiled — it was dark until root.zig
    // gained its aggregator.
    var body: [8]u8 = undefined;
    std.mem.writeInt(u16, body[0..2], 1000, .big);
    @memcpy(body[2..], "normal");
    var wire: [2 + 8]u8 = undefined;
    wire[0] = 0x88;
    wire[1] = 8;
    @memcpy(wire[2..], &body);

    try testing.expect(!conn.close_received);
    const r = try conn.receive(&wire);
    switch (r.event) {
        .close => |info| {
            try testing.expectEqual(@as(?u16, 1000), info.code);
            try testing.expectEqualStrings("normal", info.reason);
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(conn.close_received);
    try testing.expect(!conn.bothClosed());
    conn.close_sent = true;
    try testing.expect(conn.bothClosed());
}

// W2-A8/websocket-F2: `decodeCloseBody` now validates the close code against
// RFC 6455 §7.4.1 (see `frame.zig`'s `isValidCloseCode`) — check the error
// actually surfaces through `Connection.receive`, not just `frame` directly,
// and that it maps to close code 1002 like every other protocol error.
test "a close frame carrying an RFC-illegal code fails through Connection.receive, close 1002" {
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);
    var wire = [_]u8{ 0x88, 0x02, 0x03, 0xed }; // close, code 1005 — "MUST NOT be set"
    try testing.expectError(error.InvalidCloseCode, conn.receive(&wire));
    try testing.expectEqual(@as(u16, 1002), frame.closeCode(error.InvalidCloseCode));
}

// W2-A8/websocket-F3: `close_received` was tracked but never consulted by
// `receive` — a text/binary/continuation frame arriving after the peer's
// close frame was delivered as an ordinary message instead of being
// discarded per RFC 6455 §1.4.
test "a data frame after close_received is rejected, not delivered (close 1002)" {
    var scratch: [64]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);

    var close_wire = [_]u8{ 0x88, 0x00 }; // close, no code/reason
    const r1 = try conn.receive(&close_wire);
    try testing.expect(r1.event == .close);
    try testing.expect(conn.close_received);

    var text_wire = unmaskedFrame(0x81, "hi", 4);
    try testing.expectError(error.DataAfterClose, conn.receive(&text_wire));
    try testing.expectEqual(@as(u16, 1002), frame.closeCode(error.DataAfterClose));

    var cont_wire = unmaskedFrame(0x80, "hi", 4);
    try testing.expectError(error.DataAfterClose, conn.receive(&cont_wire));
}

test "unmasked client frame is rejected through the Connection too (close 1002)" {
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.server, &scratch, 1 << 20);
    var wire = unmaskedFrame(0x81, "hi", 4); // no MASK bit, server-role connection
    try testing.expectError(error.UnmaskedClientFrame, conn.receive(&wire));
}

test "need_more propagates from the underlying frame parser" {
    var scratch: [16]u8 = undefined;
    var conn: Connection = .init(.client, &scratch, 1 << 20);
    var partial = [_]u8{0x81};
    const r = try conn.receive(&partial);
    try testing.expectEqual(Connection.Event.need_more, r.event);
    try testing.expectEqual(@as(usize, 0), r.consumed);
}
