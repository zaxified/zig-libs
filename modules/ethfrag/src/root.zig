// SPDX-License-Identifier: MIT
//! ethfrag — inner-frame fragmentation and reassembly for an overlay encap.
//!
//! Splits an inner Ethernet frame across fixed-MTU carrier packets and reassembles
//! it, with strict overlap/duplicate/timeout rejection and hard resource bounds
//! (the IP-fragmentation CVE playbook — teardrop, overlap, resource exhaustion —
//! treated as adversarial input, not corner cases). Standalone codec, no network.
//! Consumer: the S1b L2-over-WireGuard data plane. See ~/CML/S1B-scada-l2vpn-venture-plan.md.
//!
//! ## Wire format
//! Every fragment is an 8-byte header followed by its payload slice:
//!
//! ```
//!  0               1               2               3
//!  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           frag_id            |            offset            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            length            |    flags     |   reserved    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        payload (length bytes)                ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! All integers are big-endian. `flags` bit 0 is `more` (1 = more fragments
//! follow, 0 = this fragment ends the datagram); the remaining 7 bits and the
//! `reserved` byte MUST be zero — `Header.decode` rejects any nonzero
//! reserved bit rather than silently ignoring it (a strict decoder closes off
//! a reserved-field covert channel / smuggling vector for free).
//!
//! `offset`/`length` are `u16`, which caps a single reassembled frame at 65535
//! bytes (`max_frame_len`) — generous headroom over both standard (1500) and
//! jumbo (~9216) Ethernet MTUs, and a hard ceiling tied directly to the header
//! width rather than an arbitrary constant. `frag_id` groups the fragments of
//! one inner frame; like the IPv4 identification field, assigning distinct
//! ids to concurrently in-flight frames (and not reusing one before its
//! reassembly window has elapsed) is the sender's responsibility, not this
//! codec's — `fragment()` takes `frag_id` as a parameter for exactly that
//! reason.
//!
//! ## Threat model (see SPEC.md for the full writeup)
//! `Reassembler` treats every fragment as adversarial input and fails closed:
//! overlapping fragments (including exact duplicates) drop the *whole*
//! in-flight datagram per RFC 5722 §3 rather than being merged or the first/
//! last write winning (the classic teardrop/evasion class); out-of-bounds or
//! contradictory `more=false` claims are rejected (teardrop-style overrun);
//! per-datagram byte and fragment counts are hard-capped (tiny-fragment
//! flood); the number of concurrently tracked datagrams is hard-capped
//! (incomplete-reassembly memory exhaustion); a caller-clocked idle timeout
//! (no wall-clock read inside this module) reclaims abandoned datagrams
//! (gap-then-never-completes). A frame is only ever returned once every byte
//! of it has been accounted for by non-overlapping fragments — there is no
//! code path that returns a partial frame.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "IP fragmentation/reassembly (RFC 791 §3.2) + RFC 5722 §3 overlap rejection, hardened",
    .deps = .{}, // std only
};

// ── wire header ──────────────────────────────────────────────────────────────

/// Encoded header size in bytes. See the module doc comment for the layout.
pub const header_len: usize = 8;

/// Hard ceiling on a reassembled frame's length, tied directly to the 16-bit
/// `offset`/`length` header fields (not an arbitrary policy choice).
pub const max_frame_len: usize = std.math.maxInt(u16);

/// Sanity ceiling on how many fragments a single datagram may be split into
/// or reassembled from. `fragment()` refuses to produce more than this many
/// pieces for one frame; `ReassemblerConfig.max_fragments_per_datagram`
/// defaults to it and is the receive-side tiny-fragment-flood defense.
pub const max_fragments_per_frame: usize = 4096;

const Header = struct {
    frag_id: u16,
    offset: u16,
    length: u16,
    more: bool,

    const flag_more: u8 = 1;

    fn encode(self: Header, out: []u8) void {
        std.debug.assert(out.len == header_len);
        std.mem.writeInt(u16, out[0..2], self.frag_id, .big);
        std.mem.writeInt(u16, out[2..4], self.offset, .big);
        std.mem.writeInt(u16, out[4..6], self.length, .big);
        out[6] = if (self.more) flag_more else 0;
        out[7] = 0; // reserved — must stay zero
    }

    const DecodeError = error{
        /// Fewer than `header_len` bytes were supplied.
        Truncated,
        /// A reserved flag bit or the reserved byte was nonzero.
        InvalidHeader,
    };

    fn decode(bytes: []const u8) DecodeError!Header {
        if (bytes.len < header_len) return error.Truncated;
        const flags = bytes[6];
        const reserved = bytes[7];
        if (flags & ~flag_more != 0 or reserved != 0) return error.InvalidHeader;
        return .{
            .frag_id = std.mem.readInt(u16, bytes[0..2], .big),
            .offset = std.mem.readInt(u16, bytes[2..4], .big),
            .length = std.mem.readInt(u16, bytes[4..6], .big),
            .more = flags & flag_more != 0,
        };
    }
};

// ── fragmentation (send side) ───────────────────────────────────────────────

/// One outgoing wire-ready fragment: `header_len` header bytes followed by
/// its payload slice. Allocator-owned — free via `Fragment.deinit` or
/// `freeFragments`.
pub const Fragment = struct {
    bytes: []u8,

    pub fn deinit(self: Fragment, allocator: Allocator) void {
        allocator.free(self.bytes);
    }
};

/// Frees every fragment in `frags` plus the slice itself.
pub fn freeFragments(allocator: Allocator, frags: []Fragment) void {
    for (frags) |f| f.deinit(allocator);
    allocator.free(frags);
}

pub const FragmentError = error{
    /// `frame.len` exceeds `max_frame_len`.
    FrameTooLarge,
    /// `carrier_mtu` leaves no room for even one payload byte after
    /// `header_overhead` + this codec's own `header_len`.
    MtuTooSmall,
    /// The frame would split into more than `max_fragments_per_frame`
    /// pieces at this MTU.
    TooManyFragments,
} || Allocator.Error;

/// Splits `frame` into fixed-size wire fragments that fit in `carrier_mtu`
/// bytes, after reserving `header_overhead` bytes for whatever outer framing
/// the caller wraps each fragment in (e.g. a UDP/tunnel header) on top of
/// this codec's own `header_len`-byte header. `frag_id` is stamped into every
/// fragment's header — callers are responsible for choosing an id that is
/// not already in flight (see the module doc comment).
///
/// A `frame` that already fits in one fragment yields exactly one `Fragment`
/// (the no-frag case) with `offset = 0`, `more = false` — including the
/// degenerate `frame.len == 0` case, which always yields exactly one
/// zero-length fragment rather than zero fragments.
///
/// Returned fragments and the slice itself are allocator-owned; free with
/// `freeFragments` (or `Fragment.deinit` each, then `allocator.free` the
/// slice).
pub fn fragment(
    allocator: Allocator,
    frame: []const u8,
    frag_id: u16,
    carrier_mtu: usize,
    header_overhead: usize,
) FragmentError![]Fragment {
    if (frame.len > max_frame_len) return error.FrameTooLarge;

    const overhead = header_overhead + header_len;
    if (overhead >= carrier_mtu) return error.MtuTooSmall;
    const payload_cap = carrier_mtu - overhead;

    const frag_count = if (frame.len == 0)
        1
    else
        std.math.divCeil(usize, frame.len, payload_cap) catch unreachable;
    if (frag_count > max_fragments_per_frame) return error.TooManyFragments;

    const frags = try allocator.alloc(Fragment, frag_count);
    var built: usize = 0;
    errdefer {
        for (frags[0..built]) |f| f.deinit(allocator);
        allocator.free(frags);
    }

    var offset: usize = 0;
    while (built < frag_count) : (built += 1) {
        const len = @min(payload_cap, frame.len - offset);
        const more = (offset + len) < frame.len;
        const buf = try allocator.alloc(u8, header_len + len);
        const hdr: Header = .{
            .frag_id = frag_id,
            .offset = @intCast(offset),
            .length = @intCast(len),
            .more = more,
        };
        hdr.encode(buf[0..header_len]);
        @memcpy(buf[header_len..], frame[offset .. offset + len]);
        frags[built] = .{ .bytes = buf };
        offset += len;
    }
    return frags;
}

// ── reassembly (receive side) ───────────────────────────────────────────────

pub const ReassemblerConfig = struct {
    /// Maximum number of concurrently tracked in-flight datagrams
    /// (distinct `frag_id`s). Bounds the incomplete-reassembly memory-
    /// exhaustion class. Must be at least 1.
    max_inflight: usize,
    /// Per-datagram reassembly buffer size cap in bytes. Must be at least 1
    /// and at most `max_frame_len`; defaults to `max_frame_len`.
    max_frame_len: usize = max_frame_len,
    /// Per-datagram fragment-count cap (tiny-fragment-flood defense).
    /// Defaults to `max_fragments_per_frame`.
    max_fragments_per_datagram: usize = max_fragments_per_frame,
    /// Idle timeout in nanoseconds: a datagram with no new fragment for
    /// longer than this is dropped the next time it is touched (on a fresh
    /// fragment for that id, or explicitly via `expireOlderThan`).
    /// Caller-clocked — this module never reads a clock itself.
    timeout_ns: u64,
};

pub const InsertResult = union(enum) {
    /// The datagram is not yet fully covered.
    incomplete,
    /// The reassembled frame, in original byte order. Allocator-owned (same
    /// allocator passed to `Reassembler.init`) — the caller must free it.
    complete: []u8,
};

pub const InsertError = Header.DecodeError || error{
    /// The wire bytes after the header don't exactly match the header's
    /// declared `length` (too few = truncated on the wire; too many =
    /// unexplained trailing bytes — both rejected rather than guessed at).
    LengthMismatch,
    /// This fragment's `[offset, offset+length)` span exceeds the
    /// configured `max_frame_len`, or exceeds a total length already
    /// established by an earlier `more=false` fragment for this datagram
    /// (a teardrop-style overrun past the claimed end).
    OutOfBounds,
    /// This fragment overlaps a byte range already accepted for this
    /// `frag_id` — including an exact duplicate of a prior fragment. Per
    /// RFC 5722 §3, the *entire* datagram is dropped, not just the
    /// overlapping fragment.
    OverlappingFragment,
    /// This datagram has already accepted `max_fragments_per_datagram`
    /// fragments (tiny-fragment-flood defense); the datagram is dropped.
    TooManyFragments,
    /// Two different `more=false` fragments for this datagram disagree on
    /// where the frame ends.
    ProtocolViolation,
    /// `max_inflight` datagrams are already tracked and none could be
    /// reclaimed (all still within their timeout window) — this fragment
    /// is dropped without creating new state.
    TableFull,
} || Allocator.Error;

/// Bounded, stateful reassembler for `fragment()`'s wire format. The free
/// functions above are reentrant; a `Reassembler` instance itself is
/// single-owner — one caller drives `insert`/`expireOlderThan` at a time.
pub const Reassembler = struct {
    allocator: Allocator,
    config: ReassemblerConfig,
    entries: std.AutoHashMapUnmanaged(u16, Entry) = .empty,

    const Interval = struct { offset: u16, length: u16 };

    const Entry = struct {
        buf: []u8, // len == config.max_frame_len
        intervals: std.ArrayListUnmanaged(Interval) = .empty,
        covered: usize = 0,
        total_len: ?usize = null,
        last_seen_ns: u64,

        fn deinit(self: *Entry, allocator: Allocator) void {
            allocator.free(self.buf);
            self.intervals.deinit(allocator);
        }
    };

    pub fn init(allocator: Allocator, config: ReassemblerConfig) Reassembler {
        std.debug.assert(config.max_inflight >= 1);
        std.debug.assert(config.max_frame_len >= 1 and config.max_frame_len <= max_frame_len);
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *Reassembler) void {
        var it = self.entries.valueIterator();
        while (it.next()) |e| e.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Number of distinct `frag_id`s currently tracked. Always
    /// `<= config.max_inflight`.
    pub fn inflightCount(self: *const Reassembler) usize {
        return self.entries.count();
    }

    fn dropEntry(self: *Reassembler, id: u16) void {
        if (self.entries.fetchRemove(id)) |kv| {
            var e = kv.value;
            e.deinit(self.allocator);
        }
    }

    /// Drops every tracked datagram idle for longer than `config.timeout_ns`
    /// as of caller-supplied `now_ns`. Caller-clocked: this never reads a
    /// clock itself, and a `now_ns` that appears to move backwards relative
    /// to an entry's last-seen time is treated as "not yet expired" (a
    /// saturating subtraction, not a wraparound) rather than either
    /// spuriously expiring everything or silently never expiring anything.
    /// Returns the number of datagrams dropped. Safe to call at any time,
    /// e.g. from a periodic caller-side tick; also called internally from
    /// `insert` when the table is full and room is needed.
    pub fn expireOlderThan(self: *Reassembler, now_ns: u64) usize {
        var doomed: std.ArrayListUnmanaged(u16) = .empty;
        defer doomed.deinit(self.allocator);

        var it = self.entries.iterator();
        while (it.next()) |kv| {
            if (now_ns -| kv.value_ptr.last_seen_ns > self.config.timeout_ns) {
                // Best-effort: on OOM here we simply expire fewer entries
                // this round (no leak, no corruption — just deferred to the
                // next call).
                doomed.append(self.allocator, kv.key_ptr.*) catch break;
            }
        }
        for (doomed.items) |id| self.dropEntry(id);
        return doomed.items.len;
    }

    /// Feeds one wire fragment (`header_len` header bytes + payload, as
    /// produced by `fragment()`) into the reassembler. `now_ns` is the
    /// caller's current time in the same clock domain used for
    /// `config.timeout_ns` / `expireOlderThan`.
    ///
    /// Never publishes a partial frame: the only way to get `.complete` is
    /// for the accepted, non-overlapping fragments of a datagram to sum to
    /// exactly its established total length.
    pub fn insert(self: *Reassembler, wire_bytes: []const u8, now_ns: u64) InsertError!InsertResult {
        const hdr = try Header.decode(wire_bytes);
        const payload = wire_bytes[header_len..];
        if (payload.len != hdr.length) return error.LengthMismatch;

        const frag_end = @as(usize, hdr.offset) + @as(usize, hdr.length);
        if (frag_end > self.config.max_frame_len) return error.OutOfBounds;

        // A very late fragment for a timed-out datagram starts a fresh
        // reassembly rather than resurrecting stale bytes.
        if (self.entries.getPtr(hdr.frag_id)) |e| {
            if (now_ns -| e.last_seen_ns > self.config.timeout_ns) self.dropEntry(hdr.frag_id);
        }

        if (!self.entries.contains(hdr.frag_id) and self.entries.count() >= self.config.max_inflight) {
            _ = self.expireOlderThan(now_ns);
            if (!self.entries.contains(hdr.frag_id) and self.entries.count() >= self.config.max_inflight) {
                return error.TableFull;
            }
        }

        const gop = try self.entries.getOrPut(self.allocator, hdr.frag_id);
        if (!gop.found_existing) {
            const buf = self.allocator.alloc(u8, self.config.max_frame_len) catch |err| {
                _ = self.entries.remove(hdr.frag_id); // undo the getOrPut slot
                return err;
            };
            gop.value_ptr.* = .{ .buf = buf, .last_seen_ns = now_ns };
        }
        const entry = gop.value_ptr;
        entry.last_seen_ns = now_ns;

        if (entry.intervals.items.len >= self.config.max_fragments_per_datagram) {
            self.dropEntry(hdr.frag_id);
            return error.TooManyFragments;
        }

        if (!hdr.more) {
            if (entry.total_len) |t| {
                if (t != frag_end) {
                    self.dropEntry(hdr.frag_id);
                    return error.ProtocolViolation;
                }
            } else {
                entry.total_len = frag_end;
            }
        }
        if (entry.total_len) |t| {
            if (frag_end > t) {
                self.dropEntry(hdr.frag_id);
                return error.OutOfBounds;
            }
        }

        // RFC 5722 §3: any overlap with a previously accepted byte range
        // (including an exact duplicate) drops the whole datagram.
        for (entry.intervals.items) |iv| {
            const iv_end = @as(usize, iv.offset) + @as(usize, iv.length);
            if (@as(usize, hdr.offset) < iv_end and frag_end > @as(usize, iv.offset)) {
                self.dropEntry(hdr.frag_id);
                return error.OverlappingFragment;
            }
        }

        if (hdr.length > 0) @memcpy(entry.buf[hdr.offset..frag_end], payload);
        entry.intervals.append(self.allocator, .{ .offset = hdr.offset, .length = hdr.length }) catch |err| {
            self.dropEntry(hdr.frag_id);
            return err;
        };
        entry.covered += hdr.length;

        if (entry.total_len) |t| {
            if (entry.covered == t) {
                const out = self.allocator.dupe(u8, entry.buf[0..t]) catch |err| {
                    self.dropEntry(hdr.frag_id);
                    return err;
                };
                self.dropEntry(hdr.frag_id);
                return .{ .complete = out };
            }
        }
        return .incomplete;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn reassembleAll(gpa: Allocator, cfg: ReassemblerConfig, frags: []const Fragment) !?[]u8 {
    var r = Reassembler.init(gpa, cfg);
    defer r.deinit();
    var result: ?[]u8 = null;
    for (frags, 0..) |f, i| {
        switch (try r.insert(f.bytes, @intCast(i))) {
            .incomplete => {},
            .complete => |bytes| result = bytes,
        }
    }
    return result;
}

test "smoke: single-fragment (no-frag) frame reassembles immediately" {
    const frame = "hello, overlay";
    const frags = try fragment(testing.allocator, frame, 42, 1500, 0);
    defer freeFragments(testing.allocator, frags);
    try testing.expectEqual(@as(usize, 1), frags.len);

    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1_000_000_000 });
    defer r.deinit();
    const res = try r.insert(frags[0].bytes, 0);
    switch (res) {
        .complete => |bytes| {
            defer testing.allocator.free(bytes);
            try testing.expectEqualSlices(u8, frame, bytes);
        },
        .incomplete => return error.TestUnexpectedResult,
    }
}

test "zero-length frame round-trips as one empty fragment" {
    const frame: []const u8 = &.{};
    const frags = try fragment(testing.allocator, frame, 7, 1500, 0);
    defer freeFragments(testing.allocator, frags);
    try testing.expectEqual(@as(usize, 1), frags.len);

    const out = try reassembleAll(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 }, frags);
    try testing.expect(out != null);
    defer testing.allocator.free(out.?);
    try testing.expectEqual(@as(usize, 0), out.?.len);
}

test "multi-fragment frame reassembles byte-identical, in-order delivery" {
    var frame: [3000]u8 = undefined;
    for (&frame, 0..) |*b, i| b.* = @truncate(i * 7 + 3);

    const frags = try fragment(testing.allocator, &frame, 99, 512, 0);
    defer freeFragments(testing.allocator, frags);
    try testing.expect(frags.len > 1);
    // Last fragment must carry more = false, all others more = true.
    for (frags, 0..) |f, i| {
        const hdr = try Header.decode(f.bytes);
        try testing.expectEqual(i + 1 == frags.len, !hdr.more);
    }

    const out = try reassembleAll(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 }, frags);
    try testing.expect(out != null);
    defer testing.allocator.free(out.?);
    try testing.expectEqualSlices(u8, &frame, out.?);
}

test "reordered delivery still reassembles correctly" {
    var frame: [4000]u8 = undefined;
    for (&frame, 0..) |*b, i| b.* = @truncate(i * 13 + 1);
    const frags = try fragment(testing.allocator, &frame, 11, 400, 4);
    defer freeFragments(testing.allocator, frags);
    try testing.expect(frags.len >= 4);

    // Reverse order.
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 });
    defer r.deinit();
    var out: ?[]u8 = null;
    var i: usize = frags.len;
    var now: u64 = 0;
    while (i > 0) {
        i -= 1;
        switch (try r.insert(frags[i].bytes, now)) {
            .incomplete => {},
            .complete => |bytes| out = bytes,
        }
        now += 1;
    }
    try testing.expect(out != null);
    defer testing.allocator.free(out.?);
    try testing.expectEqualSlices(u8, &frame, out.?);
}

test "fragment: MTU too small for header overhead is rejected" {
    try testing.expectError(error.MtuTooSmall, fragment(testing.allocator, "x", 0, header_len, 0));
    try testing.expectError(error.MtuTooSmall, fragment(testing.allocator, "x", 0, header_len - 1, 0));
}

test "fragment: frame larger than max_frame_len is rejected" {
    const big = try testing.allocator.alloc(u8, max_frame_len + 1);
    defer testing.allocator.free(big);
    try testing.expectError(error.FrameTooLarge, fragment(testing.allocator, big, 0, 1500, 0));
}

test "fragment: exceeding max_fragments_per_frame is rejected" {
    // payload_cap = 1 byte/fragment forces frame.len fragments.
    const frame = try testing.allocator.alloc(u8, max_fragments_per_frame + 1);
    defer testing.allocator.free(frame);
    try testing.expectError(error.TooManyFragments, fragment(testing.allocator, frame, 0, header_len + 1, 0));
}

test "reassembler rejects overlapping fragments and drops the whole datagram" {
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 });
    defer r.deinit();

    var buf1: [header_len + 10]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 0, .length = 10, .more = true }).encode(buf1[0..header_len]);
    @memset(buf1[header_len..], 'a');
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&buf1, 0));
    try testing.expectEqual(@as(usize, 1), r.inflightCount());

    // Overlaps bytes [5, 15) against the already-accepted [0, 10).
    var buf2: [header_len + 10]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 5, .length = 10, .more = false }).encode(buf2[0..header_len]);
    @memset(buf2[header_len..], 'b');
    try testing.expectError(error.OverlappingFragment, r.insert(&buf2, 1));

    // The whole datagram was dropped, not just the offending fragment.
    try testing.expectEqual(@as(usize, 0), r.inflightCount());
}

test "reassembler rejects an exact-duplicate fragment the same as any other overlap" {
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 });
    defer r.deinit();

    var buf: [header_len + 8]u8 = undefined;
    (Header{ .frag_id = 2, .offset = 0, .length = 8, .more = true }).encode(buf[0..header_len]);
    @memset(buf[header_len..], 'c');
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&buf, 0));

    // Byte-for-byte identical retransmit of the same fragment.
    try testing.expectError(error.OverlappingFragment, r.insert(&buf, 1));
    try testing.expectEqual(@as(usize, 0), r.inflightCount());
}

test "reassembler rejects a fragment extending past a claimed final length (teardrop-style)" {
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 });
    defer r.deinit();

    var last: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 3, .offset = 10, .length = 5, .more = false }).encode(last[0..header_len]);
    @memset(last[header_len..], 'd');
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&last, 0));
    try testing.expectEqual(@as(usize, 1), r.inflightCount());

    // A later, non-final fragment claiming to extend past the already-
    // established end (15) — a classic teardrop-style overrun.
    var over: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 3, .offset = 15, .length = 5, .more = true }).encode(over[0..header_len]);
    @memset(over[header_len..], 'e');
    try testing.expectError(error.OutOfBounds, r.insert(&over, 1));
    try testing.expectEqual(@as(usize, 0), r.inflightCount());
}

test "reassembler rejects contradictory more=false total-length claims" {
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 });
    defer r.deinit();

    // Non-final first fragment: doesn't establish a total length yet.
    var a: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 4, .offset = 0, .length = 5, .more = true }).encode(a[0..header_len]);
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&a, 0));

    // First "final" fragment: establishes total_len = 105, still incomplete
    // (only 10 of 105 bytes covered so far).
    var b: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 4, .offset = 100, .length = 5, .more = false }).encode(b[0..header_len]);
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&b, 1));

    // A second "final" fragment disagreeing on where the datagram ends.
    var c: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 4, .offset = 200, .length = 5, .more = false }).encode(c[0..header_len]);
    try testing.expectError(error.ProtocolViolation, r.insert(&c, 2));
    try testing.expectEqual(@as(usize, 0), r.inflightCount());
}

test "reassembler enforces max_frame_len (oversized reassembled length)" {
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .max_frame_len = 20, .timeout_ns = 1000 });
    defer r.deinit();

    var over: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 5, .offset = 18, .length = 5, .more = false }).encode(over[0..header_len]);
    try testing.expectError(error.OutOfBounds, r.insert(&over, 0));
    try testing.expectEqual(@as(usize, 0), r.inflightCount());
}

test "insert() itself evicts a stale entry before accepting a fresh fragment (no explicit expireOlderThan)" {
    // Distinct from the "gap then timeout" test below: there, the stale
    // entry is removed by an explicit expireOlderThan() sweep before the
    // late fragment ever reaches insert(), so insert()'s OWN inline
    // "is this tracked entry already stale?" check (right at the top of
    // insert(), before getOrPut) is never exercised. Here no sweep is
    // called — the second insert() call must detect the staleness itself.
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 100 });
    defer r.deinit();

    // First fragment of frag_id=50: bytes [0,5) = 'A'*5, non-final.
    var first: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 50, .offset = 0, .length = 5, .more = true }).encode(first[0..header_len]);
    @memset(first[header_len..], 'A');
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&first, 0));
    try testing.expectEqual(@as(usize, 1), r.inflightCount());

    // Well past the timeout, a fragment covering a DIFFERENT, non-
    // overlapping range [5,10) arrives as the datagram's final piece — no
    // expireOlderThan() call in between. If insert() fails to notice the
    // tracked entry is stale, this fragment is wrongly accepted into the
    // *old* entry (it doesn't overlap [0,5), so the overlap guard alone
    // can't catch it): covered would reach total_len=10 immediately and
    // .complete would splice in the stale 'A' bytes from a datagram whose
    // reassembly window already elapsed. The correct behaviour is a fresh
    // entry that is still incomplete (only 5 of its 10 declared bytes in).
    var second: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 50, .offset = 5, .length = 5, .more = false }).encode(second[0..header_len]);
    @memset(second[header_len..], 'B');
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&second, 1000));
    try testing.expectEqual(@as(usize, 1), r.inflightCount());

    // Finishing with the real [0,5) bytes must produce the fresh datagram
    // ('C'*5 ++ 'B'*5), never the stale 'A' bytes.
    var third: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 50, .offset = 0, .length = 5, .more = true }).encode(third[0..header_len]);
    @memset(third[header_len..], 'C');
    const res = try r.insert(&third, 1001);
    switch (res) {
        .complete => |bytes| {
            defer testing.allocator.free(bytes);
            try testing.expectEqualSlices(u8, "CCCCCBBBBB", bytes);
        },
        .incomplete => return error.TestUnexpectedResult,
    }
}

test "gap then timeout: incomplete datagram is pruned and never published" {
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 100 });
    defer r.deinit();

    var a: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 6, .offset = 0, .length = 5, .more = true }).encode(a[0..header_len]);
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&a, 0));
    try testing.expectEqual(@as(usize, 1), r.inflightCount());

    // The rest of the datagram never arrives; time passes well beyond the
    // timeout. An explicit sweep prunes it.
    try testing.expectEqual(@as(usize, 1), r.expireOlderThan(1000));
    try testing.expectEqual(@as(usize, 0), r.inflightCount());

    // A very late "final" fragment for the same id starts fresh — it does
    // not resurrect or complete against the pruned bytes.
    var b: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 6, .offset = 5, .length = 5, .more = false }).encode(b[0..header_len]);
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&b, 1000));
    try testing.expectEqual(@as(usize, 1), r.inflightCount());
}

test "tiny-fragment flood is bounded by max_fragments_per_datagram" {
    var r = Reassembler.init(testing.allocator, .{
        .max_inflight = 4,
        .max_fragments_per_datagram = 4,
        .timeout_ns = 1_000_000,
    });
    defer r.deinit();

    var offset: u16 = 0;
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        var buf: [header_len + 1]u8 = undefined;
        (Header{ .frag_id = 7, .offset = offset, .length = 1, .more = true }).encode(buf[0..header_len]);
        buf[header_len] = 'x';
        try testing.expectEqual(InsertResult.incomplete, try r.insert(&buf, @intCast(i)));
        offset += 1;
    }
    // The 5th 1-byte fragment for the same datagram trips the cap.
    var buf: [header_len + 1]u8 = undefined;
    (Header{ .frag_id = 7, .offset = offset, .length = 1, .more = true }).encode(buf[0..header_len]);
    buf[header_len] = 'x';
    try testing.expectError(error.TooManyFragments, r.insert(&buf, 4));
    try testing.expectEqual(@as(usize, 0), r.inflightCount());
}

test "resource-cap exhaustion: max_inflight bounds concurrent datagrams" {
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 2, .timeout_ns = 1_000_000 });
    defer r.deinit();

    var i: u16 = 0;
    while (i < 2) : (i += 1) {
        var buf: [header_len + 1]u8 = undefined;
        (Header{ .frag_id = i, .offset = 0, .length = 1, .more = true }).encode(buf[0..header_len]);
        buf[header_len] = 'z';
        try testing.expectEqual(InsertResult.incomplete, try r.insert(&buf, 0));
    }
    try testing.expectEqual(@as(usize, 2), r.inflightCount());

    // A third distinct datagram, table full, nothing expired yet.
    var buf: [header_len + 1]u8 = undefined;
    (Header{ .frag_id = 99, .offset = 0, .length = 1, .more = true }).encode(buf[0..header_len]);
    buf[header_len] = 'z';
    try testing.expectError(error.TableFull, r.insert(&buf, 1));
    try testing.expectEqual(@as(usize, 2), r.inflightCount());

    // Once the first two age out, the same fragment is accepted.
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&buf, 10_000_000));
    try testing.expectEqual(@as(usize, 1), r.inflightCount());
}

test "malformed header: nonzero reserved bits are rejected, never panics" {
    var buf: [header_len]u8 = @splat(0);
    buf[7] = 1; // reserved byte set
    try testing.expectError(error.InvalidHeader, Header.decode(&buf));

    var buf2: [header_len]u8 = @splat(0);
    buf2[6] = 0xFE; // undefined flag bits set (only bit 0 is defined)
    try testing.expectError(error.InvalidHeader, Header.decode(&buf2));
}

test "truncated wire bytes are rejected" {
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 });
    defer r.deinit();
    var short: [header_len - 1]u8 = @splat(0);
    try testing.expectError(error.Truncated, r.insert(&short, 0));
    try testing.expectEqual(@as(usize, 0), r.inflightCount());
}

test "length mismatch between header and actual payload is rejected" {
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 });
    defer r.deinit();

    var buf: [header_len + 3]u8 = undefined;
    (Header{ .frag_id = 8, .offset = 0, .length = 10, .more = false }).encode(buf[0..header_len]);
    // header claims 10 payload bytes but only 3 are present.
    try testing.expectError(error.LengthMismatch, r.insert(&buf, 0));
    try testing.expectEqual(@as(usize, 0), r.inflightCount());
}

test "out-of-bounds offset+length beyond max_frame_len is rejected" {
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .max_frame_len = 16, .timeout_ns = 1000 });
    defer r.deinit();

    var buf: [header_len + 10]u8 = undefined;
    (Header{ .frag_id = 9, .offset = 10, .length = 10, .more = false }).encode(buf[0..header_len]);
    try testing.expectError(error.OutOfBounds, r.insert(&buf, 0));
    try testing.expectEqual(@as(usize, 0), r.inflightCount());
}

// ── property test ────────────────────────────────────────────────────────────

test "property: any valid split of any frame reassembles byte-identical, seeded random sizes/MTUs/order" {
    var prng = std.Random.DefaultPrng.init(0xE7_F4_A6_09);
    const rand = prng.random();

    var iter: usize = 0;
    while (iter < 300) : (iter += 1) {
        const frame_len = rand.intRangeAtMost(usize, 0, 6000);
        const frame = try testing.allocator.alloc(u8, frame_len);
        defer testing.allocator.free(frame);
        rand.bytes(frame);

        const header_overhead = rand.intRangeAtMost(usize, 0, 40);
        const carrier_mtu = header_overhead + header_len + rand.intRangeAtMost(usize, 1, 600);
        const frag_id = rand.int(u16);

        const frags = fragment(testing.allocator, frame, frag_id, carrier_mtu, header_overhead) catch |err| switch (err) {
            error.TooManyFragments => continue, // extreme mtu/frame combo, not the property under test
            else => return err,
        };
        defer freeFragments(testing.allocator, frags);

        // Shuffle delivery order.
        const order = try testing.allocator.alloc(usize, frags.len);
        defer testing.allocator.free(order);
        for (order, 0..) |*o, i| o.* = i;
        rand.shuffle(usize, order);

        var r = Reassembler.init(testing.allocator, .{
            .max_inflight = 4,
            .max_fragments_per_datagram = max_fragments_per_frame,
            .timeout_ns = std.math.maxInt(u64),
        });
        defer r.deinit();

        var out: ?[]u8 = null;
        for (order, 0..) |idx, i| {
            switch (try r.insert(frags[idx].bytes, @intCast(i))) {
                .incomplete => {},
                .complete => |bytes| out = bytes,
            }
        }
        try testing.expect(out != null);
        defer testing.allocator.free(out.?);
        try testing.expectEqualSlices(u8, frame, out.?);
    }
}

// ── fuzz target ───────────────────────────────────────────────────────────────

test "fuzz: reassembler never panics and stays bounded on hostile fragment streams" {
    // Fuzzing is built into the Zig toolchain (`zig build test --fuzz`); under
    // a plain `zig build test` this runs once as a smoke test (see the icmp
    // module's identically-shaped fuzz test for the same convention). The
    // reassembler consumes wire bytes straight from an untrusted carrier, so
    // this drives arbitrary (including deliberately malformed and
    // overlapping) fragment streams at it and asserts only: it never panics,
    // and `inflightCount()` never exceeds `max_inflight`.
    try testing.fuzz({}, fuzzReassembler, .{});
}

fn fuzzReassembler(_: void, smith: *std.testing.Smith) !void {
    const max_inflight: usize = 4;
    var r = Reassembler.init(testing.allocator, .{
        .max_inflight = max_inflight,
        .max_frame_len = 512,
        .max_fragments_per_datagram = 16,
        .timeout_ns = 1000,
    });
    defer r.deinit();

    var now: u64 = 0;
    const steps = smith.valueRangeAtMost(u8, 0, 64);
    var step: usize = 0;
    while (step < steps) : (step += 1) {
        now += smith.valueRangeAtMost(u16, 0, 2000);

        if (smith.value(bool)) {
            // A structurally valid-but-hostile fragment: small frag_id range
            // to force id collisions/overlaps, arbitrary offset/length/more/
            // payload.
            var wire: [header_len + 32]u8 = undefined;
            var payload: [32]u8 = undefined;
            smith.bytes(&payload);
            const len = smith.valueRangeAtMost(u8, 0, payload.len);
            const hdr: Header = .{
                .frag_id = smith.valueRangeAtMost(u16, 0, 7),
                .offset = smith.value(u16),
                .length = len,
                .more = smith.value(bool),
            };
            hdr.encode(wire[0..header_len]);
            @memcpy(wire[header_len .. header_len + len], payload[0..len]);
            const result = r.insert(wire[0 .. header_len + len], now) catch continue;
            switch (result) {
                .incomplete => {},
                .complete => |bytes| testing.allocator.free(bytes),
            }
        } else {
            // Fully arbitrary bytes, including too-short buffers — exercises
            // Header.decode's Truncated/InvalidHeader paths directly.
            var raw: [header_len + 32]u8 = undefined;
            smith.bytes(&raw);
            const len = smith.valueRangeAtMost(u16, 0, raw.len);
            const result = r.insert(raw[0..len], now) catch continue;
            switch (result) {
                .incomplete => {},
                .complete => |bytes| testing.allocator.free(bytes),
            }
        }

        try testing.expect(r.inflightCount() <= max_inflight);
    }
}
