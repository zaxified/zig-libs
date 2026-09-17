// SPDX-License-Identifier: MIT
//! ethfrag — inner-frame fragmentation and reassembly for an overlay encap.
//!
//! Splits an inner Ethernet frame across fixed-MTU carrier packets and reassembles
//! it, with strict overlap/duplicate/timeout rejection and hard resource bounds
//! (the IP-fragmentation CVE playbook — teardrop, overlap, resource exhaustion —
//! treated as adversarial input, not corner cases). Standalone codec, no network.
//! Consumer: an L2-over-WireGuard data plane.
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
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Hardened inner-frame fragmentation/reassembly codec — RFC 5722 overlap rejection, bounded per-datagram memory, caller-clocked timeout, fuzz-tested never-panic",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
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
    /// `header_overhead` + this codec's own `header_len` — including the
    /// degenerate case where that sum does not fit in a `usize` at all.
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

    // Checked BEFORE the add, not after. `header_overhead` is caller-supplied
    // local config (the outer framing's own header size), never wire data, so
    // this is not an attacker-reachable path — but a plain `header_overhead +
    // header_len` panics on integer overflow in Debug/ReleaseSafe (and is UB
    // in ReleaseFast) for a pathological value near `usize` max, which is the
    // one place in this module where a config-shaped input was not validated
    // before use. Every other one is (`frame.len` above, `ReassemblerConfig`'s
    // fields by assert). An overflowing `header_overhead` can only ever have
    // meant "no room left", which is exactly `MtuTooSmall`. (Audit F1.)
    const overhead = std.math.add(usize, header_overhead, header_len) catch
        return error.MtuTooSmall;
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
    /// Absolute cap in nanoseconds on how long an in-flight datagram may
    /// be held, measured from its FIRST fragment, regardless of how
    /// recently it last received one. `timeout_ns` alone only bounds the
    /// GAP since the last accepted fragment — a steady trickle of fresh,
    /// individually legitimate, non-overlapping fragments for the same
    /// `frag_id` refreshes it forever and never goes idle, so nothing ever
    /// reclaimed the slot (Audit F2, HIGH). `null` (the default) applies
    /// `8 * timeout_ns`: enough slack for a legitimately bursty sender,
    /// but a real ceiling rather than none. Enforced both inline (a fresh
    /// fragment for a datagram past this age starts a new one, same as
    /// the idle check) and by `expireOlderThan`.
    max_lifetime_ns: ?u64 = null,
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
    /// A non-final (`more = true`) fragment carried zero payload bytes.
    /// `fragment()` never produces one — a non-final fragment always
    /// carries at least one payload byte, since the only `length == 0`
    /// fragment it ever emits is the sole, final fragment of an empty
    /// frame. A contentless `more = true` fragment therefore buys a
    /// legitimate sender nothing, and (before this check existed) it was
    /// the one shape RFC 5722 overlap rejection could not see on replay:
    /// the half-open `[offset, offset+length)` overlap test degenerates
    /// to the empty set whenever the incoming range has zero length, so a
    /// zero-length fragment never overlapped anything — including an
    /// exact resend of itself — and could be replayed at the wire's
    /// cheapest possible cost (8 bytes, no state built) forever (Audit
    /// F1: A3/A3b).
    EmptyNonFinalFragment,
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

/// Order `offset` against `item.offset`, for `std.sort.lowerBound` over a
/// `[]Interval` sorted by offset (Audit F9).
fn intervalOffsetOrder(offset: u16, item: Reassembler.Interval) std.math.Order {
    return std.math.order(offset, item.offset);
}

/// Does `[offset, offset+length)` overlap `iv`? Includes the F1/A21
/// zero-length-duplicate special case (see the call site's comment).
/// Counts each call in `test_f9_overlap_checks` — a timing-free measure of
/// how much overlap-check work one `insert` does (see the campaign's F9
/// test), incremented unconditionally since the cost of a `usize` add is
/// immaterial next to the comparisons/branches around it.
fn intervalOverlaps(offset: u16, length: u16, end: usize, iv: Reassembler.Interval) bool {
    test_f9_overlap_checks += 1;
    if (length == 0 and iv.length == 0 and iv.offset == offset) return true;
    const iv_end = @as(usize, iv.offset) + @as(usize, iv.length);
    return @as(usize, offset) < iv_end and end > @as(usize, iv.offset);
}
var test_f9_overlap_checks: usize = 0;
var test_f8_bytes_allocated: usize = 0;

/// Bounded, stateful reassembler for `fragment()`'s wire format. The free
/// functions above are reentrant; a `Reassembler` instance itself is
/// single-owner — one caller drives `insert`/`expireOlderThan` at a time.
pub const Reassembler = struct {
    allocator: Allocator,
    config: ReassemblerConfig,
    entries: std.AutoHashMapUnmanaged(u16, Entry) = .empty,

    const Interval = struct { offset: u16, length: u16 };

    const Entry = struct {
        // Audit F8: `buf.len` starts at whatever the datagram's FIRST
        // fragment actually needs (not `config.max_frame_len`) and grows
        // via `ensureCapacity` only as far as later fragments require —
        // measured 3648x amplification came from allocating and
        // immediately freeing the full `max_frame_len` buffer for every
        // fragment id, even a 9-byte one.
        buf: []u8,
        // Audit F9: kept SORTED by `offset` (see `insert`'s use of
        // `std.sort.lowerBound` + `ArrayListUnmanaged.insert`), so the
        // overlap check only ever looks at the immediate neighbors of the
        // insertion point instead of scanning every previously accepted
        // interval on every fragment.
        intervals: std.ArrayListUnmanaged(Interval) = .empty,
        covered: usize = 0,
        total_len: ?usize = null,
        last_seen_ns: u64,
        created_ns: u64,

        fn deinit(self: *Entry, allocator: Allocator) void {
            allocator.free(self.buf);
            self.intervals.deinit(allocator);
        }

        /// Grow `buf` to at least `needed` bytes, amortized (doubling,
        /// capped at `max_frame_len`) — a no-op if it is already that big.
        /// `Allocator.realloc` preserves the existing bytes up to the
        /// smaller of the old/new lengths, so already-written fragment
        /// data survives a grow.
        fn ensureCapacity(self: *Entry, allocator: Allocator, needed: usize, cap: usize) Allocator.Error!void {
            if (self.buf.len >= needed) return;
            const doubled = self.buf.len * 2;
            const new_len = @min(cap, @max(needed, doubled));
            self.buf = try allocator.realloc(self.buf, new_len);
            test_f8_bytes_allocated += new_len; // A1 F8 measurement
        }
    };

    /// The effective absolute-lifetime ceiling for `config` (Audit F2):
    /// `config.max_lifetime_ns` if the caller set one, else `8 *
    /// timeout_ns` — saturating, so a `timeout_ns` near `maxInt(u64)`
    /// caps at `maxInt(u64)` rather than wrapping to something small.
    fn lifetimeCap(config: ReassemblerConfig) u64 {
        return config.max_lifetime_ns orelse (8 *| config.timeout_ns);
    }

    pub fn init(allocator: Allocator, config: ReassemblerConfig) Reassembler {
        // Audit F7: these three used to be `std.debug.assert`, which is
        // compiled OUT of ReleaseFast entirely — so an invalid config there
        // was not a controlled panic but undefined behaviour (measured:
        // SIGSEGV). An unconditional `if`+`@panic` runs — and traps — in
        // every build mode, Debug through ReleaseFast alike. This also adds
        // the ONE config-shaped field that had no check at all before:
        // `max_fragments_per_datagram == 0` used to pass `init` silently in
        // every mode and only bite on the first `insert` (allocating and
        // immediately freeing the full `max_frame_len` buffer forever,
        // Audit F7's second half).
        if (config.max_inflight < 1)
            @panic("ReassemblerConfig.max_inflight must be at least 1");
        if (config.max_frame_len < 1 or config.max_frame_len > max_frame_len)
            @panic("ReassemblerConfig.max_frame_len must be at least 1 and at most max_frame_len");
        if (config.max_fragments_per_datagram < 1)
            @panic("ReassemblerConfig.max_fragments_per_datagram must be at least 1");
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

        const lifetime_cap = lifetimeCap(self.config);
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            const idle_expired = now_ns -| kv.value_ptr.last_seen_ns > self.config.timeout_ns;
            // Audit F2: an entry that a steady trickle of fresh fragments
            // keeps continuously "not idle" is otherwise never reclaimed —
            // this is the absolute half of the check, measured from
            // `created_ns` rather than `last_seen_ns`.
            const lifetime_expired = now_ns -| kv.value_ptr.created_ns > lifetime_cap;
            if (idle_expired or lifetime_expired) {
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
    /// The two exhaustion guards return through these, so a fuzz run can say
    /// whether a guard FIRED, not just whether its line was near a seen PC.
    ///
    /// ⛔ Measured 2026-09-15 (A1 F6): a coverage query on the line
    /// `return error.TooManyFragments;` stayed HIT in a harness that cannot
    /// reach that guard, because LLVM shares error-return blocks between paths.
    /// A `noinline` function has an entry PC of its own, so
    /// `ZIGLIBS_FUZZ_REACH=fn:guardTooManyFragments scripts/modtest ethfrag --fuzz`
    /// is a real answer. Error path only, so the call costs nothing that matters.
    noinline fn guardTableFull() error{TableFull} {
        return error.TableFull;
    }

    noinline fn guardTooManyFragments() error{TooManyFragments} {
        return error.TooManyFragments;
    }

    pub fn insert(self: *Reassembler, wire_bytes: []const u8, now_ns: u64) InsertError!InsertResult {
        const hdr = try Header.decode(wire_bytes);
        const payload = wire_bytes[header_len..];
        if (payload.len != hdr.length) return error.LengthMismatch;

        if (hdr.length == 0 and hdr.more) return error.EmptyNonFinalFragment;

        const frag_end = @as(usize, hdr.offset) + @as(usize, hdr.length);
        if (frag_end > self.config.max_frame_len) return error.OutOfBounds;

        // A very late fragment for a timed-out datagram starts a fresh
        // reassembly rather than resurrecting stale bytes. Deliberately
        // idle-only, NOT the absolute lifetime cap (Audit F2) below: a
        // fragment for the SAME id that keeps the entry idle-fresh is
        // exactly the sender this codec is meant to serve (a slow but
        // legitimate multi-fragment transfer), and resetting `created_ns`
        // here every time its own age crossed the cap would let a sender
        // renew its own slot forever just by continuing to send — the same
        // failure mode F2 exists to close, one level up. The lifetime cap
        // is enforced where it actually matters: when a DIFFERENT id needs
        // the slot (`expireOlderThan`, called just below and from
        // `expireOlderThan` callers directly) — that path an incumbent
        // cannot keep triggering on itself.
        if (self.entries.getPtr(hdr.frag_id)) |e| {
            if (now_ns -| e.last_seen_ns > self.config.timeout_ns) self.dropEntry(hdr.frag_id);
        }

        if (!self.entries.contains(hdr.frag_id) and self.entries.count() >= self.config.max_inflight) {
            _ = self.expireOlderThan(now_ns);
            if (!self.entries.contains(hdr.frag_id) and self.entries.count() >= self.config.max_inflight) {
                return guardTableFull();
            }
        }

        const gop = try self.entries.getOrPut(self.allocator, hdr.frag_id);
        if (!gop.found_existing) {
            // Audit F8: size the buffer to what THIS fragment needs, not
            // to `config.max_frame_len` — `ensureCapacity` grows it later
            // if a bigger fragment for the same id arrives.
            const initial_len: usize = if (hdr.length > 0) frag_end else 0;
            const buf = self.allocator.alloc(u8, initial_len) catch |err| {
                _ = self.entries.remove(hdr.frag_id); // undo the getOrPut slot
                return err;
            };
            test_f8_bytes_allocated += initial_len; // A1 F8 measurement
            gop.value_ptr.* = .{ .buf = buf, .last_seen_ns = now_ns, .created_ns = now_ns };
        }
        const entry = gop.value_ptr;
        entry.last_seen_ns = now_ns;

        if (entry.intervals.items.len >= self.config.max_fragments_per_datagram) {
            self.dropEntry(hdr.frag_id);
            return guardTooManyFragments();
        }

        if (!hdr.more) {
            if (entry.total_len) |t| {
                if (t != frag_end) {
                    self.dropEntry(hdr.frag_id);
                    return error.ProtocolViolation;
                }
            } else {
                // Newly established total length: every interval accepted
                // BEFORE this fragment arrived was accepted while
                // `entry.total_len` was still null, so the bounds check
                // just below (`if (entry.total_len) |t| { if (frag_end > t)
                // ... }`) never ran for it -- it could freely land beyond
                // where the datagram turns out to actually end. Left
                // unchecked, its length still counts toward `covered`, so
                // `covered == total_len` can become true via bytes that
                // live OUTSIDE [0, total_len) while a real gap remains
                // INSIDE it: `.complete` would then fire and hand the
                // caller uninitialized allocator memory for that gap. This
                // is the out-of-order mirror of the teardrop-style overrun
                // already rejected below for fragments arriving AFTER
                // total_len is known -- reject it the same way, retroactively.
                for (entry.intervals.items) |iv| {
                    if (@as(usize, iv.offset) + @as(usize, iv.length) > frag_end) {
                        self.dropEntry(hdr.frag_id);
                        return error.OutOfBounds;
                    }
                }
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
        //
        // Audit F9: `entry.intervals` is kept sorted by `offset` (the
        // `.insert` below, replacing the old unconditional `.append`), so
        // accepted intervals are pairwise disjoint AND in offset order —
        // an interval overlapping ANYTHING must overlap either the
        // immediate PREDECESSOR (largest offset < hdr.offset) or one of a
        // short run of SUCCESSORS whose own offset starts before this
        // fragment ends. A non-zero-length successor in that run always
        // overlaps and is caught on the very first one checked; only
        // zero-length ties (the F1/A21 shape below) can make the run
        // longer than one, and at most one zero-length AND one non-zero
        // interval can ever share the same offset (a second attempt at
        // either is itself rejected as an overlap). This replaces an
        // unconditional scan of every previously accepted interval on
        // every fragment (O(n) per insert, O(n²) per datagram) with a
        // binary search plus a check bounded by what can actually be near
        // `hdr.offset`.
        const idx = std.sort.lowerBound(Interval, entry.intervals.items, hdr.offset, intervalOffsetOrder);

        // Audit F1 (A21): the general half-open `[offset, offset+length)`
        // overlap test degenerates to the empty set whenever BOTH sides
        // have zero length — an empty range never intersects anything,
        // including an identical empty range at the same offset — so a
        // `more=false, length=0` fragment (the one legitimate use: closing
        // an all-empty frame) could be resent and accepted a second time
        // under the SAME id. `more=true` zero-length fragments are already
        // rejected outright above (`EmptyNonFinalFragment`), so only the
        // `more=false` case can still reach here; `intervalOverlaps` closes
        // it without touching length > 0 behaviour at all (an exact
        // non-zero-length duplicate already self-overlaps under the
        // ordinary test).
        if (idx > 0 and intervalOverlaps(hdr.offset, hdr.length, frag_end, entry.intervals.items[idx - 1])) {
            self.dropEntry(hdr.frag_id);
            return error.OverlappingFragment;
        }
        // `<=`, not `<`: a zero-length new fragment has `frag_end ==
        // hdr.offset`, and an existing zero-length interval at that exact
        // offset sorts at `idx` itself (not `idx - 1`) since lowerBound's
        // `>=` comparison places offset TIES at or after `idx` — so the
        // A21 same-offset-zero-length duplicate must still be in range
        // here. A real (non-zero-length) neighbor landing exactly at
        // `frag_end` is harmless to include: `intervalOverlaps` correctly
        // says "no" for two ranges that only touch at an endpoint.
        var succ = idx;
        while (succ < entry.intervals.items.len and
            @as(usize, entry.intervals.items[succ].offset) <= frag_end) : (succ += 1)
        {
            if (intervalOverlaps(hdr.offset, hdr.length, frag_end, entry.intervals.items[succ])) {
                self.dropEntry(hdr.frag_id);
                return error.OverlappingFragment;
            }
        }

        if (hdr.length > 0) {
            entry.ensureCapacity(self.allocator, frag_end, self.config.max_frame_len) catch |err| {
                self.dropEntry(hdr.frag_id);
                return err;
            };
            @memcpy(entry.buf[hdr.offset..frag_end], payload);
        }
        entry.intervals.insert(self.allocator, idx, .{ .offset = hdr.offset, .length = hdr.length }) catch |err| {
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

test "fragment: a header_overhead that overflows usize is a typed error, not a panic" {
    // Audit F1. `header_overhead + header_len` used to be a plain checked add
    // evaluated BEFORE any bound on `header_overhead`, so these calls aborted
    // with "integer overflow" in Debug/ReleaseSafe instead of returning an
    // error the caller can handle (and were UB in ReleaseFast).
    const max = std.math.maxInt(usize);
    try testing.expectError(error.MtuTooSmall, fragment(testing.allocator, "x", 0, 1500, max));
    // The exact boundary: the largest overhead that still fits, and the
    // smallest that does not. `max - header_len` sums to exactly `max`, which
    // is representable — so it must be rejected for the ORDINARY reason (it is
    // >= any carrier_mtu), and one more must be rejected for the new one.
    try testing.expectError(error.MtuTooSmall, fragment(testing.allocator, "x", 0, 1500, max - header_len));
    try testing.expectError(error.MtuTooSmall, fragment(testing.allocator, "x", 0, 1500, max - header_len + 1));

    // Not over-tight: a large-but-sane overhead that still leaves payload room
    // continues to work, so the guard did not turn into a blanket refusal.
    const frags = try fragment(testing.allocator, "hello", 0, 4096, 1024);
    defer freeFragments(testing.allocator, frags);
    try testing.expectEqual(@as(usize, 1), frags.len);
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

test "reassembler rejects a fragment retroactively found to exceed a LATER-established total length (out-of-order teardrop mirror, regression)" {
    // Real bug, found while designing this file's kernel-oracle teeth
    // check (not a hypothetical): a fragment accepted BEFORE any more=false
    // fragment has arrived is accepted while entry.total_len is still
    // null, so the `if (entry.total_len) |t| { if (frag_end > t) ... }`
    // bounds check never runs for it. If a LATER more=false fragment then
    // establishes a total_len smaller than that earlier fragment's own end,
    // the earlier fragment's length still counted toward `covered` even
    // though its bytes live entirely OUTSIDE [0, total_len). `covered` can
    // then reach `total_len` via bytes from outside the frame while a real
    // gap remains inside it, and `.complete` fired over that gap --
    // handing the caller uninitialized allocator memory for the hole.
    // Confirmed via reproduction before the fix: the returned "complete"
    // 100-byte frame was 30 bytes of 'D', 50 bytes of allocator poison
    // (0xaa, from the never-written gap), then 20 bytes of 'C'.
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .max_frame_len = 200, .timeout_ns = 1000 });
    defer r.deinit();

    // Fragment A: offset=150, length=50, more=true -- arrives while
    // total_len is still unknown, so nothing bounds-checks it yet.
    var a: [header_len + 50]u8 = undefined;
    (Header{ .frag_id = 77, .offset = 150, .length = 50, .more = true }).encode(a[0..header_len]);
    @memset(a[header_len..], 'A');
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&a, 0));

    // Fragment D: offset=0, length=30, more=true -- non-overlapping with A.
    var d: [header_len + 30]u8 = undefined;
    (Header{ .frag_id = 77, .offset = 0, .length = 30, .more = true }).encode(d[0..header_len]);
    @memset(d[header_len..], 'D');
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&d, 1));

    // Fragment C: offset=80, length=20, more=false -- establishes
    // total_len=100. Non-overlapping with A ([150,200)) or D ([0,30)).
    // Before the fix: covered = 50+30+20 = 100 == total_len -> wrongly
    // ".complete" with bytes [30,80) never written. After the fix: A's
    // interval ([150,200)) is checked against the newly-established
    // total_len (100) the moment it is set, found to exceed it, and the
    // whole datagram is dropped instead.
    var c: [header_len + 20]u8 = undefined;
    (Header{ .frag_id = 77, .offset = 80, .length = 20, .more = false }).encode(c[0..header_len]);
    @memset(c[header_len..], 'C');
    try testing.expectError(error.OutOfBounds, r.insert(&c, 2));
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

test "A1 F9: overlap-check work grows near-linearithmically with fragment count, not quadratically" {
    // Audit's own scaling shape: n=256 vs n=4096 (16x), all fragments
    // valid, non-overlapping, densely packed -- exactly what made the OLD
    // unconditional full-interval-list scan cost n^2/2 comparisons per
    // datagram (measured 56x wall-clock for this same 16x growth).
    // `test_f9_overlap_checks` counts every call to `intervalOverlaps`,
    // which is now bounded by a binary search plus a short neighbor run
    // instead of the whole list -- a timing-free, deterministic proxy for
    // the work `insert` does, immune to machine noise.
    const Case = struct { n: u16, checks: usize };
    var cases: [2]Case = .{ .{ .n = 256, .checks = 0 }, .{ .n = 4096, .checks = 0 } };
    for (&cases) |*c| {
        var r = Reassembler.init(testing.allocator, .{
            .max_inflight = 1,
            .max_fragments_per_datagram = @as(usize, c.n) + 1,
            .max_frame_len = @as(usize, c.n) + 1,
            .timeout_ns = 1_000_000_000,
        });
        defer r.deinit();
        test_f9_overlap_checks = 0;
        var offset: u16 = 0;
        var i: u16 = 0;
        while (i < c.n) : (i += 1) {
            var buf: [header_len + 1]u8 = undefined;
            (Header{ .frag_id = 1, .offset = offset, .length = 1, .more = true }).encode(buf[0..header_len]);
            buf[header_len] = 'x';
            _ = try r.insert(&buf, i);
            offset += 1;
        }
        c.checks = test_f9_overlap_checks;
    }
    const ratio_n = @as(f64, @floatFromInt(cases[1].n)) / @as(f64, @floatFromInt(cases[0].n));
    const ratio_checks = @as(f64, @floatFromInt(cases[1].checks)) / @as(f64, @floatFromInt(cases[0].checks));
    // Diagnostic only. The lane turns stderr from a PASSING test into a FAIL
    // (scripts/test-lib.sh), so the number is opt-in; the assertion below runs
    // either way.
    if (std.process.Environ.getPosix(std.testing.environ, "ETHFRAG_VERBOSE") != null) {
        std.debug.print(
            "A1 F9: n={d}->{d} ({d:.0}x fragments) overlap checks {d}->{d} ({d:.1}x) -- audit's OLD unbounded scan measured 56x WALL-CLOCK for this same 16x growth\n",
            .{ cases[0].n, cases[1].n, ratio_n, cases[0].checks, cases[1].checks, ratio_checks },
        );
    }
    // A true O(n^2) scan gives ratio_checks ~= ratio_n^2 (256x for 16x).
    // This must land far below that -- 4x the LINEAR ratio is generous
    // slack and still cleanly separates "still quadratic" from "fixed".
    try testing.expect(ratio_checks < ratio_n * 4.0);
}

test "A1 F8: repeated overlap-drop churn allocates the fragment's OWN size, not max_frame_len" {
    // Audit's own churn shape: the same tiny fragment inserted repeatedly
    // under one frag_id, every other insert an exact duplicate -> dropped
    // as OverlappingFragment -> the entry is torn down and rebuilt fresh
    // on the next insert. Measured (churn.zig, `A1/ethfrag.md` F8):
    // 450,000 B of wire traffic (50,000 x 9 B) forced 1,641,675,624 B of
    // allocate-then-immediately-free churn, because every entry ate the
    // full `max_frame_len` (65535 B) regardless of the fragment's own
    // 9-byte size -- a 3648x amplification.
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1_000_000_000 });
    defer r.deinit();

    var buf: [header_len + 9]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 0, .length = 9, .more = true }).encode(buf[0..header_len]);
    @memset(buf[header_len..], 0xAB);

    test_f8_bytes_allocated = 0;
    const inserts = 50_000;
    var i: usize = 0;
    while (i < inserts) : (i += 1) {
        _ = r.insert(&buf, @intCast(i)) catch {}; // every other call is the duplicate -> OverlappingFragment
    }
    if (std.process.Environ.getPosix(std.testing.environ, "ETHFRAG_VERBOSE") != null) {
        std.debug.print(
            "A1 F8: {d} inserts of a 9 B fragment (churn) allocated {d} B total -- audit measured 1,641,675,624 B for the same 50,000-insert shape before this fix\n",
            .{ inserts, test_f8_bytes_allocated },
        );
    }
    // Each create-or-recreate needs exactly 9 bytes; the OLD code needed
    // 65535 for every single one (450,000 B total requested here would
    // have become ~3.3 GB). Generous slack (20 B/insert) still separates
    // "sized to the fragment" from "sized to max_frame_len" by 3 orders
    // of magnitude.
    try testing.expect(test_f8_bytes_allocated < inserts * 20);
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

// ── audit regressions: F1, F2, F3 boundaries, F14 ──────────────────────────

test "F1/A3: a non-final zero-length fragment is rejected outright, not silently accepted" {
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 });
    defer r.deinit();

    var buf: [header_len]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 10, .length = 0, .more = true }).encode(&buf);
    try testing.expectError(error.EmptyNonFinalFragment, r.insert(&buf, 0));
    try testing.expectEqual(@as(usize, 0), r.inflightCount());
}

test "F1/A3b: the same zero-length fragment resent 6 times is rejected every time, not accepted every time" {
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1_000_000 });
    defer r.deinit();

    var buf: [header_len]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 10, .length = 0, .more = true }).encode(&buf);
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        try testing.expectError(error.EmptyNonFinalFragment, r.insert(&buf, @intCast(i)));
    }
    try testing.expectEqual(@as(usize, 0), r.inflightCount());
}

test "F1/A21: two final zero-length fragments claiming the same end are not both accepted" {
    // Unlike A3/A3b these are `more = false` -- the one legitimate shape a
    // zero-length fragment has (closing an all-empty frame) -- so they are
    // not caught by the EmptyNonFinalFragment check above. The general
    // half-open overlap test degenerates to the empty set for a
    // zero-length-vs-zero-length comparison (an empty range never
    // intersects an identical empty range), so before the fix the second
    // one was accepted right alongside the first.
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 });
    defer r.deinit();

    var first: [header_len]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 50, .length = 0, .more = false }).encode(&first);
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&first, 0));
    try testing.expectEqual(@as(usize, 1), r.inflightCount());

    var second: [header_len]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 50, .length = 0, .more = false }).encode(&second);
    try testing.expectError(error.OverlappingFragment, r.insert(&second, 1));
    try testing.expectEqual(@as(usize, 0), r.inflightCount());
}

test "F1/A29 (no regression): a zero-length fragment at an offset a later real fragment starts at still reassembles" {
    // The fix must not turn this legitimate sequence into a false-positive
    // overlap: a length-0 point at offset 0 carries no bytes, so it cannot
    // truly conflict with a REAL fragment that later claims [0, 50).
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 });
    defer r.deinit();

    var zero: [header_len]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 0, .length = 0, .more = true }).encode(&zero);
    try testing.expectError(error.EmptyNonFinalFragment, r.insert(&zero, 0));

    var frame: [50]u8 = undefined;
    for (&frame, 0..) |*b, i| b.* = @truncate(i);
    var real: [header_len + 50]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 0, .length = 50, .more = false }).encode(real[0..header_len]);
    @memcpy(real[header_len..], &frame);
    const res = try r.insert(&real, 1);
    switch (res) {
        .complete => |bytes| {
            defer testing.allocator.free(bytes);
            try testing.expectEqualSlices(u8, &frame, bytes);
        },
        .incomplete => return error.TestUnexpectedResult,
    }
}

test "F2: an absolute lifetime cap reclaims an entry that a steady trickle of accepted fragments keeps idle-fresh forever" {
    // Audit F2 (HIGH). `entry.last_seen_ns` refreshes on every ACCEPTED
    // fragment and the only expiry check used to be idle time since
    // `last_seen_ns` -- there was no cap on total age. 100 fragments, each
    // covering a fresh, non-overlapping single byte (nothing here is a
    // duplicate or malformed -- every one is individually legitimate), 10ns
    // apart -- always well inside `timeout_ns = 100` -- total 1000ns
    // elapsed, which crosses the default absolute cap (8 * timeout_ns =
    // 800ns) even though idle time never once did.
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 1, .timeout_ns = 100 });
    defer r.deinit();

    var now: u64 = 0;
    var offset: u16 = 0;
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var buf: [header_len + 1]u8 = undefined;
        (Header{ .frag_id = 1, .offset = offset, .length = 1, .more = true }).encode(buf[0..header_len]);
        buf[header_len] = 'x';
        now += 10;
        offset += 1;
        _ = try r.insert(&buf, now);
    }
    try testing.expectEqual(@as(usize, 1), r.inflightCount());

    // A distinct, legitimate frag_id must not starve forever just because
    // the incumbent keeps refreshing itself.
    var other: [header_len + 1]u8 = undefined;
    (Header{ .frag_id = 2, .offset = 0, .length = 1, .more = true }).encode(other[0..header_len]);
    other[header_len] = 'y';
    now += 10;
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&other, now));
}

test "F3/M8-shape: overlap is checked against every interval, not just the most recently accepted one" {
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 });
    defer r.deinit();

    var first: [header_len + 10]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 0, .length = 10, .more = true }).encode(first[0..header_len]);
    @memset(first[header_len..], 'a');
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&first, 0));

    var second: [header_len + 10]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 20, .length = 10, .more = true }).encode(second[0..header_len]);
    @memset(second[header_len..], 'b');
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&second, 1));

    // Overlaps the FIRST interval ([0,10)), not the most recently accepted
    // one ([20,30)) -- a scan that only compared against the last interval
    // would miss this.
    var third: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 5, .length = 5, .more = true }).encode(third[0..header_len]);
    @memset(third[header_len..], 'c');
    try testing.expectError(error.OverlappingFragment, r.insert(&third, 2));
    try testing.expectEqual(@as(usize, 0), r.inflightCount());
}

test "F3/M1-shape: a one-byte overlap is rejected, not just a large one" {
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 });
    defer r.deinit();

    var first: [header_len + 10]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 0, .length = 10, .more = true }).encode(first[0..header_len]);
    @memset(first[header_len..], 'a');
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&first, 0));

    // [9, 19) overlaps [0, 10) by exactly one byte (offset 9).
    var second: [header_len + 10]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 9, .length = 10, .more = true }).encode(second[0..header_len]);
    @memset(second[header_len..], 'b');
    try testing.expectError(error.OverlappingFragment, r.insert(&second, 1));
    try testing.expectEqual(@as(usize, 0), r.inflightCount());
}

test "F3/M2b-shape: frag_end exactly at max_frame_len is accepted, one past it is rejected" {
    var accepted = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .max_frame_len = 16, .timeout_ns = 1000 });
    defer accepted.deinit();
    var at_limit: [header_len + 6]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 10, .length = 6, .more = true }).encode(at_limit[0..header_len]);
    @memset(at_limit[header_len..], 'a');
    // frag_end = 16 == max_frame_len: must be accepted.
    try testing.expectEqual(InsertResult.incomplete, try accepted.insert(&at_limit, 0));
    try testing.expectEqual(@as(usize, 1), accepted.inflightCount());

    var rejected = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .max_frame_len = 16, .timeout_ns = 1000 });
    defer rejected.deinit();
    var over_limit: [header_len + 7]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 10, .length = 7, .more = true }).encode(over_limit[0..header_len]);
    @memset(over_limit[header_len..], 'a');
    // frag_end = 17 == max_frame_len + 1: must be rejected.
    try testing.expectError(error.OutOfBounds, rejected.insert(&over_limit, 0));
    try testing.expectEqual(@as(usize, 0), rejected.inflightCount());
}

test "F14: trailing bytes beyond the header's declared length are rejected, the same as too few" {
    // SPEC.md and the doc comment on `LengthMismatch` both promise BOTH
    // directions ("too few ... too many ... both rejected"), but the only
    // existing test drove the too-few direction. `payload.len != hdr.length`
    // is already symmetric in the code; this closes the coverage gap the
    // doc promise had, in both directions at once.
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 });
    defer r.deinit();

    // Header claims 3 payload bytes; 10 are actually present.
    var too_many: [header_len + 10]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 0, .length = 3, .more = false }).encode(too_many[0..header_len]);
    try testing.expectError(error.LengthMismatch, r.insert(&too_many, 0));
    try testing.expectEqual(@as(usize, 0), r.inflightCount());

    // Header claims 10; only 3 present (the pre-existing direction, kept
    // here so both directions live in one place).
    var too_few: [header_len + 3]u8 = undefined;
    (Header{ .frag_id = 2, .offset = 0, .length = 10, .more = false }).encode(too_few[0..header_len]);
    try testing.expectError(error.LengthMismatch, r.insert(&too_few, 0));
    try testing.expectEqual(@as(usize, 0), r.inflightCount());
}

test "F3/M4b-shape: idle time exactly equal to timeout_ns has not yet expired" {
    // `now_ns -| last_seen_ns > timeout_ns` -- a gap of EXACTLY timeout_ns
    // must still count as "not yet expired" (strict >, not >=). Two
    // non-overlapping fragments for the same id, the second arriving
    // exactly timeout_ns after the first, must land in the SAME entry (and
    // so go on to complete the datagram) rather than starting a fresh one.
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 100 });
    defer r.deinit();

    var a: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 0, .length = 5, .more = true }).encode(a[0..header_len]);
    @memset(a[header_len..], 'A');
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&a, 0));

    var b: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 5, .length = 5, .more = false }).encode(b[0..header_len]);
    @memset(b[header_len..], 'B');
    // now = 100 = last_seen(0) + timeout_ns exactly.
    const res = try r.insert(&b, 100);
    switch (res) {
        .complete => |bytes| {
            defer testing.allocator.free(bytes);
            try testing.expectEqualSlices(u8, "AAAAABBBBB", bytes);
        },
        .incomplete => return error.TestUnexpectedResult,
    }
}

test "F16: the sweep's idle check has the same strict boundary as insert's" {
    // Audit F2 added a SECOND copy of `now_ns -| last_seen_ns > timeout_ns`,
    // in `expireOlderThan`; the test above only reaches the copy in
    // `insert`. A gap of exactly timeout_ns must not expire here either,
    // and one nanosecond more must.
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 100 });
    defer r.deinit();

    var a: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 0, .length = 5, .more = true }).encode(a[0..header_len]);
    @memset(a[header_len..], 'A');
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&a, 0));

    try testing.expectEqual(@as(usize, 0), r.expireOlderThan(100));
    try testing.expectEqual(@as(u32, 1), r.entries.count());
    try testing.expectEqual(@as(usize, 1), r.expireOlderThan(101));
    try testing.expectEqual(@as(u32, 0), r.entries.count());
}

test "F3/M6-shape: a retroactively-checked interval that lands exactly at the newly-established total_len is accepted, one past it is not" {
    // Companion to the existing out-of-order teardrop-mirror regression
    // test, which uses a margin of 50 bytes past total_len. This pins the
    // exact boundary the retroactive check (`iv.offset + iv.length >
    // frag_end`) draws: landing exactly AT the newly-established end must
    // be accepted, one byte past it must not.
    var fits = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .max_frame_len = 200, .timeout_ns = 1000 });
    defer fits.deinit();
    // A: [150, 200) -- arrives before total_len is known.
    var a1: [header_len + 50]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 150, .length = 50, .more = true }).encode(a1[0..header_len]);
    @memset(a1[header_len..], 'A');
    try testing.expectEqual(InsertResult.incomplete, try fits.insert(&a1, 0));
    // C: a zero-length final fragment at offset 200 establishes total_len =
    // 200 exactly without overlapping A's [150,200) (a zero-length point at
    // an existing interval's END does not overlap it under the ordinary
    // half-open test -- only an exact zero-length duplicate does, Audit
    // F1). A's interval fits [150,200) precisely under this total_len.
    var c1: [header_len]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 200, .length = 0, .more = false }).encode(&c1);
    try testing.expectEqual(InsertResult.incomplete, try fits.insert(&c1, 1));
    try testing.expectEqual(@as(usize, 1), fits.inflightCount());

    var overshoots = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .max_frame_len = 300, .timeout_ns = 1000 });
    defer overshoots.deinit();
    // A: [150, 201) -- one byte past where C below will establish the end.
    var a2: [header_len + 51]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 150, .length = 51, .more = true }).encode(a2[0..header_len]);
    @memset(a2[header_len..], 'A');
    try testing.expectEqual(InsertResult.incomplete, try overshoots.insert(&a2, 0));
    var c2: [header_len]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 200, .length = 0, .more = false }).encode(&c2);
    try testing.expectError(error.OutOfBounds, overshoots.insert(&c2, 1));
    try testing.expectEqual(@as(usize, 0), overshoots.inflightCount());
}

test "F3/M7-shape: a second more=false claiming a SMALLER end is rejected too, not just a larger one" {
    // The existing "contradictory more=false" test only drives the second
    // claim LARGER than the first (105 then 205). `t != frag_end` is
    // already symmetric in the code; this pins the other direction so a
    // one-sided mutation (`frag_end > t` instead of `frag_end != t`) would
    // be caught.
    var r = Reassembler.init(testing.allocator, .{ .max_inflight = 4, .timeout_ns = 1000 });
    defer r.deinit();

    var a: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 0, .length = 5, .more = true }).encode(a[0..header_len]);
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&a, 0));

    var b: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 195, .length = 5, .more = false }).encode(b[0..header_len]);
    try testing.expectEqual(InsertResult.incomplete, try r.insert(&b, 1));

    // A second "final" fragment claiming a SMALLER end (100) than the
    // first (200).
    var c: [header_len + 5]u8 = undefined;
    (Header{ .frag_id = 1, .offset = 95, .length = 5, .more = false }).encode(c[0..header_len]);
    try testing.expectError(error.ProtocolViolation, r.insert(&c, 2));
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
    try testing.fuzz({}, fuzzReassembler, .{ .corpus = &reassembler_seeds });
}

/// `testkit.fuzz` — see that module for why a corpus entry is not the frame.
const tkfuzz = @import("testkit").fuzz;
const seed = tkfuzz.seedHex;

/// Fragment-stream scripts in the format `Smith.slice` reads.
///
/// ⛔ This target drives a state machine, so what has to come out of the byte
/// draw is a SCRIPT, read with a `testkit.fuzz.Cursor`:
///
///     NN                        step count, 0..64
///     per step:
///       TT TT                   time advance: `% 64` ns for a burst, else `% 2001` ns
///       BB                      bit 0: 1 = a structured fragment, 0 = raw bytes
///                               bits 0+1 both set: a BURST fragment (see below)
///       structured: II OO OO LL MM PP   frag_id %8, offset, len %33, more, payload fill
///       burst:      II SS LL PP         frag_id %8, offset = (SS %64)*8, len 1+LL%8, fill; more = 1
///       raw:        LL PP               length % 41, fill
///
/// The reassembler's `timeout_ns` is 1000, so a time advance above that is
/// what expires an in-flight datagram; `max_inflight` is 4, so five distinct
/// `frag_id`s is what exercises the eviction path.
///
/// ⭐ Why the burst kind exists (A1 F6, measured 2026-09-15 through
/// `scripts/modtest ethfrag --fuzz`): the `max_fragments_per_datagram` guard
/// needs 16 accepted, pairwise-disjoint fragments of ONE id with no idle gap
/// above `timeout_ns`. The structured kind draws `offset` as a full `u16`
/// against a 512-octet frame and advances time by up to 2000 ns per step, so
/// `guardTooManyFragments` was reached 0 times in 200 151 coverage-guided runs
/// while `guardTableFull` was reached. A burst keeps the clock inside the
/// timeout, puts every fragment inside the frame on an 8-octet grid (so two
/// fragments overlap only when they pick the same slot), and never closes the
/// datagram. The structured and raw kinds are unchanged: bytes `00`/`01` in
/// `BB` read exactly as before, so every seed below keeps its meaning.
const reassembler_seeds = [_][]const u8{
    // Two halves of one 32-octet datagram, same frag_id, no gap: completes.
    seed("02" ++ "0000" ++ "01" ++ "00" ++ "0000" ++ "10" ++ "01" ++ "AA" ++
        "0000" ++ "01" ++ "00" ++ "0010" ++ "10" ++ "00" ++ "BB"),
    // The same two fragments with the LAST one first — out-of-order arrival.
    seed("02" ++ "0000" ++ "01" ++ "00" ++ "0010" ++ "10" ++ "00" ++ "BB" ++
        "0000" ++ "01" ++ "00" ++ "0000" ++ "10" ++ "01" ++ "AA"),
    // The same first fragment twice: an exact duplicate, then an overlap at
    // offset 8 that disagrees with it.
    seed("03" ++ "0000" ++ "01" ++ "00" ++ "0000" ++ "10" ++ "01" ++ "AA" ++
        "0000" ++ "01" ++ "00" ++ "0000" ++ "10" ++ "01" ++ "AA" ++
        "0000" ++ "01" ++ "00" ++ "0008" ++ "10" ++ "01" ++ "CC"),
    // Five distinct frag_ids with nothing completing them: `max_inflight` is
    // 4, so this is the eviction path.
    seed("05" ++ "0000" ++ "01" ++ "00" ++ "0000" ++ "08" ++ "01" ++ "11" ++
        "0000" ++ "01" ++ "01" ++ "0000" ++ "08" ++ "01" ++ "22" ++
        "0000" ++ "01" ++ "02" ++ "0000" ++ "08" ++ "01" ++ "33" ++
        "0000" ++ "01" ++ "03" ++ "0000" ++ "08" ++ "01" ++ "44" ++
        "0000" ++ "01" ++ "04" ++ "0000" ++ "08" ++ "01" ++ "55"),
    // One fragment, then a 2000 ns jump past `timeout_ns`, then its partner:
    // the first must have expired, so nothing completes.
    seed("02" ++ "0000" ++ "01" ++ "00" ++ "0000" ++ "10" ++ "01" ++ "AA" ++
        "07D0" ++ "01" ++ "00" ++ "0010" ++ "10" ++ "00" ++ "BB"),
    // An offset of 0xFFFF against a 512-octet `max_frame_len`.
    seed("01" ++ "0000" ++ "01" ++ "00" ++ "FFFF" ++ "10" ++ "01" ++ "AA"),
    // Raw bytes: a buffer shorter than the 8-octet header, then a full one.
    seed("02" ++ "0000" ++ "00" ++ "03" ++ "EE" ++ "0000" ++ "00" ++ "28" ++ "FF"),
    // The maximum step count, alternating structured and raw.
    seed("40" ++ ("0001" ++ "01" ++ "00" ++ "0000" ++ "08" ++ "01" ++ "77" ++
        "0001" ++ "00" ++ "20" ++ "88") ** 8),
    // ⭐ A burst of 17 fragments of one id, 1 ns apart, on slots 0..16 of the
    // 8-octet grid: 16 are accepted disjoint, the 17th trips
    // `max_fragments_per_datagram`. The only seed that reaches that guard.
    seed("11" ++
        "0001" ++ "03" ++ "00" ++ "00" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "01" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "02" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "03" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "04" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "05" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "06" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "07" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "08" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "09" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "0A" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "0B" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "0C" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "0D" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "0E" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "0F" ++ "07" ++ "AB" ++
        "0001" ++ "03" ++ "00" ++ "10" ++ "07" ++ "AB"),
    seed(""), // 0 steps: the state machine's whole history until today
};

/// One step's worth of the script, applied to `r`. Shared with the corpus
/// guard so the guard cannot drive a different state machine.
/// How many times each exhaustion guard refused a fragment. Only the corpus
/// guard reads it; the fuzz target passes `null`.
const GuardTally = struct {
    table_full: usize = 0,
    too_many_fragments: usize = 0,

    fn note(self: *GuardTally, err: InsertError) void {
        if (err == error.TableFull) self.table_full += 1;
        if (err == error.TooManyFragments) self.too_many_fragments += 1;
    }
};

fn fuzzReassemblerStep(r: *Reassembler, cur: *tkfuzz.Cursor, now: *u64, tally: ?*GuardTally) !?[]u8 {
    // The advance is READ before the kind byte, as it always was, and applied
    // after it, so a seed written before the burst kind existed consumes the
    // same octets in the same order.
    const advance = cur.word();
    const kind = cur.byte();
    const burst = kind & 3 == 3;
    now.* += if (burst) advance % 64 else advance % 2001;
    if (burst) {
        var wire: [header_len + 8]u8 = undefined;
        const frag_id: u16 = @intCast(cur.ranged(0, 7));
        const offset: u16 = @intCast(cur.ranged(0, 63) * 8);
        const len: u16 = @intCast(cur.ranged(1, 8));
        const fill = cur.byte();
        const hdr: Header = .{ .frag_id = frag_id, .offset = offset, .length = len, .more = true };
        hdr.encode(wire[0..header_len]);
        @memset(wire[header_len..][0..len], fill);
        const result = r.insert(wire[0 .. header_len + len], now.*) catch |err| {
            if (tally) |t| t.note(err);
            return null;
        };
        return switch (result) {
            .incomplete => null,
            .complete => |bytes| bytes,
        };
    }
    if (kind & 1 == 1) {
        // A structurally valid-but-hostile fragment: small frag_id range
        // to force id collisions/overlaps, arbitrary offset/length/more/
        // payload.
        var wire: [header_len + 32]u8 = undefined;
        const frag_id: u16 = @intCast(cur.ranged(0, 7));
        const offset: u16 = cur.word();
        const len: u16 = @intCast(cur.ranged(0, 32));
        const more = cur.byte() & 1 == 1;
        const fill = cur.byte();
        const hdr: Header = .{ .frag_id = frag_id, .offset = offset, .length = len, .more = more };
        hdr.encode(wire[0..header_len]);
        @memset(wire[header_len..][0..len], fill);
        const result = r.insert(wire[0 .. header_len + len], now.*) catch |err| {
            if (tally) |t| t.note(err);
            return null;
        };
        return switch (result) {
            .incomplete => null,
            .complete => |bytes| bytes,
        };
    }
    // Fully arbitrary bytes, including too-short buffers — exercises
    // Header.decode's Truncated/InvalidHeader paths directly.
    var raw: [header_len + 32]u8 = undefined;
    const len: usize = cur.ranged(0, header_len + 32);
    const fill = cur.byte();
    @memset(raw[0..len], fill);
    const result = r.insert(raw[0..len], now.*) catch |err| {
        if (tally) |t| t.note(err);
        return null;
    };
    return switch (result) {
        .incomplete => null,
        .complete => |bytes| bytes,
    };
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

    var script: [1024]u8 = undefined;
    // ⚠ The script comes out of ONE `smith.slice` call, and it is the FIRST
    // draw. The step count used to be `smith.valueRangeAtMost(u8, 0, 64)` — a
    // ranged draw, which reads eight octets as a little-endian u64 and returns
    // the range MINIMUM unless that whole word lands inside the range. It was
    // therefore **0 on every replay**, so the loop below never executed once:
    // the reassembler was constructed, immediately destroyed, and handed
    // NOTHING, and the `inflightCount() <= max_inflight` assertion this test is
    // named for never ran either. Measured 2026-09-07 over the corpus above:
    // **0 steps run, 0 datagrams completed and a peak in-flight count
    // of 0 before; 81 steps run, 3 datagrams completed and a peak of 4 after.**
    const n: usize = smith.slice(&script);
    var cur: tkfuzz.Cursor = .{ .bytes = script[0..n] };

    var now: u64 = 0;
    const steps = cur.ranged(0, 64);
    var step: u32 = 0;
    while (step < steps) : (step += 1) {
        if (try fuzzReassemblerStep(&r, &cur, &now, null)) |bytes| testing.allocator.free(bytes);
        try testing.expect(r.inflightCount() <= max_inflight);
    }
}

test "corpus: every script drives the reassembler, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment.
    //
    // ⚠ For a state-machine harness "it did not crash" is 100% on a harness
    // that runs zero steps — which is exactly what this one did. The numbers
    // that carry information are steps executed, datagrams completed, and the
    // peak in-flight count, and all three are 0 for the collapsed draw.
    const max_inflight: usize = 4;
    var steps_run: usize = 0;
    var completed: usize = 0;
    var peak_inflight: usize = 0;
    var guards: GuardTally = .{};
    for (reassembler_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [1024]u8 = undefined;
        const n: usize = smith.slice(&script);
        var cur: tkfuzz.Cursor = .{ .bytes = script[0..n] };

        var r = Reassembler.init(testing.allocator, .{
            .max_inflight = max_inflight,
            .max_frame_len = 512,
            .max_fragments_per_datagram = 16,
            .timeout_ns = 1000,
        });
        defer r.deinit();

        var now: u64 = 0;
        const steps = cur.ranged(0, 64);
        var step: u32 = 0;
        while (step < steps) : (step += 1) {
            steps_run += 1;
            if (try fuzzReassemblerStep(&r, &cur, &now, &guards)) |bytes| {
                completed += 1;
                testing.allocator.free(bytes);
            }
            try testing.expect(r.inflightCount() <= max_inflight);
            peak_inflight = @max(peak_inflight, r.inflightCount());
        }
    }
    // Measured 2026-09-07: with the step count drawn as a ranged value, 0
    // steps, 0 completions and a peak in-flight count of 0 — the loop body
    // had never executed. After:
    // 2026-09-15 (A1 F6): +17 steps from the burst seed; the older seeds'
    // numbers are unchanged, which is the check that the burst kind did not
    // change what an existing script means.
    try testing.expectEqual(@as(usize, 81 + 17), steps_run);
    try testing.expectEqual(@as(usize, 3), completed);
    try testing.expectEqual(max_inflight, peak_inflight);
    // Both exhaustion guards, by seed: the five-ids seed fills the table, the
    // burst seed exceeds the per-datagram fragment cap.
    try testing.expectEqual(@as(usize, 1), guards.table_full);
    try testing.expectEqual(@as(usize, 1), guards.too_many_fragments);
}

test {
    // External anchor: real Linux kernel IPv4/IPv6 fragment reassembly,
    // captured once and frozen (see kernel_oracle.zig's module doc-comment).
    _ = @import("kernel_oracle.zig");
}
