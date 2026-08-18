// SPDX-License-Identifier: MIT

//! transport.zig — WireGuard **transport data** (type 4) seal/open: the data
//! plane that `handshake.zig` exists to key. One outbound IP packet becomes one
//! `AEAD(T_send, nonce(counter), pad16(packet), ε)` message; one inbound message
//! becomes one plaintext, after a sliding-window anti-replay check.
//!
//! Wire format (whitepaper §5.4.6, "Subsequent Messages: Transport Data
//! Messages") — 16-byte header, then ciphertext ‖ tag:
//!
//! ```
//!   offset  size  field
//!   0       1     type = 4
//!   1       3     reserved, zero          } read/written together as one
//!   0       4     …i.e. u32 4 little-endian, per wireguard-go and the kernel
//!   4       4     receiver_index (u32 LE) — the PEER's session index
//!   8       8     counter        (u64 LE) — per-direction, monotonic
//!   16      N     ciphertext (N = the zero-padded plaintext length, N % 16 == 0)
//!   16+N    16    Poly1305 tag
//! ```
//!
//! Four details decide interoperability, and each is anchored by a test below:
//!
//! 1. **Nonce = 4 zero bytes ‖ counter as 8 bytes LITTLE-endian.** Not
//!    big-endian, and the leading 4 bytes are always zero. A nonce that is
//!    wrong the same way on both ends round-trips perfectly and fails against
//!    every real peer, so the layout is pinned to fixed expected bytes
//!    ("nonce layout is byte-exact…" below), not merely round-tripped.
//! 2. **The AAD is empty.** The header is NOT authenticated as associated data:
//!    the counter is bound to the ciphertext through the nonce instead, and the
//!    receiver index is only a demultiplexing hint (flipping it selects a
//!    different session, whose key then fails to authenticate).
//! 3. **The plaintext is zero-padded to a multiple of 16 before encryption**,
//!    so packet lengths leak less. `paddedLen(0) == 0` — a keepalive is a
//!    32-byte message with an empty plaintext, not a 48-byte one.
//! 4. **The receiver does NOT learn the true length from the padding.** `open`
//!    returns the *padded* plaintext length; the real datagram length comes
//!    from the inner packet's own header (IPv4 `total_length` / IPv6
//!    `payload_length`), which is the caller's routing layer's business, not
//!    this codec's.
//!
//! Send and receive keys are DIFFERENT (`Handshake.deriveTransportKeys` returns
//! both) and each direction has its own counter. `Session` exists so that pair
//! cannot be swapped by accident: it is built from the handshake's own output
//! plus the two session indices, and the two halves are separate types with
//! separate methods.
//!
//! Zero allocation: every entry point writes into a caller-supplied buffer, and
//! the only per-session state is the key, the counter and (receive side) the
//! replay bitmap. Nothing branches on secret data — the counter, the receiver
//! index and the message length are all cleartext header fields.
//!
//! **Session lifetime — what §6.1 says and who enforces which half.** §6.1
//! bounds a session in two independent dimensions, messages *and* wall-clock
//! time, and both are enforced here:
//!
//! * `REJECT_AFTER_MESSAGES` / `REKEY_AFTER_MESSAGES` — the counter half,
//!   enforced by `seal`/`open` against the session counter.
//! * `REJECT_AFTER_TIME` (180 s) / `REKEY_AFTER_TIME` (120 s) — the clock
//!   half, enforced by `seal`/`open` against a **caller-supplied `now_s`**.
//!   Every session records a `born_s` at `init` and every seal/open takes the
//!   current time, exactly as the cookie layer's `CookieChecker.refresh` /
//!   `PeerCookie.current` already do. This module reads no clock; it makes the
//!   caller pass one, which is the only way a "you own the timers" contract
//!   cannot be silently skipped.
//!
//! The three §6.1 constants NOT here are the ones that need a socket and a
//! timer wheel rather than a session: `REKEY_TIMEOUT` (handshake retry
//! backoff), `REKEY_ATTEMPT_TIME` (give-up deadline) and `KEEPALIVE_TIMEOUT`
//! (when to emit a keepalive). They govern *scheduling* — when to send
//! something — and this module never sends anything. They are the caller's,
//! explicitly and by name.
//!
//! Provenance: clean-room from the WireGuard whitepaper (§5.4.6 and the
//! session-limit constants of §6.1 named above); the counter/replay behaviour
//! follows the RFC 6479 bitmap the reference implementations use. No source
//! consulted or copied — see ../NOTICE.

const std = @import("std");
const noise = @import("noise.zig");

// Note: `pub const meta` is declared once, canonically, in `root.zig` (per
// CONVENTIONS.md §4) — submodule files like this one do not repeat it. This
// file depends only on `noise.zig` (i.e. `chachapoly` + std.crypto), not on the
// netlink control-plane half of the module.

// ── wire constants (whitepaper §5.4.6 / §6.1) ───────────────────────────────

/// The `message_type` u32 (little-endian) of a transport-data message: the
/// type byte 4 followed by three RESERVED ZERO bytes. Reading all four bytes as
/// one LE u32 and comparing against this is exactly what wireguard-go and the
/// Linux kernel do, so a message with non-zero reserved bytes is rejected here
/// too — deliberately, to match the references rather than be laxer than them.
pub const message_type: u32 = 4;

/// Fixed header size: type+reserved(4) + receiver_index(4) + counter(8).
pub const header_len: usize = 16;

/// Poly1305 tag length.
pub const tag_len: usize = noise.tag_len; // 16

/// Bytes a transport-data message carries beyond its padded plaintext.
pub const overhead: usize = header_len + tag_len; // 32

/// The plaintext is zero-padded up to a multiple of this before encryption.
pub const pad_multiple: usize = 16;

/// `REJECT_AFTER_MESSAGES` = 2^64 − 2^13 − 1. A counter at or past this must
/// FAIL rather than wrap: a wrapped counter repeats a nonce under the same key,
/// which is catastrophic for ChaCha20-Poly1305 (keystream reuse *and* a
/// forgeable Poly1305 key). The 2^13 headroom below the u64 ceiling is exactly
/// the replay window's width, so a receiver can hold a full window of
/// in-flight counters without any of them being unrepresentable.
pub const reject_after_messages: u64 = std.math.maxInt(u64) - (1 << 13);

/// `REKEY_AFTER_MESSAGES` = 2^60. Past this the session must be replaced by a
/// fresh handshake. This is a *policy* limit with an enormous margin over
/// `reject_after_messages`, so it is reported to the caller (`RekeyState.due`)
/// rather than enforced: silently continuing would be wrong, but so would
/// dropping a packet the peer will still accept.
pub const rekey_after_messages: u64 = 1 << 60;

/// `REJECT_AFTER_TIME` = 180 seconds. The wall-clock twin of
/// `reject_after_messages`: past this age a session's keys must not be used in
/// either direction, no matter how few packets went through it. Enforced by
/// `seal`/`open` against the caller-supplied `now_s`, because a session whose
/// lifetime is nobody's job is a session that lives forever.
pub const reject_after_time_s: u64 = 180;

/// `REKEY_AFTER_TIME` = 120 seconds. The wall-clock twin of
/// `rekey_after_messages`: past this age a fresh handshake must be started,
/// but the session keeps working until `reject_after_time_s`. Like its
/// message-count sibling this is reported (`RekeyState.due`), not enforced.
pub const rekey_after_time_s: u64 = 120;

comptime {
    // Spelled out, so a refactor of the expression above cannot quietly move
    // the constants the whole nonce-safety argument rests on.
    std.debug.assert(reject_after_messages == 18446744073709543423); // 2^64-2^13-1
    std.debug.assert(rekey_after_messages == 1152921504606846976); // 2^60
    std.debug.assert(rekey_after_messages < reject_after_messages);
    std.debug.assert(reject_after_time_s == 180);
    std.debug.assert(rekey_after_time_s == 120);
    // The rekey deadline must leave a usable margin before the hard reject, in
    // both dimensions — otherwise "start a handshake" and "stop talking"
    // coincide and there is no window to complete the handshake in.
    std.debug.assert(rekey_after_time_s < reject_after_time_s);
}

/// Largest plaintext a transport-data message can carry. One WireGuard message
/// travels in exactly one UDP datagram, so the sealed message has to fit an
/// IPv4 UDP payload (65507 bytes) — rounded down so the *padded* length still
/// fits. Also makes `paddedLen` arithmetic overflow-free by construction.
pub const max_payload: usize = ((65507 - overhead) / pad_multiple) * pad_multiple;

comptime {
    std.debug.assert(sealedLen(max_payload) <= 65507);
}

// ── pure helpers (no state, hand-verifiable) ────────────────────────────────

/// The 12-byte AEAD nonce for a transport counter: **4 zero bytes followed by
/// the counter as 8 bytes little-endian** (whitepaper §5.4.6). The handshake
/// messages use this too, always with counter 0 (which is why the handshake
/// KATs cannot detect an endianness error here — the transport tests must).
pub fn counterNonce(counter: u64) [noise.Aead.nonce_length]u8 {
    var n: [noise.Aead.nonce_length]u8 = @splat(0);
    std.mem.writeInt(u64, n[4..12], counter, .little);
    return n;
}

/// The plaintext length actually encrypted for a `plaintext_len`-byte packet:
/// rounded UP to a multiple of 16. `paddedLen(0) == 0` — an empty payload
/// (a keepalive) is not padded to a full block.
pub fn paddedLen(plaintext_len: usize) usize {
    return std.mem.alignForward(usize, plaintext_len, pad_multiple);
}

/// Exact wire size of the message `seal` produces for a `plaintext_len`-byte
/// packet: header + padded plaintext + tag.
pub fn sealedLen(plaintext_len: usize) usize {
    return overhead + paddedLen(plaintext_len);
}

/// The two directional transport keys produced by a completed handshake.
/// `send` and `recv` are NOT interchangeable — see `Session.init`.
pub const TransportKeys = struct {
    send: [32]u8,
    recv: [32]u8,
};

/// The parsed 16-byte transport-data header. `parseHeader` is exposed so a
/// device demultiplexer can read `receiver_index` and pick the session BEFORE
/// deciding which key to open with.
pub const Header = struct {
    receiver_index: u32,
    counter: u64,

    /// Serialize the header into `out` (type + zero reserved bytes included).
    pub fn encode(h: Header, out: *[header_len]u8) void {
        std.mem.writeInt(u32, out[0..4], message_type, .little);
        std.mem.writeInt(u32, out[4..8], h.receiver_index, .little);
        std.mem.writeInt(u64, out[8..16], h.counter, .little);
    }
};

pub const ParseError = error{
    /// Fewer bytes than the minimum message (`overhead`).
    Truncated,
    /// The leading u32 is not `message_type` (wrong type, or non-zero
    /// reserved bytes).
    NotTransportData,
};

/// Parse and bounds-check an untrusted message's header. Total over arbitrary
/// bytes: any slice either yields a `Header` or a typed error, never an
/// out-of-bounds read. Does no cryptography.
pub fn parseHeader(msg: []const u8) ParseError!Header {
    if (msg.len < overhead) return error.Truncated;
    if (std.mem.readInt(u32, msg[0..4], .little) != message_type) return error.NotTransportData;
    return .{
        .receiver_index = std.mem.readInt(u32, msg[4..8], .little),
        .counter = std.mem.readInt(u64, msg[8..16], .little),
    };
}

// ── anti-replay window (RFC 6479 style, sized to the protocol) ──────────────

/// Default window width in counters: 2^13, the same headroom
/// `reject_after_messages` reserves below the u64 ceiling and the same width
/// the Linux kernel's implementation uses (`COUNTER_BITS_TOTAL`).
pub const default_window_bits: usize = 1 << 13;

/// A bounded sliding-window anti-replay filter over the 64-bit transport
/// counter, `bits` counters wide.
///
/// The bitmap is CIRCULAR (RFC 6479): the block index is `(counter+1) >> 6`
/// modulo the block count, so advancing the high-water mark clears only the
/// blocks actually skipped instead of shifting the whole bitmap. `capacity`
/// is `bits - 64` — one block of redundancy, which is what guarantees a
/// counter still inside `capacity` can never alias a stale block.
///
/// Counters are tracked internally as `counter + 1` so that the all-zero
/// initial state means "nothing received yet" and counter 0 is still a
/// perfectly ordinary first packet (the same trick the kernel uses).
///
/// The filter is **advisory until the AEAD tag has verified**: `accepts` is a
/// read-only pre-check and `commit` records a counter. A caller MUST
/// `accepts` → verify → `commit`, never committing an unauthenticated
/// counter — otherwise a forged packet could burn a window slot and get the
/// legitimate packet rejected as a replay it never was.
pub fn ReplayWindow(comptime bits: usize) type {
    comptime {
        std.debug.assert(bits >= 128);
        std.debug.assert(bits % 64 == 0);
        std.debug.assert(std.math.isPowerOfTwo(bits / 64));
    }
    const blocks = bits / 64;
    return struct {
        const Self = @This();

        /// How far behind the high-water mark a counter may still be accepted.
        pub const capacity: u64 = bits - 64;

        /// Circular bitmap; bit `n & 63` of block `(n >> 6) % blocks` is set
        /// when `n = counter + 1` has been committed.
        bitmap: [blocks]u64 = @splat(0),
        /// Highest committed `counter + 1`; 0 means nothing committed yet.
        last: u64 = 0,

        /// Would `counter` be accepted right now? Read-only. A caller MUST
        /// still verify the AEAD tag before `commit`ing it.
        ///
        /// `maxInt(u64)` is rejected rather than tracked: the internal
        /// representation is `counter + 1`, so that one value is
        /// unrepresentable. `RecvSession.open` can never reach it (it refuses
        /// at `reject_after_messages`, which is `maxInt(u64) - 8192`), but this
        /// generic is public and a caller wiring its own demultiplexer must get
        /// a `false`, not an integer-overflow panic, on an attacker-chosen
        /// header field.
        pub fn accepts(self: *const Self, counter: u64) bool {
            if (counter == std.math.maxInt(u64)) return false;
            const n = counter + 1;
            if (n > self.last) return true; // ahead of the window: fresh
            if (self.last - n > capacity) return false; // fell off the trailing edge
            return self.bitmap[blockIndex(n >> 6)] & bit(n) == 0;
        }

        /// Record `counter` as accepted, sliding the window forward if it is a
        /// new high. MUST only be called after the tag has verified.
        ///
        /// `maxInt(u64)` is ignored, for the same representation reason
        /// `accepts` rejects it — reaching here with it means the caller
        /// committed a counter `accepts` said no to, and dropping it is
        /// strictly safer than wrapping the bitmap index.
        pub fn commit(self: *Self, counter: u64) void {
            if (counter == std.math.maxInt(u64)) return;
            const n = counter + 1;
            if (n > self.last) {
                const from = self.last >> 6;
                const to = n >> 6;
                if (to - from >= blocks) {
                    // The window jumped clear of every tracked block.
                    @memset(&self.bitmap, 0);
                } else {
                    var i = from + 1;
                    while (i <= to) : (i += 1) self.bitmap[blockIndex(i)] = 0;
                }
                self.last = n;
            }
            self.bitmap[blockIndex(n >> 6)] |= bit(n);
        }

        /// The highest counter committed so far, or null if none.
        pub fn highest(self: *const Self) ?u64 {
            return if (self.last == 0) null else self.last - 1;
        }

        /// Drop all history (a fresh session/key means old counters are void).
        pub fn reset(self: *Self) void {
            self.* = .{};
        }

        fn bit(n: u64) u64 {
            return @as(u64, 1) << @truncate(n);
        }

        /// Map a block number (`x = (counter + 1) >> 6`, for either the current
        /// counter or one being scanned over between `from` and `to`) down to
        /// the `[blocks]u64` array index it circularly aliases. `x` itself is
        /// an unbounded `u64` -- it is derived from the attacker-controlled
        /// wire counter -- but `& (blocks - 1)` masks it into `[0, blocks)`
        /// right here, so the narrowing to `usize` is provably in range on
        /// every host width this collection targets (`blocks` is at most
        /// `bits / 64`, and `bits` is a caller-chosen comptime constant, never
        /// attacker data). This is a bounded mask-then-cast, not a truncation
        /// of the attacker-controlled counter itself -- no distinct `x` values
        /// that matter to the caller collide, because both `accepts` and
        /// `commit` only ever compare/index positions already known to be
        /// within `capacity` of `self.last`, i.e. within `blocks` of each
        /// other.
        fn blockIndex(x: u64) usize {
            return @intCast(x & (@as(u64, blocks) - 1));
        }
    };
}

// ── seal / open ─────────────────────────────────────────────────────────────

/// Whether a session has passed `rekey_after_messages` **or**
/// `rekey_after_time_s` and must be replaced by a fresh handshake. Returned
/// alongside every seal/open rather than acted on here: this module owns no
/// handshake scheduling and reads no clock, but a caller that ignores the
/// signal must do so explicitly.
pub const RekeyState = enum {
    /// Below both rekey limits — keep using the session.
    ok,
    /// At or past `rekey_after_messages` or `rekey_after_time_s` — start a new
    /// handshake. The session keeps working until `reject_after_messages` /
    /// `reject_after_time_s`; this is a deadline, not a failure.
    due,
};

/// Age of a session in whole seconds, from its `born_s` to the caller's
/// `now_s`. Saturating: a `now_s` that moved backwards (a clock step, a
/// caller mixing two time sources) yields 0 rather than wrapping to a
/// gigantic age, so a bad clock can never make a fresh session look expired.
fn ageSeconds(born_s: u64, now_s: u64) u64 {
    return now_s -| born_s;
}

pub const SealResult = struct {
    /// Bytes written to `out` (`sealedLen(packet.len)`).
    len: usize,
    /// The counter this packet went out with.
    counter: u64,
    rekey: RekeyState,
};

pub const SealError = error{
    /// `out` is smaller than `sealedLen(packet.len)`.
    BufferTooSmall,
    /// The plaintext cannot fit one UDP datagram (`max_payload`).
    PacketTooLarge,
    /// The counter reached `reject_after_messages`. Refused rather than
    /// wrapped — a wrapped counter reuses a nonce. Only a new handshake
    /// (a fresh key, counter back to 0) can continue.
    MessageLimitReached,
    /// The session is `reject_after_time_s` (180 s) or more old, per the
    /// caller-supplied `now_s`. Only a new handshake can continue.
    SessionExpired,
};

/// Sender half of a session: one transport key, the peer's session index, a
/// monotonic counter and the session's birth time. `single_owner` — one
/// loop/thread owns it, no lock.
pub const SendSession = struct {
    /// `T_send` from `Handshake.deriveTransportKeys`.
    key: [32]u8,
    /// The PEER's session index, which goes out as `receiver_index` on every
    /// packet we send them (it is *their* index, not ours).
    receiver_index: u32,
    /// When this session was keyed, on the caller's own clock — the base for
    /// `reject_after_time_s` / `rekey_after_time_s`.
    born_s: u64,
    /// Next counter to use. **Read-only in production.** Rewinding it — to 0
    /// or to any already-used value — re-emits `AEAD(key, counterNonce(n), …)`
    /// under the same key: ChaCha20 keystream reuse *and* a forgeable Poly1305
    /// key, i.e. exactly the catastrophe `reject_after_messages` exists to
    /// prevent, reached by assignment instead of by wrapping. The only safe
    /// way to move it forward is `seal`; the only sanctioned way to move it at
    /// all is `seekUnsafeForTest`, whose name says what it costs.
    counter: u64 = 0,

    pub fn init(key: [32]u8, receiver_index: u32, now_s: u64) SendSession {
        return .{ .key = key, .receiver_index = receiver_index, .born_s = now_s };
    }

    /// Deterministic-test seam: place the counter at an arbitrary value so a
    /// test can sit on a boundary (`reject_after_messages - 1`, a chosen nonce)
    /// without sealing 2^60 packets to get there. **Never call this in
    /// production** — moving the counter anywhere it has already been is
    /// silent nonce reuse under a live key. Use `seal`, which is the only
    /// operation that advances it safely.
    pub fn seekUnsafeForTest(self: *SendSession, counter: u64) void {
        self.counter = counter;
    }

    /// Seal one plaintext packet into `out` as a complete transport-data
    /// message. `out` must be at least `sealedLen(packet.len)` bytes and must
    /// NOT overlap `packet`. `now_s` is the caller's current wall-clock time in
    /// seconds, on the same clock `init` was given: it enforces
    /// `REJECT_AFTER_TIME` and reports `REKEY_AFTER_TIME`. Zero allocation; the
    /// padding and the AEAD are done in place inside `out`.
    pub fn seal(self: *SendSession, out: []u8, packet: []const u8, now_s: u64) SealError!SealResult {
        if (packet.len > max_payload) return error.PacketTooLarge;
        const ct_len = paddedLen(packet.len);
        const need = overhead + ct_len;
        if (out.len < need) return error.BufferTooSmall;
        // Refuse rather than wrap: a wrapped counter repeats a nonce.
        if (self.counter >= reject_after_messages) return error.MessageLimitReached;
        // The clock half of §6.1: a session older than REJECT_AFTER_TIME is
        // dead regardless of how few packets it carried.
        const age_s = ageSeconds(self.born_s, now_s);
        if (age_s >= reject_after_time_s) return error.SessionExpired;

        const counter = self.counter;
        (Header{ .receiver_index = self.receiver_index, .counter = counter }).encode(out[0..header_len]);

        const ct = out[header_len..][0..ct_len];
        @memcpy(ct[0..packet.len], packet);
        @memset(ct[packet.len..], 0); // the pad-to-16 rule, encrypted along with the packet
        // In place (c == m): `chachapoly` documents and tests this, and std's
        // ChaCha20 XOR is in-place-safe too. Empty AAD — the header is not
        // associated data in this protocol.
        noise.Aead.encrypt(
            ct,
            out[header_len + ct_len ..][0..tag_len],
            ct,
            "",
            counterNonce(counter),
            self.key,
        );

        self.counter = counter + 1;
        return .{ .len = need, .counter = counter, .rekey = rekeyState(counter, age_s) };
    }

    /// Whether the next `seal` would be past `rekey_after_messages` or the
    /// session is already past `rekey_after_time_s`.
    pub fn rekeyDue(self: *const SendSession, now_s: u64) bool {
        return rekeyState(self.counter, ageSeconds(self.born_s, now_s)) == .due;
    }

    /// Whether this session has passed `reject_after_time_s` and will refuse
    /// every further `seal`. Exposed so a caller can retire it proactively
    /// rather than discovering it on a dropped packet.
    pub fn expired(self: *const SendSession, now_s: u64) bool {
        return ageSeconds(self.born_s, now_s) >= reject_after_time_s;
    }

    /// Wipe the key material.
    pub fn wipe(self: *SendSession) void {
        std.crypto.secureZero(u8, &self.key);
        self.* = undefined;
    }
};

pub const OpenResult = struct {
    /// PADDED plaintext length written to `out` — i.e. `msg.len - overhead`.
    /// The true packet length is carried by the inner packet's own header
    /// (IPv4 total_length / IPv6 payload_length); WireGuard deliberately does
    /// not encode it, so this codec cannot and must not strip the padding.
    len: usize,
    /// The counter this packet carried.
    counter: u64,
    rekey: RekeyState,
};

pub const OpenError = error{
    /// Shorter than the minimum message (`overhead`).
    Truncated,
    /// The leading u32 is not `message_type` 4 (wrong type / non-zero
    /// reserved bytes).
    NotTransportData,
    /// `receiver_index` does not address this session.
    WrongReceiver,
    /// A duplicate counter, or one that has fallen out of the replay window.
    Replayed,
    /// The counter is at or past `reject_after_messages`; no session may ever
    /// legitimately produce it.
    MessageLimitReached,
    /// The session is `reject_after_time_s` (180 s) or more old, per the
    /// caller-supplied `now_s`. Only a new handshake can continue.
    SessionExpired,
    /// `out` is smaller than the message's padded plaintext.
    BufferTooSmall,
} || std.crypto.errors.AuthenticationError;

/// Receiver half of a session: one transport key, our own session index, and
/// the anti-replay window. `single_owner`, lock-free.
pub const RecvSession = struct {
    /// The replay filter type, exposed so callers can size buffers/tests
    /// against `Window.capacity`.
    pub const Window = ReplayWindow(default_window_bits);

    /// `T_recv` from `Handshake.deriveTransportKeys`.
    key: [32]u8,
    /// OUR session index. A packet addressed to a different index is not for
    /// this session (a device demultiplexes on it via `parseHeader` first;
    /// this check is the backstop).
    local_index: u32,
    /// When this session was keyed, on the caller's own clock — the base for
    /// `reject_after_time_s` / `rekey_after_time_s`.
    born_s: u64,
    window: Window = .{},

    pub fn init(key: [32]u8, local_index: u32, now_s: u64) RecvSession {
        return .{ .key = key, .local_index = local_index, .born_s = now_s };
    }

    /// Open one transport-data message into `out`, returning the padded
    /// plaintext length. `now_s` is the caller's current wall-clock time in
    /// seconds, on the same clock `init` was given; a session at or past
    /// `reject_after_time_s` refuses every message. Order: parse +
    /// bounds-check → receiver check → counter-limit check → session-age check
    /// → replay PRE-check → AEAD verify+decrypt → commit the counter. The
    /// window is committed only after authentication, so a forged packet can
    /// never burn a legitimate counter's slot. On an authentication failure
    /// `out[0..ct_len]` is zeroed — never garbage plaintext; the checks before
    /// it never write to `out` at all. `out` should not overlap `msg` (the
    /// zeroing would clobber the ciphertext).
    ///
    /// **Deliberate divergence from the references, documented rather than
    /// silent:** the replay window is consulted BEFORE the AEAD. The Linux
    /// kernel (`wg_packet_decrypt` then `counter_validate`) and wireguard-go
    /// (`RoutineDecryption` then `keypair.replayFilter.ValidateCounter`) both
    /// authenticate first and only then consult the filter. The
    /// security-critical half is identical either way — `commit` is strictly
    /// post-authentication here too, so a forgery cannot burn a slot. What the
    /// early return costs is an *unauthenticated* distinction: someone who can
    /// guess `receiver_index` learns from the typed error whether a chosen
    /// counter already sits in the receive window, without holding the key.
    /// Over a socket both outcomes are a silent drop, so this is observable
    /// only through a caller that logs or meters `error.Replayed` separately
    /// from `error.AuthenticationFailed` — such a caller should merge the two.
    /// The order is kept because it sheds a replayed flood without paying an
    /// AEAD per packet, which is the cheap-DoS-shortcut the references forgo.
    ///
    /// The padded ciphertext length is NOT required to be a multiple of 16:
    /// every conforming sender pads, but the tag is the authority on what this
    /// peer actually sent, and rejecting an authentic packet for a framing
    /// nicety would be a rejection for the wrong reason.
    pub fn open(self: *RecvSession, out: []u8, msg: []const u8, now_s: u64) OpenError!OpenResult {
        const h = try parseHeader(msg);
        if (h.receiver_index != self.local_index) return error.WrongReceiver;
        if (h.counter >= reject_after_messages) return error.MessageLimitReached;
        const age_s = ageSeconds(self.born_s, now_s);
        if (age_s >= reject_after_time_s) return error.SessionExpired;
        const ct_len = msg.len - overhead;
        if (out.len < ct_len) return error.BufferTooSmall;
        if (!self.window.accepts(h.counter)) return error.Replayed;

        const pt = out[0..ct_len];
        noise.Aead.decrypt(
            pt,
            msg[header_len..][0..ct_len],
            msg[header_len + ct_len ..][0..tag_len].*,
            "",
            counterNonce(h.counter),
            self.key,
        ) catch |e| {
            std.crypto.secureZero(u8, pt);
            return e;
        };
        self.window.commit(h.counter);
        return .{ .len = ct_len, .counter = h.counter, .rekey = rekeyState(h.counter, age_s) };
    }

    /// Whether the highest counter seen is past `rekey_after_messages`, or the
    /// session is past `rekey_after_time_s`.
    pub fn rekeyDue(self: *const RecvSession, now_s: u64) bool {
        const age_s = ageSeconds(self.born_s, now_s);
        if (age_s >= rekey_after_time_s) return true;
        const hi = self.window.highest() orelse return false;
        return hi >= rekey_after_messages;
    }

    /// Whether this session has passed `reject_after_time_s` and will refuse
    /// every further `open`.
    pub fn expired(self: *const RecvSession, now_s: u64) bool {
        return ageSeconds(self.born_s, now_s) >= reject_after_time_s;
    }

    /// Wipe the key material.
    pub fn wipe(self: *RecvSession) void {
        std.crypto.secureZero(u8, &self.key);
        self.* = undefined;
    }
};

fn rekeyState(counter: u64, age_s: u64) RekeyState {
    if (counter >= rekey_after_messages) return .due;
    if (age_s >= rekey_after_time_s) return .due;
    return .ok;
}

/// Both halves of one keyed session. Built from the handshake's own
/// `TransportKeys` plus the two indices, so `send`/`recv` cannot be swapped by
/// a caller who guessed which is which: `keys.send` is always the key we
/// encrypt with and `keys.recv` always the one we decrypt with, and the two
/// indices go to the halves that need them (`remote_index` is what we stamp on
/// what we send; `local_index` is what our peer stamps on what we receive).
pub const Session = struct {
    send: SendSession,
    recv: RecvSession,

    /// `now_s` is the caller's clock at the moment the handshake completed; it
    /// becomes both halves' `born_s` and is what `reject_after_time_s` /
    /// `rekey_after_time_s` are measured from.
    pub fn init(keys: TransportKeys, local_index: u32, remote_index: u32, now_s: u64) Session {
        return .{
            .send = SendSession.init(keys.send, remote_index, now_s),
            .recv = RecvSession.init(keys.recv, local_index, now_s),
        };
    }

    /// Whether the session has passed `reject_after_time_s` (both halves share
    /// one `born_s`, so this is one question, not two).
    pub fn expired(self: *const Session, now_s: u64) bool {
        return self.send.expired(now_s);
    }

    pub fn wipe(self: *Session) void {
        self.send.wipe();
        self.recv.wipe();
        self.* = undefined;
    }
};

// ── dark-tests: pulled into the aggregator via ../root.zig `test { }` ───────

const testing = std.testing;

fn testKey(seed: u8) [32]u8 {
    var k: [32]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = seed +% @as(u8, @truncate(i));
    return k;
}

/// A fixed "now" for every test that does not care about time. Sessions are
/// born at `t0` and every seal/open happens at `t0`, i.e. at age 0 — well
/// inside `reject_after_time_s`. The tests that DO care about time state their
/// own literal offsets from it.
const t0: u64 = 1_700_000_000;

test "constants match the whitepaper" {
    try testing.expectEqual(@as(u32, 4), message_type);
    try testing.expectEqual(@as(usize, 16), header_len);
    try testing.expectEqual(@as(usize, 16), tag_len);
    try testing.expectEqual(@as(usize, 32), overhead);
    try testing.expectEqual(@as(usize, 16), pad_multiple);
    // 2^64 - 2^13 - 1 and 2^60, written out independently of the expressions
    // that define them.
    try testing.expectEqual(@as(u64, 18446744073709543423), reject_after_messages);
    try testing.expectEqual(@as(u64, 1152921504606846976), rekey_after_messages);
    try testing.expectEqual(std.math.maxInt(u64) - 8192, reject_after_messages);
    // The headroom below the u64 ceiling is exactly one replay window.
    try testing.expectEqual(@as(u64, default_window_bits), std.math.maxInt(u64) - reject_after_messages);
    // §6.1's two SESSION-lifetime timers, as absolute seconds — the numbers a
    // peer's own timers are set from, not expressions over each other.
    try testing.expectEqual(@as(u64, 180), reject_after_time_s);
    try testing.expectEqual(@as(u64, 120), rekey_after_time_s);
}

// ── the delivered values of the two limits that used to be blind ───────────
//
// F4/F5 of the 2026-08-11 re-audit: every test that touched `max_payload` or
// `Window.capacity` was written IN TERMS OF the constant (`max_payload + 1`,
// `highest - counter <= W.capacity`), so the oracle moved with the code and
// either constant could be cut to a fraction of its documented value with the
// suite green. These pin the DELIVERED numbers — the ones README and SPEC
// quote — so the shrinking direction bites too.
test "delivered limits: max_payload and the replay window widths are the documented numbers" {
    // 65507 (max IPv4 UDP payload) − 32 (header+tag) = 65475, rounded down to a
    // multiple of 16. Written as the absolute the docs promise, not as the
    // expression that computes it.
    try testing.expectEqual(@as(usize, 65472), max_payload);
    try testing.expectEqual(@as(usize, 65504), sealedLen(max_payload));

    // The default receive window: 8192 tracked bits, of which 8128 counters
    // are usable (one 64-bit block of redundancy is what stops a still-valid
    // counter aliasing a stale block).
    try testing.expectEqual(@as(usize, 8192), default_window_bits);
    try testing.expectEqual(@as(u64, 8128), RecvSession.Window.capacity);
    // …and at the other widths the oracle test instantiates, so a `@min(…)`
    // style cut that spares those widths still cannot hide.
    try testing.expectEqual(@as(u64, 64), ReplayWindow(128).capacity);
    try testing.expectEqual(@as(u64, 192), ReplayWindow(256).capacity);
    try testing.expectEqual(@as(u64, 960), ReplayWindow(1024).capacity);
    try testing.expectEqual(@as(u64, 4032), ReplayWindow(4096).capacity);
}

test "delivered limits: a 65472-byte payload really seals, and 65473 does not" {
    // The pin above is arithmetic; this one is behaviour. The whole suite's
    // next-largest payload is 1500 bytes, so without this a cut `max_payload`
    // would silently refuse every packet between the new cap and a full
    // datagram while `sealedLen` still looked right.
    const key = testKey(30);
    var s = SendSession.init(key, 0x4242, t0);
    var r = RecvSession.init(key, 0x4242, t0);

    const big = try testing.allocator.alloc(u8, 65473);
    defer testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i *% 31);
    const wire = try testing.allocator.alloc(u8, 65504);
    defer testing.allocator.free(wire);
    const back = try testing.allocator.alloc(u8, 65504);
    defer testing.allocator.free(back);

    // 65472 bytes: accepted, and the sealed message is exactly 65504 bytes —
    // one IPv4 UDP datagram, which is the bound the constant encodes.
    const sr = try s.seal(wire, big[0..65472], t0);
    try testing.expectEqual(@as(usize, 65504), sr.len);
    const orr = try r.open(back, wire[0..sr.len], t0);
    try testing.expectEqual(@as(usize, 65472), orr.len);
    try testing.expectEqualSlices(u8, big[0..65472], back[0..65472]);

    // One byte more: refused, and nothing consumed.
    try testing.expectError(error.PacketTooLarge, s.seal(wire, big[0..65473], t0));
    try testing.expectEqual(@as(u64, 1), s.counter);
}

test "delivered limits: the default window really reaches 8128 counters back" {
    // Behavioural twin of the `capacity == 8128` pin, expressed in literals so
    // a halved window drops these packets instead of moving the expectation.
    const key = testKey(31);
    var s = SendSession.init(key, 5, t0);
    var r = RecvSession.init(key, 5, t0);

    var high: [overhead + 16]u8 = undefined; // counter 10_000
    s.seekUnsafeForTest(10_000);
    _ = try s.seal(&high, "high", t0);
    var edge: [overhead + 16]u8 = undefined; // counter 10_000 − 8128 = 1872
    s.seekUnsafeForTest(1_872);
    _ = try s.seal(&edge, "edge", t0);
    var over: [overhead + 16]u8 = undefined; // counter 1871, one too far back
    s.seekUnsafeForTest(1_871);
    _ = try s.seal(&over, "over", t0);

    var out: [64]u8 = undefined;
    _ = try r.open(&out, &high, t0);
    _ = try r.open(&out, &edge, t0); // 8128 behind: still inside
    try testing.expectError(error.Replayed, r.open(&out, &over, t0)); // 8129: gone
}

// ── THE anchor test for the classic mistake ────────────────────────────────
//
// The nonce is "4 zero bytes followed by the counter as 8 bytes LITTLE-endian"
// (whitepaper §5.4.6). A big-endian counter, or one placed in the first 8
// bytes, round-trips flawlessly against ourselves and fails against every real
// peer. These expected bytes are a transcription of that sentence — readable
// by hand, not captured from this implementation's own output.
test "nonce layout is byte-exact: 4 zero bytes then the counter little-endian" {
    const cases = [_]struct { counter: u64, expect: [12]u8 }{
        .{ .counter = 0, .expect = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .counter = 1, .expect = .{ 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .counter = 2, .expect = .{ 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .counter = 255, .expect = .{ 0, 0, 0, 0, 0xff, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .counter = 256, .expect = .{ 0, 0, 0, 0, 0x00, 1, 0, 0, 0, 0, 0, 0 } },
        // 2^32 - 1 and 2^32: the four-byte boundary, where a 32-bit truncation
        // or a byte-swap shows up unmistakably.
        .{ .counter = 0xFFFF_FFFF, .expect = .{ 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 } },
        .{ .counter = 0x1_0000_0000, .expect = .{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0 } },
        // An asymmetric value: every byte position is distinguishable.
        .{ .counter = 0x0102_0304_0506_0708, .expect = .{ 0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1 } },
        .{
            .counter = std.math.maxInt(u64),
            .expect = .{ 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        },
    };
    for (cases) |c| try testing.expectEqualSlices(u8, &c.expect, &counterNonce(c.counter));
}

test "positive control: a big-endian counter WOULD produce different nonce bytes" {
    // Permanent sentinel for the test above: if `counterNonce` ever regressed
    // to big-endian, these two would be equal and the byte-exact test's
    // expectations could no longer both hold.
    const broken = struct {
        fn f(counter: u64) [12]u8 {
            var n: [12]u8 = @splat(0);
            std.mem.writeInt(u64, n[4..12], counter, .big);
            return n;
        }
    }.f;
    try testing.expect(!std.mem.eql(u8, &counterNonce(1), &broken(1)));
    // …and only for a palindromic counter do the two agree, which is exactly
    // why counter 0 (every handshake message) cannot detect the error.
    try testing.expect(std.mem.eql(u8, &counterNonce(0), &broken(0)));
}

test "padding: plaintext is zero-padded up to a multiple of 16, and 0 stays 0" {
    const cases = [_]struct { pt: usize, padded: usize }{
        .{ .pt = 0, .padded = 0 }, // a keepalive is NOT padded to a full block
        .{ .pt = 1, .padded = 16 },
        .{ .pt = 15, .padded = 16 },
        .{ .pt = 16, .padded = 16 },
        .{ .pt = 17, .padded = 32 },
        .{ .pt = 31, .padded = 32 },
        .{ .pt = 32, .padded = 32 },
        .{ .pt = 1419, .padded = 1424 },
        .{ .pt = 1420, .padded = 1424 },
    };
    var s = SendSession.init(testKey(1), 0xAABBCCDD, t0);
    var buf: [2048]u8 = undefined;
    var pt: [1420]u8 = @splat(0x5A);
    for (cases) |c| {
        try testing.expectEqual(c.padded, paddedLen(c.pt));
        try testing.expectEqual(overhead + c.padded, sealedLen(c.pt));
        const r = try s.seal(&buf, pt[0..c.pt], t0);
        try testing.expectEqual(overhead + c.padded, r.len);
        // The ciphertext length on the wire is always a multiple of 16.
        try testing.expectEqual(@as(usize, 0), (r.len - overhead) % pad_multiple);
    }
    // A keepalive on the wire is exactly 32 bytes — the length the live
    // kernel-interop test in handshake.zig matches against.
    try testing.expectEqual(@as(usize, 32), sealedLen(0));
}

test "header: byte-exact layout, type 4 with zero reserved bytes" {
    var s = SendSession.init(testKey(2), 0x11223344, t0);
    s.seekUnsafeForTest(0x0102_0304_0506_0708);
    var buf: [64]u8 = undefined;
    const r = try s.seal(&buf, "hi", t0);
    try testing.expectEqualSlices(u8, &.{
        4, 0, 0, 0, // type = 4, three RESERVED ZERO bytes
        0x44, 0x33, 0x22, 0x11, // receiver_index, little-endian
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // counter, little-endian
    }, buf[0..header_len]);
    try testing.expectEqual(@as(usize, overhead + 16), r.len);

    const h = try parseHeader(buf[0..r.len]);
    try testing.expectEqual(@as(u32, 0x11223344), h.receiver_index);
    try testing.expectEqual(@as(u64, 0x0102_0304_0506_0708), h.counter);
}

// ── differential: the whole packet, rebuilt by a second implementation ─────
//
// No official fixed-input transport-data vector is published by the WireGuard
// project (see SPEC.md). The strongest anchor reachable offline is a
// differential: rebuild the same message with `std.crypto.aead.chacha_poly`
// (an independent AEAD implementation) over a nonce taken from the LITERAL
// table above rather than from `counterNonce`, and an independently written
// header/padding. Byte identity then covers the AEAD, the nonce layout, the
// header encoding and the padding rule at once — and a "consistent" mutation
// that changes the nonce on both seal and open still goes red here, because
// the expected nonce is a literal.
test "differential: the sealed message is byte-identical to an independent rebuild" {
    const key = testKey(3);
    const idx: u32 = 0xDEADBEEF;
    var payload: [1500]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    prng.random().bytes(&payload);

    const lens = [_]usize{ 0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 512, 1419, 1420, 1500 };
    const cases = [_]struct { counter: u64, nonce: [12]u8 }{
        .{ .counter = 0, .nonce = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .counter = 1, .nonce = .{ 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .counter = 0xFFFF_FFFF, .nonce = .{ 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 } },
        .{ .counter = 0x1_0000_0000, .nonce = .{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0 } },
        .{ .counter = 0x0102_0304_0506_0708, .nonce = .{ 0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1 } },
    };

    var ours: [1536 + overhead]u8 = undefined;
    var theirs: [1536 + overhead]u8 = undefined;

    for (lens) |len| {
        for (cases) |c| {
            var s = SendSession.init(key, idx, t0);
            s.seekUnsafeForTest(c.counter);
            const r = try s.seal(&ours, payload[0..len], t0);

            // Independent rebuild: header written field by field, padding
            // written explicitly, std's AEAD, nonce from the literal table.
            const ct_len = (len + 15) / 16 * 16;
            theirs[0] = 4;
            theirs[1] = 0;
            theirs[2] = 0;
            theirs[3] = 0;
            std.mem.writeInt(u32, theirs[4..8], idx, .little);
            std.mem.writeInt(u64, theirs[8..16], c.counter, .little);
            var padded: [1536]u8 = @splat(0);
            @memcpy(padded[0..len], payload[0..len]);
            noise.StdAead.encrypt(
                theirs[16..][0..ct_len],
                theirs[16 + ct_len ..][0..16],
                padded[0..ct_len],
                "", // empty AAD
                c.nonce,
                key,
            );
            try testing.expectEqualSlices(u8, theirs[0 .. 16 + ct_len + 16], ours[0..r.len]);

            // …and the message our sealer produced opens under the other
            // implementation, so a peer running either one interoperates.
            var back: [1536]u8 = undefined;
            try noise.StdAead.decrypt(
                back[0..ct_len],
                ours[16..][0..ct_len],
                ours[16 + ct_len ..][0..16].*,
                "",
                c.nonce,
                key,
            );
            try testing.expectEqualSlices(u8, payload[0..len], back[0..len]);
        }
    }
}

// ── round trip + directional keys ──────────────────────────────────────────

test "round trip: a sealed packet opens under the matching receive session" {
    const keys = TransportKeys{ .send = testKey(4), .recv = testKey(5) };
    // A ↔ B: A's send key is B's receive key and vice versa.
    var a = Session.init(keys, 0x0A0A0A0A, 0x0B0B0B0B, t0);
    var b = Session.init(.{ .send = keys.recv, .recv = keys.send }, 0x0B0B0B0B, 0x0A0A0A0A, t0);

    var wire: [2048]u8 = undefined;
    var out: [2048]u8 = undefined;
    const msg = "the quick brown fox jumps over the lazy dog";
    for (0..8) |i| {
        const sr = try a.send.seal(&wire, msg, t0);
        try testing.expectEqual(@as(u64, i), sr.counter);
        try testing.expectEqual(RekeyState.ok, sr.rekey);
        const orr = try b.recv.open(&out, wire[0..sr.len], t0);
        try testing.expectEqual(@as(u64, i), orr.counter);
        try testing.expectEqual(paddedLen(msg.len), orr.len);
        try testing.expectEqualSlices(u8, msg, out[0..msg.len]);
        // Everything past the plaintext is the zero padding.
        for (out[msg.len..orr.len]) |pad| try testing.expectEqual(@as(u8, 0), pad);
    }
    // …and the reverse direction, under the other key.
    const sr = try b.send.seal(&wire, "reply", t0);
    const orr = try a.recv.open(&out, wire[0..sr.len], t0);
    try testing.expectEqualSlices(u8, "reply", out[0..5]);
    try testing.expectEqual(@as(usize, 16), orr.len);
}

test "keepalive: an empty payload is a 32-byte message that opens to nothing" {
    const key = testKey(6);
    var s = SendSession.init(key, 7, t0);
    var r = RecvSession.init(key, 7, t0);
    var wire: [64]u8 = undefined;
    const sr = try s.seal(&wire, "", t0);
    try testing.expectEqual(@as(usize, 32), sr.len);
    var out: [16]u8 = undefined;
    const orr = try r.open(&out, wire[0..sr.len], t0);
    try testing.expectEqual(@as(usize, 0), orr.len);
}

test "send and receive keys are NOT interchangeable" {
    // The failure this catches is invisible to a round trip: swapping the two
    // keys on BOTH ends round-trips perfectly and fails against a real peer.
    const keys = TransportKeys{ .send = testKey(7), .recv = testKey(8) };
    var a = Session.init(keys, 1, 2, t0);
    var wire: [128]u8 = undefined;
    const sr = try a.send.seal(&wire, "payload", t0);

    var out: [64]u8 = undefined;
    // The packet is addressed to the peer (index 2). A peer that hands its
    // receiver the WRONG half of the pair cannot open it — and the failure is
    // an authentication failure, not a framing error.
    var wrong = RecvSession.init(keys.recv, 2, t0);
    try testing.expectError(error.AuthenticationFailed, wrong.open(&out, wire[0..sr.len], t0));
    for (out[0..16]) |b| try testing.expectEqual(@as(u8, 0), b); // zeroed, not garbage

    // The correctly-paired peer can: our `send` key is its `recv` key.
    var right = RecvSession.init(keys.send, 2, t0);
    _ = try right.open(&out, wire[0..sr.len], t0);

    // Session.init wires the pair: our sender holds `keys.send`, our receiver
    // holds `keys.recv` — never the other way round.
    try testing.expectEqual(keys.send, a.send.key);
    try testing.expectEqual(keys.recv, a.recv.key);
    // …and the indices go to the halves that need them: we stamp the PEER's
    // index on what we send, and expect OUR index on what we receive.
    try testing.expectEqual(@as(u32, 2), a.send.receiver_index);
    try testing.expectEqual(@as(u32, 1), a.recv.local_index);
}

// ── anti-replay ────────────────────────────────────────────────────────────

test "replay: a duplicate is rejected, out-of-order-within-window is accepted" {
    const key = testKey(9);
    var s = SendSession.init(key, 3, t0);
    var r = RecvSession.init(key, 3, t0);

    var msgs: [8][overhead + 16]u8 = undefined;
    for (&msgs) |*m| _ = try s.seal(m, "packet", t0);

    var out: [64]u8 = undefined;
    // Deliver 0, then 3 (a gap), then the skipped 1 and 2 — all fresh.
    _ = try r.open(&out, &msgs[0], t0);
    _ = try r.open(&out, &msgs[3], t0);
    _ = try r.open(&out, &msgs[1], t0);
    _ = try r.open(&out, &msgs[2], t0);
    // Every one of them is now a replay.
    for (0..4) |i| try testing.expectError(error.Replayed, r.open(&out, &msgs[i], t0));
    // …and the still-unseen ones remain openable.
    _ = try r.open(&out, &msgs[5], t0);
    _ = try r.open(&out, &msgs[4], t0);
    try testing.expectError(error.Replayed, r.open(&out, &msgs[5], t0));
}

test "replay: a counter that fell off the trailing edge is rejected" {
    const key = testKey(10);
    var s = SendSession.init(key, 3, t0);
    var r = RecvSession.init(key, 3, t0);
    const cap = RecvSession.Window.capacity;

    // Three packets, positioned relative to a high-water mark of 100 + cap:
    // exactly `cap` behind it (the last in-window slot), `cap + 1` behind it
    // (the first one off the edge), and the mark itself.
    var edge: [overhead + 16]u8 = undefined; // counter 100
    s.seekUnsafeForTest(100);
    _ = try s.seal(&edge, "edge", t0);

    var old: [overhead + 16]u8 = undefined; // counter 99
    s.seekUnsafeForTest(99);
    _ = try s.seal(&old, "old", t0);

    var high: [overhead + 16]u8 = undefined; // counter 100 + cap
    s.seekUnsafeForTest(100 + cap);
    _ = try s.seal(&high, "high", t0);

    var out: [64]u8 = undefined;
    // Jump the high-water mark to 100 + cap …
    _ = try r.open(&out, &high, t0);
    // … the counter exactly `cap` behind it is still inside the window …
    _ = try r.open(&out, &edge, t0);
    // … and 99, one further back, has fallen off the trailing edge.
    try testing.expectError(error.Replayed, r.open(&out, &old, t0));
}

test "replay: a forged packet cannot burn a legitimate counter's window slot" {
    const key = testKey(11);
    var s = SendSession.init(key, 3, t0);
    var r = RecvSession.init(key, 3, t0);
    var good: [overhead + 16]u8 = undefined;
    _ = try s.seal(&good, "genuine", t0);

    var forged = good;
    forged[overhead - 1] +%= 1; // corrupt a ciphertext byte, keep the header
    var out: [64]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, r.open(&out, &forged, t0));
    // The window was NOT committed by the failed open: the genuine packet
    // carrying the same counter still opens.
    const orr = try r.open(&out, &good, t0);
    try testing.expectEqualSlices(u8, "genuine", out[0..7]);
    try testing.expectEqual(@as(u64, 0), orr.counter);
}

test "window: agrees with a brute-force oracle over a randomised trace" {
    // A plain set of committed counters plus the same "older than capacity ⇒
    // dropped" rule. The circular bitmap must agree on every step — this is
    // what pins `capacity = bits - 64` (with capacity = bits the bitmap would
    // alias a stale block and disagree).
    inline for (.{ 128, 256, 1024 }) |bits| {
        const W = ReplayWindow(bits);
        var w = W{};
        var seen = std.AutoHashMap(u64, void).init(testing.allocator);
        defer seen.deinit();
        var highest: u64 = 0;
        var started = false;

        var prng = std.Random.DefaultPrng.init(0xA11CE + bits);
        const rnd = prng.random();
        for (0..20_000) |_| {
            const roll = rnd.intRangeAtMost(u8, 0, 99);
            const counter: u64 = if (!started)
                rnd.intRangeAtMost(u64, 0, 32)
            else if (roll < 55)
                highest + rnd.intRangeAtMost(u64, 1, 3)
            else if (roll < 90)
                highest -| rnd.intRangeAtMost(u64, 0, W.capacity + 4)
            else
                highest -| rnd.intRangeAtMost(u64, 0, W.capacity * 3);

            const ref = !started or counter > highest or
                (highest - counter <= W.capacity and seen.get(counter) == null);
            try testing.expectEqual(ref, w.accepts(counter));
            if (ref) {
                w.commit(counter);
                try seen.put(counter, {});
                if (!started or counter > highest) highest = counter;
                started = true;
            }
        }
    }
}

test "window: a jump clear of the whole bitmap resets it without stale bits" {
    const W = ReplayWindow(128);
    var w = W{};
    w.commit(5);
    try testing.expect(!w.accepts(5));
    // Jump far beyond the bitmap's span: every old bit must be gone, and a
    // counter one capacity behind the new mark must be treated as unseen.
    w.commit(1_000_000);
    try testing.expectEqual(@as(?u64, 1_000_000), w.highest());
    try testing.expect(w.accepts(1_000_000 - W.capacity));
    try testing.expect(!w.accepts(1_000_000 - W.capacity - 1)); // out of window
    try testing.expect(!w.accepts(1_000_000)); // the mark itself
    // Counter 0 is an ordinary counter, not "nothing received yet".
    var fresh = W{};
    try testing.expectEqual(@as(?u64, null), fresh.highest());
    try testing.expect(fresh.accepts(0));
    fresh.commit(0);
    try testing.expectEqual(@as(?u64, 0), fresh.highest());
    try testing.expect(!fresh.accepts(0));
    fresh.reset();
    try testing.expect(fresh.accepts(0));
}

// ── counter limits ─────────────────────────────────────────────────────────

test "seal refuses at REJECT_AFTER_MESSAGES instead of wrapping the nonce" {
    const key = testKey(12);
    var s = SendSession.init(key, 3, t0);
    var buf: [64]u8 = undefined;

    // One below the limit still works …
    s.seekUnsafeForTest(reject_after_messages - 1);
    const r = try s.seal(&buf, "last", t0);
    try testing.expectEqual(reject_after_messages - 1, r.counter);
    try testing.expectEqual(reject_after_messages, s.counter);
    // … and the very next one fails, leaving the counter untouched.
    try testing.expectError(error.MessageLimitReached, s.seal(&buf, "one too many", t0));
    try testing.expectEqual(reject_after_messages, s.counter);
    // Far past the limit fails too (no wrap-around window of validity).
    s.seekUnsafeForTest(std.math.maxInt(u64));
    try testing.expectError(error.MessageLimitReached, s.seal(&buf, "wrapped", t0));
}

test "open refuses a counter at or past REJECT_AFTER_MESSAGES" {
    const key = testKey(13);
    var s = SendSession.init(key, 3, t0);
    var r = RecvSession.init(key, 3, t0);
    var buf: [64]u8 = undefined;
    var out: [64]u8 = undefined;

    s.seekUnsafeForTest(reject_after_messages - 1);
    const sr = try s.seal(&buf, "last", t0);
    _ = try r.open(&out, buf[0..sr.len], t0); // opens: still legal
    try testing.expectEqual(@as(u64, reject_after_messages - 1), r.window.highest().?);

    // Forge the header's counter to the limit: rejected before any crypto,
    // by its own error rather than as an authentication failure.
    std.mem.writeInt(u64, buf[8..16], reject_after_messages, .little);
    try testing.expectError(error.MessageLimitReached, r.open(&out, buf[0..sr.len], t0));
    std.mem.writeInt(u64, buf[8..16], std.math.maxInt(u64), .little);
    try testing.expectError(error.MessageLimitReached, r.open(&out, buf[0..sr.len], t0));
}

test "rekey is signalled at REKEY_AFTER_MESSAGES, not silently continued" {
    const key = testKey(14);
    var s = SendSession.init(key, 3, t0);
    var r = RecvSession.init(key, 3, t0);
    var buf: [64]u8 = undefined;
    var out: [64]u8 = undefined;

    s.seekUnsafeForTest(rekey_after_messages - 1);
    try testing.expect(!s.rekeyDue(t0));
    var sr = try s.seal(&buf, "before", t0);
    try testing.expectEqual(RekeyState.ok, sr.rekey);
    var orr = try r.open(&out, buf[0..sr.len], t0);
    try testing.expectEqual(RekeyState.ok, orr.rekey);
    try testing.expect(!r.rekeyDue(t0));

    // At the limit: the session keeps working (there is 2^60 of margin to
    // REJECT_AFTER_MESSAGES) but every seal/open now says `.due`.
    try testing.expect(s.rekeyDue(t0));
    sr = try s.seal(&buf, "at the limit", t0);
    try testing.expectEqual(rekey_after_messages, sr.counter);
    try testing.expectEqual(RekeyState.due, sr.rekey);
    orr = try r.open(&out, buf[0..sr.len], t0);
    try testing.expectEqual(RekeyState.due, orr.rekey);
    try testing.expect(r.rekeyDue(t0));
}

// ── session lifetime: the CLOCK half of §6.1 ───────────────────────────────
//
// Every boundary below is written in LITERAL seconds since the session's
// birth, never as `reject_after_time_s ± 1`: the point of these tests is the
// delivered number (180 s / 120 s), which is what a peer's own timers are set
// against and what the docs promise. Written relative to the constant they
// would stay green if 180 became 18 000 and a session outlived its keys by two
// orders of magnitude.

test "lifetime: seal refuses at 180 seconds, and 179 still works" {
    const key = testKey(20);
    const born: u64 = 1_000_000;
    var s = SendSession.init(key, 9, born);
    var buf: [64]u8 = undefined;

    _ = try s.seal(&buf, "at birth", born);
    _ = try s.seal(&buf, "one second in", born + 1);
    _ = try s.seal(&buf, "179 seconds in", born + 179); // last legal second
    try testing.expect(!s.expired(born + 179));

    try testing.expectError(error.SessionExpired, s.seal(&buf, "180", born + 180));
    try testing.expect(s.expired(born + 180));
    try testing.expectError(error.SessionExpired, s.seal(&buf, "an hour later", born + 3600));
    // Refusal consumes nothing: the counter still sits where the three
    // successful seals left it.
    try testing.expectEqual(@as(u64, 3), s.counter);
}

test "lifetime: open refuses at 180 seconds, and the packet is otherwise perfect" {
    const key = testKey(21);
    const born: u64 = 5_000;
    var s = SendSession.init(key, 4, born);
    var r = RecvSession.init(key, 4, born);
    var out: [64]u8 = undefined;

    var early: [overhead + 16]u8 = undefined;
    _ = try s.seal(&early, "in time", born + 10);
    var late: [overhead + 16]u8 = undefined;
    _ = try s.seal(&late, "too late", born + 100);

    _ = try r.open(&out, &early, born + 179); // last legal second
    // Same session, same key, a counter the window has never seen, a tag that
    // verifies — refused purely on age.
    try testing.expectError(error.SessionExpired, r.open(&out, &late, born + 180));
    try testing.expectError(error.SessionExpired, r.open(&out, &late, born + 100_000));
    try testing.expect(r.expired(born + 180));
    // Rejected on age BEFORE the AEAD ran, so the window never recorded it:
    // a receiver that is rekeyed rather than expired would still accept it.
    var fresh = RecvSession.init(key, 4, born);
    _ = try fresh.open(&out, &late, born + 179);
}

test "lifetime: rekey is due at 120 seconds, well before the session dies" {
    const key = testKey(22);
    const born: u64 = 42;
    var s = SendSession.init(key, 6, born);
    var r = RecvSession.init(key, 6, born);
    var buf: [64]u8 = undefined;
    var out: [64]u8 = undefined;

    try testing.expect(!s.rekeyDue(born + 119));
    try testing.expect(!r.rekeyDue(born + 119));
    var sr = try s.seal(&buf, "119", born + 119);
    try testing.expectEqual(RekeyState.ok, sr.rekey);
    var orr = try r.open(&out, buf[0..sr.len], born + 119);
    try testing.expectEqual(RekeyState.ok, orr.rekey);

    // At 120 s the session still carries traffic — this is a deadline, not a
    // failure — but every seal and open now says so.
    try testing.expect(s.rekeyDue(born + 120));
    try testing.expect(r.rekeyDue(born + 120));
    sr = try s.seal(&buf, "120", born + 120);
    try testing.expectEqual(RekeyState.due, sr.rekey);
    orr = try r.open(&out, buf[0..sr.len], born + 120);
    try testing.expectEqual(RekeyState.due, orr.rekey);
    // …and there are 60 more seconds of margin before it stops working.
    sr = try s.seal(&buf, "179", born + 179);
    try testing.expectEqual(RekeyState.due, sr.rekey);
}

test "lifetime: a clock that runs backwards cannot age a session out" {
    // `now_s` is the caller's, so it can jump. A naive `now_s - born_s` would
    // wrap a one-second backward step into ~1.8e19 seconds of age and kill a
    // brand-new session; the saturating subtraction makes it age 0.
    const key = testKey(23);
    const born: u64 = 1_000_000;
    var s = SendSession.init(key, 8, born);
    var r = RecvSession.init(key, 8, born);
    var buf: [64]u8 = undefined;
    var out: [64]u8 = undefined;

    try testing.expectEqual(@as(u64, 0), ageSeconds(born, born - 1));
    try testing.expectEqual(@as(u64, 0), ageSeconds(born, 0));
    const sr = try s.seal(&buf, "clock stepped back", born - 5_000);
    try testing.expectEqual(RekeyState.ok, sr.rekey);
    const orr = try r.open(&out, buf[0..sr.len], 0);
    try testing.expectEqual(RekeyState.ok, orr.rekey);
    try testing.expect(!s.expired(0));
    try testing.expect(!r.expired(0));
}

test "lifetime: Session.init gives both halves one birth time" {
    const keys = TransportKeys{ .send = testKey(24), .recv = testKey(25) };
    const born: u64 = 777;
    var a = Session.init(keys, 1, 2, born);
    try testing.expectEqual(born, a.send.born_s);
    try testing.expectEqual(born, a.recv.born_s);
    try testing.expect(!a.expired(born + 179));
    try testing.expect(a.expired(born + 180));

    var wire: [64]u8 = undefined;
    try testing.expectError(error.SessionExpired, a.send.seal(&wire, "x", born + 180));
}

// ── replay window: the unrepresentable counter ─────────────────────────────

test "window: maxInt(u64) is refused, not an integer-overflow panic" {
    // The window tracks `counter + 1`, so `maxInt(u64)` has no representation.
    // `RecvSession.open` can never reach it (it refuses at
    // `reject_after_messages` = maxInt − 8192 first), but `ReplayWindow` is a
    // public generic whose doc invites callers to wire their own demultiplexer
    // against it — and the counter is an attacker-chosen header field.
    const W = ReplayWindow(128);
    var w = W{};
    w.commit(10);
    try testing.expect(!w.accepts(std.math.maxInt(u64)));
    try testing.expect(w.accepts(std.math.maxInt(u64) - 1)); // its neighbour is ordinary
    w.commit(std.math.maxInt(u64)); // must be a no-op, not a wrap
    try testing.expectEqual(@as(?u64, 10), w.highest());
    // The neighbouring value is ordinary: only the single unrepresentable one
    // is special-cased.
    var w2 = W{};
    try testing.expect(w2.accepts(std.math.maxInt(u64) - 1));
    w2.commit(std.math.maxInt(u64) - 1);
    try testing.expectEqual(@as(?u64, std.math.maxInt(u64) - 1), w2.highest());
    try testing.expect(!w2.accepts(std.math.maxInt(u64) - 1));
    try testing.expect(!w2.accepts(std.math.maxInt(u64)));
}

// ── untrusted input ────────────────────────────────────────────────────────

test "open rejects truncated, wrong-type, wrong-receiver and tampered messages" {
    const key = testKey(15);
    var s = SendSession.init(key, 0x1234, t0);
    var r = RecvSession.init(key, 0x1234, t0);
    var buf: [overhead + 16]u8 = undefined;
    const n = (try s.seal(&buf, "twelve bytes", t0)).len;
    var out: [64]u8 = undefined;

    // Shorter than the 32-byte minimum.
    try testing.expectError(error.Truncated, r.open(&out, buf[0 .. overhead - 1], t0));
    try testing.expectError(error.Truncated, r.open(&out, buf[0..0], t0));
    // A handshake message type, and a type-4 message with a dirty reserved byte.
    {
        var bad = buf;
        bad[0] = 1;
        try testing.expectError(error.NotTransportData, r.open(&out, bad[0..n], t0));
        bad = buf;
        bad[2] = 1; // reserved byte must be zero
        try testing.expectError(error.NotTransportData, r.open(&out, bad[0..n], t0));
    }
    // Addressed to another session index.
    {
        var bad = buf;
        std.mem.writeInt(u32, bad[4..8], 0x1235, .little);
        try testing.expectError(error.WrongReceiver, r.open(&out, bad[0..n], t0));
    }
    // Tampered ciphertext / tag / counter → authentication failure, and the
    // output buffer is zeroed rather than left holding garbage.
    for ([_]usize{ header_len, n - 1, 8 }) |off| {
        var bad = buf;
        bad[off] +%= 1;
        var fresh = RecvSession.init(key, 0x1234, t0);
        try testing.expectError(error.AuthenticationFailed, fresh.open(&out, bad[0..n], t0));
        for (out[0..16]) |b| try testing.expectEqual(@as(u8, 0), b);
    }
    // The untouched message still opens.
    var fresh = RecvSession.init(key, 0x1234, t0);
    const orr = try fresh.open(&out, buf[0..n], t0);
    try testing.expectEqualSlices(u8, "twelve bytes", out[0..12]);
    try testing.expectEqual(@as(usize, 16), orr.len);
}

test "buffer sizing: seal and open reject an undersized output buffer" {
    const key = testKey(16);
    var s = SendSession.init(key, 1, t0);
    var too_small: [overhead + 16 - 1]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, s.seal(&too_small, "seventeen bytes!!", t0));
    // The exact size is enough (17 bytes pads to 32).
    var exact: [overhead + 32]u8 = undefined;
    const n = (try s.seal(&exact, "seventeen bytes!!", t0)).len;
    try testing.expectEqual(exact.len, n);

    var r = RecvSession.init(key, 1, t0);
    var out_small: [31]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, r.open(&out_small, exact[0..n], t0));
    var out_exact: [32]u8 = undefined;
    _ = try r.open(&out_exact, exact[0..n], t0);
}

test "seal rejects a plaintext that cannot fit one UDP datagram" {
    const key = testKey(17);
    var s = SendSession.init(key, 1, t0);
    const big = try testing.allocator.alloc(u8, max_payload + 1);
    defer testing.allocator.free(big);
    @memset(big, 0);
    var tiny: [1]u8 = undefined;
    // Checked before the output-buffer size, so a 1-byte `out` still reports
    // the real reason.
    try testing.expectError(error.PacketTooLarge, s.seal(&tiny, big, t0));
    try testing.expectEqual(@as(u64, 0), s.counter); // nothing consumed
}

// ── fuzz: open over arbitrary bytes never panics ───────────────────────────

fn fuzzOpen(_: void, smith: *std.testing.Smith) !void {
    var buf: [160]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    var out: [160]u8 = undefined;
    var r = RecvSession.init(@splat(0x5A), 0, t0);
    // Arbitrary bytes must only ever yield a typed error or a plaintext length
    // <= input — never a panic, an OOB read, or an allocation.
    const orr = r.open(&out, buf[0..len], t0) catch return;
    try testing.expect(orr.len + overhead == len);
}

test "fuzz: RecvSession.open never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzOpen, .{});
}
