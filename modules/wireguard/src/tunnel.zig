// SPDX-License-Identifier: MIT
//! `Tunnel`: the state machine of one WireGuard peer, sans-IO. Whitepaper §6:
//! when to start a handshake, when to retry it and when to give up, when to send
//! a keepalive, which of the three live sessions a packet belongs to, when
//! keys are destroyed. It holds no socket, no TUN device and no clock, and it
//! allocates nothing: the caller feeds it plaintext from its TUN, datagrams from
//! its UDP socket and the time, and writes out what it returns.
//!
//!     var t: Tunnel = undefined;
//!     try Tunnel.init(&t, &.{ .allowed_ips = null, .static_private = &priv, .remote_static = peer }, io, clock);
//!     defer t.wipe();
//!
//!     // a packet from the TUN device
//!     switch (try t.encapsulate(io, clock, packet, &buf)) {
//!         .network => |bytes| sendToPeer(bytes),
//!         else => {},
//!     }
//!     // a datagram from the socket (errors are drops: log, never answer)
//!     const r = t.decapsulate(io, clock, datagram, &buf) catch continue;
//!     if (r.authenticated) peer_endpoint = source_of_datagram; // roaming
//!     switch (r.output) { .network => |b| sendToPeer(b), .tunnel => |p| writeToTun(p), .none => {} }
//!     // then, and on a timer (`nextDeadline`): until it says .none
//!     while (true) switch (try t.poll(io, clock, &buf)) {
//!         .network => |b| sendToPeer(b),
//!         else => break,
//!     };
//!
//! A device with many peers keeps one `Tunnel` per peer and routes: a data,
//! response or cookie datagram by asking each tunnel `ownsIndex(receiver_index)`
//! or its own table of them (or by `tunnelIdOf` with `Options.routed_id`, at the
//! cost that option states), an initiation by `handshake.peekInitiation` (one X25519,
//! however many peers), a peer-table lookup of the static key it returns and
//! `Tunnel.acceptInitiation`. The under-load gate (`handshake.CookieChecker.admit`)
//! runs in front of that, once per device. Picking the peer of an outgoing packet is
//! longest-prefix matching, `netaddr`/`trie` territory; a packet's inner source is
//! checked here against `Options.allowed_ips`, unless the caller wrote `null`.
//!
//! Timer rules ported from wireguard-go (`device/timers.go`, `device/send.go`,
//! `device/receive.go`, `device/noise-protocol.go` at b3bc704ef0ee, MIT; see
//! ../NOTICE): the deadlines replace its timer objects, so `poll` is the one
//! place they fire. The sans-IO shape (encapsulate/decapsulate/update) follows
//! boringtun's `noise::Tunn` (0.7.1, BSD-3-Clause).

const std = @import("std");
const entropy = @import("entropy");
const burn = @import("burn.zig");
const noise = @import("noise.zig");
const hs = @import("handshake.zig");
const root = @import("root.zig");
const transport = @import("transport.zig");

const Handshake = hs.Handshake;

// §6.1 timers that say when to send something; the session limits proper are
// transport.zig's `reject_after_*` / `rekey_after_*`.

/// REKEY_TIMEOUT: an initiation is retried after this (plus jitter).
pub const rekey_timeout_ms: u64 = 5_000;
/// Jitter on every retry and on the no-reply handshake, in ms (exclusive).
pub const rekey_timeout_jitter_ms: u16 = 334;
/// REKEY_ATTEMPT_TIME / REKEY_TIMEOUT: retries before giving up (18 × 5 s = 90 s).
pub const max_handshake_retries: u16 = 18;
/// KEEPALIVE_TIMEOUT: data received and nothing to send back for this long
/// means an empty packet goes out.
pub const keepalive_timeout_ms: u64 = 10_000;
/// How long keys may stay in memory with no new handshake (REJECT_AFTER_TIME × 3).
pub const zero_keys_after_ms: u64 = transport.reject_after_time_s * 3 * 1000;
/// Initiations from one peer closer together than this are dropped.
pub const initiation_rate_ms: u64 = 50;
/// The initiator re-keys on receive at REJECT_AFTER_TIME − KEEPALIVE − REKEY_TIMEOUT.
const rekey_on_receive_ms: u64 = transport.reject_after_time_s * 1000 - keepalive_timeout_ms - rekey_timeout_ms;

/// The smallest `out` any handshake message fits. The bigger answer is `sealedLen`
/// of the largest packet the caller hands in.
pub const min_out_len: usize = @sizeOf(hs.MessageInitiation);

/// The caller's time.
///
/// `mono_ms` must keep counting across suspend: CLOCK_BOOTTIME on Linux
/// (`std.Io.Clock.boot`), not CLOCK_MONOTONIC. A session's limits are in real time,
/// and a clock that stops during suspend brings a session back that should be dead.
/// Time that goes backwards is saturated, nothing wraps or panics, but it EXTENDS the
/// life of keys by as long as it stays behind: the 180 s and 540 s are measured on this
/// clock, and nothing here can see the difference. Keep it monotonic.
///
/// `tai64n` is wall time for the initiation's replay stamp (`tai64n`): it must grow
/// across restarts, or the peer's replay check drops every initiation.
pub const Clock = struct {
    mono_ms: u64,
    tai64n: [12]u8,
};

/// TAI64N of a Unix time, the low 24 bits of the nanoseconds cleared: a stamp
/// on the wire says when a peer was active, no finer than the rate limit needs.
pub fn tai64n(unix_s: u64, nanos: u32) [12]u8 {
    var out: [12]u8 = undefined;
    std.mem.writeInt(u64, out[0..8], (@as(u64, 1) << 62) +% 10 +% unix_s, .big);
    std.mem.writeInt(u32, out[8..12], nanos & ~@as(u32, 0xff_ffff), .big);
    return out;
}

/// The top 24 bits of a session index: the `Options.routed_id` of the tunnel that
/// owns it, for a device that opted into routed indices (see there). Meaningless
/// for the default random ones.
pub fn tunnelIdOf(receiver_index: u32) u24 {
    return @truncate(receiver_index >> 8);
}

/// The source address of an inner IP packet (4 or 16 bytes, a slice of `packet`),
/// or null if it is not a whole IP header. For the device's allowed-ips check.
pub fn innerSource(packet: []const u8) ?[]const u8 {
    if (packet.len == 0) return null;
    return switch (packet[0] >> 4) {
        4 => if (packet.len >= 20) packet[12..16] else null,
        6 => if (packet.len >= 40) packet[8..24] else null,
        else => null,
    };
}

/// The destination address of an inner IP packet, as `innerSource`. For picking
/// the peer of an outgoing packet.
pub fn innerDestination(packet: []const u8) ?[]const u8 {
    if (packet.len == 0) return null;
    return switch (packet[0] >> 4) {
        4 => if (packet.len >= 20) packet[16..20] else null,
        6 => if (packet.len >= 40) packet[24..40] else null,
        else => null,
    };
}

/// The length an inner IP packet says it has, or null if the header is not whole
/// or claims more than `packet` holds. Padding beyond it is not part of the packet.
fn innerLength(packet: []const u8) ?usize {
    if (packet.len == 0) return null;
    const n: usize = switch (packet[0] >> 4) {
        4 => blk: {
            if (packet.len < 20) return null;
            const total = std.mem.readInt(u16, packet[2..4], .big);
            if (total < 20) return null;
            break :blk total;
        },
        6 => blk: {
            if (packet.len < 40) return null;
            break :blk @as(usize, std.mem.readInt(u16, packet[4..6], .big)) + 40;
        },
        else => return null,
    };
    return if (n <= packet.len) n else null;
}

pub const Options = struct {
    /// Our static private key. Copied.
    static_private: *const hs.PrivateKey,
    /// The peer's static public key.
    remote_static: hs.PublicKey,
    /// Pre-shared key; null = none. Copied.
    preshared_key: ?*const hs.PresharedKey = null,
    /// Seconds; 0 = off. With a non-zero value the first `poll` starts a handshake.
    persistent_keepalive_s: u16 = 0,
    /// Cryptokey routing, required so nobody gets the unsafe side by default: the
    /// prefixes this peer's inner packets may come FROM. A packet from anywhere else
    /// is dropped (`Drop.disallowed_source`). Write `null` to take that check on
    /// yourself, as a device with a shared prefix table does (`innerSource` reads the
    /// address): without any check a peer can spoof any inner source. Scanned per
    /// packet; the caller's memory, kept until `wipe`.
    allowed_ips: ?[]const root.AllowedIp,
    /// Null, the default: every session index is 32 random bits, redrawn on a clash
    /// with this tunnel's own, as wireguard-go's. Set: the index is this id in the top
    /// 24 bits and a counter in the low 8, so a device can route by `tunnelIdOf`
    /// without a table. **The cost:** a pending index is then found within 256
    /// guesses, and each right guess with a forged response costs us 2 X25519 (mac1's
    /// key is public); and the counter tells an observer how many handshakes the
    /// tunnel made. Unique per device.
    routed_id: ?u24 = null,
    /// Where packets wait for a session, oldest dropped when full (the caller's
    /// memory, kept until `wipe`; holds plaintext; wiped when released).
    /// Empty = a packet sent before there is a session is dropped.
    stage: []u8 = &.{},
};

pub const InitError = error{
    /// The peer's key is a low-order point, or our private key gives none.
    InvalidKey,
};

/// What one call produced. The slices are in the caller's `out`.
pub const Output = union(enum) {
    /// Nothing to send or deliver.
    none,
    /// Send these bytes to the peer over UDP.
    network: []u8,
    /// A decrypted inner IP packet, without its padding, for the TUN device.
    tunnel: []u8,
};

/// Why an authentic packet was not delivered (`output` is `.none`, its plaintext
/// wiped from `out`). The session is unaffected.
pub const Drop = enum {
    no,
    /// What the peer sent is no whole IP packet.
    invalid_inner_packet,
    /// Its inner source is not in `Options.allowed_ips`.
    disallowed_source,
};

pub const Decapsulated = struct {
    output: Output,
    /// The datagram proved it comes from the peer. This is the moment to update
    /// the peer's endpoint to the datagram's source address (roaming). True for a
    /// `dropped` packet too, as in wireguard-go: it holds the session's key, whatever
    /// it carries.
    authenticated: bool,
    dropped: Drop = .no,
};

pub const EncapsulateError = error{
    /// `out` is smaller than `sealedLen(packet.len)` or `min_out_len`.
    BufferTooSmall,
    /// More than `transport.max_payload`.
    PacketTooLarge,
};

/// Every error of `decapsulate` is a drop, and the protocol sends nothing back. The
/// datagram leaves no trace in the tunnel: no counter, timer, window or session moves,
/// and no session index is spent. (Keys whose deadline had already passed go first,
/// whatever arrives: that is the time, not the datagram.) `out` may hold zeroes.
/// A packet that authenticates and then cannot be delivered is no error: `Drop`.
pub const DecapsulateError = error{
    /// `out` is smaller than the datagram or `min_out_len`.
    BufferTooSmall,
    /// `datagram` and `out` overlap: decryption would destroy its own input.
    BufferOverlap,
    /// No WireGuard message of that type has that length.
    InvalidPacket,
    /// mac1 is wrong: not addressed to our static key.
    InvalidMac1,
    /// Decryption failed: forged, or keys that do not match.
    AuthenticationFailed,
    /// The initiation is from another static key than this tunnel's peer.
    UnknownPeer,
    /// The initiation's timestamp is not newer than the last accepted one.
    StaleTimestamp,
    /// The peer's initiations come faster than one per `initiation_rate_ms`.
    Flood,
    /// A response or cookie reply to no handshake of ours, or a data packet for
    /// no live session.
    UnknownIndex,
    /// A duplicate counter or one that fell out of the replay window.
    Replayed,
    /// The session is past its message or time limit.
    SessionExpired,
};

pub const PollError = EncapsulateError;

pub const Stats = struct {
    /// Wire bytes of transport messages sent.
    tx_bytes: u64,
    /// Wire bytes of transport messages accepted.
    rx_bytes: u64,
    /// `mono_ms` of the last completed handshake, or null.
    last_handshake_ms: ?u64,
    /// Retries of the current handshake attempt.
    handshake_retries: u16,
    /// Packets lost: the stage was full, off, or given up on, or one was larger
    /// than the `out` it should have gone into.
    staged_dropped: u64,
    /// Authentic packets not delivered (`Drop`).
    inner_dropped: u64,
};

const Slot = struct {
    session: transport.Session,
    local_index: u32,
    is_initiator: bool,
    created_ms: u64,

    fn usable(s: *const Slot, now_s: u64) bool {
        return !s.session.send.expired(now_s) and s.session.send.counter < transport.reject_after_messages;
    }
};

fn wipeSlot(s: *?Slot) void {
    std.crypto.secureZero(u8, std.mem.asBytes(s));
    s.* = null;
}

/// `previous` only receives: it has no use for its send key. (`next` keeps its own:
/// it sends as soon as it is confirmed.)
fn dropSendKey(s: *?Slot) void {
    if (s.*) |*v| std.crypto.secureZero(u8, &v.session.send.key);
}

/// Whether `ip`'s prefix holds `addr`. A hand-built entry that does not add up holds
/// nothing.
fn prefixContains(ip: *const root.AllowedIp, addr: []const u8) bool {
    if (!ip.valid() or ip.bytes().len != addr.len) return false;
    const whole: usize = ip.cidr / 8;
    if (!std.mem.eql(u8, ip.bytes()[0..whole], addr[0..whole])) return false;
    const rest: u3 = @intCast(ip.cidr % 8);
    if (rest == 0) return true;
    const mask: u8 = @truncate(@as(u16, 0xff00) >> rest);
    return (ip.bytes()[whole] ^ addr[whole]) & mask == 0;
}

/// One peer's state. In place: it holds keys, and it is about 4 KiB. One owner;
/// not shared between threads.
pub const Tunnel = struct {
    static_keypair: hs.Keypair,
    remote_static: hs.PublicKey,
    preshared_key: hs.PresharedKey,
    static_static: [32]u8,
    persistent_keepalive_s: u16,
    allowed_ips: ?[]const root.AllowedIp,
    routed_id: ?u24,
    index_seq: u8,
    peer_cookie: hs.PeerCookie,

    /// The handshake we initiated and await a response to.
    pending: ?Handshake = null,
    /// `current` sends and receives. `previous` only receives (packets still in
    /// flight across a rekey). `next` is a responder's session, unused for
    /// sending until the initiator's first packet under it confirms it.
    current: ?Slot = null,
    previous: ?Slot = null,
    next: ?Slot = null,

    stage: []u8,
    stage_head: usize = 0,
    stage_tail: usize = 0,

    // Deadlines in mono_ms; null = not armed. One per timer of wireguard-go.
    retransmit_at: ?u64 = null,
    send_keepalive_at: ?u64 = null,
    need_another_keepalive: bool = false,
    new_handshake_at: ?u64 = null,
    zero_keys_at: ?u64 = null,
    persistent_at: ?u64 = null,

    want_initiation: bool = false,
    retries: u16 = 0,
    sent_last_minute: bool = false,
    last_sent_handshake_ms: ?u64 = null,
    last_initiation_ms: ?u64 = null,
    last_timestamp: [12]u8 = @splat(0),
    last_handshake_ms: ?u64 = null,
    tx_bytes: u64 = 0,
    rx_bytes: u64 = 0,
    staged_dropped: u64 = 0,
    inner_dropped: u64 = 0,

    pub fn init(out: *Tunnel, opts: *const Options, io: std.Io, clock: Clock) InitError!void {
        return burn.run(burn.keypair_burn, InitError!void, initBody, .{ out, opts, io, clock });
    }

    fn initBody(out: *Tunnel, opts: *const Options, io: std.Io, clock: Clock) InitError!void {
        var kp: hs.Keypair = undefined;
        defer std.crypto.secureZero(u8, &kp.private);
        hs.Keypair.fromPrivateKey(opts.static_private, &kp) catch return error.InvalidKey;
        var ss: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &ss);
        noise.X25519.scalarmultInto(&ss, &kp.private, opts.remote_static) catch return error.InvalidKey;
        var seq: [1]u8 = undefined;
        entropy.fill(io, &seq);
        out.* = .{
            .static_keypair = kp,
            .remote_static = opts.remote_static,
            .preshared_key = if (opts.preshared_key) |p| p.* else @splat(0),
            .static_static = ss,
            .persistent_keepalive_s = opts.persistent_keepalive_s,
            .allowed_ips = opts.allowed_ips,
            .routed_id = opts.routed_id,
            .index_seq = seq[0],
            .peer_cookie = hs.PeerCookie.init(opts.remote_static),
            .stage = opts.stage,
            .persistent_at = if (opts.persistent_keepalive_s != 0) clock.mono_ms else null,
        };
    }

    /// Destroy every key and the staged plaintext. The tunnel is unusable after.
    pub fn wipe(t: *Tunnel) void {
        std.crypto.secureZero(u8, t.stage);
        std.crypto.secureZero(u8, std.mem.asBytes(t));
        t.* = undefined;
    }

    pub fn stats(t: *const Tunnel) Stats {
        return .{
            .tx_bytes = t.tx_bytes,
            .rx_bytes = t.rx_bytes,
            .last_handshake_ms = t.last_handshake_ms,
            .handshake_retries = t.retries,
            .staged_dropped = t.staged_dropped,
            .inner_dropped = t.inner_dropped,
        };
    }

    /// Whether `receiver_index` names a live session or handshake of this tunnel:
    /// how a device without routed indices finds the tunnel of a datagram.
    pub fn ownsIndex(t: *const Tunnel, receiver_index: u32) bool {
        return t.indexInUse(receiver_index);
    }

    /// Whether a packet handed to `encapsulate` now goes straight out.
    // secret-api-ok: reads the send counter and born_s (public); no key is touched
    pub fn hasSession(t: *const Tunnel, clock: Clock) bool {
        const c = if (t.current) |*c| c else return false;
        return c.usable(clock.mono_ms / 1000);
    }

    /// The earliest `mono_ms` at which `poll` has something to do, for the
    /// event loop's sleep. Null: nothing until the next packet. `now`-or-before
    /// when something is already due.
    pub fn nextDeadline(t: *const Tunnel, clock: Clock) ?u64 {
        var best: ?u64 = null;
        for ([_]?u64{ t.retransmit_at, t.send_keepalive_at, t.new_handshake_at, t.zero_keys_at, t.persistent_at }) |d| {
            if (d) |v| best = if (best) |b| @min(b, v) else v;
        }
        if (t.want_initiation) best = 0;
        if (t.stage_head != t.stage_tail and t.hasSession(clock)) best = 0;
        return best;
    }

    // ── from the TUN device ─────────────────────────────────────────────────

    /// One packet from the TUN device (empty = a keepalive). With a session it
    /// comes back sealed; without one it is staged and the answer is an initiation,
    /// or `.none` when one went out within the last `rekey_timeout_ms`. `packet`
    /// is not kept, and may overlap `out`. Call `poll` afterwards: it may hold a
    /// due rekey.
    pub fn encapsulate(t: *Tunnel, io: std.Io, clock: Clock, packet: []const u8, out: []u8) EncapsulateError!Output {
        if (packet.len > transport.max_payload) return error.PacketTooLarge;
        if (out.len < min_out_len) return error.BufferTooSmall;
        t.expireKeys(clock.mono_ms);
        if (t.hasSession(clock)) {
            // Queue order: what waits for a session goes first.
            return t.sealCurrent(clock, packet, out);
        }
        t.stagePacket(packet);
        return t.initiate(io, clock, false, out);
    }

    /// Start a handshake now, session or no session, unless one went out within
    /// `rekey_timeout_ms` (`.none`). Output is the initiation.
    pub fn initiateHandshake(t: *Tunnel, io: std.Io, clock: Clock, out: []u8) EncapsulateError!Output {
        return t.initiate(io, clock, false, out);
    }

    fn sealCurrent(t: *Tunnel, clock: Clock, packet: []const u8, out: []u8) EncapsulateError!Output {
        const now = clock.mono_ms;
        const now_s = now / 1000;
        const c = &t.current.?;
        const r = c.session.send.seal(out, packet, now_s) catch |err| switch (err) {
            error.BufferTooSmall => return error.BufferTooSmall,
            error.PacketTooLarge => return error.PacketTooLarge,
            // `hasSession` was true a moment ago and the clock is the same.
            error.MessageLimitReached, error.SessionExpired => return .none,
        };
        t.tx_bytes +%= r.len;
        t.authenticatedTraversal(now);
        t.authenticatedSent();
        if (packet.len != 0 and t.new_handshake_at == null)
            t.new_handshake_at = now +| keepalive_timeout_ms +| rekey_timeout_ms +| t.jitter(now);
        // keepKeyFreshSending: past the message limit, or the initiator's time limit.
        if (c.session.send.counter > transport.rekey_after_messages or
            (c.is_initiator and now -| c.created_ms > transport.rekey_after_time_s * 1000))
            t.want_initiation = true;
        return .{ .network = out[0..r.len] };
    }

    /// Milliseconds of jitter. It only spreads retries in time, nothing depends on
    /// it being unpredictable, so it mixes what is at hand instead of a syscall
    /// per packet: the random index sequence, the time and the tx counter.
    fn jitter(t: *const Tunnel, now: u64) u64 {
        const x = (@as(u64, t.index_seq) +% now +% t.tx_bytes) *% 11400714819323198485;
        return (x >> 40) % rekey_timeout_jitter_ms;
    }

    fn authenticatedTraversal(t: *Tunnel, now: u64) void {
        if (t.persistent_keepalive_s != 0) t.persistent_at = now +| @as(u64, t.persistent_keepalive_s) * 1000;
    }

    fn authenticatedSent(t: *Tunnel) void {
        t.send_keepalive_at = null;
        t.need_another_keepalive = false;
    }

    fn authenticatedReceived(t: *Tunnel) void {
        t.new_handshake_at = null;
    }

    fn sessionDerived(t: *Tunnel, now: u64) void {
        t.zero_keys_at = now +| zero_keys_after_ms;
    }

    fn handshakeComplete(t: *Tunnel, now: u64) void {
        t.retransmit_at = null;
        t.retries = 0;
        t.sent_last_minute = false;
        t.last_handshake_ms = now;
    }

    /// Start or retry a handshake. A retry keeps the attempt count; at most one
    /// initiation per `rekey_timeout_ms` either way.
    fn initiate(t: *Tunnel, io: std.Io, clock: Clock, is_retry: bool, out: []u8) EncapsulateError!Output {
        if (out.len < min_out_len) return error.BufferTooSmall;
        const now = clock.mono_ms;
        if (!is_retry) t.retries = 0;
        if (t.last_sent_handshake_ms) |last| {
            if (now -| last < rekey_timeout_ms) {
                // An armed retry that fired early must not be lost.
                if (is_retry and t.retransmit_at == null) t.retransmit_at = last +| rekey_timeout_ms;
                return .none;
            }
        }
        return burn.run(burn.hs_burn, EncapsulateError!Output, initiateBody, .{ t, io, clock, out });
    }

    fn initiateBody(t: *Tunnel, io: std.Io, clock: Clock, out: []u8) EncapsulateError!Output {
        const now = clock.mono_ms;
        t.wipePending();
        t.pending = .{
            .static_keypair = t.static_keypair,
            .remote_static_public = t.remote_static,
            .preshared_key = t.preshared_key,
            .static_static = t.static_static,
            .cookie = t.peer_cookie.current(now / 1000),
            .local_index = t.nextIndex(io),
        };
        const msg = t.pending.?.createInitiation(io, clock.tai64n) catch {
            // `init` proved the peer's key: an ephemeral cannot refuse it.
            t.wipePending();
            return .none;
        };
        const bytes = std.mem.asBytes(&msg);
        @memcpy(out[0..bytes.len], bytes);
        t.peer_cookie.recordSent(bytes) catch {};
        t.last_sent_handshake_ms = now;
        t.want_initiation = false;
        t.authenticatedTraversal(now);
        t.authenticatedSent();
        t.retransmit_at = now +| rekey_timeout_ms +| t.jitter(now);
        return .{ .network = out[0..bytes.len] };
    }

    fn wipePending(t: *Tunnel) void {
        if (t.pending != null) std.crypto.secureZero(u8, std.mem.asBytes(&t.pending));
        t.pending = null;
    }

    /// The next free session index: 32 random bits (a guess at a pending one costs
    /// an attacker 2^32 tries), or under `routed_id` that id and a counter. Either
    /// way what is in use is skipped; at most four are, so this ends at once.
    fn nextIndex(t: *Tunnel, io: std.Io) u32 {
        while (true) {
            const idx: u32 = if (t.routed_id) |id| blk: {
                t.index_seq +%= 1;
                break :blk (@as(u32, id) << 8) | t.index_seq;
            } else blk: {
                var r: [4]u8 = undefined;
                entropy.fill(io, &r);
                break :blk std.mem.readInt(u32, &r, .little);
            };
            if (t.indexInUse(idx)) continue;
            return idx;
        }
    }

    fn indexInUse(t: *const Tunnel, idx: u32) bool {
        if (t.pending) |*p| if (p.local_index == idx) return true;
        for ([_]*const ?Slot{ &t.current, &t.previous, &t.next }) |s| {
            if (s.*) |*v| if (v.local_index == idx) return true;
        }
        return false;
    }

    // ── the stage ───────────────────────────────────────────────────────────

    /// Keep a packet for when a session exists: oldest out when full (like
    /// wireguard-go's staged queue). Each record is a u16 length and the bytes.
    fn stagePacket(t: *Tunnel, packet: []const u8) void {
        const need = packet.len + 2;
        if (need > t.stage.len) {
            t.staged_dropped +%= 1;
            return;
        }
        // Make room: the free tail first, then the wasted head, then the oldest.
        while (t.stage.len - t.stage_tail < need) {
            if (t.stage_head != 0) {
                const live = t.stage_tail - t.stage_head;
                std.mem.copyForwards(u8, t.stage[0..live], t.stage[t.stage_head..t.stage_tail]);
                std.crypto.secureZero(u8, t.stage[live..t.stage_tail]);
                t.stage_head = 0;
                t.stage_tail = live;
                continue;
            }
            // Full from the start: the record at the head goes.
            t.dropOldest();
        }
        std.mem.writeInt(u16, t.stage[t.stage_tail..][0..2], @intCast(packet.len), .little);
        @memcpy(t.stage[t.stage_tail + 2 ..][0..packet.len], packet);
        t.stage_tail += need;
    }

    fn dropOldest(t: *Tunnel) void {
        const n = std.mem.readInt(u16, t.stage[t.stage_head..][0..2], .little);
        std.crypto.secureZero(u8, t.stage[t.stage_head..][0 .. @as(usize, n) + 2]);
        t.stage_head += @as(usize, n) + 2;
        t.staged_dropped +%= 1;
        if (t.stage_head == t.stage_tail) {
            t.stage_head = 0;
            t.stage_tail = 0;
        }
    }

    /// The stage goes too when a handshake is given up on: those packets are old.
    fn clearStage(t: *Tunnel) void {
        while (t.stage_head != t.stage_tail) t.dropOldest();
    }

    /// Seal the oldest staged packet, if a session exists. One larger than `out`
    /// goes, counted: an `out` of that size can never send it, and it must not stand
    /// in the way of the timers behind it for ever.
    fn flushOne(t: *Tunnel, clock: Clock, out: []u8) EncapsulateError!?Output {
        if (!t.hasSession(clock)) return null;
        while (t.stage_head != t.stage_tail) {
            const n = std.mem.readInt(u16, t.stage[t.stage_head..][0..2], .little);
            if (transport.sealedLen(n) > out.len) {
                t.dropOldest();
                continue;
            }
            const packet = t.stage[t.stage_head + 2 ..][0..n];
            const r = try t.sealCurrent(clock, packet, out);
            std.crypto.secureZero(u8, t.stage[t.stage_head..][0 .. @as(usize, n) + 2]);
            t.stage_head += @as(usize, n) + 2;
            if (t.stage_head == t.stage_tail) {
                t.stage_head = 0;
                t.stage_tail = 0;
            }
            return r;
        }
        return null;
    }

    // ── from the network ────────────────────────────────────────────────────

    /// One UDP datagram. It is not kept, and must not overlap `out`
    /// (`error.BufferOverlap`).
    pub fn decapsulate(t: *Tunnel, io: std.Io, clock: Clock, datagram: []const u8, out: []u8) DecapsulateError!Decapsulated {
        if (out.len < min_out_len) return error.BufferTooSmall;
        const d0 = @intFromPtr(datagram.ptr);
        const o0 = @intFromPtr(out.ptr);
        if (datagram.len != 0 and d0 < o0 +| out.len and o0 < d0 +| datagram.len) return error.BufferOverlap;
        if (datagram.len < 4) return error.InvalidPacket;
        t.expireKeys(clock.mono_ms);
        const kind = std.mem.readInt(u32, datagram[0..4], .little);
        switch (kind) {
            @backingInt(hs.MessageType.handshake_initiation) => {
                if (datagram.len != @sizeOf(hs.MessageInitiation)) return error.InvalidPacket;
                const msg = std.mem.bytesToValue(hs.MessageInitiation, datagram[0..@sizeOf(hs.MessageInitiation)]);
                var peek: hs.InitiationPeek = undefined;
                hs.peekInitiation(&t.static_keypair, &msg, &peek) catch |err| return switch (err) {
                    error.InvalidMac1 => error.InvalidMac1,
                    error.DecryptionFailed => error.AuthenticationFailed,
                };
                defer peek.wipe();
                const o = try t.acceptInitiation(io, clock, &msg, &peek, out);
                return .{ .output = o, .authenticated = true };
            },
            @backingInt(hs.MessageType.handshake_response) => {
                if (datagram.len != @sizeOf(hs.MessageResponse)) return error.InvalidPacket;
                const msg = std.mem.bytesToValue(hs.MessageResponse, datagram[0..@sizeOf(hs.MessageResponse)]);
                return t.consumeResponse(clock, &msg, out);
            },
            @backingInt(hs.MessageType.cookie_reply) => {
                if (datagram.len != @sizeOf(hs.CookieReply)) return error.InvalidPacket;
                const msg = std.mem.bytesToValue(hs.CookieReply, datagram[0..@sizeOf(hs.CookieReply)]);
                // To our initiation, or to a response of ours.
                if (!t.indexInUse(msg.receiver_index)) return error.UnknownIndex;
                t.peer_cookie.consumeReply(msg, clock.mono_ms / 1000) catch return error.AuthenticationFailed;
                // Not from the peer's keys: it proves a path, not an identity.
                return .{ .output = .none, .authenticated = false };
            },
            @backingInt(hs.MessageType.transport_data) => return t.consumeData(clock, datagram, out),
            else => return error.InvalidPacket,
        }
    }

    /// The responder's path after `handshake.peekInitiation` found this tunnel's
    /// peer: the replay and flood checks, the response, the `next` session.
    /// `msg` must be the message peeked, `peek.initiator_static` the key of the
    /// peer this tunnel is for (else `error.UnknownPeer`). Output is the response.
    pub fn acceptInitiation(t: *Tunnel, io: std.Io, clock: Clock, msg: *const hs.MessageInitiation, peek: *const hs.InitiationPeek, out: []u8) DecapsulateError!Output {
        if (out.len < min_out_len) return error.BufferTooSmall;
        return burn.run(burn.hs_burn, DecapsulateError!Output, acceptInitiationBody, .{ t, io, clock, msg, peek, out });
    }

    fn acceptInitiationBody(t: *Tunnel, io: std.Io, clock: Clock, msg: *const hs.MessageInitiation, peek: *const hs.InitiationPeek, out: []u8) DecapsulateError!Output {
        const now = clock.mono_ms;
        var h: Handshake = .{
            .static_keypair = t.static_keypair,
            .remote_static_public = t.remote_static,
            .preshared_key = t.preshared_key,
            .static_static = t.static_static,
            .cookie = t.peer_cookie.current(now / 1000),
        };
        defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
        h.consumeInitiationPeeked(msg, peek) catch |err| return switch (err) {
            error.UnknownPeer => error.UnknownPeer,
            else => error.AuthenticationFailed,
        };
        // The checks of `consumeInitiation`'s doc, after authentication: a forged
        // initiation must not move either of them.
        const ts = h.remote_timestamp orelse return error.AuthenticationFailed;
        if (!hs.timestampNewer(ts, t.last_timestamp)) return error.StaleTimestamp;
        if (t.last_initiation_ms) |last| {
            if (now -| last <= initiation_rate_ms) return error.Flood;
        }
        // Only now: a drop spends no index.
        h.local_index = t.nextIndex(io);
        const resp = h.createResponse(io) catch return error.AuthenticationFailed;
        t.last_timestamp = ts;
        t.last_initiation_ms = now;

        var slot: ?Slot = .{ .session = undefined, .local_index = h.local_index, .is_initiator = false, .created_ms = now };
        defer std.crypto.secureZero(u8, std.mem.asBytes(&slot));
        h.transportSession(false, now / 1000, &slot.?.session);
        // rotate: `next` waits for its first packet; `previous` is dropped, as
        // the peer has moved on from it.
        wipeSlot(&t.next);
        wipeSlot(&t.previous);
        t.next = slot;

        const bytes = std.mem.asBytes(&resp);
        @memcpy(out[0..bytes.len], bytes);
        t.peer_cookie.recordSent(bytes) catch {};
        t.last_sent_handshake_ms = now;
        t.sessionDerived(now);
        t.authenticatedTraversal(now);
        t.authenticatedSent();
        return .{ .network = out[0..bytes.len] };
    }

    fn consumeResponse(t: *Tunnel, clock: Clock, msg: *const hs.MessageResponse, out: []u8) DecapsulateError!Decapsulated {
        return burn.run(burn.hs_burn, DecapsulateError!Decapsulated, consumeResponseBody, .{ t, clock, msg, out });
    }

    fn consumeResponseBody(t: *Tunnel, clock: Clock, msg: *const hs.MessageResponse, out: []u8) DecapsulateError!Decapsulated {
        const now = clock.mono_ms;
        const p = if (t.pending) |*p| p else return error.UnknownIndex;
        if (msg.receiver_index != p.local_index) return error.UnknownIndex;
        p.consumeResponse(msg.*) catch |err| return switch (err) {
            error.InvalidMac1 => error.InvalidMac1,
            error.DecryptionFailed => error.AuthenticationFailed,
            error.NoPendingInitiation => error.UnknownIndex,
        };
        var slot: ?Slot = .{ .session = undefined, .local_index = p.local_index, .is_initiator = true, .created_ms = now };
        defer std.crypto.secureZero(u8, std.mem.asBytes(&slot));
        p.transportSession(true, now / 1000, &slot.?.session);
        t.wipePending();
        // rotate: an unconfirmed `next` still decrypts in `previous`; if there is
        // none the old current does. What was in the way goes.
        if (t.next != null) {
            wipeSlot(&t.previous);
            t.previous = t.next;
            wipeSlot(&t.next);
            wipeSlot(&t.current);
        } else {
            wipeSlot(&t.previous);
            t.previous = t.current;
        }
        dropSendKey(&t.previous);
        t.current = slot;

        t.sessionDerived(now);
        t.authenticatedTraversal(now);
        t.authenticatedReceived();
        t.handshakeComplete(now);
        // The first packet confirms the session to the responder: a staged one
        // if there is one, else an empty one.
        const first = (t.flushOne(clock, out) catch null) orelse
            (t.sealCurrent(clock, "", out) catch Output.none);
        return .{ .output = first, .authenticated = true };
    }

    fn consumeData(t: *Tunnel, clock: Clock, datagram: []const u8, out: []u8) DecapsulateError!Decapsulated {
        const now = clock.mono_ms;
        const now_s = now / 1000;
        const h = transport.parseHeader(datagram) catch return error.InvalidPacket;
        const which: enum { current, previous, next } = blk: {
            if (t.current) |*s| if (s.local_index == h.receiver_index) break :blk .current;
            if (t.next) |*s| if (s.local_index == h.receiver_index) break :blk .next;
            if (t.previous) |*s| if (s.local_index == h.receiver_index) break :blk .previous;
            return error.UnknownIndex;
        };
        const slot = switch (which) {
            .current => &t.current.?,
            .previous => &t.previous.?,
            .next => &t.next.?,
        };
        const r = slot.session.recv.open(out, datagram, now_s) catch |err| return switch (err) {
            error.Truncated, error.NotTransportData, error.WrongReceiver => error.InvalidPacket,
            error.Replayed => error.Replayed,
            error.MessageLimitReached, error.SessionExpired => error.SessionExpired,
            error.BufferTooSmall => error.BufferTooSmall,
            error.AuthenticationFailed => error.AuthenticationFailed,
        };
        t.rx_bytes +%= datagram.len;
        if (which == .next) {
            // ReceivedWithKeypair: the initiator used it, so it has our response.
            wipeSlot(&t.previous);
            t.previous = t.current;
            dropSendKey(&t.previous);
            t.current = t.next;
            wipeSlot(&t.next);
            t.handshakeComplete(now);
        }
        // keepKeyFreshReceiving: the initiator's last-minute rekey.
        if (!t.sent_last_minute) {
            if (t.current) |*c| if (c.is_initiator and now -| c.created_ms > rekey_on_receive_ms) {
                t.sent_last_minute = true;
                t.want_initiation = true;
            };
        }
        t.authenticatedTraversal(now);
        t.authenticatedReceived();
        if (r.len == 0) return .{ .output = .none, .authenticated = true };

        // Data: the keepalive answer is armed, and padding comes off.
        if (t.send_keepalive_at == null)
            t.send_keepalive_at = now +| keepalive_timeout_ms
        else
            t.need_another_keepalive = true;
        // After the timers and the window, as wireguard-go: it came with the key.
        const drop: Drop = blk: {
            const n = innerLength(out[0..r.len]) orelse break :blk .invalid_inner_packet;
            if (!t.sourceAllowed(out[0..n])) break :blk .disallowed_source;
            return .{ .output = .{ .tunnel = out[0..n] }, .authenticated = true };
        };
        std.crypto.secureZero(u8, out[0..r.len]);
        t.inner_dropped +%= 1;
        return .{ .output = .none, .authenticated = true, .dropped = drop };
    }

    fn sourceAllowed(t: *const Tunnel, packet: []const u8) bool {
        const list = t.allowed_ips orelse return true;
        const src = innerSource(packet) orelse return false;
        for (list) |*ip| if (prefixContains(ip, src)) return true;
        return false;
    }

    // ── time ────────────────────────────────────────────────────────────────

    /// Everything due at this time, one output per call: call until `.none`,
    /// after every `encapsulate`/`decapsulate` and at `nextDeadline`.
    pub fn poll(t: *Tunnel, io: std.Io, clock: Clock, out: []u8) PollError!Output {
        if (out.len < min_out_len) return error.BufferTooSmall;
        const now = clock.mono_ms;

        t.expireKeys(now);
        if (try t.flushOne(clock, out)) |o| return o;
        if (t.want_initiation) {
            t.want_initiation = false;
            const o = try t.initiate(io, clock, false, out);
            if (o != .none) return o;
        }
        if (expired(t.retransmit_at, now)) {
            t.retransmit_at = null;
            if (t.retries >= max_handshake_retries) {
                // Give up: the staged packets are stale, and what is left of the
                // exchange goes at the latest in `zero_keys_after_ms`.
                t.send_keepalive_at = null;
                t.need_another_keepalive = false;
                t.clearStage();
                t.wipePending();
                if (t.zero_keys_at == null) t.zero_keys_at = now +| zero_keys_after_ms;
            } else {
                t.retries += 1;
                const o = try t.initiate(io, clock, true, out);
                if (o != .none) return o;
            }
        }
        if (expired(t.send_keepalive_at, now)) {
            t.send_keepalive_at = null;
            const again = t.need_another_keepalive;
            t.need_another_keepalive = false;
            if (t.hasSession(clock)) {
                const o = try t.sealCurrent(clock, "", out);
                if (again) t.send_keepalive_at = now +| keepalive_timeout_ms;
                return o;
            }
        }
        if (expired(t.new_handshake_at, now)) {
            t.new_handshake_at = null;
            const o = try t.initiate(io, clock, false, out);
            if (o != .none) return o;
        }
        if (expired(t.persistent_at, now)) {
            t.persistent_at = null;
            const o = try t.encapsulate(io, clock, "", out);
            if (o != .none) return o;
        }
        return .none;
    }

    fn expired(deadline: ?u64, now: u64) bool {
        return if (deadline) |d| now >= d else false;
    }

    /// The deadline for keys passed: the sessions go. An initiation in flight is
    /// younger than that deadline (it dies by retries within 95 s), and it may be
    /// the very thing that got this called late, so it stays, with what waits for it.
    fn expireKeys(t: *Tunnel, now: u64) void {
        if (!expired(t.zero_keys_at, now)) return;
        t.zero_keys_at = null;
        wipeSlot(&t.current);
        wipeSlot(&t.previous);
        wipeSlot(&t.next);
        t.send_keepalive_at = null;
        t.need_another_keepalive = false;
        t.new_handshake_at = null;
        if (t.pending == null) {
            t.clearStage();
            t.want_initiation = false;
        }
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const Pair = struct {
    a: Tunnel,
    b: Tunnel,
    a_stage: [4096]u8 = undefined,
    b_stage: [4096]u8 = undefined,
    now: u64 = 1_000_000,
    wall: u64 = 1_700_000_000,

    fn clock(p: *const Pair) Clock {
        return .{ .mono_ms = p.now, .tai64n = tai64n(p.wall +% p.now / 1000, @intCast((p.now % 1000) * 1_000_000)) };
    }

    fn init(p: *Pair, psk: ?*const [32]u8, keepalive: u16) !void {
        const pa: [32]u8 = @splat(0x11);
        const pb: [32]u8 = @splat(0x22);
        var ka: hs.Keypair = undefined;
        var kb: hs.Keypair = undefined;
        try hs.Keypair.fromPrivateKey(&pa, &ka);
        try hs.Keypair.fromPrivateKey(&pb, &kb);
        p.* = .{ .a = undefined, .b = undefined };
        try Tunnel.init(&p.a, &.{ .allowed_ips = null, .static_private = &pa, .remote_static = kb.public, .preshared_key = psk, .stage = &p.a_stage, .persistent_keepalive_s = keepalive }, testing.io, p.clock());
        try Tunnel.init(&p.b, &.{ .allowed_ips = null, .static_private = &pb, .remote_static = ka.public, .preshared_key = psk, .stage = &p.b_stage }, testing.io, p.clock());
    }

    /// Run a's initiation through to a session on both sides; returns the
    /// bytes b receives for the packet that opened the exchange.
    fn establish(p: *Pair) !void {
        var buf: [2048]u8 = undefined;
        var buf2: [2048]u8 = undefined;
        const init_msg = (try p.a.encapsulate(testing.io, p.clock(), "", &buf)).network;
        const resp = (try p.b.decapsulate(testing.io, p.clock(), init_msg, &buf2)).output.network;
        const first = (try p.a.decapsulate(testing.io, p.clock(), resp, &buf)).output.network;
        _ = try p.b.decapsulate(testing.io, p.clock(), first, &buf2);
    }

    fn drain(p: *Pair, t: *Tunnel, buf: []u8) !usize {
        var n: usize = 0;
        while (true) {
            switch (try t.poll(testing.io, p.clock(), buf)) {
                .none => return n,
                else => n += 1,
            }
        }
    }
};

/// A minimal IPv4 packet with `payload` zero-filled bytes after the header.
fn ip4(buf: []u8, payload: usize) []u8 {
    const total = 20 + payload;
    @memset(buf[0..total], 0x5a);
    buf[0] = 0x45;
    std.mem.writeInt(u16, buf[2..4], @intCast(total), .big);
    return buf[0..total];
}

test "tai64n: the epoch and the whitened nanoseconds" {
    const t = tai64n(1_700_000_000, 123_456_789);
    try testing.expectEqual((@as(u64, 1) << 62) + 10 + 1_700_000_000, std.mem.readInt(u64, t[0..8], .big));
    // 123456789 & ~0xffffff == 117440512
    try testing.expectEqual(@as(u32, 117_440_512), std.mem.readInt(u32, t[8..12], .big));
    try testing.expect(hs.timestampNewer(tai64n(2, 0), tai64n(1, 999_000_000)));
}

test "inner packets: addresses and lengths" {
    var b: [64]u8 = undefined;
    const p = ip4(&b, 10);
    b[12] = 1;
    b[16] = 2;
    try testing.expectEqual(@as(u8, 1), innerSource(p).?[0]);
    try testing.expectEqual(@as(u8, 2), innerDestination(p).?[0]);
    try testing.expectEqual(@as(usize, 30), innerLength(b[0..48]).?);
    try testing.expectEqual(@as(?usize, null), innerLength(b[0..29]));
    try testing.expectEqual(@as(?[]const u8, null), innerSource(b[0..19]));
    try testing.expectEqual(@as(?[]const u8, null), innerDestination(""));
    var v6: [64]u8 = @splat(0);
    v6[0] = 0x60;
    std.mem.writeInt(u16, v6[4..6], 8, .big);
    try testing.expectEqual(@as(usize, 48), innerLength(v6[0..64]).?);
    try testing.expectEqual(@as(usize, 16), innerSource(&v6).?.len);
    v6[0] = 0x10;
    try testing.expectEqual(@as(?usize, null), innerLength(&v6));
    // An IPv4 total length below its own header is not a packet.
    b[3] = 19;
    b[2] = 0;
    try testing.expectEqual(@as(?usize, null), innerLength(b[0..40]));
}

test "Tunnel: a stage-free initiation, data both ways, padding stripped" {
    var p: Pair = undefined;
    const psk: [32]u8 = @splat(0x77);
    try p.init(&psk, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try testing.expect(!p.a.hasSession(p.clock()));
    try p.establish();
    try testing.expect(p.a.hasSession(p.clock()));
    try testing.expect(p.b.hasSession(p.clock())); // the keepalive confirmed `next`
    try testing.expect(p.b.next == null);
    try testing.expectEqual(p.now, p.a.stats().last_handshake_ms.?);

    var pkt: [128]u8 = undefined;
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const sent = ip4(&pkt, 3); // 23 bytes, padded to 32
    const wire = (try p.a.encapsulate(testing.io, p.clock(), sent, &buf)).network;
    try testing.expectEqual(@as(usize, 32 + 32), wire.len);
    const got = (try p.b.decapsulate(testing.io, p.clock(), wire, &buf2));
    try testing.expect(got.authenticated);
    try testing.expectEqualSlices(u8, sent, got.output.tunnel);

    const back = (try p.b.encapsulate(testing.io, p.clock(), sent, &buf)).network;
    const got2 = try p.a.decapsulate(testing.io, p.clock(), back, &buf2);
    try testing.expectEqualSlices(u8, sent, got2.output.tunnel);
    // Keepalives and handshakes do not change data; both sides counted wire bytes.
    try testing.expect(p.a.stats().tx_bytes > 0 and p.b.stats().rx_bytes > 0);
}

test "Tunnel: mismatched pre-shared keys never make a session" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    @memset(&p.b.preshared_key, 0x33);
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const m1 = (try p.a.encapsulate(testing.io, p.clock(), "", &buf)).network;
    const m2 = (try p.b.decapsulate(testing.io, p.clock(), m1, &buf2)).output.network;
    try testing.expectError(error.AuthenticationFailed, p.a.decapsulate(testing.io, p.clock(), m2, &buf));
    try testing.expect(!p.a.hasSession(p.clock()));
    try testing.expect(p.a.pending != null); // a forged response does not end the attempt
}

test "Tunnel: staged packets go out in order once the session exists, oldest dropped when full" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    var pkts: [3][64]u8 = undefined;
    const p1 = ip4(&pkts[0], 1);
    const p2 = ip4(&pkts[1], 2);
    const p3 = ip4(&pkts[2], 3);
    const m1 = try p.a.encapsulate(testing.io, p.clock(), p1, &buf);
    const m1_bytes = m1.network;
    // Within the rekey timeout no second initiation goes out: only staged.
    var other: [2048]u8 = undefined;
    try testing.expectEqual(Output.none, try p.a.encapsulate(testing.io, p.clock(), p2, &other));
    try testing.expectEqual(Output.none, try p.a.encapsulate(testing.io, p.clock(), p3, &other));
    const m2 = (try p.b.decapsulate(testing.io, p.clock(), m1_bytes, &buf2)).output.network;
    const first = (try p.a.decapsulate(testing.io, p.clock(), m2, &buf)).output.network;
    try testing.expectEqualSlices(u8, p1, (try p.b.decapsulate(testing.io, p.clock(), first, &buf2)).output.tunnel);
    const second = (try p.a.poll(testing.io, p.clock(), &buf)).network;
    try testing.expectEqualSlices(u8, p2, (try p.b.decapsulate(testing.io, p.clock(), second, &buf2)).output.tunnel);
    const third = (try p.a.poll(testing.io, p.clock(), &buf)).network;
    try testing.expectEqualSlices(u8, p3, (try p.b.decapsulate(testing.io, p.clock(), third, &buf2)).output.tunnel);
    try testing.expectEqual(Output.none, try p.a.poll(testing.io, p.clock(), &buf));
    try testing.expectEqual(@as(u64, 0), p.a.stats().staged_dropped);
}

test "Tunnel: a full stage drops its oldest, a too-large packet drops itself" {
    var stage: [100]u8 = undefined;
    const priv: [32]u8 = @splat(0x11);
    const peer: [32]u8 = blk: {
        const pb: [32]u8 = @splat(0x22);
        var kb: hs.Keypair = undefined;
        try hs.Keypair.fromPrivateKey(&pb, &kb);
        break :blk kb.public;
    };
    var t: Tunnel = undefined;
    const clk: Clock = .{ .mono_ms = 1000, .tai64n = tai64n(1, 0) };
    try Tunnel.init(&t, &.{ .allowed_ips = null, .static_private = &priv, .remote_static = peer, .stage = &stage }, testing.io, clk);
    defer t.wipe();
    var a: [40]u8 = @splat('a');
    var b: [40]u8 = @splat('b');
    var c: [40]u8 = @splat('c');
    t.stagePacket(&a);
    t.stagePacket(&b);
    try testing.expectEqual(@as(u64, 0), t.staged_dropped);
    t.stagePacket(&c); // 3 × 42 > 100: `a` goes, the rest shift
    try testing.expectEqual(@as(u64, 1), t.staged_dropped);
    try testing.expectEqual(@as(u8, 'b'), t.stage[t.stage_head + 2]);
    var big: [99]u8 = undefined;
    t.stagePacket(&big); // 101 > 100: never fits
    try testing.expectEqual(@as(u64, 2), t.staged_dropped);
    t.clearStage();
    try testing.expectEqual(t.stage_head, t.stage_tail);
    // Zero-length records (keepalives) still take their header.
    t.stagePacket("");
    try testing.expectEqual(@as(usize, 2), t.stage_tail);
}

test "Tunnel: no stage means a packet before the session is dropped and counted" {
    const priv: [32]u8 = @splat(0x11);
    const pb: [32]u8 = @splat(0x22);
    var kb: hs.Keypair = undefined;
    try hs.Keypair.fromPrivateKey(&pb, &kb);
    var t: Tunnel = undefined;
    const clk: Clock = .{ .mono_ms = 1000, .tai64n = tai64n(1, 0) };
    try Tunnel.init(&t, &.{ .allowed_ips = null, .static_private = &priv, .remote_static = kb.public }, testing.io, clk);
    defer t.wipe();
    var buf: [2048]u8 = undefined;
    _ = try t.encapsulate(testing.io, clk, "x", &buf);
    try testing.expectEqual(@as(u64, 1), t.stats().staged_dropped);
}

test "Tunnel: initiation retries every rekey timeout and gives up after 18" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    var buf: [2048]u8 = undefined;
    _ = try p.a.encapsulate(testing.io, p.clock(), "\x45", &buf);
    var sent: usize = 1;
    var steps: usize = 0;
    while (steps < 200) : (steps += 1) {
        p.now += 1000;
        sent += try p.drain(&p.a, &buf);
    }
    try testing.expectEqual(@as(usize, 19), sent); // the first + 18 retries
    try testing.expect(p.a.pending == null);
    try testing.expectEqual(@as(usize, 0), p.a.stage_tail - p.a.stage_head);
    // Keys of the attempt are gone; a new packet starts a fresh attempt.
    try testing.expect(p.a.zero_keys_at != null);
    const again = try p.a.encapsulate(testing.io, p.clock(), "\x45", &buf);
    try testing.expect(again == .network);
    try testing.expectEqual(@as(u16, 0), p.a.stats().handshake_retries);
}

test "Tunnel: the initiator rekeys on send after 120 s, and packets in flight still open" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    p.now += 120_000;
    // Exactly at the limit: not yet (`>`).
    _ = try p.a.encapsulate(testing.io, p.clock(), data, &buf);
    try testing.expect(!p.a.want_initiation);
    p.now += 1;
    const inflight = (try p.a.encapsulate(testing.io, p.clock(), data, &buf)).network;
    var inflight_copy: [128]u8 = undefined;
    @memcpy(inflight_copy[0..inflight.len], inflight);
    const inflight_len = inflight.len;
    try testing.expect(p.a.want_initiation);

    const m1 = (try p.a.poll(testing.io, p.clock(), &buf)).network;
    const m2 = (try p.b.decapsulate(testing.io, p.clock(), m1, &buf2)).output.network;
    // b has a `next`; until it is confirmed, b still sends under its current.
    try testing.expect(p.b.next != null);
    var buf3: [2048]u8 = undefined;
    _ = (try p.b.encapsulate(testing.io, p.clock(), data, &buf3)).network;
    const k = (try p.a.decapsulate(testing.io, p.clock(), m2, &buf)).output.network;
    try testing.expect(p.a.previous != null);
    // The packet sealed under the old key arrives after the rekey began.
    const got = try p.b.decapsulate(testing.io, p.clock(), inflight_copy[0..inflight_len], &buf2);
    try testing.expectEqualSlices(u8, data, got.output.tunnel);
    // The new session's keepalive promotes `next`.
    _ = try p.b.decapsulate(testing.io, p.clock(), k, &buf2);
    try testing.expect(p.b.next == null and p.b.previous != null);
    // New key both ways.
    const w = (try p.b.encapsulate(testing.io, p.clock(), data, &buf2)).network;
    try testing.expectEqualSlices(u8, data, (try p.a.decapsulate(testing.io, p.clock(), w, &buf)).output.tunnel);
}

test "Tunnel: the responder does not rekey on time; a session past 180 s stages and initiates" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var buf: [2048]u8 = undefined;
    p.now += 121_000;
    const w = try p.b.encapsulate(testing.io, p.clock(), "\x45", &buf);
    try testing.expect(w == .network);
    try testing.expect(!p.b.want_initiation);
    p.now += 60_000; // 181 s
    try testing.expect(!p.b.hasSession(p.clock()));
    const m = try p.b.encapsulate(testing.io, p.clock(), "\x45", &buf);
    try testing.expectEqual(@as(usize, @sizeOf(hs.MessageInitiation)), m.network.len);
}

test "Tunnel: an initiator rekeys on receive at 165 s, once" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    p.now += 165_000;
    const w1 = (try p.b.encapsulate(testing.io, p.clock(), data, &buf)).network;
    _ = try p.a.decapsulate(testing.io, p.clock(), w1, &buf2);
    try testing.expect(!p.a.want_initiation); // at the limit, not past it
    p.now += 1;
    const w2 = (try p.b.encapsulate(testing.io, p.clock(), data, &buf)).network;
    _ = try p.a.decapsulate(testing.io, p.clock(), w2, &buf2);
    try testing.expect(p.a.want_initiation);
    _ = try p.a.poll(testing.io, p.clock(), &buf2);
    const w3 = (try p.b.encapsulate(testing.io, p.clock(), data, &buf)).network;
    _ = try p.a.decapsulate(testing.io, p.clock(), w3, &buf2);
    try testing.expect(!p.a.want_initiation); // sent_last_minute holds it
}

test "Tunnel: data received and nothing sent back means a keepalive after 10 s" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const w = (try p.a.encapsulate(testing.io, p.clock(), data, &buf)).network;
    _ = try p.b.decapsulate(testing.io, p.clock(), w, &buf2);
    p.now += keepalive_timeout_ms - 1;
    try testing.expectEqual(Output.none, try p.b.poll(testing.io, p.clock(), &buf2));
    p.now += 1;
    const k = (try p.b.poll(testing.io, p.clock(), &buf2)).network;
    try testing.expectEqual(@as(usize, 32), k.len);
    // Anything sent cancels the armed keepalive.
    const w2 = (try p.a.encapsulate(testing.io, p.clock(), data, &buf)).network;
    _ = try p.b.decapsulate(testing.io, p.clock(), w2, &buf2);
    _ = try p.b.encapsulate(testing.io, p.clock(), data, &buf2);
    try testing.expect(p.b.send_keepalive_at == null);
}

test "Tunnel: data received in a burst keeps a second keepalive due" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    for (0..2) |_| {
        const w = (try p.a.encapsulate(testing.io, p.clock(), data, &buf)).network;
        _ = try p.b.decapsulate(testing.io, p.clock(), w, &buf2);
    }
    try testing.expect(p.b.need_another_keepalive);
    p.now += keepalive_timeout_ms;
    _ = (try p.b.poll(testing.io, p.clock(), &buf2)).network;
    try testing.expectEqual(p.now + keepalive_timeout_ms, p.b.send_keepalive_at.?);
    try testing.expect(!p.b.need_another_keepalive);
}

test "Tunnel: sent data with no reply starts a new handshake after 15 s" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    var buf: [2048]u8 = undefined;
    _ = try p.a.encapsulate(testing.io, p.clock(), data, &buf);
    const at = p.a.new_handshake_at.?;
    try testing.expect(at >= p.now + 15_000 and at < p.now + 15_000 + rekey_timeout_jitter_ms);
    p.now = at - 1;
    try testing.expectEqual(Output.none, try p.a.poll(testing.io, p.clock(), &buf));
    p.now = at;
    const m = (try p.a.poll(testing.io, p.clock(), &buf)).network;
    try testing.expectEqual(@as(usize, @sizeOf(hs.MessageInitiation)), m.len);
}

test "Tunnel: persistent keepalive starts the handshake and repeats" {
    var p: Pair = undefined;
    try p.init(null, 25);
    defer p.a.wipe();
    defer p.b.wipe();
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const m1 = (try p.a.poll(testing.io, p.clock(), &buf)).network;
    try testing.expectEqual(@as(usize, @sizeOf(hs.MessageInitiation)), m1.len);
    const m2 = (try p.b.decapsulate(testing.io, p.clock(), m1, &buf2)).output.network;
    _ = try p.a.decapsulate(testing.io, p.clock(), m2, &buf);
    try testing.expectEqual(Output.none, try p.a.poll(testing.io, p.clock(), &buf));
    p.now += 25_000;
    const k = (try p.a.poll(testing.io, p.clock(), &buf)).network;
    try testing.expectEqual(@as(usize, 32), k.len);
    try testing.expectEqual(p.now + 25_000, p.a.persistent_at.?);
}

test "Tunnel: replayed and rapid initiations are refused, and neither moves the state" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const m1 = (try p.a.encapsulate(testing.io, p.clock(), "", &buf)).network;
    var copy: [148]u8 = undefined;
    @memcpy(&copy, m1);
    _ = try p.b.decapsulate(testing.io, p.clock(), m1, &buf2);
    const next_index = p.b.next.?.local_index;
    // The same bytes again: replay first, however late.
    p.now += 1000;
    try testing.expectError(error.StaleTimestamp, p.b.decapsulate(testing.io, p.clock(), &copy, &buf2));
    try testing.expectEqual(next_index, p.b.next.?.local_index);
    // A newer one inside the rate limit is a flood.
    p.a.last_sent_handshake_ms = null;
    p.b.last_initiation_ms = p.now;
    p.now += 1000;
    p.a.last_sent_handshake_ms = null;
    const m3 = (try p.a.encapsulate(testing.io, p.clock(), "", &buf)).network;
    p.b.last_initiation_ms = p.now - initiation_rate_ms;
    try testing.expectError(error.Flood, p.b.decapsulate(testing.io, p.clock(), m3, &buf2));
    try testing.expectEqual(next_index, p.b.next.?.local_index);
    // One past the limit, and the same message (its stamp was not recorded) passes.
    p.b.last_initiation_ms = p.now - initiation_rate_ms - 1;
    _ = try p.b.decapsulate(testing.io, p.clock(), m3, &buf2);
    try testing.expect(next_index != p.b.next.?.local_index);
}

test "Tunnel: a response to no handshake, or to another index, and a replayed one" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const m1 = (try p.a.encapsulate(testing.io, p.clock(), "", &buf)).network;
    const m2 = (try p.b.decapsulate(testing.io, p.clock(), m1, &buf2)).output.network;
    var bad: [92]u8 = undefined;
    @memcpy(&bad, m2);
    bad[8] ^= 1; // receiver_index
    try testing.expectError(error.UnknownIndex, p.a.decapsulate(testing.io, p.clock(), &bad, &buf));
    var copy: [92]u8 = undefined;
    @memcpy(&copy, m2);
    _ = try p.a.decapsulate(testing.io, p.clock(), m2, &buf);
    try testing.expectError(error.UnknownIndex, p.a.decapsulate(testing.io, p.clock(), &copy, &buf));
}

test "Tunnel: datagrams of no known shape" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    var buf: [2048]u8 = undefined;
    const clk = p.clock();
    try testing.expectError(error.InvalidPacket, p.a.decapsulate(testing.io, clk, "", &buf));
    try testing.expectError(error.InvalidPacket, p.a.decapsulate(testing.io, clk, "\x01\x00\x00", &buf));
    try testing.expectError(error.InvalidPacket, p.a.decapsulate(testing.io, clk, "\x01\x00\x00\x00", &buf));
    try testing.expectError(error.InvalidPacket, p.a.decapsulate(testing.io, clk, "\x02\x00\x00\x00", &buf));
    try testing.expectError(error.InvalidPacket, p.a.decapsulate(testing.io, clk, "\x03\x00\x00\x00", &buf));
    try testing.expectError(error.InvalidPacket, p.a.decapsulate(testing.io, clk, "\x04\x00\x00\x00", &buf));
    try testing.expectError(error.InvalidPacket, p.a.decapsulate(testing.io, clk, "\x05\x00\x00\x00", &buf));
    var d: [32]u8 = @splat(0);
    d[0] = 4;
    try testing.expectError(error.UnknownIndex, p.a.decapsulate(testing.io, clk, &d, &buf));
    var short: [10]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, p.a.decapsulate(testing.io, clk, &d, &short));
    try testing.expectError(error.BufferTooSmall, p.a.encapsulate(testing.io, clk, "", &short));
    try testing.expectError(error.BufferTooSmall, p.a.poll(testing.io, clk, &short));
    const huge = try testing.allocator.alloc(u8, transport.max_payload + 1);
    defer testing.allocator.free(huge);
    try testing.expectError(error.PacketTooLarge, p.a.encapsulate(testing.io, clk, huge, &buf));
}

test "Tunnel: authentic data that is no IP packet is dropped and wiped, the session lives, roaming counts" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const w = (try p.a.encapsulate(testing.io, p.clock(), "not an ip packet", &buf)).network;
    const r = try p.b.decapsulate(testing.io, p.clock(), w, &buf2);
    try testing.expectEqual(Output.none, r.output);
    try testing.expectEqual(Drop.invalid_inner_packet, r.dropped);
    try testing.expect(r.authenticated);
    try testing.expectEqual(@as(?usize, null), std.mem.find(u8, &buf2, "not an ip"));
    try testing.expectEqual(@as(u64, 1), p.b.stats().inner_dropped);
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    const w2 = (try p.a.encapsulate(testing.io, p.clock(), data, &buf)).network;
    try testing.expectEqualSlices(u8, data, (try p.b.decapsulate(testing.io, p.clock(), w2, &buf2)).output.tunnel);
}

test "Tunnel: allowed_ips drops a spoofed inner source, v4 and v6, at the prefix's edge" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var v6: [16]u8 = @splat(0);
    v6[0] = 0xfd;
    const list = [_]root.AllowedIp{ root.AllowedIp.v4(.{ 10, 0, 0, 128 }, 25), root.AllowedIp.v6(v6, 8) };
    p.b.allowed_ips = &list;
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    const Case = struct { src: [4]u8, ok: bool };
    for ([_]Case{
        .{ .src = .{ 10, 0, 0, 128 }, .ok = true },
        .{ .src = .{ 10, 0, 0, 255 }, .ok = true },
        .{ .src = .{ 10, 0, 0, 127 }, .ok = false },
        .{ .src = .{ 10, 0, 1, 128 }, .ok = false },
        .{ .src = .{ 192, 0, 2, 1 }, .ok = false },
    }) |c| {
        data[12..16].* = c.src;
        const w = (try p.a.encapsulate(testing.io, p.clock(), data, &buf)).network;
        const r = try p.b.decapsulate(testing.io, p.clock(), w, &buf2);
        if (c.ok) {
            try testing.expectEqualSlices(u8, data, r.output.tunnel);
            try testing.expectEqual(Drop.no, r.dropped);
        } else {
            try testing.expectEqual(Output.none, r.output);
            try testing.expectEqual(Drop.disallowed_source, r.dropped);
            try testing.expect(r.authenticated);
            try testing.expectEqual(@as(?usize, null), std.mem.find(u8, buf2[0..64], data[20..24]));
        }
    }
    try testing.expectEqual(@as(u64, 3), p.b.stats().inner_dropped);
    var six: [48]u8 = @splat(0);
    six[0] = 0x60;
    std.mem.writeInt(u16, six[4..6], 8, .big);
    six[8] = 0xfd;
    const w6 = (try p.a.encapsulate(testing.io, p.clock(), &six, &buf)).network;
    try testing.expectEqual(Drop.no, (try p.b.decapsulate(testing.io, p.clock(), w6, &buf2)).dropped);
    six[8] = 0xfe;
    const w7 = (try p.a.encapsulate(testing.io, p.clock(), &six, &buf)).network;
    try testing.expectEqual(Drop.disallowed_source, (try p.b.decapsulate(testing.io, p.clock(), w7, &buf2)).dropped);
    // An empty list allows nothing; a hand-built entry that does not add up, nothing.
    const bad = [_]root.AllowedIp{.{ .family = root.AF.INET, .addr_len = 4, .cidr = 33 }};
    for ([_][]const root.AllowedIp{ &.{}, &bad }) |l| {
        p.b.allowed_ips = l;
        data[12..16].* = .{ 10, 0, 0, 128 };
        const w = (try p.a.encapsulate(testing.io, p.clock(), data, &buf)).network;
        try testing.expectEqual(Drop.disallowed_source, (try p.b.decapsulate(testing.io, p.clock(), w, &buf2)).dropped);
    }
    // /0 allows all.
    const all = [_]root.AllowedIp{root.AllowedIp.v4(.{ 0, 0, 0, 0 }, 0)};
    p.b.allowed_ips = &all;
    data[12..16].* = .{ 198, 51, 100, 7 };
    const w8 = (try p.a.encapsulate(testing.io, p.clock(), data, &buf)).network;
    try testing.expectEqualSlices(u8, data, (try p.b.decapsulate(testing.io, p.clock(), w8, &buf2)).output.tunnel);
}

test "Tunnel: session indices are random by default, routed only on request, and never clash" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    var or_all: u32 = 0;
    var and_all: u32 = 0xffffffff;
    for (0..64) |_| {
        const i = p.a.nextIndex(testing.io);
        or_all |= i;
        and_all &= i;
    }
    // Every bit moved in 64 draws (a chance of 32 x 2^-63 of a false alarm).
    try testing.expectEqual(@as(u32, 0xffffffff), or_all);
    try testing.expectEqual(@as(u32, 0), and_all);

    p.a.routed_id = 0xabcdef;
    p.a.index_seq = 0xff;
    p.a.current = null;
    const first = p.a.nextIndex(testing.io);
    try testing.expectEqual(@as(u24, 0xabcdef), tunnelIdOf(first));
    try testing.expectEqual(@as(u32, 0xabcdef00), first);
    // What is in use is skipped.
    var buf: [2048]u8 = undefined;
    p.a.index_seq = 0xff;
    _ = try p.a.initiateHandshake(testing.io, p.clock(), &buf);
    try testing.expect(p.a.ownsIndex(0xabcdef00));
    try testing.expect(!p.a.ownsIndex(0xabcdef01));
    p.a.index_seq = 0xff;
    try testing.expectEqual(@as(u32, 0xabcdef01), p.a.nextIndex(testing.io));
}

test "Tunnel: a dropped initiation spends no index and moves nothing" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    p.b.routed_id = 9;
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const m1 = (try p.a.encapsulate(testing.io, p.clock(), "", &buf)).network;
    var copy: [148]u8 = undefined;
    @memcpy(&copy, m1);
    _ = try p.b.decapsulate(testing.io, p.clock(), m1, &buf2);
    const seq = p.b.index_seq;
    const ts = p.b.last_timestamp;
    const at = p.b.last_initiation_ms;
    p.now += 1000;
    try testing.expectError(error.StaleTimestamp, p.b.decapsulate(testing.io, p.clock(), &copy, &buf2));
    try testing.expectEqual(seq, p.b.index_seq);
    try testing.expectEqual(ts, p.b.last_timestamp);
    try testing.expectEqual(at, p.b.last_initiation_ms);
}

test "Tunnel: previous has no send key; next keeps its own until it sends" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const zero: [32]u8 = @splat(0);
    p.now += 6000;
    const m1 = (try p.a.initiateHandshake(testing.io, p.clock(), &buf)).network;
    const m2 = (try p.b.decapsulate(testing.io, p.clock(), m1, &buf2)).output.network;
    try testing.expect(!std.mem.eql(u8, &p.b.next.?.session.send.key, &zero));
    const k = (try p.a.decapsulate(testing.io, p.clock(), m2, &buf)).output.network;
    try testing.expectEqual(zero, p.a.previous.?.session.send.key);
    _ = try p.b.decapsulate(testing.io, p.clock(), k, &buf2);
    try testing.expectEqual(zero, p.b.previous.?.session.send.key);
    try testing.expect(!std.mem.eql(u8, &p.b.current.?.session.send.key, &zero));
    // And a rotation through `next` on the initiator's side.
    p.now += 6000;
    const m3 = (try p.b.initiateHandshake(testing.io, p.clock(), &buf)).network;
    const m4 = (try p.a.decapsulate(testing.io, p.clock(), m3, &buf2)).output.network;
    p.now += 6000;
    const m5 = (try p.a.initiateHandshake(testing.io, p.clock(), &buf)).network;
    const m6 = (try p.b.decapsulate(testing.io, p.clock(), m5, &buf2)).output.network;
    _ = m4;
    _ = try p.a.decapsulate(testing.io, p.clock(), m6, &buf);
    try testing.expectEqual(zero, p.a.previous.?.session.send.key);
}

test "Tunnel: a staged packet larger than out is dropped, and the timers behind it run" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    var big: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    var small: [200]u8 = undefined;
    var pkt: [1024]u8 = undefined;
    const large = ip4(&pkt, 900);
    const m1 = (try p.a.encapsulate(testing.io, p.clock(), large, &big)).network;
    const m2 = (try p.b.decapsulate(testing.io, p.clock(), m1, &buf2)).output.network;
    // The response finds the packet too large for `small`: an empty confirmation goes.
    const k = (try p.a.decapsulate(testing.io, p.clock(), m2, &small)).output.network;
    try testing.expectEqual(@as(usize, 32), k.len);
    try testing.expectEqual(@as(u64, 1), p.a.stats().staged_dropped);
    try testing.expectEqual(p.a.stage_head, p.a.stage_tail);

    // Staged after the session: poll does not fail, a keepalive still goes out.
    _ = try p.b.decapsulate(testing.io, p.clock(), k, &buf2);
    p.a.stagePacket(large);
    const w = (try p.b.encapsulate(testing.io, p.clock(), ip4(&pkt, 4), &buf2)).network;
    _ = try p.a.decapsulate(testing.io, p.clock(), w, &big);
    p.a.stagePacket(ip4(&pkt, 900));
    p.now += keepalive_timeout_ms;
    const o = try p.a.poll(testing.io, p.clock(), &small);
    try testing.expectEqual(@as(usize, 32), o.network.len);
    try testing.expectEqual(@as(u64, 3), p.a.stats().staged_dropped);
    try testing.expect(p.a.nextDeadline(p.clock()) != 0);
}

test "Tunnel: a datagram overlapping out is refused before anything moves" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    var buf: [2048]u8 = undefined;
    const clk = p.clock();
    try testing.expectError(error.BufferOverlap, p.a.decapsulate(testing.io, clk, buf[0..32], &buf));
    try testing.expectError(error.BufferOverlap, p.a.decapsulate(testing.io, clk, buf[100..132], buf[0..300]));
    try testing.expectError(error.BufferOverlap, p.a.decapsulate(testing.io, clk, buf[0..300], buf[100..400]));
    // Touching is not overlapping.
    buf[0] = 9;
    try testing.expectError(error.InvalidPacket, p.a.decapsulate(testing.io, clk, buf[0..8], buf[8..300]));
}

test "Tunnel: a replayed data packet and a forged one" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const w = (try p.a.encapsulate(testing.io, p.clock(), data, &buf)).network;
    _ = try p.b.decapsulate(testing.io, p.clock(), w, &buf2);
    try testing.expectError(error.Replayed, p.b.decapsulate(testing.io, p.clock(), w, &buf2));
    const w2 = (try p.a.encapsulate(testing.io, p.clock(), data, &buf)).network;
    w2[w2.len - 1] ^= 1;
    try testing.expectError(error.AuthenticationFailed, p.b.decapsulate(testing.io, p.clock(), w2, &buf2));
}

test "Tunnel: keys are gone 540 s after the last handshake" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var buf: [2048]u8 = undefined;
    p.now += zero_keys_after_ms - 1;
    _ = try p.a.poll(testing.io, p.clock(), &buf);
    try testing.expect(p.a.current != null);
    p.now += 1;
    _ = try p.a.poll(testing.io, p.clock(), &buf);
    try testing.expect(p.a.current == null and p.a.previous == null and p.a.next == null);
    try testing.expectEqual(@as(?u64, null), p.a.zero_keys_at);
}

test "Tunnel: a key deadline that passed unpolled takes the sessions, not a new attempt" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    p.now += zero_keys_after_ms + 1;
    const m1 = (try p.a.encapsulate(testing.io, p.clock(), data, &buf)).network;
    try testing.expect(p.a.current == null);
    // The late poll leaves the initiation and the staged packet alone.
    try testing.expectEqual(Output.none, try p.a.poll(testing.io, p.clock(), &buf2));
    const m2 = (try p.b.decapsulate(testing.io, p.clock(), m1, &buf2)).output.network;
    const w = (try p.a.decapsulate(testing.io, p.clock(), m2, &buf)).output.network;
    try testing.expectEqualSlices(u8, data, (try p.b.decapsulate(testing.io, p.clock(), w, &buf2)).output.tunnel);
}

test "Tunnel: simultaneous initiations end with a session both ways" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    var from_a: [148]u8 = undefined;
    var from_b: [148]u8 = undefined;
    @memcpy(&from_a, (try p.a.encapsulate(testing.io, p.clock(), "", &buf)).network);
    @memcpy(&from_b, (try p.b.encapsulate(testing.io, p.clock(), "", &buf)).network);
    var resp_b: [92]u8 = undefined;
    var resp_a: [92]u8 = undefined;
    @memcpy(&resp_b, (try p.b.decapsulate(testing.io, p.clock(), &from_a, &buf)).output.network);
    @memcpy(&resp_a, (try p.a.decapsulate(testing.io, p.clock(), &from_b, &buf)).output.network);
    const k_a = (try p.a.decapsulate(testing.io, p.clock(), &resp_b, &buf)).output.network;
    _ = try p.b.decapsulate(testing.io, p.clock(), k_a, &buf2);
    const k_b = (try p.b.decapsulate(testing.io, p.clock(), &resp_a, &buf)).output.network;
    _ = try p.a.decapsulate(testing.io, p.clock(), k_b, &buf2);
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    const w = (try p.a.encapsulate(testing.io, p.clock(), data, &buf)).network;
    try testing.expectEqualSlices(u8, data, (try p.b.decapsulate(testing.io, p.clock(), w, &buf2)).output.tunnel);
    const w2 = (try p.b.encapsulate(testing.io, p.clock(), data, &buf)).network;
    try testing.expectEqualSlices(u8, data, (try p.a.decapsulate(testing.io, p.clock(), w2, &buf2)).output.tunnel);
}

test "Tunnel: the cookie reply is taken once and stamps the next initiation's mac2" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    var buf: [2048]u8 = undefined;
    const m1 = (try p.a.encapsulate(testing.io, p.clock(), "", &buf)).network;
    const msg = std.mem.bytesToValue(hs.MessageInitiation, m1[0..@sizeOf(hs.MessageInitiation)]);
    var checker: hs.CookieChecker = undefined;
    hs.CookieChecker.init(p.b.static_keypair.public, testing.io, p.now / 1000, &checker);
    const adm = checker.admit(testing.io, p.now / 1000, std.mem.asBytes(&msg), "source", true);
    const reply = adm.cookie_reply;
    const r = std.mem.asBytes(&reply);
    const got = try p.a.decapsulate(testing.io, p.clock(), r, &buf);
    try testing.expectEqual(Output.none, got.output);
    try testing.expect(!got.authenticated);
    try testing.expectError(error.AuthenticationFailed, p.a.decapsulate(testing.io, p.clock(), r, &buf));
    p.now += rekey_timeout_ms + rekey_timeout_jitter_ms;
    const m2 = (try p.a.poll(testing.io, p.clock(), &buf)).network;
    const second = checker.admit(testing.io, p.now / 1000, m2, "source", true);
    try testing.expectEqual(hs.Admission.accept, second);
    // To another index: not ours.
    var wrong = reply;
    wrong.receiver_index +%= 77;
    try testing.expectError(error.UnknownIndex, p.a.decapsulate(testing.io, p.clock(), std.mem.asBytes(&wrong), &buf));
}

test "Tunnel: many peers behind one key, routed by peek" {
    const priv: [32]u8 = @splat(0x44);
    var server_kp: hs.Keypair = undefined;
    try hs.Keypair.fromPrivateKey(&priv, &server_kp);
    var peers: [3]Tunnel = undefined;
    var servers: [3]Tunnel = undefined;
    const clk: Clock = .{ .mono_ms = 1000, .tai64n = tai64n(100, 0) };
    for (0..3) |i| {
        const pp: [32]u8 = @splat(@intCast(0x50 + i));
        var kp: hs.Keypair = undefined;
        try hs.Keypair.fromPrivateKey(&pp, &kp);
        try Tunnel.init(&peers[i], &.{ .allowed_ips = null, .static_private = &pp, .remote_static = server_kp.public, .routed_id = @intCast(100 + i) }, testing.io, clk);
        try Tunnel.init(&servers[i], &.{ .allowed_ips = null, .static_private = &priv, .remote_static = kp.public, .routed_id = @intCast(i) }, testing.io, clk);
    }
    defer for (&peers) |*t| t.wipe();
    defer for (&servers) |*t| t.wipe();
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const m = (try peers[2].encapsulate(testing.io, clk, "", &buf)).network;
    const msg = std.mem.bytesToValue(hs.MessageInitiation, m[0..@sizeOf(hs.MessageInitiation)]);
    var peek: hs.InitiationPeek = undefined;
    try hs.peekInitiation(&server_kp, &msg, &peek);
    defer peek.wipe();
    try testing.expectEqualSlices(u8, &peers[2].static_keypair.public, &peek.initiator_static);
    // The wrong tunnel refuses it, and stays clean.
    try testing.expectError(error.UnknownPeer, servers[0].acceptInitiation(testing.io, clk, &msg, &peek, &buf2));
    try testing.expect(servers[0].next == null);
    const resp = (try servers[2].acceptInitiation(testing.io, clk, &msg, &peek, &buf2)).network;
    const k = (try peers[2].decapsulate(testing.io, clk, resp, &buf)).output.network;
    try testing.expectEqual(@as(u24, 2), tunnelIdOf(std.mem.readInt(u32, k[4..8], .little)));
    _ = try servers[2].decapsulate(testing.io, clk, k, &buf2);
    try testing.expect(servers[2].hasSession(clk));
}

test "Tunnel: an initiation from a low-order ephemeral or a low-order peer key" {
    const priv: [32]u8 = @splat(0x11);
    var t: Tunnel = undefined;
    const clk: Clock = .{ .mono_ms = 1000, .tai64n = tai64n(1, 0) };
    const zero: [32]u8 = @splat(0);
    try testing.expectError(error.InvalidKey, Tunnel.init(&t, &.{ .allowed_ips = null, .static_private = &priv, .remote_static = zero }, testing.io, clk));
}

test "Tunnel: wipe clears keys and the stage" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.b.wipe();
    try p.establish();
    var buf: [2048]u8 = undefined;
    p.a.last_sent_handshake_ms = null;
    p.a.stagePacket("secret plaintext");
    _ = &buf;
    p.a.wipe();
    try testing.expectEqual(@as(?usize, null), std.mem.find(u8, &p.a_stage, "secret plaintext"));
}

/// Raw 32-byte secrets of the live slots of `t` (zero keys left out).
fn secretsOf(t: *const Tunnel, out: *[6][32]u8) []const [32]u8 {
    const zero: [32]u8 = @splat(0);
    var n: usize = 0;
    const slots = [_]*const ?Slot{ &t.current, &t.previous, &t.next };
    for (slots) |s| {
        if (s.*) |*v| for ([_]*const [32]u8{ &v.session.send.key, &v.session.recv.key }) |k| {
            if (!std.mem.eql(u8, k, &zero)) {
                out[n] = k.*;
                n += 1;
            }
        };
    }
    return out[0..n];
}

/// None of `needles` may occur anywhere in the raw bytes of `t`.
fn expectAbsent(t: *const Tunnel, needles: []const [32]u8) !void {
    for (needles) |*k| try testing.expectEqual(@as(?usize, null), std.mem.find(u8, std.mem.asBytes(t), k));
}

/// What `b` makes of the packet `a` sends it.
fn dropOf(p: *Pair, packet: []const u8) !Drop {
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const w = (try p.a.encapsulate(testing.io, p.clock(), packet, &buf)).network;
    return (try p.b.decapsulate(testing.io, p.clock(), w, &buf2)).dropped;
}

/// A minimal IPv4 packet whose payload is `marker`.
fn markerPacket(buf: []u8, marker: []const u8) []u8 {
    const pkt = ip4(buf, marker.len);
    @memcpy(pkt[20..], marker);
    return pkt;
}

test "Tunnel: accepting an initiation arms the flood gate at 50 ms" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const m1 = (try p.a.encapsulate(testing.io, p.clock(), "", &buf)).network;
    _ = try p.b.decapsulate(testing.io, p.clock(), m1, &buf2);
    // A newer initiation (its own rate gate cleared) 49 ms later is a flood ...
    p.now += 49;
    p.a.last_sent_handshake_ms = null;
    const m3 = (try p.a.initiateHandshake(testing.io, p.clock(), &buf)).network;
    try testing.expectError(error.Flood, p.b.decapsulate(testing.io, p.clock(), m3, &buf2));
    // ... and 51 ms after the first it passes (the flood did not record its stamp).
    p.now += 2;
    _ = try p.b.decapsulate(testing.io, p.clock(), m3, &buf2);
}

test "Tunnel: a new accepted initiation drops the old previous session" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    // Sealed under the first session, held back.
    var inflight: [128]u8 = undefined;
    const w = (try p.a.encapsulate(testing.io, p.clock(), data, &buf)).network;
    @memcpy(inflight[0..w.len], w);
    const inflight_len = w.len;
    // One rekey: the first session is b's `previous` (and still opens).
    p.now += 6000;
    const m1 = (try p.a.initiateHandshake(testing.io, p.clock(), &buf)).network;
    const m2 = (try p.b.decapsulate(testing.io, p.clock(), m1, &buf2)).output.network;
    const k = (try p.a.decapsulate(testing.io, p.clock(), m2, &buf)).output.network;
    _ = try p.b.decapsulate(testing.io, p.clock(), k, &buf2);
    try testing.expect(p.b.previous != null);
    // A second initiation: the peer has moved on from `previous`.
    p.now += 6000;
    const m3 = (try p.a.initiateHandshake(testing.io, p.clock(), &buf)).network;
    _ = try p.b.decapsulate(testing.io, p.clock(), m3, &buf2);
    try testing.expect(p.b.previous == null);
    try testing.expect(p.b.next != null);
    try testing.expectError(error.UnknownIndex, p.b.decapsulate(testing.io, p.clock(), inflight[0..inflight_len], &buf2));
}

test "Tunnel: the responder's answer is a handshake sent: it holds off an initiation for 5 s" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const t0 = p.now;
    const m1 = (try p.a.encapsulate(testing.io, p.clock(), "", &buf)).network;
    _ = try p.b.decapsulate(testing.io, p.clock(), m1, &buf2);
    // No current session on b yet: the packet is staged, and nothing goes out.
    p.now = t0 + 1000;
    try testing.expectEqual(Output.none, try p.b.encapsulate(testing.io, p.clock(), data, &buf2));
    p.now = t0 + 4999;
    try testing.expectEqual(Output.none, try p.b.encapsulate(testing.io, p.clock(), data, &buf2));
    p.now = t0 + 5000;
    const m = try p.b.encapsulate(testing.io, p.clock(), data, &buf2);
    try testing.expectEqual(@as(usize, @sizeOf(hs.MessageInitiation)), m.network.len);
}

test "Tunnel: the initiation gate is 4999 ms shut and 5000 ms open" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    var buf: [2048]u8 = undefined;
    const t0 = p.now;
    _ = (try p.a.initiateHandshake(testing.io, p.clock(), &buf)).network;
    p.now = t0 + 4999;
    try testing.expectEqual(Output.none, try p.a.initiateHandshake(testing.io, p.clock(), &buf));
    p.now = t0 + 5000;
    const m = try p.a.initiateHandshake(testing.io, p.clock(), &buf);
    try testing.expectEqual(@as(usize, @sizeOf(hs.MessageInitiation)), m.network.len);
}

test "Tunnel: a cookie reply to the responder's own response is taken" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const m1 = (try p.a.encapsulate(testing.io, p.clock(), "", &buf)).network;
    const m2 = (try p.b.decapsulate(testing.io, p.clock(), m1, &buf2)).output.network;
    // a's checker answers b's response under load.
    var checker: hs.CookieChecker = undefined;
    hs.CookieChecker.init(p.a.static_keypair.public, testing.io, p.now / 1000, &checker);
    const reply = checker.admit(testing.io, p.now / 1000, m2, "source", true).cookie_reply;
    try testing.expectEqual(p.b.next.?.local_index, reply.receiver_index);
    const got = try p.b.decapsulate(testing.io, p.clock(), std.mem.asBytes(&reply), &buf);
    try testing.expectEqual(Output.none, got.output);
    try testing.expect(!got.authenticated);
}

test "Tunnel: initiating clears a due rekey request" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    var buf: [2048]u8 = undefined;
    p.now += 120_001;
    _ = try p.a.encapsulate(testing.io, p.clock(), data, &buf);
    try testing.expect(p.a.want_initiation);
    try testing.expectEqual(@as(?u64, 0), p.a.nextDeadline(p.clock()));
    _ = (try p.a.initiateHandshake(testing.io, p.clock(), &buf)).network;
    try testing.expect(!p.a.want_initiation);
    try testing.expect(p.a.nextDeadline(p.clock()).? > p.now);
}

test "Tunnel: a response consumed beside an unconfirmed next makes it previous, and the old current goes" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    // Sealed by b under the session that is about to be replaced on a.
    var old_w: [128]u8 = undefined;
    const ow = (try p.b.encapsulate(testing.io, p.clock(), data, &buf)).network;
    @memcpy(old_w[0..ow.len], ow);
    const old_len = ow.len;
    const old_index = p.a.current.?.local_index;

    p.now += 6000;
    var from_a: [148]u8 = undefined;
    var from_b: [148]u8 = undefined;
    @memcpy(&from_a, (try p.a.initiateHandshake(testing.io, p.clock(), &buf)).network);
    @memcpy(&from_b, (try p.b.initiateHandshake(testing.io, p.clock(), &buf)).network);
    var resp_b: [92]u8 = undefined;
    var resp_a: [92]u8 = undefined;
    @memcpy(&resp_b, (try p.b.decapsulate(testing.io, p.clock(), &from_a, &buf)).output.network);
    @memcpy(&resp_a, (try p.a.decapsulate(testing.io, p.clock(), &from_b, &buf)).output.network);
    // a holds b's session as an unconfirmed `next` and awaits the response to its own.
    const next_index = p.a.next.?.local_index;
    try testing.expect(p.a.pending != null);
    _ = try p.a.decapsulate(testing.io, p.clock(), &resp_b, &buf);
    try testing.expect(p.a.pending == null);
    try testing.expectEqual(next_index, p.a.previous.?.local_index);
    try testing.expect(p.a.next == null);
    const cur_index = p.a.current.?.local_index;
    try testing.expect(cur_index != old_index and cur_index != next_index);
    try testing.expectError(error.UnknownIndex, p.a.decapsulate(testing.io, p.clock(), old_w[0..old_len], &buf2));
    // b's first packet under its own initiation lands in a's `previous`, which stays.
    const k_b = (try p.b.decapsulate(testing.io, p.clock(), &resp_a, &buf)).output.network;
    try testing.expect((try p.a.decapsulate(testing.io, p.clock(), k_b, &buf2)).authenticated);
    try testing.expectEqual(cur_index, p.a.current.?.local_index);
    try testing.expectEqual(next_index, p.a.previous.?.local_index);
    // `previous` counts as an index in use.
    p.a.previous.?.local_index = 0x0701;
    p.a.routed_id = 7;
    p.a.index_seq = 0;
    try testing.expect(p.a.ownsIndex(0x0701));
    try testing.expectEqual(@as(u32, 0x0702), p.a.nextIndex(testing.io));
}

test "Tunnel: the responder never rekeys on receive, however old the session" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    p.now += 166_000; // past 165 s, inside 180 s
    const w = (try p.a.encapsulate(testing.io, p.clock(), data, &buf)).network;
    try testing.expect((try p.b.decapsulate(testing.io, p.clock(), w, &buf2)).authenticated);
    try testing.expect(!p.b.current.?.is_initiator);
    try testing.expect(!p.b.want_initiation);
    try testing.expect(!p.b.sent_last_minute);
    try testing.expectEqual(Output.none, try p.b.poll(testing.io, p.clock(), &buf2));
}

test "Tunnel: the message limit asks for a rekey one packet past rekey_after_messages" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    var buf: [2048]u8 = undefined;
    p.a.current.?.session.send.counter = transport.rekey_after_messages - 1;
    _ = try p.a.encapsulate(testing.io, p.clock(), data, &buf); // counter is now exactly the limit
    try testing.expectEqual(transport.rekey_after_messages, p.a.current.?.session.send.counter);
    try testing.expect(!p.a.want_initiation);
    _ = try p.a.encapsulate(testing.io, p.clock(), data, &buf);
    try testing.expect(p.a.want_initiation);
}

test "Tunnel: a completed handshake allows the next last-minute rekey on receive" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    for (0..2) |_| {
        p.now += 166_000;
        const w = (try p.b.encapsulate(testing.io, p.clock(), data, &buf)).network;
        _ = try p.a.decapsulate(testing.io, p.clock(), w, &buf2);
        try testing.expect(p.a.want_initiation);
        const m1 = (try p.a.poll(testing.io, p.clock(), &buf)).network;
        const m2 = (try p.b.decapsulate(testing.io, p.clock(), m1, &buf2)).output.network;
        const k = (try p.a.decapsulate(testing.io, p.clock(), m2, &buf)).output.network;
        _ = try p.b.decapsulate(testing.io, p.clock(), k, &buf2);
    }
}

test "Tunnel: expired keys are wiped from the tunnel's memory, previous and current" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    p.now += 6000;
    const m1 = (try p.a.initiateHandshake(testing.io, p.clock(), &buf)).network;
    const m2 = (try p.b.decapsulate(testing.io, p.clock(), m1, &buf2)).output.network;
    const k = (try p.a.decapsulate(testing.io, p.clock(), m2, &buf)).output.network;
    _ = try p.b.decapsulate(testing.io, p.clock(), k, &buf2);
    try testing.expect(p.a.previous != null and p.b.previous != null);
    var ka: [6][32]u8 = undefined;
    var kb: [6][32]u8 = undefined;
    const sa = secretsOf(&p.a, &ka);
    const sb = secretsOf(&p.b, &kb);
    try testing.expectEqual(@as(usize, 3), sa.len); // current send + recv, previous recv
    try testing.expectEqual(@as(usize, 3), sb.len);
    p.now = @max(p.a.zero_keys_at.?, p.b.zero_keys_at.?);
    _ = try p.a.poll(testing.io, p.clock(), &buf);
    _ = try p.b.poll(testing.io, p.clock(), &buf);
    try testing.expect(p.a.current == null and p.a.previous == null and p.a.next == null);
    try testing.expect(p.b.current == null and p.b.previous == null and p.b.next == null);
    try expectAbsent(&p.a, sa);
    try expectAbsent(&p.b, sb);
}

test "Tunnel: an expired unconfirmed next is wiped from the tunnel's memory" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    p.now += 6000;
    const m1 = (try p.a.initiateHandshake(testing.io, p.clock(), &buf)).network;
    _ = try p.b.decapsulate(testing.io, p.clock(), m1, &buf2);
    try testing.expect(p.b.next != null);
    var kb: [6][32]u8 = undefined;
    const sb = secretsOf(&p.b, &kb);
    try testing.expectEqual(@as(usize, 4), sb.len); // current and next, send + recv
    p.now = p.b.zero_keys_at.?;
    _ = try p.b.poll(testing.io, p.clock(), &buf);
    try testing.expect(p.b.current == null and p.b.previous == null and p.b.next == null);
    try expectAbsent(&p.b, sb);
}

test "Tunnel: an initiation in flight keeps the stage when the key deadline passes" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    var buf: [2048]u8 = undefined;
    const zero_at = p.a.zero_keys_at.?;
    p.now += 185_000; // the session is too old to send under
    try testing.expect(!p.a.hasSession(p.clock()));
    try testing.expect(p.now < zero_at);
    try testing.expect((try p.a.encapsulate(testing.io, p.clock(), data, &buf)) == .network);
    try testing.expect(p.a.pending != null);
    try testing.expectEqual(data.len + 2, p.a.stage_tail - p.a.stage_head);
    // The deadline passes without a poll in between; the poll takes the sessions only.
    p.now = zero_at;
    _ = try p.a.poll(testing.io, p.clock(), &buf);
    try testing.expect(p.a.current == null);
    try testing.expectEqual(data.len + 2, p.a.stage_tail - p.a.stage_head);
}

test "Tunnel: allowed_ips: a /32 and a /128 hold exactly one address" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var v6a: [16]u8 = @splat(0);
    v6a[0] = 0xfd;
    v6a[15] = 7;
    const list = [_]root.AllowedIp{ root.AllowedIp.v4(.{ 10, 0, 0, 7 }, 32), root.AllowedIp.v6(v6a, 128) };
    p.b.allowed_ips = &list;
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    for ([_]struct { last: u8, ok: bool }{ .{ .last = 7, .ok = true }, .{ .last = 8, .ok = false }, .{ .last = 6, .ok = false } }) |c| {
        data[12..16].* = .{ 10, 0, 0, c.last };
        try testing.expectEqual(if (c.ok) Drop.no else Drop.disallowed_source, try dropOf(&p, data));
    }
    var six: [48]u8 = @splat(0);
    six[0] = 0x60;
    std.mem.writeInt(u16, six[4..6], 8, .big);
    for ([_]struct { last: u8, ok: bool }{ .{ .last = 7, .ok = true }, .{ .last = 8, .ok = false }, .{ .last = 6, .ok = false } }) |c| {
        six[8..24].* = v6a;
        six[23] = c.last;
        try testing.expectEqual(if (c.ok) Drop.no else Drop.disallowed_source, try dropOf(&p, &six));
    }
}

test "Tunnel: allowed_ips: an address family never matches the other family's entries" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    var pkt: [64]u8 = undefined;
    const data = ip4(&pkt, 4);
    data[12..16].* = .{ 10, 0, 0, 7 };
    var six: [48]u8 = @splat(0);
    six[0] = 0x60;
    std.mem.writeInt(u16, six[4..6], 8, .big);
    six[8] = 0x0a; // 0a00::, the first byte of 10.0.0.0/8
    const v4_lists = [_][1]root.AllowedIp{
        .{root.AllowedIp.v4(.{ 10, 0, 0, 0 }, 8)},
        .{root.AllowedIp.v4(.{ 0, 0, 0, 0 }, 0)},
    };
    for (&v4_lists) |*l| {
        p.b.allowed_ips = l;
        try testing.expectEqual(Drop.no, try dropOf(&p, data));
        try testing.expectEqual(Drop.disallowed_source, try dropOf(&p, &six));
    }
    const v6_all = [_]root.AllowedIp{root.AllowedIp.v6(@splat(0), 0)};
    p.b.allowed_ips = &v6_all;
    try testing.expectEqual(Drop.no, try dropOf(&p, &six));
    try testing.expectEqual(Drop.disallowed_source, try dropOf(&p, data));
}

test "Tunnel: compacting the stage wipes the stale tail" {
    var stage: [100]u8 = @splat(0);
    const priv: [32]u8 = @splat(0x11);
    const pb: [32]u8 = @splat(0x22);
    var kb: hs.Keypair = undefined;
    try hs.Keypair.fromPrivateKey(&pb, &kb);
    var t: Tunnel = undefined;
    const clk: Clock = .{ .mono_ms = 1000, .tai64n = tai64n(1, 0) };
    try Tunnel.init(&t, &.{ .allowed_ips = null, .static_private = &priv, .remote_static = kb.public, .stage = &stage }, testing.io, clk);
    defer t.wipe();
    const a: [40]u8 = @splat('a');
    const b: [40]u8 = @splat('b');
    const c: [20]u8 = @splat('c');
    t.stagePacket(&a);
    t.stagePacket(&b);
    // `a` was sent: its record is wiped and the head moved past it.
    @memset(t.stage[0..42], 0);
    t.stage_head = 42;
    try testing.expectEqual(@as(usize, 84), t.stage_tail);
    t.stagePacket(&c); // 22 > 16 free: b moves to the front, c follows it
    try testing.expectEqual(@as(usize, 0), t.stage_head);
    try testing.expectEqual(@as(usize, 64), t.stage_tail);
    for (t.stage[t.stage_tail..]) |x| try testing.expectEqual(@as(u8, 0), x);
    try testing.expectEqual(@as(usize, 40), std.mem.count(u8, t.stage[0..t.stage_tail], "b"));
}

test "Tunnel: dropping the oldest staged packet wipes it" {
    var stage: [100]u8 = @splat(0);
    const priv: [32]u8 = @splat(0x11);
    const pb: [32]u8 = @splat(0x22);
    var kb: hs.Keypair = undefined;
    try hs.Keypair.fromPrivateKey(&pb, &kb);
    var t: Tunnel = undefined;
    const clk: Clock = .{ .mono_ms = 1000, .tai64n = tai64n(1, 0) };
    try Tunnel.init(&t, &.{ .allowed_ips = null, .static_private = &priv, .remote_static = kb.public, .stage = &stage }, testing.io, clk);
    defer t.wipe();
    const a: [40]u8 = @splat('a');
    const b: [40]u8 = @splat('b');
    t.stagePacket(&a);
    t.stagePacket(&b);
    t.dropOldest();
    try testing.expectEqual(@as(usize, 42), t.stage_head);
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, &stage, "a"));
    try testing.expectEqual(@as(usize, 40), std.mem.count(u8, &stage, "b"));
}

test "Tunnel: a staged packet that went out is wiped from the stage" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    var pkt: [128]u8 = undefined;
    const data = markerPacket(&pkt, "WG-MARKER-0123456789");
    var buf: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    const m1 = (try p.a.encapsulate(testing.io, p.clock(), data, &buf)).network;
    try testing.expect(std.mem.find(u8, &p.a_stage, "WG-MARKER") != null);
    const m2 = (try p.b.decapsulate(testing.io, p.clock(), m1, &buf2)).output.network;
    // The response flushes the staged packet as the first one under the session.
    const first = (try p.a.decapsulate(testing.io, p.clock(), m2, &buf)).output.network;
    try testing.expectEqualSlices(u8, data, (try p.b.decapsulate(testing.io, p.clock(), first, &buf2)).output.tunnel);
    try testing.expectEqual(p.a.stage_head, p.a.stage_tail);
    try testing.expectEqual(@as(?usize, null), std.mem.find(u8, &p.a_stage, "WG-MARKER"));
}

test "Tunnel: a finished handshake leaves no pending state, and giving up wipes the ephemeral key" {
    var p: Pair = undefined;
    try p.init(null, 0);
    defer p.a.wipe();
    defer p.b.wipe();
    try p.establish();
    try testing.expect(p.a.pending == null);
    try testing.expect(p.b.pending == null);

    var buf: [2048]u8 = undefined;
    p.now += 6000;
    _ = try p.a.initiateHandshake(testing.io, p.clock(), &buf);
    var eph: [32]u8 = p.a.pending.?.local_ephemeral.?.private;
    try testing.expect(!std.mem.allEqual(u8, &eph, 0));
    var steps: usize = 0;
    while (steps < 200) : (steps += 1) {
        p.now += 1000;
        _ = try p.drain(&p.a, &buf);
        // The newest attempt's key (each retry is a fresh one).
        if (p.a.pending) |*h| eph = h.local_ephemeral.?.private;
    }
    try testing.expect(p.a.pending == null);
    try testing.expectEqual(@as(?usize, null), std.mem.find(u8, std.mem.asBytes(&p.a), &eph));
}

/// The arbitrary-network harness and the simulated-loss model.
const fuzz_support = struct {
    // Test-only (`build.zig`'s `test_deps`, never `deps`).
    const fuzz_driver = @import("testkit").fuzz.driver;
    const Label = enum { arbitrary, peek_bad_static, accept_bad_timestamp, accept_ok, response_forged, data_forged, no_session, delivered, handshake_done, lost, reordered, forged };
    var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

    fn mark(comptime l: Label) void {
        reach[@backingInt(l)] += 1;
        fuzz_driver.hit(@tagName(l));
    }

    /// Random datagrams at a tunnel in every state: no panic, no session from bytes
    /// the peer did not sign. mac1's key is public, so a forger computes it, and so
    /// does this: otherwise nothing past mac1 would ever be reached.
    fn arbitraryHarness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
        _ = gpa;
        var p: Pair = undefined;
        try p.init(null, 0);
        defer p.a.wipe();
        defer p.b.wipe();
        if (smith.value(u8) & 1 == 0) try p.establish();
        var buf: [2048]u8 = undefined;
        var other: [2048]u8 = undefined;
        var dgram: [512]u8 = undefined;
        const mac_key = noise.mac1Key(p.a.static_keypair.public);
        const init_mac = @offsetOf(hs.MessageInitiation, "mac1");
        const resp_mac = @offsetOf(hs.MessageResponse, "mac1");
        var rounds: usize = 0;
        while (rounds < 6) : (rounds += 1) {
            p.now += @as(u64, smith.value(u8)) * 64;
            switch (smith.value(u8) % 5) {
                0 => { // anything, of any plausible length
                    mark(.arbitrary);
                    const lens = [_]usize{ 0, 3, 4, 32, 40, 64, 92, 148, 200 };
                    const n = lens[smith.value(u8) % lens.len];
                    smith.bytes(dgram[0..n]);
                    if (n >= 4) {
                        dgram[0] = smith.value(u8) % 6;
                        @memset(dgram[1..4], 0);
                    }
                    _ = p.a.decapsulate(testing.io, p.clock(), dgram[0..n], &buf) catch {};
                },
                1 => { // a forged initiation with a good mac1: the static does not open
                    smith.bytes(dgram[0..148]);
                    @memcpy(dgram[0..4], &[_]u8{ 1, 0, 0, 0 });
                    if (smith.value(u8) & 7 == 0) @memset(dgram[8..40], 0); // low-order ephemeral
                    dgram[init_mac..][0..16].* = noise.keyedMac(&mac_key, dgram[0..init_mac]);
                    if (p.a.decapsulate(testing.io, p.clock(), dgram[0..148], &buf)) |_| {
                        return error.ForgedInitiationAccepted;
                    } else |err| {
                        if (err != error.AuthenticationFailed) return error.WrongRefusal;
                        mark(.peek_bad_static);
                    }
                },
                2 => { // the peer's real initiation, then damage past the static: acceptInitiation
                    p.b.last_sent_handshake_ms = null;
                    const m = (try p.b.initiateHandshake(testing.io, p.clock(), &other)).network;
                    @memcpy(dgram[0..148], m);
                    const damage = smith.value(u8);
                    if (damage & 1 == 0) {
                        dgram[88 + smith.value(u8) % 28] ^= 1; // the timestamp
                        dgram[init_mac..][0..16].* = noise.keyedMac(&mac_key, dgram[0..init_mac]);
                        if (p.a.decapsulate(testing.io, p.clock(), dgram[0..148], &buf)) |_| {
                            return error.ForgedInitiationAccepted;
                        } else |err| {
                            if (err != error.AuthenticationFailed) return error.WrongRefusal;
                            mark(.accept_bad_timestamp);
                        }
                    } else {
                        p.a.last_initiation_ms = null;
                        _ = p.a.decapsulate(testing.io, p.clock(), dgram[0..148], &buf) catch |err| {
                            if (err != error.StaleTimestamp) return error.WrongRefusal;
                            continue;
                        };
                        mark(.accept_ok);
                    }
                },
                3 => { // a forged response to our pending index
                    p.a.last_sent_handshake_ms = null;
                    _ = try p.a.initiateHandshake(testing.io, p.clock(), &buf);
                    smith.bytes(dgram[0..92]);
                    @memcpy(dgram[0..4], &[_]u8{ 2, 0, 0, 0 });
                    std.mem.writeInt(u32, dgram[8..12], p.a.pending.?.local_index, .little);
                    if (smith.value(u8) & 7 == 0) @memset(dgram[12..44], 0);
                    dgram[resp_mac..][0..16].* = noise.keyedMac(&mac_key, dgram[0..resp_mac]);
                    if (p.a.decapsulate(testing.io, p.clock(), dgram[0..92], &buf)) |_| {
                        return error.ForgedResponseAccepted;
                    } else |err| {
                        if (err != error.AuthenticationFailed) return error.WrongRefusal;
                        if (p.a.pending == null) return error.ForgeryEndedTheAttempt;
                        mark(.response_forged);
                    }
                },
                else => { // a data packet at a live index
                    const idx = if (p.a.current) |*c| c.local_index else if (p.a.next) |*c| c.local_index else {
                        mark(.no_session);
                        continue;
                    };
                    const n: usize = 32 + @as(usize, smith.value(u8)) % 200;
                    smith.bytes(dgram[0..n]);
                    @memcpy(dgram[0..4], &[_]u8{ 4, 0, 0, 0 });
                    std.mem.writeInt(u32, dgram[4..8], idx, .little);
                    if (p.a.decapsulate(testing.io, p.clock(), dgram[0..n], &buf)) |_| {
                        return error.ForgedDataAccepted;
                    } else |_| mark(.data_forged);
                },
            }
            _ = p.a.poll(testing.io, p.clock(), &buf) catch {};
        }
    }

    /// Two tunnels over a lossy, reordering, duplicating wire on a simulated
    /// clock. Whatever comes out of the far tunnel must be a packet that went in,
    /// never twice; at the end the wire is calm and a packet gets through.
    fn simHarness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
        var p: Pair = undefined;
        try p.init(null, if (smith.value(u8) & 3 == 0) 20 else 0);
        defer p.a.wipe();
        defer p.b.wipe();
        const Pkt = struct { to_b: bool, len: usize, bytes: [256]u8 };
        var wire: std.ArrayList(Pkt) = .empty;
        defer wire.deinit(gpa);
        var seen = std.AutoHashMap(u32, void).init(gpa);
        defer seen.deinit();
        var next_id: u32 = 1;
        var buf: [1024]u8 = undefined;

        const Local = struct {
            fn push(w: *std.ArrayList(Pkt), g: std.mem.Allocator, to_b: bool, bytes: []const u8) !void {
                var pk: Pkt = .{ .to_b = to_b, .len = bytes.len, .bytes = undefined };
                @memcpy(pk.bytes[0..bytes.len], bytes);
                try w.append(g, pk);
            }
            fn makePacket(id: u32, out: []u8) []u8 {
                const pk = ip4(out, 8);
                std.mem.writeInt(u32, pk[20..24], id, .little);
                return pk;
            }
        };

        var steps: usize = 0;
        while (steps < 200) : (steps += 1) {
            switch (smith.value(u8) % 8) {
                0, 1 => { // a TUN packet
                    const to_b = smith.value(u8) & 1 == 0;
                    var raw: [64]u8 = undefined;
                    const pk = Local.makePacket(next_id, &raw);
                    next_id += 1;
                    const t = if (to_b) &p.a else &p.b;
                    switch (try t.encapsulate(testing.io, p.clock(), pk, &buf)) {
                        .network => |b| try Local.push(&wire, gpa, to_b, b),
                        else => {},
                    }
                },
                2, 3, 4 => { // something arrives
                    if (wire.items.len == 0) continue;
                    const i = smith.value(u16) % wire.items.len;
                    const pk = wire.items[i];
                    if (smith.value(u8) & 7 == 0) {
                        mark(.reordered); // left on the wire too: a duplicate
                    } else _ = wire.orderedRemove(i);
                    var dg = pk.bytes;
                    if (smith.value(u8) & 15 == 0) {
                        mark(.forged);
                        dg[smith.value(u8) % pk.len] ^= 1;
                    }
                    const t = if (pk.to_b) &p.b else &p.a;
                    const r = t.decapsulate(testing.io, p.clock(), dg[0..pk.len], &buf) catch continue;
                    switch (r.output) {
                        .network => |b| try Local.push(&wire, gpa, !pk.to_b, b),
                        .tunnel => |plain| {
                            mark(.delivered);
                            const id = std.mem.readInt(u32, plain[20..24], .little);
                            if (id == 0 or id >= next_id) return error.PacketNeverSent;
                            const gop = try seen.getOrPut(id);
                            if (gop.found_existing) return error.PacketDeliveredTwice;
                        },
                        .none => {},
                    }
                },
                5 => { // lost
                    if (wire.items.len == 0) continue;
                    mark(.lost);
                    _ = wire.swapRemove(smith.value(u16) % wire.items.len);
                },
                6 => p.now += @as(u64, smith.value(u16)) * 16, // up to about a minute
                else => {
                    for ([_]bool{ true, false }) |to_b| {
                        const t = if (to_b) &p.a else &p.b;
                        var guard: usize = 0;
                        while (guard < 300) : (guard += 1) {
                            switch (try t.poll(testing.io, p.clock(), &buf)) {
                                .network => |b| try Local.push(&wire, gpa, to_b, b),
                                else => break,
                            }
                        } else return error.PollDoesNotSettle;
                    }
                },
            }
            if (p.a.hasSession(p.clock())) mark(.handshake_done);
            if (wire.items.len > 512) wire.clearRetainingCapacity();
        }

        // Calm network, well past every timer: a new packet must get through.
        wire.clearRetainingCapacity();
        p.now += 700_000;
        p.a.last_sent_handshake_ms = null;
        var raw: [64]u8 = undefined;
        const final = Local.makePacket(next_id, &raw);
        next_id += 1;
        // Deliver everything until the wire is quiet.
        const start = try p.a.encapsulate(testing.io, p.clock(), final, &buf);
        if (start == .network) try Local.push(&wire, gpa, true, start.network);
        var hops: usize = 0;
        var arrived = false;
        while (wire.items.len != 0 and hops < 1024) : (hops += 1) {
            const pk = wire.orderedRemove(0);
            const t = if (pk.to_b) &p.b else &p.a;
            // Both sides may have initiated: a response to a replaced initiation is a drop.
            if (t.decapsulate(testing.io, p.clock(), pk.bytes[0..pk.len], &buf)) |r| {
                switch (r.output) {
                    .network => |b| try Local.push(&wire, gpa, !pk.to_b, b),
                    .tunnel => |plain| {
                        if (std.mem.readInt(u32, plain[20..24], .little) == next_id - 1) arrived = true;
                    },
                    .none => {},
                }
            } else |_| {}
            for ([_]bool{ true, false }) |to_b| {
                const q = if (to_b) &p.a else &p.b;
                while (true) switch (try q.poll(testing.io, p.clock(), &buf)) {
                    .network => |b| try Local.push(&wire, gpa, to_b, b),
                    else => break,
                };
            }
        }
        if (!arrived) return error.CalmNetworkNoDelivery;
    }
};

test "fuzz driver: WIREGUARD_FUZZ (wireguard-tunnel, wireguard-tunnel-sim)" {
    const fuzz_driver = @import("testkit").fuzz.driver;
    try fuzz_driver.runAll(.{
        .{ fuzz_support.arbitraryHarness, .{ .prefix = "WIREGUARD_FUZZ", .name = "wireguard-tunnel", .scale = 32 } },
        .{ fuzz_support.simHarness, .{ .prefix = "WIREGUARD_FUZZ", .name = "wireguard-tunnel-sim", .scale = 64 } },
    });
}

test "fuzz harness: 40 seeds in every test run, and they get everywhere" {
    const fuzz_driver = @import("testkit").fuzz.driver;
    fuzz_support.reach = @splat(0);
    for (0..40) |seed| {
        var prng = std.Random.DefaultPrng.init(seed *% 0x9E3779B97F4A7C15);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        try fuzz_support.simHarness(fuzz_driver.Rng, &rng, testing.allocator);
        var prng2 = std.Random.DefaultPrng.init(seed);
        var rng2: fuzz_driver.Rng = .{ .r = prng2.random() };
        try fuzz_support.arbitraryHarness(fuzz_driver.Rng, &rng2, testing.allocator);
    }
    for (fuzz_support.reach, 0..) |n, i| {
        if (n == 0) {
            std.debug.print("reach: label {d} never hit in 40 seeds\n", .{i});
            return error.HarnessDoesNotReach;
        }
    }
}
