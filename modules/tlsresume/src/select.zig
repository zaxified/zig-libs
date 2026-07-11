// SPDX-License-Identifier: MIT

//! tlsresume.select — server-side ClientHello PSK-identity selection (RFC
//! 8446 §4.2.11): given the offered `pre_shared_key` identities + binders
//! and the engine-supplied transcript-hash prefix, try each identity in
//! order, unseal its STEK ticket, check freshness, derive the PSK, verify
//! the binder, and return the first identity that passes all three checks.
//!
//! **`SessionState(rms_len)` is REAL** — it is pure struct (de)serialization
//! (no crypto, no judgment call), defining the minimal plaintext layout
//! this module expects INSIDE a STEK-sealed ticket blob (`stek.zig` itself
//! is agnostic to what it seals; this is `tlsresume`'s own canonical
//! choice, analogous to how `NewSessionTicket.ticket` is opaque per RFC
//! 8446 but every server still picks SOME concrete format for it). An
//! engine that seals a richer record (ALPN, negotiated group, ...) treats
//! this layout as a required PREFIX and appends its own fields after —
//! `parse` reads only the fixed prefix and ignores anything past it.
//!
//! **`selectPsk` is REAL** — it composes `stek.StekRing.open`,
//! `replay.deobfuscateAge`/`withinFreshnessWindow`, `psk.derivePsk`/
//! `earlySecret`/`binderKey`/`verifyBinder`, and (optionally)
//! `replay.StrikeRegister.checkAndMark`, iterating the offered identities
//! in order and short-circuiting on the first fully-verified one. See its
//! doc comment for the exact per-identity check sequence and the
//! binder-before-strike-register ordering rationale.

const std = @import("std");
const stek = @import("stek.zig");
const psk = @import("psk.zig");
const replay = @import("replay.zig");

/// The fixed prefix this module expects inside an opened STEK ticket
/// plaintext (see the module doc comment). `rms_len` is the resumption
/// master secret / PSK length for the negotiated cipher suite's hash (32
/// for SHA-256, 48 for SHA-384 — matches `Hkdf.prk_length`).
pub fn SessionState(comptime rms_len: usize) type {
    return struct {
        const Self = @This();

        resumption_master_secret: [rms_len]u8,
        /// View into the buffer passed to `parse`.
        ticket_nonce: []const u8,
        /// Milliseconds since the Unix epoch this server issued the
        /// ticket, per the caller's clock (this module makes no wall-clock
        /// calls itself — see `replay.zig`'s doc comment).
        issued_at_ms: i64,
        /// RFC 8446 §4.2.11.1's per-ticket `ticket_age_add`, stamped at
        /// issuance and needed again here to `replay.deobfuscateAge` the
        /// client's reported age.
        ticket_age_add: u32,

        pub const ParseError = error{Malformed};
        pub const SerializeError = error{BufferTooSmall};

        /// `rms_len + 1 + ticket_nonce.len + 8 + 4` — the exact byte count
        /// `serialize` writes for a given `ticket_nonce` length.
        pub fn wireLen(ticket_nonce_len: usize) usize {
            return rms_len + 1 + ticket_nonce_len + 8 + 4;
        }

        pub fn serialize(self: Self, out: []u8) SerializeError![]u8 {
            const total = wireLen(self.ticket_nonce.len);
            if (out.len < total) return error.BufferTooSmall;
            var w: usize = 0;
            @memcpy(out[w..][0..rms_len], &self.resumption_master_secret);
            w += rms_len;
            out[w] = @intCast(self.ticket_nonce.len);
            w += 1;
            @memcpy(out[w..][0..self.ticket_nonce.len], self.ticket_nonce);
            w += self.ticket_nonce.len;
            std.mem.writeInt(i64, out[w..][0..8], self.issued_at_ms, .big);
            w += 8;
            std.mem.writeInt(u32, out[w..][0..4], self.ticket_age_add, .big);
            w += 4;
            std.debug.assert(w == total);
            return out[0..total];
        }

        /// Parses the fixed prefix out of `bytes`; any bytes beyond it
        /// (an engine's own appended fields) are silently ignored — this
        /// is intentional (see the module doc comment), not truncation.
        pub fn parse(bytes: []const u8) ParseError!Self {
            if (bytes.len < rms_len + 1) return error.Malformed;
            var r: usize = 0;
            var rms: [rms_len]u8 = undefined;
            @memcpy(&rms, bytes[r..][0..rms_len]);
            r += rms_len;
            const nonce_len = bytes[r];
            r += 1;
            if (bytes.len < r + @as(usize, nonce_len) + 8 + 4) return error.Malformed;
            const nonce = bytes[r..][0..nonce_len];
            r += nonce_len;
            const issued_at_ms = std.mem.readInt(i64, bytes[r..][0..8], .big);
            r += 8;
            const ticket_age_add = std.mem.readInt(u32, bytes[r..][0..4], .big);
            r += 4;
            return .{
                .resumption_master_secret = rms,
                .ticket_nonce = nonce,
                .issued_at_ms = issued_at_ms,
                .ticket_age_add = ticket_age_add,
            };
        }
    };
}

pub const SelectError = error{
    /// No offered identity unsealed, passed freshness, and verified its
    /// binder. The engine should fall back to a full (non-resumed)
    /// handshake — never treat this as fatal.
    NoAcceptableIdentity,
};

/// One offered `PskIdentity` (RFC 8446 §4.2.11) — the opaque ticket bytes
/// (this server's own STEK-sealed blob, if this server issued it) and the
/// client's `obfuscated_ticket_age`. Binders are supplied separately
/// (`selectPsk`'s `binders` param) since RFC 8446 §4.2.11.2 has them as a
/// SEPARATE list, positionally aligned 1:1 with `identities`.
pub const OfferedIdentity = struct {
    ticket: []const u8,
    obfuscated_ticket_age: u32,
};

/// The successful outcome of `selectPsk`: which offered identity matched
/// (`selected_index`, into the caller's `identities` slice — RFC 8446
/// requires the server to echo this index in its own `pre_shared_key`
/// extension), the restored PSK, and the decoded session-state prefix.
pub fn Selection(comptime rms_len: usize) type {
    return struct {
        selected_index: usize,
        psk: [rms_len]u8,
        session: SessionState(rms_len),
    };
}

/// Server-side ClientHello PSK selection (RFC 8446 §4.2.11), composing this
/// module's other pieces:
///
/// For each `identities[i]` (in the order offered — RFC 8446 does not
/// require trying them in any other order, though a server MAY prefer
/// later/newer identities):
///   1. `ring.open(identities[i].ticket, open_scratch)` — unseal the STEK
///      ticket; skip (try the next identity) on any `stek.OpenError`
///      (unknown/expired key, tampered ciphertext — never fatal, just not
///      this server's live ticket).
///   2. `SessionState(Hkdf.prk_length).parse(...)` the opened plaintext.
///   3. `replay.deobfuscateAge` the client's reported age against the
///      session's `ticket_age_add`, then `replay.withinFreshnessWindow`
///      against `now_ms - session.issued_at_ms`; skip on failure.
///   4. `psk.derivePsk(Hkdf, session.resumption_master_secret,
///      session.ticket_nonce, Hkdf.prk_length)`, then
///      `psk.verifyBinder(Hkdf, Hmac, psk.binderKey(Hkdf,
///      psk.earlySecret(Hkdf, &derived_psk), empty_transcript_hash),
///      truncated_client_hello_transcript_hash, binders[i])`; skip on a
///      failed binder.
///   5. If `strike` is non-null: `strike.checkAndMark(identities[i].ticket,
///      now_ms)`; skip if it reports a replay (or fails to allocate —
///      fail-closed). **Ordering: the binder is verified BEFORE the strike
///      register is consulted/marked** — an attacker who replays a captured
///      ticket with a forged binder therefore never consumes the ticket's
///      single-use slot, so they cannot DoS the legitimate client's own
///      resumption. (An attacker who replays the FULL captured ClientHello
///      — real binder included — does consume the slot, but that is exactly
///      the §8.1 single-use semantic: whichever copy arrives first wins,
///      every later copy is rejected.) Marking only fully-verified tickets
///      also keeps the bounded register from being flooded with garbage
///      identifiers an attacker can fabricate for free.
///   6. All checks pass -> return `.{ .selected_index = i, .psk =
///      derived_psk, .session = session }`.
///
/// `error.NoAcceptableIdentity` if no offered identity passes all checks
/// (the engine should fall back to a full handshake, not fail the
/// connection). `open_scratch` backs the unsealed plaintext (see
/// `stek.StekRing.open`'s `out` buffer) — sized by the caller for the
/// largest session-state record it seals; the returned
/// `session.ticket_nonce` slice points into it.
///
/// `strike` is optional because RFC 8446 §8 only MANDATES anti-replay for
/// 0-RTT/early-data acceptance; a server that accepts a resumption PSK
/// multiple times (no early data) may pass `null`.
pub fn selectPsk(
    comptime Hkdf: type,
    comptime Hmac: type,
    comptime Ring: type,
    ring: *const Ring,
    identities: []const OfferedIdentity,
    binders: []const [Hmac.mac_length]u8,
    empty_transcript_hash: []const u8,
    truncated_client_hello_transcript_hash: []const u8,
    now_ms: i64,
    freshness_window_ms: u32,
    strike: ?*replay.StrikeRegister,
    open_scratch: []u8,
) SelectError!Selection(Hkdf.prk_length) {
    // RFC 8446 §4.2.11.2: binders align 1:1 with identities; a mismatch is
    // an engine-side parsing bug, not attacker-reachable input shape.
    std.debug.assert(identities.len == binders.len);

    for (identities, binders, 0..) |identity, binder, i| {
        // 1. Unseal — not this server's live ticket? Try the next one.
        const plaintext = ring.open(identity.ticket, open_scratch) catch continue;

        // 2. Parse the canonical session-state prefix.
        const session = SessionState(Hkdf.prk_length).parse(plaintext) catch continue;

        // 3. Freshness (RFC 8446 §4.2.11.1): the client's reported age must
        // track the server's own elapsed-time measurement.
        const elapsed_ms = now_ms - session.issued_at_ms;
        if (elapsed_ms < 0 or elapsed_ms > std.math.maxInt(u32)) continue;
        const reported_age_ms = replay.deobfuscateAge(identity.obfuscated_ticket_age, session.ticket_age_add);
        if (!replay.withinFreshnessWindow(reported_age_ms, @intCast(elapsed_ms), freshness_window_ms)) continue;

        // 4. Derive the PSK and verify the binder (RFC 8446 §4.2.11.2) —
        // constant-time compare inside psk.verifyBinder.
        const derived_psk = psk.derivePsk(Hkdf, session.resumption_master_secret, session.ticket_nonce, Hkdf.prk_length);
        const binder_key = psk.binderKey(Hkdf, psk.earlySecret(Hkdf, &derived_psk), empty_transcript_hash);
        if (!psk.verifyBinder(Hkdf, Hmac, binder_key, truncated_client_hello_transcript_hash, binder)) continue;

        // 5. Anti-replay (RFC 8446 §8.1) — only AFTER the binder verified;
        // see the doc comment for the ordering rationale. Allocation
        // failure rejects (fail-closed), never accepts.
        if (strike) |register| {
            const fresh = register.checkAndMark(identity.ticket, now_ms) catch false;
            if (!fresh) continue;
        }

        return .{ .selected_index = i, .psk = derived_psk, .session = session };
    }
    return error.NoAcceptableIdentity;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "SessionState: serialize/parse round-trip (real — pure struct packing, no crypto)" {
    const S = SessionState(32);
    const s = S{
        .resumption_master_secret = [_]u8{0xAB} ** 32,
        .ticket_nonce = &[_]u8{ 0x00, 0x00 },
        .issued_at_ms = 1_752_000_000_000,
        .ticket_age_add = 0xfad6aac5,
    };
    var buf: [64]u8 = undefined;
    const wire = try s.serialize(&buf);
    try testing.expectEqual(S.wireLen(2), wire.len);

    const parsed = try S.parse(wire);
    try testing.expectEqualSlices(u8, &s.resumption_master_secret, &parsed.resumption_master_secret);
    try testing.expectEqualSlices(u8, s.ticket_nonce, parsed.ticket_nonce);
    try testing.expectEqual(s.issued_at_ms, parsed.issued_at_ms);
    try testing.expectEqual(s.ticket_age_add, parsed.ticket_age_add);
}

test "SessionState: parse ignores an engine's trailing appended fields" {
    const S = SessionState(32);
    const s = S{
        .resumption_master_secret = [_]u8{0x11} ** 32,
        .ticket_nonce = &[_]u8{0x01},
        .issued_at_ms = 42,
        .ticket_age_add = 7,
    };
    var buf: [64]u8 = undefined;
    const wire = try s.serialize(&buf);
    var extended: [70]u8 = undefined;
    @memcpy(extended[0..wire.len], wire);
    extended[wire.len] = 0xEE; // engine's own extra field byte
    extended[wire.len + 1] = 0xFF;

    const parsed = try S.parse(extended[0 .. wire.len + 2]);
    try testing.expectEqual(s.issued_at_ms, parsed.issued_at_ms);
    try testing.expectEqual(s.ticket_age_add, parsed.ticket_age_add);
}

test "SessionState: truncated input is a typed Malformed error" {
    const S = SessionState(32);
    try testing.expectError(error.Malformed, S.parse(&[_]u8{0} ** 10));
}

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

fn sha256Of(s: []const u8) [32]u8 {
    var h: [32]u8 = undefined;
    Sha256.hash(s, &h, .{});
    return h;
}

test "selectPsk end-to-end: STEK-issued ticket -> ClientHello2 -> restored PSK; tamper/forge/stale/replay all reject" {
    // ── issue side: SessionState.serialize -> ring.seal -> ticket bytes ──
    var ring = stek.DefaultRing.init();
    ring.rotate(1, [_]u8{0x42} ** stek.key_length, 0);

    const rms = [_]u8{0xAB} ** 32;
    const ticket_nonce = [_]u8{ 0x00, 0x00 };
    const issued_at_ms: i64 = 1_000_000;
    const ticket_age_add: u32 = 0xfad6aac5;
    const state = SessionState(32){
        .resumption_master_secret = rms,
        .ticket_nonce = &ticket_nonce,
        .issued_at_ms = issued_at_ms,
        .ticket_age_add = ticket_age_add,
    };
    var plaintext_buf: [128]u8 = undefined;
    const plaintext = try state.serialize(&plaintext_buf);
    var blob_buf: [160]u8 = undefined;
    const ticket = try ring.seal(plaintext, [_]u8{0x01} ** stek.nonce_length, &blob_buf);

    // ── resume side: what an RFC-8446 client would independently derive ──
    const age_ms: u32 = 5_000;
    const now_ms: i64 = issued_at_ms + age_ms;
    const identity = OfferedIdentity{
        .ticket = ticket,
        .obfuscated_ticket_age = replay.obfuscateAge(age_ms, ticket_age_add),
    };
    const empty_hash = sha256Of("");
    const truncated_ch_hash = sha256Of("fake truncated ClientHello2");
    const client_psk = psk.derivePsk(HkdfSha256, rms, &ticket_nonce, 32);
    const client_binder_key = psk.binderKey(HkdfSha256, psk.earlySecret(HkdfSha256, &client_psk), &empty_hash);
    const binder = psk.computeBinder(HkdfSha256, HmacSha256, client_binder_key, &truncated_ch_hash);

    var strike = replay.StrikeRegister.init(testing.allocator, 8, 60_000);
    defer strike.deinit();
    var scratch: [128]u8 = undefined;
    const window_ms: u32 = 10_000;

    // ── happy path: found at index 0, PSK restored byte-exact ──
    const selection = try selectPsk(HkdfSha256, HmacSha256, stek.DefaultRing, &ring, &.{identity}, &.{binder}, &empty_hash, &truncated_ch_hash, now_ms, window_ms, &strike, &scratch);
    try testing.expectEqual(@as(usize, 0), selection.selected_index);
    try testing.expectEqualSlices(u8, &client_psk, &selection.psk);
    try testing.expectEqual(ticket_age_add, selection.session.ticket_age_add);
    try testing.expectEqualSlices(u8, &ticket_nonce, selection.session.ticket_nonce);

    // ── replay: the exact same offer again is rejected by the register ──
    try testing.expectError(error.NoAcceptableIdentity, selectPsk(HkdfSha256, HmacSha256, stek.DefaultRing, &ring, &.{identity}, &.{binder}, &empty_hash, &truncated_ch_hash, now_ms, window_ms, &strike, &scratch));

    // ── forged binder: rejected AND does not consume the single-use slot ──
    var strike2 = replay.StrikeRegister.init(testing.allocator, 8, 60_000);
    defer strike2.deinit();
    var bad_binder = binder;
    bad_binder[0] ^= 1;
    try testing.expectError(error.NoAcceptableIdentity, selectPsk(HkdfSha256, HmacSha256, stek.DefaultRing, &ring, &.{identity}, &.{bad_binder}, &empty_hash, &truncated_ch_hash, now_ms, window_ms, &strike2, &scratch));
    // The legitimate client still resumes: the forgery attempt above never
    // reached (and thus never marked) the strike register.
    _ = try selectPsk(HkdfSha256, HmacSha256, stek.DefaultRing, &ring, &.{identity}, &.{binder}, &empty_hash, &truncated_ch_hash, now_ms, window_ms, &strike2, &scratch);

    // ── tampered ticket: falls through, never a panic or false accept ──
    var tampered_buf: [160]u8 = undefined;
    @memcpy(tampered_buf[0..ticket.len], ticket);
    tampered_buf[stek.overhead - 1] ^= 1; // a ciphertext byte
    const tampered = OfferedIdentity{ .ticket = tampered_buf[0..ticket.len], .obfuscated_ticket_age = identity.obfuscated_ticket_age };
    try testing.expectError(error.NoAcceptableIdentity, selectPsk(HkdfSha256, HmacSha256, stek.DefaultRing, &ring, &.{tampered}, &.{binder}, &empty_hash, &truncated_ch_hash, now_ms, window_ms, null, &scratch));

    // ── stale age: replayed obfuscated age drifts outside the window ──
    const late_ms: i64 = issued_at_ms + age_ms + 100_000; // 100 s later, same claimed age
    try testing.expectError(error.NoAcceptableIdentity, selectPsk(HkdfSha256, HmacSha256, stek.DefaultRing, &ring, &.{identity}, &.{binder}, &empty_hash, &truncated_ch_hash, late_ms, window_ms, null, &scratch));

    // ── no strike register (strike == null): multiple accepts are allowed ──
    _ = try selectPsk(HkdfSha256, HmacSha256, stek.DefaultRing, &ring, &.{identity}, &.{binder}, &empty_hash, &truncated_ch_hash, now_ms, window_ms, null, &scratch);
    _ = try selectPsk(HkdfSha256, HmacSha256, stek.DefaultRing, &ring, &.{identity}, &.{binder}, &empty_hash, &truncated_ch_hash, now_ms, window_ms, null, &scratch);
}

test "selectPsk: second offered identity wins when the first is not ours (selected_index echoes position)" {
    var ring = stek.DefaultRing.init();
    ring.rotate(3, [_]u8{0x77} ** stek.key_length, 0);

    const rms = [_]u8{0xCD} ** 32;
    const ticket_nonce = [_]u8{0x01};
    const issued_at_ms: i64 = 500_000;
    const ticket_age_add: u32 = 0x1234_5678;
    const state = SessionState(32){
        .resumption_master_secret = rms,
        .ticket_nonce = &ticket_nonce,
        .issued_at_ms = issued_at_ms,
        .ticket_age_add = ticket_age_add,
    };
    var plaintext_buf: [128]u8 = undefined;
    const plaintext = try state.serialize(&plaintext_buf);
    var blob_buf: [160]u8 = undefined;
    const ticket = try ring.seal(plaintext, [_]u8{0x02} ** stek.nonce_length, &blob_buf);

    const age_ms: u32 = 100;
    const now_ms: i64 = issued_at_ms + age_ms;
    const empty_hash = sha256Of("");
    const truncated_ch_hash = sha256Of("another truncated ClientHello");
    const client_psk = psk.derivePsk(HkdfSha256, rms, &ticket_nonce, 32);
    const client_binder_key = psk.binderKey(HkdfSha256, psk.earlySecret(HkdfSha256, &client_psk), &empty_hash);
    const good_binder = psk.computeBinder(HkdfSha256, HmacSha256, client_binder_key, &truncated_ch_hash);

    // Identity 0: some other server's ticket (opaque garbage to our ring).
    const foreign = OfferedIdentity{ .ticket = &([_]u8{0x5C} ** 48), .obfuscated_ticket_age = 0 };
    const ours = OfferedIdentity{ .ticket = ticket, .obfuscated_ticket_age = replay.obfuscateAge(age_ms, ticket_age_add) };
    const dummy_binder = [_]u8{0} ** 32;

    var scratch: [128]u8 = undefined;
    const selection = try selectPsk(HkdfSha256, HmacSha256, stek.DefaultRing, &ring, &.{ foreign, ours }, &.{ dummy_binder, good_binder }, &empty_hash, &truncated_ch_hash, now_ms, 10_000, null, &scratch);
    try testing.expectEqual(@as(usize, 1), selection.selected_index);
    try testing.expectEqualSlices(u8, &client_psk, &selection.psk);
}
