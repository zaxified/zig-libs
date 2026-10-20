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
const burn = @import("burn.zig");
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

/// RFC 8446 §4.6.1: a server MUST NOT use a `ticket_lifetime` above 604800 s
/// (7 days). `selectPsk` skips any session older than this.
pub const max_ticket_lifetime_ms: i64 = 604_800 * 1000;

pub const SelectError = error{
    /// No offered identity unsealed and passed the checks. The engine should
    /// fall back to a full (non-resumed) handshake — never treat this as
    /// fatal.
    NoAcceptableIdentity,
    /// The first identity that unsealed and passed the checks carries a
    /// binder that does not verify. RFC 8446 §4.2.11: the server MUST abort
    /// the handshake (`decrypt_error`, as rustls `IncorrectBinder`) — the
    /// client holds a ticket of ours but not its PSK, or the ClientHello was
    /// tampered with.
    BinderMismatch,
};

/// The engine's own checks on a ticket this server issued (rustls
/// `can_resume`: same cipher suite, same SNI; a lifetime shorter than the
/// 7-day cap). `tail` is the opened plaintext after the `SessionState`
/// prefix — the engine's appended fields, as it sealed them; `age_ms` is
/// `now_ms - issued_at_ms` (0 ≤ age ≤ `max_ticket_lifetime_ms`). False
/// skips the identity like an unknown ticket: its binder is never checked.
pub const Filter = struct {
    ctx: ?*anyopaque = null,
    accept: *const fn (ctx: ?*anyopaque, tail: []const u8, age_ms: i64) bool,
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
///   1. `ring.openAt(identities[i].ticket, now_ms / 1000, policy,
///      open_scratch)` — unseal the STEK ticket; skip (try the next identity)
///      on any `stek.OpenError` (unknown key, a key past `policy.lifetime_s`
///      even if `expire` was never called, tampered ciphertext — never
///      fatal, just not this server's live ticket).
///   2. `SessionState(Hkdf.prk_length).parse(...)` the opened plaintext.
///   3. A session older than `max_ticket_lifetime_ms` (7 days, RFC 8446
///      §4.6.1) or stamped in the future is skipped. Then, if
///      `freshness_window_ms` is set, `replay.deobfuscateAge` the client's
///      reported age against the session's `ticket_age_add` and
///      `replay.withinFreshnessWindow` it against `now_ms -
///      session.issued_at_ms`; skip on failure. (Null: the reported age is
///      not checked — rustls, BoringSSL and Go check it only before taking
///      early data; it bounds a replay window, it authenticates nothing.)
///   4. If `filter` is set, `filter.accept(tail, age)`; skip on false (the
///      engine's own fields: suite, SNI, its own lifetime).
///   5. `psk.derivePsk(Hkdf, session.resumption_master_secret,
///      session.ticket_nonce, Hkdf.prk_length)`, then
///      `psk.verifyBinder(Hkdf, Hmac, psk.binderKey(Hkdf,
///      psk.earlySecret(Hkdf, &derived_psk), empty_transcript_hash),
///      truncated_client_hello_transcript_hash, binders[i])`. A binder
///      that does not verify ends the search with `error.BinderMismatch`
///      (RFC 8446 §4.2.11: "If this value is not present or does not
///      validate, the server MUST abort the handshake"; rustls). Only this
///      one binder is checked (§4.2.11: servers SHOULD NOT validate
///      several).
///   6. If `strike` is non-null: `strike.checkAndMark(identities[i].ticket,
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
///   7. All checks pass -> write `.{ .selected_index = i, .psk =
///      derived_psk, .session = session }` into `out` (zeroed on error).
///
/// `error.NoAcceptableIdentity` if no offered identity passes all checks
/// (the engine should fall back to a full handshake, not fail the
/// connection); `error.BinderMismatch` is fatal (see step 5).
/// `open_scratch` backs the unsealed plaintext (see
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
    out: *Selection(Hkdf.prk_length),
    ring: *const Ring,
    policy: stek.RotationPolicy,
    identities: []const OfferedIdentity,
    binders: []const [Hmac.mac_length]u8,
    empty_transcript_hash: []const u8,
    truncated_client_hello_transcript_hash: []const u8,
    now_ms: i64,
    freshness_window_ms: ?u32,
    strike: ?*replay.StrikeRegister,
    filter: ?Filter,
    open_scratch: []u8,
) SelectError!void {
    const r = burn.run(burn.select_burn, SelectError!void, selectBody, .{ Hkdf, Hmac, Ring, out, ring, policy, identities, binders, empty_transcript_hash, truncated_client_hello_transcript_hash, now_ms, freshness_window_ms, strike, filter, open_scratch });
    r catch std.crypto.secureZero(u8, std.mem.asBytes(out));
    return r;
}

fn selectBody(
    comptime Hkdf: type,
    comptime Hmac: type,
    comptime Ring: type,
    out: *Selection(Hkdf.prk_length),
    ring: *const Ring,
    policy: stek.RotationPolicy,
    identities: []const OfferedIdentity,
    binders: []const [Hmac.mac_length]u8,
    empty_transcript_hash: []const u8,
    truncated_client_hello_transcript_hash: []const u8,
    now_ms: i64,
    freshness_window_ms: ?u32,
    strike: ?*replay.StrikeRegister,
    filter: ?Filter,
    open_scratch: []u8,
) SelectError!void {
    // RFC 8446 §4.2.11.2: binders align 1:1 with identities; a mismatch is
    // an engine-side parsing bug, not attacker-reachable input shape.
    std.debug.assert(identities.len == binders.len);

    for (identities, binders, 0..) |identity, binder, i| {
        // 1. Unseal — not this server's live ticket? Try the next one.
        const plaintext = ring.openAt(identity.ticket, @divFloor(now_ms, 1000), policy, open_scratch) catch continue;

        // 2. Parse the canonical session-state prefix.
        const session = SessionState(Hkdf.prk_length).parse(plaintext) catch continue;

        // 3. Freshness (RFC 8446 §4.2.11.1): the client's reported age must
        // track the server's own elapsed-time measurement.
        const elapsed_ms = now_ms - session.issued_at_ms;
        // The u32 bound is the `@intCast` below; the 7-day cap is RFC 8446
        // §4.6.1 (`ticket_lifetime` MUST NOT exceed 604800 s), enforced here
        // so a session that outlived every ticket lifetime never resumes.
        if (elapsed_ms < 0 or elapsed_ms > std.math.maxInt(u32)) continue;
        if (elapsed_ms > max_ticket_lifetime_ms) continue;
        if (freshness_window_ms) |window| {
            const reported_age_ms = replay.deobfuscateAge(identity.obfuscated_ticket_age, session.ticket_age_add);
            if (!replay.withinFreshnessWindow(reported_age_ms, @intCast(elapsed_ms), window)) continue;
        }

        // 4. The engine's own fields.
        if (filter) |f| {
            const tail = plaintext[SessionState(Hkdf.prk_length).wireLen(session.ticket_nonce.len)..];
            if (!f.accept(f.ctx, tail, elapsed_ms)) continue;
        }

        // 5. Derive the PSK and verify the binder (RFC 8446 §4.2.11.2) —
        // constant-time compare inside psk.verifyBinder. A bad binder on a
        // ticket we would take is fatal (§4.2.11).
        var derived_psk: [Hkdf.prk_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &derived_psk);
        var early_secret: [Hkdf.prk_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &early_secret);
        var binder_key: [Hkdf.prk_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &binder_key);
        psk.derivePsk(Hkdf, Hkdf.prk_length, &derived_psk, &session.resumption_master_secret, session.ticket_nonce);
        psk.earlySecret(Hkdf, &early_secret, &derived_psk);
        psk.binderKey(Hkdf, &binder_key, &early_secret, empty_transcript_hash);
        if (!psk.verifyBinder(Hkdf, Hmac, &binder_key, truncated_client_hello_transcript_hash, binder)) return error.BinderMismatch;

        // 6. Anti-replay (RFC 8446 §8.1) — only AFTER the binder verified;
        // see the doc comment for the ordering rationale. Allocation
        // failure rejects (fail-closed), never accepts.
        if (strike) |register| {
            const fresh = register.checkAndMark(identity.ticket, now_ms) catch false;
            if (!fresh) continue;
        }

        out.* = .{ .selected_index = i, .psk = derived_psk, .session = session };
        return;
    }
    return error.NoAcceptableIdentity;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

/// By-value test wrapper over the `out`-pointer `selectPsk`.
fn selectV(
    ring: *const stek.DefaultRing,
    policy: stek.RotationPolicy,
    identities: []const OfferedIdentity,
    binders: []const [32]u8,
    empty_transcript_hash: []const u8,
    truncated_client_hello_transcript_hash: []const u8,
    now_ms: i64,
    freshness_window_ms: ?u32,
    strike: ?*replay.StrikeRegister,
    open_scratch: []u8,
) SelectError!Selection(32) {
    var sel: Selection(32) = undefined;
    try selectPsk(HkdfSha256, HmacSha256, stek.DefaultRing, &sel, ring, policy, identities, binders, empty_transcript_hash, truncated_client_hello_transcript_hash, now_ms, freshness_window_ms, strike, null, open_scratch);
    return sel;
}

/// The binder an RFC 8446 client derives independently of `selectPsk`
/// (test helper; the secrets are test constants).
fn clientBinder(rms: *const [32]u8, nonce: []const u8, empty_hash: []const u8, ch_hash: []const u8) [32]u8 {
    var client_psk: [32]u8 = undefined;
    var es: [32]u8 = undefined;
    var bk: [32]u8 = undefined;
    var binder: [32]u8 = undefined;
    psk.derivePsk(HkdfSha256, 32, &client_psk, rms, nonce);
    psk.earlySecret(HkdfSha256, &es, &client_psk);
    psk.binderKey(HkdfSha256, &bk, &es, empty_hash);
    psk.computeBinder(HkdfSha256, HmacSha256, &binder, &bk, ch_hash);
    return binder;
}

test "SessionState: serialize/parse round-trip (real — pure struct packing, no crypto)" {
    const S = SessionState(32);
    const s = S{
        .resumption_master_secret = @as([32]u8, @splat(0xAB)),
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
        .resumption_master_secret = @as([32]u8, @splat(0x11)),
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
    try testing.expectError(error.Malformed, S.parse(&@as([10]u8, @splat(0))));
}

// ── fuzz: SessionState.parse never panics on arbitrary bytes ──────────────
//
// `SessionState(rms_len).parse` decodes the canonical plaintext prefix this
// module writes INSIDE a STEK-sealed ticket. In the real `selectPsk` path it
// only ever runs on bytes that already passed AEAD authentication — but the
// function is exported and pure, taking a raw byte slice with a
// length-prefixed field (`ticket_nonce`) in the middle, so it is fuzzed
// directly rather than relying on that call-site invariant holding forever
// (a future caller, or a different ring implementation with a weaker
// integrity story, could feed it un-authenticated bytes). Structured half:
// a real `serialize`d record with the nonce length byte independently
// mutated, to drive the "nonce runs past the buffer" bounds check specifically.

// ⛔ AND THE UNSTRUCTURED HALF NEVER RAN — NOR DID THE MUTATION. The branch
// gate was `smith.value(bool)`, the harness's FIRST draw. A `Smith` scalar
// draw reads eight octets as a little-endian `u64` and returns the range
// minimum when fewer remain, and the target carried no corpus, so outside
// `--fuzz` the single input it ever ran was empty: the bool was false every
// time, so it always took the structured half, and inside it `nonce_len` was
// 0, `issued_at_ms` was 0, `ticket_age_add` was 0, and the second
// `smith.value(bool)` guarding the nonce-length mutation was ALSO false. The
// whole target was: serialize a record with an empty nonce and all-zero
// timestamps, then parse it back successfully. Measured 2026-09-07: 1 round,
// 1 record, 0 mutations, 0 refusals — the `bytes.len < r + nonce_len + 8 + 4`
// bounds check the comment above says the structured half exists for was
// never once evaluated against a disagreeing length.
//
// The branch and the generator are gone. `parse` takes a byte slice, so the
// harness draws one, and the shapes are a corpus built from this module's own
// `serialize`.

/// The corpus, built at run time: the only real record shape is what
/// `serialize` writes, and a hand-pasted copy would drift from it silently.
///
/// ⭐ The harness and the guard below both build it from HERE.
const StateCorpus = struct {
    const cap = 128;
    const S = SessionState(32);

    stores: [9][4 + cap]u8 = undefined,
    entries: [9][]const u8 = undefined,

    fn build(self: *StateCorpus) ![]const []const u8 {
        const kit = @import("testkit").fuzz;
        var scratch: [cap]u8 = undefined;
        var t: [cap]u8 = undefined;
        var n: usize = 0;

        // 0: a record with an empty nonce — the ONLY input this target ever
        //    ran, kept so the "before" case stays covered.
        const empty_nonce = try (S{
            .resumption_master_secret = @as([32]u8, @splat(0xAB)),
            .ticket_nonce = "",
            .issued_at_ms = 0,
            .ticket_age_add = 0,
        }).serialize(&scratch);
        self.entries[n] = kit.seedInto(&self.stores[n], empty_nonce);
        n += 1;

        // 1: a realistic record: an 8-octet nonce and non-zero timestamps.
        const full = try (S{
            .resumption_master_secret = @as([32]u8, @splat(0xAB)),
            .ticket_nonce = "\x01\x02\x03\x04\x05\x06\x07\x08",
            .issued_at_ms = 1_700_000_000_000,
            .ticket_age_add = 0xDEAD_BEEF,
        }).serialize(&scratch);
        const full_len = full.len;
        @memcpy(t[0..full_len], full);
        self.entries[n] = kit.seedInto(&self.stores[n], t[0..full_len]);
        n += 1;

        // 2: ⭐ the nonce-length octet raised to 255 with nothing behind it —
        //    the `bytes.len < r + nonce_len + 8 + 4` refusal the deleted
        //    mutation branch existed for and never produced.
        @memcpy(t[0..full_len], full);
        t[32] = 0xFF;
        self.entries[n] = kit.seedInto(&self.stores[n], t[0..full_len]);
        n += 1;

        // 3: the nonce-length octet lowered to 0 — a claimed length SHORTER
        //    than what follows, which `parse` accepts and reads past.
        @memcpy(t[0..full_len], full);
        t[32] = 0;
        self.entries[n] = kit.seedInto(&self.stores[n], t[0..full_len]);
        n += 1;

        // 4: the nonce-length octet one too large for the room left.
        @memcpy(t[0..full_len], full);
        t[32] = 9;
        self.entries[n] = kit.seedInto(&self.stores[n], t[0..full_len]);
        n += 1;

        // 5: the record truncated by one octet — the age_add field cut short.
        self.entries[n] = kit.seedInto(&self.stores[n], full[0 .. full_len - 1]);
        n += 1;

        // 6: 33 octets — the shortest input that gets past `bytes.len <
        //    rms_len + 1` and is then refused by the second check.
        @memset(t[0..33], 0);
        self.entries[n] = kit.seedInto(&self.stores[n], t[0..33]);
        n += 1;

        // 7: 32 octets — one short of that first check.
        self.entries[n] = kit.seedInto(&self.stores[n], t[0..32]);
        n += 1;

        // 8: the empty record.
        self.entries[n] = kit.seedInto(&self.stores[n], t[0..0]);
        n += 1;

        std.debug.assert(n == self.entries.len);
        return &self.entries;
    }
};

test "fuzz: SessionState(32).parse never panics on arbitrary bytes" {
    var corpus: StateCorpus = .{};
    try testing.fuzz({}, fuzzSessionStateParse, .{ .corpus = try corpus.build() });
}

fn fuzzSessionStateParse(_: void, smith: *std.testing.Smith) !void {
    return stateHarness(std.testing.Smith, smith, testing.allocator);
}

const fuzz_driver = @import("testkit").fuzz.driver;
const StateLabel = enum { raw_rejected, raw_accepted, roundtrip, truncated_rejected, flipped_parsed };
var state_reach: [@typeInfo(StateLabel).@"enum".field_names.len]usize = @splat(0);

fn markState(comptime l: StateLabel) void {
    state_reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// Generic over its source (`Smith` under `--fuzz`, `fuzz_driver.Rng` under the
/// driver). The drawn octets are parsed raw (any outcome, no panic); then they
/// also seed a PRNG that builds a genuine record: `serialize` then `parse` must
/// give the same fields back, every truncation must be refused, and a flipped
/// octet (anywhere but the nonce-length byte) must still parse.
fn stateHarness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    const St = SessionState(32);
    var buf: [StateCorpus.cap]u8 = undefined;
    const len: usize = smith.slice(&buf);
    if (St.parse(buf[0..len])) |_| markState(.raw_accepted) else |_| markState(.raw_rejected);

    var prng = std.Random.DefaultPrng.init(std.hash.Wyhash.hash(0, buf[0..len]));
    const rnd = prng.random();
    var nonce: [16]u8 = undefined;
    rnd.bytes(&nonce);
    const nonce_len = rnd.uintAtMost(usize, nonce.len);
    var rms: [32]u8 = undefined;
    rnd.bytes(&rms);
    const state = St{
        .resumption_master_secret = rms,
        .ticket_nonce = nonce[0..nonce_len],
        .issued_at_ms = rnd.int(i64),
        .ticket_age_add = rnd.int(u32),
    };
    var wire: [StateCorpus.cap]u8 = undefined;
    const enc = state.serialize(&wire) catch return error.SerializeFailed;
    const back = St.parse(enc) catch return error.GenuineRecordRejected;
    if (!std.mem.eql(u8, &back.resumption_master_secret, &rms) or
        !std.mem.eql(u8, back.ticket_nonce, state.ticket_nonce) or
        back.issued_at_ms != state.issued_at_ms or back.ticket_age_add != state.ticket_age_add)
        return error.RoundTripMismatch;
    markState(.roundtrip);

    const cut = rnd.uintLessThan(usize, enc.len);
    if (St.parse(enc[0..cut])) |_| return error.TruncatedRecordAccepted else |_| {}
    markState(.truncated_rejected);

    var flipped: [StateCorpus.cap]u8 = undefined;
    @memcpy(flipped[0..enc.len], enc);
    var at = rnd.uintLessThan(usize, enc.len);
    if (at == 32) at = 0; // the nonce-length octet decides the layout; leave it
    flipped[at] ^= @as(u8, 1) << rnd.int(u3);
    _ = St.parse(flipped[0..enc.len]) catch return error.FlippedRecordRejected;
    markState(.flipped_parsed);
}

test "fuzz driver: TLSRESUME_FUZZ (tlsresume-state)" {
    try fuzz_driver.run(stateHarness, .{ .prefix = "TLSRESUME_FUZZ", .name = "tlsresume-state" });
}

test "fuzz harness: 300 state seeds in every test run, and they get everywhere" {
    state_reach = @splat(0);
    for (0..300) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        stateHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("tlsresume-state seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (state_reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 300 seeds\n", .{@as(StateLabel, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

test "corpus: every record seed reaches parse, and the nonce octets recovered are pinned" {
    // ⭐ The measurement, executable. `nonce_octets` is the second number and
    // it is the load-bearing one: a record with an EMPTY nonce parses
    // successfully — that is exactly what the collapsed harness produced and
    // parsed on every run — so an "accepted > 0" guard would have read green
    // over it. Nonce octets recovered cannot come from that record.
    var corpus: StateCorpus = .{};
    const seeds = try corpus.build();

    var nonempty: usize = 0;
    var accepted: usize = 0;
    var refused: usize = 0;
    var nonce_octets: usize = 0;
    for (seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [StateCorpus.cap]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const s = SessionState(32).parse(buf[0..len]) catch {
            refused += 1;
            continue;
        };
        accepted += 1;
        nonce_octets += s.ticket_nonce.len;
    }
    // Measured 2026-09-07. Before: 1 round, 1 record, 0 refusals, 0 nonce
    // octets — the nonce was always empty.
    try testing.expectEqual(seeds.len - 1, nonempty); // the deliberate empty seed
    try testing.expectEqual(@as(usize, 3), accepted);
    try testing.expectEqual(@as(usize, 6), refused);
    try testing.expectEqual(@as(usize, 8), nonce_octets); // only the realistic record's 8-octet nonce survives
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
    ring.rotate(1, &(@as([stek.key_length]u8, @splat(0x42))), 0);

    const rms = @as([32]u8, @splat(0xAB));
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
    const ticket = try ring.seal(plaintext, @as([stek.nonce_length]u8, @splat(0x01)), &blob_buf);

    // ── resume side: what an RFC-8446 client would independently derive ──
    const age_ms: u32 = 5_000;
    const now_ms: i64 = issued_at_ms + age_ms;
    const identity = OfferedIdentity{
        .ticket = ticket,
        .obfuscated_ticket_age = replay.obfuscateAge(age_ms, ticket_age_add),
    };
    const empty_hash = sha256Of("");
    const truncated_ch_hash = sha256Of("fake truncated ClientHello2");
    const binder = clientBinder(&rms, &ticket_nonce, &empty_hash, &truncated_ch_hash);

    var strike = replay.StrikeRegister.init(testing.allocator, 8, 60_000);
    defer strike.deinit();
    var scratch: [128]u8 = undefined;
    const window_ms: u32 = 10_000;

    // ── happy path: found at index 0, PSK restored byte-exact ──
    const selection = try selectV(&ring, .{}, &.{identity}, &.{binder}, &empty_hash, &truncated_ch_hash, now_ms, window_ms, &strike, &scratch);
    try testing.expectEqual(@as(usize, 0), selection.selected_index);
    var client_psk: [32]u8 = undefined;
    psk.derivePsk(HkdfSha256, 32, &client_psk, &rms, &ticket_nonce);
    try testing.expectEqualSlices(u8, &client_psk, &selection.psk);
    try testing.expectEqual(ticket_age_add, selection.session.ticket_age_add);
    try testing.expectEqualSlices(u8, &ticket_nonce, selection.session.ticket_nonce);

    // ── replay: the exact same offer again is rejected by the register ──
    try testing.expectError(error.NoAcceptableIdentity, selectV(&ring, .{}, &.{identity}, &.{binder}, &empty_hash, &truncated_ch_hash, now_ms, window_ms, &strike, &scratch));

    // ── forged binder: fatal (RFC 8446 §4.2.11) AND does not consume the
    // single-use slot ──
    var strike2 = replay.StrikeRegister.init(testing.allocator, 8, 60_000);
    defer strike2.deinit();
    var bad_binder = binder;
    bad_binder[0] ^= 1;
    try testing.expectError(error.BinderMismatch, selectV(&ring, .{}, &.{identity}, &.{bad_binder}, &empty_hash, &truncated_ch_hash, now_ms, window_ms, &strike2, &scratch));
    // The legitimate client still resumes: the forgery attempt above never
    // reached (and thus never marked) the strike register.
    _ = try selectV(&ring, .{}, &.{identity}, &.{binder}, &empty_hash, &truncated_ch_hash, now_ms, window_ms, &strike2, &scratch);

    // ── tampered ticket: falls through, never a panic or false accept ──
    var tampered_buf: [160]u8 = undefined;
    @memcpy(tampered_buf[0..ticket.len], ticket);
    tampered_buf[stek.overhead - 1] ^= 1; // a ciphertext byte
    const tampered = OfferedIdentity{ .ticket = tampered_buf[0..ticket.len], .obfuscated_ticket_age = identity.obfuscated_ticket_age };
    try testing.expectError(error.NoAcceptableIdentity, selectV(&ring, .{}, &.{tampered}, &.{binder}, &empty_hash, &truncated_ch_hash, now_ms, window_ms, null, &scratch));

    // ── stale age: replayed obfuscated age drifts outside the window ──
    const late_ms: i64 = issued_at_ms + age_ms + 100_000; // 100 s later, same claimed age
    try testing.expectError(error.NoAcceptableIdentity, selectV(&ring, .{}, &.{identity}, &.{binder}, &empty_hash, &truncated_ch_hash, late_ms, window_ms, null, &scratch));

    // ── no strike register (strike == null): multiple accepts are allowed ──
    _ = try selectV(&ring, .{}, &.{identity}, &.{binder}, &empty_hash, &truncated_ch_hash, now_ms, window_ms, null, &scratch);
    _ = try selectV(&ring, .{}, &.{identity}, &.{binder}, &empty_hash, &truncated_ch_hash, now_ms, window_ms, null, &scratch);
}

test "selectPsk: second offered identity wins when the first is not ours (selected_index echoes position)" {
    var ring = stek.DefaultRing.init();
    ring.rotate(3, &(@as([stek.key_length]u8, @splat(0x77))), 0);

    const rms = @as([32]u8, @splat(0xCD));
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
    const ticket = try ring.seal(plaintext, @as([stek.nonce_length]u8, @splat(0x02)), &blob_buf);

    const age_ms: u32 = 100;
    const now_ms: i64 = issued_at_ms + age_ms;
    const empty_hash = sha256Of("");
    const truncated_ch_hash = sha256Of("another truncated ClientHello");
    const good_binder = clientBinder(&rms, &ticket_nonce, &empty_hash, &truncated_ch_hash);

    // Identity 0: some other server's ticket (opaque garbage to our ring).
    const foreign = OfferedIdentity{ .ticket = &(@as([48]u8, @splat(0x5C))), .obfuscated_ticket_age = 0 };
    const ours = OfferedIdentity{ .ticket = ticket, .obfuscated_ticket_age = replay.obfuscateAge(age_ms, ticket_age_add) };
    const dummy_binder = @as([32]u8, @splat(0));

    var scratch: [128]u8 = undefined;
    const selection = try selectV(&ring, .{}, &.{ foreign, ours }, &.{ dummy_binder, good_binder }, &empty_hash, &truncated_ch_hash, now_ms, 10_000, null, &scratch);
    try testing.expectEqual(@as(usize, 1), selection.selected_index);
    var client_psk: [32]u8 = undefined;
    psk.derivePsk(HkdfSha256, 32, &client_psk, &rms, &ticket_nonce);
    try testing.expectEqualSlices(u8, &client_psk, &selection.psk);
}

// ── audit 2026-10-04: tests asked for by mutation survivors ──────────────────

test "selectPsk: a ticket from the future and a strike register that cannot allocate both reject" {
    // A session issued after `now_ms` has no elapsed time to compare the
    // client's age against (the clock went backwards, or the blob was forged
    // with a future stamp) — not acceptable. And the strike register's
    // allocation failure is fail-closed (doc step 5: "fails to allocate —
    // fail-closed"), never an accept.
    var ring = stek.DefaultRing.init();
    ring.rotate(1, &(@as([stek.key_length]u8, @splat(0x42))), 0);
    const rms = @as([32]u8, @splat(0xAB));
    const nonce = [_]u8{ 0, 0 };
    const issued_at_ms: i64 = 1_000_000;
    const state = SessionState(32){ .resumption_master_secret = rms, .ticket_nonce = &nonce, .issued_at_ms = issued_at_ms, .ticket_age_add = 7 };
    var pt_buf: [128]u8 = undefined;
    var blob_buf: [160]u8 = undefined;
    const ticket = try ring.seal(try state.serialize(&pt_buf), @as([stek.nonce_length]u8, @splat(0x01)), &blob_buf);
    const empty_hash = sha256Of("");
    const ch_hash = sha256Of("truncated ClientHello");
    const binder = clientBinder(&rms, &nonce, &empty_hash, &ch_hash);
    const identity = OfferedIdentity{ .ticket = ticket, .obfuscated_ticket_age = replay.obfuscateAge(0, 7) };
    var scratch: [128]u8 = undefined;

    _ = try selectV(&ring, .{}, &.{identity}, &.{binder}, &empty_hash, &ch_hash, issued_at_ms, 1_000, null, &scratch); // control
    try testing.expectError(error.NoAcceptableIdentity, selectV(&ring, .{}, &.{identity}, &.{binder}, &empty_hash, &ch_hash, issued_at_ms - 1, 1_000, null, &scratch));

    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var strike = replay.StrikeRegister.init(failing.allocator(), 8, 60_000);
    defer strike.deinit();
    try testing.expectError(error.NoAcceptableIdentity, selectV(&ring, .{}, &.{identity}, &.{binder}, &empty_hash, &ch_hash, issued_at_ms, 1_000, &strike, &scratch));
}

// ── audit 2026-10-19 O4: lifetimes enforced inside selectPsk ─────────────────

/// Seals a session issued at `issued_at_ms` under a key installed at second 0
/// and returns the ticket plus its matching binder (test helper for the two
/// lifetime tests; the secrets are test constants).
const LifetimeFixture = struct {
    blob: [160]u8 = undefined,
    ticket_len: usize = 0,
    binder: [32]u8 = undefined,
    empty_hash: [32]u8 = undefined,
    ch_hash: [32]u8 = undefined,

    const nonce = [_]u8{ 0, 1 };
    const age_add: u32 = 0x0BAD_F00D;

    fn build(self: *LifetimeFixture, ring: *stek.DefaultRing, issued_at_ms: i64) !void {
        const rms = @as([32]u8, @splat(0x5A));
        const state = SessionState(32){ .resumption_master_secret = rms, .ticket_nonce = &nonce, .issued_at_ms = issued_at_ms, .ticket_age_add = age_add };
        var pt: [128]u8 = undefined;
        self.ticket_len = (try ring.seal(try state.serialize(&pt), @as([stek.nonce_length]u8, @splat(0x03)), &self.blob)).len;
        self.empty_hash = sha256Of("");
        self.ch_hash = sha256Of("lifetime test ClientHello");
        self.binder = clientBinder(&rms, &nonce, &self.empty_hash, &self.ch_hash);
    }

    fn select(self: *const LifetimeFixture, ring: *const stek.DefaultRing, policy: stek.RotationPolicy, now_ms: i64, age_ms: u32) SelectError!Selection(32) {
        const id = OfferedIdentity{ .ticket = self.blob[0..self.ticket_len], .obfuscated_ticket_age = replay.obfuscateAge(age_ms, age_add) };
        var scratch: [128]u8 = undefined;
        return selectV(ring, policy, &.{id}, &.{self.binder}, &self.empty_hash, &self.ch_hash, now_ms, 10_000, null, &scratch);
    }
};

test "selectPsk: a key past policy.lifetime_s that is still in the ring does not open tickets" {
    var ring = stek.DefaultRing.init();
    ring.rotate(1, &(@as([stek.key_length]u8, @splat(0x42))), 100); // installed at second 100
    const policy = stek.RotationPolicy{ .period_s = 50, .lifetime_s = 300 };
    const issued_at_ms: i64 = 100_000;
    var fx: LifetimeFixture = .{};
    try fx.build(&ring, issued_at_ms);

    // Key accepted while installed_at_s + lifetime_s (400) > now_s; no `expire` call anywhere.
    const age_ms: u32 = 299_000;
    _ = try fx.select(&ring, policy, 399_000 + 999, age_ms + 999); // now_s = 399
    try testing.expectError(error.NoAcceptableIdentity, fx.select(&ring, policy, 400_000, 300_000)); // now_s = 400
    try testing.expectError(error.NoAcceptableIdentity, fx.select(&ring, policy, 400_999, 300_999));
    // The plain `open` still accepts it: the refusal comes from the policy.
    var out: [128]u8 = undefined;
    _ = try ring.open(fx.blob[0..fx.ticket_len], &out);
}

test "selectPsk: a session older than 7 days (RFC 8446 section 4.6.1) is skipped, exactly at the boundary" {
    var ring = stek.DefaultRing.init();
    ring.rotate(1, &(@as([stek.key_length]u8, @splat(0x42))), 0);
    // Key lifetime well beyond 7 days so only the ticket-age cap can refuse.
    const policy = stek.RotationPolicy{ .period_s = 24 * 3600, .lifetime_s = 30 * 24 * 3600 };
    const issued_at_ms: i64 = 1_000_000;
    var fx: LifetimeFixture = .{};
    try fx.build(&ring, issued_at_ms);

    const cap: i64 = max_ticket_lifetime_ms;
    try testing.expectEqual(@as(i64, 604_800_000), cap);
    const at_cap: u32 = @intCast(cap);
    _ = try fx.select(&ring, policy, issued_at_ms + cap, at_cap); // exactly 7 days: accepted
    try testing.expectError(error.NoAcceptableIdentity, fx.select(&ring, policy, issued_at_ms + cap + 1, at_cap + 1));
}

// ── 2026-10-20: tlsserver semantics (rustls) ─────────────────────────────────

test "selectPsk: a bad binder on a ticket we would take aborts, even with a good identity behind it" {
    var ring = stek.DefaultRing.init();
    ring.rotate(1, &(@as([stek.key_length]u8, @splat(0x42))), 0);
    var fx: LifetimeFixture = .{};
    try fx.build(&ring, 1_000);
    const id = OfferedIdentity{ .ticket = fx.blob[0..fx.ticket_len], .obfuscated_ticket_age = replay.obfuscateAge(0, LifetimeFixture.age_add) };
    var bad = fx.binder;
    bad[31] ^= 0x80;
    var scratch: [128]u8 = undefined;
    // RFC 8446 §4.2.11: only the selected PSK's binder is validated, and a
    // failure is fatal — the second (good) offer is never reached.
    try testing.expectError(error.BinderMismatch, selectV(&ring, .{}, &.{ id, id }, &.{ bad, fx.binder }, &fx.empty_hash, &fx.ch_hash, 1_000, 10_000, null, &scratch));
    // A foreign ticket first is skipped, its binder never looked at.
    const foreign = OfferedIdentity{ .ticket = &(@as([48]u8, @splat(0x5C))), .obfuscated_ticket_age = 0 };
    const sel = try selectV(&ring, .{}, &.{ foreign, id }, &.{ bad, fx.binder }, &fx.empty_hash, &fx.ch_hash, 1_000, 10_000, null, &scratch);
    try testing.expectEqual(@as(usize, 1), sel.selected_index);
}

test "selectPsk: freshness null ignores the reported age; the 7-day cap still holds" {
    var ring = stek.DefaultRing.init();
    ring.rotate(1, &(@as([stek.key_length]u8, @splat(0x42))), 0);
    const policy = stek.RotationPolicy{ .period_s = 24 * 3600, .lifetime_s = 30 * 24 * 3600 };
    var fx: LifetimeFixture = .{};
    try fx.build(&ring, 1_000);
    const id = OfferedIdentity{ .ticket = fx.blob[0..fx.ticket_len], .obfuscated_ticket_age = 12345 }; // nonsense age
    var scratch: [128]u8 = undefined;
    try testing.expectError(error.NoAcceptableIdentity, selectV(&ring, policy, &.{id}, &.{fx.binder}, &fx.empty_hash, &fx.ch_hash, 500_000, 10_000, null, &scratch));
    _ = try selectV(&ring, policy, &.{id}, &.{fx.binder}, &fx.empty_hash, &fx.ch_hash, 500_000, null, null, &scratch);
    try testing.expectError(error.NoAcceptableIdentity, selectV(&ring, policy, &.{id}, &.{fx.binder}, &fx.empty_hash, &fx.ch_hash, 1_000 + max_ticket_lifetime_ms + 1, null, null, &scratch));
}

test "selectPsk: the filter sees the engine's tail and the age; refusing skips without a binder check" {
    var ring = stek.DefaultRing.init();
    ring.rotate(1, &(@as([stek.key_length]u8, @splat(0x42))), 0);
    const rms = @as([32]u8, @splat(0x5A));
    const nonce = [_]u8{ 0, 1 };
    const state = SessionState(32){ .resumption_master_secret = rms, .ticket_nonce = &nonce, .issued_at_ms = 2_000, .ticket_age_add = 9 };
    var pt: [128]u8 = undefined;
    const prefix = try state.serialize(&pt);
    pt[prefix.len] = 0x13;
    pt[prefix.len + 1] = 0x02;
    var blob: [160]u8 = undefined;
    const ticket = try ring.seal(pt[0 .. prefix.len + 2], @as([stek.nonce_length]u8, @splat(3)), &blob);
    const empty_hash = sha256Of("");
    const ch_hash = sha256Of("filter test ClientHello");
    const binder = clientBinder(&rms, &nonce, &empty_hash, &ch_hash);
    const id = OfferedIdentity{ .ticket = ticket, .obfuscated_ticket_age = 0 };

    const F = struct {
        want: [2]u8,
        seen_tail: [8]u8 = undefined,
        seen_len: usize = 0,
        seen_age: i64 = -1,
        fn accept(ctx: ?*anyopaque, tail: []const u8, age_ms: i64) bool {
            const f: *@This() = @ptrCast(@alignCast(ctx.?));
            @memcpy(f.seen_tail[0..tail.len], tail);
            f.seen_len = tail.len;
            f.seen_age = age_ms;
            return std.mem.eql(u8, tail, &f.want);
        }
    };
    var scratch: [128]u8 = undefined;
    var sel: Selection(32) = undefined;
    var yes: F = .{ .want = .{ 0x13, 0x02 } };
    try selectPsk(HkdfSha256, HmacSha256, stek.DefaultRing, &sel, &ring, .{}, &.{id}, &.{binder}, &empty_hash, &ch_hash, 7_000, null, null, .{ .ctx = &yes, .accept = F.accept }, &scratch);
    try testing.expectEqualSlices(u8, &.{ 0x13, 0x02 }, yes.seen_tail[0..yes.seen_len]);
    try testing.expectEqual(@as(i64, 5_000), yes.seen_age);
    // Refused by the filter: a forged binder is not even looked at.
    var no: F = .{ .want = .{ 0x13, 0x01 } };
    var bad = binder;
    bad[0] ^= 1;
    try testing.expectError(error.NoAcceptableIdentity, selectPsk(HkdfSha256, HmacSha256, stek.DefaultRing, &sel, &ring, .{}, &.{id}, &.{bad}, &empty_hash, &ch_hash, 7_000, null, null, .{ .ctx = &no, .accept = F.accept }, &scratch));
    try testing.expect(no.seen_len == 2);
}
