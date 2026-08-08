// SPDX-License-Identifier: MIT
//! tenantkex — per-tenant Noise_IK session establishment for the L2VPN fabric.
//!
//! Two provider edges (PEs) that already share the encrypted WireGuard
//! backbone run, PER TENANT, an independent authenticated Noise_IK handshake
//! and derive two directional 32-byte transport keys. Those keys seed a pair
//! of `aeadframe` channels (one per direction), giving each tenant its own
//! cryptographically isolated record layer end-to-end (a compliance
//! requirement: a transcript for tenant A can never be accepted as tenant B).
//!
//! This module is a thin, allocation-light DRIVER over the generic `noise`
//! module — it reimplements NO crypto. It wraps `noise.DefaultSuite`'s
//! `HandshakeState` (`Noise_IK_25519_ChaChaPoly_SHA256`), binds the tenant's
//! I-SID and the two PE ids into the Noise PROLOGUE, and hands back
//! `{ send_key, recv_key, transcript_hash }`. The caller carries the two
//! handshake messages over the WG tunnel; timeouts/retransmission are the
//! transport's job.
//!
//! IK = the initiator already knows the responder's static public key
//! (realistic on a provisioned provider fabric — the orchestrator distributes
//! PE static keys). Two-message flow:
//!
//!   initiator --msg1(e, es, s, ss)-->  responder
//!   initiator <--msg2(e, ee, se)----   responder
//!   both split() -> two directional transport keys
//!
//! Key ORIENTATION (the classic footgun — pinned by a permanent test): Noise
//! `split()` yields `pair[0]` = initiator->responder and `pair[1]` =
//! responder->initiator. Therefore
//!   * initiator: send_key = pair[0].k, recv_key = pair[1].k
//!   * responder: send_key = pair[1].k, recv_key = pair[0].k
//! so `initiator.send_key == responder.recv_key` and vice versa. Feed
//! `send_key` to that side's `aeadframe` Sealer and `recv_key` to its Opener.
//!
//! Deferred (see SPEC.md): XX fallback (responder static unknown), PSK modes
//! (IKpsk2), rekey/rehandshake scheduling (aeadframe's epoch handles in-session
//! rekey; a fresh handshake is simply a new session), handshake-message
//! retransmission/timeout, and identity-hiding hardening (moot here — the whole
//! handshake already rides an authenticated, encrypted WG tunnel).
//!
//! Provenance: clean-room composition; the cryptography lives entirely in the
//! `noise` module (see its own provenance / NOTICE). No third-party source
//! ported here; the design mirrors WireGuard's own Noise_IK usage pattern.

const std = @import("std");
const noise = @import("noise");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner, // one Initiator/Responder = one session's state
    .model_after = "Noise_IK (WireGuard-style) session establishment over the `noise` module, I-SID-bound prologue; keys feed `aeadframe`",
    .deps = .{"noise"},
};

/// The bound Noise suite: `Noise_IK_25519_ChaChaPoly_SHA256`.
const Suite = noise.DefaultSuite;
const HS = Suite.HandshakeState;

/// An X25519 static (or ephemeral) keypair — re-exported from `noise`'s suite
/// so callers need not reach into `noise` for the type.
pub const KeyPair = Suite.KeyPair;
/// A 32-byte X25519 public key (a peer's static key, distributed out of band).
pub const PublicKey = [Suite.DHLEN]u8;

/// Domain-separation label mixed into the prologue ahead of the fabric
/// context. Versioned so a future wire change is a different transcript.
pub const prologue_label = "tenantkex/v1 Noise_IK_25519_ChaChaPoly_SHA256";

/// The fabric context bound into the Noise prologue. Both PEs MUST agree on
/// every field or the handshake's first encrypted token fails its AEAD tag —
/// which is exactly what scopes a completed session to one tenant.
///
/// Bound (in this order): `prologue_label` || I-SID (u24, big-endian) ||
/// initiator PE id (u32, big-endian) || responder PE id (u32, big-endian).
pub const FabricContext = struct {
    /// Tenant service identifier (matches l2encap/l2forward's I-SID width).
    isid: u24,
    /// The initiating PE's fabric id.
    initiator_pe: u32,
    /// The responding PE's fabric id.
    responder_pe: u32,

    /// Serialized prologue length in bytes.
    pub const prologue_len = prologue_label.len + 3 + 4 + 4;

    /// Serialize the prologue into `buf`. Deterministic and fixed-width; the
    /// same `FabricContext` on both sides yields identical bytes.
    pub fn writePrologue(self: FabricContext, buf: *[prologue_len]u8) void {
        @memcpy(buf[0..prologue_label.len], prologue_label);
        var o: usize = prologue_label.len;
        std.mem.writeInt(u24, buf[o..][0..3], self.isid, .big);
        o += 3;
        std.mem.writeInt(u32, buf[o..][0..4], self.initiator_pe, .big);
        o += 4;
        std.mem.writeInt(u32, buf[o..][0..4], self.responder_pe, .big);
    }
};

/// The two directional transport keys plus the transcript hash, produced once
/// a handshake completes. `send_key`/`recv_key` are ready to seed this side's
/// `aeadframe` Sealer/Opener respectively (both are plain
/// ChaCha20-Poly1305/AES-256-GCM 32-byte keys). `transcript_hash` is Noise's
/// channel-binding value — a stable 32-byte session/context id, safe to expose
/// (usable e.g. as an `aeadframe` `aad` or a log correlation id).
pub const SessionKeys = struct {
    send_key: [32]u8,
    recv_key: [32]u8,
    transcript_hash: [32]u8,

    /// Best-effort wipe of the two secret keys (the transcript hash is not
    /// secret and is left intact).
    pub fn wipe(self: *SessionKeys) void {
        std.crypto.secureZero(u8, &self.send_key);
        std.crypto.secureZero(u8, &self.recv_key);
    }
};

/// Result of the initiator consuming msg2: the decrypted responder payload
/// length plus the derived session keys.
pub const InitiatorFinish = struct { payload_len: usize, keys: SessionKeys };
/// Result of the responder producing msg2: the msg2 wire length plus the
/// derived session keys.
pub const ResponderFinish = struct { len: usize, keys: SessionKeys };

/// Errors emitting a handshake message: `noise`'s write errors plus a
/// state-machine guard, plus `HandshakeNotComplete` (see `ReadError`) --
/// `writeMessage2` needs `Split()`'s transport pair exactly as `readMessage2`
/// does.
pub const WriteError = HS.WriteError || error{ WrongState, HandshakeNotComplete, UnexpectedHandshakeCompletion };
/// Errors consuming a handshake message: `noise`'s read errors (incl.
/// `DecryptionFailed` for a tampered message, a wrong responder static key, or
/// an I-SID/prologue mismatch) plus a state-machine guard.
///
/// `HandshakeNotComplete` guards an invariant that is true for `IK` as
/// currently written -- msg2 is IK's last pattern token, so `Split()` always
/// fires on it -- but is a property of the *pattern table*, not something
/// this module's own state machine enforces. A future `noise` pattern-table
/// change (or this module switching patterns) could turn a
/// currently-correct assumption into `unreachable` triggering in
/// ReleaseFast, which is undefined behavior, not a panic. Typed instead: the
/// `State` guard above already rules out calling `readMessage2`/
/// `writeMessage2` out of order, so this can only fire if `noise` itself
/// changes shape underneath this module.
///
/// `UnexpectedHandshakeCompletion` is `HandshakeNotComplete`'s mirror image,
/// guarding msg1 instead of msg2: IK's msg1 must NOT complete the pattern
/// (`Split()` must not have fired yet), also true only because of IK's
/// current token layout, not enforced by this module's own state machine.
pub const ReadError = HS.ReadError || error{ WrongState, HandshakeNotComplete, UnexpectedHandshakeCompletion };

/// Wire length of msg1 for a cleartext payload of `payload_len` bytes:
/// e(32) + encrypted-s(32+16) + payload(+16).
pub fn message1Len(payload_len: usize) usize {
    return Suite.DHLEN + (Suite.DHLEN + Suite.TAGLEN) + payload_len + Suite.TAGLEN;
}
/// Wire length of msg2 for a cleartext payload of `payload_len` bytes:
/// e(32) + payload(+16).
pub fn message2Len(payload_len: usize) usize {
    return Suite.DHLEN + payload_len + Suite.TAGLEN;
}

fn keysFor(comptime is_initiator: bool, pair: [2]Suite.CipherState, h: [32]u8) SessionKeys {
    // Noise split(): pair[0] = initiator->responder, pair[1] = responder->initiator.
    return if (is_initiator) .{
        .send_key = pair[0].k,
        .recv_key = pair[1].k,
        .transcript_hash = h,
    } else .{
        .send_key = pair[1].k,
        .recv_key = pair[0].k,
        .transcript_hash = h,
    };
}

/// Wipe every secret this module copied into a `noise` handshake state:
/// the static and ephemeral secret keys plus the symmetric chaining/cipher
/// keys. See `Initiator.wipe` for why this layer owns the static-key wipe.
fn wipeHandshake(hs: *HS) void {
    if (hs.s != null) std.crypto.secureZero(u8, &hs.s.?.secret_key);
    if (hs.e != null) std.crypto.secureZero(u8, &hs.e.?.secret_key);
    std.crypto.secureZero(u8, &hs.symmetric_state.ck);
    std.crypto.secureZero(u8, &hs.symmetric_state.cipher_state.k);
    hs.symmetric_state.cipher_state.has_key = false;
}

/// The initiating provider edge. Owns one session's handshake state; drive it
/// exactly once through `writeMessage1` then `readMessage2`.
pub const Initiator = struct {
    hs: HS,
    state: State = .start,

    const State = enum { start, awaiting_msg2, done };

    /// Start an IK handshake. `static_kp` is this PE's static keypair;
    /// `responder_static` is the peer's static public key (provisioned out of
    /// band); `ctx` binds the tenant/PE identity into the prologue.
    pub fn init(static_kp: KeyPair, responder_static: PublicKey, ctx: FabricContext) Initiator {
        return initEphemeral(static_kp, responder_static, ctx, null);
    }

    /// As `init`, but with an explicit ephemeral keypair — a KAT/testing hook
    /// (mirrors `noise`'s own `e` injection). Pass `null` in production so a
    /// fresh ephemeral is drawn from `writeMessage1`'s RNG.
    pub fn initEphemeral(
        static_kp: KeyPair,
        responder_static: PublicKey,
        ctx: FabricContext,
        ephemeral: ?KeyPair,
    ) Initiator {
        var self: Initiator = .{ .hs = .{} };
        var pbuf: [FabricContext.prologue_len]u8 = undefined;
        ctx.writePrologue(&pbuf);
        self.hs.initialize(
            noise.patterns.IK,
            true,
            &pbuf,
            static_kp,
            ephemeral,
            responder_static,
            null,
            &.{},
        );
        return self;
    }

    /// Destroy the private key material this initiator holds — the copy of the
    /// PE's **long-term static** secret key that `initEphemeral` handed to
    /// `noise`, plus the ephemeral secret and the chaining/cipher keys.
    ///
    /// `noise` wipes its own derived material when the handshake splits, but
    /// deliberately leaves `s` alone: from `noise`'s side that is the caller's
    /// key and it cannot know the caller's lifetime. `tenantkex` is the caller
    /// — the copy inside `hs` is ours, so under CONVENTIONS §2.1 Z1 the wipe is
    /// ours to do. Call it once the handshake is done with (the `SessionKeys`
    /// are a separate copy and survive; wipe those with `SessionKeys.wipe`).
    pub fn wipe(self: *Initiator) void {
        wipeHandshake(&self.hs);
    }

    /// Emit msg1 into `out` (needs `message1Len(payload.len)` bytes),
    /// carrying `payload` (may be empty). `random` must be a cryptographically
    /// secure RNG in production (Noise draws the ephemeral from it); it is
    /// unused when an ephemeral was injected via `initEphemeral`.
    pub fn writeMessage1(self: *Initiator, random: std.Random, payload: []const u8, out: []u8) WriteError!usize {
        if (self.state != .start) return error.WrongState;
        const step = try self.hs.writeMessage(random, payload, out);
        if (step.transport != null) return error.UnexpectedHandshakeCompletion; // msg1 never completes IK
        self.state = .awaiting_msg2;
        return step.len;
    }

    /// Consume msg2 from `message`, decrypting any responder payload into
    /// `payload_out`, and derive the session keys. A tampered message, a
    /// responder whose static key differs from `responder_static`, or a
    /// mismatched prologue (different I-SID/PE ids) fails with a typed error
    /// and yields NO keys.
    pub fn readMessage2(self: *Initiator, message: []const u8, payload_out: []u8) ReadError!InitiatorFinish {
        if (self.state != .awaiting_msg2) return error.WrongState;
        const step = try self.hs.readMessage(message, payload_out);
        const pair = step.transport orelse return error.HandshakeNotComplete; // msg2 completes IK
        self.state = .done;
        return .{
            .payload_len = step.len,
            .keys = keysFor(true, pair, self.hs.symmetric_state.getHandshakeHash()),
        };
    }
};

/// The responding provider edge. Drive it exactly once through `readMessage1`
/// then `writeMessage2`.
pub const Responder = struct {
    hs: HS,
    state: State = .start,

    const State = enum { start, awaiting_write2, done };

    /// Start an IK handshake as the responder. `static_kp` is this PE's static
    /// keypair (the initiator already knows its public half). `ctx` MUST match
    /// the initiator's fabric context or msg1 fails to authenticate.
    pub fn init(static_kp: KeyPair, ctx: FabricContext) Responder {
        return initEphemeral(static_kp, ctx, null);
    }

    /// As `init`, with an explicit ephemeral keypair (KAT/testing hook).
    pub fn initEphemeral(static_kp: KeyPair, ctx: FabricContext, ephemeral: ?KeyPair) Responder {
        var self: Responder = .{ .hs = .{} };
        var pbuf: [FabricContext.prologue_len]u8 = undefined;
        ctx.writePrologue(&pbuf);
        self.hs.initialize(
            noise.patterns.IK,
            false,
            &pbuf,
            static_kp,
            ephemeral,
            null, // responder learns the initiator's static from msg1
            null,
            &.{},
        );
        return self;
    }

    /// Destroy the private key material this responder holds — see
    /// `Initiator.wipe` (same rule, same ownership argument).
    pub fn wipe(self: *Responder) void {
        wipeHandshake(&self.hs);
    }

    /// Consume msg1, decrypting any initiator payload into `payload_out` and
    /// capturing the initiator's static + ephemeral keys. Returns the payload
    /// length. A tampered msg1 or a mismatched prologue (wrong tenant) fails
    /// with a typed error and yields no session.
    pub fn readMessage1(self: *Responder, message: []const u8, payload_out: []u8) ReadError!usize {
        if (self.state != .start) return error.WrongState;
        const step = try self.hs.readMessage(message, payload_out);
        if (step.transport != null) return error.UnexpectedHandshakeCompletion; // msg1 never completes IK
        self.state = .awaiting_write2;
        return step.len;
    }

    /// Emit msg2 into `out` (needs `message2Len(payload.len)` bytes) and derive
    /// the session keys. Must be called only after a successful `readMessage1`.
    pub fn writeMessage2(self: *Responder, random: std.Random, payload: []const u8, out: []u8) WriteError!ResponderFinish {
        if (self.state != .awaiting_write2) return error.WrongState;
        const step = try self.hs.writeMessage(random, payload, out);
        const pair = step.transport orelse return error.HandshakeNotComplete; // msg2 completes IK
        self.state = .done;
        return .{
            .len = step.len,
            .keys = keysFor(false, pair, self.hs.symmetric_state.getHandshakeHash()),
        };
    }
};

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

// Fixed static keypairs reused across tests (from noise's own KAT fixtures).
const init_static_priv = hx("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1");
const resp_static_priv = hx("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
const init_eph_priv = hx("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a");
const resp_eph_priv = hx("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b");

fn hx(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn kp(priv: [32]u8) KeyPair {
    return KeyPair.generateDeterministic(priv) catch unreachable;
}

fn testRandom(seed: u64) std.Random.DefaultPrng {
    return std.Random.DefaultPrng.init(seed);
}

const demo_ctx = FabricContext{ .isid = 0xABCDEF, .initiator_pe = 1001, .responder_pe = 2002 };

/// Run a full IK handshake with generated ephemerals and return both sides'
/// derived keys.
fn runHandshake(ctx_i: FabricContext, ctx_r: FabricContext) !struct { i: SessionKeys, r: SessionKeys } {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    var ini = Initiator.init(is, rs.public_key, ctx_i);
    var rsp = Responder.init(rs, ctx_r);

    var prng_i = testRandom(0x1111);
    var prng_r = testRandom(0x2222);

    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var pl: [64]u8 = undefined;

    const n1 = try ini.writeMessage1(prng_i.random(), "hello-r", m1[0..message1Len(7)]);
    try testing.expectEqual(message1Len(7), n1);
    const r1 = try rsp.readMessage1(m1[0..n1], &pl);
    try testing.expectEqualStrings("hello-r", pl[0..r1]);

    const fin_r = try rsp.writeMessage2(prng_r.random(), "hello-i", m2[0..message2Len(7)]);
    try testing.expectEqual(message2Len(7), fin_r.len);
    const fin_i = try ini.readMessage2(m2[0..fin_r.len], &pl);
    try testing.expectEqualStrings("hello-i", pl[0..fin_i.payload_len]);

    return .{ .i = fin_i.keys, .r = fin_r.keys };
}

test "mutual handshake: matching directional keys + equal transcript" {
    const out = try runHandshake(demo_ctx, demo_ctx);
    // The core proof: initiator's send == responder's recv, and vice versa.
    try testing.expectEqualSlices(u8, &out.i.send_key, &out.r.recv_key);
    try testing.expectEqualSlices(u8, &out.i.recv_key, &out.r.send_key);
    try testing.expectEqualSlices(u8, &out.i.transcript_hash, &out.r.transcript_hash);
    // The two directions use distinct keys.
    try testing.expect(!std.mem.eql(u8, &out.i.send_key, &out.i.recv_key));
}

test "composition: keys open in the right orientation via a direct ChaCha20-Poly1305 round-trip" {
    // aeadframe consumes these 32-byte keys as its Sealer/Opener key over the
    // SAME primitive (ChaCha20-Poly1305). We cannot import aeadframe without a
    // build dep, so we prove orientation with a direct AEAD round-trip: a
    // record sealed under the initiator's send_key MUST open under the
    // responder's recv_key (and the reverse), which only holds if the split
    // index -> send/recv mapping is correct.
    const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
    const out = try runHandshake(demo_ctx, demo_ctx);

    inline for (.{
        .{ out.i.send_key, out.r.recv_key, "i->r record" },
        .{ out.r.send_key, out.i.recv_key, "r->i record" },
    }) |dir| {
        const seal_key = dir[0];
        const open_key = dir[1];
        const msg = dir[2];
        var ct: [msg.len]u8 = undefined;
        var tag: [16]u8 = undefined;
        const nonce = [_]u8{0} ** 12;
        const aad = &out.i.transcript_hash; // transcript hash as channel/aad id
        Aead.encrypt(&ct, &tag, msg, aad, nonce, seal_key);
        var pt: [msg.len]u8 = undefined;
        try Aead.decrypt(&pt, &ct, tag, aad, nonce, open_key);
        try testing.expectEqualStrings(msg, &pt);
    }
}

test "I-SID binding: different tenant I-SIDs make the handshake FAIL (tenant isolation)" {
    const a = FabricContext{ .isid = 100, .initiator_pe = 1, .responder_pe = 2 };
    const b = FabricContext{ .isid = 200, .initiator_pe = 1, .responder_pe = 2 };

    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    var ini = Initiator.init(is, rs.public_key, a);
    var rsp = Responder.init(rs, b); // responder thinks it's a DIFFERENT tenant

    var prng = testRandom(0x3333);
    var m1: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try ini.writeMessage1(prng.random(), "x", m1[0..message1Len(1)]);
    // The responder's prologue differs -> msg1's encrypted `s` token fails its
    // AEAD tag. No keys are produced.
    try testing.expectError(error.DecryptionFailed, rsp.readMessage1(m1[0..n1], &pl));
}

test "I-SID binding: matching PE ids too — mismatched PE id also fails" {
    const a = FabricContext{ .isid = 7, .initiator_pe = 10, .responder_pe = 20 };
    const b = FabricContext{ .isid = 7, .initiator_pe = 10, .responder_pe = 999 };
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    var ini = Initiator.init(is, rs.public_key, a);
    var rsp = Responder.init(rs, b);
    var prng = testRandom(0x4444);
    var m1: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try ini.writeMessage1(prng.random(), "", m1[0..message1Len(0)]);
    try testing.expectError(error.DecryptionFailed, rsp.readMessage1(m1[0..n1], &pl));
}

test "positive control: WITHOUT the I-SID in the prologue, different tenants WRONGLY interoperate" {
    // Deliberately drop the I-SID (and PE ids) from the prologue: bind only the
    // static label. Now two DIFFERENT tenants complete a handshake — proving it
    // is the FabricContext binding above, and nothing else, that enforces
    // tenant scoping. If this test ever failed, the isolation would be coming
    // from somewhere unaudited.
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);

    var ini: HS = .{};
    var rsp: HS = .{};
    // Identical prologue on both sides, carrying NO tenant identity.
    const weak_prologue = prologue_label;
    ini.initialize(noise.patterns.IK, true, weak_prologue, is, kp(init_eph_priv), rs.public_key, null, &.{});
    rsp.initialize(noise.patterns.IK, false, weak_prologue, rs, kp(resp_eph_priv), null, null, &.{});

    var no_rng = testRandom(0);
    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const w1 = try ini.writeMessage(no_rng.random(), "", &m1);
    _ = try rsp.readMessage(m1[0..w1.len], &pl);
    const w2 = try rsp.writeMessage(no_rng.random(), "", &m2);
    const r2 = try ini.readMessage(m2[0..w2.len], &pl);
    // Handshake completed despite the two ends conceptually being different
    // tenants: with no I-SID bound, nothing distinguishes them.
    try testing.expect(r2.transport != null);
}

test "auth failure: tampered msg1 byte -> typed error, no keys" {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    var ini = Initiator.init(is, rs.public_key, demo_ctx);
    var rsp = Responder.init(rs, demo_ctx);
    var prng = testRandom(0x5555);
    var m1: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try ini.writeMessage1(prng.random(), "data", m1[0..message1Len(4)]);
    m1[n1 - 1] ^= 0x01; // flip a payload/tag byte
    try testing.expectError(error.DecryptionFailed, rsp.readMessage1(m1[0..n1], &pl));
}

test "auth failure: wrong responder static key -> handshake fails" {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    // Initiator expects a DIFFERENT responder static key than the responder holds.
    const wrong_pub = kp(init_static_priv).public_key;
    var ini = Initiator.init(is, wrong_pub, demo_ctx);
    var rsp = Responder.init(rs, demo_ctx);
    var prng = testRandom(0x6666);
    var m1: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try ini.writeMessage1(prng.random(), "", m1[0..message1Len(0)]);
    // The `es`/`ss` DH mixes the wrong static -> divergent h -> `s` token tag fails.
    try testing.expectError(error.DecryptionFailed, rsp.readMessage1(m1[0..n1], &pl));
}

test "KAT (noise as oracle): tenantkex == raw Noise_IK over the bound prologue, byte-exact" {
    // tenantkex adds exactly one thing to noise IK: the prologue. Anchor that
    // by driving raw noise.HandshakeState with the SAME injected ephemerals and
    // tenantkex's computed prologue, and asserting the wire bytes + keys are
    // identical to tenantkex's. noise itself is the (independently KAT-anchored)
    // oracle; this pins the prologue construction and the split->key mapping.
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    const ie = kp(init_eph_priv);
    const re = kp(resp_eph_priv);

    // --- reference: raw noise with an explicit prologue ---
    var pbuf: [FabricContext.prologue_len]u8 = undefined;
    demo_ctx.writePrologue(&pbuf);
    var rini: HS = .{};
    var rrsp: HS = .{};
    rini.initialize(noise.patterns.IK, true, &pbuf, is, ie, rs.public_key, null, &.{});
    rrsp.initialize(noise.patterns.IK, false, &pbuf, rs, re, null, null, &.{});
    var no_rng = testRandom(0);
    var ref_m1: [256]u8 = undefined;
    var ref_m2: [256]u8 = undefined;
    var ref_pl: [64]u8 = undefined;
    const rw1 = try rini.writeMessage(no_rng.random(), "p1", &ref_m1);
    _ = try rrsp.readMessage(ref_m1[0..rw1.len], &ref_pl);
    const rw2 = try rrsp.writeMessage(no_rng.random(), "p2", &ref_m2);
    const rr2 = try rini.readMessage(ref_m2[0..rw2.len], &ref_pl);
    const ref_pair = rr2.transport.?;

    // --- tenantkex with the same injected ephemerals ---
    var ini = Initiator.initEphemeral(is, rs.public_key, demo_ctx, ie);
    var rsp = Responder.initEphemeral(rs, demo_ctx, re);
    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try ini.writeMessage1(no_rng.random(), "p1", m1[0..message1Len(2)]);
    _ = try rsp.readMessage1(m1[0..n1], &pl);
    const fin_r = try rsp.writeMessage2(no_rng.random(), "p2", m2[0..message2Len(2)]);
    const fin_i = try ini.readMessage2(m2[0..fin_r.len], &pl);

    // Byte-exact wire equivalence with raw noise.
    try testing.expectEqualSlices(u8, ref_m1[0..rw1.len], m1[0..n1]);
    try testing.expectEqualSlices(u8, ref_m2[0..rw2.len], m2[0..fin_r.len]);
    // Key/orientation equivalence: pair[0]=i->r is the initiator's send key.
    try testing.expectEqualSlices(u8, &ref_pair[0].k, &fin_i.keys.send_key);
    try testing.expectEqualSlices(u8, &ref_pair[1].k, &fin_i.keys.recv_key);
    try testing.expectEqualSlices(u8, &ref_pair[1].k, &fin_r.keys.send_key);
    try testing.expectEqualSlices(u8, &ref_pair[0].k, &fin_r.keys.recv_key);

    // F1: transcript_hash pinned against raw noise's own handshake hash --
    // this KAT compared the wire bytes and both transport keys but never
    // the hash `keysFor` also derives from `self.hs.symmetric_state`.
    const ref_hash = rrsp.symmetric_state.getHandshakeHash();
    try testing.expectEqualSlices(u8, &ref_hash, &fin_i.keys.transcript_hash);
    try testing.expectEqualSlices(u8, &ref_hash, &fin_r.keys.transcript_hash);
}

test "F1: transcript_hash differs between two tenants that otherwise complete identically" {
    // The only prior assertions on transcript_hash were "initiator's equals
    // responder's" and "wipe leaves it intact" -- both trivially true even
    // for a fixed constant. Complete two full, otherwise-identical
    // handshakes that differ ONLY in FabricContext.isid (so both succeed --
    // this is not the "different I-SIDs fail" isolation test, it is two
    // SEPARATE tenants each with their own consistent context) and confirm
    // their resulting transcript hashes are distinct: a constant would
    // silently collapse this channel-binding value across every tenant.
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    const ctx_a = FabricContext{ .isid = 0x0A0A0A, .initiator_pe = 1, .responder_pe = 2 };
    const ctx_b = FabricContext{ .isid = 0x0B0B0B, .initiator_pe = 1, .responder_pe = 2 };

    const Run = struct {
        fn go(is_: KeyPair, rs_: KeyPair, ctx: FabricContext, seed: u64) !SessionKeys {
            var ini = Initiator.init(is_, rs_.public_key, ctx);
            var rsp = Responder.init(rs_, ctx);
            var prng = testRandom(seed);
            var m1: [256]u8 = undefined;
            var m2: [256]u8 = undefined;
            var pl: [64]u8 = undefined;
            const n1 = try ini.writeMessage1(prng.random(), "", m1[0..message1Len(0)]);
            _ = try rsp.readMessage1(m1[0..n1], &pl);
            const fin_r = try rsp.writeMessage2(prng.random(), "", m2[0..message2Len(0)]);
            const fin_i = try ini.readMessage2(m2[0..fin_r.len], &pl);
            try testing.expectEqualSlices(u8, &fin_i.keys.transcript_hash, &fin_r.keys.transcript_hash);
            return fin_i.keys;
        }
    };
    const keys_a = try Run.go(is, rs, ctx_a, 0x1010);
    const keys_b = try Run.go(is, rs, ctx_b, 0x1010); // same seed: only isid differs
    try testing.expect(!std.mem.eql(u8, &keys_a.transcript_hash, &keys_b.transcript_hash));
}

test "state machine: out-of-order calls are rejected with WrongState" {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    var ini = Initiator.init(is, rs.public_key, demo_ctx);
    var rsp = Responder.init(rs, demo_ctx);
    var prng = testRandom(0x7777);
    var buf: [256]u8 = undefined;
    var pl: [64]u8 = undefined;

    // Initiator cannot read msg2 before sending msg1.
    try testing.expectError(error.WrongState, ini.readMessage2(&buf, &pl));
    // Responder cannot write msg2 before reading msg1.
    try testing.expectError(error.WrongState, rsp.writeMessage2(prng.random(), "", &buf));

    const n1 = try ini.writeMessage1(prng.random(), "", buf[0..message1Len(0)]);
    // Initiator cannot send msg1 twice.
    try testing.expectError(error.WrongState, ini.writeMessage1(prng.random(), "", &buf));
    _ = try rsp.readMessage1(buf[0..n1], &pl);
    // Responder cannot read msg1 twice.
    try testing.expectError(error.WrongState, rsp.readMessage1(buf[0..n1], &pl));
}

test "prologue: fixed-width layout is deterministic and I-SID big-endian" {
    var buf: [FabricContext.prologue_len]u8 = undefined;
    (FabricContext{ .isid = 0x010203, .initiator_pe = 0x04050607, .responder_pe = 0x08090a0b }).writePrologue(&buf);
    try testing.expectEqualStrings(prologue_label, buf[0..prologue_label.len]);
    const tail = buf[prologue_label.len..];
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b }, tail);
}

test "message length helpers match the actual wire sizes" {
    const out = try runHandshake(demo_ctx, demo_ctx);
    _ = out;
    try testing.expectEqual(@as(usize, 96), message1Len(0));
    try testing.expectEqual(@as(usize, 48), message2Len(0));
}

test "SessionKeys.wipe zeroizes both secret keys but leaves the transcript hash intact" {
    const out = try runHandshake(demo_ctx, demo_ctx);
    var keys = out.i;
    const zero = [_]u8{0} ** 32;
    try testing.expect(!std.mem.eql(u8, &keys.send_key, &zero));
    try testing.expect(!std.mem.eql(u8, &keys.recv_key, &zero));
    const saved_transcript = keys.transcript_hash;

    keys.wipe();
    try testing.expectEqualSlices(u8, &zero, &keys.send_key);
    try testing.expectEqualSlices(u8, &zero, &keys.recv_key);
    // The transcript hash is not secret — wipe must not touch it.
    try testing.expectEqualSlices(u8, &saved_transcript, &keys.transcript_hash);
}

test "meta.deps is exactly {noise}" {
    try testing.expectEqual(@as(usize, 1), meta.deps.len);
    try testing.expectEqualStrings("noise", meta.deps[0]);
}

test "Initiator/Responder.wipe destroys the copied long-term static secret key" {
    const i_kp = kp(init_static_priv);
    const r_kp = kp(resp_static_priv);

    var ini = Initiator.init(i_kp, r_kp.public_key, demo_ctx);
    var res = Responder.init(r_kp, demo_ctx);

    // Drive a full handshake, so both sides hold live material when wiped —
    // this is the state a real caller finishes in.
    var prng_i = testRandom(0x3333);
    var prng_r = testRandom(0x4444);
    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try ini.writeMessage1(prng_i.random(), "hi", m1[0..message1Len(2)]);
    _ = try res.readMessage1(m1[0..n1], &pl);
    const fin_r = try res.writeMessage2(prng_r.random(), "hi", m2[0..message2Len(2)]);
    _ = try ini.readMessage2(m2[0..fin_r.len], &pl);

    // Preconditions: `noise`'s own split-time wipe leaves `s` alone, so the
    // caller's long-term secret is still sitting in both structs right now.
    // Without these the assertions below could pass vacuously.
    try testing.expectEqualSlices(u8, &i_kp.secret_key, &ini.hs.s.?.secret_key);
    try testing.expectEqualSlices(u8, &r_kp.secret_key, &res.hs.s.?.secret_key);

    ini.wipe();
    res.wipe();

    const zero = [_]u8{0} ** 32;
    try testing.expectEqualSlices(u8, &zero, &ini.hs.s.?.secret_key);
    try testing.expectEqualSlices(u8, &zero, &res.hs.s.?.secret_key);
    // The caller's own copy is untouched — we only own the copy inside `hs`.
    try testing.expectEqualSlices(u8, &init_static_priv, &i_kp.secret_key);
}

// ── fuzz: readMessage1 / readMessage2 over arbitrary wire bytes ──────────
//
// F3: the module had no fuzz harness and was absent from every repo-wide
// sweep, despite these two entry points taking raw attacker-supplied wire
// bytes. `noise` itself is fuzzed and covers the actual parsing; what
// tenantkex adds on top is a state-enum check and the split->key mapping,
// neither of which parses — so this is a thin harness by design, not an
// attempt to duplicate `noise`'s own coverage.

fn fuzzReadMessage1(_: void, smith: *std.testing.Smith) !void {
    var msg: [256]u8 = undefined;
    smith.bytes(&msg);
    const len: usize = smith.valueRangeAtMost(u16, 0, msg.len);

    var rsp = Responder.init(kp(resp_static_priv), demo_ctx);
    var payload_out: [256]u8 = undefined;
    // Arbitrary bytes must only ever yield a typed error (short message /
    // bad auth tag) or a successful decode, never a panic or OOB write.
    _ = rsp.readMessage1(msg[0..len], &payload_out) catch return;
}

test "fuzz: Responder.readMessage1 never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzReadMessage1, .{});
}

fn fuzzReadMessage2(_: void, smith: *std.testing.Smith) !void {
    var msg: [256]u8 = undefined;
    smith.bytes(&msg);
    const len: usize = smith.valueRangeAtMost(u16, 0, msg.len);

    // A real Initiator that has genuinely sent msg1, so readMessage2 is
    // reached in the state where it actually does work (WrongState from
    // `.start` would make this a no-op fuzz target).
    var ini = Initiator.init(kp(init_static_priv), kp(resp_static_priv).public_key, demo_ctx);
    var prng = testRandom(0x9999);
    var m1: [256]u8 = undefined;
    _ = ini.writeMessage1(prng.random(), "", m1[0..message1Len(0)]) catch return;

    var payload_out: [256]u8 = undefined;
    _ = ini.readMessage2(msg[0..len], &payload_out) catch return;
}

test "fuzz: Initiator.readMessage2 never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzReadMessage2, .{});
}
