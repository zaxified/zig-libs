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
//! XX mode (`XxInitiator`/`XxResponder`, 2026-11-17): when the initiator has
//! no provisioned responder static key, an explicit three-message `Noise_XX`
//! handshake under its own prologue label — the initiator learns the responder
//! key from msg2 and must check it before msg3; the responder still accepts
//! only the provisioned initiator key. Never entered silently from IK. Opt-in
//! PSK mode: `initPsk` (`Noise_IKpsk2`).
//!
//! Deferred (see SPEC.md): Noise Pipes' `XXfallback` role switch (needs the
//! `fallback` modifier in `noise`), rekey/rehandshake scheduling (aeadframe's
//! epoch handles in-session rekey; a fresh handshake is simply a new session), handshake-message
//! retransmission/timeout, and identity-hiding hardening (moot here — the whole
//! handshake already rides an authenticated, encrypted WG tunnel).
//!
//! Provenance: clean-room composition; the cryptography lives entirely in the
//! `noise` module (see its own provenance / NOTICE). No third-party source
//! ported here; the design mirrors WireGuard's own Noise_IK usage pattern.

const std = @import("std");
const noise = @import("noise");
const burn = @import("burn.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Per-tenant key exchange — a Noise_IK handshake (via `noise`) between provider edges, deriving directional channel keys for `aeadframe`.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
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

/// Prologue label of the opt-in PSK mode (`Noise_IKpsk2`); a distinct transcript
/// from `prologue_label`, so a PSK handshake can never be confused with a plain one.
pub const prologue_label_psk = "tenantkex/v1 Noise_IKpsk2_25519_ChaChaPoly_SHA256";

/// The Noise pattern of the PSK mode: IK with a `psk` token at the end of
/// message 2 (`IKpsk2`, as WireGuard).
const IKpsk2 = noise.patterns.withPsk(noise.patterns.IK, &.{2});

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

    /// Serialized prologue length in bytes in PSK mode.
    pub const prologue_len_psk = prologue_label_psk.len + 3 + 4 + 4;

    /// Serialized prologue length in bytes in XX mode.
    pub const prologue_len_xx = prologue_label_xx.len + 3 + 4 + 4;

    /// As `writePrologue`, with `prologue_label_xx` (the XX mode's transcript).
    pub fn writePrologueXx(self: FabricContext, buf: *[prologue_len_xx]u8) void {
        self.writeBody(prologue_label_xx, buf);
    }

    /// As `writePrologue`, with `prologue_label_psk` (the PSK mode's transcript).
    pub fn writeProloguePsk(self: FabricContext, buf: *[prologue_len_psk]u8) void {
        self.writeBody(prologue_label_psk, buf);
    }

    fn writeBody(self: FabricContext, comptime label: []const u8, buf: *[label.len + 11]u8) void {
        @memcpy(buf[0..label.len], label);
        var o: usize = label.len;
        std.mem.writeInt(u24, buf[o..][0..3], self.isid, .big);
        o += 3;
        std.mem.writeInt(u32, buf[o..][0..4], self.initiator_pe, .big);
        o += 4;
        std.mem.writeInt(u32, buf[o..][0..4], self.responder_pe, .big);
    }

    /// Serialize the prologue into `buf`. Deterministic and fixed-width; the
    /// same `FabricContext` on both sides yields identical bytes.
    pub fn writePrologue(self: FabricContext, buf: *[prologue_len]u8) void {
        self.writeBody(prologue_label, buf);
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
///
/// `UnknownInitiator`: msg1 authenticated, but under an initiator static key
/// other than the one the responder was provisioned with (see
/// `Responder.init`). IK lets ANY holder of the responder's public key build a
/// valid msg1 with a static key of its own choosing; refusing every key but
/// the provisioned one is what authenticates the initiator at all.
pub const ReadError = HS.ReadError || error{ WrongState, HandshakeNotComplete, UnexpectedHandshakeCompletion, UnknownInitiator };

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

/// Fill `out` from `Split()`'s pair. Noise split(): pair[0] = initiator->
/// responder, pair[1] = responder->initiator.
fn fillKeys(comptime is_initiator: bool, pair: *const [2]Suite.CipherState, h: [32]u8, out: *SessionKeys) void {
    out.send_key = if (is_initiator) pair[0].k else pair[1].k;
    out.recv_key = if (is_initiator) pair[1].k else pair[0].k;
    out.transcript_hash = h;
}

/// Wipe every secret this module copied into a `noise` handshake state:
/// the static and ephemeral secret keys plus the symmetric chaining/cipher
/// keys. See `Initiator.wipe` for why this layer owns the static-key wipe.
fn wipeHandshake(hs: *HS, psk: *[32]u8) void {
    std.crypto.secureZero(u8, psk);
    hs.psks = &.{};
    wipeHs(hs);
}

/// `wipeHandshake` without a PSK (the XX mode has none).
fn wipeHs(hs: *HS) void {
    if (hs.s != null) std.crypto.secureZero(u8, &hs.s.?.secret_key);
    if (hs.e != null) std.crypto.secureZero(u8, &hs.e.?.secret_key);
    std.crypto.secureZero(u8, &hs.symmetric_state.ck);
    hs.symmetric_state.cipher_state.wipe();
}

/// The initiating provider edge. Owns one session's handshake state; drive it
/// exactly once through `writeMessage1` then `readMessage2`.
pub const Initiator = struct {
    hs: HS,
    state: State = .start,
    /// Private copy of the optional PSK (the `noise` state only borrows a slice);
    /// re-bound to `hs.psks` before every handshake call so a moved struct stays
    /// valid. Wiped by `wipe`.
    psk: [32]u8 = @splat(0),
    use_psk: bool = false,

    const State = enum { start, awaiting_msg2, done };

    /// Start an IK handshake in place. `static_kp` is this PE's static keypair
    /// (by pointer: a by-value key pair is one more copy in the caller's
    /// frame); `responder_static` is the peer's static public key (provisioned
    /// out of band); `ctx` binds the tenant/PE identity into the prologue.
    pub fn init(self: *Initiator, static_kp: *const KeyPair, responder_static: PublicKey, ctx: FabricContext) void {
        self.initEphemeral(static_kp, responder_static, ctx, null);
    }

    /// As `init`, but with an explicit ephemeral keypair — a KAT/testing hook
    /// (mirrors `noise`'s own `e` injection). Pass `null` in production so a
    /// fresh ephemeral is drawn from `writeMessage1`'s RNG.
    pub fn initEphemeral(
        self: *Initiator,
        static_kp: *const KeyPair,
        responder_static: PublicKey,
        ctx: FabricContext,
        ephemeral: ?*const KeyPair,
    ) void {
        burn.run(burn.hs_burn, void, initiatorInitBody, .{ self, static_kp, responder_static, ctx, ephemeral, null });
    }

    /// Opt-in PSK mode: `Noise_IKpsk2` (the `psk` token ends message 2, as in
    /// WireGuard) with the 32-byte pre-shared secret `psk` — a hedge on top of the
    /// X25519 exchange. Both sides must use the same `psk` AND the PSK mode: a
    /// wrong or missing PSK makes `readMessage2` fail `DecryptionFailed` (a plain-IK
    /// peer already fails the responder's `readMessage1`). `psk` is copied in and
    /// wiped by `wipe`; wipe the caller's copy yourself. Wire lengths equal IK's.
    pub fn initPsk(self: *Initiator, static_kp: *const KeyPair, responder_static: PublicKey, ctx: FabricContext, psk: *const [32]u8) void {
        self.initPskEphemeral(static_kp, responder_static, ctx, psk, null);
    }

    /// As `initPsk`, with an explicit ephemeral keypair (KAT/testing hook).
    pub fn initPskEphemeral(
        self: *Initiator,
        static_kp: *const KeyPair,
        responder_static: PublicKey,
        ctx: FabricContext,
        psk: *const [32]u8,
        ephemeral: ?*const KeyPair,
    ) void {
        burn.run(burn.hs_burn, void, initiatorInitBody, .{ self, static_kp, responder_static, ctx, ephemeral, psk });
    }

    fn initiatorInitBody(
        self: *Initiator,
        static_kp: *const KeyPair,
        responder_static: PublicKey,
        ctx: FabricContext,
        ephemeral: ?*const KeyPair,
        psk: ?*const [32]u8,
    ) void {
        self.* = .{ .hs = .{} };
        if (psk) |k| {
            self.psk = k.*;
            self.use_psk = true;
            var pbuf: [FabricContext.prologue_len_psk]u8 = undefined;
            ctx.writeProloguePsk(&pbuf);
            self.hs.initialize(IKpsk2, true, &pbuf, &.{
                .s = static_kp,
                .e = ephemeral,
                .rs = responder_static,
                .psks = @as(*const [1][32]u8, @ptrCast(&self.psk)),
            });
        } else {
            var pbuf: [FabricContext.prologue_len]u8 = undefined;
            ctx.writePrologue(&pbuf);
            self.hs.initialize(noise.patterns.IK, true, &pbuf, &.{
                .s = static_kp,
                .e = ephemeral,
                .rs = responder_static,
            });
        }
    }

    fn bindPsk(self: *Initiator) void {
        self.hs.psks = if (self.use_psk) @as(*const [1][32]u8, @ptrCast(&self.psk)) else &.{};
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
        wipeHandshake(&self.hs, &self.psk);
    }

    /// Emit msg1 into `out` (needs `message1Len(payload.len)` bytes),
    /// carrying `payload` (may be empty). `random` must be a cryptographically
    /// secure RNG in production (Noise draws the ephemeral from it); it is
    /// unused when an ephemeral was injected via `initEphemeral`.
    pub fn writeMessage1(self: *Initiator, random: std.Random, payload: []const u8, out: []u8) WriteError!usize {
        return burn.run(burn.hs_burn, WriteError!usize, writeMessage1Body, .{ self, random, payload, out });
    }

    fn writeMessage1Body(self: *Initiator, random: std.Random, payload: []const u8, out: []u8) WriteError!usize {
        if (self.state != .start) return error.WrongState;
        self.bindPsk();
        var pair: [2]Suite.CipherState = undefined;
        const step = try self.hs.writeMessage(random, payload, out, &pair);
        if (step.complete) return error.UnexpectedHandshakeCompletion; // msg1 never completes IK
        self.state = .awaiting_msg2;
        return step.len;
    }

    /// Consume msg2 from `message`, decrypting any responder payload into
    /// `payload_out`, and derive the session keys. A tampered message, a
    /// responder whose static key differs from `responder_static`, or a
    /// mismatched prologue (different I-SID/PE ids) fails with a typed error
    /// and yields NO keys. Returns the decrypted payload length; the session
    /// keys are written to `keys` (only on success — an out-parameter, because
    /// keys returned by value inside an error union are a copy in the caller's
    /// dead frame).
    pub fn readMessage2(self: *Initiator, message: []const u8, payload_out: []u8, keys: *SessionKeys) ReadError!usize {
        return burn.run(burn.hs_burn, ReadError!usize, readMessage2Body, .{ self, message, payload_out, keys });
    }

    fn readMessage2Body(self: *Initiator, message: []const u8, payload_out: []u8, keys: *SessionKeys) ReadError!usize {
        if (self.state != .awaiting_msg2) return error.WrongState;
        self.bindPsk();
        var pair: [2]Suite.CipherState = undefined;
        const step = try self.hs.readMessage(message, payload_out, &pair);
        if (!step.complete) return error.HandshakeNotComplete; // msg2 completes IK
        self.state = .done;
        fillKeys(true, &pair, self.hs.symmetric_state.getHandshakeHash(), keys);
        return step.len;
    }
};

/// The responding provider edge. Drive it exactly once through `readMessage1`
/// then `writeMessage2`.
pub const Responder = struct {
    hs: HS,
    /// The initiator static public key this responder accepts — the
    /// provisioned key of `ctx.initiator_pe`.
    expected_initiator: PublicKey,
    state: State = .start,
    /// See `Initiator.psk`.
    psk: [32]u8 = @splat(0),
    use_psk: bool = false,

    const State = enum { start, awaiting_write2, done, failed };

    /// Start an IK handshake as the responder. `static_kp` is this PE's static
    /// keypair (the initiator already knows its public half);
    /// `initiator_static` is the provisioned static public key of the PE named
    /// `ctx.initiator_pe` — the only initiator key `readMessage1` accepts. `ctx`
    /// MUST match the initiator's fabric context or msg1 fails to authenticate.
    ///
    /// ⛔ Until 2026-10-05 the responder took no initiator key and accepted any:
    /// IK's msg1 carries the initiator's static key, and anyone who knows the
    /// responder's public key can build a valid msg1 around a key of their own
    /// (the I-SID and PE ids in the prologue are not secrets). WireGuard, this
    /// module's model, looks the received key up among its configured peers;
    /// with one provisioned peer per PE pair, that is this single key.
    ///
    /// Initializes `self` in place; `static_kp` is passed by pointer (see
    /// `Initiator.init`).
    pub fn init(self: *Responder, static_kp: *const KeyPair, initiator_static: PublicKey, ctx: FabricContext) void {
        self.initEphemeral(static_kp, initiator_static, ctx, null);
    }

    /// As `init`, with an explicit ephemeral keypair (KAT/testing hook).
    pub fn initEphemeral(self: *Responder, static_kp: *const KeyPair, initiator_static: PublicKey, ctx: FabricContext, ephemeral: ?*const KeyPair) void {
        burn.run(burn.hs_burn, void, responderInitBody, .{ self, static_kp, initiator_static, ctx, ephemeral, null });
    }

    /// Opt-in PSK mode (`Noise_IKpsk2`), the responder side of
    /// `Initiator.initPsk`; same contract.
    pub fn initPsk(self: *Responder, static_kp: *const KeyPair, initiator_static: PublicKey, ctx: FabricContext, psk: *const [32]u8) void {
        self.initPskEphemeral(static_kp, initiator_static, ctx, psk, null);
    }

    /// As `initPsk`, with an explicit ephemeral keypair (KAT/testing hook).
    pub fn initPskEphemeral(self: *Responder, static_kp: *const KeyPair, initiator_static: PublicKey, ctx: FabricContext, psk: *const [32]u8, ephemeral: ?*const KeyPair) void {
        burn.run(burn.hs_burn, void, responderInitBody, .{ self, static_kp, initiator_static, ctx, ephemeral, psk });
    }

    fn responderInitBody(self: *Responder, static_kp: *const KeyPair, initiator_static: PublicKey, ctx: FabricContext, ephemeral: ?*const KeyPair, psk: ?*const [32]u8) void {
        self.* = .{ .hs = .{}, .expected_initiator = initiator_static };
        // The responder learns the initiator's static from msg1 (no `rs`).
        if (psk) |k| {
            self.psk = k.*;
            self.use_psk = true;
            var pbuf: [FabricContext.prologue_len_psk]u8 = undefined;
            ctx.writeProloguePsk(&pbuf);
            self.hs.initialize(IKpsk2, false, &pbuf, &.{
                .s = static_kp,
                .e = ephemeral,
                .psks = @as(*const [1][32]u8, @ptrCast(&self.psk)),
            });
        } else {
            var pbuf: [FabricContext.prologue_len]u8 = undefined;
            ctx.writePrologue(&pbuf);
            self.hs.initialize(noise.patterns.IK, false, &pbuf, &.{
                .s = static_kp,
                .e = ephemeral,
            });
        }
    }

    fn bindPsk(self: *Responder) void {
        self.hs.psks = if (self.use_psk) @as(*const [1][32]u8, @ptrCast(&self.psk)) else &.{};
    }

    /// Destroy the private key material this responder holds — see
    /// `Initiator.wipe` (same rule, same ownership argument).
    pub fn wipe(self: *Responder) void {
        wipeHandshake(&self.hs, &self.psk);
    }

    /// Consume msg1, decrypting any initiator payload into `payload_out` and
    /// capturing the initiator's static + ephemeral keys. Returns the payload
    /// length. A tampered msg1 or a mismatched prologue (wrong tenant) fails
    /// with a typed error and yields no session; so does a msg1 under any
    /// initiator static key but `init`'s `initiator_static`
    /// (`UnknownInitiator`) — its payload is zeroed, the handshake state wiped,
    /// and the responder can no longer be driven.
    pub fn readMessage1(self: *Responder, message: []const u8, payload_out: []u8) ReadError!usize {
        return burn.run(burn.hs_burn, ReadError!usize, readMessage1Body, .{ self, message, payload_out });
    }

    fn readMessage1Body(self: *Responder, message: []const u8, payload_out: []u8) ReadError!usize {
        if (self.state != .start) return error.WrongState;
        self.bindPsk();
        var pair: [2]Suite.CipherState = undefined;
        const step = try self.hs.readMessage(message, payload_out, &pair);
        if (step.complete) return error.UnexpectedHandshakeCompletion; // msg1 never completes IK
        const got = self.hs.rs orelse unreachable; // IK's msg1 always carries `s`
        if (!std.crypto.timing_safe.eql(PublicKey, got, self.expected_initiator)) {
            std.crypto.secureZero(u8, payload_out[0..step.len]);
            wipeHandshake(&self.hs, &self.psk);
            self.state = .failed;
            return error.UnknownInitiator;
        }
        self.state = .awaiting_write2;
        return step.len;
    }

    /// Emit msg2 into `out` (needs `message2Len(payload.len)` bytes) and derive
    /// the session keys. Must be called only after a successful `readMessage1`.
    /// Returns the msg2 wire length; the session keys are written to `keys`
    /// (only on success).
    pub fn writeMessage2(self: *Responder, random: std.Random, payload: []const u8, out: []u8, keys: *SessionKeys) WriteError!usize {
        return burn.run(burn.hs_burn, WriteError!usize, writeMessage2Body, .{ self, random, payload, out, keys });
    }

    fn writeMessage2Body(self: *Responder, random: std.Random, payload: []const u8, out: []u8, keys: *SessionKeys) WriteError!usize {
        if (self.state != .awaiting_write2) return error.WrongState;
        self.bindPsk();
        var pair: [2]Suite.CipherState = undefined;
        const step = try self.hs.writeMessage(random, payload, out, &pair);
        if (!step.complete) return error.HandshakeNotComplete; // msg2 completes IK
        self.state = .done;
        fillKeys(false, &pair, self.hs.symmetric_state.getHandshakeHash(), keys);
        return step.len;
    }
};

// ── XX mode: the responder's static key is not provisioned ────────────────

/// Prologue label of the XX mode (`Noise_XX`): a distinct transcript from
/// `prologue_label` and `prologue_label_psk`, so an XX handshake can never be
/// confused with an IK one.
pub const prologue_label_xx = "tenantkex/v1 Noise_XX_25519_ChaChaPoly_SHA256";

/// Wire length of XX msg1 for a payload of `payload_len` bytes: e(32) +
/// payload. ⚠ The msg1 payload travels in CLEAR (no key exists yet).
pub fn xxMessage1Len(payload_len: usize) usize {
    return Suite.DHLEN + payload_len;
}
/// Wire length of XX msg2: e(32) + encrypted-s(32+16) + payload(+16).
pub fn xxMessage2Len(payload_len: usize) usize {
    return Suite.DHLEN + (Suite.DHLEN + Suite.TAGLEN) + payload_len + Suite.TAGLEN;
}
/// Wire length of XX msg3: encrypted-s(32+16) + payload(+16).
pub fn xxMessage3Len(payload_len: usize) usize {
    return (Suite.DHLEN + Suite.TAGLEN) + payload_len + Suite.TAGLEN;
}

/// The initiating PE of an XX handshake: it does NOT know the responder's
/// static key and learns it from msg2. Drive it exactly once through
/// `writeMessage1` → `readMessage2` → `writeMessage3`.
///
/// This is an explicit, separate mode — Noise Pipes' "full handshake"
/// (Noise spec §10.2), not its `XXfallback` role switch: an IK `Initiator`
/// or `Responder` never turns into this type, and an XX message is refused
/// by an IK peer (and the reverse) because the patterns and the prologue
/// labels differ. The caller chooses XX when it has no provisioned
/// responder key, and IK otherwise.
pub const XxInitiator = struct {
    hs: HS,
    state: State = .start,

    const State = enum { start, awaiting_msg2, awaiting_write3, done };

    /// Start an XX handshake in place. `static_kp` is this PE's static
    /// keypair (sent to the responder, encrypted, in msg3); `ctx` binds the
    /// tenant/PE identity into the prologue exactly as in IK.
    pub fn init(self: *XxInitiator, static_kp: *const KeyPair, ctx: FabricContext) void {
        self.initEphemeral(static_kp, ctx, null);
    }

    /// As `init`, with an explicit ephemeral keypair (KAT/testing hook).
    pub fn initEphemeral(self: *XxInitiator, static_kp: *const KeyPair, ctx: FabricContext, ephemeral: ?*const KeyPair) void {
        burn.run(burn.hs_burn, void, initBody, .{ self, static_kp, ctx, ephemeral });
    }

    fn initBody(self: *XxInitiator, static_kp: *const KeyPair, ctx: FabricContext, ephemeral: ?*const KeyPair) void {
        self.* = .{ .hs = .{} };
        var pbuf: [FabricContext.prologue_len_xx]u8 = undefined;
        ctx.writePrologueXx(&pbuf);
        self.hs.initialize(noise.patterns.XX, true, &pbuf, &.{ .s = static_kp, .e = ephemeral });
    }

    /// Destroy the static/ephemeral secrets and the chaining/cipher keys
    /// held in the handshake state (see `Initiator.wipe`). Call it also to
    /// abandon a handshake whose responder key the caller refuses.
    pub fn wipe(self: *XxInitiator) void {
        wipeHs(&self.hs);
    }

    /// Emit msg1 (`-> e`) into `out` (needs `xxMessage1Len(payload.len)`
    /// bytes). ⚠ `payload` is sent in CLEAR — XX's first message has no key;
    /// pass an empty payload unless it is public.
    pub fn writeMessage1(self: *XxInitiator, random: std.Random, payload: []const u8, out: []u8) WriteError!usize {
        return burn.run(burn.hs_burn, WriteError!usize, writeMessage1Body, .{ self, random, payload, out });
    }

    fn writeMessage1Body(self: *XxInitiator, random: std.Random, payload: []const u8, out: []u8) WriteError!usize {
        if (self.state != .start) return error.WrongState;
        var pair: [2]Suite.CipherState = undefined;
        const step = try self.hs.writeMessage(random, payload, out, &pair);
        if (step.complete) return error.UnexpectedHandshakeCompletion; // msg1 never completes XX
        self.state = .awaiting_msg2;
        return step.len;
    }

    /// Consume msg2 (`<- e, ee, s, es`), decrypting the responder's payload
    /// into `payload_out` and its static public key into `responder_static`.
    /// The key is authenticated as the holder of its private half (the `es`
    /// DH), but nothing provisioned vouches for it: CHECK IT against the
    /// caller's trust policy (pin it, look it up, compare a fingerprint
    /// received out of band) BEFORE `writeMessage3`, which reveals this PE's
    /// static key to it; on refusal call `wipe` and drop the handshake.
    /// A tampered msg2 or a mismatched prologue fails `DecryptionFailed`.
    pub fn readMessage2(self: *XxInitiator, message: []const u8, payload_out: []u8, responder_static: *PublicKey) ReadError!usize {
        return burn.run(burn.hs_burn, ReadError!usize, readMessage2Body, .{ self, message, payload_out, responder_static });
    }

    fn readMessage2Body(self: *XxInitiator, message: []const u8, payload_out: []u8, responder_static: *PublicKey) ReadError!usize {
        if (self.state != .awaiting_msg2) return error.WrongState;
        var pair: [2]Suite.CipherState = undefined;
        const step = try self.hs.readMessage(message, payload_out, &pair);
        if (step.complete) return error.UnexpectedHandshakeCompletion; // msg2 never completes XX
        responder_static.* = self.hs.rs orelse unreachable; // XX's msg2 always carries `s`
        self.state = .awaiting_write3;
        return step.len;
    }

    /// Emit msg3 (`-> s, se`) into `out` (needs `xxMessage3Len(payload.len)`
    /// bytes) and derive the session keys into `keys` (only on success).
    /// Returns the msg3 wire length.
    pub fn writeMessage3(self: *XxInitiator, random: std.Random, payload: []const u8, out: []u8, keys: *SessionKeys) WriteError!usize {
        return burn.run(burn.hs_burn, WriteError!usize, writeMessage3Body, .{ self, random, payload, out, keys });
    }

    fn writeMessage3Body(self: *XxInitiator, random: std.Random, payload: []const u8, out: []u8, keys: *SessionKeys) WriteError!usize {
        if (self.state != .awaiting_write3) return error.WrongState;
        var pair: [2]Suite.CipherState = undefined;
        const step = try self.hs.writeMessage(random, payload, out, &pair);
        if (!step.complete) return error.HandshakeNotComplete; // msg3 completes XX
        self.state = .done;
        fillKeys(true, &pair, self.hs.symmetric_state.getHandshakeHash(), keys);
        return step.len;
    }
};

/// The responding PE of an XX handshake: its static key is sent to the
/// initiator (encrypted) in msg2, and it still accepts exactly ONE
/// initiator key — the provisioned key of `ctx.initiator_pe`, as in IK.
/// Drive it exactly once through `readMessage1` → `writeMessage2` →
/// `readMessage3`. See `XxInitiator` for when XX is used.
pub const XxResponder = struct {
    hs: HS,
    /// The initiator static public key this responder accepts.
    expected_initiator: PublicKey,
    state: State = .start,

    const State = enum { start, awaiting_write2, awaiting_msg3, done, failed };

    /// Start an XX handshake as the responder. `initiator_static` is the
    /// provisioned static public key of `ctx.initiator_pe` — the only key
    /// `readMessage3` accepts (`UnknownInitiator` otherwise).
    pub fn init(self: *XxResponder, static_kp: *const KeyPair, initiator_static: PublicKey, ctx: FabricContext) void {
        self.initEphemeral(static_kp, initiator_static, ctx, null);
    }

    /// As `init`, with an explicit ephemeral keypair (KAT/testing hook).
    pub fn initEphemeral(self: *XxResponder, static_kp: *const KeyPair, initiator_static: PublicKey, ctx: FabricContext, ephemeral: ?*const KeyPair) void {
        burn.run(burn.hs_burn, void, initBody, .{ self, static_kp, initiator_static, ctx, ephemeral });
    }

    fn initBody(self: *XxResponder, static_kp: *const KeyPair, initiator_static: PublicKey, ctx: FabricContext, ephemeral: ?*const KeyPair) void {
        self.* = .{ .hs = .{}, .expected_initiator = initiator_static };
        var pbuf: [FabricContext.prologue_len_xx]u8 = undefined;
        ctx.writePrologueXx(&pbuf);
        self.hs.initialize(noise.patterns.XX, false, &pbuf, &.{ .s = static_kp, .e = ephemeral });
    }

    /// See `XxInitiator.wipe`.
    pub fn wipe(self: *XxResponder) void {
        wipeHs(&self.hs);
    }

    /// Consume msg1 (`-> e`), copying its CLEAR payload into `payload_out`.
    /// Nothing in msg1 is authenticated (the prologue is checked from msg2
    /// on); returns the payload length.
    pub fn readMessage1(self: *XxResponder, message: []const u8, payload_out: []u8) ReadError!usize {
        return burn.run(burn.hs_burn, ReadError!usize, readMessage1Body, .{ self, message, payload_out });
    }

    fn readMessage1Body(self: *XxResponder, message: []const u8, payload_out: []u8) ReadError!usize {
        if (self.state != .start) return error.WrongState;
        var pair: [2]Suite.CipherState = undefined;
        const step = try self.hs.readMessage(message, payload_out, &pair);
        if (step.complete) return error.UnexpectedHandshakeCompletion; // msg1 never completes XX
        self.state = .awaiting_write2;
        return step.len;
    }

    /// Emit msg2 (`<- e, ee, s, es`) into `out` (needs
    /// `xxMessage2Len(payload.len)` bytes); returns its wire length.
    pub fn writeMessage2(self: *XxResponder, random: std.Random, payload: []const u8, out: []u8) WriteError!usize {
        return burn.run(burn.hs_burn, WriteError!usize, writeMessage2Body, .{ self, random, payload, out });
    }

    fn writeMessage2Body(self: *XxResponder, random: std.Random, payload: []const u8, out: []u8) WriteError!usize {
        if (self.state != .awaiting_write2) return error.WrongState;
        var pair: [2]Suite.CipherState = undefined;
        const step = try self.hs.writeMessage(random, payload, out, &pair);
        if (step.complete) return error.UnexpectedHandshakeCompletion; // msg2 never completes XX
        self.state = .awaiting_msg3;
        return step.len;
    }

    /// Consume msg3 (`-> s, se`), decrypting the initiator's payload into
    /// `payload_out` and deriving the session keys into `keys`. A msg3 under
    /// any initiator static key but `init`'s `initiator_static` is
    /// `UnknownInitiator`: the payload is zeroed, the handshake wiped, no keys
    /// are written and the responder can no longer be driven. A tampered
    /// msg3 fails `DecryptionFailed`.
    pub fn readMessage3(self: *XxResponder, message: []const u8, payload_out: []u8, keys: *SessionKeys) ReadError!usize {
        return burn.run(burn.hs_burn, ReadError!usize, readMessage3Body, .{ self, message, payload_out, keys });
    }

    fn readMessage3Body(self: *XxResponder, message: []const u8, payload_out: []u8, keys: *SessionKeys) ReadError!usize {
        if (self.state != .awaiting_msg3) return error.WrongState;
        var pair: [2]Suite.CipherState = undefined;
        const step = try self.hs.readMessage(message, payload_out, &pair);
        if (!step.complete) return error.HandshakeNotComplete; // msg3 completes XX
        const got = self.hs.rs orelse unreachable; // XX's msg3 always carries `s`
        if (!std.crypto.timing_safe.eql(PublicKey, got, self.expected_initiator)) {
            std.crypto.secureZero(u8, payload_out[0..step.len]);
            wipeHs(&self.hs);
            self.state = .failed;
            return error.UnknownInitiator;
        }
        self.state = .done;
        fillKeys(false, &pair, self.hs.symmetric_state.getHandshakeHash(), keys);
        return step.len;
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
    return KeyPair.generateDeterministic(priv);
}

fn testRandom(seed: u64) std.Random.DefaultPrng {
    return std.Random.DefaultPrng.init(seed);
}

/// Test-side shapes of the old by-value API (a copy of a test key or of
/// derived test keys in a test frame proves nothing).
const TFinish = struct { payload_len: usize, len: usize, keys: SessionKeys };

fn tIniE(is: KeyPair, rs_pub: PublicKey, ctx: FabricContext, eph: ?KeyPair) Initiator {
    var self: Initiator = undefined;
    self.initEphemeral(&is, rs_pub, ctx, if (eph) |*e| e else null);
    return self;
}
fn tIni(is: KeyPair, rs_pub: PublicKey, ctx: FabricContext) Initiator {
    return tIniE(is, rs_pub, ctx, null);
}
fn tRspE(rs: KeyPair, is_pub: PublicKey, ctx: FabricContext, eph: ?KeyPair) Responder {
    var self: Responder = undefined;
    self.initEphemeral(&rs, is_pub, ctx, if (eph) |*e| e else null);
    return self;
}
fn tRsp(rs: KeyPair, is_pub: PublicKey, ctx: FabricContext) Responder {
    return tRspE(rs, is_pub, ctx, null);
}
fn read2(ini: *Initiator, message: []const u8, payload_out: []u8) ReadError!TFinish {
    var keys: SessionKeys = undefined;
    const n = try ini.readMessage2(message, payload_out, &keys);
    return .{ .payload_len = n, .len = n, .keys = keys };
}
fn write2(rsp: *Responder, random: std.Random, payload: []const u8, out: []u8) WriteError!TFinish {
    var keys: SessionKeys = undefined;
    const n = try rsp.writeMessage2(random, payload, out, &keys);
    return .{ .payload_len = n, .len = n, .keys = keys };
}

const demo_ctx = FabricContext{ .isid = 0xABCDEF, .initiator_pe = 1001, .responder_pe = 2002 };

/// Run a full IK handshake with generated ephemerals and return both sides'
/// derived keys.
fn runHandshake(ctx_i: FabricContext, ctx_r: FabricContext) !struct { i: SessionKeys, r: SessionKeys } {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    var ini = tIni(is, rs.public_key, ctx_i);
    var rsp = tRsp(rs, kp(init_static_priv).public_key, ctx_r);

    var prng_i = testRandom(0x1111);
    var prng_r = testRandom(0x2222);

    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var pl: [64]u8 = undefined;

    const n1 = try ini.writeMessage1(prng_i.random(), "hello-r", m1[0..message1Len(7)]);
    try testing.expectEqual(message1Len(7), n1);
    const r1 = try rsp.readMessage1(m1[0..n1], &pl);
    try testing.expectEqualStrings("hello-r", pl[0..r1]);

    const fin_r = try write2(&rsp, prng_r.random(), "hello-i", m2[0..message2Len(7)]);
    try testing.expectEqual(message2Len(7), fin_r.len);
    const fin_i = try read2(&ini, m2[0..fin_r.len], &pl);
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
        const nonce = @as([12]u8, @splat(0));
        const aad = &out.i.transcript_hash; // transcript hash as channel/aad id
        Aead.encrypt(&ct, &tag, msg, aad, nonce, seal_key);
        var pt: [msg.len]u8 = undefined;
        try Aead.decrypt(&pt, &ct, tag, aad, nonce, open_key);
        try testing.expectEqualStrings(msg, &pt);
    }
}

test "an initiator static key other than the provisioned one is UnknownInitiator, payload zeroed, no session" {
    // Review finding 2026-10-05: the responder took no initiator key at all.
    // IK's msg1 is built by whoever knows the responder's PUBLIC key, around a
    // static key of their own; the I-SID and PE ids are not secrets either.
    // Verified before the fix: this exact exchange completed with matching
    // session keys on both sides.
    const rs = kp(resp_static_priv);
    const attacker = kp(@as([32]u8, @splat(0x77))); // provisioned nowhere
    var ini = tIni(attacker, rs.public_key, demo_ctx);
    var rsp = tRsp(rs, kp(init_static_priv).public_key, demo_ctx);
    var prng = testRandom(0x7777);
    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var pl = @as([64]u8, @splat(0));
    const n1 = try ini.writeMessage1(prng.random(), "sneaky", m1[0..message1Len(6)]);
    try testing.expectError(error.UnknownInitiator, rsp.readMessage1(m1[0..n1], &pl));
    try testing.expectEqualSlices(u8, &(@as([64]u8, @splat(0))), &pl); // the unauthorised payload is gone
    try testing.expectError(error.WrongState, write2(&rsp, prng.random(), "", m2[0..message2Len(0)]));
    try testing.expectError(error.WrongState, rsp.readMessage1(m1[0..n1], &pl));
}

test "I-SID binding: different tenant I-SIDs make the handshake FAIL (tenant isolation)" {
    const a = FabricContext{ .isid = 100, .initiator_pe = 1, .responder_pe = 2 };
    const b = FabricContext{ .isid = 200, .initiator_pe = 1, .responder_pe = 2 };

    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    var ini = tIni(is, rs.public_key, a);
    var rsp = tRsp(rs, kp(init_static_priv).public_key, b); // responder thinks it's a DIFFERENT tenant

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
    var ini = tIni(is, rs.public_key, a);
    var rsp = tRsp(rs, kp(init_static_priv).public_key, b);
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
    const ie = kp(init_eph_priv);
    const re = kp(resp_eph_priv);
    ini.initialize(noise.patterns.IK, true, weak_prologue, &.{ .s = &is, .e = &ie, .rs = rs.public_key });
    rsp.initialize(noise.patterns.IK, false, weak_prologue, &.{ .s = &rs, .e = &re });

    var no_rng = testRandom(0);
    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    var tp: [2]Suite.CipherState = undefined;
    const w1 = try ini.writeMessage(no_rng.random(), "", &m1, &tp);
    _ = try rsp.readMessage(m1[0..w1.len], &pl, &tp);
    const w2 = try rsp.writeMessage(no_rng.random(), "", &m2, &tp);
    const r2 = try ini.readMessage(m2[0..w2.len], &pl, &tp);
    // Handshake completed despite the two ends conceptually being different
    // tenants: with no I-SID bound, nothing distinguishes them.
    try testing.expect(r2.complete);
}

test "auth failure: tampered msg1 byte -> typed error, no keys" {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    var ini = tIni(is, rs.public_key, demo_ctx);
    var rsp = tRsp(rs, kp(init_static_priv).public_key, demo_ctx);
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
    var ini = tIni(is, wrong_pub, demo_ctx);
    var rsp = tRsp(rs, kp(init_static_priv).public_key, demo_ctx);
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
    rini.initialize(noise.patterns.IK, true, &pbuf, &.{ .s = &is, .e = &ie, .rs = rs.public_key });
    rrsp.initialize(noise.patterns.IK, false, &pbuf, &.{ .s = &rs, .e = &re });
    var no_rng = testRandom(0);
    var ref_m1: [256]u8 = undefined;
    var ref_m2: [256]u8 = undefined;
    var ref_pl: [64]u8 = undefined;
    var ref_pair: [2]Suite.CipherState = undefined;
    var ref_scratch: [2]Suite.CipherState = undefined;
    const rw1 = try rini.writeMessage(no_rng.random(), "p1", &ref_m1, &ref_scratch);
    _ = try rrsp.readMessage(ref_m1[0..rw1.len], &ref_pl, &ref_scratch);
    const rw2 = try rrsp.writeMessage(no_rng.random(), "p2", &ref_m2, &ref_scratch);
    _ = try rini.readMessage(ref_m2[0..rw2.len], &ref_pl, &ref_pair);

    // --- tenantkex with the same injected ephemerals ---
    var ini = tIniE(is, rs.public_key, demo_ctx, ie);
    var rsp = tRspE(rs, is.public_key, demo_ctx, re);
    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try ini.writeMessage1(no_rng.random(), "p1", m1[0..message1Len(2)]);
    _ = try rsp.readMessage1(m1[0..n1], &pl);
    const fin_r = try write2(&rsp, no_rng.random(), "p2", m2[0..message2Len(2)]);
    const fin_i = try read2(&ini, m2[0..fin_r.len], &pl);

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
            var ini = tIni(is_, rs_.public_key, ctx);
            var rsp = tRsp(rs_, is_.public_key, ctx);
            var prng = testRandom(seed);
            var m1: [256]u8 = undefined;
            var m2: [256]u8 = undefined;
            var pl: [64]u8 = undefined;
            const n1 = try ini.writeMessage1(prng.random(), "", m1[0..message1Len(0)]);
            _ = try rsp.readMessage1(m1[0..n1], &pl);
            const fin_r = try write2(&rsp, prng.random(), "", m2[0..message2Len(0)]);
            const fin_i = try read2(&ini, m2[0..fin_r.len], &pl);
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
    var ini = tIni(is, rs.public_key, demo_ctx);
    var rsp = tRsp(rs, kp(init_static_priv).public_key, demo_ctx);
    var prng = testRandom(0x7777);
    var buf: [256]u8 = undefined;
    var pl: [64]u8 = undefined;

    // Initiator cannot read msg2 before sending msg1.
    try testing.expectError(error.WrongState, read2(&ini, &buf, &pl));
    // Responder cannot write msg2 before reading msg1.
    try testing.expectError(error.WrongState, write2(&rsp, prng.random(), "", &buf));

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
    const zero = @as([32]u8, @splat(0));
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

    var ini = tIni(i_kp, r_kp.public_key, demo_ctx);
    var res = tRsp(r_kp, i_kp.public_key, demo_ctx);

    // Drive a full handshake, so both sides hold live material when wiped —
    // this is the state a real caller finishes in.
    var prng_i = testRandom(0x3333);
    var prng_r = testRandom(0x4444);
    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try ini.writeMessage1(prng_i.random(), "hi", m1[0..message1Len(2)]);
    _ = try res.readMessage1(m1[0..n1], &pl);
    const fin_r = try write2(&res, prng_r.random(), "hi", m2[0..message2Len(2)]);
    _ = try read2(&ini, m2[0..fin_r.len], &pl);

    // Preconditions: `noise`'s own split-time wipe leaves `s` alone, so the
    // caller's long-term secret is still sitting in both structs right now.
    // Without these the assertions below could pass vacuously.
    try testing.expectEqualSlices(u8, &i_kp.secret_key, &ini.hs.s.?.secret_key);
    try testing.expectEqualSlices(u8, &r_kp.secret_key, &res.hs.s.?.secret_key);

    ini.wipe();
    res.wipe();

    const zero = @as([32]u8, @splat(0));
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

const fuzzseed = @import("testkit").fuzz;

const wire_buf_len = 256;
/// The msg1 the harness's own responder expects: e(32) ‖ encrypted-s(32+16)
/// ‖ payload-tag(16), for an empty payload.
const msg1_len = message1Len(0);
/// e(32) ‖ payload-tag(16), for an empty payload.
const msg2_len = message2Len(0);

/// ⭐ Every seed below is a REFUSAL, and that is not enough on its own — a
/// corpus of refusals only exercises the refusal path. The accepting seed for
/// each target is built at run time by `Msg1Corpus`/`Msg2Corpus` from this
/// module's own writer, driven by the SAME deterministic PRNG the harness
/// uses, which is what makes a genuine handshake message reproducible as a
/// corpus entry at all.
const msg1_static_seeds = [_][]const u8{
    fuzzseed.seed(""), // the empty message: exactly what the collapsed draw ran, for ever
    fuzzseed.seed(&@as([msg1_len - 1]u8, @splat(0))), // one octet short of a well-formed msg1
    fuzzseed.seed(&@as([msg1_len]u8, @splat(0))), // ⭐ the right length, all zeroes: reaches the DH and fails the tag
    fuzzseed.seed(&@as([msg1_len]u8, @splat(0xff))), // the right length, all ones
    fuzzseed.seed(&@as([msg1_len + 1]u8, @splat(0))), // one octet over
    fuzzseed.seed(&@as([wire_buf_len]u8, @splat(0))), // the whole buffer
    fuzzseed.seed(&@as([32]u8, @splat(0))), // just an ephemeral, nothing behind it
};

const msg2_static_seeds = [_][]const u8{
    fuzzseed.seed(""), // the empty message
    fuzzseed.seed(&@as([msg2_len - 1]u8, @splat(0))), // one octet short
    fuzzseed.seed(&@as([msg2_len]u8, @splat(0))), // the right length, all zeroes
    fuzzseed.seed(&@as([msg2_len]u8, @splat(0xff))), // the right length, all ones
    fuzzseed.seed(&@as([msg2_len + 1]u8, @splat(0))), // one octet over
    fuzzseed.seed(&@as([wire_buf_len]u8, @splat(0))), // the whole buffer
};

/// The msg1 an Initiator with the test static keys and `testRandom(0x1111)`
/// actually writes. Deterministic, so it can be a corpus entry.
fn genuineMessage1(out: []u8) []const u8 {
    var ini = tIni(kp(init_static_priv), kp(resp_static_priv).public_key, demo_ctx);
    var prng = testRandom(0x1111);
    const n = ini.writeMessage1(prng.random(), "", out[0..msg1_len]) catch unreachable;
    return out[0..n];
}

/// The msg2 a Responder writes after reading the msg1 that
/// `fuzzReadMessage2`'s own initiator sends — same statics, same
/// `testRandom(0x9999)`, same empty payload. That is what makes it decrypt
/// inside the harness rather than merely look like a message.
fn genuineMessage2(out: []u8) []const u8 {
    var ini = tIni(kp(init_static_priv), kp(resp_static_priv).public_key, demo_ctx);
    var prng_i = testRandom(0x9999);
    var m1: [wire_buf_len]u8 = undefined;
    const n1 = ini.writeMessage1(prng_i.random(), "", m1[0..msg1_len]) catch unreachable;

    var rsp = tRsp(kp(resp_static_priv), kp(init_static_priv).public_key, demo_ctx);
    var payload: [wire_buf_len]u8 = undefined;
    _ = rsp.readMessage1(m1[0..n1], &payload) catch unreachable;

    var prng_r = testRandom(0x2222);
    const fin = write2(&rsp, prng_r.random(), "", out[0..msg2_len]) catch unreachable;
    return out[0..fin.len];
}

/// Static seeds plus the genuine message and the same message with one octet
/// of its authenticated tail flipped — a negative case over a REAL frame
/// rather than over noise, which is the only kind that gets past the DH.
fn Corpus(comptime n_static: usize, comptime frame_len: usize) type {
    return struct {
        const Self = @This();
        frames: [2][frame_len]u8 = undefined,
        stores: [2][4 + frame_len]u8 = undefined,
        seeds: [n_static + 2][]const u8 = undefined,

        fn build(
            self: *Self,
            static: []const []const u8,
            genuine: *const fn ([]u8) []const u8,
        ) []const []const u8 {
            for (static, 0..) |sd, i| self.seeds[i] = sd;
            const g = genuine(&self.frames[0]);
            self.seeds[n_static] = fuzzseed.seedInto(&self.stores[0], g);
            @memcpy(self.frames[1][0..g.len], g);
            self.frames[1][g.len - 1] ^= 0x01; // the last tag octet
            self.seeds[n_static + 1] = fuzzseed.seedInto(&self.stores[1], self.frames[1][0..g.len]);
            return &self.seeds;
        }
    };
}

const Msg1Corpus = Corpus(msg1_static_seeds.len, msg1_len);
const Msg2Corpus = Corpus(msg2_static_seeds.len, msg2_len);

fn fuzzReadMessage1(_: void, smith: *std.testing.Smith) !void {
    var msg: [wire_buf_len]u8 = undefined;
    // ⚠ One `smith.slice`, never `bytes` then a ranged draw. `bytes` consumes
    // `@min(buf.len, in.len)` octets, so the ranged length that followed found
    // fewer than the eight it reads as a little-endian `u64` and returned the
    // range MINIMUM: `len` was 0 for every input this lane can carry, and the
    // responder was handed the empty message on every round. Measured
    // 2026-09-07: 0 of 9 seeds arrived non-empty and 0 handshakes were read
    // before; 8 and 1 after.
    const len: usize = smith.slice(&msg);

    var rsp = tRsp(kp(resp_static_priv), kp(init_static_priv).public_key, demo_ctx);
    var payload_out: [wire_buf_len]u8 = undefined;
    // Arbitrary bytes must only ever yield a typed error (short message /
    // bad auth tag) or a successful decode, never a panic or OOB write.
    _ = rsp.readMessage1(msg[0..len], &payload_out) catch return;
}

test "fuzz: Responder.readMessage1 never panics on arbitrary bytes" {
    var corpus: Msg1Corpus = .{};
    try testing.fuzz({}, fuzzReadMessage1, .{ .corpus = corpus.build(&msg1_static_seeds, genuineMessage1) });
}

fn fuzzReadMessage2(_: void, smith: *std.testing.Smith) !void {
    var msg: [wire_buf_len]u8 = undefined;
    // ⚠ See `fuzzReadMessage1`: `bytes` + a ranged length meant `len` was 0.
    const len: usize = smith.slice(&msg);

    // A real Initiator that has genuinely sent msg1, so readMessage2 is
    // reached in the state where it actually does work (WrongState from
    // `.start` would make this a no-op fuzz target).
    var ini = tIni(kp(init_static_priv), kp(resp_static_priv).public_key, demo_ctx);
    var prng = testRandom(0x9999);
    var m1: [wire_buf_len]u8 = undefined;
    _ = ini.writeMessage1(prng.random(), "", m1[0..msg1_len]) catch return;

    var payload_out: [wire_buf_len]u8 = undefined;
    _ = read2(&ini, msg[0..len], &payload_out) catch return;
}

test "fuzz: Initiator.readMessage2 never panics on arbitrary bytes" {
    var corpus: Msg2Corpus = .{};
    try testing.fuzz({}, fuzzReadMessage2, .{ .corpus = corpus.build(&msg2_static_seeds, genuineMessage2) });
}

test "corpus: both handshake targets read their seeds, and what each accepts is pinned" {
    // ⭐ The number to pin is the ACCEPTED one here, and pinning it at exactly
    // 1 is the point: without the run-time genuine seed the corpus would be
    // refusals only, which exercises one path and calls it coverage. The
    // one-octet-flipped twin of that same message pins the other side — a
    // frame that gets all the way through the DH and then fails the tag.
    var c1: Msg1Corpus = .{};
    const seeds1 = c1.build(&msg1_static_seeds, genuineMessage1);
    var nonempty1: usize = 0;
    var accepted1: usize = 0;
    for (seeds1) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var msg: [wire_buf_len]u8 = undefined;
        const len: usize = smith.slice(&msg);
        if (len != 0) nonempty1 += 1;
        var rsp = tRsp(kp(resp_static_priv), kp(init_static_priv).public_key, demo_ctx);
        var payload_out: [wire_buf_len]u8 = undefined;
        if (rsp.readMessage1(msg[0..len], &payload_out)) |_| accepted1 += 1 else |_| {}
    }

    var c2: Msg2Corpus = .{};
    const seeds2 = c2.build(&msg2_static_seeds, genuineMessage2);
    var nonempty2: usize = 0;
    var accepted2: usize = 0;
    for (seeds2) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var msg: [wire_buf_len]u8 = undefined;
        const len: usize = smith.slice(&msg);
        if (len != 0) nonempty2 += 1;
        var ini = tIni(kp(init_static_priv), kp(resp_static_priv).public_key, demo_ctx);
        var prng = testRandom(0x9999);
        var m1: [wire_buf_len]u8 = undefined;
        _ = try ini.writeMessage1(prng.random(), "", m1[0..msg1_len]);
        var payload_out: [wire_buf_len]u8 = undefined;
        if (read2(&ini, msg[0..len], &payload_out)) |_| accepted2 += 1 else |_| {}
    }

    // One seed in each corpus is deliberately the empty message.
    try testing.expectEqual(seeds1.len - 1, nonempty1);
    try testing.expectEqual(seeds2.len - 1, nonempty2);
    // Measured 2026-09-07. Before the draws were restructured both targets ran
    // the empty message for ever: 0 non-empty, 0 accepted.
    try testing.expectEqual(@as(usize, 1), accepted1);
    try testing.expectEqual(@as(usize, 1), accepted2);
}

// Mutation run 2026-10-05: the wipe test above runs after a COMPLETED
// handshake, where `noise`'s split() has already zeroed the chaining key and
// the ephemeral is spent — so dropping either wipe left it green. A
// handshake abandoned half-way (and the UnknownInitiator refusal) still holds
// both; wipe must clear them there.
test "wipe mid-handshake clears the ephemeral secret and the chaining key" {
    const rs = kp(resp_static_priv);
    var ini = tIni(kp(init_static_priv), rs.public_key, demo_ctx);
    var prng = testRandom(0x8888);
    var m1: [256]u8 = undefined;
    _ = try ini.writeMessage1(prng.random(), "", m1[0..message1Len(0)]);
    try testing.expect(!std.mem.allEqual(u8, &ini.hs.e.?.secret_key, 0));
    try testing.expect(!std.mem.allEqual(u8, &ini.hs.symmetric_state.ck, 0));
    ini.wipe();
    try testing.expect(std.mem.allEqual(u8, &ini.hs.e.?.secret_key, 0));
    try testing.expect(std.mem.allEqual(u8, &ini.hs.symmetric_state.ck, 0));

    // The refusal path wipes too: the responder's chaining key after msg1.
    var ini2 = tIni(kp(@as([32]u8, @splat(0x77))), rs.public_key, demo_ctx);
    var rsp = tRsp(rs, kp(init_static_priv).public_key, demo_ctx);
    const n1 = try ini2.writeMessage1(prng.random(), "", m1[0..message1Len(0)]);
    var pl: [8]u8 = undefined;
    try testing.expectError(error.UnknownInitiator, rsp.readMessage1(m1[0..n1], &pl));
    try testing.expect(std.mem.allEqual(u8, &rsp.hs.symmetric_state.ck, 0));
    try testing.expect(std.mem.allEqual(u8, &rsp.hs.s.?.secret_key, 0));
}

// ── PSK mode (IKpsk2) ──────────────────────────────────────────────────────

const test_psk: [32]u8 = @splat(0x5a);
const other_psk: [32]u8 = blk: {
    var k: [32]u8 = @splat(0x5a);
    k[31] ^= 1;
    break :blk k;
};

const PskMode = union(enum) { none, psk: [32]u8 };

fn startIni(ini: *Initiator, is: KeyPair, rs_pub: PublicKey, mode: PskMode, eph: ?KeyPair) void {
    const e: ?*const KeyPair = if (eph) |*k| k else null;
    switch (mode) {
        .none => ini.initEphemeral(&is, rs_pub, demo_ctx, e),
        .psk => |*k| ini.initPskEphemeral(&is, rs_pub, demo_ctx, k, e),
    }
}
fn startRsp(rsp: *Responder, rs: KeyPair, is_pub: PublicKey, mode: PskMode, eph: ?KeyPair) void {
    const e: ?*const KeyPair = if (eph) |*k| k else null;
    switch (mode) {
        .none => rsp.initEphemeral(&rs, is_pub, demo_ctx, e),
        .psk => |*k| rsp.initPskEphemeral(&rs, is_pub, demo_ctx, k, e),
    }
}

const PskOutcome = union(enum) { ok: struct { i: SessionKeys, r: SessionKeys }, msg1_failed: ReadError, msg2_failed: ReadError };

fn runPsk(mi: PskMode, mr: PskMode) !PskOutcome {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    var ini: Initiator = undefined;
    var rsp: Responder = undefined;
    startIni(&ini, is, rs.public_key, mi, null);
    startRsp(&rsp, rs, is.public_key, mr, null);
    var prng = testRandom(0x9999);
    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try ini.writeMessage1(prng.random(), "a", m1[0..message1Len(1)]);
    const r1 = rsp.readMessage1(m1[0..n1], &pl) catch |e| return .{ .msg1_failed = e };
    _ = r1;
    var rk: SessionKeys = undefined;
    const n2 = try rsp.writeMessage2(prng.random(), "b", m2[0..message2Len(1)], &rk);
    var ik: SessionKeys = undefined;
    _ = ini.readMessage2(m2[0..n2], &pl, &ik) catch |e| return .{ .msg2_failed = e };
    return .{ .ok = .{ .i = ik, .r = rk } };
}

test "PSK mode: matching PSK completes with crossed keys, differing from plain IK" {
    const out = (try runPsk(.{ .psk = test_psk }, .{ .psk = test_psk })).ok;
    try testing.expectEqualSlices(u8, &out.i.send_key, &out.r.recv_key);
    try testing.expectEqualSlices(u8, &out.i.recv_key, &out.r.send_key);
    try testing.expectEqualSlices(u8, &out.i.transcript_hash, &out.r.transcript_hash);
    const plain = try runHandshake(demo_ctx, demo_ctx);
    try testing.expect(!std.mem.eql(u8, &plain.i.send_key, &out.i.send_key));
    // A different PSK gives different (but again matching) keys.
    const o2 = (try runPsk(.{ .psk = other_psk }, .{ .psk = other_psk })).ok;
    try testing.expect(!std.mem.eql(u8, &o2.i.send_key, &out.i.send_key));
    try testing.expectEqualSlices(u8, &o2.i.send_key, &o2.r.recv_key);
}

test "PSK mode: a wrong PSK fails the initiator's msg2 decrypt (psk mixes into msg2)" {
    const o = try runPsk(.{ .psk = test_psk }, .{ .psk = other_psk });
    try testing.expectEqual(ReadError.DecryptionFailed, o.msg2_failed);
    const o2 = try runPsk(.{ .psk = other_psk }, .{ .psk = test_psk });
    try testing.expectEqual(ReadError.DecryptionFailed, o2.msg2_failed);
}

test "PSK mode: PSK on only one side fails (different protocol name and prologue)" {
    const a = try runPsk(.{ .psk = test_psk }, .none);
    try testing.expectEqual(ReadError.DecryptionFailed, a.msg1_failed);
    const b = try runPsk(.none, .{ .psk = test_psk });
    try testing.expectEqual(ReadError.DecryptionFailed, b.msg1_failed);
}

test "PSK mode: an all-zero PSK is a valid PSK, not 'absent'" {
    const zero: [32]u8 = @splat(0);
    const o = (try runPsk(.{ .psk = zero }, .{ .psk = zero })).ok;
    try testing.expectEqualSlices(u8, &o.i.send_key, &o.r.recv_key);
    const plain = try runHandshake(demo_ctx, demo_ctx);
    try testing.expect(!std.mem.eql(u8, &plain.i.send_key, &o.i.send_key));
    const mism = try runPsk(.{ .psk = zero }, .none);
    try testing.expectEqual(ReadError.DecryptionFailed, mism.msg1_failed);
}

test "PSK mode survives moving the handshake structs after init" {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    var ini0: Initiator = undefined;
    var rsp0: Responder = undefined;
    ini0.initPsk(&is, rs.public_key, demo_ctx, &test_psk);
    rsp0.initPsk(&rs, is.public_key, demo_ctx, &test_psk);
    var ini = ini0; // copy: the borrowed noise slice would dangle without re-binding
    var rsp = rsp0;
    ini0.wipe();
    rsp0.wipe();
    var prng = testRandom(0x4242);
    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try ini.writeMessage1(prng.random(), "", m1[0..message1Len(0)]);
    _ = try rsp.readMessage1(m1[0..n1], &pl);
    var rk: SessionKeys = undefined;
    const n2 = try rsp.writeMessage2(prng.random(), "", m2[0..message2Len(0)], &rk);
    var ik: SessionKeys = undefined;
    _ = try ini.readMessage2(m2[0..n2], &pl, &ik);
    try testing.expectEqualSlices(u8, &ik.send_key, &rk.recv_key);
}

test "PSK mode: wipe destroys the PSK copy; unknown initiator still refused" {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    var ini: Initiator = undefined;
    ini.initPsk(&is, rs.public_key, demo_ctx, &test_psk);
    try testing.expect(std.mem.eql(u8, &ini.psk, &test_psk));
    ini.wipe();
    try testing.expectEqualSlices(u8, &(@as([32]u8, @splat(0))), &ini.psk);

    const attacker = kp(@as([32]u8, @splat(0x77)));
    var a: Initiator = undefined;
    a.initPsk(&attacker, rs.public_key, demo_ctx, &test_psk);
    var rsp: Responder = undefined;
    rsp.initPsk(&rs, is.public_key, demo_ctx, &test_psk);
    var prng = testRandom(0x7878);
    var m1: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try a.writeMessage1(prng.random(), "x", m1[0..message1Len(1)]);
    try testing.expectError(error.UnknownInitiator, rsp.readMessage1(m1[0..n1], &pl));
    try testing.expectEqualSlices(u8, &(@as([32]u8, @splat(0))), &rsp.psk);
}

test "KAT (noise as oracle): PSK mode == raw Noise_IKpsk2 over the PSK prologue, byte-exact" {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    const ie = kp(init_eph_priv);
    const re = kp(resp_eph_priv);
    var pbuf: [FabricContext.prologue_len_psk]u8 = undefined;
    demo_ctx.writeProloguePsk(&pbuf);
    const psks = [_][32]u8{test_psk};
    var rini: HS = .{};
    var rrsp: HS = .{};
    rini.initialize(IKpsk2, true, &pbuf, &.{ .s = &is, .e = &ie, .rs = rs.public_key, .psks = &psks });
    rrsp.initialize(IKpsk2, false, &pbuf, &.{ .s = &rs, .e = &re, .psks = &psks });
    var no_rng = testRandom(0);
    var ref_m1: [256]u8 = undefined;
    var ref_m2: [256]u8 = undefined;
    var ref_pl: [64]u8 = undefined;
    var ref_pair: [2]Suite.CipherState = undefined;
    var ref_scratch: [2]Suite.CipherState = undefined;
    const rw1 = try rini.writeMessage(no_rng.random(), "p1", &ref_m1, &ref_scratch);
    _ = try rrsp.readMessage(ref_m1[0..rw1.len], &ref_pl, &ref_scratch);
    const rw2 = try rrsp.writeMessage(no_rng.random(), "p2", &ref_m2, &ref_scratch);
    _ = try rini.readMessage(ref_m2[0..rw2.len], &ref_pl, &ref_pair);

    var ini: Initiator = undefined;
    var rsp: Responder = undefined;
    startIni(&ini, is, rs.public_key, .{ .psk = test_psk }, ie);
    startRsp(&rsp, rs, is.public_key, .{ .psk = test_psk }, re);
    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try ini.writeMessage1(no_rng.random(), "p1", m1[0..message1Len(2)]);
    _ = try rsp.readMessage1(m1[0..n1], &pl);
    const fin_r = try write2(&rsp, no_rng.random(), "p2", m2[0..message2Len(2)]);
    const fin_i = try read2(&ini, m2[0..fin_r.len], &pl);
    try testing.expectEqualSlices(u8, ref_m1[0..rw1.len], m1[0..n1]);
    try testing.expectEqualSlices(u8, ref_m2[0..rw2.len], m2[0..fin_r.len]);
    try testing.expectEqualSlices(u8, &ref_pair[0].k, &fin_i.keys.send_key);
    try testing.expectEqualSlices(u8, &ref_pair[1].k, &fin_r.keys.send_key);
    try testing.expectEqualSlices(u8, &rrsp.symmetric_state.getHandshakeHash(), &fin_i.keys.transcript_hash);
}

// ── XX mode ────────────────────────────────────────────────────────────────

const XxOutcome = union(enum) {
    ok: struct { i: SessionKeys, r: SessionKeys, learned: PublicKey, n: [3]usize },
    msg2_failed: ReadError,
    msg3_failed: ReadError,
};

/// A full XX handshake: initiator `is` (context `ci`) against responder `rs`
/// provisioned with `expected` (context `cr`); payloads "a" / "b" / "c".
fn runXx(is: KeyPair, rs: KeyPair, expected: PublicKey, ci: FabricContext, cr: FabricContext) !XxOutcome {
    var ini: XxInitiator = undefined;
    var rsp: XxResponder = undefined;
    ini.init(&is, ci);
    rsp.init(&rs, expected, cr);
    var prng = testRandom(0xC0DE);
    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var m3: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try ini.writeMessage1(prng.random(), "a", m1[0..xxMessage1Len(1)]);
    try testing.expectEqualStrings("a", pl[0..try rsp.readMessage1(m1[0..n1], &pl)]);
    const n2 = try rsp.writeMessage2(prng.random(), "b", m2[0..xxMessage2Len(1)]);
    var learned: PublicKey = undefined;
    const p2 = ini.readMessage2(m2[0..n2], &pl, &learned) catch |e| return .{ .msg2_failed = e };
    try testing.expectEqualStrings("b", pl[0..p2]);
    var ik: SessionKeys = undefined;
    const n3 = try ini.writeMessage3(prng.random(), "c", m3[0..xxMessage3Len(1)], &ik);
    var rk: SessionKeys = undefined;
    const p3 = rsp.readMessage3(m3[0..n3], &pl, &rk) catch |e| return .{ .msg3_failed = e };
    try testing.expectEqualStrings("c", pl[0..p3]);
    return .{ .ok = .{ .i = ik, .r = rk, .learned = learned, .n = .{ n1, n2, n3 } } };
}

test "XX mode: an initiator without the responder's key completes, learns that key, crossed keys" {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    const out = (try runXx(is, rs, is.public_key, demo_ctx, demo_ctx)).ok;
    try testing.expectEqualSlices(u8, &out.i.send_key, &out.r.recv_key);
    try testing.expectEqualSlices(u8, &out.i.recv_key, &out.r.send_key);
    try testing.expectEqualSlices(u8, &out.i.transcript_hash, &out.r.transcript_hash);
    try testing.expect(!std.mem.eql(u8, &out.i.send_key, &out.i.recv_key));
    try testing.expectEqualSlices(u8, &rs.public_key, &out.learned);
    try testing.expectEqual([3]usize{ 33, 97, 65 }, out.n);
    try testing.expectEqual(@as(usize, 32), xxMessage1Len(0));
    try testing.expectEqual(@as(usize, 96), xxMessage2Len(0));
    try testing.expectEqual(@as(usize, 64), xxMessage3Len(0));
    // A different tenant context gives a different transcript (and keys).
    const other = (try runXx(is, rs, is.public_key, .{ .isid = 1, .initiator_pe = 1001, .responder_pe = 2002 }, .{ .isid = 1, .initiator_pe = 1001, .responder_pe = 2002 })).ok;
    try testing.expect(!std.mem.eql(u8, &other.i.transcript_hash, &out.i.transcript_hash));
    // XX and IK between the same PEs derive different keys.
    const ik = try runHandshake(demo_ctx, demo_ctx);
    try testing.expect(!std.mem.eql(u8, &ik.i.send_key, &out.i.send_key));
}

test "XX mode: the responder key is reported, not trusted — an impostor responder is visible to the caller" {
    // Whoever answers msg1 with a key pair of its own completes msg2; the
    // initiator's only protection is checking `responder_static` before msg3.
    const is = kp(init_static_priv);
    const impostor = kp(@as([32]u8, @splat(0x66)));
    const out = (try runXx(is, impostor, is.public_key, demo_ctx, demo_ctx)).ok;
    try testing.expectEqualSlices(u8, &impostor.public_key, &out.learned);
    try testing.expect(!std.mem.eql(u8, &kp(resp_static_priv).public_key, &out.learned));
}

test "XX mode: an initiator key other than the provisioned one is UnknownInitiator at msg3, payload zeroed, no keys" {
    const rs = kp(resp_static_priv);
    const attacker = kp(@as([32]u8, @splat(0x77)));
    var ini: XxInitiator = undefined;
    var rsp: XxResponder = undefined;
    ini.init(&attacker, demo_ctx);
    rsp.init(&rs, kp(init_static_priv).public_key, demo_ctx);
    var prng = testRandom(0x7171);
    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var m3: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try ini.writeMessage1(prng.random(), "", m1[0..xxMessage1Len(0)]);
    _ = try rsp.readMessage1(m1[0..n1], &pl);
    const n2 = try rsp.writeMessage2(prng.random(), "", m2[0..xxMessage2Len(0)]);
    var learned: PublicKey = undefined;
    _ = try ini.readMessage2(m2[0..n2], &pl, &learned);
    var ik: SessionKeys = undefined;
    const n3 = try ini.writeMessage3(prng.random(), "sneaky", m3[0..xxMessage3Len(6)], &ik);
    var rk: SessionKeys = .{ .send_key = @splat(0xAA), .recv_key = @splat(0xAA), .transcript_hash = @splat(0xAA) };
    @memset(&pl, 0);
    try testing.expectError(error.UnknownInitiator, rsp.readMessage3(m3[0..n3], &pl, &rk));
    try testing.expectEqualSlices(u8, &(@as([64]u8, @splat(0))), &pl);
    try testing.expectEqualSlices(u8, &(@as([32]u8, @splat(0xAA))), &rk.send_key); // no keys written
    try testing.expect(std.mem.allEqual(u8, &rsp.hs.s.?.secret_key, 0)); // wiped
    try testing.expectError(error.WrongState, rsp.readMessage3(m3[0..n3], &pl, &rk));
    try testing.expectError(error.WrongState, rsp.readMessage1(m1[0..n1], &pl));
}

test "XX mode: a different I-SID or PE id fails msg2 (the prologue is bound from msg2 on)" {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    const a = FabricContext{ .isid = 100, .initiator_pe = 1, .responder_pe = 2 };
    const b = FabricContext{ .isid = 200, .initiator_pe = 1, .responder_pe = 2 };
    const c = FabricContext{ .isid = 100, .initiator_pe = 1, .responder_pe = 3 };
    try testing.expectEqual(ReadError.DecryptionFailed, (try runXx(is, rs, is.public_key, a, b)).msg2_failed);
    try testing.expectEqual(ReadError.DecryptionFailed, (try runXx(is, rs, is.public_key, a, c)).msg2_failed);
}

test "XX mode: tampered msg2 and msg3 fail DecryptionFailed and yield no keys" {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    inline for (.{ 2, 3 }) |which| {
        var ini: XxInitiator = undefined;
        var rsp: XxResponder = undefined;
        ini.init(&is, demo_ctx);
        rsp.init(&rs, is.public_key, demo_ctx);
        var prng = testRandom(0x5151);
        var m1: [256]u8 = undefined;
        var m2: [256]u8 = undefined;
        var m3: [256]u8 = undefined;
        var pl: [64]u8 = undefined;
        const n1 = try ini.writeMessage1(prng.random(), "", m1[0..xxMessage1Len(0)]);
        _ = try rsp.readMessage1(m1[0..n1], &pl);
        const n2 = try rsp.writeMessage2(prng.random(), "", m2[0..xxMessage2Len(0)]);
        var learned: PublicKey = undefined;
        if (which == 2) {
            m2[n2 - 1] ^= 1;
            try testing.expectError(error.DecryptionFailed, ini.readMessage2(m2[0..n2], &pl, &learned));
        } else {
            _ = try ini.readMessage2(m2[0..n2], &pl, &learned);
            var ik: SessionKeys = undefined;
            const n3 = try ini.writeMessage3(prng.random(), "", m3[0..xxMessage3Len(0)], &ik);
            m3[5] ^= 1; // inside the encrypted static
            var rk: SessionKeys = undefined;
            try testing.expectError(error.DecryptionFailed, rsp.readMessage3(m3[0..n3], &pl, &rk));
        }
    }
}

test "XX and IK never cross: a provisioned (IK) peer refuses XX messages, an XX peer refuses IK ones" {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    var prng = testRandom(0x1C1C);
    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var pl: [128]u8 = undefined;

    // XX msg1 into an IK responder: too short, and at IK's length (a 64-octet
    // clear payload) the encrypted `s` it expects fails its tag.
    {
        var xi: XxInitiator = undefined;
        xi.init(&is, demo_ctx);
        const n1 = try xi.writeMessage1(prng.random(), "", m1[0..xxMessage1Len(0)]);
        var rsp = tRsp(rs, is.public_key, demo_ctx);
        try testing.expectError(error.MessageTooShort, rsp.readMessage1(m1[0..n1], &pl));
        var xi2: XxInitiator = undefined;
        xi2.init(&is, demo_ctx);
        const filler: [64]u8 = @splat(0x33);
        const n1b = try xi2.writeMessage1(prng.random(), &filler, m1[0..xxMessage1Len(64)]);
        try testing.expectEqual(message1Len(0), n1b);
        var rsp2 = tRsp(rs, is.public_key, demo_ctx);
        try testing.expectError(error.DecryptionFailed, rsp2.readMessage1(m1[0..n1b], &pl));
    }
    // IK msg1 into an XX responder: XX's msg1 is unauthenticated, so it is
    // read as `e` + a clear payload — but the IK initiator then refuses the
    // XX msg2, and the XX responder holds no keys (it waits for a msg3 that
    // never comes).
    {
        var ini = tIni(is, rs.public_key, demo_ctx);
        const n1 = try ini.writeMessage1(prng.random(), "", m1[0..message1Len(0)]);
        var xr: XxResponder = undefined;
        xr.init(&rs, is.public_key, demo_ctx);
        _ = try xr.readMessage1(m1[0..n1], &pl);
        const n2 = try xr.writeMessage2(prng.random(), "", m2[0..xxMessage2Len(0)]);
        var keys: SessionKeys = undefined;
        try testing.expectError(error.DecryptionFailed, ini.readMessage2(m2[0..n2], &pl, &keys));
        try testing.expectEqual(XxResponder.State.awaiting_msg3, xr.state);
    }
    // XX between peers with the right keys but one side on the IK prologue
    // label: the transcript differs, msg2 fails.
    {
        var pbuf: [FabricContext.prologue_len]u8 = undefined;
        demo_ctx.writePrologue(&pbuf);
        var raw: HS = .{};
        raw.initialize(noise.patterns.XX, true, &pbuf, &.{ .s = &is });
        var tp: [2]Suite.CipherState = undefined;
        const w1 = try raw.writeMessage(prng.random(), "", &m1, &tp);
        var xr: XxResponder = undefined;
        xr.init(&rs, is.public_key, demo_ctx);
        _ = try xr.readMessage1(m1[0..w1.len], &pl);
        const n2 = try xr.writeMessage2(prng.random(), "", m2[0..xxMessage2Len(0)]);
        try testing.expectError(error.DecryptionFailed, raw.readMessage(m2[0..n2], &pl, &tp));
    }
    try testing.expect(!std.mem.eql(u8, prologue_label, prologue_label_xx));
    try testing.expect(!std.mem.eql(u8, prologue_label_psk, prologue_label_xx));
}

test "XX mode: out-of-order calls are WrongState" {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    var ini: XxInitiator = undefined;
    var rsp: XxResponder = undefined;
    ini.init(&is, demo_ctx);
    rsp.init(&rs, is.public_key, demo_ctx);
    var prng = testRandom(0x0D0D);
    var buf: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    var keys: SessionKeys = undefined;
    var learned: PublicKey = undefined;
    try testing.expectError(error.WrongState, ini.readMessage2(&buf, &pl, &learned));
    try testing.expectError(error.WrongState, ini.writeMessage3(prng.random(), "", &buf, &keys));
    try testing.expectError(error.WrongState, rsp.writeMessage2(prng.random(), "", &buf));
    try testing.expectError(error.WrongState, rsp.readMessage3(&buf, &pl, &keys));
    const n1 = try ini.writeMessage1(prng.random(), "", buf[0..xxMessage1Len(0)]);
    try testing.expectError(error.WrongState, ini.writeMessage1(prng.random(), "", &buf));
    try testing.expectError(error.WrongState, ini.writeMessage3(prng.random(), "", &buf, &keys));
    _ = try rsp.readMessage1(buf[0..n1], &pl);
    try testing.expectError(error.WrongState, rsp.readMessage1(buf[0..n1], &pl));
    try testing.expectError(error.WrongState, rsp.readMessage3(&buf, &pl, &keys));
    const n2 = try rsp.writeMessage2(prng.random(), "", m2[0..xxMessage2Len(0)]);
    try testing.expectError(error.WrongState, rsp.writeMessage2(prng.random(), "", &buf));
    _ = try ini.readMessage2(m2[0..n2], &pl, &learned);
    try testing.expectError(error.WrongState, ini.readMessage2(m2[0..n2], &pl, &learned));
    var m3: [256]u8 = undefined;
    const n3 = try ini.writeMessage3(prng.random(), "", m3[0..xxMessage3Len(0)], &keys);
    _ = try rsp.readMessage3(m3[0..n3], &pl, &keys);
    // Done: every call on either side is refused by the state machine itself.
    try testing.expectError(error.WrongState, ini.writeMessage1(prng.random(), "", &buf));
    try testing.expectError(error.WrongState, ini.readMessage2(m2[0..n2], &pl, &learned));
    try testing.expectError(error.WrongState, ini.writeMessage3(prng.random(), "", &buf, &keys));
    try testing.expectError(error.WrongState, rsp.readMessage1(buf[0..n1], &pl));
    try testing.expectError(error.WrongState, rsp.writeMessage2(prng.random(), "", &buf));
    try testing.expectError(error.WrongState, rsp.readMessage3(m3[0..n3], &pl, &keys));
}

test "XX mode: wipe clears the static and ephemeral secrets and the chaining key mid-handshake" {
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    var ini: XxInitiator = undefined;
    var rsp: XxResponder = undefined;
    ini.init(&is, demo_ctx);
    rsp.init(&rs, is.public_key, demo_ctx);
    var prng = testRandom(0x0E0E);
    var m1: [256]u8 = undefined;
    var m2: [256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try ini.writeMessage1(prng.random(), "", m1[0..xxMessage1Len(0)]);
    _ = try rsp.readMessage1(m1[0..n1], &pl);
    _ = try rsp.writeMessage2(prng.random(), "", m2[0..xxMessage2Len(0)]);
    // Preconditions, so the checks below cannot pass vacuously.
    try testing.expect(!std.mem.allEqual(u8, &ini.hs.e.?.secret_key, 0));
    try testing.expect(!std.mem.allEqual(u8, &rsp.hs.symmetric_state.ck, 0));
    try testing.expect(rsp.hs.symmetric_state.cipher_state.has_key);
    ini.wipe();
    rsp.wipe();
    for ([_]*HS{ &ini.hs, &rsp.hs }) |hs| {
        try testing.expect(std.mem.allEqual(u8, &hs.s.?.secret_key, 0));
        try testing.expect(std.mem.allEqual(u8, &hs.e.?.secret_key, 0));
        try testing.expect(std.mem.allEqual(u8, &hs.symmetric_state.ck, 0));
        try testing.expect(std.mem.allEqual(u8, &hs.symmetric_state.cipher_state.k, 0));
        try testing.expect(!hs.symmetric_state.cipher_state.has_key);
    }
    try testing.expectEqualSlices(u8, &init_static_priv, &is.secret_key); // the caller's copy is untouched
}

test "XX prologue: label, then the same fixed-width fields as IK" {
    var buf: [FabricContext.prologue_len_xx]u8 = undefined;
    (FabricContext{ .isid = 0x010203, .initiator_pe = 0x04050607, .responder_pe = 0x08090a0b }).writePrologueXx(&buf);
    try testing.expectEqualStrings(prologue_label_xx, buf[0..prologue_label_xx.len]);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b }, buf[prologue_label_xx.len..]);
}

test "KAT (noise as oracle): XX mode == raw Noise_XX over the XX prologue, byte-exact" {
    // As the IK KAT: `noise`'s Noise_XX_25519_ChaChaPoly_SHA256 is itself
    // byte-exact against the official noise-c/cacophony XX vector; the
    // published vector's prologue is not tenantkex's, so its bytes cannot
    // apply here directly.
    const is = kp(init_static_priv);
    const rs = kp(resp_static_priv);
    const ie = kp(init_eph_priv);
    const re = kp(resp_eph_priv);
    var pbuf: [FabricContext.prologue_len_xx]u8 = undefined;
    demo_ctx.writePrologueXx(&pbuf);
    var rini: HS = .{};
    var rrsp: HS = .{};
    rini.initialize(noise.patterns.XX, true, &pbuf, &.{ .s = &is, .e = &ie });
    rrsp.initialize(noise.patterns.XX, false, &pbuf, &.{ .s = &rs, .e = &re });
    var no_rng = testRandom(0);
    var ref: [3][256]u8 = undefined;
    var ref_pl: [64]u8 = undefined;
    var ref_pair: [2]Suite.CipherState = undefined;
    var scratch: [2]Suite.CipherState = undefined;
    const r1 = try rini.writeMessage(no_rng.random(), "p1", &ref[0], &scratch);
    _ = try rrsp.readMessage(ref[0][0..r1.len], &ref_pl, &scratch);
    const r2 = try rrsp.writeMessage(no_rng.random(), "p2", &ref[1], &scratch);
    _ = try rini.readMessage(ref[1][0..r2.len], &ref_pl, &scratch);
    const r3 = try rini.writeMessage(no_rng.random(), "p3", &ref[2], &ref_pair);
    _ = try rrsp.readMessage(ref[2][0..r3.len], &ref_pl, &scratch);

    var ini: XxInitiator = undefined;
    var rsp: XxResponder = undefined;
    ini.initEphemeral(&is, demo_ctx, &ie);
    rsp.initEphemeral(&rs, is.public_key, demo_ctx, &re);
    var m: [3][256]u8 = undefined;
    var pl: [64]u8 = undefined;
    const n1 = try ini.writeMessage1(no_rng.random(), "p1", m[0][0..xxMessage1Len(2)]);
    _ = try rsp.readMessage1(m[0][0..n1], &pl);
    const n2 = try rsp.writeMessage2(no_rng.random(), "p2", m[1][0..xxMessage2Len(2)]);
    var learned: PublicKey = undefined;
    _ = try ini.readMessage2(m[1][0..n2], &pl, &learned);
    var ik: SessionKeys = undefined;
    const n3 = try ini.writeMessage3(no_rng.random(), "p3", m[2][0..xxMessage3Len(2)], &ik);
    var rk: SessionKeys = undefined;
    _ = try rsp.readMessage3(m[2][0..n3], &pl, &rk);

    try testing.expectEqualSlices(u8, ref[0][0..r1.len], m[0][0..n1]);
    try testing.expectEqualSlices(u8, ref[1][0..r2.len], m[1][0..n2]);
    try testing.expectEqualSlices(u8, ref[2][0..r3.len], m[2][0..n3]);
    try testing.expectEqualSlices(u8, &ref_pair[0].k, &ik.send_key);
    try testing.expectEqualSlices(u8, &ref_pair[1].k, &ik.recv_key);
    try testing.expectEqualSlices(u8, &ref_pair[1].k, &rk.send_key);
    try testing.expectEqualSlices(u8, &ref_pair[0].k, &rk.recv_key);
    const h = rrsp.symmetric_state.getHandshakeHash();
    try testing.expectEqualSlices(u8, &h, &ik.transcript_hash);
    try testing.expectEqualSlices(u8, &h, &rk.transcript_hash);
}

test {
    _ = @import("fuzz_test.zig");
    _ = @import("stackprobe_test.zig");
    _ = @import("stackprobe2_test.zig");
}
