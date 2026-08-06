// SPDX-License-Identifier: MIT
//! Double Ratchet (signal.org/docs/specifications/doubleratchet) — Part 2
//! of the Signal arc. Where `x3dh.zig` produces a single shared secret
//! `SK` (+ associated data `AD`) from an asynchronous prekey handshake,
//! the Double Ratchet turns that ONE secret into an endless stream of
//! per-message keys with **forward secrecy** (a compromise of current
//! state does not expose past messages) and **post-compromise security**
//! (the session heals after a compromise as soon as one fresh DH ratchet
//! from each side goes through). `SK` seeds the ratchet's initial root
//! key `RK`; `AD` is mixed into every message's AEAD associated data.
//!
//! **Status: COMPLETE.** State, both `KDF_RK`/`KDF_CK`, the symmetric-key
//! and DH ratchets, `MAX_SKIP`-bounded skipped-message handling, a
//! transactional (fail-closed) `decrypt`, and the header codec are all
//! real and tested (self-consistency + spec-adherence — see "Test
//! vectors" in `../NOTICE`; the spec, like X3DH/XEdDSA, publishes no
//! numeric worked example).
//!
//! ## The two ratchets (spec §3)
//!
//! - **Symmetric-key ratchet** — each sending/receiving *chain* is a
//!   sequence of chain keys advanced by `KDF_CK` (HMAC-SHA256), each step
//!   also emitting a single-use *message key* `MK`. This alone gives
//!   forward secrecy WITHIN a chain but not healing.
//! - **DH ratchet** — every time a party observes a NEW remote ratchet
//!   public key in a message header, both sides perform an X25519 DH and
//!   feed it through `KDF_RK` (HKDF-SHA256) to re-key the root and start a
//!   fresh chain. This is what heals the session (post-compromise
//!   security): new DH entropy the attacker never saw re-randomizes `RK`.
//!
//! ## Instantiation chosen by this module (the spec leaves these to the
//! application — see SPEC.md for the full rationale):
//!
//! - `KDF_RK(RK, dh_out)` = HKDF-SHA256, `salt = RK`, `ikm = dh_out`,
//!   `info = kdf_rk_info`, 64-byte output split `RK' ‖ CK` (spec §5.2).
//! - `KDF_CK(CK)` = HMAC-SHA256 keyed by `CK`; `HMAC(CK, 0x01) -> MK`,
//!   `HMAC(CK, 0x02) -> CK'` (spec §5.2, the exact recommended constants).
//! - **AEAD = ChaCha20-Poly1305** (the `chachapoly` sibling; byte-exact to
//!   `std.crypto.aead.chacha_poly.ChaCha20Poly1305`). The
//!   spec's OWN example is AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC),
//!   but it explicitly permits "an AEAD encryption scheme"; a real AEAD is
//!   simpler and less error-prone than hand-rolled EtM, and ChaCha20-
//!   Poly1305's 32-byte key lines up with our `MK`. The per-message AEAD
//!   key+nonce are HKDF-Expand'd from `MK` (`aead_info`), so `MK` itself is
//!   never used as a raw cipher key. Nonce reuse is structurally
//!   impossible: every `MK` is derived once and used for exactly one
//!   message, so a per-message fixed-derived nonce is safe. AEAD
//!   associated data = `AD ‖ serialize(header)` (spec §3.4), binding the
//!   ciphertext to the sender's ratchet key + message counters.
//!
//! ## Out of scope (deferred — see README.md / SPEC.md)
//!
//! - **Header encryption (HE, spec §4)** — headers here are sent in the
//!   clear (the DH pub + counters are visible). The HE variant (encrypting
//!   the header under a separate header key so the ratchet public key is
//!   not observable) is NOT implemented.
//! - **PQXDH** (post-quantum X3DH) seeding — this ratchet is seeded from
//!   the classical `x3dh.zig`.
//! - **Session persistence format stability** — `State` is an in-memory
//!   value; its byte layout is NOT a committed serialization format.
//!
//! Provenance: clean-room from the public Double Ratchet specification
//! (Signal Foundation / Trevor Perrin, Moxie Marlinspike). See `../NOTICE`.

const std = @import("std");
const chachapoly = @import("chachapoly");
const x3dh = @import("x3dh.zig");

const X25519 = std.crypto.dh.X25519;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
/// The ratchet AEAD — the SIMD `chachapoly` sibling, byte-exact to
/// `StdChaCha20Poly1305` below. A Double Ratchet message is one AEAD call over
/// a chat-sized payload, so this is uniformity with the rest of the repo far
/// more than it is a throughput win here (see README); the reason to do it
/// anyway is that there is then exactly ONE ChaCha20-Poly1305 implementation
/// that consumers audit, fuzz and keep constant-time.
const ChaCha20Poly1305 = chachapoly.ChaCha20Poly1305;
/// `std`'s AEAD. Not used on any production path — kept reachable so the
/// tests can assert the swap moved no ciphertext byte.
const StdChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const key_length: usize = x3dh.key_length; // 32
pub const chain_key_length: usize = 32;
pub const root_key_length: usize = 32;
pub const message_key_length: usize = 32;
pub const shared_secret_length: usize = x3dh.shared_secret_length; // 32
pub const associated_data_length: usize = x3dh.associated_data_length; // 64
pub const tag_length: usize = ChaCha20Poly1305.tag_length; // 16
const aead_key_length: usize = ChaCha20Poly1305.key_length; // 32
const aead_nonce_length: usize = ChaCha20Poly1305.nonce_length; // 12

/// Max message keys skippable within a SINGLE receiving chain in one
/// `decrypt` call — spec §6's DoS mitigation ("reasonable per-session
/// limits ... e.g. 1000"). A header claiming a message number this far
/// ahead of our position is rejected (`error.TooManySkippedMessages`)
/// BEFORE any key derivation or allocation, so a forged giant `N` cannot
/// cause CPU/OOM blowup.
pub const max_skip: u32 = 1000;

/// Upper bound on the total number of skipped message keys retained in a
/// `State`'s store across all chains (spec §6's second limit). Refuses to
/// grow the store past this (`error.TooManySkippedMessages`) rather than
/// silently evicting — a bounded store cannot be pumped to exhaust memory.
pub const max_skip_store: usize = 2000;

/// `info` for `KDF_RK`'s HKDF-Expand (spec §5.2 leaves it
/// application-defined — this is zig-libs' choice, matching `x3dh.zig`'s
/// own `x3dh_info` practice).
pub const kdf_rk_info = "zig-libs/signal/ratchet/rk/v1";

/// `info` for expanding a message key `MK` into the AEAD key+nonce.
pub const aead_info = "zig-libs/signal/ratchet/aead/v1";

// ── message header (spec §3.4) ──────────────────────────────────────────

/// The cleartext header prepended to every ciphertext: the sender's
/// CURRENT ratchet public key, the length of the sender's PREVIOUS sending
/// chain (`pn`, so the receiver knows how many trailing keys of the old
/// chain to skip before ratcheting), and this message's number within the
/// current sending chain (`n`). Header encryption (spec §4) is out of
/// scope — these three fields travel in the clear.
pub const Header = struct {
    dh: [key_length]u8,
    pn: u32,
    n: u32,

    /// `dh(32) ‖ pn(4 LE) ‖ n(4 LE)`.
    pub const encoded_length: usize = key_length + 4 + 4; // 40

    pub const DecodeError = error{InvalidHeader};

    pub fn toBytes(h: Header) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        out[0..key_length].* = h.dh;
        std.mem.writeInt(u32, out[key_length..][0..4], h.pn, .little);
        std.mem.writeInt(u32, out[key_length + 4 ..][0..4], h.n, .little);
        return out;
    }

    /// Fail-closed on any length other than exactly `encoded_length`
    /// (truncated/oversized headers are rejected, never partially parsed).
    pub fn fromBytes(bytes: []const u8) DecodeError!Header {
        if (bytes.len != encoded_length) return error.InvalidHeader;
        return .{
            .dh = bytes[0..key_length].*,
            .pn = std.mem.readInt(u32, bytes[key_length..][0..4], .little),
            .n = std.mem.readInt(u32, bytes[key_length + 4 ..][0..4], .little),
        };
    }
};

/// What `encrypt` produces / `decrypt` consumes: a cleartext `header` plus
/// the AEAD `ciphertext` (raw ciphertext followed by the 16-byte Poly1305
/// tag). `ciphertext` is heap-owned by the caller (`deinit`).
pub const Message = struct {
    header: Header,
    ciphertext: []u8,

    pub fn deinit(m: Message, allocator: std.mem.Allocator) void {
        allocator.free(m.ciphertext);
    }
};

// ── skipped-message-key store (spec §2.6 MKSKIPPED) ─────────────────────

/// Keyed by the sender's ratchet public key + message number, per spec —
/// a message key skipped over (received out of order) is retained here so
/// the delayed message can still be decrypted later.
const SkippedKey = struct {
    dh: [key_length]u8,
    n: u32,
};

const SkippedEntry = struct {
    key: SkippedKey,
    mk: [message_key_length]u8,
};

// ── State ───────────────────────────────────────────────────────────────

pub const AgreementError = error{
    /// An `X25519.scalarmult` in the DH ratchet landed on the identity
    /// element (only possible with a pathological low-order remote
    /// ratchet key). Mirrors `x3dh.AgreementError.KeyAgreementFailed`.
    KeyAgreementFailed,
};

pub const EncryptError = error{
    /// `encrypt` was called before this party has a sending chain. Bob's
    /// `State` has no `CKs` until his first `decrypt` performs the DH
    /// ratchet — in the normal Signal flow Alice always sends first, so a
    /// correct session never hits this; it fails closed rather than
    /// sending under an undefined key.
    NotInitializedForSending,
} || std.mem.Allocator.Error;

pub const DecryptError = error{
    /// The header asks us to skip more than `max_skip` keys in one chain,
    /// or would grow the skipped-key store past `max_skip_store`. Rejected
    /// before any derivation/allocation (DoS guard).
    TooManySkippedMessages,
    /// AEAD authentication failed (tampered ciphertext / wrong associated
    /// data / truncated ciphertext). Fail-closed; no state is mutated.
    MessageAuthenticationFailed,
    /// The message names a position whose key is no longer derivable (a
    /// replayed/duplicate message whose one-time key was already consumed,
    /// or a message that arrived before its chain could be established).
    MessageKeyNotAvailable,
} || AgreementError || std.mem.Allocator.Error;

/// A live Double Ratchet session (one party's view). Owns a heap-backed
/// skipped-key store — **the caller MUST call `deinit` exactly once**,
/// which frees that store AND `secureZero`s every secret the state holds
/// (root key, both chain keys, the local DH secret key, and every stored
/// message key).
pub const State = struct {
    /// `DHs` — our current ratchet keypair.
    dhs: X25519.KeyPair,
    /// `DHr` — the remote party's current ratchet public key (`null` for
    /// Bob until his first `decrypt`).
    dhr: ?[key_length]u8,
    /// `RK` — root key.
    rk: [root_key_length]u8,
    /// `CKs` — sending chain key (`null` until a sending chain exists).
    cks: ?[chain_key_length]u8,
    /// `CKr` — receiving chain key (`null` until a receiving chain exists).
    ckr: ?[chain_key_length]u8,
    /// `Ns`/`Nr` — message numbers in the current sending/receiving chain.
    ns: u32,
    nr: u32,
    /// `PN` — length of the previous sending chain (for the receiver's
    /// skip-before-ratchet bookkeeping).
    pn: u32,
    /// `AD` from X3DH — mixed into every message's AEAD associated data.
    ad: [associated_data_length]u8,
    /// `MKSKIPPED` — out-of-order message keys awaiting their message.
    mkskipped: std.AutoHashMapUnmanaged(SkippedKey, [message_key_length]u8),

    /// Alice's side (spec `RatchetInitAlice`): she already knows Bob's
    /// initial ratchet public key (his signed prekey's public half from
    /// the X3DH bundle), so she immediately performs the first DH + root
    /// KDF and can send right away. `sk`/`ad` come from `x3dh.initiate`.
    pub fn initAlice(
        sk: [shared_secret_length]u8,
        ad: [associated_data_length]u8,
        bob_ratchet_pub: [key_length]u8,
        io: std.Io,
    ) AgreementError!State {
        const dhs = X25519.KeyPair.generate(io);
        const dh_out = X25519.scalarmult(dhs.secret_key, bob_ratchet_pub) catch
            return error.KeyAgreementFailed;
        const derived = kdfRk(sk, dh_out);
        return .{
            .dhs = dhs,
            .dhr = bob_ratchet_pub,
            .rk = derived.rk,
            .cks = derived.ck,
            .ckr = null,
            .ns = 0,
            .nr = 0,
            .pn = 0,
            .ad = ad,
            .mkskipped = .empty,
        };
    }

    /// Bob's side (spec `RatchetInitBob`): his ratchet keypair IS his
    /// signed-prekey keypair (the DH key Alice already mixed into X3DH),
    /// the root key starts as `SK`, and he has NO sending chain yet — his
    /// first `decrypt` triggers the DH ratchet that gives him one. `sk`/
    /// `ad` come from `x3dh.respond` (identical to Alice's).
    pub fn initBob(
        sk: [shared_secret_length]u8,
        ad: [associated_data_length]u8,
        bob_ratchet_keypair: X25519.KeyPair,
    ) State {
        return .{
            .dhs = bob_ratchet_keypair,
            .dhr = null,
            .rk = sk,
            .cks = null,
            .ckr = null,
            .ns = 0,
            .nr = 0,
            .pn = 0,
            .ad = ad,
            .mkskipped = .empty,
        };
    }

    /// Frees the skipped-key store and zeroes all secret material.
    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        var it = self.mkskipped.valueIterator();
        while (it.next()) |mk| std.crypto.secureZero(u8, mk);
        self.mkskipped.deinit(allocator);
        std.crypto.secureZero(u8, &self.rk);
        if (self.cks) |*ck| std.crypto.secureZero(u8, ck);
        if (self.ckr) |*ck| std.crypto.secureZero(u8, ck);
        std.crypto.secureZero(u8, &self.dhs.secret_key);
        self.* = undefined;
    }

    /// Advance the sending chain and seal `plaintext` under the fresh
    /// message key (spec `RatchetEncrypt`). The returned `Message.header`
    /// carries our current ratchet public key + `PN` + `Ns`; `Ns` is then
    /// incremented. `CKs` is advanced by `KDF_CK` (forward secrecy). The
    /// message key is `secureZero`d before return.
    pub fn encrypt(
        self: *State,
        allocator: std.mem.Allocator,
        plaintext: []const u8,
    ) EncryptError!Message {
        const cks = self.cks orelse return error.NotInitializedForSending;
        const step = kdfCk(cks);
        var mk = step.mk;
        defer std.crypto.secureZero(u8, &mk);

        const header: Header = .{ .dh = self.dhs.public_key, .pn = self.pn, .n = self.ns };
        const ciphertext = try aeadSeal(allocator, mk, header, plaintext, self.ad);

        // Commit only after the (infallible-past-alloc) seal succeeded.
        self.cks = step.ck;
        self.ns += 1;
        return .{ .header = header, .ciphertext = ciphertext };
    }

    /// Decrypt `message.ciphertext` under `message.header` (spec
    /// `RatchetDecrypt`), **transactionally**: all ratchet advancement is
    /// computed on a working copy and committed to `self` ONLY after the
    /// AEAD tag verifies. A forged/tampered message therefore never
    /// mutates, advances, or corrupts the session (fail-closed) — it
    /// returns `error.MessageAuthenticationFailed` and leaves `self`
    /// untouched. Returns heap-owned plaintext (`allocator.free`).
    pub fn decrypt(
        self: *State,
        allocator: std.mem.Allocator,
        header: Header,
        ciphertext: []const u8,
        io: std.Io,
    ) DecryptError![]u8 {
        // 1. Already skipped? Try that stored key first (spec
        //    TrySkippedMessageKeys). Only remove it on a successful open,
        //    so a tampered replay does not consume a still-valid key.
        if (self.mkskipped.get(.{ .dh = header.dh, .n = header.n })) |stored| {
            var mk = stored;
            defer std.crypto.secureZero(u8, &mk);
            const pt = aeadOpen(allocator, mk, header, ciphertext, self.ad) catch |e| return e;
            self.removeSkipped(.{ .dh = header.dh, .n = header.n });
            return pt;
        }

        // Work on copies so nothing commits until the tag verifies. The
        // working copy holds secret material (root/chain keys + any freshly
        // ratcheted DH secret); zero it on exit — after a successful commit
        // `self` holds its own independent copy, so this never clobbers
        // committed state.
        var work: Scalars = .from(self);
        defer work.zeroize();
        var pending: std.ArrayList(SkippedEntry) = .empty;
        defer {
            for (pending.items) |*e| std.crypto.secureZero(u8, &e.mk);
            pending.deinit(allocator);
        }

        const need_ratchet = self.dhr == null or
            !std.mem.eql(u8, &header.dh, &self.dhr.?);
        if (need_ratchet) {
            // Finish the current receiving chain (skip up to header.pn),
            // then step the DH ratchet into the sender's new chain.
            try skipMessageKeys(&work, allocator, &pending, self.mkskipped.count(), header.pn);
            try dhRatchet(&work, header, io);
        }
        // Skip within the (possibly new) receiving chain up to header.n.
        try skipMessageKeys(&work, allocator, &pending, self.mkskipped.count(), header.n);

        const ckr = work.ckr orelse return error.MessageKeyNotAvailable;
        const step = kdfCk(ckr);
        var mk = step.mk;
        defer std.crypto.secureZero(u8, &mk);

        // Reserve store space BEFORE opening so the post-open commit of
        // skipped keys cannot fail (keeps commit infallible/atomic).
        try self.mkskipped.ensureUnusedCapacity(allocator, @intCast(pending.items.len));

        const pt = aeadOpen(allocator, mk, header, ciphertext, self.ad) catch |e| return e;

        // Tag verified → commit everything atomically.
        work.ckr = step.ck;
        work.nr += 1;
        work.commitTo(self);
        for (pending.items) |e| self.mkskipped.putAssumeCapacity(e.key, e.mk);
        return pt;
    }

    fn removeSkipped(self: *State, key: SkippedKey) void {
        if (self.mkskipped.fetchRemove(key)) |kv| {
            var v = kv.value;
            std.crypto.secureZero(u8, &v);
        }
    }
};

// ── the mutable scalar state, copied for transactional decrypt ──────────

const Scalars = struct {
    dhs: X25519.KeyPair,
    dhr: ?[key_length]u8,
    rk: [root_key_length]u8,
    cks: ?[chain_key_length]u8,
    ckr: ?[chain_key_length]u8,
    ns: u32,
    nr: u32,
    pn: u32,

    fn from(s: *const State) Scalars {
        return .{
            .dhs = s.dhs,
            .dhr = s.dhr,
            .rk = s.rk,
            .cks = s.cks,
            .ckr = s.ckr,
            .ns = s.ns,
            .nr = s.nr,
            .pn = s.pn,
        };
    }

    fn zeroize(w: *Scalars) void {
        std.crypto.secureZero(u8, &w.rk);
        std.crypto.secureZero(u8, &w.dhs.secret_key);
        if (w.cks) |*ck| std.crypto.secureZero(u8, ck);
        if (w.ckr) |*ck| std.crypto.secureZero(u8, ck);
    }

    fn commitTo(w: *const Scalars, s: *State) void {
        s.dhs = w.dhs;
        s.dhr = w.dhr;
        s.rk = w.rk;
        s.cks = w.cks;
        s.ckr = w.ckr;
        s.ns = w.ns;
        s.nr = w.nr;
        s.pn = w.pn;
    }
};

/// Skip (and stash) message keys of the CURRENT receiving chain up to
/// `until` (spec SkipMessageKeys). Fails closed if `until` is behind our
/// position with no derivable key, if it would exceed `max_skip` in one
/// step, or if the store would exceed `max_skip_store`. The DoS caps are
/// checked before any `KDF_CK`/allocation.
fn skipMessageKeys(
    work: *Scalars,
    allocator: std.mem.Allocator,
    pending: *std.ArrayList(SkippedEntry),
    store_len: usize,
    until: u32,
) DecryptError!void {
    if (work.ckr == null) {
        // No receiving chain yet: the only non-skip case is "nothing to
        // skip" (until == nr, e.g. header.pn == 0 on the very first
        // receive). Anything else means the key is unavailable.
        if (until == work.nr) return;
        return error.MessageKeyNotAvailable;
    }
    if (until < work.nr) return error.MessageKeyNotAvailable; // replay / consumed
    if (until - work.nr > max_skip) return error.TooManySkippedMessages;
    while (work.nr < until) : (work.nr += 1) {
        if (store_len + pending.items.len >= max_skip_store) return error.TooManySkippedMessages;
        const step = kdfCk(work.ckr.?);
        try pending.append(allocator, .{
            .key = .{ .dh = work.dhr.?, .n = work.nr },
            .mk = step.mk,
        });
        work.ckr = step.ck;
    }
}

/// DH ratchet step (spec DHRatchet): rotate `PN`, reset counters, adopt
/// the sender's new ratchet public key, derive the new RECEIVING chain
/// from a DH with our current key, then generate a fresh sending keypair
/// and derive the new SENDING chain.
fn dhRatchet(work: *Scalars, header: Header, io: std.Io) DecryptError!void {
    work.pn = work.ns;
    work.ns = 0;
    work.nr = 0;
    work.dhr = header.dh;

    const dh_recv = X25519.scalarmult(work.dhs.secret_key, header.dh) catch
        return error.KeyAgreementFailed;
    const recv = kdfRk(work.rk, dh_recv);
    work.rk = recv.rk;
    work.ckr = recv.ck;

    work.dhs = X25519.KeyPair.generate(io);
    const dh_send = X25519.scalarmult(work.dhs.secret_key, header.dh) catch
        return error.KeyAgreementFailed;
    const send = kdfRk(work.rk, dh_send);
    work.rk = send.rk;
    work.cks = send.ck;
}

// ── KDFs (spec §5.2) ────────────────────────────────────────────────────

const RkStep = struct { rk: [root_key_length]u8, ck: [chain_key_length]u8 };
const CkStep = struct { ck: [chain_key_length]u8, mk: [message_key_length]u8 };

/// `KDF_RK(RK, dh_out)` = HKDF-SHA256(salt = RK, ikm = dh_out,
/// info = kdf_rk_info) -> 64 bytes -> `RK' ‖ CK`.
fn kdfRk(rk: [root_key_length]u8, dh_out: [key_length]u8) RkStep {
    const prk = HkdfSha256.extract(&rk, &dh_out);
    var okm: [root_key_length + chain_key_length]u8 = undefined;
    HkdfSha256.expand(&okm, kdf_rk_info, prk);
    const result: RkStep = .{ .rk = okm[0..root_key_length].*, .ck = okm[root_key_length..].* };
    std.crypto.secureZero(u8, &okm);
    return result;
}

/// `KDF_CK(CK)` = HMAC-SHA256 keyed by `CK`: `HMAC(CK, 0x01) -> MK`,
/// `HMAC(CK, 0x02) -> CK'` (spec's exact recommended constants).
fn kdfCk(ck: [chain_key_length]u8) CkStep {
    var mk: [message_key_length]u8 = undefined;
    var next: [chain_key_length]u8 = undefined;
    HmacSha256.create(&mk, &[_]u8{0x01}, &ck);
    HmacSha256.create(&next, &[_]u8{0x02}, &ck);
    return .{ .ck = next, .mk = mk };
}

// ── AEAD (ChaCha20-Poly1305 over an MK-derived key/nonce) ───────────────

const KeyNonce = struct { key: [aead_key_length]u8, nonce: [aead_nonce_length]u8 };

/// Expand `MK` into an AEAD key + nonce (never uses `MK` as a raw cipher
/// key). `MK` is a uniform HMAC output, so it serves directly as the
/// HKDF PRK for a single Expand.
fn aeadKeyNonce(mk: [message_key_length]u8) KeyNonce {
    var okm: [aead_key_length + aead_nonce_length]u8 = undefined;
    HkdfSha256.expand(&okm, aead_info, mk);
    const result: KeyNonce = .{
        .key = okm[0..aead_key_length].*,
        .nonce = okm[aead_key_length..].*,
    };
    std.crypto.secureZero(u8, &okm);
    return result;
}

fn aeadAad(header: Header, ad: [associated_data_length]u8) [associated_data_length + Header.encoded_length]u8 {
    var aad: [associated_data_length + Header.encoded_length]u8 = undefined;
    aad[0..associated_data_length].* = ad;
    aad[associated_data_length..].* = header.toBytes();
    return aad;
}

/// Returns `ciphertext ‖ tag` (heap-owned).
fn aeadSeal(
    allocator: std.mem.Allocator,
    mk: [message_key_length]u8,
    header: Header,
    plaintext: []const u8,
    ad: [associated_data_length]u8,
) std.mem.Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, plaintext.len + tag_length);
    var kn = aeadKeyNonce(mk);
    defer std.crypto.secureZero(u8, &kn.key);
    const aad = aeadAad(header, ad);
    var tag: [tag_length]u8 = undefined;
    ChaCha20Poly1305.encrypt(out[0..plaintext.len], &tag, plaintext, &aad, kn.nonce, kn.key);
    out[plaintext.len..][0..tag_length].* = tag;
    return out;
}

/// Opens `ciphertext ‖ tag`. Fail-closed: a bad tag, wrong AD, or a
/// too-short buffer all return `error.MessageAuthenticationFailed` and
/// leak no partial plaintext.
fn aeadOpen(
    allocator: std.mem.Allocator,
    mk: [message_key_length]u8,
    header: Header,
    ciphertext: []const u8,
    ad: [associated_data_length]u8,
) DecryptError![]u8 {
    if (ciphertext.len < tag_length) return error.MessageAuthenticationFailed;
    const ct_len = ciphertext.len - tag_length;
    const tag: [tag_length]u8 = ciphertext[ct_len..][0..tag_length].*;

    var kn = aeadKeyNonce(mk);
    defer std.crypto.secureZero(u8, &kn.key);
    const aad = aeadAad(header, ad);

    const pt = try allocator.alloc(u8, ct_len);
    ChaCha20Poly1305.decrypt(pt, ciphertext[0..ct_len], tag, &aad, kn.nonce, kn.key) catch {
        allocator.free(pt);
        return error.MessageAuthenticationFailed;
    };
    return pt;
}

// ═══════════════════════════════════════════════════════════════════════
// tests
// ═══════════════════════════════════════════════════════════════════════

const testing = std.testing;

fn testIo() std.Io.Threaded {
    return std.Io.Threaded.init(testing.allocator, .{});
}

/// Seed a fresh Alice/Bob ratchet pair from a real X3DH agreement. Bob's
/// ratchet keypair is his signed-prekey keypair (the standard Signal
/// binding: the Double Ratchet's initial DH key is the X3DH signed
/// prekey). Uses `initiateUnverified`/`respond` — the XEdDSA signature is
/// irrelevant to ratchet behaviour and tested separately in `kat_test`.
fn seedSession(io: std.Io) !struct { alice: State, bob: State } {
    const alloc = testing.allocator;
    const alice_ik = X25519.KeyPair.generate(io);
    const bob_ik = X25519.KeyPair.generate(io);
    const bob_spk_kp = X25519.KeyPair.generate(io);
    const bob_opk_kp = X25519.KeyPair.generate(io);

    const bob_spk: x3dh.SignedPreKey = .{
        .key_pair = bob_spk_kp,
        .signature = undefined,
        .id = 1,
    };
    const bob_opk: x3dh.OneTimePreKey = .{ .key_pair = bob_opk_kp, .id = 2 };
    const bundle: x3dh.PreKeyBundle = .{
        .identity_key = bob_ik.public_key,
        .signed_prekey = bob_spk_kp.public_key,
        .signed_prekey_id = bob_spk.id,
        .signed_prekey_signature = undefined,
        .one_time_prekey = bob_opk_kp.public_key,
        .one_time_prekey_id = bob_opk.id,
    };

    const alice_out = try x3dh.initiateUnverified(alloc, alice_ik, bundle, "", io);
    defer alice_out.message.deinit(alloc);
    const bob_agr = try x3dh.respond(bob_ik, bob_spk, bob_opk, alice_out.message);

    try testing.expectEqualSlices(
        u8,
        &alice_out.agreement.shared_secret,
        &bob_agr.shared_secret,
    );

    const alice = try State.initAlice(
        alice_out.agreement.shared_secret,
        alice_out.agreement.associated_data,
        bob_spk_kp.public_key,
        io,
    );
    const bob = State.initBob(bob_agr.shared_secret, bob_agr.associated_data, bob_spk_kp);
    return .{ .alice = alice, .bob = bob };
}

/// Send `plaintext` from `sender` to `receiver`, asserting round-trip.
fn sendRecv(sender: *State, receiver: *State, plaintext: []const u8, io: std.Io) !void {
    const alloc = testing.allocator;
    var msg = try sender.encrypt(alloc, plaintext);
    defer msg.deinit(alloc);
    const pt = try receiver.decrypt(alloc, msg.header, msg.ciphertext, io);
    defer alloc.free(pt);
    try testing.expectEqualSlices(u8, plaintext, pt);
}

// ── differential: swapping std's AEAD for `chachapoly` moved nothing ─────
//
// The ratchet's ciphertext format is `AEAD(k, n, plaintext, AD ‖ header)`
// with the key/nonce HKDF-expanded from the message key. There is no
// published vector for it (the Double Ratchet spec leaves the AEAD to the
// application), so the anchor for the swap has to be the OTHER implementation
// of the same function: recompute `aeadSeal`'s exact output with std's AEAD
// and require byte-identity, over every length that crosses a ChaCha block
// boundary and over the associated data the header actually contributes.
test "differential: aeadSeal/aeadOpen are byte-identical under chachapoly and std" {
    try testing.expectEqual(StdChaCha20Poly1305.key_length, ChaCha20Poly1305.key_length);
    try testing.expectEqual(StdChaCha20Poly1305.nonce_length, ChaCha20Poly1305.nonce_length);
    try testing.expectEqual(StdChaCha20Poly1305.tag_length, ChaCha20Poly1305.tag_length);

    const mk: [message_key_length]u8 = @splat(0x5A);
    const ad: [associated_data_length]u8 = @splat(0x3C);
    const header: Header = .{ .dh = @splat(0x77), .pn = 4321, .n = 1234 };

    var plaintext: [600]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x516E_A100);
    prng.random().bytes(&plaintext);

    var theirs: [600 + tag_length]u8 = undefined;

    for ([_]usize{ 0, 1, 15, 63, 64, 65, 127, 128, 511, 512, 513, 600 }) |len| {
        const ours = try aeadSeal(testing.allocator, mk, header, plaintext[0..len], ad);
        defer testing.allocator.free(ours);

        // The std-side recomputation mirrors `aeadSeal` exactly: same derived
        // key/nonce, same AAD assembly, tag appended after the ciphertext.
        var kn = aeadKeyNonce(mk);
        defer std.crypto.secureZero(u8, &kn.key);
        const aad = aeadAad(header, ad);
        var tag: [tag_length]u8 = undefined;
        StdChaCha20Poly1305.encrypt(theirs[0..len], &tag, plaintext[0..len], &aad, kn.nonce, kn.key);
        theirs[len..][0..tag_length].* = tag;

        try testing.expectEqualSlices(u8, theirs[0 .. len + tag_length], ours);

        // …and `aeadOpen` (chachapoly) accepts the ciphertext std produced.
        const back = try aeadOpen(testing.allocator, mk, header, theirs[0 .. len + tag_length], ad);
        defer testing.allocator.free(back);
        try testing.expectEqualSlices(u8, plaintext[0..len], back);
    }
}

test "header codec round-trips; fromBytes rejects wrong length" {
    const h: Header = .{ .dh = [_]u8{0xAB} ** 32, .pn = 7, .n = 42 };
    const bytes = h.toBytes();
    try testing.expectEqual(@as(usize, 40), bytes.len);
    const back = try Header.fromBytes(&bytes);
    try testing.expectEqual(h.pn, back.pn);
    try testing.expectEqual(h.n, back.n);
    try testing.expectEqualSlices(u8, &h.dh, &back.dh);
    // Truncated / oversized headers fail closed (parse error).
    try testing.expectError(error.InvalidHeader, Header.fromBytes(bytes[0..39]));
    try testing.expectError(error.InvalidHeader, Header.fromBytes(&([_]u8{0} ** 41)));
}

test "KDF_CK uses distinct 0x01/0x02 constants (MK != CK', both != input)" {
    const ck: [32]u8 = [_]u8{0x11} ** 32;
    const step = kdfCk(ck);
    try testing.expect(!std.mem.eql(u8, &step.mk, &step.ck));
    try testing.expect(!std.mem.eql(u8, &step.mk, &ck));
    try testing.expect(!std.mem.eql(u8, &step.ck, &ck));
}

test "full interleaved session seeded from X3DH forces repeated DH ratchets" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    const s = try seedSession(io);
    var alice = s.alice;
    var bob = s.bob;
    defer alice.deinit(testing.allocator);
    defer bob.deinit(testing.allocator);

    // Alice must send first (Bob has no sending chain until he receives).
    try testing.expectError(error.NotInitializedForSending, bob.encrypt(testing.allocator, "nope"));

    // Alternate directions repeatedly — every direction switch is a fresh
    // DH ratchet on both sides, plus several messages within each chain.
    try sendRecv(&alice, &bob, "a0", io);
    try sendRecv(&alice, &bob, "a1", io);
    try sendRecv(&bob, &alice, "b0", io); // Bob ratchets in, then sends
    try sendRecv(&bob, &alice, "b1", io);
    try sendRecv(&alice, &bob, "a2", io); // Alice ratchets
    try sendRecv(&bob, &alice, "b2", io); // Bob ratchets
    try sendRecv(&alice, &bob, "a3", io);
    try sendRecv(&alice, &bob, "a4", io);
    try sendRecv(&bob, &alice, "b3", io);

    // Both stores should have drained back to empty (all in-order).
    try testing.expectEqual(@as(usize, 0), alice.mkskipped.count());
    try testing.expectEqual(@as(usize, 0), bob.mkskipped.count());
}

test "out-of-order within a chain: later message decrypts, earlier ones from store" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const alloc = testing.allocator;

    const s = try seedSession(io);
    var alice = s.alice;
    var bob = s.bob;
    defer alice.deinit(alloc);
    defer bob.deinit(alloc);

    // Alice produces three messages in one chain.
    var m0 = try alice.encrypt(alloc, "m0");
    defer m0.deinit(alloc);
    var m1 = try alice.encrypt(alloc, "m1");
    defer m1.deinit(alloc);
    var m2 = try alice.encrypt(alloc, "m2");
    defer m2.deinit(alloc);

    // Deliver 2, 0, 1.
    const p2 = try bob.decrypt(alloc, m2.header, m2.ciphertext, io);
    defer alloc.free(p2);
    try testing.expectEqualSlices(u8, "m2", p2);
    try testing.expectEqual(@as(usize, 2), bob.mkskipped.count()); // m0, m1 stashed

    const p0 = try bob.decrypt(alloc, m0.header, m0.ciphertext, io);
    defer alloc.free(p0);
    try testing.expectEqualSlices(u8, "m0", p0);

    const p1 = try bob.decrypt(alloc, m1.header, m1.ciphertext, io);
    defer alloc.free(p1);
    try testing.expectEqualSlices(u8, "m1", p1);
    try testing.expectEqual(@as(usize, 0), bob.mkskipped.count()); // drained
}

test "out-of-order across a DH-ratchet boundary" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const alloc = testing.allocator;

    const s = try seedSession(io);
    var alice = s.alice;
    var bob = s.bob;
    defer alice.deinit(alloc);
    defer bob.deinit(alloc);

    try sendRecv(&alice, &bob, "a0", io); // chain 1
    try sendRecv(&bob, &alice, "b0", io); // Bob ratchets & replies; Alice ratchets

    // Alice's NEW chain (chain 2): two messages n=0, n=1.
    var a1 = try alice.encrypt(alloc, "a1");
    defer a1.deinit(alloc);
    var a2 = try alice.encrypt(alloc, "a2");
    defer a2.deinit(alloc);

    // Deliver a2 (n=1) first: Bob must DH-ratchet into chain 2 AND skip
    // n=0 within it, stashing a1's key across the ratchet boundary.
    const p2 = try bob.decrypt(alloc, a2.header, a2.ciphertext, io);
    defer alloc.free(p2);
    try testing.expectEqualSlices(u8, "a2", p2);
    try testing.expectEqual(@as(usize, 1), bob.mkskipped.count());

    const p1 = try bob.decrypt(alloc, a1.header, a1.ciphertext, io);
    defer alloc.free(p1);
    try testing.expectEqualSlices(u8, "a1", p1);
    try testing.expectEqual(@as(usize, 0), bob.mkskipped.count());
}

test "MAX_SKIP: a header claiming a huge N is rejected without OOM" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const alloc = testing.allocator;

    const s = try seedSession(io);
    var alice = s.alice;
    var bob = s.bob;
    defer alice.deinit(alloc);
    defer bob.deinit(alloc);

    // Establish Bob's receiving chain (dhr + ckr set, nr = 1).
    try sendRecv(&alice, &bob, "a0", io);

    // Forge a header in the SAME chain but far beyond max_skip.
    const forged: Header = .{ .dh = bob.dhr.?, .pn = 0, .n = max_skip + 2 };
    var dummy_ct: [tag_length + 4]u8 = [_]u8{0} ** (tag_length + 4);
    try testing.expectError(
        error.TooManySkippedMessages,
        bob.decrypt(alloc, forged, &dummy_ct, io),
    );
    // State untouched: still no skipped keys, nr unchanged.
    try testing.expectEqual(@as(usize, 0), bob.mkskipped.count());
    try testing.expectEqual(@as(u32, 1), bob.nr);
}

test "tamper: flipped ciphertext, wrong AD, and truncated buffer all fail closed" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const alloc = testing.allocator;

    const s = try seedSession(io);
    var alice = s.alice;
    var bob = s.bob;
    defer alice.deinit(alloc);
    defer bob.deinit(alloc);

    var msg = try alice.encrypt(alloc, "secret payload");
    defer msg.deinit(alloc);

    // (a) Flipped ciphertext byte → auth fails, Bob's state untouched.
    {
        var tampered = try alloc.dupe(u8, msg.ciphertext);
        defer alloc.free(tampered);
        tampered[0] ^= 0x01;
        try testing.expectError(
            error.MessageAuthenticationFailed,
            bob.decrypt(alloc, msg.header, tampered, io),
        );
        try testing.expectEqual(@as(u32, 0), bob.nr); // no advance
        try testing.expectEqual(@as(?[key_length]u8, null), bob.dhr); // no ratchet
    }

    // (b) Wrong associated data (AD mixed into the AEAD tag).
    {
        var bob_bad_ad = bob;
        bob_bad_ad.ad[0] ^= 0xFF;
        // (bob and bob_bad_ad share the same mkskipped map handle; the
        // decrypt fails before touching it, so no double-free — bob.deinit
        // frees it once.)
        try testing.expectError(
            error.MessageAuthenticationFailed,
            bob_bad_ad.decrypt(alloc, msg.header, msg.ciphertext, io),
        );
    }

    // (c) Truncated ciphertext (shorter than the AEAD tag).
    {
        try testing.expectError(
            error.MessageAuthenticationFailed,
            bob.decrypt(alloc, msg.header, msg.ciphertext[0 .. tag_length - 1], io),
        );
    }

    // After all tampering, the genuine message still decrypts (state was
    // never corrupted by the failed attempts).
    const pt = try bob.decrypt(alloc, msg.header, msg.ciphertext, io);
    defer alloc.free(pt);
    try testing.expectEqualSlices(u8, "secret payload", pt);
}

test "replay of a consumed in-order message is not decryptable" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const alloc = testing.allocator;

    const s = try seedSession(io);
    var alice = s.alice;
    var bob = s.bob;
    defer alice.deinit(alloc);
    defer bob.deinit(alloc);

    var msg = try alice.encrypt(alloc, "once");
    defer msg.deinit(alloc);
    const pt = try bob.decrypt(alloc, msg.header, msg.ciphertext, io);
    defer alloc.free(pt);
    try testing.expectEqualSlices(u8, "once", pt);

    // Re-delivering the same message: its key was consumed (not stashed),
    // n is now behind nr with nothing in the store → not available.
    try testing.expectError(
        error.MessageKeyNotAvailable,
        bob.decrypt(alloc, msg.header, msg.ciphertext, io),
    );
}

test "fuzz: Header.fromBytes never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzHeaderFromBytes, .{});
}

fn fuzzHeaderFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [Header.encoded_length + 8]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const h = Header.fromBytes(buf[0..len]) catch return;
    _ = h;
}

test "fuzz: decrypt (wire header+ciphertext) never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecrypt, .{});
}

fn fuzzDecrypt(_: void, smith: *std.testing.Smith) !void {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const alloc = testing.allocator;

    // A live, X3DH-seeded receiver session — `decrypt`'s untrusted-wire
    // surface is `header`/`ciphertext`, not the session setup itself.
    const s = try seedSession(io);
    var alice = s.alice;
    var bob = s.bob;
    defer alice.deinit(alloc);
    defer bob.deinit(alloc);

    // `Header.fromBytes` requires exactly `encoded_length` bytes, so build
    // one from arbitrary content directly rather than round-tripping
    // through `fromBytes` (that path is covered by the harness above).
    var header_bytes: [Header.encoded_length]u8 = undefined;
    smith.bytes(&header_bytes);
    const header = Header.fromBytes(&header_bytes) catch return;

    var ct_buf: [256]u8 = undefined;
    smith.bytes(&ct_buf);
    const ct_len: usize = smith.valueRangeAtMost(u16, 0, ct_buf.len);

    // Arbitrary header.pn/header.n drive `skipMessageKeys`/`dhRatchet`;
    // arbitrary ciphertext drives `aeadOpen`. Every failure mode here must
    // be a typed `DecryptError`, never a panic/OOB — `self` (bob) is left
    // untouched on any error per `decrypt`'s transactional-commit doc.
    const pt = bob.decrypt(alloc, header, ct_buf[0..ct_len], io) catch return;
    alloc.free(pt);
}
