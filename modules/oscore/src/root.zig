// SPDX-License-Identifier: MIT
//! oscore — OSCORE (Object Security for Constrained RESTful Environments,
//! RFC 8613): end-to-end application-layer security for CoAP (and
//! CoAP-mappable HTTP), built on a COSE_Encrypt0 wrapper around an AEAD.
//! This module targets the MANDATORY-to-implement ciphersuite only:
//! **AES-CCM-16-64-128** (COSE algorithm 10, RFC 8152 §10.2 — 128-bit key,
//! 13-byte nonce, 64-bit/8-byte tag) for the AEAD, and **HKDF-SHA-256**
//! (RFC 5869) for §3.2.1 context derivation.
//!
//! **Status: complete** — all six crypto cores implemented and KAT-validated,
//! green in Debug + ReleaseFast. REAL pure-bookkeeping pieces: the
//! §3.2.1 `info` CBOR encoder (`encodeInfo`), the §5.4 `aad_array`/
//! `Enc_structure` CBOR encoders (`encodeAadArray`, `encodeEncStructure`),
//! the §6.1 compressed COSE option codec (`OscoreOption`), and the §3.2.2
//! anti-replay sliding window (`ReplayWindow`). The six crypto CORES —
//! `deriveKey`/`deriveContext` (§3.2.1 HKDF-SHA-256 context derivation),
//! `computeNonce` (§5.2 partial-IV/ID nonce XOR), `buildAad` (§5.4 AAD
//! composition), `protect`/`unprotect` (§8 AES-CCM-16-64-128 seal/open with
//! nonce+AAD construction and, on the receive path, fail-closed AEAD +
//! replay-window enforcement) — reproduce RFC 8613 Appendix C byte-exact.
//! `kat_vectors.zig` carries RFC 8613 Appendix C's OFFICIAL test vectors
//! (all six C.1-C.3 key-derivation vectors, client AND server directions,
//! plus all five C.4-C.8 protected-message vectors) byte-exact, transcribed
//! from the RFC text — see `NOTICE`. `kat_test.zig` asserts them all: the
//! REAL encoders against every `info`/`aad_array`/option field, and the
//! cores' Sender/Recipient Key + Common IV + nonce + AAD + ciphertext +
//! tamper-rejection + replay-rejection + an end-to-end round-trip. (NB: C.7
//! is a RESPONSE reusing the REQUEST's nonce — not a `protect` output — so
//! the protect-reproduces test skips it; it is still covered byte-exact by
//! the `unprotect` round-trip, which reconstructs the reused nonce.)
//!
//! ## Zig std recon (verify against std 0.16 source before relying on it)
//!
//! - `std.crypto.aead.aes_ccm.Aes128Ccm8` is `AesCcm(Aes128, tag_len=8,
//!   nonce_len=13)` — **exactly** OSCORE's AES-CCM-16-64-128: 128-bit key
//!   (`Aes128Ccm8.key_length == 16`), 13-byte nonce (`.nonce_length ==
//!   13`), 8-byte/64-bit tag (`.tag_length == 8`). Its API —
//!   `encrypt(c, tag: *[8]u8, m, ad, npub: [13]u8, key: [16]u8) void` /
//!   `decrypt(m, c, tag: [8]u8, ad, npub: [13]u8, key: [16]u8)
//!   AuthenticationError!void` — is a SEPARATE-tag-out-param shape (not
//!   ciphertext-appended-tag internally; `protect`/`unprotect` below are
//!   responsible for the COSE ciphertext-then-tag wire convention, RFC
//!   8152 §5.2). So the AEAD itself is NOT a gap — the crypto work this
//!   module supplies is the OSCORE CONSTRUCTION around it (context
//!   derivation, the nonce, the AAD, the compressed-option wire format,
//!   replay protection).
//! - `std.crypto.kdf.hkdf.HkdfSha256` supplies `extract(salt, ikm) -> [32]u8`
//!   and `expand(out, ctx, prk) void` — exactly RFC 5869's two-phase HKDF
//!   that §3.2.1 specifies (`ctx` there is OSCORE's own `info`).
//! - `std.crypto.hash.sha2.Sha256` (used internally by the above; this
//!   module never calls it directly).
//! - Zig std GAP: yes — std has no CBOR encoder/decoder and no OSCORE/COSE
//!   layer of any kind; both the CBOR primitives and the whole OSCORE
//!   construction (security context, nonce, AAD, compressed option,
//!   replay window) are this module's own, clean-room from RFC 8613's
//!   public text (see `NOTICE`).
//!
//! ## Scope / non-goals
//!
//! This module is **CoAP-agnostic by design**: it never imports the
//! sibling `coap` module (no build dep — `meta.deps = .{}`) and never
//! parses/serializes a CoAP message itself. `protect`/`unprotect` operate
//! on the RFC 8613 §5.3 "plaintext" (CoAP Code + Class E options + payload
//! marker + payload) and the §5.4 "options" (Class I options) as OPAQUE
//! byte strings the CALLER assembles — that assembly is the intended job
//! of the sibling `coap` module (RFC 7252 message codec, already in this
//! repository), wiring OSCORE in as its object-security layer. Likewise,
//! per-exchange bookkeeping (matching a response's Token back to the
//! request that generated it, so a response protector knows whether to
//! reuse the request's nonce per §5.2) is the CALLER's job — this module
//! takes whichever `(id, Partial IV)` pair the caller supplies.
//!
//! Only AES-CCM-16-64-128 (COSE alg 10) + HKDF-SHA-256 is implemented.
//! RFC 8613 §3.2 also permits other COSE AEAD/HKDF algorithm pairs by
//! agreement — out of scope for this pass (`Algorithm` has exactly one
//! member).

const std = @import("std");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation over caller-supplied bytes — no I/O, no CoAP framing of its own
    // A `SecurityContext` is mutable per-connection state (the Sender
    // Sequence Number increments on every `protect`; the Recipient's
    // `ReplayWindow` slides on every accepted `unprotect`) that ONE
    // caller owns and mutates via `*SecurityContext` — the same shape as
    // `bolt8.Transport`, not the fully-immutable-value shape of
    // `bip340`/`adaptor`'s keys.
    .concurrency = .single_owner,
    .model_after = "RFC 8613 (OSCORE) \u{2014} AES-CCM-16-64-128 (COSE algorithm 10, RFC 8152 \u{a7}10.2) mandatory-to-implement AEAD + HKDF-SHA-256 (RFC 5869) context derivation; std.crypto.aead.aes_ccm.Aes128Ccm8 supplies the exact AEAD, std.crypto.kdf.hkdf.HkdfSha256 the KDF",
    .deps = .{}, // std only — deliberately NOT depending on the sibling `coap` module, see the module doc comment's "Scope / non-goals"
};

// ── algorithm constants (AES-CCM-16-64-128 only — RFC 8613 §3.2's default) ──

/// COSE algorithm 10 (RFC 8152 §10.2): the only AEAD this module
/// implements — RFC 8613 §3.2's mandatory-to-implement default.
pub const Algorithm = enum(i16) {
    aes_ccm_16_64_128 = 10,
};

/// `std.crypto.aead.aes_ccm.Aes128Ccm8.key_length` — 128-bit AEAD key.
pub const key_length: usize = 16;
/// `std.crypto.aead.aes_ccm.Aes128Ccm8.nonce_length` — 13-byte AEAD nonce.
pub const nonce_length: usize = 13;
/// `std.crypto.aead.aes_ccm.Aes128Ccm8.tag_length` — 8-byte/64-bit AEAD tag.
pub const tag_length: usize = 8;

/// §5.2 Figure 8's "nonce length minus 6 bytes" ID_PIV field width — at
/// `nonce_length == 13`, that is 7 bytes. A Sender/Recipient ID longer
/// than this cannot be used to generate a nonce at this algorithm
/// (`computeNonce` rejects it).
pub const id_piv_field_width: usize = nonce_length - 6;

/// The Partial IV / Sender Sequence Number's maximum value: it must fit
/// in the AEAD nonce's 5-byte PIV field (§5.2), i.e. `< 2^40`.
pub const max_partial_iv: u64 = (1 << 40) - 1;

// ── security context (RFC 8613 §3.1) ────────────────────────────────────

/// The Common Context (§3.1): parameters shared by both the Sender and
/// Recipient side of one endpoint's security context.
pub const CommonContext = struct {
    algorithm: Algorithm = .aes_ccm_16_64_128,
    /// Derived from Master Secret/Salt/ID Context by `deriveKey`/
    /// `deriveContext` (§3.2.1) — used to generate the AEAD nonce (§5.2).
    common_iv: [nonce_length]u8,
};

/// The Sender Context (§3.1): this endpoint's OWN identity + key, used to
/// PROTECT (encrypt) messages it sends.
pub const SenderContext = struct {
    /// Sender ID (SID). MUST be `<= id_piv_field_width` (7) bytes at this
    /// algorithm for `computeNonce` to accept it.
    id: []const u8,
    /// Derived via `deriveKey(..., id = sender_id, label = .key)`.
    key: [key_length]u8,
    /// The Sender Sequence Number (§3.1/§3.2.2): starts at 0, incremented
    /// by `protect` on every successful call. Used as this endpoint's own
    /// Partial IV.
    sequence_number: u64 = 0,
};

/// The Recipient Context (§3.1): the OTHER endpoint's identity + key,
/// used to UNPROTECT (verify + decrypt) messages received from it, plus
/// the replay-protection state for that direction.
pub const RecipientContext = struct {
    /// Recipient ID (RID) — the peer's Sender ID. Same length ceiling as
    /// `SenderContext.id`.
    id: []const u8,
    /// Derived via `deriveKey(..., id = recipient_id, label = .key)`.
    key: [key_length]u8,
    /// §3.2.2/§7.4's sliding anti-replay window — REAL, see
    /// `ReplayWindow` below. Server-only per §3.1 ("Replay Window
    /// (Server only)"), but harmless to carry on a client too (a client
    /// that never receives Observe-style repeated requests simply never
    /// exercises it).
    replay_window: ReplayWindow = .{},
};

/// A full OSCORE security context for one endpoint (§3.1's three-part
/// Common/Sender/Recipient split, bundled together as `deriveContext`
/// returns it). `sender`/`recipient` are NOT symmetric with the peer's own
/// context — see the module-level `Figure 4` cross-reference in RFC
/// 8613 §3.1: this endpoint's `sender` mirrors the peer's `recipient`,
/// and vice versa.
pub const SecurityContext = struct {
    common: CommonContext,
    sender: SenderContext,
    recipient: RecipientContext,
};

// ── ReplayWindow (RFC 8613 §3.2.2 / §7.4) — REAL, pure bookkeeping ─────
//
// A sliding anti-replay window (RFC 6347 §4.1.2.6-style, the mechanism
// §3.2.2 names as its default), backed by a u64 bitmap. NOT a crypto
// core: this is pure integer/bit bookkeeping over PUBLIC sequence
// numbers (the AEAD tag is what actually authenticates a message; the
// replay window only decides whether to bother verifying one a second
// time), so it is implemented for real here rather than left for the
// crypto-specialist pass.

/// RFC 8613 §3.2.2's stated default window size.
pub const default_replay_window_size: u7 = 32;

/// A per-Recipient-Context sliding anti-replay window over Partial IV
/// values (§3.2.2, §7.4). Tracks the highest sequence number seen plus a
/// bitmap of which of the `window_size` sequence numbers just below it
/// have already been seen. `window_size` is bounded to 64 by the `u64`
/// bitmap backing (RFC 8613 does not mandate a specific size — "may be
/// different in the two endpoints", §3.2 — 64 comfortably covers the
/// §3.2.2 default of 32 and any deployment-specific widening within a
/// single AEAD-tag's worth of reordering tolerance).
pub const ReplayWindow = struct {
    highest_seen: u64 = 0,
    /// Bit `i` (0-indexed) set means `highest_seen - (i + 1)` has been
    /// seen. Only the low `window_size` bits are meaningful.
    mask: u64 = 0,
    /// False until the first `update` — before that, `check` accepts
    /// anything (there is nothing yet to compare against; the OSCORE
    /// Recipient Context has no notion of an a-priori "expected first
    /// sequence number").
    initialized: bool = false,
    window_size: u7 = default_replay_window_size,

    /// Effective window size. The u64 `mask` can track at most 64 sequence
    /// numbers below the high-water mark, so the window never exceeds 64 even if
    /// a caller sets a larger `window_size` (a `u7`, up to 127) — without this
    /// clamp a `diff`/`shift` of 64..126 would `@intCast` to `u6` and panic
    /// (config-gated latent panic on a hostile `partial_iv`).
    fn effWindow(rw: ReplayWindow) u7 {
        return @min(rw.window_size, 64);
    }

    /// Returns `true` if `seq` would be ACCEPTED right now (not an exact
    /// duplicate, not outside the window, not already recorded) —
    /// read-only, does not mutate `rw`. Callers MUST call `update` only
    /// AFTER independently verifying `seq`'s message (i.e. after the AEAD
    /// tag check succeeds) — see `update`'s own doc comment for why.
    pub fn check(rw: ReplayWindow, seq: u64) bool {
        if (!rw.initialized) return true;
        if (seq > rw.highest_seen) return true;
        const diff = rw.highest_seen - seq;
        if (diff == 0) return false; // exact duplicate of the highest seen sequence number
        if (diff > rw.effWindow()) return false; // too old — fell off the trailing edge of the window
        const bit: u64 = @as(u64, 1) << @intCast(diff - 1);
        return (rw.mask & bit) == 0;
    }

    /// Records `seq` as seen, sliding the window forward if `seq` is a
    /// new high-water mark. MUST only be called for a `seq` that has
    /// ALREADY passed AEAD verification (i.e. call `check` first, verify
    /// the message, and only then `update`) — recording an unverified
    /// sequence number here would let an on-path attacker "burn" a
    /// legitimate future replay-window slot by replaying (or forging)
    /// a garbage message with that sequence number before the real one
    /// arrives, causing the real message to be rejected as a replay
    /// it never was.
    pub fn update(rw: *ReplayWindow, seq: u64) void {
        if (!rw.initialized) {
            rw.highest_seen = seq;
            rw.mask = 0;
            rw.initialized = true;
            return;
        }
        if (seq > rw.highest_seen) {
            const shift = seq - rw.highest_seen;
            if (shift >= rw.effWindow()) {
                rw.mask = 0;
            } else {
                const shift_amt: u6 = @intCast(shift);
                // The old highest_seen now sits at bit (shift - 1) in the
                // re-based window; the rest of the old mask shifts up
                // alongside it.
                rw.mask = (rw.mask << shift_amt) | (@as(u64, 1) << @intCast(shift - 1));
            }
            rw.highest_seen = seq;
        } else if (seq < rw.highest_seen) {
            const diff = rw.highest_seen - seq;
            if (diff <= rw.effWindow()) {
                rw.mask |= @as(u64, 1) << @intCast(diff - 1);
            }
        }
        // seq == highest_seen: already implicitly "seen" (check's diff==0
        // branch); nothing further to record.
    }
};

// ── CBOR primitives (RFC 7049) — REAL, generic, no OSCORE-specific shape ──
//
// Minimal major-type-header encoder covering exactly what §3.2.1's `info`
// and §5.4's `aad_array`/`Enc_structure` need: array/bstr/text-string
// headers and small non-negative integers. Not a general CBOR library
// (no maps, no negative ints, no floats/tags) — OSCORE's own fixed shapes
// never need those.

fn cborHead(list: *std.ArrayList(u8), allocator: std.mem.Allocator, major: u3, arg: u64) std.mem.Allocator.Error!void {
    const mt: u8 = @as(u8, major) << 5;
    if (arg < 24) {
        try list.append(allocator, mt | @as(u8, @intCast(arg)));
    } else if (arg <= 0xFF) {
        try list.append(allocator, mt | 24);
        try list.append(allocator, @intCast(arg));
    } else if (arg <= 0xFFFF) {
        try list.append(allocator, mt | 25);
        var buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &buf, @intCast(arg), .big);
        try list.appendSlice(allocator, &buf);
    } else if (arg <= 0xFFFFFFFF) {
        try list.append(allocator, mt | 26);
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, @intCast(arg), .big);
        try list.appendSlice(allocator, &buf);
    } else {
        try list.append(allocator, mt | 27);
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, arg, .big);
        try list.appendSlice(allocator, &buf);
    }
}

fn cborArrayHeader(list: *std.ArrayList(u8), allocator: std.mem.Allocator, count: u64) std.mem.Allocator.Error!void {
    try cborHead(list, allocator, 4, count);
}

fn cborUint(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) std.mem.Allocator.Error!void {
    try cborHead(list, allocator, 0, value);
}

fn cborBstr(list: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error!void {
    try cborHead(list, allocator, 2, bytes.len);
    try list.appendSlice(allocator, bytes);
}

fn cborTextString(list: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) std.mem.Allocator.Error!void {
    try cborHead(list, allocator, 3, s.len);
    try list.appendSlice(allocator, s);
}

/// CBOR `null` (major type 7, simple value 22) — a single `0xf6` byte.
fn cborNull(list: *std.ArrayList(u8), allocator: std.mem.Allocator) std.mem.Allocator.Error!void {
    try cborHead(list, allocator, 7, 22);
}

// ── §3.2.1 `info` CBOR array — REAL, validated byte-exact against Appendix C ──

/// The Sender/Recipient/Common-IV distinction §3.2.1's `info.type` field
/// encodes (`"Key"` or `"IV"`).
pub const KeyLabel = enum {
    key,
    iv,

    pub fn text(label: KeyLabel) []const u8 {
        return switch (label) {
            .key => "Key",
            .iv => "IV",
        };
    }
};

/// RFC 8613 §3.2.1's `info` CBOR array:
///
/// ```text
/// info = [
///   id : bstr,
///   id_context : bstr / nil,
///   alg_aead : int,
///   type : tstr,
///   L : uint,
/// ]
/// ```
///
/// `id` is the Sender ID or Recipient ID when `label == .key`, and MUST
/// be the empty slice `&.{}` when `label == .iv` (deriving the Common
/// IV) — §3.2.1: "the empty byte string when deriving the Common IV".
/// This function does not itself enforce that convention (it just
/// encodes whatever `id`/`label` it is given); `deriveContext` is the
/// caller responsible for getting it right by construction.
///
/// REAL — pure CBOR assembly, no secret-touching arithmetic. Byte-exact
/// against every one of Appendix C.1-C.3's six `info (for Sender/
/// Recipient Key)` and three `info (for Common IV)` fields (`kat_test.zig`).
pub fn encodeInfo(
    allocator: std.mem.Allocator,
    id: []const u8,
    id_context: ?[]const u8,
    algorithm: Algorithm,
    label: KeyLabel,
    length: u16,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try cborArrayHeader(&list, allocator, 5);
    try cborBstr(&list, allocator, id);
    if (id_context) |ctx| {
        try cborBstr(&list, allocator, ctx);
    } else {
        try cborNull(&list, allocator);
    }
    try cborUint(&list, allocator, @intCast(@intFromEnum(algorithm)));
    try cborTextString(&list, allocator, label.text());
    try cborUint(&list, allocator, length);
    return list.toOwnedSlice(allocator);
}

// ── §5.4 AAD (Enc_structure / aad_array) — REAL sub-encoders + STUBBED buildAad ──

/// The pieces `encodeAadArray`/`buildAad` need beyond the
/// `SecurityContext` itself — RFC 8613 §5.4's `aad_array` fields.
pub const AadParams = struct {
    /// §5.4: "Implementations of this specification MUST set this field
    /// to 1."
    oscore_version: u8 = 1,
    algorithm: Algorithm = .aes_ccm_16_64_128,
    /// The 'kid' of the COSE object of the ORIGINAL REQUEST — even when
    /// building the AAD for a RESPONSE (§5.4: "request_kid: contains the
    /// value of the 'kid' in the COSE object of the request").
    request_kid: []const u8,
    /// The 'Partial IV' of the COSE object of the ORIGINAL REQUEST — same
    /// caveat as `request_kid`.
    request_piv: []const u8,
    /// The Class I options (§4.1.2) of the original message, RFC 7252
    /// §3.1 delta-encoded — `&.{}` when there are none (every Appendix C
    /// vector has none).
    options: []const u8 = &.{},
};

/// RFC 8613 §5.4's `aad_array`:
///
/// ```text
/// aad_array = [
///   oscore_version : uint,
///   algorithms : [ alg_aead : int ],
///   request_kid : bstr,
///   request_piv : bstr,
///   options : bstr,
/// ]
/// ```
///
/// REAL — pure CBOR assembly (the same shape of work as `encodeInfo`).
/// Byte-exact against every one of Appendix C.4-C.8's `aad_array` fields
/// (`kat_test.zig`).
pub fn encodeAadArray(allocator: std.mem.Allocator, params: AadParams) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try cborArrayHeader(&list, allocator, 5);
    try cborUint(&list, allocator, params.oscore_version);
    try cborArrayHeader(&list, allocator, 1);
    try cborUint(&list, allocator, @intCast(@intFromEnum(params.algorithm)));
    try cborBstr(&list, allocator, params.request_kid);
    try cborBstr(&list, allocator, params.request_piv);
    try cborBstr(&list, allocator, params.options);
    return list.toOwnedSlice(allocator);
}

/// RFC 8152 §5.3's generic COSE `Enc_structure`, specialized to OSCORE's
/// always-empty "protected" header (§5.4: `AAD = Enc_structure = [
/// "Encrypt0", h'', external_aad ]`):
///
/// ```text
/// Enc_structure = [
///   context : "Encrypt0",
///   protected : h'',
///   external_aad : bstr,
/// ]
/// ```
///
/// `external_aad` here is the RAW `aad_array` bytes (`encodeAadArray`'s
/// output) — this function wraps them as the CBOR bstr that is
/// `Enc_structure`'s third array element (matching §5.4's own notation,
/// `external_aad = bstr .cbor aad_array`: the wrapping bstr IS this
/// function's job, not `encodeAadArray`'s).
///
/// REAL — pure CBOR assembly + concatenation, no OSCORE-specific
/// judgment (this is plain RFC 8152 COSE, reusable by any COSE_Encrypt0
/// consumer). Byte-exact against every one of Appendix C.4-C.8's `AAD`
/// fields when composed with `encodeAadArray`'s output (`kat_test.zig`,
/// via `buildAad`).
pub fn encodeEncStructure(allocator: std.mem.Allocator, external_aad: []const u8) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try cborArrayHeader(&list, allocator, 3);
    try cborTextString(&list, allocator, "Encrypt0");
    try cborBstr(&list, allocator, &.{}); // protected header — always empty for OSCORE, §5.4
    try cborBstr(&list, allocator, external_aad);
    return list.toOwnedSlice(allocator);
}

pub const BuildAadError = std.mem.Allocator.Error;

/// RFC 8613 §5.4's full AAD: `AAD = Enc_structure = ["Encrypt0", h'',
/// external_aad]` where `external_aad` is `encodeAadArray(params)`.
///
/// Construction (both sub-steps are ALREADY REAL — see each's own doc
/// comment — this is their composition):
/// 1. `aad_array = encodeAadArray(allocator, params)`.
/// 2. `return encodeEncStructure(allocator, aad_array)` (freeing
///    `aad_array` after, since only the wrapped result is returned).
///
/// Kept as its own named core (rather than inlined into `protect`/
/// `unprotect`, and despite being a two-line composition of functions
/// that are already real) because the task brief that scaffolded this
/// module lists §5.4's AAD assembly as one of the four KAT-critical
/// crypto-adjacent pieces — key derivation, the nonce, the AAD, and the
/// AEAD seal/open — so `kat_test.zig` gates its correctness on its OWN
/// direct byte-exact assertion (Appendix C.4-C.8's `AAD` field) rather
/// than only checking it transitively through a passing `protect`/
/// `unprotect` round trip.
pub fn buildAad(allocator: std.mem.Allocator, params: AadParams) BuildAadError![]u8 {
    const aad_array = try encodeAadArray(allocator, params);
    defer allocator.free(aad_array);
    return encodeEncStructure(allocator, aad_array);
}

// ── §6.1 compressed COSE option value — REAL codec ──────────────────────

/// The RFC 8613 §6.1 compressed COSE_Encrypt0 header, as carried in the
/// OSCORE CoAP option value:
///
/// ```text
///  0 1 2 3 4 5 6 7 <------------- n bytes -------------->
/// +-+-+-+-+-+-+-+-+--------------------------------------
/// |0 0 0|h|k|  n  |       Partial IV (if any) ...
/// +-+-+-+-+-+-+-+-+--------------------------------------
///
///  <- 1 byte -> <----- s bytes ------>
/// +------------+----------------------+------------------+
/// | s (if any) | kid context (if any) | kid (if any) ... |
/// +------------+----------------------+------------------+
/// ```
///
/// `partial_iv`/`kid`/`kid_context` are `null` exactly when ABSENT
/// (flag bits `n == 0` / `k == 0` / `h == 0`). A `kid`/`kid_context` that
/// is PRESENT but zero-length (e.g. Appendix C.4's client, whose own
/// Sender ID is the empty byte string) is `.{}` — an EMPTY, non-null
/// slice — not `null`: the distinction is exactly the `k`/`h` flag bit,
/// which is independent of the field's encoded LENGTH.
pub const OscoreOption = struct {
    partial_iv: ?u64 = null,
    kid_context: ?[]const u8 = null,
    kid: ?[]const u8 = null,

    /// The Partial IV field's max width — bounded by `max_partial_iv`
    /// (5 bytes), and §6.1's own reserved `n` values (6, 7 forbidden).
    pub const max_partial_iv_bytes: usize = 5;

    pub const EncodeError = error{ OutOfMemory, PartialIvTooLarge, KidContextTooLong };

    /// §6.1 encoding, minimal-length Partial IV (the fewest bytes that
    /// hold the value, 1..5, no leading zero byte unless the value
    /// itself is 0 — in which case exactly 1 zero byte is emitted; every
    /// published Appendix C example follows this rule, e.g. `Partial IV:
    /// 0x14` is 1 byte for value 20, and C.8's `Partial IV: 0x00` is 1
    /// byte for value 0, not 0 bytes).
    ///
    /// When EVERY field is absent (`partial_iv == null`, `kid == null`,
    /// `kid_context == null` — so the flag byte would be all-zero), the
    /// output is the TRULY EMPTY byte string (0 bytes total, omitting
    /// even the zero flag byte), NOT a single `0x00` byte: Appendix
    /// C.7's response option value is published as `0x (0 bytes)`, and
    /// `decode`'s own `bytes.len == 0` special case treats an empty
    /// input identically to an all-zero flag byte, so this is a
    /// lossless (and RFC-matching) shortest-encoding choice.
    pub fn encode(opt: OscoreOption, allocator: std.mem.Allocator) EncodeError![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(allocator);

        var piv_wide: [8]u8 = undefined;
        var piv_bytes: []const u8 = &.{};
        if (opt.partial_iv) |piv| {
            const n = pivEncodedLen(piv);
            if (n > max_partial_iv_bytes) return error.PartialIvTooLarge;
            std.mem.writeInt(u64, &piv_wide, piv, .big);
            piv_bytes = piv_wide[8 - n ..];
        }
        if (opt.kid_context) |kc| {
            if (kc.len > 255) return error.KidContextTooLong;
        }

        var flag: u8 = @intCast(piv_bytes.len);
        if (opt.kid != null) flag |= 0x08;
        if (opt.kid_context != null) flag |= 0x10;
        if (flag == 0) return list.toOwnedSlice(allocator); // nothing to convey — see doc comment

        try list.append(allocator, flag);
        try list.appendSlice(allocator, piv_bytes);
        if (opt.kid_context) |kc| {
            try list.append(allocator, @intCast(kc.len));
            try list.appendSlice(allocator, kc);
        }
        if (opt.kid) |kid| {
            try list.appendSlice(allocator, kid); // MUST be the last field, §6.1
        }
        return list.toOwnedSlice(allocator);
    }

    fn pivEncodedLen(piv: u64) usize {
        if (piv == 0) return 1;
        var n: usize = 0;
        var v = piv;
        while (v != 0) : (v >>= 8) n += 1;
        return n;
    }

    pub const DecodeError = error{ ReservedPartialIvLength, ReservedFlagBits, Truncated };

    /// §6.1 decoding. An EMPTY `bytes` slice is valid and decodes to
    /// `.{}` (every field absent) — Appendix C.7's response, which omits
    /// the OSCORE option value entirely (nonce/kid both implied by the
    /// request). Returned `kid`/`kid_context` slices BORROW `bytes`.
    pub fn decode(bytes: []const u8) DecodeError!OscoreOption {
        if (bytes.len == 0) return .{};
        const flag = bytes[0];
        if (flag & 0xE0 != 0) return error.ReservedFlagBits; // bits 5-7 MUST be zero, §6.1
        const n = flag & 0x07;
        if (n == 6 or n == 7) return error.ReservedPartialIvLength;
        const k = flag & 0x08 != 0;
        const h = flag & 0x10 != 0;

        var offset: usize = 1;
        var partial_iv: ?u64 = null;
        if (n > 0) {
            if (bytes.len < offset + n) return error.Truncated;
            var v: u64 = 0;
            for (bytes[offset .. offset + n]) |b| v = (v << 8) | b;
            partial_iv = v;
            offset += n;
        }

        var kid_context: ?[]const u8 = null;
        if (h) {
            if (bytes.len < offset + 1) return error.Truncated;
            const s = bytes[offset];
            offset += 1;
            if (bytes.len < offset + s) return error.Truncated;
            kid_context = bytes[offset .. offset + s];
            offset += s;
        }

        var kid: ?[]const u8 = null;
        if (k) {
            kid = bytes[offset..]; // "the 'kid' MUST be the last field", §6.1 — everything remaining
        }

        return .{ .partial_iv = partial_iv, .kid_context = kid_context, .kid = kid };
    }
};

// ── crypto cores (RFC 8613 §3.2.1 / §5.2 / §8) ───────────────────────────

pub const DeriveKeyError = std.mem.Allocator.Error;

/// RFC 8613 §3.2.1: `output = HKDF-Expand(HKDF-Extract(salt, ikm), info,
/// L)`. `out.len` IS this call's `L` (16 for a Sender/Recipient Key, 13
/// for the Common IV, at this module's only algorithm) — there is no
/// separate length parameter. `id` is the Sender ID or Recipient ID when
/// `label == .key`, and MUST be `&.{}` when `label == .iv` (deriving the
/// Common IV) — see `encodeInfo`'s doc comment; this function does not
/// itself enforce that calling convention, `deriveContext` does by
/// construction.
///
/// Construction:
/// 1. `info = encodeInfo(allocator, id, id_context, algorithm, label,
///    @intCast(out.len))` — already REAL, see its own doc comment
///    (validated byte-exact against Appendix C.1-C.3's `info` fields).
/// 2. `prk = std.crypto.kdf.hkdf.HkdfSha256.extract(master_salt,
///    master_secret)`. Per RFC 5869 §2.2 ("if not provided, salt is set
///    to a string of HashLen zeros") and §3.2's own restatement ("OSCORE
///    sets the salt default value to empty byte string, which is
///    converted to a string of zeroes"): passing an EMPTY `master_salt`
///    slice to `HkdfSha256.extract` (which HMACs with it as the HMAC
///    key) already produces exactly this zero-padded behavior — no
///    special-casing needed here, an empty `master_salt` slice is the
///    correct call for "no Master Salt was configured".
/// 3. `std.crypto.kdf.hkdf.HkdfSha256.expand(out, info, prk)`.
/// 4. Free `info` (allocated in step 1).
///
/// Byte-exact target: Appendix C.1-C.3's Sender Key / Recipient Key /
/// Common IV outputs, client AND server directions (`kat_test.zig`, via
/// `deriveContext`).
pub fn deriveKey(
    allocator: std.mem.Allocator,
    master_secret: []const u8,
    master_salt: []const u8,
    id: []const u8,
    id_context: ?[]const u8,
    algorithm: Algorithm,
    label: KeyLabel,
    out: []u8,
) DeriveKeyError!void {
    const info = try encodeInfo(allocator, id, id_context, algorithm, label, @intCast(out.len));
    defer allocator.free(info);
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const prk = Hkdf.extract(master_salt, master_secret);
    Hkdf.expand(out, info, prk);
}

pub const DeriveContextError = std.mem.Allocator.Error;

/// Fills a full `SecurityContext` from RFC 8613 §3.2's input parameters —
/// the usual entry point (rather than calling `deriveKey` three times by
/// hand). Per §3.2.1's own worked example: derives the Sender Key
/// (`deriveKey(..., id = sender_id, label = .key, out = &key[0..16])`),
/// the Recipient Key (`id = recipient_id, label = .key`), and the Common
/// IV (`id = &.{}` — ALWAYS empty, regardless of either endpoint's actual
/// Sender/Recipient ID, `label = .iv, out = &common_iv[0..13]`).
/// `sender.sequence_number` starts at 0 (§3.2.2); `recipient.replay_window`
/// starts at its zero value (`.initialized == false`).
///
/// Byte-exact target: the SAME Appendix C.1-C.3 vectors as `deriveKey`,
/// but exercised through this composed entry point.
pub fn deriveContext(
    allocator: std.mem.Allocator,
    master_secret: []const u8,
    master_salt: []const u8,
    id_context: ?[]const u8,
    sender_id: []const u8,
    recipient_id: []const u8,
    algorithm: Algorithm,
) DeriveContextError!SecurityContext {
    var sender_key: [key_length]u8 = undefined;
    try deriveKey(allocator, master_secret, master_salt, sender_id, id_context, algorithm, .key, &sender_key);

    var recipient_key: [key_length]u8 = undefined;
    try deriveKey(allocator, master_secret, master_salt, recipient_id, id_context, algorithm, .key, &recipient_key);

    // Common IV: id is ALWAYS the empty byte string (§3.2.1), regardless
    // of either endpoint's Sender/Recipient ID.
    var common_iv: [nonce_length]u8 = undefined;
    try deriveKey(allocator, master_secret, master_salt, &.{}, id_context, algorithm, .iv, &common_iv);

    return .{
        .common = .{ .algorithm = algorithm, .common_iv = common_iv },
        .sender = .{ .id = sender_id, .key = sender_key },
        .recipient = .{ .id = recipient_id, .key = recipient_key },
    };
}

pub const ComputeNonceError = error{IdTooLong};

/// RFC 8613 §5.2's AEAD nonce construction, Figure 8, byte-exact:
///
/// ```text
///  <- nonce_length-6 bytes -> <-- 5 bytes -->
/// +---+-------------------+--------+---------+-----+
/// | S |   zero padding    | ID_PIV | zero pad| PIV |----+
/// +---+-------------------+--------+---------+-----+    |
///                                                       |
///  <---------------- nonce_length ----------------->    |
/// +------------------------------------------------+    |
/// |                   Common IV                    |->(XOR)
/// +------------------------------------------------+    |
///                                                       |
///  <---------------- nonce_length ----------------->    |
/// +------------------------------------------------+    |
/// |                     Nonce                       |<---+
/// +------------------------------------------------+
/// ```
///
/// 1. `S = id_piv.len` (as a single byte) — fail (`error.IdTooLong`) if
///    `id_piv.len > id_piv_field_width` (7 bytes at this algorithm): the
///    ID_PIV field is left-padded INTO, never truncated to fit.
/// 2. `id_piv_padded`: `id_piv_field_width` bytes, `id_piv` right-aligned,
///    LEFT-padded with zero bytes (e.g. a 1-byte ID `0x01` becomes
///    `0x00000000000001` at `id_piv_field_width == 7`).
/// 3. `piv_padded`: 5 bytes, `partial_iv` (big-endian) right-aligned,
///    LEFT-padded with zero bytes — always fits, since `partial_iv <=
///    max_partial_iv` (`< 2^40`, 5 bytes' worth) is the Sender Sequence
///    Number's own §3.1 ceiling.
/// 4. `block = [S] || id_piv_padded || piv_padded` — exactly
///    `nonce_length` (13) bytes.
/// 5. `nonce[i] = block[i] ^ common_iv[i]` for every byte.
///
/// Byte-exact target: Appendix C.1's `sender nonce` (`id_piv` = the empty
/// client Sender ID, `S = 0`, an all-zero `block`, so the sender nonce
/// equals `common_iv` unchanged) and `recipient nonce` (`id_piv` = the
/// 1-byte Recipient ID `0x01`, `S = 1`) at `partial_iv = 0`, PLUS
/// Appendix C.4/C.6's message-vector nonces at `partial_iv = 0x14`
/// (`kat_test.zig`).
pub fn computeNonce(common_iv: [nonce_length]u8, id_piv: []const u8, partial_iv: u64) ComputeNonceError![nonce_length]u8 {
    if (id_piv.len > id_piv_field_width) return error.IdTooLong;

    var block = [_]u8{0} ** nonce_length;
    // Step 1: S, a single byte.
    block[0] = @intCast(id_piv.len);
    // Step 2: id_piv right-aligned (LEFT-zero-padded) into the
    // id_piv_field_width-byte field at bytes 1..1+id_piv_field_width.
    @memcpy(block[1 + (id_piv_field_width - id_piv.len) ..][0..id_piv.len], id_piv);
    // Step 3: partial_iv as 5 big-endian bytes, right-aligned in the
    // trailing 5-byte PIV field (always fits: partial_iv <= max_partial_iv
    // < 2^40 is the Sender Sequence Number's own §3.1 ceiling).
    var piv_wide: [8]u8 = undefined;
    std.mem.writeInt(u64, &piv_wide, partial_iv, .big);
    @memcpy(block[nonce_length - 5 ..], piv_wide[3..8]);
    // Steps 4+5: XOR the whole block with the Common IV.
    var nonce: [nonce_length]u8 = undefined;
    for (&nonce, block, common_iv) |*n, b, c| n.* = b ^ c;
    return nonce;
}

/// For a RESPONSE whose own OSCORE option omits the Partial IV (§5.2:
/// "If the Partial IV is not present in a response, the nonce from the
/// request is used"), the (id, Partial IV) pair the ORIGINAL REQUEST
/// used — supplied by the CALLER (per-exchange bookkeeping is the
/// sibling `coap` module's job, not this one's; see the module doc
/// comment's "Scope / non-goals").
pub const NonceSource = struct {
    id: []const u8,
    partial_iv: u64,
};

pub const ProtectError = error{
    OutOfMemory,
    IdTooLong,
    /// `ctx.sender.sequence_number` would exceed `max_partial_iv`
    /// (`>= 2^40`) — the Sender Context has exhausted every nonce this
    /// algorithm can safely generate and MUST be re-established (§7.2.1)
    /// before protecting another message.
    SequenceNumberExhausted,
};

/// The result of `protect`: the compressed COSE option value to carry in
/// the CoAP OSCORE option, plus the AEAD output to carry as the CoAP
/// payload (ciphertext-then-tag, RFC 8152 §5.2's own wire convention —
/// `ciphertext.len == plaintext.len + tag_length`).
pub const Protected = struct {
    option: OscoreOption,
    ciphertext: []u8,
};

/// Protects `plaintext` (the caller-assembled §5.3 plaintext: CoAP Code +
/// Class E options + optional `0xff`-marked payload — an OPAQUE byte
/// string to this function, see the module doc comment's "Scope /
/// non-goals") into an OSCORE-protected ciphertext + compressed COSE
/// option.
///
/// `ctx.sender.sequence_number` is read as THIS message's Partial IV,
/// then incremented on success (§3.2.2/§7.2.1: "the Sender Sequence
/// Number is incremented by 1 for each message protected using the
/// Sender Context") — covering both the universal REQUEST-protection
/// case and the minority "fresh-PIV response" case (§5.2 — e.g. an
/// Observe notification, or Appendix B.1.2's replay-less server). For the
/// OTHER, MAJORITY response case — reusing the ORIGINAL REQUEST's nonce
/// verbatim, emitting NO Partial IV in the response's own option (§5.2's
/// "typically... the same nonce to reduce message overhead") — the
/// caller does not call `protect` at all for the nonce; it calls
/// `computeNonce`/`buildAad`/the AEAD directly with the request's own
/// `(id, partial_iv)` (`protect` always consumes a fresh sequence
/// number, by design, so it cannot express "reuse an old nonce").
///
/// `aad.request_kid`/`aad.request_piv` MUST be the ORIGINAL REQUEST's kid
/// / Partial IV even when protecting a RESPONSE (§5.4).
///
/// `include_kid`: whether the option carries this message's own `kid`
/// (`ctx.sender.id`) — true for every request (§6.1's `k` flag), normally
/// false for a response.
///
/// `kid_context`: this message's own `kid context`, if the deployment
/// wants it carried (§5.1) — a policy decision, not derived from any
/// other parameter here.
///
/// Construction (RFC 8613 §8.1/§8.3, "Protecting the Request"/
/// "Protecting the Response"):
/// 1. `piv = ctx.sender.sequence_number`; fail
///    (`error.SequenceNumberExhausted`) if `piv > max_partial_iv`.
/// 2. `nonce = computeNonce(ctx.common.common_iv, ctx.sender.id, piv)`
///    (propagates `error.IdTooLong`).
/// 3. `full_aad = buildAad(allocator, aad)`.
/// 4. `ciphertext`: allocate `plaintext.len + tag_length` bytes;
///    `std.crypto.aead.aes_ccm.Aes128Ccm8.encrypt(ciphertext[0..plaintext.len],
///    ciphertext[plaintext.len..][0..tag_length], plaintext, full_aad,
///    nonce, ctx.sender.key)` — this module's target AEAD (see the
///    module doc comment's std-recon finding); tag appended after the
///    ciphertext (COSE's own convention, RFC 8152 §5.2).
/// 5. Free `full_aad`.
/// 6. `ctx.sender.sequence_number += 1` (only after a successful
///    encrypt — a failure before this point must not burn a nonce).
/// 7. Build the `OscoreOption`: `.partial_iv = piv`, `.kid = if
///    (include_kid) ctx.sender.id else null`, `.kid_context =
///    kid_context`.
pub fn protect(
    allocator: std.mem.Allocator,
    ctx: *SecurityContext,
    plaintext: []const u8,
    aad: AadParams,
    include_kid: bool,
    kid_context: ?[]const u8,
) ProtectError!Protected {
    const piv = ctx.sender.sequence_number;
    if (piv > max_partial_iv) return error.SequenceNumberExhausted;

    const nonce = try computeNonce(ctx.common.common_iv, ctx.sender.id, piv);

    const full_aad = try buildAad(allocator, aad);
    defer allocator.free(full_aad);

    const ciphertext = try allocator.alloc(u8, plaintext.len + tag_length);
    std.crypto.aead.aes_ccm.Aes128Ccm8.encrypt(
        ciphertext[0..plaintext.len],
        ciphertext[plaintext.len..][0..tag_length],
        plaintext,
        full_aad,
        nonce,
        ctx.sender.key,
    );

    // Only after a successful encrypt — a failure before this point must
    // not burn a nonce (§3.2.2/§7.2.1).
    ctx.sender.sequence_number += 1;

    return .{
        .option = .{
            .partial_iv = piv,
            .kid = if (include_kid) ctx.sender.id else null,
            .kid_context = kid_context,
        },
        .ciphertext = ciphertext,
    };
}

pub const UnprotectError = error{
    OutOfMemory,
    IdTooLong,
    /// Neither `option.partial_iv` nor `request_nonce_source` supplied a
    /// Partial IV to build the nonce from (§5.2's two sources).
    MissingPartialIv,
    /// `ctx.recipient.replay_window.check` rejected `piv` — a request
    /// only (§8.4: a response is never replay-checked).
    Replayed,
    /// The AEAD tag did not verify
    /// (`std.crypto.errors.AuthenticationError`).
    AuthenticationFailed,
};

/// Verifies + decrypts an OSCORE-protected message back to its §5.3
/// plaintext. `option` is the ALREADY-DECODED compressed COSE option
/// (`OscoreOption.decode`, already REAL); `ciphertext` is the OSCORE
/// CoAP payload, ciphertext-then-tag (`tag_length` trailing bytes).
///
/// `request_nonce_source`: required (non-`null`) exactly when
/// `option.partial_iv == null` AND this is a RESPONSE (§5.2: "If the
/// Partial IV is not present in a response, the nonce from the request
/// is used") — the ORIGINAL REQUEST's own `(id, partial_iv)`, tracked and
/// supplied by the caller (see the module doc comment's "Scope /
/// non-goals": exchange tracking is the sibling `coap` module's job).
/// Ignored when `option.partial_iv` is present.
///
/// `is_request`: whether replay checking applies at all (§8.4: only
/// requests are replay-checked; a response's freshness is implied by the
/// request/response exchange itself).
///
/// Construction (RFC 8613 §8.2/§8.4, "Verifying the Request"/"Verifying
/// the Response"):
/// 1. Resolve `(id_piv, piv)`: `(ctx.recipient.id, option.partial_iv.?)`
///    if `option.partial_iv` is present, else
///    `(request_nonce_source.?.id, request_nonce_source.?.partial_iv)` —
///    fail (`error.MissingPartialIv`) if neither is available.
/// 2. If `is_request`: `ctx.recipient.replay_window.check(piv)`; fail
///    (`error.Replayed`) if it returns `false`. Checked BEFORE
///    decrypting (cheap rejection without spending an AEAD
///    verification) — but `replay_window.update` is only called AFTER
///    step 5 succeeds (see `ReplayWindow.update`'s own doc comment: never
///    record an unverified sequence number as seen).
/// 3. `nonce = computeNonce(ctx.common.common_iv, id_piv, piv)`.
/// 4. `full_aad = buildAad(allocator, aad)`.
/// 5. Split `ciphertext` into `body = ciphertext[0..ciphertext.len -
///    tag_length]` / `tag = ciphertext[ciphertext.len - tag_length..]`;
///    `plaintext`: allocate `body.len` bytes;
///    `std.crypto.aead.aes_ccm.Aes128Ccm8.decrypt(plaintext, body, tag.*,
///    full_aad, nonce, ctx.recipient.key)`; map
///    `error.AuthenticationFailed` through unchanged (same error name,
///    both sets define it).
/// 6. Free `full_aad`.
/// 7. If `is_request` and step 5 succeeded:
///    `ctx.recipient.replay_window.update(piv)`.
/// 8. Return `plaintext`.
pub fn unprotect(
    allocator: std.mem.Allocator,
    ctx: *SecurityContext,
    option: OscoreOption,
    ciphertext: []const u8,
    aad: AadParams,
    request_nonce_source: ?NonceSource,
    is_request: bool,
) UnprotectError![]u8 {
    // Step 1: resolve (id_piv, piv) — §5.2's two possible nonce sources.
    var id_piv: []const u8 = undefined;
    var piv: u64 = undefined;
    if (option.partial_iv) |p| {
        id_piv = ctx.recipient.id;
        piv = p;
    } else if (request_nonce_source) |src| {
        id_piv = src.id;
        piv = src.partial_iv;
    } else {
        return error.MissingPartialIv;
    }

    // Step 2: replay check (requests only, §8.4) — BEFORE decrypting
    // (cheap rejection), but the window is only UPDATED after the AEAD
    // verifies (step 7; see ReplayWindow.update's doc comment).
    if (is_request and !ctx.recipient.replay_window.check(piv)) return error.Replayed;

    // Step 3: nonce.
    const nonce = try computeNonce(ctx.common.common_iv, id_piv, piv);

    // Step 4: AAD.
    const full_aad = try buildAad(allocator, aad);
    defer allocator.free(full_aad);

    // Step 5: split ciphertext-then-tag, then AEAD-open. A payload too
    // short to even carry a tag cannot possibly authenticate — fail
    // closed with the same typed error as a tag mismatch (never a
    // panic/underflow on malformed input).
    if (ciphertext.len < tag_length) return error.AuthenticationFailed;
    const body = ciphertext[0 .. ciphertext.len - tag_length];
    const tag: [tag_length]u8 = ciphertext[ciphertext.len - tag_length ..][0..tag_length].*;

    const plaintext = try allocator.alloc(u8, body.len);
    errdefer allocator.free(plaintext);
    std.crypto.aead.aes_ccm.Aes128Ccm8.decrypt(
        plaintext,
        body,
        tag,
        full_aad,
        nonce,
        ctx.recipient.key,
    ) catch return error.AuthenticationFailed;

    // Step 7: record the now-VERIFIED sequence number (requests only).
    if (is_request) ctx.recipient.replay_window.update(piv);

    // Step 8.
    return plaintext;
}

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}

test "meta.deps is empty (coap-agnostic — see module doc comment)" {
    try std.testing.expectEqual(0, meta.deps.len);
}

test "algorithm/wire size constants match AES-CCM-16-64-128" {
    try std.testing.expectEqual(@as(i16, 10), @intFromEnum(Algorithm.aes_ccm_16_64_128));
    try std.testing.expectEqual(@as(usize, 16), key_length);
    try std.testing.expectEqual(@as(usize, 13), nonce_length);
    try std.testing.expectEqual(@as(usize, 8), tag_length);
    try std.testing.expectEqual(@as(usize, 7), id_piv_field_width);
    try std.testing.expectEqual(@as(u64, (1 << 40) - 1), max_partial_iv);
}

test "KeyLabel.text matches RFC 8613 \u{a7}3.2.1's ASCII labels" {
    try std.testing.expectEqualStrings("Key", KeyLabel.key.text());
    try std.testing.expectEqualStrings("IV", KeyLabel.iv.text());
}

test "encodeInfo: worked example from RFC 8613 \u{a7}3.2.1's own prose" {
    // "if the algorithm AES-CCM-16-64-128 ... is used, the integer value
    // for alg_aead is 10, the value for L is 16 for keys and 13 for the
    // Common IV" — cross-checked against Appendix C.1 in kat_test.zig;
    // this is just a standalone smoke test of the encoder's shape.
    const allocator = std.testing.allocator;
    const info = try encodeInfo(allocator, &.{0x01}, null, .aes_ccm_16_64_128, .key, 16);
    defer allocator.free(info);
    // array(5) bstr(1)=01 null alg(10) text(3)"Key" uint(16)
    try std.testing.expectEqualSlices(u8, &.{ 0x85, 0x41, 0x01, 0xf6, 0x0a, 0x63, 'K', 'e', 'y', 0x10 }, info);
}

test "encodeAadArray: empty kid/piv/options round-trips through the CBOR shape" {
    const allocator = std.testing.allocator;
    const arr = try encodeAadArray(allocator, .{ .request_kid = &.{}, .request_piv = &.{} });
    defer allocator.free(arr);
    // array(5) uint(1) array(1) uint(10) bstr(0) bstr(0) bstr(0)
    try std.testing.expectEqualSlices(u8, &.{ 0x85, 0x01, 0x81, 0x0a, 0x40, 0x40, 0x40 }, arr);
}

test "encodeEncStructure wraps external_aad as Enc_structure's third element" {
    const allocator = std.testing.allocator;
    const enc = try encodeEncStructure(allocator, &.{ 0xAA, 0xBB });
    defer allocator.free(enc);
    // array(3) text(8)"Encrypt0" bstr(0) bstr(2)=AABB
    var expected = std.ArrayList(u8).empty;
    defer expected.deinit(allocator);
    try expected.appendSlice(allocator, &.{0x83});
    try expected.appendSlice(allocator, &.{0x68});
    try expected.appendSlice(allocator, "Encrypt0");
    try expected.appendSlice(allocator, &.{ 0x40, 0x42, 0xAA, 0xBB });
    try std.testing.expectEqualSlices(u8, expected.items, enc);
}

test "OscoreOption round-trips through encode/decode, including present-but-empty kid" {
    const allocator = std.testing.allocator;
    const opt = OscoreOption{ .partial_iv = 20, .kid = &.{} };
    const bytes = try opt.encode(allocator);
    defer allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0x09, 0x14 }, bytes);
    const decoded = try OscoreOption.decode(bytes);
    try std.testing.expectEqual(@as(?u64, 20), decoded.partial_iv);
    try std.testing.expect(decoded.kid != null);
    try std.testing.expectEqual(@as(usize, 0), decoded.kid.?.len);
    try std.testing.expect(decoded.kid_context == null);
}

test "OscoreOption.decode on an empty slice returns every field absent" {
    const decoded = try OscoreOption.decode(&.{});
    try std.testing.expect(decoded.partial_iv == null);
    try std.testing.expect(decoded.kid == null);
    try std.testing.expect(decoded.kid_context == null);
}

test "OscoreOption.decode rejects reserved Partial-IV lengths 6 and 7" {
    try std.testing.expectError(error.ReservedPartialIvLength, OscoreOption.decode(&.{0x06}));
    try std.testing.expectError(error.ReservedPartialIvLength, OscoreOption.decode(&.{0x07}));
}

test "OscoreOption.decode rejects reserved flag bits 5-7" {
    try std.testing.expectError(error.ReservedFlagBits, OscoreOption.decode(&.{0x20}));
}

test "OscoreOption.decode rejects a truncated Partial IV" {
    try std.testing.expectError(error.Truncated, OscoreOption.decode(&.{0x02})); // n=2 but no bytes follow
}

test "ReplayWindow: first sequence number is always accepted, then becomes a replay" {
    var rw = ReplayWindow{};
    try std.testing.expect(rw.check(0));
    rw.update(0);
    try std.testing.expect(!rw.check(0)); // exact duplicate
}

test "ReplayWindow: higher sequence numbers always accepted and slide the window" {
    var rw = ReplayWindow{ .window_size = 4 };
    rw.update(0);
    try std.testing.expect(rw.check(5));
    rw.update(5); // shift = 5 >= window_size(4) -> mask cleared entirely
    try std.testing.expect(!rw.check(5)); // now the highest, a duplicate
    try std.testing.expect(rw.check(1)); // diff = 4, within window, but never independently seen — allowed
    try std.testing.expect(rw.check(2)); // diff = 3, not yet seen
    rw.update(2);
    try std.testing.expect(!rw.check(2)); // now seen
    try std.testing.expect(!rw.check(0)); // diff = 5 > window_size(4) -> too old
}

test "ReplayWindow: a large forward jump correctly re-bases and still flags the old highest as seen" {
    var rw = ReplayWindow{};
    rw.update(0);
    rw.update(5); // shift = 5, well within the default window (32)
    try std.testing.expect(!rw.check(0)); // the old highest_seen must still read as seen
    try std.testing.expect(!rw.check(5));
    try std.testing.expect(rw.check(6));
}

test "ReplayWindow: a jump at/beyond window_size clears the old mask entirely" {
    var rw = ReplayWindow{ .window_size = 4 };
    rw.update(0);
    rw.update(10); // shift = 10 >= window_size(4)
    try std.testing.expect(rw.check(7)); // diff = 3, nothing recorded, so accepted
    try std.testing.expect(rw.check(6)); // diff = 4 == window_size -> still in range, not seen -> allowed
    try std.testing.expect(!rw.check(0)); // far outside the window now
}

fn fuzzOscoreOptionDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    // §6.1's wire-facing decoder: arbitrary bytes must only ever produce a
    // typed error (reserved bits/length, truncation) or a borrowed-slice
    // struct — never a panic or OOB read.
    const opt = OscoreOption.decode(buf[0..len]) catch return;
    _ = opt;
}

test "fuzz: OscoreOption.decode never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzOscoreOptionDecode, .{});
}

test "ReplayWindow: oversized window_size (>64) + hostile diff/shift does not panic (audit F1)" {
    // window_size is a u7 (up to 127) but the u64 mask caps the real window at
    // 64; without the effWindow clamp a diff/shift of 64..126 @intCast'd to u6
    // and panicked. A misconfigured window must stay safe on any input.
    var rw = ReplayWindow{ .window_size = 100 };
    rw.update(200); // initialize highest_seen
    try std.testing.expect(!rw.check(130)); // diff = 70 > effWindow(64) -> out of window, no panic
    rw.update(130); // diff 70 > effWindow -> skipped, must not panic
    rw.update(270); // shift 70 >= effWindow(64) -> mask reset, must not panic
    try std.testing.expectEqual(@as(u64, 270), rw.highest_seen);
}
