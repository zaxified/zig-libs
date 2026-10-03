// SPDX-License-Identifier: MIT
//! presign — GG20 threshold-ECDSA signing as one state machine per signer.
//!
//! R. Gennaro, S. Goldfeder, "One Round Threshold ECDSA with Identifiable
//! Abort" (IACR ePrint 2020/540) §3.2. Each signer runs its own `Party`
//! holding nothing but its own `root.KeyShare`; parties talk only through
//! the byte messages `advance` returns and accepts. Phases 1–6 do not depend
//! on the message, so they run ahead of time and end in a `Presignature`;
//! signing a message is then ONE round (Phase 7): every signer broadcasts
//! `s_i = m·k_i + r·σ_i` and anyone holding the public half combines.
//!
//! ## Rounds (the paper's phases, one `advance` call each)
//!
//! | call | consumes | emits |
//! |---|---|---|
//! | `advance` #1 | — | bc `C_i = H(sid,i,Γ_i,ρ_i)`, `c_i = Enc_i(k_i)`; p2p range proof of `c_i` under each verifier's aux (Phase 1 + MtA msg 1) |
//! | `advance` #2 | #1 | p2p MtA response for `k_j·γ_i` + Π^MtA, MtAwc response for `k_j·w_i` + Π^MtAwc (Phase 2) |
//! | `advance` #3 | #2 | bc `δ_i`, `T_i = σ_i·G + ℓ_i·H`, proof of `(σ_i, ℓ_i)` (Phase 3) |
//! | `advance` #4 | #3 | bc `Γ_i`, `ρ_i`, Schnorr proof of `γ_i` (Phase 4) |
//! | `advance` #5 | #4 | bc `R̄_i = k_i·R`; p2p proof that `R̄_i` matches `c_i` (Phase 5) |
//! | `advance` #6 | #5 | bc `S_i = σ_i·R`, proof that `S_i` and `T_i` share `σ_i` (Phase 6) |
//! | `finish` | #6 | — → `Presignature` |
//! | `Presignature.signShare` | — | bc `s_i` (Phase 7) |
//! | `PresignaturePublic.combine` | Phase 7 shares | the signature |
//!
//! Every check the paper lists is made before anything secret-dependent is
//! sent on: Phase 5 checks `Σ R̄_j = G` (so `R = k⁻¹·G` for the `k` inside the
//! ciphertexts), Phase 6 checks `Σ S_j = X` (so the `σ_j` add up to `k·x`).
//! Once both hold the signature is guaranteed to verify, which is what makes
//! releasing `s_i` safe — an `s_i` released against a wrong `R` would leak
//! the signer's key share (paper §4.3). The in-process driver this replaced
//! (`signing.signWithShares` before 2026-10-02) had neither check; it relied
//! on the final self-check, which is enough only when one process holds
//! every share.
//!
//! ## Identifiable abort
//!
//! Any failed check aborts the party: the call returns `error.ProtocolAbort`
//! and `Party.abort` names the fault and, where the paper's §4.2 can, the
//! culprit's index — every proof failure (types 1, 2, 3, 4, 6), every
//! malformed, misaddressed, duplicate or missing message, and in Phase 7 a
//! signature share failing `s_j·R == m·R̄_j + r·S_j` (type 8). Types 5 and 7
//! (`Σ R̄_j ≠ G`, `Σ S_j ≠ X` with every proof valid) abort with
//! `culprit == null` and keep the session's nonce material: the paper's §4.3
//! opening names the party — every signer calls `openAbort` (its opening, a
//! signed broadcast) and `identify` on everyone's openings, which returns the
//! culprit and wipes the secrets. What is opened never includes the key
//! share (type 7 opens the `k_i·w_j` masks and proves `S_i = σ_i·R` by DLEQ
//! against a `σ_i·G` everyone recomputes, instead of revealing `σ_i`).
//!
//! ## Signed messages and broadcast consistency (in the protocol, not assumed)
//!
//! Every message ends with its sender's Ed25519 signature over
//! `message_domain || header || SHA-256(body)` (`signedBytes`), under the
//! `message_key` each signer publishes with its key share; a message whose
//! signature fails aborts with `bad_signature`, naming the sender.
//!
//! GG20 assumes a reliable broadcast channel. Here every message of a round
//! that follows a broadcast round starts with an attestation block: for
//! each signer, the body hash and signature of that signer's previous-round
//! broadcast as the sender received it. A receiver compares every entry with
//! its own view before using anything from the round. A different body under
//! a valid signature is two signed versions of one broadcast: the signer who
//! made them is named (`equivocation`). A different body whose signature
//! fails names the sender of the attestation instead — it misquoted. Without
//! this, a signer showing different broadcasts to different peers would make
//! the honest ones fail each other's proofs and blame each other. Phase-7
//! shares attest the Phase-6 broadcasts; `combine` checks them the same way.
//!
//! ## What the caller must provide
//!
//! - **Delivery.** Hand in only the messages of the round being run
//!   (`peekHeader().round`), buffering early ones. The signature, not the
//!   transport, decides who sent a message; a party's own messages coming
//!   back are ignored.
//! - **A fresh session id** per presigning session, agreed by all signers.
//!   The id on the wire is `SHA-256(session_domain || sid || X || t ||
//!   signers)`, so a signer configured with another set or key is refused at
//!   the first header; it is bound into every message and every proof of this
//!   file.
//! - **Timeouts.** A peer that never sends is the caller's to detect; once
//!   the inbox is handed in, a missing message is a `missing_message` fault.
//! - **One presignature, one message.** `signShare` wipes `k_i`/`σ_i` and
//!   refuses a second call; a presignature must never be copied (two
//!   messages under one `R` reveal the key).

const std = @import("std");
const paillier = @import("paillier");
const root = @import("root.zig");
const mta = @import("mta.zig");
const zkproofs = @import("zkproofs.zig");
const ecproofs = @import("ecproofs.zig");
const signing = @import("signing.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Ed25519 = std.crypto.sign.Ed25519;
const Scalar = root.Scalar;
const Secp256k1 = root.Secp256k1;
const Element = root.Element;
const Ns = root.Ns;
const Ne = root.Ne;

pub const SessionId = [32]u8;

pub const wire_version: u8 = 2;
/// `version(1) || round(1) || sid(32) || from(4) || to(4)`; `to == 0` marks a
/// broadcast (party indices start at 1). A message is `header || body ||
/// signature`: the body is the attestation block (rounds with
/// `hasAttestation`) followed by the round's payload, and the last
/// `signature_length` bytes are the sender's Ed25519 signature (see
/// `signedBytes`).
pub const header_length = 1 + 1 + 32 + 4 + 4;
pub const signature_length = 64;
/// One attestation entry: `SHA-256(body) || signature` of one signer's
/// broadcast of the previous round, as this sender received it.
pub const attestation_entry_length = 32 + signature_length;
/// Phase 7 messages carry this round number.
pub const sign_round: u8 = 7;

pub const gamma_commit_domain = "threshold_ecdsa/presign/gamma-commit/v1";
pub const session_domain = "threshold_ecdsa/presign/session/v1";
/// Domain of every message signature (`signedBytes`).
pub const message_domain = "threshold_ecdsa/presign/message/v2";

/// Rounds whose messages attest the previous round's broadcasts: every round
/// that follows a broadcast round (1, 3, 4, 5, 6), Phase 7 included.
pub fn hasAttestation(round: u8) bool {
    return round == 2 or (round >= 4 and round <= sign_round);
}

/// The §4.3 opening round: after a type-5 or type-7 abort every signer
/// broadcasts what it must reveal (`Party.openAbort`).
pub const open_round: u8 = 8;

/// `SHA-256(body)` and the sender's signature over `signedBytes(header, that
/// hash)`. Self-contained evidence: with the header rebuilt from (session,
/// round, sender, broadcast), anyone holding the sender's key can check it.
pub const Attestation = struct {
    body_hash: [32]u8,
    signature: [signature_length]u8,
};

/// What a message signature signs: `message_domain || header || SHA-256(body)`.
/// The header fixes session, round, sender and recipient (0 = broadcast), so
/// a signature on a p2p message or on another round can never stand in for
/// a broadcast of this one.
pub fn signedBytes(header: [header_length]u8, body_hash: [32]u8) [message_domain.len + header_length + 32]u8 {
    var out: [message_domain.len + header_length + 32]u8 = undefined;
    out[0..message_domain.len].* = message_domain.*;
    out[message_domain.len..][0..header_length].* = header;
    out[message_domain.len + header_length ..][0..32].* = body_hash;
    return out;
}

fn sign(kp: Ed25519.KeyPair, header: [header_length]u8, body: []const u8) Attestation {
    var h: [32]u8 = undefined;
    Sha256.hash(body, &h, .{});
    const sig = kp.sign(&signedBytes(header, h), null) catch unreachable; // a key pair from a seed signs
    return .{ .body_hash = h, .signature = sig.toBytes() };
}

fn verifyAttestation(key: Ed25519.PublicKey, header: [header_length]u8, a: Attestation) bool {
    Ed25519.Signature.fromBytes(a.signature).verify(&signedBytes(header, a.body_hash), key) catch return false;
    return true;
}

fn broadcastHeader(sid: SessionId, round: u8, from: u32) [header_length]u8 {
    var out: [header_length]u8 = undefined;
    (Header{ .round = round, .sid = sid, .from = from, .to = null }).write(&out);
    return out;
}

fn readAttestation(bytes: *const [attestation_entry_length]u8) Attestation {
    return .{ .body_hash = bytes[0..32].*, .signature = bytes[32..][0..signature_length].* };
}

fn writeAttestation(a: Attestation, out: *[attestation_entry_length]u8) void {
    out[0..32].* = a.body_hash;
    out[32..][0..signature_length].* = a.signature;
}

/// Compares an attestation block (one entry per signer, signer order) with
/// `mine`, this party's view of broadcast round `round`. A different body
/// with a valid signature by its sender is two signed versions of one
/// broadcast — that sender equivocated; an invalid signature means the
/// block's sender (`from`) lied about what it received.
fn checkAttestations(sid: SessionId, round: u8, signers: []const u32, keys: []const Ed25519.PublicKey, mine: []const Attestation, block: []const u8, from: u32) ?Abort {
    for (signers, keys, mine, 0..) |idx, key, m, pos| {
        const entry = readAttestation(block[pos * attestation_entry_length ..][0..attestation_entry_length]);
        if (std.mem.eql(u8, &entry.body_hash, &m.body_hash)) continue;
        if (verifyAttestation(key, broadcastHeader(sid, round, idx), entry)) return .{ .culprit = idx, .fault = .equivocation };
        return .{ .culprit = from, .fault = .equivocation };
    }
    return null;
}

pub const Header = struct {
    round: u8,
    sid: SessionId,
    from: u32,
    /// `null`: broadcast.
    to: ?u32,

    fn write(self: Header, out: *[header_length]u8) void {
        out[0] = wire_version;
        out[1] = self.round;
        out[2..34].* = self.sid;
        std.mem.writeInt(u32, out[34..38], self.from, .big);
        std.mem.writeInt(u32, out[38..42], self.to orelse 0, .big);
    }
};

/// The header of a message, so the transport can check `from` against the
/// authenticated sender and route `to` before handing the bytes in.
pub fn peekHeader(bytes: []const u8) error{InvalidEncoding}!Header {
    if (bytes.len < header_length or bytes[0] != wire_version) return error.InvalidEncoding;
    const from = std.mem.readInt(u32, bytes[34..38], .big);
    const to = std.mem.readInt(u32, bytes[38..42], .big);
    if (from == 0) return error.InvalidEncoding;
    return .{ .round = bytes[1], .sid = bytes[2..34].*, .from = from, .to = if (to == 0) null else to };
}

pub const Fault = enum {
    /// A message that does not decode (bad header, bad length, bad field).
    malformed_message,
    /// Wrong session, wrong round, wrong recipient, or a sender outside the
    /// signing set.
    unexpected_message,
    duplicate_message,
    missing_message,
    /// A peer's published Paillier key or aux tuple failed the checks every
    /// prover runs before committing a secret under it (audit F1/F2/F3).
    invalid_peer_keys,
    /// Phase 2: range proof on `c_j` (type 1).
    range_proof,
    /// Phase 2: Bob's proof on the `k·γ` response (type 1).
    mta_proof,
    /// Phase 2: Bob's proof on the `k·w` response (type 1).
    mtawc_proof,
    /// Phase 3: proof of `(σ_j, ℓ_j)` behind `T_j` (type 2).
    pedersen_proof,
    /// Phase 4: `Γ_j` does not open `C_j` (type 3).
    gamma_decommitment,
    /// Phase 4: proof of `γ_j` (type 3).
    gamma_proof,
    /// Phase 5: proof that `R̄_j` matches `c_j` (type 4).
    pdl_proof,
    /// Phase 5: `Σ R̄_j ≠ G` with every proof valid (type 5; unattributed
    /// until the §4.3 opening, see `Party.openAbort`).
    r_bar_sum,
    /// Phase 6: proof that `S_j` and `T_j` share `σ_j` (type 6).
    st_proof,
    /// Phase 6: `Σ S_j ≠ X` with every proof valid (type 7; unattributed
    /// until the §4.3 opening).
    s_sum,
    /// Phase 7: `s_j·R ≠ m·R̄_j + r·S_j` (type 8).
    sig_share,
    /// Two signers saw different broadcasts from one sender. The culprit is
    /// the sender when both versions carry its valid signature, or the
    /// signer whose attestation carries a signature that does not verify.
    /// Stops the session BEFORE the inconsistent views make honest signers
    /// blame each other.
    equivocation,
    /// A message whose Ed25519 signature does not verify under its sender's
    /// `message_key` (or that is too short to carry one).
    bad_signature,
    /// `δ = 0`, `R` = identity, `r = 0` or `s = 0` — probability ~2⁻²⁵⁶
    /// unless someone cheated in a way no single check pins on them.
    degenerate,
};

pub const Abort = struct {
    /// The party the fault is attributed to, or null (types 5 and 7 before
    /// the §4.3 opening, and `degenerate`).
    culprit: ?u32,
    fault: Fault,
};

pub const Error = std.mem.Allocator.Error || error{
    /// A check failed; `Party.abort` / the `abort` out-parameter says which.
    ProtocolAbort,
    /// A call out of order, or on a party that already aborted or finished.
    InvalidState,
    /// Bad local input: signer set, session, key share inconsistent with
    /// itself or with the public keys.
    InvalidParameters,
    /// `signShare` on a presignature that was already used.
    PresignatureUsed,
};

pub const Outgoing = struct {
    /// `null`: broadcast to every other signer.
    to: ?u32,
    bytes: []u8,
};

pub const Outbox = struct {
    messages: []Outgoing,

    pub fn deinit(self: Outbox, allocator: std.mem.Allocator) void {
        for (self.messages) |m| allocator.free(m.bytes);
        allocator.free(self.messages);
    }
};

const State = enum { round1, round2, round3, round4, round5, round6, finish, done, aborted, opening, identify };

/// What one signer keeps per peer for the GG20 §4.3 opening, until the
/// presignature is finished (or the opening is done).
const PeerOpen = struct {
    /// The signed round-2 message this signer (as Alice) got from the peer.
    round2: ?[]u8 = null,
    /// SECRET until opened: this signer's (as Bob) mask `β'` and Paillier
    /// randomness in the `k_j·γ_i` response it sent the peer.
    gamma_beta_prime: [zkproofs.beta_prime_bytes]u8 = @splat(0),
    gamma_r: paillier.Fe = undefined,
    /// SECRET until opened: its mask `ν'` in the `k_j·w_i` response.
    w_beta_prime: [zkproofs.beta_prime_bytes]u8 = @splat(0),
};

/// `sid || u32 index`: the context every proof of `index` is bound to.
fn proofContext(sid: SessionId, index: u32) [36]u8 {
    var out: [36]u8 = undefined;
    out[0..32].* = sid;
    std.mem.writeInt(u32, out[32..36], index, .big);
    return out;
}

fn commitGamma(sid: SessionId, index: u32, big_gamma: Element, blind: [32]u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update(gamma_commit_domain);
    h.update(&sid);
    var idx: [4]u8 = undefined;
    std.mem.writeInt(u32, &idx, index, .big);
    h.update(&idx);
    h.update(&big_gamma.toBytes());
    h.update(&blind);
    return h.finalResult();
}

fn randomScalar(random: std.Random) Scalar {
    var buf: [48]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    random.bytes(&buf);
    return Scalar.fromBytes48(buf, .big);
}

/// `int(bytes32) mod q`, the reduction `std.crypto.sign.ecdsa` applies to
/// both the message digest and `R.x`, so `m` and `r` here are the values
/// std's verifier recomputes.
fn scalarFromHash32(bytes32: [32]u8) Scalar {
    var wide = [_]u8{0} ** 48;
    wide[16..48].* = bytes32;
    return Scalar.fromBytes48(wide, .big);
}

fn decodeScalar(bytes: [Ns]u8) ?Scalar {
    return Scalar.fromBytes(bytes, .big) catch null;
}

fn ciphertextBytes(c: paillier.Ciphertext) [paillier.modulus_sq_bytes]u8 {
    var buf: [paillier.modulus_sq_bytes]u8 = undefined;
    c.toBytes(&buf) catch unreachable; // fixed-width buffer
    return buf;
}

fn appendLenPrefixed(list: *std.ArrayList(u8), allocator: std.mem.Allocator, data: []const u8) std.mem.Allocator.Error!void {
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
    try list.appendSlice(allocator, &len_buf);
    try list.appendSlice(allocator, data);
}

/// Reads one length-prefixed field; null when it runs off the end.
fn readLenPrefixed(bytes: []const u8, offset: *usize) ?[]const u8 {
    if (bytes.len - offset.* < 4) return null;
    const len = std.mem.readInt(u32, bytes[offset.*..][0..4], .big);
    offset.* += 4;
    if (bytes.len - offset.* < len) return null;
    const out = bytes[offset.*..][0..len];
    offset.* += len;
    return out;
}

/// What one signer knows about another (and about itself, at its own slot).
const Peer = struct {
    index: u32,
    pk: paillier.PublicKey,
    aux: root.AuxParams,
    /// `W_j = λ_j·X_j`.
    w_point: Element,
    /// Ed25519 key of this signer's messages.
    message_key: Ed25519.PublicKey,
    commitment: [32]u8 = undefined,
    c_k: paillier.Ciphertext = undefined,
    delta: Scalar = undefined,
    t_point: Element = undefined,
    big_gamma: Element = undefined,
    r_bar: Element = undefined,
    s_point: Element = undefined,
};

/// The secret state of one signer. Wiped by `deinit`, by an abort, and when
/// it moves into the `Presignature`.
const Secrets = struct {
    k: Scalar,
    gamma: Scalar,
    w: Scalar,
    ell: Scalar,
    delta: Scalar,
    sigma: Scalar,
    gamma_blind: [32]u8,
    /// Paillier randomness of `c_k`: the range and PDL proofs' witness.
    r_k: paillier.Fe,
};

/// One signer's side of one GG20 presigning session.
pub const Party = struct {
    allocator: std.mem.Allocator,
    share: root.KeyShare,
    sid: SessionId,
    /// Ascending signer indices, owned.
    signers: []u32,
    /// Position of this party in `signers` (and in `peers`).
    me: usize,
    peers: []Peer,
    state: State = .round1,
    secrets: Secrets = undefined,
    r_point: Element = undefined,
    r: Scalar = undefined,
    /// This party's message-signing key (from `share.message_seed`).
    message_kp: Ed25519.KeyPair,
    /// This party's view of the latest broadcast round, one attestation per
    /// signer position, its own included: attested at the head of the next
    /// round's messages and compared with every peer's (the in-protocol
    /// substitute for the reliable broadcast GG20 assumes; review F1,
    /// 2026-10-02 — signed since 2026-10-03, so the equivocator is named).
    last_bc: []Attestation,
    /// Attestation of this party's own broadcast of the current round.
    own_bc: Attestation = undefined,
    /// Per position: what the §4.3 opening needs (see `PeerOpen`).
    open: []PeerOpen,
    /// This party's own opening message, once sent.
    own_open: ?[]u8 = null,
    /// Set when a call returns `error.ProtocolAbort`.
    abort: ?Abort = null,

    /// `signers` is the signing set (any order, no duplicates, containing
    /// `share.index`, at least `share.t` and at least 2 members); every
    /// signer must pass the same set and the same `sid`. Checks that the
    /// public keys cover every signer and that `Σ λ_j·X_j` over the set is
    /// the group key, so inconsistent key material fails here rather than
    /// as an unattributed abort later. `share` is borrowed: its
    /// `public_keys` must outlive the party.
    pub fn init(allocator: std.mem.Allocator, share: root.KeyShare, signers: []const u32, sid: SessionId) Error!Party {
        if (signers.len < 2 or signers.len < share.t or signers.len > share.n) return error.InvalidParameters;
        const sorted = try allocator.dupe(u32, signers);
        errdefer allocator.free(sorted);
        std.mem.sort(u32, sorted, {}, std.sort.asc(u32));
        for (sorted[1..], 0..) |s, i| if (s == sorted[i]) return error.InvalidParameters;
        if (sorted[0] == 0) return error.InvalidParameters;
        const me = std.mem.indexOfScalar(u32, sorted, share.index) orelse return error.InvalidParameters;
        for (sorted) |idx| {
            var count: usize = 0;
            for (share.public_keys.entries) |e| count += @intFromBool(e.index == idx);
            if (count != 1) return error.InvalidParameters;
        }

        const peers = try allocator.alloc(Peer, sorted.len);
        errdefer allocator.free(peers);
        const message_kp = Ed25519.KeyPair.generateDeterministic(share.message_seed) catch return error.InvalidParameters;
        var x_sum = Secp256k1.identityElement;
        for (sorted, peers) |idx, *p| {
            const pub_keys = share.public_keys.get(idx) orelse return error.InvalidParameters;
            const x_pt = pub_keys.verifying_share.point() catch return error.InvalidParameters;
            const lambda = signing.lagrangeCoefficient(sorted, idx);
            const w_pt = x_pt.mulPublic(lambda.toBytes(.big), .big) catch return error.InvalidParameters;
            x_sum = x_sum.add(w_pt);
            p.* = .{
                .index = idx,
                .pk = pub_keys.paillier_pk,
                .aux = pub_keys.aux,
                .w_point = Element.fromPoint(w_pt) catch return error.InvalidParameters,
                .message_key = Ed25519.PublicKey.fromBytes(pub_keys.message_key) catch return error.InvalidParameters,
            };
        }
        // This party's own share must be the one its public entry announces.
        const own_x = share.public_keys.get(share.index).?.verifying_share;
        if (!std.mem.eql(u8, &own_x.toBytes(), &share.verifying_share.toBytes())) return error.InvalidParameters;
        const x_g = Secp256k1.basePoint.mul(share.secret_share.toBytes(.big), .big) catch return error.InvalidParameters;
        if (!x_g.equivalent(own_x.point() catch return error.InvalidParameters)) return error.InvalidParameters;
        // …and so must its message key.
        if (!std.mem.eql(u8, &message_kp.public_key.toBytes(), &share.public_keys.get(share.index).?.message_key)) return error.InvalidParameters;
        const group_pt = share.group_public_key.point() catch return error.InvalidParameters;
        if (!x_sum.equivalent(group_pt)) return error.InvalidParameters;

        // The session id on the wire binds the caller's `sid` to the group
        // key, the threshold and the signing set: signers configured with a
        // different set fail at the first header instead of later, at a proof
        // (review F7).
        var h = Sha256.init(.{});
        h.update(session_domain);
        h.update(&sid);
        h.update(&share.group_public_key.toBytes());
        var u: [4]u8 = undefined;
        std.mem.writeInt(u32, &u, share.t, .big);
        h.update(&u);
        for (sorted) |idx| {
            std.mem.writeInt(u32, &u, idx, .big);
            h.update(&u);
        }
        const ssid = h.finalResult();
        const last_bc = try allocator.alloc(Attestation, sorted.len);
        errdefer allocator.free(last_bc);
        const open = try allocator.alloc(PeerOpen, sorted.len);
        @memset(open, .{});
        return .{
            .allocator = allocator,
            .share = share,
            .sid = ssid,
            .signers = sorted,
            .me = me,
            .peers = peers,
            .message_kp = message_kp,
            .last_bc = last_bc,
            .open = open,
        };
    }

    pub fn deinit(self: *Party) void {
        self.wipe();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.share.secret_share));
        std.crypto.secureZero(u8, &self.share.message_seed);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.message_kp.secret_key));
        self.share.paillier_secret.deinit();
        self.allocator.free(self.peers);
        self.allocator.free(self.signers);
        self.allocator.free(self.last_bc);
        self.allocator.free(self.open);
        if (self.own_open) |m| self.allocator.free(m);
        self.* = undefined;
    }

    fn messageKeys(self: *const Party, out: []Ed25519.PublicKey) void {
        for (self.peers, out) |p, *k| k.* = p.message_key;
    }

    fn wipe(self: *Party) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.secrets));
        for (self.open) |*o| {
            if (o.round2) |m| self.allocator.free(m);
            std.crypto.secureZero(u8, std.mem.asBytes(o));
            o.* = .{};
        }
    }

    fn fail(self: *Party, culprit: ?u32, fault: Fault) error{ProtocolAbort} {
        self.abort = .{ .culprit = culprit, .fault = fault };
        self.state = .aborted;
        self.wipe();
        return error.ProtocolAbort;
    }

    /// A type-5 or type-7 abort: unattributed for now, and the secrets the
    /// §4.3 opening reveals are kept (`openAbort`, `identify`).
    fn failOpen(self: *Party, fault: Fault) error{ProtocolAbort} {
        self.abort = .{ .culprit = null, .fault = fault };
        self.state = .opening;
        return error.ProtocolAbort;
    }

    fn myIndex(self: *const Party) u32 {
        return self.signers[self.me];
    }

    fn myCtx(self: *const Party) [36]u8 {
        return proofContext(self.sid, self.myIndex());
    }

    /// Runs the next round: hand in every message addressed to this party
    /// for the round just finished (empty for the first call). The returned
    /// messages are owned by the caller.
    /// Any error ends the party: an abort as described above, anything
    /// else (`OutOfMemory`, a misuse) with `abort == null` — the round's
    /// accumulators would be half-updated, so it cannot be retried.
    pub fn advance(self: *Party, inbox: []const []const u8, random: std.Random) Error!Outbox {
        const result = switch (self.state) {
            .round1 => if (inbox.len != 0) error.InvalidParameters else self.round1(random),
            .round2 => self.round2(inbox, random),
            .round3 => self.round3(inbox, random),
            .round4 => self.round4(inbox, random),
            .round5 => self.round5(inbox, random),
            .round6 => self.round6(inbox, random),
            .finish, .done, .aborted, .opening, .identify => return error.InvalidState,
        };
        return result catch |e| {
            if (self.state != .opening) {
                self.state = .aborted;
                self.wipe();
            }
            return e;
        };
    }

    // ── inbox handling ───────────────────────────────────────────────────

    const Slots = struct {
        broadcast: []?[]const u8,
        p2p: []?[]const u8,
    };

    /// Sorts `inbox` into one broadcast and/or one p2p payload per peer and
    /// requires every peer to have sent exactly what `round` calls for. Every
    /// message's signature is checked first, then its attestation block
    /// against this party's view of the previous broadcast round.
    fn collect(self: *Party, inbox: []const []const u8, round: u8, want_bc: bool, want_p2p: bool, slots: Slots) Error!void {
        @memset(slots.broadcast, null);
        @memset(slots.p2p, null);
        const bc_att = try self.allocator.alloc(Attestation, self.peers.len);
        defer self.allocator.free(bc_att);
        const keys = try self.allocator.alloc(Ed25519.PublicKey, self.peers.len);
        defer self.allocator.free(keys);
        self.messageKeys(keys);
        const att_len: usize = if (hasAttestation(round)) self.peers.len * attestation_entry_length else 0;
        for (inbox) |msg| {
            const h = peekHeader(msg) catch return self.fail(null, .malformed_message);
            // A bus that hands a party its own broadcast back is not a fault.
            if (h.from == self.myIndex()) continue;
            const pos = std.mem.indexOfScalar(u32, self.signers, h.from) orelse return self.fail(h.from, .unexpected_message);
            if (h.round != round or !std.mem.eql(u8, &h.sid, &self.sid)) return self.fail(h.from, .unexpected_message);
            if (msg.len < header_length + signature_length) return self.fail(h.from, .bad_signature);
            const body = msg[header_length .. msg.len - signature_length];
            var att: Attestation = .{ .body_hash = undefined, .signature = msg[msg.len - signature_length ..][0..signature_length].* };
            Sha256.hash(body, &att.body_hash, .{});
            if (!verifyAttestation(self.peers[pos].message_key, msg[0..header_length].*, att)) return self.fail(h.from, .bad_signature);
            var payload = body;
            if (att_len != 0) {
                if (payload.len < att_len) return self.fail(h.from, .malformed_message);
                if (checkAttestations(self.sid, round - 1, self.signers, keys, self.last_bc, payload[0..att_len], h.from)) |ab|
                    return self.fail(ab.culprit, ab.fault);
                payload = payload[att_len..];
            }
            const slot = if (h.to) |to| blk: {
                if (to != self.myIndex() or !want_p2p) return self.fail(h.from, .unexpected_message);
                break :blk &slots.p2p[pos];
            } else blk: {
                if (!want_bc) return self.fail(h.from, .unexpected_message);
                bc_att[pos] = att;
                break :blk &slots.broadcast[pos];
            };
            if (slot.* != null) return self.fail(h.from, .duplicate_message);
            slot.* = payload;
        }
        for (self.peers, 0..) |p, pos| {
            if (pos == self.me) continue;
            if (want_bc and slots.broadcast[pos] == null) return self.fail(p.index, .missing_message);
            if (want_p2p and slots.p2p[pos] == null) return self.fail(p.index, .missing_message);
        }
        if (want_bc) {
            for (self.last_bc, bc_att, 0..) |*l, a, pos| l.* = if (pos == self.me) self.own_bc else a;
        }
    }

    fn withSlots(self: *Party, comptime f: anytype, inbox: []const []const u8, random: std.Random) Error!Outbox {
        const bc = try self.allocator.alloc(?[]const u8, self.peers.len);
        defer self.allocator.free(bc);
        const p2p = try self.allocator.alloc(?[]const u8, self.peers.len);
        defer self.allocator.free(p2p);
        return f(self, inbox, .{ .broadcast = bc, .p2p = p2p }, random);
    }

    const OutboxBuilder = struct {
        list: std.ArrayList(Outgoing) = .empty,
        allocator: std.mem.Allocator,

        fn deinit(self: *OutboxBuilder) void {
            for (self.list.items) |m| self.allocator.free(m.bytes);
            self.list.deinit(self.allocator);
        }

        fn add(self: *OutboxBuilder, party: *Party, round: u8, to: ?u32, payload: []const u8) std.mem.Allocator.Error!void {
            const att_len: usize = if (hasAttestation(round)) party.peers.len * attestation_entry_length else 0;
            const bytes = try self.allocator.alloc(u8, header_length + att_len + payload.len + signature_length);
            errdefer self.allocator.free(bytes);
            (Header{ .round = round, .sid = party.sid, .from = party.myIndex(), .to = to }).write(bytes[0..header_length]);
            for (party.last_bc, 0..) |a, pos| {
                if (att_len == 0) break;
                writeAttestation(a, bytes[header_length + pos * attestation_entry_length ..][0..attestation_entry_length]);
            }
            @memcpy(bytes[header_length + att_len ..][0..payload.len], payload);
            const a = sign(party.message_kp, bytes[0..header_length].*, bytes[header_length .. bytes.len - signature_length]);
            bytes[bytes.len - signature_length ..][0..signature_length].* = a.signature;
            if (to == null) party.own_bc = a;
            try self.list.append(self.allocator, .{ .to = to, .bytes = bytes });
        }

        fn finish(self: *OutboxBuilder) std.mem.Allocator.Error!Outbox {
            return .{ .messages = try self.list.toOwnedSlice(self.allocator) };
        }
    };

    /// Maps an error from proving under peer `j`'s keys: a refused key or
    /// tuple is `j`'s fault, anything else propagates.
    fn proveFailed(self: *Party, j: u32, err: anyerror) Error {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => self.fail(j, .invalid_peer_keys),
        };
    }

    // ── Phase 1 ──────────────────────────────────────────────────────────

    fn round1(self: *Party, random: std.Random) Error!Outbox {
        const me = &self.peers[self.me];
        // This party's own Paillier key and aux tuple get the checks every
        // peer will run on them, so a bad local key fails here instead of
        // blaming an honest peer later (review F3).
        me.aux.validate(random) catch return error.InvalidParameters;
        if (!root.paillierNMeetsFloor(me.pk) or !root.paillierGeneratorIsStandard(me.pk)) return error.InvalidParameters;
        const lambda = signing.lagrangeCoefficient(self.signers, me.index);
        self.secrets = .{
            .k = randomScalar(random),
            .gamma = randomScalar(random),
            .w = lambda.mul(self.share.secret_share),
            .ell = Scalar.zero,
            .delta = Scalar.zero,
            .sigma = Scalar.zero,
            .gamma_blind = undefined,
            .r_k = undefined,
        };
        random.bytes(&self.secrets.gamma_blind);
        while (true) {
            const pt = Secp256k1.basePoint.mul(self.secrets.gamma.toBytes(.big), .big) catch {
                self.secrets.gamma = randomScalar(random);
                continue;
            };
            me.big_gamma = Element.fromPoint(pt) catch unreachable;
            break;
        }
        me.commitment = commitGamma(self.sid, me.index, me.big_gamma, self.secrets.gamma_blind);
        const init_k = mta.mtaAliceInitChecked(self.secrets.k, me.pk, random) catch return self.fail(me.index, .invalid_peer_keys);
        me.c_k = init_k.c_a;
        self.secrets.r_k = init_k.r_a;

        var out: OutboxBuilder = .{ .allocator = self.allocator };
        errdefer out.deinit();

        var bc: [32 + 4 + paillier.modulus_sq_bytes]u8 = undefined;
        bc[0..32].* = me.commitment;
        std.mem.writeInt(u32, bc[32..36], paillier.modulus_sq_bytes, .big);
        bc[36..].* = ciphertextBytes(me.c_k);
        try out.add(self, 1, null, &bc);

        const my_ctx = self.myCtx();
        for (self.peers, 0..) |p, pos| {
            if (pos == self.me) continue;
            const proof = zkproofs.proveAliceRange(self.allocator, self.secrets.k, self.secrets.r_k, me.pk, p.aux, &my_ctx, random) catch |e|
                return self.proveFailed(p.index, e);
            defer proof.deinit(self.allocator);
            const bytes = proof.toBytesAlloc(self.allocator) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else unreachable;
            defer self.allocator.free(bytes);
            try out.add(self, 1, p.index, bytes);
        }
        self.state = .round2;
        return out.finish();
    }

    // ── Phase 2 ──────────────────────────────────────────────────────────

    fn round2(self: *Party, inbox: []const []const u8, random: std.Random) Error!Outbox {
        return self.withSlots(round2Inner, inbox, random);
    }

    fn round2Inner(self: *Party, inbox: []const []const u8, slots: Slots, random: std.Random) Error!Outbox {
        try self.collect(inbox, 1, true, true, slots);
        const me = &self.peers[self.me];
        const ctx_me = me.*;

        // Every range proof first: nothing is computed on a ciphertext whose
        // proof has not been checked.
        for (self.peers, 0..) |*p, pos| {
            if (pos == self.me) continue;
            const bc = slots.broadcast[pos].?;
            if (bc.len < 32) return self.fail(p.index, .malformed_message);
            p.commitment = bc[0..32].*;
            var off: usize = 32;
            const c_bytes = readLenPrefixed(bc, &off) orelse return self.fail(p.index, .malformed_message);
            if (off != bc.len) return self.fail(p.index, .malformed_message);
            p.c_k = paillier.Ciphertext.fromBytes(p.pk, c_bytes) catch return self.fail(p.index, .malformed_message);

            const proof = zkproofs.RangeProof.fromBytesAlloc(self.allocator, ctx_me.aux.n_tilde, p.pk, slots.p2p[pos].?) catch |e|
                return if (e == error.OutOfMemory) error.OutOfMemory else self.fail(p.index, .malformed_message);
            defer proof.deinit(self.allocator);
            const p_ctx = proofContext(self.sid, p.index);
            if (!zkproofs.verifyAliceRange(proof, p.c_k, p.pk, ctx_me.aux, &p_ctx)) return self.fail(p.index, .range_proof);
        }

        var out: OutboxBuilder = .{ .allocator = self.allocator };
        errdefer out.deinit();
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);

        const my_ctx = self.myCtx();
        for (self.peers, 0..) |p, pos| {
            if (pos == self.me) continue;
            payload.clearRetainingCapacity();

            // MtA for k_j·γ_i: this party is Bob.
            var g = mta.mtaBobResponseChecked(self.secrets.gamma, p.c_k, p.pk, random) catch |e| return self.proveFailed(p.index, e);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&g));
            const g_proof = zkproofs.proveBobMta(self.allocator, self.secrets.gamma, &g.beta_prime, g.r_b, p.c_k, g.c_b, p.pk, p.aux, &my_ctx, random) catch |e|
                return self.proveFailed(p.index, e);
            defer g_proof.deinit(self.allocator);

            // MtAwc for k_j·w_i, bound to W_i.
            var x = mta.mtaBobResponseChecked(self.secrets.w, p.c_k, p.pk, random) catch |e| return self.proveFailed(p.index, e);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&x));
            const x_proof = zkproofs.proveBobMtaWc(self.allocator, self.secrets.w, &x.beta_prime, x.r_b, p.c_k, x.c_b, p.pk, p.aux, me.w_point, &my_ctx, random) catch |e|
                return self.proveFailed(p.index, e);
            defer x_proof.deinit(self.allocator);

            self.secrets.delta = self.secrets.delta.add(g.beta);
            self.secrets.sigma = self.secrets.sigma.add(x.beta);
            // Kept for a §4.3 opening (wiped with the other secrets).
            self.open[pos].gamma_beta_prime = g.beta_prime;
            self.open[pos].gamma_r = g.r_b;
            self.open[pos].w_beta_prime = x.beta_prime;

            try appendLenPrefixed(&payload, self.allocator, &ciphertextBytes(g.c_b));
            const gp = g_proof.toBytesAlloc(self.allocator) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else unreachable;
            defer self.allocator.free(gp);
            try appendLenPrefixed(&payload, self.allocator, gp);
            try appendLenPrefixed(&payload, self.allocator, &ciphertextBytes(x.c_b));
            const xp = x_proof.toBytesAlloc(self.allocator) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else unreachable;
            defer self.allocator.free(xp);
            try appendLenPrefixed(&payload, self.allocator, xp);
            try out.add(self, 2, p.index, payload.items);
        }
        self.state = .round3;
        return out.finish();
    }

    // ── Phase 3 ──────────────────────────────────────────────────────────

    fn round3(self: *Party, inbox: []const []const u8, random: std.Random) Error!Outbox {
        return self.withSlots(round3Inner, inbox, random);
    }

    fn round3Inner(self: *Party, inbox: []const []const u8, slots: Slots, random: std.Random) Error!Outbox {
        try self.collect(inbox, 2, false, true, slots);
        // The signed round-2 messages, for a §4.3 opening (`collect` checked
        // that each peer sent exactly one).
        for (inbox) |raw| {
            const h = peekHeader(raw) catch unreachable;
            if (h.from == self.myIndex() or h.to == null) continue;
            const pos = std.mem.indexOfScalar(u32, self.signers, h.from).?;
            if (self.open[pos].round2 == null) self.open[pos].round2 = try self.allocator.dupe(u8, raw);
        }
        const me = &self.peers[self.me];
        const sk = self.share.paillier_secret;

        for (self.peers, 0..) |p, pos| {
            if (pos == self.me) continue;
            const msg = slots.p2p[pos].?;
            var off: usize = 0;
            const cg_bytes = readLenPrefixed(msg, &off) orelse return self.fail(p.index, .malformed_message);
            const gp_bytes = readLenPrefixed(msg, &off) orelse return self.fail(p.index, .malformed_message);
            const cx_bytes = readLenPrefixed(msg, &off) orelse return self.fail(p.index, .malformed_message);
            const xp_bytes = readLenPrefixed(msg, &off) orelse return self.fail(p.index, .malformed_message);
            if (off != msg.len) return self.fail(p.index, .malformed_message);
            const c_g = paillier.Ciphertext.fromBytes(me.pk, cg_bytes) catch return self.fail(p.index, .malformed_message);
            const c_x = paillier.Ciphertext.fromBytes(me.pk, cx_bytes) catch return self.fail(p.index, .malformed_message);
            const g_proof = zkproofs.MtaProof.fromBytesAlloc(self.allocator, me.aux.n_tilde, me.pk, gp_bytes) catch |e|
                return if (e == error.OutOfMemory) error.OutOfMemory else self.fail(p.index, .malformed_message);
            defer g_proof.deinit(self.allocator);
            const x_proof = zkproofs.MtaProofWc.fromBytesAlloc(self.allocator, me.aux.n_tilde, me.pk, xp_bytes) catch |e|
                return if (e == error.OutOfMemory) error.OutOfMemory else self.fail(p.index, .malformed_message);
            defer x_proof.deinit(self.allocator);

            const p_ctx = proofContext(self.sid, p.index);
            if (!zkproofs.verifyBobMta(g_proof, me.c_k, c_g, me.pk, me.aux, &p_ctx)) return self.fail(p.index, .mta_proof);
            if (!zkproofs.verifyBobMtaWc(x_proof, me.c_k, c_x, me.pk, me.aux, p.w_point, &p_ctx)) return self.fail(p.index, .mtawc_proof);
            var alpha = mta.mtaAliceFinalizeVerified(c_g, sk) catch return self.fail(p.index, .mta_proof);
            var mu = mta.mtaAliceFinalizeVerified(c_x, sk) catch return self.fail(p.index, .mtawc_proof);
            self.secrets.delta = self.secrets.delta.add(alpha);
            self.secrets.sigma = self.secrets.sigma.add(mu);
            std.crypto.secureZero(u8, std.mem.asBytes(&alpha));
            std.crypto.secureZero(u8, std.mem.asBytes(&mu));
        }
        self.secrets.delta = self.secrets.delta.add(self.secrets.k.mul(self.secrets.gamma));
        self.secrets.sigma = self.secrets.sigma.add(self.secrets.k.mul(self.secrets.w));

        while (true) {
            self.secrets.ell = randomScalar(random);
            me.t_point = ecproofs.pedersenCommit(self.secrets.sigma, self.secrets.ell) catch continue;
            break;
        }
        me.delta = self.secrets.delta;
        const ctx = self.myCtx();
        const proof = ecproofs.provePedersen(self.secrets.sigma, self.secrets.ell, me.t_point, &ctx, random);

        var payload: [Ns + Ne + ecproofs.PedersenProof.encoded_length]u8 = undefined;
        payload[0..Ns].* = me.delta.toBytes(.big);
        payload[Ns..][0..Ne].* = me.t_point.toBytes();
        payload[Ns + Ne ..].* = proof.toBytes();

        var out: OutboxBuilder = .{ .allocator = self.allocator };
        errdefer out.deinit();
        try out.add(self, 3, null, &payload);
        self.state = .round4;
        return out.finish();
    }

    // ── Phase 4 ──────────────────────────────────────────────────────────

    fn round4(self: *Party, inbox: []const []const u8, random: std.Random) Error!Outbox {
        return self.withSlots(round4Inner, inbox, random);
    }

    fn round4Inner(self: *Party, inbox: []const []const u8, slots: Slots, random: std.Random) Error!Outbox {
        try self.collect(inbox, 3, true, false, slots);
        const len = Ns + Ne + ecproofs.PedersenProof.encoded_length;
        for (self.peers, 0..) |*p, pos| {
            if (pos == self.me) continue;
            const msg = slots.broadcast[pos].?;
            if (msg.len != len) return self.fail(p.index, .malformed_message);
            p.delta = decodeScalar(msg[0..Ns].*) orelse return self.fail(p.index, .malformed_message);
            p.t_point = Element.fromBytes(msg[Ns..][0..Ne].*) catch return self.fail(p.index, .malformed_message);
            const proof = ecproofs.PedersenProof.fromBytes(msg[Ns + Ne ..][0..ecproofs.PedersenProof.encoded_length].*) catch
                return self.fail(p.index, .malformed_message);
            const ctx = proofContext(self.sid, p.index);
            if (!ecproofs.verifyPedersen(proof, p.t_point, &ctx)) return self.fail(p.index, .pedersen_proof);
        }

        const me = &self.peers[self.me];
        const ctx = self.myCtx();
        const proof = ecproofs.proveSchnorr(self.secrets.gamma, me.big_gamma, &ctx, random);
        var payload: [Ne + 32 + ecproofs.SchnorrProof.encoded_length]u8 = undefined;
        payload[0..Ne].* = me.big_gamma.toBytes();
        payload[Ne..][0..32].* = self.secrets.gamma_blind;
        payload[Ne + 32 ..].* = proof.toBytes();

        var out: OutboxBuilder = .{ .allocator = self.allocator };
        errdefer out.deinit();
        try out.add(self, 4, null, &payload);
        self.state = .round5;
        return out.finish();
    }

    // ── Phase 5 ──────────────────────────────────────────────────────────

    fn round5(self: *Party, inbox: []const []const u8, random: std.Random) Error!Outbox {
        return self.withSlots(round5Inner, inbox, random);
    }

    fn round5Inner(self: *Party, inbox: []const []const u8, slots: Slots, random: std.Random) Error!Outbox {
        try self.collect(inbox, 4, true, false, slots);
        const len = Ne + 32 + ecproofs.SchnorrProof.encoded_length;
        for (self.peers, 0..) |*p, pos| {
            if (pos == self.me) continue;
            const msg = slots.broadcast[pos].?;
            if (msg.len != len) return self.fail(p.index, .malformed_message);
            p.big_gamma = Element.fromBytes(msg[0..Ne].*) catch return self.fail(p.index, .malformed_message);
            const blind = msg[Ne..][0..32].*;
            const proof = ecproofs.SchnorrProof.fromBytes(msg[Ne + 32 ..][0..ecproofs.SchnorrProof.encoded_length].*) catch
                return self.fail(p.index, .malformed_message);
            if (!std.mem.eql(u8, &commitGamma(self.sid, p.index, p.big_gamma, blind), &p.commitment))
                return self.fail(p.index, .gamma_decommitment);
            const ctx = proofContext(self.sid, p.index);
            if (!ecproofs.verifySchnorr(proof, p.big_gamma, &ctx)) return self.fail(p.index, .gamma_proof);
        }

        // δ = Σ δ_j, Γ = Σ Γ_j, R = δ⁻¹·Γ, r = R.x mod q.
        var delta = Scalar.zero;
        var gamma_sum = Secp256k1.identityElement;
        for (self.peers) |p| {
            delta = delta.add(p.delta);
            gamma_sum = gamma_sum.add(p.big_gamma.point() catch unreachable);
        }
        if (delta.isZero()) return self.fail(null, .degenerate);
        const r_full = gamma_sum.mulPublic(delta.invert().toBytes(.big), .big) catch return self.fail(null, .degenerate);
        self.r_point = Element.fromPoint(r_full) catch return self.fail(null, .degenerate);
        self.r = scalarFromHash32(r_full.affineCoordinates().x.toBytes(.big));
        if (self.r.isZero()) return self.fail(null, .degenerate);

        const me = &self.peers[self.me];
        const r_bar_pt = r_full.mul(self.secrets.k.toBytes(.big), .big) catch return self.fail(null, .degenerate);
        me.r_bar = Element.fromPoint(r_bar_pt) catch return self.fail(null, .degenerate);

        var out: OutboxBuilder = .{ .allocator = self.allocator };
        errdefer out.deinit();
        try out.add(self, 5, null, &me.r_bar.toBytes());
        const ctx = self.myCtx();
        for (self.peers, 0..) |p, pos| {
            if (pos == self.me) continue;
            const proof = zkproofs.provePdl(self.allocator, self.secrets.k, self.secrets.r_k, me.pk, p.aux, self.r_point, me.r_bar, &ctx, random) catch |e|
                return self.proveFailed(p.index, e);
            defer proof.deinit(self.allocator);
            const bytes = proof.toBytesAlloc(self.allocator) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else unreachable;
            defer self.allocator.free(bytes);
            try out.add(self, 5, p.index, bytes);
        }
        self.state = .round6;
        return out.finish();
    }

    // ── Phase 6 ──────────────────────────────────────────────────────────

    fn round6(self: *Party, inbox: []const []const u8, random: std.Random) Error!Outbox {
        return self.withSlots(round6Inner, inbox, random);
    }

    fn round6Inner(self: *Party, inbox: []const []const u8, slots: Slots, random: std.Random) Error!Outbox {
        try self.collect(inbox, 5, true, true, slots);
        const me = &self.peers[self.me];
        for (self.peers, 0..) |*p, pos| {
            if (pos == self.me) continue;
            const bc = slots.broadcast[pos].?;
            if (bc.len != Ne) return self.fail(p.index, .malformed_message);
            p.r_bar = Element.fromBytes(bc[0..Ne].*) catch return self.fail(p.index, .malformed_message);
            const proof = zkproofs.PdlProof.fromBytesAlloc(self.allocator, me.aux.n_tilde, p.pk, slots.p2p[pos].?) catch |e|
                return if (e == error.OutOfMemory) error.OutOfMemory else self.fail(p.index, .malformed_message);
            defer proof.deinit(self.allocator);
            const ctx = proofContext(self.sid, p.index);
            if (!zkproofs.verifyPdl(proof, p.c_k, p.pk, me.aux, self.r_point, p.r_bar, &ctx)) return self.fail(p.index, .pdl_proof);
        }
        var r_bar_sum = Secp256k1.identityElement;
        for (self.peers) |p| r_bar_sum = r_bar_sum.add(p.r_bar.point() catch unreachable);
        if (!r_bar_sum.equivalent(Secp256k1.basePoint)) return self.failOpen(.r_bar_sum);

        const r_pt = self.r_point.point() catch unreachable;
        const s_pt = r_pt.mul(self.secrets.sigma.toBytes(.big), .big) catch return self.fail(null, .degenerate);
        me.s_point = Element.fromPoint(s_pt) catch return self.fail(null, .degenerate);
        const ctx = self.myCtx();
        const proof = ecproofs.proveSt(self.secrets.sigma, self.secrets.ell, self.r_point, me.s_point, me.t_point, &ctx, random) catch unreachable;

        var payload: [Ne + ecproofs.StProof.encoded_length]u8 = undefined;
        payload[0..Ne].* = me.s_point.toBytes();
        payload[Ne..].* = proof.toBytes();
        var out: OutboxBuilder = .{ .allocator = self.allocator };
        errdefer out.deinit();
        try out.add(self, 6, null, &payload);
        self.state = .finish;
        return out.finish();
    }

    // ── end of presigning ────────────────────────────────────────────────

    /// Consumes the Phase-6 messages, checks `Σ S_j = X`, and moves this
    /// party's secrets into the returned `Presignature` (the party keeps
    /// none; only `deinit` remains to be called on it).
    pub fn finish(self: *Party, inbox: []const []const u8) Error!Presignature {
        if (self.state != .finish) return error.InvalidState;
        return self.finishInner(inbox) catch |e| {
            if (self.state != .opening) {
                self.state = .aborted;
                self.wipe();
            }
            return e;
        };
    }

    fn finishInner(self: *Party, inbox: []const []const u8) Error!Presignature {
        const bc = try self.allocator.alloc(?[]const u8, self.peers.len);
        defer self.allocator.free(bc);
        const p2p = try self.allocator.alloc(?[]const u8, self.peers.len);
        defer self.allocator.free(p2p);
        try self.collect(inbox, 6, true, false, .{ .broadcast = bc, .p2p = p2p });

        const len = Ne + ecproofs.StProof.encoded_length;
        for (self.peers, 0..) |*p, pos| {
            if (pos == self.me) continue;
            const msg = bc[pos].?;
            if (msg.len != len) return self.fail(p.index, .malformed_message);
            p.s_point = Element.fromBytes(msg[0..Ne].*) catch return self.fail(p.index, .malformed_message);
            const proof = ecproofs.StProof.fromBytes(msg[Ne..][0..ecproofs.StProof.encoded_length].*) catch
                return self.fail(p.index, .malformed_message);
            const ctx = proofContext(self.sid, p.index);
            if (!ecproofs.verifySt(proof, self.r_point, p.s_point, p.t_point, &ctx)) return self.fail(p.index, .st_proof);
        }
        var s_sum = Secp256k1.identityElement;
        for (self.peers) |p| s_sum = s_sum.add(p.s_point.point() catch unreachable);
        if (!s_sum.equivalent(self.share.group_public_key.point() catch unreachable)) return self.failOpen(.s_sum);

        const signers = try self.allocator.dupe(u32, self.signers);
        errdefer self.allocator.free(signers);
        const r_bar = try self.allocator.alloc(Element, self.peers.len);
        errdefer self.allocator.free(r_bar);
        const s_points = try self.allocator.alloc(Element, self.peers.len);
        errdefer self.allocator.free(s_points);
        for (self.peers, r_bar, s_points) |p, *rb, *sp| {
            rb.* = p.r_bar;
            sp.* = p.s_point;
        }
        const bc6 = try self.allocator.dupe(Attestation, self.last_bc);
        errdefer self.allocator.free(bc6);
        const keys = try self.allocator.alloc(Ed25519.PublicKey, self.peers.len);
        self.messageKeys(keys);
        const presig: Presignature = .{
            .public = .{
                .allocator = self.allocator,
                .sid = self.sid,
                .group_public_key = self.share.group_public_key,
                .signers = signers,
                .r_point = self.r_point,
                .r = self.r,
                .r_bar = r_bar,
                .s_points = s_points,
                .round6 = bc6,
                .message_keys = keys,
            },
            .index = self.myIndex(),
            .k = self.secrets.k,
            .sigma = self.secrets.sigma,
            .message_seed = self.share.message_seed,
        };
        self.wipe();
        self.state = .done;
        return presig;
    }

    // ── §4.3 identification of type-5 and type-7 aborts ─────────────────

    /// After `advance`/`finish` aborted with `r_bar_sum` (type 5) or `s_sum`
    /// (type 7) and `culprit == null`: this signer's opening, a broadcast
    /// for every other signer (GG20 §4.3). The session is dead, so its
    /// nonce material may be revealed; nothing that leaks the key share is.
    ///
    /// - Type 5: `k_i` and the randomness of `c_i`, `γ_i`, every signed
    ///   round-2 message this signer received, and per peer its own mask
    ///   `β'` and randomness in the `k_j·γ_i` response. Anyone recomputes
    ///   every `δ_j` and names the signer whose broadcast `δ_j` differs, or
    ///   whose opening does not match its earlier messages.
    /// - Type 7: `k_i` and the randomness of `c_i`, every signed round-2
    ///   message received with the decryption `μ'` of its `k_i·w_j` part
    ///   and that ciphertext's randomness (a proof of the decryption), per
    ///   peer its own mask `ν'`, and a DLEQ proof that `S_i = σ_i·R` for the
    ///   `σ_i·G` everyone computes from the opened values (`σ_i` itself
    ///   would reveal `w_i`).
    ///
    /// Then hand every peer's opening to `identify`.
    pub fn openAbort(self: *Party, random: std.Random) Error!Outbox {
        if (self.state != .opening) return error.InvalidState;
        const fault = self.abort.?.fault;
        const me = self.peers[self.me];
        var payload: std.ArrayList(u8) = .empty;
        defer {
            std.crypto.secureZero(u8, payload.items);
            payload.deinit(self.allocator);
        }
        try payload.append(self.allocator, if (fault == .r_bar_sum) 5 else 7);
        try payload.appendSlice(self.allocator, &self.secrets.k.toBytes(.big));
        var fe_buf: [paillier.modulus_sq_bytes]u8 = undefined;
        self.secrets.r_k.toBytes(&fe_buf, .big) catch unreachable;
        try appendLenPrefixed(&payload, self.allocator, &fe_buf);
        if (fault == .r_bar_sum) {
            try payload.appendSlice(self.allocator, &self.secrets.gamma.toBytes(.big));
            for (self.open, 0..) |o, pos| {
                if (pos == self.me) continue;
                try appendLenPrefixed(&payload, self.allocator, o.round2.?);
                try payload.appendSlice(self.allocator, &o.gamma_beta_prime);
                o.gamma_r.toBytes(&fe_buf, .big) catch unreachable;
                try appendLenPrefixed(&payload, self.allocator, &fe_buf);
            }
        } else {
            const sk = self.share.paillier_secret;
            const n_len = me.pk.nByteLen();
            for (self.open, 0..) |o, pos| {
                if (pos == self.me) continue;
                try appendLenPrefixed(&payload, self.allocator, o.round2.?);
                const fields = round2Fields(o.round2.?, self.peers.len) orelse unreachable; // checked in round 3
                const c_w = paillier.Ciphertext.fromBytes(me.pk, fields[2]) catch unreachable;
                const opened = mta.decryptWithRandomness(sk, me.pk, c_w) catch return error.InvalidParameters;
                var m_buf: [paillier.modulus_bytes]u8 = undefined;
                opened.m.toBytes(m_buf[0..n_len], .big) catch unreachable;
                try appendLenPrefixed(&payload, self.allocator, m_buf[0..n_len]);
                opened.rho.toBytes(&fe_buf, .big) catch unreachable;
                try appendLenPrefixed(&payload, self.allocator, &fe_buf);
                try payload.appendSlice(self.allocator, &o.w_beta_prime);
            }
            const sigma_pt = Secp256k1.basePoint.mul(self.secrets.sigma.toBytes(.big), .big) catch return error.InvalidParameters;
            const sigma_el = Element.fromPoint(sigma_pt) catch return error.InvalidParameters;
            const proof = ecproofs.proveDleq(self.secrets.sigma, self.r_point, me.s_point, sigma_el, &self.myCtx(), random) catch unreachable;
            try payload.appendSlice(self.allocator, &proof.toBytes());
        }
        var out: OutboxBuilder = .{ .allocator = self.allocator };
        errdefer out.deinit();
        try out.add(self, open_round, null, payload.items);
        self.own_open = try self.allocator.dupe(u8, out.list.items[0].bytes);
        self.state = .identify;
        return out.finish();
    }

    /// Checks every signer's opening (the inbox: one `openAbort` broadcast
    /// from every peer) and names the culprit: the first signer, in signer
    /// order of the checks below, whose opening contradicts its earlier
    /// signed messages or the values it broadcast. Returns the verdict (also
    /// in `abort`); the party is done afterwards, its secrets wiped. A peer
    /// whose opening is missing, unsigned or malformed is the culprit.
    pub fn identify(self: *Party, inbox: []const []const u8) Error!Abort {
        if (self.state != .identify) return error.InvalidState;
        const fault = self.abort.?.fault;
        const verdict = self.identifyInner(inbox, fault) catch |e| switch (e) {
            error.ProtocolAbort => self.abort.?, // from `collect`: missing, unsigned, malformed
            else => {
                self.state = .aborted;
                self.wipe();
                return e;
            },
        };
        self.abort = verdict;
        self.state = .aborted;
        self.wipe();
        return verdict;
    }

    fn identifyInner(self: *Party, inbox: []const []const u8, fault: Fault) Error!Abort {
        const n = self.peers.len;
        const bc = try self.allocator.alloc(?[]const u8, n);
        defer self.allocator.free(bc);
        const p2p = try self.allocator.alloc(?[]const u8, n);
        defer self.allocator.free(p2p);
        try self.collect(inbox, open_round, true, false, .{ .broadcast = bc, .p2p = p2p });
        const own = self.own_open.?;
        bc[self.me] = own[header_length .. own.len - signature_length];

        const openings = try self.allocator.alloc(Opening, n);
        defer self.allocator.free(openings);
        const sections = try self.allocator.alloc(OpenSection, n * n);
        defer self.allocator.free(sections);
        for (openings, bc, 0..) |*o, body, i| {
            o.* = parseOpening(body.?, fault, i, sections[i * n ..][0..n]) orelse
                return .{ .culprit = self.signers[i], .fault = fault };
        }
        const culprit = if (fault == .r_bar_sum)
            try self.identifyType5(openings, sections)
        else
            try self.identifyType7(openings, sections);
        return .{ .culprit = culprit, .fault = fault };
    }

    /// The round-2 message `a` (Alice) received from `b`, as `a` opened it:
    /// signed by `b`, addressed to `a`, this session. Its four fields, or
    /// null (then `a` forged or mangled it — `a` is named).
    fn openedRound2(self: *const Party, sec: OpenSection, a: usize, b: usize) ?[4][]const u8 {
        const msg = sec.round2;
        const h = peekHeader(msg) catch return null;
        if (h.round != 2 or h.from != self.signers[b] or h.to != self.signers[a] or !std.mem.eql(u8, &h.sid, &self.sid)) return null;
        if (msg.len < header_length + signature_length) return null;
        var att: Attestation = .{ .body_hash = undefined, .signature = msg[msg.len - signature_length ..][0..signature_length].* };
        Sha256.hash(msg[header_length .. msg.len - signature_length], &att.body_hash, .{});
        if (!verifyAttestation(self.peers[b].message_key, msg[0..header_length].*, att)) return null;
        return round2Fields(msg, self.peers.len);
    }

    fn checkNonce(self: *const Party, o: Opening, i: usize) bool {
        const pk = self.peers[i].pk;
        const r_k = paillier.Fe.fromBytes(pk.n_sq, o.r_k, .big) catch return false;
        const c = paillier.encrypt(pk, mta.scalarToFe(o.k, pk), r_k) catch return false;
        return std.mem.eql(u8, &ciphertextBytes(c), &ciphertextBytes(self.peers[i].c_k));
    }

    fn identifyType5(self: *const Party, openings: []const Opening, sections: []const OpenSection) Error!?u32 {
        const n = self.peers.len;
        for (openings, self.peers, 0..) |o, p, i| {
            if (!self.checkNonce(o, i)) return p.index;
            const g_pt = Secp256k1.basePoint.mul(o.gamma.toBytes(.big), .big) catch return p.index;
            if (!g_pt.equivalent(p.big_gamma.point() catch unreachable)) return p.index;
        }
        // α_ab = k_a·γ_b + β'_ba for every Alice a, Bob b — once b's opened
        // β' and randomness rebuild the c_γ that b signed and a opened.
        for (0..n) |a| for (0..n) |b| {
            if (a == b) continue;
            const fields = self.openedRound2(sections[a * n + b], a, b) orelse return self.signers[a];
            const pk = self.peers[a].pk;
            const bob = sections[b * n + a];
            const r = paillier.Fe.fromBytes(pk.n_sq, bob.rand, .big) catch return self.signers[b];
            const beta_fe = zkproofs.feFromSecretBytes(pk.n_sq, paillier.Fe, bob.mask);
            const scaled = paillier.mulPlaintext(pk, self.peers[a].c_k, mta.scalarToFe(openings[b].gamma, pk)) catch return self.signers[b];
            const masked = paillier.encrypt(pk, beta_fe, r) catch return self.signers[b];
            const want = paillier.addCiphertexts(pk, scaled, masked);
            if (!std.mem.eql(u8, fields[0], &ciphertextBytes(want))) return self.signers[b];
        };
        for (openings, self.peers, 0..) |o, p, a| {
            var delta = o.k.mul(o.gamma);
            for (0..n) |b| {
                if (a == b) continue;
                // As Alice: α_ab; as Bob: −β'_ab.
                delta = delta.add(o.k.mul(openings[b].gamma)).add(zkproofs.scalarFromWide(sections[b * n + a].mask));
                delta = delta.sub(zkproofs.scalarFromWide(sections[a * n + b].mask));
            }
            if (!delta.equivalent(p.delta)) return p.index;
            const r_pt = self.r_point.point() catch unreachable;
            const r_bar = r_pt.mul(o.k.toBytes(.big), .big) catch return p.index;
            if (!r_bar.equivalent(p.r_bar.point() catch unreachable)) return p.index;
        }
        return null;
    }

    fn identifyType7(self: *const Party, openings: []const Opening, sections: []const OpenSection) Error!?u32 {
        const n = self.peers.len;
        for (openings, self.peers, 0..) |o, p, i| if (!self.checkNonce(o, i)) return p.index;
        const mu = try self.allocator.alloc(Scalar, n * n);
        defer self.allocator.free(mu);
        for (0..n) |a| for (0..n) |b| {
            if (a == b) continue;
            const fields = self.openedRound2(sections[a * n + b], a, b) orelse return self.signers[a];
            const pk = self.peers[a].pk;
            const alice = sections[a * n + b];
            // a's decryption of c_w, with its randomness: re-encrypt and compare.
            const m_fe = paillier.Fe.fromBytes(pk.n_sq, alice.plain, .big) catch return self.signers[a];
            const rho = paillier.Fe.fromBytes(pk.n_sq, alice.rand, .big) catch return self.signers[a];
            const again = paillier.encrypt(pk, m_fe, rho) catch return self.signers[a];
            if (!std.mem.eql(u8, fields[2], &ciphertextBytes(again))) return self.signers[a];
            var n_buf: [paillier.modulus_bytes]u8 = undefined;
            const n_len = pk.nByteLen();
            pk.nToBytes(n_buf[0..n_len]) catch unreachable;
            if (alice.plain.len != n_len) return self.signers[a];
            mu[a * n + b] = mta.centeredModQ(alice.plain, n_buf[0..n_len]);
            // b's mask: μ_ab·G = k_a·W_b + ν'_ba·G.
            const nu = zkproofs.scalarFromWide(sections[b * n + a].mask);
            const lhs = pointMulPublic(mu[a * n + b]);
            const wb = self.peers[b].w_point.point() catch unreachable;
            const ka_wb = wb.mulPublic(openings[a].k.toBytes(.big), .big) catch Secp256k1.identityElement;
            const rhs = ka_wb.add(pointMulPublic(nu));
            if (!lhs.equivalent(rhs)) return self.signers[b];
        };
        for (openings, self.peers, 0..) |o, p, i| {
            // σ_i·G = k_i·W_i + Σ_b μ_ib·G − Σ_b ν'_ib·G.
            var scalar_part = Scalar.zero;
            for (0..n) |b| {
                if (b == i) continue;
                scalar_part = scalar_part.add(mu[i * n + b]).sub(zkproofs.scalarFromWide(sections[i * n + b].mask));
            }
            const wi = p.w_point.point() catch unreachable;
            const ki_wi = wi.mulPublic(o.k.toBytes(.big), .big) catch Secp256k1.identityElement;
            const sigma_pt = ki_wi.add(pointMulPublic(scalar_part));
            const sigma_el = Element.fromPoint(sigma_pt) catch return p.index;
            const ctx = proofContext(self.sid, p.index);
            if (!ecproofs.verifyDleq(o.dleq.?, self.r_point, p.s_point, sigma_el, &ctx)) return p.index;
        }
        return null;
    }
};

/// `s·G` for a public scalar (the identity for `s = 0`).
fn pointMulPublic(s: Scalar) Secp256k1 {
    return Secp256k1.basePoint.mulPublic(s.toBytes(.big), .big) catch Secp256k1.identityElement;
}

/// The four length-prefixed fields of a round-2 payload (`c_γ`, its proof,
/// `c_w`, its proof), from the full signed message; null when malformed.
fn round2Fields(msg: []const u8, signers: usize) ?[4][]const u8 {
    const at = header_length + signers * attestation_entry_length;
    if (msg.len < at + signature_length) return null;
    const payload = msg[at .. msg.len - signature_length];
    var off: usize = 0;
    var out: [4][]const u8 = undefined;
    for (&out) |*f| f.* = readLenPrefixed(payload, &off) orelse return null;
    if (off != payload.len) return null;
    return out;
}

/// One signer's opening, parsed (slices into the message).
const Opening = struct {
    k: Scalar,
    r_k: []const u8,
    /// Type 5 only.
    gamma: Scalar = Scalar.zero,
    /// Type 7 only.
    dleq: ?ecproofs.DleqProof = null,
};

/// The opener's section for one peer (by the peer's position).
const OpenSection = struct {
    round2: []const u8 = &.{},
    /// The opener's own mask as Bob for that peer (`β'` in type 5, `ν'` in 7).
    mask: []const u8 = &.{},
    /// Type 5: the opener's Bob randomness; type 7: the randomness of its
    /// decryption (as Alice).
    rand: []const u8 = &.{},
    /// Type 7: the opener's decryption of the peer's `c_w`.
    plain: []const u8 = &.{},
};

fn parseOpening(body: []const u8, fault: Fault, me: usize, sections: []OpenSection) ?Opening {
    const kind: u8 = if (fault == .r_bar_sum) 5 else 7;
    if (body.len < 1 + Ns or body[0] != kind) return null;
    var off: usize = 1;
    var o: Opening = .{ .k = decodeScalar(body[off..][0..Ns].*) orelse return null, .r_k = undefined };
    off += Ns;
    o.r_k = readLenPrefixed(body, &off) orelse return null;
    if (kind == 5) {
        if (body.len - off < Ns) return null;
        o.gamma = decodeScalar(body[off..][0..Ns].*) orelse return null;
        off += Ns;
    }
    for (sections, 0..) |*sec, pos| {
        sec.* = .{};
        if (pos == me) continue;
        sec.round2 = readLenPrefixed(body, &off) orelse return null;
        if (kind == 5) {
            if (body.len - off < zkproofs.beta_prime_bytes) return null;
            sec.mask = body[off..][0..zkproofs.beta_prime_bytes];
            off += zkproofs.beta_prime_bytes;
            sec.rand = readLenPrefixed(body, &off) orelse return null;
        } else {
            sec.plain = readLenPrefixed(body, &off) orelse return null;
            sec.rand = readLenPrefixed(body, &off) orelse return null;
            if (body.len - off < zkproofs.beta_prime_bytes) return null;
            sec.mask = body[off..][0..zkproofs.beta_prime_bytes];
            off += zkproofs.beta_prime_bytes;
        }
    }
    if (kind == 7) {
        if (body.len - off != ecproofs.DleqProof.encoded_length) return null;
        o.dleq = ecproofs.DleqProof.fromBytes(body[off..][0..ecproofs.DleqProof.encoded_length].*) catch return null;
        off += ecproofs.DleqProof.encoded_length;
    }
    if (off != body.len) return null;
    return o;
}

/// The message to sign: raw bytes (hashed with SHA-256, as
/// `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256` does) or a 32-byte digest
/// the caller computed.
pub const Message = union(enum) {
    bytes: []const u8,
    prehashed: [32]u8,

    fn scalar(self: Message) Scalar {
        return switch (self) {
            .bytes => |b| blk: {
                var digest: [32]u8 = undefined;
                Sha256.hash(b, &digest, .{});
                break :blk scalarFromHash32(digest);
            },
            .prehashed => |d| scalarFromHash32(d),
        };
    }
};

/// Everything about a presignature that is not secret: enough to combine
/// the Phase-7 shares and to name a signer whose share is wrong.
pub const PresignaturePublic = struct {
    allocator: std.mem.Allocator,
    sid: SessionId,
    group_public_key: Element,
    /// Ascending, owned.
    signers: []u32,
    r_point: Element,
    r: Scalar,
    /// `R̄_j = k_j·R`, by position in `signers`, owned.
    r_bar: []Element,
    /// `S_j = σ_j·R`, by position in `signers`, owned.
    s_points: []Element,
    /// This signer's view of the Phase-6 broadcasts, one attestation per
    /// signer position, owned: every Phase-7 share attests its sender's view
    /// and `combine` compares (naming an equivocator as in presigning).
    round6: []Attestation,
    /// Every signer's message key, by position, owned: `combine` checks each
    /// share's signature.
    message_keys: []Ed25519.PublicKey,

    pub fn deinit(self: *PresignaturePublic) void {
        self.allocator.free(self.signers);
        self.allocator.free(self.r_bar);
        self.allocator.free(self.s_points);
        self.allocator.free(self.round6);
        self.allocator.free(self.message_keys);
        self.* = undefined;
    }

    /// Length of a Phase-7 share message for this signer set.
    pub fn shareLength(self: *const PresignaturePublic) usize {
        return header_length + self.signers.len * attestation_entry_length + Ns + signature_length;
    }

    /// Phase 7: checks every share against `s_j·R == m·R̄_j + r·S_j`
    /// (naming the first signer whose share fails, fault `sig_share`), sums
    /// them, normalises to low-S and verifies the result under the group key
    /// with std ECDSA. `shares` must hold exactly one Phase-7 message from
    /// EVERY signer — the caller's own share too, when the caller signed.
    /// Each share's signature is checked under its sender's message key
    /// (`bad_signature`), and its attestation of the Phase-6 broadcasts
    /// against this signer's (`equivocation`, named as in presigning).
    pub fn combine(self: *const PresignaturePublic, message: Message, shares: []const []const u8, abort: *?Abort) Error!signing.Signature {
        abort.* = null;
        const found = try self.allocator.alloc(?Scalar, self.signers.len);
        defer self.allocator.free(found);
        @memset(found, null);
        for (shares) |msg| {
            const h = peekHeader(msg) catch return failCombine(abort, null, .malformed_message);
            const pos = std.mem.indexOfScalar(u32, self.signers, h.from) orelse return failCombine(abort, h.from, .unexpected_message);
            if (h.round != sign_round or h.to != null or !std.mem.eql(u8, &h.sid, &self.sid)) return failCombine(abort, h.from, .unexpected_message);
            if (msg.len != self.shareLength()) return failCombine(abort, h.from, .malformed_message);
            if (found[pos] != null) return failCombine(abort, h.from, .duplicate_message);
            const body = msg[header_length .. msg.len - signature_length];
            var att: Attestation = .{ .body_hash = undefined, .signature = msg[msg.len - signature_length ..][0..signature_length].* };
            Sha256.hash(body, &att.body_hash, .{});
            if (!verifyAttestation(self.message_keys[pos], msg[0..header_length].*, att)) return failCombine(abort, h.from, .bad_signature);
            const att_len = self.signers.len * attestation_entry_length;
            if (checkAttestations(self.sid, 6, self.signers, self.message_keys, self.round6, body[0..att_len], h.from)) |ab|
                return failCombine(abort, ab.culprit, ab.fault);
            found[pos] = decodeScalar(body[att_len..][0..Ns].*) orelse return failCombine(abort, h.from, .malformed_message);
        }
        const m = message.scalar();
        const r_pt = self.r_point.point() catch unreachable;
        var s = Scalar.zero;
        for (found, self.signers, 0..) |maybe, idx, pos| {
            const s_j = maybe orelse return failCombine(abort, idx, .missing_message);
            // s_j·R == m·R̄_j + r·S_j (GG20 §4.2, equation 1).
            const lhs = r_pt.mulPublic(s_j.toBytes(.big), .big) catch return failCombine(abort, idx, .sig_share);
            const rb = self.r_bar[pos].point() catch unreachable;
            const sp = self.s_points[pos].point() catch unreachable;
            const m_rb = rb.mulPublic(m.toBytes(.big), .big) catch Secp256k1.identityElement;
            const r_sp = sp.mulPublic(self.r.toBytes(.big), .big) catch unreachable; // r ≠ 0
            if (!lhs.equivalent(m_rb.add(r_sp))) return failCombine(abort, idx, .sig_share);
            s = s.add(s_j);
        }
        if (s.isZero()) return failCombine(abort, null, .degenerate);
        const neg = s.neg();
        const s_low = if (std.mem.order(u8, &s.toBytes(.big), &neg.toBytes(.big)) == .gt) neg else s;
        const sig: signing.Signature = .{ .r = self.r.toBytes(.big), .s = s_low.toBytes(.big) };

        const pk = signing.ecdsa.PublicKey.fromSec1(&self.group_public_key.toBytes()) catch return failCombine(abort, null, .degenerate);
        const ok = switch (message) {
            .bytes => |b| sig.verify(b, pk),
            .prehashed => |d| sig.verifyPrehashed(d, pk),
        };
        ok catch return failCombine(abort, null, .degenerate);
        return sig;
    }
};

fn failCombine(abort: *?Abort, culprit: ?u32, fault: Fault) error{ProtocolAbort} {
    abort.* = .{ .culprit = culprit, .fault = fault };
    return error.ProtocolAbort;
}

/// One signer's presignature: the public half plus its secret `k_i`, `σ_i`.
/// Use exactly once (`signShare`); never copy it.
pub const Presignature = struct {
    public: PresignaturePublic,
    index: u32,
    k: Scalar,
    sigma: Scalar,
    /// SECRET: this signer's message-signing seed, for the Phase-7 share.
    message_seed: [32]u8,
    used: bool = false,

    /// Phase 7: `s_i = m·k_i + r·σ_i` as a broadcast message (owned by the
    /// caller). Wipes `k_i`, `σ_i`; a second call is `PresignatureUsed`.
    pub fn signShare(self: *Presignature, message: Message) Error![]u8 {
        if (self.used) return error.PresignatureUsed;
        self.used = true;
        defer self.wipe();
        const s_i = message.scalar().mul(self.k).add(self.public.r.mul(self.sigma));
        const bytes = try self.public.allocator.alloc(u8, self.public.shareLength());
        (Header{ .round = sign_round, .sid = self.public.sid, .from = self.index, .to = null }).write(bytes[0..header_length]);
        for (self.public.round6, 0..) |a, pos| writeAttestation(a, bytes[header_length + pos * attestation_entry_length ..][0..attestation_entry_length]);
        const att_len = self.public.signers.len * attestation_entry_length;
        bytes[header_length + att_len ..][0..Ns].* = s_i.toBytes(.big);
        var kp = Ed25519.KeyPair.generateDeterministic(self.message_seed) catch unreachable; // checked by Party.init
        defer std.crypto.secureZero(u8, std.mem.asBytes(&kp.secret_key));
        const a = sign(kp, bytes[0..header_length].*, bytes[header_length .. bytes.len - signature_length]);
        bytes[bytes.len - signature_length ..][0..signature_length].* = a.signature;
        return bytes;
    }

    fn wipe(self: *Presignature) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.k));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.sigma));
    }

    /// Also wipes the message seed (`deinit`; a used presignature keeps it
    /// until then only because the type is one value).
    fn wipeAll(self: *Presignature) void {
        self.wipe();
        std.crypto.secureZero(u8, &self.message_seed);
    }

    pub fn deinit(self: *Presignature) void {
        self.wipeAll();
        self.public.deinit();
        self.* = undefined;
    }
};

// ── tests ────────────────────────────────────────────────────────────────
//
// The decisive net is adversarial: one signer (the "cheater", position 1)
// deviates in exactly one way, and every honest signer must abort naming the
// fault — and the cheater, wherever GG20 §4.2 can attribute it. Deviations
// are injected into the cheater's outgoing bytes (and, where a consistent
// cheater would also change its own view, into its state), so each case is
// what a real malicious peer could send.

const testing = std.testing;
const builtin = @import("builtin");

const Case = enum {
    honest,
    range_proof,
    mta_swap,
    mtawc_swap,
    delta_shift,
    pedersen_proof,
    gamma_swap,
    gamma_blind,
    gamma_proof,
    pdl_proof,
    r_bar_swap,
    st_proof,
    sigma_shift,
    missing,
    duplicate,
    wrong_sid,
    wrong_round,
    misaddressed,
    truncated,
    equivocate,
    bad_signature,
    false_echo,
    /// `delta_shift`, and signer 0 lies in its §4.3 opening (a wrong γ).
    open_lie,
    /// `delta_shift`; signer 0's opening carries a round-2 message the
    /// sender never signed.
    open_lie_round2,
    /// `sigma_shift`; signer 0 opens a wrong `ν'` for signer 1.
    open_lie_nu,
};

const Observed = struct { observer: u32, abort: Abort };

const SessionResult = struct {
    presigs: []Presignature,
    aborts: []Observed,

    fn deinit(self: *SessionResult, allocator: std.mem.Allocator) void {
        for (self.presigs) |*p| p.deinit();
        allocator.free(self.presigs);
        allocator.free(self.aborts);
    }
};

/// Flips the last payload byte (the byte before the signature).
fn flipLast(bytes: []u8) void {
    bytes[bytes.len - signature_length - 1] ^= 0x01;
}

/// Offset of a round's payload in a message: past the header and, for a
/// round that attests, the attestation block.
fn payloadAt(round: u8, signers: usize) usize {
    return header_length + if (hasAttestation(round)) signers * attestation_entry_length else 0;
}

/// Re-signs a message the test changed, as its (malicious) sender would; a
/// broadcast also becomes the sender's own view of what it sent.
fn resign(party: *Party, msg: []u8, own: bool) void {
    const a = sign(party.message_kp, msg[0..header_length].*, msg[header_length .. msg.len - signature_length]);
    msg[msg.len - signature_length ..][0..signature_length].* = a.signature;
    if (own and (peekHeader(msg) catch unreachable).to == null) party.own_bc = a;
}

/// Swaps the first and third length-prefixed fields of a Phase-2 payload
/// (`c_γ` and `c_w`), or puts the first in place of the third (`both_first`).
fn rewriteRound2(allocator: std.mem.Allocator, msg: []u8, both_first: bool, signers: usize) !void {
    const payload = msg[payloadAt(2, signers) .. msg.len - signature_length];
    var off: usize = 0;
    var fields: [4][]const u8 = undefined;
    for (&fields) |*f| f.* = readLenPrefixed(payload, &off).?;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);
    const order = if (both_first) [4][]const u8{ fields[0], fields[1], fields[0], fields[3] } else [4][]const u8{ fields[2], fields[1], fields[0], fields[3] };
    for (order) |f| try appendLenPrefixed(&list, allocator, f);
    try testing.expectEqual(payload.len, list.items.len); // ciphertexts are fixed-width
    @memcpy(payload, list.items);
}

/// Drives one presigning session over `shares` with the cheater at position
/// 1 deviating per `case`; returns the presignatures (honest run) or every
/// abort seen in the round where the first one happened.
fn runSession(allocator: std.mem.Allocator, shares: []const root.KeyShare, random: std.Random, case: Case) !SessionResult {
    const t = shares.len;
    var indices: [8]u32 = undefined;
    for (shares, 0..) |s, i| indices[i] = s.index;
    var sid: SessionId = undefined;
    random.bytes(&sid);

    var parties: [8]Party = undefined;
    for (0..t) |i| parties[i] = try Party.init(allocator, shares[i], indices[0..t], sid);
    defer for (parties[0..t]) |*p| p.deinit();
    const cheat = indices[1];
    const cheat_pos = for (parties[0..t], 0..) |p, i| {
        if (p.myIndex() == cheat) break i;
    } else unreachable;

    var inboxes: [8]std.ArrayList([]const u8) = @splat(.empty);
    defer for (&inboxes) |*b| b.deinit(allocator);
    var boxes: [8]?Outbox = @splat(null);
    defer for (boxes) |b| if (b) |o| o.deinit(allocator);
    var aborts: std.ArrayList(Observed) = .empty;
    defer aborts.deinit(allocator);
    var copies: std.ArrayList([]u8) = .empty;
    defer {
        for (copies.items) |c| allocator.free(c);
        copies.deinit(allocator);
    }

    for (1..7) |round| {
        var next: [8]?Outbox = @splat(null);
        errdefer for (next) |b| if (b) |o| o.deinit(allocator);
        for (0..t) |i| {
            if ((case == .sigma_shift or case == .open_lie_nu) and round == 3 and i == cheat_pos)
                parties[i].secrets.sigma = parties[i].secrets.sigma.add(Scalar.one);
            next[i] = parties[i].advance(inboxes[i].items, random) catch |e| switch (e) {
                error.ProtocolAbort => blk: {
                    try aborts.append(allocator, .{ .observer = parties[i].myIndex(), .abort = parties[i].abort.? });
                    // An abort wipes the secrets — except one that awaits the
                    // §4.3 opening (wiped by `identify`, checked there).
                    if (parties[i].state != .opening)
                        try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&parties[i].secrets), 0));
                    break :blk null;
                },
                else => return e,
            };
        }
        for (boxes) |b| if (b) |o| o.deinit(allocator);
        boxes = next;
        if (aborts.items.len != 0) {
            try openIfTypes5or7(allocator, parties[0..t], &aborts, random, case);
            return .{ .presigs = try allocator.alloc(Presignature, 0), .aborts = try aborts.toOwnedSlice(allocator) };
        }

        // The cheater's deviation, on its outgoing bytes — re-signed, as a
        // malicious signer holding its own key would (except `bad_signature`).
        for (boxes[cheat_pos].?.messages) |m| {
            const r: u8 = @intCast(round);
            const at = payloadAt(r, t);
            switch (case) {
                .range_proof => if (r == 1 and m.to != null) flipLast(m.bytes),
                .mta_swap => if (r == 2) try rewriteRound2(allocator, m.bytes, false, t),
                .mtawc_swap => if (r == 2) try rewriteRound2(allocator, m.bytes, true, t),
                .delta_shift, .open_lie, .open_lie_round2 => if (r == 3) {
                    const me = &parties[cheat_pos].peers[parties[cheat_pos].me];
                    me.delta = me.delta.add(Scalar.one);
                    m.bytes[at..][0..Ns].* = me.delta.toBytes(.big);
                },
                .pedersen_proof => if (r == 3) flipLast(m.bytes),
                .gamma_swap => if (r == 4) {
                    m.bytes[at..][0..Ne].* = (Element.fromPoint(Secp256k1.basePoint) catch unreachable).toBytes();
                },
                .gamma_blind => if (r == 4) {
                    m.bytes[at + Ne] ^= 0x01;
                },
                .gamma_proof => if (r == 4) flipLast(m.bytes),
                .pdl_proof => if (r == 5 and m.to != null) {
                    m.bytes[m.bytes.len - signature_length - Ne - 1] ^= 0x01; // last byte of the range proof's s2
                },
                .r_bar_swap => if (r == 5 and m.to == null) {
                    m.bytes[at..][0..Ne].* = (Element.fromPoint(Secp256k1.basePoint) catch unreachable).toBytes();
                },
                .st_proof => if (r == 6) flipLast(m.bytes),
                .wrong_sid => if (r == 2) {
                    m.bytes[2] ^= 0x01;
                },
                .wrong_round => if (r == 1 and m.to == null) {
                    m.bytes[1] = 2;
                },
                .misaddressed => if (r == 1 and m.to != null) {
                    std.mem.writeInt(u32, m.bytes[38..42], 9999, .big);
                },
                // Lies about signer 0's round-3 broadcast in its round-4
                // attestations (a body hash signer 0 never signed).
                .false_echo => if (r == 4) {
                    m.bytes[header_length] ^= 0x01;
                },
                else => {},
            }
            if (case == .bad_signature) {
                if (r == 3 and m.to == null) m.bytes[m.bytes.len - 1] ^= 0x01;
            } else resign(&parties[cheat_pos], m.bytes, true);
        }

        for (&inboxes) |*b| b.clearRetainingCapacity();
        for (0..t) |from| {
            for (boxes[from].?.messages) |m| {
                for (0..t) |to| {
                    // Every party also gets its own broadcasts back, as from a
                    // bus: they must be ignored, not taken as a fault.
                    if (to == from and m.to != null) continue;
                    if (m.to) |dst| if (dst != parties[to].myIndex()) continue;
                    const deliver = from == cheat_pos and to != cheat_pos;
                    // Equivocation: the last signer gets a different δ than
                    // everyone else, on a broadcast whose proof does not cover δ.
                    if (deliver and case == .equivocate and round == 3 and m.to == null and to == t - 1) {
                        const copy = try allocator.dupe(u8, m.bytes);
                        try copies.append(allocator, copy);
                        const at = payloadAt(3, t);
                        const d = Scalar.fromBytes(copy[at..][0..Ns].*, .big) catch unreachable;
                        copy[at..][0..Ns].* = d.add(Scalar.one).toBytes(.big);
                        // The cheater signs this second version too.
                        resign(&parties[cheat_pos], copy, false);
                        try inboxes[to].append(allocator, copy);
                        continue;
                    }
                    if (deliver and case == .missing and round == 3) continue;
                    if (deliver and case == .truncated and round == 4) {
                        try inboxes[to].append(allocator, m.bytes[0 .. m.bytes.len - 1]);
                        continue;
                    }
                    try inboxes[to].append(allocator, m.bytes);
                    if (deliver and case == .duplicate and round == 4) try inboxes[to].append(allocator, m.bytes);
                }
            }
        }
    }

    const presigs = try allocator.alloc(Presignature, t);
    var ok: [8]bool = @splat(false);
    errdefer {
        for (presigs, ok[0..t]) |*p, made| if (made) p.deinit();
        allocator.free(presigs);
    }
    for (0..t) |i| {
        presigs[i] = parties[i].finish(inboxes[i].items) catch |e| switch (e) {
            error.ProtocolAbort => {
                try aborts.append(allocator, .{ .observer = parties[i].myIndex(), .abort = parties[i].abort.? });
                continue;
            },
            else => return e,
        };
        ok[i] = true;
    }
    if (aborts.items.len != 0) {
        for (presigs, ok[0..t]) |*p, made| if (made) p.deinit();
        allocator.free(presigs);
        try openIfTypes5or7(allocator, parties[0..t], &aborts, random, case);
        return .{ .presigs = try allocator.alloc(Presignature, 0), .aborts = try aborts.toOwnedSlice(allocator) };
    }
    return .{ .presigs = presigs, .aborts = try aborts.toOwnedSlice(allocator) };
}

/// When every party aborted with an unattributed type 5 or 7, runs the §4.3
/// opening among them and replaces each abort by that party's verdict.
fn openIfTypes5or7(allocator: std.mem.Allocator, parties: []Party, aborts: *std.ArrayList(Observed), random: std.Random, case: Case) !void {
    if (aborts.items.len != parties.len) return;
    for (aborts.items) |a| {
        if (a.abort.culprit != null or (a.abort.fault != .r_bar_sum and a.abort.fault != .s_sum)) return;
    }
    var openings: [8]Outbox = undefined;
    for (parties, 0..) |*p, i| openings[i] = try p.openAbort(random);
    defer for (openings[0..parties.len]) |o| o.deinit(allocator);
    if (case == .open_lie or case == .open_lie_round2 or case == .open_lie_nu) {
        // Signer 0 lies in its opening, and signs the lie.
        const m = openings[0].messages[0].bytes;
        const body = m[header_length .. m.len - signature_length];
        var sections: [8]OpenSection = undefined;
        _ = parseOpening(body, parties[0].abort.?.fault, 0, sections[0..parties.len]).?;
        const at = switch (case) {
            .open_lie => header_length + 1 + Ns + 4 + paillier.modulus_sq_bytes + Ns - 1, // γ
            .open_lie_round2 => @intFromPtr(sections[1].round2.ptr) - @intFromPtr(m.ptr) + header_length + 10,
            else => @intFromPtr(sections[1].mask.ptr) - @intFromPtr(m.ptr) + 7,
        };
        m[at] ^= 0x01;
        resign(&parties[0], m, false);
    }
    for (parties, aborts.items) |*p, *a| {
        var inbox: [8][]const u8 = undefined;
        var k: usize = 0;
        for (openings[0..parties.len]) |o| {
            inbox[k] = o.messages[0].bytes;
            k += 1;
        }
        a.abort = try p.identify(inbox[0..k]);
        try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&p.secrets), 0));
    }
}

fn expectLowS(sig: signing.Signature) !void {
    const s = try Scalar.fromBytes(sig.s, .big);
    try testing.expect(std.mem.order(u8, &sig.s, &s.neg().toBytes(.big)) != .gt);
}

/// Signs `message` with every presignature, combines with the first one's
/// public half.
fn signAll(allocator: std.mem.Allocator, presigs: []Presignature, message: Message, abort: *?Abort) !signing.Signature {
    var shares: [8][]u8 = undefined;
    for (presigs, 0..) |*p, i| shares[i] = try p.signShare(message);
    defer for (shares[0..presigs.len]) |s| allocator.free(s);
    return presigs[0].public.combine(message, shares[0..presigs.len], abort);
}

test "presign: per-signer state machines, 2-of-3 and 3-of-3, sign bytes and a prehashed digest; std ECDSA verifies" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x7072_6573_6967_6e31);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);
    const pk = try signing.ecdsa.PublicKey.fromSec1(&kg.key_shares[0].group_public_key.toBytes());

    // 2-of-3 over shares {3, 1} (out of order on purpose).
    {
        var res = try runSession(allocator, &[_]root.KeyShare{ kg.key_shares[2], kg.key_shares[0] }, random, .honest);
        defer res.deinit(allocator);
        try testing.expectEqual(@as(usize, 0), res.aborts.len);
        var abort: ?Abort = null;
        const sig = try signAll(allocator, res.presigs, .{ .bytes = "presigned, then signed" }, &abort);
        try sig.verify("presigned, then signed", pk);
        try expectLowS(sig);
        try testing.expect(abort == null);
        // A presignature signs once.
        try testing.expectError(error.PresignatureUsed, res.presigs[0].signShare(.{ .bytes = "again" }));
    }
    // 3-of-3, prehashed.
    {
        var res = try runSession(allocator, kg.key_shares, random, .honest);
        defer res.deinit(allocator);
        var digest: [32]u8 = undefined;
        Sha256.hash("prehashed", &digest, .{});
        var abort: ?Abort = null;
        const sig = try signAll(allocator, res.presigs, .{ .prehashed = digest }, &abort);
        try sig.verifyPrehashed(digest, pk);
        try sig.verify("prehashed", pk);
        try expectLowS(sig);
    }
}

test "presign: every deviation aborts every honest signer, naming the cheater where GG20 §4.2 can" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6368_6561_7465_7273);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);
    const shares = [_]root.KeyShare{ kg.key_shares[0], kg.key_shares[1], kg.key_shares[2] };
    const cheat = shares[1].index;

    const Expect = struct { case: Case, fault: Fault, attributed: bool };
    const cases = [_]Expect{
        .{ .case = .range_proof, .fault = .range_proof, .attributed = true },
        .{ .case = .mta_swap, .fault = .mta_proof, .attributed = true },
        .{ .case = .mtawc_swap, .fault = .mtawc_proof, .attributed = true },
        .{ .case = .pedersen_proof, .fault = .pedersen_proof, .attributed = true },
        .{ .case = .gamma_swap, .fault = .gamma_decommitment, .attributed = true },
        .{ .case = .gamma_blind, .fault = .gamma_decommitment, .attributed = true },
        .{ .case = .gamma_proof, .fault = .gamma_proof, .attributed = true },
        .{ .case = .pdl_proof, .fault = .pdl_proof, .attributed = true },
        .{ .case = .r_bar_swap, .fault = .pdl_proof, .attributed = true },
        .{ .case = .st_proof, .fault = .st_proof, .attributed = true },
        .{ .case = .missing, .fault = .missing_message, .attributed = true },
        .{ .case = .duplicate, .fault = .duplicate_message, .attributed = true },
        .{ .case = .wrong_sid, .fault = .unexpected_message, .attributed = true },
        .{ .case = .wrong_round, .fault = .unexpected_message, .attributed = true },
        .{ .case = .misaddressed, .fault = .unexpected_message, .attributed = true },
        // A truncated message no longer carries its signature.
        .{ .case = .truncated, .fault = .bad_signature, .attributed = true },
        .{ .case = .bad_signature, .fault = .bad_signature, .attributed = true },
        // Different broadcasts to different signers: caught by the signed
        // attestations before anyone acts on the split view (review F1) —
        // and since the cheater signed both versions, it is named.
        .{ .case = .equivocate, .fault = .equivocation, .attributed = true },
        // An attestation of a broadcast its sender never signed: the
        // attester is named, not the signer it misquotes.
        .{ .case = .false_echo, .fault = .equivocation, .attributed = true },
        // Types 5 and 7: consistent lies every proof accepts; caught by the
        // sums, then named by the §4.3 opening (`openAbort`, `identify`).
        .{ .case = .delta_shift, .fault = .r_bar_sum, .attributed = true },
        .{ .case = .sigma_shift, .fault = .s_sum, .attributed = true },
    };
    for (cases) |c| {
        var res = try runSession(allocator, &shares, random, c.case);
        defer res.deinit(allocator);
        errdefer std.debug.print("case {s}: {any}\n", .{ @tagName(c.case), res.aborts });
        try testing.expectEqual(@as(usize, 0), res.presigs.len);
        // Every honest signer aborted (p2p deviations hit both: the cheater
        // sends one to each), and only with the expected verdict.
        var honest_aborts: usize = 0;
        for (res.aborts) |a| {
            if (a.observer == cheat) {
                // The cheater's own party only ever sees honest input — except
                // its own second version of a broadcast, which the victims'
                // attestations show it: then it names itself.
                if (c.case == .equivocate) {
                    try testing.expectEqual(Abort{ .culprit = cheat, .fault = .equivocation }, a.abort);
                } else if (c.case == .delta_shift or c.case == .sigma_shift) {
                    // It opens too, and its own opening convicts it.
                    try testing.expectEqual(Abort{ .culprit = cheat, .fault = c.fault }, a.abort);
                } else try testing.expect(!c.attributed);
                continue;
            }
            honest_aborts += 1;
            try testing.expectEqual(c.fault, a.abort.fault);
            try testing.expectEqual(if (c.attributed) @as(?u32, cheat) else null, a.abort.culprit);
        }
        try testing.expectEqual(shares.len - 1, honest_aborts);
    }
}

test "presign: §4.3 opening — a signer lying in its opening is named by everyone who received the lie" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6f70_656e_6c69_65);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);
    const shares = [_]root.KeyShare{ kg.key_shares[0], kg.key_shares[1], kg.key_shares[2] };
    var res = try runSession(allocator, &shares, random, .open_lie);
    defer res.deinit(allocator);
    try testing.expectEqual(shares.len, res.aborts.len);
    for (res.aborts) |a| {
        // Signer 0 checks its own opening as it made it (true γ) and so
        // names the δ cheater; everyone else saw the false γ and names it.
        const want = if (a.observer == shares[0].index) shares[1].index else shares[0].index;
        try testing.expectEqual(Abort{ .culprit = want, .fault = .r_bar_sum }, a.abort);
    }
}

test "presign: §4.3 opening — a forged round-2 message or a false ν' in an opening names the opener" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6f70_656e_6c69_6532);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);
    const shares = [_]root.KeyShare{ kg.key_shares[0], kg.key_shares[1], kg.key_shares[2] };
    for ([_]struct { Case, Fault }{ .{ .open_lie_round2, .r_bar_sum }, .{ .open_lie_nu, .s_sum } }) |c| {
        var res = try runSession(allocator, &shares, random, c[0]);
        defer res.deinit(allocator);
        errdefer std.debug.print("case {s}: {any}\n", .{ @tagName(c[0]), res.aborts });
        try testing.expectEqual(shares.len, res.aborts.len);
        for (res.aborts) |a| {
            if (a.observer == shares[0].index) continue; // it checks its own honest version
            try testing.expectEqual(Abort{ .culprit = shares[0].index, .fault = c[1] }, a.abort);
        }
    }
}

test "presign: a wrong signature share is named by combine; a missing or foreign one is refused" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x7369_6773_6861_7265);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 2);
    defer kg.deinit(allocator);

    var res = try runSession(allocator, kg.key_shares, random, .honest);
    defer res.deinit(allocator);
    const msg: Message = .{ .bytes = "share check" };
    const s1 = try res.presigs[0].signShare(msg);
    defer allocator.free(s1);
    const s2 = try res.presigs[1].signShare(msg);
    defer allocator.free(s2);
    const public = &res.presigs[0].public;
    var abort: ?Abort = null;

    // Signer 2's share shifted by one (and re-signed by signer 2): equation
    // (1) of §4.2 fails for 2 only.
    const kp2 = try Ed25519.KeyPair.generateDeterministic(kg.key_shares[1].message_seed);
    const s_at = header_length + public.signers.len * attestation_entry_length;
    const bad = try allocator.dupe(u8, s2);
    defer allocator.free(bad);
    const s_val = Scalar.fromBytes(bad[s_at..][0..Ns].*, .big) catch unreachable;
    bad[s_at..][0..Ns].* = s_val.add(Scalar.one).toBytes(.big);
    bad[bad.len - signature_length ..][0..signature_length].* = sign(kp2, bad[0..header_length].*, bad[header_length .. bad.len - signature_length]).signature;
    try testing.expectError(error.ProtocolAbort, public.combine(msg, &[_][]const u8{ s1, bad }, &abort));
    try testing.expectEqual(Abort{ .culprit = kg.key_shares[1].index, .fault = .sig_share }, abort.?);

    // The same change without signer 2's signature: refused before any math.
    const unsigned = try allocator.dupe(u8, s2);
    defer allocator.free(unsigned);
    unsigned[s_at] ^= 0x01;
    try testing.expectError(error.ProtocolAbort, public.combine(msg, &[_][]const u8{ s1, unsigned }, &abort));
    try testing.expectEqual(Abort{ .culprit = kg.key_shares[1].index, .fault = .bad_signature }, abort.?);

    // Signer 2 attesting a Phase-6 broadcast of signer 1 that signer 1 never
    // signed: signer 2 is named.
    const lying = try allocator.dupe(u8, s2);
    defer allocator.free(lying);
    lying[header_length] ^= 0x01;
    lying[lying.len - signature_length ..][0..signature_length].* = sign(kp2, lying[0..header_length].*, lying[header_length .. lying.len - signature_length]).signature;
    try testing.expectError(error.ProtocolAbort, public.combine(msg, &[_][]const u8{ s1, lying }, &abort));
    try testing.expectEqual(Abort{ .culprit = kg.key_shares[1].index, .fault = .equivocation }, abort.?);

    // The right shares for another message: every share fails, the first is named.
    try testing.expectError(error.ProtocolAbort, public.combine(.{ .bytes = "other" }, &[_][]const u8{ s1, s2 }, &abort));
    try testing.expectEqual(Fault.sig_share, abort.?.fault);

    try testing.expectError(error.ProtocolAbort, public.combine(msg, &[_][]const u8{s1}, &abort));
    try testing.expectEqual(Abort{ .culprit = kg.key_shares[1].index, .fault = .missing_message }, abort.?);
    try testing.expectError(error.ProtocolAbort, public.combine(msg, &[_][]const u8{ s1, s1 }, &abort));
    try testing.expectEqual(Fault.duplicate_message, abort.?.fault);

    const sig = try public.combine(msg, &[_][]const u8{ s2, s1 }, &abort);
    try testing.expect(abort == null);
    const pk = try signing.ecdsa.PublicKey.fromSec1(&kg.key_shares[0].group_public_key.toBytes());
    try sig.verify("share check", pk);
    try expectLowS(sig);
}

test "presign: init refuses a bad signer set" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6261_6473_6574);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);
    const sid = [_]u8{7} ** 32;
    const share = kg.key_shares[0];
    try testing.expectError(error.InvalidParameters, Party.init(allocator, share, &[_]u32{1}, sid));
    try testing.expectError(error.InvalidParameters, Party.init(allocator, share, &[_]u32{ 2, 3 }, sid));
    try testing.expectError(error.InvalidParameters, Party.init(allocator, share, &[_]u32{ 1, 1 }, sid));
    try testing.expectError(error.InvalidParameters, Party.init(allocator, share, &[_]u32{ 1, 4 }, sid));
    try testing.expectError(error.InvalidParameters, Party.init(allocator, share, &[_]u32{ 1, 2, 3, 4 }, sid));
    // Fewer signers than the threshold the share was dealt for.
    var t3 = share;
    t3.t = 3;
    try testing.expectError(error.InvalidParameters, Party.init(allocator, t3, &[_]u32{ 1, 2 }, sid));
    // A public-keys list naming signer 2 twice.
    const dup = try std.mem.concat(allocator, root.PartyPublicKeys, &.{ share.public_keys.entries, share.public_keys.entries[1..2] });
    defer allocator.free(dup);
    var dup_share = share;
    dup_share.public_keys = .{ .entries = dup };
    try testing.expectError(error.InvalidParameters, Party.init(allocator, dup_share, &[_]u32{ 1, 2 }, sid));
    // Signer 2's announced X_2 replaced: signer 1's own share is fine, but
    // Σ λ_j·X_j over {1, 2} is no longer the group key.
    const bad_x = try allocator.dupe(root.PartyPublicKeys, share.public_keys.entries);
    defer allocator.free(bad_x);
    bad_x[1].verifying_share = try Element.fromPoint(Secp256k1.basePoint);
    var bad_x_share = share;
    bad_x_share.public_keys = .{ .entries = bad_x };
    try testing.expectError(error.InvalidParameters, Party.init(allocator, bad_x_share, &[_]u32{ 1, 2 }, sid));
    // Public material intact, but signer 1's secret share is not the x_1
    // behind X_1: only the own-share check can see it.
    var bad_secret = share;
    bad_secret.secret_share = share.secret_share.add(Scalar.one);
    try testing.expectError(error.InvalidParameters, Party.init(allocator, bad_secret, &[_]u32{ 1, 2 }, sid));
    var p = try Party.init(allocator, share, &[_]u32{ 3, 1 }, sid);
    defer p.deinit();
    try testing.expectError(error.InvalidParameters, p.advance(&[_][]const u8{"x"}, random));
    try testing.expectError(error.InvalidState, p.finish(&.{}));
}

test "fuzz: peekHeader and PresignaturePublic.combine never panic on arbitrary shares" {
    try testing.fuzz({}, fuzzCombine, .{});
}
fn fuzzCombine(_: void, smith: *std.testing.Smith) !void {
    var buf: [2][header_length + 2 * attestation_entry_length + Ns + signature_length + 8]u8 = undefined;
    var shares: [2][]const u8 = undefined;
    for (&buf, &shares) |*b, *s| s.* = b[0..smith.slice(b)];
    for (shares) |s| _ = peekHeader(s) catch {};
    const g = Element.fromPoint(Secp256k1.basePoint) catch unreachable;
    var signers = [_]u32{ 1, 2 };
    var r_bar = [_]Element{ g, g };
    var s_points = [_]Element{ g, g };
    var round6: [2]Attestation = @splat(.{ .body_hash = @splat(0), .signature = @splat(0) });
    const kp = Ed25519.KeyPair.generateDeterministic(@splat(1)) catch unreachable;
    var keys = [_]Ed25519.PublicKey{ kp.public_key, kp.public_key };
    const public: PresignaturePublic = .{
        .allocator = testing.allocator,
        .sid = [_]u8{0} ** 32,
        .group_public_key = g,
        .signers = &signers,
        .r_point = g,
        .r = Scalar.one,
        .r_bar = &r_bar,
        .s_points = &s_points,
        .round6 = &round6,
        .message_keys = &keys,
    };
    var abort: ?Abort = null;
    _ = public.combine(.{ .bytes = "fuzz" }, &shares, &abort) catch {};
}
