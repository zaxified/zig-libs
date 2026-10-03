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
//! signed broadcast), `echoOpenings` on everyone's openings (its echo: an
//! attestation of the openings as received, so two versions of one opening
//! name their signer) and `identify` on everyone's echoes, which returns the
//! culprit and wipes the secrets; `abandon` gives an opening up. What is opened never includes the key
//! share (type 7 opens the `k_i·w_j` masks and proves `S_i = σ_i·R` by DLEQ
//! against a `σ_i·G` everyone recomputes, instead of revealing `σ_i`).
//!
//! ## Signed messages and broadcast consistency (in the protocol, not assumed)
//!
//! Every message ends with its sender's Ed25519 signature over
//! `message_domain || header || SHA-256(body)` (`signedBytes`), under the
//! `message_key` each signer publishes with its key share. Only such a
//! message — signed by its claimed sender for this round of this session —
//! is evidence against that sender; a message whose signature fails, or a
//! signed one of another round or session (a replay), is dropped as transport
//! noise, and a sender whose valid message never arrives is named with
//! `missing_message`.
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
//!   signers || SHA-256(public-key table))`, so a signer configured with
//!   another set, key or key table is refused at the first header; it is
//!   bound into every message and every proof of this file.
//! - **Timeouts.** A peer that never sends is the caller's to detect; once
//!   the inbox is handed in, a missing message is a `missing_message` fault.
//! - **One presignature, one message.** `signShare` wipes `k_i`/`σ_i` and
//!   refuses a second call; a presignature must never be copied (two
//!   messages under one `R` reveal the key). To keep presignatures across a
//!   restart, use `PresignaturePool` over a `PresignatureStore` whose `take`
//!   hands each record out at most once (`MemoryPresignatureStore` for one
//!   process); `Presignature.toBytesAlloc` is the codec underneath.

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
pub const session_domain = "threshold_ecdsa/presign/session/v2";
/// Domain of every message signature (`signedBytes`).
pub const message_domain = "threshold_ecdsa/presign/message/v2";

/// Rounds whose messages attest the previous round's broadcasts: every round
/// that follows a broadcast round (1, 3, 4, 5, 6), Phase 7 included.
pub fn hasAttestation(round: u8) bool {
    return round == 2 or (round >= 4 and round <= sign_round) or round == open_echo_round;
}

/// The §4.3 opening round: after a type-5 or type-7 abort every signer
/// broadcasts what it must reveal (`Party.openAbort`).
pub const open_round: u8 = 8;
/// The echo of the openings (`Party.echoOpenings`): an empty broadcast whose
/// attestation block carries the round-8 openings as its sender received
/// them, so a signer who showed different signed openings to different
/// peers is named before anyone judges an opening (review 2026-10-03 F5).
pub const open_echo_round: u8 = 9;

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
    Ed25519.Signature.fromBytes(a.signature).verifyStrict(&signedBytes(header, a.body_hash), key) catch return false;
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
/// block's sender (`from`) lied about what it received. An entry whose hash
/// matches is taken without checking its signature: the block is a hash
/// echo for this comparison, not evidence to forward to anyone else
/// (review 2026-10-03 F8).
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
    /// A signed message that does not decode (bad length, bad field).
    malformed_message,
    /// A signed message of this round of the wrong kind: a broadcast in a
    /// round of p2p messages, or the reverse.
    unexpected_message,
    /// Two different signed messages for one slot of one round.
    duplicate_message,
    /// No validly signed message for a slot. Messages that are not signed by
    /// their claimed sender for this round of this session are dropped as
    /// transport noise, so this also covers a sender whose message was
    /// mangled, forged or misrouted on the way (review 2026-10-03 F3).
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

const State = enum { round1, round2, round3, round4, round5, round6, finish, done, aborted, opening, echo, identify };

/// What one signer keeps per peer for the GG20 §4.3 opening, until the
/// presignature is finished (or the opening is done).
const PeerOpen = struct {
    /// The signed round-2 message this signer (as Alice) got from the peer.
    round2: ?[]u8 = null,
    /// SECRET until opened: this signer's (as Bob) mask `β'` and Paillier
    /// randomness in the `k_j·γ_i` response it sent the peer.
    gamma_beta_prime: [zkproofs.beta_prime_bytes]u8 = @splat(0),
    gamma_r: paillier.Fe = undefined,
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
    /// Every signer's opening body as this party received it (owned copies),
    /// from `echoOpenings` to `identify`.
    opened: [][]u8 = &.{},
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
                .message_key = root.decodeMessageKey(pub_keys.message_key) catch return error.InvalidParameters,
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
        // key, the threshold, the signing set and the public-key table:
        // signers configured with a different set, or holding different
        // Paillier/ring-Pedersen/message keys for someone (a split refresh),
        // fail at the first header instead of later, at a proof that blames a
        // peer (review F7; the table since review 2026-10-03 F9).
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
        {
            const table = share.public_keys.toBytesAlloc(allocator) catch |e|
                return if (e == error.OutOfMemory) error.OutOfMemory else error.InvalidParameters;
            defer allocator.free(table);
            var th: [32]u8 = undefined;
            Sha256.hash(table, &th, .{});
            h.update(&th);
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
        self.freeOpened();
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

    /// Gives up a pending §4.3 opening — its round timed out, or the caller
    /// will not identify: wipes the nonce material and key-share copy kept
    /// for it now rather than at `deinit` (review 2026-10-03 F11). The abort
    /// stays unattributed. No effect in any other state.
    pub fn abandon(self: *Party) void {
        if (self.state != .opening and self.state != .echo and self.state != .identify) return;
        self.state = .aborted;
        self.wipe();
        self.freeOpened();
    }

    /// A type-5 or type-7 abort: unattributed for now, and the secrets the
    /// §4.3 opening reveals are kept (`openAbort`, `identify`, or `abandon`).
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
            .finish, .done, .aborted, .opening, .echo, .identify => return error.InvalidState,
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
    ///
    /// Only a message its sender signed, for this round of this session and
    /// addressed to all or to this party, is evidence against that sender.
    /// Anything else — garbage, a forged header, a bad signature, another
    /// session's or round's message, a copy of a message already taken — is
    /// transport noise and is dropped (review 2026-10-03 F3: a forged
    /// `from = A` header used to abort the session naming honest A). If the
    /// sender's real message never arrives, `missing_message` names it, as
    /// for any loss.
    fn collect(self: *Party, inbox: []const []const u8, round: u8, want_bc: bool, want_p2p: bool, slots: Slots) Error!void {
        @memset(slots.broadcast, null);
        @memset(slots.p2p, null);
        const bc_att = try self.allocator.alloc(Attestation, self.peers.len);
        defer self.allocator.free(bc_att);
        const p2p_hash = try self.allocator.alloc([32]u8, self.peers.len);
        defer self.allocator.free(p2p_hash);
        const keys = try self.allocator.alloc(Ed25519.PublicKey, self.peers.len);
        defer self.allocator.free(keys);
        self.messageKeys(keys);
        const att_len: usize = if (hasAttestation(round)) self.peers.len * attestation_entry_length else 0;
        for (inbox) |msg| {
            const h = peekHeader(msg) catch continue;
            // A bus that hands a party its own broadcast back is not a fault.
            if (h.from == self.myIndex()) continue;
            const pos = std.mem.indexOfScalar(u32, self.signers, h.from) orelse continue;
            if (msg.len < header_length + signature_length) continue;
            const body = msg[header_length .. msg.len - signature_length];
            var att: Attestation = .{ .body_hash = undefined, .signature = msg[msg.len - signature_length ..][0..signature_length].* };
            Sha256.hash(body, &att.body_hash, .{});
            if (!verifyAttestation(self.peers[pos].message_key, msg[0..header_length].*, att)) continue;
            // Signed, but for another round or session (a replay), or for
            // another recipient (misrouted): no evidence of anything here.
            if (h.round != round or !std.mem.eql(u8, &h.sid, &self.sid)) continue;
            if (h.to) |to| if (to != self.myIndex()) continue;
            // From here `h.from` signed this message for this round.
            if (if (h.to == null) !want_bc else !want_p2p) return self.fail(h.from, .unexpected_message);
            const slot = if (h.to == null) &slots.broadcast[pos] else &slots.p2p[pos];
            const seen = if (h.to == null) &bc_att[pos].body_hash else &p2p_hash[pos];
            if (slot.* != null) {
                // The same message twice is a replay; two signed versions are the sender's.
                if (std.mem.eql(u8, seen, &att.body_hash)) continue;
                return self.fail(h.from, .duplicate_message);
            }
            var payload = body;
            if (att_len != 0) {
                if (payload.len < att_len) return self.fail(h.from, .malformed_message);
                if (checkAttestations(self.sid, round - 1, self.signers, keys, self.last_bc, payload[0..att_len], h.from)) |ab|
                    return self.fail(ab.culprit, ab.fault);
                payload = payload[att_len..];
            }
            if (h.to == null) bc_att[pos] = att else p2p_hash[pos] = att.body_hash;
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

    /// Maps an error from proving under peer `j`'s keys: allocation failure
    /// propagates, everything else is `j`'s fault. That holds because every
    /// other input of these provers is sound by construction: this party's
    /// own Paillier key and aux tuple passed the same checks in `round1`
    /// (review F3), its secrets are canonical scalars and `random` cannot
    /// fail — so a refused key, tuple, floor or a Paillier operation that
    /// fails can only come from `j`'s published key, tuple or ciphertext
    /// (review 2026-10-03 F15: checked, kept). The parameter is the provers'
    /// error sets, not `anyerror`, so a new error variant there has to be
    /// placed here deliberately.
    fn proveFailed(self: *Party, j: u32, err: ProverError) Error {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => self.fail(j, .invalid_peer_keys),
        };
    }

    const ProverError = zkproofs.ProveError || mta.MtaError;

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
    ///   and that ciphertext's randomness (a proof of the decryption), and a
    ///   DLEQ proof that `S_i = σ_i·R` for the `σ_i·G` everyone computes
    ///   from the opened values (`σ_i` itself would reveal `w_i`). The
    ///   signer's own masks `ν'` as Bob stay secret: `μ'_ji = k_j·w_i + ν'`
    ///   is public now and `k_j` too, so a published `ν'` would hand out
    ///   `w_i = (μ'_ji − ν')/k_j` (review 2026-10-03 F1 — the first version
    ///   did exactly that). Everyone derives `ν'·G = μ'_ji·G − k_j·W_i`
    ///   instead; `μ'_ji` alone hides `k_j·w_i` behind `ν' < q⁵`.
    ///
    /// Then hand every peer's opening to `echoOpenings`, and every peer's
    /// echo to `identify`.
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
        self.state = .echo;
        return out.finish();
    }

    /// Takes every signer's opening (the inbox: one `openAbort` broadcast
    /// from every peer), keeps a copy, and returns this party's echo: an
    /// empty broadcast attesting the openings as received (round 9). A peer
    /// whose opening is missing or unsigned is named here (`ProtocolAbort`,
    /// the verdict in `abort`; the party is done, its secrets wiped).
    pub fn echoOpenings(self: *Party, inbox: []const []const u8) Error!Outbox {
        if (self.state != .echo) return error.InvalidState;
        return self.echoInner(inbox) catch |e| {
            if (self.state != .aborted) {
                self.state = .aborted;
                self.wipe();
            }
            return e;
        };
    }

    fn echoInner(self: *Party, inbox: []const []const u8) Error!Outbox {
        const n = self.peers.len;
        const bc = try self.allocator.alloc(?[]const u8, n);
        defer self.allocator.free(bc);
        const p2p = try self.allocator.alloc(?[]const u8, n);
        defer self.allocator.free(p2p);
        try self.collect(inbox, open_round, true, false, .{ .broadcast = bc, .p2p = p2p });
        const own = self.own_open.?;
        bc[self.me] = own[header_length .. own.len - signature_length];
        const opened = try self.allocator.alloc([]u8, n);
        var copied: usize = 0;
        errdefer {
            for (opened[0..copied]) |o| self.allocator.free(o);
            self.allocator.free(opened);
        }
        while (copied < n) : (copied += 1) opened[copied] = try self.allocator.dupe(u8, bc[copied].?);
        self.opened = opened;
        var out: OutboxBuilder = .{ .allocator = self.allocator };
        errdefer out.deinit();
        try out.add(self, open_echo_round, null, &.{});
        self.state = .identify;
        return out.finish();
    }

    fn freeOpened(self: *Party) void {
        for (self.opened) |o| {
            std.crypto.secureZero(u8, o);
            self.allocator.free(o);
        }
        if (self.opened.len != 0) self.allocator.free(self.opened);
        self.opened = &.{};
    }

    /// Checks every peer's echo (round 9) against the openings this party
    /// received — two signed versions of one opening name the signer who made
    /// them (`equivocation`), so honest signers judge the same openings
    /// (review 2026-10-03 F5) — then every opening, and names the culprit:
    /// the first signer, in signer order of the checks below, whose opening
    /// contradicts its earlier signed messages or the values it broadcast.
    /// Returns the verdict (also in `abort`); the party is done afterwards,
    /// its secrets wiped. A peer whose echo is missing or unsigned, or whose
    /// opening is malformed, is the culprit.
    pub fn identify(self: *Party, inbox: []const []const u8) Error!Abort {
        if (self.state != .identify) return error.InvalidState;
        const fault = self.abort.?.fault;
        const verdict = self.identifyInner(inbox, fault) catch |e| switch (e) {
            error.ProtocolAbort => self.abort.?, // from `collect`: missing, unsigned, equivocation
            else => {
                self.state = .aborted;
                self.wipe();
                self.freeOpened();
                return e;
            },
        };
        self.abort = verdict;
        self.state = .aborted;
        self.wipe();
        self.freeOpened();
        return verdict;
    }

    fn identifyInner(self: *Party, inbox: []const []const u8, fault: Fault) Error!Abort {
        const n = self.peers.len;
        const bc = try self.allocator.alloc(?[]const u8, n);
        defer self.allocator.free(bc);
        const p2p = try self.allocator.alloc(?[]const u8, n);
        defer self.allocator.free(p2p);
        try self.collect(inbox, open_echo_round, true, false, .{ .broadcast = bc, .p2p = p2p });

        const openings = try self.allocator.alloc(Opening, n);
        defer self.allocator.free(openings);
        const sections = try self.allocator.alloc(OpenSection, n * n);
        defer self.allocator.free(sections);
        for (openings, self.opened, 0..) |*o, body, i| {
            o.* = parseOpening(body, fault, i, sections[i * n ..][0..n]) orelse
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
        // Every Alice's decryption first, so a lie in one is named before
        // any σ is derived from it (review 2026-10-03 F2).
        const mu = try self.allocator.alloc(Scalar, n * n);
        defer self.allocator.free(mu);
        for (0..n) |a| for (0..n) |b| {
            if (a == b) continue;
            const fields = self.openedRound2(sections[a * n + b], a, b) orelse return self.signers[a];
            const pk = self.peers[a].pk;
            const alice = sections[a * n + b];
            var n_buf: [paillier.modulus_bytes]u8 = undefined;
            const n_len = pk.nByteLen();
            pk.nToBytes(n_buf[0..n_len]) catch unreachable;
            // The plaintext is unique only below N: (1+N)^m has period N, so
            // `m + N` re-encrypts to the same ciphertext but lifts to another μ.
            if (alice.plain.len != n_len or std.mem.order(u8, alice.plain, n_buf[0..n_len]) != .lt) return self.signers[a];
            // a's decryption of c_w, with its randomness: re-encrypt and compare.
            const m_fe = paillier.Fe.fromBytes(pk.n_sq, alice.plain, .big) catch return self.signers[a];
            const rho = paillier.Fe.fromBytes(pk.n_sq, alice.rand, .big) catch return self.signers[a];
            const again = paillier.encrypt(pk, m_fe, rho) catch return self.signers[a];
            if (!std.mem.eql(u8, fields[2], &ciphertextBytes(again))) return self.signers[a];
            mu[a * n + b] = mta.centeredModQ(alice.plain, n_buf[0..n_len]);
        };
        for (openings, self.peers, 0..) |o, p, i| {
            // σ_i = k_i·w_i + Σ_b μ'_ib − Σ_b ν'_ib, with i's own masks as Bob
            // known only in the exponent: ν'_ib·G = μ'_bi·G − k_b·W_i.
            const wi = p.w_point.point() catch unreachable;
            var scalar_part = Scalar.zero;
            var k_sum = o.k;
            for (0..n) |b| {
                if (b == i) continue;
                scalar_part = scalar_part.add(mu[i * n + b]).sub(mu[b * n + i]);
                k_sum = k_sum.add(openings[b].k);
            }
            // k_i·W_i + Σ_b k_b·W_i = (Σ_j k_j)·W_i.
            const k_wi = wi.mulPublic(k_sum.toBytes(.big), .big) catch Secp256k1.identityElement;
            const sigma_pt = k_wi.add(pointMulPublic(scalar_part));
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
    /// Type 5: the opener's own mask `β'` as Bob for that peer.
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
    /// Each share's signature is checked under its sender's message key (a
    /// share that fails is dropped, so its sender ends up `missing_message`),
    /// and its attestation of the Phase-6 broadcasts against this signer's
    /// (`equivocation`, named as in presigning).
    pub fn combine(self: *const PresignaturePublic, message: Message, shares: []const []const u8, abort: *?Abort) Error!signing.Signature {
        abort.* = null;
        const found = try self.allocator.alloc(?Scalar, self.signers.len);
        defer self.allocator.free(found);
        @memset(found, null);
        const hashes = try self.allocator.alloc([32]u8, self.signers.len);
        defer self.allocator.free(hashes);
        for (shares) |msg| {
            // As in `Party.collect`: only a share its sender signed for this
            // session is evidence against it; noise is dropped (review F3).
            const h = peekHeader(msg) catch continue;
            const pos = std.mem.indexOfScalar(u32, self.signers, h.from) orelse continue;
            if (msg.len < header_length + signature_length) continue;
            const body = msg[header_length .. msg.len - signature_length];
            var att: Attestation = .{ .body_hash = undefined, .signature = msg[msg.len - signature_length ..][0..signature_length].* };
            Sha256.hash(body, &att.body_hash, .{});
            if (!verifyAttestation(self.message_keys[pos], msg[0..header_length].*, att)) continue;
            if (h.round != sign_round or !std.mem.eql(u8, &h.sid, &self.sid)) continue;
            if (h.to != null) return failCombine(abort, h.from, .unexpected_message);
            if (found[pos] != null) {
                if (std.mem.eql(u8, &hashes[pos], &att.body_hash)) continue;
                return failCombine(abort, h.from, .duplicate_message);
            }
            if (msg.len != self.shareLength()) return failCombine(abort, h.from, .malformed_message);
            hashes[pos] = att.body_hash;
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

    pub const codec_version: u8 = 1;

    /// The presignature as bytes, SECRET (`k_i`, `σ_i`, the message seed): a
    /// store must keep them encrypted at rest. CONSUMES the presignature: on
    /// success it is marked used and `k_i`, `σ_i` are wiped, so the bytes are
    /// the only copy left and the in-memory one can no longer sign (review
    /// 2026-10-03 F11 — before, a caller could encode, keep the original and
    /// sign with both, which reveals the key). Restoring the same bytes twice
    /// does the same — go through `PresignaturePool`, whose `take` hands a
    /// stored presignature out at most once. Refuses a used presignature.
    ///
    /// `version || sid || index || group key || n || signers[n] || R || r ||
    /// R̄[n] || S[n] || Phase-6 attestations[n] || message keys[n] || k || σ ||
    /// message seed`, integers big-endian.
    pub fn toBytesAlloc(self: *Presignature, allocator: std.mem.Allocator) Error![]u8 {
        if (self.used) return error.PresignatureUsed;
        const pb = &self.public;
        const n = pb.signers.len;
        var list: std.ArrayList(u8) = .empty;
        errdefer {
            std.crypto.secureZero(u8, list.items);
            list.deinit(allocator);
        }
        var u: [4]u8 = undefined;
        try list.append(allocator, codec_version);
        try list.appendSlice(allocator, &pb.sid);
        std.mem.writeInt(u32, &u, self.index, .big);
        try list.appendSlice(allocator, &u);
        try list.appendSlice(allocator, &pb.group_public_key.toBytes());
        std.mem.writeInt(u32, &u, @intCast(n), .big);
        try list.appendSlice(allocator, &u);
        for (pb.signers) |idx| {
            std.mem.writeInt(u32, &u, idx, .big);
            try list.appendSlice(allocator, &u);
        }
        try list.appendSlice(allocator, &pb.r_point.toBytes());
        try list.appendSlice(allocator, &pb.r.toBytes(.big));
        for (pb.r_bar) |e| try list.appendSlice(allocator, &e.toBytes());
        for (pb.s_points) |e| try list.appendSlice(allocator, &e.toBytes());
        for (pb.round6) |a| {
            var buf: [attestation_entry_length]u8 = undefined;
            writeAttestation(a, &buf);
            try list.appendSlice(allocator, &buf);
        }
        for (pb.message_keys) |k| try list.appendSlice(allocator, &k.toBytes());
        try list.appendSlice(allocator, &self.k.toBytes(.big));
        try list.appendSlice(allocator, &self.sigma.toBytes(.big));
        try list.appendSlice(allocator, &self.message_seed);
        const out = try list.toOwnedSlice(allocator);
        self.used = true;
        self.wipe();
        return out;
    }

    pub const DecodeError = Error || error{InvalidEncoding};

    /// Inverse of `toBytesAlloc`, checking every field (points on the curve,
    /// canonical scalars, ascending signers holding `index`, decodable keys,
    /// the seed matching this signer's key) and the relations a finished
    /// session leaves between them: `r = R.x mod q`, `Σ R̄_j = G`,
    /// `Σ S_j = X`, `k·R = R̄_i`, `σ·R = S_i` (review 2026-10-03 F4: a
    /// damaged record would otherwise release a share against an `R` its
    /// `k` does not belong to). Not a substitute for authenticated
    /// encryption at rest: whoever can write a record can write a coherent
    /// one. Allocates with `allocator`.
    pub fn fromBytesAlloc(allocator: std.mem.Allocator, bytes: []const u8) DecodeError!Presignature {
        const fixed = 1 + 32 + 4 + Ne + 4;
        if (bytes.len < fixed or bytes[0] != codec_version) return error.InvalidEncoding;
        const index = std.mem.readInt(u32, bytes[33..37], .big);
        const group_public_key = Element.fromBytes(bytes[37..][0..Ne].*) catch return error.InvalidEncoding;
        const n = std.mem.readInt(u32, bytes[37 + Ne ..][0..4], .big);
        if (n < 2 or n > 0xffff) return error.InvalidEncoding;
        const per = 4 + Ne + Ne + attestation_entry_length + 32;
        if (bytes.len != fixed + n * per + Ne + Ns + 3 * 32) return error.InvalidEncoding;
        var off: usize = fixed;

        const signers = try allocator.alloc(u32, n);
        errdefer allocator.free(signers);
        for (signers, 0..) |*sg, i| {
            sg.* = std.mem.readInt(u32, bytes[off..][0..4], .big);
            off += 4;
            if (sg.* == 0 or (i > 0 and sg.* <= signers[i - 1])) return error.InvalidEncoding;
        }
        const pos = std.mem.indexOfScalar(u32, signers, index) orelse return error.InvalidEncoding;
        const r_point = Element.fromBytes(bytes[off..][0..Ne].*) catch return error.InvalidEncoding;
        off += Ne;
        const r = decodeScalar(bytes[off..][0..Ns].*) orelse return error.InvalidEncoding;
        off += Ns;
        const r_bar = try allocator.alloc(Element, n);
        errdefer allocator.free(r_bar);
        for (r_bar) |*e| {
            e.* = Element.fromBytes(bytes[off..][0..Ne].*) catch return error.InvalidEncoding;
            off += Ne;
        }
        const s_points = try allocator.alloc(Element, n);
        errdefer allocator.free(s_points);
        for (s_points) |*e| {
            e.* = Element.fromBytes(bytes[off..][0..Ne].*) catch return error.InvalidEncoding;
            off += Ne;
        }
        const round6 = try allocator.alloc(Attestation, n);
        errdefer allocator.free(round6);
        for (round6) |*a| {
            a.* = readAttestation(bytes[off..][0..attestation_entry_length]);
            off += attestation_entry_length;
        }
        const keys = try allocator.alloc(Ed25519.PublicKey, n);
        errdefer allocator.free(keys);
        for (keys) |*k| {
            k.* = root.decodeMessageKey(bytes[off..][0..32].*) catch return error.InvalidEncoding;
            off += 32;
        }
        // The secrets' stack copies are wiped on every path (review F11).
        var k = decodeScalar(bytes[off..][0..Ns].*) orelse return error.InvalidEncoding;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&k));
        off += Ns;
        var sigma = decodeScalar(bytes[off..][0..Ns].*) orelse return error.InvalidEncoding;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&sigma));
        off += Ns;
        var seed = bytes[off..][0..32].*;
        defer std.crypto.secureZero(u8, &seed);
        off += 32;
        var kp = Ed25519.KeyPair.generateDeterministic(seed) catch return error.InvalidEncoding;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&kp.secret_key));
        if (!std.mem.eql(u8, &kp.public_key.toBytes(), &keys[pos].toBytes())) return error.InvalidEncoding;
        std.debug.assert(off == bytes.len);
        const r_pt = r_point.point() catch return error.InvalidEncoding;
        if (!r.equivalent(scalarFromHash32(r_pt.affineCoordinates().x.toBytes(.big)))) return error.InvalidEncoding;
        var r_bar_sum = Secp256k1.identityElement;
        var s_sum = Secp256k1.identityElement;
        for (r_bar, s_points) |rb, sp| {
            r_bar_sum = r_bar_sum.add(rb.point() catch return error.InvalidEncoding);
            s_sum = s_sum.add(sp.point() catch return error.InvalidEncoding);
        }
        if (!r_bar_sum.equivalent(Secp256k1.basePoint)) return error.InvalidEncoding;
        if (!s_sum.equivalent(group_public_key.point() catch return error.InvalidEncoding)) return error.InvalidEncoding;
        // k and σ are secret: constant-time multiplications.
        const k_r = r_pt.mul(k.toBytes(.big), .big) catch return error.InvalidEncoding;
        const sigma_r = r_pt.mul(sigma.toBytes(.big), .big) catch return error.InvalidEncoding;
        if (!k_r.equivalent(r_bar[pos].point() catch unreachable)) return error.InvalidEncoding;
        if (!sigma_r.equivalent(s_points[pos].point() catch unreachable)) return error.InvalidEncoding;
        return .{
            .public = .{
                .allocator = allocator,
                .sid = bytes[1..33].*,
                .group_public_key = group_public_key,
                .signers = signers,
                .r_point = r_point,
                .r = r,
                .r_bar = r_bar,
                .s_points = s_points,
                .round6 = round6,
                .message_keys = keys,
            },
            .index = index,
            .k = k,
            .sigma = sigma,
            .message_seed = seed,
        };
    }

    /// The id a `PresignaturePool` files this presignature under:
    /// `SHA-256(domain || sid || index || R)` — one per signer per session.
    pub fn id(self: *const Presignature) [32]u8 {
        var h = Sha256.init(.{});
        h.update("threshold_ecdsa/presign/pool-id/v1");
        h.update(&self.public.sid);
        var u: [4]u8 = undefined;
        std.mem.writeInt(u32, &u, self.index, .big);
        h.update(&u);
        h.update(&self.public.r_point.toBytes());
        return h.finalResult();
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

/// Where a `PresignaturePool` keeps encoded presignatures (SECRET bytes:
/// encrypt at rest). The contract that makes a presigning pool safe across
/// restarts is `take`'s: it hands a record out at most once, ever — it must
/// remove the record durably (and atomically) BEFORE returning it, so a crash
/// after `take` loses the presignature instead of letting it be taken again.
pub const PresignatureStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Files `bytes` under `id` (copying them). Refuse an `id` already there.
        put: *const fn (ptr: *anyopaque, id: [32]u8, bytes: []const u8) anyerror!void,
        /// Removes the record under `id` and returns it (owned by
        /// `allocator`), or null when there is none.
        take: *const fn (ptr: *anyopaque, id: [32]u8, allocator: std.mem.Allocator) anyerror!?[]u8,
    };
};

/// A pool of presignatures over a `PresignatureStore`: `put` moves an
/// in-memory presignature into the store (wiping the original, so the only
/// copy is the stored one) and `take` restores it at most once.
pub const PresignaturePool = struct {
    store: PresignatureStore,

    /// Encodes `presig`, files it, then wipes and deinits `presig` (also on
    /// failure: a presignature that may have reached the store must not live
    /// on in memory). Returns its id.
    pub fn put(self: PresignaturePool, allocator: std.mem.Allocator, presig: *Presignature) anyerror![32]u8 {
        defer presig.deinit();
        const presig_id = presig.id();
        const bytes = try presig.toBytesAlloc(allocator);
        defer {
            std.crypto.secureZero(u8, bytes);
            allocator.free(bytes);
        }
        try self.store.vtable.put(self.store.ptr, presig_id, bytes);
        return presig_id;
    }

    /// The presignature filed under `id`, removed from the store; null when
    /// it is not there (never stored, or taken before). Deinit the result.
    pub fn take(self: PresignaturePool, allocator: std.mem.Allocator, presig_id: [32]u8) anyerror!?Presignature {
        const bytes = (try self.store.vtable.take(self.store.ptr, presig_id, allocator)) orelse return null;
        defer {
            std.crypto.secureZero(u8, bytes);
            allocator.free(bytes);
        }
        const presig = try Presignature.fromBytesAlloc(allocator, bytes);
        if (!std.mem.eql(u8, &presig.id(), &presig_id)) {
            var p = presig;
            p.deinit();
            return error.InvalidEncoding;
        }
        return presig;
    }
};

/// An in-memory `PresignatureStore` (one process, nothing survives a
/// restart): for tests and for a pool that never needs to outlive its
/// process. Wipes what it holds on `deinit`. Not synchronised: one thread
/// only, or the caller's lock around every `put`/`take` — two concurrent
/// `take`s of one id could both get the record, and a presignature used
/// twice reveals the key share (review 2026-10-03 F12).
pub const MemoryPresignatureStore = struct {
    allocator: std.mem.Allocator,
    map: std.AutoHashMapUnmanaged([32]u8, []u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) MemoryPresignatureStore {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MemoryPresignatureStore) void {
        var it = self.map.valueIterator();
        while (it.next()) |v| {
            std.crypto.secureZero(u8, v.*);
            self.allocator.free(v.*);
        }
        self.map.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn store(self: *MemoryPresignatureStore) PresignatureStore {
        return .{ .ptr = self, .vtable = &.{ .put = putFn, .take = takeFn } };
    }

    fn putFn(ptr: *anyopaque, presig_id: [32]u8, bytes: []const u8) anyerror!void {
        const self: *MemoryPresignatureStore = @ptrCast(@alignCast(ptr));
        if (self.map.contains(presig_id)) return error.DuplicateId;
        const copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copy);
        try self.map.put(self.allocator, presig_id, copy);
    }

    fn takeFn(ptr: *anyopaque, presig_id: [32]u8, allocator: std.mem.Allocator) anyerror!?[]u8 {
        const self: *MemoryPresignatureStore = @ptrCast(@alignCast(ptr));
        const kv = self.map.fetchRemove(presig_id) orelse return null;
        defer {
            std.crypto.secureZero(u8, kv.value);
            self.allocator.free(kv.value);
        }
        return try allocator.dupe(u8, kv.value);
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
    /// Honest signers; the transport adds noise to every round: each message
    /// twice, a forged header in its sender's name, a copy with a broken
    /// signature, and genuine (re-signed) copies for another round, another
    /// session and another recipient. Nothing may abort (review F3).
    noise,
    /// `sigma_shift`; signer 0 opens its decryption of signer 1's `c_w`
    /// plus `N` — the same ciphertext, another `μ'` (review F2).
    open_plain_n,
    /// The cheater's round-2 messages (p2p-only round) are signed as
    /// broadcasts: a signed message of the wrong kind (mutation audit).
    bc_in_p2p_round,
    /// The cheater's round-3 broadcast (broadcast-only round) is signed as
    /// a message to each recipient in turn.
    p2p_in_bc_round,
    /// The cheater's round-4 messages carry a signed body shorter than the
    /// attestation block that must head them.
    short_body,
    /// `sigma_shift`, then every signer abandons the opening (`abandon`).
    abandon_open,
    /// `sigma_shift`; the last signer shows signer 0 a second, signed version
    /// of its opening (review F5): the echo round names it.
    open_equivocate,
    /// `sigma_shift`; signer 0 opens a `k` that is not the one in its signed `c_k`.
    open_lie_k,
    /// A type-7 / type-5 opening of the LAST signer with a byte appended, or
    /// cut to a few bytes, and signed: malformed, so its sender is named.
    open_trailing7,
    open_short7,
    open_trailing5,
    open_short5,
    /// The LAST signer lies about its section for signer 0, each lie signed
    /// and well-formed, so a skipped check would let the first-checked
    /// honest signer take the blame (mutation audit round 2): its decryption
    /// of signer 0's `c_w` plus one (type 7), the same decryption with a
    /// leading zero byte dropped (same integer, wrong width), signer 0's
    /// round-2 message cut to fewer bytes than a header and a signature,
    /// and its own Bob mask `β'` for signer 0 (type 5).
    open7_late_mu,
    open7_late_strip,
    open7_late_round2,
    open5_late_mask,
};

/// The signer position that lies in its opening in this case: the last one
/// for the cases where the first-checked honest signer would otherwise be
/// blamed instead (mutation audit), else the first.
fn openLiar(case: Case, n: usize) usize {
    return switch (case) {
        .open_lie_k, .open_trailing7, .open_short7, .open_trailing5, .open_short5, .open7_late_mu, .open7_late_strip, .open7_late_round2, .open5_late_mask => n - 1,
        else => 0,
    };
}

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

/// The `noise` case: around `msg` from `party`, the transport delivers the
/// message again, garbage under its sender's name, a copy whose signature
/// fails, and genuine copies (re-signed by the sender, as a replay of its
/// real messages would be) for another round, session and recipient.
fn addNoise(allocator: std.mem.Allocator, party: *Party, msg: []const u8, copies: *std.ArrayList([]u8), inbox: *std.ArrayList([]const u8), other: u32) !void {
    try inbox.append(allocator, msg);
    const forged = try allocator.alloc(u8, header_length + 3);
    try copies.append(allocator, forged);
    @memcpy(forged[0..header_length], msg[0..header_length]);
    forged[1] +%= 40;
    @memset(forged[header_length..], 0xEE);
    try inbox.append(allocator, forged);
    for (0..4) |kind| {
        const copy = try allocator.dupe(u8, msg);
        try copies.append(allocator, copy);
        switch (kind) {
            0 => copy[copy.len - 1] ^= 0x01, // broken signature
            1 => copy[1] +%= 1, // another round
            2 => copy[2] ^= 0x01, // another session
            else => {
                const h = peekHeader(copy) catch unreachable;
                if (h.to == null) continue; // a broadcast has no recipient to change
                std.mem.writeInt(u32, copy[38..42], if (h.to.? == other) h.from else other, .big);
            },
        }
        if (kind != 0) resign(party, copy, false);
        try inbox.append(allocator, copy);
    }
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
            if ((case == .sigma_shift or case == .open_plain_n or case == .open_lie_k or case == .open_trailing7 or case == .open_short7 or
                case == .open7_late_mu or case == .open7_late_strip or case == .open7_late_round2 or
                case == .abandon_open or case == .open_equivocate) and round == 3 and i == cheat_pos)
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
                .delta_shift, .open_lie, .open_lie_round2, .open_trailing5, .open_short5, .open5_late_mask => if (r == 3) {
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
                .bc_in_p2p_round => if (r == 2) {
                    std.mem.writeInt(u32, m.bytes[38..42], 0, .big);
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
                    if (deliver and case == .short_body and round == 4) {
                        const short = try allocator.alloc(u8, header_length + 10 + signature_length);
                        try copies.append(allocator, short);
                        @memcpy(short[0 .. header_length + 10], m.bytes[0 .. header_length + 10]);
                        resign(&parties[cheat_pos], short, false);
                        try inboxes[to].append(allocator, short);
                        continue;
                    }
                    if (deliver and case == .p2p_in_bc_round and round == 3 and m.to == null) {
                        const copy = try allocator.dupe(u8, m.bytes);
                        try copies.append(allocator, copy);
                        std.mem.writeInt(u32, copy[38..42], parties[to].myIndex(), .big);
                        resign(&parties[cheat_pos], copy, false);
                        try inboxes[to].append(allocator, copy);
                        continue;
                    }
                    if (case == .noise) try addNoise(allocator, &parties[from], m.bytes, &copies, &inboxes[to], parties[(from + 1) % t].myIndex());
                    if (deliver and case == .truncated and round == 4) {
                        try inboxes[to].append(allocator, m.bytes[0 .. m.bytes.len - 1]);
                        continue;
                    }
                    try inboxes[to].append(allocator, m.bytes);
                    // A second, different version of the message, also signed by
                    // the cheater (an identical copy would be a harmless replay).
                    if (deliver and case == .duplicate and round == 4) {
                        const copy = try allocator.dupe(u8, m.bytes);
                        try copies.append(allocator, copy);
                        flipLast(copy);
                        resign(&parties[cheat_pos], copy, false);
                        try inboxes[to].append(allocator, copy);
                    }
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
    if (case == .abandon_open) {
        for (parties) |*p| {
            p.abandon();
            try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&p.secrets), 0));
            try testing.expectError(error.InvalidState, p.openAbort(random));
        }
        return;
    }
    var openings: [8]Outbox = undefined;
    for (parties, 0..) |*p, i| openings[i] = try p.openAbort(random);
    defer for (openings[0..parties.len]) |o| o.deinit(allocator);
    if (case == .sigma_shift) try expectNoMaskInOpenings(parties, openings[0..parties.len]);
    if (case == .sigma_shift or case == .delta_shift) try expectStrictOpeningParser(allocator, parties, openings[0..parties.len]);
    if (case == .open_trailing7 or case == .open_short7 or case == .open_trailing5 or case == .open_short5) {
        const liar = openLiar(case, parties.len);
        const old = openings[liar].messages[0].bytes;
        const body_len: usize = if (case == .open_short7 or case == .open_short5) 5 else old.len - header_length - signature_length;
        const extra: usize = if (case == .open_trailing7 or case == .open_trailing5) 1 else 0;
        const fresh = try allocator.alloc(u8, header_length + body_len + extra + signature_length);
        @memcpy(fresh[0 .. header_length + body_len], old[0 .. header_length + body_len]);
        if (extra == 1) fresh[header_length + body_len] = 0xAA;
        try lieConsistently(allocator, &parties[liar], fresh);
        allocator.free(old);
        openings[liar].messages[0].bytes = fresh;
    }
    if (case == .open7_late_mu or case == .open7_late_strip or case == .open7_late_round2 or case == .open5_late_mask) {
        const liar = openLiar(case, parties.len);
        const m = openings[liar].messages[0].bytes;
        var sections: [8]OpenSection = undefined;
        _ = parseOpening(m[header_length .. m.len - signature_length], parties[0].abort.?.fault, liar, sections[0..parties.len]).?;
        const sec = sections[0];
        switch (case) {
            .open7_late_mu => {
                // +1 at the last byte; μ' < q⁵ + q² ≪ N − 1, so no carry and still below N.
                const at = @intFromPtr(sec.plain.ptr) - @intFromPtr(m.ptr) + sec.plain.len - 1;
                m[at] +%= 1;
                if (m[at] == 0) m[at - 1] += 1;
            },
            .open5_late_mask => m[@intFromPtr(sec.mask.ptr) - @intFromPtr(m.ptr) + 5] ^= 0x01,
            else => {
                const field = if (case == .open7_late_strip) sec.plain else sec.round2;
                const new = if (case == .open7_late_strip) blk: {
                    try testing.expectEqual(@as(u8, 0), field[0]); // μ' has ~95 leading zero bytes
                    break :blk field[1..];
                } else field[0 .. header_length + 8];
                const start = @intFromPtr(field.ptr) - @intFromPtr(m.ptr);
                var list: std.ArrayList(u8) = .empty;
                errdefer list.deinit(allocator);
                try list.appendSlice(allocator, m[0 .. start - 4]);
                try appendLenPrefixed(&list, allocator, new);
                try list.appendSlice(allocator, m[start + field.len ..]);
                const fresh = try list.toOwnedSlice(allocator);
                allocator.free(m);
                openings[liar].messages[0].bytes = fresh;
            },
        }
        try lieConsistently(allocator, &parties[liar], openings[liar].messages[0].bytes);
    }
    if (case == .open_lie or case == .open_lie_round2 or case == .open_plain_n or case == .open_lie_k) {
        // Signer 0 (the last one for `open_lie_k`) lies in its opening, and signs the lie.
        const liar = openLiar(case, parties.len);
        const m = openings[liar].messages[0].bytes;
        const body = m[header_length .. m.len - signature_length];
        var sections: [8]OpenSection = undefined;
        _ = parseOpening(body, parties[0].abort.?.fault, liar, sections[0..parties.len]).?;
        const at = switch (case) {
            .open_lie => header_length + 1 + Ns + 4 + paillier.modulus_sq_bytes + Ns - 1, // γ
            .open_lie_k => header_length + Ns, // the last byte of k
            .open_lie_round2 => @intFromPtr(sections[1].round2.ptr) - @intFromPtr(m.ptr) + header_length + 10,
            else => @intFromPtr(sections[1].plain.ptr) - @intFromPtr(m.ptr),
        };
        if (case == .open_plain_n) {
            // plain += N, big-endian, in place (μ' < q⁵ + q², so no carry out).
            const plain = m[at..][0..sections[1].plain.len];
            const pk = parties[0].peers[parties[0].me].pk;
            var n_buf: [paillier.modulus_bytes]u8 = undefined;
            try pk.nToBytes(n_buf[0..plain.len]);
            var carry: u16 = 0;
            var j = plain.len;
            while (j > 0) {
                j -= 1;
                const sum = @as(u16, plain[j]) + n_buf[j] + carry;
                plain[j] = @truncate(sum);
                carry = sum >> 8;
            }
            try testing.expectEqual(@as(u16, 0), carry);
        } else m[at] ^= 0x01;
        try lieConsistently(allocator, &parties[liar], m);
    }
    // `open_equivocate`: the last signer shows signer 0 a second, signed
    // version of its opening (a byte of its decryption for signer 0 changed)
    // and everyone else the real one.
    var second: ?[]u8 = null;
    defer if (second) |b| allocator.free(b);
    if (case == .open_equivocate) {
        const liar = parties.len - 1;
        const m = try allocator.dupe(u8, openings[liar].messages[0].bytes);
        second = m;
        var sections: [8]OpenSection = undefined;
        _ = parseOpening(m[header_length .. m.len - signature_length], parties[0].abort.?.fault, liar, sections[0..parties.len]).?;
        m[@intFromPtr(sections[0].plain.ptr) - @intFromPtr(m.ptr) + sections[0].plain.len - 1] ^= 0x01;
        resign(&parties[liar], m, false);
    }
    // Round 8 → 9: every party echoes the openings it got.
    var echoes: [8]?Outbox = @splat(null);
    defer for (echoes[0..parties.len]) |e| if (e) |o| o.deinit(allocator);
    for (parties, aborts.items, 0..) |*p, *a, to| {
        var inbox: [8][]const u8 = undefined;
        for (openings[0..parties.len], 0..) |o, from| {
            inbox[from] = if (second != null and from == parties.len - 1 and to == 0) second.? else o.messages[0].bytes;
        }
        echoes[to] = p.echoOpenings(inbox[0..parties.len]) catch |e| switch (e) {
            error.ProtocolAbort => blk: {
                a.abort = p.abort.?;
                break :blk null;
            },
            else => return e,
        };
    }
    for (parties, aborts.items, 0..) |*p, *a, to| {
        if (echoes[to] == null) continue;
        var inbox: [8][]const u8 = undefined;
        var k: usize = 0;
        for (echoes[0..parties.len], 0..) |e, from| {
            if (from == to) continue;
            if (e) |o| {
                inbox[k] = o.messages[0].bytes;
                k += 1;
            }
        }
        a.abort = try p.identify(inbox[0..k]);
        try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&p.secrets), 0));
    }
}

/// A lying signer's opening, as a real one would send it: signed, and the
/// same lie to everyone — its own record (`own_bc`, `own_open`) is the lie
/// too, or the echo round would see two versions and call it equivocation.
fn lieConsistently(allocator: std.mem.Allocator, party: *Party, msg: []u8) !void {
    resign(party, msg, true);
    allocator.free(party.own_open.?);
    party.own_open = try allocator.dupe(u8, msg);
}

/// `parseOpening` on hostile bytes (mutation audit round 2): every strict
/// prefix of a real opening, a wrong kind byte and a non-canonical `k` are
/// refused, never read past the end.
fn expectStrictOpeningParser(allocator: std.mem.Allocator, parties: []Party, openings: []const Outbox) !void {
    const n = parties.len;
    const fault = parties[0].abort.?.fault;
    var sections: [8]OpenSection = undefined;
    const m = openings[n - 1].messages[0].bytes;
    const body = m[header_length .. m.len - signature_length];
    _ = parseOpening(body, fault, n - 1, sections[0..n]).?;
    for (0..body.len) |len| try testing.expect(parseOpening(body[0..len], fault, n - 1, sections[0..n]) == null);
    const copy = try allocator.dupe(u8, body);
    defer allocator.free(copy);
    copy[0] = if (fault == .r_bar_sum) 7 else 5;
    try testing.expect(parseOpening(copy, fault, n - 1, sections[0..n]) == null);
    copy[0] = body[0];
    @memset(copy[1..][0..Ns], 0xff); // k ≥ q
    try testing.expect(parseOpening(copy, fault, n - 1, sections[0..n]) == null);
}

/// Review 2026-10-03 F1: a type-7 opening published every signer's Bob
/// mask `β'` of the `k_a·w_b` MtA next to Alice's `μ' = k_a·w_b + β'` and
/// `k_a` — enough for anyone to compute `w_b`. For every pair, rebuilds that
/// `β'` from the secrets and asserts its encoding is in no opening.
fn expectNoMaskInOpenings(parties: []Party, openings: []const Outbox) !void {
    const n = parties.len;
    for (0..n) |a| {
        const m = openings[a].messages[0].bytes;
        var sections: [8]OpenSection = undefined;
        _ = parseOpening(m[header_length .. m.len - signature_length], .s_sum, a, sections[0..n]).?;
        for (0..n) |b| {
            if (a == b) continue;
            // β' = μ' − k_a·w_b over the integers.
            var wide: [512]u8 = @splat(0);
            const plain = sections[b].plain;
            @memcpy(wide[wide.len - plain.len ..], plain);
            const mu = std.mem.readInt(u4096, &wide, .big);
            const k: u4096 = std.mem.readInt(u256, &parties[a].secrets.k.toBytes(.big), .big);
            const w: u4096 = std.mem.readInt(u256, &parties[b].secrets.w.toBytes(.big), .big);
            const beta = mu - k * w;
            try testing.expect(beta >> (8 * zkproofs.beta_prime_bytes) == 0); // the rebuild is right
            std.mem.writeInt(u4096, &wide, beta, .big);
            const enc = wide[wide.len - zkproofs.beta_prime_bytes ..];
            for (openings) |o| try testing.expect(std.mem.indexOf(u8, o.messages[0].bytes, enc) == null);
        }
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
    // 3-of-3 over a noisy transport (review F3): replays, forged headers,
    // broken signatures, other rounds/sessions/recipients — all dropped.
    {
        var res = try runSession(allocator, kg.key_shares, random, .noise);
        defer res.deinit(allocator);
        try testing.expectEqual(@as(usize, 0), res.aborts.len);
        var abort: ?Abort = null;
        const sig = try signAll(allocator, res.presigs, .{ .bytes = "noisy" }, &abort);
        try sig.verify("noisy", pk);
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
        // A message for another session, round or recipient, a truncated
        // one and one whose signature fails are dropped as noise — they
        // prove nothing about their claimed sender (review F3) — so the
        // cheater's message for the slot is missing.
        .{ .case = .wrong_sid, .fault = .missing_message, .attributed = true },
        .{ .case = .wrong_round, .fault = .missing_message, .attributed = true },
        .{ .case = .misaddressed, .fault = .missing_message, .attributed = true },
        .{ .case = .truncated, .fault = .missing_message, .attributed = true },
        .{ .case = .bad_signature, .fault = .missing_message, .attributed = true },
        // A signed message of the wrong kind for the round (mutation audit):
        // a broadcast where only p2p messages are due, and the reverse.
        .{ .case = .bc_in_p2p_round, .fault = .unexpected_message, .attributed = true },
        .{ .case = .p2p_in_bc_round, .fault = .unexpected_message, .attributed = true },
        // Signed, but too short to hold the attestation block (a signed lie).
        .{ .case = .short_body, .fault = .malformed_message, .attributed = true },
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
        // Everyone judges the same (false) γ — the liar too — and names it.
        try testing.expectEqual(Abort{ .culprit = shares[0].index, .fault = .r_bar_sum }, a.abort);
    }
}

test "presign: §4.3 opening — a forged round-2 message or a decryption lifted by N names the opener" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6f70_656e_6c69_6532);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);
    const shares = [_]root.KeyShare{ kg.key_shares[0], kg.key_shares[1], kg.key_shares[2] };
    for ([_]struct { Case, Fault }{
        .{ .open_lie_round2, .r_bar_sum },
        .{ .open_plain_n, .s_sum },
        .{ .open_lie_k, .s_sum },
        .{ .open_trailing7, .s_sum },
        .{ .open_short7, .s_sum },
        .{ .open_trailing5, .r_bar_sum },
        .{ .open_short5, .r_bar_sum },
        .{ .open7_late_mu, .s_sum },
        .{ .open7_late_strip, .s_sum },
        .{ .open7_late_round2, .s_sum },
        .{ .open5_late_mask, .r_bar_sum },
    }) |c| {
        var res = try runSession(allocator, &shares, random, c[0]);
        defer res.deinit(allocator);
        errdefer std.debug.print("case {s}: {any}\n", .{ @tagName(c[0]), res.aborts });
        try testing.expectEqual(shares.len, res.aborts.len);
        for (res.aborts) |a| {
            const liar = shares[openLiar(c[0], shares.len)].index;
            if (a.observer == liar) continue; // it checks its own honest version
            try testing.expectEqual(Abort{ .culprit = liar, .fault = c[1] }, a.abort);
        }
    }
}

test "presign: an opening shown two ways is caught by the echo round, its signer named by everyone (review F5)" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6563_686f_6f70_656e);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);
    var res = try runSession(allocator, kg.key_shares, random, .open_equivocate);
    defer res.deinit(allocator);
    try testing.expectEqual(kg.key_shares.len, res.aborts.len);
    const liar = kg.key_shares[kg.key_shares.len - 1].index;
    // Signers 0 and 1 saw different openings from the liar; the echoes show
    // both its signatures to both, and the liar its own two versions.
    for (res.aborts) |a| try testing.expectEqual(Abort{ .culprit = liar, .fault = .equivocation }, a.abort);
}

test "presign: an abandoned §4.3 opening wipes the kept secrets at once (review F11)" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6162_616e_646f_6e);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);
    var res = try runSession(allocator, kg.key_shares, random, .abandon_open);
    defer res.deinit(allocator);
    try testing.expectEqual(kg.key_shares.len, res.aborts.len);
    for (res.aborts) |a| try testing.expectEqual(Abort{ .culprit = null, .fault = .s_sum }, a.abort);
}

test "presign: a pooled presignature survives encoding, is taken at most once, and signs" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x706f_6f6c);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 2);
    defer kg.deinit(allocator);
    var res = try runSession(allocator, kg.key_shares, random, .honest);
    defer res.deinit(allocator);

    // The codec round-trips, and refuses what it must. Encoding consumes the
    // original (review F11): it can no longer sign or be encoded again.
    const k_orig = res.presigs[1].k;
    const sigma_orig = res.presigs[1].sigma;
    const bytes = try res.presigs[1].toBytesAlloc(allocator);
    defer allocator.free(bytes);
    try testing.expectError(error.PresignatureUsed, res.presigs[1].signShare(.{ .bytes = "kept copy" }));
    try testing.expectError(error.PresignatureUsed, res.presigs[1].toBytesAlloc(allocator));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&res.presigs[1].k), 0));
    {
        var back = try Presignature.fromBytesAlloc(allocator, bytes);
        defer back.deinit();
        try testing.expectEqualSlices(u8, &res.presigs[1].id(), &back.id());
        try testing.expect(back.k.equivalent(k_orig) and back.sigma.equivalent(sigma_orig));
        const again = try back.toBytesAlloc(allocator);
        defer allocator.free(again);
        try testing.expectEqualSlices(u8, bytes, again);
    }
    const bad = try allocator.dupe(u8, bytes);
    defer allocator.free(bad);
    bad[0] = 9; // version
    try testing.expectError(error.InvalidEncoding, Presignature.fromBytesAlloc(allocator, bad));
    try testing.expectError(error.InvalidEncoding, Presignature.fromBytesAlloc(allocator, bytes[0 .. bytes.len - 1]));
    @memcpy(bad, bytes);
    bad[bad.len - 1] ^= 0x01; // a message seed that is not this signer's key
    try testing.expectError(error.InvalidEncoding, Presignature.fromBytesAlloc(allocator, bad));
    @memcpy(bad, bytes);
    const signers_at = 1 + 32 + 4 + Ne + 4;
    std.mem.writeInt(u32, bad[signers_at..][0..4], std.mem.readInt(u32, bad[signers_at + 4 ..][0..4], .big), .big); // signers not ascending
    try testing.expectError(error.InvalidEncoding, Presignature.fromBytesAlloc(allocator, bad));
    @memcpy(bad, bytes);
    std.mem.writeInt(u32, bad[signers_at..][0..4], 0, .big); // signer index 0 (still ascending)
    try testing.expectError(error.InvalidEncoding, Presignature.fromBytesAlloc(allocator, bad));
    {
        // A small-order message key for the other signer (not this one's own).
        const n = res.presigs[1].public.signers.len;
        const keys_at = signers_at + 4 * n + Ne + Ns + 2 * n * Ne + n * attestation_entry_length;
        @memcpy(bad, bytes);
        @memset(bad[keys_at..][0..32], 0);
        bad[keys_at] = 1; // the identity point
        try testing.expectError(error.InvalidEncoding, Presignature.fromBytesAlloc(allocator, bad));
    }
    // Review F4: well-formed fields that break the relations of a finished
    // session — r, each R̄_j and S_j, k, σ — are refused.
    {
        const n = res.presigs[1].public.signers.len;
        const r_at = signers_at + 4 * n + Ne;
        const r_bar_at = r_at + Ns;
        const s_at = r_bar_at + n * Ne;
        const k_at = s_at + n * Ne + n * attestation_entry_length + n * 32;
        const g_bytes = (Element.fromPoint(Secp256k1.basePoint) catch unreachable).toBytes();
        var offsets: [16]usize = undefined;
        var count: usize = 0;
        for ([_]usize{ r_at, k_at, k_at + Ns }) |at| {
            offsets[count] = at;
            count += 1;
        }
        for (0..n) |j| {
            offsets[count] = r_bar_at + j * Ne;
            offsets[count + 1] = s_at + j * Ne;
            count += 2;
        }
        for (offsets[0..count], 0..) |at, i| {
            @memcpy(bad, bytes);
            if (i < 3) {
                const v = Scalar.fromBytes(bad[at..][0..Ns].*, .big) catch unreachable;
                bad[at..][0..Ns].* = v.add(Scalar.one).toBytes(.big);
            } else bad[at..][0..Ne].* = g_bytes;
            try testing.expectError(error.InvalidEncoding, Presignature.fromBytesAlloc(allocator, bad));
        }
    }

    // Pool: put moves it out (the in-memory original is wiped), take restores
    // it once. (The original was consumed by the encoding above: start from
    // its bytes.)
    res.presigs[1].deinit();
    res.presigs[1] = try Presignature.fromBytesAlloc(allocator, bytes);
    var mem = MemoryPresignatureStore.init(allocator);
    defer mem.deinit();
    const pool: PresignaturePool = .{ .store = mem.store() };
    const presig_id = try pool.put(allocator, &res.presigs[1]);
    res.presigs[1] = (try pool.take(allocator, presig_id)).?; // res.deinit frees it
    try testing.expect((try pool.take(allocator, presig_id)) == null);

    var abort: ?Abort = null;
    const sig = try signAll(allocator, res.presigs, .{ .bytes = "from the pool" }, &abort);
    const pk = try signing.ecdsa.PublicKey.fromSec1(&kg.key_shares[0].group_public_key.toBytes());
    try sig.verify("from the pool", pk);
    // A used presignature is not encoded (it no longer holds k_i, σ_i).
    try testing.expectError(error.PresignatureUsed, res.presigs[1].toBytesAlloc(allocator));
}

test "fuzz: Presignature.fromBytesAlloc never panics" {
    try testing.fuzz({}, fuzzPresigDecode, .{});
}
fn fuzzPresigDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [1200]u8 = undefined;
    const bytes = buf[0..smith.slice(&buf)];
    var p = Presignature.fromBytesAlloc(testing.allocator, bytes) catch return;
    p.deinit();
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

    // The same change without signer 2's signature: dropped before any math
    // (it proves nothing about signer 2, review F3), so 2's share is missing —
    // and next to 2's real share, or a replay of it, it is ignored.
    const unsigned = try allocator.dupe(u8, s2);
    defer allocator.free(unsigned);
    unsigned[s_at] ^= 0x01;
    try testing.expectError(error.ProtocolAbort, public.combine(msg, &[_][]const u8{ s1, unsigned }, &abort));
    try testing.expectEqual(Abort{ .culprit = kg.key_shares[1].index, .fault = .missing_message }, abort.?);
    _ = try public.combine(msg, &[_][]const u8{ unsigned, s1, s2, s2 }, &abort);
    try testing.expect(abort == null);

    // Shares signer 2 signed, but that are no evidence of a share for THIS
    // combine (mutation audit): too short, another round or session — dropped,
    // so 2's share is missing; addressed to someone, or one byte too long —
    // 2's fault.
    {
        try testing.expectError(error.ProtocolAbort, public.combine(msg, &[_][]const u8{ s1, s2[0 .. header_length + 5] }, &abort));
        try testing.expectEqual(Abort{ .culprit = kg.key_shares[1].index, .fault = .missing_message }, abort.?);
        const Edit = enum { round, session, to, long, scalar };
        for ([_]Edit{ .round, .session, .to, .long, .scalar }) |edit| {
            const len = s2.len + @intFromBool(edit == .long);
            const copy = try allocator.alloc(u8, len);
            defer allocator.free(copy);
            @memcpy(copy[0 .. s2.len - signature_length], s2[0 .. s2.len - signature_length]);
            if (edit == .long) copy[s2.len - signature_length] = 0;
            switch (edit) {
                .round => copy[1] = 6,
                .session => copy[2] ^= 0x01,
                .to => std.mem.writeInt(u32, copy[38..42], kg.key_shares[0].index, .big),
                .long => {},
                .scalar => @memset(copy[s_at..][0..Ns], 0xff), // not below the group order
            }
            copy[len - signature_length ..][0..signature_length].* = sign(kp2, copy[0..header_length].*, copy[header_length .. len - signature_length]).signature;
            try testing.expectError(error.ProtocolAbort, public.combine(msg, &[_][]const u8{ s1, copy }, &abort));
            const want: Abort = switch (edit) {
                .round, .session => .{ .culprit = kg.key_shares[1].index, .fault = .missing_message },
                .to => .{ .culprit = kg.key_shares[1].index, .fault = .unexpected_message },
                .long, .scalar => .{ .culprit = kg.key_shares[1].index, .fault = .malformed_message },
            };
            try testing.expectEqual(want, abort.?);
        }
    }

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
    // The same share twice is a replay (skipped, so signer 2 is still
    // missing); two different shares both signed by 2 are its duplicate.
    try testing.expectError(error.ProtocolAbort, public.combine(msg, &[_][]const u8{ s1, s1 }, &abort));
    try testing.expectEqual(Abort{ .culprit = kg.key_shares[1].index, .fault = .missing_message }, abort.?);
    try testing.expectError(error.ProtocolAbort, public.combine(msg, &[_][]const u8{ s1, s2, bad }, &abort));
    try testing.expectEqual(Abort{ .culprit = kg.key_shares[1].index, .fault = .duplicate_message }, abort.?);

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

test "presign: a message signature binds its whole header; peekHeader refuses a foreign version and sender 0" {
    const kp = Ed25519.KeyPair.generateDeterministic(@splat(5)) catch unreachable;
    var h1: [header_length]u8 = undefined;
    (Header{ .round = 3, .sid = @splat(1), .from = 2, .to = null }).write(&h1);
    const att = sign(kp, h1, "body");
    try testing.expect(verifyAttestation(kp.public_key, h1, att));
    // Every header byte that carries something: version, round, session, sender, recipient.
    for ([_]usize{ 0, 1, 2, 33, 37, 41 }) |at| {
        var h2 = h1;
        h2[at] ^= 0x01;
        try testing.expect(!verifyAttestation(kp.public_key, h2, att));
    }
    var other_body = att;
    other_body.body_hash[0] ^= 0x01;
    try testing.expect(!verifyAttestation(kp.public_key, h1, other_body));
    _ = try peekHeader(&h1);
    var bad = h1;
    bad[0] ^= 0x01;
    try testing.expectError(error.InvalidEncoding, peekHeader(&bad));
    bad = h1;
    std.mem.writeInt(u32, bad[34..38], 0, .big);
    try testing.expectError(error.InvalidEncoding, peekHeader(&bad));
    try testing.expectError(error.InvalidEncoding, peekHeader(h1[0 .. header_length - 1]));
}

test "presign: the session id binds the signer set, the threshold and the public-key table (review F9)" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x7373_6964_6269_6e64);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);
    const sid = [_]u8{3} ** 32;
    const share = kg.key_shares[0];

    var base = try Party.init(allocator, share, &[_]u32{ 1, 2 }, sid);
    defer base.deinit();
    var same = try Party.init(allocator, share, &[_]u32{ 2, 1 }, sid); // the order of the set does not matter
    defer same.deinit();
    try testing.expectEqualSlices(u8, &base.sid, &same.sid);

    var other_set = try Party.init(allocator, share, &[_]u32{ 1, 3 }, sid);
    defer other_set.deinit();
    try testing.expect(!std.mem.eql(u8, &base.sid, &other_set.sid));

    // Peer 2 holds another message key in this party's table (a split refresh).
    const entries = try allocator.dupe(root.PartyPublicKeys, share.public_keys.entries);
    defer allocator.free(entries);
    entries[1].message_key = try root.messagePublicKey(@splat(9));
    var other_table_share = share;
    other_table_share.public_keys = .{ .entries = entries };
    var other_table = try Party.init(allocator, other_table_share, &[_]u32{ 1, 2 }, sid);
    defer other_table.deinit();
    try testing.expect(!std.mem.eql(u8, &base.sid, &other_table.sid));

    // The same three signers under another threshold.
    var all3 = try Party.init(allocator, share, &[_]u32{ 1, 2, 3 }, sid);
    defer all3.deinit();
    var t3_share = share;
    t3_share.t = 3;
    var all3_t3 = try Party.init(allocator, t3_share, &[_]u32{ 1, 2, 3 }, sid);
    defer all3_t3.deinit();
    try testing.expect(!std.mem.eql(u8, &all3.sid, &all3_t3.sid));
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

test "presign: round 1 refuses a party whose own aux tuple or Paillier key fails the peer checks" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6c6f_6361_6c6b_6579);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 2);
    defer kg.deinit(allocator);
    const sid = [_]u8{9} ** 32;

    // Own ring-Pedersen tuple with h1 = 1: `AuxParams.validate` refuses it.
    {
        const entries = try allocator.dupe(root.PartyPublicKeys, kg.key_shares[0].public_keys.entries);
        defer allocator.free(entries);
        entries[0].aux.h1 = entries[0].aux.n_tilde.one();
        var share = kg.key_shares[0];
        share.public_keys = .{ .entries = entries };
        var p = try Party.init(allocator, share, &[_]u32{ 1, 2 }, sid);
        defer p.deinit();
        try testing.expectError(error.InvalidParameters, p.advance(&.{}, random));
    }
    // Own Paillier generator is not N + 1.
    {
        const entries = try allocator.dupe(root.PartyPublicKeys, kg.key_shares[1].public_keys.entries);
        defer allocator.free(entries);
        entries[1].paillier_pk.g = paillier.Fe.fromBytes(entries[1].paillier_pk.n_sq, &[_]u8{4}, .big) catch unreachable;
        var share = kg.key_shares[1];
        share.public_keys = .{ .entries = entries };
        var p = try Party.init(allocator, share, &[_]u32{ 1, 2 }, sid);
        defer p.deinit();
        try testing.expectError(error.InvalidParameters, p.advance(&.{}, random));
    }
}

test "presign: the pool refuses a duplicate id, and a record filed under another id" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x706f_6f6c_6964);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 2);
    defer kg.deinit(allocator);
    var res = try runSession(allocator, kg.key_shares, random, .honest);
    defer res.deinit(allocator);
    const bytes = try res.presigs[0].toBytesAlloc(allocator);
    defer allocator.free(bytes);

    var mem = MemoryPresignatureStore.init(allocator);
    defer mem.deinit();
    const pool: PresignaturePool = .{ .store = mem.store() };
    var first = try Presignature.fromBytesAlloc(allocator, bytes);
    const presig_id = try pool.put(allocator, &first);
    // The same presignature again: the store refuses the id (and `put` still
    // wipes what it was handed).
    var second = try Presignature.fromBytesAlloc(allocator, bytes);
    try testing.expectError(error.DuplicateId, pool.put(allocator, &second));
    // A record that decodes fine but sits under another presignature's id is
    // not handed out.
    const other_id: [32]u8 = @splat(7);
    try mem.store().vtable.put(mem.store().ptr, other_id, bytes);
    try testing.expectError(error.InvalidEncoding, pool.take(allocator, other_id));
    var back = (try pool.take(allocator, presig_id)).?;
    back.deinit();
}
