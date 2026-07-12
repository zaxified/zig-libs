// SPDX-License-Identifier: MIT
//! The Sphinx CRYPTO CORES: BOLT#4's shared-secret/blinding-key chain, and
//! the `construct`/`process` operations built on top of it. All three are
//! IMPLEMENTED and KAT-verified against the official BOLT#4 test vector
//! (`kat_vectors.zig` / `kat_test.zig`): `deriveHopSecrets` reproduces all
//! 5 published per-hop shared secrets, `construct` reproduces the published
//! 1366-byte onion packet byte-exact, and `process` peels every layer of a
//! full 5-hop round-trip.
//!
//! The sibling files carry everything keyless: the fixed 1366-byte packet
//! codec (`packet.zig`), the key-derivation primitives
//! `generateKey`/`generateCipherStream` (`keyderive.zig`), the per-hop TLV
//! framing + shift-size arithmetic (`hopframe.zig`), and the BOLT#1
//! `bigsize` codec (`bigsize.zig`). The three functions here are the ONLY
//! things that (a) do elliptic-curve scalar multiplication, or (b) drive
//! the full per-hop loop tying keys + framing + ChaCha20 + HMAC together.
//!
//! std recon (verified against Zig 0.16.0's
//! `lib/std/crypto/pcurves/secp256k1.zig` — see `SPEC.md` for the full
//! notes):
//!   - ECDH point: `hop_pubkey_point.mul(scalar_bytes, .big)` where
//!     `hop_pubkey_point = Secp256k1.fromSec1(&pubkey_33_bytes)`. `.mul`
//!     returns `IdentityElementError!Secp256k1` — the identity-element
//!     case is a real failure mode (an all-zero/order-n scalar), not just
//!     defensive plumbing.
//!   - Serialize the shared point: `.toCompressedSec1()` (33 bytes, the
//!     SAME compressed form `packet.zig`'s `public_key` field uses) then
//!     `std.crypto.hash.sha2.Sha256.hash(&compressed, &out, .{})`.
//!   - Blinding-factor point mult for the NEXT ephemeral pubkey: same
//!     `.mul` call, this time on the base point / current ephemeral point
//!     with the blinding factor as the scalar.
//!   - Blinding the ephemeral SCALAR (needed so `construct` can derive
//!     every hop's shared secret without redoing EC math per hop, and so a
//!     future `constructForBlindedPath`-style helper could work purely in
//!     scalar space): `Secp256k1.scalar.mul(a_bytes, b_bytes, .big)` — a
//!     mod-n scalar multiply, NOT a point operation.

const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const packet = @import("packet.zig");
const hopframe = @import("hopframe.zig");
const keyderive = @import("keyderive.zig");

pub const OnionPacket = packet.OnionPacket;
pub const pubkey_len = packet.pubkey_len;
pub const hop_payloads_len = packet.hop_payloads_len;
pub const hmac_len = packet.hmac_len;

/// One hop's derived secret material, as produced by the shared-secret /
/// blinding chain below.
pub const HopSecret = struct {
    /// `ss_i = SHA256(compressed(ephemeral_i · node_i_privkey))` — BOLT#4
    /// "Shared Secret".
    shared_secret: [32]u8,
    /// `epk_i`, the (already-blinded, for `i > 0`) ephemeral public key
    /// this hop actually sees embedded in the onion packet at its layer.
    ephemeral_pubkey: [pubkey_len]u8,
};

pub const SharedSecretError = error{
    /// A hop pubkey byte string does not decode to a valid on-curve
    /// compressed secp256k1 point.
    InvalidPublicKey,
    /// An ECDH product, an ephemeral point, or a blinded scalar landed on
    /// the identity element / zero — astronomically unlikely for honest
    /// random inputs, but a real, checked failure mode (mirrors
    /// `Secp256k1.mul`'s `IdentityElementError`).
    IdentityElement,
};

/// BOLT#4 "Shared Secret" + "Blinding Ephemeral Onion Keys" — the chain the
/// origin node walks ONCE, forward through the route, to derive every
/// hop's shared secret AND the sequence of ephemeral public keys a
/// forwarding hop will actually see. `out.len` must equal
/// `hop_pubkeys.len`; `out[i]` is hop `i`'s `HopSecret`.
///
/// For `i` in `0..hop_pubkeys.len`, starting with `ephemeral_scalar_0 =
/// session_key`:
///
/// 1. `ephemeral_pubkey_i = ephemeral_scalar_i · G` (`G` = the secp256k1
///    base point) — this is exactly the value embedded in the wire packet
///    at hop `i`'s layer (`OnionPacket.public_key`, hop 0's case, is
///    literally `ephemeral_pubkey_0`).
/// 2. ECDH: `shared_point_i = hop_pubkeys[i] · ephemeral_scalar_i` (a point
///    — the sender does NOT have `hop_pubkeys[i]`'s private key, so this
///    is the "public point times private scalar" ECDH direction; a
///    receiving hop instead computes `ephemeral_pubkey_i ·
///    node_privkey`, landing on the SAME point by ECDH's commutativity).
/// 3. `ss_i = SHA256(compressed(shared_point_i))` — BOLT#4 "Shared
///    Secret".
/// 4. `blinding_factor_i = SHA256(compressed(ephemeral_pubkey_i) ‖
///    ss_i)` — BOLT#4 "Blinding Ephemeral Onion Keys". Note the hash
///    input order: the EPHEMERAL pubkey first, then the shared secret —
///    swapping them silently produces a non-interoperable blinding chain.
/// 5. `ephemeral_scalar_{i+1} = ephemeral_scalar_i · blinding_factor_i mod
///    n` (`n` = the secp256k1 group order; `Secp256k1.scalar.mul`) — feeds
///    the next iteration's step 1. There is no step 5 on the LAST hop
///    (nothing consumes `ephemeral_scalar_{r}`).
///
/// A receiving hop (`process`, below) does NOT run this whole chain — it
/// only ever computes ONE step of it (its own `ss`), plus the single
/// blinding-factor point-multiply needed to produce the pubkey it forwards
/// onward. This function is `construct`'s (the SENDER's) helper, run once
/// up front so `construct`'s own per-hop loop (which runs in REVERSE route
/// order — see its doc comment) already has every `ss_i` in hand.
pub fn deriveHopSecrets(session_key: [32]u8, hop_pubkeys: []const [pubkey_len]u8, out: []HopSecret) SharedSecretError!void {
    std.debug.assert(out.len == hop_pubkeys.len);
    if (hop_pubkeys.len == 0) return;

    // Step 1 for i == 0: epk_0 = session_key * G. Later iterations update
    // the POINT directly via the blinding factor (step 4's point-multiply)
    // instead of recomputing scalar_i * G from scratch — same value, one
    // point-multiply per hop instead of a fresh base-point multiply.
    var ephemeral_scalar = session_key;
    var ephemeral_point = Secp256k1.basePoint.mul(ephemeral_scalar, .big) catch
        return error.IdentityElement;

    for (hop_pubkeys, out, 0..) |hop_pubkey, *hop_secret, i| {
        // Step 2: ECDH, sender direction (public point x private scalar).
        const hop_point = Secp256k1.fromSec1(&hop_pubkey) catch return error.InvalidPublicKey;
        const shared_point = hop_point.mul(ephemeral_scalar, .big) catch
            return error.IdentityElement;

        // Step 3: ss_i = SHA256(compressed(shared_point_i)).
        const shared_compressed = shared_point.toCompressedSec1();
        var shared_secret: [32]u8 = undefined;
        Sha256.hash(&shared_compressed, &shared_secret, .{});

        const epk = ephemeral_point.toCompressedSec1();
        hop_secret.* = .{ .shared_secret = shared_secret, .ephemeral_pubkey = epk };

        // No step 4/5 on the last hop — nothing consumes the next scalar.
        if (i + 1 == hop_pubkeys.len) break;

        // Step 4: blinding_factor_i = SHA256(compressed(epk_i) ‖ ss_i) —
        // the EPHEMERAL pubkey first, then the shared secret.
        var blinding_factor: [32]u8 = undefined;
        var hasher = Sha256.init(.{});
        hasher.update(&epk);
        hasher.update(&shared_secret);
        hasher.final(&blinding_factor);

        // Step 5 (+ next iteration's step 1): blind both the point and the
        // scalar. `scalar.mul` rejects a non-canonical (>= group order n)
        // operand with error.NonCanonical — a SHA256 output lands there
        // with probability ~2^-128, the same "degenerate scalar" class as
        // the identity element, so it folds into the same checked error.
        ephemeral_point = ephemeral_point.mul(blinding_factor, .big) catch
            return error.IdentityElement;
        ephemeral_scalar = Secp256k1.scalar.mul(ephemeral_scalar, blinding_factor, .big) catch
            return error.IdentityElement;
    }
}

/// Upper bound on the number of hops any route can carry: the smallest
/// legal frame is `bigsize(2) ‖ 2-byte payload ‖ hmac(32)` = 35 bytes, so
/// at most `1300 / 35 == 37` frames ever fit in `hop_payloads`. Used to
/// size `construct`'s stack-resident `HopSecret` scratch array — any
/// longer route is `error.RouteTooLong` before EC math runs.
pub const max_hops: usize = hop_payloads_len / (1 + 2 + hmac_len);

pub const ConstructError = SharedSecretError || hopframe.FrameError || error{
    /// The route (given each hop's `shiftSize`) does not fit in the fixed
    /// 1300-byte `hop_payloads` budget.
    RouteTooLong,
    /// `hop_pubkeys.len != hop_payloads.len`, or either is empty.
    HopCountMismatch,
};

/// BOLT#4 "Packet Construction" (the SENDER's operation) — builds the full
/// 1366-byte onion packet for the route `hop_pubkeys[0..r]` (hop 0 = the
/// first peer the sender forwards to; the last entry = the final
/// recipient), carrying `hop_payloads[i]` (already-TLV-encoded, WITHOUT its
/// own bigsize length prefix — `hopframe.writeHopFrame` adds that) as each
/// hop's payload, under `associated_data` (commonly the payment_hash).
///
/// 1. `hop_secrets = deriveHopSecrets(session_key, hop_pubkeys)` (this
///    file, above) — every hop's `ss_i` and `epk_i` up front.
/// 2. Check the route fits: `sum_i hopframe.shiftSize(hop_payloads[i].len)
///    <= hopframe.hop_payloads_len` (else `error.RouteTooLong`).
/// 3. Seed the 1300-byte `hop_payloads` buffer with CSPRNG-*looking*
///    (but fully deterministic from `session_key`) padding:
///    `paddingKey = keyderive.generateKey(.pad, session_key)`;
///    `keyderive.generateCipherStream(paddingKey, &hop_payloads)`.
/// 4. Generate the `filler` (see BOLT#4 "Filler Generation" — a
///    ROUTE-ORDER pass, hop 0 to hop r-2, each iteration left-shifting a
///    scratch buffer and re-obfuscating with that hop's `rho` stream; the
///    LAST hop contributes no filler, since it never forwards). The filler
///    is what lets every intermediate hop's freshly-revealed tail look
///    like fresh randomness instead of "all zero" (which would leak this
///    hop's position in the route to an observer comparing packet sizes
///    over time).
/// 5. Walk the hops in REVERSE (`r-1` down to `0`) — BOLT#4: "the packet
///    construction is performed in the reverse order of the route, i.e.
///    the last hop's operations are applied first." For each hop `i`:
///    a. `rho_i = keyderive.generateKey(.rho, hop_secrets[i].shared_secret)`,
///       `mu_i = keyderive.generateKey(.mu, hop_secrets[i].shared_secret)`.
///    b. `hopframe.rightShift(&hop_payloads, hopframe.shiftSize(hop_payloads[i].len))`.
///    c. `hopframe.writeHopFrame(hop_payloads[0..], hop_payloads[i],
///       next_hmac)` where `next_hmac` is the HMAC computed by the
///       PREVIOUS iteration (all-zero on the very first iteration, i.e.
///       hop `r-1`, since there is no next hop beyond the final
///       recipient).
///    d. XOR all 1300 bytes of `hop_payloads` with
///       `keyderive.generateCipherStream(rho_i, 1300)`.
///    e. On the FIRST iteration only (`i == r-1`, the final hop): splice
///       the pre-generated `filler` into the tail of `hop_payloads` (it
///       replaces what the right-shift+XOR just obfuscated there, since
///       that tail is logically "past the end of a shorter route" from
///       every other hop's point of view).
///    f. `next_hmac = HMAC-SHA256(key=mu_i, msg=hop_payloads ‖
///       associated_data)` — becomes step (c)'s input for the NEXT
///       (lower-index) iteration.
/// 6. The final `next_hmac` (after the `i == 0` iteration) is the packet's
///    top-level `hmac`. Return `OnionPacket{ .public_key =
///    hop_secrets[0].ephemeral_pubkey, .hop_payloads = <the buffer>, .hmac
///    = next_hmac }`.
///
/// KAT oracle: `kat_vectors.onion` (the exact 1366-byte published packet)
/// for `kat_vectors.session_key`/`.pubkeys`/`.payloads`/`.associated_data`.
pub fn construct(
    session_key: [32]u8,
    hop_pubkeys: []const [pubkey_len]u8,
    hop_payloads: []const []const u8,
    associated_data: []const u8,
) ConstructError!OnionPacket {
    const n = hop_pubkeys.len;
    if (n == 0 or n != hop_payloads.len) return error.HopCountMismatch;
    if (n > max_hops) return error.RouteTooLong;

    // Step 2 (pulled ahead of step 1 so all cheap validation fails before
    // any EC math): the route must fit the fixed 1300-byte budget, and no
    // payload may use a reserved (< 2) length.
    var total_shift: usize = 0;
    for (hop_payloads) |payload| {
        if (payload.len < 2) return error.ReservedPayloadLength;
        total_shift += hopframe.shiftSize(payload.len);
    }
    if (total_shift > hopframe.hop_payloads_len) return error.RouteTooLong;

    // Step 1: every hop's ss_i / epk_i up front (the FORWARD pass).
    var hop_secrets: [max_hops]HopSecret = undefined;
    try deriveHopSecrets(session_key, hop_pubkeys, hop_secrets[0..n]);

    // Step 4 (before the wrap loop needs it): BOLT#4 "Filler Generation" —
    // a ROUTE-ORDER pass over hops 0..n-2 (the last hop forwards nothing,
    // so it contributes no filler). Invariant maintained: after hop i's
    // iteration, `filler[0..filler_len]` is exactly the tail of the buffer
    // hop i+1 will observe past its own route data — i.e. what hops
    // 0..i's deobfuscation streams force into the bytes their left-shifts
    // reveal. Recurrence (L = filler_len before this hop, s = this hop's
    // shift): filler' = (filler ‖ 0^s) XOR rho_i-stream[1300-L .. 1300+s].
    // The stream slice starts mid-stream because hop i's `process` XORs a
    // 2600-byte stream against (its 1300-byte view ‖ 0^1300) and the
    // revealed tail lands at exactly those stream offsets.
    var filler: [hopframe.hop_payloads_len]u8 = undefined;
    var filler_len: usize = 0;
    {
        var stream: [2 * hopframe.hop_payloads_len]u8 = undefined;
        for (hop_payloads[0 .. n - 1], hop_secrets[0 .. n - 1]) |payload, hop_secret| {
            const shift = hopframe.shiftSize(payload.len);
            @memset(filler[filler_len..][0..shift], 0);
            const rho = keyderive.generateKey(.rho, hop_secret.shared_secret);
            keyderive.generateCipherStream(rho, stream[0 .. hopframe.hop_payloads_len + shift]);
            const forced = stream[hopframe.hop_payloads_len - filler_len ..][0 .. filler_len + shift];
            for (filler[0 .. filler_len + shift], forced) |*f, s| f.* ^= s;
            filler_len += shift;
        }
    }

    // Step 3: seed the working buffer with deterministic-from-session_key
    // padding (looks like CSPRNG output to every observer).
    var buf: [hopframe.hop_payloads_len]u8 = undefined;
    keyderive.generateCipherStream(keyderive.generateKey(.pad, session_key), &buf);

    // Step 5: the REVERSE-order wrap loop (last hop's layer first).
    var next_hmac = [_]u8{0} ** hmac_len; // all-zero marks "final hop" for hop n-1
    var i = n;
    while (i > 0) {
        i -= 1;
        const shift = hopframe.shiftSize(hop_payloads[i].len);
        hopframe.rightShift(&buf, shift);
        _ = try hopframe.writeHopFrame(&buf, hop_payloads[i], next_hmac);

        const rho = keyderive.generateKey(.rho, hop_secrets[i].shared_secret);
        var stream: [hopframe.hop_payloads_len]u8 = undefined;
        keyderive.generateCipherStream(rho, &stream);
        for (&buf, stream) |*b, s| b.* ^= s;

        // Step 5e: on the first iteration only, splice the filler over the
        // tail — from every earlier hop's viewpoint that tail is "past the
        // end of the route", and the filler is bit-for-bit what their own
        // deobfuscation streams will force there.
        if (i == n - 1) @memcpy(buf[hopframe.hop_payloads_len - filler_len ..], filler[0..filler_len]);

        const mu = keyderive.generateKey(.mu, hop_secrets[i].shared_secret);
        var mac = HmacSha256.init(&mu);
        mac.update(&buf);
        mac.update(associated_data);
        mac.final(&next_hmac);
    }

    // Step 6: the last-computed HMAC (hop 0's) is the packet-level hmac.
    return .{
        .public_key = hop_secrets[0].ephemeral_pubkey,
        .hop_payloads = buf,
        .hmac = next_hmac,
    };
}

pub const ProcessError = SharedSecretError || hopframe.FrameError || error{
    /// BOLT#4 "Onion Decryption": the computed HMAC does not match the
    /// packet's `hmac` field — this hop is not the intended recipient of
    /// this onion, or the packet was tampered with in transit. MUST be a
    /// constant-time comparison (`std.crypto.timing_safe.eql`) — this is
    /// the packet's core integrity/anti-tamper guarantee, and a
    /// timing-variable compare would let an attacker forge a valid HMAC
    /// byte-by-byte.
    IntegrityCheckFailed,
    /// The deobfuscated `hop_payloads` did not contain a well-formed
    /// `bigsize(length) ‖ payload` frame (malformed bigsize, or fewer
    /// bytes remain than the declared length + 32-byte next-hmac need).
    MalformedPayload,
};

/// One hop's `process` result: this hop's own `payload` (borrowed from
/// `payload_buf`), and either the packet to forward to the NEXT hop, or
/// `null` if `next_hmac` was all-zero (BOLT#4: "this is the final
/// destination of the onion").
pub const ProcessResult = struct {
    /// Scratch storage for the extracted payload bytes (owned by this
    /// result, not the caller's `pkt` — `process` needs a working buffer
    /// twice `hop_payloads_len` internally anyway, per BOLT#4 "Filler
    /// Generation"'s decode-side padding step).
    payload_buf: [hop_payloads_len]u8,
    payload_len: usize,
    next_packet: ?OnionPacket,

    pub fn payload(self: *const ProcessResult) []const u8 {
        return self.payload_buf[0..self.payload_len];
    }
};

/// BOLT#4 "Onion Decryption" (a single HOP's operation) — unwraps one
/// layer of `pkt` using this node's `node_privkey`, returning this hop's
/// own `payload` and (unless this was the final hop) the `OnionPacket` to
/// forward onward.
///
/// `pkt.public_key`/version validity are ALREADY checked by
/// `OnionPacket.fromBytes` (see `packet.zig`) before this function would
/// ever be called — this function starts from BOLT#4's "Derive the shared
/// secret" step:
///
/// 1. `ss = SHA256(compressed(pkt.public_key · node_privkey))` — the
///    RECEIVING hop's ECDH direction (private scalar × public point;
///    lands on the same point the sender's `hop_pubkeys[i] ·
///    ephemeral_scalar_i` produced, by ECDH commutativity — see
///    `deriveHopSecrets`'s doc comment).
/// 2. `mu = keyderive.generateKey(.mu, ss)`.
/// 3. `expected_hmac = HMAC-SHA256(key=mu, msg=pkt.hop_payloads ‖
///    associated_data)`.
/// 4. Constant-time compare `expected_hmac` against `pkt.hmac`
///    (`std.crypto.timing_safe.eql`) — MUST fail closed
///    (`error.IntegrityCheckFailed`) on any mismatch, timing-safely (see
///    `ProcessError.IntegrityCheckFailed`'s doc comment on why this can't
///    be a plain `std.mem.eql`).
/// 5. `rho = keyderive.generateKey(.rho, ss)`.
/// 6. Deobfuscate: build a `2 * hop_payloads_len`-byte scratch buffer whose
///    first `hop_payloads_len` bytes are `pkt.hop_payloads` and whose
///    second half is all-zero, then XOR the WHOLE thing with
///    `keyderive.generateCipherStream(rho, 2 * hop_payloads_len)` — the
///    zero-padded second half is what "reveals" the next hop's freshly
///    un-shifted tail instead of leaking an all-zero (and thus
///    fingerprintable) suffix; see BOLT#4 "Filler Generation".
/// 7. `hopframe.readHopFrame(&deobfuscated)` — extracts this hop's
///    `payload` and the 32-byte `next_hmac` (`error.MalformedPayload` on
///    a bad bigsize / too-short remainder, from `hopframe`'s own checked
///    failure modes).
/// 8. If `next_hmac` is all-zero: this is the final hop — return
///    `.{ .next_packet = null, ... }` with `payload`/`payload_len` set.
/// 9. Otherwise, build the OUTGOING packet for the next hop:
///    a. `blinding_factor = SHA256(compressed(pkt.public_key) ‖ ss)` —
///       BOLT#4 "Blinding Ephemeral Onion Keys" (same formula
///       `deriveHopSecrets` uses on the sender side, now run by the
///       FORWARDING hop instead).
///    b. `next_public_key = pkt.public_key · blinding_factor` (a point
///       multiply — `Secp256k1.fromSec1(&pkt.public_key).mul(blinding_
///       factor, .big).toCompressedSec1()`).
///    c. `next_hop_payloads = hopframe.leftShift`'d
///       `deobfuscated[hop_payloads_len..]` truncated back down to
///       `hop_payloads_len` bytes (BOLT#4: "`hop_payloads` set to the
///       `unwrapped_payloads`, truncated to the incoming `hop_payloads`
///       size").
///    d. Return `.{ .next_packet = OnionPacket{ .public_key =
///       next_public_key, .hop_payloads = next_hop_payloads, .hmac =
///       next_hmac }, ... }`.
///
/// KAT oracle: process `kat_vectors.onion` with `kat_vectors.
/// node_privkeys[0]` and `kat_vectors.associated_data`; the extracted
/// `payload` must equal `kat_vectors.payloads[0]`'s TLV content (i.e. with
/// its own bigsize length prefix stripped) and the resulting `next_packet`
/// must be constructible by feeding `kat_vectors.node_privkeys[1]` in turn
/// (this module ships the first-hop KAT only — see `kat_test.zig`).
pub fn process(node_privkey: [32]u8, pkt: OnionPacket, associated_data: []const u8) ProcessError!ProcessResult {
    // Step 1: ECDH, receiver direction (private scalar x public point).
    const ephemeral_point = Secp256k1.fromSec1(&pkt.public_key) catch
        return error.InvalidPublicKey;
    const shared_point = ephemeral_point.mul(node_privkey, .big) catch
        return error.IdentityElement;
    const shared_compressed = shared_point.toCompressedSec1();
    var shared_secret: [32]u8 = undefined;
    Sha256.hash(&shared_compressed, &shared_secret, .{});

    // Steps 2-4: verify the packet HMAC in constant time, BEFORE touching
    // hop_payloads' content in any data-dependent way.
    const mu = keyderive.generateKey(.mu, shared_secret);
    var expected_hmac: [hmac_len]u8 = undefined;
    var mac = HmacSha256.init(&mu);
    mac.update(&pkt.hop_payloads);
    mac.update(associated_data);
    mac.final(&expected_hmac);
    if (!std.crypto.timing_safe.eql([hmac_len]u8, expected_hmac, pkt.hmac))
        return error.IntegrityCheckFailed;

    // Steps 5-6: deobfuscate `hop_payloads ‖ 0^1300` with a full 2600-byte
    // rho stream — the zero-padded second half becomes raw keystream, i.e.
    // exactly the "revealed tail" the sender's filler generation predicted.
    const rho = keyderive.generateKey(.rho, shared_secret);
    var stream: [2 * hop_payloads_len]u8 = undefined;
    keyderive.generateCipherStream(rho, &stream);
    var unwrapped: [2 * hop_payloads_len]u8 = undefined;
    for (unwrapped[0..hop_payloads_len], pkt.hop_payloads, stream[0..hop_payloads_len]) |*u, p, s|
        u.* = p ^ s;
    @memcpy(unwrapped[hop_payloads_len..], stream[hop_payloads_len..]);

    // Step 7: this hop's frame off the front of the deobfuscated buffer.
    const frame = hopframe.readHopFrame(&unwrapped) catch |err| switch (err) {
        error.ReservedPayloadLength => return error.ReservedPayloadLength,
        error.Truncated, error.NonCanonical, error.BufferTooSmall => return error.MalformedPayload,
    };
    // The frame must have fit inside the INCOMING 1300-byte hop_payloads —
    // a declared length reaching into the zero-padding half could never
    // have been legitimately constructed (and would overflow payload_buf).
    if (frame.consumed > hop_payloads_len) return error.MalformedPayload;

    var result: ProcessResult = .{
        .payload_buf = undefined,
        .payload_len = frame.payload.len,
        .next_packet = null,
    };
    @memcpy(result.payload_buf[0..frame.payload.len], frame.payload);
    @memset(result.payload_buf[frame.payload.len..], 0);

    // Step 8: an all-zero next_hmac marks the final hop.
    if (std.mem.allEqual(u8, &frame.hmac, 0)) return result;

    // Step 9a: blinding_factor = SHA256(compressed(epk) ‖ ss) — the same
    // formula deriveHopSecrets runs sender-side.
    var blinding_factor: [32]u8 = undefined;
    var hasher = Sha256.init(.{});
    hasher.update(&pkt.public_key);
    hasher.update(&shared_secret);
    hasher.final(&blinding_factor);

    // Step 9b: the outgoing ephemeral pubkey, re-blinded for the next hop.
    const next_point = ephemeral_point.mul(blinding_factor, .big) catch
        return error.IdentityElement;

    // Step 9c-d: the outgoing hop_payloads is the deobfuscated buffer with
    // this hop's frame stripped off the front, truncated back to 1300
    // bytes — expressed directly as the slice [consumed .. consumed+1300]
    // (identical to hopframe.leftShift-then-truncate, minus the extra
    // in-place move).
    result.next_packet = .{
        .public_key = next_point.toCompressedSec1(),
        .hop_payloads = unwrapped[frame.consumed..][0..hop_payloads_len].*,
        .hmac = frame.hmac,
    };
    return result;
}

// ── tests ────────────────────────────────────────────────────────────────
//
// Shape/error-set checks live here; the real KAT coverage (official BOLT#4
// vector, byte-exact) is in `kat_test.zig`.

test "error sets: ConstructError/ProcessError both include SharedSecretError" {
    const c: ConstructError = error.InvalidPublicKey;
    const p: ProcessError = error.IdentityElement;
    try std.testing.expect(c == error.InvalidPublicKey);
    try std.testing.expect(p == error.IdentityElement);
}

test "construct: empty route / hop-count mismatch / reserved payload length fail closed" {
    const session_key = [_]u8{0x41} ** 32;
    const g = Secp256k1.basePoint.toCompressedSec1();
    const payload = [_]u8{ 0x02, 0x03, 0x04 };

    try std.testing.expectError(error.HopCountMismatch, construct(session_key, &.{}, &.{}, ""));
    try std.testing.expectError(
        error.HopCountMismatch,
        construct(session_key, &.{ g, g }, &.{&payload}, ""),
    );
    try std.testing.expectError(
        error.ReservedPayloadLength,
        construct(session_key, &.{g}, &.{&[_]u8{0x01}}, ""),
    );
}

test "construct: a route that cannot fit 1300 bytes is RouteTooLong (both forms)" {
    const session_key = [_]u8{0x41} ** 32;
    const g = Secp256k1.basePoint.toCompressedSec1();

    // 4 hops x shiftSize(300) = 4 x 335 = 1340 > 1300.
    const big_payload = [_]u8{0xaa} ** 300;
    const pubkeys4 = [_][pubkey_len]u8{g} ** 4;
    const payloads4 = [_][]const u8{&big_payload} ** 4;
    try std.testing.expectError(
        error.RouteTooLong,
        construct(session_key, &pubkeys4, &payloads4, ""),
    );

    // More hops than can ever fit (max_hops + 1), regardless of payload size.
    const tiny = [_]u8{ 0x01, 0x02 };
    const pubkeys38 = [_][pubkey_len]u8{g} ** (max_hops + 1);
    const payloads38 = [_][]const u8{&tiny} ** (max_hops + 1);
    try std.testing.expectError(
        error.RouteTooLong,
        construct(session_key, &pubkeys38, &payloads38, ""),
    );
}

test "deriveHopSecrets: an off-curve hop pubkey is InvalidPublicKey" {
    const g = Secp256k1.basePoint.toCompressedSec1();
    var bad = g;
    bad[0] = 0x05; // not a defined SEC1 encoding-type byte
    var out: [2]HopSecret = undefined;
    try std.testing.expectError(
        error.InvalidPublicKey,
        deriveHopSecrets([_]u8{0x41} ** 32, &.{ g, bad }, &out),
    );
}

test "HopSecret / ProcessResult field shapes" {
    const hs = HopSecret{ .shared_secret = [_]u8{0} ** 32, .ephemeral_pubkey = [_]u8{2} ++ [_]u8{0} ** 32 };
    try std.testing.expectEqual(@as(usize, 32), hs.shared_secret.len);
    try std.testing.expectEqual(@as(usize, pubkey_len), hs.ephemeral_pubkey.len);

    var pr = ProcessResult{ .payload_buf = [_]u8{0} ** hop_payloads_len, .payload_len = 3, .next_packet = null };
    @memcpy(pr.payload_buf[0..3], &[_]u8{ 1, 2, 3 });
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, pr.payload());
}
