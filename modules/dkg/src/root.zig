// SPDX-License-Identifier: MIT

//! dkg — secure **Distributed Key Generation** for `threshold_ecdsa`,
//! removing the trusted-dealer assumption: `n` parties jointly generate an
//! ECDSA secret sharing with NO party ever holding the whole key and NO
//! dealer to trust.
//!
//! This is the **GJKR** construction (Gennaro-Jarecki-Krawczyk-Rabin,
//! "Secure Distributed Key Generation for Discrete-Log Based
//! Cryptosystems") over secp256k1 — the bias-resistant DKG that fixes the
//! rushing-adversary bias of naive Pedersen-DKG by committing (Pedersen)
//! and fixing the QUAL set BEFORE revealing Feldman commitments. See
//! `SPEC.md` for the full construction, the Fable-vs-mechanical split, and
//! the frost-dedup verdict (frost has NO DKG — trusted dealer only — so
//! this is genuinely new work, not an adaptation).
//!
//! **Scope (Phase 1): the secret-key DKG only.** Output is per-party ECDSA
//! key material (`DkgShareOutput`) directly consumable by the existing
//! `threshold_ecdsa` signing via `assembleKeyShares`. CGGMP21 signing-phase
//! identifiable-abort, proactive refresh, and aux-parameter DKG are LATER
//! increments (SPEC "Out of scope").
//!
//! **Status — COMPLETE.** The five irreducible GJKR functions in
//! `core.zig` (`verifyPedersenShare`, `verifyFeldmanShare`, `computeQual`,
//! `deriveGroupPublicKey`, `combineKeyShare`) are implemented and
//! `gate.fable_core_implemented` is `true`: the formerly-gated tests —
//! including the decisive end-to-end anchor (DKG shares →
//! `threshold_ecdsa.signWithShares` → std-ECDSA verify under `Q`) — run
//! for real. The `BrokenDkg` positive control keeps proving the harness
//! discriminates (it still catches the poisoned key).

const std = @import("std");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any, // pure protocol logic verified in-process; no OS/network I/O
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "Gennaro, Jarecki, Krawczyk, Rabin — \"Secure Distributed Key Generation for Discrete-Log Based Cryptosystems\" (J. Cryptology 2007), over secp256k1; feeds this repo's threshold_ecdsa signing",
    .deps = .{ "threshold_ecdsa", "paillier" },
};

// ── submodule re-exports ─────────────────────────────────────────────────

pub const gate = @import("gate.zig");

const types = @import("types.zig");
pub const Config = types.Config;
pub const PedersenBroadcast = types.PedersenBroadcast;
pub const FeldmanBroadcast = types.FeldmanBroadcast;
pub const ShareMsg = types.ShareMsg;
pub const Complaint = types.Complaint;
pub const DkgShareOutput = types.DkgShareOutput;
pub const Scalar = types.Scalar;
pub const Element = types.Element;

pub const commit = @import("commit.zig");

const core = @import("core.zig");
pub const verifyPedersenShare = core.verifyPedersenShare;
pub const verifyFeldmanShare = core.verifyFeldmanShare;
pub const computeQual = core.computeQual;
pub const deriveGroupPublicKey = core.deriveGroupPublicKey;
pub const combineKeyShare = core.combineKeyShare;

pub const checks = @import("checks.zig");

const protocol = @import("protocol.zig");
pub const Corruption = protocol.Corruption;
pub const DriverError = protocol.DriverError;
pub const Dkg = protocol.Dkg;
pub const BrokenDkg = protocol.BrokenDkg;

const tecdsa = @import("threshold_ecdsa");
const paillier = @import("paillier");

// ── the bridge to threshold_ecdsa signing (REAL, mechanical) ─────────────

pub const AssembleError = error{ LengthMismatch, IndexMismatch } || std.mem.Allocator.Error;

/// Turn `n` `DkgShareOutput`s into `n` `threshold_ecdsa.KeyShare`s by
/// attaching each party's independently-generated Paillier keypair and
/// ring-Pedersen aux params (the DKG generates the ECDSA secret sharing;
/// Paillier/aux are per-party local key material, out of the secret-key
/// DKG's scope). REAL, mechanical assembly — mirrors
/// `threshold_ecdsa.keygenTrustedDealer`'s output shape, including the
/// shared `public_keys.entries` allocation (free it exactly ONCE:
/// `allocator.free(key_shares[0].public_keys.entries)`), then free the
/// `key_shares` slice.
///
/// `outputs`, `paillier_keys`, `aux_params` are index-aligned length `n`;
/// `outputs[r].index` must be `r + 1`. All outputs must carry the same
/// `group_public_key` (checked upstream by `checks.allSameQ`).
pub fn assembleKeyShares(
    allocator: std.mem.Allocator,
    outputs: []const DkgShareOutput,
    t: u32,
    paillier_keys: []const paillier.KeyPair,
    aux_params: []const tecdsa.AuxParams,
) AssembleError![]tecdsa.KeyShare {
    const n = outputs.len;
    if (paillier_keys.len != n or aux_params.len != n) return error.LengthMismatch;

    const entries = try allocator.alloc(tecdsa.PartyPublicKeys, n);
    errdefer allocator.free(entries);
    for (entries, 0..) |*e, i| {
        e.* = .{
            .index = @intCast(i + 1),
            .paillier_pk = paillier_keys[i].public,
            .aux = aux_params[i],
        };
    }
    const public_keys: tecdsa.PublicKeys = .{ .entries = entries };

    const shares = try allocator.alloc(tecdsa.KeyShare, n);
    errdefer allocator.free(shares);
    for (shares, 0..) |*s, i| {
        if (outputs[i].index != i + 1) return error.IndexMismatch;
        s.* = .{
            .index = outputs[i].index,
            .t = t,
            .n = @intCast(n),
            .secret_share = outputs[i].secret_share,
            .group_public_key = outputs[i].group_public_key,
            .verifying_share = outputs[i].verifying_share,
            .paillier_secret = paillier_keys[i].secret,
            .public_keys = public_keys,
        };
    }
    return shares;
}

// ── the end-to-end anchor (GATED on core) ────────────────────────────────

fn randomScalar(random: std.Random) Scalar {
    var buf: [48]u8 = undefined;
    random.bytes(&buf);
    return Scalar.fromBytes48(buf, .big);
}

fn sampleFeBelow(m: tecdsa.AuxModulus, random: std.Random) tecdsa.AuxFe {
    const n_bits = tecdsa.aux_modulus_bits;
    const n_len = (n_bits + 7) / 8;
    var buf: [tecdsa.aux_modulus_bytes]u8 = undefined;
    while (true) {
        random.bytes(buf[0..n_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * n_len - n_bits);
        const r = tecdsa.AuxFe.fromBytes(m, buf[0..n_len], .big) catch continue;
        if (!r.isZero()) return r;
    }
}

fn testAuxParams(random: std.Random) !tecdsa.AuxParams {
    const nt_kp = try paillier.generate(random, 2048);
    var nt_buf: [paillier.modulus_bytes]u8 = undefined;
    const nt_len = nt_kp.public.nByteLen();
    try nt_kp.public.nToBytes(nt_buf[0..nt_len]);
    var strip: usize = 0;
    while (strip < nt_len and nt_buf[strip] == 0) : (strip += 1) {}
    const n_tilde = try tecdsa.AuxModulus.fromBytes(nt_buf[strip..nt_len], .big);
    const x = sampleFeBelow(n_tilde, random);
    const h1 = n_tilde.sq(x);
    const h2 = n_tilde.sq(h1);
    return .{ .n_tilde = n_tilde, .h1 = h1, .h2 = h2 };
}

test "END-TO-END ANCHOR: DKG shares -> threshold sign -> std ECDSA verify under Q — GATED on core" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const testing = std.testing;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xA9C_0E2E);
    const random = prng.random();
    const cfg: Config = .{ .t = 2, .n = 3 };

    // 1. Run the real DKG (no dealer) to completion.
    const outs = try Dkg.run(allocator, cfg, .{}, random);
    defer {
        for (outs) |*o| o.deinit();
        allocator.free(outs);
    }
    try testing.expect(checks.allSameQ(outs));

    // 2. Attach per-party Paillier + aux material.
    const paillier_keys = try allocator.alloc(paillier.KeyPair, cfg.n);
    defer allocator.free(paillier_keys);
    const aux_params = try allocator.alloc(tecdsa.AuxParams, cfg.n);
    defer allocator.free(aux_params);
    for (0..cfg.n) |i| {
        paillier_keys[i] = try paillier.generate(random, 2048);
        aux_params[i] = try testAuxParams(random);
    }
    const key_shares = try assembleKeyShares(allocator, outs, cfg.t, paillier_keys, aux_params);
    defer {
        allocator.free(key_shares[0].public_keys.entries);
        allocator.free(key_shares);
    }

    // 3. Threshold-sign with any t shares, verify under Q with std ECDSA.
    const message = "dkg end-to-end anchor";
    const sig = try tecdsa.signing.signWithShares(allocator, key_shares[0..2], message, random);
    const ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const pk = try ecdsa.PublicKey.fromSec1(&outs[0].group_public_key.toBytes());
    try sig.verify(message, pk); // the decisive assertion: DKG key is real + std-usable
}

// ── dark-tests aggregator (CONVENTIONS §6.3) ─────────────────────────────

test {
    _ = types;
    _ = commit;
    _ = core;
    _ = checks;
    _ = protocol;
}
